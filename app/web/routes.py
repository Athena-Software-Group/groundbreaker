"""Server-rendered UI core: case list, case creation and the tabbed case page. Thin: logic lives in
app.services. Feature routes live in routes_<feature>.py (one router per feature)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import services
from app.ai.assistant import stored_summary
from app.ai.context import local_context
from app.ai.rules import derive
from app.core.audit import CREATE, audit
from app.core.csrf import require_csrf
from app.core.permissions import (
    EXTERNAL,
    CaseAccess,
    can,
    effective_role,
    may_create_cases,
    require_case_role,
    visible_cases,
)
from app.core.security import require_user
from app.db.models import (
    AIMode,
    Alert,
    Case,
    Chain,
    Notification,
    SeedRole,
    StopOrderStatus,
    User,
    WatchItem,
)
from app.db.session import get_db
from app.domain import correspondence as desk
from app.domain import notify, sender
from app.domain.evidence import mask_reference
from app.tracing.freeze import freeze_candidates
from app.tracing.graph import build_graph, summary
from app.web import tabs
from app.web.templating import _render_md, templates  # noqa: F401 - re-exported for older imports

log = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]


@router.get("/", response_class=HTMLResponse)
def index(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    rows = []
    for c in db.scalars(visible_cases(user)).unique().all():
        run = services.latest_run(db, c)
        rows.append({"case": c, "run": run, "role": effective_role(db, user, c),
                     "open_orders": sum(1 for o in c.stop_orders if o.status in (StopOrderStatus.DRAFT, StopOrderStatus.SENT))})
    return templates.TemplateResponse(request, "index.html", {"rows": rows})


def _require_case_creator(db: Session, user: User) -> None:
    """Opening a case makes you its admin, so it is a system-level permission (never a case role)."""
    if not may_create_cases(user):
        audit(db, user, CREATE, None, ("cases", None), outcome="denied", reason="not_allowed_to_create_cases")
        raise HTTPException(403, "creating cases needs a system administrator or the can-create-cases permission")


@router.get("/cases/new", response_class=HTMLResponse)
def new_case_form(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    _require_case_creator(db, user)
    return templates.TemplateResponse(request, "case_new.html", {
        "chains": list(Chain), "org_name": sender.org_name(), "signatory": sender.signatory_name(),
        "instrument_default": sender.DEFAULT_INSTRUMENT})


@router.post("/cases/new", dependencies=_csrf)
def new_case(
    request: Request, user: User = Depends(require_user), db: Session = Depends(get_db),
    reference: str = Form(...), title: str = Form(...), victim_name: str = Form(...),
    victim_entity: str = Form(""), loss_amount: str = Form(...), loss_asset: str = Form("USDC"),
    loss_usd: str = Form(""), fraud_date: str = Form(""), chain: str = Form("ethereum"),
    origin_tx: str = Form(""), victim_wallet: str = Form(""), perpetrator_wallet: str = Form(""),
    summary: str = Form(""), client_email: str = Form(""), authority_instrument: str = Form(""),
):
    _require_case_creator(db, user)
    try:
        amt = Decimal(loss_amount.replace(",", ""))
        usd = Decimal(loss_usd.replace(",", "")) if loss_usd else amt
    except InvalidOperation:
        raise HTTPException(400, "invalid amount")
    try:
        fd = datetime.fromisoformat(fraud_date).replace(tzinfo=UTC) if fraud_date else None
        chain_value = Chain(chain)
    except ValueError:
        raise HTTPException(400, "invalid fraud date or chain") from None
    if not (origin_tx or perpetrator_wallet):
        raise HTTPException(400, "origin tx hash or perpetrator wallet is required")
    try:
        reference = services.check_new_reference(db, reference)
        sender.clean_client_email(client_email)
        sender.clean_instrument(authority_instrument)
    except services.CaseReferenceError as e:
        raise HTTPException(409 if e.taken else 400, str(e)) from None
    except sender.SenderError as e:
        raise HTTPException(400, str(e)) from None
    case = services.create_case(
        db, reference=reference, title=title.strip(), victim_name=victim_name.strip(),
        victim_entity=victim_entity.strip() or None, loss_amount=amt, loss_asset=loss_asset.strip().upper(),
        loss_usd=usd, fraud_date=fd, chain=chain_value, origin_tx=origin_tx or None,
        victim_wallet=victim_wallet or None, perpetrator_wallet=perpetrator_wallet or None, summary=summary or None,
        created_by=user, client_email=client_email, authority_instrument=authority_instrument,
    )
    audit(db, user, CREATE, case, case)
    sender.audit_default_profile(db, user, case, sender.get_profile(db, case), source="case_created")
    return RedirectResponse(f"/cases/{case.id}", status_code=303)


@router.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(request: Request, tab: str = "overview", access: CaseAccess = Depends(require_case_role(EXTERNAL)),
                db: Session = Depends(get_db)):
    """The tabbed case page. Only the active tab's partial is rendered (its context provider runs)."""
    visible = [t for t in tabs.TABS if access.at_least(t.min_role)]
    if tab not in {t.key for t in visible}:
        tab = visible[0].key
    page = next((t.href for t in visible if t.key == tab and t.href), None)
    if page is not None:  # a tab that is its own page (the Recovery plan)
        return RedirectResponse(f"/cases/{access.case.id}{page}", status_code=303)
    ctx = {
        "case": access.case, "access": access, "tab": tab, "tabs": visible,
        "can": lambda action: can(access, None, action),
    }
    ctx.update(tabs.context_for(tab, request, db, access))
    return templates.TemplateResponse(request, "case_detail.html", ctx)


@tabs.tab_context("overview")
def overview_tab(request: Request, db: Session, access: CaseAccess) -> dict:
    """Case status at a glance: assistant summary, funds position, open stop orders, overdue and
    upcoming replies, latest notifications and movement alerts. Each block degrades on its own."""
    case = access.case
    now = datetime.now(tz=UTC)
    run = services.latest_run(db, case)
    stats = cands = None
    if run:
        stats = summary(build_graph(db, run))
        cands = freeze_candidates(db, run)
    alerts = db.scalars(
        select(Alert).join(WatchItem).where(WatchItem.case_id == case.id).order_by(Alert.created_at.desc()).limit(8)
    ).all()

    # funds position: the assistant's deterministic figures (same numbers as its rule-based summary)
    funds = None
    try:
        funds = derive(local_context(db, case, now=now, blocks=False), now)["funds_position"]
    except Exception:  # the overview must render even if one figure cannot be computed
        log.exception("overview: funds position failed for case %s", case.id)

    days = notify.overdue_days(db, case)
    authorities = desk.case_authorities(db, case, run=run, cands=cands)
    open_orders, overdue, upcoming, holds = [], [], [], []
    for a in authorities:
        for o in a.stop_orders:
            state = desk.order_state(o)
            if desk.order_open(o):
                due = desk.response_due(o, days) if desk.awaiting_response(o) else None
                open_orders.append({"order": o, "authority": a, "state": state, "due": due,
                                    "overdue": due is not None and due < now})
            hold = desk.hold_state(o)
            if hold.get("state") in ("frozen", "acknowledged", desk.RELEASED) and hold.get("amount"):
                holds.append({"authority": a, "order": o, "hold": hold})
        for kind, obj_id, due in a.awaiting(days):
            row = {"authority": a, "kind": kind, "id": obj_id, "due": due,
                   "link": f"/cases/{case.id}/authorities/{a.key}#{'o' if kind == 'stop_order' else 'c'}{obj_id}"}
            if due < now:
                overdue.append({**row, "days_late": max(1, (now - due).days)})
            elif due < now + timedelta(days=7):
                upcoming.append({**row, "days_left": (due - now).days})
    open_orders.sort(key=lambda r: (not r["overdue"], r["due"] or now + timedelta(days=3650), r["order"].id))
    overdue.sort(key=lambda r: r["due"])
    upcoming.sort(key=lambda r: r["due"])

    stored = stored_summary(case)
    summary_visible = stored is not None and (stored.get("mode") != AIMode.FULL.value or access.can("view_restricted"))
    notes = db.scalars(select(Notification).where(Notification.case_id == case.id)
                       .order_by(Notification.id.desc()).limit(8)).all()
    return {
        "run": run, "stats": stats, "cands": cands, "alerts": alerts, "funds": funds,
        "open_orders": open_orders, "overdue": overdue, "upcoming": upcoming, "holds": holds,
        "drafts": sum(1 for o in case.stop_orders if desk.order_state(o) == "draft"),
        "summary_meta": stored,
        "summary": ((stored or {}).get("summary_full") if access.can("view_restricted") else None)
        or (stored or {}).get("summary") if summary_visible else None,
        "summary_hidden": stored is not None and not summary_visible,
        "notifications": notes, "read_ids": {n.id for n in notes if notify.is_read(n, access.user)},
        "event_labels": notify.EVENT_LABELS,
        "pending": [s for s in case.seeds if s.value.endswith("_PENDING")], "SeedRole": SeedRole,
        "watch_count": sum(1 for w in case.watch_items if w.active), "now": now,
        "complaints": _complaints(case, access),
        "sender_setup": _sender_setup(db, access),
    }


def _sender_setup(db: Session, access: CaseAccess) -> dict | None:
    """The Overview's setup line while the case's sender profile has no signed authority document attached yet
    (investigators and up, who see the profile on the authorities tab)."""
    if not access.can("view_restricted"):
        return None
    profile = sender.get_profile(db, access.case)
    if profile is None or profile.authority_evidence_ids:
        return None
    return {"signatory": profile.signatory_name or profile.org_name or sender.org_name(),
            "on_behalf_of": profile.on_behalf_of, "instrument": profile.instrument or sender.DEFAULT_INSTRUMENT,
            "link": f"/cases/{access.case.id}/sender-profile"}


def _complaints(case: Case, access: CaseAccess) -> list[dict]:
    """Complaint authorities and references; the references are R3, masked below view_restricted
    (as on the LE-contact views, app.domain.evidence.mask_reference)."""
    full = access.can("view_restricted")
    out = []
    for c in (case.facts or {}).get("complaints") or []:
        if not isinstance(c, dict):
            continue
        ref = c.get("reference")
        out.append({"authority": c.get("authority"), "reference": ref if full else mask_reference(ref),
                    "masked": bool(ref) and not full})
    return out
