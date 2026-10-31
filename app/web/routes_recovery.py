"""Recovery plan (app.blocks.recovery): the ranked moves that trap the most money fastest, next to Block status.

    GET  /cases/{id}/recovery-plan                   read_only+    the page (rebuilt from the case's state on every load)
    GET  /api/cases/{id}/recovery-plan               read_only+    the same plan as JSON
    GET  /cases/{id}/recovery-plan/pack/{key}.zip    investigator  the LE brief pack of one move (EXPORT audit)
    POST /cases/{id}/recovery-plan/watch             investigator  add trace wallets to the watch list (poll_watch)
    POST /cases/{id}/recovery-plan/waive             admin         waive / un-waive an evidence requirement (manage_case)
    POST /cases/{id}/recovery-plan/use-evidence      admin         use evidence #N for a requirement (its tag; manage_case)

Every POST is a CSRF-protected web form, audited with ids, requirement keys and counts only (never a reason's text or an
address). Nothing here sends or drafts mail: a move's action opens the prefilled letter on the authority page.

Wiring: `app.main` includes `router`. Importing this module registers the Jinja global `recovery_card(case, access)`
(the Overview card, recovery_card.html).
"""

from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.blocks import recovery as rp
from app.blocks import status as bs
from app.core.audit import CREATE, EXPORT, UPDATE, audit
from app.core.csrf import require_csrf
from app.core.permissions import ADMIN, INVESTIGATOR, READ_ONLY, CaseAccess, require_case_role
from app.core.security import require_user
from app.db.session import SessionLocal, get_db
from app.domain import evidence_requirements as er
from app.web.routes_blocks import _jsonable
from app.web.templating import templates

log = logging.getLogger(__name__)
router = APIRouter(tags=["recovery"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]
PACK_KEY_RE = re.compile(r"[oc]\d{1,12}|entity-\d{1,12}")
DONE_TEXT = {"watch": "Added to the watch list.", "waived": "Requirement waived: it is in the audit log.",
             "unwaived": "Waiver removed.", "used": "Evidence item tagged for the requirement: it is in the audit log.",
             "lookup": "Owner lookups done: the public tags found are in \"Who owns these wallets\" (audited).",
             "marked": "Your attribution is recorded: it wins over every other source (audited).",
             "enabled": "Owner lookups are on for this case: your consent and the endpoints are in the audit log.",
             "disabled": "Owner lookups are off for this case: nothing more is sent."}


def _plan_url(case_id: int, anchor: str = "") -> str:
    return f"/cases/{case_id}/recovery-plan{anchor}"


@router.get("/cases/{case_id}/recovery-plan", response_class=HTMLResponse)
def recovery_page(request: Request, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                  db: Session = Depends(get_db)):
    from app.web import tabs

    plan = rp.build(db, access.case)
    return templates.TemplateResponse(request, "recovery.html", {
        "case": access.case, "access": access, "v": rp.view(plan, access),
        "tabs": [t for t in tabs.TABS if access.at_least(t.min_role)], "tab": "recovery",
        "can_refresh": access.can("log_correspondence"), "done": DONE_TEXT.get(request.query_params.get("done") or ""),
    })


@router.get("/api/cases/{case_id}/recovery-plan")
def api_recovery(access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db)):
    v = rp.view(rp.build(db, access.case), access)
    return JSONResponse(_jsonable({"case": access.case.reference, **{k: v[k] for k in (
        "moves", "waiting", "secured", "done", "totals", "run", "requester", "notes", "generated_at", "owners",
        "owner_lookups")},
        "advisory": rp_disclaimer()}))


def rp_disclaimer() -> str:
    return ("Aegis's ranking from rules (no AI): advisory. A hold, freeze or return counts only once a person confirms "
            "it, and a person drafts, reviews and sends every letter.")


@router.get("/cases/{case_id}/recovery-plan/pack/{key}.zip")
def recovery_pack(key: str, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                  db: Session = Depends(get_db), brief: str = ""):
    if not PACK_KEY_RE.fullmatch(key or ""):
        raise HTTPException(404, "no such move")
    access.require("export")
    access.require("view_restricted")
    try:
        for_counsel = brief == "counsel"
        body, filename, manifest = rp.pack(db, access, key, counsel=for_counsel)
    except rp.PackError as exc:
        raise HTTPException(exc.status, exc.message) from None
    pack_kind = "counsel_brief_pack" if brief == "counsel" else "le_brief_pack"
    audit(db, access, EXPORT, access.case, ("recovery_plan", key), kind=pack_kind, format="zip",
          evidence_ids=[e["id"] for e in manifest["evidence"]], brief_id=manifest["brief"]["correspondence_id"],
          has_brief=bool(manifest["brief"]["file"]), run_id=(manifest["trace_run"] or {}).get("id"))
    return Response(body, media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})


@router.post("/cases/{case_id}/recovery-plan/watch", dependencies=_csrf)
def recovery_watch(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
                   address_id: list[str] = Form([])):
    from app import services
    from app.db.models import TraceNode

    access.require("poll_watch")
    run = services.latest_run(db, access.case)
    ids = {int(x) for x in address_id if x.strip().isdigit()}
    if run is None or not ids:
        raise HTTPException(400, "no wallet to watch")
    nodes = db.scalars(select(TraceNode).where(TraceNode.run_id == run.id, TraceNode.address_id.in_(ids))).all()
    if len(nodes) != len(ids):
        raise HTTPException(404, "wallet not in the latest trace")
    for n in nodes:
        item = services.add_watch(db, access.case, n.address, commit=False)
        item.active = True  # a wallet taken off the watch list earlier goes back on it
        db.commit()
        audit(db, access, CREATE, access.case, item, via="recovery_plan", run_id=run.id)
    return RedirectResponse(_plan_url(access.case.id, "?done=watch"), status_code=303)


@router.post("/cases/{case_id}/recovery-plan/waive", dependencies=_csrf)
def recovery_waive(access: CaseAccess = Depends(require_case_role(ADMIN)), db: Session = Depends(get_db),
                   key: str = Form(...), reason: str = Form(""), undo: str = Form(""), move: str = Form("")):
    access.require("manage_case")
    anchor = f"#m-{move}" if re.fullmatch(r"[a-z0-9:_-]{1,40}", move or "") else ""
    if undo in ("1", "on", "yes", "true"):
        changed = er.unwaive(db, access.case, key)
        audit(db, access, UPDATE, access.case, ("recovery_plan", None), op="unwaive_evidence", requirement=key[:40],
              changed=changed)
        return RedirectResponse(_plan_url(access.case.id, f"?done=unwaived{anchor}"), status_code=303)
    try:
        er.waive(db, access.case, key, user=access.user, reason=reason)
    except er.WaiverError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from None
    audit(db, access, UPDATE, access.case, ("recovery_plan", None), op="waive_evidence", requirement=key,
          has_reason=True)
    return RedirectResponse(_plan_url(access.case.id, f"?done=waived{anchor}"), status_code=303)


@router.post("/cases/{case_id}/recovery-plan/use-evidence", dependencies=_csrf)
def recovery_use_evidence(access: CaseAccess = Depends(require_case_role(ADMIN)), db: Session = Depends(get_db),
                          key: str = Form(...), evidence_id: str = Form(...), move: str = Form("")):
    access.require("manage_case")
    anchor = f"#m-{move}" if re.fullmatch(r"[a-z0-9:_-]{1,40}", move or "") else ""
    item_id = int(evidence_id.strip().lstrip("#")) if evidence_id.strip().lstrip("#").isdigit() else 0
    try:
        item = er.use_item(db, access, key, item_id)
    except er.WaiverError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from None
    audit(db, access, UPDATE, access.case, item, op="use_for_requirement", requirement=key, via="recovery_plan")
    return RedirectResponse(_plan_url(access.case.id, f"?done=used{anchor}"), status_code=303)


# --------------------------------------------------------------------------- Jinja global
def recovery_card(case, access) -> dict | None:
    """The Overview card (recovery_card.html): the top moves and the totals. None on failure or with nothing to do."""
    return overview_cards(case, access)["recovery"]


def overview_cards(case, access) -> dict:
    """{"blocks": the Block status card, "recovery": the Recovery plan card, "todo": the To do list (its card and the
    tab bar's badge: app.web.routes_todo)} from one session and one case_blocks pass, computed once per request (kept on
    this request's CaseAccess). Each is None on its own failure."""
    memo = getattr(access, "_overview_cards", None)
    if isinstance(memo, dict) and memo.get("case") == getattr(case, "id", None):
        return memo
    from app.db.models import Case
    from app.web import routes_blocks

    out: dict = {"case": getattr(case, "id", None), "blocks": None, "recovery": None, "owners": None, "todo": None,
                 "plan": None}
    try:
        with SessionLocal() as db:
            c = db.get(Case, case.id)
            rows = bs.case_blocks(db, c)
            try:
                out["blocks"] = routes_blocks.card_from_rows(c, rows, access)
            except Exception as err:  # noqa: BLE001 - a DB error's text carries bound parameters: log the type only
                log.warning("block status card failed for case %s (%s)", case.id, type(err).__name__)
            plan = rp.build(db, c, rows=rows)
            out["owners"] = plan.owners  # the freeze card reads the same attribution pass
            v = rp.view(plan, access)
            out["plan"] = v["totals"]  # the Overview's funds tiles: the plan's own figures (plan_totals)
            out["recovery"] =({"moves": v["moves"][:3], "totals": v["totals"], "n": len(v["moves"])}
                               if v["moves"] else None)
            try:  # the To do card and the tab bar's badge: the same block rows (app.domain.todo; last, it may commit)
                from app.core.permissions import CaseAccess
                from app.domain import todo

                out["todo"] = todo.build(db, c, CaseAccess(case=c, user=access.user, role=access.role, member=None),
                                         rows=rows)
            except Exception as err:  # noqa: BLE001 - a DB error's text carries bound parameters: log the type only
                log.warning("to do card failed for case %s (%s)", case.id, type(err).__name__)
    except Exception as err:  # noqa: BLE001 - a DB error's text carries bound parameters: log the type only
        log.warning("overview cards failed for case %s (%s)", getattr(case, "id", None), type(err).__name__)
    access._overview_cards = out  # this request's CaseAccess: the memo lives as long as the request
    return out


def plan_totals(case, access) -> dict | None:
    """The Recovery plan's totals (app.blocks.recovery.build: in play, the issuers' lever, owner unknown, …) for the
    Overview's funds tiles, from the same pass as its cards; None on failure."""
    return overview_cards(case, access)["plan"]


templates.env.globals["recovery_card"] = recovery_card
templates.env.globals["plan_totals"] = plan_totals
