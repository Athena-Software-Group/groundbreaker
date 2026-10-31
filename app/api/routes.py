"""JSON API. Everything the HTML UI does is also available here for automation / AWS integration.

Authentication: the browser session or HTTP Basic against `users` (app.core.security).
Every case-scoped route sits under /api/cases/{case_id}/… and goes through require_case_role;
objects addressed by id (runs, stop orders) are checked to belong to that case.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app import services
from app.api import schemas
from app.blocks import freeze_board as fb
from app.core.audit import CREATE, EXPORT, LIVE_PROVIDER_QUERY, RUN_TRACE, UPDATE, audit
from app.core.permissions import (
    INVESTIGATOR,
    READ_ONLY,
    CaseAccess,
    effective_role,
    get_case_object,
    may_create_cases,
    require_case_role,
    role_at_least,
    visible_cases,
)
from app.core.security import require_user
from app.db.models import SeedRole, StopOrder, TraceRun, User
from app.db.session import get_db
from app.domain import correspondence as desk
from app.domain import notify, sender
from app.tracing.annotate import annotate_elements
from app.tracing.diff import emit_trace_completed
from app.tracing.freeze import freeze_candidates
from app.tracing.graph import build_graph, summary, to_cytoscape

TRACE_MODES = (None, "", "fixture", "live")
LABEL_MAX = 128

router = APIRouter(prefix="/api", tags=["api"], dependencies=[Depends(require_user)])


@router.get("/cases", response_model=list[schemas.CaseListOut])
def list_cases(user: User = Depends(require_user), db: Session = Depends(get_db)):
    out = []
    for c in db.scalars(visible_cases(user)).unique().all():
        role = effective_role(db, user, c)
        if role is None:
            continue
        if role_at_least(role, READ_ONLY):
            row = schemas.CaseListOut.model_validate(c)
        else:  # external: what the case list page shows them, nothing more
            row = schemas.CaseListOut(id=c.id, reference=c.reference, title=c.title, status=c.status)
        row.role = role.value
        out.append(row)
    return out


@router.post("/cases", response_model=schemas.CaseOut, status_code=201)
def create_case(payload: schemas.CaseCreate, user: User = Depends(require_user), db: Session = Depends(get_db)):
    if not may_create_cases(user):
        audit(db, user, CREATE, None, ("cases", None), outcome="denied", reason="not_allowed_to_create_cases")
        raise HTTPException(403, "creating cases needs a system administrator or the can-create-cases permission")
    try:
        case = services.create_case(db, **payload.model_dump(), created_by=user)
    except services.CaseReferenceError as e:
        raise HTTPException(409 if e.taken else 422, str(e)) from None
    except sender.SenderError as e:
        db.rollback()
        raise HTTPException(422, str(e)) from None
    audit(db, user, CREATE, case, case)
    sender.audit_default_profile(db, user, case, sender.get_profile(db, case), source="case_created")
    return case


@router.get("/cases/{case_id}", response_model=schemas.CaseOut)
def get_case(access: CaseAccess = Depends(require_case_role(READ_ONLY))):
    return access.case


@router.put("/cases/{case_id}/seeds", status_code=204)
def update_seed(payload: schemas.SeedUpdate, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                db: Session = Depends(get_db)):
    try:
        seed_role = SeedRole(payload.role)
    except ValueError:
        raise HTTPException(422, f"unknown seed role {payload.role!r}") from None
    seed = services.update_seed(db, access.case, seed_role, payload.chain, payload.value, payload.note)
    audit(db, access, UPDATE, access.case, seed, role=payload.role, chain=payload.chain)


@router.post("/cases/{case_id}/trace", response_model=schemas.TraceRunOut)
def run_trace(mode: str | None = None, label: str | None = None,
              access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db)):
    if mode not in TRACE_MODES:  # no typo silently goes live
        raise HTTPException(400, f"unknown provider mode {mode!r}")
    label = (label or "").strip()[:LABEL_MAX] or None
    run = services.run_trace(db, access.case, provider_mode=mode or None, actor=access.user, label=label)
    if (run.params or {}).get("provider_mode") == "live":
        audit(db, access, LIVE_PROVIDER_QUERY, access.case, run, purpose="trace")
    audit(db, access, RUN_TRACE, access.case, run, provider_mode=mode or "default", status=run.status,
          labelled=bool(run.label))
    emit_trace_completed(db, access.case, run)
    return run


@router.get("/cases/{case_id}/trace/latest", response_model=schemas.TraceRunOut)
def latest_trace(access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db)):
    run = services.latest_run(db, access.case)
    if not run:
        raise HTTPException(404, "no trace yet")
    return run


@router.get("/cases/{case_id}/trace/{run_id}/graph")
def trace_graph(run_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db)):
    run = get_case_object(db, TraceRun, run_id, access)
    g = build_graph(db, run)
    elements = to_cytoscape(g)
    # the same freeze status / recommended targets as the Fund flow tab (no contact data)
    recs = annotate_elements(db, access.case, run, elements, can_act=access.can("draft_letter"),
                             show_names=access.can("view_restricted"))
    return {"elements": elements, "summary": summary(g), "recommendations": recs,
            "run": schemas.TraceRunOut.model_validate(run).model_dump()}


@router.get("/cases/{case_id}/trace/{run_id}/freeze-candidates")
def trace_freeze_candidates(run_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                            db: Session = Depends(get_db)):
    run = get_case_object(db, TraceRun, run_id, access)
    out = []
    for c in freeze_candidates(db, run):
        out.append({
            "entity": c.entity_name, "category": c.category, "kind": c.kind, "priority": c.priority,
            "total_taint_usd": str(c.total_taint_usd), "rationale": c.rationale,
            "compliance_email": c.entity.compliance_email if c.entity else None,
            "identifiers": [
                {"chain": i.chain, "address": i.address, "type": i.address_type, "label": i.label,
                 "taint_usd": str(i.taint_usd), "risk": i.risk, "flags": i.flags, "dwell_minutes": i.dwell_minutes,
                 "inbound": i.inbound, "outbound": i.outbound}
                for i in c.identifiers
            ],
        })
    return out


@router.post("/cases/{case_id}/stop-orders", response_model=list[schemas.StopOrderOut], status_code=201)
def generate_stop_orders(response: Response, entities: list[str] | None = None,
                         access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db)):
    """Draft freeze requests (an LE-only issuer: a notice) for the latest trace's targets no freeze was asked of yet
    (`entities`: only those), by the same plan as the Authorities tab's button (app.blocks.freeze_board.generator_plan):
    never a second request to a target already contacted, answered LE only / court order, declined, held or frozen,
    and never over a draft already made. The targets left out come back in the
    X-Aegis-Skipped header ("<target key>:<reason>:<request key>,…", reasons: freeze_board.SKIP_TEXT) and are
    audited."""
    access.require("draft_letter")
    run = services.latest_run(db, access.case)
    if not run:
        raise HTTPException(400, "run a trace first")
    try:
        board = fb.build(db, access.case, access, run=run)
    except Exception as err:  # noqa: BLE001 - never draft blind: the board says which targets were already asked
        import logging

        logging.getLogger(__name__).warning("freeze board failed for case %s (%s)", access.case.id, type(err).__name__)
        raise HTTPException(503, "the freeze board could not be built; nothing drafted") from None
    names, skipped = fb.generator_plan(board, only=entities)
    from app.domain import request_gate as rg

    gated: dict = {}  # candidate name -> the request gate's decision (one open request per provider)
    try:
        created = services.generate_stop_orders(db, access.case, run, only=names, actor=access.user,
                                                extra=fb.owner_addresses(board, names), refused=gated) if names else []
    except rg.Unavailable:
        raise HTTPException(503, "the counterparties' requests could not be read; nothing drafted") from None
    for order in created:
        audit(db, access, CREATE, access.case, order, origin="generated", run_id=run.id)
    skipped += fb.generator_result(board, names, created, gated)[0]
    if skipped:
        audit(db, access, "STOP_ORDERS_SKIPPED", access.case, run_id=run.id, skipped=len(skipped),
              reasons=sorted({code for _, code, _ in skipped}))
        response.headers["X-Aegis-Skipped"] = fb.skip_param(skipped)
    return created


@router.get("/cases/{case_id}/stop-orders", response_model=list[schemas.StopOrderOut])
def list_stop_orders(access: CaseAccess = Depends(require_case_role(READ_ONLY))):
    restricted = not access.can("view_restricted")  # the letter text and non-chain identifiers are R3
    mask = desk.contact_mask(access)  # LE / PI contacts and complaint references, below manage_le_contacts
    out = []
    for o in access.case.stop_orders:
        row = schemas.stop_order_out(o, restricted=restricted)
        if mask.active:
            row.subject = mask.text(row.subject)
            row.recipient_email = mask.value(row.recipient_email)
        out.append(row)
    return out


@router.patch("/cases/{case_id}/stop-orders/{order_id}", response_model=schemas.StopOrderOut)
def update_stop_order(order_id: int, payload: schemas.StopOrderStatusUpdate,
                      access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db)):
    from app.web.routes_authorities import _duplicate, _pointless, sent_refusal

    access.require("send_letter" if payload.status == "sent" else "log_correspondence")
    order = get_case_object(db, StopOrder, order_id, access)
    if payload.status == "sent" and _duplicate(db, access, order) is not None:  # as the stop-order page's form
        raise HTTPException(409, "this draft repeats a request already sent to the same counterparty: discard it "
                                 "(a case admin) instead of sending it")
    if payload.status == "sent" and (no := sent_refusal(_pointless(db, access, order))):  # a pointless draft too
        raise HTTPException(409, no)
    try:
        desk.record_stop_order_status(db, access.case, order, payload.status, actor=access.user,
                                      external_ref=payload.external_ref, note=payload.notes)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    audit(db, access, UPDATE, access.case, order, status=payload.status, external_ref_set=bool(payload.external_ref))
    db.refresh(order)
    return order


@router.get("/cases/{case_id}/stop-orders/{order_id}/docx")
def download_stop_order(order_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                        db: Session = Depends(get_db)):
    order = get_case_object(db, StopOrder, order_id, access)
    access.require("export")
    access.require("view_restricted")  # the letter text is R3
    path = services.export_stop_order_docx(order)
    audit(db, access, EXPORT, access.case, order, format="docx")
    return FileResponse(path, filename=path.name,
                        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")


@router.post("/cases/{case_id}/watch/poll")
def poll_watch(mode: str | None = None, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
               db: Session = Depends(get_db)):
    if mode not in TRACE_MODES:
        raise HTTPException(400, f"unknown provider mode {mode!r}")
    alerts, notes = notify.poll_and_notify(db, access.case, provider_mode=mode or None)
    audit(db, access, "POLL_WATCH", access.case, new_alerts=len(alerts), notifications=len(notes))
    return {"new_alerts": [{"id": a.id, "severity": a.severity, "tx_hash": a.tx_hash, "message": a.message} for a in alerts],
            "notifications": [n.id for n in notes]}
