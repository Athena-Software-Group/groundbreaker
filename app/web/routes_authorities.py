"""Authorities & stop-order desk: counterparties, communications timeline, form letters, stop orders.

Owner: the authorities feature. Logic: app/domain/correspondence.py. Letter templates:
app/reports/templates/letters/*.md.j2 (stop orders: app/reports/stop_orders.py).
Templates: case/_tab_authorities.html (tab), authority_detail.html (one counterparty),
authority_letter.html (one letter / message), stop_order.html (generated stop order).
Static: css/authorities.css, js/authorities.js.

Pages
    GET  /cases/{id}/authorities                          → 303 to the tab
    GET  /cases/{id}/authorities/{key}                    authority page (key: entity-<id> | le-<id> |
                                                          complaint-<n> | pi-<n>)
    POST /cases/{id}/authorities/{key}/log                log an inbound reply / outbound message / note
    POST /cases/{id}/authorities/{key}/letters            generate a form letter (saved as a draft) through the request
                                                          gate (app.domain.request_gate: one open request per
                                                          provider): an open draft / prepared e-mail, a request already
                                                          sent (only its follow-ups), an LE-only answer: 409 with what
                                                          to do instead; a new address (`about` / `freeze_address`) for
                                                          a provider with an open draft is added to that draft (303 to
                                                          it); a stop order over a draft only with
                                                          replace_draft=<its key> (the page's option); unreadable: 503
    GET  /cases/{id}/authorities/correspondence/{cid}     one letter / message (drafts are editable)
    POST /cases/{id}/authorities/correspondence/{cid}     edit a draft
    POST /cases/{id}/authorities/correspondence/{cid}/sent  mark a draft sent (409 for one a newer letter replaced)
    POST /cases/{id}/stop-orders                          draft freeze requests / notices for the latest trace's targets
                                                          no freeze was asked of (entity=<name>: one target; redraft=1:
                                                          its draft from an earlier trace); skips every contacted /
                                                          LE-only / answered target and says why (app.blocks.freeze_board)
    POST /cases/{id}/authorities/correspondence/{cid}/discard  discard a draft letter the board flags as pointless (the
                                                          provider answered LE only / declined; case admins)
    POST /cases/{id}/stop-orders/{oid}/discard            discard a draft the board flags as a duplicate (case admins):
                                                          its prepared e-mails cancelled, the letter never sent
    GET  /cases/{id}/stop-orders/{oid}                    stop-order page (a draft the board flags as a duplicate: the
                                                          warning, no Prepare e-mail, no "sent")
    POST /cases/{id}/stop-orders/{oid}/status             status change (+ amount held), logged + emitted ("sent": 409 for
                                                          a flagged duplicate)
API
    GET  /api/cases/{id}/authorities                      counterparties with counts / due dates
    GET  /api/cases/{id}/authorities/{key}/timeline       the timeline (R3 bodies need view_restricted)
    GET  /api/cases/{id}/authorities/correspondence/{cid}/md | /docx   export (written under EXPORT_DIR)
    POST /api/cases/{id}/authorities/check-overdue        emit response_overdue for late replies
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app import services
from app.ai import providers as ai_providers
from app.blocks import classify_ai
from app.blocks import freeze_board as fb
from app.blocks import translate as tr
from app.core.audit import CREATE, EXPORT, LETTER_SENT, UPDATE, audit
from app.core.csrf import require_csrf
from app.core.permissions import (
    ADMIN,
    EXTERNAL,
    INVESTIGATOR,
    READ_ONLY,
    CaseAccess,
    get_case_object,
    require_case_role,
)
from app.core.security import require_user
from app.db.models import (
    Classification,
    Correspondence,
    CorrespondenceChannel,
    CorrespondenceDirection,
    CorrespondenceKind,
    CorrespondenceStatus,
    StopOrder,
    StopOrderStatus,
)
from app.db.session import get_db
from app.domain import correspondence as desk
from app.domain import directory, sender
from app.domain import evidence as ev
from app.domain import evidence_requirements as er
from app.tracing.freeze import freeze_candidates
from app.web import mail_flow
from app.web.tabs import tab_context
from app.web.templating import templates

router = APIRouter(tags=["authorities"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]
DOCX_MEDIA = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _parse_dt(v: str | None) -> datetime | None:
    """A datetime-local / ISO value from a form, taken as UTC when it carries no offset."""
    s = (v or "").strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "invalid date / time") from None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _split(v: str | None) -> list[str]:
    return [p.strip() for p in (v or "").replace(";", ",").replace("\n", ",").split(",") if p.strip()]


def _int(v: str | None, what: str) -> int | None:
    s = (v or "").strip()
    if not s:
        return None
    if not s.isdigit():
        raise HTTPException(400, f"invalid {what}")
    return int(s)


def _authority_or_404(db: Session, access: CaseAccess, key: str, **kw) -> desk.Authority:
    authority = desk.get_authority(db, access.case, key, shared_only=access.is_external, **kw)
    if authority is None:
        raise HTTPException(404, "authority not found")
    return authority


def _authority_of(db: Session, access: CaseAccess, corr: Correspondence) -> desk.Authority | None:
    for a in desk.case_authorities(db, access.case, shared_only=access.is_external, include_prospects=False):
        if corr in a.correspondence:
            return a
    return None


def _desk_error(exc: desk.DeskError) -> HTTPException:
    return HTTPException(400, str(exc))


# --------------------------------------------------------------------------- tab
@tab_context("authorities")
def authorities_tab(request: Request, db: Session, access: CaseAccess) -> dict:
    case = access.case
    if access.is_external:  # externals see only correspondence explicitly shared with them
        return {"orders": [], "cands": None, "run": None, "authorities": desk.case_authorities(
            db, case, shared_only=True), "unassigned": desk.unassigned_correspondence(case, shared_only=True),
            "now": datetime.now(tz=UTC), "order_state": desk.order_state, "hold_state": desk.hold_state,
            "response_due": desk.response_due, "mask": desk.contact_mask(access)}
    run = services.latest_run(db, case)
    cands = freeze_candidates(db, run) if run else None
    authorities = desk.case_authorities(db, case, run=run, cands=cands)
    mail = _mail_tab_context(db, access, request)
    board = _board(db, access, run=run, cands=cands or [], authorities=authorities, awaiting=mail["mail_awaiting"])
    if board is not None and mail["mail_awaiting"]:  # a pointless draft's prepared e-mail is no call to Send
        gone = {p["prepared"] for t in board.targets for p in [*t.pointless, *t.duplicates] if p.get("prepared")}
        mail["mail_awaiting"] = [m for m in mail["mail_awaiting"] if m.id not in gone]
    return {
        "run": run, "cands": cands, "orders": sorted(case.stop_orders, key=lambda o: -o.id),
        "order_groups": fb.order_groups(case.stop_orders), "board": board,
        "dup_orders": {d["order_id"]: d for t in board.targets for d in t.duplicates} if board is not None else {},
        "board_flash": _board_flash(request, board), "block_status": _block_status(board, access),
        "authorities": authorities,
        "unassigned": desk.unassigned_correspondence(case), "now": datetime.now(tz=UTC),
        "order_state": desk.order_state, "hold_state": desk.hold_state, "response_due": desk.response_due,
        "mask": desk.contact_mask(access), **mail,
    }


def _board(db: Session, access: CaseAccess, **kw) -> fb.Board | None:
    """The Freeze & stop-order board (app.blocks.freeze_board); None when it cannot be built (the tab still renders)."""
    try:
        return fb.build(db, access.case, access, **kw)
    except Exception as err:  # noqa: BLE001 - a broken source never takes the tab down
        import logging

        logging.getLogger(__name__).warning("freeze board failed for case %s (%s)", access.case.id,
                                            type(err).__name__)
        return None


def _block_status(board: fb.Board | None, access: CaseAccess) -> dict | None:
    """The tab's Block status column from the board's own block rows (one case_blocks pass for the tab): authority
    key -> [{key, kind, request, status_text, tone, needs_confirmation, overdue}], as block_status_by_authority
    (app/web/routes_blocks.py) gives it. None without a board: the template falls back to that global."""
    if board is None:
        return None
    from app.blocks import report

    out: dict[str, list[dict]] = {}
    try:
        for r in board.rows:
            if r.kind == "onchain":
                continue
            v = report.row_view(r, access, access.case)
            out.setdefault(r.authority.key, []).append(
                {"key": r.key, "kind": r.kind, "request": v["request"], "status_text": v["status_text"],
                 "tone": v["tone"], "needs_confirmation": v["needs_confirmation"], "confirm_tag": v["confirm_tag"],
                 "overdue": v["overdue"], "due": r.due_at,
                 "order_id": r.order.id if getattr(r, "order", None) is not None else None})
    except Exception as err:  # noqa: BLE001 - the column only; the template falls back to its own pass
        import logging

        logging.getLogger(__name__).warning("block status column failed for case %s (%s)", access.case.id,
                                            type(err).__name__)
        return None
    return out


def _board_flash(request: Request, board: fb.Board | None) -> dict | None:
    """What the generator ("Draft freeze requests") did (?so=1&so_n=N&so_skip=…&so_notice=…, set by stop_orders
    below): the count drafted, the targets it skipped with the reason and the drafted notice-only issuers (names and
    reasons from the board, never the query)."""
    q = request.query_params
    if q.get("so") != "1":
        return None
    if q.get("so_err") == "board":
        return {"drafted": 0, "skipped": [], "notices": [], "error": BOARD_ERROR}
    n = int(q["so_n"]) if (q.get("so_n") or "").isdigit() else 0
    return {"drafted": n, "skipped": fb.skip_lines(q.get("so_skip") or "", board),
            "notices": fb.notice_lines(q.get("so_notice") or "", board), "error": None}


BOARD_ERROR = ("The freeze & stop-order board could not be built, so nothing was drafted (without it the generator "
               "cannot tell which targets were already asked). Try again shortly; if it persists, check the server log.")


def _duplicate(db: Session, access: CaseAccess, order: StopOrder) -> dict | None:
    """The board's duplicate flag for draft `order` (it repeats a request already sent: {order_id, no, of, of_key,
    answer, prepared, text}), from its counterparty's own rows; None for any other order."""
    if order.status != StopOrderStatus.DRAFT or order.entity_id is None:
        return None
    try:
        authority = desk.get_authority(db, access.case, f"entity-{order.entity_id}",
                                       run=services.latest_run(db, access.case))
        t = fb.target_for(db, access.case, access, authority)
    except Exception as err:  # noqa: BLE001 - the warning only; the page still renders
        import logging

        logging.getLogger(__name__).warning("duplicate check failed for stop order %s (%s)", order.id,
                                            type(err).__name__)
        return None
    return next((d for d in (t.duplicates if t is not None else []) if d["order_id"] == order.id), None)


def _pointless(db: Session, access: CaseAccess, order: StopOrder) -> dict | None:
    """The board's pointless flag for draft `order` (its provider answered LE only / declined, or its playbook gates
    us: freeze_board.pointless_flag), or None."""
    if order.status != StopOrderStatus.DRAFT or order.entity_id is None:
        return None
    try:
        authority = desk.get_authority(db, access.case, f"entity-{order.entity_id}",
                                       run=services.latest_run(db, access.case))
    except Exception:  # noqa: BLE001 - no authority: not flagged
        return None
    return fb.pointless_flag(db, access.case, authority, f"o{order.id}")


def sent_refusal(flag: dict | None) -> str | None:
    """Why a draft the board flags (pointless: its provider answered LE only / declined, its playbook gates us, a
    follow-up drafted before their reply; or a duplicate) is never recorded as sent by hand (freeze_board
    .pointless_text), or None. One exception: a draft whose e-mail may already be out (`busy`) is settled by
    recording it as sent."""
    if flag is None or flag.get("busy"):
        return None
    return fb.pointless_text(flag)


MAIL_SYNC_TEXT = {"ok": "Mailbox checked: {received} repl{ies} filed on this case, {review} waiting for review.",
                  "busy": "Another mailbox check is running; try again in a minute.",
                  "too_soon": "The mailbox was checked less than a minute ago; try again shortly.",
                  "off": "Inbound mail is not configured (AEGIS_MAIL_INBOUND / AEGIS_MAIL_TRANSPORT).",
                  "error": "The mailbox check failed; see /admin/mail."}


def _mail_tab_context(db: Session, access: CaseAccess, request: Request) -> dict:
    """The e-mail desk's line on the tab: the sender profile, the prepared e-mails waiting for a case
    admin to press Send, and for case admins "Check mailbox now" (POST /cases/{id}/mail/sync in
    app/web/routes_mail_admin.py, which redirects back with ?mail_sync=<flag>&mail_received=N&mail_review=M;
    disabled with the reason when inbound mail is not set up) and the inbound mail waiting for review."""
    from app.domain.mail_send import awaiting_send

    review, flash, inbound_problem = 0, None, None
    if access.can("triage_mail"):
        from app.mail.config import mail_settings
        from app.mail.ingest import case_review_count, inbound_transport

        review = case_review_count(db, access.case.id)
        settings = mail_settings()
        if not settings.aegis_mail_inbound:
            inbound_problem = "inbound mail is off (AEGIS_MAIL_INBOUND)"
        elif not settings.mail_from:
            inbound_problem = "no case mailbox (AEGIS_MAIL_FROM)"
        else:
            try:
                inbound_problem = inbound_transport(settings)[1]
            except Exception:  # noqa: BLE001 - a broken mail setup only disables the button
                inbound_problem = "the mail transport is not configured"
        q = request.query_params
        flag = q.get("mail_sync") or ""
        if flag in MAIL_SYNC_TEXT:
            n_in = int(q["mail_received"]) if (q.get("mail_received") or "").isdigit() else 0
            n_rv = int(q["mail_review"]) if (q.get("mail_review") or "").isdigit() else 0
            flash = (MAIL_SYNC_TEXT[flag].format(received=n_in, ies="y" if n_in == 1 else "ies", review=n_rv),
                     flag not in ("ok",))
    awaiting = awaiting_send(db, access.case.id) if access.can("prepare_email") else []
    return {"sender_profile": sender.get_profile(db, access.case) if access.can("view_restricted") else None,
            "mail_review_count": review, "mail_sync_flash": flash, "mail_inbound_problem": inbound_problem,
            "mail_awaiting": awaiting, "mail_manual": _mail_manual()}


def _mail_manual() -> bool:
    """AEGIS_MAIL_TRANSPORT=manual ("Draft — you send", the default): wording for a person sending from Outlook."""
    from app.domain.mail_compose import is_manual

    try:
        return is_manual()
    except Exception:  # noqa: BLE001 - a broken mail setup only changes the wording
        return False


@router.get("/cases/{case_id}/authorities")
def authorities_tab_page(case_id: int, access: CaseAccess = Depends(require_case_role(EXTERNAL))):
    return RedirectResponse(f"/cases/{case_id}?tab=authorities", status_code=303)


# --------------------------------------------------------------------------- one letter / message
# (registered before /authorities/{key} so "correspondence" is never read as an authority key)
@router.get("/cases/{case_id}/authorities/correspondence/{corr_id}", response_class=HTMLResponse)
def correspondence_page(request: Request, corr_id: int, access: CaseAccess = Depends(require_case_role(EXTERNAL)),
                        db: Session = Depends(get_db)):
    corr = get_case_object(db, Correspondence, corr_id, access)
    authority = _authority_of(db, access, corr)
    from app.domain.mail_send import (
        mail_history,  # local: the mail feature's module (no app.mail import)
    )

    show_body = desk.can_view_body(access, corr)
    # a draft to a provider that answered LE only / declined (or whose playbook gates us): pointless, discard it; the
    # letter of a duplicate stop-order draft likewise
    pointless = (fb.letter_flag(db, access.case, corr, authority) if authority is not None
                 and corr.status == CorrespondenceStatus.DRAFT
                 and corr.direction == CorrespondenceDirection.OUT and not fb.discarded(corr) else None)
    return templates.TemplateResponse(request, "authority_letter.html", {
        "pointless": pointless if access.can("view_restricted") else None,
        "can_discard": pointless is not None and access.can("manage_case"),
        # never "send it outside Aegis, then record it" for a pointless / duplicate draft (unless its e-mail may be
        # out: recording it as sent settles it), nor its export for sending
        "can_mark_sent": sent_refusal(pointless) is None,
        "mail_messages": mail_history(db, corr) if access.can("prepare_email") else [],
        "added": (request.query_params.get("added") or "")[:200] or None,
        "can_prepare_email": (access.can("prepare_email") and show_body and authority is not None
                              and corr.status == CorrespondenceStatus.DRAFT and not fb.discarded(corr)
                              and pointless is None  # never e-mailed (compose and Send refuse it)
                              and not _replaced(corr) and corr.direction == CorrespondenceDirection.OUT),
        "external_mail": (corr.meta or {}).get("source") == "mailbox",
        "case": access.case, "access": access, "corr": corr, "authority": authority,
        "mask": desk.contact_mask(access, authority, corr), "order_shared": desk.order_shared,
        "ev_text": ev.ref_mask(access),
        "show_body": desk.can_view_body(access, corr), "channels": list(CorrespondenceChannel),
        "evidence": desk.linked_evidence(access.case, corr, shared_only=access.is_external, access=access),
        "kind_labels": desk.KIND_LABELS, "order_state": desk.order_state,
        "default_due_days": desk.DEFAULT_RESPONSE_DAYS,
        **_translate_context(request, access, corr),
    })


def _translate_context(request: Request, access: CaseAccess, corr: Correspondence) -> dict:
    """The letter page's translation panel: only inbound e-mail, only for those who may read it."""
    shown = corr.direction == CorrespondenceDirection.IN and desk.can_view_body(access, corr)
    if not shown:
        return {"translation": None, "can_translate": False}
    ok, reason = classify_ai.may_call(access.case, ai_providers.get_provider())
    failed = (request.query_params.get("translate") or "")[:40]
    return {"translation": tr.translation(corr), "can_translate": access.can("draft_letter"), "translate_ready": ok,
            "translate_blocked": None if ok else classify_ai.REASON_TEXT.get(reason, reason),
            "translate_language": tr.language_of(corr.body_markdown),
            "translate_error": classify_ai.REASON_TEXT.get(failed, "The translation failed: try again.") if failed else None}


@router.post("/cases/{case_id}/authorities/correspondence/{corr_id}/translate", dependencies=_csrf)
def translate_correspondence(corr_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                             db: Session = Depends(get_db)):
    """Translate an inbound e-mail into English, beside the original (app.blocks.translate)."""
    corr = get_case_object(db, Correspondence, corr_id, access)
    if corr.direction != CorrespondenceDirection.IN or not desk.can_view_body(access, corr):
        raise HTTPException(404, "correspondence not found")
    _, reason = tr.translate(db, access.case, corr, actor=access)
    query = f"?translate={reason}" if reason else ""
    return RedirectResponse(f"/cases/{access.case.id}/authorities/correspondence/{corr.id}{query}#translation",
                            status_code=303)


@router.post("/cases/{case_id}/authorities/correspondence/{corr_id}", dependencies=_csrf)
def correspondence_edit(corr_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                        db: Session = Depends(get_db), subject: str = Form(...), body_markdown: str = Form(""),
                        recipients: str = Form(""), cc: str = Form("")):
    access.require("draft_letter")
    corr = get_case_object(db, Correspondence, corr_id, access)
    from app.domain import mail_compose

    busy = mail_compose.letter_in_flight(db, corr) if corr.status == CorrespondenceStatus.DRAFT else None
    if busy is not None:  # the letter's text stays what the e-mail being sent (or sent) carries
        raise HTTPException(409, mail_compose.letter_busy_text(corr, busy))
    if not mail_compose.is_manual() and (chk := mail_compose.open_checklist(db, corr)) is not None:
        # an Outlook checklist may have gone out with this text: changing it would block its Record as sent
        raise HTTPException(409, mail_compose.checklist_text(chk))
    try:
        desk.update_draft(db, corr, subject=subject, body=body_markdown.replace("\r\n", "\n"),
                          recipients=_split(recipients), cc=_split(cc))
    except desk.DeskError as exc:
        raise HTTPException(409, str(exc)) from None
    audit(db, access, UPDATE, access.case, corr, fields=["subject", "body_markdown", "recipients", "cc"],
          stop_order_id=corr.stop_order_id)
    return RedirectResponse(f"/cases/{access.case.id}/authorities/correspondence/{corr.id}", status_code=303)


@router.post("/cases/{case_id}/authorities/correspondence/{corr_id}/sent", dependencies=_csrf)
def correspondence_sent(corr_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                        db: Session = Depends(get_db), sent_at: str = Form(""), channel: str = Form("email"),
                        external_ref: str = Form(""), due_days: str = Form("")):
    access.require("send_letter")
    corr = get_case_object(db, Correspondence, corr_id, access)
    if fb.discarded(corr):  # a duplicate stop-order draft a case admin discarded: never "sent"
        raise HTTPException(409, "this draft was discarded as a duplicate of a request already sent; nothing to send")
    if _replaced(corr):  # the authority page's "replaces draft #N": the newer letter carries the request
        raise HTTPException(409, "a newer letter replaced this draft; nothing to send (send the newer one)")
    if channel not in CorrespondenceChannel._value2member_map_:
        raise HTTPException(400, "unknown channel")
    authority = _authority_of(db, access, corr)
    # a draft the board flags as pointless or a duplicate is never recorded as sent (read now, never from the form)
    if authority is not None and corr.status == CorrespondenceStatus.DRAFT and (
            no := sent_refusal(fb.letter_flag(db, access.case, corr, authority))):
        raise HTTPException(409, no)
    days = _int(due_days, "number of days")
    try:
        desk.mark_sent(db, access.case, corr, actor=access.user, sent_at=_parse_dt(sent_at), channel=channel,
                       external_ref=external_ref, due_days=desk.DEFAULT_RESPONSE_DAYS if days is None else days,
                       authority_key=authority.key if authority else None)
    except desk.DeskError as exc:
        raise HTTPException(409, str(exc)) from None
    audit(db, access, LETTER_SENT, access.case, corr, channel=channel, stop_order_id=corr.stop_order_id,
          kind=corr.kind.value, external_ref_set=bool(external_ref.strip()))
    target = f"/cases/{access.case.id}/authorities/{authority.key}#c{corr.id}" if authority else \
        f"/cases/{access.case.id}/authorities/correspondence/{corr.id}"
    return RedirectResponse(target, status_code=303)


@router.post("/cases/{case_id}/authorities/correspondence/{corr_id}/discard", dependencies=_csrf)
def correspondence_discard(corr_id: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                           db: Session = Depends(get_db)):
    """Discard a draft letter the board flags as pointless (its provider answered LE only / declined, its playbook
    gates us, or a follow-up drafted before their reply: freeze_board.pointless_flag, read now, never from the form): its prepared e-mails cancelled, marked
    discarded, audited. Any other letter: 409."""
    corr = get_case_object(db, Correspondence, corr_id, access)
    authority = _authority_of(db, access, corr)
    flag = fb.pointless_flag(db, access.case, authority, f"c{corr.id}") if authority is not None else None
    if flag is None:
        raise HTTPException(409, "only a draft letter the board flags as pointless (the provider answered LE only or "
                                 "declined, or a follow-up drafted before their reply) can be discarded here")
    try:
        cancelled = fb.discard_letter(db, access.case, corr, access=access, why=flag["why"])
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    for mm in cancelled:
        audit(db, access, "MAIL_CANCELLED", access.case, mm, correspondence_id=mm.correspondence_id,
              reason="pointless_draft_discarded")
    audit(db, access, UPDATE, access.case, corr, status="discarded", reason="pointless_draft", why=flag["why"],
          cancelled_mail=[m.id for m in cancelled])
    return RedirectResponse(f"/cases/{access.case.id}?tab=authorities#freeze", status_code=303)


# --------------------------------------------------------------------------- authority page
def _replaced(corr: Correspondence) -> bool:
    """A draft letter a newer letter replaced (generate_letter's `replace`: `meta.superseded_by_letter`)."""
    return corr.status == CorrespondenceStatus.DRAFT and corr.stop_order_id is None and bool(
        (corr.meta or {}).get("superseded_by_letter"))


_UNREAD = object()


def _gate_options(db: Session, access: CaseAccess, authority, options: list[dict], about: list[str],
                  ref: str | None, want: str = "", *, st=_UNREAD) -> tuple[dict | None, dict | None]:
    """The authority page's template options through the request gate (app.domain.request_gate): a template the gate
    refuses shows the gate's message (what to do instead, and its link) instead of being drafted; a stop order over the
    open draft is offered only as "replaces draft #N" (fb.replace_offer). Returns (the gate's notice for the page:
    {kind, text, href, label}, the replace offer). Unreadable: every provider letter closed (GATE_ERROR). `want`: the
    template the link selects — when the gate allows it (the follow-up a link offers: an information request about a
    new address quoting the request out, `about` / `ref`), the notice says it is that follow-up, never another
    template's refusal above the form that drafts it. `st`: the provider's state as the page read it (an Unavailable
    when it could not be read), else read here."""
    from app.domain import request_gate as rg

    if not access.can("draft_letter") or not rg.is_provider(authority):
        return None, None
    try:
        if st is _UNREAD:
            st = rg.state(db, access.case, authority)
        if isinstance(st, rg.Unavailable):
            raise st
    except rg.Unavailable as err:
        why = f"{str(err)[:1].upper()}{str(err)[1:]}."
        for o in options:
            if o["available"] and o["key"] not in rg.LE_TEMPLATES:
                o.update(available=False, reason=why)
        return {"kind": rg.UNAVAILABLE, "text": why, "href": None, "label": ""}, None
    offer = fb.replace_offer(st)
    notice = None
    for o in options:
        if not o["available"] or o["key"] in rg.LE_TEMPLATES:
            continue
        d = rg.with_step(rg.decide(st, o["key"], about=about if o["key"] == "info_request" else (),
                                   ref=ref if o["key"] == "info_request" else None), st)
        if d.allowed or d.kind == rg.ADD_TO_DRAFT:
            continue
        if o["key"] == "stop_order" and offer is not None:
            o.update(label=f"{o['label']} — replaces draft {offer['no']}",
                     description=f"{offer['text']} {o['description']}")
            continue
        o.update(available=False, reason=d.text, gate=d.kind)
        if notice is None or o["key"] == "stop_order":
            notice = {"kind": d.kind, "text": d.text, "href": d.href, "label": d.label() if d.href else ""}
    if about:  # the link's address: added to the open draft, or a request already asks about it
        d = rg.decide(st, "info_request", about=about, ref=ref)
        if d.kind == rg.ADD_TO_DRAFT:
            notice = {"kind": d.kind, "text": d.text, "href": d.href, "label": d.label()}
        elif not d.allowed:
            notice = {"kind": d.kind, "text": rg.with_step(d, st).text, "href": d.href,
                      "label": d.label() if d.href else ""}
    chosen = next((o for o in options if o["key"] == want and o["available"]), None)
    if chosen is not None and notice is not None and notice["kind"] != rg.ADD_TO_DRAFT and want not in rg.LE_TEMPLATES:
        d = rg.decide(st, want, about=about if want == "info_request" else (),
                      ref=ref if want == "info_request" else None)
        if d.allowed:  # the link's own letter is the follow-up the gate allows: say so, not another template's refusal
            s = st.sent if st is not None else None
            new = f" about {', '.join(rg.short(a) for a in d.about)}" if d.about else ""
            notice = None if s is None else {
                "kind": "follow_up", "href": None, "label": "",
                "text": (f"This is the follow-up to request {s.no} to {authority.name}{new}, quoting it: the one letter "
                         f"to {authority.name} now (one open request per provider: no second request).")}
    return notice, offer


@router.get("/cases/{case_id}/authorities/{key}", response_class=HTMLResponse)
def authority_page(request: Request, key: str, access: CaseAccess = Depends(require_case_role(EXTERNAL)),
                   db: Session = Depends(get_db), direction: str = "", kind: str = "", channel: str = "",
                   status: str = "", order: str = "asc"):
    latest = None if access.is_external else services.latest_run(db, access.case)
    authority = _authority_or_404(db, access, key, run=latest)
    # a stop order to a counterparty the latest run no longer reaches comes from an earlier run
    run = desk.letter_run(db, access.case, authority, latest) if access.can("draft_letter") else latest
    items = desk.timeline(authority, direction=direction or None, kind=kind or None, channel=channel or None,
                          status=status or None, newest_first=order == "desc")
    evidence = {i.anchor: desk.linked_evidence(access.case, i.corr, shared_only=access.is_external, access=access)
                for i in items}
    options = (desk.template_options(authority, run, sender.requester_kind(db, access.case),
                                     er.held_instruments(access.case, er.provider_names(authority))) if not access.is_external else [])
    # the template a deep link names (?template=info_response&ref=o12 from the Recovery plan / Block status) is the
    # one selected, when it applies here; else the page's first available one
    # one open request per provider (app.domain.request_gate): a template it refuses shows what to do instead; a stop
    # order over the open draft is offered as "replaces draft #N" only (the POST confirms it)
    from app.domain import request_gate as rg

    freeze = (request.query_params.get("freeze") or "")[:120] if access.can("draft_letter") else ""
    about = rg.norm_about([freeze, *(request.query_params.get("about") or "")[:600].split(",")]) \
        if access.can("draft_letter") else []
    # the provider's state, read once: the gate's notice and the drafts the board says to discard (pointless,
    # duplicate: never e-mailed, so the timeline offers no e-mail for them and no "awaiting Send" tag)
    st = None
    if (access.can("draft_letter") or access.can("prepare_email")) and rg.is_provider(authority):
        try:
            st = rg.state(db, access.case, authority)
        except rg.Unavailable as err:
            st = err
    gate_notice, offer = _gate_options(db, access, authority, options, about,
                                       (request.query_params.get("ref") or "")[:16] or None,
                                       (request.query_params.get("template") or "")[:40], st=st)
    flags = fb.draft_flags(access.case.id, st) if isinstance(st, rg.State) else []
    replace_draft = ",".join(offer["keys"]) if offer is not None else None
    want = request.query_params.get("template") or ""
    selected = want if any(o["key"] == want and o["available"] for o in options) else None
    return templates.TemplateResponse(request, "authority_detail.html", {
        "case": access.case, "access": access, "authority": authority, "items": items, "evidence": evidence,
        "filters": {"direction": direction, "kind": kind, "channel": channel, "status": status, "order": order},
        "all_count": len(desk.timeline(authority)), "run": run, "latest_run": latest, "now": datetime.now(tz=UTC),
        "mask": desk.contact_mask(access, authority), "order_shared": desk.order_shared, "ev_text": ev.ref_mask(access),
        "complaint_ref": (authority.contact.get("reference") if access.can("view_restricted")
                          else ev.mask_reference(authority.contact.get("reference"))),
        "templates_": options, "selected_template": selected, "replace_draft": replace_draft,
        # a freeze request for a deposit address a reply names (the Recovery plan: ?template=info_request&freeze=…)
        "freeze_address": freeze, "about": ",".join(about),
        # the request gate's message (an open draft, a request already out, LE only) instead of a second letter
        "gate_notice": gate_notice,
        # the guided send's entry page (To do / board / Recovery plan): carried through Generate draft to the editor
        "return_to": mail_flow.safe_return(request.query_params.get("return_to"), access.case.id) or "",
        "refs": desk.sent_references(authority), "frozen": desk.frozen_orders(authority),
        # the provider requests an LE / counsel brief follows up (?template=le_brief&ref=o12 from the Block status page)
        "briefs": desk.brief_candidates(db, access.case) if access.can("draft_letter") and (
            authority.is_le or authority.category == "legal_counsel") else [],
        "brief_ref": (request.query_params.get("ref") or "")[:16],
        # a paragraph the Recovery plan prefills (the wallet a reply names as where the funds went)
        "note": (request.query_params.get("note") or "")[:1500] if access.can("draft_letter") else "",
        "directions": list(CorrespondenceDirection), "kinds": list(CorrespondenceKind),
        "channels": list(CorrespondenceChannel), "classifications": list(Classification),
        "statuses": sorted({s.value for s in CorrespondenceStatus} | set(desk.ALL_STATUSES)),
        "status_choices": desk.STATUS_CHOICES, "kind_labels": desk.KIND_LABELS,
        "direction_labels": desk.DIRECTION_LABELS, "order_state": desk.order_state, "hold_state": desk.hold_state,
        "response_due": desk.response_due, "can_view_body": lambda i: desk.can_view_body(access, i),
        "case_evidence": [] if access.is_external else sorted(ev.visible_items(access), key=lambda e: e.id),
        "default_due_days": desk.DEFAULT_RESPONSE_DAYS,
        "card": None if access.is_external else directory.channels_for(db, access, authority),
        "ch_err": (request.query_params.get("ch_err") or "")[:200] or None,
        "awaiting_mail": _awaiting_by_letter(db, access),
        "draft_flag": lambda i: _item_flag(i, flags),
    })


def _item_flag(i, flags: list[dict]) -> dict | None:
    """The board's pointless / duplicate flag (freeze_board.draft_flags) of a timeline item's draft: its letter's own
    (c<id>), or its draft stop order's (o<id>); None for any other item."""
    if not flags or not i.is_draft:
        return None
    keys = set()
    if i.corr is not None:
        keys.add(f"c{i.corr.id}")
    if i.order is not None and i.order.status == StopOrderStatus.DRAFT:
        keys.add(f"o{i.order.id}")
    return next((f for f in flags if f["key"] in keys), None)


def _awaiting_by_letter(db: Session, access: CaseAccess) -> dict[int, list]:
    """{correspondence id: [prepared, unexpired MailMessage]} for the timeline's "awaiting Send" tag."""
    if not access.can("prepare_email"):
        return {}
    from app.domain.mail_send import awaiting_send

    out: dict[int, list] = {}
    for mm in awaiting_send(db, access.case.id):
        if mm.correspondence_id:
            out.setdefault(mm.correspondence_id, []).append(mm)
    return out


@router.post("/cases/{case_id}/authorities/{key}/log", dependencies=_csrf)
def authority_log(key: str, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                  db: Session = Depends(get_db), direction: str = Form(...), channel: str = Form("email"),
                  kind: str = Form("other"), subject: str = Form(...), body: str = Form(""),
                  body_format: str = Form("text"), occurred_at: str = Form(""), sender: str = Form(""),
                  recipients: str = Form(""), external_ref: str = Form(""), stop_order_id: str = Form(""),
                  in_reply_to_id: str = Form(""), evidence_ids: list[str] = Form([]), due_days: str = Form(""),
                  classification: str = Form("R2"), shared_with_external: str = Form("")):
    access.require("log_correspondence")
    authority = _authority_or_404(db, access, key)
    for value, enum in ((direction, CorrespondenceDirection), (channel, CorrespondenceChannel),
                        (kind, CorrespondenceKind), (classification, Classification)):
        if value not in enum._value2member_map_:
            raise HTTPException(400, f"invalid {enum.__name__}")
    order_id, reply_id = _int(stop_order_id, "stop order"), _int(in_reply_to_id, "message")
    order = get_case_object(db, StopOrder, order_id, access) if order_id else None
    reply_to = get_case_object(db, Correspondence, reply_id, access) if reply_id else None
    share = bool(shared_with_external) and access.can("share_external")
    try:
        corr = desk.log_entry(
            db, access.case, authority, actor=access.user, direction=direction, channel=channel, kind=kind,
            subject=subject, body=body.replace("\r\n", "\n"), body_format=body_format,
            occurred_at=_parse_dt(occurred_at), sender=sender, recipients=_split(recipients),
            external_ref=external_ref, stop_order=order, in_reply_to=reply_to,
            evidence_ids=_visible_evidence_ids(access, evidence_ids),
            due_days=_int(due_days, "number of days") if direction == "out" else None,
            classification=classification, shared_with_external=share)
    except desk.DeskError as exc:
        raise _desk_error(exc) from None
    audit(db, access, CREATE, access.case, corr, direction=direction, kind=kind, channel=channel,
          stop_order_id=corr.stop_order_id, evidence_count=len(corr.meta.get("evidence_ids") or []),
          shared_with_external=share)
    return RedirectResponse(f"/cases/{access.case.id}/authorities/{authority.key}#c{corr.id}", status_code=303)


@router.post("/cases/{case_id}/authorities/{key}/letters", dependencies=_csrf)
def authority_letter(key: str, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                     db: Session = Depends(get_db), template: str = Form(...), ref: str = Form(""),
                     hold_ref: str = Form(""), brief_ref: str = Form(""), extra_note: str = Form(""),
                     freeze_address: str = Form(""), about: str = Form(""), replace_draft: str = Form(""),
                     return_to: str = Form("")):
    """Generate a letter through the request gate (module doc): refused → 409 with what to do instead; a new address for
    a provider with an open draft → added to that draft (audited, 303 to it); unreadable → 503."""
    from app.domain import request_gate as rg

    access.require("draft_letter")
    latest = services.latest_run(db, access.case)
    authority = _authority_or_404(db, access, key, run=latest)
    freeze = (freeze_address.strip() or None) if template == "info_request" else None
    about_l = rg.norm_about([*([freeze] if freeze else []), *about[:600].split(",")])
    the_ref = (hold_ref if template == "release_request" else brief_ref if template in desk.BRIEF_TEMPLATES
               else ref).strip() or None
    # the drafts the form confirmed it replaces (the page's "replaces draft #N" option: a stop order only)
    replace = {x.strip() for x in replace_draft.split(",") if fb.REF_RE.fullmatch(x.strip())} \
        if template == "stop_order" else set()
    run = desk.letter_run(db, access.case, authority, latest)  # an earlier run's candidate when the latest has none
    try:
        st = rg.state(db, access.case, authority)
    except rg.Unavailable as err:  # never drafted blind: it could repeat a request or replace a draft
        raise HTTPException(503, f"{str(err)[:1].upper()}{str(err)[1:]}.") from None
    if replace:  # only the drafts the page offers to replace now count (a stale form, a forged field: none)
        offer = fb.replace_offer(st)
        replace &= set(offer["keys"]) if offer is not None else set()
    d = rg.with_step(rg.decide(st, template, about=about_l, ref=the_ref, replace=replace), st)
    if d.kind == rg.ADD_TO_DRAFT:  # one open request per provider: the new address goes into the open draft
        try:
            obj = rg.add_to_draft(db, access.case, authority, d, actor=access.user)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        audit(db, access, UPDATE, access.case, obj, added_about=d.about, reason="request_gate_add_to_draft",
              request=d.key, template_key=template)
        where = (f"/cases/{access.case.id}/authorities/correspondence/{obj.id}" if isinstance(obj, Correspondence)
                 else f"/cases/{access.case.id}/stop-orders/{obj.id}")
        back = mail_flow.safe_return(return_to, access.case.id)
        q = {"added": ",".join(d.about), **({"return_to": back} if back else {})}
        return RedirectResponse(f"{where}?{urlencode(q)}", status_code=303)
    if not d.allowed:
        offer = fb.replace_offer(st) if template == "stop_order" and d.kind == rg.OPEN_EXISTING else None
        if offer is not None:  # a ready draft is replaced only when the form said so (the option names it)
            raise HTTPException(409, offer["text"] + " Generate it from the authority page (its option says which "
                                                     "draft it replaces) to confirm.")
        raise HTTPException(409, d.text)
    try:
        corr = desk.generate_letter(db, access.case, authority, template, actor=access.user, run=run,
                                    ref=the_ref, extra_note=extra_note, freeze=freeze, about=about_l,
                                    replace=replace)
    except desk.GateRefused as exc:  # the requests changed between the two reads
        raise HTTPException(503 if exc.decision.kind == rg.UNAVAILABLE else 409, str(exc)) from None
    except desk.DeskError as exc:
        raise _desk_error(exc) from None
    if corr.stop_order is not None and template == "stop_order":
        audit(db, access, CREATE, access.case, corr.stop_order, origin="generated", run_id=run.id if run else None,
              template_key=template)
    audit(db, access, CREATE, access.case, corr, template_key=template, kind=corr.kind.value,
          stop_order_id=corr.stop_order_id, run_id=run.id if run else None, about=about_l or None,
          replaced=sorted(replace) or None)
    back = mail_flow.safe_return(return_to, access.case.id)  # the guided send returns to where it started
    return RedirectResponse(f"/cases/{access.case.id}/authorities/correspondence/{corr.id}"
                            + (f"?{urlencode({'return_to': back})}" if back else ""), status_code=303)


# --------------------------------------------------------------------------- stop orders
@router.post("/cases/{case_id}/stop-orders", dependencies=_csrf)
def stop_orders(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
                entity: str = Form(""), redraft: str = Form("")):
    """Draft freeze requests (an LE-only issuer: a notice) for the latest trace's targets no freeze was asked of yet
    (`entity`: one of them; with `redraft`=1, that row's "Redraft from trace #N" replaces its draft from an earlier
    trace). Never a second request to a target already contacted, with a draft or a prepared e-mail, answered LE only /
    court order, declined, frozen or held: those are listed in the flash with the reason (a follow-up is a status
    request; an LE-only target gets the LE brief)."""
    access.require("draft_letter")
    run = services.latest_run(db, access.case)
    if not run:
        raise HTTPException(400, "run a trace first")
    board = _board(db, access, run=run)
    if board is None:  # never draft blind: without the board nobody knows which targets were already asked
        q = urlencode({"tab": "authorities", "so": "1", "so_err": "board"})
        return RedirectResponse(f"/cases/{access.case.id}?{q}", status_code=303)
    names, skipped = fb.generator_plan(board, only=entity.strip() or None,
                                       redraft=redraft == "1" and bool(entity.strip()))
    from app.domain import request_gate as rg

    gated: dict = {}  # candidate name -> the request gate's decision (one open request per provider)
    try:
        created = services.generate_stop_orders(
            db, access.case, run, only=names, actor=access.user, extra=fb.owner_addresses(board, names),
            replace=fb.redraft_keys(board, names) if redraft == "1" else None, refused=gated) if names else []
    except rg.Unavailable:
        q = urlencode({"tab": "authorities", "so": "1", "so_err": "board"})
        return RedirectResponse(f"/cases/{access.case.id}?{q}", status_code=303)
    for order in created:
        audit(db, access, CREATE, access.case, order, origin="generated", run_id=run.id)
    refused, notices = fb.generator_result(board, names, created, gated)
    skipped += refused
    if skipped:
        audit(db, access, "STOP_ORDERS_SKIPPED", access.case, run_id=run.id, skipped=len(skipped),
              reasons=sorted({code for _, code, _ in skipped}))
    q = {"tab": "authorities", "so": "1", "so_n": str(len(created))}
    if skipped:
        q["so_skip"] = fb.skip_param(skipped)
    if notices:
        q["so_notice"] = ",".join(t.key for t in notices)[:600]
    return RedirectResponse(f"/cases/{access.case.id}?{urlencode(q)}#freeze", status_code=303)


@router.post("/cases/{case_id}/stop-orders/{order_id}/discard", dependencies=_csrf)
def stop_order_discard(order_id: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                       db: Session = Depends(get_db)):
    """Discard a draft the board flags as a duplicate of a request already sent (the request it repeats comes from the
    board, never the form): its prepared e-mails cancelled, superseded, audited. Any other order: 409."""
    order = get_case_object(db, StopOrder, order_id, access)
    dup = _duplicate(db, access, order)
    flag = _pointless(db, access, order) if dup is None else None
    if dup is None and flag is None:
        raise HTTPException(409, "only a draft the board flags as a duplicate of a request already sent (or as "
                                 "pointless: the provider answered LE only or declined) can be discarded here; change "
                                 "any other stop order's status on its page")
    reason = "duplicate_draft" if dup is not None else "pointless_draft"
    try:
        cancelled = fb.discard(db, access.case, order, duplicates=dup["of_key"] if dup is not None else None,
                               access=access, reason=reason, why=flag["why"] if flag is not None else None)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    for mm in cancelled:
        audit(db, access, "MAIL_CANCELLED", access.case, mm, correspondence_id=mm.correspondence_id,
              reason=f"{reason}_discarded")
    audit(db, access, UPDATE, access.case, order, status="superseded", reason=reason,
          duplicates=dup["of_key"] if dup is not None else None, cancelled_mail=[m.id for m in cancelled])
    return RedirectResponse(f"/cases/{access.case.id}?tab=authorities#freeze", status_code=303)


@router.get("/cases/{case_id}/stop-orders/{order_id}", response_class=HTMLResponse)
def stop_order_detail(request: Request, order_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                      db: Session = Depends(get_db)):
    order = get_case_object(db, StopOrder, order_id, access)
    state = desk.order_state(order)
    # a draft the board flags as a duplicate of a request already sent: the warning, no e-mail, never "sent"
    dup = _duplicate(db, access, order) if access.can("view_restricted") else None
    pointless = _pointless(db, access, order) if dup is None else None
    # "sent" only for a draft (a superseded one is no request any more: its newer draft carries it)
    # never for a pointless draft either (unless its e-mail may be out: recording it as sent settles it)
    statuses = ["sent", *desk.STATUS_CHOICES] if (access.can("send_letter") and dup is None
                                                  and sent_refusal(pointless) is None
                                                  and order.status == StopOrderStatus.DRAFT) else list(desk.STATUS_CHOICES)
    if order.status == StopOrderStatus.SUPERSEDED:
        statuses = []  # no status form: nothing is recorded on it (record_stop_order_status refuses)
    elif state not in statuses:
        statuses.insert(0, state)
    return templates.TemplateResponse(request, "stop_order.html", {
        "duplicate": dup, "can_discard": (dup is not None or pointless is not None) and access.can("manage_case"),
        "pointless": pointless if access.can("view_restricted") else None,
        "can_export": dup is None and sent_refusal(pointless) is None,  # no letter to send outside Aegis
        # the addresses the request gate just added to this draft (app.domain.request_gate.add_to_draft)
        "added": (request.query_params.get("added") or "")[:200] or None,
        "can_prepare_email": (access.can("prepare_email") and order.status.value == "draft" and order.entity_id
                              is not None and access.can("view_restricted") and dup is None
                              and pointless is None),  # a pointless draft is never e-mailed
        "order": order, "statuses": statuses, "order_state": state, "access": access,
        "mask": desk.contact_mask(access),
        "authority_key": f"entity-{order.entity_id}" if order.entity_id else None,
    })


@router.post("/cases/{case_id}/stop-orders/{order_id}/status", dependencies=_csrf)
def stop_order_status(order_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                      db: Session = Depends(get_db), status: str = Form(...), external_ref: str = Form(""),
                      notes: str = Form(""), amount_held: str = Form(""), asset: str = Form(""),
                      occurred_at: str = Form(""), back: str = Form(""), evidence_ids: list[str] = Form([])):
    access.require("send_letter" if status == "sent" else "log_correspondence")
    order = get_case_object(db, StopOrder, order_id, access)
    if status == "sent" and _duplicate(db, access, order) is not None:
        raise HTTPException(409, "this draft repeats a request already sent to the same counterparty: discard it "
                                 "(a case admin) instead of sending it")
    if status == "sent" and (no := sent_refusal(_pointless(db, access, order))):
        raise HTTPException(409, no)
    key = f"entity-{order.entity_id}" if order.entity_id else None
    try:
        amount = desk.parse_amount(amount_held)
        ev_ids = _visible_evidence_ids(access, evidence_ids)
        corr = desk.record_stop_order_status(
            db, access.case, order, status, actor=access.user, amount_held=amount, asset=asset,
            external_ref=external_ref or None, note=notes or None, occurred_at=_parse_dt(occurred_at),
            authority_key=key, evidence_ids=ev_ids)
    except desk.DeskError as exc:
        raise _desk_error(exc) from None
    audit(db, access, UPDATE, access.case, order, status=status, external_ref_set=bool(external_ref),
          amount_held_set=amount is not None, correspondence_id=corr.id if corr is not None else None)
    if back == "authority" and key:
        return RedirectResponse(f"/cases/{access.case.id}/authorities/{key}#o{order.id}", status_code=303)
    return RedirectResponse(f"/cases/{access.case.id}/stop-orders/{order.id}", status_code=303)


def _visible_evidence_ids(access: CaseAccess, raw: list[str]) -> list[int]:
    """Evidence ids from a form, each one an item this member may see (never the admin-only
    Financial folder for lower roles). Raises DeskError like an unknown id."""
    ids = [_int(e, "evidence item") for e in raw if e.strip()]
    valid = {e.id for e in ev.visible_items(access)}
    if any(i not in valid for i in ids):
        raise desk.DeskError("unknown evidence item")
    return ids


# --------------------------------------------------------------------------- API
def _authority_json(a: desk.Authority, now: datetime, mask: desk.ContactMask | None = None) -> dict:
    due = a.next_due()
    return {
        "key": a.key, "name": a.name, "category": a.category, "type": a.type_label, "contacted": a.contacted,
        "recipient_email": mask.value(a.recipient_email) if mask is not None else a.recipient_email,
        "in_latest_trace": a.in_trace, "trace_label": a.trace_label,
        "last_contact": a.last_contact.isoformat() if a.last_contact else None, "counts": a.counts,
        "open_stop_orders": [{"id": o.id, "status": desk.order_state(o), "kind": o.kind} for o in a.open_orders],
        "response_due": due.isoformat() if due else None, "overdue": bool(due and due < now),
        "freeze_candidate": a.candidate is not None, "non_custodial": a.non_custodial,
    }


@router.get("/api/cases/{case_id}/authorities")
def api_authorities(access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db)):
    now = datetime.now(tz=UTC)
    return [_authority_json(a, now, desk.contact_mask(access, a)) for a in desk.case_authorities(db, access.case)]


@router.get("/api/cases/{case_id}/authorities/{key}/timeline")
def api_timeline(key: str, access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db),
                 direction: str = "", kind: str = "", channel: str = "", status: str = "", order: str = "asc"):
    authority = _authority_or_404(db, access, key)
    mask = desk.contact_mask(access, authority)
    items = desk.timeline(authority, direction=direction or None, kind=kind or None, channel=channel or None,
                          status=status or None, newest_first=order == "desc")
    return {
        "authority": _authority_json(authority, datetime.now(tz=UTC), mask),
        "items": [{
            "anchor": i.anchor, "at": i.at.isoformat() if i.at else None, "direction": i.direction, "kind": i.kind,
            "channel": i.channel, "status": i.status, "subject": mask.text(i.subject),
            "classification": i.classification,
            "correspondence_id": i.corr.id if i.corr else None, "stop_order_id": i.order.id if i.order else None,
            "sender": mask.value(i.corr.sender) if i.corr else None,
            "recipients": mask.values(i.corr.recipients) if i.corr else [],
            "cc": mask.values(i.corr.cc) if i.corr else [],
            "body": mask.text(i.body) if desk.can_view_body(access, i) else None,
            "evidence_ids": [e.id for e in desk.linked_evidence(access.case, i.corr, access=access)],
        } for i in items],
    }


def _export(corr_id: int, fmt: str, access: CaseAccess, db: Session):
    access.require("export")
    corr = get_case_object(db, Correspondence, corr_id, access)
    if not desk.can_view_body(access, corr):
        raise HTTPException(403, "this letter is restricted (R3): it needs the investigator role")
    mask = desk.contact_mask(access, _authority_of(db, access, corr), corr)
    path = desk.export_correspondence(corr, fmt, mask=mask)
    audit(db, access, EXPORT, access.case, corr, format=fmt, contacts_masked=mask.active)
    media = DOCX_MEDIA if fmt == "docx" else "text/markdown; charset=utf-8"
    return FileResponse(path, filename=path.name, media_type=media)


@router.get("/api/cases/{case_id}/authorities/correspondence/{corr_id}/md")
def api_export_md(corr_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                  db: Session = Depends(get_db)):
    return _export(corr_id, "md", access, db)


@router.get("/api/cases/{case_id}/authorities/correspondence/{corr_id}/docx")
def api_export_docx(corr_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                    db: Session = Depends(get_db)):
    return _export(corr_id, "docx", access, db)


@router.post("/api/cases/{case_id}/authorities/check-overdue")
def api_check_overdue(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db)):
    emitted = desk.check_overdue(db, access.case)
    audit(db, access, "CHECK_OVERDUE", access.case, emitted=len(emitted))
    return {"emitted": [{"id": n.id, "title": n.title, "link": n.link} for n in emitted]}
