"""Mail administration and inbound triage (system admins; case review for case admins).

Owner: the mail feature (inbound / transports). Logic: app/mail/*. Templates: admin_mail.html,
admin_mail_sync.html, admin_mail_unassigned.html, admin_mail_message.html, case_mail_review.html. Static: css/mail_admin.css
(linked from the templates' head block). Every page answers `Cache-Control: no-store` and never shows
the client secret, a token, the delta link or a vault path.

System admins
    GET  /admin/mail                              transport, inbound sync, queues, recent outbound (metadata only)
    POST /admin/mail/token-test                   graph: request a token; ok, expires_in, roles     MAIL_TOKEN_TEST
    POST /admin/mail/mailbox-test                 graph: inbox folder; file: folders writable       MAIL_MAILBOX_TEST
    POST /admin/mail/test-send                    fixed non-case message to `to` (≤ N per hour)     MAIL_TEST_SEND
    POST /admin/mail/sync                         read the mailbox now                              MAIL_SYNC
    POST /admin/mail/reset-sync                   confirm=1: forget the delta link, since = now     MAIL_SYNC_RESET
    GET  /admin/mail/mailbox                      mailbox sync: Inbox / Sent Items state, Sent Items to review
    POST /admin/mail/mailbox/sync                 "Sync now" (both folders)                          MAIL_SYNC
    POST /admin/mail/mailbox/backfill             since=YYYY-MM-DD, confirm=1: re-read both folders  MAIL_BACKFILL
    POST /admin/mail/mailbox/sent/{mid}/tie       a Sent Items e-mail for review → its letter (letter=c<id>|o<id>)  MAIL_SENT_FOUND
    POST /admin/mail/mailbox/sent/{mid}/dismiss   it carried no letter: off the review list               MAIL_SENT_FOUND
    GET  /admin/mail/unassigned                   inbound mail no case claimed
    GET  /admin/mail/unassigned/{mid}[?case_id=]  one message (plain text) + assign / ignore forms
    POST /admin/mail/unassigned/{mid}/load        metadata-only row: read the message from the mailbox  MAIL_TRIAGE_OPENED
    POST /admin/mail/unassigned/{mid}/assign      case_id, authority_key, in_reply_to               MAIL_ASSIGNED
    POST /admin/mail/unassigned/{mid}/ignore      reason (≤ 200)                                     MAIL_IGNORED
Case admins
    POST /cases/{id}/mail/sync                    "Check mailbox now" → ?tab=authorities&mail_sync=… (this case's counts)
    GET  /cases/{id}/mail/review                  inbound mail matched to this case but not filed (forged-tag guard)
    POST /cases/{id}/mail/review/{mid}/accept     file it on the suggested / chosen authority     MAIL_REVIEW_ACCEPTED
    POST /cases/{id}/mail/review/{mid}/reject     not ours: back to the unassigned queue           MAIL_REVIEW_REJECTED

Audit details are ids, counts, enum values and the recipient *domain* of a test send only.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.utils import format_datetime, formataddr, make_msgid
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.config import get_settings
from app.core.csrf import require_csrf
from app.core.permissions import ADMIN, CaseAccess, get_case_object, require_case_role
from app.core.security import require_system_admin, require_user
from app.db.models import AuditEvent, Case, User
from app.db.session import get_db
from app.domain.mail_compose import SEND_POLICY
from app.mail import ingest
from app.mail.config import describe, mail_settings
from app.mail.transport import TransportError, check_local_dir, get_transport
from app.web.templating import templates

router = APIRouter(tags=["mail-admin"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]

TEST_SUBJECT = "Aegis test message"
TEST_BODY = "Test message from Aegis (no case data).\n"
_ADDR_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")


def _M():
    from app.db import models as M  # call time: the mail models come from migration 0008

    return M


def _page(request: Request, name: str, ctx: dict, status_code: int = 200) -> HTMLResponse:
    response = templates.TemplateResponse(request, name, ctx, status_code=status_code)
    response.headers["Cache-Control"] = "no-store"
    return response


def valid_test_address(value: str) -> str:
    """The admin test-send recipient: one bare address (no display name, no CR/LF, ASCII, a dotted
    domain, no IP literal). A local copy of the directory's address rules."""
    s = (value or "").strip()
    if not s or len(s) > 254 or not s.isascii() or any(c in s for c in "\r\n\x00<>\"' ,;()[]\\"):
        raise ValueError("enter one plain e-mail address")
    if not _ADDR_RE.fullmatch(s):
        raise ValueError("enter one plain e-mail address")
    local, _, domain = s.rpartition("@")
    if len(local) > 64 or domain.replace(".", "").isdigit():
        raise ValueError("enter one plain e-mail address")
    return f"{local}@{domain.lower()}"


# --------------------------------------------------------------------------- /admin/mail
def _overview(db: Session) -> dict:
    M = _M()
    settings = mail_settings()
    transport = get_transport(settings)
    state = db.get(M.MailSyncState, settings.mail_from) if settings.mail_from else None
    _, inbound_problem = ingest.inbound_transport(settings)
    reviews = ingest.review_counts(db)
    refs = dict(db.execute(select(Case.id, Case.reference).where(Case.id.in_([c for c, _ in reviews]))).all()) \
        if reviews else {}
    recent = db.scalars(select(M.MailMessage).where(M.MailMessage.direction == M.MailDirection.OUT)
                        .order_by(M.MailMessage.id.desc()).limit(20)).all()
    out_refs = dict(db.execute(select(Case.id, Case.reference).where(
        Case.id.in_({m.case_id for m in recent if m.case_id}))).all()) if recent else {}
    return {
        "info": describe(settings), "status": transport.status(),
        "dev_enforced": get_settings().is_local and settings.aegis_mail_transport == "graph"
        and not settings.aegis_mail_live_sending,
        "inbound": {
            "enabled": settings.aegis_mail_inbound, "problem": inbound_problem,
            # the cutover once a sync ran, else the configured backfill start (AEGIS_MAIL_INBOUND_SINCE)
            "since": (state.since if state and state.since else ingest.parse_since(settings.aegis_mail_inbound_since)),
            "last_started_at": state.last_started_at if state else None,
            "last_finished_at": state.last_finished_at if state else None,
            "last_success_at": state.last_success_at if state else None,
            "last_result": (state.last_result or {}) if state else {},
            "last_error": state.last_error if state else None,
            "lease_held": ingest.lease_held(state) if state else False,
            "delta_stored": bool(state and state.delta_link),
        },
        "unassigned": ingest.unassigned_count(db),
        "reviews": [{"case_id": c, "reference": refs.get(c, f"#{c}"), "count": n} for c, n in reviews],
        "recent": [{"id": m.id, "case_id": m.case_id, "reference": out_refs.get(m.case_id),
                    "corr_id": m.correspondence_id, "status": m.status.value, "transport": m.transport,
                    "sent_at": m.sent_at, "size": m.mime_size} for m in recent],
    }


def _render_admin(request: Request, db: Session, *, result: dict | None = None, status_code: int = 200):
    return _page(request, "admin_mail.html", {**_overview(db), "result": result}, status_code)


@router.get("/admin/mail", response_class=HTMLResponse)
def admin_mail(request: Request, me: User = Depends(require_system_admin), db: Session = Depends(get_db)):
    return _render_admin(request, db)


@router.post("/admin/mail/token-test", response_class=HTMLResponse, dependencies=_csrf)
def admin_mail_token_test(request: Request, me: User = Depends(require_system_admin), db: Session = Depends(get_db)):
    transport = get_transport()
    if transport.name != "graph":
        result = {"action": "token", "ok": False, "reason": "invalid",
                  "error": "The token test applies to AEGIS_MAIL_TRANSPORT=graph only."}
    else:
        try:
            info = transport.token_info()
            result = {"action": "token", "ok": True, "expires_in": info.get("expires_in"),
                      "roles": info.get("roles") or []}
        except TransportError as e:
            result = {"action": "token", "ok": False, "reason": e.reason, "error": str(e)}
    audit(db, me, "MAIL_TOKEN_TEST", None, ("mail_transport", None), ok=result["ok"], reason=result.get("reason"),
          transport=transport.name, n_roles=len(result.get("roles") or []))
    return _render_admin(request, db, result=result)


def _dir_check(raw: str, label: str) -> dict:
    try:
        path = check_local_dir(raw, label, forbid_vault=True)
    except TransportError as e:
        return {"label": label, "ok": False, "error": str(e)}
    if not path.is_dir():
        return {"label": label, "ok": False, "error": "does not exist yet (created on first use)"}
    if not os.access(path, os.W_OK):
        return {"label": label, "ok": False, "error": "not writable"}
    return {"label": label, "ok": True, "error": None}


@router.post("/admin/mail/mailbox-test", response_class=HTMLResponse, dependencies=_csrf)
def admin_mail_mailbox_test(request: Request, me: User = Depends(require_system_admin),
                            db: Session = Depends(get_db)):
    settings = mail_settings()
    transport = get_transport(settings)
    result: dict = {"action": "mailbox"}
    if transport.name == "graph":
        try:
            info = transport.mailbox_check()
            result.update(ok=True, total=info.get("total"), unread=info.get("unread"))
        except TransportError as e:
            result.update(ok=False, reason=e.reason, error=str(e))
    elif transport.name == "file":
        checks = [_dir_check(settings.aegis_mail_outbox_dir, "AEGIS_MAIL_OUTBOX_DIR"),
                  _dir_check(settings.aegis_mail_inbox_dir, "AEGIS_MAIL_INBOX_DIR")]
        result.update(ok=all(c["ok"] for c in checks), checks=checks)
    else:
        result.update(ok=False, reason="disabled", error="Sending is disabled (AEGIS_MAIL_TRANSPORT=none)")
    audit(db, me, "MAIL_MAILBOX_TEST", None, ("mail_transport", None), ok=result["ok"], reason=result.get("reason"),
          transport=transport.name)
    return _render_admin(request, db, result=result)


def _test_sends_last_hour(db: Session) -> int:
    since = datetime.now(tz=UTC) - timedelta(hours=1)
    return int(db.scalar(select(func.count(AuditEvent.id)).where(AuditEvent.action == "MAIL_TEST_SEND",
                                                                 AuditEvent.outcome == "allowed",
                                                                 AuditEvent.ts > since)) or 0)


def build_test_message(to: str, settings) -> tuple[bytes, str]:
    """The fixed test message (no case data)."""
    msg = EmailMessage()
    message_id = make_msgid(idstring="aegis-test", domain=settings.mail_domain or "localhost")
    msg["From"] = formataddr((settings.from_name, settings.mail_from))
    msg["To"] = to
    msg["Subject"] = TEST_SUBJECT
    msg["Date"] = format_datetime(datetime.now(tz=UTC))
    msg["Message-ID"] = message_id
    msg.set_content(TEST_BODY)
    return msg.as_bytes(policy=SEND_POLICY), message_id


@router.post("/admin/mail/test-send", response_class=HTMLResponse, dependencies=_csrf)
def admin_mail_test_send(request: Request, to: str = Form(""), me: User = Depends(require_system_admin),
                         db: Session = Depends(get_db)):
    settings = mail_settings()
    transport = get_transport(settings)
    result: dict = {"action": "test_send"}
    domain = None
    status_code = 200
    outcome = "allowed"
    try:
        addr = valid_test_address(to)
        domain = addr.rpartition("@")[2]
    except ValueError as e:
        result.update(ok=False, reason="invalid", error=str(e))
        status_code, outcome = 400, "denied"
    else:
        if _test_sends_last_hour(db) >= settings.aegis_mail_test_sends_per_hour:
            result.update(ok=False, reason="rate_limited",
                          error=f"At most {settings.aegis_mail_test_sends_per_hour} test messages per hour.")
            status_code, outcome = 429, "denied"
        elif get_settings().is_local and transport.name == "graph" and not settings.aegis_mail_live_sending and not any(
                domain == d or domain.endswith("." + d) for d in settings.dev_allowed_domains):
            result.update(ok=False, reason="dev_domain", error="APP_ENV=local: test messages through Graph go "
                                                               "only to AEGIS_MAIL_DEV_ALLOWED_DOMAINS.")
            status_code, outcome = 400, "denied"
        elif not transport.status().configured:
            result.update(ok=False, reason="not_configured", error=transport.status().reason)
            outcome = "denied"
        else:
            raw, message_id = build_test_message(addr, settings)
            try:
                res = transport.send_mime(raw, message_id=message_id)
                result.update(ok=True, transport=res.transport)
            except TransportError as e:
                result.update(ok=False, reason=e.reason, error=str(e))
    audit(db, me, "MAIL_TEST_SEND", None, ("mail_transport", None), outcome=outcome, ok=result["ok"],
          reason=result.get("reason"), transport=transport.name, recipient_domain=domain)
    return _render_admin(request, db, result=result, status_code=status_code)


SYNC_TEXT = {
    "busy": "Another mailbox sync is running; try again in a few minutes.",
    "too_soon": "The mailbox was checked less than a minute ago; try again shortly.",
}


def _run_sync(db: Session, actor: User, trigger: str):
    """(report or None, problem text or None)."""
    settings = mail_settings()
    if not settings.aegis_mail_inbound:
        return None, "Inbound mail is off (AEGIS_MAIL_INBOUND)."
    report = ingest.sync_mailbox(db, trigger=trigger, actor=actor, settings=settings)
    if report.disabled:
        return report, report.disabled
    if report.busy:
        return report, SYNC_TEXT["busy"]
    if report.too_soon:
        return report, SYNC_TEXT["too_soon"]
    return report, None


@router.post("/admin/mail/sync", response_class=HTMLResponse, dependencies=_csrf)
def admin_mail_sync(request: Request, me: User = Depends(require_system_admin), db: Session = Depends(get_db)):
    report, problem = _run_sync(db, me, "admin")
    counts = report.counts() if report else {}
    result = {"action": "sync", "ok": problem is None and report is not None and not report.error,
              "error": problem or (report.error if report else None), "counts": counts or None}
    audit(db, me, "MAIL_SYNC", None, ("mail_sync_state", None), ok=result["ok"], trigger="admin",
          busy=bool(report and report.busy), too_soon=bool(report and report.too_soon), **counts)
    return _render_admin(request, db, result=result, status_code=429 if report is not None and report.too_soon else 200)


@router.post("/admin/mail/reset-sync", response_class=HTMLResponse, dependencies=_csrf)
def admin_mail_reset_sync(request: Request, confirm: str = Form(""), me: User = Depends(require_system_admin),
                          db: Session = Depends(get_db)):
    settings = mail_settings()
    if confirm != "1":
        return _render_admin(request, db, status_code=400, result={
            "action": "reset", "ok": False, "error": "Tick the confirmation to reset the inbound sync."})
    if not settings.mail_from:
        return _render_admin(request, db, status_code=400, result={
            "action": "reset", "ok": False, "error": "AEGIS_MAIL_FROM is not set."})
    state = ingest.get_state(db, settings.mail_from, settings.aegis_mail_transport)
    had_delta = bool(state.delta_link)
    state.delta_link = None
    state.since = datetime.now(tz=UTC)
    db.commit()
    audit(db, me, "MAIL_SYNC_RESET", None, ("mail_sync_state", None), had_delta=had_delta)
    return _render_admin(request, db, result={"action": "reset", "ok": True})


# --------------------------------------------------------------------------- mailbox sync (Inbox + Sent Items)
FOLDER_LABELS = {"inbox": "Inbox", "sentitems": "Sent Items"}
MIN_BACKFILL = datetime(2020, 1, 1, tzinfo=UTC)


def _domains(addrs) -> list[str]:
    return sorted({str(a).rpartition("@")[2].lower() for a in addrs or [] if "@" in str(a)})[:5]


def _mailbox_overview(db: Session) -> dict:
    from app.mail import sync_outbound

    M = _M()
    settings = mail_settings()
    state = db.get(M.MailSyncState, settings.mail_from) if settings.mail_from else None
    _, problem = ingest.inbound_transport(settings)
    states = ingest.folder_states(db, settings.mail_from)
    folders = []
    for f in ingest.FOLDERS:
        fs = states.get(f)
        folders.append({"key": f, "label": FOLDER_LABELS[f], "since": fs.since if fs else None,
                        "delta_stored": bool(fs and fs.delta_link), "last_started_at": fs.last_started_at if fs else None,
                        "last_finished_at": fs.last_finished_at if fs else None,
                        "last_success_at": fs.last_success_at if fs else None,
                        "last_result": (fs.last_result or {}) if fs else {}, "last_error": fs.last_error if fs else None,
                        "backfill_requested_at": fs.backfill_requested_at if fs else None})
    review = sync_outbound.needs_review(db, limit=50)
    refs = dict(db.execute(select(Case.id, Case.reference).where(
        Case.id.in_({m.case_id for m in review if m.case_id}))).all()) if review else {}
    triage = int(db.scalar(select(func.count(M.MailMessage.id)).where(
        M.MailMessage.direction == M.MailDirection.IN, M.MailMessage.status == M.MailStatus.UNASSIGNED,
        M.MailMessage.match_method == "triage")) or 0)
    found = int(db.scalar(select(func.count(M.MailMessage.id)).where(
        M.MailMessage.direction == M.MailDirection.OUT, M.MailMessage.outside_sent.is_(True))) or 0)
    default_since = ingest.parse_since(settings.aegis_mail_inbound_since)
    return {
        "info": describe(settings), "settings_problem": problem, "inbound_enabled": settings.aegis_mail_inbound,
        "graph": settings.aegis_mail_transport == "graph", "folders": folders,
        "lease_held": ingest.lease_held(state) if state else False,
        "last_result": (state.last_result or {}) if state else {}, "last_error": state.last_error if state else None,
        "sync_minutes": _sync_minutes(), "triage": triage, "found": found,
        "review": [{"id": m.id, "case_id": m.case_id, "reference": refs.get(m.case_id), "corr_id": m.correspondence_id,
                    "sent_at": m.sent_at, "domains": _domains([*(m.to_addrs or []), *(m.cc_addrs or [])])
                    or [str(d) for d in (m.meta or {}).get("recipient_domains") or []][:5],
                    "reason": (m.meta or {}).get("review_reason"), "metadata_only": bool((m.meta or {}).get("metadata_only")),
                    "evidence_id": m.eml_evidence_id,
                    "letters": [(x.id, _letter_label(x)) for x in sync_outbound.tie_candidates(db, m)[:20]]}
                   for m in review],
        "default_since": (default_since or (state.since if state and state.since else None)),
    }


def _letter_label(x) -> str:
    """A tie candidate as listed: "stop order #7 (draft)" / "letter #12 (sent)" — ids and state, never a subject."""
    what = f"stop order #{x.order.id}" if x.order is not None else f"letter #{x.corr.id}"
    return f"{what} ({'draft' if x.is_draft else 'sent'})"


def _sync_minutes() -> int:
    try:
        return max(1, int(os.environ.get("AEGIS_MAIL_SYNC_MINUTES") or 15))
    except ValueError:
        return 15


def _render_mailbox(request: Request, db: Session, *, result: dict | None = None, status_code: int = 200):
    return _page(request, "admin_mail_sync.html", {**_mailbox_overview(db), "result": result}, status_code)


@router.get("/admin/mail/mailbox", response_class=HTMLResponse)
def admin_mail_mailbox(request: Request, me: User = Depends(require_system_admin), db: Session = Depends(get_db)):
    return _render_mailbox(request, db)


def _sync_result(report, problem) -> dict:
    counts = report.counts() if report else {}
    return {"action": "sync", "ok": problem is None and report is not None and not report.error,
            "error": problem or (report.error if report else None), "counts": counts or None}


@router.post("/admin/mail/mailbox/sync", response_class=HTMLResponse, dependencies=_csrf)
def admin_mail_mailbox_sync(request: Request, me: User = Depends(require_system_admin), db: Session = Depends(get_db)):
    report, problem = _run_sync(db, me, "admin")
    result = _sync_result(report, problem)
    audit(db, me, "MAIL_SYNC", None, ("mail_sync_state", None), ok=result["ok"], trigger="admin",
          busy=bool(report and report.busy), too_soon=bool(report and report.too_soon), **(result["counts"] or {}))
    return _render_mailbox(request, db, result=result,
                           status_code=429 if report is not None and report.too_soon else 200)


@router.post("/admin/mail/mailbox/backfill", response_class=HTMLResponse, dependencies=_csrf)
def admin_mail_mailbox_backfill(request: Request, since: str = Form(""), confirm: str = Form(""),
                                me: User = Depends(require_system_admin), db: Session = Depends(get_db)):
    settings = mail_settings()
    try:
        day = datetime.strptime((since or "").strip(), "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        day = None
    error = None
    if confirm != "1":
        error = "Tick the confirmation to re-read the mailbox from that date."
    elif day is None:
        error = "Give the start date as YYYY-MM-DD."
    elif day < MIN_BACKFILL or day > datetime.now(tz=UTC):
        error = "The start date must be after 2020-01-01 and not in the future."
    elif not settings.mail_from:
        error = "AEGIS_MAIL_FROM is not set."
    elif not settings.aegis_mail_inbound:
        error = "Inbound mail is off (AEGIS_MAIL_INBOUND)."
    if error:
        return _render_mailbox(request, db, status_code=400, result={"action": "backfill", "ok": False, "error": error})
    state = ingest.get_state(db, settings.mail_from, settings.aegis_mail_transport)
    if ingest.lease_held(state):
        return _render_mailbox(request, db, status_code=409, result={
            "action": "backfill", "ok": False, "error": SYNC_TEXT["busy"]})
    ingest.request_backfill(db, settings.mail_from, day, me)
    report, problem = _run_sync(db, me, "backfill")
    result = {**_sync_result(report, problem), "action": "backfill", "since": day}
    audit(db, me, "MAIL_BACKFILL", None, ("mail_sync_state", None), ok=result["ok"], since=day.date().isoformat(),
          **(result["counts"] or {}))
    return _render_mailbox(request, db, result=result)


@router.post("/admin/mail/mailbox/sent/{mid}/{action}", dependencies=_csrf)
def admin_mail_mailbox_review(mid: int, action: str, letter: str = Form(""), me: User = Depends(require_system_admin),
                              db: Session = Depends(get_db)):
    """A Sent Items e-mail logged for review: "dismiss" (it carried no letter) or "tie" it to `letter` (c<id> /
    o<id>): a draft is recorded as sent at the e-mail's date, a sent letter linked (app.mail.sync_outbound)."""
    from app.mail import sync_outbound

    if action not in ("tie", "dismiss"):
        raise HTTPException(404, "unknown action")
    try:
        mm = sync_outbound.review_row(db, mid)
        if action == "dismiss":
            sync_outbound.dismiss(db, mm, actor=me)
        else:
            sync_outbound.tie_to_letter(db, mm, letter, actor=me)
    except sync_outbound.ReviewError as exc:
        db.rollback()
        raise HTTPException(exc.status, exc.message) from None
    return RedirectResponse(f"/admin/mail/mailbox?reviewed={action}#mail-sent-review", status_code=303)


# --------------------------------------------------------------------------- unassigned queue
@router.get("/admin/mail/unassigned", response_class=HTMLResponse)
def admin_mail_unassigned(request: Request, show: str = "open", me: User = Depends(require_system_admin),
                          db: Session = Depends(get_db)):
    M = _M()
    q = select(M.MailMessage).where(M.MailMessage.direction == M.MailDirection.IN, M.MailMessage.case_id.is_(None))
    if show != "all":
        q = q.where(M.MailMessage.status == M.MailStatus.UNASSIGNED)
    rows = db.scalars(q.order_by(M.MailMessage.id.desc()).limit(200)).all()
    return _page(request, "admin_mail_unassigned.html", {"rows": rows, "show": "all" if show == "all" else "open"})


def _unassigned_or_404(db: Session, mid: int):
    """An inbound message the system-admin queue may act on: unassigned (no case), or waiting for
    review on a case (system admins see every case)."""
    mm = ingest.get_inbound(db, mid)
    if mm is None or (mm.case_id is not None and mm.status.value != "needs_review"):
        raise HTTPException(404, "message not found")
    return mm


def _assign_context(db: Session, mm, case_id: int | None) -> dict:
    from app.domain import correspondence as desk

    M = _M()
    cases = db.execute(select(Case.id, Case.reference).order_by(Case.id.desc())).all()
    chosen = db.get(Case, case_id) if case_id else (db.get(Case, mm.case_id) if mm.case_id else None)
    authorities, letters = [], []
    if chosen is not None:
        for a in desk.case_authorities(db, chosen, include_prospects=False):
            authorities.append({"key": a.key, "name": a.name, "type": a.type_label})
            for c in a.correspondence:
                if c.direction == M.CorrespondenceDirection.OUT and c.status == M.CorrespondenceStatus.SENT:
                    letters.append({"id": c.id, "authority_key": a.key, "authority": a.name,
                                    "subject": (c.subject or "")[:120], "occurred_at": c.occurred_at})
    suggestion = None
    match = mm.match or {}
    if match.get("case_id"):
        ref = db.scalar(select(Case.reference).where(Case.id == match["case_id"]))
        suggestion = {"case_id": match["case_id"], "reference": ref,
                      "correspondence_id": match.get("correspondence_id")}
    return {"cases": cases, "chosen": chosen, "authorities": authorities, "letters": letters,
            "suggestion": suggestion}


def _filed_at(db: Session, mm) -> dict | None:
    """Where an inbound e-mail was filed (case, timeline entry), for a message no longer in the queue."""
    if mm.case_id is None or mm.correspondence_id is None:
        return None
    case = db.get(Case, mm.case_id)
    if case is None:
        return None
    return {"case_id": case.id, "reference": case.reference, "correspondence_id": mm.correspondence_id,
            "url": f"/cases/{case.id}/authorities/correspondence/{mm.correspondence_id}",
            "evidence_url": f"/cases/{case.id}/evidence/{mm.eml_evidence_id}" if mm.eml_evidence_id else None}


def _message_page(request: Request, db: Session, mm, *, case_id: int | None = None, error: str | None = None,
                  status_code: int = 200):
    return _page(request, "admin_mail_message.html",
                 {"mm": mm, "error": error, "filed": _filed_at(db, mm), **_assign_context(db, mm, case_id)},
                 status_code)


@router.get("/admin/mail/unassigned/{mid}", response_class=HTMLResponse)
def admin_mail_message(mid: int, request: Request, case_id: int | None = None,
                       me: User = Depends(require_system_admin), db: Session = Depends(get_db)):
    """The triage page; for a message already filed on a case, a page saying where (no forms)."""
    mm = ingest.get_inbound(db, mid)
    if mm is None:
        raise HTTPException(404, "message not found")
    if mm.case_id is not None and mm.status.value != "needs_review":
        return _message_page(request, db, mm)
    return _message_page(request, db, mm, case_id=case_id)


@router.post("/admin/mail/unassigned/{mid}/load", dependencies=_csrf)
def admin_mail_load(mid: int, request: Request, me: User = Depends(require_system_admin), db: Session = Depends(get_db)):
    """A metadata-only triage row (from an authority's domain, nothing cited): read the message from the
    mailbox now, so the admin can read it and assign or ignore it."""
    mm = _unassigned_or_404(db, mid)
    if not ingest.is_metadata_only(mm):
        return RedirectResponse(f"/admin/mail/unassigned/{mid}", status_code=303)
    try:
        ingest.load_metadata_only(db, mm, actor=me)
    except ingest.IngestError as e:
        db.rollback()
        return _message_page(request, db, _unassigned_or_404(db, mid), error=str(e), status_code=502)
    return RedirectResponse(f"/admin/mail/unassigned/{mid}", status_code=303)  # load_metadata_only audits


@router.post("/admin/mail/unassigned/{mid}/assign", dependencies=_csrf)
def admin_mail_assign(mid: int, request: Request, case_id: int = Form(0), authority_key: str = Form(""),
                      in_reply_to: str = Form(""), me: User = Depends(require_system_admin),
                      db: Session = Depends(get_db)):
    mm = _unassigned_or_404(db, mid)
    case = db.get(Case, case_id) if case_id else None
    if case is None:
        return _message_page(request, db, mm, error="Choose a case.", status_code=400)
    try:
        corr = ingest.assign(db, mm, case, authority_key=authority_key, in_reply_to_id=in_reply_to or None, actor=me)
    except ingest.IngestError as e:
        db.rollback()
        return _message_page(request, db, _unassigned_or_404(db, mid), case_id=case.id, error=str(e),
                             status_code=400)
    audit(db, me, "MAIL_ASSIGNED", case, ("mail_messages", mm.id), mail_message_id=mm.id, correspondence_id=corr.id,
          in_reply_to_id=corr.in_reply_to_id, eml_evidence_id=mm.eml_evidence_id)
    return RedirectResponse(f"/cases/{case.id}/authorities/correspondence/{corr.id}", status_code=303)


@router.post("/admin/mail/unassigned/{mid}/ignore", dependencies=_csrf)
def admin_mail_ignore(mid: int, request: Request, reason: str = Form(""), me: User = Depends(require_system_admin),
                      db: Session = Depends(get_db)):
    mm = _unassigned_or_404(db, mid)
    if len(reason) > 200:
        return _message_page(request, db, mm, error="The reason is limited to 200 characters.", status_code=400)
    try:
        ingest.ignore(db, mm, reason, me)
    except ingest.IngestError as e:
        return _message_page(request, db, mm, error=str(e), status_code=400)
    audit(db, me, "MAIL_IGNORED", None, ("mail_messages", mm.id), mail_message_id=mm.id,
          reason_given=bool(reason.strip()))
    return RedirectResponse("/admin/mail/unassigned", status_code=303)


# --------------------------------------------------------------------------- case admins
@router.post("/cases/{case_id}/mail/sync", dependencies=_csrf)
def case_mail_sync(case_id: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                   db: Session = Depends(get_db)):
    report, problem = _run_sync(db, access.user, "case_admin")
    mine = (report.per_case.get(access.case.id) if report else None) or {"received": 0, "needs_review": 0}
    if report is not None and report.too_soon:
        flag = "too_soon"
    elif report is not None and report.busy:
        flag = "busy"
    elif problem:
        flag = "off"
    elif report is not None and report.error:
        flag = "error"
    else:
        flag = "ok"
    audit(db, access, "MAIL_SYNC", access.case, ("mail_sync_state", None), ok=flag == "ok", trigger="case_admin",
          result=flag, received=mine.get("received", 0), needs_review=mine.get("needs_review", 0))
    q = urlencode({"tab": "authorities", "mail_sync": flag, "mail_received": mine.get("received", 0),
                   "mail_review": mine.get("needs_review", 0)})
    return RedirectResponse(f"/cases/{access.case.id}?{q}", status_code=303)


def _review_page(request: Request, db: Session, access: CaseAccess, *, error: str | None = None,
                 error_id: int | None = None, status_code: int = 200):
    from app.domain import correspondence as desk

    M = _M()
    rows = db.scalars(select(M.MailMessage).where(
        M.MailMessage.direction == M.MailDirection.IN, M.MailMessage.case_id == access.case.id,
        M.MailMessage.status == M.MailStatus.NEEDS_REVIEW).order_by(M.MailMessage.id.desc())).all()
    authorities = desk.case_authorities(db, access.case, include_prospects=False)
    letters = [{"id": c.id, "authority_key": a.key, "authority": a.name, "subject": (c.subject or "")[:120],
                "occurred_at": c.occurred_at, "preselect": not _unanchored_outlook(c)}
               for a in authorities for c in a.correspondence
               if c.direction == M.CorrespondenceDirection.OUT and c.status == M.CorrespondenceStatus.SENT]
    suggestions = {}
    for mm in rows:
        corr_id = (mm.match or {}).get("correspondence_id")
        corr = db.get(M.Correspondence, corr_id) if corr_id else None
        if corr is not None and corr.case_id == access.case.id:
            # never preselect an Outlook e-mail under review that matches no letter (it answers for none yet)
            suggestions[mm.id] = {"correspondence_id": None if _unanchored_outlook(corr) else corr.id,
                                  "authority_key": ingest.authority_key_for(corr)}
        elif mm.authority_key and any(a.key == mm.authority_key for a in authorities):
            # the mailbox sync tied it to an authority (its sender's domain) but to no letter: suggest that
            # authority and its sent letter whose subject the reply's subject resembles most
            suggestions[mm.id] = {"correspondence_id": _closest_letter(mm.subject, [
                lt for lt in letters if lt["authority_key"] == mm.authority_key and lt["preselect"]]),
                "authority_key": mm.authority_key}
    ctx = {"case": access.case, "access": access, "rows": rows, "suggestions": suggestions,
           "authorities": [{"key": a.key, "name": a.name, "type": a.type_label} for a in authorities],
           "letters": letters, "error": error, "error_id": error_id}
    return _page(request, "case_mail_review.html", ctx, status_code)


def _unanchored_outlook(c) -> bool:
    """A Sent Items entry logged for review (app.mail.sync_outbound) with no candidate letter: an e-mail sent from
    Outlook that is not known to carry any letter, so a reply is never preselected as answering it."""
    from app.mail import matching

    return matching.under_review_entry(c) and not (c.meta or {}).get("candidates")


def _closest_letter(subject: str | None, letters: list[dict]) -> int | None:
    """The id of the letter whose subject the reply's subject (Re: / Fw: removed) resembles most (ratio ≥ 0.6)."""
    from difflib import SequenceMatcher

    from app.mail import matching

    norm = matching.normalise_subject(subject or "")
    if not norm or not letters:
        return None
    ratio, best = max(((SequenceMatcher(None, norm, matching.normalise_subject(lt["subject"])).ratio(), lt["id"])
                       for lt in letters), default=(0.0, None))
    return best if ratio >= 0.6 else None


@router.get("/cases/{case_id}/mail/review", response_class=HTMLResponse)
def case_mail_review(case_id: int, request: Request, access: CaseAccess = Depends(require_case_role(ADMIN)),
                     db: Session = Depends(get_db)):
    return _review_page(request, db, access)


def _review_item(db: Session, mid: int, access: CaseAccess):
    M = _M()
    mm = get_case_object(db, M.MailMessage, mid, access)
    if mm.direction != M.MailDirection.IN or mm.status != M.MailStatus.NEEDS_REVIEW:
        raise HTTPException(404, "message not found")
    return mm


@router.post("/cases/{case_id}/mail/review/{mid}/accept", dependencies=_csrf)
def case_mail_review_accept(case_id: int, mid: int, request: Request, authority_key: str = Form(""),
                            in_reply_to: str = Form(""), access: CaseAccess = Depends(require_case_role(ADMIN)),
                            db: Session = Depends(get_db)):
    mm = _review_item(db, mid, access)
    try:
        corr = ingest.accept_review(db, mm, access.case, authority_key=authority_key or None,
                                    in_reply_to_id=in_reply_to or None, actor=access.user)
    except ingest.IngestError as e:
        db.rollback()
        return _review_page(request, db, access, error=str(e), error_id=mid, status_code=400)
    audit(db, access, "MAIL_REVIEW_ACCEPTED", access.case, ("mail_messages", mm.id), mail_message_id=mm.id,
          correspondence_id=corr.id, in_reply_to_id=corr.in_reply_to_id, eml_evidence_id=mm.eml_evidence_id)
    return RedirectResponse(f"/cases/{access.case.id}/authorities/correspondence/{corr.id}", status_code=303)


@router.post("/cases/{case_id}/mail/review/{mid}/reject", dependencies=_csrf)
def case_mail_review_reject(case_id: int, mid: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                            db: Session = Depends(get_db)):
    mm = _review_item(db, mid, access)
    ingest.reject_review(db, mm, access.case, access.user)
    audit(db, access, "MAIL_REVIEW_REJECTED", access.case, ("mail_messages", mid), mail_message_id=mid)
    return RedirectResponse(f"/cases/{access.case.id}/mail/review", status_code=303)
