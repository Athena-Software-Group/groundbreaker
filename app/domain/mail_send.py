"""Send a prepared e-mail, file it as evidence, reconcile uncertain sends (the e-mail desk, step 2).

Owner: the mail feature (web layer: app/web/routes_mail.py). Case admins only (`send_email`), and
only through the web form (session cookie + CSRF): there is no API endpoint that sends, and nothing
under app/ai/ may import this module or app.mail (tests/test_mail_no_ai_send.py).

    outcome = send(db, access, mm, form)    # SendOutcome(mm, "sent" | "failed" | "unknown" | "already")
    finalize(db, mm, actor, due_days)       # .eml evidence, correspondence sent, reply clock (idempotent)
    reconcile(db, mm)                       # after an uncertain send: ask the transport what happened

**One e-mail per letter.** A letter (`MailMessage.letter_key`: the stop order for a stop order's
letter, else the correspondence row) goes out at most once: while any of its e-mails is `sending`,
`sent` or `unknown`, prepare (app.domain.mail_compose) and Send are refused, and the partial unique
index `uq_mail_messages_letter_in_flight` makes the claim of a second row fail at the database even
when two Sends of two previews race. After an `unknown` outcome the only way forward is
**reconcile**: the transport is asked (Graph: the draft's isDraft, else Sent Items by
internetMessageId; file: the outbox) and the row becomes `sent` (filed) or, once MISSING_GRACE has
passed with the message missing or still an unsent draft, `failed` (the letter can then be prepared
again). An unsent Graph draft is first **deleted** (`transport.delete_drafts`: the immutable id and
every draft with the Message-ID); when that fails the row stays `unknown` (`error_reason`
draft_not_deleted, the preview tells the admin) so the letter is never prepared again while a
draft of it may still be in the mailbox. There is no manual retry of an uncertain send.

**Sender of record.** When `mail_compose.sender_check` reports a mismatch (`needs_ack`: a body signed for another
sender, a From name that differs from the profile), Send needs the case admin's explicit acknowledgement (one tick,
`ack_sender=1`; an optional note, `ack_sender_reason`), recorded in `meta.sender_ack` and the history. A case without
a sender profile is an information note only: nothing to acknowledge.

Send, in order (D2, D7):

1. **Preconditions** (SendError → 400 / 409 / 429): transport configured, mailbox set, vault set,
   the row belongs to the case and is outbound; a row that is no longer `prepared` is returned as
   it is (a double click or a second tab never sends twice); a demo / training case's e-mail names only
   reserved demo addresses (`mail_compose.demo_lock_problem`, also when a send outside Aegis is recorded);
   the letter has no open old "Draft — you send"
   checklist (`mail_compose.open_checklist`: it may have gone out from Outlook; this is the one choke point for
   every Send, the preview's and the compose page's confirmation alike, and a checklist itself is never
   transmitted); the preview has not expired; the
   one-time prepare token matches; the confirmation boxes equal exactly what the preview asked for
   (every recipient whose address is unverified or typed in, every evidence attachment); the draft
   is unchanged since the preview; the attached evidence still has the same sha256 and is not newly
   TLP-blocked; the per-case and global hourly limits are not exceeded; no other e-mail of the
   same letter is sending / sent / unknown; the sender of record matches (or the case admin
   ticked the acknowledgement of the mismatch).
2. **Atomic claim:** `UPDATE … SET status='sending' WHERE id=:id AND status='prepared'`; only the
   request that wins the update sends, and the partial unique index on `letter_key` refuses the
   claim when another row of the letter is already sending / sent / unknown.
3. The pending bytes are re-hashed against the prepared sha256, then handed to the transport.
4. A transport error with an unknown outcome leaves the row `unknown` (only reconcile moves it on;
   never resend manually); any other error leaves it `failed` and the letter
   a draft. On success the row is committed as `sent` at once (a sent message is never marked
   failed afterwards), then `finalize` files the exact bytes as an R3 .eml evidence item, marks the
   letter sent through the desk (stop order SENT, reply clock, correspondence_out /
   stop_order_status events) and stamps the directory. The letter's other `prepared` previews are
   cancelled ("superseded"), so none of them can be sent later. A failing finalize keeps the row `sent`
   with `meta.finalize_error`; the preview offers **Retry filing**. Whenever a finalize files the e-mail (the
   send itself, reconcile, Retry filing, the scheduler), the Block status refresh follows (rules only:
   `refresh_status`). Bcc addresses (`meta.bcc`, never in the MIME) are
   handed to the transport with the bytes (`send_mime(raw, message_id=…, bcc=[…])`).

**Sent outside Aegis (manual mode, `record_external`).** In "Draft — you send" mode nothing is
transmitted here: a person sends the prepared draft from the investigations mailbox, then a case
admin records it (web form only, CSRF, an explicit confirmation): the actual date and time, the To /
Cc actually used (prefilled from the preview), and optionally the sent message itself (.eml or .msg),
stored in the vault as an R3 evidence item with its sha256. The row becomes `sent_external`
(one e-mail per letter: `mail_compose.LETTER_BUSY` includes it, so the letter is never prepared or
sent again; a follow-up letter is the way to write again), the letter and its stop order are marked
sent through the desk (`sent_via` "email (sent outside Aegis)", reply clock, correspondence_out /
stop_order_status), the checklist's Bcc addresses kept on the letter (`meta.bcc`, as `finalize` does), the
other previews of the letter are cancelled and the directory stamped. The
claim is the same conditional UPDATE as Send (prepared / expired → sent_external), in the same
transaction as the evidence row.

The transport and settings are reached only through the two seams `_transport()` / `_settings()`
(app.mail is imported lazily, so tests swap in fakes). Nothing here audits; routes do.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from io import BytesIO

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import (
    Case,
    Correspondence,
    CorrespondenceChannel,
    CorrespondenceStatus,
    EvidenceItem,
    MailDirection,
    MailMessage,
    MailStatus,
    User,
)
from app.domain import correspondence as desk
from app.domain import directory
from app.domain import evidence as ev
from app.domain import mail_compose as compose

MISSING_GRACE = timedelta(minutes=15)  # reconcile: missing / still a draft this long after the attempt = failed
ACK_REASON_MAX = 300  # the sender-mismatch acknowledgement's optional note
STUCK_SENDING = timedelta(minutes=10)  # a 'sending' row this old (the process died) is treated as unknown
UNKNOWN_TEXT = ("Aegis could not confirm the send. Only a check of the mailbox (Check the mailbox now, also run "
                "by the scheduler) can mark it sent or failed; do not resend manually, and nothing else is sent "
                "for this letter until then.")


def _transport():
    from app.mail.transport import get_transport

    return get_transport()


def _settings():
    from app.mail.config import mail_settings

    return mail_settings()


class SendError(desk.DeskError):
    """A send that is refused before anything was transmitted (HTTP `status`)."""

    def __init__(self, message: str, status: int = 400, reason: str = "invalid"):
        super().__init__(message)
        self.status = status
        self.reason = reason


@dataclass
class SendOutcome:
    mm: MailMessage
    outcome: str  # sent | failed | unknown | already
    message: str = ""


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _aware(v: datetime | None) -> datetime | None:
    return v.replace(tzinfo=UTC) if v is not None and v.tzinfo is None else v


def _history(mm: MailMessage, status: str, by: int | None = None, **extra) -> None:
    meta = dict(mm.meta or {})
    meta["history"] = list(meta.get("history") or []) + [
        {"status": status, "at": _now().isoformat(), "by": by, **{k: v for k, v in extra.items() if v is not None}}]
    mm.meta = meta


def _set_meta(mm: MailMessage, **values) -> None:
    meta = dict(mm.meta or {})
    for k, v in values.items():
        if v is None:
            meta.pop(k, None)
        else:
            meta[k] = v
    mm.meta = meta


def _clean_error(text: str | None) -> str:
    """An error text safe to store and show: one line, no control characters, ≤ 300 characters."""
    s = " ".join(str(text or "").split())
    return "".join(c for c in s if c.isprintable())[:300]


def transport_status():
    """(TransportStatus-like or None, problem text or None) without raising."""
    try:
        st = _transport().status()
    except Exception as e:  # noqa: BLE001 - shown as "not configured", never a 500
        return None, _clean_error(f"mail transport unavailable ({type(e).__name__})")
    return st, None if st.configured else (st.reason or "not configured")


def expected_confirmations(mm: MailMessage) -> dict:
    c = dict(mm.confirmations or {})
    return {"unverified": [str(a) for a in c.get("unverified") or []],
            "attachments": [int(i) for i in c.get("attachments") or [] if str(i).isdigit()]}


def _rate_counts(db: Session, mm: MailMessage) -> tuple[int, int]:
    since = _now() - timedelta(hours=1)
    busy = (MailStatus.SENDING, MailStatus.SENT, MailStatus.UNKNOWN)
    q = select(func.count(MailMessage.id)).where(MailMessage.direction == MailDirection.OUT,
                                                 MailMessage.status.in_(busy), MailMessage.created_at > since)
    return db.scalar(q.where(MailMessage.case_id == mm.case_id)) or 0, db.scalar(q) or 0


def _expire(db: Session, mm: MailMessage) -> None:
    path = compose.retire_prepared(db, mm, by=None, status=MailStatus.EXPIRED)  # compare-and-swap, as every cancel
    db.commit()
    if path is None:
        db.refresh(mm)
    compose.unlink_pending(path)


def _check_preconditions(db: Session, access, mm: MailMessage, form: dict) -> SendOutcome | None:
    _st, problem = transport_status()
    if problem:
        raise SendError(f"Sending is not available: {problem}", 409, "not_configured")
    settings = _settings()
    if not settings.mail_from:
        raise SendError("AEGIS_MAIL_FROM is not set: Aegis has no mailbox to send from", 409, "not_configured")
    ok, _why = ev.vault_status()
    if not ok:
        raise SendError("AEGIS_VAULT_DIR must be set: every sent e-mail is filed as evidence", 409, "not_configured")
    if mm.case_id != access.case.id or mm.direction != MailDirection.OUT:
        raise LookupError("message not found")
    if mm.status != MailStatus.PREPARED:
        return SendOutcome(mm, "already", "This e-mail was already sent." if mm.status == MailStatus.SENT
                           else f"This e-mail is {mm.status.value}; nothing was sent again.")
    demo = compose.demo_lock_problem(access.case, [*(mm.to_addrs or []), *(mm.cc_addrs or []), *compose.bcc_of(mm)])
    if demo:  # the demo lock, checked again at Send (whatever the transport and AEGIS_MAIL_LIVE_SENDING say)
        raise SendError(demo[:1].upper() + demo[1:] + ".", 409, "demo_lock")
    corr = db.get(Correspondence, mm.correspondence_id) if mm.correspondence_id else None
    checklist = compose.open_checklist(db, corr) if corr is not None else None
    if checklist is not None or mm.transport == "manual" or not mm.message_id:
        # the single choke point for every Send: never while the letter's old checklist may have gone out from Outlook
        # (an unsent Outlook draft itself — X-Unsent, a Bcc header, no Message-ID — is one)
        raise SendError(compose.checklist_text(checklist or mm), 409, "checklist")
    gone = compose.superseded_text(corr) if corr is not None else None
    if gone is not None:  # a newer draft carries the request: this one never goes out next to it
        raise SendError(gone, 409, "superseded")
    gone = compose.pointless_text(db, corr) if corr is not None else None
    if gone is not None:  # the provider answered LE only / declined, or the draft predates their reply: discard it
        raise SendError(gone, 409, "pointless")
    if mm.expires_at is None or _now() >= _aware(mm.expires_at):
        _expire(db, mm)
        raise SendError("This preview expired (30 minutes). Prepare the e-mail again.", 409, "expired")
    token = str(form.get("prepare_token") or "")
    if not mm.prepare_token or not hmac.compare_digest(token.encode(), mm.prepare_token.encode()):
        raise SendError("This form is out of date. Reload the preview and try again.", 409, "token")
    if str(form.get("confirm_send") or "") != "1":
        raise SendError("Tick the box confirming the recipients and attachments.", 400, "confirm")
    want = expected_confirmations(mm)
    got_addr = {str(a).strip().lower() for a in form.get("confirm_unverified") or [] if str(a).strip()}
    need_addr = {a.lower() for a in want["unverified"]}
    if got_addr != need_addr:
        missing = sorted(need_addr - got_addr)
        raise SendError(("Confirm that each unverified address is an intended recipient: " + ", ".join(missing))
                        if missing else "Unexpected address confirmation; reload the preview.", 400, "confirm")
    got_att = {int(i) for i in form.get("confirm_attachment") or [] if str(i).strip().isdigit()}
    if got_att != set(want["attachments"]):
        missing = sorted(set(want["attachments"]) - got_att)
        raise SendError(("Confirm each evidence attachment: " + ", ".join(f"#{i}" for i in missing))
                        if missing else "Unexpected attachment confirmation; reload the preview.", 400, "confirm")
    if corr is None or corr.case_id != mm.case_id or corr.status != CorrespondenceStatus.DRAFT:
        raise SendError("The letter is no longer a draft; prepare again from the current letter.", 409, "draft")
    busy = compose.letter_in_flight(db, corr, exclude_id=mm.id)
    if busy is not None:
        raise SendError(compose.letter_busy_text(corr, busy), 409, "letter_busy")
    if compose.draft_hash(corr) != (mm.meta or {}).get("draft_hash"):
        raise SendError("The draft changed after the preview; prepare again.", 409, "draft")
    check = compose.sender_check(db, access.case, corr, settings)
    if check.needs_ack and str(form.get("ack_sender") or "") != "1":
        raise SendError("Sender of record: " + check.text + " To send it as it is, tick the acknowledgement.", 409,
                        "sender")
    for m in mm.attachments or []:
        if not m.get("evidence_id"):
            continue
        item = db.get(EvidenceItem, int(m["evidence_id"]))
        if item is None or item.case_id != mm.case_id or item.sha256 != m.get("sha256"):
            raise SendError("An attached evidence item changed or was removed; prepare again.", 409, "attachment")
        if compose.tlp_blocked(item, db) or compose.static_block_reason(access, item) is not None:
            raise SendError("An attached evidence item may no longer be attached (TLP marking, integrity, active "
                            "content or a received file no longer marked safe); prepare again without it.", 409,
                            "attachment")
        if compose.is_correspondence_item(item, db):  # evidence, and profile documents that are mail items
            key = str((mm.meta or {}).get("authority_key") or "")
            authority = desk.get_authority(db, access.case, key) if key else None
            if authority is None or compose.authority_block_reason(
                    db, item, authority, exempt=compose._profile_doc_ids(db, access.case)) is not None:
                raise SendError("An attached evidence item is correspondence with another authority (or of unknown "
                                "origin) and only goes to the authority it came from; prepare again without it.",
                                409, "attachment")
    per_case, overall = _rate_counts(db, mm)
    if per_case >= int(settings.aegis_mail_send_per_hour) or overall >= int(settings.aegis_mail_send_per_hour_global):
        raise SendError("Hourly sending limit reached; try again later.", 429, "rate_limited")
    return None


def _due_days(form: dict) -> int:
    raw = str(form.get("due_days") if form.get("due_days") is not None else "").strip()
    if not raw:
        return desk.DEFAULT_RESPONSE_DAYS
    if not raw.isdigit() or not 0 <= int(raw) <= 365:
        raise SendError("Reply expected within: 0 to 365 days.", 400, "due_days")
    return int(raw)


def _claim(db: Session, mm: MailMessage, user_id: int | None, *, from_status: MailStatus) -> bool:
    """prepared → sending for exactly one request. The partial unique index on letter_key refuses it
    (IntegrityError → SendError 409) when another e-mail of the letter is sending / sent / unknown."""
    try:
        res = db.execute(update(MailMessage)
                         .where(MailMessage.id == mm.id, MailMessage.status == from_status)
                         .values(status=MailStatus.SENDING, attempts=MailMessage.attempts + 1, sent_by=user_id,
                                 updated_at=_now())
                         .execution_options(synchronize_session=False))
        db.commit()
    except IntegrityError:
        db.rollback()
        db.refresh(mm)
        raise SendError("Another e-mail of this letter is being sent, was sent or has an unknown outcome; nothing "
                        "was sent.", 409, "letter_busy") from None
    db.refresh(mm)
    return res.rowcount == 1


def _apply_result(mm: MailMessage, res, user_id: int | None) -> None:
    mm.status = MailStatus.SENT
    mm.sent_at = _aware(getattr(res, "sent_at", None)) or _now()
    mm.internet_message_id = getattr(res, "internet_message_id", None) or mm.message_id
    mm.provider_message_id = getattr(res, "provider_message_id", None) or mm.provider_message_id
    mm.conversation_id = getattr(res, "conversation_id", None) or mm.conversation_id
    mm.error_reason = mm.error_message = None
    detail = dict(getattr(res, "detail", None) or {})
    _set_meta(mm, ids_pending=True if detail.get("ids_pending") else None, mailbox_draft=None)
    _history(mm, "sent", user_id)


def _transmit(db: Session, mm: MailMessage, actor: User | None, raw_call) -> SendOutcome:
    """Run one transport call for a claimed ('sending') row and record what happened."""
    uid = actor.id if actor is not None else None
    _set_meta(mm, send_started_at=_now().isoformat())
    db.commit()
    try:
        res = raw_call()
    except Exception as e:  # noqa: BLE001 - TransportError (app.mail) or anything unexpected
        unknown = bool(getattr(e, "outcome_unknown", False)) or not hasattr(e, "reason")
        mm.provider_message_id = getattr(e, "provider_message_id", None) or mm.provider_message_id
        mm.error_reason = ("unknown_outcome" if unknown else str(getattr(e, "reason", "server")))[:32]
        mm.error_message = _clean_error(str(e) if hasattr(e, "reason") else f"unexpected error ({type(e).__name__})")
        mm.status = MailStatus.UNKNOWN if unknown else MailStatus.FAILED
        _history(mm, mm.status.value, uid, reason=mm.error_reason)
        db.commit()
        return SendOutcome(mm, mm.status.value, UNKNOWN_TEXT if unknown else
                           f"Sending failed ({mm.error_reason}): {mm.error_message}")
    _apply_result(mm, res, uid)
    db.commit()  # sent is final from here on
    _retire_siblings(db, mm, uid)
    _finalize_quietly(db, mm, actor)  # then the Block status refresh
    return SendOutcome(mm, "sent", "E-mail sent.")


def refresh_status(db: Session, mm: MailMessage, actor: User | None = None) -> None:
    """After a letter went out: the Block status refresh (rules only, no AI call), so its snapshot and
    the block_status_changed notices follow the send at once (the Block status and Recovery plan pages
    read the letter's state live). Never fails the send."""
    try:
        from app.blocks import status as block_status

        case = db.get(Case, mm.case_id)
        if case is not None:
            block_status.refresh(db, case, actor=actor, use_ai=False)
    except Exception:  # noqa: BLE001 - advisory: a sent and filed e-mail stays sent and filed
        db.rollback()


def _retire_siblings(db: Session, mm: MailMessage, user_id: int | None) -> int:
    """The letter went out through `mm`: every other prepared preview of the same letter
    (`letter_key`: a stop order's letter may be drafted on more than one correspondence row) is
    cancelled as superseded (never sent later)."""
    if mm.letter_key:
        same = MailMessage.letter_key == mm.letter_key
        if mm.correspondence_id is not None:
            same = same | (MailMessage.correspondence_id == mm.correspondence_id)
    elif mm.correspondence_id is not None:
        same = MailMessage.correspondence_id == mm.correspondence_id
    else:
        return 0
    paths = []
    for other in db.scalars(select(MailMessage).where(same, MailMessage.direction == MailDirection.OUT,
                                                      MailMessage.status == MailStatus.PREPARED,
                                                      MailMessage.id != mm.id)).all():
        path = compose.retire_prepared(db, other, by=user_id, reason=f"superseded: sent as e-mail #{mm.id}",
                                       superseded_by=mm.id)  # compare-and-swap: never one a Send claimed
        if path is not None:
            paths.append(path)
    if paths:
        db.commit()
        for path in paths:
            compose.unlink_pending(path)
    return len(paths)


def send(db: Session, access, mm: MailMessage, form: dict) -> SendOutcome:
    if not access.can("send_email"):
        raise SendError("only case admins may send e-mail", 403, "forbidden")
    done = _check_preconditions(db, access, mm, form)
    if done is not None:
        return done
    due_days = _due_days(form)
    check = compose.sender_check(db, access.case, db.get(Correspondence, mm.correspondence_id), _settings())
    if not _claim(db, mm, access.user.id, from_status=MailStatus.PREPARED):
        return SendOutcome(mm, "already", "This e-mail is already being sent or was sent.")
    _set_meta(mm, due_days=due_days, n_unverified_confirmed=len(expected_confirmations(mm)["unverified"]),
              sender_problem=check.problem)
    if check.needs_ack:
        note = " ".join(str(form.get("ack_sender_reason") or "").split())[:ACK_REASON_MAX]
        _set_meta(mm, sender_ack={"problem": check.problem, "by": access.user.id, "at": _now().isoformat(),
                                  **({"reason": note} if note else {})})
        _history(mm, "sender_acknowledged", access.user.id, reason=(f"{check.problem}: {note}" if note else
                                                                     check.problem)[:200])
    db.commit()
    try:
        raw = compose.read_raw(mm)
    except (OSError, ev.EvidenceError):
        raw = None
    if raw is None or hashlib.sha256(raw).hexdigest() != mm.mime_sha256:
        mm.status, mm.error_reason = MailStatus.FAILED, "integrity"
        mm.error_message = "the prepared message bytes are missing or changed"
        _history(mm, "failed", access.user.id, reason="integrity")
        db.commit()
        return SendOutcome(mm, "failed", "Sending failed: the prepared message changed on disk. Prepare again.")
    t = _transport()
    bcc = compose.bcc_of(mm)  # never in the MIME: the transport adds them as hidden recipients
    return _transmit(db, mm, access.user, lambda: t.send_mime(raw, message_id=mm.message_id,
                                                                 **({"bcc": bcc} if bcc else {})))


def _finalize_quietly(db: Session, mm: MailMessage, actor: User | None) -> bool:
    """File a sent message (`finalize`); when that filed it now (the direct send, reconcile, Retry filing, the
    scheduler), the Block status refresh follows (`refresh_status`)."""
    already = bool((mm.meta or {}).get("finalized"))
    try:
        finalize(db, mm, actor, (mm.meta or {}).get("due_days"))
    except Exception as e:  # noqa: BLE001 - a sent message stays sent; the preview offers "Retry filing"
        db.rollback()
        db.refresh(mm)
        _set_meta(mm, finalize_error=_clean_error(f"{type(e).__name__}: {e}"))
        db.commit()
        return False
    if not already:
        refresh_status(db, mm, actor)
    return True


class FinalizeError(RuntimeError):
    pass


def finalize(db: Session, mm: MailMessage, actor: User | None, due_days: int | None = None) -> MailMessage:
    """File a sent message (idempotent): the exact bytes as an R3 .eml evidence item, the letter
    marked sent through the desk, the directory stamped. Raises on failure (the caller records it)."""
    if mm.status != MailStatus.SENT:
        raise FinalizeError("only a sent message is filed")
    if (mm.meta or {}).get("finalized"):
        return mm
    case = db.get(Case, mm.case_id)
    corr = db.get(Correspondence, mm.correspondence_id) if mm.correspondence_id else None
    if case is None or corr is None:
        raise FinalizeError("the case or letter of this message no longer exists")
    days = desk.DEFAULT_RESPONSE_DAYS if due_days is None else int(due_days)
    sent_at = _aware(mm.sent_at) or _now()
    ref = re.sub(r"[^A-Za-z0-9._-]+", "-", case.reference)[:40]
    if mm.eml_evidence_id is None:
        raw = compose.read_raw(mm)
        if hashlib.sha256(raw).hexdigest() != mm.mime_sha256:
            raise FinalizeError("the stored message bytes do not match the sent hash")
        item = ev.store_upload(
            db, case, BytesIO(raw), filename=f"{ref}_email-{corr.id}.eml", folder="stop_orders_correspondence",
            title=f"E-mail as sent: letter #{corr.id} ({sent_at.astimezone(UTC):%Y-%m-%d %H:%M} UTC)",
            source_type="eml", classification="R3", tags=["aegis-mail", "sent-email"], actor=actor,
            doc_date=sent_at)
        if item.sha256 != mm.mime_sha256:
            raise FinalizeError("the evidence copy does not match the sent hash")
        mm.eml_evidence_id = item.id
        db.flush()
    was_draft = corr.status == CorrespondenceStatus.DRAFT
    ours = (corr.meta or {}).get("mail_message_id") == mm.id  # an earlier finalize of this message got this far
    corr.recipients, corr.cc = list(mm.to_addrs or []), list(mm.cc_addrs or [])
    bcc = compose.bcc_of(mm)
    corr.sender = mm.mailbox
    corr.channel = CorrespondenceChannel.EMAIL
    corr.thread_key = (mm.internet_message_id or mm.message_id)[:255]
    corr.evidence_item_id = mm.eml_evidence_id
    meta = dict(corr.meta or {})
    kept, unsent = compose.split_unsent_uploads(corr, mm)
    ids = [mm.eml_evidence_id] + [i for i in kept if i != mm.eml_evidence_id]
    meta.update({"mail_message_id": mm.id, "sent_via": "aegis_mail", "transport": mm.transport, "evidence_ids": ids})
    if unsent:  # uploaded for the letter but left out of the e-mail: filed, never evidence of what was sent
        meta["unsent_uploads"] = sorted(set(unsent) | {int(i) for i in meta.get("unsent_uploads") or []
                                                       if str(i).isdigit()})
    if bcc:
        meta["bcc"] = bcc
    corr.meta = meta
    db.flush()
    if was_draft:
        desk.mark_sent(db, case, corr, actor=actor, sent_at=sent_at, channel="email", due_days=days,
                       authority_key=(mm.meta or {}).get("authority_key"))
    elif not ours:  # someone marked the letter sent by hand meanwhile: keep their record, flag it
        _set_meta(mm, mark_sent_conflict=True)
    directory.touch_used(db, case, [*(mm.to_addrs or []), *(mm.cc_addrs or []), *bcc])
    _set_meta(mm, finalized=True, finalize_error=None)
    db.commit()
    compose.delete_pending(mm)
    db.commit()
    return mm


# --------------------------------------------------------------------------- reconcile / cancel
def reconcile(db: Session, mm: MailMessage, actor: User | None = None) -> str:
    """Ask the transport what happened to an uncertain send: sent (fill the ids, file it); missing or
    still an unsent draft in the mailbox (failed once MISSING_GRACE has passed since the attempt, else
    still unknown). This is the only way out of `unknown`. Returns the state seen, or "" when there
    was nothing to do."""
    pending_ids = mm.status == MailStatus.SENT and (mm.meta or {}).get("ids_pending")
    if compose.stale_draft_left(mm):  # failed before drafts were deleted: delete it now
        removed = _delete_stale_draft(db, mm, None, actor.id if actor else None, keep_status=True)
        if removed == "deleted":
            _set_meta(mm, mailbox_draft=None, draft_deleted=True, draft_delete_error=None)
            db.commit()
            return "draft_deleted"
        if removed == "sent":  # marked failed, yet the mailbox shows it sent: the letter stays blocked
            _set_meta(mm, draft_delete_error="the mailbox shows this e-mail as sent: check Sent Items before "
                                             "writing to the recipient again")
            db.commit()
        return "draft"
    if mm.status != MailStatus.UNKNOWN and not pending_ids:
        return ""
    lookup = _transport().lookup_sent(message_id=mm.message_id, provider_message_id=mm.provider_message_id)
    state = getattr(lookup, "state", "missing")
    actor = actor or (db.get(User, mm.sent_by) if mm.sent_by else None)
    if state == "sent":
        res = getattr(lookup, "result", None)
        if mm.status == MailStatus.UNKNOWN:
            _apply_result(mm, res if res is not None else _Bare(mm.message_id), actor.id if actor else None)
            db.commit()
            _retire_siblings(db, mm, actor.id if actor else None)
        elif res is not None:
            mm.internet_message_id = res.internet_message_id or mm.internet_message_id
            mm.conversation_id = res.conversation_id or mm.conversation_id
            _set_meta(mm, ids_pending=True if (res.detail or {}).get("ids_pending") else None)
        db.commit()
        _finalize_quietly(db, mm, actor)
        return "sent"
    if mm.status != MailStatus.UNKNOWN:
        return state
    started = (mm.meta or {}).get("send_started_at")
    at = datetime.fromisoformat(started) if started else _aware(mm.updated_at or mm.prepared_at) or _now()
    draft = state == "draft"
    uid = actor.id if actor else None
    if _now() - at <= MISSING_GRACE:
        if (mm.meta or {}).get("last_reconcile") != state:  # the scheduler re-checks: one history line per state
            _history(mm, "unknown", uid, reconcile=state)
        _set_meta(mm, mailbox_draft=True if draft else None, last_reconcile=state)
        db.commit()
        return "draft" if draft else "missing"
    if draft:
        res = getattr(lookup, "result", None)
        removed = _delete_stale_draft(db, mm, getattr(res, "provider_message_id", None), uid)
        if removed == "sent":  # it went out meanwhile: reconcile once more from the mailbox
            return reconcile(db, mm, actor) if (mm.meta or {}).get("draft_recheck", 0) <= 1 else "draft"
        if removed != "deleted":
            return "draft"  # still unknown: the letter stays blocked
    mm.status, mm.error_reason = MailStatus.FAILED, "unsent_draft" if draft else "not_found"
    mm.error_message = ("the message never left the mailbox: Aegis deleted the unsent draft, nothing was sent"
                        if draft else "the mailbox has no record of this message")
    _history(mm, "failed", uid, reason=mm.error_reason, reconcile=state)
    _set_meta(mm, mailbox_draft=None, draft_deleted=True if draft else None, draft_delete_error=None,
              last_reconcile=state)
    compose.delete_pending(mm)
    db.commit()
    return "draft" if draft else "missing"


DRAFT_DELETE_FAILED = ("The mailbox still holds this e-mail as an unsent draft and Aegis could not delete it ({why}). "
                       "The letter stays blocked (outcome unknown) until the draft is gone: delete it in the "
                       "mailbox's Drafts folder (or fix the problem) and use “Check the mailbox now”.")


def _delete_stale_draft(db: Session, mm: MailMessage, provider_id: str | None, uid: int | None, *,
                        keep_status: bool = False) -> str | None:
    """Before an unsent draft's e-mail is marked failed: delete the draft (every draft with its
    Message-ID) through the transport. Returns "deleted", "sent" (the mailbox shows it sent) or None
    (not deleted: the row stays unknown, the admin is told on the preview, the letter stays blocked)."""
    t = _transport()
    deleter = getattr(t, "delete_drafts", None)
    why = None
    result = None
    if deleter is None:
        why = "this transport cannot delete drafts"
    else:
        try:
            result = deleter(message_id=mm.message_id, provider_message_id=provider_id or mm.provider_message_id)
        except Exception as e:  # noqa: BLE001 - TransportError or anything unexpected: stays blocked
            why = _clean_error(str(e) if hasattr(e, "reason") else f"unexpected error ({type(e).__name__})")
    if result == "deleted":
        _history(mm, "draft_deleted", uid)
        db.commit()
        return "deleted"
    if result == "sent":
        _set_meta(mm, draft_recheck=int((mm.meta or {}).get("draft_recheck") or 0) + 1)
        db.commit()
        return "sent"
    why = why or f"unexpected answer {str(result)[:40]!r}"
    first = (mm.meta or {}).get("draft_delete_error") is None
    if not keep_status:
        mm.error_reason = "draft_not_deleted"
        mm.error_message = _clean_error(DRAFT_DELETE_FAILED.format(why=why))
    _set_meta(mm, mailbox_draft=True, draft_delete_error=why, last_reconcile="draft")
    if first:
        _history(mm, mm.status.value, uid, reason="unsent draft could not be deleted", reconcile="draft")
    db.commit()
    return None


@dataclass(frozen=True)
class _Bare:
    internet_message_id: str
    provider_message_id: str | None = None
    conversation_id: str | None = None
    sent_at: datetime | None = None
    detail: dict | None = None


def cancel(db: Session, access, mm: MailMessage) -> MailMessage:
    """Drop a prepared (unsent) message: its own author (investigator) or any case admin."""
    if mm.case_id != access.case.id or mm.direction != MailDirection.OUT:
        raise LookupError("message not found")
    if not (access.can("send_email") or (access.can("prepare_email") and mm.created_by == access.user.id)):
        raise SendError("only the member who prepared it or a case admin may cancel this e-mail", 403, "forbidden")
    if mm.status != MailStatus.PREPARED:
        raise SendError(f"This e-mail is {mm.status.value}; only a prepared e-mail can be cancelled.", 409, "invalid")
    if compose.is_open_checklist(mm) and not compose.is_manual():  # it may have gone out: retire it or record it
        raise SendError(compose.checklist_text(mm), 409, "checklist")
    path = compose.retire_prepared(db, mm, by=access.user.id)  # compare-and-swap: a Send claimed it → refused
    if path is None:
        db.rollback()
        db.refresh(mm)
        raise SendError(f"This e-mail is {mm.status.value} now; only a prepared e-mail can be cancelled.", 409,
                        "invalid")
    db.commit()
    compose.unlink_pending(path)
    return mm


def retry_filing(db: Session, access, mm: MailMessage) -> bool:
    if mm.case_id != access.case.id or mm.direction != MailDirection.OUT:
        raise LookupError("message not found")
    if mm.status != MailStatus.SENT:
        raise SendError("Only a sent e-mail is filed.", 409, "invalid")
    return _finalize_quietly(db, mm, access.user)


# --------------------------------------------------------------------------- scheduler hooks (app.mail / scripts)
def expire_prepared(db: Session) -> int:
    """Mark prepared messages past their 30 minutes expired and delete their pending files."""
    now = _now()
    paths = []
    for mm in db.scalars(select(MailMessage).where(MailMessage.direction == MailDirection.OUT,
                                                   MailMessage.status == MailStatus.PREPARED,
                                                   MailMessage.expires_at < now)).all():
        path = compose.retire_prepared(db, mm, by=None, status=MailStatus.EXPIRED)  # never one a Send claimed
        if path is not None:
            paths.append(path)
    db.commit()
    for path in paths:
        compose.unlink_pending(path)
    return len(paths)


def reconcile_unknown_all(db: Session) -> int:
    """Reconcile every uncertain send (and file sent messages whose filing failed). Returns the
    number of rows that changed state or were filed."""
    now = _now()
    n = 0
    for mm in db.scalars(select(MailMessage).where(MailMessage.direction == MailDirection.OUT,
                                                   MailMessage.status == MailStatus.SENDING)).all():
        if now - (_aware(mm.updated_at) or _aware(mm.prepared_at) or now) > STUCK_SENDING:
            mm.status, mm.error_reason = MailStatus.UNKNOWN, "unknown_outcome"
            _history(mm, "unknown", None, reason="stuck")
    db.commit()
    rows = db.scalars(select(MailMessage).where(MailMessage.direction == MailDirection.OUT,
                                                MailMessage.status.in_((MailStatus.UNKNOWN, MailStatus.SENT))
                                                | ((MailMessage.status == MailStatus.FAILED)
                                                   & (MailMessage.error_reason == "unsent_draft")))).all()
    for mm in rows:
        try:
            before = (mm.status, (mm.meta or {}).get("finalized"), compose.stale_draft_left(mm))
            if mm.status == MailStatus.FAILED:
                if compose.stale_draft_left(mm):
                    reconcile(db, mm)
            elif mm.status == MailStatus.UNKNOWN or (mm.meta or {}).get("ids_pending"):
                reconcile(db, mm)
            elif not (mm.meta or {}).get("finalized"):
                _finalize_quietly(db, mm, db.get(User, mm.sent_by) if mm.sent_by else None)
            if (mm.status, (mm.meta or {}).get("finalized"), compose.stale_draft_left(mm)) != before:
                n += 1
        except Exception:  # noqa: BLE001 - one row never stops the pass
            db.rollback()
    return n


def status_json(mm: MailMessage) -> dict:
    """Status of one message for the API: ids, counts and states only (no addresses, no body)."""
    def iso(v):
        return _aware(v).isoformat() if v else None

    return {"id": mm.id, "case_id": mm.case_id, "correspondence_id": mm.correspondence_id,
            "direction": mm.direction.value, "status": mm.status.value, "transport": mm.transport,
            "attempts": mm.attempts, "n_to": len(mm.to_addrs or []), "n_cc": len(mm.cc_addrs or []),
            "n_attachments": len(mm.attachments or []), "mime_size": mm.mime_size, "mime_sha256": mm.mime_sha256,
            "eml_evidence_id": mm.eml_evidence_id, "error_reason": mm.error_reason,
            "finalized": bool((mm.meta or {}).get("finalized")), "prepared_at": iso(mm.prepared_at),
            "expires_at": iso(mm.expires_at), "sent_at": iso(mm.sent_at), "created_at": iso(mm.created_at)}


def awaiting_send(db: Session, case_id: int) -> list[MailMessage]:
    """Prepared, unexpired outbound e-mails of a case: each waits for a case admin to press Send."""
    now = _now()
    rows = db.scalars(select(MailMessage).where(MailMessage.case_id == case_id,
                                                MailMessage.direction == MailDirection.OUT,
                                                MailMessage.status == MailStatus.PREPARED)
                      .order_by(MailMessage.id.desc())).all()
    return [m for m in rows if m.expires_at is not None and _aware(m.expires_at) > now]


def mail_history(db: Session, corr: Correspondence | None) -> list[MailMessage]:
    """The outbound e-mails prepared / sent for one letter (the letter page's E-mail history panel)."""
    if corr is None or corr.id is None:
        return []
    return list(db.scalars(select(MailMessage).where(MailMessage.correspondence_id == corr.id,
                                                     MailMessage.direction == MailDirection.OUT)
                           .order_by(MailMessage.id.desc())))


# --------------------------------------------------------------------------- sent outside Aegis (manual mode)
EXTERNAL_SENT_VIA = "email (sent outside Aegis)"
EXTERNAL_RECORDABLE = (MailStatus.PREPARED, MailStatus.EXPIRED)
SENT_UPLOAD_TYPES = {".eml": "message/rfc822", ".msg": "application/vnd.ms-outlook"}
SENT_UPLOAD_MAX = 25 * 1024 * 1024
CFB_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")  # an Outlook .msg is an OLE compound file
SENT_AT_SLACK = timedelta(hours=1)  # a recorded send may not be (much) earlier than the preview


def parse_sent_at(raw: str | None, *, now: datetime | None = None, not_before: datetime | None = None) -> datetime:
    """'YYYY-MM-DDTHH:MM' (a datetime-local field, read as UTC) or an ISO time with an offset."""
    now = now or _now()
    value = (raw or "").strip()
    if not value:
        raise SendError("Enter the date and time the e-mail was sent (UTC).", 400, "sent_at")
    try:
        at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise SendError("Sent at: use the format YYYY-MM-DD HH:MM (UTC).", 400, "sent_at") from None
    at = at if at.tzinfo else at.replace(tzinfo=UTC)
    if at > now + timedelta(minutes=5):
        raise SendError("Sent at is in the future.", 400, "sent_at")
    if not_before is not None and at < _aware(not_before) - SENT_AT_SLACK:
        raise SendError("Sent at is before this e-mail was prepared. A letter sent earlier is recorded with Mark sent "
                        "on the letter itself.", 400, "sent_at")
    return at


def _sent_upload(upload, mm: MailMessage, case) -> dict | None:
    """Check an uploaded sent message (filename, bytes): .eml (RFC 5322) or .msg (OLE). Returns
    {ext, data, sha256, message_id, subject_tag_missing} or None when nothing was uploaded."""
    if upload is None:
        return None
    filename, data = upload
    if not filename and not data:
        return None
    ext = "." + (filename or "").rsplit(".", 1)[-1].lower() if "." in (filename or "") else ""
    if ext not in SENT_UPLOAD_TYPES:
        raise SendError("The sent message must be an .eml or .msg file (Outlook: File → Save As).", 400, "upload")
    if not data:
        raise SendError("The uploaded file is empty.", 400, "upload")
    if len(data) > SENT_UPLOAD_MAX:
        raise SendError(f"The uploaded file is larger than {SENT_UPLOAD_MAX // (1 << 20)} MB.", 400, "upload")
    out = {"ext": ext, "data": data, "sha256": hashlib.sha256(data).hexdigest(), "message_id": None,
           "subject_tag_missing": None}
    tag = compose.TAG_RE.search(mm.subject or "")
    if ext == ".msg":
        if not data.startswith(CFB_MAGIC):
            raise SendError("This .msg file is not an Outlook message (no compound-file header).", 400, "upload")
        return out
    from email import policy
    from email.parser import BytesParser

    head = data[:256 * 1024]
    msg = BytesParser(policy=policy.default).parsebytes(head, headersonly=True)
    if not (msg.get("Subject") or msg.get("From") or msg.get("To")):
        raise SendError("This .eml file has no e-mail headers.", 400, "upload")
    mid = str(msg.get("Message-ID") or "").strip()
    out["message_id"] = mid[:255] or None
    if tag is not None:
        out["subject_tag_missing"] = tag.group(0) not in " ".join(str(msg.get("Subject") or "").split())
    return out


def record_external(db: Session, access, mm: MailMessage, form: dict, upload=None) -> SendOutcome:
    """A case admin records that a prepared e-mail was sent from outside Aegis (module doc).
    `form`: sent_at, to, cc, due_days, confirm_external ("1"); `upload`: (filename, bytes) or None.
    Returns SendOutcome(mm, "sent_external" | "already"). Raises SendError / LookupError."""
    if not access.can("send_email"):
        raise SendError("only case admins may record an e-mail as sent", 403, "forbidden")
    if mm.case_id != access.case.id or mm.direction != MailDirection.OUT:
        raise LookupError("message not found")
    if mm.status == MailStatus.SENT_EXTERNAL:
        return SendOutcome(mm, "already", "This e-mail was already recorded as sent.")
    if mm.status not in EXTERNAL_RECORDABLE:
        raise SendError(f"This e-mail is {mm.status.value}; only a prepared e-mail is recorded as sent.", 409, "invalid")
    corr = db.get(Correspondence, mm.correspondence_id) if mm.correspondence_id else None
    if corr is None or corr.case_id != mm.case_id:
        raise SendError("This e-mail has no letter on this case.", 409, "draft")
    if corr.status != CorrespondenceStatus.DRAFT:
        raise SendError("The letter is no longer a draft (it was marked sent already).", 409, "draft")
    if compose.draft_hash(corr) != (mm.meta or {}).get("draft_hash"):
        raise SendError("The draft changed after this e-mail was prepared: what went out is not the current letter. "
                        "Restore the draft or prepare the e-mail again before recording it.", 409, "draft")
    busy = compose.letter_in_flight(db, corr, exclude_id=mm.id)
    if busy is not None:
        raise SendError(compose.letter_busy_text(corr, busy), 409, "letter_busy")
    if str(form.get("confirm_external") or "") != "1":
        raise SendError("Tick the box confirming that this e-mail was sent.", 400, "confirm")
    sent_at = parse_sent_at(form.get("sent_at"), not_before=mm.prepared_at)
    try:
        to = compose._addresses(compose._split(form.get("to")), "to")
        cc = [a for a in compose._addresses(compose._split(form.get("cc")), "cc") if a.lower() not in {x.lower() for x in to}]
    except compose.ComposeError as e:
        raise SendError(f"Recipients: {e}", 400, "recipients") from None
    if not to:
        raise SendError("Enter the To address(es) the e-mail was sent to.", 400, "recipients")
    demo = compose.demo_lock_problem(access.case, to + cc, mailbox=mm.mailbox or _settings().mail_from)
    if demo:  # a demo case's e-mail never went to a real organisation: nothing to record
        raise SendError(demo[:1].upper() + demo[1:] + ".", 400, "demo_lock")
    if len(to) > compose.MAX_TO or len(cc) > compose.MAX_CC or len(to) + len(cc) > compose.MAX_UNIQUE:
        raise SendError(f"At most {compose.MAX_TO} To, {compose.MAX_CC} Cc, {compose.MAX_UNIQUE} in all.", 400,
                        "recipients")
    due_days = _due_days(form)
    up = _sent_upload(upload, mm, access.case)
    if up is not None:
        ok, _why = ev.vault_status()
        if not ok:
            raise SendError("AEGIS_VAULT_DIR must be set to keep the sent message as evidence.", 409, "not_configured")

    item = None
    ref = re.sub(r"[^A-Za-z0-9._-]+", "-", access.case.reference)[:40]
    if up is not None:
        item = ev.store_upload(
            db, access.case, BytesIO(up["data"]), filename=f"{ref}_email-sent-{corr.id}{up['ext']}",
            folder="stop_orders_correspondence",
            title=f"E-mail as sent outside Aegis: letter #{corr.id} ({sent_at.astimezone(UTC):%Y-%m-%d %H:%M} UTC)",
            source_type="eml" if up["ext"] == ".eml" else "msg", classification="R3",
            tags=["aegis-mail", "sent-email"], actor=access.user, doc_date=sent_at, max_bytes=SENT_UPLOAD_MAX)
        item.mime = SENT_UPLOAD_TYPES[up["ext"]]
        item.meta = {**(item.meta or {}), "mail_message_id": mm.id, "sent_outside_aegis": True}
        if item.sha256 != up["sha256"]:
            raise SendError("The stored copy of the sent message does not match the upload.", 500, "integrity")
    try:  # the partial unique index (0009: incl. sent_external) refuses a second e-mail of the letter
        res = db.execute(update(MailMessage)
                         .where(MailMessage.id == mm.id, MailMessage.status.in_(EXTERNAL_RECORDABLE))
                         .values(status=MailStatus.SENT_EXTERNAL, sent_by=access.user.id, updated_at=_now())
                         .execution_options(synchronize_session=False))
    except IntegrityError:
        db.rollback()
        _drop_vault_copy(item)
        db.refresh(mm)
        raise SendError("Another e-mail of this letter was sent, recorded as sent or is being sent; nothing was "
                        "recorded.", 409, "letter_busy") from None
    if res.rowcount != 1:
        db.rollback()
        _drop_vault_copy(item)
        db.refresh(mm)
        return SendOutcome(mm, "already", "This e-mail was already recorded, or is no longer prepared.")
    prepared_to = [a.lower() for a in mm.to_addrs or []]
    prepared_cc = [a.lower() for a in mm.cc_addrs or []]
    changed = sorted(a.lower() for a in to) != sorted(prepared_to) or sorted(a.lower() for a in cc) != sorted(prepared_cc)
    mm.status = MailStatus.SENT_EXTERNAL
    mm.sent_by = access.user.id
    mm.sent_at = sent_at
    mm.to_addrs, mm.cc_addrs = to, cc
    mm.error_reason = mm.error_message = None
    if up is not None and up.get("message_id"):
        mm.internet_message_id = up["message_id"]
    record = {"recorded_by": access.user.id, "recorded_at": _now().isoformat(), "sent_at": sent_at.isoformat(),
              "evidence_id": item.id if item is not None else None, "upload": up["ext"].lstrip(".") if up else None,
              "recipients_changed": changed, "subject_tag_missing": up.get("subject_tag_missing") if up else None}
    if changed:  # what the preview had (the row now holds what was actually used)
        record.update(prepared_to=prepared_to, prepared_cc=prepared_cc)
    _set_meta(mm, due_days=due_days, sent_external=record)
    _history(mm, "sent_external", access.user.id, reason="recorded as sent outside Aegis"
             + ("; recipients differ from the preview" if changed else ""))
    corr.recipients, corr.cc = list(to), list(cc)
    corr.sender = mm.mailbox or None
    corr.channel = CorrespondenceChannel.EMAIL
    meta = dict(corr.meta or {})
    ids, unsent = compose.split_unsent_uploads(corr, mm)
    if unsent:
        meta["unsent_uploads"] = sorted(set(unsent))
    if item is not None:
        corr.evidence_item_id = item.id
        ids = [item.id] + [i for i in ids if i != item.id]
    meta.update({"mail_message_id": mm.id, "sent_via": "email_external", "transport": mm.transport,
                 "evidence_ids": ids})
    bcc = compose.bcc_of(mm)  # the checklist's hidden recipients, as `finalize` keeps them for an Aegis send
    if bcc:
        meta["bcc"] = bcc
    corr.meta = meta
    db.flush()
    desk.mark_sent(db, access.case, corr, actor=access.user, sent_at=sent_at, channel="email", due_days=due_days,
                   authority_key=(mm.meta or {}).get("authority_key"))  # commits: claim, evidence, letter together
    order = corr.stop_order
    if order is not None and order.sent_at is not None and order.sent_via == CorrespondenceChannel.EMAIL.value:
        order.sent_via = EXTERNAL_SENT_VIA
    directory.touch_used(db, access.case, [*to, *cc, *bcc])
    db.commit()
    _retire_siblings(db, mm, access.user.id)
    refresh_status(db, mm, access.user)
    return SendOutcome(mm, "sent_external", "Recorded as sent outside Aegis.")


def _drop_vault_copy(item: EvidenceItem | None) -> None:
    """Remove the vault file of an evidence row that was rolled back (never committed)."""
    if item is None or not item.vault_path:
        return
    try:
        root = ev.vault_dir(create=False)
        p = (root / item.vault_path).resolve()
        if p.is_relative_to(root):
            p.unlink(missing_ok=True)
    except (OSError, ev.EvidenceError):
        pass
