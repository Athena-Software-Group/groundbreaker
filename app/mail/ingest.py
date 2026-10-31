"""Mailbox ingestion: fetch inbound mail, file replies on the right authority, queue the rest.

    report = sync_mailbox(db, trigger="scheduler" | "admin" | "case_admin" | "letter_check", actor=None)
    corr   = persist_to_case(db, mm, case, authority_key, in_reply_to, actor)
    assign(db, mm, case, authority_key=…, in_reply_to_id=…, actor=…)     # /admin/mail triage
    ignore(db, mm, reason, actor) · accept_review(…) · reject_review(…)   # triage / case review

**Sync** (one mailbox, the configured AEGIS_MAIL_FROM):

1. Lease: the `mail_sync_state` row is locked with a conditional UPDATE (`locked_until`, 5 min);
   a second sync while it is held returns `busy`. A manual sync within 60 s of the last start is
   refused (`too_soon`; 5 s for "letter_check", the Sent Items read before an old checklist is retired).
2. Cutover: graph mailboxes ingest only mail received after `since` (AEGIS_MAIL_INBOUND_SINCE, else
   the first sync), so switching it on never imports a mailbox's history. The file transport's inbox
   folder only holds new files (processed ones move out), so it has no cutover unless
   AEGIS_MAIL_INBOUND_SINCE is set.
3. Each message, in its own try (a failure counts in `errors`, the batch continues): dedupe on
   (mailbox, provider id), then on the raw sha256; oversized → a `rejected` row with headers only;
   parse; match (app.mail.matching); write the raw .eml to the vault (`mailbox/<uuid>.eml`, 0600);
   confident → `persist_to_case`; otherwise the row waits in needs_review (on a case) or unassigned
   (system admins only). Audited `MAIL_INGESTED` (ids, method, status, case id only).
4. The new Graph delta link is stored only when the whole batch went through without an error.

**Filing** (`persist_to_case`): the raw .eml and each attachment become R3 evidence items in Stop
orders & correspondence (at most app.mail.inbound.MAX_ATTACHMENTS / MAX_ATTACHMENT_TOTAL of them;
beyond the caps an attachment stays only in the .eml and the message is flagged
`attachments_truncated`); attachments are never attachable to outgoing e-mail until a case admin
marks them safe (app.domain.mail_compose); then a reply is logged with `desk.log_entry(direction="in")` (stops the
reply clock, emits `correspondence_in`); an auto-reply or a bounce is logged as a **note** (never
stops the clock; a bounce emits a warning `correspondence_in` and flags the original e-mail). The
vault copy is deleted only once the evidence copy verified by sha256. Then `block_status_hook` reads the
filed reply for the Block status report (app.blocks.status.on_reply_filed: advisory, never a status change).

Inbound content is untrusted data: it never creates drafts, sends anything or changes a stop-order
status. Correspondence filed from the mailbox carries `meta.source="mailbox"`,
`meta.untrusted_external=True` and is shown as escaped plain text.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser
from pathlib import Path

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.logging import redact
from app.mail import inbound, matching
from app.mail.config import MailSettings, mail_settings
from app.mail.transport import InboundItem, TransportError

log = logging.getLogger("app.mail")

LEASE = timedelta(minutes=5)
MANUAL_MIN_INTERVAL = timedelta(seconds=60)
# the read of Sent Items before an old "Draft — you send" checklist is retired (trigger "letter_check"): it must see
# a send from Outlook made a moment ago, so only this short floor applies (the lease still keeps one sync at a time)
LETTER_CHECK_MIN_INTERVAL = timedelta(seconds=5)
RAW_DIR = "mailbox"
INBOUND_FOLDER = "stop_orders_correspondence"
OPEN_INBOUND = ("unassigned", "needs_review")
FOLDERS = ("inbox", "sentitems")  # the mailbox folders a graph sync reads (app.mail.graph.FOLDERS), as listed
# Sent Items first: a letter sent from Outlook is recorded on its letter before the replies to it are read in the
# same sync (a backfill reads both histories at once), so those replies thread onto the recorded letter
SYNC_ORDER = ("sentitems", "inbox")


class IngestError(ValueError):
    """A triage / filing request that cannot be done (shown to the admin)."""


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _aware(v: datetime | None) -> datetime | None:
    return v if v is None or v.tzinfo else v.replace(tzinfo=UTC)


def _M():
    from app.db import models as M  # call time: the mail models come from migration 0008

    return M


def sanitize_error(err: BaseException) -> str:
    """The error as shown on /admin/mail/mailbox and logged. A database error carries its SQL and bound
    parameters (fragments of a subject or body) in its text: only its type is kept."""
    from sqlalchemy.exc import SQLAlchemyError

    if isinstance(err, SQLAlchemyError):
        return f"{type(err).__name__}: database error (details withheld)"
    text = str(err) if isinstance(err, (TransportError, IngestError)) else f"{type(err).__name__}: {err}"
    return redact(text.replace("\r", " ").replace("\n", " "))[:300]


SENT_KEYS = ("fetched", "recorded", "linked", "logged", "known", "metadata_only", "duplicates", "not_related",
             "skipped_old", "errors")


@dataclass
class SyncReport:
    """One sync. The top-level counters are the Inbox's (and the file inbox's); `sent` holds Sent Items'
    (graph mailbox sync only: app.mail.sync_outbound)."""

    mailbox: str | None = None
    transport: str | None = None
    trigger: str = ""
    busy: bool = False
    too_soon: bool = False
    disabled: str | None = None  # why nothing ran (not configured)
    fetched: int = 0
    received: int = 0  # filed on a case
    needs_review: int = 0
    unassigned: int = 0
    ignored: int = 0
    rejected: int = 0
    duplicates: int = 0
    skipped_old: int = 0
    errors: int = 0
    triage: int = 0  # unassigned rows kept as metadata only (from an authority's domain, nothing cited)
    not_related: int = 0  # counted, never stored (data minimisation, docs/data-handling.md §6.4)
    error: str | None = None
    sent: dict[str, int] = field(default_factory=lambda: dict.fromkeys(SENT_KEYS, 0))
    folders: list[str] = field(default_factory=list)  # the folders read (graph mailbox sync)
    per_case: dict[int, dict[str, int]] = field(default_factory=dict)
    mail_ids: list[int] = field(default_factory=list)

    def counts(self) -> dict:
        out = {k: getattr(self, k) for k in ("fetched", "received", "needs_review", "unassigned", "ignored",
                                             "rejected", "duplicates", "skipped_old", "errors")}
        out.update(triage=self.triage, not_related=self.not_related)
        if "sentitems" in self.folders:
            out.update({f"sent_{k}": v for k, v in self.sent.items()})
        return out

    def bump_case(self, case_id: int | None, key: str) -> None:
        if case_id is None:
            return
        row = self.per_case.setdefault(int(case_id), {"received": 0, "needs_review": 0})
        row[key] = row.get(key, 0) + 1

    def bump_sent(self, key: str, n: int = 1) -> None:
        self.sent[key] = self.sent.get(key, 0) + n

    @property
    def ok(self) -> bool:
        return not (self.busy or self.too_soon or self.disabled or self.error)


@dataclass
class SyncContext:
    """What one sync's message handlers share."""

    db: Session
    transport: object
    settings: MailSettings
    mailbox: str
    trigger: str
    actor: object = None
    since: datetime | None = None
    folder: str | None = None  # inbox | sentitems (graph mailbox sync); None: the legacy single inbox
    _index: object = None

    @property
    def minimise(self) -> bool:
        """The graph transport reads a real shared mailbox: store only what is case-related (§6.4). The
        file transport's inbox folder holds only files dropped for Aegis (local demos): every one is kept."""
        return getattr(self.transport, "name", None) == "graph"

    def index(self):
        if self._index is None:
            self._index = matching.build_index(self.db, mailbox=self.mailbox)
        return self._index


# --------------------------------------------------------------------------- vault copies
def _raw_root(create: bool = True) -> Path:
    from app.domain import evidence as ev

    root = ev.vault_dir(create=create) / RAW_DIR
    if create:
        root.mkdir(mode=0o700, exist_ok=True)
    return root


def write_raw(raw: bytes) -> str:
    """Store raw inbound MIME in the vault; returns the vault-relative path."""
    root = _raw_root()
    name = f"{uuid.uuid4().hex}.eml"
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
    return f"{RAW_DIR}/{name}"


def _raw_path(rel: str) -> Path:
    root = _raw_root(create=False)
    name = Path(rel or "").name
    if not rel or rel != f"{RAW_DIR}/{name}" or not name.endswith(".eml"):
        raise IngestError("invalid stored mail path")
    return root / name


def read_raw(mm) -> bytes:
    if not mm.mime_path:
        raise IngestError("the raw e-mail is no longer stored")
    data = _raw_path(mm.mime_path).read_bytes()
    if mm.mime_sha256 and hashlib.sha256(data).hexdigest() != mm.mime_sha256:
        raise IngestError("the stored e-mail does not match its recorded sha256")
    return data


def delete_raw(rel: str | None) -> None:
    if not rel:
        return
    try:
        _raw_path(rel).unlink()
    except (FileNotFoundError, IngestError):
        pass


# --------------------------------------------------------------------------- state & lease
def get_state(db: Session, mailbox: str, transport: str):
    M = _M()
    state = db.get(M.MailSyncState, mailbox)
    if state is None:
        state = M.MailSyncState(mailbox=mailbox, transport=transport, last_result={})
        db.add(state)
        try:
            db.commit()
        except Exception:  # noqa: BLE001 - another process created it first
            db.rollback()
            state = db.get(M.MailSyncState, mailbox)
    return state


def acquire_lease(db: Session, mailbox: str, now: datetime) -> bool:
    M = _M()
    res = db.execute(update(M.MailSyncState)
                     .where(M.MailSyncState.mailbox == mailbox,
                            (M.MailSyncState.locked_until.is_(None)) | (M.MailSyncState.locked_until < now))
                     .values(locked_until=now + LEASE, last_started_at=now)
                     .execution_options(synchronize_session=False))
    db.commit()
    return res.rowcount == 1


def lease_held(state, now: datetime | None = None) -> bool:
    until = _aware(getattr(state, "locked_until", None))
    return until is not None and until > (now or _now())


def parse_since(value: str) -> datetime | None:
    v = (value or "").strip()
    if not v:
        return None
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        log.warning("AEGIS_MAIL_INBOUND_SINCE is not an ISO date; ignored")
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def inbound_transport(settings: MailSettings):
    """(transport, problem): the transport to read from, or why inbound cannot run."""
    from app.mail.transport import FileTransport

    name = settings.aegis_mail_transport
    if name == "file":
        t = FileTransport(settings)
        st = t.inbound_status()
        return (t, None) if st.configured else (None, st.reason)
    if name == "graph":
        from app.mail.graph import GraphTransport

        t = GraphTransport(settings)
        st = t.status()
        return (t, None) if st.configured else (None, st.reason)
    return None, "inbound mail needs AEGIS_MAIL_TRANSPORT=file or graph"


# --------------------------------------------------------------------------- per-folder state
def get_folder_state(db: Session, mailbox: str, folder: str, *, since: datetime | None):
    """The mailbox folder's sync row (created with `since` as its backfill start)."""
    M = _M()
    fs = db.get(M.MailSyncFolder, (mailbox, folder))
    if fs is None:
        fs = M.MailSyncFolder(mailbox=mailbox, folder=folder, since=since, last_result={})
        db.add(fs)
        try:
            db.commit()
        except Exception:  # noqa: BLE001 - another process created it first
            db.rollback()
            fs = db.get(M.MailSyncFolder, (mailbox, folder))
    return fs


def folder_states(db: Session, mailbox: str) -> dict[str, object]:
    M = _M()
    rows = db.scalars(select(M.MailSyncFolder).where(M.MailSyncFolder.mailbox == mailbox)).all() if mailbox else []
    return {r.folder: r for r in rows}


def request_backfill(db: Session, mailbox: str, since: datetime, actor=None) -> None:
    """"Backfill since <date>": both folders forget their delta link and start again from `since` on the
    next sync. Messages already stored are recognised (provider id / internetMessageId) and skipped."""
    M = _M()
    since = _aware(since)
    now = _now()
    for folder in FOLDERS:
        fs = get_folder_state(db, mailbox, folder, since=since)
        fs.delta_link = None
        fs.since = since
        fs.backfill_requested_at = now
        fs.backfill_requested_by = getattr(actor, "id", None)
    state = db.get(M.MailSyncState, mailbox)
    if state is not None:
        state.delta_link = None
    db.commit()


def _default_since(settings: MailSettings, state, now: datetime) -> datetime:
    """A new folder's backfill start: AEGIS_MAIL_INBOUND_SINCE, else the mailbox's cutover, else now."""
    return parse_since(settings.aegis_mail_inbound_since) or _aware(getattr(state, "since", None)) or now


# --------------------------------------------------------------------------- sync
def sync_mailbox(db: Session, *, trigger: str, actor=None, transport=None,
                 settings: MailSettings | None = None) -> SyncReport:
    settings = settings or mail_settings()
    mailbox = settings.mail_from
    report = SyncReport(mailbox=mailbox or None, trigger=trigger)
    if transport is None:
        transport, problem = inbound_transport(settings)
        if transport is None:
            report.disabled = problem
            return report
    report.transport = transport.name
    if not mailbox:
        report.disabled = "not configured: set AEGIS_MAIL_FROM"
        return report
    M = _M()
    now = _now()
    state = get_state(db, mailbox, transport.name)
    floor = LETTER_CHECK_MIN_INTERVAL if trigger == "letter_check" else MANUAL_MIN_INTERVAL
    if trigger not in ("scheduler", "backfill") and _aware(state.last_started_at) and \
            _aware(state.last_started_at) > now - floor:
        report.too_soon = True
        return report
    if not acquire_lease(db, mailbox, now):
        report.busy = True
        return report
    db.refresh(state)
    if state.since is None:
        since = parse_since(settings.aegis_mail_inbound_since)
        if since is None and transport.name != "file":
            since = now
        if since is not None:
            state.since = since
    state.transport = transport.name
    db.commit()
    ctx = SyncContext(db=db, transport=transport, settings=settings, mailbox=mailbox, trigger=trigger, actor=actor,
                      since=_aware(state.since))
    batch = None
    inbox_link = None
    try:
        if hasattr(transport, "fetch_folder"):  # graph: Inbox and Sent Items, each with its own delta link
            for folder in SYNC_ORDER:
                link = _sync_folder(ctx, folder, report, default_since=_default_since(settings, state, now))
                if folder == "inbox":
                    inbox_link = link
        else:
            batch = transport.fetch_inbound(state)
            for item in batch:
                report.fetched += 1
                try:
                    _ingest_one(ctx, item, report)
                except Exception as err:  # noqa: BLE001 - one bad message never stops the batch
                    db.rollback()
                    report.errors += 1
                    report.error = report.error or sanitize_error(err)
                    log.warning("mail ingest: one message failed (%s)", type(err).__name__)
    except Exception as err:  # noqa: BLE001 - a fetch failure is recorded on the state row
        db.rollback()
        report.errors += 1
        report.error = report.error or sanitize_error(err)
        log.warning("mail sync failed: %s", report.error)
    finally:
        db.rollback()
        state = db.get(M.MailSyncState, mailbox)
        end = _now()
        if state is not None:
            if batch is not None and batch.complete and report.errors == 0 and batch.delta_link:
                state.delta_link = batch.delta_link
            elif inbox_link:
                state.delta_link = inbox_link  # mirrors the Inbox folder's link (kept for older readers)
            state.locked_until = None
            state.last_finished_at = end
            if not report.error:
                state.last_success_at = end
            state.last_result = {**report.counts(), "trigger": trigger, "at": end.isoformat()}
            state.last_error = report.error
            db.commit()
    return report


def _sync_folder(ctx: SyncContext, folder: str, report: SyncReport, *, default_since: datetime) -> str | None:
    """Read one mailbox folder (graph). Returns the new delta link when the whole batch went through."""
    from app.mail import sync_outbound

    db, M = ctx.db, _M()
    fs = get_folder_state(db, ctx.mailbox, folder, since=default_since)
    if fs.since is None:
        fs.since = default_since
    fs.last_started_at = _now()
    db.commit()
    report.folders.append(folder)
    fctx = SyncContext(db=db, transport=ctx.transport, settings=ctx.settings, mailbox=ctx.mailbox, trigger=ctx.trigger,
                       actor=ctx.actor, since=_aware(fs.since), folder=folder, _index=ctx._index)
    errors = 0
    first_error = None
    seen = 0
    batch = None
    try:
        batch = ctx.transport.fetch_folder(folder, fs)
        items = batch
        if folder == "sentitems":
            # oldest first (Graph's delta lists the newest first): a letter's first send is read before its forward
            # or follow-up, so the first send is what records it (metadata only: nothing is downloaded here)
            items = sorted(batch, key=_sent_order)
        for item in items:
            seen += 1
            if folder == "inbox":
                report.fetched += 1
            else:
                report.bump_sent("fetched")
            try:
                if folder == "inbox":
                    _ingest_one(fctx, item, report)
                else:
                    sync_outbound.process_item(fctx, item, report)
            except Exception as err:  # noqa: BLE001 - one bad message never stops the batch
                db.rollback()
                errors += 1
                first_error = first_error or sanitize_error(err)
                log.warning("mail sync (%s): one message failed (%s)", folder, type(err).__name__)
    except Exception as err:  # noqa: BLE001 - a fetch failure is recorded on the folder row
        db.rollback()
        errors += 1
        first_error = first_error or sanitize_error(err)
        log.warning("mail sync (%s) failed: %s", folder, first_error)
    finally:
        db.rollback()
        ctx._index = fctx._index  # built once per sync, shared by both folders
        if folder == "inbox":
            report.errors += errors
        else:
            report.bump_sent("errors", errors)
        report.error = report.error or first_error
        fs = db.get(M.MailSyncFolder, (ctx.mailbox, folder))
        end = _now()
        link = batch.delta_link if batch is not None and batch.complete and errors == 0 else None
        if fs is not None:
            if link:
                fs.delta_link = link
            fs.last_finished_at = end
            if not first_error:
                fs.last_success_at = end
            fs.last_result = {"seen": seen, "errors": errors, "trigger": ctx.trigger, "at": end.isoformat(),
                              **({k: v for k, v in report.counts().items() if not k.startswith("sent_")}
                                 if folder == "inbox" else dict(report.sent))}
            fs.last_error = first_error
            db.commit()
    return link


def _sent_order(item: InboundItem):
    meta = item.meta or {}
    at = _aware(meta.get("sent_at")) or _aware(item.received_at)
    return (at is None, at or datetime.min.replace(tzinfo=UTC))


def _headers_only(item: InboundItem) -> dict:
    """Subject / From / Message-ID of an oversized message, without loading its body."""
    head = b""
    if item.path is not None:
        try:
            with open(item.path, "rb") as fh:
                head = fh.read(64 * 1024)
        except OSError:
            head = b""
    if head:
        msg = BytesParser(policy=policy.default).parsebytes(head, headersonly=True)
        ids = inbound.message_ids(msg.get("Message-ID"))
        frm = inbound._addr_list(msg.get("From") or "")
        return {"message_id": ids[0] if ids else None, "subject": inbound.clean_header_text(msg.get("Subject")),
                "from_addr": frm[0][1] if frm else None}
    meta = item.meta or {}
    return {"message_id": meta.get("internet_message_id"), "subject": inbound.clean_header_text(meta.get("subject")),
            "from_addr": inbound.clean_header_text(meta.get("from_addr"), 254) or None}


def _exchange_ndr(transport, item: InboundItem, parsed: inbound.ParsedEmail, settings: MailSettings) -> bool:
    """Graph only, and only for a delivery-status report: do the message's internetMessageHeaders
    show Exchange generated it inside our tenant (app.mail.matching.exchange_generated)? A failure
    to read them is "no" (the bounce then waits for review)."""
    if not parsed.bounce or transport.name != "graph" or not hasattr(transport, "message_headers"):
        return False
    try:
        headers = transport.message_headers(item.provider_id)
    except Exception:  # noqa: BLE001 - unreadable headers: review, never a trusted bounce
        log.warning("mail ingest: could not read the internet message headers of a bounce")
        return False
    return matching.exchange_generated(headers, settings.aegis_m365_tenant_id)


# --------------------------------------------------------------------------- data minimisation
def probe_from_meta(item: InboundItem) -> inbound.ParsedEmail:
    """A ParsedEmail of what the folder listing says (no body): for the decision before a download."""
    meta = item.meta or {}
    imid = inbound.message_ids(meta.get("internet_message_id"))
    return inbound.ParsedEmail(message_id=imid[0] if imid else None,
                               subject=inbound.clean_header_text(meta.get("subject")),
                               from_addr=(inbound.clean_header_text(meta.get("from_addr"), 254).lower() or None),
                               to=[str(a).lower() for a in meta.get("to") or []][:100],
                               cc=[str(a).lower() for a in meta.get("cc") or []][:100])


_DSN_SENDER = re.compile(r"^(?:mailer-daemon|mail-daemon|postmaster|maildelivery|mail-delivery|bounces?|"
                         r"microsoftexchange[0-9a-f]{32})(?:[+._-][^@]*)?@", re.IGNORECASE)
_DSN_SUBJECT = re.compile(
    r"^\s*(?:undeliverable|undelivered\s+mail|undeliverable\s+mail|delivery\s+status\s+notification|delivery\s+"
    r"(?:has\s+)?failed|delivery\s+failure|mail\s+delivery\s+(?:failed|failure|subsystem)|returned\s+mail|"
    r"failure\s+notice|non[- ]?delivery|message\s+not\s+delivered|unzustellbar|nicht\s+zustellbar|"
    r"non\s+recapitabile|mancato\s+recapito|impossibile\s+recapitare|non\s+remis|non\s+distribuable|"
    r"échec\s+de\s+(?:la\s+)?remise|no\s+se\s+puede\s+entregar|no\s+entregado|onbestelbaar)\b", re.IGNORECASE)


def dsn_like(meta: dict) -> bool:
    """A delivery-status report by what the folder listing shows (a mailer-daemon / postmaster sender, or an
    "Undeliverable:" / "Delivery Status Notification" subject): read in memory and matched by the original
    Message-ID it carries before it is dropped (data-handling §6.4). Never makes anything a trusted bounce."""
    sender = str((meta or {}).get("from_addr") or "")
    subject = inbound.clean_header_text((meta or {}).get("subject"))
    return bool(_DSN_SENDER.match(sender) or _DSN_SUBJECT.match(subject or ""))


def _headers_say_report(rows) -> bool:
    ctype = next((h.get("value") or "" for h in rows or [] if str(h.get("name") or "").lower() == "content-type"), "")
    return ctype.strip().lower().startswith("multipart/report")


def prescreen(ctx: SyncContext, item: InboundItem) -> matching.Relevance | None:
    """Before downloading a message: could it be case-related? Decided from the folder listing's metadata
    (tag, sender / recipients, subject, conversationId), then, when that finds nothing, from its thread
    headers (In-Reply-To / References) and, for Sent Items, its text body read in memory (rule (c)).
    None means "download it and decide on the full message" (related, or the listing lacked the fields)."""
    meta = item.meta or {}
    folder = ctx.folder or "inbox"
    if folder == "inbox" and not meta.get("from_addr"):
        return None
    if folder == "sentitems" and not (meta.get("to") or meta.get("cc")):
        return None
    probe = probe_from_meta(item)
    rel = matching.assess(ctx.db, probe, folder=folder, index=ctx.index(), conversation_id=meta.get("conversation_id"),
                          mailbox=ctx.mailbox)
    if rel.method == "loop" or rel.store != matching.STORE_NONE:
        return rel if rel.method == "loop" else None
    if folder == "inbox" and dsn_like(meta):
        return None  # (e) a delivery-status report: read, kept only when it returns a stored message
    t = ctx.transport
    if folder == "inbox" and hasattr(t, "message_headers"):
        rows = t.message_headers(item.provider_id)
        probe.in_reply_to = inbound.message_ids(" ".join(h["value"] for h in rows if h["name"].lower() == "in-reply-to"))
        probe.references = inbound.message_ids(" ".join(h["value"] for h in rows if h["name"].lower() == "references"))
        if _headers_say_report(rows):
            return None  # (e) multipart/report from any domain
        if matching.thread_row(ctx.db, probe, meta.get("conversation_id"), mailbox=ctx.mailbox) is not None:
            return None
    elif hasattr(t, "thread_headers"):
        probe.in_reply_to, probe.references = t.thread_headers(item.provider_id)
        row = matching.thread_row(ctx.db, probe, meta.get("conversation_id"), mailbox=ctx.mailbox)
        if row is not None:
            return None
    if folder == "sentitems" and hasattr(t, "text_body"):
        if ctx.index().citing(probe.subject, t.text_body(item.provider_id)):
            return None
    if folder == "inbox" and matching.is_reply_subject(probe.subject) and hasattr(t, "text_body"):
        # (d') a reply from an unknown sender citing the case reference in its text (read in memory only)
        if ctx.index().answering(probe.subject, t.text_body(item.provider_id)):
            return None
    return rel


def _triage_row(ctx: SyncContext, item: InboundItem, parsed: inbound.ParsedEmail, rel: matching.Relevance,
                received: datetime):
    """An Inbox message from an authority's domain that cites nothing: from, subject and date only. The
    body is fetched from the mailbox only when a system admin opens or assigns it (`load_metadata_only`)."""
    M = _M()
    meta = item.meta or {}
    conv = meta.get("conversation_id")
    imid = meta.get("internet_message_id") or parsed.message_id
    return M.MailMessage(
        direction=M.MailDirection.IN, status=M.MailStatus.UNASSIGNED, transport=ctx.transport.name, mailbox=ctx.mailbox,
        message_id=(parsed.message_id or imid or "")[:255], internet_message_id=(imid or None),
        provider_message_id=item.provider_id, conversation_id=conv, graph_conversation_id=conv,
        subject=parsed.subject or None, from_addr=parsed.from_addr, to_addrs=[], cc_addrs=[], attachments=[],
        received_at=received, folder=ctx.folder, match_method="triage",
        match={"method": "triage", "case_id": None, "correspondence_id": None, "confident": False,
               "reason": rel.reason[:200],
               "candidate_case_ids": sorted({c for c, _ in rel.candidates} | set(rel.cited_cases or []))[:20]},
        meta={"trigger": ctx.trigger, "metadata_only": True})


def _known_in_folder(ctx: SyncContext, item: InboundItem) -> bool:
    imid = (item.meta or {}).get("internet_message_id")
    if not imid or not ctx.folder:
        return False
    M = _M()
    return ctx.db.scalar(select(M.MailMessage.id).where(
        M.MailMessage.mailbox == ctx.mailbox, M.MailMessage.folder == ctx.folder,
        M.MailMessage.internet_message_id == imid)) is not None


def _ingest_one(ctx: SyncContext, item: InboundItem, report: SyncReport) -> None:
    db, transport, settings, mailbox, since = ctx.db, ctx.transport, ctx.settings, ctx.mailbox, ctx.since
    trigger, actor = ctx.trigger, ctx.actor
    M = _M()
    exists = db.scalar(select(M.MailMessage.id).where(M.MailMessage.mailbox == mailbox,
                                                      M.MailMessage.provider_message_id == item.provider_id))
    if exists is not None or _known_in_folder(ctx, item):
        report.duplicates += 1
        transport.ack(item)
        return
    received = _aware(item.received_at) or _now()
    if since is not None and received < since:
        report.skipped_old += 1
        transport.ack(item)
        return
    if ctx.minimise:
        pre = prescreen(ctx, item)
        if pre is not None:  # nothing ties it to a case: counted, never downloaded or stored
            report.not_related += 1
            transport.ack(item)
            return
    too_large = bool(item.meta.get("too_large"))
    raw = None
    if not too_large:
        try:
            raw = item.load()
        except TransportError as e:
            if e.reason != "too_large":
                raise
            too_large = True
    if too_large:
        head = _headers_only(item)
        if ctx.minimise:
            probe = inbound.ParsedEmail(message_id=head["message_id"], subject=head["subject"] or "",
                                        from_addr=head["from_addr"])
            rel = matching.assess(db, probe, folder="inbox", index=ctx.index(),
                                  conversation_id=item.meta.get("conversation_id"), mailbox=mailbox)
            if rel.store == matching.STORE_NONE:
                report.not_related += 1
                transport.ack(item)
                return
        mm = M.MailMessage(direction=M.MailDirection.IN, status=M.MailStatus.REJECTED, transport=transport.name,
                           mailbox=mailbox, message_id=(head["message_id"] or "")[:255],
                           provider_message_id=item.provider_id, subject=head["subject"] or None,
                           from_addr=head["from_addr"], to_addrs=[], cc_addrs=[], received_at=received,
                           mime_size=item.meta.get("size"), attachments=[], match={"method": "none"},
                           error_reason="too_large", folder=ctx.folder,
                           error_message="larger than AEGIS_MAIL_MAX_INBOUND_BYTES: read it in the mailbox itself",
                           meta={"trigger": trigger})
        db.add(mm)
        db.commit()
        report.rejected += 1
        report.mail_ids.append(mm.id)
        audit(db, actor, "MAIL_INGESTED", None, mm, mail_message_id=mm.id, method="none", status="rejected",
              case_id=None, reason="too_large")
        transport.ack(item)
        return

    sha = hashlib.sha256(raw).hexdigest()
    dup = db.scalar(select(M.MailMessage.id).where(M.MailMessage.mailbox == mailbox,
                                                   M.MailMessage.direction == M.MailDirection.IN,
                                                   M.MailMessage.mime_sha256 == sha))
    if dup is not None:
        report.duplicates += 1
        transport.ack(item)
        return
    parsed = inbound.parse(raw)
    conv = item.meta.get("conversation_id")
    rel = None
    if ctx.minimise:
        rel = matching.assess(db, parsed, folder="inbox", index=ctx.index(), conversation_id=conv, mailbox=mailbox)
        if rel.store == matching.STORE_NONE:
            report.not_related += 1
            transport.ack(item)
            return
        if rel.store == matching.STORE_TRIAGE:
            mm = _triage_row(ctx, item, parsed, rel, received)
            db.add(mm)
            db.commit()
            report.unassigned += 1
            report.triage += 1
            report.mail_ids.append(mm.id)
            audit(db, actor, "MAIL_INGESTED", None, mm, mail_message_id=mm.id, method="triage", status="unassigned",
                  case_id=None, metadata_only=True)
            transport.ack(item)
            return
    exchange_ndr = _exchange_ndr(transport, item, parsed, settings)
    result = matching.match(db, parsed, mailbox=mailbox, conversation_id=conv,
                            transport=transport.name, exchange_ndr=exchange_ndr)
    if ctx.minimise and result.case_id is not None and matching.is_demo_case(db, result.case_id):
        # a demo / training case never takes part in the real mailbox's matching (Case.is_demo)
        result = matching.MatchResult(matching.NONE, reason="no matching letter")
    if rel is not None and result.method == matching.NONE and rel.case_id is not None:
        # nothing Aegis sent answers it, but it comes from an authority of the case and cites its material:
        # the case admins review it (never filed automatically)
        result = matching.MatchResult(rel.method, rel.case_id, None, False, f"{rel.reason}: review",
                                      sender_domain_ok=bool(rel.candidates) or None,
                                      authenticated=bool(parsed.from_authenticated))
    status = result.status
    mm = M.MailMessage(
        direction=M.MailDirection.IN, status=M.MailStatus(status if status != "received" else "needs_review"),
        transport=transport.name, mailbox=mailbox, message_id=(parsed.message_id or "")[:255],
        internet_message_id=(item.meta.get("internet_message_id") or parsed.message_id or None),
        provider_message_id=item.provider_id, conversation_id=conv, graph_conversation_id=conv if ctx.folder else None,
        in_reply_to=" ".join(parsed.in_reply_to)[:512] or None, references=" ".join(parsed.references) or None,
        subject=parsed.subject or None, from_addr=parsed.from_addr, to_addrs=parsed.to, cc_addrs=parsed.cc,
        mime_sha256=sha, mime_size=len(raw), body_text=parsed.text,
        attachments=[{**a.manifest(), "kind": "inbound", "evidence_id": None, "blocked_reason": None}
                     for a in parsed.attachments],
        match=result.as_meta(), received_at=received,
        case_id=result.case_id if status != "ignored" else None,
        folder=ctx.folder, match_method=(rel.method if rel is not None and result.method == matching.NONE
                                         else result.method)[:32],
        authority_key=(rel.authority_key if rel is not None and rel.case_id == result.case_id else None),
        meta={"trigger": trigger, "auto_reply": parsed.auto_reply, "bounce": parsed.bounce,
              "inline_skipped": parsed.inline_skipped, "html_present": parsed.html_present,
              "parse_defects": parsed.defects, "attachments_truncated": parsed.attachments_truncated,
              "attachments_omitted": parsed.attachments_omitted,
              **({"relevance": rel.method} if rel is not None else {})})
    if status != "ignored":
        mm.mime_path = write_raw(raw)
    db.add(mm)
    db.commit()
    report.mail_ids.append(mm.id)
    if status == "received":
        case = db.get(M.Case, result.case_id)
        orig = db.get(M.Correspondence, result.correspondence_id) if result.correspondence_id else None
        try:
            persist_to_case(db, mm, case, None, orig, actor, raw=raw, parsed=parsed)
        except IngestError as err:
            db.rollback()
            mm = db.get(M.MailMessage, mm.id)
            mm.status = M.MailStatus.NEEDS_REVIEW
            mm.match = {**(mm.match or {}), "confident": False, "reason": f"needs review: {err}"[:200]}
            db.commit()
            status = "needs_review"
    if status == "received":
        report.received += 1
        report.bump_case(mm.case_id, "received")
    elif status == "needs_review":
        report.needs_review += 1
        report.bump_case(mm.case_id, "needs_review")
    elif status == "unassigned":
        report.unassigned += 1
    else:
        report.ignored += 1
    audit(db, actor, "MAIL_INGESTED", mm.case_id, mm, mail_message_id=mm.id, method=result.method,
          status=mm.status.value, case_id=mm.case_id)
    transport.ack(item)


# --------------------------------------------------------------------------- filing
def authority_key_for(corr) -> str | None:
    if corr is None:
        return None
    if corr.entity_id:
        return f"entity-{corr.entity_id}"
    if corr.le_contact_id:
        return f"le-{corr.le_contact_id}"
    return (corr.meta or {}).get("authority_key")


_AUTO_PREFIX = re.compile(r"^\s*(?:(?:automatic reply|auto(?:matic)?[- ]?(?:reply|response)|autoreply|auto|"
                          r"out of (?:the )?office|ooo|abwesenheitsnotiz|risposta automatica|réponse automatique|"
                          r"respuesta automática)\s*:\s*)+", re.IGNORECASE)


def _auto_subject(subject: str | None) -> str:
    """The auto-reply's subject without its own "Automatic reply:" prefix (the timeline entry names it)."""
    return _AUTO_PREFIX.sub("", subject or "").strip() or "(no subject)"


def _day(v: datetime | None) -> str:
    return (_aware(v) or _now()).astimezone(UTC).strftime("%d %b %Y %H:%M UTC")


def persist_to_case(db: Session, mm, case, authority_key: str | None = None, in_reply_to=None, actor=None, *,
                    raw: bytes | None = None, parsed: inbound.ParsedEmail | None = None, status: str = "received"):
    """File an inbound e-mail on `case`: evidence (.eml + attachments), a timeline entry, the row's
    status. Raises IngestError (nothing filed) when the authority cannot be resolved."""
    from app.core import events
    from app.domain import correspondence as desk
    from app.domain import evidence as ev

    M = _M()
    if mm.direction != M.MailDirection.IN:
        raise IngestError("only inbound e-mail can be filed")
    if mm.correspondence_id is not None:
        return db.get(M.Correspondence, mm.correspondence_id)  # already filed (idempotent)
    if case is None:
        raise IngestError("no case")
    orig = in_reply_to
    if orig is None and (mm.match or {}).get("correspondence_id") and (mm.match or {}).get("case_id") == case.id:
        orig = db.get(M.Correspondence, mm.match["correspondence_id"])
    if orig is not None and orig.case_id != case.id:
        raise IngestError("that letter belongs to another case")
    key = authority_key or authority_key_for(orig)
    authority = desk.get_authority(db, case, key) if key else None
    if authority is None:
        raise IngestError("the authority could not be resolved")
    if orig is not None and orig not in authority.correspondence:
        raise IngestError("that letter belongs to another authority")
    if raw is None:
        raw = read_raw(mm)
    if mm.mime_sha256 and hashlib.sha256(raw).hexdigest() != mm.mime_sha256:
        raise IngestError("the e-mail bytes do not match the recorded sha256")
    parsed = parsed or inbound.parse(raw)
    received = _aware(mm.received_at) or _now()
    ref = case.reference

    try:
        eml = ev.store_upload(
            db, case, io.BytesIO(raw), filename=f"{ref}_email-in-{mm.id}.eml", folder=INBOUND_FOLDER,
            title=(f"Reply e-mail to letter #{orig.id} ({_day(received)})" if orig is not None
                   else f"E-mail received ({_day(received)})"),
            source_type="eml", classification="R3", tags=["aegis-mail", "received-email"],
            received_from=mm.from_addr, actor=actor)
    except ev.EvidenceError as err:
        raise IngestError(str(err)) from None
    if eml.sha256 != hashlib.sha256(raw).hexdigest():
        raise IngestError("the filed .eml does not match the received bytes")
    eml.meta = {**(eml.meta or {}), "mail_message_id": mm.id}
    manifest = [dict(a) for a in (mm.attachments or [])]
    att_ids: list[int] = []
    for n, att in enumerate(parsed.attachments, start=1):
        entry = next((m for m in manifest if m.get("sha256") == att.sha256 and m.get("evidence_id") is None), None)
        if not att.data:
            if entry is not None:
                entry["blocked_reason"] = "empty"
            continue
        try:
            item = ev.store_upload(db, case, io.BytesIO(att.data), filename=att.filename_safe, folder=INBOUND_FOLDER,
                                   title=f"Attachment {n} of e-mail #{mm.id}", source_type="email_attachment",
                                   classification="R3",
                                   tags=["aegis-mail", "email-attachment"] + (["dangerous"] if att.dangerous else []),
                                   received_from=mm.from_addr, actor=actor)
        except ev.EvidenceError:
            if entry is not None:
                entry["blocked_reason"] = "unreadable"
            continue
        item.meta = {**(item.meta or {}), "original_filename": att.filename_safe, "dangerous": att.dangerous,
                     "mail_message_id": mm.id}
        att_ids.append(item.id)
        if entry is not None:
            entry["evidence_id"] = item.id
    db.flush()

    thread = (orig.thread_key if orig is not None else None) or mm.message_id or None
    common = {"actor": actor, "channel": "email", "body": parsed.text or "(no text)", "body_format": "text",
              "occurred_at": received, "sender": mm.from_addr, "recipients": list(mm.to_addrs or []),
              "cc": list(mm.cc_addrs or []), "in_reply_to": orig, "evidence_ids": [eml.id, *att_ids],
              "classification": "R3", "thread_key": thread}
    original_mm = None
    if (mm.match or {}).get("original_mail_id"):
        original_mm = db.get(M.MailMessage, mm.match["original_mail_id"])
    if parsed.bounce:
        corr = desk.log_entry(db, case, authority, direction="note", kind="other",
                              subject=(f"Delivery failed for letter #{orig.id}" if orig is not None
                                       else "Delivery failure notice received"), **common)
        if original_mm is not None:
            original_mm.meta = {**(original_mm.meta or {}), "bounced": True, "bounce_mail_id": mm.id}
        events.emit(db, case, events.CORRESPONDENCE_IN, severity="warning",
                    title=(f"{case.reference}: delivery failure for letter #{orig.id}" if orig is not None
                           else f"{case.reference}: delivery failure notice"),
                    body="The case mailbox received a delivery-failure report. Check the recipient address before "
                         "sending again.",
                    link=f"/cases/{case.id}/authorities/{authority.key}#c{corr.id}",
                    payload={"correspondence_id": corr.id, "mail_message_id": mm.id}, commit=False)
    elif parsed.auto_reply:
        corr = desk.log_entry(db, case, authority, direction="note", kind="other",
                              subject=f"Automatic reply received: {_auto_subject(parsed.subject)}"[:512], **common)
    else:
        order = orig.stop_order if orig is not None and orig.stop_order in authority.stop_orders else None
        corr = desk.log_entry(db, case, authority, direction="in", kind="reply",
                              subject=parsed.subject or "(no subject)", stop_order=order, **common)
    corr.meta = {**(corr.meta or {}), "source": "mailbox", "mail_message_id": mm.id, "untrusted_external": True,
                 "auto_reply": bool(parsed.auto_reply), "bounce": bool(parsed.bounce),
                 "sender_domain_ok": (mm.match or {}).get("sender_domain_ok"),
                 "authenticated": (mm.match or {}).get("authenticated"),
                 "attachments_truncated": bool(parsed.attachments_truncated or (mm.meta or {}).get("attachments_truncated")),
                 "attachments_omitted": max(int(parsed.attachments_omitted),
                                            int((mm.meta or {}).get("attachments_omitted") or 0))}
    old_path = mm.mime_path
    mm.status = M.MailStatus(status)
    mm.case_id, mm.correspondence_id, mm.eml_evidence_id = case.id, corr.id, eml.id
    mm.authority_key = authority.key
    mm.attachments = manifest
    mm.mime_path = None
    mm.match = {**(mm.match or {}), "case_id": case.id, "correspondence_id": orig.id if orig is not None else None,
                "authority_key": authority.key}
    db.commit()
    delete_raw(old_path)  # the evidence copy verified above
    block_status_hook(db, case, corr, actor)
    return corr


def block_status_hook(db: Session, case, corr, actor=None) -> None:
    """After a reply is filed: its block-status reading (app.blocks.status.on_reply_filed: the rules, the AI
    when the case's "AI reads mailbox replies" setting allows it, a `block_status_changed` notification).
    Advisory only, never raises, never changes a stop order."""
    try:
        from app.blocks import status as block_status

        block_status.on_reply_filed(db, case, corr, actor=actor)
    except Exception as err:  # noqa: BLE001 - filing never fails because the status reading did
        db.rollback()
        log.warning("block status hook failed for a filed reply (%s)", type(err).__name__)


# --------------------------------------------------------------------------- triage
def _inbound(db: Session, mail_id: int):
    M = _M()
    mm = db.get(M.MailMessage, mail_id)
    if mm is None or mm.direction != M.MailDirection.IN:
        return None
    return mm


def get_inbound(db: Session, mail_id: int):
    return _inbound(db, mail_id)


def _resolve_letter(db: Session, case, authority_key: str, in_reply_to_id):
    from app.domain import correspondence as desk

    M = _M()
    authority = desk.get_authority(db, case, authority_key)
    if authority is None:
        raise IngestError("choose an authority of that case")
    orig = None
    if in_reply_to_id not in (None, ""):
        try:
            cid = int(in_reply_to_id)
        except (TypeError, ValueError):
            raise IngestError("invalid letter id") from None
        orig = db.get(M.Correspondence, cid)
        if orig is None or orig.case_id != case.id or orig not in authority.correspondence \
                or orig.direction != M.CorrespondenceDirection.OUT:
            raise IngestError("that letter is not an outbound letter of the chosen authority")
    return authority, orig


def _check_sender_domain(db: Session, mm, case, authority, orig) -> bool:
    """Is the sender on one of the *chosen* authority's own domains (manual filing)? Recorded in
    mm.match (and so on the filed entry's meta): the pages show the red "sender domain not
    expected" tag when it is not."""
    parsed_domain = (mm.from_addr or "").rpartition("@")[2].lower() or None
    allowed = matching.authority_domains(db, case, authority, orig, mailbox=mm.mailbox)
    ok = matching.domain_ok(parsed_domain, allowed)
    if (mm.meta or {}).get("bounce") and (mm.match or {}).get("method") == matching.HEADER \
            and (mm.match or {}).get("bounce_trusted"):
        ok = True  # a trusted bounce from the case mailbox's own server (matching.trusted_bounce)
    mm.match = {**(mm.match or {}), "sender_domain_ok": ok, "sender_domain_checked_for": authority.key}
    return ok


def is_metadata_only(mm) -> bool:
    return bool((mm.meta or {}).get("metadata_only"))


def load_metadata_only(db: Session, mm, *, actor=None, transport=None, settings: MailSettings | None = None) -> bool:
    """A system admin opens (or assigns) a metadata-only triage row: only now is the message read from the
    mailbox and stored like any unassigned e-mail (vault copy, plain text). Returns True when it loaded it.
    Raises IngestError when the mailbox cannot give it (gone, too large, not configured)."""
    M = _M()
    if not is_metadata_only(mm):
        return False
    if mm.direction != M.MailDirection.IN or mm.status.value not in OPEN_INBOUND:
        raise IngestError("this e-mail was already handled")
    if transport is None:
        transport, problem = inbound_transport(settings or mail_settings())
        if transport is None:
            raise IngestError(f"the mailbox cannot be read: {problem}")
    if not hasattr(transport, "get_mime") or not mm.provider_message_id:
        raise IngestError("this mailbox cannot fetch the message again")
    try:
        raw = transport.get_mime(mm.provider_message_id)
    except TransportError as e:
        raise IngestError(f"the mailbox did not return the message: {e}") from None
    if not raw:
        raise IngestError("the mailbox returned an empty message")
    parsed = inbound.parse(raw)
    mm.message_id = (parsed.message_id or mm.message_id or "")[:255]
    mm.in_reply_to = " ".join(parsed.in_reply_to)[:512] or None
    mm.references = " ".join(parsed.references) or None
    mm.subject, mm.from_addr = parsed.subject or mm.subject, parsed.from_addr or mm.from_addr
    mm.to_addrs, mm.cc_addrs = parsed.to, parsed.cc
    mm.mime_sha256, mm.mime_size, mm.body_text = hashlib.sha256(raw).hexdigest(), len(raw), parsed.text
    mm.attachments = [{**a.manifest(), "kind": "inbound", "evidence_id": None, "blocked_reason": None}
                      for a in parsed.attachments]
    mm.mime_path = write_raw(raw)
    mm.meta = {**(mm.meta or {}), "metadata_only": False, "opened_by": getattr(actor, "id", None),
               "opened_at": _now().isoformat(), "auto_reply": parsed.auto_reply, "bounce": parsed.bounce,
               "html_present": parsed.html_present, "attachments_truncated": parsed.attachments_truncated,
               "attachments_omitted": parsed.attachments_omitted}
    db.commit()
    # every read of a metadata-only message from the mailbox (open or assign) is audited
    audit(db, actor, "MAIL_TRIAGE_OPENED", None, ("mail_messages", mm.id), mail_message_id=mm.id)
    return True


def assign(db: Session, mm, case, *, authority_key: str, in_reply_to_id=None, actor=None):
    """System-admin triage: file an unassigned / needs-review e-mail on a case."""
    if mm.status.value not in OPEN_INBOUND:
        raise IngestError("this e-mail was already handled")
    load_metadata_only(db, mm, actor=actor)
    authority, orig = _resolve_letter(db, case, authority_key, in_reply_to_id)
    _check_sender_domain(db, mm, case, authority, orig)
    corr = persist_to_case(db, mm, case, authority.key, orig, actor, status="assigned")
    mm.assigned_by = actor.id if actor is not None else None
    db.commit()
    return corr


def ignore(db: Session, mm, reason: str, actor=None) -> None:
    M = _M()
    if mm.status.value not in OPEN_INBOUND:
        raise IngestError("this e-mail was already handled")
    mm.status = M.MailStatus.IGNORED
    mm.assigned_by = actor.id if actor is not None else None
    mm.meta = {**(mm.meta or {}), "ignore_reason": inbound.clean_header_text(reason, 200) or None,
               "ignored_at": _now().isoformat()}
    db.commit()


def accept_review(db: Session, mm, case, *, authority_key: str | None = None, in_reply_to_id=None, actor=None):
    """Case-admin review: file a needs-review e-mail on its suggested (or a chosen) authority / letter."""
    if mm.status.value != "needs_review" or mm.case_id != case.id:
        raise IngestError("this e-mail is not waiting for review on this case")
    match = mm.match or {}
    if not authority_key:
        orig = None
        if match.get("correspondence_id"):
            from app.db import models as M

            orig = db.get(M.Correspondence, match["correspondence_id"])
        authority_key = authority_key_for(orig) if orig is not None and orig.case_id == case.id else None
        in_reply_to_id = in_reply_to_id or (orig.id if orig is not None and orig.case_id == case.id else None)
    if not authority_key:
        raise IngestError("choose the authority this e-mail comes from")
    authority, orig = _resolve_letter(db, case, authority_key, in_reply_to_id)
    _check_sender_domain(db, mm, case, authority, orig)
    corr = persist_to_case(db, mm, case, authority.key, orig, actor, status="assigned")
    mm.assigned_by = actor.id if actor is not None else None
    db.commit()
    return corr


def reject_review(db: Session, mm, case, actor=None) -> None:
    """Case-admin review: "not ours" — back to the system admins' unassigned queue."""
    M = _M()
    if mm.status.value != "needs_review" or mm.case_id != case.id:
        raise IngestError("this e-mail is not waiting for review on this case")
    mm.case_id = None
    mm.status = M.MailStatus.UNASSIGNED
    mm.match = {**(mm.match or {}), "case_id": None, "correspondence_id": None, "confident": False,
                "reason": "rejected on case review"}
    mm.meta = {**(mm.meta or {}), "rejected_by": actor.id if actor is not None else None}
    db.commit()


# --------------------------------------------------------------------------- queries for the pages
def unassigned_count(db: Session) -> int:
    M = _M()
    return int(db.scalar(select(func.count(M.MailMessage.id)).where(
        M.MailMessage.direction == M.MailDirection.IN, M.MailMessage.status == M.MailStatus.UNASSIGNED)) or 0)


def review_counts(db: Session) -> list[tuple[int, int]]:
    """(case id, needs-review count) per case."""
    M = _M()
    rows = db.execute(select(M.MailMessage.case_id, func.count(M.MailMessage.id)).where(
        M.MailMessage.direction == M.MailDirection.IN, M.MailMessage.status == M.MailStatus.NEEDS_REVIEW,
        M.MailMessage.case_id.is_not(None)).group_by(M.MailMessage.case_id)).all()
    return [(int(c), int(n)) for c, n in rows]


def case_review_count(db: Session, case_id: int) -> int:
    M = _M()
    return int(db.scalar(select(func.count(M.MailMessage.id)).where(
        M.MailMessage.direction == M.MailDirection.IN, M.MailMessage.status == M.MailStatus.NEEDS_REVIEW,
        M.MailMessage.case_id == case_id)) or 0)
