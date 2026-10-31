"""The mail transport contract (what app.domain.mail_send codes against) and the local transports.

    t = get_transport()                      # from AEGIS_MAIL_TRANSPORT: manual (default) | none | file | graph
    t.status()                               # TransportStatus(name, configured, reason, mailbox)
    res = t.send_mime(raw, message_id=mid)   # SendResult, or raises TransportError
    res = t.send_mime(raw, message_id=mid, bcc=[...])   # hidden recipients (never a header of `raw`)
    t.lookup_sent(message_id=mid, provider_message_id=pid)   # LookupResult(state=sent|draft|missing)

There is deliberately no "resend": after an uncertain send app.domain.mail_send only reconciles
(lookup_sent) and marks the e-mail sent or failed.

* `ManualTransport` (the default, "Draft — you send"): Aegis never transmits anything. It builds the
  draft (an X-Unsent .eml, copy-ready fields, the attachments) and a person sends it from the
  investigations mailbox in Outlook, then records it as sent (app.domain.mail_send.record_external).
  Every transport call raises TransportError("disabled"); it opens no connection of any kind.
* `NoneTransport`: sending is disabled; every call raises TransportError("disabled").
* `FileTransport` (local demos, D6): outbound writes `<UTC>_<sha12>.eml` (0600) to
  AEGIS_MAIL_OUTBOX_DIR; inbound reads `*.eml` from AEGIS_MAIL_INBOX_DIR and moves each processed
  file to `processed/` under it. Both directories must be absolute and outside the repository (the
  outbox also outside the evidence vault).
* `GraphTransport` (app/mail/graph.py): Microsoft 365 through Microsoft Graph.

Inbound (used only inside app.mail): `fetch_inbound(state)` returns an `InboundBatch` of
`InboundItem`s; `ack(item)` is called once an item is stored. The batch's `delta_link` (graph) is
known when it has been iterated to the end; the caller stores it only then.

TransportError messages never carry tokens, secrets, request bodies or e-mail content.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from app.mail.config import MailSettings, mail_settings

REPO_ROOT = Path(__file__).resolve().parents[2]

REASONS = ("disabled", "not_configured", "invalid", "auth", "forbidden", "mailbox_not_found", "too_large",
           "throttled", "server", "network", "unknown_outcome")


@dataclass(frozen=True)
class TransportStatus:
    name: str
    configured: bool
    reason: str
    mailbox: str | None


@dataclass(frozen=True)
class SendResult:
    transport: str
    message_id: str  # our Message-ID header
    internet_message_id: str  # as the server reports it (= message_id for file)
    provider_message_id: str | None = None
    conversation_id: str | None = None
    sent_at: datetime | None = None
    detail: dict = field(default_factory=dict)  # ids only


@dataclass(frozen=True)
class LookupResult:
    state: Literal["sent", "draft", "missing"]
    result: SendResult | None = None


class TransportError(Exception):
    def __init__(self, reason: str, message: str = "", *, retryable: bool = False, outcome_unknown: bool = False,
                 status: int | None = None, provider_message_id: str | None = None):
        self.reason = reason if reason in REASONS else "invalid"
        self.message = (message or reason)[:512]
        self.retryable = retryable
        self.outcome_unknown = outcome_unknown
        self.status = status
        self.provider_message_id = provider_message_id
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


class MailTransport(Protocol):
    name: str

    def status(self) -> TransportStatus: ...

    def send_mime(self, raw: bytes, *, message_id: str, bcc: list[str] | None = None) -> SendResult: ...

    def lookup_sent(self, *, message_id: str, provider_message_id: str | None) -> LookupResult: ...


# --------------------------------------------------------------------------- inbound plumbing
@dataclass
class InboundItem:
    """One inbound message. `raw` is loaded on demand by `load()` (graph: GET …/$value)."""

    provider_id: str
    received_at: datetime | None
    meta: dict = field(default_factory=dict)
    raw: bytes | None = None
    loader: Callable[[], bytes] | None = None
    path: Path | None = None  # file transport: the inbox file

    def load(self) -> bytes:
        if self.raw is None and self.loader is not None:
            self.raw = self.loader()
        if self.raw is None:
            raise TransportError("invalid", "message content is not available")
        return self.raw


class InboundBatch:
    """Iterate once. `delta_link` is set (graph) once the iteration has reached the end."""

    def __init__(self, source: Iterable[InboundItem] | Callable[[InboundBatch], Iterator[InboundItem]]):
        self.delta_link: str | None = None
        self.complete = False
        self._source = source

    def __iter__(self) -> Iterator[InboundItem]:
        it = self._source(self) if callable(self._source) else iter(self._source)
        yield from it
        self.complete = True


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _vault_root() -> Path | None:
    from app.domain.evidence import configured_vault_dir  # late: keeps this module import-light

    raw = configured_vault_dir()
    if not raw:
        return None
    try:
        return Path(raw).expanduser().resolve()
    except OSError:
        return None


def check_local_dir(raw: str, label: str, *, forbid_vault: bool = False) -> Path:
    """An absolute directory outside the repository (and the vault). Raises TransportError."""
    value = (raw or "").strip()
    if not value:
        raise TransportError("not_configured", f"{label} is not set")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise TransportError("not_configured", f"{label} must be an absolute path")
    try:
        resolved = path.resolve()
    except OSError:
        raise TransportError("not_configured", f"{label} cannot be resolved") from None
    if resolved.is_relative_to(REPO_ROOT.resolve()):
        raise TransportError("not_configured", f"{label} is inside the repository: refusing to write mail there")
    if forbid_vault:
        vault = _vault_root()
        if vault is not None and (resolved.is_relative_to(vault) or vault.is_relative_to(resolved)):
            raise TransportError("not_configured", f"{label} must be outside the evidence vault")
    return resolved


# --------------------------------------------------------------------------- none
class NoneTransport:
    name = "none"

    def __init__(self, settings: MailSettings | None = None):
        self.settings = settings or mail_settings()

    def status(self) -> TransportStatus:
        return TransportStatus("none", False, "Sending is disabled (AEGIS_MAIL_TRANSPORT=none)",
                               self.settings.mail_from or None)

    def _disabled(self):
        raise TransportError("disabled", "Sending is disabled (AEGIS_MAIL_TRANSPORT=none)")

    def send_mime(self, raw: bytes, *, message_id: str, bcc: list[str] | None = None) -> SendResult:
        self._disabled()

    def lookup_sent(self, *, message_id: str, provider_message_id: str | None) -> LookupResult:
        self._disabled()

    def fetch_inbound(self, state=None) -> InboundBatch:
        self._disabled()


# --------------------------------------------------------------------------- manual
MANUAL_TEXT = "Manual mode (AEGIS_MAIL_TRANSPORT=manual): Aegis drafts the e-mail, you send it from Outlook"


class ManualTransport(NoneTransport):
    """"Draft — you send": nothing ever leaves Aegis through a transport (no network, no files)."""

    name = "manual"

    def status(self) -> TransportStatus:
        return TransportStatus("manual", False, MANUAL_TEXT, self.settings.mail_from or None)

    def _disabled(self):
        raise TransportError("disabled", MANUAL_TEXT)


# --------------------------------------------------------------------------- file
def _header_message_id(path: Path) -> str | None:
    """The Message-ID header of an .eml file (headers only, first 64 KB)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(64 * 1024)
    except OSError:
        return None
    head = head.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    for line in head.replace(b"\r\n", b"\n").split(b"\n"):
        if line[:11].lower() == b"message-id:":
            return line[11:].strip().decode("ascii", "replace")
    return None


class FileTransport:
    """Writes outbound mail as .eml files and reads inbound .eml files (local demos only)."""

    name = "file"
    PROCESSED = "processed"

    def __init__(self, settings: MailSettings | None = None, *, now: Callable[[], datetime] = _now):
        self.settings = settings or mail_settings()
        self._now = now

    # outbound
    def outbox(self) -> Path:
        return check_local_dir(self.settings.aegis_mail_outbox_dir, "AEGIS_MAIL_OUTBOX_DIR", forbid_vault=True)

    def status(self) -> TransportStatus:
        mailbox = self.settings.mail_from or None
        try:
            self.outbox()
        except TransportError as e:
            return TransportStatus("file", False, e.message, mailbox)
        if not mailbox:
            return TransportStatus("file", False, "not configured: set AEGIS_MAIL_FROM", None)
        return TransportStatus("file", True, "Writes .eml files to the local outbox (demo transport)", mailbox)

    def send_mime(self, raw: bytes, *, message_id: str, bcc: list[str] | None = None) -> SendResult:
        """Write the exact bytes to the outbox. Bcc addresses (the envelope only, never a header) are
        written next to it as `<name>.bcc` (one address per line, 0600), like a delivery log, before the
        .eml: an .eml in the outbox (what `lookup_sent` reports as sent) always has its Bcc beside it."""
        if not raw:
            raise TransportError("invalid", "empty message")
        if len(raw) > self.settings.max_message_bytes:
            raise TransportError("too_large", "the message is larger than AEGIS_MAIL_MAX_MESSAGE_BYTES")
        outbox = self.outbox()
        try:
            outbox.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            raise TransportError("server", "the outbox directory cannot be created") from None
        now = self._now()
        sha = hashlib.sha256(raw).hexdigest()
        name = f"{now.astimezone(UTC):%Y%m%dT%H%M%SZ}_{sha[:12]}.eml"
        path = outbox / name
        if path.exists():  # the very same bytes in the same second: already written (idempotent)
            return self._result(name, message_id, now)
        try:
            if bcc:
                bfd = os.open(outbox / f"{name}.bcc", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(bfd, "w", encoding="ascii") as fh:
                    fh.write("".join(f"{a}\n" for a in bcc))
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return self._result(name, message_id, now)  # written meanwhile by the same call (idempotent)
        except OSError:
            raise TransportError("server", "the outbox is not writable") from None
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw)
        except OSError:
            raise TransportError("server", "writing to the outbox failed") from None
        return self._result(name, message_id, now)

    def _result(self, name: str, message_id: str, sent_at: datetime) -> SendResult:
        return SendResult(transport="file", message_id=message_id, internet_message_id=message_id,
                          provider_message_id=f"file:{name}", sent_at=sent_at, detail={"file": name})

    def lookup_sent(self, *, message_id: str, provider_message_id: str | None) -> LookupResult:
        outbox = self.outbox()
        if provider_message_id and provider_message_id.startswith("file:"):
            name = Path(provider_message_id[5:]).name
            path = outbox / name
            if path.is_file() and not path.is_symlink():
                ts = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
                return LookupResult("sent", self._result(name, message_id, ts))
            return LookupResult("missing")
        if outbox.is_dir():
            for path in sorted(outbox.glob("*.eml")):
                if path.is_file() and not path.is_symlink() and _header_message_id(path) == message_id:
                    ts = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
                    return LookupResult("sent", self._result(path.name, message_id, ts))
        return LookupResult("missing")

    # inbound
    def inbox(self) -> Path:
        return check_local_dir(self.settings.aegis_mail_inbox_dir, "AEGIS_MAIL_INBOX_DIR", forbid_vault=True)

    def inbound_status(self) -> TransportStatus:
        try:
            self.inbox()
        except TransportError as e:
            return TransportStatus("file", False, e.message, self.settings.mail_from or None)
        return TransportStatus("file", True, "Reads .eml files from the local inbox folder",
                               self.settings.mail_from or None)

    def fetch_inbound(self, state=None) -> InboundBatch:
        inbox = self.inbox()
        limit = self.settings.max_inbound_bytes

        def items(_batch: InboundBatch) -> Iterator[InboundItem]:
            if not inbox.is_dir():
                return
            for path in sorted(inbox.glob("*.eml")):
                try:
                    st = path.lstat()
                except OSError:
                    continue
                if path.is_symlink() or not path.is_file():
                    continue
                received = datetime.fromtimestamp(st.st_mtime, tz=UTC)
                meta = {"size": st.st_size}
                if st.st_size > limit:
                    meta["too_large"] = True
                    yield InboundItem(provider_id=f"file:{path.name}", received_at=received, meta=meta, path=path)
                    continue
                yield InboundItem(provider_id=f"file:{path.name}", received_at=received, meta=meta, path=path,
                                  loader=lambda p=path: _read_regular(p, limit))

        return InboundBatch(items)

    def ack(self, item: InboundItem) -> None:
        """Move a processed inbox file to processed/ (never overwriting an earlier one)."""
        if item.path is None:
            return
        done = self.inbox() / self.PROCESSED
        done.mkdir(mode=0o700, exist_ok=True)
        target = done / item.path.name
        n = 1
        while target.exists():
            target = done / f"{item.path.stem}.{n}{item.path.suffix}"
            n += 1
        try:
            os.replace(item.path, target)
        except FileNotFoundError:
            pass


def _read_regular(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise TransportError("too_large", "the message is larger than AEGIS_MAIL_MAX_INBOUND_BYTES")
    return data


# --------------------------------------------------------------------------- factory
def get_transport(settings: MailSettings | None = None) -> MailTransport:
    s = settings or mail_settings()
    if s.aegis_mail_transport == "file":
        return FileTransport(s)
    if s.aegis_mail_transport == "graph":
        from app.mail.graph import GraphTransport

        return GraphTransport(s)
    if s.aegis_mail_transport == "none":
        return NoneTransport(s)
    return ManualTransport(s)
