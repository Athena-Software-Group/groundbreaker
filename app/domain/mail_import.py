"""Import a reply by hand: an .eml or Outlook .msg file uploaded on a case (the e-mail desk, manual mode).

Owner: the mail feature (routes in app/web/routes_mail.py: POST /cases/{id}/mail/import, the
authority page's "How to email" panel and the case page /cases/{id}/mail/import).

    res = import_reply(db, access, filename, data, authority=None)   # ImportResult(mm, duplicate, …)
    raw = msg_to_eml(data)                                           # Outlook .msg -> RFC 5322 bytes

In "Draft — you send" mode Aegis reads no mailbox: a member saves the reply from Outlook (.msg, or
.eml) and uploads it. The bytes go through the same inbound pipeline as the mailbox (app.mail.inbound
parse, app.mail.matching with **file-transport semantics**: an upload is never trusted, nothing is
filed automatically) and the message waits on the case's **Mail to review** with the letter it
answers pre-selected (the tracking tag in the subject; else, when uploaded on an authority's page,
that authority's latest letter). A case admin accepts it there (app.mail.ingest.accept_review), and
only then is it filed on the timeline (evidence .eml + attachments, the reply clock stopped).

Rules: investigators and up (`log_correspondence`); at most AEGIS_MAIL_MAX_INBOUND_BYTES (25 MiB);
the same bytes are imported once per case (a .msg converts to the same .eml every time: fixed MIME
boundaries); a file the parser cannot read (e.g. MIME nested thousands deep) is refused with a 400; a match to another case's letter is dropped (an upload
never reveals or touches another case); a message sent *from* the case mailbox is refused (record
your own send on the e-mail's preview instead). An uploaded .msg is converted to an .eml for the
pipeline and the original .msg is kept as an R3 evidence item (never attachable: it is a received
e-mail). Inbound content stays untrusted data: it changes no status and sends nothing.

The .msg reader is a small, defensive reader of the OLE compound-file format (MS-CFB) and the
Outlook message properties (MS-OXMSG): subject, body (text / HTML), transport headers, sender,
recipients, attachments. Embedded messages inside a .msg are skipped (counted as omitted). It reads
only the property streams it uses, skips a stream declared larger than the file or starting where
another stream starts, and stops (MsgError) once it has copied READ_BUDGET_FACTOR times the file size:
a crafted file cannot make it allocate more than that.
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime, formataddr

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import (
    Correspondence,
    CorrespondenceDirection,
    CorrespondenceStatus,
    MailDirection,
    MailMessage,
    MailStatus,
)
from app.domain.mail_compose import SEND_POLICY

UPLOAD_EXTS = (".eml", ".msg")
CFB_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
FREE, END, FAT_SECT, DIFAT_SECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF
MAX_ENTRIES = 4096  # directory entries read from one .msg
MAX_ATTACHMENTS = 25
MAX_RECIPIENTS = 500
READ_BUDGET_FACTOR = 4  # bytes read out of a .msg (sectors, streams) at most this many times the file size


class MailImportError(ValueError):
    """An upload that cannot be imported (shown to the member, HTTP 400)."""


class MsgError(MailImportError):
    pass


def _now() -> datetime:
    return datetime.now(tz=UTC)


# --------------------------------------------------------------------------- MS-CFB (compound file) reader
@dataclass
class _Entry:
    name: str
    kind: int  # 1 storage, 2 stream, 5 root
    left: int
    right: int
    child: int
    start: int
    size: int


class CompoundFile:
    """Read-only access to the streams of an OLE compound file (version 3 or 4)."""

    def __init__(self, data: bytes):
        if len(data) < 512 or not data.startswith(CFB_MAGIC):
            raise MsgError("not an Outlook .msg file (no compound-file header)")
        self.data = data
        # every byte copied out of the file counts against one budget (a crafted file can point many
        # directory entries at one long sector chain: entries x size bytes otherwise)
        self.budget = READ_BUDGET_FACTOR * len(data)
        self.claimed: dict[tuple[bool, int], int] = {}  # (mini stream?, start sector) -> the entry that read it
        (major, byte_order, sector_shift, mini_shift) = struct.unpack_from("<HHHH", data, 0x1A)
        if byte_order != 0xFFFE or major not in (3, 4) or sector_shift not in (9, 12) or mini_shift != 6:
            raise MsgError("unsupported compound-file header")
        self.ssize = 1 << sector_shift
        self.mini_size = 1 << mini_shift
        n_fat, self.first_dir = struct.unpack_from("<II", data, 0x2C)  # FAT sector count, first directory sector
        self.cutoff = struct.unpack_from("<I", data, 0x38)[0] or 4096
        first_minifat, n_minifat, first_difat, n_difat = struct.unpack_from("<IIII", data, 0x3C)
        self.n_sectors = max(0, (len(data) - self.ssize) // self.ssize)
        difat = [v for v in struct.unpack_from("<109I", data, 0x4C) if v not in (FREE, END)]
        sect, seen = first_difat, set()
        per = self.ssize // 4 - 1
        while sect not in (FREE, END) and len(seen) < max(n_difat, 0) + 1 and sect < self.n_sectors:
            if sect in seen:
                raise MsgError("corrupt compound file (DIFAT loop)")
            seen.add(sect)
            vals = struct.unpack_from(f"<{per + 1}I", self._sector(sect))
            difat += [v for v in vals[:per] if v not in (FREE, END)]
            sect = vals[per]
        difat = difat[:n_fat] if n_fat else difat
        fat_bytes = b"".join(self._sector(s) for s in difat if s < self.n_sectors)
        self.fat = list(struct.unpack(f"<{len(fat_bytes) // 4}I", fat_bytes))
        minifat_bytes = self._chain_bytes(first_minifat) if n_minifat and first_minifat not in (FREE, END) else b""
        self.minifat = list(struct.unpack(f"<{len(minifat_bytes) // 4}I", minifat_bytes))
        dir_bytes = self._chain_bytes(self.first_dir)
        self.entries: list[_Entry] = []
        for off in range(0, min(len(dir_bytes), MAX_ENTRIES * 128), 128):
            raw = dir_bytes[off:off + 128]
            if len(raw) < 128:
                break
            name_len = struct.unpack_from("<H", raw, 64)[0]
            name = raw[:max(0, min(name_len, 64) - 2)].decode("utf-16-le", "replace")
            kind = raw[66]
            left, right, child = struct.unpack_from("<III", raw, 68)
            start = struct.unpack_from("<I", raw, 116)[0]
            size = struct.unpack_from("<Q", raw, 120)[0]
            if major == 3:
                size &= 0xFFFFFFFF
            self.entries.append(_Entry(name, kind, left, right, child, start, size))
        if not self.entries or self.entries[0].kind != 5:
            raise MsgError("corrupt compound file (no root entry)")
        root = self.entries[0]
        self.ministream = self._chain_bytes(root.start)[:root.size] if root.start not in (FREE, END) else b""

    def _spend(self, n: int) -> None:
        self.budget -= n
        if self.budget < 0:
            raise MsgError("corrupt compound file (streams larger than the file)")

    def _sector(self, n: int) -> bytes:
        off = (n + 1) * self.ssize
        if n >= self.n_sectors or off + self.ssize > len(self.data):
            raise MsgError("corrupt compound file (sector out of range)")
        self._spend(self.ssize)
        return self.data[off:off + self.ssize]

    def _chain_bytes(self, start: int, size: int | None = None) -> bytes:
        """The sectors of a chain (only as many as `size` needs, when given)."""
        out, sect, seen = [], start, set()
        while sect not in (FREE, END) and (size is None or len(out) * self.ssize < size):
            if sect in seen or sect >= len(self.fat) or len(seen) > self.n_sectors:
                raise MsgError("corrupt compound file (sector chain)")
            seen.add(sect)
            out.append(self._sector(sect))
            sect = self.fat[sect]
        return b"".join(out)

    def _mini_bytes(self, start: int, size: int) -> bytes:
        out, sect, seen = [], start, set()
        while sect not in (FREE, END) and len(out) * self.mini_size < size:
            if sect in seen or sect >= len(self.minifat):
                raise MsgError("corrupt compound file (mini chain)")
            seen.add(sect)
            off = sect * self.mini_size
            self._spend(self.mini_size)
            out.append(self.ministream[off:off + self.mini_size])
            sect = self.minifat[sect]
        return b"".join(out)[:size]

    def children(self, idx: int) -> list[int]:
        """Entry ids directly inside storage `idx` (an in-order walk of its red-black tree)."""
        out: list[int] = []
        stack, seen = [], set()
        node = self.entries[idx].child if idx < len(self.entries) else NOSTREAM
        while (stack or node != NOSTREAM) and len(seen) <= len(self.entries):
            while node != NOSTREAM and node < len(self.entries) and node not in seen:
                stack.append(node)
                node = self.entries[node].left
            if not stack:
                break
            node = stack.pop()
            seen.add(node)
            out.append(node)
            node = self.entries[node].right
        return out

    def stream(self, idx: int) -> bytes:
        """One stream's bytes. A stream declared larger than the file, or starting where another entry's
        stream already started (no real file shares sectors), reads as empty."""
        e = self.entries[idx]
        if e.kind != 2 or e.size == 0 or e.size > len(self.data) or e.start in (FREE, END):
            return b""
        mini = e.size < self.cutoff
        owner = self.claimed.setdefault((mini, e.start), idx)
        if owner != idx:
            return b""
        if mini:
            return self._mini_bytes(e.start, e.size)
        return self._chain_bytes(e.start, e.size)[:e.size]

    def named(self, idx: int) -> dict[str, int]:
        return {self.entries[i].name: i for i in self.children(idx)}


# --------------------------------------------------------------------------- MS-OXMSG properties
PR_SUBJECT, PR_BODY, PR_HTML, PR_HEADERS = 0x0037, 0x1000, 0x1013, 0x007D
PR_SENDER_EMAIL, PR_SENDER_SMTP, PR_SENDER_NAME = 0x0C1F, 0x5D01, 0x0C1A
PR_MESSAGE_ID, PR_IN_REPLY_TO, PR_REFERENCES = 0x1035, 0x1042, 0x1039
PR_DISPLAY_NAME, PR_EMAIL_ADDRESS, PR_SMTP_ADDRESS, PR_RECIPIENT_TYPE = 0x3001, 0x3003, 0x39FE, 0x0C15
PR_ATTACH_DATA, PR_ATTACH_FILENAME, PR_ATTACH_LONG_FILENAME, PR_ATTACH_MIME = 0x3701, 0x3704, 0x3707, 0x370E
PR_CLIENT_SUBMIT_TIME, PR_DELIVERY_TIME = 0x0039, 0x0E06
_SUBSTG = re.compile(r"__substg1\.0_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})")


TOP_PROPS = frozenset({PR_SUBJECT, PR_BODY, PR_HTML, PR_HEADERS, PR_SENDER_EMAIL, PR_SENDER_SMTP, PR_SENDER_NAME,
                       PR_MESSAGE_ID, PR_IN_REPLY_TO, PR_REFERENCES})
RECIP_PROPS = frozenset({PR_DISPLAY_NAME, PR_EMAIL_ADDRESS, PR_SMTP_ADDRESS})
ATTACH_PROPS = frozenset({PR_ATTACH_DATA, PR_ATTACH_FILENAME, PR_ATTACH_LONG_FILENAME, PR_ATTACH_MIME})


def _props(cf: CompoundFile, idx: int, wanted: frozenset[int]) -> dict[int, object]:
    """The variable-length properties (strings, binaries) in `wanted` of one storage: {prop id: str | bytes}.
    Other property streams are never read."""
    out: dict[int, object] = {}
    for name, i in cf.named(idx).items():
        m = _SUBSTG.fullmatch(name)
        if not m or cf.entries[i].kind != 2:
            continue
        pid, ptype = int(m.group(1), 16), int(m.group(2), 16)
        if pid not in wanted or ptype not in (0x001F, 0x001E, 0x0102):
            continue
        data = cf.stream(i)
        if ptype == 0x001F:
            out[pid] = data.decode("utf-16-le", "replace").rstrip("\x00")
        elif ptype == 0x001E:
            out[pid] = data.decode("cp1252", "replace").rstrip("\x00")
        elif ptype == 0x0102:
            out[pid] = data
    return out


def _fixed(cf: CompoundFile, idx: int, header: int) -> dict[int, bytes]:
    """Fixed-length properties from `__properties_version1.0` ({prop id: 8 value bytes})."""
    i = cf.named(idx).get("__properties_version1.0")
    if i is None:
        return {}
    data = cf.stream(i)[header:header + 16 * 1024]  # a property table is a few hundred bytes
    out = {}
    for off in range(0, len(data) - 15, 16):
        tag, _flags = struct.unpack_from("<II", data, off)
        out[tag >> 16] = data[off + 8:off + 16]
    return out


def _filetime(v: bytes | None) -> datetime | None:
    if not v or len(v) < 8:
        return None
    ticks = struct.unpack("<Q", v[:8])[0]
    if not ticks:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=ticks // 10)
    except OverflowError:
        return None


_CTL = re.compile("[\x00-\x08\x0a-\x1f\x7f  ]+")


def _hdr(value) -> str:
    return " ".join(_CTL.sub(" ", str(value or "")).split())[:998]


def _addr(v: str | None) -> str | None:
    s = _hdr(v)
    return s if re.fullmatch(r"[^@\s<>]+@[^@\s<>]+", s) else None


@dataclass
class MsgMessage:
    subject: str
    body: str
    html: str | None
    headers: str | None
    sender: str | None
    sender_name: str | None
    to: list[tuple[str, str]]
    cc: list[tuple[str, str]]
    message_id: str | None
    in_reply_to: str | None
    references: str | None
    sent_at: datetime | None
    attachments: list[tuple[str, str, bytes]]
    omitted: int = 0


def read_msg(data: bytes) -> MsgMessage:
    cf = CompoundFile(data)
    top = _props(cf, 0, TOP_PROPS)
    fixed = _fixed(cf, 0, 32)
    to, cc, atts, omitted = [], [], [], 0
    for name, i in cf.named(0).items():
        if cf.entries[i].kind != 1:
            continue
        if name.startswith("__recip_version1.0_"):
            if len(to) + len(cc) >= MAX_RECIPIENTS:
                continue
            p = _props(cf, i, RECIP_PROPS)
            addr = _addr(p.get(PR_SMTP_ADDRESS)) or _addr(p.get(PR_EMAIL_ADDRESS))
            if not addr:
                continue
            rtype = struct.unpack("<I", _fixed(cf, i, 8).get(PR_RECIPIENT_TYPE, b"\x01\0\0\0")[:4])[0] & 0x0F
            (cc if rtype == 2 else to if rtype == 1 else []).append((_hdr(p.get(PR_DISPLAY_NAME)), addr))
        elif name.startswith("__attach_version1.0_"):
            if len(atts) >= MAX_ATTACHMENTS:
                omitted += 1
                continue
            p = _props(cf, i, ATTACH_PROPS)
            blob = p.get(PR_ATTACH_DATA)
            if not isinstance(blob, bytes):
                omitted += 1  # an embedded message or an OLE object: only in the original .msg
                continue
            fname = _hdr(p.get(PR_ATTACH_LONG_FILENAME) or p.get(PR_ATTACH_FILENAME) or f"attachment-{len(atts) + 1}")
            mime = _hdr(p.get(PR_ATTACH_MIME)).lower()
            atts.append((fname, mime if re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", mime) else "application/octet-stream",
                         blob))
    html = top.get(PR_HTML)
    if isinstance(html, bytes):
        html = html.decode("utf-8", "replace")
    return MsgMessage(
        subject=_hdr(top.get(PR_SUBJECT)), body=str(top.get(PR_BODY) or ""), html=html or None,
        headers=str(top.get(PR_HEADERS) or "") or None,
        sender=_addr(top.get(PR_SENDER_SMTP)) or _addr(top.get(PR_SENDER_EMAIL)), sender_name=_hdr(top.get(PR_SENDER_NAME)),
        to=to, cc=cc, message_id=_hdr(top.get(PR_MESSAGE_ID)) or None, in_reply_to=_hdr(top.get(PR_IN_REPLY_TO)) or None,
        references=_hdr(top.get(PR_REFERENCES)) or None,
        sent_at=_filetime(fixed.get(PR_CLIENT_SUBMIT_TIME)) or _filetime(fixed.get(PR_DELIVERY_TIME)),
        attachments=atts, omitted=omitted)


KEEP_HEADERS = ("From", "Sender", "To", "Cc", "Reply-To", "Subject", "Date", "Message-ID", "In-Reply-To", "References",
                "Authentication-Results", "Auto-Submitted", "X-Auto-Response-Suppress", "Precedence")


def msg_to_eml(data: bytes) -> bytes:
    """Convert an Outlook .msg to RFC 5322 bytes for the inbound pipeline: the original transport
    headers when the .msg kept them (a received message does), else headers rebuilt from the
    message properties; the text (and HTML) body; the file attachments."""
    m = read_msg(data)
    out = EmailMessage(policy=SEND_POLICY)
    hdrs = None
    if m.headers:
        hdrs = BytesParser(policy=policy.default).parsebytes(m.headers.encode("utf-8", "replace") + b"\r\n\r\n",
                                                            headersonly=True)
    for name in KEEP_HEADERS:
        value = None
        if hdrs is not None and hdrs.get(name) is not None:
            value = _hdr(hdrs.get(name))
        if not value:
            value = {
                "From": formataddr((m.sender_name or "", m.sender)) if m.sender else None,
                "To": ", ".join(formataddr(r) for r in m.to) or None,
                "Cc": ", ".join(formataddr(r) for r in m.cc) or None,
                "Subject": m.subject or None,
                "Date": format_datetime(m.sent_at) if m.sent_at else None,
                "Message-ID": m.message_id, "In-Reply-To": m.in_reply_to, "References": m.references,
            }.get(name)
        if value:
            try:
                out[name] = value
            except (ValueError, TypeError):
                continue
    out.set_content(m.body or "", subtype="plain", charset="utf-8")
    if m.html:
        out.add_alternative(m.html, subtype="html", charset="utf-8")
    if m.attachments:
        out.make_mixed()
        for name, mime, blob in m.attachments:
            maintype, _, subtype = mime.partition("/")
            out.add_attachment(blob, maintype=maintype or "application", subtype=subtype or "octet-stream",
                               filename=name)
    # fixed MIME boundaries derived from the .msg's own bytes: the same .msg always converts to the same
    # .eml, so the same upload is recognised (mime_sha256) and imported once
    seed = hashlib.sha256(data).hexdigest()[:32]
    for n, part in enumerate(p for p in out.walk() if p.is_multipart()):
        part.set_boundary(f"=_aegis_{seed}_{n}")
    return out.as_bytes()


# --------------------------------------------------------------------------- import
@dataclass
class ImportResult:
    mm: MailMessage
    duplicate: bool = False
    letter_id: int | None = None  # the letter pre-selected for review
    method: str = "upload"
    original_evidence_id: int | None = None  # an uploaded .msg, kept as is


def _settings():
    from app.domain import mail_send

    return mail_send._settings()


def _latest_letter(authority) -> Correspondence | None:
    sent = [c for c in getattr(authority, "correspondence", None) or []
            if c.direction == CorrespondenceDirection.OUT and c.status == CorrespondenceStatus.SENT]
    return max(sent, key=lambda c: ((c.occurred_at or c.created_at or datetime.min).replace(tzinfo=None), c.id or 0),
               default=None)


def import_reply(db: Session, access, filename: str, data: bytes, authority=None) -> ImportResult:
    """Parse and queue one uploaded reply for review on this case (module doc). The caller audits."""
    from app.domain import evidence as ev
    from app.mail import inbound, ingest, matching

    if not access.can("log_correspondence"):
        raise MailImportError("your role cannot import e-mail")
    settings = _settings()
    name = (filename or "").strip()
    ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
    if not data:
        raise MailImportError("the file is empty")
    if ext not in UPLOAD_EXTS:
        ext = ".msg" if data.startswith(CFB_MAGIC) else ""
    if ext not in UPLOAD_EXTS:
        raise MailImportError("upload the reply as an .eml or .msg file (Outlook: File → Save As, or drag it out)")
    limit = int(getattr(settings, "max_inbound_bytes", 25 * 1024 * 1024))
    if len(data) > limit:
        raise MailImportError(f"the file is larger than {limit // (1 << 20)} MB")
    ok, _why = ev.vault_status()
    if not ok:
        raise MailImportError("AEGIS_VAULT_DIR must be set: imported e-mail is kept in the vault")
    original = None
    if ext == ".msg":
        original = data
        try:
            raw = msg_to_eml(data)
        except MailImportError:
            raise
        except (RecursionError, MemoryError, ValueError, TypeError, struct.error, LookupError) as exc:
            raise MailImportError("this .msg file could not be read") from exc
    else:
        raw = data
        head = BytesParser(policy=policy.default).parsebytes(raw[:256 * 1024], headersonly=True)
        if not (head.get("From") or head.get("Subject")):
            raise MailImportError("this .eml file has no e-mail headers (From / Subject)")
    case = access.case
    sha = hashlib.sha256(raw).hexdigest()
    dup = db.scalar(select(MailMessage).where(MailMessage.case_id == case.id, MailMessage.direction == MailDirection.IN,
                                              MailMessage.mime_sha256 == sha).order_by(MailMessage.id).limit(1))
    if dup is not None:
        return ImportResult(dup, duplicate=True, letter_id=(dup.match or {}).get("correspondence_id"),
                            method=(dup.match or {}).get("method") or "upload")
    try:
        parsed = inbound.parse(raw)
    except (RecursionError, MemoryError) as exc:  # e.g. thousands of nested multiparts
        raise MailImportError("this e-mail could not be read (its MIME structure is nested too deeply)") from exc
    except Exception as exc:  # an uploaded file must give a clean 400, never a 500
        raise MailImportError("this e-mail could not be read") from exc
    mailbox = (getattr(settings, "mail_from", "") or "").lower()
    if mailbox and (parsed.from_addr or "").lower() == mailbox:
        raise MailImportError("this message was sent from the case mailbox itself: record your own sent e-mail with "
                           "“Record as sent” on its preview instead")
    result = matching.match(db, parsed, mailbox=mailbox or None, transport="file")
    letter_id = result.correspondence_id if result.case_id == case.id else None
    method = result.method if letter_id is not None else "upload"
    why = result.reason.replace("local file mailbox (no sender authentication)", "an uploaded file is never trusted alone")
    reason = f"imported by hand: {why}" if letter_id is not None else "imported by hand: no letter matched"
    sender_ok = result.sender_domain_ok if letter_id is not None else None
    if letter_id is None and authority is not None:
        latest = _latest_letter(authority)
        if latest is not None:
            letter_id = latest.id
            reason = f"imported by hand on {authority.name}'s page: their latest letter pre-selected"
    received = parsed.date if parsed.date is not None and parsed.date <= _now() + timedelta(minutes=5) else None
    received = (received if received is None or received.tzinfo else received.replace(tzinfo=UTC)) or _now()
    mm = MailMessage(
        direction=MailDirection.IN, status=MailStatus.NEEDS_REVIEW, transport="upload", mailbox=mailbox or "upload",
        message_id=(parsed.message_id or "")[:255], internet_message_id=(parsed.message_id or None),
        provider_message_id=f"upload:{case.id}:{sha[:48]}", in_reply_to=" ".join(parsed.in_reply_to)[:512] or None,
        references=" ".join(parsed.references) or None, subject=(parsed.subject or None),
        from_addr=parsed.from_addr, to_addrs=parsed.to, cc_addrs=parsed.cc, mime_sha256=sha, mime_size=len(raw),
        body_text=parsed.text,
        attachments=[{**a.manifest(), "kind": "inbound", "evidence_id": None, "blocked_reason": None}
                     for a in parsed.attachments],
        match={"method": method, "case_id": case.id, "correspondence_id": letter_id, "confident": False,
               "sender_domain_ok": sender_ok, "authenticated": None, "reason": reason[:200],
               "original_mail_id": result.original_mail_id if result.case_id == case.id else None},
        received_at=received, case_id=case.id, created_by=access.user.id,
        meta={"trigger": "upload", "imported_by": access.user.id, "imported_at": _now().isoformat(),
              "imported_from": ext.lstrip("."), "original_sha256": hashlib.sha256(original).hexdigest() if original else None,
              "auto_reply": parsed.auto_reply, "bounce": parsed.bounce, "inline_skipped": parsed.inline_skipped,
              "html_present": parsed.html_present, "parse_defects": parsed.defects,
              "attachments_truncated": parsed.attachments_truncated, "attachments_omitted": parsed.attachments_omitted,
              "authority_key": getattr(authority, "key", None)})
    mm.mime_path = ingest.write_raw(raw)
    db.add(mm)
    item = None
    try:
        db.flush()
        orig_id = None
        if original is not None:
            ref = re.sub(r"[^A-Za-z0-9._-]+", "-", case.reference)[:40]
            item = ev.store_upload(db, case, io.BytesIO(original), filename=f"{ref}_email-in-{mm.id}.msg",
                                   folder="stop_orders_correspondence",
                                   title=f"Imported reply (Outlook .msg as uploaded), e-mail #{mm.id}",
                                   source_type="msg", classification="R3", tags=["aegis-mail", "received-email"],
                                   received_from=parsed.from_addr, actor=access.user, max_bytes=limit)
            item.mime = "application/vnd.ms-outlook"
            item.meta = {**(item.meta or {}), "mail_message_id": mm.id}
            orig_id = item.id
            mm.meta = {**(mm.meta or {}), "original_evidence_id": item.id}
        db.commit()
    except Exception:
        from app.domain.mail_send import _drop_vault_copy

        path = mm.mime_path
        db.rollback()
        ingest.delete_raw(path)
        _drop_vault_copy(item)
        raise
    return ImportResult(mm, letter_id=letter_id, method=method, original_evidence_id=orig_id)
