"""Inbound e-mail: parse raw MIME into plain, safe data (D5).

    parsed = parse(raw_bytes)        # ParsedEmail: ids, subject, addresses, text, attachments, flags

* **Headers.** Message-ID, In-Reply-To and References as lists of `<…>` ids; the subject RFC 2047
  decoded, whitespace collapsed, control and bidi / zero-width characters removed, ≤ 512 chars.
* **Body.** text/plain is preferred; otherwise HTML is converted to text by `html_to_text` (a stdlib
  HTMLParser: script / style / head / title / template / svg / object contents dropped, block tags
  become newlines, links become `text <url>` for http / https / mailto only, images `[image]`, never
  fetched). Inbound HTML is never stored or rendered anywhere: only this text is.
* **Attachments.** Parts that are attachments, or carry a filename and are not a small inline image
  (signature logos under 20 KB are only counted). Names are sanitized (`safe_filename`); a set of
  executable / active-content extensions is flagged `dangerous`. At most MAX_ATTACHMENTS (25) and
  MAX_ATTACHMENT_TOTAL (20 MiB) are extracted; the rest are counted in `attachments_omitted`
  (`attachments_truncated`): they stay only in the raw .eml filed as evidence.
* **Authentication-Results** (RFC 8601): only the topmost header is kept (the one the receiving
  MTA, Exchange Online for the graph transport, prepends; a header the sender wrote sits below it).
  `from_authenticated` is true when it reports `dmarc=pass` (or Exchange's `compauth=pass`) for
  the From domain; inbound matching needs it before a subject tag alone files a reply.
* **Auto-replies** are detected from the standard headers (RFC 3834 Auto-Submitted, X-Autoreply,
  Precedence) and common out-of-office subjects. A **bounce** (`bounce`) is a delivery-status
  report by structure only (`_is_dsn`: multipart/report delivery-status, a message/delivery-status
  part, or an Exchange NDR returning the original); a postmaster / mailer-daemon From alone never
  makes one. Whether a bounce is trusted (our own MTA, authenticated) is decided in
  app.mail.matching.trusted_bounce.

Everything decodes with errors="replace": hostile input degrades to replacement characters, never
to an exception that stops a mailbox sync.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from typing import ClassVar

MAX_SUBJECT = 512
MAX_TEXT = 200 * 1024
TRUNCATED = "[… truncated]"
INLINE_IMAGE_SKIP_BYTES = 20 * 1024
MAX_ATTACHMENTS = 25  # extracted per inbound message; beyond it they stay only in the raw .eml
MAX_ATTACHMENT_TOTAL = 20 * 1024 * 1024  # decoded bytes extracted per inbound message
DANGEROUS_EXT = {
    "exe", "js", "jse", "vbs", "vbe", "scr", "bat", "cmd", "ps1", "psm1", "html", "htm", "xhtml", "svg", "hta", "lnk",
    "iso", "img", "vhd", "vhdx", "jar", "sh", "bash", "zsh", "msi", "msp", "dll", "com", "pif", "wsf", "wsh", "reg",
    "chm", "cpl", "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "apk", "dmg", "pkg", "app", "scf",
    "url", "inf", "gadget", "application", "appref-ms", "library-ms", "settingcontent-ms", "one", "xll",
}
AUTO_SUBJECTS = ("automatic reply:", "out of office", "abwesenheitsnotiz", "risposta automatica")
BOUNCE_SENDERS = ("mailer-daemon", "postmaster")  # app.mail.matching.trusted_bounce: identity, never the test

# C0 / C1 controls except \n and \t, bidi overrides / isolates, zero-width characters, BOM
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff\u2028\u2029]")
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_MSGID_RE = re.compile(r"<[^<>\s]{1,500}>")


def strip_invisible(text: str, *, keep_newlines: bool = True) -> str:
    text = _INVISIBLE.sub("", text or "")
    if keep_newlines:
        return _CONTROL.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))
    return _CONTROL.sub(" ", text.replace("\r", " ").replace("\n", " ").replace("\t", " "))


def clean_header_text(value, limit: int = MAX_SUBJECT) -> str:
    """A decoded header as one safe line: no controls, no bidi / zero-width, whitespace collapsed."""
    s = strip_invisible(str(value or ""), keep_newlines=False)
    return re.sub(r"\s+", " ", s).strip()[:limit]


def message_ids(value) -> list[str]:
    """The `<…>` ids in a Message-ID / In-Reply-To / References header (at most 50)."""
    return _MSGID_RE.findall(str(value or ""))[:50]


# --------------------------------------------------------------------------- HTML -> text
class _TextExtractor(HTMLParser):
    DROP: ClassVar[set[str]] = {"script", "style", "head", "title", "template", "svg", "object", "noscript", "iframe"}
    BLOCK: ClassVar[set[str]] = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "table", "ul", "ol", "blockquote",
             "hr", "pre", "section", "article", "header", "footer"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self._drop = 0
        self._href: list[str | None] = []
        self.size = 0

    def _emit(self, s: str) -> None:
        if self.size <= MAX_TEXT:
            self.out.append(s)
            self.size += len(s)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self.DROP:
            self._drop += 1
            return
        if self._drop:
            return
        if tag == "li":
            self._emit("\n- ")
        elif tag in self.BLOCK:
            self._emit("\n")
        elif tag == "td" or tag == "th":
            self._emit("\t")
        if tag == "img":
            self._emit(" [image] ")
        elif tag == "a":
            href = dict(attrs).get("href") or ""
            href = href.strip()
            ok = re.match(r"(?i)(https?:|mailto:)", href) is not None
            self._href.append(clean_header_text(href, 500) if ok else None)

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if tag in self.DROP:
            return
        if tag == "a":  # <a/> carries no text
            return
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self.DROP:
            self._drop = max(0, self._drop - 1)
            return
        if self._drop:
            return
        if tag == "a" and self._href:
            href = self._href.pop()
            if href:
                self._emit(f" <{href}>")
        elif tag in self.BLOCK and tag != "br":
            self._emit("\n")

    def handle_data(self, data):
        if not self._drop:  # literal angle brackets in the text become look-alikes: no tag survives
            self._emit(data.replace("<", "\u2039").replace(">", "\u203a"))


def _tidy_text(text: str) -> str:
    text = strip_invisible(text)
    lines = [re.sub(r"[  ]+", " ", ln).rstrip() for ln in text.split("\n")]
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT].rstrip() + "\n" + TRUNCATED
    return text


def html_to_text(markup: str) -> str:
    """Plain text from untrusted HTML (no tag survives; nothing is fetched)."""
    p = _TextExtractor()
    try:
        p.feed(markup or "")
        p.close()
    except Exception:  # noqa: BLE001, S110 - malformed markup must never stop a sync: keep what was read
        pass
    return _tidy_text("".join(p.out))


# --------------------------------------------------------------------------- attachments
def safe_filename(name: str | None, n: int) -> str:
    """Basename only; no separators, NUL or controls; NFKC; [A-Za-z0-9._ -] else '-'; ≤ 100 chars."""
    s = str(name or "")
    s = s.replace("\\", "/").split("/")[-1]
    s = _CONTROL.sub("", _INVISIBLE.sub("", s.replace("\x00", "")))
    s = unicodedata.normalize("NFKC", s)
    s = re.sub(r"[^A-Za-z0-9._ -]", "-", s).strip()
    s = re.sub(r"-{2,}", "-", s)
    if len(s) > 100:
        stem, dot, ext = s.rpartition(".")
        s = (stem[: 100 - len(ext) - 1] + "." + ext) if dot and 0 < len(ext) <= 10 else s[:100]
    if not s or s.startswith(".") or not s.strip(". -"):
        s = f"attachment-{n}"
    return s


def extension(name: str) -> str:
    return name.rpartition(".")[2].lower() if "." in name else ""


@dataclass
class Attachment:
    filename_safe: str
    mime: str
    data: bytes
    sha256: str
    size: int
    dangerous: bool

    def manifest(self) -> dict:
        return {"filename": self.filename_safe, "mime": self.mime, "size": self.size, "sha256": self.sha256,
                "dangerous": self.dangerous}


@dataclass
class ParsedEmail:
    message_id: str | None = None
    in_reply_to: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    subject: str = ""
    from_addr: str | None = None
    from_name: str | None = None
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    date: datetime | None = None
    text: str = ""
    html_present: bool = False
    attachments: list[Attachment] = field(default_factory=list)
    inline_skipped: int = 0
    auto_reply: bool = False
    bounce: bool = False
    bounce_original_message_id: str | None = None
    defects: int = 0
    auth_results: str = ""  # the topmost Authentication-Results header, one cleaned line
    attachments_omitted: int = 0  # beyond MAX_ATTACHMENTS / MAX_ATTACHMENT_TOTAL: only in the raw .eml

    @property
    def attachments_truncated(self) -> bool:
        return self.attachments_omitted > 0

    @property
    def from_authenticated(self) -> bool:
        return auth_passes(self.auth_results, self.sender_domain)

    @property
    def sender_domain(self) -> str | None:
        return self.from_addr.rpartition("@")[2] if self.from_addr and "@" in self.from_addr else None

    def thread_ids(self) -> list[str]:
        return list(dict.fromkeys([*self.in_reply_to, *self.references]))


_AR_COMMENT = re.compile(r"\([^()]*\)")
_AR_PASS_METHODS = ("dmarc", "compauth")


def auth_passes(header: str | None, from_domain: str | None) -> bool:
    """True when an Authentication-Results value reports dmarc=pass or compauth=pass and every
    `header.from=` in it names `from_domain` (comments dropped; clauses split on ';')."""
    if not header or not from_domain:
        return False
    text = str(header).lower()
    for _ in range(5):  # nested comments
        text = _AR_COMMENT.sub(" ", text)
    dom = from_domain.lower().strip(".")
    froms, passed = [], False
    for clause in text.split(";"):
        tokens = clause.split()
        if not tokens:
            continue
        method, eq, result = tokens[0].partition("=")
        for t in tokens[1:]:
            k, _, v = t.partition("=")
            if k == "header.from":
                froms.append(v.strip(".").strip('"'))
        if eq and method in _AR_PASS_METHODS and result == "pass":
            passed = True
    return passed and bool(froms) and all(f == dom for f in froms)


def _addr_list(*values) -> list[tuple[str, str]]:
    out = []
    for name, addr in getaddresses([str(v) for v in values if v]):
        addr = clean_header_text(addr, 254).strip("<>").lower()
        if "@" in addr and " " not in addr:
            out.append((clean_header_text(name, 200), addr))
    return out[:50]


def _header(msg: Message, name: str) -> str:
    try:
        v = msg.get(name)
    except Exception:  # noqa: BLE001 - a malformed header degrades to empty
        return ""
    return "" if v is None else str(v)


def _part_text(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True) or b""
    except Exception:  # noqa: BLE001
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _is_auto_reply(msg: Message, subject: str) -> bool:
    auto = _header(msg, "Auto-Submitted").strip().lower()
    if auto and not auto.startswith("no"):
        return True
    if _header(msg, "X-Autoreply").strip() or _header(msg, "X-Autorespond").strip():
        return True
    if _header(msg, "Precedence").strip().lower() in {"auto_reply", "bulk", "junk"}:
        return True
    return subject.lower().startswith(AUTO_SUBJECTS)


DSN_TYPES = ("message/delivery-status", "message/global-delivery-status")
RETURNED_TYPES = ("message/rfc822", "text/rfc822-headers", "message/global", "message/global-headers")


def _is_dsn(msg: Message) -> bool:
    """A delivery-status report by its structure, never by its sender: a multipart/report of
    report-type delivery-status (RFC 3464 / 6533), or a message whose own parts (not an attached
    message's) carry a message/delivery-status part, or an Exchange NDR
    (X-MS-Exchange-Message-Is-Ndr) that returns the original message or its headers."""
    if msg.get_content_type() == "multipart/report" and \
            (msg.get_param("report-type") or "").lower() in ("delivery-status", "global-delivery-status"):
        return True
    leaves = list(_leaves(msg))
    if any(p.get_content_type() in DSN_TYPES for p in leaves):
        return True
    return "X-MS-Exchange-Message-Is-Ndr" in msg \
        and any(p.get_content_type() in RETURNED_TYPES for p in leaves)


def _bounce(msg: Message) -> tuple[bool, str | None]:
    """(is a delivery-status report, the returned message's Message-ID). Who sent it and whether
    it is trusted is app.mail.matching.trusted_bounce: a sender local part (postmaster,
    mailer-daemon) alone never makes a message a bounce."""
    if not _is_dsn(msg):
        return False, None
    original = None
    for part in _leaves(msg):
        ctype = part.get_content_type()
        if ctype in ("message/rfc822", "message/global"):
            payload = part.get_payload()
            inner = payload[0] if isinstance(payload, list) and payload else None
            if isinstance(inner, Message):
                ids = message_ids(_header(inner, "Message-ID"))
                original = ids[0] if ids else original
        elif ctype in ("text/rfc822-headers", "message/global-headers"):
            m = re.search(r"(?im)^message-id:\s*(<[^<>\s]+>)", _part_text(part))
            original = m.group(1) if m else original
        if original:
            break
    return True, original


def _leaves(msg: Message, depth: int = 0):
    """The non-multipart parts, not descending into attached messages (message/rfc822) or any other
    message/* part (a message/delivery-status report's field blocks are not body text)."""
    if depth > 20:
        return
    if msg.get_content_maintype() == "message" or not msg.is_multipart():
        yield msg
        return
    payload = msg.get_payload()
    for part in payload if isinstance(payload, list) else []:
        if isinstance(part, Message):
            yield from _leaves(part, depth + 1)


def parse(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw or b"")
    out = ParsedEmail(defects=len(getattr(msg, "defects", []) or []))
    ids = message_ids(_header(msg, "Message-ID"))
    out.message_id = ids[0] if ids else None
    out.in_reply_to = message_ids(_header(msg, "In-Reply-To"))
    out.references = message_ids(_header(msg, "References"))
    out.subject = clean_header_text(_header(msg, "Subject"))
    sender = _addr_list(_header(msg, "From"))
    if sender:
        out.from_name, out.from_addr = sender[0]
    out.to = [a for _, a in _addr_list(_header(msg, "To"))]
    out.cc = [a for _, a in _addr_list(_header(msg, "Cc"))]
    try:
        d = parsedate_to_datetime(_header(msg, "Date")) if _header(msg, "Date") else None
        out.date = (d if d.tzinfo else d.replace(tzinfo=UTC)).astimezone(UTC) if d else None
    except (TypeError, ValueError, IndexError):
        out.date = None
    out.auth_results = clean_header_text(_header(msg, "Authentication-Results"), 2000)
    out.auto_reply = _is_auto_reply(msg, out.subject)
    out.bounce, out.bounce_original_message_id = _bounce(msg)

    plain: list[str] = []
    htmls: list[str] = []
    n = 0
    total = 0

    def room(size: int) -> bool:
        # another attachment fits the caps; otherwise it is only counted (it stays in the raw .eml)
        if len(out.attachments) >= MAX_ATTACHMENTS or total + size > MAX_ATTACHMENT_TOTAL:
            out.attachments_omitted += 1
            return False
        return True

    for part in _leaves(msg):
        ctype = part.get_content_type()
        if ctype == "message/rfc822":  # a forwarded / returned message: kept whole, never descended into
            if (part.get_content_disposition() or "").lower() != "attachment":
                continue
            if not room(0):
                continue
            payload = part.get_payload()
            inner = payload[0] if isinstance(payload, list) and payload else None
            data = inner.as_bytes() if isinstance(inner, Message) else b""
            if not room(len(data)):
                continue
            total += len(data)
            n += 1
            name = safe_filename(part.get_filename() or f"forwarded-{n}.eml", n)
            out.attachments.append(Attachment(filename_safe=name, mime="message/rfc822", data=data,
                                              sha256=hashlib.sha256(data).hexdigest(), size=len(data),
                                              dangerous=extension(name) in DANGEROUS_EXT))
            continue
        disp = (part.get_content_disposition() or "").lower()
        raw_name = part.get_filename()
        is_attachment = disp == "attachment" or bool(raw_name)
        if not is_attachment and ctype == "text/plain":
            plain.append(_part_text(part))
            continue
        if not is_attachment and ctype == "text/html":
            out.html_present = True
            htmls.append(_part_text(part))
            continue
        if not is_attachment and ctype in ("message/delivery-status", "text/rfc822-headers"):
            continue
        if not is_attachment:
            if ctype.startswith("image/"):
                out.inline_skipped += 1
            continue
        if len(out.attachments) >= MAX_ATTACHMENTS:  # counted without decoding it
            out.attachments_omitted += 1
            continue
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:  # noqa: BLE001
            data = b""
        if disp != "attachment" and ctype.startswith("image/") and len(data) < INLINE_IMAGE_SKIP_BYTES:
            out.inline_skipped += 1  # signature logos and the like
            continue
        if not room(len(data)):
            continue
        total += len(data)
        n += 1
        name = safe_filename(raw_name, n)
        out.attachments.append(Attachment(
            filename_safe=name, mime=clean_header_text(ctype, 100) or "application/octet-stream", data=data,
            sha256=hashlib.sha256(data).hexdigest(), size=len(data), dangerous=extension(name) in DANGEROUS_EXT))
    if plain:
        out.text = _tidy_text("\n\n".join(plain))
    elif htmls:
        out.text = html_to_text("\n".join(htmls))
    return out
