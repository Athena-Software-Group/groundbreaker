"""Text out of an evidence file (pure: bytes in, text out). Nothing is executed or rendered: PDF text layers (pypdf),
.docx paragraphs and tables (python-docx, entities never resolved), e-mails (headers, the plain / HTML body, the list
of attachments: their bytes are not opened), plain text / CSV / JSON / Markdown, HTML and RTF with the markup removed.

    t = extract_text(data, name="Denuncia 2026-10-03.pdf", mime="application/pdf")
    t.kind, t.status, t.text, t.note, t.pages, t.truncated, t.meta

Caps: `MAX_READ_BYTES` read at all (a larger file is not parsed: "too_large"), `MAX_PDF_PAGES` pages, `MAX_TEXT_CHARS`
characters kept, a .docx whose XML would inflate past `MAX_DOCX_XML` is refused (a zip bomb). Images have no text
(no OCR on this machine): status "image", the note asks for a description or a text version; the classifier still
reads the file name and folder. An Outlook .msg in its binary (OLE) form is "unsupported" (save it as .eml); a .msg
that is a plain RFC 822 message is read as one.
"""

from __future__ import annotations

import contextlib
import io
import re
import zipfile
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

MAX_READ_BYTES = 25 * (1 << 20)
MAX_PDF_PAGES = 60
MAX_TEXT_CHARS = 200_000
MAX_DOCX_XML = 40 * (1 << 20)
MAX_ATTACHMENTS = 50
IMAGE_NOTE = "no text (image): describe it in the description or attach a text version"
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".heif", ".tif", ".tiff", ".bmp")
TEXT_EXTS = (".txt", ".csv", ".tsv", ".json", ".md", ".markdown", ".log", ".xml", ".text")
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_HEADER_LINE = re.compile(rb"^(?:From|To|Subject|Date|Received|Return-Path|Message-ID|MIME-Version|Delivered-To|Cc)"
                          rb":", re.IGNORECASE | re.MULTILINE)


@dataclass
class Text:
    kind: str  # pdf | docx | email | text | html | rtf | image | unsupported
    status: str = "ok"  # ok | no_text | image | too_large | encrypted | unsupported | error
    text: str = ""
    note: str | None = None
    pages: int | None = None
    truncated: bool = False
    meta: dict = field(default_factory=dict)  # e-mail: {"attachments": [{name, type, size}], "headers": {...}}

    @property
    def ok(self) -> bool:
        return self.status == "ok" and bool(self.text.strip())


def _ext(name: str | None) -> str:
    n = (name or "").lower().rsplit("/", 1)[-1]
    return "." + n.rsplit(".", 1)[-1] if "." in n else ""


def _clean(s: str) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    s = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", s)
    s = re.sub(r"[ \t\u00a0]+\n", "\n", s)
    return re.sub(r"\n{4,}", "\n\n\n", s).strip()


def _cap(t: Text) -> Text:
    t.text = _clean(t.text)
    if len(t.text) > MAX_TEXT_CHARS:
        t.text, t.truncated = t.text[:MAX_TEXT_CHARS], True
    if t.status == "ok" and not t.text.strip():
        t.status, t.note = "no_text", t.note or "no text found in the file"
    return t


def decode(data: bytes) -> str:
    """UTF-8 (with or without BOM), UTF-16 with a BOM, else Windows-1252 (never fails)."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


class _HTML(HTMLParser):
    BLOCK = frozenset({"p", "br", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "section", "article",
                       "hr", "blockquote", "pre", "ul", "ol", "dt", "dd"})

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head", "template", "noscript"):
            self.skip += 1
        elif tag in self.BLOCK:
            self.out.append("\n")
        elif tag in ("td", "th"):
            self.out.append("\t")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "template", "noscript"):
            self.skip = max(0, self.skip - 1)
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def html_text(s: str) -> str:
    p = _HTML()
    with contextlib.suppress(Exception):  # malformed markup: what was read so far
        p.feed(s)
        p.close()
    return re.sub(r"[ \t]+", " ", "".join(p.out))


_RTF_TOKEN = re.compile(r"\\([a-z]{1,32})(-?\d{1,10})? ?|\\'([0-9a-fA-F]{2})|\\([^a-z])|([{}])|[\r\n]+|(.)", re.DOTALL)
_RTF_DEST = {"aftncn", "aftnsep", "aftnsepc", "annotation", "atnauthor", "atndate", "atnicn", "atnid", "atnparent",
             "atnref", "atntime", "atrfend", "atrfstart", "author", "background", "bkmkend", "bkmkstart", "buptim",
             "colortbl", "comment", "company", "creatim", "datafield", "do", "doccomm", "docvar", "dptxbxtext",
             "falt", "fchars", "ffdeftext", "ffentrymcr", "ffexitmcr", "ffformat", "ffhelptext", "ffl", "ffname",
             "ffstattext", "field", "file", "filetbl", "fldinst", "fldtype", "fname", "fontemb", "fontfile",
             "fonttbl", "footer", "footerf", "footerl", "footerr", "footnote", "ftncn", "ftnsep", "ftnsepc",
             "header", "headerf", "headerl", "headerr", "info", "keycode", "keywords", "lchars", "levelnumbers",
             "leveltext", "lfolevel", "linkval", "list", "listlevel", "listname", "listoverride",
             "listoverridetable", "listpicture", "liststylename", "listtable", "listtext", "lsdlockedexcept",
             "macc", "maccPr", "mailmerge", "manager", "mmathPr", "nonshppict", "object", "objdata", "objclass",
             "objname", "operator", "panose", "passwordhash", "pict", "pn", "printim", "private", "pxe", "revtbl",
             "revtim", "rsidtbl", "shp", "shpinst", "shppict", "shptxt", "stylesheet", "subject", "tc", "template",
             "themedata", "title", "txe", "ud", "upr", "userprops", "wgrffmtfilter", "windowcaption", "writereservation",
             "writereservhash", "xe", "xform", "xmlattrname", "xmlattrvalue", "xmlclose", "xmlname", "xmlnstbl",
             "xmlopen", "datastore", "latentstyles", "generator", "pgdsctbl"}
_RTF_CHARS = {"par": "\n", "sect": "\n\n", "page": "\n\n", "line": "\n", "tab": "\t", "emdash": "—", "endash": "–",
              "emspace": " ", "enspace": " ", "qmspace": " ", "bullet": "•", "lquote": "‘", "rquote": "’",
              "ldblquote": "“", "rdblquote": "”", "cell": "\t", "row": "\n"}


def rtf_text(s: str) -> str:
    """The text of an RTF document: control words and the destinations that hold no text (font / colour tables,
    pictures, embedded objects, fields' instructions) dropped. Never interprets an embedded object."""
    stack: list[tuple[int, bool]] = []
    ignorable, ucskip, curskip = False, 1, 0
    out: list[str] = []
    for m in _RTF_TOKEN.finditer(s):
        word, arg, hexv, char, brace, tchar = m.groups()
        if brace:
            curskip = 0
            if brace == "{":
                stack.append((ucskip, ignorable))
            elif stack:
                ucskip, ignorable = stack.pop()
        elif char:
            curskip = 0
            if char in "~{}\\" and not ignorable:
                out.append(" " if char == "~" else char)
            elif char == "*":
                ignorable = True
        elif word:
            curskip = 0
            if word in _RTF_DEST:
                ignorable = True
            elif ignorable:
                pass
            elif word in _RTF_CHARS:
                out.append(_RTF_CHARS[word])
            elif word == "uc":
                ucskip = int(arg or 1)
            elif word == "u":
                c = int(arg or 0)
                out.append(chr(c + 0x10000 if c < 0 else c) if -0x10000 < c < 0x110000 else "")
                curskip = ucskip
        elif hexv:
            if curskip > 0:
                curskip -= 1
            elif not ignorable:
                out.append(bytes([int(hexv, 16)]).decode("cp1252", errors="replace"))
        elif tchar:
            if curskip > 0:
                curskip -= 1
            elif not ignorable:
                out.append(tchar)
    return "".join(out)


def _pdf(data: bytes) -> Text:
    from pypdf import PdfReader

    t = Text("pdf")
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            try:
                opened = reader.decrypt("")
            except Exception:  # noqa: BLE001 - an unsupported cipher reads as locked
                opened = 0
            if not opened:
                t.status, t.note = "encrypted", "the PDF is password-protected: no text read"
                return t
        n = len(reader.pages)
        t.pages = n
        parts = []
        for i in range(min(n, MAX_PDF_PAGES)):
            try:
                parts.append(reader.pages[i].extract_text() or "")
            except Exception:  # noqa: BLE001 - a broken page: the others are still read
                parts.append("")
            if sum(len(p) for p in parts) > MAX_TEXT_CHARS:
                break
        t.text = "\n\n".join(parts)
        if n > MAX_PDF_PAGES:
            t.truncated, t.note = True, f"read the first {MAX_PDF_PAGES} of {n} pages"
        if not t.text.strip():
            t.status, t.note = "no_text", "no text layer (a scan?): describe it or attach a text version"
    except Exception:  # noqa: BLE001 - not a readable PDF
        t.status, t.note = "error", "the PDF could not be read"
    return t


def _docx(data: bytes) -> Text:
    t = Text("docx")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if sum(i.file_size for i in infos) > MAX_DOCX_XML * 4 or any(
                    i.filename.startswith("word/") and i.file_size > MAX_DOCX_XML for i in infos):
                t.status, t.note = "too_large", "the document would expand past the read limit"
                return t
        import docx

        d = docx.Document(io.BytesIO(data))
        parts = [p.text for p in d.paragraphs]
        for table in d.tables:
            for row in table.rows:
                parts.append("\t".join(c.text for c in row.cells))
        t.text = "\n".join(parts)
    except Exception:  # noqa: BLE001 - not a readable .docx
        t.status, t.note = "error", "the .docx could not be read"
    return t


def _body(part) -> str:
    try:
        content = part.get_content()
    except Exception:  # noqa: BLE001 - an unknown charset: the raw bytes, decoded leniently
        raw = part.get_payload(decode=True) or b""
        content = decode(raw) if isinstance(raw, bytes) else str(raw)
    if isinstance(content, bytes):
        content = decode(content)
    return html_text(content) if part.get_content_type() == "text/html" else str(content)


def _email(data: bytes) -> Text:
    t = Text("email")
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
        heads = {k: " ".join(str(msg.get(k) or "").split()) for k in ("From", "To", "Cc", "Date", "Subject")}
        body = msg.get_body(preferencelist=("plain", "html")) if msg.is_multipart() else msg
        text = _body(body) if body is not None and body.get_content_maintype() == "text" else ""
        atts = []
        for part in msg.iter_attachments() if msg.is_multipart() else ():
            if len(atts) >= MAX_ATTACHMENTS:
                break
            raw = part.get_payload(decode=True)
            atts.append({"name": (part.get_filename() or "")[:200] or None, "type": part.get_content_type(),
                         "size": len(raw) if isinstance(raw, bytes) else None})
        head = "\n".join(f"{k}: {v}" for k, v in heads.items() if v)
        listing = "\n".join(f"- {a['name'] or '(unnamed)'} ({a['type']}"
                            + (f", {a['size']} bytes" if a["size"] is not None else "") + ")" for a in atts)
        t.text = head + "\n\n" + text + (f"\n\nAttachments:\n{listing}" if atts else "")
        t.meta = {"attachments": atts, "headers": [k for k, v in heads.items() if v]}
        if not text.strip():
            t.note = "the e-mail has no text body" + (" (attachments listed, not opened)" if atts else "")
    except Exception:  # noqa: BLE001 - not a readable message
        t.status, t.note = "error", "the e-mail could not be read"
    return t


def detect(data: bytes, name: str | None, mime: str | None) -> str:
    """The reader for these bytes: by their signature first, then the file name, then the declared type."""
    ext, mime = _ext(name), (mime or "").lower()
    head = data[:16]
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                return "docx" if "word/document.xml" in zf.namelist() else "archive"
        except zipfile.BadZipFile:
            return "unsupported"
    if head.startswith(_OLE):
        return "ole"
    from app.domain.evidence import sniff

    if sniff(head) or ext in IMAGE_EXTS or mime.startswith("image/"):
        return "image"
    if mime.startswith(("video/", "audio/")):
        return "media"
    if b"\x00" in data[:4096] and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "unsupported"
    if ext in (".eml", ".msg") or mime == "message/rfc822" or len(_HEADER_LINE.findall(data[:4096])) >= 3:
        return "email"
    low = data[:512].lstrip().lower()
    if ext in (".html", ".htm") or mime == "text/html" or low.startswith((b"<!doctype html", b"<html")):
        return "html"
    if ext == ".rtf" or mime in ("text/rtf", "application/rtf") or low.startswith(b"{\\rtf"):
        return "rtf"
    return "text"


def extract_text(data: bytes, *, name: str | None = None, mime: str | None = None) -> Text:
    """The text of `data` (see the module doc). Never raises."""
    if len(data) > MAX_READ_BYTES:
        return Text("unsupported", "too_large", note=f"larger than the read limit ({MAX_READ_BYTES >> 20} MB)")
    kind = detect(data, name, mime)
    if kind == "image":
        return Text("image", "image", note=IMAGE_NOTE)
    if kind == "media":
        return Text("unsupported", "unsupported", note="a recording: no text (attach its transcript)")
    if kind == "ole":
        note = ("an Outlook .msg in its binary form: save it as .eml" if _ext(name) == ".msg"
                else "a legacy Office file: save it as .docx or PDF")
        return Text("unsupported", "unsupported", note=note)
    if kind == "archive":
        return Text("unsupported", "unsupported", note="an archive: add its files one by one")
    if kind == "unsupported":
        return Text("unsupported", "unsupported", note="a binary file Aegis cannot read")
    if kind == "pdf":
        return _cap(_pdf(data))
    if kind == "docx":
        return _cap(_docx(data))
    if kind == "email":
        return _cap(_email(data))
    s = decode(data)
    if kind == "html":
        return _cap(Text("html", text=html_text(s)))
    if kind == "rtf":
        return _cap(Text("rtf", text=rtf_text(s)))
    return _cap(Text("text", text=s))
