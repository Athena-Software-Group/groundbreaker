r"""Pre-commit PII / secret scanner for the Aegis repository.

    python scripts/pii_scan.py                       # scan every file that would be committed
    python scripts/pii_scan.py path [path ...]       # scan only these files
    AEGIS_DENYLIST=/secure/path/denylist.txt python scripts/pii_scan.py
    python scripts/pii_scan.py --denylist /secure/path/denylist.txt

File selection: `git ls-files --cached --others --exclude-standard` when the repo is a git
work tree, otherwise a walk that honours the root .gitignore (simple fnmatch semantics).
Only .git is skipped: third-party bundles (app/web/static/vendor) are scanned like everything else.

Content (fails closed: what cannot be read is a finding, not a pass):
  text       line by line, plus decoded variants: HTML/XML entities (&#97;), JS/JSON escapes
             (\u0061, \x61, \n), and base64 `data:` URIs (decoded and scanned recursively)
  zip        every entry, recursively (.docx/.xlsx/.pptx XML parts and docProps metadata included)
  pdf        FlateDecode streams decompressed; text strings extracted
  png        tEXt/zTXt/iTXt/eXIf chunks
  forbidden  .pdf .zip .eml .msg .doc .heic .jpg .jpeg .mp4 .mov archives, key stores and databases
             are reported as `forbidden_format` even when their content scans clean: they are
             evidence-shaped and this repository ships none
  binary     any other binary is reported as `binary` (its printable strings are scanned too),
             unless its path and sha256 are pinned in ALLOWLISTED_BINARIES
Multi-word denylist literals match across any whitespace, line breaks included.

Rules:
  denylist   case-insensitive literals / `re:` regexes from a denylist file kept OUTSIDE the repo
  email      addresses not on the allowlist (reserved example domains, generic role aliases at known
             service domains, noreply@anthropic.com)
  phone      international (+CC) numbers other than all-zero placeholders (+41 00 000 00 00)
  api_key    gsk_ (Groq), sk-/sk-ant- (OpenAI/Anthropic), AKIA (AWS), ghp_/github_pat_, xox?-
  jwt        eyJ... tokens (e.g. Supabase anon/service keys)
  private_key  PEM private-key headers

Exit status 1 when anything is found. Findings print as file:line:rule: value, with the value
masked (first/last 2 characters kept) so the scan output itself does not leak.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import fnmatch
import hashlib
import html
import os
import re
import struct
import subprocess
import sys
import zipfile
import zlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ALWAYS_SKIP_DIRS = {".git"}
# Directories scanned with every rule except `phone`. Empty: the vendored bundles pass every rule
# today. Add a directory only if minified number runs there trip the phone rule.
REDUCED_RULE_DIRS: set[str] = set()
# compiled Python only (gitignored; never committed)
SKIP_SUFFIXES = {".pyc", ".pyo"}
# evidence-shaped, archive, key-store and database formats: always a finding
FORBIDDEN_SUFFIXES = {
    ".pdf", ".zip", ".eml", ".msg", ".doc", ".heic", ".jpg", ".jpeg", ".mp4", ".mov",
    ".7z", ".rar", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".p12", ".pfx",
    ".db", ".sqlite", ".sqlite3", ".db-journal",
}
# binaries reviewed by hand: repo-relative path -> sha256. A changed file is flagged again.
ALLOWLISTED_BINARIES: dict[str, str] = {}
MAX_DEPTH = 4  # nested zip / data-URI recursion

# ----------------------------------------------------------------------------- allowlists
# Organisation-published role mailboxes that are not a generic alias (e.g. Circle's own auto-reply names
# circleblocklisting@ for freeze requests). Exact addresses only; add new ones deliberately.
ALLOWED_EMAILS = {"noreply@anthropic.com", "circleblocklisting@circle.com", "inforequests@tether.to"}
RESERVED_DOMAINS = {"example.com", "example.org", "example.net"}
ROLE_ALIASES = {
    "compliance", "legal", "abuse", "support", "security", "privacy", "lawenforcement", "le", "dpo",
    "subpoena", "subpoenas", "law-enforcement", "le-requests",
}
KNOWN_SERVICE_DOMAINS = {
    "kucoin.com", "rainbet.com", "swft.pro", "bridgers.xyz", "tether.to", "circle.com", "hostinger.com",
    "supabase.com", "supabase.io", "groq.com", "uniswap.org", "kraken.com", "coinbase.com", "binance.com",
    "okx.com", "bybit.com",
}
# "icon@2x.png" and friends look like e-mail addresses
NON_EMAIL_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "js", "css", "map", "py", "json", "md", "html"}

EMAIL_RE = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])")
PHONE_RES = [
    re.compile(r"(?<![\w+])\+\d{1,3}(?:[ \-]\(?\d{1,5}\)?){2,6}(?![\d])"),
    re.compile(r"(?<![\w+])\+\d{10,14}(?![\d])"),
]
SECRET_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("api_key", re.compile(r"gsk_[A-Za-z0-9]{8,}")),
    ("api_key", re.compile(r"(?<![\w-])sk-(?:ant-)?[A-Za-z0-9_-]{20,}")),
    ("api_key", re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")),
    ("api_key", re.compile(r"(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}")),
    ("api_key", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{20,}")),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
]


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    value: str

    def render(self) -> str:
        return f"{self.path}:{self.line}:{self.rule}: {mask(self.value)}"


def mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 4:
        return "*" * len(v)
    return v[:2] + "*" * (len(v) - 4) + v[-2:]


# ----------------------------------------------------------------------------- denylist
@dataclass(frozen=True)
class DenyRule:
    source: str
    pattern: re.Pattern[str]
    multiword: bool = False  # literal with spaces: also matched across line breaks


def load_denylist(path: str | os.PathLike | None) -> list[DenyRule]:
    if not path:
        return []
    rules: list[DenyRule] = []
    for raw in Path(path).expanduser().read_text(encoding="utf-8").splitlines():
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("re:"):
            rules.append(DenyRule(line, re.compile(line[3:], re.IGNORECASE)))
        else:
            words = line.split()
            rules.append(DenyRule(line, re.compile(r"\s+".join(map(re.escape, words)), re.IGNORECASE), len(words) > 1))
    return rules


# ----------------------------------------------------------------------------- generic rules
def email_allowed(addr: str) -> bool:
    a = addr.lower()
    if a in ALLOWED_EMAILS:
        return True
    local, _, domain = a.rpartition("@")
    if domain.endswith(".example") or domain == "example" or domain in RESERVED_DOMAINS:
        return True
    if any(domain.endswith("." + d) for d in RESERVED_DOMAINS):
        return True
    return local in ROLE_ALIASES and domain in KNOWN_SERVICE_DOMAINS


def phone_allowed(match: str) -> bool:
    digits = re.sub(r"\D", "", match)
    # placeholder numbers: everything after the country code is zero (+41 00 000 00 00)
    return any(set(digits[k:]) <= {"0"} and len(digits) > k for k in (1, 2, 3))


_ESCAPE_RE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|[nrt])")
_ENTITY_NL_RE = re.compile(r"&#(?:0*10|0*13|[xX]0*[aAdD]);")
DATA_URI_RE = re.compile(r"data:[\w/+.-]*(?:;[\w=.-]+)*;base64,([A-Za-z0-9+/=]{8,})")


def _escape_decode(line: str) -> str:
    def sub(m: re.Match[str]) -> str:
        code = m.group(1) or m.group(2)
        ch = chr(int(code, 16)) if code else " "
        return " " if ch in "\r\n" else ch
    return _ESCAPE_RE.sub(sub, line)


def _html_decode(line: str) -> str:
    return html.unescape(_ENTITY_NL_RE.sub(" ", line)).replace("\n", " ").replace("\r", " ")


def scan_text(text: str, path: str, denylist: Iterable[DenyRule] = (), line_offset: int = 0,
              reduced: bool = False, _depth: int = 0) -> list[Finding]:
    """All rules over `text` and its decoded variants. `reduced` drops the phone rule (vendor bundles)."""
    deny = list(denylist)
    lines = text.splitlines()
    out = _scan_lines(lines, path, deny, line_offset, reduced)
    seen = {(f.line, f.rule, f.value.lower()) for f in out}

    def add(found: Iterable[Finding]) -> None:
        for f in found:
            key = (f.line, f.rule, f.value.lower())
            if key not in seen:
                seen.add(key)
                out.append(f)

    for decode in (_html_decode, _escape_decode):
        decoded = [decode(line) for line in lines]
        if decoded != lines:
            add(_scan_lines(decoded, path, deny, line_offset, reduced))
            if any(r.multiword for r in deny):
                add(_scan_multiline("\n".join(decoded), path, deny, line_offset))
    add(_scan_multiline(text, path, deny, line_offset))
    if _depth < MAX_DEPTH:
        for i, line in enumerate(lines, start=1 + line_offset):
            for m in DATA_URI_RE.finditer(line):
                try:
                    raw = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4))
                except (binascii.Error, ValueError):
                    continue
                add(scan_bytes(raw, f"{path}[data-uri:{i}]", deny, reduced=reduced, _depth=_depth + 1, forbid=False))
    return out


def _scan_multiline(text: str, path: str, deny: list[DenyRule], line_offset: int) -> list[Finding]:
    """Multi-word denylist literals broken across lines ("Acme\nSecret Corp")."""
    out = []
    for rule in deny:
        if not rule.multiword:
            continue
        for m in rule.pattern.finditer(text):
            if "\n" in m.group(0):
                out.append(Finding(path, line_offset + text.count("\n", 0, m.start()) + 1, "denylist", " ".join(m.group(0).split())))
    return out


def _scan_lines(lines: list[str], path: str, deny: list[DenyRule], line_offset: int, reduced: bool) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(lines, start=1 + line_offset):
        deny_spans: set[tuple[int, int]] = set()
        for rule in deny:
            for m in rule.pattern.finditer(line):
                if any(s <= m.start() < e or m.start() <= s < m.end() for s, e in deny_spans):
                    continue  # overlapping rules (e.g. two spellings) report once
                deny_spans.add(m.span())
                out.append(Finding(path, i, "denylist", m.group(0)))
        for m in EMAIL_RE.finditer(line):
            addr = m.group(0)
            if addr.rsplit(".", 1)[-1].lower() in NON_EMAIL_TLDS:
                continue
            if not email_allowed(addr):
                out.append(Finding(path, i, "email", addr))
        seen_spans: list[tuple[int, int]] = []
        for rx in () if reduced else PHONE_RES:
            for m in rx.finditer(line):
                if any(s <= m.start() < e for s, e in seen_spans):
                    continue
                seen_spans.append(m.span())
                if not phone_allowed(m.group(0)):
                    out.append(Finding(path, i, "phone", m.group(0)))
        for name, rx in SECRET_RULES:
            for m in rx.finditer(line):
                out.append(Finding(path, i, name, m.group(0)))
    return out


# ----------------------------------------------------------------------------- content extraction
XML_TAG_RE = re.compile(r"<[^>]+>")


def _xml_to_text(xml: str) -> str:
    xml = re.sub(r"</w:p>|</a:p>|<w:br/>|</dc:\w+>|</cp:\w+>|</dcterms:\w+>", "\n", xml)
    text = XML_TAG_RE.sub("", xml)
    return (text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
            .replace("&quot;", '"').replace("&apos;", "'"))


def office_parts(data: bytes) -> Iterator[tuple[str, str]]:
    """Text of the XML parts of an Office (or any) zip container."""
    for name, body in zip_entries(data):
        if name.endswith((".xml", ".rels")):
            yield name, _xml_to_text(body.decode("utf-8", errors="replace"))


def zip_entries(data: bytes) -> Iterator[tuple[str, bytes]]:
    import io

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if not info.is_dir():
                yield info.filename, zf.read(info)


PDF_STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)
PDF_LITERAL_RE = re.compile(rb"\((?:\\.|[^\\)])*\)", re.DOTALL)
PDF_HEX_RE = re.compile(rb"<([0-9A-Fa-f\s]{4,})>")


def pdf_text(data: bytes) -> str:
    """Raw PDF bytes plus every decompressible stream, reduced to printable strings and the text
    of its string literals (TJ arrays are joined, so kerned words come back together)."""
    chunks = [data]
    for m in PDF_STREAM_RE.finditer(data):
        body = m.group(1)
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                chunks.append(zlib.decompress(body, wbits))
                break
            except zlib.error:
                continue
    out: list[str] = []
    for c in chunks:
        out += printable_strings(c, 4)
        lits = []
        for lm in PDF_LITERAL_RE.finditer(c):
            s = lm.group(0)[1:-1]
            s = re.sub(rb"\\([nrtbf])", b" ", s)
            s = re.sub(rb"\\([0-7]{1,3})", lambda x: bytes([int(x.group(1), 8) & 0xFF]), s)
            lits.append(re.sub(rb"\\(.)", rb"\1", s).decode("latin-1"))
        for hm in PDF_HEX_RE.finditer(c):
            try:
                lits.append(bytes.fromhex(re.sub(rb"\s", b"", hm.group(1)).decode()).decode("latin-1"))
            except ValueError:
                continue
        if lits:
            out.append("".join(lits))
            out.append(" ".join(lits))
    return "\n".join(out)


def png_text_chunks(data: bytes) -> Iterator[str]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return
    pos = 8
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        try:
            if ctype == b"tEXt":
                yield body.replace(b"\x00", b": ").decode("latin-1")
            elif ctype == b"zTXt":
                key, _, rest = body.partition(b"\x00")
                yield key.decode("latin-1") + ": " + zlib.decompress(rest[1:]).decode("latin-1")
            elif ctype == b"iTXt":
                key, _, rest = body.partition(b"\x00")
                compressed, rest = rest[0], rest[2:]
                _lang, _, rest = rest.partition(b"\x00")
                _tkey, _, txt = rest.partition(b"\x00")
                txt = zlib.decompress(txt) if compressed else txt
                yield key.decode("latin-1") + ": " + txt.decode("utf-8", errors="replace")
            elif ctype in (b"eXIf",):
                yield "\n".join(printable_strings(body))
        except (zlib.error, IndexError, UnicodeDecodeError):
            continue
        if ctype == b"IEND":
            break


def printable_strings(data: bytes, min_len: int = 6) -> list[str]:
    return [m.group(0).decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data)]


def scan_file(path: Path, rel: str, denylist: list[DenyRule], reduced: bool = False) -> list[Finding]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"warning: cannot read {rel}: {exc}", file=sys.stderr)
        return [Finding(rel, 0, "unreadable", path.name)]
    pinned = ALLOWLISTED_BINARIES.get(rel)
    if pinned is not None and hashlib.sha256(data).hexdigest() == pinned:
        return scan_bytes(data, rel, denylist, reduced=reduced, forbid=False, allow_binary=True)
    return scan_bytes(data, rel, denylist, reduced=reduced, suffix=path.suffix.lower())


def scan_bytes(data: bytes, rel: str, denylist: list[DenyRule], *, reduced: bool = False, suffix: str = "",
               forbid: bool = True, allow_binary: bool = False, _depth: int = 0) -> list[Finding]:
    """Dispatch on content (magic bytes), not on the file name, so a renamed archive is still opened."""
    out: list[Finding] = []
    if forbid and suffix in FORBIDDEN_SUFFIXES:
        out.append(Finding(rel, 0, "forbidden_format", rel.rsplit("/", 1)[-1]))
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        try:
            for name, body in zip_entries(data):
                part = f"{rel}[{name}]"
                if name.endswith((".xml", ".rels")):
                    out += scan_text(_xml_to_text(body.decode("utf-8", errors="replace")), part, denylist, reduced=reduced)
                elif _depth < MAX_DEPTH:
                    out += scan_bytes(body, part, denylist, reduced=reduced, suffix=Path(name).suffix.lower(),
                                      allow_binary=allow_binary, _depth=_depth + 1)
                else:
                    out.append(Finding(part, 0, "binary", "nested too deep"))
            return out
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:  # encrypted / unsupported
            out.append(Finding(rel, 0, "binary", f"unreadable zip ({type(exc).__name__})"))
            return out + scan_text("\n".join(printable_strings(data)), f"{rel}[strings]", denylist, reduced=reduced)
    if data.startswith(b"%PDF-"):
        return out + scan_text(pdf_text(data), f"{rel}[pdf]", denylist, reduced=reduced)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return out + scan_text("\n".join(png_text_chunks(data)), f"{rel}[png-text]", denylist, reduced=reduced)
    if b"\x00" not in data[:8192]:
        return out + scan_text(data.decode("utf-8", errors="replace"), rel, denylist, reduced=reduced, _depth=_depth)
    if not allow_binary:
        out.append(Finding(rel, 0, "binary", "unrecognised binary"))
    return out + scan_text("\n".join(printable_strings(data)), f"{rel}[strings]", denylist, reduced=reduced)


# ----------------------------------------------------------------------------- file selection
def _gitignore_patterns(root: Path) -> list[str]:
    gi = root / ".gitignore"
    if not gi.exists():
        return []
    pats = []
    for line in gi.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            pats.append(s)
    return pats


def _match_one(rel: str, is_dir: bool, pat: str) -> bool:
    dir_only = pat.endswith("/")
    p = pat.rstrip("/")
    anchored = p.startswith("/") or "/" in p
    p = p.lstrip("/")
    if dir_only and not is_dir:
        return False
    if anchored:
        return fnmatch.fnmatchcase(rel, p) or fnmatch.fnmatchcase(rel, p + "/**")
    return fnmatch.fnmatchcase(rel.rsplit("/", 1)[-1], p)


def is_ignored(rel: str, is_dir: bool, patterns: list[str]) -> bool:
    """Last matching pattern wins; `!pattern` re-includes. Parent-directory ignores are handled by the walker."""
    ignored = False
    for pat in patterns:
        neg = pat.startswith("!")
        body = pat[1:] if neg else pat
        if _match_one(rel, is_dir, body):
            ignored = not neg
    return ignored


def _in_dirs(rel: str, dirs: set[str]) -> bool:
    return any(rel == d or rel.startswith(d + "/") for d in dirs)


def _skip_dir(rel: str) -> bool:
    return _in_dirs(rel, ALWAYS_SKIP_DIRS)


def candidate_files(root: Path) -> list[str]:
    try:
        inside = subprocess.run(["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
                                capture_output=True, text=True, check=False)
        if inside.returncode == 0 and inside.stdout.strip() == "true":
            res = subprocess.run(
                ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                capture_output=True, check=True,
            )
            files = [f for f in res.stdout.decode("utf-8").split("\0") if f]
            return sorted(f for f in files if not _skip_dir(f) and (root / f).is_file())
    except (OSError, subprocess.CalledProcessError):
        pass
    patterns = _gitignore_patterns(root)
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        keep = []
        for d in dirnames:
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if not _skip_dir(rel) and not is_ignored(rel, True, patterns):
                keep.append(d)
        dirnames[:] = sorted(keep)
        for fn in sorted(filenames):
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
            if not is_ignored(rel, False, patterns) and not Path(dirpath, fn).is_symlink():
                out.append(rel)
    return out


# ----------------------------------------------------------------------------- main
def scan(root: Path, files: list[str] | None, denylist: list[DenyRule]) -> list[Finding]:
    findings: list[Finding] = []
    if files is not None:  # expand directories given on the command line
        expanded: list[str] = []
        for f in files:
            d = Path(f) if Path(f).is_absolute() or (Path.cwd() / f).exists() else root / f
            if d.is_dir():
                expanded += [str(d / sub) for sub in candidate_files(d)]
            else:
                expanded.append(f)
        files = expanded
    for rel in files if files is not None else candidate_files(root):
        p = Path(rel)
        if not p.is_absolute():
            # explicit paths are relative to the caller's cwd; walked paths to the repo root
            p = Path.cwd() / rel if files is not None and (Path.cwd() / rel).exists() else root / rel
        try:
            rel_s = p.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel_s = str(p)
        if _skip_dir(rel_s) or p.suffix.lower() in SKIP_SUFFIXES or not p.is_file():
            continue
        findings += scan_file(p, rel_s, denylist, reduced=_in_dirs(rel_s, REDUCED_RULE_DIRS))
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scan files that would be committed for PII and secrets.")
    ap.add_argument("paths", nargs="*", help="files to scan (default: every file that would be committed)")
    ap.add_argument("--denylist", help="denylist file (default: $AEGIS_DENYLIST); keep it outside the repo")
    ap.add_argument("--root", default=str(REPO_ROOT), help="repository root (default: this repo)")
    ap.add_argument("--require-denylist", action="store_true", help="fail if no denylist is configured")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    deny_path = args.denylist or os.environ.get("AEGIS_DENYLIST") or None
    if deny_path:
        dp = Path(deny_path).expanduser().resolve()
        if not dp.is_file():
            print(f"error: denylist {dp} not found", file=sys.stderr)
            return 2
        if dp.is_relative_to(root):
            print("error: the denylist must live outside the repository (it lists real identifiers)", file=sys.stderr)
            return 2
    elif args.require_denylist:
        print("error: no denylist configured (set AEGIS_DENYLIST or pass --denylist)", file=sys.stderr)
        return 2
    else:
        print("note: no denylist configured (AEGIS_DENYLIST); running generic rules only", file=sys.stderr)
    denylist = load_denylist(deny_path)

    findings = scan(root, args.paths or None, denylist)
    for f in findings:
        print(f.render())
    n_files = len({f.path.split("[", 1)[0] for f in findings})
    if findings:
        print(f"\npii_scan: {len(findings)} finding(s) in {n_files} file(s)", file=sys.stderr)
        return 1
    print("pii_scan: clean", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
