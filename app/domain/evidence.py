"""Evidence register: folders, ingest (upload / reference / inline), integrity, role rules, LE contacts.

Owner: the evidence feature (router app/web/routes_evidence.py, CLI scripts/import_evidence.py).

Storage modes (EvidenceStorage):

* ``reference`` — metadata and hash only. ``source_path`` points at the original, which is opened
  read-only and **never copied**. Two compound forms are understood: ``/abs/archive.zip!member/path``
  (a zip member, read from the archive without extracting it) and ``/abs/Letter.rtfd`` (a macOS
  RTF bundle, hashed as its ``TXT.rtf``).
* ``vault`` — an uploaded file stored under ``AEGIS_VAULT_DIR`` as ``<case_id>/<uuid>`` (no original
  file name on disk). The vault must be an absolute path **outside** the repository; uploads are
  refused otherwise. Encryption at rest is out of scope here (an encrypted volume is the operator's
  job, docs/data-handling.md §3).
* ``inline`` — a short text held in the database.

Every item carries a sha256 computed on ingest; `verify_integrity` re-hashes and records the result
in ``verified_at`` (match) or ``meta["integrity"]`` (mismatch / missing).

Role rules (on top of the tab's minimum role):

* ``financial`` items exist only for case admins.
* External members see only items with ``shared_with_external``.
* Content (inline text, preview, download) of an R3 item needs investigator or above; read-only
  and external members see its metadata only.
* ``source_path`` (where the original lives) is shown to admins only.
* LE contacts: hidden from externals, masked for read-only (``M. L*****``), full for investigators.
* Complaint references (``DEMO-IT-0000000000``) inside evidence metadata (title, description, tags,
  received from) are masked below view_restricted (``DEMO-IT-******00``), like on the Overview
  (`ref_mask`).
* The 'Stop orders & correspondence' folder also lists the case's stop orders and letters as
  virtual entries (`linked_entries`), next to the evidence items filed there.
"""

from __future__ import annotations

import contextlib
import errno
import fnmatch
import hashlib
import io
import json
import mimetypes
import os
import re
import stat
import uuid
import zipfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import IO, Any

from sqlalchemy import select
from sqlalchemy.orm import Session, object_session

from app.core import events
from app.core import permissions as perms
from app.db.models import (
    Case,
    Classification,
    Correspondence,
    EvidenceFolder,
    EvidenceItem,
    EvidenceStorage,
    LEContact,
    TraceRun,
    User,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
# Synthetic demo artifacts shipped with the repo (data/fixtures/demo_evidence). A reference item with
# no source_path may name one of them as meta.demo_file (repo-relative); nothing else in the repo is
# ever read or served as evidence.
DEMO_EVIDENCE_DIR = REPO_ROOT / "data" / "fixtures" / "demo_evidence"
CHUNK = 1 << 20
MAX_INLINE_BYTES = 256 * 1024  # inline notes / --mode inline imports
MAX_PREVIEW_TEXT = 512 * 1024  # text files shown in the page
DEFAULT_MAX_UPLOAD_MB = 200
SKIP_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini", "Icon\r"}


class EvidenceError(ValueError):
    """A request the evidence register refuses (bad path, vault not configured, …)."""


# --------------------------------------------------------------------------- folders
@dataclass(frozen=True)
class Section:
    key: str
    label: str


@dataclass(frozen=True)
class FolderSpec:
    folder: EvidenceFolder
    label: str
    sections: tuple[Section, ...] = ()
    admin_only: bool = False
    hint: str = ""


FOLDERS: tuple[FolderSpec, ...] = (
    FolderSpec(EvidenceFolder.LAW_ENFORCEMENT, "Law enforcement",
               (Section("contacts", "Contacts"), Section("reports", "Reports & complaints")),
               hint="Police and IC3 complaints, statements, powers of attorney / agent"),
    FolderSpec(EvidenceFolder.DIGITAL_ARTIFACTS, "Digital artifacts",
               (Section("messaging", "Messaging"), Section("recordings", "Recordings & transcripts"),
                Section("screenshots", "Screenshots"), Section("emails", "E-mails")),
               hint="Chats, call recordings and transcripts, screenshots, e-mails"),
    FolderSpec(EvidenceFolder.INVESTIGATOR_REPORTS, "Investigator reports",
               hint="PI work product, intelligence reports, fund-flow graphs, invoices"),
    FolderSpec(EvidenceFolder.STOP_ORDERS_CORRESPONDENCE, "Stop orders & correspondence",
               hint="Letters as sent and replies; linked to the case's stop orders and correspondence"),
    FolderSpec(EvidenceFolder.LEGAL, "Legal & deal documents", hint="Contracts, term sheets, counsel letters"),
    FolderSpec(EvidenceFolder.FINANCIAL, "Financial", admin_only=True,
               hint="Bank and exchange statements, due diligence (case admins only)"),
    FolderSpec(EvidenceFolder.CHAIN_REPORTS, "Chain reports", hint="Trace exports saved as evidence"),
    FolderSpec(EvidenceFolder.OTHER, "Other"),
)
FOLDER_SPEC: dict[EvidenceFolder, FolderSpec] = {f.folder: f for f in FOLDERS}
SECTION_KEYS: dict[EvidenceFolder, tuple[str, ...]] = {
    f.folder: tuple(s.key for s in f.sections if s.key != "contacts") for f in FOLDERS
}


def folder_label(folder: EvidenceFolder | str) -> str:
    return FOLDER_SPEC[EvidenceFolder(folder)].label


# a source type as people read it (the stored value stays the key: "police_report" → "Police report")
SOURCE_TYPE_LABELS = {
    "complaint_receipt": "Complaint receipt", "authority_instrument": "Authority document", "police_report": "Police report",
    "chat_export": "Chat export", "chat": "Chat", "transcript": "Transcript", "screenshot": "Screenshot",
    "eml": "E-mail (.eml)", "msg": "E-mail (.msg)", "email_attachment": "E-mail attachment", "upload": "Upload",
    "note": "Note", "text": "Text", "trace_report": "Trace report", "pdf": "PDF",
}


def source_type_label(value: str | None) -> str:
    """'police_report' → 'Police report'; an unknown key is shown with spaces, its first letter capitalised."""
    v = (value or "").strip()
    if not v:
        return ""
    if v.lower() in SOURCE_TYPE_LABELS:
        return SOURCE_TYPE_LABELS[v.lower()]
    v = v.replace("_", " ")
    return v[:1].upper() + v[1:]


def as_folder(value: str | EvidenceFolder | None) -> EvidenceFolder:
    try:
        return EvidenceFolder(value or "other")
    except ValueError as e:
        raise EvidenceError(f"unknown evidence folder {value!r}") from e


def as_classification(value: str | Classification | None, default: Classification = Classification.R3
                      ) -> Classification:
    if not value:
        return default
    try:
        return Classification(value)
    except ValueError as e:
        raise EvidenceError(f"unknown classification {value!r}") from e


# higher = more restricted; lowering an item's tier is a declassification (case admins only)
CLASSIFICATION_RANK: dict[Classification, int] = {
    Classification.I0: 0, Classification.C1: 1, Classification.R2: 2, Classification.R3: 3,
}


def infer_section(folder: EvidenceFolder, *, source_type: str | None = None, mime: str | None = None,
                  title: str | None = None) -> str | None:
    """Best-guess sub-section for folders that have them (used when meta.section is unset)."""
    text = " ".join(x for x in (source_type, title) if x).lower()
    mime = (mime or "").lower()
    if folder == EvidenceFolder.LAW_ENFORCEMENT:
        return "reports"
    if folder != EvidenceFolder.DIGITAL_ARTIFACTS:
        return None
    if _has_kw(text, ("whatsapp", "chat", "telegram", "signal", "messag", "sms")):
        return "messaging"
    if mime.startswith(("video/", "audio/")) or _has_kw(text, ("transcript", "recording", "meeting", "call")):
        return "recordings"
    if mime in ("message/rfc822", "application/vnd.ms-outlook") or _has_kw(text, ("email", "e-mail", "eml")):
        return "emails"
    if mime.startswith("image/") or _has_kw(text, ("screenshot",)):
        return "screenshots"
    return None


def section_of(item: EvidenceItem) -> str | None:
    section = (item.meta or {}).get("section")
    if section in SECTION_KEYS.get(item.folder, ()):
        return section
    return infer_section(item.folder, source_type=item.source_type, mime=item.mime, title=item.title)


def _has_kw(text: str, keywords: Iterable[str]) -> bool:
    return any(re.search(rf"(?<![a-z0-9]){re.escape(k)}", text) for k in keywords)


# --------------------------------------------------------------------------- permissions
# Evidence-specific actions. They follow permissions.ACTIONS when the integrator adds them there
# (one line each); until then this table is the source of truth.
EVIDENCE_ACTIONS: dict[str, perms.CaseRole] = {
    "view_financial": perms.ADMIN,  # the Financial folder
    "view_source_path": perms.ADMIN,  # where a referenced original lives
    "delete_evidence": perms.ADMIN,
    "verify_evidence": perms.INVESTIGATOR,
}


def allowed(access: perms.CaseAccess, action: str) -> bool:
    min_role = perms.ACTIONS.get(action) or EVIDENCE_ACTIONS[action]
    return access.at_least(min_role)


def can_see(access: perms.CaseAccess, item: EvidenceItem) -> bool:
    """May this member see the item's metadata at all?"""
    if item.case_id != access.case.id:
        return False
    if item.folder == EvidenceFolder.FINANCIAL and not allowed(access, "view_financial"):
        return False
    return item.shared_with_external or not access.is_external


def can_open(access: perms.CaseAccess, item: EvidenceItem) -> bool:
    """May this member read the content (inline text, preview, download)? R3 needs investigator+."""
    if not can_see(access, item):
        return False
    return item.classification != Classification.R3 or allowed(access, "view_restricted")


def visible_items(access: perms.CaseAccess) -> list[EvidenceItem]:
    items = [e for e in access.case.evidence_items if can_see(access, e)]
    return sorted(items, key=lambda e: (e.doc_date or e.created_at or datetime.min.replace(tzinfo=UTC), e.id),
                  reverse=True)


def flags_for(access: perms.CaseAccess) -> dict[str, bool]:
    """Booleans the templates use (the shell's can() knows only permissions.ACTIONS)."""
    return {
        "add": allowed(access, "add_evidence"),
        "verify": allowed(access, "verify_evidence"),
        "restricted": allowed(access, "view_restricted"),
        "financial": allowed(access, "view_financial"),
        "source_path": allowed(access, "view_source_path"),
        "share": allowed(access, "share_external"),
        "delete": allowed(access, "delete_evidence"),
        "contacts": not access.is_external,
        "manage_contacts": allowed(access, "manage_le_contacts"),
        "contacts_masked": not allowed(access, "manage_le_contacts"),
        "trace_report": allowed(access, "add_evidence"),
    }


# --------------------------------------------------------------------------- masking (LE contacts)
def mask_name(name: str | None) -> str | None:
    """'Mara Lindqvist' -> 'M. L*****' (fixed-length stars: the length is not revealed)."""
    if not name or not name.strip():
        return name
    parts = [p for p in re.split(r"\s+", name.strip()) if p]
    if len(parts) == 1:
        return parts[0][0] + "*****"
    return f"{parts[0][0]}. {parts[-1][0]}*****"


def mask_email(email: str | None) -> str | None:
    """'mara.lindqvist@kestrel-ridge.example' -> 'm***@k***.example'."""
    if not email or "@" not in email:
        return "***" if email else email
    local, _, domain = email.strip().partition("@")
    labels = domain.split(".")
    tld = labels[-1] if len(labels) > 1 else ""
    return f"{local[:1]}***@{domain[:1]}***" + (f".{tld}" if tld else "")


def mask_phone(phone: str | None) -> str | None:
    """'+41 00 000 00 00' -> '+41 *** *** 00' (country code and last two digits kept)."""
    if not phone:
        return phone
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 4:
        return "***"
    prefix = f"+{digits[:2]} " if phone.strip().startswith("+") else ""
    return f"{prefix}*** *** {digits[-2:]}"


def mask_reference(ref: str | None) -> str | None:
    """'DEMO-IT-0000000000' -> 'DEMO-IT-******00': the letter prefix and the last two characters."""
    if not ref:
        return ref
    m = re.match(r"^([A-Za-z]+(?:[-_ ][A-Za-z]+)*[-_ ]?)", ref)
    prefix = m.group(1) if m else ""
    rest = ref[len(prefix):]
    return prefix + "******" + (rest[-2:] if len(rest) > 4 else "")


def known_references(case: Case) -> list[str]:
    """Complaint / LE references the case holds (facts.complaints, complaints_pending, LE contacts)."""
    facts = case.facts or {}
    refs = [c.get("reference") for c in [*(facts.get("complaints") or []), *(facts.get("complaints_pending") or [])]
            if isinstance(c, dict)]
    refs += [le.reference for le in case.le_contacts]
    out = []
    for r in refs:
        r = str(r or "").strip()
        if len(r) >= 4 and "enter here" not in r.lower() and r not in out:
            out.append(r)
    return out


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


@dataclass
class RefMask:
    """Masks the case's complaint references and its LE / PI contact details (names and their
    variants, e-mails, phones; any address on a PI firm's own domain) inside free text, for members
    below view_restricted. `md=True` returns the masked values Markdown-escaped (their ``*`` must
    not turn into emphasis in a rendered letter or a .docx)."""

    refs: dict[str, str] = field(default_factory=dict)  # lower-cased known value -> masked
    domains: frozenset[str] = frozenset()  # lower-cased e-mail domains whose addresses are masked
    _pattern: re.Pattern | None = None

    @property
    def active(self) -> bool:
        return bool(self.refs or self.domains)

    def __call__(self, text, *, md: bool = False):
        if not self.active or not text or not isinstance(text, str):
            return text
        if md:
            from app.reports.stop_orders import md_escape

            esc = md_escape
        else:
            def esc(v):
                return v
        if self.refs:
            if self._pattern is None:
                alts = "|".join(re.escape(r) for r in sorted(self.refs, key=len, reverse=True))
                self._pattern = re.compile(rf"(?<![\w@])(?:{alts})(?![\w@])", re.IGNORECASE)
            text = self._pattern.sub(lambda m: esc(self.refs.get(m.group(0).lower(), "******")), text)
        if self.domains:
            text = _EMAIL_RE.sub(lambda m: esc(mask_email(m.group(0)) or "***")
                                 if _on_domain(m.group(1), self.domains) else m.group(0), text)
        return text

    def tags(self, tags) -> list[str]:
        return [self(t) for t in tags or []]


def _on_domain(domain: str, domains: frozenset[str]) -> bool:
    d = domain.lower()
    return any(d == x or d.endswith("." + x) for x in domains)


def masked_values(case: Case) -> dict[str, str]:
    """Every value the masks hide below view_restricted, lower-cased -> masked: the complaint
    references and the LE / PI contact details (app.domain.correspondence.contact_values)."""
    from app.domain.correspondence import contact_values

    out = {r.lower(): mask_reference(r) or "******" for r in known_references(case)}
    for k, v in contact_values(case).items():
        out.setdefault(k, v)
    return out


def ref_mask(access: perms.CaseAccess) -> RefMask:
    """The RefMask for `access`: inactive (identity) for investigators and admins."""
    from app.domain.correspondence import contact_domains

    if allowed(access, "view_restricted"):
        return RefMask()
    return RefMask(masked_values(access.case), contact_domains(access.case))


@dataclass
class ContactView:
    id: int
    agency: str
    unit: str | None
    role: str | None
    name: str | None
    email: str | None
    phone: str | None
    reference: str | None
    jurisdiction: str | None
    notes: str | None
    classification: str
    masked: bool
    row: LEContact | None = None


def contact_view(access: perms.CaseAccess, c: LEContact) -> ContactView:
    masked = not allowed(access, "manage_le_contacts")
    return ContactView(
        id=c.id, agency=c.agency, unit=c.unit, role=c.role, jurisdiction=c.jurisdiction,
        classification=c.classification.value, masked=masked,
        name=mask_name(c.name) if masked else c.name,
        email=mask_email(c.email) if masked else c.email,
        phone=mask_phone(c.phone) if masked else c.phone,
        reference=mask_reference(c.reference) if masked else c.reference,
        notes=None if masked else c.notes,
        row=None if masked else c,
    )


def contacts_for(access: perms.CaseAccess) -> list[ContactView]:
    if access.is_external:
        return []
    return [contact_view(access, c) for c in sorted(access.case.le_contacts, key=lambda c: (c.agency, c.id))]


CONTACT_FIELDS = ("agency", "unit", "role", "name", "email", "phone", "reference", "jurisdiction", "notes")


def save_contact(db: Session, case: Case, values: dict[str, Any], *, contact: LEContact | None = None,
                 actor: User | None = None) -> LEContact:
    """Create or update an LE contact (caller audits, which commits)."""
    clean = {k: (str(values.get(k) or "").strip() or None) for k in CONTACT_FIELDS}
    if not clean["agency"]:
        raise EvidenceError("agency is required")
    if clean["email"] and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", clean["email"]):
        raise EvidenceError("not an e-mail address")
    if contact is None:
        contact = LEContact(case=case, agency=clean["agency"], created_by=actor.id if actor else None)
        db.add(contact)
    for k, v in clean.items():
        setattr(contact, k, v)
    contact.classification = as_classification(values.get("classification"), Classification.R3)
    db.flush()
    return contact


# --------------------------------------------------------------------------- paths & configuration
def _inside_repo(path: Path) -> bool:
    try:
        return path.resolve().is_relative_to(REPO_ROOT.resolve())
    except OSError:
        return True  # fail closed


def configured_vault_dir() -> str:
    """AEGIS_VAULT_DIR from the environment, else Settings.aegis_vault_dir when the integrator adds it."""
    value = os.environ.get("AEGIS_VAULT_DIR")
    if value is None:
        from app.core.config import get_settings

        value = getattr(get_settings(), "aegis_vault_dir", "") or ""
    return value.strip()


def vault_dir(*, create: bool = True) -> Path:
    """The evidence vault root. Raises EvidenceError when unset, relative or inside the repository."""
    raw = configured_vault_dir()
    if not raw:
        raise EvidenceError("AEGIS_VAULT_DIR is not set: uploads are disabled until it points at a "
                            "directory outside the repository (ideally an encrypted volume)")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise EvidenceError("AEGIS_VAULT_DIR must be an absolute path")
    if _inside_repo(path):
        raise EvidenceError("AEGIS_VAULT_DIR is inside the repository: refusing to store evidence there")
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path.resolve()


def vault_status() -> tuple[bool, str]:
    """(uploads enabled?, reason) for the UI. Never reveals the vault path."""
    try:
        vault_dir(create=False)
    except EvidenceError as e:
        return False, str(e)
    return True, "uploads are stored in the evidence vault (outside the repository)"


def evidence_root_specs() -> list[tuple[str | None, Path]]:
    """The configured AEGIS_EVIDENCE_ROOTS entries (os.pathsep-separated), as (case reference, root).

    * ``REFERENCE=/abs/dir`` allows that directory for the case with that reference only;
    * a plain ``/abs/dir`` allows ``/abs/dir/<case reference>/`` for each case.

    The CLI importer is not limited by this: it runs as the operator on the machine."""
    raw = os.environ.get("AEGIS_EVIDENCE_ROOTS")
    if raw is None:
        from app.core.config import get_settings

        raw = getattr(get_settings(), "aegis_evidence_roots", "") or ""
    specs: list[tuple[str | None, Path]] = []
    for part in raw.split(os.pathsep):
        part = part.strip()
        ref: str | None = None
        if "=" in part and not part.startswith("/"):
            ref, part = (x.strip() for x in part.split("=", 1))
        if part and Path(part).is_absolute():
            specs.append((ref or None, Path(part).expanduser().resolve()))
    return specs


def evidence_roots() -> list[Path]:
    """Every configured base root (see evidence_root_specs). Use case_evidence_roots for a decision."""
    return [root for _, root in evidence_root_specs()]


# a reference only names a directory when it is a plain ASCII name (no case or Unicode
# normalisation games on the file system); app.services.REFERENCE_RE is what new cases must match
_DIR_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _reference_dir_name(reference: str | None) -> str | None:
    ref = (reference or "").strip()
    if ref != (reference or "") or not _DIR_NAME.fullmatch(ref) or ref in (".", ".."):
        return None
    return ref


def _plain_roots_apply(case: Case) -> bool:
    """Plain roots (<root>/<case reference>/) serve only cases the operator opened: seeded or created
    on the machine (no creator) or opened by a system administrator. A reference chosen by a user
    who merely holds can_create_cases never claims a directory that is already on disk; such a case
    needs an explicit REFERENCE=<dir> entry from the operator."""
    if case.created_by is None:
        return True
    db = object_session(case)
    creator = db.get(User, case.created_by) if db is not None else None
    return bool(creator is not None and creator.is_system_admin)


def _same_dir(a: Path, b: Path) -> bool:
    """a and b are the same directory, or one lies inside the other (by identity, not by text)."""
    try:
        if a.exists() and b.exists() and os.path.samefile(a, b):
            return True
        ra, rb = a.resolve(), b.resolve()
    except OSError:
        return True  # fail closed
    return ra.is_relative_to(rb) or rb.is_relative_to(ra)


def _clashes(d: Path, entry: Path) -> bool:
    """Another root entry (or another case's directory) takes d away from this case.

    A real directory belongs to the entry spelled like it: a symlink elsewhere that points at it
    never claims it (and is refused for its own case). A symlinked d shares with nobody."""
    try:
        if not entry.exists():
            return False
        if not d.is_symlink() and entry.is_symlink():
            return False
    except OSError:
        return True
    return _same_dir(d, entry)


def _exact_child(root: Path, name: str) -> Path | None:
    """root/name when it is spelled exactly `name` on disk and no other entry of root is (or holds,
    or lies in) that directory.

    On a case-insensitive file system (macOS APFS by default) root/'demo-2026-001' opens the
    directory 'DEMO-2026-001'; that directory belongs to the case spelled that way, not to this one."""
    d = root / name
    try:
        if not d.exists():
            return d.resolve()  # nothing to read yet; re-checked on every request
        names = os.listdir(root)
    except OSError:
        return None
    if name not in names:
        return None
    if any(_clashes(d, root / other) for other in names if other != name):
        return None
    try:
        return d.resolve()
    except OSError:
        return None


def case_evidence_roots(case: Case) -> list[Path]:
    """The directories one case may reference originals from (never another case's subtree).

    * ``REFERENCE=<dir>`` entries (operator-assigned) match the reference exactly;
    * plain roots give ``<root>/<reference>/`` to operator-opened cases (_plain_roots_apply), with the
      directory compared by identity: it must be spelled exactly like the reference and must not be
      (or contain, or lie in) another case's directory or another reference's explicit directory."""
    specs = evidence_root_specs()
    out = [root for ref, root in specs if ref is not None and ref == case.reference]
    name = _reference_dir_name(case.reference)
    plain = [root for ref, root in specs if ref is None]
    if name is None or not plain or not _plain_roots_apply(case):
        return out
    explicit_other = [root for ref, root in specs if ref is not None and ref != case.reference]
    db = object_session(case)
    others = list(db.scalars(select(Case.reference).where(Case.id != case.id))) if db is not None else []
    others_dirs = [n for n in map(_reference_dir_name, others) if n is not None]
    for root in plain:
        d = _exact_child(root, name)
        if d is None:
            continue
        if any(_same_dir(d, e) for e in explicit_other):
            continue
        if any(_clashes(root / name, other_root / n) for other_root in plain for n in others_dirs
               if not (other_root == root and n == name)):
            continue
        out.append(d)
    return out


_ZIP_REF = re.compile(r"^(?P<zip>.+?\.zip)!(?P<member>.+)$", re.IGNORECASE)
NOT_ALLOWED = "no readable original at that path under this case's evidence roots"


@dataclass(frozen=True)
class SourceRef:
    """A parsed reference: a plain file, a zip member, or an .rtfd bundle (hashed as TXT.rtf)."""

    path: Path  # the file on disk (the zip archive for members, the bundle directory for .rtfd)
    member: str | None = None  # zip member name

    @property
    def kind(self) -> str:
        if self.member is not None:
            return "zip_member"
        return "rtfd" if self.path.suffix.lower() == ".rtfd" else "file"

    @property
    def display_name(self) -> str:
        return _basename(self.member) if self.member else self.path.name

    @property
    def target(self) -> Path:
        """The file actually opened: the archive, the bundle's TXT.rtf, or the file itself."""
        return self.path / "TXT.rtf" if self.kind == "rtfd" else self.path

    def as_source_path(self) -> str:
        return f"{self.path}!{self.member}" if self.member is not None else str(self.path)


def _basename(name: str) -> str:
    return name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def parse_reference(source_path: str) -> SourceRef:
    m = _ZIP_REF.match(source_path)
    if m:
        return SourceRef(Path(m.group("zip")), m.group("member"))
    return SourceRef(Path(source_path))


def _inside_vault(path: Path) -> bool:
    raw = configured_vault_dir()
    if not raw or not Path(raw).is_absolute():
        return False
    try:
        return path.resolve().is_relative_to(Path(raw).expanduser().resolve())
    except OSError:
        return True  # fail closed


def _is_symlink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except OSError:
        return True


def _target_allowed(ref: SourceRef, roots: list[Path] | None) -> bool:
    """The file that would be read is a regular file (not a symlink), outside the repository and
    the vault, and, when `roots` is given, inside one of them once every link is resolved."""
    target = ref.target
    if _is_symlink(target):
        return False
    try:
        real = target.resolve()
    except OSError:
        return False
    if _inside_repo(real) or _inside_vault(real):
        return False
    if ref.kind == "rtfd" and not real.is_relative_to(ref.path.resolve()):
        return False
    return roots is None or any(real.is_relative_to(r) for r in roots)


def check_reference_path(source_path: str, *, restrict_to_roots: bool = True, case: Case | None = None) -> SourceRef:
    """Validate a path given for a reference item and return it with every link resolved.

    Web requests restrict it to the case's own evidence roots (case_evidence_roots); every request
    refuses the repository (that is where .env and keys live), the vault and a symlinked final file.
    Paths that are not allowed and paths that do not exist get the same answer (no existence oracle)."""
    source_path = (source_path or "").strip()
    if not source_path:
        raise EvidenceError("a file path is required")
    ref = parse_reference(source_path)
    if not ref.path.is_absolute():
        raise EvidenceError("the reference path must be absolute")
    if _inside_repo(ref.path):
        raise EvidenceError("the path is inside the repository: originals never live there")
    roots = None
    if restrict_to_roots:
        roots = case_evidence_roots(case) if case is not None else evidence_roots()
        if not roots:
            raise EvidenceError("referencing files from the web UI needs AEGIS_EVIDENCE_ROOTS for this case "
                                "(<root>/<case reference>/ or REFERENCE=<dir>); use scripts/import_evidence.py "
                                "on the machine instead")
    try:
        resolved = SourceRef(ref.path.resolve(), ref.member)
    except OSError:
        raise EvidenceError(NOT_ALLOWED) from None
    if not _target_allowed(ref, roots) or not _target_allowed(resolved, roots) or not resolved.target.is_file():
        raise EvidenceError(NOT_ALLOWED)
    if resolved.member is not None:
        try:
            with _open_nofollow(resolved.path) as fh, zipfile.ZipFile(fh) as zf:
                _zip_entry(zf, resolved.member)
        except (zipfile.BadZipFile, KeyError, OSError):
            raise EvidenceError(NOT_ALLOWED) from None
    return resolved


def zip_name(info: zipfile.ZipInfo) -> str:
    """A member's name as its author meant it. Without the UTF-8 flag (bit 0x800) zipfile decodes
    the raw bytes as cp437, which garbles the UTF-8 names most archivers (macOS Archive Utility,
    Windows) write anyway: try the cp437 -> UTF-8 round trip and keep cp437 when it fails."""
    name = info.filename
    if info.flag_bits & 0x800:
        return name
    try:
        return name.encode("cp437").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return name


def _zip_entry(zf: zipfile.ZipFile, member: str) -> zipfile.ZipInfo:
    """The zip entry to read for a member reference (by its decoded name, or the raw one).

    'x.rtfd' is read as the bundle's 'x.rtfd/TXT.rtf' only when the archive holds that directory;
    a flat file whose name merely ends in .rtfd is read as itself. Raises KeyError."""
    by_name: dict[str, zipfile.ZipInfo] = {}
    for info in zf.infolist():
        by_name.setdefault(zip_name(info), info)
        by_name.setdefault(info.filename, info)
    m = member.rstrip("/")
    if m.lower().endswith(".rtfd"):
        prefix = m + "/"
        if any(n.startswith(prefix) for n in by_name):
            info = by_name.get(prefix + "TXT.rtf")
            if info is None:
                raise KeyError(f"bundle without TXT.rtf: {m!r}")
            return info
    info = by_name.get(member) or by_name.get(m)
    if info is None or info.is_dir():
        raise KeyError(f"no such member: {member!r}")
    return info


def _open_nofollow(path: Path) -> IO[bytes]:
    """Open read-only, refusing a symlink as the final component (O_NOFOLLOW)."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise EvidenceError("refusing to follow a symbolic link") from e
        raise
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise EvidenceError("not a regular file")
    return os.fdopen(fd, "rb")


class _MemberStream:
    """A zip member opened from an O_NOFOLLOW archive handle; closing it closes everything."""

    def __init__(self, archive: Path, member: str):
        self._fh = _open_nofollow(archive)
        try:
            self._zf = zipfile.ZipFile(self._fh)
            self._member = self._zf.open(_zip_entry(self._zf, member))
        except Exception:
            self._fh.close()
            raise

    def read(self, n: int = -1) -> bytes:
        return self._member.read(n)

    def close(self) -> None:
        for x in (self._member, self._zf, self._fh):
            with contextlib.suppress(Exception):  # best effort: close everything that was opened
                x.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def open_reference(ref: SourceRef, *, roots: list[Path] | None = None) -> IO[bytes]:
    """Open the bytes of a reference read-only: symlinked final files, the repository and the vault
    are refused (and, with `roots`, anything outside them)."""
    if not _target_allowed(ref, roots):
        raise EvidenceError(NOT_ALLOWED)
    if ref.member is not None:
        try:
            return _MemberStream(ref.path, ref.member)  # type: ignore[return-value]
        except (zipfile.BadZipFile, KeyError) as e:
            raise FileNotFoundError(str(e)) from e
    return _open_nofollow(ref.target)


# --------------------------------------------------------------------------- hashing
def sha256_bytes(data: bytes) -> tuple[str, int]:
    return hashlib.sha256(data).hexdigest(), len(data)


def sha256_stream(fh: IO[bytes]) -> tuple[str, int]:
    h, size = hashlib.sha256(), 0
    for chunk in iter(lambda: fh.read(CHUNK), b""):
        h.update(chunk)
        size += len(chunk)
    return h.hexdigest(), size


def sha256_file(path: Path) -> tuple[str, int]:
    with path.open("rb") as fh:  # read-only; the original is never modified
        return sha256_stream(fh)


def hash_reference(ref: SourceRef) -> tuple[str, int]:
    with open_reference(ref) as fh:
        return sha256_stream(fh)


def guess_mime(name: str) -> str:
    if name.lower().endswith(".rtfd"):
        return "text/rtf"
    mime, _ = mimetypes.guess_type(name)
    return mime or "application/octet-stream"


def _vault_file(item: EvidenceItem) -> Path:
    if not item.vault_path:
        raise EvidenceError("the item has no vault path")
    p = Path(item.vault_path)
    if not p.is_absolute():
        root = vault_dir(create=False)
        p = (root / p).resolve()
        if not p.is_relative_to(root):
            raise EvidenceError("vault path escapes the vault")
    return p


def demo_file(item: EvidenceItem) -> Path | None:
    """The synthetic demo file a path-less reference item points at (meta.demo_file), if valid."""
    rel = (item.meta or {}).get("demo_file")
    if item.source_path or item.storage != EvidenceStorage.REFERENCE or not isinstance(rel, str):
        return None
    path = (REPO_ROOT / rel).resolve()
    return path if path.is_relative_to(DEMO_EVIDENCE_DIR.resolve()) and path.is_file() else None


def _web_registered(item: EvidenceItem) -> bool:
    return (item.meta or {}).get("ingest") == "reference"


def open_item(item: EvidenceItem) -> IO[bytes]:
    """A fresh read-only stream over the item's bytes. Reference originals are opened without
    following a symlinked final file and never from the repository or the vault; one registered
    through the web UI must still lie under its case's evidence roots."""
    if item.storage == EvidenceStorage.INLINE:
        return io.BytesIO((item.inline_text or "").encode("utf-8"))
    if item.storage == EvidenceStorage.VAULT:
        return _open_nofollow(_vault_file(item))
    demo = demo_file(item)
    if demo is not None:
        return demo.open("rb")
    if not item.source_path:
        raise EvidenceError("the item has no source path")
    roots = case_evidence_roots(item.case) if _web_registered(item) else None
    if roots is not None and not roots:
        raise EvidenceError("this case's evidence roots are no longer configured")
    return open_reference(parse_reference(item.source_path), roots=roots)


def current_hash(item: EvidenceItem) -> tuple[str, int]:
    """Re-hash the item's bytes. Raises FileNotFoundError / EvidenceError when unreadable."""
    if item.storage == EvidenceStorage.INLINE:
        return sha256_bytes((item.inline_text or "").encode("utf-8"))
    with open_item(item) as fh:
        return sha256_stream(fh)


def read_bytes(item: EvidenceItem, limit: int | None = None) -> bytes:
    """The item's bytes (or the first `limit` bytes). Reference originals are opened read-only."""
    with open_item(item) as fh:
        return fh.read(limit) if limit else fh.read()


def read_verified(item: EvidenceItem, limit: int | None = None) -> bytes:
    """Read the item once, check those very bytes against the recorded sha256 and return them
    (the first `limit` bytes when given). Raises IntegrityError on a mismatch, OSError /
    EvidenceError when the original cannot be read."""
    with open_item(item) as fh:
        h, size, kept = hashlib.sha256(), 0, bytearray()
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
            size += len(chunk)
            if limit is None or len(kept) < limit:
                kept += chunk
    if item.sha256 and h.hexdigest() != item.sha256:
        raise IntegrityError(item.id)
    return bytes(kept if limit is None else kept[:limit])


class IntegrityError(EvidenceError):
    """The bytes no longer match the recorded sha256."""


# --------------------------------------------------------------------------- integrity
@dataclass
class IntegrityResult:
    status: str  # ok | mismatch | missing | unhashed
    expected: str | None
    actual: str | None
    checked_at: datetime


def verify_integrity(db: Session, item: EvidenceItem) -> IntegrityResult:
    """Re-hash the item and record the result (verified_at on a match, meta.integrity always).
    Commits nothing: the caller audits (which commits)."""
    now = datetime.now(tz=UTC)
    try:
        actual, size = current_hash(item)
    except (OSError, EvidenceError):
        actual, size = None, None
    if actual is None:
        status = "missing"
    elif not item.sha256:
        status = "unhashed"
        item.sha256, item.size_bytes = actual, size
        item.verified_at = now
    elif actual == item.sha256:
        status = "ok"
        item.verified_at = now
    else:
        status = "mismatch"
    meta = dict(item.meta or {})
    meta["integrity"] = {"status": status, "checked_at": now.isoformat(), "actual_sha256": actual,
                         "actual_size": size}
    item.meta = meta
    db.flush()
    if status in ("mismatch", "missing"):
        integrity_event = events.EVIDENCE_INTEGRITY
        if integrity_event:
            events.emit(db, item.case, integrity_event, title=f"{item.case.reference}: evidence integrity {status}",
                        body=f"Evidence item #{item.id} failed its integrity check ({status}).",
                        link=f"/cases/{item.case_id}/evidence/{item.id}", severity="high",
                        payload={"evidence_item_id": item.id}, commit=False)
    return IntegrityResult(status, item.sha256, actual, now)


def integrity_status(item: EvidenceItem) -> str | None:
    return ((item.meta or {}).get("integrity") or {}).get("status")


def integrity_alerts(items: Iterable[EvidenceItem]) -> list[EvidenceItem]:
    return [e for e in items if integrity_status(e) in ("mismatch", "missing")]


# --------------------------------------------------------------------------- previews
_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "image/png"), (b"\xff\xd8\xff", "image/jpeg"), (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"), (b"%PDF-", "application/pdf"),
)


def sniff(head: bytes) -> str | None:
    for magic, mime in _MAGIC:
        if head.startswith(magic):
            return mime
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    return None


def preview_kind(item: EvidenceItem) -> tuple[str | None, str | None]:
    """('text'|'image'|'pdf'|None, mime to serve). Images/PDF are recognised by their bytes, not the
    declared mime, so a mislabelled upload is never rendered as something else."""
    if item.storage == EvidenceStorage.INLINE:
        return "text", "text/plain"
    try:
        head = read_bytes(item, limit=16)
    except (OSError, EvidenceError, zipfile.BadZipFile, KeyError):
        return None, None
    sniffed = sniff(head)
    if sniffed == "application/pdf":
        return "pdf", sniffed
    if sniffed:
        return "image", sniffed
    if (item.mime or "").startswith("text/plain") and (item.size_bytes or 0) <= MAX_PREVIEW_TEXT:
        return "text", "text/plain"
    return None, None


def preview_text(item: EvidenceItem) -> tuple[str | None, str]:
    """(text, status) for an in-page text preview. The bytes are re-hashed first, exactly like a
    download: status is ok, mismatch (no text returned) or missing."""
    try:
        data = read_verified(item, limit=MAX_PREVIEW_TEXT)
    except IntegrityError:
        return None, "mismatch"
    except (OSError, EvidenceError, zipfile.BadZipFile, KeyError):
        return None, "missing"
    return data.decode("utf-8", errors="replace"), "ok"


# --------------------------------------------------------------------------- ingest
def _parse_date(value: str | datetime | None) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError as e:
        raise EvidenceError(f"not a date: {value!r}") from e
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def parse_tags(value: str | Iterable[str] | None) -> list[str]:
    if not value:
        return []
    parts = value.split(",") if isinstance(value, str) else list(value)
    out: list[str] = []
    for p in parts:
        t = str(p).strip()[:64]
        if t and t not in out:
            out.append(t)
    return out


def find_by_sha(db: Session, case: Case, sha: str, *, exclude_id: int | None = None) -> EvidenceItem | None:
    q = select(EvidenceItem).where(EvidenceItem.case_id == case.id, EvidenceItem.sha256 == sha)
    if exclude_id:
        q = q.where(EvidenceItem.id != exclude_id)
    return db.scalars(q.order_by(EvidenceItem.id)).first()


def _apply_meta(item: EvidenceItem, *, folder: EvidenceFolder, section: str | None, title: str,
                description: str | None, source_type: str | None, doc_date, received_from: str | None,
                classification, tlp: str | None, tags, shared_with_external: bool = False) -> None:
    title = (title or "").strip()
    if not title:
        raise EvidenceError("a title is required")
    item.folder = folder
    item.title = title[:512]
    item.description = (description or "").strip() or None
    item.source_type = (source_type or "").strip()[:64] or None
    item.doc_date = _parse_date(doc_date)
    item.received_from = (received_from or "").strip()[:255] or None
    item.classification = as_classification(classification)
    item.tlp = (tlp or "").strip()[:32] or None
    item.tags = parse_tags(tags)
    item.shared_with_external = bool(shared_with_external)
    meta = dict(item.meta or {})
    if section and section in SECTION_KEYS.get(folder, ()):
        meta["section"] = section
    else:
        meta.pop("section", None)
    item.meta = meta


def _mark_duplicate(db: Session, case: Case, item: EvidenceItem) -> EvidenceItem | None:
    """Tag both rows when another item of the case has the same bytes."""
    if not item.sha256:
        return None
    other = find_by_sha(db, case, item.sha256, exclude_id=item.id)
    if other is not None:
        item.tags = parse_tags([*(item.tags or []), "duplicate"])
        other.tags = parse_tags([*(other.tags or []), "has-duplicate"])
        item.meta = {**(item.meta or {}), "duplicate_of": other.id}
    return other


def store_upload(db: Session, case: Case, fh: IO[bytes], *, filename: str, folder: str | EvidenceFolder,
                 title: str | None = None, section: str | None = None, description: str | None = None,
                 source_type: str | None = None, doc_date=None, received_from: str | None = None,
                 classification=None, tlp: str | None = None, tags=None, actor: User | None = None,
                 max_bytes: int | None = None) -> EvidenceItem:
    """Stream an upload into the vault (named by uuid), hashing on the way. Refuses when the vault is
    unset or inside the repo. Metadata is validated before any byte is written. Caller audits (commits)."""
    root = vault_dir()
    safe_name = _basename(filename or "") or "upload"
    item = EvidenceItem(storage=EvidenceStorage.VAULT, mime=guess_mime(safe_name),
                        created_by=actor.id if actor else None,
                        meta={"original_filename": safe_name[:255], "ingest": "upload"})
    _apply_meta(item, folder=as_folder(folder), section=section, title=title or safe_name, description=description,
                source_type=source_type, doc_date=doc_date, received_from=received_from,
                classification=classification, tlp=tlp, tags=tags)
    case_dir = root / str(case.id)
    case_dir.mkdir(mode=0o700, exist_ok=True)
    name = uuid.uuid4().hex
    tmp, final = case_dir / f"{name}.part", case_dir / name
    max_bytes = max_bytes if max_bytes is not None else max_upload_bytes()
    h, size = hashlib.sha256(), 0
    try:
        with open(tmp, "xb") as out:
            os.chmod(tmp, 0o600)
            for chunk in iter(lambda: fh.read(CHUNK), b""):
                size += len(chunk)
                if size > max_bytes:
                    raise EvidenceError(f"the file is larger than the upload limit ({max_bytes // (1 << 20)} MB)")
                h.update(chunk)
                out.write(chunk)
        if size == 0:
            raise EvidenceError("the file is empty")
        os.replace(tmp, final)
    finally:
        if tmp.exists():
            tmp.unlink()
    item.vault_path, item.sha256, item.size_bytes = f"{case.id}/{name}", h.hexdigest(), size
    item.verified_at = datetime.now(tz=UTC)
    item.case = case
    db.add(item)
    db.flush()
    _mark_duplicate(db, case, item)
    db.flush()
    return item


def add_reference(db: Session, case: Case, source_path: str, *, folder: str | EvidenceFolder,
                  title: str | None = None, section: str | None = None, description: str | None = None,
                  source_type: str | None = None, doc_date=None, received_from: str | None = None,
                  classification=None, tlp: str | None = None, tags=None, actor: User | None = None,
                  restrict_to_roots: bool = True) -> EvidenceItem:
    """Register an existing file by path (never copied), hashing it read-only. Caller audits.

    The path is stored with every link resolved. With restrict_to_roots (web requests) it must lie
    under the case's own evidence roots, and every later read re-checks that."""
    ref = check_reference_path(source_path, restrict_to_roots=restrict_to_roots, case=case)
    sha, size = hash_reference(ref)
    item = EvidenceItem(case=case, storage=EvidenceStorage.REFERENCE, source_path=ref.as_source_path(),
                        sha256=sha, size_bytes=size, mime=guess_mime(ref.display_name),
                        created_by=actor.id if actor else None, verified_at=datetime.now(tz=UTC),
                        meta={"ingest": "reference" if restrict_to_roots else "reference:operator",
                              "reference_kind": ref.kind})
    db.add(item)
    _apply_meta(item, folder=as_folder(folder), section=section, title=title or ref.display_name,
                description=description, source_type=source_type, doc_date=doc_date, received_from=received_from,
                classification=classification, tlp=tlp, tags=tags)
    db.flush()
    _mark_duplicate(db, case, item)
    db.flush()
    return item


def add_note(db: Session, case: Case, *, title: str, text: str, folder: str | EvidenceFolder = "other",
             section: str | None = None, description: str | None = None, source_type: str | None = "note",
             doc_date=None, received_from: str | None = None, classification=None, tlp: str | None = None,
             tags=None, actor: User | None = None, meta: dict | None = None) -> EvidenceItem:
    """An inline text item (hashed as UTF-8). Caller audits."""
    text = (text or "").replace("\r\n", "\n")
    if not text.strip():
        raise EvidenceError("the note is empty")
    raw = text.encode("utf-8")
    if len(raw) > MAX_INLINE_BYTES:
        raise EvidenceError(f"inline notes are limited to {MAX_INLINE_BYTES // 1024} KB; upload a file instead")
    sha, size = sha256_bytes(raw)
    item = EvidenceItem(case=case, storage=EvidenceStorage.INLINE, inline_text=text, sha256=sha, size_bytes=size,
                        mime="text/plain", created_by=actor.id if actor else None, verified_at=datetime.now(tz=UTC),
                        meta={"ingest": "inline", **(meta or {})})
    db.add(item)
    _apply_meta(item, folder=as_folder(folder), section=section, title=title, description=description,
                source_type=source_type, doc_date=doc_date, received_from=received_from,
                classification=as_classification(classification, Classification.R2), tlp=tlp, tags=tags)
    db.flush()
    _mark_duplicate(db, case, item)
    db.flush()
    return item


# Provenance tags the e-mail desk files mail items with (app.mail.ingest, app.domain.mail_send). The
# attachment rules (app.domain.mail_compose) read them, so the edit form keeps them, and keeps the
# source type of a mail item, whatever the form sends.
MAIL_SYSTEM_TAGS = frozenset({"aegis-mail", "received-email", "sent-email", "email-attachment"})
MAIL_SYSTEM_SOURCE_TYPES = frozenset({"eml", "email_attachment"})


def update_item(item: EvidenceItem, values: dict[str, Any]) -> list[str]:
    """Edit metadata (never the bytes or the hash). Returns the changed field names. The e-mail
    desk's provenance (MAIL_SYSTEM_TAGS, and the source type of an item carrying one) is kept."""
    before = {f: getattr(item, f) for f in ("folder", "title", "description", "source_type", "doc_date",
                                            "received_from", "classification", "tlp", "tags")}
    before_section = (item.meta or {}).get("section")
    system_tags = [t for t in item.tags or [] if str(t).strip().lower() in MAIL_SYSTEM_TAGS]
    keep_source = item.source_type if system_tags and (item.source_type or "") in MAIL_SYSTEM_SOURCE_TYPES else None
    _apply_meta(item, folder=as_folder(values.get("folder") or item.folder.value),
                section=values.get("section"), title=values.get("title") or item.title,
                description=values.get("description"), source_type=values.get("source_type"),
                doc_date=values.get("doc_date"), received_from=values.get("received_from"),
                classification=values.get("classification") or item.classification.value,
                tlp=values.get("tlp"), tags=values.get("tags"), shared_with_external=item.shared_with_external)
    have = {str(t).strip().lower() for t in item.tags or []}
    missing = [t for t in system_tags if str(t).strip().lower() not in have]
    if missing:
        item.tags = parse_tags([*missing, *(item.tags or [])])
    if keep_source:
        item.source_type = keep_source
    changed = [f for f, v in before.items() if getattr(item, f) != v]
    if (item.meta or {}).get("section") != before_section:
        changed.append("section")
    return changed


def max_upload_bytes() -> int:
    try:
        mb = int(os.environ.get("AEGIS_MAX_UPLOAD_MB", DEFAULT_MAX_UPLOAD_MB))
    except ValueError:
        mb = DEFAULT_MAX_UPLOAD_MB
    return max(1, mb) * (1 << 20)


# --------------------------------------------------------------------------- trace report
def trace_report_text(db: Session, case: Case, run: TraceRun) -> str:
    """A Markdown summary of a trace run (graph statistics + freeze candidates), chain data only."""
    from app.tracing.freeze import freeze_candidates
    from app.tracing.graph import build_graph, summary

    stats = summary(build_graph(db, run))
    cands = freeze_candidates(db, run)
    lines = [
        f"# Trace report — {case.reference}, run #{run.id}",
        "",
        f"* Run started: {run.started_at.isoformat() if run.started_at else '—'}; status: {run.status.value}"
        + (f"; label: {run.label}" if run.label else ""),
        f"* Provider mode: {(run.params or {}).get('provider_mode', '—')}",
        (f"* Graph: {stats['nodes']} nodes, {stats['edges']} edges, max hop {stats['max_hop']}, "
         f"chains {', '.join(stats['chains']) or '—'}"),
        f"* VASP touchpoints: {stats['vasp_touchpoints']}; services: {', '.join(stats['entities']) or '—'}",
        "",
        "## Freeze / preservation candidates",
        "",
        "| Priority | Entity | Action | Tainted USD (upper bound) | Identifiers |",
        "|---|---|---|---|---|",
    ]
    for c in cands:
        ids = "; ".join(f"{i.chain}:{i.address}" for i in c.identifiers)
        lines.append(f"| {c.priority} | {c.entity_name} | {c.kind} | {Decimal(c.total_taint_usd):,.2f} | {ids} |")
    if not cands:
        lines.append("| — | none | — | — | — |")
    lines += ["", f"Generated by Aegis on {datetime.now(tz=UTC).isoformat(timespec='seconds')}."]
    return "\n".join(lines) + "\n"


def save_trace_report(db: Session, case: Case, run: TraceRun, *, actor: User | None = None) -> EvidenceItem:
    if run.case_id != case.id:
        raise EvidenceError("the run belongs to another case")
    return add_note(db, case, title=f"Trace report — run #{run.id}", text=trace_report_text(db, case, run),
                    folder=EvidenceFolder.CHAIN_REPORTS, source_type="trace_report", classification="C1",
                    doc_date=run.finished_at or run.started_at, received_from="Aegis trace engine",
                    tags=["trace", f"run-{run.id}"], actor=actor, meta={"trace_run_id": run.id})


# --------------------------------------------------------------------------- linked records
def linked_correspondence(access: perms.CaseAccess) -> tuple[list, list[Correspondence]]:
    """Stop orders and correspondence shown in the 'Stop orders & correspondence' folder."""
    case = access.case
    corr = [c for c in case.correspondence if c.shared_with_external or not access.is_external]
    orders = [] if access.is_external else sorted(case.stop_orders, key=lambda o: -o.id)
    return orders, sorted(corr, key=lambda c: (c.occurred_at or c.created_at), reverse=True)


@dataclass
class LinkedEntry:
    """A stop order or a letter / message shown as a virtual entry of the 'Stop orders &
    correspondence' folder (it lives on the Authorities desk, not in the evidence register)."""

    kind: str  # stop_order | correspondence
    id: int
    title: str
    href: str
    at: datetime | None
    counterparty: str | None
    status: str
    detail: str
    classification: str
    evidence_item_id: int | None = None

    @property
    def anchor(self) -> str:
        return f"{'so' if self.kind == 'stop_order' else 'corr'}-{self.id}"


def linked_entries(access: perms.CaseAccess) -> list[LinkedEntry]:
    """The folder's virtual entries: stop orders (not for externals) and the letters, replies and
    notes this member may see (externals: shared ones), newest first. Letters that a stop order
    already stands for (its own outbound copy) are listed once, as the stop order."""
    from app.domain.correspondence import order_state

    orders, corr = linked_correspondence(access)
    case_id = access.case.id
    mask = ref_mask(access)  # subjects carry contact names and complaint references
    out: list[LinkedEntry] = []
    for o in orders:
        out.append(LinkedEntry(
            "stop_order", o.id, mask(o.subject) or f"Stop order #{o.id}", f"/cases/{case_id}/stop-orders/{o.id}",
            o.sent_at or o.created_at, mask(o.entity.name) if o.entity else None,
            order_state(o),
            f"stop order · {o.kind.replace('_', ' ')} · {o.origin.value}", Classification.R3.value))
    shown_orders = {o.id for o in orders}
    for c in corr:
        if c.stop_order_id in shown_orders and c.kind.value == "stop_order" and c.direction.value == "out":
            continue
        out.append(LinkedEntry(
            "correspondence", c.id, mask(c.subject) or c.kind.value.replace("_", " "),
            f"/cases/{case_id}/authorities/correspondence/{c.id}", c.occurred_at or c.created_at,
            mask(c.entity.name) if c.entity else None, c.status.value, f"{c.direction.value} · {c.channel.value}",
            c.classification.value, c.evidence_item_id))
    epoch = datetime.min.replace(tzinfo=UTC)
    out.sort(key=lambda x: (x.at.replace(tzinfo=UTC) if x.at and x.at.tzinfo is None else x.at) or epoch,
             reverse=True)
    return out


# --------------------------------------------------------------------------- events
def notify_added(db: Session, case: Case, items: list[EvidenceItem], *, commit: bool = True) -> None:
    """One evidence_added event (no titles or file names: those can carry PII)."""
    if not items:
        return
    folders = sorted({folder_label(i.folder) for i in items})
    tiers = sorted({i.classification.value for i in items})
    n = len(items)
    events.emit(
        db, case, events.EVIDENCE_ADDED, title=f"{case.reference}: {n} evidence item{'s' if n != 1 else ''} added",
        body=f"Folder: {', '.join(folders)}. Classification: {', '.join(tiers)}.",
        link=f"/cases/{case.id}?tab=evidence" + (f"&folder={items[0].folder.value}" if len(folders) == 1 else ""),
        severity="info", payload={"evidence_item_ids": [i.id for i in items][:100]}, commit=commit,
    )


# --------------------------------------------------------------------------- bulk import (CLI)
@dataclass
class Rule:
    folder: EvidenceFolder
    section: str | None = None
    dirs: tuple[str, ...] = ()  # a path component equals one of these (case-insensitive)
    globs: tuple[str, ...] = ()  # fnmatch on any path component (case-insensitive)
    keywords: tuple[str, ...] = ()  # word-start match anywhere in the relative path
    exts: tuple[str, ...] = ()  # file extension (with dot); combined with keywords as AND
    tags: tuple[str, ...] = ()
    classification: str | None = None
    label: str = ""

    def matches(self, rel: str) -> bool:
        low = rel.lower()
        parts = [p for p in re.split(r"[/!]", low) if p]
        name = parts[-1] if parts else low
        ext = os.path.splitext(name)[1]
        checks = []
        if self.dirs:
            checks.append(any(p in {d.lower() for d in self.dirs} for p in parts[:-1]))
        if self.globs:
            checks.append(any(fnmatch.fnmatchcase(p, g.lower()) for p in parts for g in self.globs))
        if self.keywords:
            checks.append(_has_kw(low, [k.lower() for k in self.keywords]))
        if self.exts:
            checks.append(ext in {e.lower() for e in self.exts})
        return bool(checks) and all(checks)


_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".heic", ".gif", ".webp")
# Default rules for an investment-fraud case folder; first match wins.
DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(EvidenceFolder.STOP_ORDERS_CORRESPONDENCE, dirs=("Stop Orders",), label="dir 'Stop Orders'"),
    Rule(EvidenceFolder.LEGAL, dirs=("Legal Docs",), label="dir 'Legal Docs'"),
    Rule(EvidenceFolder.FINANCIAL, globs=("*Due Diligence*",), label="'*Due Diligence*'"),
    Rule(EvidenceFolder.LAW_ENFORCEMENT, "reports",
         keywords=("police", "ic3", "statement", "power-of-attorney", "power of attorney", "power_of_attorney",
                   "agent", "complaint", "carabinieri", "denuncia"), label="law-enforcement keywords"),
    Rule(EvidenceFolder.DIGITAL_ARTIFACTS, "messaging", keywords=("whatsapp", "chat", "telegram"), label="chat"),
    Rule(EvidenceFolder.DIGITAL_ARTIFACTS, "recordings", keywords=("transcript", "meeting", "recording"),
         label="transcript / meeting"),
    Rule(EvidenceFolder.DIGITAL_ARTIFACTS, "recordings", exts=(".mp4", ".mov", ".m4a", ".mp3", ".wav"),
         label="recording file"),
    Rule(EvidenceFolder.DIGITAL_ARTIFACTS, "emails", keywords=("email", "e-mail", "mail"), exts=_IMAGE_EXTS,
         label="e-mail screenshot"),
    Rule(EvidenceFolder.DIGITAL_ARTIFACTS, "emails", exts=(".eml", ".msg"), label="e-mail file"),
    Rule(EvidenceFolder.INVESTIGATOR_REPORTS,
         keywords=("invoice", "work product", "work-product", "work_product", "intelligence report",
                   "intelligence_report", "intelligence-report", "fund flow graph", "fund-flow graph",
                   "fund_flow_graph", "fund flow", "fund-flow"), label="investigator keywords"),
    Rule(EvidenceFolder.DIGITAL_ARTIFACTS, "screenshots", exts=_IMAGE_EXTS, label="image"),
)


def _rule_from_json(d: dict) -> Rule:
    def tup(key):
        v = d.get(key) or ()
        return (v,) if isinstance(v, str) else tuple(v)

    rule = Rule(as_folder(d["folder"]), d.get("section"), dirs=tup("dir") + tup("dirs"),
                globs=tup("glob") + tup("globs"), keywords=tup("keyword") + tup("keywords"),
                exts=tuple(e if e.startswith(".") else f".{e}" for e in tup("ext") + tup("exts")),
                tags=tup("tags"), classification=d.get("classification"), label=d.get("label") or "mapping")
    if not (rule.dirs or rule.globs or rule.keywords or rule.exts):
        raise EvidenceError(f"mapping rule {d!r} has no condition (dir, glob, keyword or ext)")
    if rule.classification:
        as_classification(rule.classification)
    return rule


@dataclass
class Mapping:
    rules: tuple[Rule, ...] = DEFAULT_RULES
    default_folder: EvidenceFolder = EvidenceFolder.OTHER
    classification: Classification = Classification.R3
    exclude: tuple[str, ...] = ()

    def classify(self, rel: str) -> tuple[EvidenceFolder, str | None, Rule | None]:
        for r in self.rules:
            if r.matches(rel):
                return r.folder, r.section, r
        return self.default_folder, None, None


def load_mapping(path: str | Path | None) -> Mapping:
    """--map mapping.json: {"rules": [...], "replace_defaults": false, "default_folder": "other",
    "classification": "R3", "exclude": ["*.tmp"]}. Custom rules run before the defaults."""
    if not path:
        return Mapping()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    custom = tuple(_rule_from_json(r) for r in data.get("rules") or [])
    rules = custom if data.get("replace_defaults") else custom + DEFAULT_RULES
    return Mapping(rules=rules, default_folder=as_folder(data.get("default_folder", "other")),
                   classification=as_classification(data.get("classification")),
                   exclude=tuple(data.get("exclude") or ()))


@dataclass
class Candidate:
    rel: str  # path relative to the source root; zip members as 'archive.zip!member'
    source_path: str  # absolute reference path ('/abs/archive.zip!member' for members)
    sha256: str
    size: int
    mime: str
    kind: str  # file | zip_member | rtfd
    meta: dict = field(default_factory=dict)
    error: str | None = None


def _skipped(name: str, exclude: Iterable[str]) -> bool:
    return (name in SKIP_NAMES or name.startswith("._") or name.startswith("~$")
            or any(fnmatch.fnmatch(name, pat) for pat in exclude))


def _zip_candidates(path: Path, rel: str, exclude: Iterable[str]) -> Iterator[Candidate]:
    """Index a zip's members without extracting anything to disk."""
    container_sha, container_size = sha256_file(path)
    container = {"container_sha256": container_sha, "container_size": container_size}
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        yield Candidate(rel, str(path), container_sha, container_size, "application/zip", "file",
                        meta={"zip_error": "bad zip"}, error=str(e))
        return
    with zf:
        names = [zip_name(i) for i in zf.infolist()]
        bundles = sorted({n[: n.lower().index(".rtfd/") + 5] for n in names if ".rtfd/" in n.lower()})
        for info in zf.infolist():
            name = zip_name(info)
            parts = [p for p in name.split("/") if p]
            if info.is_dir() or not parts or "__MACOSX" in parts or _skipped(parts[-1], exclude):
                continue
            bundle = next((b for b in bundles if name.startswith(b + "/")), None)
            if bundle is not None:
                if name != bundle + "/TXT.rtf":
                    continue  # attachments inside a bundle belong to the bundle item
                member, mime, kind = bundle, "text/rtf", "rtfd"
            else:
                member, mime, kind = name, guess_mime(name), "zip_member"
            if info.flag_bits & 0x1:
                yield Candidate(f"{rel}!{member}", f"{path}!{member}", "", info.file_size, mime, kind,
                                meta=container, error="encrypted member")
                continue
            with zf.open(info) as fh:
                sha, size = sha256_stream(fh)
            yield Candidate(f"{rel}!{member}", f"{path}!{member}", sha, size, mime, kind,
                            meta={**container, "zip_member_mtime": _zip_time(info)})


def _zip_time(info: zipfile.ZipInfo) -> str | None:
    try:
        return datetime(*info.date_time).isoformat()
    except ValueError:
        return None


def walk_source(root: str | Path, *, exclude: Iterable[str] = ()) -> Iterator[Candidate]:
    """Every evidence candidate under `root`, hashed read-only. .rtfd bundles are one item; zips are
    indexed by member; .DS_Store and other OS litter are skipped.

    Order: every loose file and bundle first (depth-first, sorted), then the members of the zip
    archives (in the same order), so that when an archive repeats a loose original, the loose file
    becomes the canonical item and the zip member is recorded as its duplicate."""
    root = Path(root).expanduser().resolve()
    exclude = tuple(exclude)
    archives: list[tuple[Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        here = Path(dirpath)
        bundles = [d for d in dirnames if d.lower().endswith(".rtfd")]
        dirnames[:] = [d for d in dirnames if d not in bundles and not _skipped(d, exclude) and d != "__MACOSX"]
        for d in bundles:
            p = here / d
            rel = p.relative_to(root).as_posix()
            txt = p / "TXT.rtf"
            if p.is_symlink() or txt.is_symlink():
                yield Candidate(rel, str(p), "", 0, "text/rtf", "rtfd", error="symbolic link (not followed)")
                continue
            if not txt.is_file():
                yield Candidate(rel, str(p), "", 0, "text/rtf", "rtfd", error="bundle without TXT.rtf")
                continue
            sha, size = sha256_file(txt)
            extra = sorted(f.name for f in p.iterdir() if f.name != "TXT.rtf" and not _skipped(f.name, ()))
            yield Candidate(rel, str(p), sha, size, "text/rtf", "rtfd", meta={"bundle_files": len(extra)})
        for name in sorted(filenames):
            if _skipped(name, exclude):
                continue
            p = here / name
            if p.is_symlink() or not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            if name.lower().endswith(".zip"):
                archives.append((p, rel))
                continue
            sha, size = sha256_file(p)
            yield Candidate(rel, str(p), sha, size, guess_mime(name), "file")
    for p, rel in archives:
        yield from _zip_candidates(p, rel, exclude)


_DATE_IN_NAME = (
    (re.compile(r"(?<!\d)(20\d\d)[-_.]?(0[1-9]|1[0-2])[-_.]?(0[1-9]|[12]\d|3[01])(?!\d)"), (1, 2, 3)),
    (re.compile(r"(?<!\d)(0[1-9]|[12]\d|3[01])[.](0[1-9]|1[0-2])[.](20\d\d)(?!\d)"), (3, 2, 1)),
)


def date_from_name(name: str) -> datetime | None:
    for rx, (y, m, d) in _DATE_IN_NAME:
        hit = rx.search(name)
        if hit:
            try:
                return datetime(int(hit.group(y)), int(hit.group(m)), int(hit.group(d)), tzinfo=UTC)
            except ValueError:
                continue
    return None


def _title_from_rel(rel: str) -> str:
    last = re.split(r"[/!]", rel.rstrip("/"))[-1]
    stem = last[: -len(".rtfd")] if last.lower().endswith(".rtfd") else os.path.splitext(last)[0]
    return (stem or last)[:512]


@dataclass
class ImportRow:
    candidate: Candidate
    folder: EvidenceFolder
    section: str | None
    rule: str
    action: str  # new | duplicate | unchanged | changed | error
    item_id: int | None = None


@dataclass
class ImportReport:
    rows: list[ImportRow] = field(default_factory=list)
    created: list[EvidenceItem] = field(default_factory=list)

    def count(self, action: str) -> int:
        return sum(1 for r in self.rows if r.action == action)

    def by_folder(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.rows:
            if r.action == "new":
                out[r.folder.value] = out.get(r.folder.value, 0) + 1
        return out


def import_directory(db: Session, case: Case, root: str | Path, *, mode: str = "reference",
                     mapping: Mapping | None = None, dry_run: bool = False, received_from: str | None = None,
                     actor: User | None = None) -> ImportReport:
    """Walk `root`, hash, map to folders and register items (never modifying the originals).

    mode: reference (default; nothing copied), inline (small UTF-8 text files only, e.g. the demo
    artifacts) or vault (copy into AEGIS_VAULT_DIR). Duplicates (same sha256 already in the case)
    are not re-registered: the existing item is tagged 'has-duplicate' and lists the path in
    meta.duplicates. With dry_run nothing is written. The caller commits and audits."""
    if mode not in ("reference", "inline", "vault"):
        raise EvidenceError(f"unknown import mode {mode!r}")
    mapping = mapping or Mapping()
    root = Path(root).expanduser()
    if not root.is_dir():
        raise EvidenceError("the source is not a directory")
    if mode in ("reference", "vault") and _inside_repo(root):
        raise EvidenceError("the source is inside the repository: originals never live there")
    if mode == "vault" and not dry_run:
        vault_dir()
    report = ImportReport()
    # sha256 -> the first item holding those bytes (None: seen earlier in this dry run)
    existing: dict[str, EvidenceItem | None] = {
        e.sha256: e for e in sorted(case.evidence_items, key=lambda e: e.id, reverse=True) if e.sha256}
    by_path = {e.source_path: e for e in case.evidence_items if e.source_path}
    by_title_inline = {(e.folder, e.title): e for e in case.evidence_items if e.storage == EvidenceStorage.INLINE}
    for cand in walk_source(root, exclude=mapping.exclude):
        folder, section, rule = mapping.classify(cand.rel)
        row = ImportRow(cand, folder, section, rule.label if rule else "default", "new")
        report.rows.append(row)
        if cand.error:
            row.action = "error"
            continue
        if mode == "inline":
            if cand.size > MAX_INLINE_BYTES or not cand.mime.startswith("text/"):
                row.action, cand.error = "error", "not a small text file (inline mode)"
                continue
        prior = by_path.get(cand.source_path)
        if prior is not None:
            row.item_id = prior.id
            row.action = "unchanged" if prior.sha256 == cand.sha256 else "changed"
            if row.action == "changed" and not dry_run:
                verify_integrity(db, prior)
            continue
        title = _title_from_rel(cand.rel)
        if mode == "inline":
            inline_prior = by_title_inline.get((folder, title))
            if inline_prior is not None and inline_prior.sha256 == cand.sha256:
                row.item_id, row.action = inline_prior.id, "unchanged"
                continue
        if cand.sha256 in existing:
            dup = existing[cand.sha256]
            row.action, row.item_id = "duplicate", dup.id if dup is not None else None
            if dup is not None and not dry_run:
                meta = dict(dup.meta or {})
                dups = list(meta.get("duplicates") or [])
                if cand.source_path not in dups and cand.source_path != dup.source_path:
                    dups.append(cand.source_path)
                meta["duplicates"] = dups[:200]
                dup.meta = meta
                dup.tags = parse_tags([*(dup.tags or []), "has-duplicate"])
            continue
        if dry_run:
            existing[cand.sha256] = None
            continue
        classification = (rule.classification if rule and rule.classification else mapping.classification)
        tags = list(rule.tags) if rule else []
        meta = {"ingest": f"import:{mode}", "import_rel_path": cand.rel, "reference_kind": cand.kind,
                "mapping_rule": row.rule, **cand.meta}
        common = {"folder": folder, "title": title, "description": None, "source_type": _source_type(cand),
                  "doc_date": date_from_name(cand.rel), "received_from": received_from,
                  "classification": classification, "tlp": None, "tags": tags}
        if mode == "inline":
            text = Path(cand.source_path).read_text(encoding="utf-8")
            item = add_note(db, case, text=text, section=section, actor=actor, meta=meta,
                            **{**common, "source_type": common["source_type"] or "text"})
            if item.sha256 != cand.sha256:  # CRLF normalised: keep the file's own hash on record
                item.meta = {**item.meta, "file_sha256": cand.sha256}
        elif mode == "vault":
            with _open_candidate(cand) as fh:
                item = store_upload(db, case, fh, filename=cand.rel.rsplit("/", 1)[-1], section=section,
                                    actor=actor, **common)
            item.meta = {**item.meta, **meta, "import_source": cand.source_path}
        else:
            item = EvidenceItem(case=case, storage=EvidenceStorage.REFERENCE, source_path=cand.source_path,
                                sha256=cand.sha256, size_bytes=cand.size, mime=cand.mime, meta=meta,
                                created_by=actor.id if actor else None, verified_at=datetime.now(tz=UTC))
            db.add(item)
            _apply_meta(item, section=section, **common)
            db.flush()
        row.item_id = item.id
        report.created.append(item)
        existing[cand.sha256] = item
        by_path[cand.source_path] = item
    if not dry_run:
        db.flush()
    return report


def _source_type(c: Candidate) -> str | None:
    ext = os.path.splitext(c.rel.rsplit("!", 1)[-1])[1].lower().lstrip(".")
    if c.kind == "rtfd":
        return "rtfd"
    return ext or None


class _open_candidate:
    def __init__(self, c: Candidate):
        self.c = c
        self._zf = None
        self._fh = None

    def __enter__(self):
        self._fh = open_reference(parse_reference(self.c.source_path))
        return self._fh

    def __exit__(self, *exc):
        if self._fh:
            self._fh.close()
        if self._zf:
            self._zf.close()


# --------------------------------------------------------------------------- serialisation
def item_dict(access: perms.CaseAccess, e: EvidenceItem, *, with_content: bool = False,
              mask: RefMask | None = None) -> dict:
    mask = mask if mask is not None else ref_mask(access)
    d = {
        "id": e.id, "folder": e.folder.value, "section": section_of(e), "title": mask(e.title),
        "description": mask(e.description), "source_type": e.source_type, "storage": e.storage.value,
        "sha256": e.sha256, "size_bytes": e.size_bytes, "mime": e.mime,
        "doc_date": e.doc_date.isoformat() if e.doc_date else None, "received_from": mask(e.received_from),
        "classification": e.classification.value, "tlp": e.tlp, "tags": mask.tags(e.tags),
        "shared_with_external": e.shared_with_external, "parent_id": e.parent_id,
        "verified_at": e.verified_at.isoformat() if e.verified_at else None,
        "integrity": integrity_status(e), "can_open": can_open(access, e),
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }
    if allowed(access, "view_source_path"):
        d["source_path"] = e.source_path
        d["duplicates"] = list((e.meta or {}).get("duplicates") or [])
    if with_content and e.storage == EvidenceStorage.INLINE and can_open(access, e):
        d["inline_text"] = e.inline_text
    return d


def contact_dict(v: ContactView) -> dict:
    return {k: getattr(v, k) for k in ("id", "agency", "unit", "role", "name", "email", "phone", "reference",
                                       "jurisdiction", "notes", "classification", "masked")}
