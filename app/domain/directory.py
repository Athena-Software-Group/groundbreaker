"""Contact directory: which authorities a case can reach, and how ("authorities listed and means to
contact them").

Owner: the mail feature (web layer: app/web/routes_mail.py; the "How to contact" card on the
authority page, case/_contact_card.html).

Where a channel comes from (D8), merged per authority by `channels_for`, de-duplicated on the
lower-cased (kind, value):

1. **Catalogue** (`data/catalogue/channels.json`, I0, in git): generic organisational channels only
   (homepages, portals; every law-enforcement / compliance channel the organisation has not
   published to us is `value: null`, "to be confirmed"). Read at runtime, validated and cached by
   file mtime (`load_catalogue`); never copied into the DB. A *global* `entity_channels` row with
   the same `catalogue_key` overlays it (verification, notes, a confirmed value).
   The provider playbooks (`data/catalogue/providers/<org_key>.json`, app.domain.playbook) are merged into it:
   each channel's `who` (le_only channels are never offered to a private sender), declared channels, and
   `Org.playbook` (`playbook_for(authority)`).
2. **Global rows** (`entity_channels.case_id IS NULL`, I0): channels a system admin added for the
   authority's entity or catalogue organisation.
3. **The entity record** (`entities.compliance_email` / `le_portal_url`, I0): source `entity_record`,
   unverified unless a directory row verifies the same value.
4. **Case-scoped rows** (`entity_channels.case_id = case`, R2): channels a case admin added or
   verified for this authority (its entity, organisation or LE contact).
5. **Derived case recipients** (R2, computed at read time, never stored until an admin verifies or
   saves one): LE contacts' e-mail addresses and the addresses of the authority's own
   correspondence (senders of inbound rows, except mailbox replies from an unexpected domain; the To
   recipients of sent outbound rows, never their Cc), minus the case mailbox, the sender profile's
   own addresses and the case members' sign-in addresses.

Visibility: external members get an empty card; read-only members see the catalogue and global
entries, and case-scoped values masked (`ev.mask_email` / `ev.mask_phone`); investigators and up see
everything. Mutations (`add_channel`, `verify_channel`, `disable_channel`, `touch_used`) never audit:
the routes do, with ids, kinds and counts only.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from email.headerregistry import Address
from pathlib import Path
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models import (
    Case,
    ChannelKind,
    ChannelPurpose,
    ChannelRole,
    ChannelSource,
    Classification,
    CorrespondenceDirection,
    CorrespondenceStatus,
    EntityChannel,
    User,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOGUE_PATH = REPO_ROOT / "data" / "catalogue" / "channels.json"
# Generic role aliases only (never a person). Organisation-specific role aliases are added only when the
# organisation itself publishes them (e.g. Circle's circleblocklisting@ and subpoenas@).
EMAIL_LOCAL_PARTS = frozenset({"compliance", "legal", "abuse", "lawenforcement", "le-requests", "legalrequests",
                               "circleblocklisting", "subpoenas", "inforequests"})
KINDS = tuple(k.value for k in ChannelKind)
PURPOSES = tuple(p.value for p in ChannelPurpose)
ROLES = tuple(r.value for r in ChannelRole)
MAX_VALUE = 512
_ADDR_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")
_PHONE_OK = re.compile(r"\+?[0-9][0-9 ]{1,31}")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_PLACEHOLDER = re.compile(r"(?i)^\s*(tbc|tbd|todo|tba|n/?a|unknown|none|null|\?+|-+|x+|to be confirmed)\s*$")
GROUPS = ("Send to (e-mail)", "Portals & forms", "Phone / post", "This case only", "To be confirmed", "Disabled")


class DirectoryError(ValueError):
    """A directory change that is refused (shown to the user, HTTP 400)."""


class DirectoryForbidden(DirectoryError):
    """The member's role does not allow this directory change (HTTP 403)."""


class CatalogueError(ValueError):
    """data/catalogue/channels.json breaks a catalogue rule (it is never loaded half-valid)."""


def _now() -> datetime:
    return datetime.now(tz=UTC)


# --------------------------------------------------------------------------- addresses
def validate_address(s: str) -> str:
    """A bare e-mail address (no display name), strictly checked, with the domain lower-cased.
    Raises DirectoryError. Refuses CR / LF / NUL, display names, quotes, IP literals, non-ASCII,
    a domain without a dot, more than 254 characters or a local part over 64."""
    if not isinstance(s, str):
        raise DirectoryError("not an e-mail address")
    v = s.strip()
    if not v:
        raise DirectoryError("an e-mail address is required")
    if any(c in v for c in "\r\n\x00"):
        raise DirectoryError("an e-mail address cannot contain line breaks")
    if "<" in v or ">" in v or " " in v or '"' in v or "," in v or ";" in v:
        raise DirectoryError("give the bare address only (no display name, quotes or lists)")
    if "[" in v or "]" in v:
        raise DirectoryError("IP-literal addresses are not accepted")
    if not v.isascii():
        raise DirectoryError("only ASCII e-mail addresses are accepted")
    if len(v) > 254:
        raise DirectoryError("the e-mail address is too long")
    local, at, domain = v.rpartition("@")
    if not at or not local or not domain:
        raise DirectoryError("not an e-mail address")
    if len(local) > 64:
        raise DirectoryError("the part before @ is too long")
    if "." not in domain:
        raise DirectoryError("the domain needs a dot (e.g. example.com)")
    if not _ADDR_RE.fullmatch(v):
        raise DirectoryError("not a valid e-mail address")
    if local.startswith(".") or local.endswith(".") or ".." in local or any(
            p.startswith("-") or p.endswith("-") or not p for p in domain.split(".")):
        raise DirectoryError("not a valid e-mail address")
    try:
        Address(addr_spec=v)
    except Exception:  # noqa: BLE001 - email.errors.* and ValueError: one answer for all
        raise DirectoryError("not a valid e-mail address") from None
    return f"{local}@{domain.lower()}"


def _clean_text(v: str | None, what: str, limit: int) -> str | None:
    s = (v or "").strip()
    if not s:
        return None
    if _CTRL.search(s.replace("\n", "").replace("\t", "")):
        raise DirectoryError(f"the {what} contains control characters")
    if len(s) > limit:
        raise DirectoryError(f"the {what} is longer than {limit} characters")
    return s


def validate_value(kind: str, value: str | None) -> str | None:
    """A channel value for its kind (None = 'to be confirmed'). E-mail: validate_address; portals,
    web forms, websites: https:// URLs only; phone: digits, '+' and spaces (≤ 32); postal: text."""
    if kind not in KINDS:
        raise DirectoryError("unknown channel kind")
    s = (value or "").strip()
    if not s:
        return None
    if len(s) > MAX_VALUE:
        raise DirectoryError(f"the value is longer than {MAX_VALUE} characters")
    if _CTRL.search(s if kind != "postal" else s.replace("\n", " ")):
        raise DirectoryError("the value contains control characters")
    if kind == "email":
        return validate_address(s)
    if "@" in s and kind != "postal":
        raise DirectoryError("an address with '@' must be recorded as an e-mail channel")
    if kind in ("portal", "webform", "website"):
        if not s.lower().startswith("https://") or len(s) < 12 or any(c in s for c in " <>\"'`\\"):
            raise DirectoryError("portals, forms and websites must be https:// URLs")
        return s
    if kind == "phone":
        if not _PHONE_OK.fullmatch(s):
            raise DirectoryError("a phone number may contain only digits, '+' and spaces (at most 32)")
        return s
    return s.replace("\r\n", "\n")


# --------------------------------------------------------------------------- catalogue
@dataclass(frozen=True)
class CatalogueChannel:
    key: str
    org_key: str
    kind: str
    value: str | None
    purpose: str
    role_default: str
    label: str | None
    notes: str | None
    source_url: str | None
    who: str | None = None  # the provider playbook's who-may-use (app.domain.playbook.WHO); None: not stated


@dataclass(frozen=True)
class Org:
    key: str
    name: str
    aliases: tuple[str, ...]
    category: str
    homepage: str | None
    freeze_capable: bool
    info_only: bool
    notes: str | None
    channels: tuple[CatalogueChannel, ...]
    playbook: Any = None  # app.domain.playbook.Playbook (data/catalogue/providers/<key>.json), or None

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys([self.name, *self.aliases]))

    @property
    def portal_url(self) -> str | None:
        return next((c.value for c in self.channels if c.kind in ("portal", "webform") and c.value
                     and c.who != "le_only"), None)

    @property
    def portal_only(self) -> bool:
        """No e-mail channel at all, but a known portal (e.g. IC3): prepare, submit there, mark sent."""
        return self.portal_url is not None and not any(c.kind == "email" for c in self.channels)


@dataclass(frozen=True)
class Catalogue:
    version: int
    orgs: tuple[Org, ...]

    @property
    def by_key(self) -> dict[str, Org]:
        return {o.key: o for o in self.orgs}

    def channel(self, key: str) -> CatalogueChannel | None:
        return next((c for o in self.orgs for c in o.channels if c.key == key), None)


_cache: dict[str, Any] = {}
_cache_lock = threading.Lock()
_stamp_seen: dict[str, tuple[float, Any]] = {}  # key -> (monotonic time, stamp) of the last stat() of the shipped files
STAMP_TTL = 1.0


def _forbidden_keys(node, path="") -> list[str]:
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            if str(k).lower() in ("verified", "verified_by"):
                out.append(f"{path}.{k}".lstrip("."))
            out += _forbidden_keys(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += _forbidden_keys(v, f"{path}[{i}]")
    return out


def _parse_channel(c, key: str, chan_keys: set[str]) -> CatalogueChannel:
    if not isinstance(c, dict):
        raise CatalogueError(f"{key}: a channel must be an object")
    ck = str(c.get("key") or "").strip()
    if not ck or len(ck) > 128:
        raise CatalogueError(f"{key}: a channel needs a key (≤ 128 characters)")
    if ck in chan_keys:
        raise CatalogueError(f"duplicate channel key {ck!r}")
    chan_keys.add(ck)
    kind, purpose, role = c.get("kind"), c.get("purpose", "general"), c.get("role_default", "to")
    if kind not in KINDS:
        raise CatalogueError(f"{ck}: unknown kind {kind!r}")
    if purpose not in PURPOSES:
        raise CatalogueError(f"{ck}: unknown purpose {purpose!r}")
    if role not in ROLES:
        raise CatalogueError(f"{ck}: unknown role {role!r}")
    value = c.get("value")
    if value is not None and not isinstance(value, str):
        raise CatalogueError(f"{ck}: the value must be a string or null")
    if value is not None and _PLACEHOLDER.match(value):
        raise CatalogueError(f"{ck}: {value!r} is a placeholder; use null for 'to be confirmed'")
    if value and "@" in value and kind != "email":
        raise CatalogueError(f"{ck}: a value with '@' must be kind email")
    if kind == "email" and value:
        src = c.get("source_url")
        if not (isinstance(src, str) and src.startswith("https://")):
            raise CatalogueError(f"{ck}: an e-mail value needs a source_url on the organisation's own site")
        if value.strip().rpartition("@")[0].lower() not in EMAIL_LOCAL_PARTS:
            raise CatalogueError(f"{ck}: only generic e-mail aliases ({', '.join(sorted(EMAIL_LOCAL_PARTS))}) "
                                 "may be catalogued")
    try:
        value = validate_value(kind, value) if value else None
    except DirectoryError as e:
        raise CatalogueError(f"{ck}: {e}") from None
    return CatalogueChannel(key=ck, org_key=key, kind=kind, value=value, purpose=purpose, role_default=role,
                            label=c.get("label"), notes=c.get("notes"), source_url=c.get("source_url"))


def parse_catalogue(data: dict, playbooks: dict[str, dict] | None = None) -> Catalogue:
    """Validate the catalogue JSON (see the file's _comment) and merge the provider playbooks
    (`playbooks`: file name -> parsed JSON of data/catalogue/providers/*.json; app.domain.playbook). Raises
    CatalogueError."""
    if not isinstance(data, dict) or not isinstance(data.get("orgs"), list):
        raise CatalogueError("the catalogue needs an 'orgs' list")
    bad = _forbidden_keys(data)
    if bad:
        raise CatalogueError(f"verification state never lives in the catalogue: {', '.join(bad[:5])}")
    orgs, org_keys, chan_keys = [], set(), set()
    for o in data["orgs"]:
        key = str(o.get("key") or "").strip()
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", key):
            raise CatalogueError(f"invalid organisation key {key!r}")
        if key in org_keys:
            raise CatalogueError(f"duplicate organisation key {key!r}")
        org_keys.add(key)
        channels = [_parse_channel(c, key, chan_keys) for c in o.get("channels") or []]
        orgs.append(Org(
            key=key, name=str(o.get("name") or key), aliases=tuple(str(a) for a in o.get("aliases") or []),
            category=str(o.get("category") or "unknown"), homepage=o.get("homepage"),
            freeze_capable=bool(o.get("freeze_capable", False)), info_only=bool(o.get("info_only", False)),
            notes=o.get("notes"), channels=tuple(channels)))
    if playbooks:
        orgs = _merge_playbooks(orgs, chan_keys, playbooks)
    return Catalogue(version=int(data.get("version") or 1), orgs=tuple(orgs))


def _merge_playbooks(orgs: list[Org], chan_keys: set[str], playbooks: dict[str, dict]) -> list[Org]:
    """Each playbook into its Org: `Org.playbook`, the channels' `who` (and a purpose it corrects), declared
    channels appended. One playbook per organisation, named <org_key>.json."""
    from app.domain import playbook as pbm

    by_key = {o.key: i for i, o in enumerate(orgs)}
    seen: set[str] = set()
    for name, raw in sorted(playbooks.items()):
        where = f"providers/{name}"
        key = raw.get("key") if isinstance(raw, dict) else None
        if key not in by_key:
            raise CatalogueError(f"{where}: no catalogue organisation {key!r} in channels.json")
        if name != f"{key}.json" or key in seen:
            raise CatalogueError(f"{where}: one playbook per organisation, named {key}.json")
        seen.add(key)
        org = orgs[by_key[key]]
        try:
            pb, declared = pbm.parse(raw, org_channels={c.key: c.purpose for c in org.channels},
                                     org_values={c.key: c.value for c in org.channels},
                                     all_channel_keys=frozenset(chan_keys), where=where)
        except pbm.PlaybookError as e:
            raise CatalogueError(str(e)) from None
        channels = list(org.channels) + [_parse_channel(c, key, chan_keys) for c in declared]
        out = []
        for c in channels:
            rule = pb.rule(c.key)
            out.append(replace(c, who=rule.who, purpose=rule.purpose or c.purpose) if rule else c)
        orgs[by_key[key]] = replace(org, channels=tuple(out), playbook=pb)
        unknown = sorted({k for i in pb.issues for k in i.to} - set(by_key))
        if unknown:
            raise CatalogueError(f"{where}: issues name unknown organisations: {', '.join(unknown)}")
    return orgs


def _provider_files(providers: Path) -> list[Path]:
    try:
        return sorted(p for p in providers.iterdir() if p.suffix == ".json" and p.is_file())
    except OSError:
        return []


def load_catalogue(path: Path | str | None = None, providers: Path | str | None = None) -> Catalogue:
    """The shipped catalogue with its provider playbooks (`providers`: default the `providers/` folder next to the
    catalogue file), validated; cached until a file's mtime changes. A missing catalogue file is an empty catalogue
    (the directory then holds DB rows only); an invalid catalogue or playbook raises CatalogueError."""
    p = Path(path) if path else CATALOGUE_PATH
    prov_dir = Path(providers) if providers else p.parent / "providers"
    key = f"{p}|{prov_dir}"
    shipped = path is None and providers is None
    if shipped:  # the shipped files: their stat() stamp is re-read at most every STAMP_TTL seconds (a page asks often)
        with _cache_lock:
            hit, seen = _cache.get(key), _stamp_seen.get(key)
            if hit and seen and seen[1] == hit[0] and time.monotonic() - seen[0] < STAMP_TTL:
                return hit[1]
    try:
        mtime = p.stat().st_mtime_ns
    except OSError:
        return Catalogue(version=0, orgs=())
    files = _provider_files(prov_dir)
    try:
        stamp = (mtime, tuple((f.name, f.stat().st_mtime_ns) for f in files))
    except OSError:
        stamp = (mtime, None)
    with _cache_lock:
        hit = _cache.get(key)
        if shipped:
            _stamp_seen[key] = (time.monotonic(), stamp)
        if hit and hit[0] == stamp:
            return hit[1]
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise CatalogueError(f"the catalogue cannot be read: {type(e).__name__}") from None
    playbooks = {}
    for f in files:
        try:
            playbooks[f.name] = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise CatalogueError(f"providers/{f.name} cannot be read: {type(e).__name__}") from None
    cat = parse_catalogue(data, playbooks)
    with _cache_lock:
        _cache[key] = (stamp, cat)
    return cat


# --------------------------------------------------------------------------- authority -> organisation
def _word_in(alias: str, text: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9]){re.escape(alias)}(?![A-Za-z0-9])", text, re.IGNORECASE) is not None


def org_for(authority, catalogue: Catalogue | None = None) -> Org | None:
    """The catalogue organisation of an authority: an exact alias (case-insensitive) of its entity's
    name, else its own name, else an LE contact's agency; then an alias of 3+ characters found as a
    whole word in the name / agency strings (e.g. "Carabinieri — Demo City station (demo)")."""
    cat = catalogue or load_catalogue()
    names = [n for n in ([getattr(authority.entity, "name", None) if authority.entity is not None else None,
                          authority.name] + [le.agency for le in authority.le_contacts]) if n]
    for n in names:
        for o in cat.orgs:
            if any(n.strip().casefold() == a.casefold() for a in o.names):
                return o
    agencies = [n for n in [authority.name if authority.entity is None else None,
                            *[le.agency for le in authority.le_contacts]] if n]
    best: tuple[int, Org] | None = None
    for text in agencies:
        for o in cat.orgs:
            for a in o.names:
                if len(a) >= 3 and _word_in(a, text) and (best is None or len(a) > best[0]):
                    best = (len(a), o)
    return best[1] if best else None


def playbook_for(authority, catalogue: Catalogue | None = None):
    """The provider playbook (app.domain.playbook.Playbook) of an authority's catalogue organisation, or None."""
    org = org_for(authority, catalogue)
    return org.playbook if org is not None else None


# --------------------------------------------------------------------------- the contact card
@dataclass
class ChannelEntry:
    id: int | None
    catalogue_key: str | None
    kind: str
    value: str | None
    label: str | None
    purpose: str
    role_default: str
    source: str
    verified: bool
    verified_at: datetime | None
    verification_note: str | None
    notes: str | None
    last_used_at: datetime | None
    scope: str  # catalogue | global | case
    disabled: bool = False
    source_url: str | None = None
    masked: bool = False
    meta: dict = field(default_factory=dict)
    who: str | None = None  # the catalogue channel's who-may-use (playbook); le_only: never for a private sender

    @property
    def le_only(self) -> bool:
        return self.who == "le_only"

    @property
    def to_be_confirmed(self) -> bool:
        return self.value is None

    @property
    def sendable(self) -> bool:
        return self.kind == "email" and self.value is not None and not self.disabled and not self.masked

    @property
    def group(self) -> str:
        if self.disabled:
            return "Disabled"
        if self.value is None:
            return "To be confirmed"
        if self.scope == "case":
            return "This case only"
        if self.kind == "email":
            return "Send to (e-mail)"
        if self.kind in ("portal", "webform", "website"):
            return "Portals & forms"
        return "Phone / post"

    def as_dict(self) -> dict:
        return {"id": self.id, "catalogue_key": self.catalogue_key, "kind": self.kind, "value": self.value,
                "label": self.label, "purpose": self.purpose, "role_default": self.role_default,
                "source": self.source, "verified": self.verified,
                "verified_at": self.verified_at.isoformat() if self.verified_at else None,
                "verification_note": self.verification_note, "notes": self.notes,
                "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
                "scope": self.scope, "to_be_confirmed": self.to_be_confirmed, "disabled": self.disabled,
                "who": self.who}


@dataclass
class ContactCard:
    org: Org | None = None
    entries: list[ChannelEntry] = field(default_factory=list)
    visible: bool = True
    masked: bool = False
    can_manage: bool = False  # case admin: case-scoped add / verify / disable
    can_manage_global: bool = False  # system admin: global rows and catalogue verifications
    attachable: bool = False  # the authority has an entity, organisation or LE contact to attach rows to

    @property
    def info_only(self) -> bool:
        return bool(self.org and self.org.info_only)

    @property
    def portal_only(self) -> bool:
        return bool(self.org and self.org.portal_only) and not any(e.sendable for e in self.entries)

    @property
    def portal_url(self) -> str | None:
        return next((e.value for e in self.entries if e.kind in ("portal", "webform") and e.value and not e.disabled
                     and not e.masked and not e.le_only), None) or (self.org.portal_url if self.org else None)

    def groups(self) -> list[tuple[str, list[ChannelEntry]]]:
        out = []
        for g in GROUPS:
            rows = [e for e in self.entries if e.group == g]
            if g == "Disabled" and not (self.can_manage or self.can_manage_global):
                continue
            if rows:
                out.append((g, rows))
        return out

    def emails(self) -> list[ChannelEntry]:
        return [e for e in self.entries if e.sendable]

    def le_only_addresses(self) -> set[str]:
        """E-mail channels the provider reserves for law enforcement (playbook who le_only)."""
        return {e.value.lower() for e in self.emails() if e.le_only}

    def verified_addresses(self) -> set[str]:
        return {e.value.lower() for e in self.emails() if e.verified}

    def entry_for(self, address: str) -> ChannelEntry | None:
        a = (address or "").lower()
        hits = [e for e in self.emails() if e.value.lower() == a]
        return next((e for e in hits if e.verified), hits[0] if hits else None)


def _row_entry(row: EntityChannel, scope: str) -> ChannelEntry:
    return ChannelEntry(
        id=row.id, catalogue_key=row.catalogue_key, kind=row.kind.value, value=row.value, label=row.label,
        purpose=row.purpose.value, role_default=row.role_default.value, source=row.source.value,
        verified=bool(row.verified), verified_at=row.verified_at, verification_note=row.verification_note,
        notes=row.notes, last_used_at=row.last_used_at, scope=scope, disabled=bool(row.disabled),
        meta=dict(row.meta or {}))


def _mailbox_addresses() -> set[str]:
    """The configured case mailbox (never offered as a recipient). Empty when mail is not set up."""
    try:
        from app.domain import mail_send

        mbx = mail_send._settings().mail_from
    except Exception:  # noqa: BLE001 - the directory works without the mail feature
        return set()
    return {mbx.lower()} if mbx else set()


def _profile_addresses(db: Session, case: Case) -> set[str]:
    from app.domain import sender

    p = sender.get_profile(db, case)
    if p is None:
        return set()
    out = {str(c).strip().lower() for c in (p.cc_default or []) if str(c).strip()}
    if p.contact_email:
        out.add(p.contact_email.strip().lower())
    return out


def _member_addresses(case: Case) -> set[str]:
    """The case members' own sign-in addresses (our team, never an authority's contact)."""
    return {m.user.email.strip().lower() for m in case.members if m.user is not None and m.user.email}


def _target(authority, org: Org | None) -> dict:
    """The directory keys a channel of this authority is stored under."""
    entity = authority.entity
    le_id = authority.le_contacts[0].id if (entity is None and authority.le_contacts) else None
    return {"entity_id": entity.id if entity is not None else None, "org_key": org.key if org else None,
            "le_contact_id": le_id}


def _merge(into: ChannelEntry, other: ChannelEntry) -> None:
    if other.who and not into.who:
        into.who = other.who
    if other.verified and not into.verified:
        into.verified, into.verified_at, into.verification_note = True, other.verified_at, other.verification_note
        if into.id is None:
            into.id = other.id
    if other.last_used_at and (into.last_used_at is None or other.last_used_at > into.last_used_at):
        into.last_used_at = other.last_used_at
    if other.meta.get("seen"):
        s, o = dict(into.meta.get("seen") or {"in": 0, "out": 0, "last": None}), other.meta["seen"]
        s["in"], s["out"] = s.get("in", 0) + o.get("in", 0), s.get("out", 0) + o.get("out", 0)
        s["last"] = max([x for x in (s.get("last"), o.get("last")) if x], default=None)
        into.meta["seen"] = s


OUTLOOK_NOT_TO_AUTHORITY = "no recipient is the letter's authority"  # app.mail.sync_outbound's review reason


def recipients_untrusted(c) -> bool:
    """An outbound entry the mailbox sync logged from Sent Items (meta.source "mailbox_sent") that waits for
    review, was dismissed, or was rejected because no recipient is the letter's authority: its recipients
    say nothing about the authority's addresses (the directory, the guidance and the compose page skip them)."""
    meta = c.meta or {}
    if meta.get("source") != "mailbox_sent":
        return False
    return bool(meta.get("needs_review") or meta.get("dismissed")
                or str(meta.get("review_reason") or "").startswith(OUTLOOK_NOT_TO_AUTHORITY))


def _derived(authority, exclude: set[str]) -> list[ChannelEntry]:
    from app.domain import correspondence as desk

    seen: dict[str, dict] = {}

    def add(addr: str, src: str, way: str | None, at: datetime | None, role: str = "to") -> None:
        a = addr.strip().lower()
        if not a or a in exclude:
            return
        try:
            a = validate_address(a)
        except DirectoryError:
            return
        d = seen.setdefault(a, {"source": src, "in": 0, "out": 0, "last": None, "roles": set()})
        if src == "le_contact":
            d["source"] = "le_contact"
        if way:
            d[way] += 1
        d["roles"].add(role)
        if at is not None:
            iso = at.astimezone(UTC).isoformat()
            d["last"] = max([x for x in (d["last"], iso) if x], default=None)

    for le in authority.le_contacts:
        for m in desk._EMAIL_RE.finditer(le.email or ""):
            add(m.group(0), "le_contact", None, None)
    for c in authority.correspondence:
        at = c.occurred_at or c.created_at
        if c.direction == CorrespondenceDirection.IN:
            if (c.meta or {}).get("sender_domain_ok") is False:
                continue  # a mailbox reply from a foreign domain says nothing about the authority's addresses
            for m in desk._EMAIL_RE.finditer(c.sender or ""):
                add(m.group(0), "case_correspondence", "in", at)
        elif c.direction == CorrespondenceDirection.OUT and c.status == CorrespondenceStatus.SENT:
            if recipients_untrusted(c):
                continue  # an Outlook e-mail logged for review / dismissed / not to the authority
            # To only: a letter's Cc is the victim, our own team or a third party, not the authority
            for r in c.recipients or []:
                for m in desk._EMAIL_RE.finditer(str(r)):
                    add(m.group(0), "case_correspondence", "out", at, "to")
    out = []
    for a, d in seen.items():
        role = "to" if "to" in d["roles"] or not d["roles"] else "cc"
        label = "LE contact on file" if d["source"] == "le_contact" else "From this case's correspondence"
        out.append(ChannelEntry(
            id=None, catalogue_key=None, kind="email", value=a, label=label, purpose="general", role_default=role,
            source=d["source"], verified=False, verified_at=None, verification_note=None, notes=None,
            last_used_at=None, scope="case",
            meta={"seen": {"in": d["in"], "out": d["out"], "last": d["last"]}} if d["source"] != "le_contact" else {}))
    return out


def _mask_value(kind: str, value: str | None) -> str | None:
    from app.domain import evidence as ev

    if value is None:
        return None
    if kind == "email":
        return ev.mask_email(value)
    if kind == "phone":
        return ev.mask_phone(value)
    if kind in ("portal", "webform", "website"):
        m = re.match(r"(https://[^/]+)", value)
        return (m.group(1) + "/…") if m else "***"
    return "***"


def channels_for(db: Session, access, authority, *, catalogue: Catalogue | None = None) -> ContactCard:
    """The "How to contact" card of one authority for one member (module doc: sources, merge order,
    visibility)."""
    if access is not None and access.is_external:
        return ContactCard(visible=False)
    cat = catalogue or load_catalogue()
    org = org_for(authority, cat)
    case = access.case
    entity = authority.entity
    le_ids = [le.id for le in authority.le_contacts]
    entries: list[ChannelEntry] = []
    index: dict[tuple, ChannelEntry] = {}

    def push(e: ChannelEntry) -> None:
        key = (e.kind, e.value.lower()) if e.value else ("tbc", e.catalogue_key or e.id or e.label)
        if key in index:
            _merge(index[key], e)
            return
        index[key] = e
        entries.append(e)

    conds_global = []
    if entity is not None:
        conds_global.append(EntityChannel.entity_id == entity.id)
    if org is not None:
        conds_global.append(EntityChannel.org_key == org.key)
        conds_global.append(EntityChannel.catalogue_key.in_([c.key for c in org.channels] or [""]))
    global_rows = list(db.scalars(select(EntityChannel).where(EntityChannel.case_id.is_(None), or_(*conds_global))
                                  .order_by(EntityChannel.id))) if conds_global else []
    overlays = {r.catalogue_key: r for r in global_rows if r.catalogue_key}
    # 1. catalogue (+ the global row that verifies / overrides it)
    if org is not None:
        for c in org.channels:
            row = overlays.get(c.key)
            e = ChannelEntry(
                id=row.id if row else None, catalogue_key=c.key, kind=row.kind.value if row else c.kind,
                value=(row.value if row and row.value else c.value), label=(row.label if row and row.label else c.label),
                purpose=c.purpose, role_default=c.role_default, source="catalogue",
                verified=bool(row.verified) if row else False, verified_at=row.verified_at if row else None,
                verification_note=row.verification_note if row else None,
                notes=(row.notes if row and row.notes else c.notes), last_used_at=row.last_used_at if row else None,
                scope="catalogue", disabled=bool(row.disabled) if row else False, source_url=c.source_url, who=c.who)
            push(e)
    # 2. global rows
    for r in global_rows:
        if r.catalogue_key and org is not None and r.catalogue_key in {c.key for c in org.channels}:
            continue
        push(_row_entry(r, "global"))
    # 3. the entity record
    if entity is not None:
        if entity.compliance_email:
            try:
                addr = validate_address(entity.compliance_email)
                push(ChannelEntry(id=None, catalogue_key=None, kind="email", value=addr, label="Entity record",
                                  purpose="compliance", role_default="to", source="entity_record", verified=False,
                                  verified_at=None, verification_note=None, notes=None, last_used_at=None,
                                  scope="global"))
            except DirectoryError:
                pass
        if entity.le_portal_url:
            push(ChannelEntry(id=None, catalogue_key=None, kind="portal", value=entity.le_portal_url.strip(),
                              label="Entity record (LE portal)", purpose="le_request", role_default="to",
                              source="entity_record", verified=False, verified_at=None, verification_note=None,
                              notes=None, last_used_at=None, scope="global"))
    # 4. case-scoped rows
    conds_case = []
    if entity is not None:
        conds_case.append(EntityChannel.entity_id == entity.id)
    if org is not None:
        conds_case.append(EntityChannel.org_key == org.key)
    if le_ids:
        conds_case.append(EntityChannel.le_contact_id.in_(le_ids))
    if conds_case:
        for r in db.scalars(select(EntityChannel).where(EntityChannel.case_id == case.id, or_(*conds_case))
                            .order_by(EntityChannel.id)):
            push(_row_entry(r, "case"))
    # 5. derived case recipients
    exclude = _mailbox_addresses() | _profile_addresses(db, case) | _member_addresses(case)
    for e in _derived(authority, exclude):
        push(e)

    masked = access is not None and not access.can("view_restricted")
    if masked:
        for e in entries:
            if e.scope == "case":
                e.value, e.masked, e.meta = _mask_value(e.kind, e.value), True, {}
    user = access.user if access is not None else None
    return ContactCard(
        org=org, entries=entries, visible=True, masked=masked,
        can_manage=access is not None and access.can("manage_channels"),
        can_manage_global=bool(user is not None and user.is_system_admin),
        attachable=bool(entity is not None or org is not None or le_ids))


# --------------------------------------------------------------------------- mutations (the caller audits)
def _may_case(access) -> None:
    if access is None or not access.can("manage_channels"):
        raise DirectoryForbidden("only case admins may change this case's contact channels")


def _may_global(user: User | None) -> None:
    if user is None or not user.is_system_admin:
        raise DirectoryForbidden("only system administrators may change the global directory")


def _fields(kind: str, value: str | None, purpose: str, role_default: str, label: str | None,
            notes: str | None) -> dict:
    if purpose not in PURPOSES:
        raise DirectoryError("unknown purpose")
    if role_default not in ROLES:
        raise DirectoryError("unknown role (to / cc)")
    return {"kind": ChannelKind(kind), "value": validate_value(kind, value), "purpose": ChannelPurpose(purpose),
            "role_default": ChannelRole(role_default), "label": _clean_text(label, "label", 255),
            "notes": _clean_text(notes, "notes", 2000)}


def _stamp(row: EntityChannel, user: User | None, verified: bool, note: str | None) -> None:
    row.verified = bool(verified)
    row.verified_by = user.id if (verified and user is not None) else None
    row.verified_at = _now() if verified else None
    row.verification_note = _clean_text(note, "verification note", 512)


def add_channel(db: Session, access, authority, *, kind: str, value: str | None, purpose: str = "general",
                role_default: str = "to", label: str | None = None, notes: str | None = None, scope: str = "case",
                verified: bool = False, note: str | None = None, source: str = "manual") -> EntityChannel:
    """A channel for `authority`: `scope="case"` (case admins; R2, this case only) or
    `scope="global"` (system admins; I0, every case). `verified` records who confirmed it."""
    if scope == "global":
        _may_global(access.user if access is not None else None)
    elif scope == "case":
        _may_case(access)
    else:
        raise DirectoryError("unknown scope")
    if source not in {s.value for s in ChannelSource} or source == "catalogue":
        raise DirectoryError("unknown source")
    org = org_for(authority)
    target = _target(authority, org)
    if not any(target.values()):
        raise DirectoryError("this counterparty has no entity, organisation or contact record to attach a channel to")
    f = _fields(kind, value, purpose, role_default, label, notes)
    if f["value"] is None and kind == "email":
        raise DirectoryError("an e-mail channel needs an address")
    case_id = access.case.id if scope == "case" else None
    existing = _find_same(db, case_id, target, f["kind"], f["value"])
    row = existing or EntityChannel(**target, case_id=case_id, source=ChannelSource(source),
                                    created_by=access.user.id if access is not None else None, meta={})
    for k, v in f.items():
        if v is not None or k in ("kind",):
            setattr(row, k, v)
    row.classification = Classification.R2 if scope == "case" else Classification.I0
    row.disabled = False
    if verified or existing is None:
        _stamp(row, access.user if access is not None else None, verified, note)
    db.add(row)
    db.flush()
    return row


def _find_same(db: Session, case_id: int | None, target: dict, kind: ChannelKind, value: str | None):
    if value is None:
        return None
    q = select(EntityChannel).where(EntityChannel.kind == kind,
                                    EntityChannel.case_id.is_(None) if case_id is None else EntityChannel.case_id == case_id)
    for k in ("entity_id", "org_key", "le_contact_id"):
        if target[k] is not None:
            q = q.where(getattr(EntityChannel, k) == target[k])
    return next((r for r in db.scalars(q) if (r.value or "").lower() == value.lower()), None)


def add_global_channel(db: Session, user: User, *, org_key: str | None = None, entity_id: int | None = None,
                       kind: str, value: str | None, purpose: str = "general", role_default: str = "to",
                       label: str | None = None, notes: str | None = None, verified: bool = False,
                       note: str | None = None) -> EntityChannel:
    """A global directory row (the /directory page): system admins only."""
    _may_global(user)
    if org_key and org_key not in load_catalogue().by_key:
        raise DirectoryError("unknown organisation")
    if not org_key and not entity_id:
        raise DirectoryError("choose the organisation the channel belongs to")
    f = _fields(kind, value, purpose, role_default, label, notes)
    if f["value"] is None:
        raise DirectoryError("a global channel needs a value")
    target = {"entity_id": entity_id, "org_key": org_key or None, "le_contact_id": None}
    row = _find_same(db, None, target, f["kind"], f["value"]) or EntityChannel(
        **target, case_id=None, source=ChannelSource.MANUAL, created_by=user.id, meta={})
    for k, v in f.items():
        setattr(row, k, v)
    row.classification, row.disabled = Classification.I0, False
    _stamp(row, user, verified, note)
    db.add(row)
    db.flush()
    return row


def verify_catalogue(db: Session, user: User | None, catalogue_key: str, *, verified: bool,
                     note: str | None = None) -> EntityChannel:
    """Verify (or unverify) a shipped catalogue channel: creates / updates its one global overlay row
    (system admins only). A 'to be confirmed' channel cannot be verified until it has a value."""
    _may_global(user)
    cat = load_catalogue()
    chan = cat.channel(catalogue_key)
    if chan is None:
        raise DirectoryError("unknown catalogue channel")
    row = db.scalar(select(EntityChannel).where(EntityChannel.case_id.is_(None),
                                                EntityChannel.catalogue_key == catalogue_key,
                                                EntityChannel.disabled.is_(False)).order_by(EntityChannel.id))
    if row is None:
        row = EntityChannel(org_key=chan.org_key, case_id=None, catalogue_key=catalogue_key, kind=ChannelKind(chan.kind),
                            value=None, purpose=ChannelPurpose(chan.purpose), role_default=ChannelRole(chan.role_default),
                            source=ChannelSource.CATALOGUE, classification=Classification.I0, created_by=user.id,
                            meta={})
        db.add(row)
    if verified and not (row.value or chan.value):
        raise DirectoryError("a channel that is still 'to be confirmed' needs a value before it can be verified")
    _stamp(row, user, verified, note)
    db.flush()
    return row


def verify_channel(db: Session, access, ref: int | str, *, verified: bool, note: str | None = None,
                   user: User | None = None) -> EntityChannel:
    """Verify / unverify a directory row by id (global rows: system admins; case rows: that case's
    admins), or a catalogue channel by its key (system admins)."""
    actor = user or (access.user if access is not None else None)
    if isinstance(ref, str) and not ref.isdigit():
        return verify_catalogue(db, actor, ref, verified=verified, note=note)
    row = db.get(EntityChannel, int(ref))
    if row is None or (row.case_id is not None and (access is None or row.case_id != access.case.id)):
        raise LookupError("channel not found")
    if row.case_id is None:
        _may_global(actor)
    else:
        _may_case(access)
    if verified and row.value is None:
        raise DirectoryError("a channel that is still 'to be confirmed' needs a value before it can be verified")
    _stamp(row, actor, verified, note)
    db.flush()
    return row


def disable_channel(db: Session, access, channel_id: int, *, user: User | None = None,
                    disabled: bool = True) -> EntityChannel:
    actor = user or (access.user if access is not None else None)
    row = db.get(EntityChannel, int(channel_id))
    if row is None or (row.case_id is not None and (access is None or row.case_id != access.case.id)):
        raise LookupError("channel not found")
    if row.case_id is None:
        _may_global(actor)
    else:
        _may_case(access)
    row.disabled = bool(disabled)
    db.flush()
    return row


def touch_used(db: Session, case: Case, addresses) -> int:
    """Stamp last_used_at on the directory rows (this case's and global ones) of the addresses a
    message just went to. Flushes; returns the number of rows touched."""
    wanted = {str(a).strip().lower() for a in addresses or [] if str(a).strip()}
    if not wanted:
        return 0
    now, n = _now(), 0
    rows = db.scalars(select(EntityChannel).where(EntityChannel.kind == ChannelKind.EMAIL,
                                                  or_(EntityChannel.case_id.is_(None), EntityChannel.case_id == case.id)))
    for r in rows:
        if (r.value or "").lower() in wanted:
            r.last_used_at = now
            n += 1
    db.flush()
    return n


# --------------------------------------------------------------------------- the /directory page
@dataclass
class DirectoryOrg:
    org: Org | None
    name: str
    entries: list[ChannelEntry]


def global_directory(db: Session) -> list[DirectoryOrg]:
    """Every catalogue organisation with its channels (overlaid by their global rows) and the global
    rows added for it; then global rows of entities outside the catalogue. I0 only: no case rows."""
    from app.db.models import Entity

    cat = load_catalogue()
    rows = list(db.scalars(select(EntityChannel).where(EntityChannel.case_id.is_(None)).order_by(EntityChannel.id)))
    overlays = {r.catalogue_key: r for r in rows if r.catalogue_key}
    used: set[int] = set()
    out = []
    for o in cat.orgs:
        entries = []
        for c in o.channels:
            r = overlays.get(c.key)
            if r is not None:
                used.add(r.id)
            entries.append(ChannelEntry(
                id=r.id if r else None, catalogue_key=c.key, kind=c.kind, value=(r.value if r and r.value else c.value),
                label=c.label, purpose=c.purpose, role_default=c.role_default, source="catalogue",
                verified=bool(r.verified) if r else False, verified_at=r.verified_at if r else None,
                verification_note=r.verification_note if r else None, notes=c.notes,
                last_used_at=r.last_used_at if r else None, scope="catalogue",
                disabled=bool(r.disabled) if r else False, source_url=c.source_url, who=c.who))
        for r in rows:
            if r.id not in used and r.org_key == o.key:
                used.add(r.id)
                entries.append(_row_entry(r, "global"))
        out.append(DirectoryOrg(org=o, name=o.name, entries=entries))
    rest = [r for r in rows if r.id not in used]
    if rest:
        names = {e.id: e.name for e in db.scalars(select(Entity).where(
            Entity.id.in_({r.entity_id for r in rest if r.entity_id})))}
        by_entity: dict[str, list[ChannelEntry]] = {}
        for r in rest:
            by_entity.setdefault(names.get(r.entity_id, r.org_key or "Other"), []).append(_row_entry(r, "global"))
        out += [DirectoryOrg(org=None, name=n, entries=e) for n, e in sorted(by_entity.items())]
    return out
