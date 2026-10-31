"""Provider playbooks: who may use which channel of an organisation, its request paths (requester, instrument,
evidence, clocks), the reply phrases that mean something and the sources of every claim.

Owner: the mail feature. One file per catalogue organisation, `data/catalogue/providers/<org_key>.json` (I0, in
git: generic public facts, never case data). `app.domain.directory.load_catalogue` parses each file with `parse`
and merges it into its `Org` (`Org.playbook`, the channels' `who`, declared channels), cached by mtime with the
catalogue; `directory.playbook_for(authority)` returns it. A file that breaks a rule makes the whole catalogue
invalid (never loaded half-valid).

Schema (version 1; unknown keys are refused at every level):

    key, version: 1, side: provider | le, jurisdiction: "US" | null, issuer_jurisdictions: ["US", "FR"],
    ground_truth: reply | onchain, notes, le_role: police | judicial | intake | coordination (side "le" only;
    intake: a complaint portal that never files with a provider, so it is never the brief's recipient),
    entities: [{key, name, jurisdiction, separate, notes, source_ids}],
    domains: {own: [domain], sibling: [{domain, entity, purpose, <provenance>}],
              vendor_portals: [{host, path_prefix, tenant, le_only, <provenance>}]},
    channels: [{key "<org>.<name>", kind, value, purpose, role_default, label, notes, source_url, who, <provenance>}],
    channels_ext: {"<channels.json key>": {who, purpose, notes, <provenance>}},
    paths: [{key, kind, requester: [..], entity, channel_keys, instrument: {type, issuer_jurisdictions, signing,
             language, notes}, evidence: [..], produces: [..], timing: {response_days, ack_hours, hold_days,
             auto_lift_days, preservation_days, portal_onboarding_days, deadlines: [{key, what, hours | days |
             working_days | months, starts, by, action, <provenance>}]}, expected_replies, outcomes, on_refusal,
             conflict, notes, <provenance>}],
    reply_signals: [{phrase, means, instrument, channel_key, path, <provenance>}],
    tickets: [{system, regex, <provenance>}],
    issues: [{instrument, jurisdiction, by, to: [org keys], notes, <provenance>}]     (side "le" only)
    addresses: [{chain, address, kind, label, <provenance>}]   the organisation's own published wallets (side
             "provider" only; kind exchange_deposit | exchange_hot_wallet | swap_bridge | issuer | casino; never an
             observed source: an address seen in a reply is case data), read by app.attribution
    sources: [{id, title, url, retrieved_at, observed}]

    <provenance> = source_ids (≥ 1 id of `sources`), basis D | R | I | O, confidence H | M | L,
                   retrieved_at "YYYY-MM-DD" | "YYYY-MM" ("YYYY-MM" only for basis O: an observed fact never
                   carries a day that could tie it to a case)

Rules beyond the shapes: every le_request channel of the organisation has a `who`; a path's channels exist (in
channels.json for this organisation or declared here); a path open to a private party never uses an le_only channel;
a private_notice / victim_report path takes no binding instrument; an observed source has no URL, a month-only
date and no day-level date or address in its title; `null` means "to be confirmed" and placeholders ("TBC",
"unknown") are refused; `verified` / `verified_by` never appear (verification lives in entity_channels).

**LE-only gate** (`may_use`, `Playbook.gate`): a channel whose `who` is le_only is never offered to, or sent to by, a
private requester (victim, PI, counsel): the next action is a brief to LE with the pack (`LE_ONLY_REASON`). Aegis
senders are never LE (`app.domain.sender.requester_kind`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from urllib.parse import urlsplit

from app.db.models import ChannelKind, ChannelPurpose, ChannelRole, ReplyStatus
from app.domain.addresses import addr_key

VERSION = 1
BASIS = {"D": "documented on the provider's own page", "R": "reported by a secondary source", "I": "inferred",
         "O": "observed in a provider's reply to us"}
CONFIDENCE = {"H": "high", "M": "medium", "L": "low"}
SIDES = ("provider", "le")
LE_ROLES = ("police", "judicial", "intake", "coordination")
GROUND_TRUTH = ("reply", "onchain")  # onchain: only the issuer's own event (app.freeze) makes "frozen" true
REQUESTERS = ("victim", "pi", "counsel", "le", "court", "regulator")
PRIVATE = frozenset({"victim", "pi", "counsel"})
OFFICIAL = frozenset({"le", "court", "regulator"})
WHO = {
    "any": "anyone",
    "victim_or_rep": "the victim or their representative (PI, counsel)",
    "le_only": "law enforcement / judicial authorities only (private parties are excluded by the provider)",
    "counsel_with_order": "anyone may write, but it acts only on LE process or a court order (expect a redirect)",
}
LE_ONLY_REASON = "LE only: send the officer the pack"
PATH_KINDS = {
    "private_notice": "an unsolicited notice from the victim / PI / counsel to a channel not published for victims: "
                      "preservation and a risk flag, asking for a precautionary hold (no instrument)",
    "victim_report": "the provider's own published intake for victims or their representatives (form, ticket, "
                     "address); may lead to a discretionary, time-limited hold",
    "complaint": "a criminal complaint or report filed with law enforcement (IC3, denuncia-querela)",
    "le_request": "a request by law enforcement through the provider's LE channel (freeze, hold, preservation)",
    "data_disclosure": "records / KYC disclosure on legal process",
    "court_order": "a binding order served on the provider (freeze, seizure, sequestro, TRO)",
    "cross_border": "MLAT, EIO, Reg. (EU) 2018/1805 freezing order, rogatoria",
    "release": "lifting a block or returning the funds",
    "takedown": "hosting / infrastructure abuse takedown",
}
INSTRUMENTS = {
    "none": "no instrument", "police_report": "a police report / complaint receipt",
    "le_request": "an LE request (agency letterhead, official domain)", "subpoena": "a subpoena",
    "court_order": "a court order", "us_or_fr_court_order": "a US or French court order",
    "freezing_order": "a freezing / seizure order (e.g. decreto di sequestro preventivo)",
    "seizure_warrant": "a seizure warrant", "formal_directive": "a formal legal directive",
    "mlat": "an MLAT request", "eu_freezing_order": "an EU freezing order (Reg. (EU) 2018/1805)",
    "eio": "a European Investigation Order", "judicial_decision": "a judicial decision (asset return / release)",
}
BINDING = frozenset(INSTRUMENTS) - {"none", "police_report"}
SIGNING = ("any", "not_digital")  # not_digital: a digital signature / e-seal is refused (a signed scan may do)
EVIDENCE = frozenset({
    "incident_narrative", "ownership_proof", "victim_id", "tx_list_copyable", "trace_report_run", "balance_reading",
    "freeze_check", "receiving_account", "provider_ids", "police_report", "complaint_ref", "ic3_ref", "loa", "poa",
    "special_proxy", "le_agency_identity", "le_letterhead_request", "court_order", "seizure_warrant", "mlat_bundle",
    "english_version", "freeze_duration_stmt", "non_disclosure_stmt", "prior_ticket_ref", "native_vs_bridged_stmt",
    "comms_export", "wire_details", "urgency_stmt", "domestic_order",
})
TIMING_KEYS = ("response_days", "ack_hours", "hold_days", "auto_lift_days", "preservation_days",
               "portal_onboarding_days")
DEADLINE_WHAT = ("submit_by", "file_by", "reply_by", "hold_until", "auto_lift", "recognise_by", "execute_by",
                 "validate_by", "decide_by")
CLOCK_STARTS = {
    "sent": "our request was sent", "provider_ack": "the provider acknowledged it",
    "provider_freeze_confirmed": "the provider confirmed a temporary freeze",
    "hold_confirmed": "a hold was confirmed", "order_served": "the order was served",
    "fact_known": "the victim learned of the offence", "seizure": "an urgent seizure was executed",
    "validation_requested": "validation of the seizure was requested",
    "certificate_received": "the executing authority received the certificate", "recognition": "the order was recognised",
}
UNITS = ("hours", "days", "working_days", "months")
REPLY_MEANS = tuple(s.value for s in ReplyStatus)
KINDS = tuple(k.value for k in ChannelKind)
PURPOSES = tuple(p.value for p in ChannelPurpose)
ROLES = tuple(r.value for r in ChannelRole)
_KEY = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_ORG_KEY = re.compile(r"[a-z0-9][a-z0-9-]{1,63}")
_JUR = re.compile(r"[A-Z]{2}")
_DOMAIN = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")
_DATE = re.compile(r"(\d{4})-(\d{2})(?:-(\d{2}))?")
_PLACEHOLDER = re.compile(r"(?i)^\s*(tbc|tbd|todo|tba|n/?a|unknown|none|null|\?+|-+|x+|to be confirmed)\s*$")
_MONTH = (r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|"
          r"oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)(?![a-z])")
# a day-level date in any common form (ISO, with a time, compact, d.m.y / d-m-y / d/m, "3 Oct", "3-Oct-2026",
# "03Oct2026", "October 3", "3rd of October"): month names exact, so "market 24 hours" is no date
_DAY_DATE = re.compile(r"(?i)\b\d{4}-\d{2}-\d{2}(?=T|\b)|\b20\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\b|"
                       r"\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b|\b\d{1,2}/\d{1,2}\b|\b\d{1,2}\.\d{1,2}\.(?!\d)|"
                       r"\b(?:0[1-9]|[12]\d|3[01])-(?:0[1-9]|1[0-2])\b|"
                       r"\b\d{1,2}(?:st|nd|rd|th)?[\s-]*" + _MONTH + r"|"
                       r"\b" + _MONTH + r"\.?\s+\d{1,2}(?:st|nd|rd|th)?(?!\d)|"
                       r"\b\d{1,2}(?:st|nd|rd|th)?\s+of\s+" + _MONTH + r"|"
                       # 2026.10.03, 2026 10 03, 2026-10-3; 3-10 (not a range: "1-2 days"); "Tuesday the 3rd"
                       r"\b(?:19|20)\d{2}[-./ ](?:0?[1-9]|1[0-2])[-./ ](?:0?[1-9]|[12]\d|3[01])\b|"
                       r"\b(?:0?[1-9]|[12]\d|3[01])-(?:0?[1-9]|1[0-2])\b(?!\s*(?:hours?|days?|weeks?|months?|years?|"
                       r"business|working|calendar|minutes?|h\b|d\b|%|x\b))|"
                       r"\b(?:mon|tues|wednes|thurs|fri|satur|sun)day,?\s+(?:the\s+)?\d{1,2}(?:st|nd|rd|th)?\b|"
                       # Italian / French / German / Spanish month names after a day ("3 ottobre", "3. Oktober")
                       r"\b\d{1,2}(?:\.|º|°|er)?\s*(?:de\s+)?(?:gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|"
                       r"agosto|settembre|ottobre|novembre|dicembre|janvier|f[ée]vrier|mars|avril|mai|juin|juillet|"
                       r"ao[uû]t|septembre|octobre|d[ée]cembre|januar|j[äa]nner|februar|m[äa]e?rz|m[äa]r|juni|juli|"
                       r"oktober|okt|dezember|dez|enero|febrero|abril|mayo|junio|julio|septiembre|setiembre|octubre|"
                       r"noviembre|diciembre)(?![^\W\d_])")
_DASHES = re.compile(r"[\u2010-\u2015\u2212\ufe58\ufe63\uff0d]")


def _day_date(text: str) -> bool:
    """A day-level date in `text` (_DAY_DATE), after folding Unicode hyphens and spaces into ASCII ones."""
    t = _DASHES.sub("-", text).replace("\u00a0", " ").replace("\u202f", " ")
    return bool(_DAY_DATE.search(t))
_ADDR = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")
_JUR_NAMES = {"us": "US", "usa": "US", "u.s.": "US", "u.s.a.": "US", "united states": "US",
              "united states of america": "US", "it": "IT", "italy": "IT", "italia": "IT", "fr": "FR", "france": "FR",
              "ch": "CH", "switzerland": "CH", "schweiz": "CH", "suisse": "CH", "de": "DE", "germany": "DE",
              "uk": "GB", "gb": "GB", "united kingdom": "GB", "es": "ES", "spain": "ES", "nl": "NL",
              "netherlands": "NL", "ie": "IE", "ireland": "IE", "at": "AT", "austria": "AT", "be": "BE",
              "belgium": "BE", "lt": "LT", "lithuania": "LT", "sc": "SC", "seychelles": "SC", "sg": "SG",
              "singapore": "SG", "hk": "HK", "hong kong": "HK"}
EU = frozenset({"AT", "BE", "BG", "HR", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HU", "IE", "IT", "LT",
                "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK"})


class PlaybookError(ValueError):
    """A provider playbook file breaks a rule (directory.load_catalogue reports it as a CatalogueError)."""


# --------------------------------------------------------------------------- dataclasses
@dataclass(frozen=True)
class Source:
    id: str
    title: str
    url: str | None
    retrieved_at: str
    observed: bool = False


@dataclass(frozen=True)
class Prov:
    source_ids: tuple[str, ...]
    basis: str
    confidence: str
    retrieved_at: str


@dataclass(frozen=True)
class Entity:
    key: str
    name: str
    jurisdiction: str | None = None
    separate: bool = False
    notes: str | None = None
    source_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Sibling:
    domain: str
    entity: str | None
    purpose: str | None
    prov: Prov


@dataclass(frozen=True)
class VendorPortal:
    host: str
    path_prefix: str
    tenant: str | None
    le_only: bool
    prov: Prov


@dataclass(frozen=True)
class Domains:
    own: tuple[str, ...] = ()
    sibling: tuple[Sibling, ...] = ()
    vendor_portals: tuple[VendorPortal, ...] = ()


@dataclass(frozen=True)
class KnownAddress:
    """A wallet the organisation itself publishes (app.attribution: the catalogue source)."""

    chain: str
    address: str  # EVM lower-case, TRON / Bitcoin verbatim
    kind: str
    label: str | None
    prov: Prov


@dataclass(frozen=True)
class ChannelRule:
    """What the playbook says about one channel of the organisation (channels.json key or declared here)."""

    key: str
    who: str
    purpose: str | None
    notes: str | None
    declared: bool
    prov: Prov


@dataclass(frozen=True)
class Instrument:
    type: str = "none"
    issuer_jurisdictions: tuple[str, ...] = ()
    signing: str = "any"
    language: tuple[str, ...] = ()
    notes: str | None = None

    @property
    def binding(self) -> bool:
        return self.type in BINDING

    @property
    def label(self) -> str:
        return INSTRUMENTS[self.type]


@dataclass(frozen=True)
class Deadline:
    key: str
    what: str
    unit: str
    amount: float
    starts: str
    by: str | None
    action: str | None
    prov: Prov

    @property
    def span(self) -> str:
        n = int(self.amount) if float(self.amount).is_integer() else self.amount
        return f"{n} {self.unit.replace('_', ' ')}" if n != 1 else f"1 {self.unit.replace('_', ' ').rstrip('s')}"


@dataclass(frozen=True)
class Timing:
    response_days: float | None = None
    ack_hours: float | None = None
    hold_days: float | None = None
    auto_lift_days: float | None = None
    preservation_days: float | None = None
    portal_onboarding_days: float | None = None
    deadlines: tuple[Deadline, ...] = ()


@dataclass(frozen=True)
class Path:
    key: str
    kind: str
    requester: tuple[str, ...]
    instrument: Instrument
    prov: Prov
    entity: str | None = None
    channel_keys: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    timing: Timing = field(default_factory=Timing)
    expected_replies: tuple[str, ...] = ()
    outcomes: tuple[str, ...] = ()
    on_refusal: str | None = None
    conflict: str | None = None
    notes: str | None = None

    def open_to(self, requester: str, held=()) -> bool:
        """`requester` may take this path now: it is one of the path's requesters and, for a binding instrument,
        holds it (`held`: instrument types an LE officer or counsel has supplied)."""
        return requester in self.requester and (not self.instrument.binding or self.instrument.type in set(held))


@dataclass(frozen=True)
class Signal:
    phrase: str
    means: str
    prov: Prov
    instrument: str | None = None
    channel_key: str | None = None
    path: str | None = None


@dataclass(frozen=True)
class TicketFormat:
    system: str
    regex: str | None
    prov: Prov


@dataclass(frozen=True)
class Issue:
    """An instrument a law-enforcement / judicial side can produce, and for whom (side "le")."""

    instrument: str
    jurisdiction: str | None
    by: str | None
    to: tuple[str, ...]
    notes: str | None
    prov: Prov


@dataclass(frozen=True)
class Gate:
    open: tuple[Path, ...]
    le_only: bool  # no path at all lists this requester
    needs: tuple[str, ...]  # binding instruments of the paths that do list the requester
    reason: str | None  # None: a path is open


@dataclass(frozen=True)
class Playbook:
    key: str
    side: str
    sources: tuple[Source, ...]
    jurisdiction: str | None = None
    issuer_jurisdictions: tuple[str, ...] = ()
    ground_truth: str = "reply"
    notes: str | None = None
    entities: tuple[Entity, ...] = ()
    domains: Domains = field(default_factory=Domains)
    channels: tuple[ChannelRule, ...] = ()
    paths: tuple[Path, ...] = ()
    signals: tuple[Signal, ...] = ()
    tickets: tuple[TicketFormat, ...] = ()
    issues: tuple[Issue, ...] = ()
    le_role: str | None = None
    addresses: tuple[KnownAddress, ...] = ()

    def rule(self, channel_key: str) -> ChannelRule | None:
        return next((c for c in self.channels if c.key == channel_key), None)

    def who(self, channel_key: str) -> str | None:
        r = self.rule(channel_key)
        return r.who if r else None

    def path(self, key: str) -> Path | None:
        return next((p for p in self.paths if p.key == key), None)

    def source(self, sid: str) -> Source | None:
        return next((s for s in self.sources if s.id == sid), None)

    def open_paths(self, requester: str, held=()) -> list[Path]:
        return [p for p in self.paths if p.open_to(requester, held)]

    def gate(self, requester: str, held=(), name: str = "this provider") -> Gate:
        """Which paths `requester` may take now; when none, why and what to do instead (the LE-only and
        instrument gates). A playbook without paths gates nothing."""
        open_ = tuple(self.open_paths(requester, held))
        if open_ or not self.paths or requester in OFFICIAL:
            return Gate(open=open_, le_only=False, needs=(), reason=None)
        listed = [p for p in self.paths if requester in p.requester]
        if not listed:
            return Gate(open=(), le_only=True, needs=(), reason=(
                f"{LE_ONLY_REASON}: {name} acts only on requests from law enforcement or a court, so no letter from "
                "us goes to it; brief the case officer with the pack (an LE cover letter to the case's LE "
                "authority)."))
        needs = tuple(dict.fromkeys(p.instrument.type for p in listed))
        what = " or ".join(INSTRUMENTS[t] for t in needs)
        return Gate(open=(), le_only=False, needs=needs, reason=(
            f"{name} needs {what}, which only law enforcement or counsel can supply: brief them with the pack."))

    def acts_on(self, jurisdiction: str | None) -> bool | None:
        """Does the provider act on an authority / court of `jurisdiction` directly? None: the playbook does not
        say (no issuer_jurisdictions) or the jurisdiction is unknown."""
        code = jurisdiction_code(jurisdiction)
        if not self.issuer_jurisdictions or code is None:
            return None
        return code in self.issuer_jurisdictions or ("EU" in self.issuer_jurisdictions and code in EU)

    def route_for(self, jurisdiction: str | None) -> str | None:
        """"direct" (the provider acts on this jurisdiction's authorities), "cross_border" (it does not: MLAT, EIO,
        an EU freezing order to its EU entity's state, or counsel in its jurisdiction) or None (not stated)."""
        ok = self.acts_on(jurisdiction)
        return None if ok is None else ("direct" if ok else "cross_border")

    @staticmethod
    def _host_path(value: str | None, path: str = "") -> tuple[str, str]:
        v = (value or "").strip().lower()
        host = v.rpartition("@")[2] if "@" in v and "://" not in v else re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
        if "/" in host and not path:
            host, _, rest = host.partition("/")
            path = "/" + rest
        return _norm_host(host.split("/")[0].split(":")[0]), path

    def portal_for(self, value: str | None, path: str = "") -> VendorPortal | None:
        """The vendor portal (a Kodex tenant, …) an address / URL points to, or None."""
        host, path = self._host_path(value, path)
        return next((vp for vp in self.domains.vendor_portals if host == vp.host and _on_portal(path, vp.path_prefix)),
                    None)

    def domain_class(self, value: str | None, path: str = "") -> str | None:
        """own | sibling | vendor_portal | vendor_portal_le_only | None for an address, URL or host."""
        vp = self.portal_for(value, path)
        if vp is not None:
            return "vendor_portal_le_only" if vp.le_only else "vendor_portal"
        host, _ = self._host_path(value, path)
        if any(host == d or host.endswith("." + d) for d in self.domains.own):
            return "own"
        if any(host == s.domain or host.endswith("." + s.domain) for s in self.domains.sibling):
            return "sibling"
        return None

    def stale(self, days: int = 180, now: datetime | None = None) -> list[str]:
        """The claims (paths, channels, signals) last retrieved more than `days` ago: re-check them."""
        today = (now or datetime.now(tz=UTC)).date()
        out = []
        items = [(f"path {p.key}", p.prov) for p in self.paths] + [(f"channel {c.key}", c.prov) for c in self.channels]
        items += [(f"signal {s.phrase!r}", s.prov) for s in self.signals]
        for what, prov in items:
            if (today - _as_date(prov.retrieved_at)).days > days:
                out.append(what)
        return out


# --------------------------------------------------------------------------- gate helpers
def may_use(who: str | None, requester: str) -> bool:
    """May `requester` write to a channel of this `who`? le_only: LE / courts / regulators only; victim_or_rep:
    private parties only; any / counsel_with_order / unknown (None): yes."""
    if who == "le_only":
        return requester in OFFICIAL
    if who == "victim_or_rep":
        return requester in PRIVATE
    return True


def jurisdiction_code(text: str | None) -> str | None:
    """'USA' / 'Italy' / 'IT' → ISO code (a few common names; anything else → None)."""
    s = (text or "").strip()
    if not s:
        return None
    if _JUR.fullmatch(s) or s == "EU":
        return s
    return _JUR_NAMES.get(s.casefold())


def _as_date(s: str) -> date:
    m = _DATE.fullmatch(s)
    return date(int(m.group(1)), int(m.group(2)), int(m.group(3) or 1))


# --------------------------------------------------------------------------- parsing
def _only(d, allowed: set[str], where: str) -> dict:
    if not isinstance(d, dict):
        raise PlaybookError(f"{where}: an object is required")
    extra = sorted(set(d) - allowed)
    if extra:
        raise PlaybookError(f"{where}: unknown field(s) {', '.join(extra)}")
    return d


def _str(d: dict, k: str, where: str, *, required: bool = False, limit: int = 2000) -> str | None:
    v = d.get(k)
    if v is None:
        if required:
            raise PlaybookError(f"{where}: '{k}' is required")
        return None
    if not isinstance(v, str) or not v.strip():
        raise PlaybookError(f"{where}: '{k}' must be a non-empty string or null")
    if len(v) > limit:
        raise PlaybookError(f"{where}: '{k}' is longer than {limit} characters")
    if _PLACEHOLDER.match(v):
        raise PlaybookError(f"{where}: '{k}' is a placeholder ({v!r}); use null for 'to be confirmed'")
    return v.strip()


def _list(d: dict, k: str, where: str, vocab=None, *, required: bool = False) -> tuple:
    v = d.get(k)
    if v is None:
        if required:
            raise PlaybookError(f"{where}: '{k}' is required")
        return ()
    if not isinstance(v, list):
        raise PlaybookError(f"{where}: '{k}' must be a list")
    if required and not v:
        raise PlaybookError(f"{where}: '{k}' needs at least one value")
    for x in v:
        if not isinstance(x, str) or (vocab is not None and x not in vocab):
            raise PlaybookError(f"{where}: unknown {k} value {x!r}")
    if len(set(v)) != len(v):
        raise PlaybookError(f"{where}: duplicate {k} values")
    return tuple(v)


def _jur(v, where: str, *, allow_eu: bool = True) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str) or not (_JUR.fullmatch(v) or (allow_eu and v == "EU")):
        raise PlaybookError(f"{where}: jurisdiction {v!r} must be an ISO 3166 alpha-2 code (or EU) or null")
    return v


def _num(v, where: str):
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
        raise PlaybookError(f"{where}: a non-negative number or null is required")
    return v


def _date(v, where: str, *, month_only: bool = False) -> str:
    m = _DATE.fullmatch(v) if isinstance(v, str) else None
    if not m:
        raise PlaybookError(f"{where}: retrieved_at must be YYYY-MM-DD or YYYY-MM")
    if not 1 <= int(m.group(2)) <= 12:
        raise PlaybookError(f"{where}: retrieved_at has an invalid month")
    if month_only and m.group(3):
        raise PlaybookError(f"{where}: an observed fact carries the month only (YYYY-MM), never the day")
    try:
        when = _as_date(v)
    except ValueError:
        raise PlaybookError(f"{where}: retrieved_at is not a valid date") from None
    if when > date.today():
        raise PlaybookError(f"{where}: retrieved_at {v} is in the future")
    return v


PROV_FIELDS = {"source_ids", "basis", "confidence", "retrieved_at"}
ADDRESS_CHAINS = ("ethereum", "arbitrum", "base", "bsc", "polygon", "optimism", "tron", "bitcoin", "solana")
ADDRESS_KINDS = ("exchange_deposit", "exchange_hot_wallet", "swap_bridge", "issuer", "casino")
_WALLET = re.compile(r"0x[0-9a-fA-F]{40}|T[1-9A-HJ-NP-Za-km-z]{33}|(bc1|[13])[0-9A-Za-z]{25,62}|[1-9A-HJ-NP-Za-km-z]{32,44}")
_NOT_TEXT = PROV_FIELDS | {"key", "regex", "source_url"}


def _texts(d, key: str = "") -> list[tuple[str, str]]:
    """(field, string) of every string value in a claim, nested ones included (not its provenance, keys or regexes)."""
    if isinstance(d, str):
        return [(key, d)]
    if isinstance(d, dict):
        return [x for k, v in d.items() if k not in _NOT_TEXT for x in _texts(v, k)]
    if isinstance(d, (list, tuple)):
        return [x for v in d for x in _texts(v, key)]
    return []


def _prov(d: dict, where: str, sources: dict[str, Source], own: frozenset[str] = frozenset()) -> Prov:
    """A claim's provenance. `own`: the organisation's catalogued addresses (lower case), the only ones a basis O
    signal phrase may quote."""
    ids = _list(d, "source_ids", where, set(sources), required=True)
    basis, conf = d.get("basis"), d.get("confidence")
    if basis not in BASIS:
        raise PlaybookError(f"{where}: basis must be one of D, R, I, O")
    if conf not in CONFIDENCE:
        raise PlaybookError(f"{where}: confidence must be one of H, M, L")
    observed = any(sources[i].observed for i in ids)
    when = _date(d.get("retrieved_at"), where, month_only=observed or basis == "O")
    if basis == "O" and not observed:
        raise PlaybookError(f"{where}: a basis O claim cites an observed source (a reply we received)")
    if observed and basis != "O":
        raise PlaybookError(f"{where}: an observed source backs only a basis O claim")
    if basis == "O":
        key = d.get("key")
        if isinstance(key, str) and re.search(r"(?:19|20)\d{2}[-_.]?(?:0[1-9]|1[0-2])[-_.]?(?:0[1-9]|[12]\d|3[01])", key):
            raise PlaybookError(f"{where}: an observed fact's key names no day-level date")
        for k, v in _texts(d):  # every free-text field of the claim (notes, action, conflict, on_refusal, …)
            # a signal phrase may quote the provider's own published address (`own`: checked by the caller)
            addr = [a for a in _ADDR.findall(v) if not (k == "phrase" and a.lower() in own)]
            if _day_date(v) or addr:
                raise PlaybookError(f"{where}: an observed fact's {k} names no day-level date and no address")
    if all(_as_date(when) > _as_date(sources[i].retrieved_at) for i in ids):
        raise PlaybookError(f"{where}: retrieved_at {when} is later than every source it cites was retrieved")
    if basis == "I" and conf == "H":
        raise PlaybookError(f"{where}: an inferred claim (basis I) is never high confidence")
    return Prov(source_ids=ids, basis=basis, confidence=conf, retrieved_at=when)


def _forbidden(node, path="") -> list[str]:
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            if str(k).lower() in ("verified", "verified_by"):
                out.append(f"{path}.{k}".lstrip("."))
            out += _forbidden(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += _forbidden(v, f"{path}[{i}]")
    return out


def _sources(raw, where: str) -> dict[str, Source]:
    if not isinstance(raw, list) or not raw:
        raise PlaybookError(f"{where}: 'sources' needs at least one source")
    out: dict[str, Source] = {}
    for i, s in enumerate(raw):
        w = f"{where}.sources[{i}]"
        _only(s, {"id", "title", "url", "retrieved_at", "observed"}, w)
        sid = s.get("id")
        if not isinstance(sid, str) or not _KEY.fullmatch(sid):
            raise PlaybookError(f"{w}: invalid source id {sid!r}")
        if sid in out:
            raise PlaybookError(f"{w}: duplicate source id {sid!r}")
        title = _str(s, "title", w, required=True, limit=300)
        observed = s.get("observed", False)
        if not isinstance(observed, bool):
            raise PlaybookError(f"{w}: 'observed' must be true or false")
        url = s.get("url")
        if observed:
            if url is not None:
                raise PlaybookError(f"{w}: an observed source (a reply we received) has no URL")
            if _day_date(title) or _ADDR.search(title):
                raise PlaybookError(f"{w}: an observed source's title names no day-level date and no address")
            when = _date(s.get("retrieved_at"), w, month_only=True)
        else:
            if not (isinstance(url, str) and url.startswith("https://") and len(url) <= 1000 and " " not in url):
                raise PlaybookError(f"{w}: a source needs an https:// url")
            when = _date(s.get("retrieved_at"), w)
        out[sid] = Source(id=sid, title=title, url=url, retrieved_at=when, observed=observed)
    return out


def _instrument(raw, where: str) -> Instrument:
    if raw is None:
        raise PlaybookError(f"{where}: 'instrument' is required (type 'none' when there is none)")
    _only(raw, {"type", "issuer_jurisdictions", "signing", "language", "notes"}, where)
    t = raw.get("type")
    if t not in INSTRUMENTS:
        raise PlaybookError(f"{where}: unknown instrument type {t!r}")
    jurs = tuple(_jur(j, where) for j in _list(raw, "issuer_jurisdictions", where))
    signing = raw.get("signing", "any")
    if signing not in SIGNING:
        raise PlaybookError(f"{where}: signing must be one of {', '.join(SIGNING)}")
    langs = _list(raw, "language", where)
    if any(not re.fullmatch(r"[a-z]{2}", x) for x in langs):
        raise PlaybookError(f"{where}: language codes are ISO 639-1 (e.g. en)")
    return Instrument(type=t, issuer_jurisdictions=jurs, signing=signing, language=langs,
                      notes=_str(raw, "notes", where))


def _timing(raw, where: str, sources) -> Timing:
    if raw is None:
        return Timing()
    _only(raw, {*TIMING_KEYS, "deadlines"}, where)
    vals = {k: _num(raw.get(k), f"{where}.{k}") for k in TIMING_KEYS}
    deadlines, keys = [], set()
    for i, d in enumerate(raw.get("deadlines") or []):
        w = f"{where}.deadlines[{i}]"
        _only(d, {"key", "what", *UNITS, "starts", "by", "action", *PROV_FIELDS}, w)
        key = d.get("key")
        if not isinstance(key, str) or not _KEY.fullmatch(key) or key in keys:
            raise PlaybookError(f"{w}: a deadline needs a unique key")
        keys.add(key)
        if d.get("what") not in DEADLINE_WHAT:
            raise PlaybookError(f"{w}: what must be one of {', '.join(DEADLINE_WHAT)}")
        units = [u for u in UNITS if d.get(u) is not None]
        if len(units) != 1:
            raise PlaybookError(f"{w}: exactly one of {', '.join(UNITS)} is required")
        amount = _num(d[units[0]], w)
        if not amount:
            raise PlaybookError(f"{w}: the deadline must be longer than zero")
        if d.get("starts") not in CLOCK_STARTS:
            raise PlaybookError(f"{w}: starts (what starts the clock) must be one of {', '.join(CLOCK_STARTS)}")
        by = d.get("by")
        if by is not None and by not in REQUESTERS:
            raise PlaybookError(f"{w}: by must be a requester ({', '.join(REQUESTERS)}) or null")
        deadlines.append(Deadline(key=key, what=d["what"], unit=units[0], amount=amount, starts=d["starts"], by=by,
                                  action=_str(d, "action", w, limit=500), prov=_prov(d, w, sources)))
    return Timing(**vals, deadlines=tuple(deadlines))


def _domains(raw, where: str, sources, entity_keys) -> Domains:
    if raw is None:
        return Domains()
    _only(raw, {"own", "sibling", "vendor_portals"}, where)
    own = _list(raw, "own", where)
    for d in own:
        if not _DOMAIN.fullmatch(d):
            raise PlaybookError(f"{where}: invalid domain {d!r} (lower-case, no scheme)")
    sib = []
    for i, s in enumerate(raw.get("sibling") or []):
        w = f"{where}.sibling[{i}]"
        _only(s, {"domain", "entity", "purpose", *PROV_FIELDS}, w)
        if not isinstance(s.get("domain"), str) or not _DOMAIN.fullmatch(s["domain"]):
            raise PlaybookError(f"{w}: invalid domain")
        if s.get("entity") is not None and s["entity"] not in entity_keys:
            raise PlaybookError(f"{w}: unknown entity {s['entity']!r}")
        sib.append(Sibling(domain=s["domain"], entity=s.get("entity"), purpose=_str(s, "purpose", w, limit=200),
                           prov=_prov(s, w, sources)))
    vps = []
    for i, v in enumerate(raw.get("vendor_portals") or []):
        w = f"{where}.vendor_portals[{i}]"
        _only(v, {"host", "path_prefix", "tenant", "le_only", *PROV_FIELDS}, w)
        if not isinstance(v.get("host"), str) or not _DOMAIN.fullmatch(v["host"]):
            raise PlaybookError(f"{w}: invalid host")
        prefix = v.get("path_prefix", "/")
        if not isinstance(prefix, str) or not prefix.startswith("/"):
            raise PlaybookError(f"{w}: path_prefix must start with '/'")
        if not isinstance(v.get("le_only", False), bool):
            raise PlaybookError(f"{w}: le_only must be true or false")
        vps.append(VendorPortal(host=v["host"], path_prefix=prefix, tenant=_str(v, "tenant", w, limit=64),
                                le_only=bool(v.get("le_only", False)), prov=_prov(v, w, sources)))
    return Domains(own=own, sibling=tuple(sib), vendor_portals=tuple(vps))


CHANNEL_FIELDS = {"key", "kind", "value", "purpose", "role_default", "label", "notes", "source_url", "who",
                  *PROV_FIELDS}


LE_REQUEST_WHO = frozenset({"le_only", "counsel_with_order"})  # an LE request channel is never open to "anyone"


def _norm_path(path: str | None) -> str:
    """A URL path as compared: percent-decoded, repeated slashes collapsed, dot segments resolved ("//binance/x",
    "/%62inance/x" and "/./binance/x" are "/binance/x"), the trailing slash kept."""
    from posixpath import normpath
    from urllib.parse import unquote

    p = unquote(path or "/")
    p = "/" + p.lstrip("/")
    out = normpath(p)
    out = "/" + out.lstrip("/")  # normpath keeps a leading "//"
    return out + "/" if p.endswith("/") and out != "/" else out


def _on_portal(path: str | None, prefix: str) -> bool:
    """`path` is under the portal's `prefix`, case-insensitive, with or without its trailing slash."""
    p, pre = _norm_path(path).lower(), (prefix or "/").lower()
    return p.startswith(pre) or (pre.rstrip("/") != "" and p == pre.rstrip("/"))


def _norm_host(host: str) -> str:
    """A host as compared: lower case, no trailing dot (an FQDN), no www., IDNA (punycode) for a non-ASCII name."""
    h = host.strip().lower().rstrip(".").removeprefix("www.")
    try:
        return h.encode("idna").decode("ascii") if not h.isascii() else h
    except UnicodeError:
        return h


def _portal_value(domains: Domains, value) -> VendorPortal | None:
    """The vendor portal (a Kodex tenant, …) a channel's URL sits on, or None."""
    if not isinstance(value, str):
        return None
    u = urlsplit(value.strip())
    host = _norm_host(u.hostname or "")
    return next((v for v in domains.vendor_portals if host == v.host and _on_portal(u.path, v.path_prefix)), None)


def _check_who(domains: Domains, w: str, who: str, purpose: str | None, value) -> None:
    """The LE-only gate is only as good as the data: a channel on an LE-only vendor portal is le_only, and an
    le_request channel is le_only or counsel_with_order (it acts only on LE process / an order)."""
    vp = _portal_value(domains, value)
    if vp is not None and vp.le_only and who != "le_only":
        raise PlaybookError(f"{w}: {vp.host}{vp.path_prefix} is an LE-only vendor portal: the channel's who must be "
                            "le_only")
    if vp is not None and who == "le_only" and not vp.le_only:
        raise PlaybookError(f"{w}: vendor portal {vp.host}{vp.path_prefix} serves an LE-only channel: mark it le_only")
    if purpose == "le_request" and who not in LE_REQUEST_WHO:
        raise PlaybookError(f"{w}: an le_request channel is le_only or counsel_with_order, not {who!r}")


def parse(data: dict, *, org_channels: dict[str, str] | None = None, all_channel_keys=frozenset(),
          where: str | None = None, org_values: dict[str, str | None] | None = None) -> tuple[Playbook, list[dict]]:
    """Validate one playbook file (module doc). `org_channels`: the organisation's channels.json channels
    {key: purpose}; `org_values`: their values {key: URL / address} (a channel on an LE-only vendor portal is
    le_only); `all_channel_keys`: every catalogue channel key (declared keys must be new). Returns the
    playbook and the declared channels (raw dicts without the playbook-only fields, for the catalogue's own
    channel validation). Raises PlaybookError."""
    org_channels = dict(org_channels or {})
    org_values = dict(org_values or {})
    w0 = where or "playbook"
    _only(data, {"key", "version", "side", "jurisdiction", "issuer_jurisdictions", "ground_truth", "notes", "le_role",
                 "entities", "domains", "channels", "channels_ext", "paths", "reply_signals", "tickets", "issues",
                 "addresses", "sources", "_comment"}, w0)
    bad = _forbidden(data)
    if bad:
        raise PlaybookError(f"{w0}: verification state never lives in the catalogue: {', '.join(bad[:5])}")
    key = data.get("key")
    if not isinstance(key, str) or not _ORG_KEY.fullmatch(key):
        raise PlaybookError(f"{w0}: invalid organisation key {key!r}")
    if data.get("version") != VERSION:
        raise PlaybookError(f"{w0}: version must be {VERSION}")
    side = data.get("side")
    if side not in SIDES:
        raise PlaybookError(f"{w0}: side must be provider or le")
    gt = data.get("ground_truth", "reply")
    if gt not in GROUND_TRUTH:
        raise PlaybookError(f"{w0}: ground_truth must be reply or onchain")
    sources = _sources(data.get("sources"), w0)
    entities, ekeys = [], set()
    for i, e in enumerate(data.get("entities") or []):
        w = f"{w0}.entities[{i}]"
        _only(e, {"key", "name", "jurisdiction", "separate", "notes", "source_ids"}, w)
        if not isinstance(e.get("key"), str) or not _KEY.fullmatch(e["key"]) or e["key"] in ekeys:
            raise PlaybookError(f"{w}: an entity needs a unique key")
        ekeys.add(e["key"])
        eids = _list(e, "source_ids", w, set(sources), required=True)
        if any(sources[s].observed for s in eids) and any(_day_date(v) or _ADDR.search(v)
                                                          for _k, v in _texts(e)):
            raise PlaybookError(f"{w}: an entity citing an observed source names no day-level date and no address")
        entities.append(Entity(key=e["key"], name=_str(e, "name", w, required=True, limit=255),
                               jurisdiction=_jur(e.get("jurisdiction"), w, allow_eu=False),
                               separate=bool(e.get("separate", False)), notes=_str(e, "notes", w),
                               source_ids=eids))
    domains = _domains(data.get("domains"), f"{w0}.domains", sources, ekeys)
    rules: dict[str, ChannelRule] = {}
    declared: list[dict] = []
    for i, c in enumerate(data.get("channels") or []):
        w = f"{w0}.channels[{i}]"
        _only(c, CHANNEL_FIELDS, w)
        ck = c.get("key")
        if not isinstance(ck, str) or not ck.startswith(f"{key}.") or len(ck) > 128:
            raise PlaybookError(f"{w}: a declared channel key starts with '{key}.'")
        if ck in all_channel_keys or ck in org_channels:
            raise PlaybookError(f"{w}: channel {ck!r} already exists in channels.json (use channels_ext)")
        if c.get("who") not in WHO:
            raise PlaybookError(f"{w}: who must be one of {', '.join(WHO)}")
        if c.get("value") is not None and (not isinstance(c["value"], str) or _PLACEHOLDER.match(c["value"])):
            raise PlaybookError(f"{w}: the value must be a real value or null ('to be confirmed')")
        if c.get("kind") == "email" and c.get("value"):
            dom = c["value"].rpartition("@")[2].lower()
            src = str(c.get("source_url") or "")
            if domains.own and not any(dom == d or dom.endswith("." + d) for d in
                                       [*domains.own, *(s.domain for s in domains.sibling)]):
                raise PlaybookError(f"{w}: an e-mail value must be on one of the organisation's own domains")
            if not any(re.match(rf"https://([a-z0-9-]+\.)*{re.escape(d)}(/|$)", src) for d in
                       [*domains.own, *(s.domain for s in domains.sibling)]):
                raise PlaybookError(f"{w}: an e-mail value needs a source_url on the organisation's own site")
        prov = _prov(c, w, sources)
        purpose = c.get("purpose", "general")
        _check_who(domains, w, c["who"], purpose, c.get("value"))
        rules[ck] = ChannelRule(key=ck, who=c["who"], purpose=purpose, notes=_str(c, "notes", w), declared=True,
                                prov=prov)
        declared.append({k: v for k, v in c.items() if k not in {"who", *PROV_FIELDS}})
        org_channels[ck] = purpose
    ext = data.get("channels_ext") or {}
    if not isinstance(ext, dict):
        raise PlaybookError(f"{w0}: channels_ext must be an object keyed by channel key")
    for ck, c in ext.items():
        w = f"{w0}.channels_ext[{ck}]"
        _only(c, {"who", "purpose", "notes", *PROV_FIELDS}, w)
        if ck not in org_channels or ck in rules:
            raise PlaybookError(f"{w}: no channel {ck!r} of {key} in channels.json (declare it under 'channels')")
        if c.get("who") not in WHO:
            raise PlaybookError(f"{w}: who must be one of {', '.join(WHO)}")
        purpose = c.get("purpose")
        if purpose is not None and purpose not in PURPOSES:
            raise PlaybookError(f"{w}: unknown purpose {purpose!r}")
        if org_channels.get(ck) == "le_request" and purpose not in (None, "le_request"):
            raise PlaybookError(f"{w}: an le_request channel of channels.json keeps its purpose (LE only)")
        _check_who(domains, w, c["who"], purpose or org_channels.get(ck), org_values.get(ck))
        rules[ck] = ChannelRule(key=ck, who=c["who"], purpose=purpose, notes=_str(c, "notes", w), declared=False,
                                prov=_prov(c, w, sources))
        if purpose:
            org_channels[ck] = purpose
    for ck, purpose in org_channels.items():
        if purpose == "le_request" and ck not in rules:
            raise PlaybookError(f"{w0}: le_request channel {ck!r} needs a 'who' (channels_ext)")
    for ck, value in org_values.items():  # a channels.json channel on an LE-only portal is never offered to anyone
        vp = _portal_value(domains, value)
        if vp is not None and vp.le_only and (ck not in rules or rules[ck].who != "le_only"):
            raise PlaybookError(f"{w0}: channel {ck!r} is on the LE-only vendor portal {vp.host}{vp.path_prefix}: its "
                                "who must be le_only (channels_ext)")
    paths: list[Path] = []
    raw_paths = data.get("paths") or []
    path_keys = [p.get("key") for p in raw_paths if isinstance(p, dict)]
    for i, p in enumerate(raw_paths):
        w = f"{w0}.paths[{i}]"
        _only(p, {"key", "kind", "requester", "entity", "channel_keys", "instrument", "evidence", "produces", "timing",
                  "expected_replies", "outcomes", "on_refusal", "conflict", "notes", *PROV_FIELDS}, w)
        pk = p.get("key")
        if not isinstance(pk, str) or not _KEY.fullmatch(pk) or path_keys.count(pk) != 1:
            raise PlaybookError(f"{w}: a path needs a unique key")
        w = f"{w0}.paths[{pk}]"
        kind = p.get("kind")
        if kind not in PATH_KINDS:
            raise PlaybookError(f"{w}: unknown kind {kind!r} ({', '.join(PATH_KINDS)})")
        req = _list(p, "requester", w, REQUESTERS, required=True)
        chans = _list(p, "channel_keys", w)
        for ck in chans:
            if ck not in org_channels:
                raise PlaybookError(f"{w}: unknown channel {ck!r} (not in channels.json for {key} nor declared)")
        if p.get("entity") is not None and p["entity"] not in ekeys:
            raise PlaybookError(f"{w}: unknown entity {p['entity']!r}")
        inst = _instrument(p.get("instrument"), f"{w}.instrument")
        if kind in ("private_notice", "victim_report"):
            if set(req) - PRIVATE:
                raise PlaybookError(f"{w}: a {kind} path is for private requesters only")
            if inst.binding:
                raise PlaybookError(f"{w}: a {kind} path takes no binding instrument")
        if kind == "le_request" and (set(req) & PRIVATE or "le" not in req):
            raise PlaybookError(f"{w}: an le_request path is for law enforcement only")
        if set(req) & PRIVATE and any(rules.get(ck) and rules[ck].who == "le_only" for ck in chans):
            raise PlaybookError(f"{w}: a path open to private requesters cannot use an le_only channel")
        if kind in ("le_request", "court_order", "cross_border") and not set(req) & PRIVATE and any(
                rules.get(ck) and rules[ck].who == "victim_or_rep" for ck in chans):
            raise PlaybookError(f"{w}: a path for official requesters cannot use a victim_or_rep channel (the brief "
                                "would send the officer to the victims' intake)")
        if kind in ("private_notice", "victim_report") and {*_list(p, "outcomes", w, REPLY_MEANS),
                                                            *_list(p, "expected_replies", w, REPLY_MEANS)} & {
                "frozen", "funds_returned"}:
            raise PlaybookError(f"{w}: a {kind} path leads at most to a hold (hold_placed), never frozen / returned")
        refusal = p.get("on_refusal")
        if refusal is not None and (refusal not in path_keys or refusal == pk):
            raise PlaybookError(f"{w}: on_refusal must name another path of this playbook")
        paths.append(Path(
            key=pk, kind=kind, requester=req, instrument=inst, prov=_prov(p, w, sources), entity=p.get("entity"),
            channel_keys=chans, evidence=_list(p, "evidence", w, EVIDENCE), produces=_list(p, "produces", w, EVIDENCE),
            timing=_timing(p.get("timing"), f"{w}.timing", sources),
            expected_replies=_list(p, "expected_replies", w, REPLY_MEANS),
            outcomes=_list(p, "outcomes", w, REPLY_MEANS), on_refusal=refusal, conflict=_str(p, "conflict", w),
            notes=_str(p, "notes", w)))
    signals = []
    for i, s in enumerate(data.get("reply_signals") or []):
        w = f"{w0}.reply_signals[{i}]"
        _only(s, {"phrase", "means", "instrument", "channel_key", "path", *PROV_FIELDS}, w)
        phrase = _str(s, "phrase", w, required=True, limit=200)
        if s.get("means") not in REPLY_MEANS:
            raise PlaybookError(f"{w}: means must be a reply status ({', '.join(REPLY_MEANS)})")
        if s.get("instrument") is not None and s["instrument"] not in INSTRUMENTS:
            raise PlaybookError(f"{w}: unknown instrument {s['instrument']!r}")
        if s.get("channel_key") is not None and s["channel_key"] not in org_channels:
            raise PlaybookError(f"{w}: unknown channel {s['channel_key']!r}")
        if s.get("path") is not None and s["path"] not in path_keys:
            raise PlaybookError(f"{w}: unknown path {s['path']!r}")
        if s.get("means") in ("frozen", "funds_returned") and s.get("path") is not None and next(
                (x.kind for x in paths if x.key == s["path"]), None) in ("private_notice", "victim_report"):
            raise PlaybookError(f"{w}: a private path's reply means at most hold_placed, never {s['means']}")
        own = frozenset(str(v).strip().lower() for v in [*org_values.values(), *(c.get("value") for c in declared)]
                        if isinstance(v, str) and "@" in v)
        signals.append(Signal(phrase=phrase, means=s["means"], prov=_prov(s, w, sources, own),
                              instrument=s.get("instrument"),
                              channel_key=s.get("channel_key"), path=s.get("path")))
    tickets = []
    for i, t in enumerate(data.get("tickets") or []):
        w = f"{w0}.tickets[{i}]"
        _only(t, {"system", "regex", *PROV_FIELDS}, w)
        if not isinstance(t.get("system"), str) or not _KEY.fullmatch(t["system"]):
            raise PlaybookError(f"{w}: a ticket format needs a system key")
        rx = t.get("regex")
        if rx is not None:
            if not isinstance(rx, str) or len(rx) > 200:
                raise PlaybookError(f"{w}: regex must be a string (≤ 200 characters) or null")
            try:
                re.compile(rx)
            except re.error:
                raise PlaybookError(f"{w}: the regex does not compile") from None
        tickets.append(TicketFormat(system=t["system"], regex=rx, prov=_prov(t, w, sources)))
    issues = []
    le_role = data.get("le_role")
    if le_role is not None and (side != "le" or le_role not in LE_ROLES):
        raise PlaybookError(f"{w0}: le_role is for side 'le' only, one of {', '.join(LE_ROLES)}")
    if data.get("issues") and side != "le":
        raise PlaybookError(f"{w0}: 'issues' (instruments an authority can produce) is for side 'le' only")
    for i, s in enumerate(data.get("issues") or []):
        w = f"{w0}.issues[{i}]"
        _only(s, {"instrument", "jurisdiction", "by", "to", "notes", *PROV_FIELDS}, w)
        if s.get("instrument") not in INSTRUMENTS or s["instrument"] == "none":
            raise PlaybookError(f"{w}: unknown instrument {s.get('instrument')!r}")
        to = _list(s, "to", w)
        if any(not _ORG_KEY.fullmatch(x) for x in to):
            raise PlaybookError(f"{w}: 'to' lists organisation keys")
        issues.append(Issue(instrument=s["instrument"], jurisdiction=_jur(s.get("jurisdiction"), w),
                            by=_str(s, "by", w, limit=300), to=to, notes=_str(s, "notes", w), prov=_prov(s, w, sources)))
    addresses = []
    if data.get("addresses") and side != "provider":
        raise PlaybookError(f"{w0}: 'addresses' (an organisation's own wallets) is for side 'provider' only")
    for i, s in enumerate(data.get("addresses") or []):
        w = f"{w0}.addresses[{i}]"
        _only(s, {"chain", "address", "kind", "label", *PROV_FIELDS}, w)
        chain, addr = s.get("chain"), s.get("address")
        if chain not in ADDRESS_CHAINS or not isinstance(addr, str) or not _WALLET.fullmatch(addr.strip()):
            raise PlaybookError(f"{w}: a known address needs a chain ({', '.join(ADDRESS_CHAINS)}) and a wallet address")
        if s.get("kind") not in ADDRESS_KINDS:
            raise PlaybookError(f"{w}: kind must be one of {', '.join(ADDRESS_KINDS)}")
        prov = _prov(s, w, sources)
        if prov.basis == "O":
            raise PlaybookError(f"{w}: a known address is never an observed fact (an address seen in a reply is case data)")
        addr = addr.strip()
        addresses.append(KnownAddress(chain=chain, address=addr_key(chain, addr),
                                      kind=s["kind"], label=_str(s, "label", w, limit=255), prov=prov))
    pb = Playbook(
        key=key, side=side, sources=tuple(sources.values()), jurisdiction=_jur(data.get("jurisdiction"), w0),
        issuer_jurisdictions=tuple(_jur(j, w0) for j in _list(data, "issuer_jurisdictions", w0)), ground_truth=gt,
        notes=_str(data, "notes", w0, limit=4000), entities=tuple(entities), domains=domains,
        channels=tuple(rules.values()), paths=tuple(paths), signals=tuple(signals), tickets=tuple(tickets),
        issues=tuple(issues), le_role=le_role, addresses=tuple(addresses))
    return pb, declared
