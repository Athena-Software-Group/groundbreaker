"""Authorities & stop-order desk: the counterparties a case has engaged, their communications
timeline, form letters, stop-order status changes and response-overdue checks.

Owner: the authorities feature (web layer: app/web/routes_authorities.py).

* **Authority.** One counterparty on the stop-order side: an `Entity` (VASP, swap service,
  infrastructure provider, stablecoin issuer, PI firm, counsel, regulator, or a law-enforcement
  agency recorded as an entity), keyed ``entity-<id>``; a case `LEContact` that has no entity,
  keyed ``le-<id>`` (typed by its role: an LE contact that is really a PI firm or counsel is not
  "law enforcement"); a complaint authority from `case.facts["complaints"]` with no LE contact,
  keyed ``complaint-<n>``; or a PI firm from `case.facts["investigator"]` / `other_investigators`
  with no entity, keyed ``pi-<n>``. `case_authorities()` lists the UNION of every counterparty the
  case has engaged (stop orders, correspondence, LE contacts, complaints, the PI firm: always,
  whatever the latest trace shows) and the ones the latest trace touches (freeze candidates, other
  services carrying taint, the infrastructure providers in `case.facts`). `Authority.trace_label`
  marks each entity "in latest trace" or "engaged earlier" (engaged, but not reached by the latest
  run). A stop order to a counterparty the latest run no longer reaches is built from the newest
  earlier run that lists it as a freeze candidate (`letter_run`).
* **Timeline.** Correspondence rows of the authority plus its stop orders that have no
  correspondence row of their own (generated drafts, imported letters loaded without one), in
  chronological order.
* **Form letters.** `generate_letter()` renders `app/reports/templates/letters/<key>.md.j2` (or, for
  a stop order, the existing freeze-candidate generator) into a *draft* correspondence row (plus a
  stop-order row for the stop-order kind). Drafts stay editable until `mark_sent()`. The LE brief / counsel brief
  (`le_brief`, `counsel_brief`) is about one provider request (`ref`: its block-status key): `meta.follow_up_of`
  links it, and once sent the request reads "LE briefed" (app.blocks.status).
* **Status.** `record_stop_order_status()` moves a stop order to acknowledged / frozen / declined /
  released (with the amount held), logs a correspondence entry and emits `stop_order_status`.
* **Overdue.** A sent letter is due a reply by `response_due_at` (default: sent + 7 days).
  `check_overdue(db, case)` emits `response_overdue` once per due date, then the block requests' clocks
  (app.blocks.status.check_clocks); the notifications feature schedules it.

Nothing here writes the audit log: the routes call `app.core.audit.audit` after each change.
Event titles and bodies carry no PII and no counterparty names (case ref, ids, amounts only).
"""

from __future__ import annotations

import hashlib
import logging
import re
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, object_session

from app import services
from app.core import events
from app.db.models import (
    Address,
    Case,
    Classification,
    Correspondence,
    CorrespondenceChannel,
    CorrespondenceDirection,
    CorrespondenceKind,
    CorrespondenceStatus,
    Entity,
    EntityCategory,
    EvidenceItem,
    LEContact,
    SeedRole,
    StopOrder,
    StopOrderOrigin,
    StopOrderStatus,
    TraceNode,
    TraceRun,
    User,
)
from app.providers.prices import to_usd
from app.reports.stop_orders import (
    DEFAULT_RECORDS,
    RECORDS_BY_CATEGORY,
    SWAP_ORDER_REF,
    _fmt_amt,
    _fmt_usd,
    markdown_to_docx,
    md_escape,
    render_letter,
    verified_addresses,
)
from app.tracing.freeze import FreezeCandidate, freeze_candidates

log = logging.getLogger(__name__)

DEFAULT_RESPONSE_DAYS = 7
RELEASED = "released"  # StopOrderStatus.RELEASED (migration 0004); also kept as identifiers.hold.state
STATUS_CHOICES = ("acknowledged", "frozen", "declined", RELEASED)  # the authority page's status form
ALL_STATUSES = tuple(s.value for s in StopOrderStatus) + ((RELEASED,) if RELEASED not in
                                                           {s.value for s in StopOrderStatus} else ())
CLOSED_STATES = {"declined", "superseded", RELEASED}
LE_CATEGORIES = {EntityCategory.LAW_ENFORCEMENT, EntityCategory.REGULATOR}
ADVISER_CATEGORIES = {EntityCategory.PI_FIRM, EntityCategory.LEGAL_COUNSEL}
LE_CATEGORY_VALUES = {c.value for c in LE_CATEGORIES}
ADVISER_CATEGORY_VALUES = {c.value for c in ADVISER_CATEGORIES}
KEY_RE = re.compile(r"(entity|le|complaint|pi)-\d{1,12}")
VIRTUAL_PREFIXES = ("complaint-", "pi-")  # authorities with neither an entity nor an LE contact row
OFF_CHAIN_CATEGORIES = {"hosting", "infra"}  # infrastructure providers: never on a trace, so no trace label
MAX_EARLIER_RUNS = 10  # letter_run looks this far back for a freeze candidate

TYPE_LABELS = {
    "exchange": "VASP · exchange", "casino": "VASP · casino", "otc": "VASP · OTC desk",
    "swap_service": "Swap service", "bridge": "Bridge", "dex": "DEX / router (non-custodial)", "mixer": "Mixer",
    "hosting": "Infrastructure · hosting", "infra": "Infrastructure provider", "stablecoin_issuer": "Stablecoin issuer",
    "law_enforcement": "Law enforcement", "pi_firm": "PI firm", "legal_counsel": "Legal counsel",
    "regulator": "Regulator", "unknown": "Other",
}
ORDER_KIND_PHRASE = {
    "freeze": "an urgent preservation and risk-control (freeze) request",
    "preservation": "an urgent preservation request",
    "issuer_blacklist": "a request to blacklist the address(es) concerned",
    "info_request": "an information request",
}
KIND_LABELS = {
    "stop_order": "Stop order", "status_request": "Status request", "info_request": "Information request",
    "le_cover": "LE cover letter", "release_request": "Release request", "reply": "Reply", "other": "Message",
}
DIRECTION_LABELS = {"in": "Inbound", "out": "Outbound", "note": "Note"}


class DeskError(ValueError):
    """A desk action that cannot be done in the current state (shown to the user, HTTP 400/409)."""


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _aware(v: datetime | None) -> datetime | None:
    return v.replace(tzinfo=UTC) if v is not None and v.tzinfo is None else v


def _fmt_day(v: datetime | None) -> str:
    return _aware(v).astimezone(UTC).strftime("%d.%m.%Y") if v else "—"


def _cat(entity: Entity | None) -> str:
    if entity is None:
        return "law_enforcement"
    return entity.category.value if isinstance(entity.category, EntityCategory) else str(entity.category)


def _kw(text: str, words: tuple[str, ...]) -> bool:
    return any(re.search(rf"(?<![a-z0-9]){re.escape(w)}", text) for w in words)


_LE_WORDS = ("police", "polizia", "polizei", "carabinieri", "gendarm", "fbi", "ic3", "internet crime", "prosecut",
             "procura", "staatsanw", "europol", "interpol", "fedpol", "questura", "guardia di finanza",
             "law enforcement", "cybercrime", "officer", "detective", "investigating unit", "court", "tribunal",
             "secret service", "usss", "federal bureau of investigation", "homeland security", "department of justice",
             "u.s. attorney", "us attorney", "united states attorney", "attorney general", "district attorney",
             "state attorney", "state's attorney", "sheriff", "u.s. marshal", "us marshals", "special agent",
             "task force officer", "irs criminal investigation", "irs-ci", "drug enforcement", "postal inspection")
_LE_ABBR = re.compile(r"(?<![a-z0-9])(?:hsi|doj|usao|dea|atf|nypd|lapd|ncis|irs ci|da's office|ag's office)(?![a-z0-9])")
_REGULATOR_WORDS = ("regulator", "supervisory", "finma", "consob", "bafin", "fca", "securities and exchange")
_COUNSEL_WORDS = ("counsel", "lawyer", "law firm", "attorney", "solicitor", "barrister", "avvocat", "rechtsanw",
                  "legal")
_PI_WORDS = ("pi firm", "private investigat", "investigations", "investigator", "intelligence firm", "forensic")
# LE titles that themselves contain a counsel word: only these turn a role with a counsel word into LE ("Assistant U.S.
# Attorney"); "officer" / "court" / "special agent" never do ("Court-appointed counsel", "Chief Legal Officer")
_LE_COUNSEL_TITLES = ("district attorney", "u.s. attorney", "us attorney", "united states attorney", "attorney general",
                      "state's attorney", "state attorney")
_FORMER = re.compile(r"(?<![a-z0-9])(?:former|ex-|retired)\s*[^,;/()]*")


def contact_category(le: LEContact, entity: Entity | None = None) -> str:
    """What an LE contact really is: its entity's category when it has one, else read from its
    agency name and role (a PI firm or a lawyer recorded as a contact is not law enforcement;
    an agency nothing identifies is 'unknown')."""
    if entity is None and le.entity_id:
        session = object_session(le)
        entity = session.get(Entity, le.entity_id) if session is not None else None
    if entity is not None:
        return _cat(entity)
    agency, role = (le.agency or "").lower().replace("\u2019", "'"), (le.role or "").lower()
    # the agency's own name first: "U.S. Attorney's Office" and "Homeland Security Investigations" are LE, whatever
    # "attorney" / "investigations" would say on their own
    if _kw(agency, _LE_WORDS) or _LE_ABBR.search(agency):
        return "law_enforcement"
    now = _FORMER.sub(" ", role)  # "Partner, former U.S. Attorney": what the person is now
    for words, cat, le_words in ((_REGULATOR_WORDS, "regulator", _LE_WORDS), (_COUNSEL_WORDS, "legal_counsel",
                                  _LE_COUNSEL_TITLES), (_PI_WORDS, "pi_firm", _LE_WORDS)):
        if _kw(agency, words) or _kw(role, words) and not _kw(now, le_words):
            return cat
    return "law_enforcement" if _kw(now, _LE_WORDS) or _LE_ABBR.search(now) else "unknown"


def is_non_custodial(entity: Entity | None) -> bool:
    """Routers / AMMs (and mixers) hold no accounts or balances: never the target of a freeze letter."""
    if entity is None:
        return False
    return (entity.category == EntityCategory.DEX and not entity.freeze_capable) or entity.category == EntityCategory.MIXER


# --------------------------------------------------------------------------- stop-order state
def hold_state(order: StopOrder) -> dict:
    return dict((order.identifiers or {}).get("hold") or {})


def order_state(order: StopOrder) -> str:
    """The stop order's status, with `released` (recorded as the hold state until the status enum
    has the member) taking precedence."""
    if hold_state(order).get("state") == RELEASED:
        return RELEASED
    return order.status.value


def order_open(order: StopOrder) -> bool:
    return order_state(order) not in CLOSED_STATES


def response_due(order: StopOrder, default_days: int | None = None) -> datetime | None:
    """When a reply to a sent stop order is due: response_due_at, else sent_at + default_days (7)."""
    if order.sent_at is None:
        return None
    days = DEFAULT_RESPONSE_DAYS if default_days is None else default_days
    return _aware(order.response_due_at) or _aware(order.sent_at) + timedelta(days=days)


def awaiting_response(order: StopOrder) -> bool:
    return order.status == StopOrderStatus.SENT and order.responded_at is None and order.sent_at is not None


# --------------------------------------------------------------------------- authorities
@dataclass
class Authority:
    key: str  # "entity-<id>" | "le-<id>" | "complaint-<n>" | "pi-<n>"
    name: str
    category: str
    entity: Entity | None = None
    le_contacts: list[LEContact] = field(default_factory=list)
    correspondence: list[Correspondence] = field(default_factory=list)
    stop_orders: list[StopOrder] = field(default_factory=list)
    candidate: FreezeCandidate | None = None
    in_trace: bool = False  # the latest run reaches it (a freeze candidate or an address carrying taint)
    trace_checked: bool = False  # case_authorities looked at the latest run (include_prospects)
    run: TraceRun | None = None  # that latest run
    candidate_run: TraceRun | None = None  # the run `candidate` comes from (latest, or earlier: letter_run)
    contact: dict = field(default_factory=dict)  # complaint / PI-firm facts of a virtual authority

    @property
    def type_label(self) -> str:
        return TYPE_LABELS.get(self.category, self.category.replace("_", " "))

    @property
    def virtual(self) -> bool:
        """Listed from case.facts (a complaint authority or a PI firm) with no entity or LE contact row."""
        return self.key.startswith(VIRTUAL_PREFIXES)

    @property
    def is_le(self) -> bool:
        if self.entity is not None:
            return self.entity.category in LE_CATEGORIES
        return self.category in LE_CATEGORY_VALUES

    @property
    def is_adviser(self) -> bool:
        if self.entity is not None:
            return self.entity.category in ADVISER_CATEGORIES
        return self.category in ADVISER_CATEGORY_VALUES

    @property
    def is_contact_party(self) -> bool:
        """Its contact details are LE / PI contacts (masked below manage_le_contacts), not a
        service's published compliance address."""
        return self.entity is None or self.is_le or self.is_adviser

    @property
    def engaged(self) -> bool:
        """The case has dealt with it: stop orders, correspondence, LE contacts, a complaint, the PI firm."""
        return bool(self.stop_orders or self.correspondence or self.le_contacts or self.virtual)

    @property
    def trace_label(self) -> str | None:
        """'in latest trace' / 'engaged earlier' for services, once the latest run was checked."""
        if (not self.trace_checked or self.run is None or self.entity is None or self.is_le or self.is_adviser
                or self.category in OFF_CHAIN_CATEGORIES):
            return None
        if self.in_trace:
            return "in latest trace"
        return "engaged earlier" if self.engaged else None

    @property
    def non_custodial(self) -> bool:
        return is_non_custodial(self.entity)

    @property
    def jurisdiction(self) -> str | None:
        if self.entity is not None:
            return self.entity.jurisdiction
        return next((c.jurisdiction for c in self.le_contacts if c.jurisdiction), None) or self.contact.get("jurisdiction")

    @property
    def recipient_email(self) -> str | None:
        if self.entity is not None and self.entity.compliance_email:
            return self.entity.compliance_email
        return next((c.email for c in self.le_contacts if c.email), None) or self.contact.get("email")

    @property
    def counts(self) -> dict[str, int]:
        out = {"in": 0, "out": 0, "note": 0, "draft": 0}
        for c in self.correspondence:
            if c.status == CorrespondenceStatus.DRAFT:
                out["draft"] += 1
            else:
                out[c.direction.value] += 1
        logged = {c.stop_order_id for c in self.correspondence if c.kind == CorrespondenceKind.STOP_ORDER}
        for o in self.stop_orders:  # letters without a correspondence row of their own
            if o.id not in logged:
                out["out" if o.sent_at else "draft"] += 1
        return out

    @property
    def last_contact(self) -> datetime | None:
        stamps = [c.occurred_at for c in self.correspondence if c.status != CorrespondenceStatus.DRAFT]
        stamps += [o.sent_at for o in self.stop_orders] + [o.responded_at for o in self.stop_orders]
        stamps = [_aware(s) for s in stamps if s is not None]
        return max(stamps) if stamps else None

    @property
    def open_orders(self) -> list[StopOrder]:
        return [o for o in self.stop_orders if order_open(o)]

    @property
    def contacted(self) -> bool:
        return any(c.status != CorrespondenceStatus.DRAFT for c in self.correspondence) or any(
            o.sent_at for o in self.stop_orders)

    def awaiting(self, default_days: int | None = None) -> list[tuple[str, int, datetime]]:
        """Open requests waiting for this authority's reply: (kind, id, due_at).

        A stop order's own letter is tracked by the order (its response clock); every other sent
        letter with a due date (status / information requests, also when linked to an order that
        has since been answered) waits until a later inbound message answers it. The assistant uses
        the same rule (letter_awaits_reply)."""
        out = [("stop_order", o.id, response_due(o, default_days)) for o in self.stop_orders if awaiting_response(o)]
        for c in self.correspondence:
            if letter_awaits_reply(c, self.correspondence):
                out.append(("correspondence", c.id, _aware(c.due_at)))
        return sorted(out, key=lambda t: t[2])

    def next_due(self) -> datetime | None:
        waiting = self.awaiting()
        return waiting[0][2] if waiting else None

    def overdue(self, now: datetime | None = None) -> bool:
        due = self.next_due()
        return due is not None and due < (now or _now())


def tracked_by_stop_order(c: Correspondence) -> bool:
    """The outbound copy of a stop order's own letter: its reply clock is the order's."""
    return c.stop_order_id is not None and c.kind == CorrespondenceKind.STOP_ORDER


def letter_awaits_reply(c: Correspondence, rows: list[Correspondence]) -> bool:
    """A sent outbound letter with a due date that no later inbound message (in `rows`, the same
    counterparty's correspondence) has answered."""
    return (c.direction == CorrespondenceDirection.OUT and c.status == CorrespondenceStatus.SENT
            and c.due_at is not None and not tracked_by_stop_order(c) and not _answered(c, rows))


def _answered(c: Correspondence, rows: list[Correspondence]) -> bool:
    """Has an inbound message answered outbound `c` (a reply to it, or any later inbound one)?"""
    sent = _aware(c.occurred_at)
    for r in rows:
        if r.direction != CorrespondenceDirection.IN:
            continue
        if r.in_reply_to_id == c.id or (c.thread_key and r.thread_key == c.thread_key):
            return True
        if sent is not None and r.occurred_at is not None and _aware(r.occurred_at) >= sent:
            return True
    return False


def _corr_key(c: Correspondence, le_by_id: dict[int, LEContact], by_id: dict[int, Correspondence],
              depth: int = 0) -> str | None:
    if c.entity_id:
        return f"entity-{c.entity_id}"
    if c.le_contact_id and c.le_contact_id in le_by_id:
        le = le_by_id[c.le_contact_id]
        return f"entity-{le.entity_id}" if le.entity_id else f"le-{le.id}"
    virtual = str((c.meta or {}).get("authority_key") or "")
    if virtual.startswith(VIRTUAL_PREFIXES) and KEY_RE.fullmatch(virtual):
        return virtual
    if c.stop_order is not None and c.stop_order.entity_id:
        return f"entity-{c.stop_order.entity_id}"
    if c.in_reply_to_id and c.in_reply_to_id in by_id and depth < 5:
        return _corr_key(by_id[c.in_reply_to_id], le_by_id, by_id, depth + 1)
    return None


def unassigned_correspondence(case: Case, *, shared_only: bool = False) -> list[Correspondence]:
    le_by_id = {c.id: c for c in case.le_contacts}
    by_id = {c.id: c for c in case.correspondence}
    return [c for c in case.correspondence if _corr_key(c, le_by_id, by_id) is None
            and (not shared_only or c.shared_with_external)]


def _same_org(a: str | None, b: str | None) -> bool:
    x, y = (a or "").strip().casefold(), (b or "").strip().casefold()
    return bool(x and y) and (x == y or x in y or y in x)


def _complaint_authorities(case: Case, taken: list[str]) -> list[Authority]:
    """Complaint authorities in case.facts that no LE contact (or entity) stands for: complaint-<n>."""
    out = []
    for n, c in enumerate((case.facts or {}).get("complaints") or []):
        if not isinstance(c, dict) or not str(c.get("authority") or "").strip():
            continue
        name = str(c["authority"]).strip()
        if any(_same_org(name, t) for t in taken):
            continue
        ref = c.get("reference")
        out.append(Authority(key=f"complaint-{n}", name=name[:255], category="law_enforcement", contact={
            "reference": None if ref and "enter here" in str(ref).lower() else ref,
            "filed_at": c.get("filed_at"), "jurisdiction": c.get("jurisdiction"), "email": c.get("email")}))
        taken.append(name)
    return out


def _pi_firms(case: Case) -> list[tuple[int, dict]]:
    """(n, profile) of the PI firms in case.facts: n=0 the investigator signing the letters, then
    other_investigators."""
    facts = case.facts or {}
    firms = [facts.get("investigator")] + list(facts.get("other_investigators") or [])
    return [(n, f) for n, f in enumerate(firms) if isinstance(f, dict) and str(f.get("firm") or "").strip()]


def case_authorities(db: Session, case: Case, *, run: TraceRun | None = None,
                     cands: list[FreezeCandidate] | None = None, shared_only: bool = False,
                     include_prospects: bool = True) -> list[Authority]:
    """Every counterparty of the case (see module doc): the union of the ones engaged (always) and
    the ones the latest trace reaches (with `include_prospects`). `shared_only` (external members)
    keeps only correspondence shared with externals and the authorities that have some."""
    le_by_id = {c.id: c for c in case.le_contacts}
    by_id = {c.id: c for c in case.correspondence}
    entity_ids: set[int] = set()
    entity_ids |= {o.entity_id for o in case.stop_orders if o.entity_id}
    entity_ids |= {c.entity_id for c in case.le_contacts if c.entity_id}
    corr_keys = {c.id: _corr_key(c, le_by_id, by_id) for c in case.correspondence}
    entity_ids |= {int(k.split("-")[1]) for k in corr_keys.values() if k and k.startswith("entity-")}
    pi_firms = _pi_firms(case)
    pi_entities: dict[int, int] = {}  # pi index -> entity id (a PI firm recorded as an entity)
    if pi_firms:
        rows = db.execute(select(Entity.id, Entity.name).where(
            func.lower(Entity.name).in_([str(f["firm"]).strip().lower() for _, f in pi_firms]))).all()
        by_name = {name.lower(): eid for eid, name in rows}
        for n, f in pi_firms:
            eid = by_name.get(str(f["firm"]).strip().lower())
            if eid is not None:
                pi_entities[n] = eid
        entity_ids |= set(pi_entities.values())

    candidates: dict[int, FreezeCandidate] = {}
    traced: set[int] = set()
    checked = False
    if include_prospects and not shared_only:
        checked = True
        if run is None:
            run = services.latest_run(db, case)
        if run is not None:
            if cands is None:
                cands = freeze_candidates(db, run)
            traced |= set(db.scalars(select(Address.entity_id).join(TraceNode, TraceNode.address_id == Address.id)
                                     .where(TraceNode.run_id == run.id, TraceNode.taint_usd > 0,
                                            Address.entity_id.is_not(None))).all())
        candidates = {c.entity.id: c for c in (cands or []) if c.entity is not None}
        entity_ids |= set(candidates) | traced
        facts = case.facts or {}
        names = {str(i.get("provider", "")).lower() for i in facts.get("infrastructure") or [] if i.get("provider")}
        if names:
            entity_ids |= set(db.scalars(select(Entity.id).where(func.lower(Entity.name).in_(names))).all())

    entities = {e.id: e for e in db.scalars(select(Entity).where(Entity.id.in_(entity_ids))).all()} if entity_ids else {}
    out: dict[str, Authority] = {}
    for eid, e in entities.items():
        out[f"entity-{eid}"] = Authority(
            key=f"entity-{eid}", name=e.name, category=_cat(e), entity=e, candidate=candidates.get(eid),
            candidate_run=run if eid in candidates else None, in_trace=eid in traced or eid in candidates,
            trace_checked=checked, run=run if checked else None)
    for le in case.le_contacts:
        key = f"entity-{le.entity_id}" if le.entity_id else f"le-{le.id}"
        if key not in out:
            out[key] = Authority(key=key, name=le.agency, category=contact_category(le, entities.get(le.entity_id)))
        out[key].le_contacts.append(le)
    taken = [le.agency for le in case.le_contacts] + [e.name for e in entities.values()]
    for a in _complaint_authorities(case, taken):
        out[a.key] = a
    for n, f in pi_firms:
        if n in pi_entities:
            continue
        key = f"pi-{n}"
        out[key] = Authority(key=key, name=str(f["firm"]).strip()[:255], category="pi_firm", contact={
            "email": f.get("email"), "phone": f.get("phone"), "contact": f.get("contact"),
            "jurisdiction": f.get("jurisdiction"), "case_investigator": n == 0})
    if not shared_only:
        for o in case.stop_orders:
            if o.entity_id and f"entity-{o.entity_id}" in out:
                out[f"entity-{o.entity_id}"].stop_orders.append(o)
    for c in case.correspondence:
        key = corr_keys.get(c.id)
        if key in out and (not shared_only or c.shared_with_external):
            out[key].correspondence.append(c)
    rows = list(out.values())
    if shared_only:
        rows = [a for a in rows if a.correspondence]
    now = _now()
    rows.sort(key=lambda a: (not a.overdue(now), not a.open_orders, not a.contacted,
                             -a.last_contact.timestamp() if a.last_contact else 0,
                             -(a.candidate.priority if a.candidate else 0), not a.in_trace, a.virtual,
                             a.name.lower()))
    return rows


def get_authority(db: Session, case: Case, key: str, *, shared_only: bool = False, run: TraceRun | None = None,
                  cands: list[FreezeCandidate] | None = None) -> Authority | None:
    if not KEY_RE.fullmatch(key or ""):
        return None
    return next((a for a in case_authorities(db, case, run=run, cands=cands, shared_only=shared_only)
                 if a.key == key), None)


def letter_run(db: Session, case: Case, authority: Authority, latest: TraceRun | None) -> TraceRun | None:
    """The trace run a stop order to `authority` is built from: the latest run when it lists the
    counterparty as a freeze candidate, else the newest of the MAX_EARLIER_RUNS earlier runs that
    does (`authority.candidate` / `candidate_run` are then set from it). Counterparties that take no
    stop order (LE, advisers, non-custodial routers) keep the latest run."""
    if authority.candidate is not None:
        authority.candidate_run = authority.candidate_run or latest
        return authority.candidate_run
    if authority.entity is None or authority.is_le or authority.is_adviser or authority.non_custodial:
        return latest
    q = select(TraceRun).where(TraceRun.case_id == case.id).order_by(TraceRun.id.desc()).limit(MAX_EARLIER_RUNS)
    if latest is not None:
        q = q.where(TraceRun.id != latest.id)
    for earlier in db.scalars(q):
        cand = next((c for c in freeze_candidates(db, earlier) if c.entity is not None
                     and c.entity.id == authority.entity.id), None)
        if cand is not None:
            authority.candidate, authority.candidate_run = cand, earlier
            return earlier
    return latest


# --------------------------------------------------------------------------- contact masking
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_PHONE_RE = re.compile(r"\+?\d[\d ()./-]{6,}\d")


def _mask_contacts(value: str) -> tuple[str, int]:
    """Every e-mail address and phone number in `value` masked like the LE-contact views."""
    from app.domain import evidence as ev

    out, hits = _EMAIL_RE.subn(lambda m: ev.mask_email(m.group(0)) or "***", value)
    out, phones = _PHONE_RE.subn(lambda m: ev.mask_phone(m.group(0)) or "***", out)
    return out, hits + phones


_NAME_ADDR_RE = re.compile(r"(.*?)\s*<([^<>]+)>")
# public webmail domains: an investigator writing from one does not make every address there a contact
_WEBMAIL = frozenset({"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
                      "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net", "gmx.de",
                      "aol.com", "mail.com", "yandex.com"})


def _name_variants(name: str) -> list[str]:
    """'Brigadiere Tullio Esempione' -> its contiguous spans of two or more words ('Tullio
    Esempione', 'Brigadiere Tullio') and the surname ('Esempione'): a letter seldom repeats a
    contact's name exactly as the register holds it (rank, title, first name dropped)."""
    words = [w for w in re.split(r"\s+", name.strip()) if w]
    out = [" ".join(words[i:j]) for i in range(len(words)) for j in range(i + 2, len(words) + 1)
           if (i, j) != (0, len(words))]
    if len(words) >= 2 and len(words[-1].strip(".,")) >= 4:
        out.append(words[-1].strip(".,"))
    return out


COMPLAINT_CONTACT_FIELDS = (("email", "email"), ("emails", "email"), ("contact_email", "email"), ("phone", "phone"),
                            ("contact_phone", "phone"), ("name", "name"), ("contact", "name"), ("contact_name", "name"),
                            ("officer", "name"))


def contact_values(case: Case) -> dict[str, str]:
    """Every LE, PI and complaint contact detail the case holds (names and their variants, e-mails,
    phones), lower-cased -> masked. Complaints: facts['complaints'] / ['complaints_pending'] entries'
    e-mail, phone and name fields (COMPLAINT_CONTACT_FIELDS)."""
    from app.domain import evidence as ev

    out: dict[str, str] = {}

    def add(v, kind: str) -> None:
        if not isinstance(v, str) or len(v.strip()) < 3:
            return
        v = v.strip()
        if kind == "email":
            _, addr = _split_name_addr(v)
            out.setdefault(addr.lower(), ev.mask_email(addr) or "***")
            return
        masked = {"phone": ev.mask_phone}.get(kind, ev.mask_name)(v)
        out.setdefault(v.lower(), masked or "***")
        if kind == "name":  # 'Mara Lindqvist — Director' -> also 'Mara Lindqvist', 'Lindqvist'
            short = re.split(r"\s[—–-]\s|,|\(", v)[0].strip()
            for n in [short, *_name_variants(short)]:
                if len(n) >= 3 and n.lower() not in out:
                    out[n.lower()] = ev.mask_name(n) or "***"

    for le in case.le_contacts:
        add(le.name, "name")
        add(le.email, "email")
        add(le.phone, "phone")
    for _, f in _pi_firms(case):
        add(f.get("contact"), "name")
        add(f.get("email"), "email")
        add(f.get("phone"), "phone")
        for cc in f.get("cc") or []:
            add(cc, "email")
    facts = case.facts or {}
    for c in [*(facts.get("complaints") or []), *(facts.get("complaints_pending") or [])]:
        if not isinstance(c, dict):
            continue
        for key, kind in COMPLAINT_CONTACT_FIELDS:
            v = c.get(key)
            for item in v if isinstance(v, list) else [v]:
                add(item, kind)
    return out


def contact_domains(case: Case) -> frozenset[str]:
    """The PI firms' own e-mail domains (from their contact address): any address there is a PI
    contact detail, listed in the facts or not (e.g. a generic info@ sender)."""
    out = set()
    for _, f in _pi_firms(case):
        _, addr = _split_name_addr(str(f.get("email") or ""))
        domain = addr.rpartition("@")[2].strip().lower()
        if "@" in addr and "." in domain and domain not in _WEBMAIL:
            out.add(domain)
    return frozenset(out)


def _split_name_addr(v: str) -> tuple[str, str]:
    """'Name <addr>' -> ('Name', 'addr'); anything else -> ('', v)."""
    m = _NAME_ADDR_RE.fullmatch(v.strip())
    if not m:
        return "", v.strip()
    return m.group(1).strip().strip("\"'").strip(), m.group(2).strip()


@dataclass
class ContactMask:
    """LE / PI contact details as one member may see them: masked (``m***@k***.example``, ``M. L*****``,
    ``+41 *** *** 00``) for every role below manage_le_contacts (read-only and external members),
    exactly like the LE-contact views, together with the case's complaint references
    (``DEMO-IT-******00``, app.domain.evidence.ref_mask). `party`: every sender / recipient of this
    authority is an LE or PI contact (not a service's compliance desk), so each value is masked,
    known or not."""

    active: bool = False
    party: bool = False
    redact: Any = None  # app.domain.evidence.RefMask

    @property
    def known(self) -> dict[str, str]:
        return self.redact.refs if self.redact is not None else {}

    def value(self, v):
        """One sender / recipient / contact field."""
        if not self.active or not v or not isinstance(v, str):
            return v
        s = v.strip()
        if s.lower() in self.known:
            return self.known[s.lower()]
        if not self.party:
            return self.text(s)
        name, addr = _split_name_addr(s)
        if name or addr != s:  # 'Display Name <addr>': both parts masked
            masked_addr = self.value(addr)
            return f"{self.value(name)} <{masked_addr}>" if name else f"<{masked_addr}>"
        t = self.text(s)
        out, hits = _mask_contacts(t)
        if hits or t != s:
            return out
        from app.domain import evidence as ev

        return ev.mask_name(s) or s

    def values(self, vs) -> list:
        return [self.value(v) for v in vs or []]

    def text(self, t):
        """Free text (a subject, a plain-text body) with every known contact value and complaint
        reference masked."""
        if not self.active or not t or self.redact is None:
            return t
        return self.redact(t)

    def md(self, t):
        """Markdown (a letter body) masked like text(), the masked values escaped so their ``*``
        render as asterisks (in the page, in .md and .docx exports)."""
        if not self.active or not t or self.redact is None:
            return t
        return self.redact(t, md=True)


def contact_mask(access, authority: Authority | None = None, corr: Correspondence | None = None) -> ContactMask:
    """The ContactMask for `access` (inactive for investigators and admins)."""
    from app.domain import evidence as ev

    if ev.allowed(access, "manage_le_contacts"):
        return ContactMask()
    party = authority.is_contact_party if authority is not None else bool(
        corr is not None and (corr.le_contact_id or (corr.entity is not None and corr.entity.category in
                                                     LE_CATEGORIES | ADVISER_CATEGORIES)))
    redact = ev.ref_mask(access)
    if not redact.active:  # a role with view_restricted but not manage_le_contacts: contacts only
        redact = ev.RefMask(contact_values(access.case), contact_domains(access.case))
    return ContactMask(active=True, party=party, redact=redact)


def order_shared(order: StopOrder | None) -> bool:
    """A stop order counts as shared with external members when its own letter was shared."""
    return order is not None and any(c.shared_with_external and c.kind == CorrespondenceKind.STOP_ORDER
                                     for c in order.correspondence)


# --------------------------------------------------------------------------- timeline
@dataclass
class TimelineItem:
    at: datetime | None
    direction: str  # in | out | note
    kind: str  # CorrespondenceKind value
    channel: str | None
    status: str
    subject: str
    corr: Correspondence | None = None
    order: StopOrder | None = None

    @property
    def anchor(self) -> str:
        return f"c{self.corr.id}" if self.corr is not None else f"o{self.order.id}"

    @property
    def body(self) -> str:
        if self.corr is not None:
            return self.corr.body_markdown or ""
        return self.order.body_markdown or ""

    @property
    def body_format(self) -> str:
        return (self.corr.meta or {}).get("format", "markdown") if self.corr is not None else "markdown"

    @property
    def classification(self) -> str:
        return self.corr.classification.value if self.corr is not None else Classification.R3.value

    @property
    def shared(self) -> bool:
        return bool(self.corr is not None and self.corr.shared_with_external)

    @property
    def is_draft(self) -> bool:
        return self.status == "draft"


def timeline(authority: Authority, *, direction: str | None = None, kind: str | None = None,
             channel: str | None = None, status: str | None = None, newest_first: bool = False) -> list[TimelineItem]:
    items: list[TimelineItem] = []
    logged = {c.stop_order_id for c in authority.correspondence if c.kind == CorrespondenceKind.STOP_ORDER}
    for c in authority.correspondence:
        items.append(TimelineItem(
            at=_aware(c.occurred_at or c.created_at), direction=c.direction.value, kind=c.kind.value,
            channel=c.channel.value if c.channel else None, status=c.status.value,
            subject=c.subject or KIND_LABELS.get(c.kind.value, c.kind.value), corr=c, order=c.stop_order))
    for o in authority.stop_orders:
        if o.id in logged:
            continue
        items.append(TimelineItem(at=_aware(o.sent_at or o.created_at), direction="out", kind="stop_order",
                                  channel=o.sent_via, status=order_state(o) if o.sent_at else o.status.value,
                                  subject=o.subject, order=o))
    if direction:
        items = [i for i in items if i.direction == direction]
    if kind:
        items = [i for i in items if i.kind == kind]
    if channel:
        items = [i for i in items if i.channel == channel]
    if status:
        items = [i for i in items if i.status == status]
    epoch = datetime.min.replace(tzinfo=UTC)
    items.sort(key=lambda i: (i.at or epoch, 0 if i.corr is None else 1, i.corr.id if i.corr else i.order.id),
               reverse=newest_first)
    return items


def can_view_body(access, item: TimelineItem | Correspondence) -> bool:
    """R3 bodies (letters, LE material) need view_restricted; externals see what was shared with them."""
    if isinstance(item, Correspondence):
        cls, shared = item.classification.value, item.shared_with_external
    else:
        cls, shared = item.classification, item.shared
    if access.is_external:
        return shared
    return cls != Classification.R3.value or access.can("view_restricted")


def linked_evidence(case: Case, corr: Correspondence | None, *, shared_only: bool = False,
                    access=None) -> list[EvidenceItem]:
    """The evidence items a message links to. With `access`, only items that member may see
    (app.domain.evidence.can_see: the Financial folder is for case admins, externals see shared items)."""
    if corr is None:
        return []
    ids = [corr.evidence_item_id] if corr.evidence_item_id else []
    ids += [int(i) for i in (corr.meta or {}).get("evidence_ids") or [] if str(i).isdigit()]
    items = [e for e in case.evidence_items if not shared_only or e.shared_with_external]
    if access is not None:
        from app.domain.evidence import can_see

        items = [e for e in items if can_see(access, e)]
    by_id = {e.id: e for e in items}
    return [by_id[i] for i in dict.fromkeys(ids) if i in by_id]


# --------------------------------------------------------------------------- logging & status
def _emit_link(case: Case, authority_key: str | None, anchor: str = "") -> str:
    base = f"/cases/{case.id}/authorities/{authority_key}" if authority_key else f"/cases/{case.id}?tab=authorities"
    return base + (f"#{anchor}" if anchor else "")


def _attach(corr: Correspondence, authority: Authority) -> None:
    corr.entity = authority.entity
    if authority.entity is None and authority.le_contacts:
        corr.le_contact_id = authority.le_contacts[0].id
    elif authority.virtual:  # no row to point at: the key itself ties the message to the authority
        corr.meta = {**(corr.meta or {}), "authority_key": authority.key}


def log_entry(db: Session, case: Case, authority: Authority, *, actor: User | None, direction: str, channel: str,
              kind: str, subject: str, body: str | None, body_format: str = "markdown",
              occurred_at: datetime | None = None, sender: str | None = None, recipients: list[str] | None = None,
              cc: list[str] | None = None, external_ref: str | None = None, stop_order: StopOrder | None = None,
              in_reply_to: Correspondence | None = None, evidence_ids: list[int] | None = None,
              due_days: int | None = None, classification: str = "R2", shared_with_external: bool = False,
              thread_key: str | None = None) -> Correspondence:
    """Log an inbound reply, an outbound message sent outside Aegis, or an internal note / call."""
    d = CorrespondenceDirection(direction)
    occurred = _aware(occurred_at) or _now()
    if not (subject or "").strip():
        raise DeskError("a subject is required")
    if stop_order is not None and stop_order not in authority.stop_orders:
        raise DeskError("that stop order belongs to another counterparty")
    status = {CorrespondenceDirection.IN: CorrespondenceStatus.RECEIVED, CorrespondenceDirection.OUT:
              CorrespondenceStatus.SENT, CorrespondenceDirection.NOTE: CorrespondenceStatus.LOGGED}[d]
    evidence_ids = [int(i) for i in evidence_ids or []]
    valid = {e.id for e in case.evidence_items}
    if any(i not in valid for i in evidence_ids):
        raise DeskError("unknown evidence item")
    corr = Correspondence(
        case=case, direction=d, channel=CorrespondenceChannel(channel), kind=CorrespondenceKind(kind), status=status,
        subject=subject.strip()[:512], body_markdown=body or None, sender=(sender or "").strip() or None,
        recipients=[r for r in recipients or [] if r], cc=[r for r in cc or [] if r], occurred_at=occurred,
        stop_order=stop_order, in_reply_to_id=in_reply_to.id if in_reply_to is not None else None,
        thread_key=thread_key or (in_reply_to.thread_key if in_reply_to is not None else None),
        evidence_item_id=evidence_ids[0] if evidence_ids else None, external_ref=(external_ref or "").strip() or None,
        shared_with_external=shared_with_external, classification=Classification(classification),
        meta={"format": "text" if body_format == "text" else "markdown", "evidence_ids": evidence_ids,
              "source": "logged"},
        created_by=actor.id if actor else None,
    )
    _attach(corr, authority)
    if d == CorrespondenceDirection.OUT and due_days:
        corr.due_at = occurred + timedelta(days=int(due_days))
    db.add(corr)
    if stop_order is not None and d == CorrespondenceDirection.IN and stop_order.responded_at is None:
        stop_order.responded_at = occurred
        if external_ref and not stop_order.external_ref:
            stop_order.external_ref = corr.external_ref
    db.flush()
    if d != CorrespondenceDirection.NOTE:
        inbound = d == CorrespondenceDirection.IN
        events.emit(
            db, case, events.CORRESPONDENCE_IN if inbound else events.CORRESPONDENCE_OUT,
            title=f"{case.reference}: {'reply received' if inbound else 'message sent'} (correspondence #{corr.id})",
            body=f"{DIRECTION_LABELS[d.value]} {KIND_LABELS.get(corr.kind.value, 'message').lower()} logged on the "
                 f"authorities desk" + (f" for stop order #{stop_order.id}." if stop_order is not None else "."),
            link=_emit_link(case, authority.key, f"c{corr.id}"), severity="info",
            payload={"correspondence_id": corr.id, "stop_order_id": stop_order.id if stop_order is not None else None},
            commit=False)
    db.commit()
    return corr


def parse_amount(v: str | None) -> Decimal | None:
    s = (v or "").replace(",", "").replace("_", "").strip()
    if not s:
        return None
    try:
        d = Decimal(s)
    except InvalidOperation:
        raise DeskError("the amount held must be a number") from None
    if d < 0 or not d.is_finite():
        raise DeskError("the amount held must be a positive number")
    return d


def record_stop_order_status(db: Session, case: Case, order: StopOrder, status: str, *, actor: User | None,
                             amount_held: Decimal | None = None, asset: str | None = None,
                             external_ref: str | None = None, note: str | None = None,
                             occurred_at: datetime | None = None, authority_key: str | None = None,
                             evidence_ids: list[int] | None = None, observed: bool = False) -> Correspondence | None:
    """Move a stop order to `status` and log it on the timeline.

    `sent` turns the order's draft letter into a sent outbound entry (or logs one); acknowledged /
    frozen / declined / released log a correspondence entry (status `logged`) with the amount held,
    set `responded_at` once, and keep the hold history in `identifiers.hold`. Emits stop_order_status.

    Never `draft` or `superseded` (the generator sets those), and never away from SUPERSEDED: a newer draft carries
    that request, so reviving or sending the old one would give the provider a second request (one open request per
    provider). `observed`: the mailbox found the letter in Sent Items — it did go out, so `sent` is recorded even on a
    superseded order."""
    if status not in ALL_STATUSES:
        raise DeskError(f"unknown stop-order status {status!r}")
    if status == StopOrderStatus.SUPERSEDED.value or (status == StopOrderStatus.DRAFT.value
                                                      and order.status != StopOrderStatus.DRAFT):
        raise DeskError(f"a stop order is never set to {status} by hand: generate a new draft from the authority page")
    if order.status == StopOrderStatus.SUPERSEDED and not (observed and status == "sent"):
        raise DeskError(f"stop order #{order.id} was superseded by a newer draft and is no request any more: record "
                        "the status on the newer stop order")
    now = _now()
    at = _aware(occurred_at) or now
    previous = order_state(order)
    ids = dict(order.identifiers or {})
    hold = dict(ids.get("hold") or {})
    asset = (asset or "").strip().upper()[:16] or None
    if status == RELEASED and previous != "frozen":
        raise DeskError("only a frozen stop order can be marked released")
    if amount_held is not None and status not in ("frozen", RELEASED, "acknowledged"):
        raise DeskError("an amount held only applies to acknowledged / frozen / released")

    corr: Correspondence | None = None
    if status == RELEASED:
        enum_member = StopOrderStatus._value2member_map_.get(RELEASED)
        if enum_member is not None:
            order.status = enum_member  # type: ignore[assignment]
    else:
        order.status = StopOrderStatus(status)
    if status == "sent":
        order.sent_at = order.sent_at or at
        order.response_due_at = order.response_due_at or _aware(order.sent_at) + timedelta(days=DEFAULT_RESPONSE_DAYS)
        draft = next((c for c in order.correspondence if c.kind == CorrespondenceKind.STOP_ORDER
                      and c.direction == CorrespondenceDirection.OUT), None)
        if draft is not None and draft.status == CorrespondenceStatus.DRAFT:
            draft.status, draft.occurred_at, draft.due_at = CorrespondenceStatus.SENT, order.sent_at, order.response_due_at
            corr = draft
        elif draft is None:
            corr = Correspondence(
                case=case, entity=order.entity, direction=CorrespondenceDirection.OUT, channel=_channel(order.sent_via),
                kind=CorrespondenceKind.STOP_ORDER, status=CorrespondenceStatus.SENT, subject=order.subject,
                body_markdown=order.body_markdown, recipients=[r for r in [order.recipient_email] if r],
                cc=list(order.recipient_cc or []), occurred_at=order.sent_at, due_at=order.response_due_at,
                stop_order=order, classification=Classification.R3, meta={"format": "markdown", "source": "status"},
                created_by=actor.id if actor else None)
            db.add(corr)
    elif status in ("acknowledged", "frozen", "declined", RELEASED):
        if order.responded_at is None:
            order.responded_at = at
        if status in ("frozen", RELEASED, "acknowledged") and (amount_held is not None or status != "acknowledged"):
            hold.update({"state": status, "at": at.isoformat()})
            if amount_held is not None:
                hold["amount"] = str(amount_held)
            if asset:
                hold["asset"] = asset
            if amount_held is not None and status == "frozen":
                hold.setdefault("frozen_amount", str(amount_held))
        elif hold and status == "declined":
            hold["state"] = "declined"
        held = f" — {_amount_text(amount_held, asset)} held" if amount_held is not None else ""
        corr = Correspondence(
            case=case, entity=order.entity, direction=CorrespondenceDirection.NOTE, channel=CorrespondenceChannel.OTHER,
            kind=CorrespondenceKind.OTHER, status=CorrespondenceStatus.LOGGED,
            subject=f"Stop order #{order.id} marked {status}{held}"[:512], body_markdown=(note or "").strip() or None,
            occurred_at=at, stop_order=order, external_ref=(external_ref or "").strip() or None,
            classification=Classification.R3,
            evidence_item_id=(evidence_ids or [None])[0],
            meta={"format": "text", "source": "stop_order_status", "status": status, "previous": previous,
                  "amount_held": str(amount_held) if amount_held is not None else None, "asset": asset,
                  "evidence_ids": list(evidence_ids or [])},
            created_by=actor.id if actor else None)
        db.add(corr)
    if external_ref and external_ref.strip():
        order.external_ref = external_ref.strip()[:255]
    if note and note.strip():
        order.notes = (order.notes + "\n" if order.notes else "") + note.strip()
    history = list(ids.get("status_history") or [])
    history.append({"status": status, "previous": previous, "at": at.isoformat(), "by": actor.id if actor else None,
                    "amount": str(amount_held) if amount_held is not None else None, "asset": asset})
    ids["status_history"] = history
    if hold:
        ids["hold"] = hold
    order.identifiers = ids  # JSON column: reassign so the change is flushed
    db.flush()
    usd = to_usd(asset, amount_held) if (asset and amount_held is not None) else None
    severity = {"frozen": "high", "declined": "warning"}.get(status, "info")
    events.emit(
        db, case, events.STOP_ORDER_STATUS, usd=usd, severity=severity,
        title=f"{case.reference}: stop order #{order.id} {status}",
        body=(f"Stop order #{order.id} moved from {previous} to {status}"
              + (f"; {_amount_text(amount_held, asset)} reported held." if amount_held is not None else ".")),
        link=_emit_link(case, authority_key or (f"entity-{order.entity_id}" if order.entity_id else None),
                        f"c{corr.id}" if corr is not None and corr.id else f"o{order.id}"),
        payload={"stop_order_id": order.id, "correspondence_id": corr.id if corr is not None else None,
                 "status": status}, commit=False)
    db.commit()
    return corr


def _amount_text(amount: Decimal | None, asset: str | None) -> str:
    if amount is None:
        return ""
    d = amount.normalize()
    return f"{d:,f} {asset or ''}".strip()


def _channel(v: str | None) -> CorrespondenceChannel:
    return CorrespondenceChannel(v) if v in CorrespondenceChannel._value2member_map_ else CorrespondenceChannel.EMAIL


# --------------------------------------------------------------------------- drafts
def update_draft(db: Session, corr: Correspondence, *, subject: str, body: str, recipients: list[str],
                 cc: list[str]) -> Correspondence:
    if corr.status != CorrespondenceStatus.DRAFT:
        raise DeskError("only drafts can be edited; this letter is already sent")
    if not subject.strip():
        raise DeskError("a subject is required")
    before = (corr.subject, list(corr.recipients or []), list(corr.cc or []))
    corr.subject, corr.body_markdown = subject.strip()[:512], body
    corr.recipients, corr.cc = [r for r in recipients if r], [r for r in cc if r]
    meta = {**(corr.meta or {}), "edited": True}
    saved = meta.get("mail_draft")
    if isinstance(saved, dict):  # the e-mail editor's saved fields: what is changed here wins on the compose page
        saved = dict(saved)
        if corr.subject != before[0]:
            saved.pop("subject", None)
        if corr.recipients != before[1] or corr.cc != before[2]:
            for k in ("to", "cc", "to_other", "cc_other"):
                saved.pop(k, None)
        meta["mail_draft"] = saved
    corr.meta = meta
    order = corr.stop_order
    if order is not None and corr.kind == CorrespondenceKind.STOP_ORDER and order.status == StopOrderStatus.DRAFT:
        order.subject, order.body_markdown = corr.subject, body
        order.recipient_email = corr.recipients[0] if corr.recipients else None
        order.recipient_cc = list(corr.cc)
    db.commit()
    return corr


BODY_VERSIONS_KEPT = 10  # earlier texts of a draft kept in meta.versions (newest last)


def update_body(db: Session, corr: Correspondence, body: str, *, actor: User | None, source: str = "edit") -> bool:
    """Replace a draft letter's text (the e-mail editor), keeping the previous text as a version in
    `meta.versions` ({at, by, source, sha256, chars, body}; the last BODY_VERSIONS_KEPT). A draft stop
    order's own letter updates the stop order too. Returns False when the text is unchanged. Flushes
    only: the caller commits and audits."""
    if corr.status != CorrespondenceStatus.DRAFT:
        raise DeskError("only drafts can be edited; this letter is already sent")
    body = (body or "").replace("\r\n", "\n").replace("\r", "\n")
    if body == (corr.body_markdown or ""):
        return False
    old = corr.body_markdown or ""
    meta = dict(corr.meta or {})
    versions = list(meta.get("versions") or [])
    versions.append({"at": _now().isoformat(), "by": actor.id if actor is not None else None, "source": source,
                     "sha256": hashlib.sha256(old.encode("utf-8")).hexdigest(), "chars": len(old), "body": old})
    meta.update({"versions": versions[-BODY_VERSIONS_KEPT:], "edited": True})
    corr.meta = meta
    corr.body_markdown = body
    order = corr.stop_order
    if order is not None and corr.kind == CorrespondenceKind.STOP_ORDER and order.status == StopOrderStatus.DRAFT:
        order.body_markdown = body
    db.flush()
    return True


def mark_sent(db: Session, case: Case, corr: Correspondence, *, actor: User | None, sent_at: datetime | None = None,
              channel: str | None = None, external_ref: str | None = None, due_days: int | None = DEFAULT_RESPONSE_DAYS,
              authority_key: str | None = None) -> Correspondence:
    """A draft letter was sent (outside Aegis): record when and how, start the reply clock."""
    if corr.status != CorrespondenceStatus.DRAFT or corr.direction != CorrespondenceDirection.OUT:
        raise DeskError("only an outbound draft can be marked sent")
    at = _aware(sent_at) or _now()
    corr.status, corr.occurred_at = CorrespondenceStatus.SENT, at
    if channel:
        corr.channel = CorrespondenceChannel(channel)
    if external_ref and external_ref.strip():
        corr.external_ref = external_ref.strip()[:255]
    days = DEFAULT_RESPONSE_DAYS if due_days is None else int(due_days)
    corr.due_at = at + timedelta(days=days) if days > 0 else None
    order = corr.stop_order
    order_sent = False
    if order is not None and corr.kind == CorrespondenceKind.STOP_ORDER and order.status == StopOrderStatus.DRAFT:
        order.status, order.sent_at, order.sent_via = StopOrderStatus.SENT, at, corr.channel.value
        order.response_due_at = corr.due_at or at + timedelta(days=DEFAULT_RESPONSE_DAYS)
        order.subject, order.body_markdown = corr.subject or order.subject, corr.body_markdown or order.body_markdown
        order.recipient_email = corr.recipients[0] if corr.recipients else order.recipient_email
        order.recipient_cc = list(corr.cc or [])
        if corr.external_ref:
            order.external_ref = corr.external_ref
        ids = dict(order.identifiers or {})
        ids["status_history"] = list(ids.get("status_history") or []) + [
            {"status": "sent", "previous": "draft", "at": at.isoformat(), "by": actor.id if actor else None}]
        order.identifiers = ids
        order_sent = True
    db.flush()
    key = authority_key or (f"entity-{corr.entity_id}" if corr.entity_id else None)
    events.emit(db, case, events.CORRESPONDENCE_OUT, severity="info",
                title=f"{case.reference}: letter sent (correspondence #{corr.id})",
                body=f"{KIND_LABELS.get(corr.kind.value, 'Letter')} marked sent; reply expected by "
                     f"{_fmt_day(corr.due_at)}." if corr.due_at else
                     f"{KIND_LABELS.get(corr.kind.value, 'Letter')} marked sent.",
                link=_emit_link(case, key, f"c{corr.id}"),
                payload={"correspondence_id": corr.id, "stop_order_id": order.id if order is not None else None},
                commit=False)
    if order_sent:
        events.emit(db, case, events.STOP_ORDER_STATUS, severity="info",
                    title=f"{case.reference}: stop order #{order.id} sent",
                    body=f"Stop order #{order.id} moved from draft to sent.", link=_emit_link(case, key, f"c{corr.id}"),
                    payload={"stop_order_id": order.id, "correspondence_id": corr.id, "status": "sent"}, commit=False)
    db.commit()
    return corr


# --------------------------------------------------------------------------- form letters
@dataclass(frozen=True)
class LetterTemplate:
    key: str
    label: str
    kind: CorrespondenceKind
    description: str


LETTER_TEMPLATES: dict[str, LetterTemplate] = {t.key: t for t in (
    LetterTemplate("stop_order", "Stop order (preservation / freeze)", CorrespondenceKind.STOP_ORDER,
                   "Preservation / risk-control request built from this counterparty's freeze-candidate identifiers "
                   "in the latest trace (the stop-order generator)."),
    LetterTemplate("status_request", "Status request / follow-up", CorrespondenceKind.STATUS_REQUEST,
                   "Refers to an earlier letter by date and subject, repeats its identifiers, asks to confirm the "
                   "hold and the account status, and states the days elapsed."),
    LetterTemplate("info_response", "Answer to their request", CorrespondenceKind.STATUS_REQUEST,
                   "Answers what a provider's reply asked for (the police report receipt, proof of ownership, …), "
                   "quoting their ticket and their deadline, lists what is enclosed and what follows, and asks them to "
                   "keep a temporary hold in place while law enforcement files."),
    LetterTemplate("info_request", "Information request", CorrespondenceKind.INFO_REQUEST,
                   "Preservation and information request without a freeze (infrastructure providers, non-custodial "
                   "routers, issuers, any counterparty)."),
    LetterTemplate("le_cover", "Law-enforcement cover letter", CorrespondenceKind.LE_COVER,
                   "To the police / IC3: summarises the identifiers, where the funds sit and the status of every "
                   "stop order."),
    LetterTemplate("release_request", "Release / return-of-funds request", CorrespondenceKind.RELEASE_REQUEST,
                   "Asks a counterparty that confirmed a hold to release the funds for return to the victim."),
    LetterTemplate("le_brief", "LE brief (a provider needs LE process)", CorrespondenceKind.LE_COVER,
                   "To the case officer, about one provider request: what the provider answered (quoted), its ticket, "
                   "the instrument and channel it requires, the route (cross-border when it does not act on this "
                   "authority), what is at stake and the clocks. Linked to that request (follow-up)."),
    LetterTemplate("counsel_brief", "Counsel brief (court-order route)", CorrespondenceKind.OTHER,
                   "To counsel, about one provider request that needs a court order (TRO, 1782, sequestro): the "
                   "provider's answer, the order it acts on, what is at stake and the clocks. Linked to that request."),
)}
BRIEF_TEMPLATES = frozenset({"le_brief", "counsel_brief"})


def sent_references(authority: Authority) -> list[dict]:
    """Earlier letters to this authority that a follow-up can refer to (newest first)."""
    refs: list[dict] = []
    logged = {c.stop_order_id for c in authority.correspondence if c.kind == CorrespondenceKind.STOP_ORDER}
    for o in authority.stop_orders:
        if o.sent_at and o.id not in logged and order_state(o) != "superseded":
            refs.append({"value": f"o{o.id}", "at": _aware(o.sent_at), "subject": o.subject, "order": o, "corr": None})
    for c in authority.correspondence:
        if c.direction == CorrespondenceDirection.OUT and c.status == CorrespondenceStatus.SENT and c.occurred_at:
            refs.append({"value": f"c{c.id}", "at": _aware(c.occurred_at), "subject": c.subject or "(no subject)",
                         "order": c.stop_order, "corr": c})
    for r in refs:
        r["label"] = f"{_fmt_day(r['at'])} – {(r['subject'] or '')[:90]}"
    return sorted(refs, key=lambda r: r["at"], reverse=True)


def frozen_orders(authority: Authority) -> list[StopOrder]:
    return [o for o in authority.stop_orders if order_state(o) == "frozen"]


GATED_TEMPLATES = frozenset({"stop_order", "info_request"})  # first contact only: a follow-up on a letter already sent
# (status / release request) stays available; the LE-only rule then holds per channel (mail_compose.prepare)


def playbook_gate_reason(authority: Authority, requester: str = "pi", held=()) -> str | None:
    """Why no letter from us (a private requester) goes to this counterparty: its provider playbook has no path
    open to `requester` (the LE-only gate: brief the case officer with the pack instead; or a binding instrument only
    LE or counsel holds; `held`: the instrument types on file, evidence_requirements.held_instruments, open the
    binding paths that take them). None when a path is open, for LE / advisers, or without a playbook."""
    if authority.is_le or authority.is_adviser:
        return None
    try:
        from app.domain import directory

        pb = directory.playbook_for(authority)
    except Exception:  # noqa: BLE001 - an invalid catalogue gates nothing (the directory page reports it)
        return None
    return pb.gate(requester, held, name=authority.name).reason if pb is not None else None


def template_options(authority: Authority, run: TraceRun | None, requester: str = "pi", held=()) -> list[dict]:
    """Each letter template with whether it applies to this authority now, and why not. `requester`: who the
    case's letters come from (app.domain.sender.requester_kind; never LE); `held`: the orders on file
    (evidence_requirements.held_instruments): a binding path that takes one opens."""
    gate = playbook_gate_reason(authority, requester, held)

    def reason(key: str) -> str | None:
        if gate and key in GATED_TEMPLATES:
            return gate
        if key == "stop_order":
            if authority.is_le or authority.is_adviser:
                return "Stop orders go to services that hold funds or records, not to law enforcement or advisers."
            if authority.non_custodial:
                return ("Non-custodial router: it holds no accounts or balances and cannot freeze funds. "
                        "Send an information request instead.")
            if run is None:
                return "Run a trace first: stop orders are built from its freeze candidates."
            if authority.candidate is None:
                return ("No freeze-candidate identifiers for this counterparty in the latest trace (or the "
                        f"{MAX_EARLIER_RUNS} runs before it); send an information request instead.")
        elif key == "status_request" and not sent_references(authority):
            return "Nothing has been sent to this counterparty yet."
        elif key == "info_response" and not any(c.direction == CorrespondenceDirection.IN
                                                for c in authority.correspondence):
            return "No reply from this counterparty to answer yet."
        elif key in ("le_cover", "le_brief") and not authority.is_le:
            return "For law-enforcement agencies only."
        elif key == "counsel_brief" and authority.category != EntityCategory.LEGAL_COUNSEL.value:
            return "For counsel only."
        elif key == "release_request" and not frozen_orders(authority):
            return "No hold has been confirmed by this counterparty (mark a stop order frozen first)."
        return None

    return [{"key": t.key, "label": t.label, "description": t.description, "reason": reason(t.key),
             "available": reason(t.key) is None} for t in LETTER_TEMPLATES.values()]


def sender_profile(case: Case, actor: User | None = None) -> dict:
    """Who signs: the case's sender profile when it has one ("<organisation>, on behalf
    of …", app.domain.sender); else the investigator profile in case.facts; otherwise the signed-in
    user, without claiming to be a firm (never the victim's company as a "PI firm")."""
    from app.domain import sender as sender_mod  # local import: no cycle at module import time

    athena = sender_mod.letter_sender(case, actor)
    if athena is not None:
        return athena
    inv = dict((case.facts or {}).get("investigator") or {})
    if inv.get("firm"):
        address = inv.get("address") or ""
        return {"firm": inv["firm"], "contact": inv.get("contact") or inv["firm"], "email": inv.get("email"),
                "address": address, "phone": inv.get("phone"), "cc": list(inv.get("cc") or []),
                "instrument": inv.get("authority_instrument") or "Letter of Authority",
                "based_in": address.split(",")[-1].strip() if address else None}
    return {"firm": None, "contact": (actor.display_name if actor else None) or "The case team", "email": None,
            "address": None, "phone": None, "cc": [], "instrument": "written authorisation from the victim",
            "based_in": None}


def _victim(case: Case) -> dict:
    vc = dict((case.facts or {}).get("victim_contact") or {})
    return {"name": case.victim_name or vc.get("name") or "the victim",
            "role": vc.get("role") or case.victim_entity, "jurisdiction": case.victim_jurisdiction}


def complaint_list(case: Case) -> list[dict]:
    """LE complaints from case.facts, completed by the case's LE contacts (deduplicated by reference)."""
    out: list[dict] = []
    seen: set[str] = set()
    for c in (case.facts or {}).get("complaints") or []:
        ref = c.get("reference")
        if ref and "enter here" in str(ref).lower():
            ref = None
        out.append({"authority": c.get("authority") or "law enforcement", "reference": ref,
                    "filed_at": c.get("filed_at")})
        if ref:
            seen.add(str(ref))
    for le in case.le_contacts:
        if le.reference and le.reference not in seen:
            out.append({"authority": le.agency, "reference": le.reference, "filed_at": None})
            seen.add(le.reference)
    return out


def _origin(case: Case) -> dict:
    facts = case.facts or {}
    if facts.get("origin"):
        return dict(facts["origin"])
    seeds = {s.role: s.value for s in case.seeds}
    return {"tx_hash": seeds.get(SeedRole.ORIGIN_TX), "victim_wallet": seeds.get(SeedRole.VICTIM_WALLET),
            "first_recipient": seeds.get(SeedRole.PERPETRATOR_WALLET)}


_ORDER_REF = SWAP_ORDER_REF


def _swap_orders(txs: list[dict]) -> list[str]:
    return list(dict.fromkeys(m.group(1) for t in txs for m in _ORDER_REF.finditer(t.get("notes") or "")))


def _norm_ident(i, chain: str | None = None) -> dict:
    """An identifier as the letter templates use it, from a FreezeCandidate Identifier or the stored
    stop-order identifiers (dicts from the generator, or bare strings from imported letters)."""
    if isinstance(i, str):
        return {"chain": chain or "", "address": i, "address_type": "unknown", "label": None, "inbound": [], "outbound": [],
                "flags": [], "swap_orders": []}
    get = i.get if isinstance(i, dict) else (lambda k, d=None: getattr(i, k, d))
    inbound, outbound = list(get("inbound") or []), list(get("outbound") or [])
    return {"chain": get("chain") or "", "address": get("address") or "",
            "address_type": get("address_type") or get("type") or "unknown", "label": get("label"),
            "inbound": inbound, "outbound": outbound, "flags": list(get("flags") or []),
            "swap_orders": _swap_orders(inbound + outbound)}


def _unverified(db: Session, run_id, identifiers: list[dict]) -> set[str]:
    run = db.get(TraceRun, run_id) if run_id else None
    if run is None:
        return set()
    ok = verified_addresses(run)
    return {i["address"] for i in identifiers if i["inbound"] and i["address"] not in ok}


def latest_inbound(case: Case, entity: Entity | None, since: datetime | None = None) -> Correspondence | None:
    """The counterparty's most recent inbound message (on or after `since`), e.g. an auto-acknowledgement."""
    if entity is None:
        return None
    rows = [c for c in case.correspondence if c.entity_id == entity.id and c.direction == CorrespondenceDirection.IN
            and c.occurred_at is not None and (since is None or _aware(c.occurred_at) >= _aware(since))]
    return max(rows, key=lambda c: (_aware(c.occurred_at), c.id), default=None)


def _their_ref(order: StopOrder | None, inbound: Correspondence | None) -> str | None:
    return (inbound.external_ref if inbound is not None else None) or (order.external_ref if order is not None else None)


def _order_status_line(order: StopOrder | None, now: datetime, inbound: Correspondence | None = None) -> str:
    """One line on where a request stands, for the LE cover letter. `inbound` is the counterparty's
    latest message since the request was sent (as the status request derives it)."""
    if order is None:
        return "not yet contacted"
    state = order_state(order)
    hold = hold_state(order)
    held = _amount_text(parse_amount(hold.get("amount")), hold.get("asset")) if hold.get("amount") else ""
    when = _fmt_day(datetime.fromisoformat(hold["at"]) if hold.get("at") else order.responded_at)
    if state == "draft":
        return "request drafted, not yet sent"
    if state == "sent":
        ref = _their_ref(order, inbound)
        ref_txt = f" (their reference {ref})" if ref else ""
        if inbound is not None:
            return (f"request sent {_fmt_day(order.sent_at)}; receipt acknowledged {_fmt_day(inbound.occurred_at)}"
                    f"{ref_txt}, no substantive answer yet")
        due = response_due(order)
        late = " (reply overdue)" if due and due < now else ""
        return f"request sent {_fmt_day(order.sent_at)}; no reply yet{late}"
    if state == "acknowledged":
        ref = _their_ref(order, inbound)
        return f"request acknowledged {_fmt_day(order.responded_at)}" + (f" (their reference {ref})" if ref else "")
    if state == "frozen":
        return f"hold confirmed {when}" + (f": {held}" if held else "")
    if state == RELEASED:
        return f"funds released {when}" + (f" ({held})" if held else "")
    if state == "declined":
        return f"request declined {_fmt_day(order.responded_at)}"
    return state


def _latest_order(case: Case, entity: Entity | None) -> StopOrder | None:
    if entity is None:
        return None
    orders = [o for o in case.stop_orders if o.entity_id == entity.id and order_state(o) != "superseded"]
    rank = {"frozen": 6, RELEASED: 5, "acknowledged": 4, "sent": 3, "declined": 2, "draft": 1}
    return max(orders, key=lambda o: (rank.get(order_state(o), 0), o.id), default=None)


def _resolve_ref(authority: Authority, ref: str | None, *, frozen: bool = False) -> dict | None:
    if frozen:
        orders = frozen_orders(authority)
        chosen = next((o for o in orders if ref == f"o{o.id}"), orders[-1] if orders else None)
        if chosen is None:
            return None
        corr = next((c for c in chosen.correspondence if c.kind == CorrespondenceKind.STOP_ORDER), None)
        return {"value": f"o{chosen.id}", "at": _aware(chosen.sent_at or chosen.created_at), "subject": chosen.subject,
                "order": chosen, "corr": corr}
    refs = sent_references(authority)
    return next((r for r in refs if r["value"] == ref), refs[0] if refs else None)


def _base_context(case: Case, authority: Authority, template: LetterTemplate, actor: User | None,
                  run: TraceRun | None, extra_note: str | None, now: datetime) -> dict:
    facts = case.facts or {}
    return {
        "case": case, "facts": facts, "sender": sender_profile(case, actor), "victim": _victim(case),
        "complaints": complaint_list(case), "entity_name": authority.name, "authority": authority,
        "salutation": "Sir or Madam" if authority.is_le else "Compliance / Legal Team",
        "loss_fmt": f"{_fmt_amt(case.loss_amount)} {case.loss_asset}" if case.loss_amount else None,
        "loss_usd_fmt": f"USD {_fmt_usd(case.loss_usd)}" if case.loss_usd else None,
        "fraud_date_fmt": case.fraud_date.strftime("%d %B %Y") if case.fraud_date else None,
        "origin": _origin(case), "generated_at": now.strftime("%d.%m.%Y %H:%M UTC"), "template_label": template.label,
        "run_ref": run.id if run else None, "extra_note": (extra_note or "").strip() or None,
        "reply_days": DEFAULT_RESPONSE_DAYS, "identifiers": [], "unverified": set(),
    }


def _context_status_request(db, case, authority, ctx, ref, now) -> dict:
    order, corr = ref["order"], ref["corr"]
    ident_src = (order.identifiers or {}).get("addresses") if order is not None else (corr.meta or {}).get("identifiers")
    chain = (order.identifiers or {}).get("chain") if order is not None else None
    identifiers = [_norm_ident(i, chain) for i in ident_src or []]
    tx_hashes = [h for h in ((order.identifiers or {}).get("tx_hashes") or [] if order is not None else [])
                 if isinstance(h, str) and not h.startswith("ASSERTED:")]
    run_id = (order.identifiers or {}).get("trace_run_id") or order.trace_run_id if order is not None else None
    replies = [c for c in authority.correspondence if c.direction == CorrespondenceDirection.IN and c.occurred_at
               and _aware(c.occurred_at) >= ref["at"]]
    last_in = max(replies, key=lambda c: (_aware(c.occurred_at), c.id)) if replies else None
    # their own ticket, when they gave one (an auto-acknowledgement), else the reference on our letter
    ext = ((last_in.external_ref if last_in is not None else None) or (order.external_ref if order is not None else None)
           or (corr.external_ref if corr is not None else None))
    order_ids = list(dict.fromkeys(
        [str(x) for x in ((order.identifiers or {}).get("order_ids") or [] if order is not None else [])]
        + [ref_ for i in identifiers for ref_ in i["swap_orders"]]))
    kind = order.kind if order is not None and (corr is None or corr.kind == CorrespondenceKind.STOP_ORDER) else None
    days = max(0, (now.astimezone(UTC).date() - ref["at"].astimezone(UTC).date()).days)  # calendar days
    ctx.update({
        "ref": {"date_fmt": _fmt_day(ref["at"]), "subject": " ".join((ref["subject"] or "").split()),
                "external_ref": ext, "channel": (corr.channel.value if corr is not None else order.sent_via) or None,
                "description": ORDER_KIND_PHRASE.get(kind or "", "a letter") if kind else
                (f"our {KIND_LABELS.get(corr.kind.value, 'letter').lower()}" if corr is not None else "a letter"),
                "last_reply_fmt": _fmt_day(max(_aware(c.occurred_at) for c in replies)) if replies else None,
                "held": hold_state(order) if order is not None else {}},
        "days_elapsed": days, "identifiers": identifiers, "tx_hashes": tx_hashes, "order_ids": order_ids,
        "unverified": _unverified(db, run_id, identifiers),
        "subject": f"Status request – our letter of {_fmt_day(ref['at'])}: {' '.join((ref['subject'] or '').split())}"
                   [:500],
    })
    return ctx


def _is_row_ref(row, ref: str | None) -> bool:
    """`ref` names this block row: its own key (o12 / c5), or one of the letters it carried (the c<id> a stop order's
    logged sending, or a follow-up, has in the "Answer their reply to" choice)."""
    if not ref:
        return False
    if row.key == ref:
        return True
    ids = {f"c{c.id}" for c in [row.letter, *row.outbound] if c is not None}
    if row.order is not None:
        ids |= {f"c{c.id}" for c in row.order.correspondence or []}
    return ref in ids


def _context_info_response(db, case, authority, ctx, ref, now) -> dict:
    """The answer to a provider's reply on one request (`ref`: its block-status key; default: this provider's request
    with the latest reply): their ticket, what they asked (each ask: enclosed when on file, else to follow), their
    deadline, the identifiers, and — when they hold the funds — the ask to keep the hold while LE files."""
    from app.blocks import path as pathmod
    from app.blocks import status as bs
    from app.domain import evidence_requirements as er

    rows = [r for r in bs.case_blocks(db, case, now=now) if r.authority.key == authority.key and r.deciding is not None]
    row = next((r for r in rows if _is_row_ref(r, ref)), None) if ref else None
    if ref and row is None:  # never silently the answer to another request (its ticket, identifiers, deadline)
        raise DeskError("That letter has no reply to answer yet: pick the letter whose reply you answer.")
    row = row or max(rows, key=lambda r: r.deciding.at, default=None)
    if row is None:
        raise DeskError("No reply from this counterparty to answer yet.")
    st, d, intel = row.path, row.deciding, row.intel
    order = row.order
    ids_src = (order.identifiers or {}) if order is not None else ((row.letter.meta or {}) if row.letter else {})
    identifiers = [_norm_ident(i, ids_src.get("chain")) for i in (ids_src.get("addresses") or ids_src.get(
        "identifiers") or [])][:12]
    tx = [h for h in ids_src.get("tx_hashes") or [] if isinstance(h, str) and not h.startswith("ASSERTED:")][:12]
    ticket = row.ticket or next((t.get("value") for t in intel.get("tickets") or [] if t.get("value")), None)
    h = er.holdings(db, case, run=None)
    keys = [a["req_key"] for a in intel.get("asks") or [] if a.get("req_key")]
    have = {e["key"]: e for e in er.check(h, keys, tickets=[ticket] if ticket else [], cited=bool(identifiers))}
    refs = [c["reference"] for c in ctx["complaints"] if c.get("reference")]
    asks = []
    for a in intel.get("asks") or []:
        k, lab = a.get("req_key"), a.get("label") or (a.get("req_key") or "").replace("_", " ")
        if not lab:
            continue
        e = have.get(k) or {}
        if k in ("police_report", "complaint_ref") and refs:
            answer = f"enclosed (the police report receipt; reference {', '.join(refs[:3])})"
        elif k in ("tx_list_copyable", "receiving_account", "provider_ids") and (identifiers or tx):
            answer = "listed below"
        elif e.get("state") == "have":
            answer = "enclosed"
        elif k == "freeze_duration_stmt":
            answer = "law enforcement will state the duration in its request"
        else:
            answer = "to follow as soon as we have it"
        asks.append({"label": _cap(lab), "answer": answer})
    ask = pathmod.our_ask(row, now)
    due = ask["due_at"] if ask is not None else (row.next_deadline or {}).get("due_at")
    held = st is not None and st.freeze_at is not None
    le_clock = next((c for c in row.clocks if c.get("by") == "le" and c.get("what") in pathmod.ACTION_WHAT
                     and not c.get("met") and c["due_at"] > now), None)
    keep = None
    if held:
        # "has been asked" only once an LE / counsel brief on this request went out after their reply
        briefed = any(ln.get("sent") and ln.get("at") and _aware(ln["at"]) >= _aware(d.at)
                      for ln in (st.links if st is not None else []))
        by = f" by {_fmt_ts(le_clock['due_at'])}" if le_clock else ""
        keep = ((f"Law enforcement has been asked to send its own request{by}." if briefed else
                 f"We are briefing law enforcement now so that it sends its own request{by}.")
                + " We respectfully ask you to keep the temporary freeze in place, and to extend it if the officer's "
                  "access to your law-enforcement channel is not yet approved by then.")
    # the funds moved to another account / deposit address on their own platform: ask them to hold that one too (the
    # same custodian aliases as the Recovery plan: a UID at another exchange is never "on your platform")
    from app.blocks import recovery as rp

    orgs, _by = rp._custodians([])
    extend = list(dict.fromkeys(x for dst in pathmod.destinations(row, orgs) if dst["where"] == "own"
                                for x in [*dst["accounts"], dst["value"]]))
    ctx.update({
        "ans": {"ticket": ticket, "reply_fmt": _fmt_day(d.at), "sent_fmt": _fmt_day(row.requested_at), "held": held,
                "asks": asks, "deadline_fmt": _fmt_ts(due) if due else None, "keep": keep, "extend": extend,
                # their own stated deadline, or the playbook's (MEXC: 48 hours from our submission, earlier than the
                # 48 hours from their message): never attributed to their message
                "deadline_theirs": due is not None and (ask or row.next_deadline or {}).get("source") != "playbook"},
        "identifiers": identifiers, "tx_hashes": tx, "order_ids": [],
        "unverified": _unverified(db, (ids_src.get("trace_run_id") or getattr(order, "trace_run_id", None)),
                                  identifiers),
        "subject": ((f"Your ticket {ticket} – " if ticket else "")
                    + f"our answer to your message of {_fmt_day(d.at)}"
                    + (f" (deadline {_fmt_ts(due)})" if due else ""))[:500],
    })
    ctx["_row"] = row
    return ctx


def _fmt_ts(v: datetime | None) -> str:
    return _aware(v).astimezone(UTC).strftime("%d.%m.%Y %H:%M UTC") if v else ""


_FREEZE_ADDR = re.compile(r"(?:(ethereum|tron|bitcoin|evm|bsc|polygon|arbitrum|base|optimism|avalanche|solana):)?"
                          r"([A-Za-z0-9]{20,100})")


def freeze_key(chain: str | None, address: str) -> str:
    """A freeze target as an info request's `meta["freeze"]` records it: "<chain>:<address>" (an EVM address
    lower-cased; no chain prefix when the request named none)."""
    a = (address or "").strip()
    a = a.lower() if a[:2].lower() == "0x" else a
    c = (chain or "").strip().lower()
    return f"{c}:{a}" if c else a


def freeze_address(corr: Correspondence) -> str | None:
    """The deposit address an outgoing letter asks to freeze (`meta["freeze"]`), lower-cased; else None."""
    v = (corr.meta or {}).get("freeze")
    return str(v).rsplit(":", 1)[-1].strip().lower() or None if v else None


def _context_info_request(db, case, authority, ctx, run, freeze: str | None = None, ref: str | None = None) -> dict:
    """An information / preservation request; `freeze` ("<chain>:<address>"): a deposit address a reply names as where
    the funds went (the Recovery plan): an urgent freeze request for the account it credits, the address first among
    the identifiers. With `ref` (a request already sent to it): the new deposit as a follow-up of that request (its
    date and ticket quoted), still a freeze request of its own."""
    facts = case.facts or {}
    name = authority.name.lower()
    iocs = [f"{i.get('provider')}: {i.get('detail')}" for i in facts.get("infrastructure") or []
            if str(i.get("provider", "")).lower() == name or name.startswith(str(i.get("provider", "")).lower() + " ")]
    identifiers = [_norm_ident(i) for i in (authority.candidate.identifiers if authority.candidate else [])]
    if not identifiers and run is not None and authority.entity is not None:
        identifiers = [_norm_ident({"chain": n.address.chain.value, "address": n.address.address,
                                    "address_type": n.address.address_type.value, "label": n.address.label})
                       for n in run.nodes if n.address.entity_id == authority.entity.id and (n.taint_usd or 0) > 0][:10]
    cat = authority.category
    if cat in ("hosting", "infra"):
        records = [
            ("Subscriber / account-holder details for the resources listed above: name, e-mail, phone, sign-up date "
            "and sign-up IP."),
            "Access and API logs with IP addresses, timestamps and user-agents for those resources.",
            "Billing and payment records, including the payment instrument used.",
            "Any other projects, keys, domains or accounts linked to the same account, e-mail, payment method or IP.",
            ("Preservation of the content and configuration of the resources (files, functions, logs) pending formal "
            "process."),
        ]
    elif authority.non_custodial:
        records = [
            ("Whether an interface, API or routing service operated by you processed the transactions listed below "
            "and, if so, the associated IP addresses, user-agents and timestamps."),
            "Any off-chain record you hold that identifies the recipient of the swap output.",
        ]
    elif authority.is_le:
        records = [
            "The status of the complaint and the name of the investigating unit.",
            "Your requirements for receiving our forensic report and supporting evidence.",
        ]
    else:
        records = RECORDS_BY_CATEGORY.get(cat, DEFAULT_RECORDS)
    fz = _FREEZE_ADDR.fullmatch((freeze or "").strip()) if freeze and not authority.non_custodial else None
    target = None
    if fz is not None:
        target = _norm_ident({"chain": fz.group(1) or "", "address": fz.group(2), "address_type": "deposit",
                              "label": "the deposit address the funds were moved to"})
        identifiers = [target] + [i for i in identifiers if i["address"].lower() != target["address"].lower()]
    earlier = next((r for r in sent_references(authority) if r["value"] == ref or (
        r["order"] is not None and f"o{r['order'].id}" == ref)), None) if target is not None and ref else None
    follow = None
    if earlier is not None:
        order = earlier["order"]
        follow = {"date_fmt": _fmt_day(earlier["at"]), "external_ref": (order.external_ref if order is not None else None)
                  or (earlier["corr"].external_ref if earlier["corr"] is not None else None)}
    ctx.update({
        "iocs": iocs, "identifiers": identifiers, "records": records, "non_custodial": authority.non_custodial,
        "unverified": _unverified(db, run.id if run else None, identifiers), "freeze": target, "follow_up": follow,
        "subject": (f"Urgent: new deposit {target['address']} – freeze – further to our letter of {follow['date_fmt']}"
                    if target and follow else
                    f"Urgent freeze request – deposit address {target['address']} – {authority.name}" if target else
                    f"Information and preservation request – {authority.name}")[:500],
    })
    return ctx


_PLAN_BUSY: ContextVar[bool] = ContextVar("le_cover_plan_busy", default=False)


def _plan_for(db, case, run, now):
    """The Recovery plan (app.blocks.recovery.build) when the letter cites the latest trace run, for the cover letter's
    "where the funds sit": the same figure per service as the plan's moves (an issuer wallet the trace saw forward
    everything on holds no amount) and its total, each traced dollar once. None for an older run, inside a plan being
    built, or when the plan fails: the letter then cites the trace's candidates as before."""
    if _PLAN_BUSY.get() or run is None:
        return None
    latest = services.latest_run(db, case)
    if latest is None or latest.id != run.id:
        return None
    from app.blocks import recovery as rp

    token = _PLAN_BUSY.set(True)
    try:
        return rp.build(db, case, now=now)
    except Exception as err:  # noqa: BLE001 - a DB error's text carries bound parameters: log the type only
        log.warning("LE cover letter: recovery plan failed for case %s (%s)", case.id, type(err).__name__)
        return None
    finally:
        _PLAN_BUSY.reset(token)


def _plan_amount(st, taint: Decimal) -> tuple[str | None, float]:
    """(the cover letter's amount line for a service, its sort value) from the plan's Stake (app.blocks.recovery)."""
    if st is None:
        return None, float(taint)
    if st.moved_on and not st.usd:
        return (f"received up to USD {taint:,.2f} (traced), but the trace saw the funds leave "
                f"{', '.join(st.moved_on)}: the current balance is unknown and no amount is counted here"), 0.0
    if st.confirmed:
        line = f"USD {st.confirmed:,.2f} read on-chain, not frozen"
        if st.unconfirmed:
            line += f", plus up to USD {st.unconfirmed:,.2f} traced (upper bound)"
        return line, st.confirmed + st.unconfirmed
    if st.usd:
        return f"up to USD {st.usd:,.2f} traced (upper bound)", float(st.usd)
    return None, float(taint)


def _context_le_cover(db, case, authority, ctx, run, now) -> dict:
    own = next((c.reference for c in authority.le_contacts if c.reference), None)
    services_ = []
    plan = _plan_for(db, case, run, now)
    if run is not None:
        verified = verified_addresses(run)
        for cand in freeze_candidates(db, run):
            receiving = [i for i in cand.identifiers if i.inbound]
            suspected = bool(receiving) and all(i.address not in verified for i in receiving)
            latest = _latest_order(case, cand.entity)
            idents = [_norm_ident(i) for i in cand.identifiers]
            # swap-order references: the same source the stop-order generator cites, plus the order's own record
            order_ids = list(dict.fromkeys(
                [ref_ for i in idents for ref_ in i["swap_orders"]]
                + [str(x) for x in ((latest.identifiers or {}).get("order_ids") or [] if latest is not None else [])]))
            inbound = latest_inbound(case, cand.entity, latest.sent_at) if latest is not None and latest.sent_at else None
            st = plan.stakes.get(f"entity-{cand.entity.id}") if plan is not None and cand.entity is not None else None
            amount, value = _plan_amount(st, cand.total_taint_usd)
            services_.append({
                "name": cand.entity_name, "type_label": TYPE_LABELS.get(cand.category, cand.category),
                "jurisdiction": cand.entity.jurisdiction if cand.entity else None,
                "taint_usd": f"{cand.total_taint_usd:,.2f}", "amount": amount, "suspected": suspected,
                "identifiers": idents[:6], "order_ids": order_ids,
                "status": _order_status_line(latest, now, inbound), "_value": value,
            })
        if plan is not None:  # the plan's order: the most money first, a wallet that moved everything on last
            services_.sort(key=lambda s: -s["_value"])
            ctx["in_play"] = (f"{plan.totals['in_play_usd']:,.2f}" if plan.totals.get("in_play_usd") and len(services_) > 1
                              else None)
        tainted_from = {e.transfer.from_address_id for e in run.edges if (e.taint_usd or 0) > 0}
        dormant = [n for n in run.nodes if (n.taint_usd or 0) > 0 and not n.is_terminal and n.address.entity_id is None
                   and n.address.address_type.value != "victim" and n.address_id not in tainted_from
                   and not n.address.address.endswith("_PENDING")
                   and not {"pending_input", "context_only"} & set(n.flags or [])]
        dormant.sort(key=lambda n: -(n.taint_usd or 0))
        ctx["dormant"] = [{"chain": n.address.chain.value, "address": n.address.address,
                           "taint_usd": f"{n.taint_usd:,.2f}"} for n in dormant[:5]]
        ctx["run_date"] = _fmt_day(run.finished_at or run.started_at)
    facts = case.facts or {}
    ctx.update({
        "own_reference": own, "services": services_, "iocs": [f"{i.get('provider')}: {i.get('detail')}"
                                                              for i in facts.get("infrastructure") or []],
        "other_complaints": [c for c in ctx["complaints"] if c.get("reference") != own],
        "subject": ("Fund-flow summary and freeze opportunities" + (f" – your reference {own}" if own else
                    f" – cryptocurrency fraud of {_fmt_day(case.fraud_date)}"))[:500],
    })
    ctx.setdefault("dormant", [])
    ctx.setdefault("run_date", None)
    ctx.setdefault("in_play", None)
    return ctx


def _context_release(db, case, authority, ctx, ref) -> dict:
    order = ref["order"]
    hold = hold_state(order)
    held_at = datetime.fromisoformat(hold["at"]) if hold.get("at") else order.responded_at
    identifiers = [_norm_ident(i, (order.identifiers or {}).get("chain"))
                   for i in (order.identifiers or {}).get("addresses") or []]
    ctx.update({
        "ref": {"date_fmt": _fmt_day(ref["at"]), "subject": " ".join((order.subject or "").split()),
                "external_ref": order.external_ref},
        "hold": {"date_fmt": _fmt_day(held_at), "amount": hold.get("amount"), "asset": hold.get("asset")},
        "identifiers": identifiers,
        "unverified": _unverified(db, (order.identifiers or {}).get("trace_run_id") or order.trace_run_id, identifiers),
        "subject": (f"Request for release of held funds – {authority.name}"
                    + (f" – your reference {order.external_ref}" if order.external_ref else ""))[:500],
    })
    return ctx


def brief_candidates(db: Session, case: Case) -> list[dict]:
    """The provider requests an LE / counsel brief can follow up (app.blocks.status rows with a path step), the most
    pressing first (LE process required, a hold, an acknowledgement from a provider that acts only on LE process):
    [{value: request key, label, row}]."""
    from app.blocks import path as pathmod
    from app.blocks import status as bs

    rows = [r for r in bs.case_blocks(db, case) if r.path is not None and r.path_step is not None]
    hot = ("le_only_redirect", "hold_discretionary", "provider_ack", "provider_ask", "notice_sent")
    rows.sort(key=lambda r: (r.path_step not in hot, hot.index(r.path_step) if r.path_step in hot else 0,
                             not r.path.handoff, -pathmod.RANK[r.path_step]))
    return [{"value": r.key, "label": f"{r.authority.name} – {r.title} ({r.path.label})", "row": r} for r in rows]


# what the LE request must state (EVIDENCE keys a letter states: app.domain.evidence_requirements.LETTER)
BRIEF_STATEMENTS = {
    "freeze_duration_stmt": "The request must state how long the restriction lasts: {name} lifts a freeze whose "
                            "duration is not stated{after}.",
    "non_disclosure_stmt": "Ask {name} not to inform the account holder: it tells the user otherwise.",
    "native_vs_bridged_stmt": "Name the token and its contract: {name} controls only the native token on each chain, "
                              "not a bridged variant (such as USDC.e).",
    "urgency_stmt": "Mark it urgent (Exigent / URGENT REQUEST): the funds can move at any moment.",
    "english_version": "Send it in English (or with an English version).",
}
COURT_INSTRUMENTS = frozenset({"court_order", "us_or_fr_court_order", "freezing_order", "seizure_warrant",
                               "judicial_decision", "subpoena"})


def _cap(s: str) -> str:
    return s[:1].upper() + s[1:] if s else s


def _brief_request(name: str, ins: dict, route: dict, st, *, jur: str | None, via: str, ticket: str) -> str:
    """The brief's request, worded by the instrument and the route: the police never "send a court order"."""
    from app.blocks import path as pathmod

    judicial = st.le is not None and st.le.role == "judicial"
    who = "you" if judicial else "the competent prosecutor"
    if route.get("kind") == "cross_border" and route.get("options"):
        o = route["options"][0]
        to = "/".join(o.get("to") or []) or "the provider's state"
        lead = "We respectfully ask you" if judicial else "We respectfully ask you to bring this to the prosecutor and ask"
        if o["type"] == "eu_freezing_order":
            return (f"{lead} to obtain a domestic freezing order (decreto di sequestro preventivo) naming the addresses "
                    f"above and to issue a Reg. (EU) 2018/1805 freezing certificate to the executing authority in {to}, "
                    "stating that immediate freezing is necessary (Art. 9(3): 48 hours to recognise; Art. 9(4): 48 "
                    f"hours to execute), so that {name} is served by an authority it acts on{ticket}.")
        if o["type"] == "mlat":
            return (f"{lead} to request the freeze from {to} through mutual legal assistance (MLAT) on a domestic "
                    f"freezing order naming the addresses above{ticket}; the MLAT takes months, so pair it with a faster "
                    "route where one exists.")
        if o["type"] == "counsel":
            return (f"{name} acts only on {pathmod._label(o.get('instrument'))}: we are instructing counsel for it; we "
                    "ask you to confirm the criminal proceedings and share the case reference counsel can cite.")
        return f"{lead} to request the measure from {to} ({o['text']}), naming the addresses above{ticket}."
    itype = ins.get("type")
    label = ins.get("label") or "a formal request"
    if pathmod.le_issued(st):  # a freezing order LE sends itself (Binance, MEXC, KuCoin): no court application first
        return (f"We respectfully ask you to send {name} a freezing order / freeze request on official letterhead "
                f"naming the addresses above{via}{ticket}, so that the funds are held before they move further: "
                f"{name} accepts it from law enforcement, with no court application first. We can supply anything "
                "listed above that is not attached.")
    if itype in COURT_INSTRUMENTS:
        apply = ("to apply to the competent court" if judicial else
                 f"to ask {who} to apply to the competent court")
        urgent = route.get("urgent") if route.get("kind") == "direct" else None
        first = (f"As a first step, we respectfully ask you to send {name} {urgent['label']} to block the addresses "
                 f"above pending a court order{via}{ticket}: {name}'s policy provides for an urgent law-enforcement "
                 "request pending a valid order. Then, we ask you " if urgent else "We respectfully ask you ")
        return (f"{first}{apply} for {label}{f' ({jur})' if jur else ''} naming the addresses above "
                f"with particularity, and to serve it on {name}{via}{ticket}, so that the funds are held before they "
                "move further. We can supply anything listed above that is not attached.")
    return (f"We respectfully ask you to send {name} {label}{via}{ticket}, so that the funds are held before they move "
            "further. We can supply anything listed above that is not attached.")


def _context_brief(db, case, authority, ctx, ref, *, counsel: bool = False) -> str:
    """The LE / counsel brief about one provider request (`ref`: its key, e.g. "o12"; default: the most pressing)."""
    from app.blocks import extract as ex
    from app.blocks import path as pathmod
    from app.blocks import status as bs

    cands = brief_candidates(db, case)
    chosen = next((c for c in cands if c["value"] == ref), None) if ref else (cands[0] if cands else None)
    if chosen is None:
        raise DeskError("No provider request to brief on: send a request first (or pick one of this case's requests).")
    row, st = chosen["row"], chosen["row"].path
    name, d = row.authority.name, row.deciding
    ins = st.instrument or {}
    intel = row.intel
    quote = ((intel.get("instrument") or {}).get("quote") or (d.quote if d is not None else None)
             or (ex._quote(d.own) if d is not None and d.own else None))
    if d is not None and st.freeze_at is not None and d.own:  # a hold: quote its own sentence (and its clock)
        from app.blocks import classify_rules as rules

        held = [x for _, x in rules.sentences(d.own) if pathmod.temp_freeze_stated(x)]
        quote = ex._quote(held[0]) if held else quote
    t = st.target
    route = st.route or {}
    cpath = None
    if counsel and row.playbook is not None:  # counsel's own route: the court-order path's channel and evidence
        c = route.get("counsel") or pathmod._counsel(row.playbook, list(route.get("acts_on") or []))
        cpath = row.playbook.path(c["path"]) if c else None
    if cpath is not None:
        t = cpath
        ins = {"type": t.instrument.type, "label": pathmod._label(t.instrument.type),
               "issuer_jurisdictions": list(t.instrument.issuer_jurisdictions), "source": "playbook"}
    org = bs._org(row.org_key)
    keys = getattr(t, "channel_keys", ()) or ()
    chans = [c for c in getattr(org, "channels", ()) or () if c.key in keys]
    chans = ([c for c in chans if c.who != "le_only"] if counsel else [c for c in chans if c.who == "le_only"]) or (
        [] if counsel else chans)
    named = {(u.get("value") or "").lower() for u in (intel.get("channels") or []) if u.get("value")}
    pick = [c for c in chans if c.value and any(c.value.lower() in v or v in c.value.lower() for v in named)]
    chans = pick or chans[:1]  # the channel their reply named, else the provider's main LE channel
    channels = [(c.label or c.key) + (" (LE only)" if c.who == "le_only" else "")
                + ("" if c.value else f" — not published: {'counsel' if counsel else 'the officer'} confirms it with "
                   + name) for c in chans]
    via = f" through {channels[0]}" if channels else ""
    onboard = getattr(getattr(t, "timing", None), "portal_onboarding_days", None)
    if channels and onboard:  # MEXC's LEORS: weeks to approve an officer, against a 48-hour clock
        channels[0] += (f" — access for a new officer takes about {onboard:g} days to approve: register at once, and "
                        "see the clock below for what keeps the hold meanwhile")
    order_ids = ((row.order.identifiers or {}) if row.order is not None else
                 ((row.letter.meta or {}) if row.letter is not None else {}))
    addresses = [_norm_ident(i, order_ids.get("chain")) for i in (order_ids.get("addresses") or order_ids.get(
        "identifiers") or [])][:12]
    amounts = [f"{_cap(k.replace('_', ' '))}: {v}" for k, v in (order_ids.get("amounts") or {}).items()
               if isinstance(v, str)][:6]
    for e in (row.onchain or {}).get("unfrozen_balance") or []:
        amounts.append(f"{e['short']} ({e['chain_label']}) holds {e['balance_label']} {e['symbol']}, not frozen")
    if row.amount and row.source in ("recorded", "human"):
        amounts.append(f"Held by {name} (confirmed): {row.amount} {row.asset or ''}".strip())
    # one line per deadline: their reply's and the playbook's readings of the same time merge (MEXC's 48 hours: the
    # victim's receipt and LE's request), the officer's own action first
    groups: dict[datetime, list[dict]] = {}
    for c in row.clocks:
        if c["due_at"] <= _now() or c.get("met"):
            continue
        groups.setdefault(c["due_at"].replace(minute=0, second=0, microsecond=0), []).append(c)
    clocks = []
    for _due, cs in sorted(groups.items(), key=lambda kv: kv[0]):
        cs = sorted(cs, key=lambda c: (c.get("by") != "le", c.get("source") != "playbook"))
        c = cs[0]
        acts = list(dict.fromkeys(x["action"].rstrip(".") for x in cs if x.get("action")))
        clocks.append(f"{_cap(c['label'])} {c['due_at']:%d %b %Y %H:%M} UTC"
                      + (f" ({c['span']} after {c['starts_label']})" if c.get("span") else " (stated in their reply)")
                      + (f": {'. '.join(acts)}." if acts else ""))
    clocks = clocks[:4]
    tx = [h for h in order_ids.get("tx_hashes") or [] if isinstance(h, str) and not h.startswith("ASSERTED:")][:6]
    # what LE's request needs, not the victim's ticket; counsel: what the court-order path needs
    need = pathmod._evidence(cpath) if cpath is not None else st.le_evidence or st.evidence
    if not row.ticket:  # no ticket was captured: never list one as required
        need = [e for e in need if e["key"] != "prior_ticket_ref"]
    letter_keys = [e["key"] for e in need if e["key"] in BRIEF_STATEMENTS]
    days = getattr(getattr(t, "timing", None), "auto_lift_days", None)
    statements = [BRIEF_STATEMENTS[k].format(name=name, after=f" (after {days:g} days)" if days else "")
                  for k in letter_keys]
    jur = "/".join(ins.get("issuer_jurisdictions") or (() if cpath is not None else route.get("acts_on")) or []) or None
    xb = route.get("kind") == "cross_border" and not counsel  # LE's cross-border route: not counsel's
    tk = f", quoting their ticket {row.ticket}" if row.ticket else ""
    request = _brief_request(name, ins, route, st, jur=jur, via=via, ticket=tk)
    ctx.update({
        "counsel": counsel, "own_reference": next((c.reference for c in authority.le_contacts if c.reference), None),
        **({"salutation": "Counsel"} if counsel else {}),
        "p": {"name": name, "ticket": row.ticket, "sent_fmt": _fmt_day(row.requested_at),
              "reply_fmt": _fmt_day(d.at) if d is not None else None, "status": d.label if d is not None else None,
              "quote": quote, "instrument": ins.get("label"),
              "jur": jur,
              "jur_intro": None if ins.get("type") == "us_or_fr_court_order" else
              "/".join(ins.get("issuer_jurisdictions") or []) or None,
              "signing": ("not digitally signed (a signed scan; digital signatures refused)"
                          if t is not None and t.instrument.signing == "not_digital" else None),
              "language": ", ".join(t.instrument.language).upper() if t is not None and t.instrument.language else None,
              "channels": channels, "le_only": any("(LE only)" in c for c in channels),
              # the provider acts on LE process only (its reply or its playbook: pathmod.le_only); else the letter says
              # the formal route, never that the provider "requires" it (Block status words it the same way)
              "required": counsel or pathmod.le_only(st, row.playbook),
              "evidence": [_cap(e["label"]) for e in need if e["key"] not in BRIEF_STATEMENTS],
              "statements": statements, "request": request,
              "route": (f"{name} acts directly only on {'/'.join(route.get('acts_on') or [])} authorities and courts, "
                        f"so a request from {route.get('jur')} goes cross-border:" if xb else None),
              "options": [o["text"][0].upper() + o["text"][1:] for o in route.get("options") or []] if xb else [],
              "addresses": addresses, "tx_hashes": tx, "amounts": amounts, "clocks": clocks},
        "subject": ((f"{name} requires {ins.get('label') or 'law-enforcement process'}"
                     if counsel or pathmod.le_only(st, row.playbook) else
                     f"{name}: {ins.get('label') or 'law-enforcement process'} to hold the funds")
                    + (f" – their ticket {row.ticket}" if row.ticket else "")
                    + f" – our request of {_fmt_day(row.requested_at)}")[:500],
    })
    return row.key


def build_letter(db: Session, case: Case, authority: Authority, template_key: str, *, actor: User | None = None,
                 run: TraceRun | None = None, ref: str | None = None, extra_note: str | None = None,
                 now: datetime | None = None, freeze: str | None = None) -> tuple[str, str, dict]:
    """Render a non-stop-order letter: (subject, body_markdown, references). `freeze`: the info request's freeze
    address (`_context_info_request`)."""
    template = LETTER_TEMPLATES.get(template_key)
    if template is None or template_key == "stop_order":
        raise DeskError(f"unknown letter template {template_key!r}")
    now = now or _now()
    ctx = _base_context(case, authority, template, actor, run, extra_note, now)
    refs: dict = {}
    if template_key == "status_request":
        chosen = _resolve_ref(authority, ref)
        if chosen is None:
            raise DeskError("Nothing has been sent to this counterparty yet.")
        _context_status_request(db, case, authority, ctx, chosen, now)
        refs = {"references": chosen["value"]}
        if chosen["order"] is not None:
            refs["stop_order_id"] = chosen["order"].id
    elif template_key == "info_response":
        _context_info_response(db, case, authority, ctx, ref, now)
        row = ctx.pop("_row")
        refs = {"references": row.key}
        if row.order is not None:
            refs["stop_order_id"] = row.order.id
    elif template_key == "info_request":
        _context_info_request(db, case, authority, ctx, run, freeze, ref)
        if ctx.get("freeze"):  # the deposit address it asks to freeze (what the request gate's `cites` reads)
            refs = {"freeze": freeze_key(ctx["freeze"]["chain"], ctx["freeze"]["address"])}
            if ctx.get("follow_up") and ref:  # a follow-up quoting a sent request (request_gate: stale after its reply)
                refs["references"] = ref
    elif template_key == "le_cover":
        _context_le_cover(db, case, authority, ctx, run, now)
    elif template_key == "release_request":
        chosen = _resolve_ref(authority, ref, frozen=True)
        if chosen is None:
            raise DeskError("No hold has been confirmed by this counterparty.")
        _context_release(db, case, authority, ctx, chosen)
        refs = {"references": chosen["value"], "stop_order_id": chosen["order"].id}
    elif template_key in BRIEF_TEMPLATES:
        key = _context_brief(db, case, authority, ctx, ref, counsel=template_key == "counsel_brief")
        refs = {"references": key, "follow_up_of": key}  # the provider request it follows up (app.blocks.status)
    body = render_letter(template_key, **ctx)
    return ctx["subject"], body, refs


SIGNATURE_OPENERS = ("Yours respectfully,", "Yours faithfully,", "Yours sincerely,", "Kind regards,")


def insert_before_signature(body: str, note: str) -> str:
    """`note` (plain text, Markdown-escaped like every value in the form letters) as its own
    paragraph right before the letter's closing formula; appended when the letter has none."""
    note = md_escape((note or "").strip()) if (note or "").strip() else ""
    if not note:
        return body
    at = max(body.rfind(o) for o in SIGNATURE_OPENERS)
    if at < 0:
        return body.rstrip("\n") + "\n\n" + note + "\n"
    return body[:at] + note + "\n\n" + body[at:]


_FREEZE_ASK = re.compile(r"\b(?:freez\w*|blacklist\w*|block(?:ed|ing|s)?\b)", re.IGNORECASE)


def asks_freeze(template_key: str, authority: Authority, about, *, freeze: str | None = None,
                note: str | None = None) -> bool:
    """An information request to a provider that asks it to freeze an account (`meta["asks_freeze"]`, read by
    freeze_board._asks_freeze and the request gate): its deposit to freeze (`freeze`), or a paragraph asking for a
    freeze / block / blacklist of an address it concerns (the hot-wallet owner letter: "identify the customer account
    they were credited to, freeze it"; an issuer's blacklist request). A records-only request (swap order records, a
    host's preservation) is none."""
    if template_key != "info_request" or authority.is_le or authority.is_adviser or authority.non_custodial:
        return False
    return bool(freeze) or (bool(about) and bool(_FREEZE_ASK.search(note or "")))


class GateRefused(DeskError):
    """The request gate (app.domain.request_gate) refused the letter: `decision` says what instead (the open draft, the
    address added to it, a follow-up, the LE brief, or the requests could not be read)."""

    def __init__(self, decision):
        super().__init__(decision.text or "one open request per provider: nothing drafted")
        self.decision = decision


def generate_letter(db: Session, case: Case, authority: Authority, template_key: str, *, actor: User | None,
                    run: TraceRun | None = None, ref: str | None = None, extra_note: str | None = None,
                    now: datetime | None = None, freeze: str | None = None, about=None,
                    replace: set[str] | None = None) -> Correspondence:
    """Save a generated letter as a draft outbound correspondence row (the caller audits).

    Every letter to a provider passes the request gate first (app.domain.request_gate: one open request per provider;
    raises GateRefused with its decision — an ADD_TO_DRAFT decision is the caller's to apply, request_gate
    .add_to_draft). `about`: the chain:address list the letter concerns (with `freeze`, recorded as `meta.about`; an
    address its body does not name gets a sentence before the signature). `replace`: the draft keys the person
    confirmed this letter supersedes (the authority page's "replaces draft #N"): a replaced letter draft is marked
    `meta.superseded_by` and its `about` addresses are carried into the stop order.

    `stop_order` reuses the freeze-candidate generator (services.generate_stop_orders), which also
    creates the stop-order row and supersedes this entity's earlier generated drafts; it cites the deposits the
    Recovery plan's owner moves attribute to this counterparty and no request cites yet (app.blocks.recovery
    .owner_deposits), like the tab's generator: one letter asks to freeze both."""
    now = now or _now()
    from app.domain import evidence_requirements as er
    from app.domain import request_gate as rg
    from app.domain import sender as sender_mod

    option = next((o for o in template_options(authority, run, sender_mod.requester_kind(db, case),
                                               er.held_instruments(case, er.provider_names(authority)))
                   if o["key"] == template_key), None)
    if option is None:
        raise DeskError(f"unknown letter template {template_key!r}")
    if not option["available"]:
        raise DeskError(option["reason"])
    about = rg.norm_about([*([freeze] if freeze and template_key == "info_request" else []), *rg.norm_about(about)])
    replace = set(replace or ())
    d = rg.gate(db, case, authority, template_key, about=about, ref=ref, replace=replace, now=now)
    if not d.allowed:
        raise GateRefused(d)
    replaced = [c for c in authority.correspondence if f"c{c.id}" in replace and c.status == CorrespondenceStatus.DRAFT
                and c.direction == CorrespondenceDirection.OUT and c.stop_order_id is None]
    # the drafts this letter supersedes (a stop order: the entity's draft stop orders too): never one whose e-mail is
    # prepared or under way — it could still be sent next to the new letter (the gate read it before the e-mail was)
    olds = [o for o in authority.stop_orders if o.status == StopOrderStatus.DRAFT and (
        f"o{o.id}" in replace or o.origin != StopOrderOrigin.IMPORTED)] if template_key == "stop_order" else []
    busy = services.mail_pending(db, olds, replaced) if olds or replaced else None
    if busy is not None:
        raise GateRefused(rg.Decision(rg.OPEN_EXISTING, template=template_key, who=authority.name,
                                      text=services.mail_pending_text(busy)))
    template = LETTER_TEMPLATES[template_key]
    sender = sender_profile(case, actor)
    meta = {"template_key": template_key, "format": "markdown", "generated_at": now.isoformat(), "source": "generated",
            "trace_run_id": run.id if run else None}
    if template_key == "stop_order":
        run = authority.candidate_run or run  # an earlier run when the latest no longer reaches it (letter_run)
        meta["trace_run_id"] = run.id if run else None
        from app.blocks import recovery as rp

        name = authority.candidate.entity_name
        # a replaced records-only letter (no freeze ask: a swap order's records) keeps its ask in the stop order
        carried = [(k.rpartition(":")[0], k.rpartition(":")[2],
                    *(() if (c.meta or {}).get("freeze") or (c.meta or {}).get("asks_freeze") else ("records",)))
                   for c in replaced
                   for k in rg.norm_about([*((c.meta or {}).get("about") or []),
                                           *([c.meta["freeze"]] if (c.meta or {}).get("freeze") else [])])]
        deposits = [*rp.owner_deposits(db, case, authority), *carried,  # and the addresses the form names
                    *((k.rpartition(":")[0], k.rpartition(":")[2]) for k in about)]
        for o in authority.stop_orders:  # an imported draft the person confirmed this replaces
            if (f"o{o.id}" in replace and o.status == StopOrderStatus.DRAFT
                    and o.origin == StopOrderOrigin.IMPORTED):
                o.status = StopOrderStatus.SUPERSEDED
        orders = services.generate_stop_orders(db, case, run, only=[name], actor=actor,
                                               extra={name: deposits} if deposits else None, gate=False)
        if not orders:
            raise DeskError("the trace produced no stop order for this counterparty")
        order = orders[0]
        order.template_key = "stop_order"
        if extra_note and extra_note.strip():  # the form's "additional paragraph": in the letter, before the signature
            order.body_markdown = insert_before_signature(order.body_markdown or "", extra_note)
        for old in authority.correspondence:  # drafts of letters the generator just superseded
            if (old.status == CorrespondenceStatus.DRAFT and old.stop_order is not None
                    and old.stop_order.status == StopOrderStatus.SUPERSEDED):
                old.meta = {**(old.meta or {}), "superseded_by": order.id}
        for old in replaced:  # a letter draft the person confirmed this stop order replaces
            old.meta = {**(old.meta or {}), "superseded_by": order.id, "superseded_at": now.isoformat()}
        subject, body, stop_order = order.subject, order.body_markdown, order
        recipients = [order.recipient_email] if order.recipient_email else []
        order.recipient_cc = list(sender["cc"])
        ids = order.identifiers or {}
        meta["about"] = rg.norm_about([f"{(x.get('chain') or ids.get('chain') or '') if isinstance(x, dict) else ''}:"
                                       f"{x.get('address') if isinstance(x, dict) else x}"
                                       for x in ids.get("addresses") or []])
    else:
        subject, body, refs = build_letter(db, case, authority, template_key, actor=actor, run=run, ref=ref,
                                           extra_note=extra_note, now=now, freeze=freeze)
        meta.update(refs)
        missing = [k for k in about if rg.addr_of(k) not in body.lower()]
        if missing:  # the addresses it concerns that its own wording does not name
            body = insert_before_signature(body, rg.about_sentence(authority, missing))
        meta["about"] = about
        if asks_freeze(template_key, authority, about, freeze=refs.get("freeze"), note=extra_note):
            meta["asks_freeze"] = True  # a freeze ask (freeze_board._asks_freeze): never "records only"
        stop_order = next((o for o in authority.stop_orders if o.id == refs.get("stop_order_id")), None)
        recipients = [authority.recipient_email] if authority.recipient_email else []
    corr = Correspondence(
        case=case, direction=CorrespondenceDirection.OUT, channel=CorrespondenceChannel.EMAIL, kind=template.kind,
        status=CorrespondenceStatus.DRAFT, subject=subject[:512], body_markdown=body,
        sender=sender["email"] or sender["firm"] or sender["contact"], recipients=recipients, cc=list(sender["cc"]),
        stop_order=stop_order, classification=Classification.R3, meta=meta, created_by=actor.id if actor else None,
    )
    _attach(corr, authority)
    db.add(corr)
    db.flush()
    for old in replaced:  # no request any more (app.blocks.status skips it): the new letter carries it
        old.meta = {**(old.meta or {}), "superseded_by_letter": corr.id}
    db.commit()
    return corr


# --------------------------------------------------------------------------- export
def _slug(text: str, max_len: int) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text or "").strip("-")[:max_len].strip("-") or "x"


def export_path(corr: Correspondence, fmt: str, *, masked: bool = False, subject: str | None = None) -> Path:
    """Where an export of `corr` goes: inside services.EXPORT_DIR (Settings.export_dir), with a name
    built only from slugs and the numeric id; refuses anything that would resolve elsewhere.
    `subject`: the subject to slug instead of corr.subject (the masked one for a masked export)."""
    if fmt not in ("md", "docx"):
        raise DeskError(f"unknown export format {fmt!r}")
    root = Path(services.EXPORT_DIR).resolve()
    name = (f"{_slug(corr.case.reference, 40)}_letter-{int(corr.id)}{'-masked' if masked else ''}_"
            f"{_slug((corr.subject if subject is None else subject) or 'letter', 80)}.{fmt}")
    path = (root / name).resolve()
    if path.parent != root:
        raise ValueError(f"export path escapes the export directory: {name!r}")
    return path


def export_correspondence(corr: Correspondence, fmt: str, *, mask: ContactMask | None = None) -> Path:
    """Write the letter as .md / .docx. With an active `mask` (read-only members) LE / PI contact
    details in the subject and body are masked, in a file of its own."""
    masked = mask is not None and mask.active
    subject, body = corr.subject or "Letter", corr.body_markdown or ""
    if masked:  # the body is Markdown: masked values are escaped so their '*' stay asterisks
        subject, body = mask.text(subject), mask.md(body)
    path = export_path(corr, fmt, masked=masked, subject=subject if masked else None)
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "md":
        path.write_text(body, encoding="utf-8")
        return path
    return markdown_to_docx(subject, body, corr.case.reference, path)


# --------------------------------------------------------------------------- overdue
def check_overdue(db: Session, case: Case, now: datetime | None = None, *, default_days: int | None = None) -> list:
    """Emit `response_overdue` for every sent stop order / letter whose reply is late.

    A stop order is due a reply by `response_due_at` (default sent_at + 7 days) until it is
    answered (responded_at set: an inbound reply was logged or the status moved to acknowledged /
    frozen / declined). A sent letter with `due_at` is due until an inbound message from the same
    authority follows it. Each due date is notified once (recorded on the row itself), so the
    notifications feature may schedule this as often as it likes. `default_days` replaces the 7-day
    default for stop orders without response_due_at (e.g. the response_overdue rule's overdue_days).
    Returns the emitted notifications."""
    now = now or _now()
    out = []
    authorities = case_authorities(db, case, include_prospects=False)
    orphans = [o for o in case.stop_orders if o.entity_id is None]  # letters with no entity on file
    if orphans:
        authorities.append(Authority(key="", name="", category="unknown", stop_orders=orphans))
    for authority in authorities:
        for kind, obj_id, due in authority.awaiting(default_days):
            if due >= now:
                continue
            stamp = due.isoformat()
            days = max(1, (now - due).days)
            if kind == "stop_order":
                obj = next(o for o in authority.stop_orders if o.id == obj_id)
                ids = dict(obj.identifiers or {})
                if ids.get("overdue_notified_for") == stamp:
                    continue
                ids["overdue_notified_for"] = stamp
                obj.identifiers = ids
                title = f"{case.reference}: no reply to stop order #{obj.id} ({days} day{'s' if days != 1 else ''} overdue)"
                anchor, payload = f"o{obj.id}", {"stop_order_id": obj.id, "due_at": stamp}
            else:
                obj = next(c for c in authority.correspondence if c.id == obj_id)
                meta = dict(obj.meta or {})
                if meta.get("overdue_notified_for") == stamp:
                    continue
                meta["overdue_notified_for"] = stamp
                obj.meta = meta
                title = f"{case.reference}: no reply to letter #{obj.id} ({days} day{'s' if days != 1 else ''} overdue)"
                anchor, payload = f"c{obj.id}", {"correspondence_id": obj.id, "due_at": stamp}
            note = events.emit(db, case, events.RESPONSE_OVERDUE, title=title,
                               body=f"The reply was due on {_fmt_day(due)}. Consider a status request.",
                               link=_emit_link(case, authority.key or None, anchor),
                               severity="high" if days > DEFAULT_RESPONSE_DAYS else "warning",
                               payload=payload, commit=False)
            if note is not None:
                out.append(note)
    db.commit()
    # the clocks of the block requests (a provider's submit-by, a playbook clock, a confirmed hold's expiry): rules only
    try:
        from app.blocks import status as block_status

        out += block_status.check_clocks(db, case, now)
    except Exception as err:  # noqa: BLE001 - the clocks never stop the overdue pass
        db.rollback()
        log.warning("block clocks failed for case %s (%s)", case.id, type(err).__name__)
    return out
