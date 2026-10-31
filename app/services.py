"""Application services: case lifecycle, seeding from fixtures, tracing, stop orders, watch list."""

from __future__ import annotations

import logging
import re
import unicodedata
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.permissions import add_member
from app.db.models import (
    Address,
    AddressType,
    AIMode,
    Alert,
    Case,
    CaseRole,
    CaseSeed,
    Chain,
    DataSource,
    EntityCategory,
    SeedRole,
    StopOrder,
    StopOrderOrigin,
    StopOrderStatus,
    TraceRun,
    User,
    WatchItem,
)
from app.domain.notify import seed_default_rules
from app.fixture_sections import SeedReport, load_sections
from app.providers.fixture import fixture_transfers, load_fixture
from app.providers.registry import get_provider
from app.reports.stop_orders import render_stop_order, to_docx
from app.tracing.engine import Tracer
from app.tracing.freeze import FreezeCandidate, freeze_candidates
from app.tracing.repository import (
    get_or_create_address,
    get_or_create_entity,
    ingest_transfer,
    link_bridge,
    normalise_address,
)

log = logging.getLogger(__name__)
REPO_ROOT = Path(__file__).resolve().parents[1]


def _export_root(configured: str) -> Path:
    path = Path(configured).expanduser()
    return (path if path.is_absolute() else REPO_ROOT / path).resolve()


# Settings.export_dir (env EXPORT_DIR); module attribute so tests can redirect it
EXPORT_DIR = _export_root(get_settings().export_dir)


# --------------------------------------------------------------------------- seeding
def seed_from_fixture(db: Session, fixture: str | Path | None = None, *, report: SeedReport | None = None) -> Case:
    """Seed one case from a fixture file (default: settings.aegis_fixture_path).

    Besides the case, seeds, entities, addresses and transfers, loads the optional workspace
    sections (team, stop_orders_imported, correspondence, le_contacts, evidence,
    notification_rules; see docs/fixture-schema.md). Pass `report` to receive generated
    passwords and per-section counts."""
    data = load_fixture(fixture)

    entities = {}
    for e in data.get("entities", []):
        fields = {k: v for k, v in e.items() if k != "name"}
        fields["category"] = EntityCategory(fields.get("category", "unknown"))
        entities[e["name"]] = get_or_create_entity(db, e["name"], **fields)

    for a in data.get("addresses", []):
        get_or_create_address(
            db, Chain(a["chain"]), a["address"], address_type=AddressType(a.get("address_type", "unknown")),
            label=a.get("label"), label_source=a.get("label_source"),
            entity=entities.get(a["entity"]) if a.get("entity") else None, is_contract=a.get("is_contract"),
        )

    raws = fixture_transfers(data)
    ingested = {}
    for raw in raws:
        ingested[(raw.chain, raw.tx_hash, raw.sub_index)] = (ingest_transfer(db, raw, DataSource.FIXTURE), raw)
    for t, raw in ingested.values():
        if raw.bridged_to:
            link_bridge(db, t, *raw.bridged_to)

    c = data["case"]
    case = db.scalar(select(Case).where(Case.reference == c["reference"]))
    if case is None:
        case = Case(reference=c["reference"])
        db.add(case)
    case.title = c["title"]
    case.status = c.get("status", "open")
    case.victim_name = c.get("victim_name")
    case.victim_entity = c.get("victim_entity")
    case.victim_jurisdiction = c.get("victim_jurisdiction")
    case.fraud_type = c.get("fraud_type")
    case.fraud_date = datetime.fromisoformat(c["fraud_date"].replace("Z", "+00:00")) if c.get("fraud_date") else None
    case.loss_amount = Decimal(c["loss_amount"]) if c.get("loss_amount") else None
    case.loss_asset = c.get("loss_asset")
    case.loss_usd = Decimal(c["loss_usd"]) if c.get("loss_usd") else None
    case.summary = c.get("summary")
    # underscore keys are app-internal (e.g. the assistant's stored summary): a re-seed keeps them
    internal = {k: v for k, v in (case.facts or {}).items() if k.startswith("_")}
    case.facts = {**c.get("facts", {}), **internal}
    if c.get("ai_mode"):
        case.ai_mode = AIMode(c["ai_mode"])
    case.status_summary = c.get("status_summary", case.status_summary)
    db.flush()

    existing = {(s.role, s.chain, s.value) for s in case.seeds}
    for s in data.get("seeds", []):
        key = (SeedRole(s["role"]), Chain(s["chain"]), s["value"])
        if key not in existing:
            db.add(CaseSeed(case=case, role=key[0], chain=key[1], value=key[2], note=s.get("note")))
    db.flush()
    load_sections(db, case, data, report)
    # after the fixture's own rules, so they keep the lowest ids; fills only missing event types
    seed_default_rules(db, case)
    db.commit()
    db.refresh(case)
    return case


# --------------------------------------------------------------------------- cases
# A case reference names the case everywhere, including its evidence directory under a plain
# AEGIS_EVIDENCE_ROOTS root (app.domain.evidence.case_evidence_roots). It is therefore ASCII only
# and unique without regard to case: on a case-insensitive file system (macOS APFS by default)
# 'demo-2026-001' and 'DEMO-2026-001' are the same directory.
REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
REFERENCE_RULE = "3 to 64 characters: ASCII letters, digits, '.', '_' or '-', starting with a letter or digit"


class CaseReferenceError(ValueError):
    """A new case reference that is malformed (`taken` False) or already in use (`taken` True)."""

    def __init__(self, message: str, *, taken: bool = False):
        super().__init__(message)
        self.taken = taken


def reference_key(reference: str) -> str:
    """The comparison key for case references: Unicode-normalised (NFKC), stripped and case-folded."""
    return unicodedata.normalize("NFKC", reference or "").strip().casefold()


def check_new_reference(db: Session, reference: str) -> str:
    """Validate a reference for a new case and return it normalised (NFC, stripped).

    Refuses a malformed reference and one that equals an existing case's reference ignoring case and
    Unicode normalisation. The unique index on lower(reference) backs this up in the database."""
    ref = unicodedata.normalize("NFC", reference or "").strip()
    if not REFERENCE_RE.fullmatch(ref):
        raise CaseReferenceError(f"invalid case reference: {REFERENCE_RULE}")
    key = reference_key(ref)
    if any(reference_key(r) == key for r in db.scalars(select(Case.reference))):
        raise CaseReferenceError("a case with this reference already exists (references ignore case)", taken=True)
    return ref


def create_case(
    db: Session, *, reference: str, title: str, victim_name: str, victim_entity: str | None, loss_amount: Decimal,
    loss_asset: str, loss_usd: Decimal, fraud_date: datetime | None, chain: Chain, origin_tx: str | None,
    victim_wallet: str | None, perpetrator_wallet: str | None, summary: str | None = None, facts: dict | None = None,
    created_by: User | None = None, client_email: str | None = None, authority_instrument: str | None = None,
) -> Case:
    """Create a case; its creator (when given) becomes the case admin. The case gets its sender profile (the default
    model of app.domain.sender: the deployment's organisation on behalf of the client, `client_email` as the default Cc,
    `authority_instrument` defaulting to a Letter of Authorisation); the caller audits both.

    Raises CaseReferenceError for a malformed reference or one already used (ignoring case), and
    app.domain.sender.SenderError for an invalid client e-mail or instrument (nothing is created then)."""
    from app.domain import sender

    reference = check_new_reference(db, reference)
    client_email = sender.clean_client_email(client_email)
    authority_instrument = sender.clean_instrument(authority_instrument)
    case = Case(
        reference=reference, title=title, victim_name=victim_name, victim_entity=victim_entity,
        loss_amount=loss_amount, loss_asset=loss_asset, loss_usd=loss_usd, fraud_date=fraud_date,
        summary=summary, facts=facts or {}, created_by=created_by.id if created_by else None,
    )
    db.add(case)
    db.flush()
    if created_by is not None:
        add_member(db, case, created_by, CaseRole.ADMIN, added_by=created_by)
    if origin_tx:
        db.add(CaseSeed(case=case, role=SeedRole.ORIGIN_TX, chain=chain, value=origin_tx.strip()))
    if victim_wallet:
        db.add(CaseSeed(case=case, role=SeedRole.VICTIM_WALLET, chain=chain, value=normalise_address(chain, victim_wallet)))
        get_or_create_address(db, chain, victim_wallet, address_type=AddressType.VICTIM, label="Victim wallet", label_source="manual")
    if perpetrator_wallet:
        db.add(CaseSeed(case=case, role=SeedRole.PERPETRATOR_WALLET, chain=chain, value=normalise_address(chain, perpetrator_wallet)))
        get_or_create_address(db, chain, perpetrator_wallet, address_type=AddressType.PERPETRATOR, label="Perpetrator wallet", label_source="manual")
    seed_default_rules(db, case, created_by=created_by)
    sender.create_default_profile(db, case, client_email=client_email, instrument=authority_instrument,
                                  created_by=created_by)
    db.commit()
    db.refresh(case)
    return case


def update_seed(db: Session, case: Case, role: SeedRole, chain: Chain, value: str, note: str | None = None) -> CaseSeed:
    seed = next((s for s in case.seeds if s.role == role), None)
    value = value.strip() if role == SeedRole.ORIGIN_TX else normalise_address(chain, value)
    if seed is None:
        seed = CaseSeed(case=case, role=role, chain=chain, value=value, note=note)
        db.add(seed)
    else:
        seed.chain, seed.value = chain, value
        if note:
            seed.note = note
    db.commit()
    return seed


# --------------------------------------------------------------------------- tracing
def run_trace(db: Session, case: Case, provider_mode: str | None = None, actor: User | None = None,
              label: str | None = None) -> TraceRun:
    run = Tracer(db, case, provider_mode=provider_mode).run()
    if actor is not None:
        run.created_by = actor.id
    if label:
        run.label = label
    # auto-watch every non-terminal tainted address so movement triggers an alert
    for node in run.nodes:
        if node.taint_usd and node.taint_usd > 0 and not node.is_terminal:
            add_watch(db, case, node.address, commit=False)
    db.commit()
    # owner identification by default: the run's wallets get their public explorer tags (never fails the trace)
    from app.attribution.service import auto_lookups

    auto_lookups(db, case, trigger="trace")
    return run


def latest_run(db: Session, case: Case) -> TraceRun | None:
    return db.scalar(select(TraceRun).where(TraceRun.case_id == case.id).order_by(TraceRun.id.desc()))


# --------------------------------------------------------------------------- stop orders
def generate_stop_orders(db: Session, case: Case, run: TraceRun, only: list[str] | None = None,
                         actor: User | None = None, extra: dict[str, list[tuple[str, str]]] | None = None, *,
                         gate: bool = True, replace: set[str] | None = None, refused: dict | None = None
                         ) -> list[StopOrder]:
    """Draft a stop order for each freeze candidate of `run` (`only`: those names). Every one passes the request gate
    (app.domain.request_gate: one open request per provider — an open draft or prepared e-mail, a request already sent,
    an LE-only / declined answer each refuse it; `refused`: candidate name -> its Decision); `replace`: the draft keys
    the caller confirmed it supersedes (a row's "Redraft from trace #N", the authority page's "replaces draft #N").
    `gate=False`: the caller already passed the gate (correspondence.generate_letter). `extra`: candidate name ->
    [(chain, address)] of deposit addresses attributed to that service that its identifiers lack (the freeze board's
    `owner_addresses`), or (chain, address, "records") of a swap / order address whose records are asked for: cited in
    the same stop order, so one letter asks for both."""
    import dataclasses
    from types import SimpleNamespace

    from app.domain import directory
    from app.domain import request_gate as rg
    from app.domain import sender as sender_mod
    from app.tracing.freeze import Identifier

    cands: list[FreezeCandidate] = freeze_candidates(db, run)
    created: list[StopOrder] = []
    requester = sender_mod.requester_kind(db, case)
    from app.domain import evidence_requirements as er

    states = _gate_states(db, case, run, cands, only) if gate else None
    for cand in cands:
        if only and cand.entity_name not in only:
            continue
        who = SimpleNamespace(entity=cand.entity, name=cand.entity_name, le_contacts=[])
        try:  # the LE-only gate (app.domain.playbook): no stop order to a provider no path of ours reaches
            pb = directory.playbook_for(who)
        except Exception:  # noqa: BLE001 - an invalid catalogue gates nothing
            pb = None
        # an order LE / counsel supplied that names this provider opens the binding path that takes it
        reason = pb.gate(requester, er.held_instruments(case, er.provider_names(who))).reason if pb is not None else None
        if reason:
            if refused is not None:
                refused[cand.entity_name] = rg.Decision(rg.LE_BRIEF_ONLY, text=reason, template="stop_order")
            continue
        if states is not None:  # one open request per provider
            d = rg.decide(states.get(states.by_entity.get(cand.entity.id)) if cand.entity is not None else None,
                          "stop_order", replace=replace)
            if not d.allowed:
                if refused is not None:
                    refused[cand.entity_name] = d
                continue
        # supersede earlier drafts for the same entity, unless one has an e-mail waiting for Send or under way (a
        # prepared Graph / SMTP e-mail, an open "Draft — you send" checklist that may have gone out from Outlook, one
        # sending or of unknown outcome): a new letter would get a new letter key and slip past that e-mail's guard,
        # and the superseded letter could still go out next to it
        eid = cand.entity.id if cand.entity else None
        olds = [o for o in case.stop_orders if o.entity_id == eid and o.status == StopOrderStatus.DRAFT
                and o.origin != StopOrderOrigin.IMPORTED]
        busy = mail_pending(db, olds) if olds else None
        if busy is not None:
            if refused is not None:
                refused[cand.entity_name] = rg.Decision(rg.OPEN_EXISTING, template="stop_order",
                                                        text=mail_pending_text(busy))
            continue
        for old in olds:
            old.status = StopOrderStatus.SUPERSEDED
        have = {i.address.lower() for i in cand.identifiers}
        more = []
        for x in (extra or {}).get(cand.entity_name, []):
            c, a = x[0], x[1]
            if not a or a.lower() in have:
                continue
            have.add(a.lower())
            records = len(x) > 2 and x[2] == "records"  # a swap / order address: its order records asked for too
            more.append(Identifier(
                chain=c, address=a, address_type="unknown" if records else "deposit",
                label=("address of your service the funds passed through (wallet owner identification): please "
                       "freeze any balance or account it credits and preserve its order records (IP, device, payout "
                       "destination)") if records else
                "deposit address attributed to your service (wallet owner identification)"))
        if more:
            cand = dataclasses.replace(cand, identifiers=[*cand.identifiers, *more])
        order = render_stop_order(case, run, cand)
        order.origin = StopOrderOrigin.GENERATED
        order.trace_run_id = run.id
        order.created_by = actor.id if actor else None
        db.add(order)
        created.append(order)
    db.commit()
    return created


def _gate_states(db: Session, case: Case, run: TraceRun, cands: list, only: list[str] | None):
    """The request gate's per-provider states for the candidates (app.domain.request_gate.States, `by_entity`:
    entity id -> its counterparty). Raises request_gate.Unavailable when the requests cannot be read."""
    from app.blocks import status as bs
    from app.domain import correspondence as desk
    from app.domain import request_gate as rg

    try:
        auths = desk.case_authorities(db, case, run=run, cands=cands)
        names = {c.entity_name for c in cands if not only or c.entity_name in only}
        mine = [a for a in auths if a.is_le or (a.candidate is not None and a.candidate.entity_name in names)]
        rows = bs.case_blocks(db, case, authorities=mine)
        states = rg.states_for(db, case, rows, mine)
    except Exception as err:  # noqa: BLE001 - never drafted blind
        logging.getLogger(__name__).warning("request gate unreadable for case %s (%s)", case.id, type(err).__name__)
        raise rg.Unavailable("the requests of these counterparties could not be read: nothing drafted") from None
    states.by_entity = {a.entity.id: a for a in mine if a.entity is not None and not a.is_le}
    return states


def mail_pending(db: Session, orders: list[StopOrder], letters: list | None = None):
    """The e-mail that keeps these draft stop orders / draft letters from being superseded, or None: one prepared and
    waiting for Send (any transport), an open "Draft — you send" checklist (manual transport, prepared or expired, not
    superseded: it may have gone out from Outlook), one sending, sent, recorded as sent or of unknown outcome, or a
    failed one that left an unsent draft in the mailbox. Superseding such a letter would let it go out next to its
    replacement (one open request per provider)."""
    from app.db.models import MailDirection, MailMessage, MailStatus
    from app.domain import mail_compose

    now = datetime.now(tz=UTC)
    keys = [f"o{o.id}" for o in orders if o.id is not None] + [f"c{c.id}" for c in letters or [] if c.id is not None]
    cids = [c.id for o in orders for c in o.correspondence if c.id is not None] + \
        [c.id for c in letters or [] if c.id is not None]
    if not keys and not cids:
        return None
    rows = db.scalars(select(MailMessage).where(
        MailMessage.letter_key.in_(keys) | MailMessage.correspondence_id.in_(cids),
        MailMessage.direction == MailDirection.OUT,
        MailMessage.status.in_((MailStatus.PREPARED, MailStatus.EXPIRED, MailStatus.FAILED, *mail_compose.LETTER_BUSY)))
        .order_by(MailMessage.id)).all()
    for r in rows:
        if r.status in mail_compose.LETTER_BUSY or mail_compose.stale_draft_left(r):
            return r
        if r.transport == "manual" and mail_compose.is_open_checklist(r):
            return r
        until = r.expires_at.replace(tzinfo=r.expires_at.tzinfo or UTC) if r.expires_at is not None else None
        if r.transport != "manual" and r.status == MailStatus.PREPARED and until is not None and until > now:
            return r  # waiting for Send (an expired preview is never sent: mail_send refuses it)
    return None


def mail_pending_text(mm) -> str:
    """Why a draft with e-mail `mm` (mail_pending) is not superseded."""
    status = str(getattr(mm.status, "value", mm.status))
    what = ("an Outlook checklist" if mm.transport == "manual" else
            "a prepared e-mail waiting for Send" if status == "prepared" else f"e-mail ({status})")
    return (f"The draft has {what} (#{mm.id}): it is not replaced. Send it (or cancel / retire the e-mail first). "
            "One open request per provider: no second letter or stop order while it is open.")


def _slug(text: str, max_len: int) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")[:max_len].strip("-") or "x"


def export_stop_order_docx(order: StopOrder) -> Path:
    """Write the .docx under EXPORT_DIR. The name is built only from slugs and the numeric id, and
    the resolved path is checked to stay inside the export root (case reference / subject are
    user-controlled)."""
    root = Path(EXPORT_DIR).resolve()
    name = f"{_slug(order.case.reference, 40)}_{int(order.id)}_{_slug(order.subject, 80)}.docx"
    path = (root / name).resolve()
    if path.parent != root:
        raise ValueError(f"export path escapes the export directory: {name!r}")
    return to_docx(order, path)


def mark_stop_order(db: Session, order: StopOrder, status: StopOrderStatus, external_ref: str | None = None, notes: str | None = None) -> StopOrder:
    order.status = status
    now = datetime.now(tz=UTC)
    if status == StopOrderStatus.SENT:
        order.sent_at = now
    elif status in (StopOrderStatus.ACKNOWLEDGED, StopOrderStatus.FROZEN, StopOrderStatus.DECLINED):
        order.responded_at = now
    if external_ref:
        order.external_ref = external_ref
    if notes:
        order.notes = (order.notes + "\n" if order.notes else "") + notes
    db.commit()
    return order


# --------------------------------------------------------------------------- watch list
def add_watch(db: Session, case: Case, address: Address, commit: bool = True) -> WatchItem:
    item = db.scalar(select(WatchItem).where(WatchItem.case_id == case.id, WatchItem.address_id == address.id))
    if item is None:
        # baseline at creation: movements already captured by the trace are not "new"
        item = WatchItem(case=case, address=address, active=True, last_checked_at=datetime.now(tz=UTC))
        db.add(item)
        if commit:
            db.commit()
    return item


WATCH_LOOKBACK = timedelta(minutes=15)


def poll_watch_items(db: Session, case: Case, provider_mode: str | None = None) -> list[Alert]:
    """Check each watched address for new outgoing transfers since last check; raise alerts.

    In production this runs on a schedule (EventBridge → ECS task / Lambda) every few
    minutes; here it is triggered from the UI so the demo stays self-contained.

    Each poll looks back WATCH_LOOKBACK before the previous check (an explorer can index a transfer
    after a poll although it was mined before it) and skips transactions that already raised an
    alert for this address, so nothing is missed and nothing is alerted twice.
    """
    alerts: list[Alert] = []
    now = datetime.now(tz=UTC)
    for item in case.watch_items:
        if not item.active:
            continue
        provider = get_provider(item.address.chain, provider_mode)
        since = item.last_checked_at - WATCH_LOOKBACK if item.last_checked_at else None
        try:
            rows = provider.outgoing_transfers(item.address.address, since=since, limit=50)
        except Exception as exc:  # noqa: BLE001
            log.warning("watch poll failed for %s: %s", item.address.address, exc)
            continue
        alerted = set(db.scalars(select(Alert.tx_hash).where(Alert.watch_item_id == item.id)))
        new = [r for r in rows if r.tx_hash not in alerted and (since is None or r.timestamp >= since)]
        for r in new:
            ingest_transfer(db, r, DataSource.MANUAL)
            dest = db.scalar(select(Address).where(Address.chain == r.chain, Address.address == normalise_address(r.chain, r.to_address)))
            dest_label = dest.entity.name if dest and dest.entity else (dest.label if dest and dest.label else "unknown address")
            sev = "critical" if dest and dest.entity else "high"
            alert = Alert(watch_item_id=item.id, severity=sev, tx_hash=r.tx_hash,
                          message=f"{r.amount if r.amount is not None else '?'} {r.asset} moved from {item.address.short()} to {dest_label} ({r.to_address[:12]}…) at {r.timestamp:%d.%m.%Y %H:%M UTC}"
                                  + (" — VASP touchpoint: issue freeze request now." if dest and dest.entity else ""))
            db.add(alert)  # in the session at once (no cascade along WatchItem.alerts needed)
            alerts.append(alert)
            item.last_seen_tx = r.tx_hash
        item.last_checked_at = now
    db.commit()
    return alerts
