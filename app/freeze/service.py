"""On-chain freeze detection for a case: the consent setting, which wallets, running the checks, status.

    set_enabled(db, case, user, True)                  # case admin; the route audits the consent
    report = run_checks(db, case, trigger="manual")    # FreezeChecksDisabled unless enabled
    status = case_status(db, case)                     # overview, freeze page, graph, /freeze-status

**Consent gate.** No request leaves Aegis for a case until a case admin enables "On-chain freeze
checks" (`freeze_settings.enabled`, off by default) after seeing `egress_plan()`: which public endpoint
receives what. `AEGIS_FREEZE_CHECKS_DISABLED=1` switches every case off. `run_checks` raises
`FreezeChecksDisabled` before it builds an HTTP client, also when the endpoints have changed since the
consent (`new_hosts`: e.g. ETHERSCAN_API_KEY set later moves the explorer to etherscan.io; the admin
confirms again) and while another run of the same case holds the run claim (`run_started_at`, a
conditional UPDATE: a manual run and a scheduler pass never read and flip the same wallet twice).

**Which wallets** (`targets`): every address of the latest trace run on a chain where an issuer
contract is checked (app.freeze.issuers.CHAINS) that sent or received USDT / USDC in the run (that
token's contract only), except the victim, placeholders, context-only nodes and contracts / DEX routers;
plus every wallet an investigator added to watch (`freeze_watch`; every issuer contract on its chain).
Exchange and casino *accounts* are not visible on-chain: their freeze stays confirmed by the
recipient's reply (stop orders), and `case_status` names those services.

**What a check stores** (`freeze_checks`, one row per wallet and issuer contract): blacklisted, balance,
the block it was read at, method, the sha256 of the raw response (and of every other response in
`meta.responses`), the freeze time (`frozen_at`: the issuer's blacklist event from the explorer's logs
API, basis `event`; otherwise an upper bound, basis `at_or_before`: the first failed transfer, or the
check time; while the wallet stays blacklisted the bound is carried forward, never moved later), and
the failed transfer attempts (app.freeze.signals). Transaction hashes from the explorer / TronGrid are
checked (`clean_tx_hash`) before they are stored. The first blacklisted reading of a wallet and contract
(no earlier reading, or the earlier one was not blacklisted) emits `freeze_detected` (critical, in-app by
default): once per flip, never on every re-check. A reading that is no longer blacklisted after a
blacklisted one records the lift (`meta.unfrozen`: when it was frozen, the issuer's removal event or an
"at or before" time) and emits `freeze_lifted` (critical): the funds can move again; the wallet's state
stays `unfrozen` on later readings. A blacklisted balance that falls to zero is recorded as
`meta.balance_destroyed` (Tether's DestroyedBlackFunds). A balance that falls between two good readings (not
blacklisted) means the funds are moving: `wallet_movement` (high), unless the watch list already reported the wallet
moving since, or app.attribution (the plan's own resolution) puts the wallet at a service: a deposit address swept
into its service (`swept`) or a service's hot / payout wallet paying out of its float (`float_moved`) is expected. A failed reading (`status='error'`, e.g. host_unavailable) never shadows the last good one: every reader
(`wallet_rows`) shows the latest OK reading with "last checked OK <time>; the last attempt failed".
Domain code: it emits events but never audits (the routes and the scheduler audit).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session, selectinload

from app.core.events import FREEZE_DETECTED, FREEZE_LIFTED, VASP_DEPOSIT, WALLET_MOVEMENT, emit
from app.db.models import (
    Address,
    AddressType,
    Case,
    EntityCategory,
    FreezeCheck,
    FreezeSetting,
    FreezeWatch,
    Notification,
    TraceEdge,
    TraceNode,
    TraceRun,
    Transfer,
    User,
    WalletAttribution,
)
from app.domain import addresses
from app.freeze import issuers, signals
from app.freeze.issuers import CHAIN_LABELS, CHAINS, TokenContract, contracts_for, normalise_wallet
from app.freeze.transport import FreezeHttp, FreezeHttpError, host_of
from app.providers.prices import to_usd

log = logging.getLogger("app.freeze")

TLP_CHOICES = ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT")
TLP_REFUSED = ("TLP:RED",)  # named recipients only: never stored outside the evidence vault (data-handling §7)
TLP_WITHHELD = ("TLP:AMBER", "TLP:AMBER+STRICT")  # label / source note never shown outside the case pages
STABLE_SYMBOLS = {"USDT", "USDC"}
RUN_LEASE = timedelta(minutes=15)  # a run claim older than this is a crashed run: the next run takes it over
NOT_VISIBLE_CATEGORIES = (EntityCategory.EXCHANGE, EntityCategory.CASINO, EntityCategory.OTC)
SKIP_CATEGORIES = (EntityCategory.DEX, EntityCategory.BRIDGE, EntityCategory.MIXER)
DROP_MIN_UNITS = Decimal(1)  # a fall in balance between two good readings smaller than this (or 1%) is noise
DROP_MIN_SHARE = Decimal("0.01")


class FreezeChecksDisabled(Exception):
    """No request may be sent: `reason` case_setting_off | deployment_disabled | consent_outdated (the
    endpoints changed since the admin consented) | run_in_progress (another run of this case's checks)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------- settings & consent
def _settings(settings=None):
    if settings is None:
        from app.core.config import get_settings

        settings = get_settings()
    return settings


def setting_for(db: Session, case: Case) -> FreezeSetting | None:
    return db.scalar(select(FreezeSetting).where(FreezeSetting.case_id == case.id))


def is_enabled(db: Session, case: Case, settings=None) -> bool:
    row = setting_for(db, case)
    return bool(row is not None and row.enabled and not _settings(settings).freeze_checks_disabled)


def node_url(chain: str, settings) -> str:
    if chain == "tron":
        return (settings.aegis_trongrid_url or "").strip()
    return (getattr(settings, issuers.RPC_SETTING.get(chain, ""), "") or "").strip()


def egress_plan(settings=None) -> list[dict]:
    """What each public endpoint receives when the checks run (shown before consent, kept with it).
    Hosts only: never a URL with a key in it."""
    settings = _settings(settings)
    rows: list[dict] = []
    for chain in CHAINS:
        tokens = ", ".join(f"{c.issuer} {c.symbol}" for c in contracts_for(chain))
        url = node_url(chain, settings)
        if chain == "tron":
            rows.append({"chain": chain, "chain_label": CHAIN_LABELS[chain], "purpose": "blacklist, balance, failed transfers, freeze event",
                         "host": host_of(url) if url else None, "configured": bool(url),
                         "sends": f"each checked TRON wallet address ({tokens} isBlackListed / balanceOf calls, the "
                                  "wallet's outgoing transactions, the contract's AddedBlackList events)",
                         "auth": "TRON-PRO-API-KEY header" if settings.trongrid_api_key else None})
            continue
        rows.append({"chain": chain, "chain_label": CHAIN_LABELS[chain], "purpose": "blacklist and balance (eth_call)",
                     "host": host_of(url) if url else None, "configured": bool(url),
                     "sends": f"each checked wallet address inside eth_call ({tokens}: blacklist getter, balanceOf) "
                              "and eth_blockNumber", "auth": None})
        ex = issuers.explorer_for(chain, settings)
        if url and ex is not None:
            rows.append({"chain": chain, "chain_label": CHAIN_LABELS[chain],
                         "purpose": "failed transfers and freeze time (explorer)", "host": ex.host, "configured": True,
                         "sends": "each checked wallet address (account txlist); the issuer contract and the wallet "
                                  "in a logs query for the blacklist event",
                         "auth": "Etherscan API key (query string, never logged)" if ex.kind == "etherscan" else None})
    return rows


def consent_hosts(plan: list[dict]) -> list[str]:
    return sorted({r["host"] for r in plan if r.get("configured") and r.get("host")})


def new_hosts(row: FreezeSetting | None, settings=None) -> list[str]:
    """Hosts the checks would now reach that the enabling admin did not consent to (an RPC URL or the
    explorer changed since, e.g. ETHERSCAN_API_KEY set later moves the explorer from Blockscout to
    etherscan.io). Non-empty: the checks are refused until a case admin confirms again."""
    if row is None or not row.enabled:
        return []
    consented = set((row.consent or {}).get("hosts") or [])
    return sorted(set(consent_hosts(egress_plan(settings))) - consented)


def set_enabled(db: Session, case: Case, user: User | None, enabled: bool, *, settings=None) -> FreezeSetting:
    """Turn the case's checks on (recording the plan the admin consented to; also how an admin confirms
    changed endpoints) or off. Flushes; the caller audits and commits."""
    row = setting_for(db, case)
    if row is None:
        row = FreezeSetting(case_id=case.id, enabled=False, consent={}, last_result={})
        db.add(row)
    now = datetime.now(tz=UTC)
    if enabled:
        plan = egress_plan(settings)
        row.enabled, row.enabled_at, row.enabled_by = True, now, user.id if user else None
        row.consent = {"at": now.isoformat(timespec="seconds"), "by": user.id if user else None,
                       "hosts": consent_hosts(plan), "plan": plan}
        row.last_result = {k: v for k, v in (row.last_result or {}).items() if k != "refused"}
    else:
        row.enabled, row.disabled_at, row.disabled_by = False, now, user.id if user else None
    db.flush()
    return row


# --------------------------------------------------------------------------- watched wallets
def add_watch(db: Session, case: Case, user: User | None, *, chain: str, address: str, label: str | None = None,
              source_note: str | None = None, tlp: str | None = None) -> FreezeWatch:
    """Add (or re-activate) a watched wallet. ValueError on a bad chain / address / TLP."""
    chain = (chain or "").strip().lower()
    if chain not in CHAINS:
        raise ValueError(f"choose one of: {', '.join(CHAINS)}")
    addr = normalise_wallet(chain, address)
    tlp = (tlp or "").strip().upper() or None
    if tlp in TLP_REFUSED:
        raise ValueError("TLP:RED material is for named recipients only and is not stored in Aegis outside the "
                         "evidence vault (docs/data-handling.md §7)")
    if tlp is not None and tlp not in TLP_CHOICES:
        raise ValueError(f"TLP must be one of {', '.join(TLP_CHOICES)}")
    row = db.scalar(select(FreezeWatch).where(FreezeWatch.case_id == case.id, FreezeWatch.chain == chain,
                                              FreezeWatch.address == addr))
    if row is None:
        row = FreezeWatch(case_id=case.id, chain=chain, address=addr, created_by=user.id if user else None)
        db.add(row)
    row.label = (label or "").strip()[:255] or None
    row.source_note = (source_note or "").strip()[:512] or None
    row.tlp, row.active, row.removed_at, row.removed_by = tlp, True, None, None
    db.flush()
    return row


def remove_watch(db: Session, row: FreezeWatch, user: User | None) -> FreezeWatch:
    row.active, row.removed_at, row.removed_by = False, datetime.now(tz=UTC), user.id if user else None
    db.flush()
    return row


def watched(db: Session, case: Case, *, active_only: bool = True) -> list[FreezeWatch]:
    q = select(FreezeWatch).where(FreezeWatch.case_id == case.id)
    if active_only:
        q = q.where(FreezeWatch.active.is_(True))
    return list(db.scalars(q.order_by(FreezeWatch.id)))


# --------------------------------------------------------------------------- targets
@dataclass
class Target:
    chain: str
    address: str  # normalised
    symbols: frozenset[str] | None  # None = every issuer contract on the chain
    in_trace: bool = False
    watch: FreezeWatch | None = None
    entity: str | None = None
    entity_category: str | None = None
    label: str | None = None
    first_block: int | None = None  # earliest block the wallet received the token in the run
    first_at: datetime | None = None
    taint_usd: float = 0.0  # what the trace put into it
    address_type: str | None = None

    @property
    def source(self) -> str:
        return "trace" if self.in_trace else "watched"

    @property
    def key(self) -> tuple[str, str]:
        return self.chain, self.address

    def contracts(self) -> list[TokenContract]:
        return contracts_for(self.chain, self.symbols)


def wallet_key(chain: str, address: str) -> tuple[str, str]:
    return addresses.wallet_key(chain, address)


def latest_run(db: Session, case: Case) -> TraceRun | None:
    return db.scalar(select(TraceRun).where(TraceRun.case_id == case.id).order_by(TraceRun.id.desc()).limit(1))


def targets(db: Session, case: Case, run: TraceRun | None = None) -> list[Target]:
    run = run if run is not None else latest_run(db, case)
    out: dict[tuple[str, str], Target] = {}
    if run is not None:
        nodes = db.scalars(select(TraceNode).where(TraceNode.run_id == run.id)
                           .options(selectinload(TraceNode.address).selectinload(Address.entity))).all()
        edges = db.scalars(select(TraceEdge).where(TraceEdge.run_id == run.id)
                           .options(selectinload(TraceEdge.transfer))).all()
        syms: dict[int, set[str]] = {}
        first: dict[int, tuple[int | None, datetime | None]] = {}
        for e in edges:
            t: Transfer = e.transfer
            sym = (t.asset or "").split("→")[-1].strip().upper()
            if sym not in STABLE_SYMBOLS:
                continue
            for aid in (t.from_address_id, t.to_address_id):
                syms.setdefault(aid, set()).add(sym)
            if not t.tx_hash.startswith("ASSERTED:"):
                blk, at = first.get(t.to_address_id, (None, None))
                if t.block_number is not None and (blk is None or t.block_number < blk):
                    blk = t.block_number
                if at is None or t.timestamp < at:
                    at = t.timestamp
                first[t.to_address_id] = (blk, at)
        for n in nodes:
            a = n.address
            chain = a.chain.value
            s = syms.get(a.id)
            if not s or chain not in CHAINS or {"context_only", "pending_input"} & set(n.flags or []):
                continue
            if a.address.endswith("_PENDING") or a.address_type in (AddressType.VICTIM, AddressType.CONTRACT):
                continue
            if a.entity is not None and a.entity.category in SKIP_CATEGORIES:
                continue
            available = {c.symbol for c in contracts_for(chain)}
            s = frozenset(s & available)
            if not s:
                continue
            try:
                addr = normalise_wallet(chain, a.address, checksum=False)
            except ValueError:
                continue
            blk, at = first.get(a.id, (None, None))
            out[(chain, addr)] = Target(chain, addr, s, in_trace=True, entity=a.entity.name if a.entity else None,
                                        entity_category=a.entity.category.value if a.entity else None,
                                        label=a.label, first_block=blk, first_at=at, taint_usd=float(n.taint_usd or 0),
                                        address_type=a.address_type.value if a.address_type else None)
    for w in watched(db, case):
        key = (w.chain, w.address)
        if key in out:
            out[key].watch, out[key].symbols = w, None
        else:
            out[key] = Target(w.chain, w.address, None, watch=w, label=w.label)
    return list(out.values())


# --------------------------------------------------------------------------- running the checks
@dataclass
class CheckReport:
    checked: int = 0  # readings stored (ok)
    errors: int = 0
    blacklisted: int = 0
    newly_frozen: list[int] = field(default_factory=list)  # FreezeCheck ids that emitted freeze_detected
    newly_lifted: list[int] = field(default_factory=list)  # FreezeCheck ids that emitted freeze_lifted
    funds_left: list[int] = field(default_factory=list)  # FreezeCheck ids whose balance fell (wallet_movement, high)
    swept: list[int] = field(default_factory=list)  # FreezeCheck ids of a deposit address swept into its service
    float_moved: list[int] = field(default_factory=list)  # FreezeCheck ids of a service float paying out (no alert)
    skipped: list[dict] = field(default_factory=list)  # {chain, reason}
    wallets: int = 0
    requests: int = 0
    hosts: list[str] = field(default_factory=list)

    def counts(self) -> dict:
        return {"checked": self.checked, "errors": self.errors, "blacklisted": self.blacklisted,
                "newly_frozen": len(self.newly_frozen), "newly_lifted": len(self.newly_lifted),
                "funds_left": len(self.funds_left),
                "wallets": self.wallets, "requests": self.requests,
                "skipped": len(self.skipped), "hosts": self.hosts}


def _latest(db: Session, case: Case, *, ok_only: bool) -> dict[tuple[str, str, str], FreezeCheck]:
    q = select(FreezeCheck).where(FreezeCheck.case_id == case.id)
    if ok_only:
        q = q.where(FreezeCheck.status == "ok")
    out: dict[tuple[str, str, str], FreezeCheck] = {}
    for row in db.scalars(q.order_by(FreezeCheck.checked_at, FreezeCheck.id)):
        out[(row.chain, row.address, row.token_contract)] = row
    return out


@dataclass
class History:
    """One wallet and issuer contract's readings: the latest good one (`ok`), the latest attempt (`last`: an error
    after `ok` never shadows it) and the latest fall in balance between two good readings (`left`: (before, after))."""

    ok: FreezeCheck | None = None
    last: FreezeCheck | None = None
    left: tuple[FreezeCheck, FreezeCheck] | None = None
    falls: list[tuple[FreezeCheck, FreezeCheck]] = field(default_factory=list)  # every such fall, oldest first

    @property
    def shown(self) -> FreezeCheck | None:
        return self.ok or self.last

    @property
    def failed_since(self) -> FreezeCheck | None:
        """The failed attempt newer than the good reading shown, or None."""
        return self.last if self.ok is not None and self.last is not None and self.last.status != "ok" else None


def funds_dropped(before: FreezeCheck, after: FreezeCheck) -> bool:
    """The balance fell between two good readings (not blacklisted: a blacklisted balance falling is the issuer's
    burn, `balance_destroyed`): the funds are moving."""
    a, b = exact_balance(before), exact_balance(after)
    if a is None or b is None or after.blacklisted or before.blacklisted or b >= a:
        return False
    return a - b >= DROP_MIN_UNITS and a - b >= a * DROP_MIN_SHARE


POOLED_FACTOR = 5.0  # balance / traced inflow above which a traced wallet reads as a service's pooled float


def pooled_float(before, after, traced: float, service: bool = False) -> bool:
    """A service hot wallet's float moving, not the case's funds (the alert, the Overview, the freeze page, Block
    status and the Recovery plan all skip it): a wallet the trace attributes to a service, or one that received a
    traced amount, still holding at least that amount after holding POOLED_FACTOR times more before."""
    if before is None or after is None or not (traced > 0 or service):
        return False
    cap = max(float(traced or 0), 1.0)
    return float(after) >= cap and float(before) > POOLED_FACTOR * cap


DEPOSIT_KINDS = frozenset({"exchange_deposit", "casino"})  # app.attribution: one customer's deposit address
FLOAT_KINDS = frozenset({"exchange_hot_wallet", "swap_bridge"})  # app.attribution: a service's pooled float
SERVICE_KINDS = DEPOSIT_KINDS | FLOAT_KINDS
DEPOSIT_CATEGORIES = frozenset({"exchange", "casino", "otc"})
# the trace entity categories that hold a pooled float (app.attribution.CATEGORY_KIND's service kinds): a hosting,
# infrastructure, mixer, law-enforcement or "unknown" entity owns no float its wallet pays out of
SERVICE_CATEGORIES = frozenset({"exchange", "otc", "casino", "swap_service", "bridge"})


def sure_service(att) -> bool:
    """A service attribution a balance drop can be read by (swept into it / its float paying out): the service is
    named, or a source other than the behaviour profile says so, or the profile is at least M. An unnamed L guess
    (a large balance, a fast sweep) never silences the case's funds leaving."""
    return bool(att.owner) or att.source != "behaviour" or att.confidence in ("M", "H")


def _stored_kinds(db: Session, case: Case) -> dict[tuple[str, str], tuple[str, str | None]]:
    """The stored rows only (a person's wins over an explorer's): the fallback when the attribution fails."""
    latest: dict[tuple[str, str, str], WalletAttribution] = {}
    for r in db.scalars(select(WalletAttribution).where(WalletAttribution.case_id == case.id)
                        .order_by(WalletAttribution.id)):
        latest[(*wallet_key(r.chain, r.address), r.source)] = r
    out: dict[tuple[str, str], tuple[str, str | None]] = {}

    def live(k) -> bool:  # a person's attribution that was not withdrawn: it wins
        m = latest.get((*k, "manual"))
        return m is not None and not (m.detail or {}).get("cleared")
    for (chain, addr, src), r in latest.items():
        k = (chain, addr)
        if (src == "manual" and live(k)) or (src == "explorer" and not live(k)):
            out[k] = (r.kind, r.owner)
    return {k: v for k, v in out.items() if v[0] and v[0] != "unknown"}


def service_kinds(db: Session, case: Case) -> dict[tuple[str, str], tuple[str, str | None]]:
    """{wallet key: (kind, owner)} of every wallet app.attribution gives a kind (the same resolution the Recovery plan
    uses: a person's call, the catalogue, the trace's entity map, public explorer tags, the behaviour profile, e.g. a
    deposit address seen forwarding its funds to a known exchange hot wallet within minutes). No network."""
    try:
        from app.attribution import service as attr

        atts = attr.attribute(db, case, freeze_rows=[], asks=False)
        return {k: (a.kind, a.owner) for k, a in atts.items() if a.kind and a.kind != "unknown" and (
            a.kind not in SERVICE_KINDS or sure_service(a))}
    except Exception:  # the stored rows only: the alert still never fires on a marked deposit sweep
        log.exception("freeze: wallet owners failed for case %s", getattr(case, "id", None))
        return _stored_kinds(db, case)


def swept_into(t: Target | None, kinds: dict, key: tuple[str, str]) -> str | None:
    """The service a deposit address belongs to (app.attribution's deposit kinds, else the trace's typed deposit
    address): its balance falling is that service sweeping it into its own wallet (the account was credited), not the
    case's funds leaving."""
    kind, owner = kinds.get(wallet_key(*key), (None, None))
    if kind in DEPOSIT_KINDS:
        return owner or (t.entity if t is not None else None) or "the service"
    if kind is None and t is not None and t.entity and t.address_type == "deposit" and \
            t.entity_category in DEPOSIT_CATEGORIES:
        return t.entity
    return None


def service_float(t: Target | None, kinds: dict, key: tuple[str, str]) -> str | None:
    """The service whose pooled float the wallet is (app.attribution's hot wallet / swap kinds, else a wallet the
    trace puts at a service that is not a deposit address): its balance falling is that service paying out, never
    the case's funds leaving (the case's share is at most what the trace put in)."""
    kind, owner = kinds.get(wallet_key(*key), (None, None))
    if kind in FLOAT_KINDS:
        return owner or (t.entity if t is not None else None) or "the service"
    if kind is None and t is not None and t.entity and t.address_type != "deposit" and \
            t.entity_category in SERVICE_CATEGORIES:
        return t.entity
    return None


def is_service(t: Target | None, kinds: dict, key: tuple[str, str]) -> bool:
    kind = kinds.get(wallet_key(*key), (None, None))[0]
    return kind in SERVICE_KINDS or (kind is None and bool(t is not None and t.entity))


HISTORY_ROWS = 24  # readings per wallet and contract read back (and the two latest good ones, however old)


def _history_ids(db: Session, case: Case) -> list[int]:
    part = (FreezeCheck.chain, FreezeCheck.address, FreezeCheck.token_contract)
    order = (FreezeCheck.checked_at.desc(), FreezeCheck.id.desc())
    ids: set[int] = set()
    for ok_only, n in ((False, HISTORY_ROWS), (True, 2)):
        q = select(FreezeCheck.id, func.row_number().over(partition_by=part, order_by=order).label("rn")).where(
            FreezeCheck.case_id == case.id)
        if ok_only:
            q = q.where(FreezeCheck.status == "ok")
        sub = q.subquery()
        ids |= set(db.scalars(select(sub.c.id).where(sub.c.rn <= n)))
    return sorted(ids)


def history(db: Session, case: Case) -> dict[tuple[str, str, str], History]:
    """Per wallet and contract: the latest HISTORY_ROWS readings (a window query: the load does not grow with the
    scheduled runs) plus the two latest good ones."""
    out: dict[tuple[str, str, str], History] = {}
    ids = _history_ids(db, case)
    q = select(FreezeCheck).where(FreezeCheck.id.in_(ids)).order_by(FreezeCheck.checked_at, FreezeCheck.id)
    for row in db.scalars(q) if ids else ():
        h = out.setdefault((row.chain, row.address, row.token_contract), History())
        h.last = row
        if row.status != "ok":
            continue
        if h.ok is not None and funds_dropped(h.ok, row):
            h.left = (h.ok, row)
            h.falls.append(h.left)
        h.ok = row
    return out


def short_address(a: str) -> str:
    return a if len(a) <= 14 else f"{a[:8]}…{a[-6:]}"


def fmt_amount(v: Decimal | None) -> str:
    return "?" if v is None else f"{Decimal(v).quantize(Decimal('0.01')):,}"


def exact_balance(row: FreezeCheck) -> Decimal | None:
    """The balance in token units, exact: from the raw uint256 kept in meta (Numeric is a float on SQLite)."""
    raw = (row.meta or {}).get("balance_raw")
    token = issuers.contract_by_id(row.chain, row.token_contract)
    if raw is not None and token is not None:
        try:
            return issuers.units(int(raw), token.decimals)
        except ValueError:
            pass
    return Decimal(row.balance) if row.balance is not None else None


def onchain_label(issuer: str, symbol: str, balance: Decimal | None) -> str:
    """'frozen (on-chain: Tether blacklist, 1,234.56 USDT)'."""
    return f"frozen (on-chain: {issuer} blacklist, {fmt_amount(balance)} {symbol})"


def _when_text(at: datetime | None, basis: str | None) -> str:
    if at is None:
        return ""
    return f"{at:%d %b %Y %H:%M} UTC" if basis == "event" else f"at or before {at:%d %b %Y %H:%M} UTC"


def _emit_freeze(db: Session, case: Case, row: FreezeCheck) -> None:
    bal = exact_balance(row)
    amount = f"{fmt_amount(bal)} {row.token_symbol}"
    when = f"blacklisted {_when_text(row.frozen_at, row.frozen_at_basis)}" if row.frozen_at is not None else ""
    block = f" · read at block {row.block_number}" if row.block_number else ""
    body = (f"{case.reference} · {row.issuer} blacklisted {short_address(row.address)} on "
            f"{CHAIN_LABELS.get(row.chain, row.chain)} · {amount} held{block}" + (f" · {when}" if when else "")
            + " — ask the issuer to hold the funds for law enforcement.")
    emit(db, case, FREEZE_DETECTED, usd=to_usd(row.token_symbol, bal) if bal is not None else None,
         title=f"On-chain freeze: {row.issuer} blacklisted {short_address(row.address)} ({amount})", body=body,
         link=f"/cases/{case.id}/freeze", severity="critical",
         payload={"freeze_check_id": row.id, "chain": row.chain, "issuer": row.issuer}, commit=False)


def _emit_lifted(db: Session, case: Case, row: FreezeCheck, info: dict) -> None:
    bal = exact_balance(row)
    amount = f"{fmt_amount(bal)} {row.token_symbol}"
    was = _when_text(_dt(info.get("was_frozen_at")), info.get("was_frozen_at_basis"))
    removed = _when_text(_dt(info.get("removed_at")), info.get("removed_at_basis"))
    block = f" · read at block {row.block_number}" if row.block_number else ""
    body = (f"{case.reference} · {row.issuer} removed {short_address(row.address)} on "
            f"{CHAIN_LABELS.get(row.chain, row.chain)} from its blacklist · balance {amount}{block}"
            + (f" · blacklisted {was}" if was else "") + (f" · removed {removed}" if removed else "")
            + " — the funds can move again: contact the issuer and the receiving services now.")
    emit(db, case, FREEZE_LIFTED, usd=to_usd(row.token_symbol, bal) if bal is not None else None,
         title=f"Freeze lifted: {row.issuer} un-blacklisted {short_address(row.address)} ({amount}) — funds can move",
         body=body, link=f"/cases/{case.id}/freeze", severity="critical",
         payload={"freeze_check_id": row.id, "chain": row.chain, "issuer": row.issuer}, commit=False)


def _emit_left(db: Session, case: Case, row: FreezeCheck, earlier: FreezeCheck) -> bool:
    """The balance fell between two good readings: the funds are moving (wallet_movement, high), unless the watch
    list already reported this wallet moving since the earlier reading. True when emitted."""
    since = _aware(earlier.checked_at)
    low = row.address if row.chain == "tron" else row.address.lower()
    ids = [a.id for a in db.scalars(select(Address).where(
        Address.address.in_({row.address, low}) if row.chain == "tron" else func.lower(Address.address) == low))]
    q = select(Notification).where(Notification.case_id == case.id, Notification.event_type.in_(
        (WALLET_MOVEMENT, VASP_DEPOSIT)))
    if since is not None:  # either match was raised after the earlier reading (a margin for whole-second clocks)
        q = q.where(Notification.created_at >= since - timedelta(hours=1))
    for n in db.scalars(q):
        p = n.payload or {}
        if p.get("previous_check_id") == earlier.id or (p.get("address_id") in ids and _aware(n.created_at)
                                                       and _aware(n.created_at) >= since):
            return False
    a, b = exact_balance(earlier), exact_balance(row)
    usd = to_usd(row.token_symbol, a - b) if a is not None and b is not None else None
    chain = CHAIN_LABELS.get(row.chain, row.chain)
    body = (f"{case.reference} · {short_address(row.address)} on {chain}: {row.token_symbol} balance fell from "
            f"{fmt_amount(a)} to {fmt_amount(b)} between {earlier.checked_at:%d %b %Y %H:%M} and "
            f"{row.checked_at:%d %b %Y %H:%M} UTC — the funds are moving: re-trace now and ask the next custodian "
            "or issuer.")
    emit(db, case, WALLET_MOVEMENT, usd=usd,
         title=f"Funds left {short_address(row.address)}: {fmt_amount(a - b) if a is not None and b is not None else '?'} "
               f"{row.token_symbol} moved", body=body, link=f"/cases/{case.id}/recovery-plan", severity="high",
         payload={"freeze_check_id": row.id, "previous_check_id": earlier.id, "chain": row.chain,
                  "address_id": ids[0] if ids else None}, commit=False)
    return True


def _dt(v) -> datetime | None:
    if isinstance(v, datetime):
        return v
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def _iso(v: datetime | None) -> str | None:
    return v.isoformat(timespec="seconds") if v is not None else None


def _aware(v: datetime | None) -> datetime | None:
    return None if v is None else (v if v.tzinfo else v.replace(tzinfo=UTC))


_EVM_TX = re.compile(r"0x[0-9a-f]{64}")
_TRON_TX = re.compile(r"[0-9a-f]{64}")


def clean_tx_hash(chain: str, value) -> str | None:
    """A transaction hash from an explorer / TronGrid answer, checked before it is stored: EVM 0x + 64 hex,
    TRON 64 hex (lower-case). Anything else (an oversized or malformed value from a misbehaving endpoint)
    is None."""
    v = str(value or "").strip().lower()
    if chain == "tron":
        v = v.removeprefix("0x")
        return v if _TRON_TX.fullmatch(v) else None
    return v if _EVM_TX.fullmatch(v) else None


def _read(http: FreezeHttp, settings, token: TokenContract, wallet: str):
    url = node_url(token.chain, settings)
    if token.is_tron:
        return issuers.read_tron(http, url, settings.trongrid_api_key, token, wallet)
    return issuers.read_evm(http, url, token, wallet)


def _failed(http: FreezeHttp, settings, token: TokenContract, wallet: str):
    if token.is_tron:
        return signals.fetch_failed_tron(http, node_url("tron", settings), settings.trongrid_api_key, wallet,
                                         token.contract)
    ex = issuers.explorer_for(token.chain, settings)
    if ex is None:
        return None
    return signals.fetch_failed_evm(http, ex, wallet, token.contract)


def event_lookup_unavailable(token: TokenContract, settings, block: int | None) -> str | None:
    """Why no explorer can be asked for the issuer's events of this token: no_explorer (none configured
    for the chain, AEGIS_FREEZE_EXPLORER=none, OP Mainnet without ETHERSCAN_API_KEY) | no_block; None when one can."""
    if token.is_tron:
        return None
    if issuers.explorer_for(token.chain, settings) is None:
        return "no_explorer"
    return "no_block" if block is None else None


def _event(http: FreezeHttp, settings, token: TokenContract, wallet: str, *, kind: str, block: int | None,
           from_block: int | None, after: datetime | None):
    """The issuer's latest `kind` event (added | removed | destroyed) for the wallet, or None."""
    if token.is_tron:
        name = {"added": "AddedBlackList", "removed": issuers.REMOVED_EVENT_NAME.get(token.issuer),
                "destroyed": issuers.DESTROYED_EVENT_NAME.get(token.issuer)}[kind]
        if not name:
            return None
        return issuers.find_freeze_event_tron(http, node_url("tron", settings), settings.trongrid_api_key, token,
                                              wallet, min_timestamp=after, event_name=name)
    ex = issuers.explorer_for(token.chain, settings)
    if ex is None or block is None:
        return None
    topic = {"added": token.added_topic, "removed": token.removed_topic, "destroyed": token.destroyed_topic}[kind]
    if topic is None:
        return None
    lo = from_block if from_block is not None else max(0, block - settings.aegis_freeze_log_lookback_blocks)
    return issuers.find_freeze_event_evm(http, ex, token, wallet, from_block=lo, to_block=block, topic=topic,
                                         indexed=False if kind == "destroyed" else None)


def _freeze_event(http: FreezeHttp, settings, token: TokenContract, target: Target, block: int | None):
    return _event(http, settings, token, target.address, kind="added", block=block, from_block=target.first_block,
                  after=target.first_at)


def _event_meta(ev) -> dict:
    return {"host": ev.host, "sha256": ev.sha256, "block": ev.block_number, "requests": ev.requests}


def _claim_run(db: Session, setting: FreezeSetting) -> None:
    """One run of a case's checks at a time (a manual run and a scheduler pass, two clicks): a conditional
    UPDATE claims the case; a claim older than RUN_LEASE (a crashed run) is taken over. Commits."""
    now = datetime.now(tz=UTC)
    res = db.execute(update(FreezeSetting).where(
        FreezeSetting.id == setting.id, FreezeSetting.enabled.is_(True),
        or_(FreezeSetting.run_started_at.is_(None), FreezeSetting.run_started_at < now - RUN_LEASE),
    ).values(run_started_at=now).execution_options(synchronize_session=False))
    db.commit()
    if res.rowcount != 1:
        raise FreezeChecksDisabled("run_in_progress")
    db.refresh(setting)


def _release_run(db: Session, setting_id: int) -> None:
    db.execute(update(FreezeSetting).where(FreezeSetting.id == setting_id).values(run_started_at=None)
               .execution_options(synchronize_session=False))
    db.commit()


def run_checks(db: Session, case: Case, *, http: FreezeHttp | None = None, settings=None, trigger: str = "manual",
               transport=None) -> CheckReport:
    """Read every target's issuer contracts once, store the readings and emit freeze_detected on a flip to
    blacklisted (freeze_lifted on a flip back). Raises FreezeChecksDisabled (nothing sent) unless the case's
    setting is on, the endpoints are the consented ones and no other run of the case is in progress. Commits."""
    settings = _settings(settings)
    if settings.freeze_checks_disabled:
        raise FreezeChecksDisabled("deployment_disabled")
    setting = setting_for(db, case)
    if setting is None or not setting.enabled:
        raise FreezeChecksDisabled("case_setting_off")
    if new_hosts(setting, settings):
        raise FreezeChecksDisabled("consent_outdated")
    _claim_run(db, setting)
    setting_id = setting.id
    try:
        report = _run(db, case, setting, http=http, settings=settings, trigger=trigger, transport=transport)
    except BaseException:
        db.rollback()
        _release_run(db, setting_id)
        raise
    return report


def _run(db: Session, case: Case, setting: FreezeSetting, *, http, settings, trigger: str, transport) -> CheckReport:
    report = CheckReport()
    tg = targets(db, case)
    report.wallets = len(tg)
    own = http is None
    http = http or FreezeHttp(settings, transport=transport)
    prev_ok = _latest(db, case, ok_only=True)
    kinds = service_kinds(db, case)
    try:
        for t in tg:
            for token in t.contracts():
                if not node_url(token.chain, settings):
                    report.skipped.append({"chain": token.chain, "reason": "no_rpc_configured"})
                    continue
                key = (t.chain, t.address, token.contract_id)
                earlier = prev_ok.get(key)
                row = FreezeCheck(case_id=case.id, chain=t.chain, address=t.address, issuer=token.issuer,
                                  token_symbol=token.symbol, token_contract=token.contract_id, source=t.source,
                                  watch_id=t.watch.id if t.watch is not None else None, trigger=trigger, meta={},
                                  failed_count=0, method="rpc")
                try:
                    reading = _read(http, settings, token, t.address)
                except (FreezeHttpError, ValueError) as exc:
                    reason = exc.reason if isinstance(exc, FreezeHttpError) else "bad_response"
                    row.status, row.error, row.checked_at = "error", reason[:64], datetime.now(tz=UTC)
                    row.meta = {"host": getattr(exc, "host", None)}
                    db.add(row)
                    report.errors += 1
                    continue
                row.status, row.blacklisted, row.balance = "ok", reading.blacklisted, reading.balance
                row.block_number, row.checked_at, row.raw_sha256 = reading.block_number, reading.checked_at, reading.raw_sha256
                meta: dict = {"responses": reading.responses}
                if reading.balance_raw is not None:
                    meta["balance_raw"] = str(reading.balance_raw)  # exact (SQLite stores Numeric as a float)
                attempts = None
                try:
                    got = _failed(http, settings, token, t.address)
                    if got is not None:
                        attempts, sha = got
                        meta["txlist_sha256"] = sha
                except (FreezeHttpError, ValueError) as exc:
                    meta["failed_tx_error"] = getattr(exc, "reason", "bad_response")
                if attempts is not None and attempts.count:
                    row.failed_count, row.first_failed_at = attempts.count, attempts.first_at
                    row.first_failed_tx = clean_tx_hash(t.chain, attempts.first_tx)
                    meta["failed_txs"] = [{**tx, "hash": clean_tx_hash(t.chain, tx.get("hash"))} for tx in attempts.txs]
                if reading.blacklisted:
                    report.blacklisted += 1
                    _freeze_time(http, settings, token, t, reading, row, meta, earlier, attempts)
                    _destroyed(http, settings, token, t, reading, row, meta, earlier)
                elif earlier is not None and earlier.blacklisted:
                    meta["unfrozen"] = _lifted(http, settings, token, t, reading, earlier)
                elif earlier is not None and (earlier.meta or {}).get("unfrozen"):
                    meta["unfrozen"] = {**earlier.meta["unfrozen"], "carried_from": earlier.id}
                row.meta = meta
                db.add(row)
                db.flush()
                report.checked += 1
                if reading.blacklisted and (earlier is None or not earlier.blacklisted):
                    _emit_freeze(db, case, row)
                    report.newly_frozen.append(row.id)
                elif not reading.blacklisted and earlier is not None and earlier.blacklisted:
                    _emit_lifted(db, case, row, meta["unfrozen"])
                    report.newly_lifted.append(row.id)
                elif earlier is not None and funds_dropped(earlier, row) and swept_into(t, kinds, t.key):
                    report.swept.append(row.id)  # a deposit address swept into its service: expected, no alert
                elif earlier is not None and funds_dropped(earlier, row) and service_float(t, kinds, t.key):
                    report.float_moved.append(row.id)  # a service's float paying out: never the case's funds leaving
                elif earlier is not None and funds_dropped(earlier, row) and not pooled_float(
                        exact_balance(earlier), exact_balance(row), t.taint_usd, is_service(t, kinds, t.key)) and \
                        _emit_left(db, case, row, earlier):
                    report.funds_left.append(row.id)
                prev_ok[key] = row
    finally:
        report.requests, report.hosts = http.requests, sorted(http.hosts)
        if own:
            http.close()
    setting.last_run_at = datetime.now(tz=UTC)
    setting.last_result = {**report.counts(), "trigger": trigger}
    setting.run_started_at = None
    db.commit()
    return report


def _freeze_time(http, settings, token: TokenContract, t: Target, reading, row: FreezeCheck, meta: dict,
                 earlier: FreezeCheck | None, attempts) -> None:
    """frozen_at / frozen_at_basis / freeze_tx_hash of a blacklisted reading. An event found once is reused.
    Without one, the upper bound never moves later: the earliest of an earlier blacklisted reading's own
    bound (the same freeze: no flip between), the first failed transfer and this check."""
    still = earlier is not None and earlier.blacklisted
    if still and earlier.frozen_at_basis == "event":
        row.freeze_tx_hash, row.frozen_at, row.frozen_at_basis = earlier.freeze_tx_hash, earlier.frozen_at, "event"
        meta["freeze_event"] = {**(earlier.meta or {}).get("freeze_event", {}), "reused": earlier.id}
        return
    why = event_lookup_unavailable(token, settings, reading.block_number)
    ev = None
    if why is None:
        try:
            ev = _freeze_event(http, settings, token, t, reading.block_number)
        except (FreezeHttpError, ValueError) as exc:
            meta["freeze_event_error"] = getattr(exc, "reason", "bad_response")
    else:
        meta["freeze_event_lookup"] = why
    tx = clean_tx_hash(t.chain, ev.tx_hash) if ev is not None else None
    if ev is not None and ev.tx_hash and tx is None:
        meta["freeze_event_error"] = "bad_tx_hash"
    if tx is not None:
        row.freeze_tx_hash, row.frozen_at, row.frozen_at_basis = tx, ev.at, "event"
        meta["freeze_event"] = _event_meta(ev)
        return
    if why is None and "freeze_event_error" not in meta:
        meta["freeze_event_lookup"] = "not_found"
    bounds: list[tuple[datetime, str, int | None]] = [(_aware(reading.checked_at), "check_time", None)]
    if attempts is not None and attempts.count and attempts.first_at is not None:
        bounds.append((_aware(attempts.first_at), "first_failed_transfer", None))
    if still and earlier.frozen_at is not None:
        src = (earlier.meta or {}).get("frozen_at_source") or "check_time"
        bounds.append((_aware(earlier.frozen_at), src, (earlier.meta or {}).get("frozen_at_check") or earlier.id))
    at, source, from_check = min(bounds, key=lambda b: b[0])
    row.frozen_at, row.frozen_at_basis = at, "at_or_before"
    meta["frozen_at_source"] = source
    if from_check is not None:
        meta["frozen_at_check"] = from_check  # the earlier reading whose bound this is


def _lifted(http, settings, token: TokenContract, t: Target, reading, earlier: FreezeCheck) -> dict:
    """The record of an issuer lifting a blacklist (the earlier reading was blacklisted, this one is not):
    when it was frozen, and when it was removed (the issuer's removal event, else at or before this check)."""
    info = {"previous_check_id": earlier.id, "was_frozen_at": _iso(_aware(earlier.frozen_at)),
            "was_frozen_at_basis": earlier.frozen_at_basis, "was_freeze_tx": earlier.freeze_tx_hash,
            "last_blacklisted_at": _iso(_aware(earlier.checked_at)),
            "last_blacklisted_balance": str(exact_balance(earlier)) if exact_balance(earlier) is not None else None,
            "removed_at": _iso(_aware(reading.checked_at)), "removed_at_basis": "at_or_before", "removed_tx": None}
    why = event_lookup_unavailable(token, settings, reading.block_number)
    if why is not None:
        info["removed_event_lookup"] = why
        return info
    after = _aware(earlier.checked_at)
    try:
        ev = _event(http, settings, token, t.address, kind="removed", block=reading.block_number,
                    from_block=earlier.block_number, after=after - timedelta(minutes=10) if after else None)
    except (FreezeHttpError, ValueError) as exc:
        info["removed_event_error"] = getattr(exc, "reason", "bad_response")
        return info
    tx = clean_tx_hash(t.chain, ev.tx_hash) if ev is not None else None
    if tx is not None and ev.at is not None and after is not None and ev.at < after - timedelta(minutes=10):
        tx = None  # a removal from before the last blacklisted reading: an earlier lift, not this one
    if tx is None:
        info["removed_event_lookup"] = "not_found"
        return info
    info.update(removed_at=_iso(ev.at) if ev.at else info["removed_at"], removed_at_basis="event" if ev.at else "at_or_before",
                removed_tx=tx, removed_event=_event_meta(ev))
    return info


def _destroyed(http, settings, token: TokenContract, t: Target, reading, row: FreezeCheck, meta: dict,
               earlier: FreezeCheck | None) -> None:
    """Tether can burn a blacklisted wallet's balance (DestroyedBlackFunds): the balance falls to zero while the
    wallet stays blacklisted. Recorded (with the event when the explorer has it) and carried on later readings."""
    if earlier is None or not earlier.blacklisted:
        return
    carried = (earlier.meta or {}).get("balance_destroyed")
    if carried and not reading.balance_raw:
        meta["balance_destroyed"] = {**carried, "carried_from": earlier.id}
        return
    before = exact_balance(earlier)
    if before is None or before <= 0 or reading.balance_raw != 0:
        return
    info = {"previous_check_id": earlier.id, "balance_before": str(before), "after": _iso(_aware(earlier.checked_at)),
            "at": _iso(_aware(reading.checked_at)), "basis": "at_or_before", "tx": None}
    if token.destroyed_topic is not None or token.is_tron:
        if event_lookup_unavailable(token, settings, reading.block_number) is None:
            try:
                ev = _event(http, settings, token, t.address, kind="destroyed", block=reading.block_number,
                            from_block=earlier.block_number, after=_aware(earlier.checked_at))
            except (FreezeHttpError, ValueError):
                ev = None
            tx = clean_tx_hash(t.chain, ev.tx_hash) if ev is not None else None
            if tx is not None:
                info.update(tx=tx, at=_iso(ev.at) if ev.at else info["at"], basis="event" if ev.at else "at_or_before")
    meta["balance_destroyed"] = info


# --------------------------------------------------------------------------- status
EVENT_NOTES = {
    "no_explorer": "no explorer is configured for this chain, so the blacklist event was not looked up",
    "no_block": "the node reported no block, so the blacklist event was not looked up",
    "not_found": "the blacklist event was not found in the explorer's logs",
    "not_found_tron": "the blacklist event was not found in TronGrid's events",
}
SOURCE_NOTES = {"first_failed_transfer": "the first failed transfer", "check_time": "the check time"}


def frozen_at_note(row: FreezeCheck) -> str | None:
    """Why a blacklisted reading has only an upper bound for its freeze time (shown next to it)."""
    if not row.blacklisted or row.frozen_at_basis != "at_or_before":
        return None
    meta = row.meta or {}
    source = SOURCE_NOTES.get(meta.get("frozen_at_source"), "the check time")
    if meta.get("frozen_at_check") and meta.get("frozen_at_source") in (None, "check_time"):
        source = "the first check that read it blacklisted"  # carried forward: the bound never moves later
    err = meta.get("freeze_event_error")
    lookup = meta.get("freeze_event_lookup")
    if err:
        why = f"the blacklist event lookup failed ({err})"
    elif lookup in ("no_explorer", "no_block"):
        why = EVENT_NOTES[lookup]
    else:
        why = EVENT_NOTES["not_found_tron" if row.chain == "tron" else "not_found"]
    return f"{source}; {why}"


def _unfrozen_dict(row: FreezeCheck) -> dict | None:
    info = (row.meta or {}).get("unfrozen")
    if not info or row.blacklisted:
        return None
    token = issuers.contract_by_id(row.chain, row.token_contract)
    removed_basis = info.get("removed_at_basis") or "at_or_before"
    if removed_basis == "event":
        note = None
    elif info.get("removed_event_error"):
        note = f"the removal event lookup failed ({info['removed_event_error']})"
    elif info.get("removed_event_lookup") in ("no_explorer", "no_block"):
        note = EVENT_NOTES[info["removed_event_lookup"]].replace("blacklist event", "removal event")
    else:
        note = (f"after the last blacklisted reading ({_fmt_iso(info.get('last_blacklisted_at'))}); the removal event "
                "was not found")
    bal = info.get("last_blacklisted_balance")
    return {
        "was_frozen_at": info.get("was_frozen_at"), "was_frozen_at_basis": info.get("was_frozen_at_basis"),
        "was_freeze_tx": info.get("was_freeze_tx"), "removed_at": info.get("removed_at"),
        "removed_at_basis": removed_basis, "removed_tx": info.get("removed_tx"), "removed_note": note,
        "last_blacklisted_at": info.get("last_blacklisted_at"),
        "last_blacklisted_balance_label": fmt_amount(Decimal(bal)) if bal else None,
        "event_name": issuers.REMOVED_EVENT_NAME.get(token.issuer) if token else None,
    }


def _destroyed_dict(row: FreezeCheck) -> dict | None:
    info = (row.meta or {}).get("balance_destroyed")
    if not info or not row.blacklisted:
        return None
    bal = info.get("balance_before")
    return {"balance_before_label": fmt_amount(Decimal(bal)) if bal else None, "at": info.get("at"),
            "basis": info.get("basis"), "tx": info.get("tx"), "after": info.get("after")}


def _fmt_iso(v) -> str:
    d = _dt(v)
    return f"{d:%d %b %Y %H:%M} UTC" if d is not None else "an earlier check"


def _check_dict(row: FreezeCheck, h: History | None = None) -> dict:
    d = _reading_dict(row)
    failed = h.failed_since if h is not None else None
    d["last_attempt"] = ({"status": failed.status, "error": failed.error, "checked_at": _iso(_aware(failed.checked_at))}
                         if failed is not None else None)
    d["stale_note"] = (f"last checked OK {_fmt_iso(d['checked_at'])}; the last attempt failed ({failed.error or 'error'}, "
                       f"{_fmt_iso(_iso(_aware(failed.checked_at)))})" if failed is not None else None)
    left = h.left if h is not None else None
    if left is not None:
        a, b = exact_balance(left[0]), exact_balance(left[1])
        usd = to_usd(row.token_symbol, a - b) if a is not None and b is not None else None
        d["funds_left"] = {"from": str(a), "to": str(b), "from_label": fmt_amount(a), "to_label": fmt_amount(b),
                           "from_at": _iso(_aware(left[0].checked_at)), "at": _iso(_aware(left[1].checked_at)),
                           "usd": float(usd) if usd is not None else None, "check_id": left[1].id,
                           "previous_check_id": left[0].id}
    else:
        d["funds_left"] = None
    falls = []
    for x, y in (h.falls if h is not None else ()):
        a, b = exact_balance(x), exact_balance(y)
        usd = to_usd(row.token_symbol, a - b) if a is not None and b is not None else None
        falls.append({"usd": float(usd) if usd is not None else None, "at": _iso(_aware(y.checked_at))})
    d["falls"] = falls
    return d


def _reading_dict(row: FreezeCheck) -> dict:
    bal = exact_balance(row)
    usd = to_usd(row.token_symbol, bal) if bal is not None else None
    meta = row.meta or {}
    return {
        "id": row.id, "issuer": row.issuer, "symbol": row.token_symbol, "contract": row.token_contract,
        "status": row.status, "error": row.error, "blacklisted": row.blacklisted,
        "balance": str(bal) if bal is not None else None, "balance_label": fmt_amount(bal),
        "usd": float(usd) if usd is not None else None, "block_number": row.block_number,
        "checked_at": row.checked_at.isoformat(timespec="seconds") if row.checked_at else None,
        "method": row.method, "raw_sha256": row.raw_sha256, "freeze_tx_hash": row.freeze_tx_hash,
        "frozen_at": row.frozen_at.isoformat(timespec="seconds") if row.frozen_at else None,
        "frozen_at_basis": row.frozen_at_basis, "frozen_at_source": meta.get("frozen_at_source"),
        "failed_count": row.failed_count or 0, "first_failed_tx": row.first_failed_tx,
        "first_failed_at": row.first_failed_at.isoformat(timespec="seconds") if row.first_failed_at else None,
        "failed_txs": list(meta.get("failed_txs") or [])[:10], "trigger": row.trigger,
        "label": onchain_label(row.issuer, row.token_symbol, bal) if row.blacklisted else None,
        "frozen_at_note": frozen_at_note(row), "unfrozen": _unfrozen_dict(row) if row.status == "ok" else None,
        "balance_destroyed": _destroyed_dict(row),
    }


def _state(checks: list[dict]) -> str:
    if not checks:
        return "unchecked"
    if any(c["blacklisted"] for c in checks):
        return "frozen"
    if any(c.get("unfrozen") for c in checks):
        return "unfrozen"  # the issuer lifted its blacklist: the funds can move again
    if any(c["failed_count"] for c in checks if c["status"] == "ok"):
        return "failing"
    if all(c["status"] == "error" for c in checks):
        return "error"
    return "clear"


def wallet_rows(db: Session, case: Case, *, settings=None) -> list[dict]:
    """One row per target wallet (and per earlier-checked wallet no longer a target) with its latest good reading
    per issuer contract (a failed attempt after it never shadows it: `last_attempt` / `stale_note` say so; only a
    contract never read OK shows the error) and the latest fall in balance between two good readings (`funds_left`)."""
    by_wallet: dict[tuple[str, str], list[tuple[FreezeCheck, History]]] = {}
    for (chain, addr, _c), h in history(db, case).items():
        by_wallet.setdefault((chain, addr), []).append((h.shown, h))
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    settings = _settings(settings)
    run = latest_run(db, case)
    since = _aware(run.finished_at or run.started_at) if run is not None else None
    dropped = any(h.left for hs in by_wallet.values() for _, h in hs)
    kinds = service_kinds(db, case) if dropped else {}
    nodes: dict[tuple[str, str], Target] = {}  # the trace's view of an earlier-checked wallet (no longer a target)
    if dropped and run is not None:
        for n in db.scalars(select(TraceNode).where(TraceNode.run_id == run.id)
                            .options(selectinload(TraceNode.address).selectinload(Address.entity))):
            a = n.address
            k = wallet_key(a.chain.value, a.address)
            nodes[k] = Target(k[0], k[1], None, in_trace=True, entity=a.entity.name if a.entity else None,
                              entity_category=a.entity.category.value if a.entity else None,
                              taint_usd=float(n.taint_usd or 0),
                              address_type=a.address_type.value if a.address_type else None)

    def row_for(chain, addr, *, target: Target | None):
        checks = sorted((_check_dict(r, h) for r, h in by_wallet.get((chain, addr), [])),
                        key=lambda c: (c["issuer"], c["symbol"]))
        w = target.watch if target is not None else None
        pending = [] if target is None else [f"{c.issuer} {c.symbol}" for c in target.contracts()
                                             if c.contract_id not in {k["contract"] for k in checks}]
        blocked = [] if target is None else sorted({CHAIN_LABELS.get(c.chain, c.chain) for c in target.contracts()
                                                     if not node_url(c.chain, settings)})
        for c in checks:  # a service's float moving / a deposit address swept is not the case's funds leaving
            f = c.get("funds_left")
            if not f:
                continue
            t = target or nodes.get(wallet_key(chain, addr))
            into = swept_into(t, kinds, (chain, addr))
            at = _dt(f.get("at"))
            if since is not None and at is not None and _aware(at) < since.replace(microsecond=0):
                c["left_before_trace"], c["funds_left"] = f, None  # re-traced since: the trace shows where they went
            elif into:
                # every fall of a deposit address is its service's sweep: the account was credited all of them
                total = sum(x["usd"] or 0 for x in c.get("falls") or []) or f.get("usd")
                c["swept"], c["funds_left"] = {**f, "owner": into, "total_usd": total}, None
            elif (pool := service_float(t, kinds, (chain, addr))):
                c["float_moved"], c["funds_left"] = {**f, "owner": pool}, None
            elif pooled_float(f["from"], f["to"], t.taint_usd if t is not None else 0.0, is_service(t, kinds, (chain, addr))):
                c["float_moved"], c["funds_left"] = f, None
        frozen = [c for c in checks if c["blacklisted"]]
        return {
            "chain": chain, "chain_label": CHAIN_LABELS.get(chain, chain), "address": addr, "short": short_address(addr),
            "source": target.source if target is not None else "earlier",
            "in_trace": bool(target and target.in_trace), "watch_id": w.id if w is not None else None,
            "label": (target.label if target is not None else None), "entity": target.entity if target else None,
            "address_type": target.address_type if target is not None else None,
            "entity_category": target.entity_category if target is not None else None,
            "tlp": w.tlp if w is not None else None, "source_note": w.source_note if w is not None else None,
            "checks": checks, "state": _state(checks), "pending": pending, "not_configured": blocked,
            "frozen_usd": sum(c["usd"] or 0 for c in frozen),
            "label_text": "; ".join(c["label"] for c in frozen) or None,
            "stale": [c for c in checks if c.get("stale_note")], "funds_left": [c for c in checks if c.get("funds_left")],
        }

    for t in targets(db, case, run):
        seen.add(t.key)
        rows.append(row_for(t.chain, t.address, target=t))
    for key in by_wallet:
        if key not in seen:
            rows.append(row_for(*key, target=None))
    order = {"unfrozen": 0, "frozen": 1, "failing": 2, "error": 3, "unchecked": 4, "clear": 5}
    rows.sort(key=lambda r: (order.get(r["state"], 9), -r["frozen_usd"], r["chain"], r["address"]))
    return rows


def not_visible_services(db: Session, case: Case) -> list[str]:
    """Exchange / casino / OTC services in the latest trace: their accounts cannot be seen on-chain."""
    from app.tracing.annotate import short_entity

    run = latest_run(db, case)
    if run is None:
        return []
    names = set()
    for n in db.scalars(select(TraceNode).where(TraceNode.run_id == run.id)
                        .options(selectinload(TraceNode.address).selectinload(Address.entity))):
        e = n.address.entity
        if e is not None and e.category in NOT_VISIBLE_CATEGORIES:
            names.add(short_entity(e.name))
    return sorted(names, key=str.lower)


def case_status(db: Session, case: Case, *, settings=None) -> dict:
    """Everything the overview, the freeze page, the graph and the assistant show (no network)."""
    settings = _settings(settings)
    row = setting_for(db, case)
    wallets = wallet_rows(db, case, settings=settings)
    frozen = [w for w in wallets if w["state"] == "frozen"]
    started = _aware(row.run_started_at) if row is not None else None
    return {
        "enabled": bool(row is not None and row.enabled), "deployment_disabled": bool(settings.freeze_checks_disabled),
        "consent_outdated": new_hosts(row, settings),  # hosts not consented to: re-confirm before the next run
        "running": bool(started is not None and datetime.now(tz=UTC) - started < RUN_LEASE),
        "unfrozen": [w for w in wallets if w["state"] == "unfrozen"],
        "enabled_at": row.enabled_at if row is not None else None,
        "last_run_at": row.last_run_at if row is not None else None,
        "last_result": dict(row.last_result or {}) if row is not None else {},
        "consent_hosts": list((row.consent or {}).get("hosts") or []) if row is not None else [],
        "interval_minutes": settings.aegis_freeze_check_minutes,
        "wallets": wallets, "frozen": frozen,
        "failing": [w for w in wallets if w["state"] == "failing"],
        "unchecked": [w for w in wallets if w["state"] == "unchecked"],
        "errors": [w for w in wallets if w["state"] == "error"],
        "stale": [w for w in wallets if w["stale"]],  # read OK earlier, the last attempt failed: the OK reading shows
        "moved": [w for w in wallets if w["funds_left"]],  # the balance fell between two good readings
        "frozen_usd": round(sum(w["frozen_usd"] for w in frozen), 2),
        "n_wallets": len(wallets), "n_checked": sum(1 for w in wallets if w["checks"]),
        "not_visible": not_visible_services(db, case),
        "explorer_tx": issuers.EXPLORER_TX, "explorer_address": issuers.EXPLORER_ADDRESS,
    }


def wallet_states(db: Session, case: Case) -> dict[tuple[str, str], dict]:
    """(chain, address key) -> wallet row, for the graph (trace wallets that have a reading)."""
    if db.scalar(select(FreezeCheck.id).where(FreezeCheck.case_id == case.id).limit(1)) is None:
        return {}
    return {wallet_key(w["chain"], w["address"]): w for w in wallet_rows(db, case) if w["checks"]}


# --------------------------------------------------------------------------- scheduler
def due_settings(db: Session, now: datetime, settings=None) -> list[FreezeSetting]:
    settings = _settings(settings)
    if settings.freeze_checks_disabled:
        return []
    every = timedelta(minutes=max(1, settings.aegis_freeze_check_minutes))
    out = []
    for row in db.scalars(select(FreezeSetting).where(FreezeSetting.enabled.is_(True)).order_by(FreezeSetting.case_id)):
        case = db.get(Case, row.case_id)
        if case is None or case.status != "open":
            continue
        if row.last_run_at is None or now - row.last_run_at >= every:
            out.append(row)
    return out


def run_due(db: Session, *, now: datetime | None = None, settings=None, transport=None) -> dict:
    """The scheduler's pass: run the checks of every enabled open case whose last run is older than
    AEGIS_FREEZE_CHECK_MINUTES. Each run is audited as FREEZE_CHECK (actor: none, trigger scheduler)."""
    from app.core.audit import audit

    now = now or datetime.now(tz=UTC)
    out = {"cases": 0, "checked": 0, "newly_frozen": 0, "newly_lifted": 0, "errors": 0, "failed_cases": 0}
    for row in due_settings(db, now, settings):
        case = db.get(Case, row.case_id)
        try:
            rep = run_checks(db, case, settings=settings, trigger="scheduler", transport=transport)
        except FreezeChecksDisabled as exc:
            if exc.reason == "consent_outdated" and (row.last_result or {}).get("refused") != "consent_outdated":
                # audited once (not on every pass) until a case admin confirms the new endpoints
                row.last_result = {**(row.last_result or {}), "refused": "consent_outdated"}
                db.commit()
                audit(db, None, "FREEZE_CHECK", case, ("freeze_checks", None), outcome="denied", trigger="scheduler",
                      reason=exc.reason, hosts=new_hosts(row, settings))
            continue
        except Exception:
            db.rollback()
            log.exception("freeze checks failed for case id %s", case.id)
            out["failed_cases"] += 1  # the run itself failed (an exception), not a reading
            continue
        audit(db, None, "FREEZE_CHECK", case, ("freeze_checks", None), trigger="scheduler", **rep.counts())
        out["cases"] += 1
        out["checked"] += rep.checked
        out["newly_frozen"] += len(rep.newly_frozen)
        out["newly_lifted"] += len(rep.newly_lifted)
        out["errors"] += rep.errors  # readings that failed (HTTP errors): the next run retries them
    return out
