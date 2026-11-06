"""Forward fund-flow tracer.

Model
-----
Breadth-first walk from the origin transaction (or the perpetrator wallet when
the origin hash is not yet known), following value *forward in time*. Each node
carries a USD "taint" — the portion of the victim's loss that could have
reached it. Allocation across a node's outgoing transfers is chronological
(FIFO-like): the earliest outflows absorb taint first until it is exhausted.
An edge whose amount is unknown (asserted by an investigator report but not
yet observed on-chain) passes the full remaining taint as an *upper bound*
and marks the downstream node `unquantified_taint`.

Stopping rules
--------------
* Deposit address at a freeze-capable service → record, follow the single
  sweep hop to the omnibus wallet, then stop (`vasp`).
* Omnibus / hot wallet → stop immediately (`vasp_omnibus`).
* Swap / bridge contract → do not enumerate the contract's outflows (they are
  every customer's); instead continue along the known cross-chain leg
  (`bridged_to`) and stop at the contract (`swap_service`).
* `max_hops`, `min_taint_usd`, `max_fanout` guards.

Everything fetched is persisted, so re-running a trace is cheap and the graph
can be diffed over time.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.models import (
    Address,
    AddressType,
    Case,
    Chain,
    DataSource,
    EntityCategory,
    SeedRole,
    TraceEdge,
    TraceNode,
    TraceRun,
    TraceStatus,
    Transfer,
)
from app.providers.base import ChainProvider, ProviderError
from app.providers.registry import get_provider
from app.tracing import heuristics
from app.tracing.repository import (
    REFUTED,
    get_or_create_address,
    ingest_transfer,
    link_bridge,
    normalise_address,
    outgoing_from_db,
)

log = logging.getLogger(__name__)

PROVIDER_SOURCE = {
    "etherscan": DataSource.ETHERSCAN,
    "blockscout": DataSource.BLOCKSCOUT,
    "trongrid": DataSource.TRONGRID,
    "mempool": DataSource.MEMPOOL,
    "fixture": DataSource.FIXTURE,
}


@dataclass
class NodeState:
    address: Address
    hop: int
    taint_usd: Decimal
    arrival: datetime | None
    confidence: float = 1.0
    unquantified: bool = False
    incoming: list[Transfer] = field(default_factory=list)
    outgoing: list[Transfer] = field(default_factory=list)
    terminal_reason: str | None = None
    extra_flags: list[str] = field(default_factory=list)


class Tracer:
    def __init__(self, db: Session, case: Case, settings: Settings | None = None, provider_mode: str | None = None):
        self.db = db
        self.case = case
        self.settings = settings or get_settings()
        self.provider_mode = provider_mode
        self.loss_usd: Decimal = Decimal(case.loss_usd or 0)
        self.now = datetime.now(tz=UTC)
        self.nodes: dict[int, NodeState] = {}
        self.edges: dict[int, tuple[int, Decimal]] = {}  # transfer_id -> (hop, taint)
        self.stats = {"provider_calls": 0, "transfers_ingested": 0, "truncated_fanout": 0, "cross_chain_hops": 0}

    # ------------------------------------------------------------------ providers
    def _provider(self, chain: Chain) -> ChainProvider:
        return get_provider(chain, self.provider_mode)

    def _source_for(self, provider: ChainProvider) -> DataSource:
        return PROVIDER_SOURCE.get(provider.name, DataSource.MANUAL)

    def _fetch_outgoing(self, addr: Address, since: datetime | None) -> list[Transfer]:
        provider = self._provider(addr.chain)
        try:
            raws = provider.outgoing_transfers(addr.address, since=since, limit=self.settings.trace_max_fanout * 4)
            self.stats["provider_calls"] += 1
        except (ProviderError, Exception) as exc:  # noqa: BLE001 - provider failures must not kill the run
            log.warning("outgoing fetch failed for %s: %s", addr.address, exc)
            raws = []
        for raw in raws:
            t = ingest_transfer(self.db, raw, self._source_for(provider))
            self.stats["transfers_ingested"] += 1
            if raw.bridged_to:
                self._resolve_bridge(t, raw.bridged_to)
        return outgoing_from_db(self.db, addr, since)

    def _fetch_incoming(self, addr: Address) -> list[Transfer]:
        provider = self._provider(addr.chain)
        try:
            raws = provider.incoming_transfers(addr.address, since=None, limit=200)
            self.stats["provider_calls"] += 1
        except (ProviderError, Exception) as exc:  # noqa: BLE001
            log.warning("incoming fetch failed for %s: %s", addr.address, exc)
            raws = []
        rows = [ingest_transfer(self.db, raw, self._source_for(provider)) for raw in raws]
        self.stats["transfers_ingested"] += len(rows)
        return [t for t in rows if t.confidence > REFUTED]

    def _resolve_bridge(self, src: Transfer, bridged_to: tuple[Chain, str]) -> Transfer | None:
        dst_chain, dst_hash = bridged_to
        dst = link_bridge(self.db, src, dst_chain, dst_hash)
        if dst:
            return dst
        provider = self._provider(dst_chain)
        try:
            detail = provider.get_tx(dst_hash)
            self.stats["provider_calls"] += 1
        except Exception as exc:  # noqa: BLE001
            log.warning("bridge leg fetch failed %s/%s: %s", dst_chain, dst_hash, exc)
            return None
        if not detail:
            return None
        rows = [ingest_transfer(self.db, raw, self._source_for(provider)) for raw in detail.transfers]
        self.stats["transfers_ingested"] += len(rows)
        return link_bridge(self.db, src, dst_chain, dst_hash)

    def _enrich(self, addr: Address) -> None:
        provider = self._provider(addr.chain)
        try:
            info = provider.address_info(addr.address)
            self.stats["provider_calls"] += 1
        except Exception:  # noqa: BLE001
            return
        get_or_create_address(self.db, addr.chain, addr.address, info=info)

    # ------------------------------------------------------------------ roots
    def _roots(self) -> list[NodeState]:
        roots: list[NodeState] = []
        origin = next((s for s in self.case.seeds if s.role == SeedRole.ORIGIN_TX), None)
        victim = next((s for s in self.case.seeds if s.role == SeedRole.VICTIM_WALLET), None)

        if origin:
            provider = self._provider(origin.chain)
            detail = None
            try:
                detail = provider.get_tx(origin.value)
                self.stats["provider_calls"] += 1
            except Exception as exc:  # noqa: BLE001
                log.warning("origin tx fetch failed: %s", exc)
            if detail:
                victim_norm = normalise_address(origin.chain, victim.value) if victim else None
                for raw in detail.transfers:
                    t = ingest_transfer(self.db, raw, self._source_for(provider))
                    frm, to = t.from_address, t.to_address
                    if victim_norm and frm.address == victim_norm:
                        frm.address_type = AddressType.VICTIM
                    if frm.address_type == AddressType.VICTIM or victim is None:
                        to.address_type = (
                            AddressType.PERPETRATOR if to.address_type == AddressType.UNKNOWN else to.address_type
                        )
                        taint = t.amount_usd if t.amount_usd is not None else self.loss_usd
                        taint = min(taint, self.loss_usd) if self.loss_usd else taint
                        self.nodes[frm.id] = NodeState(frm, 0, taint, t.timestamp, t.confidence, outgoing=[t])
                        self.edges[t.id] = (0, taint)
                        roots.append(NodeState(to, 1, taint, t.timestamp, t.confidence, incoming=[t]))
        if not roots:
            for seed in (s for s in self.case.seeds if s.role == SeedRole.PERPETRATOR_WALLET):
                addr = get_or_create_address(self.db, seed.chain, seed.value, address_type=AddressType.PERPETRATOR)
                roots.append(NodeState(addr, 1, self.loss_usd, self.case.fraud_date, 1.0))
        return roots

    # ------------------------------------------------------------------ terminal rules
    def _terminal_reason(self, addr: Address, hop: int) -> str | None:
        ent = addr.entity
        if ent is None:
            return None
        if addr.address_type == AddressType.HOT_WALLET:
            return "vasp_omnibus"
        if ent.category in (EntityCategory.SWAP_SERVICE, EntityCategory.BRIDGE, EntityCategory.DEX):
            return "swap_service"
        if ent.category in (EntityCategory.EXCHANGE, EntityCategory.CASINO, EntityCategory.OTC, EntityCategory.MIXER):
            return "vasp"
        return None

    # ------------------------------------------------------------------ main loop
    def run(self) -> TraceRun:
        run = TraceRun(
            case=self.case, status=TraceStatus.RUNNING,
            params={
                "max_hops": self.settings.trace_max_hops, "max_fanout": self.settings.trace_max_fanout,
                "min_taint_usd": self.settings.trace_min_taint_usd,
                "provider_mode": self.provider_mode or self.settings.provider_mode,
            },
        )
        self.db.add(run)
        self.db.flush()
        try:
            self._walk()
            self._persist(run)
            run.status = TraceStatus.COMPLETE
        except Exception as exc:
            log.exception("trace failed")
            run.status = TraceStatus.FAILED
            run.error = str(exc)
        run.finished_at = datetime.now(tz=UTC)
        run.stats = self.stats
        self.db.commit()
        return run

    def _walk(self) -> None:
        queue: deque[NodeState] = deque(self._roots())
        max_hops = self.settings.trace_max_hops
        min_taint = Decimal(str(self.settings.trace_min_taint_usd))
        max_fanout = self.settings.trace_max_fanout

        while queue:
            state = queue.popleft()
            addr = state.address
            existing = self.nodes.get(addr.id)
            if existing is not None:
                # merge: accumulate taint (bounded by the loss), keep the shortest path
                existing.taint_usd = min(existing.taint_usd + state.taint_usd, self.loss_usd or existing.taint_usd + state.taint_usd)
                existing.incoming.extend(t for t in state.incoming if t not in existing.incoming)
                existing.unquantified = existing.unquantified or state.unquantified
                earlier = bool(state.arrival and existing.arrival and state.arrival < existing.arrival)
                if state.arrival and (existing.arrival is None or state.arrival < existing.arrival):
                    existing.arrival = state.arrival
                if earlier:
                    # Reached first (fewer hops) through a *later* inflow, now through an earlier one:
                    # the outflows between the two arrivals (e.g. a deposit address's sweep to the
                    # omnibus wallet) were never looked at. Evaluate them with the earlier taint.
                    self._reexpand(existing, state, queue, min_taint, max_fanout, max_hops)
                continue

            self.nodes[addr.id] = state
            self._enrich(addr)
            self.db.refresh(addr)

            # Always pull incoming for attribution context (pre-fraud activity etc.)
            state.incoming = list({t.id: t for t in state.incoming + self._fetch_incoming(addr)}.values())

            state.terminal_reason = self._terminal_reason(addr, state.hop)
            if state.terminal_reason == "swap_service":
                self._continue_cross_chain(state, queue, min_taint)
                continue
            if state.terminal_reason == "vasp_omnibus":
                continue
            if state.hop >= max_hops:
                state.terminal_reason = state.terminal_reason or "max_hops"
                continue

            outgoing = self._outflows(state, state.arrival)
            state.outgoing = outgoing
            self._allocate(state, outgoing, state.taint_usd, queue, min_taint, max_fanout)

    def _outflows(self, state: NodeState, since: datetime | None) -> list[Transfer]:
        outgoing = self._fetch_outgoing(state.address, since)
        if state.terminal_reason == "vasp":
            # deposit address: show the sweep to the omnibus wallet, nothing further
            outgoing = [t for t in outgoing if t.to_address.entity_id == state.address.entity_id]
        return outgoing

    def _reexpand(self, existing: NodeState, earlier: NodeState, queue: deque[NodeState], min_taint: Decimal,
                  max_fanout: int, max_hops: int) -> None:
        """Follow the outflows that only an earlier arrival makes eligible (they predate the arrival
        the node was first expanded from)."""
        if existing.terminal_reason not in (None, "vasp") or existing.hop >= max_hops:
            return
        known = {t.id for t in existing.outgoing}
        fresh = [t for t in self._outflows(existing, earlier.arrival) if t.id not in known]
        if not fresh:
            return
        existing.outgoing.extend(fresh)
        self.stats["reexpanded"] = self.stats.get("reexpanded", 0) + 1
        self._allocate(existing, fresh, earlier.taint_usd, queue, min_taint, max_fanout)

    def _allocate(self, state: NodeState, outgoing: list[Transfer], taint: Decimal, queue: deque[NodeState],
                  min_taint: Decimal, max_fanout: int) -> None:
        addr = state.address
        # fan-out guard: keep asserted links (amount None) and the largest observed outflows
        ranked = sorted(outgoing, key=lambda t: (t.amount_usd is not None, -(t.amount_usd or 0)))
        if len(ranked) > max_fanout:
            self.stats["truncated_fanout"] += 1
            if "high_fanout" not in state.extra_flags:
                state.extra_flags.append("high_fanout")
            ranked = ranked[:max_fanout]
        # Allocate observed (quantified) outflows first, chronologically; asserted edges with
        # unknown amounts then carry only what is left as an upper bound.
        chosen = sorted(ranked, key=lambda t: (t.amount_usd is None, t.timestamp, t.sub_index))

        remaining = taint
        for t in chosen:
            if t.to_address_id == addr.id or t.id in self.edges:
                continue
            if t.amount_usd is None:
                edge_taint, unq = remaining, True
            else:
                edge_taint, unq = min(t.amount_usd, remaining), state.unquantified
                remaining -= edge_taint
            if edge_taint <= 0:
                continue
            self.edges[t.id] = (state.hop, edge_taint)
            if edge_taint < min_taint and not unq:
                continue
            queue.append(
                NodeState(
                    t.to_address, state.hop + 1, edge_taint, t.timestamp,
                    min(state.confidence, t.confidence), unq, incoming=[t],
                )
            )

    def _continue_cross_chain(self, state: NodeState, queue: deque[NodeState], min_taint: Decimal) -> None:
        """At a swap/bridge contract, hop to the known destination legs only."""
        for t in state.incoming:
            if t.id not in self.edges or t.bridged_to_transfer_id is None:
                continue
            dst: Transfer | None = self.db.get(Transfer, t.bridged_to_transfer_id)
            if dst is None:
                continue
            self.stats["cross_chain_hops"] += 1
            # The payout wallet (dst.from) belongs to the swap service; show it as part of the service
            payout = dst.from_address
            if payout.entity_id is None and state.address.entity_id is not None:
                payout.entity_id = state.address.entity_id
                payout.address_type = AddressType.HOT_WALLET
            if payout.id not in self.nodes:
                self.nodes[payout.id] = NodeState(payout, state.hop, Decimal(0), dst.timestamp,
                                                  terminal_reason="swap_service", extra_flags=["swap_service"])
            edge_taint = min(dst.amount_usd, self.edges[t.id][1]) if dst.amount_usd is not None else self.edges[t.id][1]
            self.edges[dst.id] = (state.hop, edge_taint)
            if edge_taint >= min_taint or dst.amount_usd is None:
                queue.append(
                    NodeState(dst.to_address, state.hop + 1, edge_taint, dst.timestamp,
                              min(state.confidence, dst.confidence), dst.amount_usd is None, incoming=[dst])
                )

    # ------------------------------------------------------------------ persistence
    def _persist(self, run: TraceRun) -> None:
        tainted_ids = set(self.nodes)
        # context nodes: senders of pre-fraud deposits into tainted VASP deposit addresses
        for state in list(self.nodes.values()):
            for t in state.incoming:
                if t.id in self.edges:
                    continue
                if t.from_address_id in tainted_ids:
                    continue
                if self.case.fraud_date and t.timestamp < self.case.fraud_date:
                    ctx = NodeState(t.from_address, state.hop, Decimal(0), t.timestamp,
                                    terminal_reason="context", extra_flags=["context_only"], outgoing=[t])
                    self.nodes.setdefault(t.from_address_id, ctx)
                    self.edges[t.id] = (state.hop, Decimal(0))

        for state in self.nodes.values():
            self.db.refresh(state.address)
            if "context_only" in state.extra_flags:
                flags = ["context_only", "pre_fraud_activity"]
            else:
                flags = heuristics.node_flags(
                    state.address, state.incoming, state.outgoing, state.arrival, self.case.fraud_date,
                    self.settings.trace_max_fanout, self.now,
                    taint_share=float(state.taint_usd / self.loss_usd) if self.loss_usd else 0.0,
                )
            for f in state.extra_flags:
                if f not in flags:
                    flags.append(f)
            if state.unquantified and "unquantified_taint" not in flags:
                flags.append("unquantified_taint")
            score = heuristics.risk_score(flags, state.taint_usd, self.loss_usd, state.hop, state.confidence)
            frac = float(state.taint_usd / self.loss_usd) if self.loss_usd else 0.0
            self.db.add(
                TraceNode(
                    run=run, address=state.address, hop=state.hop, taint_usd=state.taint_usd,
                    taint_fraction=min(1.0, frac), is_terminal=state.terminal_reason is not None,
                    terminal_reason=state.terminal_reason, risk_score=score, flags=flags,
                )
            )
        for transfer_id, (hop, taint) in self.edges.items():
            self.db.add(TraceEdge(run=run, transfer_id=transfer_id, hop=hop, taint_usd=taint))

        self.stats.update(
            nodes=len(self.nodes), edges=len(self.edges),
            terminal_vasp=sum(1 for s in self.nodes.values() if s.terminal_reason in ("vasp", "vasp_omnibus")),
            max_hop=max((s.hop for s in self.nodes.values()), default=0),
        )
