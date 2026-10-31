"""Compare two trace runs of a case: what a re-run added, removed or re-weighted.

Runs are versions: a re-run never edits an earlier run, so any two runs can be compared.

    base, head = snapshot(db, run_a), snapshot(db, run_b)
    d = diff_runs(base, head)     # pure function, no DB
    d.nodes_added, d.edges_removed, d.taint_changes, d.new_touchpoints, …

* A node is keyed by (chain, address); an edge by its transfer (chain, tx hash, sub-index), so
  an asserted placeholder edge that a live run replaces with the observed transfer shows as one
  edge removed and one added.
* `taint_changes`: nodes present in both runs whose tainted USD moved by at least `min_delta`.
* `new_touchpoints`: VASP / service touchpoints (terminal at a deposit, omnibus or swap service)
  in `head` that were not touchpoints in `base`; `new_terminals` lists other new terminals
  (max_hops, dust, …).

`emit_trace_completed(db, case, run)` reports a finished run (trace_completed) with the counts
against the previous run. Its title and body carry the case reference, run ids and counts only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.events import TRACE_COMPLETED, emit
from app.db.models import Address, Case, TraceEdge, TraceNode, TraceRun, TraceStatus, Transfer
from app.tracing.export import run_summary

TOUCHPOINT_REASONS = ("vasp", "vasp_omnibus", "swap_service")

NodeKey = tuple[str, str]  # (chain, address)
EdgeKey = tuple[str, str, int]  # (chain, tx_hash, sub_index)


@dataclass(frozen=True)
class NodeSnap:
    chain: str
    address: str
    hop: int
    taint_usd: Decimal
    terminal: bool = False
    terminal_reason: str | None = None
    entity: str | None = None
    label: str | None = None
    risk: int = 0

    @property
    def key(self) -> NodeKey:
        return (self.chain, self.address)

    @property
    def short(self) -> str:
        a = self.address
        return a if len(a) <= 14 else f"{a[:6]}…{a[-4:]}"

    @property
    def is_touchpoint(self) -> bool:
        return self.terminal and self.terminal_reason in TOUCHPOINT_REASONS

    def as_dict(self) -> dict:
        return {"chain": self.chain, "address": self.address, "short": self.short, "hop": self.hop,
                "taint_usd": str(self.taint_usd), "terminal": self.terminal, "terminal_reason": self.terminal_reason,
                "entity": self.entity, "label": self.label, "risk": self.risk}


@dataclass(frozen=True)
class EdgeSnap:
    chain: str
    tx_hash: str
    sub_index: int
    from_address: str
    to_address: str
    asset: str
    amount: Decimal | None
    taint_usd: Decimal
    hop: int
    asserted: bool = False

    @property
    def key(self) -> EdgeKey:
        return (self.chain, self.tx_hash, self.sub_index)

    def as_dict(self) -> dict:
        return {"chain": self.chain, "tx_hash": self.tx_hash, "sub_index": self.sub_index,
                "from": self.from_address, "to": self.to_address, "asset": self.asset,
                "amount": None if self.amount is None else str(self.amount), "taint_usd": str(self.taint_usd),
                "hop": self.hop, "asserted": self.asserted}


@dataclass
class RunSnapshot:
    run_id: int
    nodes: dict[NodeKey, NodeSnap] = field(default_factory=dict)
    edges: dict[EdgeKey, EdgeSnap] = field(default_factory=dict)

    @classmethod
    def of(cls, run_id: int, nodes: list[NodeSnap], edges: list[EdgeSnap]) -> RunSnapshot:
        return cls(run_id, {n.key: n for n in nodes}, {e.key: e for e in edges})


@dataclass(frozen=True)
class TaintChange:
    node: NodeSnap  # as in head
    before: Decimal
    after: Decimal

    @property
    def delta(self) -> Decimal:
        return self.after - self.before

    def as_dict(self) -> dict:
        return {**self.node.as_dict(), "before": str(self.before), "after": str(self.after), "delta": str(self.delta)}


@dataclass
class RunDiff:
    base_id: int
    head_id: int
    nodes_added: list[NodeSnap]
    nodes_removed: list[NodeSnap]
    edges_added: list[EdgeSnap]
    edges_removed: list[EdgeSnap]
    taint_changes: list[TaintChange]
    new_touchpoints: list[NodeSnap]
    removed_touchpoints: list[NodeSnap]
    new_terminals: list[NodeSnap]
    unchanged_nodes: int = 0
    unchanged_edges: int = 0

    @property
    def is_empty(self) -> bool:
        return not (self.nodes_added or self.nodes_removed or self.edges_added or self.edges_removed
                    or self.taint_changes or self.new_touchpoints or self.removed_touchpoints or self.new_terminals)

    def counts(self) -> dict[str, int]:
        return {"nodes_added": len(self.nodes_added), "nodes_removed": len(self.nodes_removed),
                "edges_added": len(self.edges_added), "edges_removed": len(self.edges_removed),
                "taint_changes": len(self.taint_changes), "new_touchpoints": len(self.new_touchpoints),
                "removed_touchpoints": len(self.removed_touchpoints), "new_terminals": len(self.new_terminals),
                "unchanged_nodes": self.unchanged_nodes, "unchanged_edges": self.unchanged_edges}

    def as_dict(self) -> dict:
        return {
            "base_run_id": self.base_id, "head_run_id": self.head_id, "counts": self.counts(),
            "nodes_added": [n.as_dict() for n in self.nodes_added],
            "nodes_removed": [n.as_dict() for n in self.nodes_removed],
            "edges_added": [e.as_dict() for e in self.edges_added],
            "edges_removed": [e.as_dict() for e in self.edges_removed],
            "taint_changes": [c.as_dict() for c in self.taint_changes],
            "new_touchpoints": [n.as_dict() for n in self.new_touchpoints],
            "removed_touchpoints": [n.as_dict() for n in self.removed_touchpoints],
            "new_terminals": [n.as_dict() for n in self.new_terminals],
        }


def _dec(v) -> Decimal:
    return Decimal(str(v or 0))


def snapshot(db: Session, run: TraceRun) -> RunSnapshot:
    nodes = db.scalars(
        select(TraceNode).where(TraceNode.run_id == run.id)
        .options(selectinload(TraceNode.address).selectinload(Address.entity))
    ).all()
    edges = db.scalars(
        select(TraceEdge).where(TraceEdge.run_id == run.id)
        .options(selectinload(TraceEdge.transfer).selectinload(Transfer.from_address),
                 selectinload(TraceEdge.transfer).selectinload(Transfer.to_address))
    ).all()
    snap_nodes = [
        NodeSnap(chain=n.address.chain.value, address=n.address.address, hop=n.hop, taint_usd=_dec(n.taint_usd),
                 terminal=bool(n.is_terminal), terminal_reason=n.terminal_reason,
                 entity=n.address.entity.name if n.address.entity else None, label=n.address.label,
                 risk=n.risk_score or 0)
        for n in nodes
    ]
    snap_edges = [
        EdgeSnap(chain=e.transfer.chain.value, tx_hash=e.transfer.tx_hash, sub_index=e.transfer.sub_index or 0,
                 from_address=e.transfer.from_address.address, to_address=e.transfer.to_address.address,
                 asset=e.transfer.asset, amount=e.transfer.amount, taint_usd=_dec(e.taint_usd), hop=e.hop,
                 asserted=e.transfer.tx_hash.startswith("ASSERTED:") or e.transfer.amount is None)
        for e in edges
    ]
    return RunSnapshot.of(run.id, snap_nodes, snap_edges)


def diff_runs(base: RunSnapshot, head: RunSnapshot, *, min_delta: Decimal = Decimal("0.01")) -> RunDiff:
    """What changed from `base` to `head` (usually: an earlier run to a later one)."""

    def by_hop(items):
        return sorted(items, key=lambda x: (x.hop, x.key))

    added = by_hop(n for k, n in head.nodes.items() if k not in base.nodes)
    removed = by_hop(n for k, n in base.nodes.items() if k not in head.nodes)
    e_added = by_hop(e for k, e in head.edges.items() if k not in base.edges)
    e_removed = by_hop(e for k, e in base.edges.items() if k not in head.edges)
    changes = [
        TaintChange(n, base.nodes[k].taint_usd, n.taint_usd)
        for k, n in head.nodes.items()
        if k in base.nodes and abs(n.taint_usd - base.nodes[k].taint_usd) >= min_delta
    ]
    changes.sort(key=lambda c: (-abs(c.delta), c.node.key))
    new_tp = by_hop(n for k, n in head.nodes.items()
                    if n.is_touchpoint and not (k in base.nodes and base.nodes[k].is_touchpoint))
    lost_tp = by_hop(n for k, n in base.nodes.items()
                     if n.is_touchpoint and not (k in head.nodes and head.nodes[k].is_touchpoint))
    new_term = by_hop(n for k, n in head.nodes.items()
                      if n.terminal and not n.is_touchpoint and not (k in base.nodes and base.nodes[k].terminal))
    changed_keys = {c.node.key for c in changes}
    return RunDiff(
        base_id=base.run_id, head_id=head.run_id, nodes_added=added, nodes_removed=removed, edges_added=e_added,
        edges_removed=e_removed, taint_changes=changes, new_touchpoints=new_tp, removed_touchpoints=lost_tp,
        new_terminals=new_term,
        unchanged_nodes=sum(1 for k in head.nodes if k in base.nodes and k not in changed_keys),
        unchanged_edges=sum(1 for k in head.edges if k in base.edges),
    )


def diff(db: Session, base: TraceRun, head: TraceRun) -> RunDiff:
    return diff_runs(snapshot(db, base), snapshot(db, head))


def previous_run(db: Session, run: TraceRun) -> TraceRun | None:
    """The case's run just before `run` (by id), if any."""
    return db.scalar(select(TraceRun).where(TraceRun.case_id == run.case_id, TraceRun.id < run.id)
                     .order_by(TraceRun.id.desc()))


def emit_trace_completed(db: Session, case: Case, run: TraceRun, *, commit: bool = True):
    """Report a finished run (event trace_completed) with its counts against the previous run.

    Title and body: case reference, run ids and counts only (no addresses, labels or names)."""
    s = run_summary(db, run)
    prev = previous_run(db, run)
    d = diff(db, prev, run) if prev is not None and run.status == TraceStatus.COMPLETE else None
    failed = run.status != TraceStatus.COMPLETE
    title = (f"{case.reference}: trace #{run.id} failed" if failed else
             f"{case.reference}: trace #{run.id} complete, {s.nodes} addresses, {s.vasp_touchpoints} VASP touchpoints")
    body = (f"Run #{run.id} ({s.provider_mode or 'default'}): {s.nodes} addresses, {s.edges} movements, "
            f"deepest hop {s.max_hop}, {s.vasp_touchpoints} VASP touchpoints.")
    if d is not None:
        body += (f" Against run #{prev.id}: +{len(d.nodes_added)}/-{len(d.nodes_removed)} addresses, "
                 f"+{len(d.edges_added)}/-{len(d.edges_removed)} movements, {len(d.taint_changes)} taint changes, "
                 f"{len(d.new_touchpoints)} new touchpoints, {len(d.removed_touchpoints)} no longer reached.")
    # new VASP touchpoint = a fresh freeze window (high); a touchpoint no longer reached deserves a look
    if failed or (d is not None and d.removed_touchpoints and not d.new_touchpoints):
        severity = "warning"
    else:
        severity = "high" if d is not None and d.new_touchpoints else "info"
    payload = {"trace_run_id": run.id, "previous_run_id": prev.id if prev else None,
               "new_touchpoints": len(d.new_touchpoints) if d else None,
               "removed_touchpoints": len(d.removed_touchpoints) if d else None}
    return emit(db, case, TRACE_COMPLETED, usd=s.vasp_taint_usd if not failed else None, title=title, body=body,
                link=f"/cases/{case.id}?tab=fund_flow&run_id={run.id}", severity=severity, payload=payload,
                commit=commit)
