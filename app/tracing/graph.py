"""Build a NetworkX graph from a persisted TraceRun and serialise it for Cytoscape.js."""

from __future__ import annotations

from datetime import UTC
from decimal import Decimal

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.models import Address, TraceEdge, TraceNode, TraceRun, Transfer
from app.tracing.annotate import style_elements

# node colour is the coin (annotate.COIN_COLORS) and the chain is the node's shape; the chain colour
# stays in the data as `chain_color` for other consumers
CHAIN_COLORS = {
    "ethereum": "#627EEA",
    "arbitrum": "#28A0F0",
    "base": "#0052FF",
    "bsc": "#F3BA2F",
    "polygon": "#8247E5",
    "tron": "#EB0029",
    "bitcoin": "#F7931A",
    "solana": "#14F195",
}
NON_CUSTODIAL = frozenset({"dex", "mixer"})  # no account to freeze, no customer records (summary: `non_custodial`)


def _fmt_amount(t: Transfer) -> str:
    if t.amount is None:
        return f"? {t.asset}"
    q = Decimal("0.0001") if t.amount < 1 else Decimal("0.01")
    return f"{t.amount.quantize(q).normalize():f} {t.asset}"


def _merge(link: dict, one: dict) -> None:
    """Fold one more movement between the same two addresses into their link: the link's taint and USD are the sums,
    its amount the sum when every movement has one in the same asset (else None: partly unconfirmed), `transfers` lists
    each movement (oldest first) and `n` counts them. The link keeps its first movement's tx hash and time."""
    link["transfers"].append(dict(one))
    link["n"] = len(link["transfers"])
    link["taint_usd"] = round(link["taint_usd"] + one["taint_usd"], 2)
    usd = [x["amount_usd"] for x in link["transfers"]]
    link["amount_usd"] = round(sum(usd), 2) if all(v is not None for v in usd) else None
    same = len({x["asset"] for x in link["transfers"]}) == 1
    amounts = [x["amount"] for x in link["transfers"]]
    if same and all(a is not None for a in amounts):
        total = Decimal(str(sum(amounts)))
        q = Decimal("0.0001") if total < 1 else Decimal("0.01")
        link["amount"] = float(total)
        link["amount_label"] = f"{total.quantize(q).normalize():f} {link['asset']} ({link['n']} txs)"
    else:
        link["amount"] = None
        link["amount_label"] = f"{link['n']} transfers"
    # drawn dashed only when every movement on it is asserted; a mix is said in the details panel, per movement
    link["asserted"] = all(x["asserted"] for x in link["transfers"])
    link["partly_asserted"] = not link["asserted"] and any(x["asserted"] for x in link["transfers"])
    link["notes"] = link["notes"] or one["notes"]


def build_graph(db: Session, run: TraceRun) -> nx.DiGraph:
    nodes = db.scalars(
        select(TraceNode).where(TraceNode.run_id == run.id)
        .options(selectinload(TraceNode.address).selectinload(Address.entity))
    ).all()
    edges = db.scalars(
        select(TraceEdge).where(TraceEdge.run_id == run.id)
        .options(selectinload(TraceEdge.transfer).selectinload(Transfer.from_address),
                 selectinload(TraceEdge.transfer).selectinload(Transfer.to_address))
    ).all()

    g = nx.DiGraph()
    for n in nodes:
        a = n.address
        g.add_node(
            a.id,
            address=a.address, short=a.short(), chain=a.chain.value, type=a.address_type.value,
            label=a.label or "", entity=a.entity.name if a.entity else None,
            entity_category=a.entity.category.value if a.entity else None,
            hop=n.hop, taint_usd=float(n.taint_usd or 0), taint_fraction=n.taint_fraction,
            terminal=n.is_terminal, terminal_reason=n.terminal_reason, risk=n.risk_score, flags=n.flags,
            first_seen=a.first_seen.astimezone(UTC).isoformat() if a.first_seen else None,
        )
    for e in sorted(edges, key=lambda e: (e.transfer.timestamp, e.transfer.id)):
        t = e.transfer
        if t.from_address_id not in g or t.to_address_id not in g:
            continue
        one = {
            "transfer_id": t.id, "tx_hash": t.tx_hash, "chain": t.chain.value, "asset": t.asset,
            "amount": float(t.amount) if t.amount is not None else None, "amount_label": _fmt_amount(t),
            "amount_usd": float(t.amount_usd) if t.amount_usd is not None else None,
            "taint_usd": float(e.taint_usd or 0), "timestamp": t.timestamp.astimezone(UTC).isoformat(),
            "method": t.method, "data_source": t.source.value, "confidence": t.confidence,
            "asserted": t.tx_hash.startswith("ASSERTED:") or t.amount is None, "notes": t.notes, "hop": e.hop,
        }
        pair = (t.from_address_id, t.to_address_id)
        if g.has_edge(*pair) and not g.edges[pair].get("virtual"):
            _merge(g.edges[pair], one)  # one link, every movement on it
            continue
        g.add_edge(t.from_address_id, t.to_address_id, key=t.id, **one, n=1, transfers=[dict(one)])
        # virtual cross-chain edge: swap contract -> payout wallet on the other chain
        if t.bridged_to_transfer_id:
            dst = db.get(Transfer, t.bridged_to_transfer_id)
            if dst and dst.from_address_id in g:
                g.add_edge(
                    t.to_address_id, dst.from_address_id, transfer_id=None, tx_hash=f"{t.tx_hash} → {dst.tx_hash}",
                    chain=f"{t.chain.value}→{dst.chain.value}", asset=f"{t.asset}→{dst.asset}",
                    amount=None, amount_label="cross-chain swap", amount_usd=None, taint_usd=float(e.taint_usd or 0),
                    timestamp=dst.timestamp.astimezone(UTC).isoformat(), method="bridge", data_source=t.source.value,
                    confidence=t.confidence, asserted=False, notes="Swap service internal leg (off-chain order).",
                    hop=e.hop, virtual=True,
                )
    return g


def to_cytoscape(g: nx.DiGraph) -> dict:
    """Cytoscape elements. Nodes carry coin / color (the dominant tainted inflow's asset), shape (by
    chain), value_usd / value_label / size (sqrt-scaled), dust and upper_bound / asserted_peers (taint
    that reached it only over asserted links with no on-chain amount); edges (one per pair of addresses:
    `n` movements, each in `transfers`) their coin and coin_color (app.tracing.annotate.style_elements).
    Freeze status and recommendations are added per viewer by annotate.annotate_elements."""
    elements = {"nodes": [], "edges": []}
    for nid, d in g.nodes(data=True):
        elements["nodes"].append({"data": {"id": str(nid), **d, "chain_color": CHAIN_COLORS.get(d["chain"], "#999")}})
    for i, (u, v, d) in enumerate(g.edges(data=True)):
        elements["edges"].append({"data": {"id": f"e{i}", "source": str(u), "target": str(v), **d}})
    return style_elements(elements)


def summary(g: nx.DiGraph) -> dict:
    terminals = [d for _, d in g.nodes(data=True) if d.get("terminal") and d.get("terminal_reason") in ("vasp", "vasp_omnibus")]
    entities = {d["entity"]: d.get("entity_category") for _, d in g.nodes(data=True) if d.get("entity")}
    return {
        "nodes": g.number_of_nodes(),
        "edges": g.number_of_edges(),
        "chains": sorted({d["chain"] for _, d in g.nodes(data=True)}),
        "entities": sorted(entities),
        # services the funds reached (accounts / order records to ask about) vs non-custodial routers and mixers
        "services": sorted(e for e, cat in entities.items() if cat not in NON_CUSTODIAL),
        "non_custodial": sorted(e for e, cat in entities.items() if cat in NON_CUSTODIAL),
        "vasp_touchpoints": len(terminals),
        "max_hop": max((d["hop"] for _, d in g.nodes(data=True)), default=0),
    }
