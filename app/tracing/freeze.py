"""Derive freeze / preservation candidates from a trace run.

A candidate is one *entity* (exchange, casino, swap desk, stablecoin issuer)
plus every identifier an analyst needs to put in front of its compliance team:
deposit addresses, inbound tx hashes, amounts, timestamps, dwell time, and the
behavioural flags that justify urgency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.models import Address, Entity, EntityCategory, TraceEdge, TraceNode, TraceRun, Transfer
from app.tracing.annotate import MOVED_ON_SHARE
from app.tracing.heuristics import FREEZABLE_STABLECOINS

STABLECOIN_ISSUER = {"USDT": "Tether (USDT issuer)", "USDC": "Circle (USDC issuer)"}


@dataclass
class Identifier:
    chain: str
    address: str
    address_type: str
    label: str | None
    inbound: list[dict] = field(default_factory=list)  # {tx_hash, amount, asset, amount_usd, timestamp, from}
    outbound: list[dict] = field(default_factory=list)
    context_inbound: list[dict] = field(default_factory=list)  # pre-fraud deposits (account attribution)
    taint_usd: Decimal = Decimal(0)
    flags: list[str] = field(default_factory=list)
    risk: int = 0
    # time between inbound and the first *observed* outbound (None = dormant, or onward hop only asserted)
    dwell_minutes: float | None = None
    # the trace saw (about) everything it received leave again (observed or asserted onward hops carry >= 90% of its
    # taint; not dormant, not a deposit address): nothing is held here unless an on-chain reading says otherwise. The
    # same rule as the Recovery plan's "moved on" (app.blocks.recovery._moved_on, an unread wallet)
    moved_on: bool = False


@dataclass
class FreezeCandidate:
    entity: Entity | None
    entity_name: str
    category: str
    kind: str  # "freeze" | "preservation" | "issuer_blacklist"
    priority: int
    identifiers: list[Identifier]
    rationale: list[str]
    total_taint_usd: Decimal


def _asserted(t: Transfer) -> bool:
    return t.tx_hash.startswith("ASSERTED:")


def _short(addr: str) -> str:
    return f"{addr[:6]}…{addr[-4:]}" if len(addr) > 12 else addr


def _issuer_note(status: str, addr: str, sym: str) -> str:
    a = f"`{_short(addr)}`"
    return {
        "asserted_onward": f"{a} received the {sym} on-chain; its onward movement is asserted only (hop hash pending) — ask the issuer to check the current balance.",
        "other_assets_out": f"{a} moved other assets onward (consistent with swapping out of {sym}); whether any {sym} remains is unconfirmed — ask the issuer to check the current balance.",
        "unobserved_onward": f"{a}: whether the {sym} is still held is unconfirmed (onward amounts unobserved) — ask the issuer to check the current balance.",
        "no_outbound": f"{a}: no onward movement observed — balance likely still at the address.",
    }[status]


def _moved_on(n: TraceNode, a: Address, sent: Decimal) -> bool:
    """The trace saw the wallet forward (about) all the case funds it received (Identifier.moved_on)."""
    taint = n.taint_usd or Decimal(0)
    if taint <= 0 or "dormant" in (n.flags or []) or a.address_type.value == "deposit":
        return False
    return sent >= Decimal(str(MOVED_ON_SHARE)) * taint


def _tx_dict(t: Transfer) -> dict:
    return {
        "tx_hash": t.tx_hash, "asset": t.asset, "amount": str(t.amount) if t.amount is not None else None,
        "amount_usd": str(t.amount_usd) if t.amount_usd is not None else None,
        "timestamp": t.timestamp.isoformat(), "from": t.from_address.address, "to": t.to_address.address,
        "chain": t.chain.value, "asserted": t.tx_hash.startswith("ASSERTED:"), "notes": t.notes,
        "to_label": t.to_address.label or (t.to_address.entity.name if t.to_address.entity else None),
        "from_label": t.from_address.label or (t.from_address.entity.name if t.from_address.entity else None),
    }


def freeze_candidates(db: Session, run: TraceRun) -> list[FreezeCandidate]:
    nodes = db.scalars(
        select(TraceNode).where(TraceNode.run_id == run.id)
        .options(selectinload(TraceNode.address).selectinload(Address.entity))
    ).all()
    edges = db.scalars(
        select(TraceEdge).where(TraceEdge.run_id == run.id)
        .options(selectinload(TraceEdge.transfer).selectinload(Transfer.from_address),
                 selectinload(TraceEdge.transfer).selectinload(Transfer.to_address))
    ).all()
    tainted_edges = [e for e in edges if (e.taint_usd or 0) > 0]
    by_to: dict[int, list[Transfer]] = {}
    by_from: dict[int, list[Transfer]] = {}
    out_taint: dict[int, Decimal] = {}
    context_by_to: dict[int, list[Transfer]] = {}
    for e in tainted_edges:
        by_to.setdefault(e.transfer.to_address_id, []).append(e.transfer)
        by_from.setdefault(e.transfer.from_address_id, []).append(e.transfer)
        out_taint[e.transfer.from_address_id] = out_taint.get(e.transfer.from_address_id, Decimal(0)) + e.taint_usd
    for e in edges:
        if (e.taint_usd or 0) == 0:
            context_by_to.setdefault(e.transfer.to_address_id, []).append(e.transfer)

    by_entity: dict[int, list[tuple[TraceNode, Identifier]]] = {}
    issuer_hits: dict[str, list[Identifier]] = {}
    issuer_notes: dict[str, list[str]] = {}

    for n in nodes:
        a = n.address
        if "context_only" in (n.flags or []) or "pending_input" in (n.flags or []):
            continue
        inbound = by_to.get(a.id, [])
        outbound = by_from.get(a.id, [])
        dwell = None
        observed_out = [t for t in outbound if not _asserted(t)]
        if inbound and observed_out:
            # an asserted hop's timestamp may be a placeholder (window lower bound): never derive dwell from it
            dwell = (min(t.timestamp for t in observed_out) - min(t.timestamp for t in inbound)).total_seconds() / 60
        ident = Identifier(
            chain=a.chain.value, address=a.address, address_type=a.address_type.value, label=a.label,
            inbound=[_tx_dict(t) for t in inbound], outbound=[_tx_dict(t) for t in outbound],
            context_inbound=[_tx_dict(t) for t in context_by_to.get(a.id, [])],
            taint_usd=n.taint_usd or Decimal(0), flags=n.flags or [], risk=n.risk_score, dwell_minutes=dwell,
            moved_on=_moved_on(n, a, out_taint.get(a.id, Decimal(0))),
        )
        if a.entity_id is not None:
            by_entity.setdefault(a.entity_id, []).append((n, ident))
        # stablecoin issuer lever: tainted stablecoin at a non-VASP address that has not
        # demonstrably left. It has left when an observed onward transfer with a known amount exists,
        # or when an asserted one does and the stablecoin's arrival here was itself only asserted
        # (a relay in the middle of an asserted path). Where the stablecoin was *observed* arriving
        # and only asserted hops continue, the address stays in the letter until those are verified.
        if a.entity_id is None:
            for sym in sorted({t.asset.upper() for t in inbound} & FREEZABLE_STABLECOINS):
                sym_in = [t for t in inbound if t.asset.upper() == sym]
                sym_out = [t for t in outbound if t.asset.upper() == sym]
                observed_arrival = any(not _asserted(t) for t in sym_in)
                if any(t.amount is not None and not _asserted(t) for t in sym_out):
                    continue
                if any(t.amount is not None and _asserted(t) for t in sym_out):
                    if not observed_arrival:
                        continue
                    status = "asserted_onward"
                elif sym_out:
                    status = "unobserved_onward"
                elif outbound:
                    status = "other_assets_out"
                else:
                    status = "no_outbound"
                issuer_hits.setdefault(STABLECOIN_ISSUER[sym], []).append(ident)
                issuer_notes.setdefault(STABLECOIN_ISSUER[sym], []).append(_issuer_note(status, a.address, sym))

    out: list[FreezeCandidate] = []
    for ent_id, items in by_entity.items():
        ent = db.get(Entity, ent_id)
        if ent.category == EntityCategory.DEX and not ent.freeze_capable:
            # non-custodial router / AMM: no accounts, balances or order records to freeze or preserve.
            # The swap output is followed by the trace; the lever is the output token's issuer.
            continue
        idents = [i for _, i in items]
        # deposit addresses carry the customer-attributable amount; omnibus wallets would double count
        deposit_taint = [i.taint_usd for i in idents if i.address_type == "deposit"]
        total = sum(deposit_taint, Decimal(0)) if deposit_taint else max((i.taint_usd for i in idents), default=Decimal(0))
        rationale: list[str] = []
        flags = {f for i in idents for f in i.flags}
        if ent.category in (EntityCategory.EXCHANGE, EntityCategory.CASINO, EntityCategory.OTC):
            kind = "freeze" if ent.freeze_capable else "preservation"
            rationale.append(f"Tainted funds deposited to a {ent.category.value} account; KYC and withdrawal records exist.")
        elif ent.category in (EntityCategory.SWAP_SERVICE, EntityCategory.BRIDGE, EntityCategory.DEX):
            kind = "preservation"
            rationale.append("Funds swapped cross-chain; order records (IP, device, destination) identify the operator.")
        else:
            kind = "preservation"
        if "pre_fraud_activity" in flags:
            rationale.append("Account was active before the fraud — an established, KYC'd account rather than a throwaway.")
        if "rapid_forward" in flags:
            rationale.append("Deposits swept within minutes — consistent with automated custody; funds now in omnibus wallet.")
        if "dormant" in flags or "sweep_imminent" in flags:
            rationale.append("Funds not yet moved onward — freeze window is open.")
        if "asserted_link" in flags or "unquantified_taint" in flags:
            rationale.append("Part of the path is asserted (investigator's report or victim statement), not yet observed on-chain; amounts shown are upper bounds until the live trace resolves intermediate hops.")
        priority = max((i.risk for i in idents), default=0)
        out.append(FreezeCandidate(ent, ent.name, ent.category.value, kind, priority, idents, rationale, total))

    for issuer_name, idents in issuer_hits.items():
        ent = db.scalar(select(Entity).where(Entity.name == issuer_name))
        # one letter per issuer: fold in any candidate already built for the same entity
        # (an issuer-owned address on the path) instead of emitting a second request
        dupes = [c for c in out if c.entity_name == issuer_name or (ent is not None and c.entity is ent)]
        for d in dupes:
            out.remove(d)
            idents = idents + d.identifiers
        seen: set[tuple[str, str]] = set()
        idents = [i for i in idents if (i.chain, i.address) not in seen and not seen.add((i.chain, i.address))]
        # identifiers on one path carry the same dollars: never claim more than entered the trace
        total = min(sum((i.taint_usd for i in idents), Decimal(0)), max((n.taint_usd or Decimal(0) for n in nodes), default=Decimal(0)))
        out.append(
            FreezeCandidate(
                ent, issuer_name, "stablecoin_issuer", "issuer_blacklist",
                max(60, max((i.risk for i in idents), default=0)), idents,
                ["Centrally-issued stablecoin received at a self-custodied address; the issuer can blacklist the address on verified LE request, independent of any exchange."]
                + list(dict.fromkeys(issuer_notes.get(issuer_name, []))),
                total,
            )
        )

    out.sort(key=lambda c: (-c.priority, -c.total_taint_usd))
    return out
