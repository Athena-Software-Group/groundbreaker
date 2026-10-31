"""Behavioural flags attached to trace nodes.

These are the "relevant details that facilitate issuing a stop order": they
tell the investigator *why* an address matters and how urgent the request is.
Each flag is a short machine-readable code; the UI maps codes to explanations.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal

from app.db.models import Address, AddressType, EntityCategory, Transfer

FREEZABLE_STABLECOINS = {"USDT", "USDC"}

FLAG_TEXT: dict[str, str] = {
    "vasp_deposit": "Customer deposit address at a regulated/freeze-capable service — primary freeze target.",
    "vasp_hot_wallet": "Service omnibus/hot wallet — funds commingled; request must cite the deposit address and tx hash.",
    "swap_service": "Cross-chain swap/bridge — funds changed asset/chain; request order records (IP, device, destination).",
    "rapid_forward": "Funds moved on within 15 minutes of arrival — automated sweep or active laundering.",
    "peel_chain": "Peel-chain pattern: one large onward transfer plus small side payments.",
    "high_fanout": "Split into many outputs — layering; fan-out truncated at the configured limit.",
    "pre_fraud_activity": "Address was active before the fraud date — established account, not a throwaway.",
    "stablecoin_freezable": "Holds or received a centrally-freezable stablecoin (USDT/USDC) — issuer can blacklist.",
    "asserted_link": "Linkage asserted by investigator report; intermediate hops not yet observed on-chain.",
    "unquantified_taint": "Amount on an upstream edge is unknown — taint shown is an upper bound.",
    "pending_input": "Placeholder — real transaction hash / wallet must be supplied.",
    "dormant": "No onward movement observed — funds may still be at this address (freeze window open).",
    "sweep_imminent": "Deposit at a VASP within its typical sweep window — act now.",
    "context_only": "Pre-fraud movement shown for account attribution; not part of the tainted flow.",
    "trace_next": "Holds a material share of the loss with no resolved onward movement — trace this address next.",
}
# the short heading a person reads for each flag (the Fund flow details panel; FLAG_TEXT explains it)
FLAG_LABELS: dict[str, str] = {
    "vasp_deposit": "Deposit address at a service",
    "vasp_hot_wallet": "Service hot wallet",
    "swap_service": "Swap / bridge service",
    "rapid_forward": "Swept fast",
    "peel_chain": "Peel chain",
    "high_fanout": "Split into many outputs",
    "pre_fraud_activity": "Active before the fraud",
    "stablecoin_freezable": "Issuer-freezable stablecoin (USDT / USDC)",
    "asserted_link": "Asserted link (not confirmed on-chain)",
    "unquantified_taint": "Amount unconfirmed (upper bound)",
    "pending_input": "Placeholder (not resolved yet)",
    "dormant": "Dormant (no onward movement seen)",
    "sweep_imminent": "Sweep window open: act now",
    "context_only": "Pre-fraud context",
    "trace_next": "Trace further",
}


def node_flags(
    address: Address,
    incoming: list[Transfer],
    outgoing: list[Transfer],
    arrival: datetime | None,
    fraud_date: datetime | None,
    max_fanout: int,
    now: datetime,
    taint_share: float = 0.0,
) -> list[str]:
    flags: list[str] = []
    ent = address.entity

    if address.address.endswith("_PENDING"):
        flags.append("pending_input")
    if address.address_type == AddressType.VICTIM:
        return flags  # behavioural heuristics are meaningless for the victim's own wallet

    if ent is not None:
        if address.address_type == AddressType.DEPOSIT:
            flags.append("vasp_deposit")
        elif address.address_type == AddressType.HOT_WALLET:
            flags.append("vasp_hot_wallet")
        if ent.category in (EntityCategory.SWAP_SERVICE, EntityCategory.BRIDGE, EntityCategory.DEX):
            flags.append("swap_service")

    if arrival and outgoing:
        first_out = min(t.timestamp for t in outgoing)
        if first_out - arrival <= timedelta(minutes=15):
            flags.append("rapid_forward")

    amounts = [t.amount_usd for t in outgoing if t.amount_usd is not None]
    if len(amounts) >= 2:
        amounts_sorted = sorted(amounts, reverse=True)
        if amounts_sorted[0] > 0 and sum(amounts_sorted[1:]) / amounts_sorted[0] < Decimal("0.15"):
            flags.append("peel_chain")
    if len(outgoing) >= max_fanout:
        flags.append("high_fanout")

    if fraud_date and address.first_seen and address.first_seen < fraud_date and address.address_type not in (
        AddressType.VICTIM,
    ):
        flags.append("pre_fraud_activity")

    assets = {t.asset.upper() for t in incoming}
    if assets & FREEZABLE_STABLECOINS:
        flags.append("stablecoin_freezable")

    if any(t.amount is None for t in incoming):
        flags.append("unquantified_taint")
    if any(t.tx_hash.startswith("ASSERTED:") for t in incoming):
        flags.append("asserted_link")

    if not outgoing and ent is None and address.address_type not in (AddressType.VICTIM,):
        flags.append("dormant")
        if taint_share >= 0.05 and "pending_input" not in flags:
            flags.append("trace_next")

    if "vasp_deposit" in flags and arrival and ent and ent.sweep_window_hours is not None:
        if not outgoing and now - arrival <= timedelta(hours=max(ent.sweep_window_hours, 1)):
            flags.append("sweep_imminent")

    return flags


def risk_score(flags: list[str], taint_usd: Decimal, loss_usd: Decimal | None, hop: int, confidence: float) -> int:
    """0-100 freeze priority. Deliberately simple and explainable."""
    score = 0
    share = float(taint_usd / loss_usd) if loss_usd and loss_usd > 0 else 0.0
    if "unquantified_taint" in flags:
        share *= 0.5  # upper bound only — do not let an unresolved link dominate the ranking
    score += min(40, int(share * 40))  # up to 40 for share of loss
    if "vasp_deposit" in flags:
        score += 30
    elif "vasp_hot_wallet" in flags:
        score += 20
    elif "swap_service" in flags:
        score += 15
    if "stablecoin_freezable" in flags:
        score += 10
    if "dormant" in flags:
        score += 10
    if "sweep_imminent" in flags:
        score += 10
    if "trace_next" in flags:
        score += 15
    if "pre_fraud_activity" in flags and "vasp_deposit" in flags:
        score += 5  # established account => KYC likely exists
    score -= max(0, hop - 3) * 3
    score = int(score * (0.6 + 0.4 * confidence))
    if "pending_input" in flags or "context_only" in flags:
        score = 0
    return max(0, min(100, score))
