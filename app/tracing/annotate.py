"""Fund-flow graph annotations: coin, value size, freeze status and recommended stop-order targets.

Pure functions (unit-tested in tests/test_graph_annotations.py) plus one database-facing wrapper,
`annotate_elements`, which the Fund flow tab calls on the Cytoscape elements of a run:

* **coin** — the asset of a node's dominant inbound tainted value (its largest tainted inflow); a
  node without one (the victim) takes its largest tainted outflow, else the chain's native coin.
  Edges are coloured by their own asset (a cross-chain leg by the asset paid out).
* **size** — node diameter scaled by sqrt(tainted USD), relative to the run's largest node and
  clamped to [NODE_MIN_PX, NODE_MAX_PX].
* **freeze_status** — derived from the case's stop orders (generated and imported). A node matches
  an order when the order cites its address in full (case-insensitive; never a truncated form) in
  its identifiers or, for an imported letter, in its body text, or when the node belongs to the
  entity the order is addressed to. The strongest status wins (FREEZE_STATUS_RANK). An imported
  letter that only cites a wallet's address (it is addressed to someone else, and is not an issuer
  blacklist request) marks the wallet `cited`, not `requested`: such letters quote every address in
  their body (peel wallets, prior depositors, swap-order senders), and no freeze was asked of those.
  `cited` is the weakest status (no lock badge, not counted as a freeze request).
* **recommended** — freeze candidates (app/tracing/freeze.py) holding at least RECOMMEND_MIN_USD
  whose entity has no stop order sent yet (a draft does not count as sent). Issuer levers (Tether /
  Circle) land on the USDT / USDC-holding wallets, never on one the trace saw the funds leave
  (`moved_on`: the action is listed as `nothing_held`, no ring). On the latest run hover.hover_data
  aligns the actions with the Recovery plan (align_with_plan: the plan's value, next step and order).
* **upper_bound** / **asserted_peers** — the node's taint reached it only over asserted links with no
  on-chain amount (the sender's untraced remainder, given in full to each asserted destination).
* **owner** — who owns the wallet (app.attribution: owner, kind, confidence, source, evidence lines, who to ask).
* **onchain_freeze** — the latest issuer blacklist readings of the wallet (app/freeze: Tether /
  Circle contract reads, when the case's "On-chain freeze checks" are on). A blacklisted reading sets
  `onchain_frozen` (a distinct style: green double border + lock-and-chain badge, separate from the
  exchange-confirmed `frozen` stop-order status) and the label "frozen (on-chain: Tether blacklist,
  1,234.56 USDT)". It is a fact read from the chain, not a request, so it never changes
  `freeze_status` or the recommendations; exchange accounts cannot be seen on-chain at all.

The graph JSON never carries LE / PI contact data: a stop order is described by its id, the
recipient organisation's name, its status, the day it was sent and a link.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal

COIN_COLORS = {
    "USDC": "#2775CA",
    "USDT": "#26A17B",
    "ETH": "#A78BFA",  # violet rather than the ETH brand blue, which is too close to USDC on the graph
    "BTC": "#F7931A",
    "TRX": "#EB0029",
    "OTHER": "#8A94A6",
}
COIN_ALIASES = {"WETH": "ETH", "STETH": "ETH", "WBTC": "BTC", "USDC.E": "USDC", "USDT0": "USDT", "WTRX": "TRX"}
NATIVE_COIN = {"ethereum": "ETH", "arbitrum": "ETH", "base": "ETH", "bitcoin": "BTC", "tron": "TRX"}
# chain -> Cytoscape node shape (colour is the coin's); every other (EVM) chain is an ellipse
CHAIN_SHAPES = {"tron": "diamond", "bitcoin": "hexagon"}
DEFAULT_SHAPE = "ellipse"

NODE_MIN_PX, NODE_MAX_PX = 18.0, 80.0
DUST_USD = 50.0  # the legend's "hide dust" filter
RECOMMEND_MIN_USD = 50.0  # a freeze candidate's address carrying less is not called out
# a wallet "moved on" when its tainted outflows carry at least this share of what reached it (not dormant, not a
# deposit address): app.tracing.freeze.Identifier.moved_on, app.blocks.recovery._moved_on
MOVED_ON_SHARE = 0.9

# StopOrder status (desk.order_state) -> graph freeze status; superseded orders are ignored
FREEZE_STATUS = {
    "draft": "draft",
    "sent": "requested",
    "acknowledged": "acknowledged",
    "frozen": "frozen",
    "declined": "declined",
    "released": "released",
}
FREEZE_STATUS_RANK = {"frozen": 6, "acknowledged": 5, "requested": 4, "released": 3, "declined": 2, "draft": 1,
                      "cited": 0}
CITED = "cited"  # an imported letter to another recipient quotes the address; no freeze asked of it
FREEZE_STATUS_LABELS = {
    "requested": "Freeze / preservation requested",
    "acknowledged": "Request acknowledged",
    "frozen": "Frozen",
    "declined": "Request declined",
    "released": "Hold released",
    "draft": "Stop order drafted (not sent)",
    "cited": "Cited in a letter to another recipient (no freeze asked of this wallet)",
}
MIN_ADDRESS_LEN = 25  # shorter strings (placeholders, truncated forms) never match an address

_TOKEN_RE = re.compile(r"[0-9A-Za-z]+")
_PAREN_RE = re.compile(r"\s*\([^)]*\)\s*")


# --------------------------------------------------------------------------- coin, shape, size
def coin_of(asset: str | None) -> str:
    """Normalise an asset symbol to one of COIN_COLORS ("ETH→USDT" = the asset paid out)."""
    sym = (asset or "").split("→")[-1].strip().upper()
    sym = COIN_ALIASES.get(sym, sym)
    return sym if sym in COIN_COLORS else "OTHER"


def coin_color(coin: str) -> str:
    return COIN_COLORS.get(coin, COIN_COLORS["OTHER"])


def chain_shape(chain: str | None) -> str:
    return CHAIN_SHAPES.get((chain or "").lower(), DEFAULT_SHAPE)


def _dominant(flows: Iterable[tuple[str | None, float | None]]) -> str | None:
    best: tuple[float, str] | None = None
    for asset, usd in flows:
        v = float(usd or 0)
        if v > 0 and (best is None or v > best[0]):
            best = (v, asset or "")
    return coin_of(best[1]) if best is not None else None


def node_coin(inflows: Iterable[tuple[str | None, float | None]], chain: str | None,
              outflows: Iterable[tuple[str | None, float | None]] = ()) -> str:
    """The coin of a node: the asset of its largest tainted inflow ((asset, taint_usd) pairs), else
    of its largest tainted outflow (the victim's wallet), else the chain's native coin."""
    return _dominant(inflows) or _dominant(outflows) or NATIVE_COIN.get((chain or "").lower(), "OTHER")


def node_size(value_usd: float | None, max_usd: float | None) -> float:
    """Diameter in px: NODE_MIN_PX + (NODE_MAX_PX - NODE_MIN_PX) * sqrt(value / max), clamped."""
    v, m = max(float(value_usd or 0), 0.0), float(max_usd or 0)
    if m <= 0 or v <= 0:
        return NODE_MIN_PX
    px = NODE_MIN_PX + (NODE_MAX_PX - NODE_MIN_PX) * math.sqrt(v / m)
    return round(min(NODE_MAX_PX, max(NODE_MIN_PX, px)), 1)


def short_usd(v: float | None) -> str:
    n = float(v or 0)
    if n >= 1e6:
        return f"${n / 1e6:.{0 if n >= 1e7 else 1}f}M"
    if n >= 1e3:
        return f"${n / 1e3:.{0 if n >= 1e4 else 1}f}k"
    return f"${n:.0f}"


def short_entity(name: str | None) -> str:
    """'Tether (USDT issuer)' -> 'Tether'; 'SWFT / Bridgers' stays."""
    return _PAREN_RE.sub(" ", name or "").strip() or (name or "")


def entity_key(name: str | None) -> str | None:
    return (name or "").strip().lower() or None


# --------------------------------------------------------------------------- stop-order matching
def address_tokens(text: str | None) -> set[str]:
    """Every alphanumeric run of `text`, lower-cased. A full address is one token; a truncated
    form (`0x1234…abcd`) splits into fragments that never equal an address."""
    return {t.lower() for t in _TOKEN_RE.findall(text or "") if len(t) >= MIN_ADDRESS_LEN}


def _strings(value) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from _strings(v)


def cited_addresses(identifiers: Mapping | None, body: str | None = None, *, imported: bool = False) -> frozenset[str]:
    """The full addresses a stop order cites, lower-cased. Generated orders cite their
    `identifiers.addresses[*].address` (the candidate's own identifiers, not the senders inside the
    tx details); imported letters every full address in their identifiers JSON and body text."""
    ids = dict(identifiers or {})
    out: set[str] = set()
    for a in ids.get("addresses") or []:
        v = a.get("address") if isinstance(a, Mapping) else a
        if isinstance(v, str) and len(v.strip()) >= MIN_ADDRESS_LEN:
            out.add(v.strip().lower())
    if imported:
        for key, value in ids.items():
            if key in ("hold", "status_history"):
                continue
            for s in _strings(value):
                out |= address_tokens(s)
        out |= address_tokens(body)
    return frozenset(out)


@dataclass(frozen=True)
class OrderRef:
    """What the graph needs of one stop order (no contact data)."""

    id: int
    recipient: str  # the recipient organisation's name
    status: str  # a FREEZE_STATUS value
    sent_at: str | None = None  # ISO day
    url: str | None = None
    cited: frozenset[str] = frozenset()
    amount_held: str | None = None
    asset_held: str | None = None
    imported: bool = False  # an imported letter (it cites every full address in its body)
    kind: str = ""  # freeze | preservation | issuer_blacklist | …

    @property
    def key(self) -> str | None:
        return entity_key(self.recipient)

    @property
    def sent(self) -> bool:
        return self.status != "draft"


def freeze_status_of(state: str) -> str | None:
    return FREEZE_STATUS.get(state)


def match_orders(address: str | None, entity: str | None, orders: Iterable[OrderRef]) -> list[tuple[OrderRef, str]]:
    """The stop orders that cover a node: (order, "entity") when it is addressed to the node's own
    entity (its deposit / hot wallets), (order, "address") when it cites the node's full address
    (case-insensitive) without being addressed to its owner."""
    addr = (address or "").strip().lower()
    ent = entity_key(entity)
    out: list[tuple[OrderRef, str]] = []
    for o in orders:
        if ent is not None and o.key == ent:
            out.append((o, "entity"))
        elif len(addr) >= MIN_ADDRESS_LEN and addr in o.cited:
            out.append((o, "address"))
    return out


def hit_status(order: OrderRef, how: str) -> str:
    """The graph status one matching order gives a node: its own status, except `cited` for an
    imported letter that only cites the address (not addressed to the owner, not an issuer request)."""
    if how == "address" and order.imported and order.kind != "issuer_blacklist":
        return CITED
    return order.status


def node_freeze(address: str | None, entity: str | None, orders: Iterable[OrderRef]) -> tuple[str | None, list[dict]]:
    """(freeze_status, stop_orders) for one node: the strongest status of the matching orders."""
    hits = match_orders(address, entity, orders)
    if not hits:
        return None, []
    status = max((hit_status(o, how) for o, how in hits), key=lambda s: FREEZE_STATUS_RANK.get(s, 0))
    hits.sort(key=lambda h: (-FREEZE_STATUS_RANK.get(h[0].status, 0), h[0].id))
    return status, [{
        "id": o.id, "recipient": o.recipient, "status": o.status, "sent_at": o.sent_at, "url": o.url, "match": how,
        **({"amount_held": o.amount_held, "asset_held": o.asset_held} if o.amount_held else {}),
    } for o, how in hits]


# --------------------------------------------------------------------------- recommendations
@dataclass
class CandidateRef:
    """A freeze candidate as the graph needs it."""

    entity: str
    kind: str  # freeze | preservation | issuer_blacklist
    priority: int
    addresses: list[tuple[str, float]] = field(default_factory=list)  # (address, taint_usd)
    category: str = ""
    entity_id: int | None = None
    # lower-case addresses the trace saw forward (about) everything they received (freeze.Identifier.moved_on)
    moved_on: frozenset[str] = frozenset()

    @property
    def key(self) -> str | None:
        return entity_key(self.entity)


def _sym(entity: str) -> str:
    return "USDT" if "tether" in entity.lower() else "USDC" if "circle" in entity.lower() else "stablecoin"


def _short_addr(a: str) -> str:
    return f"{a[:6]}…{a[-4:]}" if len(a) > 12 else a


def _gone_reason(c: CandidateRef, addrs: list[str]) -> str:
    names = ", ".join(_short_addr(a) for a in addrs[:3]) + (f" and {len(addrs) - 3} more" if len(addrs) > 3 else "")
    return (f"The {_sym(c.entity)} at {names} moved on (the trace saw it leave): nothing is held there for "
            f"{short_entity(c.entity)} to blacklist. Follow the funds; a balance check shows anything left.")


def _reason(c: CandidateRef) -> str:
    name = short_entity(c.entity)
    if c.kind == "issuer_blacklist":
        return f"{_sym(c.entity)} at a self-custodied wallet: {name} can blacklist the address on an LE request."
    if c.kind == "freeze":
        return f"Tainted funds at {name}: ask it to freeze the account and preserve KYC / withdrawal records."
    return f"{name} holds the records (orders, IPs, payout addresses): ask it to preserve them."


def recommendations(candidates: Iterable[CandidateRef], orders: Iterable[OrderRef], *,
                    min_usd: float = RECOMMEND_MIN_USD) -> list[dict]:
    """One recommended action per candidate entity with no stop order standing yet: its addresses
    that carry at least `min_usd` of taint. A draft to the entity is reported (`draft_id`) but does
    not suppress the recommendation; nor does a request that was only ever declined (`declined`),
    which matches the assistant's /stop-orders plan (app/ai/skills.stop_order_plan). Non-custodial
    services (mixers) take an information request, never a stop order. Sorted by priority, then value.

    An issuer lever (Tether / Circle) counts only the wallets still holding the stablecoin: `held` leaves out the ones
    the trace saw forward everything (CandidateRef.moved_on). When none is left the action stays listed with
    `nothing_held` (value 0, last, no ring / callout on the graph): the issuer can still be asked, but the trace puts no
    balance there (the Recovery plan says the same: "moved on")."""
    orders = list(orders)
    standing = {o.key for o in orders if o.sent and o.status != "declined" and o.key}
    declined = {o.key for o in orders if o.status == "declined" and o.key}
    drafts = {o.key: o for o in sorted(orders, key=lambda o: o.id) if not o.sent and o.key}
    out: list[dict] = []
    for c in candidates:
        if c.key is None or c.key in standing or c.category == "mixer":
            continue
        addrs = [(a, float(t or 0)) for a, t in c.addresses if float(t or 0) >= min_usd]
        if not addrs:
            continue
        gone = c.moved_on if c.kind == "issuer_blacklist" else frozenset()
        held = [(a, t) for a, t in addrs if a.strip().lower() not in gone]
        draft = drafts.get(c.key)
        out.append({
            "entity": c.entity, "short": short_entity(c.entity), "entity_id": c.entity_id, "kind": c.kind,
            "category": c.category, "priority": int(c.priority or 0), "declined": c.key in declined,
            "reason": (_reason(c) if held else _gone_reason(c, [a for a, _ in addrs]))
            + (" An earlier request was declined." if c.key in declined else ""),
            "value_usd": max((t for _, t in held), default=0.0), "addresses": [a for a, _ in addrs],
            "held": [a for a, _ in held], "nothing_held": not held,
            "drafted": draft is not None, "draft_id": draft.id if draft else None,
            "draft_url": draft.url if draft else None, "plan": None,
        })
    out.sort(key=lambda r: (r["nothing_held"], -r["priority"], -r["value_usd"], r["entity"].lower()))
    return out


def recommendation_by_address(recs: Iterable[dict]) -> dict[str, dict]:
    """address (lower-case) -> the highest-priority recommendation that names it as holding funds (`held`: a wallet
    whose funds moved on gets no recommendation of its own)."""
    out: dict[str, dict] = {}
    for r in recs:  # already sorted by priority
        for a in r.get("held", r["addresses"]):
            out.setdefault(a.strip().lower(), r)
    return out


def align_with_plan(recs: list[dict], moves: Iterable[Mapping] | None, *, case_id: int | None = None,
                    min_usd: float = RECOMMEND_MIN_USD) -> list[dict]:
    """Bring the recommended actions in line with the Recovery plan (app.blocks.recovery.view moves, as this member
    sees them): the plan's move for the same authority gives each action its value (what the plan counts at stake:
    an on-chain reading, else the traced funds still there), its next step and its rank, and the actions follow the
    plan's order. A plan value under `min_usd` (the funds moved on, a balance read at 0) makes the action
    `nothing_held`: no wallet keeps a ring or callout for it. An action without a plan move keeps its own figures.
    In place; returns `recs`."""
    by_name: dict[str, Mapping] = {}
    for m in moves or []:
        a = m.get("authority") or {}
        if a.get("name") and ":" not in str(m.get("key") or ""):
            by_name.setdefault(entity_key(a["name"]), m)
    for r in recs:
        m = by_name.get(entity_key(r["entity"]))
        if m is None:
            continue
        value = float(m["value"]) if m.get("value") is not None else None
        r["plan"] = {
            "rank": m.get("rank"), "key": m.get("key"), "title": m.get("title"), "kind_label": m.get("kind_label"),
            "value": value, "value_fmt": m.get("value_fmt"), "basis": m.get("basis"), "actionable": m.get("actionable"),
            "url": (f"/cases/{int(case_id)}/recovery-plan#m-{m['key']}" if case_id is not None and m.get("key")
                    else None),
        }
        if value is None:
            continue
        r["value_usd"] = round(value, 2)
        if value < min_usd and not r["nothing_held"]:
            r["nothing_held"], r["held"] = True, []
            if m.get("basis"):
                r["reason"] = f"Nothing at stake by the Recovery plan: {m['basis']}."
        elif value >= min_usd and r["nothing_held"]:
            r["nothing_held"], r["held"] = False, list(r["addresses"])  # a balance reading shows funds there
    recs.sort(key=lambda r: (r["nothing_held"], (r["plan"] or {}).get("rank") or 10_000, -r["priority"],
                             -r["value_usd"], r["entity"].lower()))
    return recs


def apply_recommended(elements: dict, recs: list[dict]) -> dict:
    """Write `recommended` onto the node data: the recommendation naming the node's address as holding funds, with
    its deep link `url` as the recommendation carries it (None = no action link for this viewer) and the Recovery
    plan's next step for it (`next`, `plan_rank`; align_with_plan)."""
    by_addr = recommendation_by_address(recs)
    for n in elements.get("nodes", []):
        d = n["data"]
        rec = by_addr.get((d.get("address") or "").strip().lower())
        plan = (rec or {}).get("plan") or {}
        d["recommended"] = None if rec is None else {
            "entity": rec["entity"], "short": rec["short"], "kind": rec["kind"], "reason": rec["reason"],
            "priority": rec["priority"], "url": rec.get("url"), "draft_id": rec["draft_id"],
            "drafted": rec["drafted"], "next": plan.get("title"), "plan_rank": plan.get("rank"),
        }
    return elements


# --------------------------------------------------------------------------- elements
def style_elements(elements: dict) -> dict:
    """Add coin, colour, shape, value and size to Cytoscape elements built by graph.to_cytoscape."""
    nodes, edges = elements.get("nodes", []), elements.get("edges", [])
    inflows: dict[str, list[tuple[str, float]]] = {}
    outflows: dict[str, list[tuple[str, float]]] = {}
    tainted_in: dict[str, list[dict]] = {}
    unquantified: dict[str, set[str]] = {}  # source -> targets of its tainted links with no on-chain amount
    for e in edges:
        d = e["data"]
        d["coin"] = coin_of(d.get("asset"))
        d["coin_color"] = coin_color(d["coin"])
        inflows.setdefault(d["target"], []).append((d.get("asset"), d.get("taint_usd") or 0))
        outflows.setdefault(d["source"], []).append((d.get("asset"), d.get("taint_usd") or 0))
        if float(d.get("taint_usd") or 0) > 0:
            tainted_in.setdefault(d["target"], []).append(d)
            if _unquantified(d):
                unquantified.setdefault(d["source"], set()).add(d["target"])
    vmax = max((float(n["data"].get("taint_usd") or 0) for n in nodes), default=0.0)
    for n in nodes:
        d = n["data"]
        d["coin"] = node_coin(inflows.get(d["id"], []), d.get("chain"), outflows.get(d["id"], []))
        d["color"] = coin_color(d["coin"])
        d["shape"] = chain_shape(d.get("chain"))
        d["value_usd"] = round(float(d.get("taint_usd") or 0), 2)
        # an upper bound: every tainted link into it is asserted with no on-chain amount (the sender's untraced
        # remainder, given in full to each of its asserted destinations: `asserted_peers` others share it)
        ins = tainted_in.get(d["id"], [])
        d["upper_bound"] = bool(ins) and d["value_usd"] > 0 and all(_unquantified(x) for x in ins)
        d["asserted_peers"] = max((len(unquantified.get(x["source"], ())) - 1 for x in ins), default=0) \
            if d["upper_bound"] else 0
        d["value_label"] = (("≤" if d["upper_bound"] else "") + short_usd(d["value_usd"])) if d["value_usd"] else ""
        # the trace saw (about) all of it leave again (freeze.Identifier.moved_on, the Recovery plan's "moved on")
        sent = sum(float(t or 0) for _, t in outflows.get(d["id"], []))
        d["moved_on"] = (d["value_usd"] > 0 and "dormant" not in (d.get("flags") or []) and d.get("type") != "deposit"
                         and sent >= MOVED_ON_SHARE * d["value_usd"])
        d["size"] = node_size(d["value_usd"], vmax)
        d["dust"] = d["value_usd"] < DUST_USD
    return elements


def _unquantified(edge: Mapping) -> bool:
    """A link with no on-chain amount (an asserted hop: its taint is the sender's untraced remainder)."""
    return edge.get("amount") is None and not edge.get("virtual")


def apply_annotations(elements: dict, orders: list[OrderRef], recs: list[dict], *,
                      rec_url=None) -> dict:
    """Write freeze_status / stop_orders / recommended onto the node data. `rec_url(rec)` gives the
    deep link of a recommendation (None = no action link for this viewer)."""
    for n in elements.get("nodes", []):
        d = n["data"]
        status, linked = node_freeze(d.get("address"), d.get("entity"), orders)
        # the key is left out when there is no status: Cytoscape's `node[freeze_status]` matches a null value too
        d.pop("freeze_status", None)
        if status is not None:
            d["freeze_status"] = status
        d["stop_orders"] = linked
    for r in recs:
        r["url"] = rec_url(r) if rec_url else None
    return apply_recommended(elements, recs)


ONCHAIN_STATES = ("frozen", "unfrozen", "failing", "clear", "error")
ONCHAIN_LABELS = {
    "frozen": "Frozen on-chain (issuer blacklist)",
    "unfrozen": "Freeze lifted on-chain: removed from the issuer blacklist, funds can move",
    "failing": "Token transfers failing on-chain (not blacklisted)",
    "clear": "Checked on-chain: not blacklisted",
    "error": "On-chain check failed",
}
_ONCHAIN_CHECK_KEYS = ("issuer", "symbol", "contract", "status", "error", "blacklisted", "balance_label", "usd",
                       "block_number", "checked_at", "method", "raw_sha256", "freeze_tx_hash", "frozen_at",
                       "frozen_at_basis", "frozen_at_source", "failed_count", "first_failed_tx", "first_failed_at",
                       "failed_txs", "label", "frozen_at_note", "unfrozen", "balance_destroyed")


def onchain_key(chain: str | None, address: str | None) -> tuple[str, str]:
    """(chain, address) as app.freeze / app.attribution key it (app.domain.addresses)."""
    from app.domain.addresses import wallet_key

    return wallet_key(chain, address)


def apply_onchain(elements: dict, states: Mapping[tuple[str, str], Mapping]) -> dict:
    """Write `onchain_freeze` (and `onchain_frozen` for a blacklisted wallet) onto the nodes that have an
    on-chain reading. `states` maps onchain_key -> a wallet row of app.freeze.service.wallet_rows."""
    for n in elements.get("nodes", []):
        d = n["data"]
        d.pop("onchain_frozen", None)  # absent unless true: `node[?onchain_frozen]` must not match null
        d.pop("onchain_unfrozen", None)
        d.pop("onchain_freeze", None)
        w = states.get(onchain_key(d.get("chain"), d.get("address")))
        if not w or not w.get("checks"):
            continue
        state = w.get("state") if w.get("state") in ONCHAIN_STATES else "clear"
        d["onchain_freeze"] = {
            "state": state, "title": ONCHAIN_LABELS[state], "label": w.get("label_text"),
            "frozen_usd": w.get("frozen_usd") or 0,
            "checks": [{k: c.get(k) for k in _ONCHAIN_CHECK_KEYS} for c in w["checks"]],
        }
        if state == "frozen":
            d["onchain_frozen"] = True
        elif state == "unfrozen":
            d["onchain_unfrozen"] = True
    return elements


def onchain_counts(elements: dict) -> dict[str, int]:
    """Nodes per on-chain state (the legend's counts)."""
    out: dict[str, int] = {}
    for n in elements.get("nodes", []):
        st = (n["data"].get("onchain_freeze") or {}).get("state")
        if st:
            out[st] = out.get(st, 0) + 1
    return out


# --------------------------------------------------------------------------- database wrapper
def order_refs(case, *, case_id: int) -> list[OrderRef]:
    """The case's stop orders as OrderRefs (superseded ones dropped)."""
    from app.db.models import CorrespondenceKind, StopOrderOrigin
    from app.domain.correspondence import hold_state, order_state

    out: list[OrderRef] = []
    for o in case.stop_orders:
        status = freeze_status_of(order_state(o))
        if status is None:
            continue
        ids = dict(o.identifiers or {})
        recipient = o.entity.name if o.entity is not None else str(ids.get("entity") or "")
        if not recipient:
            continue
        letter = next((c for c in o.correspondence if c.kind == CorrespondenceKind.STOP_ORDER), None)
        url = (f"/cases/{case_id}/authorities/correspondence/{letter.id}" if letter is not None
               else f"/cases/{case_id}/stop-orders/{o.id}")
        hold = hold_state(o)
        out.append(OrderRef(
            id=o.id, recipient=recipient, status=status, url=url,
            sent_at=o.sent_at.date().isoformat() if o.sent_at else None,
            cited=cited_addresses(ids, o.body_markdown, imported=o.origin == StopOrderOrigin.IMPORTED),
            amount_held=str(hold["amount"]) if hold.get("amount") else None, asset_held=hold.get("asset"),
            imported=o.origin == StopOrderOrigin.IMPORTED, kind=str(o.kind or ""),
        ))
    return out


def candidate_refs(cands) -> list[CandidateRef]:
    return [CandidateRef(
        entity=c.entity_name, kind=c.kind, priority=int(c.priority or 0), category=c.category,
        entity_id=c.entity.id if c.entity is not None else None,
        addresses=[(i.address, float(i.taint_usd or Decimal(0))) for i in c.identifiers],
        moved_on=frozenset(i.address.strip().lower() for i in c.identifiers if getattr(i, "moved_on", False)),
    ) for c in cands]


def letter_url(case_id: int, rec: dict) -> str:
    """Deep link to the authority page's Generate-letter form, stop order pre-selected (a draft
    already written for the entity opens that draft instead)."""
    if rec.get("draft_url"):
        return rec["draft_url"]
    if rec.get("entity_id"):
        return f"/cases/{case_id}/authorities/entity-{int(rec['entity_id'])}?template=stop_order#generate"
    return f"/cases/{case_id}?tab=authorities"


def annotate_elements(db, case, run, elements: dict, *, can_act: bool, owners: bool = True,
                      show_names: bool = False) -> list[dict]:
    """Annotate the run's Cytoscape elements in place; returns the recommended actions (each with
    `url` for viewers who may draft letters, else None, and the graph node ids it concerns). Viewers
    who may not draft get `drafted` (a draft exists) but no `draft_id` / `draft_url` / `entity_id`.
    `owners=False`: the wallet owners are left to app.tracing.hover.hover_data (one attribution pass, the plan's);
    `show_names`: a person's free-text owner name (view_restricted), as the Fund flow tab and the plan show it."""
    from app.tracing.freeze import freeze_candidates

    orders = order_refs(case, case_id=case.id)
    recs = recommendations(candidate_refs(freeze_candidates(db, run)), orders)
    for r in recs:
        r["url"] = letter_url(case.id, r) if can_act else None
        if not can_act:  # deep links, and the ids they are built from, only for members who may draft
            r["draft_url"] = r["entity_id"] = r["draft_id"] = None
    apply_annotations(elements, orders, recs, rec_url=(lambda r: r["url"]))
    ids_by_addr: dict[str, list[str]] = {}
    for n in elements.get("nodes", []):
        ids_by_addr.setdefault((n["data"].get("address") or "").lower(), []).append(n["data"]["id"])
    for r in recs:
        r["node_ids"] = [i for a in r["addresses"] for i in ids_by_addr.get(a.lower(), [])]
    annotate_onchain(db, case, elements)
    if owners:
        annotate_owners(db, case, run, elements, show_names=show_names)
    return recs


def annotate_owners(db, case, run, elements: dict, owners: dict | None = None, show_names: bool = False) -> dict:
    """Who owns each wallet (app.attribution: the owner, kind, confidence, source, the evidence lines and who to ask)
    onto the nodes as `owner`. Never a person's note (case data); reads the database only. A failure never breaks the
    graph. `owners`: {wallet key: Attribution.as_dict(show_notes=False)} when the caller already has them; a person's
    free-text owner name only with `show_names` (view_restricted)."""
    try:
        from app.attribution import service as attr

        owners = owners if owners is not None else attr.by_key(db, case, run=run, show_names=show_names)
    except Exception:
        import logging

        logging.getLogger(__name__).exception("owner annotation failed for case %s", getattr(case, "id", None))
        return elements
    for n in elements.get("nodes", []):
        d = n["data"]
        o = owners.get(onchain_key(d.get("chain"), d.get("address")))
        d.pop("owner", None)
        if o:
            d["owner"] = {k: o[k] for k in ("owner", "owner_label", "kind", "kind_label", "confidence", "source",
                                            "source_label")}
            d["owner"].update(lines=o["lines"][:4], ask=(o.get("ask") or {}).get("text"))
    return elements


def annotate_onchain(db, case, elements: dict) -> dict:
    """On-chain freeze readings (app.freeze) onto the nodes; reads the database only, never the network.
    A failure here never breaks the graph."""
    try:
        from app.freeze.service import wallet_states

        return apply_onchain(elements, wallet_states(db, case))
    except Exception:
        import logging

        logging.getLogger(__name__).exception("on-chain freeze annotation failed for case %s", getattr(case, "id", None))
        return elements
