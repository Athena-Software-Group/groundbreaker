"""Fund-flow graph hover cards: `data.hover` on every node and edge of a run's Cytoscape elements.

    hover_data(db, case, run, elements, access)   # in place, after annotate.annotate_elements; returns elements

One pass per page, read-only, no network: the hover's own reads are a fixed number of queries (never one per node);
on the latest run it also builds the Recovery plan (app.blocks.recovery.build: its own fixed passes), on an older run
it does not (the plan is the latest run's).

* **flows** — what went through the wallet in this run (its TraceEdges, plus the swap service's cross-chain legs the
  graph draws as virtual edges): transfers in / out of the *case's* money (pre-fraud context transfers apart: only
  counted, `context`), USD (`amount_usd`; `partial` when some transfer has no USD, `asserted` when one has no on-chain
  amount, `unpriced` when an on-chain one has no price), tainted USD, the amount per asset, the swap legs (`swaps`),
  the first and last case transfer (asserted day-only dates apart), and the TOP_TRANSFERS largest transfers, case
  transfers first (direction, amount, USD, time, counterparty, short tx hash). Edges get the same for the movements
  one link draws (no direction: a link runs source → target; the EDGE_TRANSFERS largest, oldest first).
* **status** — `taint`: the wallet's tainted USD and share of the loss, or the USD traced *through* it (`through`:
  a swap service's payout wallet carries no taint of its own); the latest *good* on-chain reading per issuer
  contract (balance, blacklisted / lifted, when), with a later failed check said separately (`failed`, never in place
  of the good reading), and `unchecked` for an issuer-freezable wallet nobody checked yet; `dropped` when a reading
  after the trace holds far less than the case money traced in (funds left the wallet: its "dormant" tag qualified);
  the watch list (watched, every movement alert raised after this run with the unacknowledged ones counted apart,
  `checked`: the watcher's last check); the node's flags as short tags (deposit, sweep, recommended, freeze status,
  terminal).
* **owner** — who the trace says holds the wallet: entity / label and category, else "unknown" (unhosted, contract,
  placeholder). `float`: a wallet the trace attributes to a service holding a stablecoin balance holds that service's
  float, not the case's money (app.blocks.recovery._stake); `pooled`: an unattributed wallet holding more than
  recovery.POOLED_FACTOR × what was traced in reads as a possible service hot wallet. The dict is the hook for the
  wallet-owner attribution release (`source` says where the name came from).
* **authorities** — who can act: the owner entity, and the token issuer (Tether / Circle) for a stablecoin wallet the
  trace marks issuer-freezable or that has an issuer reading; each with its request status from app.blocks.status
  ("Sent 18 Oct — awaiting reply, due 21 Oct", "Acknowledged — ticket #… · sent 18 Oct, replied 19 Oct", "LE process
  required · sent 18 Oct, replied 19 Oct — our move"; `cited` False when the requests sent do not name this address)
  and the Recovery plan's next actionable move for it (none while only waiting, and none on an older run: the plan is
  the latest run's). `move`: the plan's wallet move that names this address (watch, re-trace, a reply's lead).
  `next_unavailable`: the plan could not be read (no "Next" is not "nothing to do"). `no_authority`: why nobody is
  listed (self-custody, a placeholder, an owner not identified yet).

A part that fails (each fetch in its own savepoint, its error logged by type only) leaves its section None — the card
says "unavailable" — never the no-data defaults; an element that fails loses its `hover`, the graph still renders.

Roles: the texts go through the same masks as the Block status page and the Recovery plan (LE / PI contacts and
complaint references masked below manage_le_contacts / view_restricted; moves built from reply content only with
view_restricted); no links, ids or contact data enter `hover` (request lines are built from the status label, never
the "resend to <address>" detail, and every line is scrubbed of e-mail addresses and URLs).
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from decimal import Decimal

from sqlalchemy import select

from app.tracing.annotate import FREEZE_STATUS_LABELS, entity_key, onchain_key, short_entity

log = logging.getLogger(__name__)

TOP_TRANSFERS = 5
EDGE_TRANSFERS = 3
FLOAT_MIN_USD = 1.0
DROPPED_FACTOR = 0.5  # a reading after the trace below this share of the case money traced in: funds left
STABLE_ISSUER = {"USDT": "Tether", "USDC": "Circle"}
CATEGORY_LABELS = {"exchange": "exchange", "casino": "casino", "otc": "OTC desk", "swap_service": "swap service",
                   "bridge": "bridge", "dex": "DEX (non-custodial)", "mixer": "mixer", "stablecoin_issuer": "issuer",
                   "hosting": "hosting", "infra": "infrastructure", "unknown": "unknown"}
NON_CUSTODIAL = frozenset({"dex", "bridge", "mixer"})
TYPE_OWNER = {"victim": "the victim", "perpetrator": "perpetrator (self-custody)", "eoa": "unhosted wallet",
              "contract": "contract", "deposit": "deposit address", "hot_wallet": "service hot wallet"}
TAGS = {"vasp_deposit": "deposit address", "vasp_hot_wallet": "service hot wallet", "rapid_forward": "swept fast",
        "sweep": "sweep", "dormant": "dormant", "trace_next": "trace further", "stablecoin_freezable": "issuer-freezable",
        "swap_service": "swap", "asserted_link": "asserted link (unconfirmed)", "pending_input": "placeholder",
        "unquantified_taint": "amount unconfirmed (upper bound)",
        "context_only": "pre-fraud context", "possible_service_wallet": "possible service wallet"}
SELF_CUSTODY = frozenset({"victim", "perpetrator"})
TERMINAL_LABELS = {"vasp": "service account", "vasp_omnibus": "service hot wallet", "swap_service": "swap service",
                   "max_hops": "hop limit reached", "context": "pre-fraud context"}
REC_KIND = {"issuer_blacklist": "issuer blacklist", "freeze": "freeze", "preservation": "preserve records"}
TYPE_LABELS = {"victim": "victim", "perpetrator": "perpetrator wallet", "eoa": "wallet", "contract": "contract",
               "deposit": "deposit address", "hot_wallet": "service hot wallet", "unknown": "type unknown"}
SOURCE_LABELS = {"etherscan": "Etherscan", "blockscout": "Blockscout", "trongrid": "TronGrid", "mempool": "mempool.space",
                 "fixture": "demo data", "pi_report": "investigator's report", "manual": "entered by hand",
                 "etherscan_tag": "Etherscan tag", "tronscan": "Tronscan"}


def display_labels() -> dict:
    """The plain words the graph's details panel shows for the trace's codes (static/graph.js `graph-labels`)."""
    from app.tracing.heuristics import FLAG_LABELS

    return {"flags": FLAG_LABELS, "types": TYPE_LABELS, "terminal": TERMINAL_LABELS, "sources": SOURCE_LABELS,
            "rec_kind": REC_KIND}
_CONTACT = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+|(?:https?://|www\.)\S+", re.IGNORECASE)


def scrub(text: str | None) -> str | None:
    """`text` without e-mail addresses or URLs (a hover line never carries contact data)."""
    return _CONTACT.sub("[address withheld]", text) if text else text


def _fmt(v: datetime | None) -> str | None:
    if v is None:
        return None
    return (v if v.tzinfo else v.replace(tzinfo=UTC)).astimezone(UTC).strftime("%d %b %Y %H:%M UTC")


def _day(v: datetime | None) -> str:
    return (v if v.tzinfo else v.replace(tzinfo=UTC)).astimezone(UTC).strftime("%d %b") if v else ""


def amount_text(v: Decimal | None, asset: str | None) -> str:
    if v is None:
        return f"? {asset or ''}".strip()
    q = Decimal("0.0001") if abs(v) < 1 else Decimal("0.01")
    return f"{v.quantize(q).normalize():,f} {asset or ''}".strip()


def short_tx(h: str | None) -> str:
    h = h or ""
    if h.startswith("ASSERTED:") or "PENDING" in h:
        return "asserted"
    return h if len(h) <= 22 else f"{h[:10]}…{h[-6:]}"


def _party(d: dict | None) -> str:
    if not d:
        return "?"
    name = d.get("entity") or d.get("label")
    if name:
        name = short_entity(name) if d.get("entity") else name
        return name if len(name) <= 28 else name[:27] + "…"
    return d.get("short") or ""


def _usd(v: float) -> str:
    return f"${v:,.0f}" if v >= 10 else f"${v:,.2f}"


# --------------------------------------------------------------------------- flows
def _movements(db, run) -> list[dict]:
    from app.db.models import TraceEdge, Transfer

    q = (select(TraceEdge.id, TraceEdge.taint_usd, Transfer.from_address_id, Transfer.to_address_id, Transfer.asset,
                Transfer.amount, Transfer.amount_usd, Transfer.timestamp, Transfer.tx_hash)
         .join(Transfer, TraceEdge.transfer_id == Transfer.id).where(TraceEdge.run_id == run.id))
    return [{"id": r[0], "taint": float(r[1] or 0), "src": str(r[2]), "dst": str(r[3]), "asset": r[4], "amount": r[5],
             "usd": float(r[6]) if r[6] is not None else None, "at": r[7], "tx": r[8]} for r in db.execute(q).all()]


def _swaps(edges: list[dict]) -> list[dict]:
    """The swap service's cross-chain legs (graph.build_graph's virtual edges: no transfer of their own) as movements."""
    out = []
    for i, e in enumerate(edges):
        d = e["data"]
        if not d.get("virtual"):
            continue
        a, _, b = str(d.get("tx_hash") or "").partition(" → ")
        try:
            at = datetime.fromisoformat(d["timestamp"]) if d.get("timestamp") else None
        except ValueError:
            at = None
        out.append({"id": -1 - i, "taint": float(d.get("taint_usd") or 0), "src": d["source"], "dst": d["target"],
                    "asset": d.get("asset") or "", "amount": None, "usd": None, "at": at, "tx": a, "tx2": b,
                    "swap": True})
    return out


def _asserted(m: dict) -> bool:
    return not m.get("swap") and (short_tx(m["tx"]) == "asserted" or m["amount"] is None)


def _at(m: dict) -> str | None:
    """The time as shown: an asserted transfer's date alone (its time of day is not known)."""
    if m["at"] is None or not _asserted(m):
        return _fmt(m["at"])
    v = m["at"] if m["at"].tzinfo else m["at"].replace(tzinfo=UTC)
    return v.astimezone(UTC).strftime("%d %b %Y") + ", asserted"


def _transfer(m: dict, nodes: dict, *, node_id: str | None = None) -> dict:
    out = node_id is not None and m["src"] == node_id
    other = nodes.get(m["dst"] if out else m["src"]) if node_id is not None else None
    swap = bool(m.get("swap"))
    party = _party(other) if other is not None else None
    if swap and other is not None:
        party = f"{party} ({other.get('chain')})"
    return {"dir": None if node_id is None else "out" if out else "in",
            "amount": f"cross-chain swap {m['asset']}" if swap else amount_text(m["amount"], m["asset"]),
            "usd": round(m["usd"], 2) if m["usd"] is not None else None, "at": _at(m), "party": party,
            "tx": f"{short_tx(m['tx'])} → {short_tx(m['tx2'])}" if swap else short_tx(m["tx"]),
            "asserted": _asserted(m), "swap": swap, "context": bool(m.get("ctx"))}


def _side(ms: list[dict]) -> dict:
    assets: dict[str, Decimal] = {}
    for m in ms:
        if m["amount"] is not None:
            assets[m["asset"]] = assets.get(m["asset"], Decimal(0)) + Decimal(m["amount"])
    return {"n": len(ms), "usd": round(sum(m["usd"] or 0 for m in ms), 2),
            "partial": any(m["usd"] is None and not m.get("swap") for m in ms),
            "asserted": any(_asserted(m) for m in ms), "asserted_n": sum(1 for m in ms if _asserted(m)),
            "unpriced": any(m["usd"] is None and not m.get("swap") and not _asserted(m) for m in ms),
            "taint_usd": round(sum(m["taint"] for m in ms), 2),
            "assets": [amount_text(v, a) for a, v in sorted(assets.items(), key=lambda x: -x[1])][:4],
            "swaps": sorted({m["asset"] for m in ms if m.get("swap")})}


def _span(ms: list[dict]) -> tuple[str | None, str | None]:
    """(first, last) of the case transfers: pre-fraud context apart, an exact time before an asserted date."""
    case = [m for m in ms if not m.get("ctx") and m["at"] is not None]
    pick = sorted([m for m in case if not _asserted(m)] or case, key=_ts)
    return (_at(pick[0]), _at(pick[-1])) if pick else (None, None)


def _ts(m: dict) -> float:
    at = m["at"]
    return (at if at.tzinfo else at.replace(tzinfo=UTC)).timestamp() if at is not None else 0.0


def _rank(m: dict) -> tuple:
    return (-(m["usd"] if m["usd"] is not None else m["taint"]), _ts(m), m["id"])


def flows(node_id: str, ins: list[dict], outs: list[dict], nodes: dict) -> dict:
    """In / out of the case's money (pre-fraud context counted apart), the span, the top transfers (case ones first)."""
    top = sorted(ins + outs, key=lambda m: (bool(m.get("ctx")), *_rank(m)))[:TOP_TRANSFERS]
    first, last = _span(ins + outs)
    return {"in": _side([m for m in ins if not m.get("ctx")]), "out": _side([m for m in outs if not m.get("ctx")]),
            "first": first, "last": last, "context": sum(1 for m in ins + outs if m.get("ctx")),
            "top": [_transfer(m, nodes, node_id=node_id) for m in sorted(top, key=lambda m: (bool(m.get("ctx")),
                                                                                              _ts(m)))]}


# --------------------------------------------------------------------------- on-chain readings, watch list
def _readings(db, case) -> dict[tuple[str, str], list[dict]]:
    """onchain_key -> one entry per issuer contract: the latest good reading, and a later failed check apart."""
    from app.db.models import FreezeCheck
    from app.freeze.service import exact_balance, fmt_amount
    from app.providers.prices import to_usd

    good: dict[tuple, FreezeCheck] = {}
    last: dict[tuple, FreezeCheck] = {}
    for row in db.scalars(select(FreezeCheck).where(FreezeCheck.case_id == case.id)
                          .order_by(FreezeCheck.checked_at, FreezeCheck.id)):
        k = (onchain_key(row.chain, row.address), row.token_contract)
        last[k] = row
        if row.status == "ok":
            good[k] = row
    out: dict[tuple[str, str], list[dict]] = {}
    for k, latest in last.items():
        ok = good.get(k)
        e = {"issuer": latest.issuer, "symbol": latest.token_symbol, "checked": None, "balance": None, "usd": None,
             "blacklisted": None, "lifted": False, "failed": None, "unchecked": False, "_at": None}
        if ok is not None:
            bal = exact_balance(ok)
            usd = to_usd(ok.token_symbol, bal) if bal is not None else None
            e.update(checked=_fmt(ok.checked_at), _at=_aware(ok.checked_at), balance=f"{fmt_amount(bal)} {ok.token_symbol}",
                     usd=float(usd) if usd is not None else None, blacklisted=bool(ok.blacklisted),
                     lifted=bool((ok.meta or {}).get("unfrozen")) and not ok.blacklisted)
        if latest.status != "ok":
            e["failed"] = {"at": _fmt(latest.checked_at), "error": (latest.error or "error")[:64]}
        out.setdefault(k[0], []).append(e)
    for v in out.values():
        v.sort(key=lambda e: (e["issuer"], e["symbol"]))
    return out


def _aware(v: datetime | None) -> datetime | None:
    return v.replace(tzinfo=UTC) if v is not None and v.tzinfo is None else v


def _since(run) -> datetime | None:
    return _aware(run.finished_at or run.started_at)


def _watch(db, case, run) -> tuple[dict[int, str | None], dict[int, dict]]:
    """(watched address id -> the watcher's last check after the run (None: not checked since), address id ->
    {n, unacknowledged, last} of every movement alert raised after the run, acknowledged or not: an alert someone saw
    is still movement)."""
    from app.db.models import Alert, WatchItem

    since = _since(run)
    watched: dict[int, str | None] = {}
    for aid, at in db.execute(select(WatchItem.address_id, WatchItem.last_checked_at)
                              .where(WatchItem.case_id == case.id, WatchItem.active.is_(True))).all():
        at = _aware(at)
        watched[aid] = _fmt(at) if at is not None and (since is None or at > since) else None
    alerts: dict[int, dict] = {}
    q = (select(WatchItem.address_id, Alert.created_at, Alert.acknowledged)
         .join(Alert, Alert.watch_item_id == WatchItem.id).where(WatchItem.case_id == case.id))
    for aid, at, ack in db.execute(q).all():
        at = _aware(at)
        if at is None or (since is not None and at <= since):
            continue
        a = alerts.setdefault(aid, {"n": 0, "unacknowledged": 0, "at": at})
        a["n"] += 1
        a["unacknowledged"] += 0 if ack else 1
        a["at"] = max(a["at"], at)
    return watched, {k: {"n": v["n"], "unacknowledged": v["unacknowledged"], "last": _fmt(v["at"])}
                     for k, v in alerts.items()}


def _tags(d: dict) -> list[dict]:
    tags: list[dict] = []
    if d.get("type") == "victim":
        tags.append({"t": "victim", "tone": "ok"})
    for f in d.get("flags") or []:
        if f == "stablecoin_freezable" and d.get("moved_on"):
            # it received the stablecoin, and the trace saw it leave: nothing left for the issuer to blacklist
            tags.append({"t": f"received {d.get('coin') or 'stablecoin'}, moved on", "tone": "muted"})
            continue
        if f in TAGS and TAGS[f] not in {t["t"] for t in tags}:
            tags.append({"t": TAGS[f], "tone": "warn" if f in ("rapid_forward", "sweep", "stablecoin_freezable")
                         else "muted"})
    if d.get("type") == "deposit" and "deposit address" not in {t["t"] for t in tags}:
        tags.insert(0, {"t": "deposit address", "tone": "muted"})
    r = d.get("recommended")
    if r:
        tags.append({"t": f"recommended: {REC_KIND.get(r.get('kind'), 'stop order')} → {r.get('short') or r.get('entity')}",
                     "tone": "danger"})
    st = d.get("freeze_status")
    if st:
        tags.append({"t": FREEZE_STATUS_LABELS.get(st, st), "tone": "ok" if st == "frozen" else "warn"
                     if st in ("requested", "acknowledged") else "muted"})
    if d.get("terminal") and d.get("terminal_reason") not in (None, "context"):
        tags.append({"t": f"trace ends here ({terminal_label(d['terminal_reason'])})", "tone": "muted"})
    return tags


def terminal_label(reason: str | None) -> str:
    """'vasp_omnibus' -> 'service hot wallet' (the graph's plain words for why the walk stopped)."""
    return TERMINAL_LABELS.get(reason or "", str(reason or "").replace("_", " "))


# --------------------------------------------------------------------------- owner
FLOAT_KINDS = frozenset({"exchange_hot_wallet", "swap_bridge"})  # app.attribution: a service's pooled float
DEPOSIT_KINDS = frozenset({"exchange_deposit", "casino"})  # app.attribution: one customer's deposit address
SERVICE_KINDS = FLOAT_KINDS | DEPOSIT_KINDS


def _att_wins(d: dict) -> dict | None:
    """The attribution (annotate_owners) when it, not the trace's entity map, decides the owner: the same choice the
    Recovery plan and the click panel make (a person's call always; a catalogue / explorer / behaviour claim that won
    over the trace's). None: the trace's entity map (or nothing) decides."""
    att = d.get("owner") or {}
    src = att.get("source")
    if not att or src in (None, "trace"):
        return None
    if src != "manual" and not att.get("owner"):
        return None  # an unnamed claim never hides the service the trace names (nor the trace's own type label)
    return att


def owner(d: dict, readings: list[dict]) -> dict:
    from app.blocks.recovery import POOLED_FACTOR

    att = _att_wins(d)
    cat = d.get("entity_category")
    o = {"name": d.get("entity"), "label": d.get("label") or None, "category": cat,
         "category_label": CATEGORY_LABELS.get(cat or "", (cat or "").replace("_", " ")) or None,
         "known": bool(d.get("entity")), "source": "trace" if d.get("entity") else None, "float": None, "pooled": None,
         "deposit": None, "self_custody": not d.get("entity") and d.get("type") in SELF_CUSTODY}
    if att is not None:
        kind = att.get("kind")
        o.update(name=att.get("owner"), category=kind, category_label=att.get("kind_label"),
                 known=bool(att.get("owner")), source=att.get("source_label"), confidence=att.get("confidence"),
                 self_custody=kind == "unhosted" and not att.get("owner"))
    elif not o["known"]:
        kind = None
        placeholder = "_" in (d.get("address") or "") or "pending_input" in (d.get("flags") or [])
        o["category_label"] = "placeholder (not resolved yet)" if placeholder else TYPE_OWNER.get(d.get("type") or "",
                                                                                                   "unknown")
    else:  # the trace's entity map, read as the plan reads it (app.attribution.trace_kind: by the entity's category)
        from app.attribution.service import trace_kind

        kind = trace_kind(cat, d.get("type"))
    held = [e for e in readings if e["usd"] is not None and not e["blacklisted"] and e["usd"] >= FLOAT_MIN_USD]
    usd = sum(e["usd"] for e in held)
    who = (short_entity(d["entity"]) if att is None and d.get("entity") else o["name"]) or "the service"
    if o["known"] and kind in DEPOSIT_KINDS:
        o["deposit"] = (f"deposit address of {who}" + (f" ({_usd(usd)} on-chain)" if held else "")
                        + f": what reached it was credited to the depositor's account at {who}: ask {who} to freeze it")
    elif held and o["known"] and kind in FLOAT_KINDS:
        o["float"] = (f"{_usd(usd)} on-chain is {who}'s float (the service's funds, not the case's balance): ask "
                      f"{who}")
    elif held and kind not in SERVICE_KINDS | {"unhosted", "non_custodial", "issuer"}:
        traced = float(d.get("taint_usd") or 0)
        if traced > 0 and usd > POOLED_FACTOR * traced:
            o["pooled"] = (f"holds {_usd(usd)}, {_usd(traced)} traced in: possibly an exchange / service hot wallet — "
                           "identify the owner before asking the issuer")
    return o


# --------------------------------------------------------------------------- authorities
def _cites(row, address: str) -> bool:
    o = row.order
    if o is None or len(address) < 25:
        return False
    a = address.lower()
    return a in str(o.identifiers or {}).lower() or a in (o.body_markdown or "").lower()


def _status_base(row) -> str:
    """row.status_text without the addresses it can carry: a redirect's "resend to <address>", a resend's addressees."""
    from app.blocks import status as bs

    if row.status == bs.rules.REDIRECTED:
        base = f"{row.label}: resend to the address their reply names" if row.resend_to else row.label
    elif row.status == bs.AWAITING and row.resent:
        base = "Sent (resent), awaiting reply"
    else:
        base = row._status_text()
    return f"{base} — {row.suggestion_text}, needs confirmation" if row.suggestion is not None else base


def request_line(row) -> str:
    """'Sent 18 Oct — awaiting reply, due 21 Oct' / 'Acknowledged — ticket #RB-1' / 'Not sent (draft)'."""
    from app.blocks import status as bs

    if row.status == bs.NOT_SENT:
        return "Drafted, not sent"
    day = _day(row.requested_at) if row.requested_at else ""
    base = _status_base(row)
    t = row.ticket
    ticket = f" — ticket {t if t.startswith('#') else '#' + t}" if t and t not in base else ""
    if row.status == bs.AWAITING and row.suggestion is None:
        s = f"Sent {day} — {'resent, ' if row.resent else ''}awaiting reply{ticket}".replace("Sent  ", "Sent ")
    elif row.status == bs.ONCHAIN_ONLY:
        s = base
    else:
        s = base + ticket + (f" · sent {day}" if day else "")
        rep = row.last_reply
        if rep is not None and rep.at is not None:
            s += f"{',' if day else ' ·'} replied {_day(rep.at)}"
    if row.status in bs.OUR_ACTION:  # their clock no longer runs: the ball is in our court
        s += " — our move"
    elif row.due_at is not None and row.status in bs.WAITING and row.suggestion is None:
        s += f", {'overdue since' if row.overdue else 'due'} {_day(row.due_at)}"
    return s


def _mask_row(text: str, row, access) -> str:
    from app.domain import correspondence as desk

    mask = desk.contact_mask(access, row.authority)
    if not mask.active or not text:
        return text
    text = mask.text(text)
    if mask.party:
        for addr in dict.fromkeys([x for x in [row.resend_to, *row.to] if x]):
            text = text.replace(addr, str(mask.value(addr)))
    return text


def _move_line(m: dict) -> str:
    line = m["title"] if m["actionable"] else (m["text"] or m["title"])
    line = scrub(line) or ""
    return line if len(line) <= 180 else line[:179] + "…"


def _authority(name: str, role: str, rows: list, moves: list[dict], access, address: str, *,
               optional: bool = False) -> dict:
    """`optional`: a non-custodial service (records only): no request is no gap."""
    from app.blocks import status as bs

    rows = [r for r in rows if r.kind != "outlook"]
    cited = [r for r in rows if _cites(r, address)]
    pool = cited or rows
    row = max(pool, key=lambda r: (r.status != bs.NOT_SENT, r.requested_at.timestamp() if r.requested_at else 0),
              default=None)
    out = {"name": short_entity(name), "role": role, "status": None, "tone": None, "step": None, "more": 0,
           "next": None, "cited": None, "sent": row is not None and row.status != bs.NOT_SENT}
    if row is None:
        out.update(status="No request sent (records request optional)" if optional else "No request sent yet",
                   tone="neutral" if optional else "amber")
    else:
        out.update(status=scrub(_mask_row(request_line(row), row, access)), tone=bs.TONES.get(row.status, "neutral"),
                   step=row.path.label if row.path is not None and row.path.step else None, more=len(rows) - 1)
        if len(address) >= 25 and any(r.order is not None for r in rows):
            out["cited"] = bool(cited)
    for m in moves:  # an actionable step only: a "wait" move repeats the status
        line = _move_line(m)
        if m["actionable"] and m["kind"] != "wait" and not (row is not None and line.startswith(row.label)):
            out["next"] = line
            break
    return out


def _flag_issuer(d: dict) -> str | None:
    """The token issuer of an unattributed wallet the trace marks issuer-freezable (Tether / Circle), else None."""
    if d.get("entity") or "_" in (d.get("address") or "") or "stablecoin_freezable" not in (d.get("flags") or []):
        return None
    return STABLE_ISSUER.get(d.get("coin") or "")


def _authorities(d: dict, readings: list[dict], by_name: dict, rows_by: dict, moves_by: dict, access) -> list[dict]:
    from app.freeze.issuers import ISSUER_ENTITY

    out: list[dict] = []
    addr = d.get("address") or ""
    ent, cat = d.get("entity"), d.get("entity_category")
    att = _att_wins(d)
    if att is not None:  # the attribution names the holder (the plan's choice), not the trace's entity map
        kind = att.get("kind")
        ent = att.get("owner") if kind in SERVICE_KINDS or (att.get("owner") and kind not in (
            "unhosted", "non_custodial", "issuer")) else None
        cat = "dex" if kind == "non_custodial" else ("stablecoin_issuer" if kind == "issuer" else None)
    if ent and cat != "stablecoin_issuer":
        key = by_name.get(entity_key(ent))
        a = _authority(ent, "account holder" if cat not in NON_CUSTODIAL else "records only (non-custodial)",
                       rows_by.get(key, []), moves_by.get(key, []), access, addr, optional=cat in NON_CUSTODIAL)
        out.append(a)
    issuers = {e["issuer"] for e in readings} | ({_flag_issuer(d)} - {None})
    if "_" in addr:
        issuers = set()
    for issuer in sorted(issuers):
        name = ISSUER_ENTITY.get(issuer, issuer)
        key = by_name.get(entity_key(name))
        out.append(_authority(name, "issuer blacklist", rows_by.get(key, []), moves_by.get(key, []), access, addr))
    return out


def _no_authority(d: dict) -> str | None:
    """Why nobody can be asked to freeze the wallet (the card says so rather than leave the section out)."""
    addr = d.get("address") or ""
    if d.get("type") == "victim":
        return None
    if "_" in addr or "pending_input" in (d.get("flags") or []):
        return "Resolve the placeholder address first"
    if d.get("entity_category") == "stablecoin_issuer":
        return None
    if d.get("type") in SELF_CUSTODY:
        return "No one can freeze this: self-custody, no token issuer (watch / trace further)"
    return "No known custodian or token issuer: identify the owner, watch, or trace further"


def _plan_moves(plan, access) -> tuple[dict[str, list[dict]], list[dict], list[dict]]:
    """(authority key -> its moves, wallet moves, every move), as this member may see them (recovery.view)."""
    from app.blocks import recovery as rp

    v = rp.view(plan, access)
    by: dict[str, list[dict]] = {}
    wallet: list[dict] = []
    for m in v["moves"] + v["waiting"]:
        if ":" in m["key"] or m["authority"] is None:
            wallet.append(m)
        else:
            by.setdefault(m["authority"]["key"], []).append(m)
    return by, wallet, v["moves"] + v["waiting"]


def _wallet_move(address: str, wallet: list[dict]) -> str | None:
    from app.blocks import recovery as rp

    a, short = address.lower(), rp._short(address)
    for m in wallet:
        if ":" in m["key"] and m["key"].split(":", 2)[2].lower() == a:
            return _move_line(m)
    for m in wallet:
        if ":" not in m["key"] and short in m["related"]:
            return _move_line(m)
    return None


# --------------------------------------------------------------------------- the pass
def _part(db, what: str, case_id, fn):
    """(ok, fn()) in a savepoint (a failed statement never aborts the request's transaction); a failure is logged by
    type only (a DB error's text carries bound parameters)."""
    try:
        with db.begin_nested():
            return True, fn()
    except Exception as err:  # noqa: BLE001 - the graph renders without this part
        log.warning("hover: %s failed for case %s (%s)", what, case_id, type(err).__name__)
        return False, None


def _index(rows: list, plan) -> dict[str, str]:
    by_name: dict[str, str] = {}
    auths = [r.authority for r in rows] + [m.authority for m in (plan.moves + plan.waiting if plan else [])]
    for a in auths:
        if a is not None:
            for n in (a.name, a.entity.name if a.entity is not None else None):
                if n:
                    by_name.setdefault(entity_key(n), a.key)
    return by_name


def _taint(d: dict, f: dict | None, loss: float | None) -> dict:
    """The wallet's own taint, else the USD traced through it (a swap payout wallet carries no taint of its own).
    `upper`: it reached the wallet only over asserted links with no on-chain amount (annotate.style_elements), shared
    with `peers` other asserted destinations of the same sender."""
    own = float(d.get("taint_usd") or 0)
    bound = {"upper": bool(d.get("upper_bound")), "peers": int(d.get("asserted_peers") or 0)}
    if own > 0:
        return {"usd": round(own, 2), "share": float(d.get("taint_fraction") or 0), "through": False, **bound}
    t = max([float((f or {}).get(k, {}).get("taint_usd") or 0) for k in ("in", "out")])
    return {"usd": round(t, 2), "share": t / loss if loss else None, "through": t > 0, **bound}


def _cap(f: dict | None, d: dict, loss: float | None) -> dict | None:
    """Never a traced figure above what reached the wallet (or the loss): the parts of a side can count the same funds
    twice (an asserted link carries the sender's whole untraced remainder to each of its destinations; a wallet the
    funds pass through twice). A capped side keeps `capped` (its true sum in `taint_sum`)."""
    if not f:
        return f
    own = float(d.get("taint_usd") or 0)
    limits = [x for x in (own if own > 0 else None, loss) if x]
    if not limits:
        return f
    limit = round(min(limits), 2)
    for k in ("in", "out"):
        s = f.get(k) or {}
        if float(s.get("taint_usd") or 0) > limit + 0.5:
            s.update(taint_sum=s["taint_usd"], taint_usd=limit, capped=True)
    return f


def _dropped(rd: list[dict], f: dict | None, since: datetime | None) -> bool:
    """A good reading after the trace holds far less than the case money the trace left in the wallet."""
    if not f or since is None:
        return False
    held = float(f["in"]["taint_usd"]) - float(f["out"]["taint_usd"])
    after = [e for e in rd if e["_at"] is not None and e["_at"] > since and e["usd"] is not None]
    if held < FLOAT_MIN_USD or not after or any(e["blacklisted"] for e in after):
        return False
    return sum(e["usd"] for e in after) < DROPPED_FACTOR * held


def hover_data(db, case, run, elements: dict, access, *, rows: list | None = None, plan=None,
               current: bool | None = None, recs: list[dict] | None = None) -> dict:
    """Write `data.hover` onto every node and edge (module doc). `rows` / `plan`: the case's block rows and Recovery
    plan when the caller has them; `current`: whether `run` is the case's latest run (looked up when None). `recs`: the
    tab's recommended actions (annotate.annotate_elements), brought in line with the plan's moves in place
    (annotate.align_with_plan: the same value and next step as the plan, no ring on a wallet whose funds moved on)
    before the cards are built, so the card, the click panel and the actions column say the same."""
    from app.blocks import recovery as rp
    from app.blocks import status as bs

    nodes = {n["data"]["id"]: n["data"] for n in elements.get("nodes", [])}
    cid = getattr(case, "id", None)
    ok_m, ms = _part(db, "movements", cid, lambda: _movements(db, run))
    ms = [m for m in (ms or []) + _swaps(elements.get("edges", [])) if m["src"] in nodes and m["dst"] in nodes]
    for m in ms:
        m["ctx"] = any("context_only" in (nodes[k].get("flags") or []) for k in (m["src"], m["dst"]))
    ok_r, readings = _part(db, "on-chain readings", cid, lambda: _readings(db, case))
    ok_w, wl = _part(db, "watch list", cid, lambda: _watch(db, case, run))
    watched, alerts = wl if ok_w else ({}, {})
    ok_b, rows = (True, rows) if rows is not None else _part(db, "block status", cid, lambda: bs.case_blocks(db, case))
    rows_by: dict[str, list] = {}
    for r in rows or []:
        rows_by.setdefault(r.authority.key, []).append(r)
    if current is None:
        from app import services

        latest = services.latest_run(db, case)
        current = latest is not None and latest.id == run.id
    moves_by: dict[str, list[dict]] = {}
    wallet: list[dict] = []
    plan_ok = ok_b
    if current and ok_b and plan is None:  # the plan is the latest run's: an older run's card shows no moves
        plan_ok, plan = _part(db, "recovery plan", cid, lambda: rp.build(db, case, rows=rows))
    if plan is not None and current:
        ok_p, mv = _part(db, "recovery plan view", cid, lambda: _plan_moves(plan, access))
        plan_ok = plan_ok and ok_p
        moves_by, wallet, every = mv if ok_p else ({}, [], [])
        if recs is not None and ok_p:
            from app.tracing.annotate import align_with_plan, apply_recommended

            align_with_plan(recs, every, case_id=cid)
            apply_recommended(elements, recs)
    by_name = _index(rows or [], plan) if ok_b else {}
    # the wallet owners (app.attribution): the plan's own pass on the latest run, else one pass for this run; the
    # click panel's `owner` and the card's owner section read the same result
    from app.tracing.annotate import annotate_owners

    atts = getattr(plan, "owners", None) if plan is not None and current else None
    names = bool(getattr(access, "can", lambda _p: False)("view_restricted"))  # a person's owner name
    annotate_owners(db, case, run, elements, owners={k: a.as_dict(False, names) for k, a in atts.items()} if atts
                    else None, show_names=names)
    since = _since(run)
    loss = next((float(d["taint_usd"]) / float(d["taint_fraction"]) for d in nodes.values()
                 if float(d.get("taint_fraction") or 0) > 0 and float(d.get("taint_usd") or 0) > 0), None)
    ins: dict[str, list[dict]] = {}
    outs: dict[str, list[dict]] = {}
    pairs: dict[tuple[str, str], list[dict]] = {}
    for m in ms:
        outs.setdefault(m["src"], []).append(m)
        ins.setdefault(m["dst"], []).append(m)
        pairs.setdefault((m["src"], m["dst"]), []).append(m)
    failed = 0
    for nid, d in nodes.items():
        if d.get("callout"):
            continue
        try:
            raw = readings.get(onchain_key(d.get("chain"), d.get("address")), []) if ok_r else None
            aid = int(nid) if nid.isdigit() else None
            auths = _authorities(d, raw or [], by_name, rows_by, moves_by, access) if ok_b else None
            f = _cap(flows(nid, ins.get(nid, []), outs.get(nid, []), nodes), d, loss) if ok_m else None
            rd = None if raw is None else [{k: v for k, v in e.items() if k != "_at"} for e in raw]
            issuer = _flag_issuer(d)
            if rd is not None and issuer and issuer not in {e["issuer"] for e in rd}:
                rd.append({"issuer": issuer, "symbol": d.get("coin"), "checked": None, "balance": None, "usd": None,
                           "blacklisted": None, "lifted": False, "failed": None, "unchecked": True})
            dropped = bool(raw) and _dropped(raw, f, since)
            tags = _tags(d)
            if dropped:
                tags = [{**t, "t": "dormant at the trace"} if t["t"] == "dormant" else t for t in tags]
            d["hover"] = {
                "flows": f,
                "status": {"onchain": rd, "tags": tags, "taint": _taint(d, f, loss), "dropped": dropped,
                           "watched": aid in watched if ok_w else None, "checked": watched.get(aid),
                           "alerts": alerts.get(aid)},
                "owner": owner(d, rd or []),
                "authorities": auths,
                "no_authority": _no_authority(d) if auths == [] else None,
                "move": None if current and not plan_ok else _wallet_move(d.get("address") or "", wallet),
                "next_unavailable": bool(current and not plan_ok),
            }
        except Exception:  # noqa: BLE001 - this node loses its card, the graph and its click panel still render
            d.pop("hover", None)
            failed += 1
    for e in elements.get("edges", []):
        d = e["data"]
        try:
            group = sorted(pairs.get((d["source"], d["target"]), []), key=_rank)
            if not group:
                continue
            first, last = _span(group)
            d["hover"] = {**_side(group), "first": first, "last": last,
                          "transfers": [_transfer(m, nodes) for m in sorted(group[:EDGE_TRANSFERS], key=_ts)]}
        except Exception:  # noqa: BLE001
            d.pop("hover", None)
            failed += 1
    if failed:
        log.warning("hover: %d graph elements without a card for case %s", failed, cid)
    return elements
