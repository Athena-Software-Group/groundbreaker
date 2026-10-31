"""Recovery plan: the ranked moves that trap the most money fastest, rebuilt from the case's current state on every
read (nothing is stored but the evidence waivers a case admin records).

    plan = build(db, case)                       # Plan: moves (best first), waiting, secured, totals; no writes
    v = view(plan, access)                       # as this member may see it (masked contacts, allowed actions)
    body, name, manifest = pack(db, access, key) # the LE brief pack (.zip): brief, manifest, movements, readings

**Inputs.** Every block request (app.blocks.status: its path step, next action, clocks, the asks read from replies),
the latest trace run's freeze candidates (where the funds sit: custodial deposit addresses, issuer-freezable stablecoin
wallets, swap services) and unhosted wallets still holding or moving funds, the on-chain freeze readings (frozen, still
freezable, lifted), the watch list and its movement alerts, and the evidence on file.

**Moves.** One per target (a provider, issuer or wallet group): the next action of its most actionable request, or for
a target with funds in the trace and no request yet ("untouched") "send <template> to <provider> now" — the LE-only gate
turns that into a brief to the case officer. Plus watch-list, re-trace and reply-wallet moves (a wallet a reply names:
another service's deposit address → a freeze request to that service; an address the trace puts at a provider of the
case → tell that provider the funds just arrived; an external wallet → watch it, then the issuer; one at the replying
provider → its own answer asks it to extend the hold, or to freeze it when the reported account is empty), and a
funds-left move per wallet whose balance fell between two good on-chain readings after the trace (re-trace now, ask the
next custodian or issuer). An on-chain reading that failed never hides the last good one (app.freeze.wallet_rows). A
move a person cannot act on now (waiting for their reply, LE filing) is listed under "waiting" with its clock.

**Score** = value × urgency × likelihood ÷ effort (docs/recovery-plan.md):
* value: USD at stake — the not-yet-frozen balance read on-chain at an issuer's wallets, else the traced amount (an
  upper bound, flagged), the amount a person confirmed held; static prices (app.providers.prices). Each move keeps
  its own value (for ranking); moves on the same funds (only: the same wallet, or one downstream of the other's in
  the trace graph) say so ("same funds as …"), and the totals count each traced
  dollar once: per group of such moves the largest value, never the sum, at most the traced loss, plus the
  balances read at wallets the trace never saw (labelled);
* urgency (1–4): clock proximity (a playbook / reply deadline, a hold's expiry), an overdue reply, funds observed moving
  (a movement alert after the trace, a lifted issuer freeze), recent arrival, the sweep window, nobody asked yet;
* likelihood (0–0.95): what the target can do (an issuer's blacklist, an exchange account, records only) × the provider
  playbook's path for our requester (voluntary hold possible / LE process only / no playbook) × the jurisdiction route
  (direct, cross-border) × the request's path step (a hold in place, LE filed, an order);
* effort (0.3–4.5): the move's kind (confirm, send, letter, LE brief, cross-border) plus the evidence still missing.
Every move carries its reasoning in one line and its evidence checklist (app.domain.evidence_requirements).

Advisory throughout: a hold / freeze / return still counts only once a person confirms it (the secured total), the AI is
never consulted here, and nothing is sent or drafted: each action opens the prefilled letter, posts to an existing form
(watch list, freeze watch, re-trace) or downloads the pack.

**One open request per provider.** Every action linking a letter to a provider passes the request gate
(app.domain.request_gate, `_gate_actions`; the owner moves and the owners panel's lines too: `_owner_moves`,
`_gate_asks`): an open draft → "Open & send draft" (or "Add <wallet> to draft #N", the authority page's form adds it),
a request already out → its follow-up (quoting it), LE only / declined → the LE brief naming the wallet. Never a
new-letter link the gate refuses.

**One step per provider.** A provider's move takes its primary action (label, link or form), kind and whether it is
actionable from the freeze board's row for that provider (`_provider_steps`: freeze_board.provider_target, the one
function the board's row comes from): the plan's own value, score, urgency and evidence stay. A pointless draft or a
duplicate one the board flags is never one of its actions.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import re
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.attribution import service as attr
from app.blocks import classify_rules as rules
from app.blocks import path as pathmod
from app.blocks import status as bs
from app.domain import correspondence as desk
from app.domain import evidence_requirements as er
from app.domain import playbook as pbm
from app.domain.addresses import addr_key, wallet_key

log = logging.getLogger(__name__)

UNKNOWN_VALUE_USD = 100.0  # a move with no traced value (records, takedown): ranks by urgency among its peers
MAX_URGENCY = 4.0
MAX_LIKELIHOOD = 0.95
MAX_WATCH = 5
EFFORT = {"watch": 0.3, "confirm": 0.5, "send": 0.5, "review": 0.5, "check": 0.5, "resend": 0.75, "chase": 0.75,
          "retrace": 0.8, "trace": 0.8, "request": 1.0, "answer": 1.0, "le": 1.5, "cross_border": 3.0}
ACTIONABLE = frozenset(EFFORT)
KIND_ORDER = ("confirm", "le", "answer", "resend", "send", "request", "chase", "review", "check", "trace", "wait",
              "none", "close")
BASE = {"exchange": 0.5, "casino": 0.4, "otc": 0.4, "stablecoin_issuer": 0.6, "swap_service": 0.1, "bridge": 0.1,
        "dex": 0.05, "hosting": 0.02, "infra": 0.02}
ROUTE_FACTOR = {"direct": 0.85, "agent": 0.75, "counsel": 0.6, "cross_border": 0.5, None: 0.7}
STEP_FACTOR = {"provider_ask": 1.1, "hold_discretionary": 1.6, "le_route_open": 1.2, "le_filed": 1.4,
               "binding_instrument": 1.6, "cross_border": 1.2}
HELD = frozenset({rules.FROZEN, rules.HOLD_PLACED})
POOLED_FACTOR = 5.0  # balance / traced inflow above which a traced wallet reads as a possible service hot wallet
POOLED_FLAG = "possible_service_wallet"
KIND_LABELS = {"confirm": "confirm", "le": "brief LE", "cross_border": "cross-border", "answer": "answer",
               "resend": "resend", "send": "send", "request": "send now", "chase": "chase", "review": "read",
               "check": "check", "trace": "re-trace", "retrace": "re-trace", "watch": "watch", "wait": "waiting"}
# who our letters come from, as the providers' playbooks read it (app.domain.sender.requester_kind): the KPI strip's line
REQUESTER_LABELS = {"pi": "a private investigator's (not law enforcement)", "victim": "the victim's own",
                    "counsel": "counsel's (not law enforcement)"}


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _aware(v: datetime | None) -> datetime | None:
    return v if v is None or v.tzinfo else v.replace(tzinfo=UTC)


def _iso(v: Any) -> datetime | None:
    try:
        return _aware(datetime.fromisoformat(v)) if isinstance(v, str) and v else None
    except ValueError:
        return None


def money(v: float | None) -> str:
    return "value unknown" if v is None else f"${v:,.0f}"


def _ago(now: datetime, at: datetime) -> str:
    h = (now - at).total_seconds() / 3600
    return f"{max(1, round(h))}h ago" if h < 48 else f"{round(h / 24)} days ago"


def _left(now: datetime, at: datetime) -> str:
    h = (at - now).total_seconds() / 3600
    return f"in {max(1, round(h))}h" if h < 48 else f"in {round(h / 24)} days"


def _key(chain: str | None, address: str | None) -> tuple[str, str]:
    return wallet_key(chain, address)


def _short(a: str) -> str:
    return a if len(a) <= 14 else f"{a[:6]}…{a[-4:]}"


# --------------------------------------------------------------------------- what is at stake
@dataclass
class Stake:
    usd: float | None = None
    basis: str = ""
    confirmed: float = 0.0  # read on-chain (not frozen), or confirmed held by a person
    unconfirmed: float = 0.0  # traced: an upper bound
    secured: float = 0.0  # frozen on-chain / a hold a person confirmed
    secured_basis: str = ""
    lifted: list[dict] = field(default_factory=list)
    addresses: list[tuple[str, str]] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)
    arrived_at: datetime | None = None
    moved_at: datetime | None = None
    unread: int = 0  # issuer wallets without an on-chain reading
    left: list[dict] = field(default_factory=list)  # balance fell between two good readings: {short, from, to, at}
    stale: list[str] = field(default_factory=list)  # read OK earlier, the last attempt failed: "<short> <when>"
    upper: dict = field(default_factory=dict)  # wallet key -> traced USD counted as an upper bound (no reading)
    moved_on: list[str] = field(default_factory=list)  # unread issuer wallets the trace saw forward everything on
    not_case: list[str] = field(default_factory=list)  # read balances that are not the case's traced funds
    # an issuer stake's value wallet by wallet, for the totals (each traced dollar once): {k: wallet key, traced: USD
    # of the case's traced funds, untraced: USD read at a wallet the trace never saw, flow: an unread traced upper
    # bound (it includes what the wallet sent on)}
    parts: list[dict] = field(default_factory=list)


def _drained(c: dict, w: dict, cap: float, since: datetime | None) -> dict | None:
    """The fall in balance a good reading shows (app.freeze funds_left) as the case's funds moving: after the latest
    trace (a re-trace resolves it), never a service hot wallet's float still above what was traced in."""
    f = c.get("funds_left")
    at = _iso((f or {}).get("at"))
    if not f or at is None or (since is not None and at < since.replace(microsecond=0)):  # readings: whole seconds
        return None
    from app.freeze.service import SERVICE_CATEGORIES, pooled_float
    from app.freeze.service import sure_service as fz_sure_service

    att = w.get("attribution")
    sure = att is not None and fz_sure_service(att)  # an unnamed L behaviour guess never hides funds leaving
    if sure and att.kind in attr.DEPOSIT_KINDS:
        return None  # a deposit address swept into its service: the account was credited (ask the service)
    if (sure and att.kind in attr.FLOAT_KINDS) or (
            (att is None or att.kind == "unknown" or not sure) and w.get("entity") and w.get("address_type") != "deposit"
            and w.get("entity_category") in SERVICE_CATEGORIES):
        return None  # a service's float paying out (a hot / payout wallet): never the case's funds leaving
    svc = bool(w.get("entity")) or (att is not None and att.service and bool(att.owner))
    if pooled_float(bs._dec(f.get("from")) or 0, bs._dec(f.get("to")) or 0, cap, svc):
        return None  # a pooled wallet's float moving: the case's share may still sit there
    return {"short": w["short"], "chain": w["chain"], "address": w["address"], "chain_label": w["chain_label"],
            "symbol": c.get("symbol"), "from": f.get("from_label"), "to": f.get("to_label"), "at": at,
            "from_at": _iso(f.get("from_at")), "usd": f.get("usd")}


def _moved_on(att) -> bool:
    """The trace saw the wallet forward (about) everything it received and nothing is read on-chain there: no balance
    left for an issuer to blacklist (the wallet's own valuation, whatever other moves count)."""
    w = att.wallet if att is not None else None
    if w is None or not w.in_trace or w.held_usd is not None or w.holding or w.money_usd >= 1:
        return False
    # the case funds each transfer carried (never its whole amount: a mixed wallet's large transfer is partly tainted)
    return w.taint_usd <= 0 or sum(w.out_taint.values()) >= 0.9 * w.taint_usd


def _stake(a: desk.Authority, rows: list, wallets: list[dict], alerts: dict, now: datetime, *,
           since: datetime | None = None, atts: dict | None = None) -> Stake:
    cand = a.candidate
    s = Stake()
    idents = list(cand.identifiers) if cand is not None else []
    s.addresses = [(i.chain, i.address) for i in idents]
    s.flags = {f for i in idents for f in i.flags or []}
    arr = [_iso(t.get("timestamp")) for i in idents for t in i.inbound if not t.get("asserted")]
    s.arrived_at = max((t for t in arr if t), default=None)
    moved = [alerts[_key(c, x)] for c, x in s.addresses if _key(c, x) in alerts]
    s.moved_at = max(moved, default=None)
    issuer = bs._issuer_of(a)
    if issuer is not None:
        read: set[tuple[str, str]] = set()
        # a traced wallet holding far more than the trace put into it is likely an exchange / service hot wallet:
        # the value at stake is what was traced in, and its owner is identified before the issuer is asked
        traced = {_key(i.chain, i.address): float(i.taint_usd or 0) for i in idents}
        pooled: list[str] = []
        known: list[str] = []  # wallets the trace attributes to a service
        for w in wallets:
            for c in w.get("checks") or []:
                if c.get("status") != "ok" or c.get("issuer") != issuer:
                    continue
                k = _key(w["chain"], w["address"])
                read.add(k)
                if k not in {_key(*x) for x in s.addresses}:
                    s.addresses.append((w["chain"], w["address"]))
                usd = float(c.get("usd") or 0)
                att = w.get("attribution")
                # a traced wallet's cap is what the trace put in, whichever candidate names it (a watched wallet the
                # trace never saw: its whole balance)
                tw = att.wallet if att is not None and att.wallet.in_trace else None
                cap = traced.get(k) or (tw.taint_usd if tw is not None else 0.0)
                # what the trace left there: in, less what it saw go on (it saw nothing go on: all it put in)
                gone_out = sum(tw.out_taint.values()) if tw is not None else 0.0
                stayed = max(0.0, tw.taint_usd - gone_out) if tw is not None and gone_out >= 1 else cap
                mine = None  # the case's traced funds in the reading (None: at most what the trace put in)
                gone = _drained(c, w, cap, since)
                if gone is not None:
                    s.left.append(gone)
                if c.get("stale_note"):
                    s.stale.append(f"{w['short']}: {c['stale_note']}")
                svc = att.owner if att is not None and att.service and att.owner else None
                owner = w.get("entity") or svc
                owner = owner if owner and owner != a.name else None
                deposit = (att is not None and att.kind in attr.DEPOSIT_KINDS) or (
                    bool(w.get("entity")) and w.get("address_type") == "deposit")
                swept = c.get("swept")
                if swept and owner:
                    known.append(f"{w['short']} swept into {owner} {_fmt(_iso(swept.get('at')))} (expected: the "
                                 f"depositor's account was credited): ask {owner} to freeze that account")
                if owner and not c.get("blacklisted") and usd >= 1:
                    # the trace / an attribution (app.attribution) puts the wallet at a service (an exchange deposit or
                    # hot wallet, a swap payout wallet): its balance is that service's float, the case's share is what
                    # was traced in, and the service is asked, not the issuer
                    what = w.get("label") if w.get("entity") else f"{owner}'s {att.kind_label} ({att.confidence})"
                    held = "credited to the depositor's account" if deposit else "its float"
                    known.append(f"{w['short']} is {what or owner} ({money(usd)}, {held}): ask {owner}")
                    s.flags.add(POOLED_FLAG)
                    # a deposit: what was credited (all that reached it); a float: the case's share, what stayed
                    usd = min(usd, cap if deposit else stayed)
                elif cap > 0 and usd > POOLED_FACTOR * cap:
                    pooled.append(f"{w['short']} holds {money(usd)}, {money(cap)} traced in"
                                  + (f", the trace left {money(stayed)} there" if stayed < cap - 0.5 else ""))
                    s.flags.add(POOLED_FLAG)
                    usd = min(cap, stayed)  # a service's float: the case's share is what the trace left there
                if att is not None and att.router and usd >= 1 and not c.get("blacklisted"):
                    s.not_case.append(f"{w['short']} is a non-custodial router ({money(usd)} there is no customer's)")
                    usd = 0.0
                elif (tw is not None and usd >= 1 and not c.get("blacklisted") and gone_out >= 1
                      and usd > stayed + 0.5):
                    # the trace saw the case's funds leave it: only what the trace left there (in, less what it saw go
                    # on) is the case's traced funds; the rest of the reading is an untraced find, added on top and
                    # labelled. The move keeps the whole reading for its rank (blacklisting it still helps)
                    s.not_case.append(f"{w['short']} holds {money(usd)}, the trace left {money(stayed)} of the "
                                      "case's funds there")
                    mine = stayed
                if c.get("blacklisted"):
                    s.secured += usd
                elif c.get("unfrozen"):
                    s.lifted.append({"short": w["short"], "chain": w["chain_label"], "usd": usd})
                    s.confirmed += usd
                elif usd >= 1:
                    s.confirmed += usd
                if not c.get("blacklisted") and usd >= 1:
                    # for the totals: the case's traced funds are at most what the trace put in; the rest of the
                    # balance (all of it at a wallet the trace never saw) is an untraced find, added and labelled
                    mine = min(usd, cap if mine is None else mine) if (tw is not None or k in traced) else 0.0
                    s.parts.append({"k": k, "traced": mine, "untraced": usd - mine, "flow": False})
        unread = [i for i in idents if _key(i.chain, i.address) not in read]
        for i in unread:  # no reading: an attribution putting the wallet at a service still names who is asked
            att = (atts or {}).get(_key(i.chain, i.address))
            owner = att.owner if att is not None and att.service and att.owner else None
            if owner and owner != a.name:
                known.append(f"{_short(i.address)} is {owner}'s {att.kind_label} ({att.confidence}): ask {owner}")
                s.flags.add(POOLED_FLAG)
        s.unread = len(unread)
        # an unread wallet the trace saw forward everything on (app.attribution: nothing held there) holds nothing to
        # blacklist (re-trace / read it on-chain to be sure)
        gone_on = [i for i in unread if _moved_on((atts or {}).get(_key(i.chain, i.address)))]
        held_unread = [i for i in unread if i not in gone_on]
        s.moved_on = [_short(i.address) for i in gone_on]
        s.upper = {_key(i.chain, i.address): float(i.taint_usd or 0) for i in held_unread}
        up = sum(s.upper.values())
        s.unconfirmed = min(float(sum((i.taint_usd for i in held_unread), Decimal(0))),
                            float(cand.total_taint_usd)) if cand is not None else 0.0
        s.parts += [{"k": k, "traced": v * (s.unconfirmed / up), "untraced": 0.0, "flow": True}
                    for k, v in s.upper.items() if up > 0 and v > 0]
        parts = []
        if s.confirmed:
            parts.append(f"{money(s.confirmed)} on-chain, not frozen")
        if s.unconfirmed:
            parts.append(f"{'+ up to ' if parts else 'up to '}{money(s.unconfirmed)} traced (balance not read on-chain)")
        if gone_on:
            parts.append(f"{'(' if parts else ''}{', '.join(_short(i.address) for i in gone_on[:4])} moved on (the "
                         "trace saw the funds leave: re-trace / read on-chain)" + (")" if parts else ""))
        if not parts and read:
            parts.append("balance 0 on-chain: the funds left these wallets")
        if known:
            parts.append(f"(not the case's balance: {'; '.join(known)})")
        if pooled:
            parts.append(f"(possibly an exchange / service hot wallet: {'; '.join(pooled)}; identify the owner "
                         f"before asking {issuer} to blacklist it)")
        if s.not_case:
            parts.append(f"(not the case's traced funds: {'; '.join(s.not_case[:3])}; blacklisting it still helps)")
        if s.left:
            parts.append("(funds left " + "; ".join(f"{x['short']}: {x['from']} → {x['to']} {x['symbol']}"
                                                    for x in s.left) + ")")
        if s.stale:
            parts.append(f"({'; '.join(s.stale[:2])})")
        s.basis = " ".join(parts)
        if s.secured:
            s.secured_basis = f"{money(s.secured)} frozen on-chain ({issuer} blacklist)"
        s.usd = s.confirmed + s.unconfirmed if (parts or read) else None
    elif cand is not None:
        s.unconfirmed = float(cand.total_taint_usd)
        s.usd = s.unconfirmed
        if cand.kind == "preservation" and a.category in ("swap_service", "bridge", "dex"):
            s.basis = f"{money(s.usd)} passed through (order records, a pending payout)"
        else:
            n = sum(1 for i in idents if i.address_type == "deposit") or len(idents)
            s.basis = f"{money(s.usd)} traced into {n} deposit address{'es' if n != 1 else ''} (upper bound)"
    held = 0.0
    from app.providers.prices import to_usd

    lapsed = 0.0
    for r in rows:
        if r.status in HELD and r.amount and r.source in bs.HUMAN_SOURCES and r.kind != "onchain":
            amt = bs._dec(r.amount)
            usd = to_usd(r.asset or "", amt) if amt is not None and r.asset else None
            gone = r.path.lapsed if r.path is not None else None
            if gone is not None:  # its lapse / the provider's condition passed: maybe released, never "secured"
                lapsed += float(usd) if usd is not None else 0.0
                s.basis = (f"{bs.fmt_amount(r.amount, r.asset)} {r.asset or ''} held by {a.name} until "
                           f"{gone['at']:%d %b %Y} (lapsed? ask whether it still stands)").replace("  ", " ")
                continue
            held += float(usd) if usd is not None else 0.0
            s.secured_basis = (f"{bs.fmt_amount(r.amount, r.asset)} {r.asset or ''} held by {a.name} "
                               "(confirmed by a person)").replace("  ", " ")
    if held:
        s.secured += held
        s.confirmed = max(s.confirmed, held)
        s.usd = max(s.usd or 0.0, held)
        s.basis = s.basis or f"{money(held)} held (confirmed by a person)"
    if lapsed:  # still the value at stake (the funds may still be there), no longer secured
        s.usd = max(s.usd or 0.0, lapsed)
    if s.usd is None:  # no trace candidate: the amounts our own request cites (an upper bound)
        cited = 0.0
        for r in rows:
            for v in ((r.order.identifiers or {}).get("amounts") or {}).values() if r.order is not None else ():
                amt, sym = rules.find_amount(str(v)) if isinstance(v, str) else (None, None)
                usd = to_usd(sym, amt) if amt is not None and sym else None
                cited += float(usd) if usd is not None else 0.0
        if cited:
            s.usd = s.unconfirmed = cited
            s.basis = f"up to {money(cited)} cited in our request (upper bound)"
    if s.usd is None and not s.basis:
        s.basis = "no funds traced here (records / takedown)"
    return s


# --------------------------------------------------------------------------- scoring
def _likelihood(a: desk.Authority, stake: Stake, pb, requester: str, *, route: dict | None, step: str | None,
                gated: bool, status: str | None = None) -> tuple[float, str]:
    issuer = bs._issuer_of(a) is not None
    if issuer:
        total = stake.confirmed + stake.unconfirmed
        base = ((0.7 * stake.confirmed + 0.35 * stake.unconfirmed) / total) if total else 0.3
        what = "issuer blacklist" + (" (balance read on-chain)" if stake.confirmed else " (balance unconfirmed)")
        if POOLED_FLAG in stake.flags:  # an issuer rarely blacklists a service's hot wallet: its owner is asked first
            base *= 0.5
            what += "; a service hot wallet: its owner is asked first"
    else:
        base = BASE.get(a.category, 0.3)
        if a.entity is not None and not a.entity.freeze_capable and a.category in ("exchange", "casino", "otc"):
            base = 0.2
        what = {"exchange": "exchange account", "casino": "casino account", "otc": "OTC desk account",
                "swap_service": "swap service (records, a pending order)", "bridge": "bridge (records)",
                "hosting": "hosting (no funds)", "infra": "infrastructure (no funds)"}.get(a.category, a.type_label)
    rk = (route or {}).get("kind")
    agent = (route or {}).get("agent")
    rtext = ""
    if rk == "direct" and route.get("le"):
        rtext = f"{route['le']} can ask directly"
    elif agent is not None:
        rk = "agent"  # the best route: a domestic case agent asks directly (the cross-border one is the fallback)
        rtext = f"a {agent['jur']} case agent can ask directly" + (f" (via {agent['via']})" if agent.get("via") else "")
    elif rk == "cross_border":
        rtext = "cross-border: " + " / ".join(o["text"] for o in (route.get("options") or [])[:2])
    if rk in ("cross_border", None) and (route or {}).get("counsel") and requester in pathmod.PRIVATE_BY:
        rk = "counsel" if ROUTE_FACTOR["counsel"] > ROUTE_FACTOR.get(rk, 0.7) else rk
        rtext += ("; " if rtext else "") + f"or {route['counsel']['text']}"
    path = pathmod.our_path(pb, requester) if pb is not None else None
    exp = set(path.expected_replies) | set(path.outcomes) if path is not None else set()
    if pb is None:
        f, why = 0.8, "no playbook: generic odds"
    elif gated:
        f, why = ROUTE_FACTOR.get(rk, 0.7), "LE requests only"
    elif step == "le_only_redirect":  # their reply refused a private request: a voluntary hold is off the table
        f, why = ROUTE_FACTOR.get(rk, 0.7), "acts on LE process only (their reply)"
    elif exp & HELD:
        f, why = 1.0, "voluntary hold possible"
    elif rules.LE_PROCESS_REQUIRED in exp:
        f, why = ROUTE_FACTOR.get(rk, 0.7), "acts on LE process only"
    else:
        f, why = 0.7, "a notice flags and preserves; no hold expected"
    f *= STEP_FACTOR.get(step or "", 1.0)
    if status in (rules.DECLINED, rules.DECLINED_NO_ASSETS):
        f *= 0.5
    p = round(min(MAX_LIKELIHOOD, base * f), 2)
    return p, f"{what}; {why}" + (f" ({rtext})" if rtext else "")


def _urgency(now: datetime, stake: Stake, *, name: str, clock: dict | None = None, hold_at: datetime | None = None,
             overdue: bool = False, untouched: bool = False) -> tuple[float, list[str]]:
    fs: list[tuple[float, str]] = []

    def near(at: datetime, label: str) -> None:
        h = (at - now).total_seconds() / 3600
        if h <= 0:
            fs.append((2.5, f"{label} passed"))
        elif h <= 24:
            fs.append((3.0, f"{label} {_left(now, at)}"))
        elif h <= 72:
            fs.append((2.0, f"{label} {_left(now, at)}"))
        elif h <= 168:
            fs.append((1.4, f"{label} {_left(now, at)}"))

    if clock and clock.get("due_at"):
        near(clock["due_at"], clock.get("label") or "deadline")
    if hold_at is not None and (not clock or clock.get("due_at") != hold_at):
        near(hold_at, "the hold lapses")
    if overdue:
        # one phrase for one fact: a passed reply clock and an overdue reply read "reply overdue" (both still weigh)
        passed = next((i for i, (_, w) in enumerate(fs) if w == "reply due passed"), None)
        if passed is not None:
            fs[passed] = (fs[passed][0], "reply overdue")
        fs.append((1.5, "" if passed is not None else "reply overdue"))
    if stake.lifted:
        fs.append((3.0, f"the issuer lifted its freeze on {stake.lifted[0]['short']}: the funds can move"))
    if stake.moved_at is not None:
        fs.append((2.5, f"funds moved {_ago(now, stake.moved_at)} (watch-list alert)"))
    if stake.left:
        x = max(stake.left, key=lambda x: x["at"])
        why = f"funds left {x['short']} {_ago(now, x['at'])} (on-chain balance {x['from']} → {x['to']} {x['symbol']})"
        fs.append((3.0 if now - x["at"] <= timedelta(hours=48) else 2.0, why))
    if "sweep_imminent" in stake.flags:
        fs.append((2.0, "inside the sweep window"))
    if stake.arrived_at is not None:
        age = now - stake.arrived_at
        if age <= timedelta(hours=48):
            fs.append((1.6, f"funds arrived {_ago(now, stake.arrived_at)}"))
        elif age <= timedelta(days=7):
            fs.append((1.3, f"funds arrived {_ago(now, stake.arrived_at)}"))
    if untouched and (stake.usd or 0) > 0:
        fs.append((1.5, f"nobody has asked {name} yet"))
    u = 1.0
    for f, _ in fs:
        u *= f
    return round(min(MAX_URGENCY, u), 2), [w for _, w in fs if w]


def _effort(kind: str, evidence: list[dict]) -> tuple[float, str]:
    c = er.counts(evidence)
    base = EFFORT.get(kind, 1.0)
    e = base + min(1.5, 0.2 * c["open"])
    what = {"watch": "one click", "confirm": "read and confirm", "send": "send the draft", "review": "read the reply",
            "check": "check first", "resend": "one follow-up", "chase": "one status request", "retrace": "one re-run",
            "trace": "one re-run", "request": "one letter", "answer": "one answer", "le": "one LE brief",
            "cross_border": "a cross-border request (slow)"}.get(kind, "one step")
    return round(e, 2), what + (f", {c['open']} item{'s' if c['open'] != 1 else ''} to obtain" if c["open"] else "")


# --------------------------------------------------------------------------- moves
@dataclass
class Move:
    key: str  # "o12" / "c5" (a request), "entity-5" (untouched), "watch", "fwatch:<chain>:<address>", "retrace"
    kind: str
    title: str
    authority: Any = None  # desk.Authority (None for wallet moves)
    row: Any = None  # the request's bs.BlockRow
    text: str = ""  # what to do (the next action's text)
    href: str | None = None
    value: float | None = None
    basis: str = ""
    urgency: float = 1.0
    urgency_why: list[str] = field(default_factory=list)
    likelihood: float = 0.0
    likelihood_why: str = ""
    effort: float = 1.0
    effort_why: str = ""
    evidence: list[dict] = field(default_factory=list)
    clock: dict | None = None
    actions: list[dict] = field(default_factory=list)  # {label, href | post + fields, perm, primary}
    actionable: bool = True
    untouched: bool = False
    step: str | None = None
    step_label: str | None = None
    route: dict | None = None
    related: list[str] = field(default_factory=list)  # the target's other requests
    secured: float = 0.0
    sensitive: bool = False  # built from reply content (a wallet a reply names): view_restricted only
    wallets: list[tuple[str, str]] = field(default_factory=list)  # the wallets the move is about (chain, address)
    owners: list[dict] = field(default_factory=list)  # their owners (app.attribution): the move's "Owner" line
    moved_on: list[str] = field(default_factory=list)  # a target's issuer wallets the trace saw forward everything on
    counts: bool = False  # a wallet move whose value no target move counts (an owner move): in the totals
    # an owner move the request gate points at a request of the service (app.domain.request_gate): {state: "draft"
    # (send it) | "add" (add the wallet to that draft) | "sent" (a request already cites it: wait on it) | "le" (LE
    # only: the LE brief), key, no, href, at}
    cites: dict | None = None
    ask: dict | None = None  # the owners panel's line for its wallet ({text, href}): the gate's step, never a 2nd letter
    merged: list = field(default_factory=list)  # the cited owner moves folded into this request's move (_merge_cited)
    # a request's move: its row's next action as the plan reads it (`_row_move`: an own-platform destination their
    # reply names is a freeze ask, a drafted request after a sent one an escalation): what the board's row follows
    next_action: dict | None = field(default=None, repr=False, compare=False)
    # a provider's move: the freeze board's row its step comes from (freeze_board.provider_target, `_provider_steps`)
    target: Any = field(default=None, repr=False, compare=False)

    @property
    def score(self) -> float:
        v = self.value if self.value else UNKNOWN_VALUE_USD
        return round(v * self.likelihood * self.urgency / max(self.effort, 0.1), 2)

    @property
    def expected(self) -> float | None:
        return round(self.value * self.likelihood, 2) if self.value else None

    @property
    def reason(self) -> str:
        parts = [self.basis or money(self.value)] + self.urgency_why[:2] + [self.likelihood_why, self.effort_why]
        return " · ".join(p for p in parts if p)


@dataclass
class Plan:
    case_id: int
    moves: list[Move] = field(default_factory=list)  # actionable, best first
    waiting: list[Move] = field(default_factory=list)
    secured: list[dict] = field(default_factory=list)  # {authority, text, usd}
    done: list[dict] = field(default_factory=list)  # {authority, text}
    totals: dict = field(default_factory=dict)
    run: dict | None = None
    requester: str = "pi"
    generated_at: datetime = field(default_factory=_now)
    notes: list[str] = field(default_factory=list)
    owners: dict = field(default_factory=dict)  # (chain, address key) -> app.attribution Attribution, most money first
    owner_lookups: dict = field(default_factory=dict)  # app.attribution.service.status
    ledger: dict = field(default_factory=dict, repr=False)  # _count's claims (checks only)
    # the request gate's per-provider states (app.domain.request_gate.States): every action's letter link passes it
    gate: Any = field(default=None, repr=False)
    asks: dict = field(default_factory=dict)  # wallet key -> the owners panel's line the gate gives ({text, href})
    stakes: dict = field(default_factory=dict, repr=False)  # authority key -> its Stake (the LE cover letter's values)

    def find(self, key: str) -> Move | None:
        return next((m for m in self.moves + self.waiting if m.key == key), None) or next(
            (x for m in self.moves + self.waiting for x in m.merged if x.key == key), None)

    def owner_moves(self) -> list[Move]:
        """Every owner move ("owner:…"), those folded into their request's move too (`_merge_cited`)."""
        every = self.moves + self.waiting
        return [m for m in every if m.key.startswith("owner:")] + [x for m in every for x in m.merged]


def _row_title(kind: str, name: str, route: dict | None, st) -> str:
    le = (route or {}).get("le")
    agent = (route or {}).get("agent")
    if kind == "le":
        if agent is not None and (route or {}).get("case_agent", True):
            return f"Get a {agent['jur']} case agent on {name}: they can ask directly"
        if (route or {}).get("kind") == "cross_border":
            return f"Start the cross-border route for {name} (brief {le})"
        if st is not None and st.step == "hold_discretionary":
            return f"Lock in {name}'s hold: brief {le or 'LE'} for the order"
        return f"Brief {le or 'LE'} about {name}"
    return {"confirm": f"Confirm {name}'s reply", "answer": f"Answer {name}'s questions", "resend": f"Resend to {name}",
            "send": f"Send the drafted request to {name}", "request": f"Ask {name} to freeze",
            "chase": f"Chase {name}", "review": f"Read {name}'s reply", "check": f"Check before sending to {name}",
            "trace": f"Re-trace from {name}'s payout", "wait": f"Waiting on {name}", "none": f"Nothing to do at {name}",
            "close": f"Close the request to {name}"}.get(kind, f"Next step with {name}")


def _pick(rows: list) -> Any:
    return min(rows, key=lambda r: (KIND_ORDER.index(r.next_action.get("kind")) if r.next_action.get("kind")
                                    in KIND_ORDER else 50, -(r.requested_at.timestamp() if r.requested_at else 0)))


def _clock(r) -> dict | None:
    gone = r.path.lapsed if getattr(r, "path", None) is not None else None
    if gone is not None:  # passed: the most urgent clock there is (the hold may already be released)
        return {"label": "the hold's lapse date" if gone["kind"] == "hold_expired" else
                "the LE request's deadline" if gone.get("side") == "le" else "their deadline on our side",
                "due_at": gone["at"], "action": (gone.get("clock") or {}).get("action"), "source": "lapsed"}
    nd = r.next_deadline
    if nd is not None:
        return {"label": nd.get("label"), "due_at": nd["due_at"], "action": nd.get("action"),
                "source": nd.get("source")}
    # their reply is due: never once they replied with something a person reads or confirms (a hold to confirm, an
    # unclear reply) — a late reply's old due date is no deadline any more
    replied = r.suggestion is not None or (getattr(r, "deciding", None) is not None and r.status not in (
        bs.AWAITING, rules.AUTO_REPLY, rules.ACKNOWLEDGED))
    if r.due_at is not None and not replied and r.status not in bs.RESOLVED and r.status not in bs.OUR_ACTION:
        return {"label": "reply due", "due_at": r.due_at, "action": None, "source": "reply"}
    return None


def _row_move(cid: int, a: desk.Authority, arows: list, stake: Stake, h: er.Holdings, *, pb, requester: str,
              now: datetime, orgs: dict | None = None) -> Move:
    r = _pick(arows)
    na = dict(r.next_action or {})
    own, oref = [], r.key
    for x in sorted(arows, key=lambda x: x.requested_at.timestamp() if x.requested_at else 0):
        mine = [d for d in pathmod.destinations(x, orgs) if d["where"] == "own"]
        own += mine
        oref = x.key if mine else oref  # the answer letter answers the reply naming them, never a newer request awaiting
    ended = r.path is not None and r.path.step == "outcome" and r.path.outcome == "declined_terminal"
    if own and (na.get("kind") == "close" or ended and na.get("kind") in ("le", "answer")):
        # "the reported account is empty" but the funds went to another account / deposit address on its own platform
        # (an internal transfer, another UID's deposit address): still at this provider, which can freeze them. Never
        # a closed request, never "withdrawn to the wallet its reply names"
        many = len(own) + len({u for d in own for u in d["accounts"]}) > 1
        what = (f"the account{'s' if many else ''} / deposit address{'es' if many else ''} its reply names on its own "
                "platform")
        na.update(kind="answer", title=f"Ask {a.name} to freeze {what.replace(' its reply names', '')} now",
                  text=(f"{a.name} says the reported account holds nothing now, but its reply says the funds went to "
                        f"{what} ({', '.join(_short(d['value']) for d in own[:3])}"
                        + (f"; UID {', '.join(dict.fromkeys(u for d in own for u in d['accounts']))}"
                           if any(d["accounts"] for d in own) else "")
                        + f"): they are still at {a.name}. Answer at once{f', quoting their ticket {r.ticket}' if r.ticket else ''}: "
                        f"ask {a.name} to freeze {'them' if many else 'it'} and preserve the records (the answer letter "
                        "quotes it); brief LE in parallel."),
                  href=f"/cases/{cid}/authorities/{a.key}?template=info_response&ref={oref}#generate")
    elif own and na.get("kind") in ("answer", "wait", "le", "confirm", None):
        # the funds moved to another account / deposit address on their own platform: they can hold that one too
        many = len(own) + len({u for d in own for u in d["accounts"]}) > 1
        na["text"] = ((na.get("text") or "") + f" Ask {a.name} to extend the hold to the account{'s' if many else ''}"
                      f" / deposit address{'es' if many else ''} their reply names on its own platform (the answer "
                      f"letter quotes {'them' if many else 'it'}).").strip()
        if na.get("kind") in (None, "wait"):
            na["kind"] = "answer"
            na["href"] = f"/cases/{cid}/authorities/{a.key}?template=info_response&ref={oref}#generate"
    # a follow-up drafted after a request already sent and awaiting its reply (a freeze request after a preservation
    # one): an escalation of that request, on its clock, never a first contact
    sent = [x for x in arows if x is not r and x.requested_at is not None
            and x.status in (bs.AWAITING, rules.AUTO_REPLY, rules.ACKNOWLEDGED)]
    prev = max(sent, key=lambda x: x.requested_at) if na.get("kind") == "send" and sent else None
    if prev is not None:
        was, new = _req_label(prev), _req_label(r)
        new = f"second {new}" if new == was else new
        due = f", due {prev.due_at:%d %b}" if prev.due_at else ""
        na["title"] = f"Escalate {a.name}: send the drafted {new}"
        na["text"] = (f"{was[:1].upper()}{was[1:]} sent {prev.requested_at:%d %b} (awaiting reply{due}); a {new} is "
                      f"drafted: send it to escalate. " + (na.get("text") or "")).strip()
    kind = na.get("kind") or "wait"
    st = r.path
    route = st.route if st is not None else None
    if kind == "le" and (route or {}).get("kind") == "cross_border" and not (route or {}).get("agent"):
        kind_e = "cross_border"
    else:
        kind_e = kind
    keys = [x["req_key"] for x in r.intel.get("asks") or [] if x.get("req_key")]  # what their reply asks, first
    keys += [e["key"] for e in na.get("evidence") or []]
    if kind == "le" and not keys and st is not None:
        keys = [e["key"] for e in st.evidence]
    tickets = [t["value"] for t in r.intel.get("tickets") or []] or ([r.ticket] if r.ticket else [])
    evidence = er.check(h, keys, addresses=stake.addresses, tickets=tickets,
                        cited=bool(r.order is not None and (r.order.identifiers or {}).get("addresses")),
                        emits=er.emits_for(na.get("href")))
    held = r.status in HELD and r.source in bs.HUMAN_SOURCES
    value = stake.usd
    basis = stake.basis
    if held and stake.secured:
        value, basis = stake.secured, stake.secured_basis or basis
    clock = _clock(r) or (_clock(prev) if prev is not None else None)
    gated = bool(pb is not None and pb.gate(requester, h.held_for(a)).reason)
    lk, lk_why = _likelihood(a, stake, pb, requester, route=route,
                             step=r.path_step or (prev.path_step if prev is not None else None), gated=gated,
                             status=None if own and kind == "answer" else r.status)
    if kind == "confirm":
        lk, lk_why = max(lk, 0.5), "a reply suggests an outcome: a person confirms it" + (f" ({lk_why})" if lk_why else "")
    gone = st.lapsed if st is not None else None
    u, u_why = _urgency(now, stake, name=a.name, clock=clock, overdue=r.overdue or bool(prev and prev.overdue),
                        hold_at=r.hold_expires_at if gone is None else None)
    eff, eff_why = _effort(kind_e, evidence)
    actionable = kind in ACTIONABLE
    title = na.get("title") or _row_title(kind, a.name, route, st)
    if kind == "answer" and clock and clock.get("due_at") and clock.get("source") != "lapsed":
        title = (f"Answer {a.name} by {clock['due_at']:%d %b %H:%M} UTC "
                 f"({'their process' if clock.get('source') == 'playbook' else 'their deadline'})")
    m = Move(key=r.key, kind=kind_e if actionable else kind, title=title, authority=a,
             row=r, text=na.get("text") or "", href=na.get("href"), value=value, basis=basis, urgency=u,
             urgency_why=u_why, likelihood=lk, likelihood_why=lk_why, effort=eff, effort_why=eff_why,
             evidence=evidence, clock=clock, actionable=actionable, step=r.path_step,
             step_label=st.label if st is not None and st.step else None, route=route,
             related=[x.title for x in arows if x is not r], secured=stake.secured, next_action=na)
    if na.get("href"):
        agent = (route or {}).get("agent")
        if kind == "le" and agent is not None and "template=" not in na["href"]:
            # the intake's page (IC3: its reference gets a case agent assigned), else the LE contacts to add one to
            label = (f"Open the {agent['via']} complaint (get a {agent['jur']} case agent assigned)"
                     if agent.get("via_key") and agent.get("via") else f"Add the {agent['jur']} case agent (LE contact)")
        else:
            label = _primary_label(kind, na["href"])
        m.actions.append({"label": label, "href": na["href"], "primary": True,
                          "perm": "draft_letter" if "template=" in na["href"] else "view"})
    answer = f"/cases/{cid}/authorities/{a.key}?template=info_response&ref={oref}#generate"
    if own and kind in ("confirm", "le") and na.get("href") != answer:  # the text asks them to extend the hold
        m.actions.append({"label": "Open the answer letter", "href": answer, "perm": "draft_letter"})
    agent = (route or {}).get("agent")
    if st is not None and st.le is not None and (route or {}).get("case_agent", True) and (
            kind in ("answer", "confirm") or (kind == "le" and agent is not None)):
        slow = " (cross-border, slower)" if agent is not None and kind == "le" else ""
        m.actions.append({"label": f"LE brief to {st.le.name}{slow}", "perm": "draft_letter",
                          "href": f"/cases/{cid}/authorities/{st.le.authority.key}?template=le_brief&ref={r.key}#generate"})
    m.actions.append({"label": "Block status row", "href": f"/cases/{cid}/blocks#{r.key}", "perm": "view"})
    if stake.unread and bs._issuer_of(a) is not None:
        m.actions.append({"label": "Check the balance on-chain", "href": f"/cases/{cid}/freeze", "perm": "view"})
    if st is not None and st.le is not None:
        m.actions.append({"label": "LE brief pack (.zip)", "href": f"/cases/{cid}/recovery-plan/pack/{r.key}.zip",
                          "perm": "pack"})
    counsel = (route or {}).get("counsel")
    if counsel and requester in pathmod.PRIVATE_BY and st is not None and st.step in (
            "le_only_redirect", "provider_ack", "le_route_open", "hold_discretionary"):
        cto = f" ({'/'.join(counsel['to'])})" if counsel.get("to") else ""
        m.actions.append({"label": f"Instruct {counsel['text']}{cto}: counsel brief pack",
                          "href": f"/cases/{cid}/recovery-plan/pack/{r.key}.zip?brief=counsel", "perm": "pack"})
    return m


REQ_LABELS = {"freeze": "freeze request", "preservation": "preservation request", "issuer_blacklist": "blacklist request",
              "info_request": "information request", "stop_order": "freeze request", "status_request": "status request"}


def _req_label(r) -> str:
    """"preservation request" / "freeze request": what a request row's letter is (its stop order's kind, else the
    letter's template)."""
    k = r.order.kind if r.order is not None else ((r.letter.meta or {}).get("template_key") if r.letter is not None
                                                  else None)
    return REQ_LABELS.get(k or "", "request")


def _primary_label(kind: str, href: str) -> str:
    if "template=le_brief" in href:
        return "Open the LE brief"
    if "template=le_cover" in href:
        return "Open the LE cover letter"
    if "template=status_request" in href:
        return "Open the status request"
    if "template=info_response" in href:
        return "Open the answer letter"
    if "template=stop_order" in href:
        return "Open the stop order"
    if "/correspondence/" in href:
        return "Open the letter"
    return {"confirm": "Confirm on Block status", "answer": "Open their reply", "review": "Open their reply",
            "trace": "Open Fund flow"}.get(kind, "Open")


def _untouched_move(cid: int, a: desk.Authority, stake: Stake, h: er.Holdings, *, pb, org_key, requester: str,
                    targets: list, run, now: datetime, victim_jur: str | None = None) -> Move | None:
    if a.non_custodial or ((stake.usd or 0) <= 0 and not stake.moved_on):
        return None  # (wallets that moved everything on keep a $0 move: read them on-chain / re-trace)
    our = pathmod.our_path(pb, requester) if pb is not None else None
    held = h.held_for(a)
    gate = pb.gate(requester, held, name=a.name) if pb is not None else None
    st = pathmod.PathState(path=our, requester=requester, victim_jur=victim_jur)
    st.target = pathmod._target(pb, our, None, {str(c) for c, _ in stake.addresses if c}) if pb is not None else None
    if st.target is not None:
        t = st.target.instrument
        st.instrument = {"type": t.type, "label": pathmod._label(t.type),
                         "issuer_jurisdictions": list(t.issuer_jurisdictions), "source": "playbook"}
    route, le = pathmod._route(pb, st, targets, org_key) if pb is not None else (None, targets[0] if targets else None)
    if route is None and le is not None:
        route = {"kind": None, "le": le.name, "options": []}
    if le is not None and not le.briefable:  # only a complaint intake (IC3) on the case: it files nothing
        le = None
    opts = {o["key"]: o for o in desk.template_options(a, a.candidate_run or run, requester, held)}
    issuer = bs._issuer_of(a) is not None
    exp = set(getattr(our, "expected_replies", ()) or ()) | set(getattr(our, "outcomes", ()) or ())
    handoff = our is not None and rules.LE_PROCESS_REQUIRED in exp and not exp & HELD
    le_href = (f"/cases/{cid}/authorities/{le.authority.key}?template=le_cover#generate" if le is not None else None)
    gated = bool(gate is not None and gate.reason)
    agent = (route or {}).get("agent")
    agent_txt = ""
    if agent is not None:  # a domestic case agent asks directly: the fastest LE route, the cross-border one after
        ref = f", quoting {agent['via']} reference {agent['reference']}" if agent.get("reference") else ""
        agent_txt = (f" Fastest LE route: a {agent['jur']} case agent ({agent['who']}){ref} can ask {a.name} "
                     "directly.")
    if gated:
        kind = "cross_border" if (route or {}).get("kind") == "cross_border" and agent is None else "le"
        title = f"Brief {le.name if le else 'LE'} about {a.name} now (LE requests only)"
        text = (gate.reason + agent_txt + (f" Brief {le.name} with the pack." if le else
                                           " Add the case's LE contact first."))
        href = le_href or f"/cases/{cid}?tab=authorities"
        keys = [*(st.target.evidence if st.target is not None else ())]
    else:
        tpl = "stop_order" if opts.get("stop_order", {}).get("available") else (
            "info_request" if opts.get("info_request", {}).get("available") else None)
        if tpl is None:
            return None
        kind = "request"
        what = "a stop order" if tpl == "stop_order" else "a preservation / information request"
        title = (f"Ask {a.name} to blacklist the wallets now" if issuer and tpl == "stop_order"
                 else f"Send {what} to {a.name} now")
        text = (f"No request to {a.name} yet: generate {what} from the latest trace's identifiers and send it.")
        if handoff:
            tk = " and gets a ticket the officer quotes" if pb is not None and pb.tickets else ""
            text += (f" {a.name} acts on LE process only: the notice flags the wallets{tk}; brief "
                     f"{le.name if le else 'the case officer'} in parallel.")
        text += agent_txt
        if (route or {}).get("kind") == "cross_border" and route.get("text"):
            text += (" Slower: " if agent is not None else " ") + route["text"]
        counsel = (route or {}).get("counsel")
        if counsel and requester in pathmod.PRIVATE_BY and (route or {}).get("kind") == "cross_border":
            text += f" In parallel, counsel can seek {pathmod._label(counsel.get('instrument'))}."
        href = f"/cases/{cid}/authorities/{a.key}?template={tpl}#generate"
        keys = list(getattr(our, "evidence", ()) or ())
    evidence = er.check(h, keys, addresses=stake.addresses, cited=bool(stake.addresses))
    lk, lk_why = _likelihood(a, stake, pb, requester, route=route, step=None, gated=gated)
    u, u_why = _urgency(now, stake, name=a.name, untouched=True)
    eff, eff_why = _effort(kind, evidence)
    m = Move(key=a.key, kind=kind, title=title, authority=a, text=text, href=href, value=stake.usd, basis=stake.basis,
             urgency=u, urgency_why=u_why, likelihood=lk, likelihood_why=lk_why, effort=eff, effort_why=eff_why,
             evidence=evidence, untouched=True, route=route, secured=stake.secured)
    m.actions.append({"label": "Open the LE cover letter" if gated else _primary_label("request", href), "href": href,
                      "primary": True, "perm": "draft_letter"})
    if handoff and le_href and not gated:
        m.actions.append({"label": f"LE cover letter to {le.name}", "href": le_href, "perm": "draft_letter"})
    if stake.unread and issuer:
        m.actions.append({"label": "Check the balance on-chain", "href": f"/cases/{cid}/freeze", "perm": "view"})
    if le is not None:
        m.actions.append({"label": "LE brief pack (.zip)", "href": f"/cases/{cid}/recovery-plan/pack/{a.key}.zip",
                          "perm": "pack"})
    return m


# --------------------------------------------------------------------------- wallets: watch, freeze watch, re-trace
def _alerts(db: Session, case, run) -> dict[tuple[str, str], datetime]:
    """(chain, address) -> the latest unacknowledged movement alert raised after the latest trace run."""
    from app.db.models import Alert, WatchItem

    since = _aware(run.finished_at or run.started_at) if run is not None else None
    out: dict[tuple[str, str], datetime] = {}
    q = select(Alert, WatchItem).join(WatchItem).where(WatchItem.case_id == case.id, Alert.acknowledged.is_(False))
    for al, w in db.execute(q).all():
        at = _aware(al.created_at)
        if at is None or (since is not None and at <= since):
            continue
        k = _key(w.address.chain.value, w.address.address)
        out[k] = max(out.get(k, at), at)
    return out


def _wallet_moves(db: Session, case, run, alerts: dict, now: datetime, owned: set | None = None) -> list[Move]:
    """Re-trace, trace-further and watch moves for unhosted trace wallets (`owned`: wallets an attribution puts at a
    service, which are asked through their owner's move instead)."""
    from app.db.models import Address, AddressType, TraceNode

    if run is None:
        return []
    cid = case.id
    loss = float(case.loss_usd or 0)
    threshold = max(1000.0, loss * 0.01)
    nodes = db.scalars(select(TraceNode).where(TraceNode.run_id == run.id).options(selectinload(TraceNode.address))).all()
    watched = {w.address_id for w in case.watch_items if w.active}
    unwatched, nxt, moved = [], [], []
    for n in nodes:
        a: Address = n.address
        flags = set(n.flags or [])
        k = _key(a.chain.value, a.address)
        if k in alerts:
            moved.append((n, alerts[k]))
        if a.entity_id is not None or flags & {"context_only", "pending_input"} or a.address.endswith("_PENDING") or \
                a.address_type in (AddressType.VICTIM, AddressType.CONTRACT) or float(n.taint_usd or 0) < threshold \
                or k in (owned or ()):
            continue
        if "trace_next" in flags:
            nxt.append(n)
        if (flags & {"dormant", "trace_next"} or n.is_terminal) and a.id not in watched:
            unwatched.append(n)
    out: list[Move] = []
    traced = max((float(n.taint_usd or 0) for n in nodes), default=0.0)
    groups = [("retrace", [n for n, _ in moved], max((t for _, t in moved), default=None)),
              ("trace_next", [n for n in nxt if n not in {x for x, _ in moved}], None)]
    for key, ns, at in groups:
        if not ns:
            continue
        value = min(traced, sum(float(n.taint_usd or 0) for n in ns)) or None
        u, why = _urgency(now, Stake(usd=value, moved_at=at), name="")
        n_ = f"{len(ns)} wallet{'s' if len(ns) != 1 else ''}"
        eff, eff_why = _effort("retrace", [])
        m = Move(key=key, kind="retrace",
                 title=("Re-trace now: the funds moved after the trace" if key == "retrace"
                        else "Trace further: funds sit where the trace stopped"),
                 text=(f"{n_} on the watch list moved funds after trace run #{run.id}: run the trace again to find the "
                       "next service that can freeze them." if key == "retrace" else
                       f"{n_} hold funds with no resolved onward movement (the trace stopped there): run a longer / "
                       "live trace to find where they went."),
                 value=value, basis=(f"up to {money(value)} " + ("moved on" if key == "retrace" else "not traced further")
                                     if value else ""), urgency=u, urgency_why=why,
                 likelihood=0.15 if key == "retrace" else 0.05, effort=eff,
                 likelihood_why=("a re-trace finds the next exchange / issuer to ask" if key == "retrace" else
                                 "a longer trace may reach the next exchange / issuer"), effort_why=eff_why)
        m.actions = [{"label": "Re-run the trace", "post": f"/cases/{cid}/trace", "fields": {"mode": "", "label":
                      "re-trace (recovery plan)"}, "perm": "run_trace", "primary": True},
                     {"label": "Open Fund flow", "href": f"/cases/{cid}?tab=fund_flow", "perm": "view"}]
        m.related = [_short(n.address.address) for n in ns[:MAX_WATCH]]
        m.wallets = [_key(n.address.chain.value, n.address.address) for n in ns[:MAX_WATCH]]
        out.append(m)
    unwatched.sort(key=lambda n: -float(n.taint_usd or 0))
    if unwatched:
        top = unwatched[:MAX_WATCH]
        value = min(traced, sum(float(n.taint_usd or 0) for n in top)) or None
        u, why = _urgency(now, Stake(usd=value), name="")
        m = Move(key="watch", kind="watch", title=f"Watch {len(top)} unhosted wallet{'s' if len(top) != 1 else ''} "
                 "for movement", text="Add them to the watch list: the moment the funds move to a service that can "
                 "freeze them, the alert names it.", value=value,
                 basis=f"{money(value)} in self-custody (no one can freeze it there)", urgency=u, urgency_why=why,
                 likelihood=0.05, likelihood_why="unhosted: only a later deposit at a service can be frozen",
                 effort=0.3, effort_why="one click")
        m.actions = [{"label": "Add to the watch list", "post": f"/cases/{cid}/recovery-plan/watch",
                      "fields": {"address_id": [n.address_id for n in top]}, "perm": "poll_watch", "primary": True}]
        m.related = [_short(n.address.address) for n in top]
        m.wallets = [_key(n.address.chain.value, n.address.address) for n in top]
        out.append(m)
    return out


def _left_moves(db: Session, cid: int, run, wallets: list[dict], now: datetime) -> list[Move]:
    """A wallet whose balance fell between two good on-chain readings after the latest trace (app.freeze funds_left):
    the funds are moving. One move each: re-trace from it now and ask the next custodian or issuer."""
    from app.db.models import TraceNode

    if not any(c.get("funds_left") for w in wallets for c in w.get("checks") or []):
        return []
    since = _aware(run.finished_at or run.started_at) if run is not None else None
    traced = {_key(n.address.chain.value, n.address.address): float(n.taint_usd or 0)
              for n in db.scalars(select(TraceNode).where(TraceNode.run_id == run.id)
                                  .options(selectinload(TraceNode.address)))} if run is not None else {}
    out: list[Move] = []
    for w in wallets:
        k = _key(w["chain"], w["address"])
        for c in w.get("checks") or []:
            x = _drained(c, w, traced.get(k) or 0.0, since)
            if x is None:
                continue
            usd = x["usd"]
            cap = traced.get(k) or 0.0
            if k in traced and cap < 1:
                continue  # the trace put none of the case's funds here: whatever left is not the case's money
            value = min(usd, cap) if usd and k in traced else usd  # at most what the trace put in
            stake = Stake(usd=value, left=[x])
            u, why = _urgency(now, stake, name="")
            m = Move(key=f"left:{w['chain']}:{w['address']}", kind="retrace",
                     title=f"Funds left {x['short']}: re-trace now and ask the next custodian or issuer",
                     text=(f"The {x['symbol']} balance of {x['short']} ({x['chain_label']}) fell from {x['from']} to "
                           f"{x['to']} between {_fmt(x['from_at'])} and {_fmt(x['at'])} (two good on-chain readings): "
                           "the funds are moving. Re-run the trace from it to find where they went, then ask the next "
                           "custodian (the exchange it reaches) or the issuer to freeze them before they move again."),
                     value=value, basis=(f"up to {money(value)} left {x['short']}" + (" (capped at what the trace put "
                                                                                       "in)" if cap and usd and usd > cap
                                                                                       else "") if value else ""),
                     urgency=u, urgency_why=why, likelihood=0.2,
                     likelihood_why="a re-trace finds the next exchange / issuer to ask", effort=EFFORT["retrace"],
                     effort_why="one re-run, then one letter")
            m.actions = [{"label": "Re-run the trace", "post": f"/cases/{cid}/trace", "fields": {"mode": "", "label":
                          "re-trace (funds left a wallet)"}, "perm": "run_trace", "primary": True},
                         {"label": "Open Fund flow", "href": f"/cases/{cid}?tab=fund_flow", "perm": "view"},
                         {"label": "On-chain freeze readings", "href": f"/cases/{cid}/freeze", "perm": "view"}]
            m.wallets = [k]
            out.append(m)
            break
    return out


def _left_for(r) -> bool:
    """The provider says the funds left (withdrawn / sent out to a wallet its reply names): that wallet is the lead."""
    st = r.path
    return r.status == rules.DECLINED_NO_ASSETS and bool(pathmod._moved_to(r)) or (
        st is not None and (st.outcome == "funds_moved" or st.suggests == "outcome:funds_moved"))


def _catalogue_playbook(key: str | None):
    from app.domain import directory

    try:
        org = directory.load_catalogue().by_key.get(key) if key else None
    except Exception:  # noqa: BLE001 - an invalid catalogue: no gate
        return None
    return org.playbook if org is not None else None


def _note_href(base: str, note: str) -> str:
    """`base` (an authority page with ?template=…) with its letter's extra paragraph prefilled (routes_authorities)."""
    from urllib.parse import quote

    path, _, frag = base.partition("#")
    return f"{path}{'&' if '?' in path else '?'}note={quote(note, safe='')}" + (f"#{frag}" if frag else "")


def _freeze_watch_moves(cid: int, rows: list, fwatched: set, covered: set, now: datetime, *,
                        stakes: dict | None = None, issuers: dict | None = None, le_pick=None,
                        orgs: dict | None = None, by_org: dict | None = None, requester: str = "pi",
                        owners: dict | None = None, h: er.Holdings | None = None) -> list[Move]:
    """Moves for the new wallets replies name (app.blocks.path.destinations): a deposit address at another service
    → ask that service to freeze it (a freeze request naming it); an address the trace already puts at a provider of
    the case (`owners`: address key → its authority) → tell that provider the funds just arrived, on the request
    already open; an external wallet → watch it for a USDT / USDC balance (one click) and, once the funds just left
    there, ask the issuer to blacklist it. A UID / address at the replying provider itself is asked of that provider
    in its own answer (`_row_move`). Every letter opens with the wallet prefilled. Every lead is built first, then at
    most MAX_WATCH leads are kept: deposit addresses at a service (a freeze request) first, best score first, then the
    external wallets (a wallet's watch + issuer moves count as one lead), best score first."""
    dests: list[list[Move]] = []
    wallets: list[list[Move]] = []
    seen: set[str] = set()
    for r in rows:
        left = _left_for(r)
        name = r.authority.name
        stake = (stakes or {}).get(r.authority.key)
        upto = stake.usd if left and stake is not None and stake.usd else None
        for d in pathmod.destinations(r, orgs):
            v = d["value"]
            k = v if v.startswith("T") else v.lower()
            owner = (owners or {}).get(k) if k in covered else None
            if owner is not None and owner.key == r.authority.key:
                continue  # an address of the replying provider's own request
            if d["where"] == "own" or (k in covered and owner is None) or k in seen or \
                    d.get("chain") not in ("tron", "evm"):
                continue
            seen.add(k)
            chain = "tron" if d["chain"] == "tron" else "ethereum"
            short = _short(v)
            src = f"named in reply c{d.get('reply_id')}"
            fmoved = [f"funds moved: {name} names {short} as where they went"] if left else [
                "a new wallet named in their reply"]
            if owner is not None or d["where"] == "other":
                m = _dest_move(cid, r, d, chain, short, name=name, upto=upto, left=left, fmoved=fmoved, owner=owner,
                               rows=rows, le_pick=le_pick, by_org=by_org, requester=requester, h=h)
                dests.append([m])
                continue
            if k in fwatched:  # on the freeze watch already: its reading counts in the issuer's own move
                continue
            # an external wallet: read its USDT / USDC balance first (one click), then the issuer
            m = Move(key=f"fwatch:{chain}:{v}", kind="watch", row=r, authority=r.authority,
                     title=(f"The funds left {name} for {short}: check it for a USDT / USDC balance now" if left
                            else f"Check {short} for an issuer freeze"),
                     text=(f"{name}'s reply names {short}, not in the trace: add it to the freeze watch so Aegis reads "
                           "its USDT / USDC balance and blacklist status."
                           + (" The funds just left for it: once it shows a balance, ask the issuer to blacklist it "
                              "(the issuer request below)." if left else "")),
                     basis=f"named in a reply (balance unknown){f'; up to {money(upto)} left {name}' if upto else ''}",
                     urgency=min(MAX_URGENCY, 1.5 * 2.5) if left else 1.5, urgency_why=fmoved, likelihood=0.3,
                     likelihood_why="an issuer can blacklist it if it holds USDT / USDC", effort=0.3,
                     effort_why="one click", sensitive=True)
            m.actions = [{"label": "Watch for a freeze", "post": f"/cases/{cid}/freeze/watch", "primary": True,
                          "fields": {"chain": chain, "address": v, "source_note": src,
                                     "next": f"/cases/{cid}/recovery-plan"}, "perm": "edit"}]
            group = [m]
            wallets.append(group)
            if left:  # the issuer letter, ranked on its own: the balance there is not read yet
                note = (f"The funds were moved on to {v} ({chain.title()}), named by {name} as where they went. "
                        "Please blacklist the address if it holds your token, and preserve its records.")
                le_note = (f"{name} named {v} ({chain.title()}) as where the funds went. We ask you to request the "
                           f"issuer ({'Tether' if chain == 'tron' else 'Tether / Circle'}) to blacklist it if it holds "
                           "their token, and to preserve its records.")
                lm = Move(key=f"issuer:{chain}:{v}", kind="request", row=r, authority=r.authority,
                          title=f"Ask the issuer to blacklist {short} (the funds left {name} for it)",
                          text=(f"{name}'s reply says the funds left for {short}, not in the trace. Ask "
                                + ("Tether (USDT on TRON)" if chain == "tron" else "Tether / Circle")
                                + " to blacklist it (the address is prefilled) and brief LE with it"
                                + (" (on TRON: the T3 FCU form, through the officer)" if chain == "tron" else "")
                                + ". Check its balance first: the issuer acts only on what it still holds."),
                          value=upto, basis=(f"up to {money(upto)} moved here from {name} (balance not read on-chain;"
                                             " upper bound)" if upto else "balance unknown"),
                          urgency=3.0, urgency_why=fmoved, likelihood=0.1,
                          likelihood_why="issuer blacklist (balance not read: the funds may have moved on)",
                          effort=EFFORT["request"], effort_why="one letter, the address prefilled", sensitive=True)
                first = next((x for x in ((issuers or {}).get(k) for k in ("Tether", "Circle")) if x), None)
                le_href, le_hint = le_pick(*bs._playbook(first)) if le_pick and first is not None else (
                    le_pick(None, None) if le_pick else (None, ""))
                for key in (("Tether",) if chain == "tron" else ("Tether", "Circle")):
                    a = (issuers or {}).get(key)
                    if a is not None:
                        lm.actions.append({"label": f"Ask {a.name} to blacklist it", "perm": "draft_letter",
                                           "primary": not lm.actions,
                                           "href": _note_href(f"/cases/{cid}/authorities/{a.key}?template=info_request"
                                                              f"&about={chain}:{v}#generate", note)})
                if le_href:
                    lm.text += le_hint
                    lm.actions.append({"label": "Brief LE (the address prefilled)", "href": _note_href(le_href, le_note),
                                       "perm": "draft_letter"})
                lm.actions.append({"label": "Re-trace from it", "href": f"/cases/{cid}/trace", "perm": "view"})
                lm.href = next((x.get("href") for x in lm.actions if x.get("primary")), None)
                group.append(lm)
    kept = sorted(dests, key=lambda g: -g[0].score)[:MAX_WATCH]
    kept += sorted(wallets, key=lambda g: -max(x.score for x in g))[:MAX_WATCH - len(kept)]
    return [m for g in kept for m in g]


def _dest_move(cid: int, r, d: dict, chain: str, short: str, *, name: str, upto: float | None, left: bool,
               fmoved: list[str], owner, rows: list, le_pick, by_org: dict | None, requester: str,
               h: er.Holdings | None) -> Move:
    """A deposit address at another service a reply names (`d["org"]`), or one the trace already puts at `owner` (a
    provider of the case): ask that service to freeze the account it credits — a freeze request naming the address,
    or, with a request to it already open, a follow-up on that request naming the new deposit."""
    v = d["value"]
    if owner is not None:
        a, okey, oname = owner, owner.key, owner.name
    else:
        okey, oname = d["org"] if d["org"] else (None, "the exchange their reply names")
        a = (by_org or {}).get(okey) if okey else None
    where = f" at {oname}" if a is not None or okey else " at another exchange"
    issuer = owner is not None and bs._issuer_of(owner) is not None  # a wallet the issuer can blacklist
    what = "a wallet holding its token" if issuer else f"a deposit address{where}"
    ask = "blacklist it" if issuer else "freeze the account it credits"
    note = (f"The funds were moved on to {v} ({chain.title()}), which {name} identified as where they went "
            f"({'a wallet in our trace' if issuer else what.removeprefix('a ')}). Please {ask} at once and preserve "
            "its records" + ("." if issuer else " (KYC, deposit and withdrawal history, IP logs)."))
    le_note = (f"{name} identified {v} ({chain.title()}) as where the funds were moved ({what.removeprefix('a ')}). "
               f"We ask you to request {oname if a is not None or okey else 'that exchange'} to {ask} and to preserve "
               "its records.")
    pb = bs._playbook(a)[0] if a is not None else _catalogue_playbook(okey)
    # the LE the destination's own playbook routes to (the one that can ask it directly, reachable first)
    le_href, le_hint = le_pick(pb, okey or (bs._playbook(a)[1] if a is not None else None)) if le_pick else (None, "")
    held = h.held_for(a) if h is not None and a is not None else frozenset()
    gate = pb.gate(requester, held, name=oname).reason if pb is not None else None
    our = pathmod.our_path(pb, requester) if pb is not None and not gate else None
    exp = set(getattr(our, "expected_replies", ()) or ()) | set(getattr(our, "outcomes", ()) or ())
    # it never holds on a private letter (Binance: LE process only): the officer's request is the move, the letter
    # only flags the deposit
    handoff = our is not None and rules.LE_PROCESS_REQUIRED in exp and not exp & HELD and bool(le_href)
    # a request to it already open (the trace puts the address there, or the exchange is on the case): a follow-up
    # on that request naming the new deposit (it knows the case)
    open_ = [x for x in rows if a is not None and x.authority.key == a.key and x.requested_at is not None
             and x.kind not in ("onchain", "outlook")]
    if owner is not None:
        title = f"Tell {oname} the funds just arrived at {short}: {name} moved them there"
        text = (f"{name}'s reply says the funds went to {short}, an address the trace already puts at {oname}. "
                + (f"{gate} " if gate else
                   f"{oname} acts on LE process only: brief LE with the address now (the officer's request freezes "
                   f"it; a letter to {oname} only flags the deposit), " if handoff else
                   (f"Send {oname} an urgent freeze request for the new deposit, quoting the request already open "
                    f"(the address is prefilled): ask it to {ask} now, " if open_ else
                    f"Send {oname} a freeze request naming it (the address is prefilled) and "))
                + ("" if handoff else "brief LE with the address, ")
                + "so the account behind it is held before it is withdrawn again.")
        urgency_why = [f"funds just arrived from {name} (their reply)", *fmoved]
    else:
        title = (f"Ask {oname} to freeze {short} now: the funds left {name} for it" if okey and not handoff else
                 f"Brief LE to have {oname} freeze {short} now: the funds left {name} for it" if okey else
                 f"Find the exchange behind {short}: the funds left {name} for it")
        ask_it = (f"Send {oname} an urgent freeze request for the new deposit, quoting the request already open "
                  "(the address is prefilled), and " if open_ else
                  f"Send {oname} a freeze request naming it (the address is prefilled) and ")
        text = (f"{name}'s reply says the funds went to {short}, a deposit address at {oname}. "
                + (f"{gate} " if gate else
                   f"{oname} acts on LE process only: brief LE with the address now (the officer's request freezes "
                   f"it; a letter to {oname} only flags the deposit), " if handoff else ask_it)
                + ("" if handoff else "brief LE with the address, ")
                + "so the account behind it is held before it is withdrawn again.")
        urgency_why = fmoved
    if le_href:
        text += le_hint
    lead_le = bool(gate) or handoff
    m = Move(key=f"dest:{chain}:{v}", kind="le" if lead_le else "request", authority=a, row=r, title=title, text=text,
             value=upto, basis=(f"up to {money(upto)} moved here from {name} (their reply; upper bound)"
                                if upto else f"moved here from {name} (named in their reply)"),
             urgency=min(MAX_URGENCY, 1.5 * 2.5) if left else 1.5, urgency_why=urgency_why,
             likelihood=0.3 if lead_le else 0.4,
             likelihood_why="exchange deposit address: the account it credits can be held"
             + ("; acts on LE process only" if handoff else ""),
             effort=EFFORT["le" if lead_le else "request"], effort_why="one letter, the address prefilled", sensitive=True)
    if a is not None and not gate:
        if open_:
            # a freeze request of its own for the new deposit (the address first, the freeze in the subject), quoting
            # the request already open: never a status request about the old identifiers
            last = max(open_, key=lambda x: x.requested_at)
            m.actions.append({"label": f"Write to {a.name} on request {last.key} (the new deposit prefilled)",
                              "primary": not handoff, "perm": "draft_letter",
                              "href": f"/cases/{cid}/authorities/{a.key}?template=info_request&freeze={chain}:{v}"
                                      f"&ref={last.key}#generate"})
            clk = next((d for d in (our.timing.deadlines if our is not None else ()) if d.starts == "sent"
                        and d.what in pathmod.ACTION_WHAT | {"reply_by", "hold_until", "auto_lift"}), None)
            if clk is not None and clk.span:
                m.text += f" {oname}'s clock ({clk.span} from the submission) runs from this new freeze request."
        else:
            m.actions.append({"label": f"Open the freeze request to {a.name}", "primary": not handoff,
                              "perm": "draft_letter",
                              "href": _note_href(f"/cases/{cid}/authorities/{a.key}?template=info_request&freeze="
                                                 f"{chain}:{v}#generate", note)})
    elif a is None:
        m.actions.append({"label": f"Add {oname} as a counterparty" if okey else "Find the exchange (Authorities)",
                          "primary": not handoff, "perm": "view", "href": f"/cases/{cid}?tab=authorities"})
    if le_href:
        m.actions.append({"label": "Brief LE (the address prefilled)", "perm": "draft_letter", "primary": lead_le,
                          "href": _note_href(le_href, le_note)})
        if lead_le:  # one primary: the LE brief leads
            for x in m.actions[:-1]:
                x["primary"] = False
            m.actions.insert(0, m.actions.pop())
    m.actions.append({"label": "Re-trace from it", "href": f"/cases/{cid}/trace", "perm": "view"})
    m.href = next((x.get("href") for x in m.actions if x.get("primary")), None)
    return m


def _lead_le(cid: int, pb, org_key: str | None, targets: list, requester: str,
             victim_jur: str | None) -> tuple[str | None, str]:
    """(the LE cover letter's link, a hint) for a lead a reply names: the LE the lead's own playbook routes to
    (pathmod._route: the one that can ask that provider directly, a reachable one first), else a reachable briefable
    LE, else the first briefable one; the hint names a reachable one when the chosen one has no contact on file."""
    le, route = None, None
    if pb is not None and targets:
        st = pathmod.PathState(path=pathmod.our_path(pb, requester), requester=requester, victim_jur=victim_jur)
        st.target = pathmod._target(pb, st.path, None)
        if st.target is not None:
            t = st.target.instrument
            st.instrument = {"type": t.type, "label": pathmod._label(t.type),
                             "issuer_jurisdictions": list(t.issuer_jurisdictions), "source": "playbook"}
        route, le = pathmod._route(pb, st, targets, org_key)
    brief = [t for t in targets if t.briefable]
    if le is None or not le.briefable:
        le = next((t for t in brief if t.reachable), brief[0] if brief else None)
    if le is None:
        return None, ""
    other = (route or {}).get("reachable") or next((t.name for t in brief if t.reachable and t is not le), None)
    hint = (f" {le.name} has no named officer or e-mail on file: add one, or brief {other} (reachable) instead."
            if not le.reachable and other else "")
    return f"/cases/{cid}/authorities/{le.authority.key}?template=le_cover#generate", hint


# --------------------------------------------------------------------------- wallet owners (app.attribution)
OWNER_MIN_USD = 50.0  # a service wallet holding less does not merit a letter of its own
OWNER_BASE = {"exchange_deposit": 0.5, "casino": 0.4, "exchange_hot_wallet": 0.35, "swap_bridge": 0.1}
OWNER_CONF = {"H": 1.0, "M": 0.8, "L": 0.5}
OWNER_TITLES = {"exchange_deposit": "Ask {o} to freeze the account behind {s} (its deposit address)",
                "casino": "Ask {o} to freeze the account behind {s} (its deposit address)",
                "exchange_hot_wallet": "Ask {o} which account received the funds at {s} (its hot wallet), not the issuer",
                "swap_bridge": "Ask {o} for the order records behind {s} (where the payout went)"}


OWNER_DEPOSITS = frozenset({"exchange_deposit", "casino"})  # an identified deposit a stop order can cite
OWNER_RECORDS = frozenset({"swap_bridge"})  # a swap / order address: its owner letter asks for records only


def uncited_deposit(m: Move) -> bool:
    """An owner move asking a service (a counterparty) to freeze the account behind an identified deposit that no request
    of it cites yet: the stop order the generators draft for that service cites the deposit too (one letter)."""
    return (m.key.startswith("owner:") and (not m.cites or m.cites["state"] == "add") and bool(m.wallets)
            and m.kind in ("request", "send") and any(o.get("kind") in OWNER_DEPOSITS for o in m.owners))


def records_only(m: Move) -> bool:
    """An owner move whose letter asks the service for records only (a swap order: where the payout went), no freeze."""
    kinds = {o.get("kind") for o in m.owners if o.get("kind")}
    return m.key.startswith("owner:") and bool(kinds) and kinds <= OWNER_RECORDS


def uncited_records(m: Move) -> bool:
    """A records-only owner move (`records_only`) that no request of the service cites yet: the stop order the generators
    draft for that service cites its address too and asks for its order records (one letter, the freeze ask first)."""
    return (records_only(m) and (not m.cites or m.cites["state"] == "add") and bool(m.wallets)
            and m.kind in ("request", "send"))


def owner_cites(m: Move) -> list[tuple[str, ...]]:
    """What a stop order to the owner move's service cites for it: (chain, address) of an identified deposit, (chain,
    address, "records") of a swap / order address (its records asked for); [] for neither (services
    .generate_stop_orders' `extra`)."""
    if uncited_deposit(m):
        return list(m.wallets[:1])
    if uncited_records(m):
        return [(c, a, "records") for c, a in m.wallets[:1]]
    return []


def owner_deposits(db: Session, case, authority) -> list[tuple[str, ...]]:
    """The identified deposits (chain, address) the Recovery plan's owner moves attribute to `authority` and no request
    of it cites yet (`uncited_deposit`), and its swap / order addresses ((chain, address, "records"):
    `uncited_records`): what a stop order drafted for it from a page or the assistant cites too
    (app.domain.correspondence.generate_letter), like the tab's generator (freeze_board.owner_addresses). Empty when
    the plan cannot be built (the stop order is drafted from the trace alone)."""
    try:
        plan = build(db, case)
    except Exception as err:  # noqa: BLE001 - no plan: the trace's identifiers only
        log.warning("recovery plan: owner deposits failed for case %s (%s)", case.id, type(err).__name__)
        return []
    out: list[tuple[str, str]] = []
    for m in plan.owner_moves():
        if m.authority is not None and m.authority.key == authority.key:
            out.extend(owner_cites(m))
    return out


def _owner_threshold(case) -> float:
    return max(1000.0, float(case.loss_usd or 0) * 0.01)


def outside_aegis(owner: str) -> str:
    """What to do about a service that is no counterparty of the case (Aegis has no form that adds one by name)."""
    return (f"{owner} is not a counterparty of the case yet, and Aegis cannot add one by name: write to {owner} outside "
            "Aegis (the deposit address and the evidence are under “Who owns it”).")


def _owner_moves(case, owners: dict, owner_of: dict, by_key: dict, now: datetime,
                 rows: dict | None = None, gate=None) -> list[Move]:
    """A wallet an attribution puts at a service (an exchange deposit or hot wallet, a casino, a swap service: a
    public tag, a person, the forwarding pattern) that no move of that service covers yet: ask that service, the
    address prefilled (an LE brief when its playbook takes LE requests only). Its value is in the totals (a move on
    the same funds, an issuer's at the same wallet, is counted once with it: _count). A deposit address whose traced
    funds the trace followed on to a wallet no service owns keeps a move with what stayed credited (often nothing):
    the tag conflicts with the trace, a person checks it. The move's letter passes the request gate
    (app.domain.request_gate, `gate`: its per-provider states): one open request per provider — an open draft is
    sent (the wallet added to it when it does not cite it yet), a request already citing the wallet is waited on (its
    clock; a follow-up or chase is that request's own next step, app.blocks.status), a request sent without it gets
    the follow-up quoting it, an LE-only answer the LE brief. `rows`: block-status key -> its row (the request's
    clock)."""
    from app.domain import request_gate as rg

    out: list[Move] = []
    for k, att in owners.items():
        w = att.wallet
        if not att.service or not att.owner or (max(w.money_usd, att.share_usd) < OWNER_MIN_USD
                                                and not (att.conflict and w.taint_usd >= OWNER_MIN_USD)):
            continue
        value, vbasis = att.share_usd, att.share_basis  # a service float: the case's share, never the whole balance
        holder = owner_of.get(k[1])  # the authority whose move already covers the address
        if holder is not None and (holder.name.casefold() == att.owner.casefold() or att.ask.get("authority") ==
                                   holder.key or (holder.entity is not None and w.entity is not None
                                                  and holder.entity.id == w.entity.id)):
            continue  # that service's own move asks it (the Owner line names the wallet there)
        if w.in_trace and w.taint_usd and w.held_usd is not None:
            value = min(value, w.taint_usd)  # the case's share of a service's float
        value = round(value, 2) if value >= attr.MONEY_MIN_USD else 0.0
        if att.router:
            value = 0.0  # a non-custodial router holds no customer's funds
        counts = bool(value)
        ask = att.ask or {}
        gated = bool(ask.get("gated"))
        title = OWNER_TITLES.get(att.kind, "Ask {o} about {s}").format(o=att.owner, s=w.short)
        if gated:
            title = f"Brief LE to have {att.owner} act on {w.short} ({att.kind_label}): LE requests only"
        a = by_key.get(ask.get("authority")) if ask.get("authority") else None
        u, why = _urgency(now, Stake(usd=value, arrived_at=w.first_in), name=att.owner,
                          untouched=a is None or not (a.correspondence or a.stop_orders))
        lk = round(min(MAX_LIKELIHOOD, OWNER_BASE.get(att.kind, 0.2) * OWNER_CONF.get(att.confidence, 0.5)
                       * (ROUTE_FACTOR[None] if gated else 1.0) * (0.5 if att.conflict else 1.0)
                       * (0.5 if att.shared else 1.0)), 2)
        eff, eff_why = _effort("le" if gated else "request", [])
        src = att.chosen.line if att.chosen is not None else att.badge
        d, alt = rg.gated_link(gate.get(a), ask.get("href")) if gate is not None and a is not None else (None, None)
        if alt is not None and alt["kind"] in ("send", "add", "wait", "le") and d.request is not None:
            r = d.request
            cites = {"state": {"send": "draft", "wait": "sent"}.get(alt["kind"], alt["kind"]), "key": r.key,
                     "no": r.no, "href": alt["href"], "at": r.at if r.sent else None, "text": d.text,
                     "label": alt["label"], "cited": r.cites(w.address), "about": list(d.about),
                     "late": r.late if alt["kind"] == "send" and r.held else None}
            out.append(_cited_move(case, att, a, cites, value=value, vbasis=vbasis, counts=counts, urgency=(u, why),
                                   likelihood=lk, src=src, key=k, row=(rows or {}).get(r.key), now=now))
            continue
        if alt is not None and alt["kind"] == "le":  # the provider's playbook takes LE requests only
            gated = True
            title = f"Brief LE to have {att.owner} act on {w.short} ({att.kind_label}): LE requests only"
            ask = {**ask, "href": alt["href"], "text": alt["text"]}
        elif alt is not None:  # a follow-up quoting the request already out (the link's own template, ref=<it>)
            ask = {**ask, "href": alt["href"]}
        m = Move(key=f"owner:{w.chain}:{w.address}", kind="le" if gated else "request", title=title, authority=a,
                 text=(f"{w.short} ({w.chain}) is {att.owner}'s {att.kind_label}: {src}. {ask.get('text') or ''}."
                       .replace("..", ".")),
                 value=value or None, basis=(f"{money(value)} {vbasis}" if value else vbasis)
                 + (f" ({att.conflict})" if att.conflict and att.conflict not in vbasis else ""), urgency=u,
                 urgency_why=why,
                 likelihood=lk, likelihood_why=f"{att.kind_label} of {att.owner} ({att.confidence} confidence)"
                 + ("; acts on LE process only" if gated else "")
                 + ("; the trace saw the funds go on to a wallet no service owns (lower)" if att.conflict else "")
                 + ("; reached over an asserted link: the amount is not observed (lower)" if att.shared else ""),
                 effort=eff,
                 effort_why=eff_why + (", the address prefilled" if ask.get("href") or gated else
                                       f"; {att.owner} is no counterparty of the case: the letter is written outside "
                                       "Aegis"), wallets=[k], counts=counts)
        if ask.get("href"):
            m.actions.append({"label": ("Open the LE cover letter" if gated else f"Open the letter to {att.owner}"),
                              "href": ask["href"], "primary": True, "perm": "draft_letter"})
        elif not gated and a is None:  # no form adds a counterparty by name: the move says to write outside Aegis
            m.text = f"{m.text} {outside_aegis(att.owner)}".strip()
        m.actions.append({"label": "Who owns it (evidence)", "href": f"/cases/{case.id}/recovery-plan#owners",
                          "perm": "view"})
        m.href = next((x.get("href") for x in m.actions if x.get("primary")), None)
        out.append(m)
    return out


def _cited_move(case, att, a, cites: dict, *, value: float, vbasis: str, counts: bool, urgency: tuple, likelihood: float,
                src: str, key: tuple, row=None, now: datetime | None = None) -> Move:
    """An owner move the request gate points at a request of the service (`cites`, module doc of
    app.domain.request_gate): "draft", send that draft (it cites the wallet, or its e-mail is prepared); "add", add the
    wallet to the open draft, then send it; "sent", a request already cites the wallet: wait on it (the request's
    clock; never a second letter for the same wallet), chase it once its reply is overdue (that request's own next
    step); "le", the service answered LE only / declined: the LE brief (naming the wallet)."""
    w = att.wallet
    u, why = urgency
    basis = (f"{money(value)} {vbasis}" if value else vbasis)
    evidence = {"label": "Who owns it (evidence)", "href": f"/cases/{case.id}/recovery-plan#owners", "perm": "view"}
    common = {"authority": a, "value": value or None, "basis": basis, "urgency": u, "urgency_why": why,
              "likelihood": likelihood, "likelihood_why": f"{att.kind_label} of {att.owner} ({att.confidence} confidence)",
              "wallets": [key], "counts": counts, "row": row}
    who = f"{w.short} ({w.chain}) is {att.owner}'s {att.kind_label}: {src}."
    state = cites["state"]
    if state in ("draft", "add"):
        eff, eff_why = _effort("send", [])
        cited = state == "draft" and bool(cites.get("cited"))
        title = (f"Send the drafted freeze request for {w.short} to {att.owner}" if cited else
                 f"Add {w.short} to draft {cites['no']} to {att.owner}, then send it" if state == "add" else
                 f"Send draft {cites['no']} to {att.owner}")
        if state == "draft" and cites.get("late"):  # its e-mail is held: it was drafted before their reply
            title = f"{title} ({cites['late']}: check it still fits)"
        text = (f"{who} Draft {cites['no']} already asks {att.owner} to freeze the account behind {w.short}: open it, "
                "check it and send it (no second letter for the same deposit)." if cited else f"{who} {cites['text']}")
        m = Move(key=f"owner:{w.chain}:{w.address}", kind="send", title=title, text=text, effort=eff,
                 effort_why=eff_why, **common)
        m.actions = [{"label": cites["label"], "href": cites["href"], "primary": True, "perm": "draft_letter"},
                     evidence]
    elif state == "le":
        eff, eff_why = _effort("le", [])
        m = Move(key=f"owner:{w.chain}:{w.address}", kind="le",
                 title=f"Brief LE to have {att.owner} act on {w.short} ({att.kind_label})",
                 text=f"{who} {cites['text']}", effort=eff, effort_why=eff_why, **common)
        m.actions = [{"label": cites["label"], "href": cites["href"], "primary": True, "perm": "draft_letter"},
                     evidence]
    else:
        at = cites.get("at")
        clock = _clock(row) if row is not None else None
        late = row is not None and (bool(getattr(row, "overdue", False)) or (
            clock is not None and now is not None and clock["due_at"] <= now))
        m = Move(key=f"owner:{w.chain}:{w.address}", kind="wait", actionable=False,
                 title=(f"{'Chase' if late else 'Waiting on'} {att.owner}: the freeze request for {w.short}"
                        + (f" sent {at:%d %b}" if at else "") + (" (reply overdue)" if late else "")),
                 text=(f"{who} Request {cites['no']} asks {att.owner} to freeze the account behind {w.short}"
                       + (f" (sent {at:%d %b %Y})" if at else "")
                       + (": its reply is overdue: chase it (a status request on that request, its own next step)."
                          if late else ": wait for its reply; a follow-up or a chase is that request's own next "
                          "step.")),
                 effort=1.0, clock=clock, **common)
        m.actions = [{"label": f"Open request {cites['no']}", "href": cites["href"], "perm": "view"}, evidence]
    m.href = cites["href"]
    m.cites = cites
    at = cites.get("at")
    m.ask = {"href": cites["href"], "text": (
        f"Send draft {cites['no']} (it asks {att.owner} to freeze the account behind {w.short})"
        if state == "draft" and cites.get("cited") else
        f"Request {cites['no']} asks {att.owner} to freeze the account behind {w.short}"
        + (f" (sent {at:%d %b %Y})" if at else "") + ": wait for its reply" if state == "sent" else
        f"{cites['label']}: {cites['text']}")}
    if not (state == "draft" and cites.get("cited")) and state != "sent":
        m.ask["label"] = cites["label"]  # the owners table's button
    return m


def _unknown_owned(case, owners: dict) -> list:
    """The wallets whose owner is unknown, one definition for the plan's "Identify the owner" move, its KPI tile and
    the Overview's tile: holding at least `_owner_threshold` (the larger of $1,000 and 1% of the loss) and named by no
    source (or a service wallet whose service is unknown), most money first."""
    todo = [a for a in owners.values() if a.wallet.money_usd >= _owner_threshold(case) and not a.owner and (
        a.kind in ("unknown", "exchange_hot_wallet", "exchange_deposit") or
        (a.kind == "unhosted" and a.confidence == "L"))]
    return sorted(todo, key=lambda a: -a.wallet.money_usd)


def unknown_owner(case, owners: dict) -> dict:
    """{usd: the case's share at the wallets whose owner is unknown (`_unknown_owned`), n, threshold_usd}."""
    todo = _unknown_owned(case, owners)
    return {"usd": round(sum(a.share_usd for a in todo), 2), "n": len(todo),
            "threshold_usd": round(_owner_threshold(case), 2)}


def _identify_move(case, owners: dict, lookups: dict, now: datetime) -> Move | None:
    """Wallets holding a large balance whose owner no source names (or a service wallet whose service is unknown):
    identify the owner first (run the public explorer lookups — the case's consent —, mark it, re-trace)."""
    todo = _unknown_owned(case, owners)
    if not todo:
        return None
    top = todo[:MAX_WATCH]
    value = round(sum(a.share_usd for a in top), 2)  # a service float: the case's share only
    n = f"{len(top)} wallet{'s' if len(top) != 1 else ''}"
    u, why = _urgency(now, Stake(usd=value), name="")
    cid = case.id
    ready = lookups.get("enabled") and not lookups.get("consent_outdated") and not lookups.get("deployment_disabled")
    svc = [a for a in top if a.service]
    held = money(value) if value else "a service float"
    m = Move(key="identify", kind="check", title=f"Identify the owner of {n} holding {held}",
             text=(f"No source names who controls {', '.join(a.wallet.short for a in top)}"
                   + (f" ({', '.join(a.wallet.short for a in svc)} behave{'s' if len(svc) == 1 else ''} like a "
                      "service's wallet: its service, not the issuer, is asked)" if svc else "")
                   + ". A public explorer tag or the forwarding pattern often shows an exchange deposit or a service's "
                     "hot wallet, which that service can freeze. "
                   + ("Run the owner lookups (the addresses go to the public explorers the case admin consented to), "
                      if ready else "Owner lookups are off for this case: a case admin can turn them on (the addresses "
                                    "go to public explorers), ")
                   + "mark the owner if you know it, or re-trace."),
             value=value or None, basis=(f"{money(value)} at wallets with no known owner" if value else
                                         "wallets with no known owner (a service's float: the case's share unknown)"),
             urgency=u, urgency_why=why,
             likelihood=0.15, likelihood_why="an identified exchange deposit / service wallet can be frozen there",
             effort=EFFORT["check"], effort_why="one lookup", wallets=[a.key for a in top])
    if ready:
        m.actions.append({"label": "Run the owner lookups now", "post": f"/cases/{cid}/owners/lookup", "primary": True,
                          "fields": {"next": f"/cases/{cid}/recovery-plan"}, "perm": "poll_watch"})
    else:
        m.actions.append({"label": "Turn on owner lookups (case admin)", "href": f"/cases/{cid}/recovery-plan#owner-lookups",
                          "primary": True, "perm": "manage_case"})
    m.actions += [{"label": "Mark the owner", "href": f"/cases/{cid}/recovery-plan#owners", "perm": "edit"},
                  {"label": "Re-run the trace", "post": f"/cases/{cid}/trace", "fields": {"mode": "", "label":
                   "re-trace (identify the owner)"}, "perm": "run_trace"}]
    m.related = [f"{a.wallet.short} ({money(a.wallet.money_usd)}, {a.kind_label})" for a in top]
    m.href = next((x.get("href") for x in m.actions if x.get("primary")), None)
    return m


@dataclass
class _Claim:
    """A piece of a move's value on its wallets, for the totals: `traced` (the case's traced funds), `untraced` (a
    balance read at a wallet the trace never saw); `flow`: an upper bound of what reached the wallets, which includes
    what they sent on (an unread traced wallet, a deposit address, a swap's input), else what is there now (a
    reading, a service's share). `stop`: the wallets the trace saw the funds leave for that this claim's value leaves
    out (a service wallet's onward, app.attribution): a claim below them is not inside this one. `extra`: the part of an
    issuer move's value beyond its per-wallet readings (held by a person / cited); it never excludes the same move's
    own readings (they are both the move's money)."""
    move: Move
    wallets: frozenset
    traced: float
    untraced: float = 0.0
    flow: bool = True
    stop: frozenset = frozenset()
    extra: bool = False


def _claims(m: Move, stakes: dict, atts: dict) -> list[_Claim]:
    ws = frozenset(_move_wallets(m, stakes))
    value = float(m.value or 0)
    st = stakes.get(m.authority.key) if m.authority is not None and ":" not in m.key else None
    if st is not None and st.parts:  # an issuer's stake, wallet by wallet
        whole = sum(p["traced"] + p["untraced"] for p in st.parts)
        f = min(1.0, value / whole) if whole > 0 else 0.0
        out = [_Claim(m, frozenset([p["k"]]), p["traced"] * f, p["untraced"] * f, p["flow"]) for p in st.parts
               if p["traced"] + p["untraced"] >= 0.005]
        if value - whole >= 1:  # held by a person / cited beyond the readings: on the move's wallets
            out.append(_Claim(m, ws, value - whole, extra=True))
        return out
    if m.key.startswith("owner:") and len(ws) == 1:
        att = atts.get(next(iter(ws)))
        if att is None:
            return [_Claim(m, ws, value)]
        w = att.wallet
        # the case's traced funds there: what the trace put in, less what it followed on to wallets not of its
        # service (app.attribution onward); the rest of the value (never traced there) is an untraced find. Unread,
        # it bounds what reached the wallet and stayed with its service: never the funds below its onward wallets
        mine = min(value, att.upper_usd) if w.in_trace else 0.0
        return [_Claim(m, ws, mine, value - mine, w.held_usd is None, stop=frozenset(att.onward or ()))]
    return [_Claim(m, ws, value)]


def _count(moves: list[Move], stakes: dict, atts: dict, *, cap: float, notes: bool = True) -> dict:
    """The totals, each traced dollar once. Two claims are on the same funds ONLY when they are on the same wallet, or
    when one is an upper bound of what reached a wallet the other's descends from in the trace graph (its ancestry:
    the wallets the trace saw the funds come from; a claim that leaves out what its wallet sent on, a service wallet's
    onward, covers nothing below those onward wallets). Nothing else links two claims: two balances read on separate
    branches below one hub are both counted, and the pieces of one move (its readings, the part a person recorded
    beyond them) never exclude each other. The largest claim of a group on the same funds counts, never the sum,
    and every claim no counted claim overlaps is added. The traced part is capped at the traced loss (`cap`); a
    balance read at a wallet the trace never saw is added on top, once per wallet (labelled). `notes`: each move with
    others on its funds says so ("same funds as …")."""
    claims = [c for m in moves for c in _claims(m, stakes, atts)]
    memo: dict = {}

    def anc(k, stop: frozenset = frozenset()) -> frozenset:
        """The wallet and every wallet the trace saw its funds come from, never walking up through `stop`."""
        if (k, stop) not in memo:
            seen, todo = set(), [k] if k not in stop else []
            seen.update(todo)
            while todo:
                a = atts.get(todo.pop())
                for p in a.wallet.sources if a is not None else ():
                    if p not in seen and p not in stop:
                        seen.add(p)
                        todo.append(p)
            memo[(k, stop)] = frozenset(seen)
        return memo[(k, stop)]

    def covers(a: _Claim, b: _Claim) -> bool:  # a bounds what reached a wallet b's funds descend from
        return a.flow and any(a.wallets & anc(k, a.stop) for k in b.wallets)

    def same(i: int, j: int) -> bool:
        a, b = claims[i], claims[j]
        if a.move is b.move and (a.extra or b.extra):
            return False
        return bool(a.wallets & b.wallets or covers(a, b) or covers(b, a))
    picked: list[int] = []
    for i in sorted(range(len(claims)), key=lambda i: -claims[i].traced):
        if claims[i].traced >= 0.005 and not any(same(i, j) for j in picked):
            picked.append(i)
    traced = sum(claims[i].traced for i in picked)
    expected = sum(claims[i].traced * claims[i].move.likelihood for i in picked)
    # each counted claim recovers its value with its move's likelihood (or not): the spread of the outcome
    variance = sum(claims[i].traced ** 2 * claims[i].move.likelihood * (1 - claims[i].move.likelihood) for i in picked)
    finds: dict = {}  # wallet key -> (USD, expected) read at wallets the trace never saw
    for c in claims:
        if c.untraced >= 1:
            k = min(c.wallets) if c.wallets else c.move.key
            usd, ex = finds.get(k, (0.0, 0.0))
            finds[k] = (max(usd, c.untraced), max(ex, c.untraced * c.move.likelihood))
    untraced = sum(v for v, _ in finds.values())
    variance += sum(v * (e / v) * (1 - e / v) * v for v, e in finds.values() if v)
    base = min(traced, cap) if cap else traced
    if notes:
        near: dict[int, list[Move]] = {}  # move id -> the other moves on its funds
        for i in range(len(claims)):
            for j in range(i + 1, len(claims)):
                a, b = claims[i].move, claims[j].move
                if a is not b and same(i, j):  # traced or untraced claims alike
                    near.setdefault(id(a), []).append(b)
                    near.setdefault(id(b), []).append(a)
        for m in moves:
            names = list(dict.fromkeys(o.authority.name if o.authority is not None else o.title[:40]
                                       for o in near.get(id(m), [])))
            if names and m.value:
                m.basis += f" (same funds as {', '.join(names[:3])}{' …' if len(names) > 3 else ''}: counted once)"
    return {"traced": round(traced, 2), "untraced": round(untraced, 2), "capped": bool(cap and traced > cap),
            "in_play": round(base + untraced, 2), "variance": variance,
            "expected": round(min(base + untraced, min(expected, base) + sum(e for _, e in finds.values())), 2),
            "finds": [k for k in finds if isinstance(k, tuple)],
            # for checks: every claim, the counted ones, and for each other claim of a dollar or more the counted
            # claim on its funds (at least as large) that holds it
            "ledger": {"claims": claims, "picked": picked,
                       "cover": {i: next((j for j in picked if same(i, j)), None) for i in range(len(claims))
                                 if i not in picked and claims[i].traced >= 1},
                       "sources": {k: frozenset(a.wallet.sources) for k, a in atts.items()}}}


def _projection(case, t: dict, plan) -> dict:
    """The case's projected loss and how certain it is (Overview, Status summary, Recovery plan):
    projected recovery = secured (frozen on-chain / a hold a person confirmed) + the expected recovery of the open
    moves (each traced dollar once, at its move's likelihood); projected loss = loss - projected recovery.
    Certainty = 1 - (one standard deviation of the open moves' outcome / loss): 100 % when every dollar's outcome is
    settled (secured, or nothing left in play), lower the more still depends on open requests. The range is the
    projected loss +/- that standard deviation, within [0, loss]."""
    import math

    loss = float(getattr(case, "loss_usd", None) or 0)
    secured = round(sum(s["usd"] for s in plan.secured), 2)
    expected = float(t.get("expected") or 0)
    sigma = math.sqrt(max(0.0, float(t.get("variance") or 0)))
    if loss <= 0:
        return {"projected_loss_usd": None, "projected_recovery_usd": round(secured + expected, 2),
                "projection_certainty_pct": None, "projected_loss_low_usd": None, "projected_loss_high_usd": None}
    recovery = min(loss, secured + expected)
    projected = max(0.0, loss - recovery)
    return {"projected_loss_usd": round(projected, 2), "projected_recovery_usd": round(recovery, 2),
            "projected_recovery_pct": round(100 * recovery / loss, 1),
            "projection_certainty_pct": round(max(0.0, min(100.0, 100 * (1 - sigma / loss))), 1),
            "projected_loss_low_usd": round(max(0.0, projected - sigma), 2),
            "projected_loss_high_usd": round(min(loss, projected + sigma), 2)}


def _traced_loss(case, run) -> float:
    """What the trace put at stake (its first hop's funds), else the loss the case reports; the smaller of both."""
    traced = float(sum((n.taint_usd or 0) for n in run.nodes if n.hop == 0)) if run is not None else 0.0
    vals = [v for v in (traced, float(case.loss_usd or 0)) if v > 0]
    return min(vals) if vals else 0.0


def _move_wallets(m: Move, stakes: dict) -> list[tuple[str, str]]:
    if m.wallets:
        return m.wallets
    if m.key.startswith(("dest:", "fwatch:", "issuer:")):
        _, chain, addr = m.key.split(":", 2)
        return [_key(chain, addr)]
    st = stakes.get(m.authority.key) if m.authority is not None and ":" not in m.key else None
    return [_key(c, x) for c, x in st.addresses] if st is not None else []


def _owner_line(att) -> dict:
    return {"short": att.wallet.short, "owner": att.owner_label, "kind": att.kind, "kind_label": att.kind_label,
            "confidence": att.confidence, "source": att.source, "known": bool(att.owner),
            "text": f"{att.wallet.short}: {att.owner_label} · {att.kind_label} · {att.confidence}",
            "private": sorted(att.private_names)}


# --------------------------------------------------------------------------- the plan
CUSTODIANS = frozenset({"exchange", "casino", "otc", "swap_service"})
FREEZABLE = frozenset({"exchange", "casino", "otc"})  # an account the service itself can freeze (the Overview's tile)


def _custodians(auths: list) -> tuple[dict[str, tuple[str, str]], dict[str, Any]]:
    """({lower-case name / alias: (catalogue key, name)} of the catalogue's custodial services, {catalogue key: the
    case's authority for it}): where a reply's "deposit address at <service>" points."""
    from app.domain import directory

    try:
        cat = directory.load_catalogue()
    except Exception:  # noqa: BLE001 - an invalid catalogue: no named service
        return {}, {}
    orgs = {n.casefold(): (o.key, o.name) for o in cat.orgs if o.category in CUSTODIANS
            for n in {o.name, *o.names} if n and len(n) >= 3}
    by_org: dict[str, Any] = {}
    for a in auths:
        if a.is_le or a.is_adviser:
            continue
        try:
            o = directory.org_for(a, cat)
        except Exception:  # noqa: BLE001
            o = None
        if o is not None:
            by_org.setdefault(o.key, a)
    return orgs, by_org


def ask_context(db: Session, case, *, run=None, cands: list | None = None, auths: list | None = None) -> dict:
    """{auths, requester, targets, le_pick}: who the plan (and app.attribution's asks, on every page) can write to,
    the requester kind and the LE an LE-only route is briefed through."""
    from app import services
    from app.domain import directory
    from app.domain import sender as sender_mod
    from app.tracing.freeze import freeze_candidates

    if auths is None:
        run = run if run is not None else services.latest_run(db, case)
        cands = cands if cands is not None else (freeze_candidates(db, run) if run is not None else [])
        auths = desk.case_authorities(db, case, run=run, cands=cands)
    requester = sender_mod.requester_kind(db, case)
    targets = pathmod.le_targets([a for a in auths if a.is_le], directory.playbook_for)
    victim_jur = pbm.jurisdiction_code(case.victim_jurisdiction)

    def le_pick(pb, okey) -> tuple[str | None, str]:
        return _lead_le(case.id, pb, okey, targets, requester, victim_jur)
    return {"auths": auths, "requester": requester, "targets": targets, "le_pick": le_pick}


def build(db: Session, case, *, now: datetime | None = None, rows: list | None = None,
          keep: Callable[[list], list] | None = None, gate_rows: list | None = None, steps: bool = True) -> Plan:
    """The plan (module doc). `rows`: the case's block rows when the caller already has them (bs.case_blocks: the
    Overview's two cards share one pass); `keep`: a filter over them (the pack route leaves out the freeze board's
    duplicate drafts); `gate_rows`: every block row, for the request gate (app.domain.request_gate: the freeze board
    builds its plan without the untouched targets' drafts, but their drafts are open requests all the same).
    Every action's letter to a provider passes the gate (`_gate_actions`). `steps`: each provider's move takes its
    step from the freeze board's row for it (`_provider_steps`); False only for the board's own plan (the board derives
    those rows itself, from this plan's moves)."""
    from app import services
    from app.domain import request_gate as rg
    from app.freeze import service as fz
    from app.tracing.freeze import freeze_candidates

    now = now or _now()
    run = services.latest_run(db, case)
    cands = freeze_candidates(db, run) if run is not None else []
    auths = desk.case_authorities(db, case, run=run, cands=cands)
    rows = rows if rows is not None else bs.case_blocks(db, case, now=now, authorities=auths)
    if keep is not None:
        rows = keep(rows)
    try:
        wallets = fz.wallet_rows(db, case)
    except Exception as err:  # noqa: BLE001 - no readings: values fall back to the trace
        log.warning("recovery plan: freeze readings failed for case %s (%s)", case.id, type(err).__name__)
        wallets = []
    ctx = ask_context(db, case, auths=auths)
    requester, targets, le_pick = ctx["requester"], ctx["targets"], ctx["le_pick"]
    h = er.holdings(db, case, run=run, wallets=wallets)
    alerts = _alerts(db, case, run)
    since = _aware(run.finished_at or run.started_at) if run is not None else None
    try:
        atts = attr.attribute(db, case, run=run, freeze_rows=wallets, auths=auths, requester=requester,
                              le_pick=le_pick)
    except Exception as err:  # noqa: BLE001 - no attribution: the plan as before
        log.warning("recovery plan: wallet owners failed for case %s (%s)", case.id, type(err).__name__)
        atts = {}
    for w in wallets:
        w["attribution"] = atts.get(attr.key_of(w["chain"], w["address"]))
    plan = Plan(case_id=case.id, requester=requester, generated_at=now,
                run=({"id": run.id, "label": run.label, "at": _aware(run.finished_at or run.started_at)}
                     if run is not None else None))
    plan.owners, plan.owner_lookups = atts, attr.status(case)
    plan.gate = rg.states_for(db, case, gate_rows if gate_rows is not None else rows, auths, requester=requester)
    orgs, by_org = _custodians(auths)
    by_auth: dict[str, list] = {}
    for r in rows:
        by_auth.setdefault(r.authority.key, []).append(r)
    seen: set[str] = set()
    covered: set[str] = set()
    owners: dict[str, Any] = {}  # address key -> the authority whose stake holds it
    extra = [r.authority for r in rows if r.kind == "onchain" and r.authority.key not in {a.key for a in auths}]
    cand_by_ent = {c.entity.id: c for c in cands if c.entity is not None}
    stakes: dict[str, Stake] = {}
    # the move the freeze board's own plan holds for a provider (its input to freeze_board.provider_target): that plan
    # leaves out the duplicate drafts and treats a provider with drafts only as untouched (`_board_move`)
    board_moves: dict[str, Move | None] = {}
    outlook = {r.authority.key for r in rows if r.kind == "outlook"}
    for a in [*auths, *extra]:
        if a.is_le or a.is_adviser or a.key in seen or a.virtual:
            continue
        seen.add(a.key)
        if a.candidate is None and a.entity is not None and a.entity.id in cand_by_ent:
            a.candidate = cand_by_ent[a.entity.id]
        reqs = [r for r in by_auth.get(a.key, []) if r.kind not in ("onchain", "outlook")]
        stake = stakes[a.key] = _stake(a, reqs, wallets, alerts, now, since=since, atts=atts)
        for c, x in stake.addresses:
            k = addr_key(c, x)
            covered.add(k)
            owners.setdefault(k, a)
        pb, org_key = bs._playbook(a)
        if stake.secured:
            plan.secured.append({"authority": a.name, "key": a.key, "usd": round(stake.secured, 2),
                                 "text": stake.secured_basis})
        if reqs and steps:
            bm = _board_move(case.id, a, reqs, stake, h, pb=pb, org_key=org_key, requester=requester,
                             targets=targets, run=run, now=now, orgs=orgs, outlook=a.key in outlook,
                             victim_jur=pbm.jurisdiction_code(case.victim_jurisdiction))
            if bm is not ...:
                board_moves[a.key] = bm
        if reqs:
            m = _row_move(case.id, a, reqs, stake, h, pb=pb, requester=requester, now=now, orgs=orgs)
            if m.kind == "close" or (m.row is not None and m.row.path is not None and m.row.path.step == "outcome"
                                     and m.kind not in ACTIONABLE):
                went = [d["value"] for x in reqs for d in pathmod.destinations(x, orgs) if d["where"] != "own"]
                text = (f"{a.name} holds nothing now: the funds moved to {', '.join(_short(v) for v in went[:3])} "
                        "(see the lead); close the request." if went and m.kind == "close" else m.text)
                plan.done.append({"authority": a.name, "key": m.key, "text": text})
                continue
        else:
            m = _untouched_move(case.id, a, stake, h, pb=pb, org_key=org_key, requester=requester, targets=targets,
                                run=run, now=now, victim_jur=pbm.jurisdiction_code(case.victim_jurisdiction))
            if m is None:
                continue
        (plan.moves if m.actionable else plan.waiting).append(m)
    fwatched = {addr_key(w.chain, w.address) for w in fz.watched(db, case)}
    issuers = {bs._issuer_of(a): a for a in auths if bs._issuer_of(a)}
    leads = _freeze_watch_moves(case.id, rows, fwatched, covered, now, stakes=stakes, issuers=issuers,
                                le_pick=le_pick, orgs=orgs, by_org=by_org, requester=requester, owners=owners, h=h)
    by_key = {m.authority.key: m for m in plan.moves + plan.waiting if m.authority is not None and ":" not in m.key}
    for lead in leads:  # the funds just arrived at a provider of the case (a reply says so): its own move is hotter
        tgt = by_key.get(lead.authority.key) if lead.key.startswith("dest:") and lead.authority is not None else None
        why = next((w for w in lead.urgency_why if w.startswith("funds just arrived")), None)
        if tgt is not None and why and why not in tgt.urgency_why:
            tgt.urgency = round(min(MAX_URGENCY, tgt.urgency * 1.6), 2)
            tgt.urgency_why.insert(0, why)
    plan.moves += leads
    owned = {k for k, x in atts.items() if x.service and x.owner}
    plan.moves += _wallet_moves(db, case, run, alerts, now, owned)
    plan.moves += _left_moves(db, case.id, run, wallets, now)
    _gate_actions(plan, [*plan.moves, *plan.waiting], {a.key: a for a in auths})
    if steps:
        _gate_actions(plan, [m for m in board_moves.values() if m is not None], {a.key: a for a in auths})
        _provider_steps(plan, db, case, run=run, rows=gate_rows if gate_rows is not None else rows, auths=auths,
                        wallets=wallets, now=now, board_moves=board_moves)
    for m in _owner_moves(case, atts, owners, {a.key: a for a in auths}, now, rows={r.key: r for r in rows},
                          gate=plan.gate):
        (plan.moves if m.actionable else plan.waiting).append(m)
    plan.asks = _gate_asks(plan, atts, {a.key: a for a in auths})
    ident = _identify_move(case, atts, plan.owner_lookups, now)
    if ident is not None:
        plan.moves.append(ident)
        further = next((m for m in plan.moves if m.key == "trace_next"), None)
        if further is not None and further.wallets and set(further.wallets) <= set(ident.wallets):
            further.basis += " (the same wallets as “Identify the owner”: one re-run serves both)"
    plan.stakes = stakes
    for m in plan.moves + plan.waiting:  # the "Owner" line of every move
        m.owners = [_owner_line(atts[k]) for k in _move_wallets(m, stakes)[:4] if k in atts]
        st = stakes.get(m.authority.key) if m.authority is not None and ":" not in m.key else None
        m.moved_on = list(st.moved_on) if st is not None else []
    plan.moves.sort(key=lambda m: (-m.score, m.clock["due_at"] if m.clock else now + timedelta(days=3650), m.key))
    plan.waiting.sort(key=lambda m: (m.clock["due_at"] if m.clock else now + timedelta(days=3650), -m.score))
    # a wallet a reply names counts once, in its provider's move (its own moves are leads, not more money)
    targets_usd = [m for m in plan.moves + plan.waiting if m.value and (m.counts or (m.authority is not None
                                                                                    and ":" not in m.key))]
    loss = _traced_loss(case, run)
    t = _count(targets_usd, stakes, atts, cap=loss)
    fresh = _count([m for m in targets_usd if m.untouched], stakes, atts, cap=loss, notes=False)
    # the Overview's tiles, each the plan's own figure (each traced dollar once): the issuers' blacklist lever and the
    # accounts at freezable services (exchanges, casinos, OTC desks: the freeze candidates of kind "freeze", as the
    # assistant's funds position counts them; a swap service's records and the issuers are in play on top)
    issuer_moves = [m for m in targets_usd if m.authority is not None and bs._issuer_of(m.authority) is not None]
    issuers = _count(issuer_moves, stakes, atts, cap=loss, notes=False)
    freezable = _count([m for m in targets_usd if m.authority is not None and m.authority.category in FREEZABLE],
                       stakes, atts, cap=loss, notes=False)
    moved_on = [{"name": a.name, "wallets": list(stakes[a.key].moved_on)} for a in {x.key: x for x in auths}.values()
                if bs._issuer_of(a) is not None and a.key in stakes and stakes[a.key].moved_on and not stakes[a.key].usd]
    replies_overdue = sum(1 for r in rows if r.overdue and r.kind not in ("onchain", "outlook"))
    plan.totals = {
        "in_play_usd": t["in_play"], "in_play_capped": t["capped"], "in_play_sum_usd": round(t["traced"] + t["untraced"], 2),
        "traced_usd": t["traced"], "untraced_usd": t["untraced"], "traced_loss_usd": round(loss, 2),
        "expected_usd": t["expected"],
        "secured_usd": round(sum(s["usd"] for s in plan.secured), 2),
        **_projection(case, t, plan),
        "untouched_usd": round(min(t["in_play"], fresh["in_play"]), 2),
        "untouched": sum(1 for m in plan.moves if m.untouched),
        "moves": len(plan.moves), "waiting": len(plan.waiting),
        "next_clock": min((m.clock for m in plan.moves + plan.waiting if m.clock and m.clock["due_at"] > now),
                          key=lambda c: c["due_at"], default=None),
        # the clocks that ran out: replies overdue, counted as Block status counts them (its "overdue" tile)
        "replies_overdue": replies_overdue,
        "issuer_usd": issuers["in_play"], "issuer_moved_on": moved_on, "freezable_usd": freezable["in_play"],
        "unknown_owner": unknown_owner(case, atts),
    }
    plan.ledger = t["ledger"]
    _merge_cited(plan)
    plan.totals["moves"], plan.totals["waiting"] = len(plan.moves), len(plan.waiting)
    plan.notes += _standing_notes(case, targets, now)
    if t["capped"]:
        plan.notes.append(f"The moves' traced values come to {money(t['traced'])} (each traced dollar once), more than "
                          f"the {money(loss)} traced: upper bounds along one path. In play is capped at the traced loss.")
    if t["untraced"]:
        plan.notes.append(f"In play includes {money(t['untraced'])} read on-chain beyond the traced funds (at wallets "
                          "the trace never saw, or above what the trace left there: "
                          + ", ".join(_short(k[1]) for k in t["finds"][:4]) + "): untraced finds, added on top.")
    if run is None:
        plan.notes.append("No trace yet: run one so the plan knows where the funds sit.")
    if not targets:
        plan.notes.append("No law-enforcement authority on the case: every LE-only route needs the case officer "
                          "(add the complaint or an LE contact).")
    if not h.readings and any(bs._issuer_of(m.authority) for m in plan.moves if m.authority is not None):
        plan.notes.append("No on-chain freeze readings yet: the issuer values are traced upper bounds. Turn on the "
                          "on-chain freeze checks to read the real balances.")
    return plan


def _gate_actions(plan: Plan, moves: list[Move], by_key: dict) -> None:
    """Every move action linking a letter to a provider (/cases/{id}/authorities/entity-N?template=…) passes the request
    gate (app.domain.request_gate): an open draft → "Open & send draft" (or "Add <address> to draft #N", the page's
    form adds it), a request already out → its follow-up, LE only → the LE brief. Never a new-letter link the gate
    refuses; the move's own link follows its primary action."""
    from app.domain import request_gate as rg

    for m in moves:
        for x in m.actions:
            p = rg.parse_link(x.get("href"))
            if p is None or p["key"] not in by_key:
                continue
            d, alt = rg.gated_link(plan.gate.get(by_key[p["key"]]), x["href"])
            if alt is None:
                continue
            was = x["href"]
            if alt["kind"] == "wait":  # a request already asks about it: the follow-up on that request
                x.update(label=d.label(), href=alt["follow"], gate="follow_up")
            else:
                x.update(label=alt["label"], href=alt["href"], gate=alt["kind"])
            if m.href == was:
                m.href = alt["href"]
        seen: set = set()  # one button per link (a draft the gate points two actions at)
        m.actions = [x for x in m.actions if not x.get("href") or not (x["href"] in seen or seen.add(x["href"]))]


def _board_move(cid: int, a: desk.Authority, reqs: list, stake: Stake, h: er.Holdings, *, pb, org_key,
                requester: str, targets: list, run, now: datetime, orgs: dict, outlook: bool,
                victim_jur: str | None):
    """The move the freeze board's own plan holds for this provider (freeze_board.build: its plan leaves out the
    duplicate drafts, and a provider whose only requests are unsent drafts is untouched there): the input
    freeze_board.provider_target derives the provider's row — and so this plan's move for it — from. `...`: this
    plan's own move is that move."""
    from app.blocks import freeze_board as fb

    if not outlook and all(r.status == bs.NOT_SENT for r in reqs) and not a.is_le and not a.is_adviser:
        return _untouched_move(cid, a, stake, h, pb=pb, org_key=org_key, requester=requester, targets=targets,
                               run=run, now=now, victim_jur=victim_jur)
    live = fb.without_duplicates(reqs)
    if len(live) == len(reqs):
        return ...
    return _row_move(cid, a, live, stake, h, pb=pb, requester=requester, now=now, orgs=orgs) if live else None


# the freeze board's step kinds as plan move kinds (KIND_LABELS, EFFORT): its "draft request" is a request to send now,
# a follow-up (a status request on a request) a chase, a page to check first a check
STEP_KINDS = {"draft": "request", "redraft": "request", "follow_up": "chase", "open": "check", "add": "send",
              "owner": "request", "evidence": "check", "pack": "check"}


def step_kind(kind: str | None) -> str:
    """The plan move kind of a freeze-board step kind."""
    return STEP_KINDS.get(kind or "", kind or "wait")


def _provider_steps(plan: Plan, db: Session, case, *, run, rows: list, auths: list, wallets: list, now: datetime,
                    board_moves: dict) -> None:
    """ONE source of truth for a provider's next step: each provider's move takes its primary action (label, href or
    form), kind and whether it is actionable from the freeze board's row for that provider (freeze_board
    .provider_target over the request gate's state: an open draft → send it, a pointless one → the LE step, a
    records-only request with funds traced → the stop order, a request out → its follow-up or the reply it waits
    for); the plan keeps its own value, score, urgency and evidence. A pointless draft's page is never one of its
    actions. The owner moves keep their own gated step (`_owner_moves`)."""
    from app.blocks import freeze_board as fb
    from app.domain import request_gate as rg

    if plan.gate is None:
        return
    ctx = fb.step_board(db, case, run=run, rows=rows, auths=auths, now=now)
    readings = fb._readings(db, case, wallets)
    prepared = plan.gate.prepared
    by_auth: dict[str, list] = {}
    for r in rows:
        if r.kind != "outlook":
            by_auth.setdefault(r.authority.key, []).append(r)
    changed = False
    for m in [*plan.moves, *plan.waiting]:
        a = m.authority
        if a is None or ":" in m.key or not rg.is_provider(a):
            continue
        st = plan.gate.get(a)
        if st is None:
            continue
        try:
            t = fb.provider_target(case.id, a, by_auth.get(a.key, []), board_moves.get(a.key, m), readings,
                                   prepared, ctx, now, st)
        except Exception as err:  # noqa: BLE001 - no row: the move as the plan read it (every POST still gates)
            log.warning("recovery plan: board step failed for %s (%s)", a.key, type(err).__name__)
            continue
        was = m.actionable
        _take_step(m, t, st)
        changed = changed or was != m.actionable
    if changed:  # a provider's move goes where its step puts it (actionable: the moves; else waiting)
        was = {id(m) for m in plan.moves}
        every = [*plan.moves, *plan.waiting]
        plan.moves = [m for m in every if (m.actionable if m.target is not None else id(m) in was)]
        now_in = {id(m) for m in plan.moves}
        plan.waiting = [m for m in every if id(m) not in now_in]


def _take_step(m: Move, t, st) -> None:
    """The move's primary action, href, kind and actionable from the board row `t` (its step), its other actions kept
    (never a pointless draft's page, never a second link to the step's)."""
    from app.blocks import freeze_board as fb

    s = t.step
    m.target = t
    # never a draft the board says to discard: a pointless one, a duplicate of a request already sent
    gone = {x for r in st.pointless for x in (r.href, r.mail_href, r.held_href) if x}
    cid = st.case_id
    gone |= {f"/cases/{cid}/stop-orders/{d['order_id']}" for d in t.duplicates}
    gone |= {f"/cases/{cid}/mail/messages/{d['prepared']}" for d in t.duplicates if d.get("prepared")}
    button = bool(s.label and (s.href or s.post))
    kind = step_kind(s.kind)
    if kind in fb.LE_KINDS and m.kind in fb.LE_KINDS:
        kind = m.kind  # LE / cross-border: the plan's own reading of the route
    primary = next((x for x in m.actions if x.get("primary")), None)
    same = button and primary is not None and kind == m.kind and (
        primary.get("href") == s.href if s.href else primary.get("post") == s.post)
    rest = [x for x in m.actions if x is not primary and not (x.get("href") and x["href"] in gone)]
    if same:
        m.actions = [primary, *rest]
        return
    name = m.authority.name
    old_kind, old_text = m.kind, m.text
    if primary is not None and not (primary.get("href") and primary["href"] in gone):
        rest = [{**primary, "primary": False}, *rest]
    if button:
        act = {"label": s.label, "primary": True, "perm": s.perm, "step": s.kind}
        if s.href:
            act["href"] = s.href
        else:
            act.update(post=s.post, fields=dict(s.fields))
        alts = [{"label": x.label, "href": x.href, "perm": x.perm, "step": x.kind} for x in s.alts
                if x.label and x.href and x.href not in gone]  # the reachable LE's letter, the evidence
        seen = {s.href, *(x["href"] for x in alts)}
        rest = [x for x in rest if not (x.get("href") and x["href"] in seen)]
        m.actions = [act, *alts, *rest]
        if s.href:
            m.href = s.href
        elif m.href in gone:
            m.href = None
        m.actionable = True
    else:
        m.actions = rest
        if m.href in gone:
            m.href = None
        m.actionable = False
        if old_kind not in ACTIONABLE:  # it already waits: the plan's own title and text
            return
        kind = "wait"
    held = st.open if st.open is not None and st.open.held else None
    if kind == old_kind and button:  # the same kind of step, another action (the board's): its first sentence leads
        if held is not None and s.href and s.href == held.held_href and s.text:
            m.text = s.text  # its e-mail is prepared or may be out: settle that e-mail, never "open the editor"
            if held.busy is not None and m.effort_why.startswith("send the draft"):
                m.effort_why = "settle its e-mail" + m.effort_why[len("send the draft"):]
        elif s.lead and s.lead not in m.text:
            m.text = f"{s.lead} {m.text}".strip()
        return
    m.kind = kind
    if kind in ACTIONABLE:  # the effort of the step it takes now (never the old kind's "send the draft"); its
        # weight stays the plan's own, so the score the board ranks its row by stays the plan's
        m.effort_why = _effort(kind, m.evidence)[1]
    m.title = _step_title(m, t, s, kind, name)
    if s.text:
        m.text = (f"{s.text} {old_text}".strip() if old_kind == "wait" and old_text and old_text not in s.text
                  else s.text)


def _step_title(m: Move, t, s, kind: str, name: str) -> str:
    """The move's title for the board row's step (`_take_step`)."""
    to_order = s.post or "template=stop_order" in (s.href or "")
    if kind == "request" and to_order:
        rep = re.search(r"\(replaces draft ([^)]+)\)", s.label or "")
        return f"Send a stop order to {name}" + (f" (it replaces records-only draft {rep.group(1)})" if rep else "")
    if s.kind == "follow_up":
        return f"Follow up with {name}: {s.label[:1].lower()}{s.label[1:]}" if s.label else f"Follow up with {name}"
    if kind == "check" and s.label:
        return f"{s.label} ({name})"
    return _row_title(kind, name, m.route, None)


def _gate_asks(plan: Plan, atts: dict, by_key: dict) -> dict:
    """wallet key -> the owners panel's ask line where the request gate points elsewhere than the ask's own letter
    (an owner move's own line, else the ask's link through the gate)."""
    from app.domain import request_gate as rg

    out: dict = {}
    for m in plan.owner_moves():
        if m.ask is not None and m.wallets:
            out[m.wallets[0]] = m.ask
    for k, att in atts.items():
        ask = att.ask or {}
        p = rg.parse_link(ask.get("href"))
        if k in out or p is None or p["key"] not in by_key:
            continue
        _d, alt = rg.gated_link(plan.gate.get(by_key[p["key"]]), ask["href"])
        if alt is not None:
            out[k] = {"text": f"{alt['label']}: {alt['text']}", "href": alt["href"], "label": alt["label"]}
    return out


def _folds_into(m: Move, own: dict) -> Move | None:
    """The untouched service's own stop-order move a records-only owner move folds into (`uncited_records`: the stop
    order cites its address and asks for its records), or None."""
    if m.cites or m.authority is None or not uncited_records(m):
        return None
    req = own.get(m.authority.key)
    if req is None or not req.untouched or not req.actionable or req.kind != "request" or \
            "template=stop_order" not in (req.href or ""):
        return None
    return req


def _merge_cited(plan: Plan) -> None:
    """An owner move whose wallet a request already cites, when that request has its own move in the plan: one move,
    the request's, carrying the wallet's value and basis (when larger), its owner line and its evidence link; the owner
    move is kept on it (`merged`: the board's owner rows, the owners panel) and leaves the lists. The totals are
    counted before (the wallet's value stays in them once)."""
    every = plan.moves + plan.waiting
    own = {m.key: m for m in every if m.authority is not None and not m.key.startswith("owner:")}
    gone: set[int] = set()
    for m in every:
        req = own.get(m.cites["key"]) if m.key.startswith("owner:") and m.cites else None
        fold = _folds_into(m, own) if req is None else None
        if fold is not None:  # a swap order's records at a service nobody asked yet: in its stop order, freeze first
            short = m.owners[0].get("short") if m.owners else None
            if short and short not in fold.text:
                fold.text = (f"{fold.text} The stop order cites {short} too (an identified swap / order address of "
                             f"{fold.authority.name}) and asks for its order records: one letter, the freeze ask "
                             "first.").strip()
            seen = {o.get("short") or o.get("text") for o in fold.owners}
            fold.owners = [*fold.owners, *(o for o in m.owners if (o.get("short") or o.get("text")) not in seen)]
            for x in m.actions:
                if str(x.get("label", "")).startswith("Who owns it") and not any(
                        y.get("href") == x.get("href") for y in fold.actions):
                    fold.actions.append(x)
            if m.wallets and fold.href:  # the owners panel's line: that stop order, never the records-only letter
                m.ask = {"text": f"Open the stop order to {fold.authority.name}: it cites {short or 'the address'} too "
                                 "and asks for its order records (one letter, the freeze ask first)",
                         "href": fold.href}
                plan.asks[m.wallets[0]] = m.ask
            fold.merged.append(m)
            gone.add(id(m))
            continue
        if req is None:
            continue
        if (m.value or 0) > (req.value or 0):
            req.value, req.basis = m.value, m.basis
        seen = {o.get("short") or o.get("text") for o in req.owners}
        req.owners = [*req.owners, *(o for o in m.owners if (o.get("short") or o.get("text")) not in seen)]
        for x in m.actions:
            if str(x.get("label", "")).startswith("Who owns it") and not any(
                    y.get("href") == x.get("href") for y in req.actions):
                req.actions.append(x)
        short = m.owners[0].get("short") if m.owners else None
        who = m.authority.name if m.authority else "them"
        if short and short not in req.text:
            req.text = (f"{req.text} " + (
                f"{short} (an identified address of {who}) is not in draft {m.cites['no']} yet: add it, then send the "
                "one letter." if m.cites["state"] == "add" else
                f"The LE brief names {short} (an identified address of {who}) too." if m.cites["state"] == "le" else
                f"Request {m.cites['no']} asks {who} to freeze the account behind {short} (an identified deposit).")
            ).strip()
        if m.cites["state"] in ("add", "le"):  # its step leads the request's move: add the wallet / the LE brief naming it
            lead = next((x for x in m.actions if x.get("primary")), None)
            if lead is not None:
                for x in req.actions:
                    x["primary"] = False if m.cites["state"] == "add" else x.get("primary")
                if m.cites["state"] == "add":
                    req.actions.insert(0, dict(lead))
                    req.href = lead["href"]
                    if str(m.title or "").startswith("Add "):  # the title names the step it leads with
                        req.title = m.title
                else:  # the request's own LE brief, naming the wallet too
                    from app.domain import request_gate as rg

                    for x in req.actions:
                        if "template=le_brief" in (x.get("href") or "") or "template=le_cover" in (x.get("href") or ""):
                            x["href"] = rg._with_about(x["href"], [f"{m.wallets[0][0]}:{m.wallets[0][1]}"])
                    if req.href and ("template=le_brief" in req.href or "template=le_cover" in req.href):
                        req.href = rg._with_about(req.href, [f"{m.wallets[0][0]}:{m.wallets[0][1]}"])
        req.merged.append(m)
        gone.add(id(m))
    if gone:
        plan.moves = [m for m in plan.moves if id(m) not in gone]
        plan.waiting = [m for m in plan.waiting if id(m) not in gone]
        now = plan.generated_at
        plan.moves.sort(key=lambda m: (-m.score, m.clock["due_at"] if m.clock else now + timedelta(days=3650), m.key))


def _standing_notes(case, targets: list, now: datetime) -> list[str]:
    """The victim's own deadlines an LE playbook of the case runs from the offence itself (the querela term: 3 months
    from learning of the fact, art. 124 c.p.), counted from the case's fraud date (the earliest the victim can have
    learned of it), whether a complaint is on file or not: a late querela loses the prosecution of a querela-based
    offence."""
    filed = [c for c in desk.complaint_list(case) if c.get("reference")]
    groups: dict[str, dict] = {}
    for t in targets:
        for c in pathmod.standing_clocks(t.playbook, case.fraud_date):
            g = groups.setdefault(c["action"] or c["key"], {"c": c, "names": []})
            g["names"].append(t.name)
    out = []
    for g in groups.values():
        c, names = g["c"], " / ".join(dict.fromkeys(g["names"]))
        what = "querela" if "querela" in c["key"] else "complaint"
        span = f"{c['span']} from learning of the fact" if c.get("span") else "its term"
        refs = [x for x in filed if any(n.casefold() in (x["authority"] or "").casefold()
                                        or (x["authority"] or "").casefold() in n.casefold() for n in g["names"])]
        check = (f" A complaint is on file with {refs[0]['authority']}: check that it includes the {what} (a "
                 "denuncia-querela)." if refs else "")
        cite = re.search(r"\(art\.[^)]*\)", c.get("action") or "")
        why = f" {cite.group(0)}" if cite else ""
        if c["due_at"] is None:
            out.append(f"{what.title()} term ({names}): {span}{why}. The case has no fraud date, so Aegis cannot count "
                       "it: record the date the victim learned of the fraud." + check)
        elif c["due_at"] <= now:
            out.append(f"{what.title()} term ({names}): {span} passed on {c['due_at']:%d %b %Y} (counted from the "
                       f"fraud date {c['start_at']:%d %b %Y}){why}." + (check or f" No complaint is on file: file the "
                       f"{what} at once and ask counsel whether the offence is prosecutable ex officio."))
        else:
            out.append(f"{what.title()} term ({names}): file the {what} by {c['due_at']:%d %b %Y} ({span}, counted from "
                       f"the fraud date {c['start_at']:%d %b %Y}; {_left(now, c['due_at'])}){why}." + check)
    return out


# --------------------------------------------------------------------------- as one member may see it
PERMS = {"view": "view", "draft_letter": "draft_letter", "edit": "edit", "poll_watch": "poll_watch",
         "run_trace": "run_trace"}


def may(access, perm: str) -> bool:
    if perm == "pack":
        return access.can("view_restricted") and access.can("export")
    return access.can(PERMS.get(perm, perm))


def _fmt(v: datetime | None) -> str:
    return v.astimezone(UTC).strftime("%d %b %Y %H:%M UTC") if v else "—"


def _seen_evidence(e: dict, access, items: dict) -> dict:
    """An evidence row as this member may see it: an item they may not open (the Financial folder without
    view_financial) shows "on file (restricted)", without its id or type (evidence_requirements)."""
    from app.domain import evidence as ev

    if not e.get("ids"):
        return e
    seen = [i for i in e["ids"] if i in items and ev.can_see(access, items[i])]
    if seen == list(e["ids"]):
        return e
    if not seen:
        return {**e, "ids": [], "source": "on file (restricted)"}
    x = items[seen[0]]
    return {**e, "ids": seen, "source": f"evidence #{x.id} ({(x.source_type or x.folder.value).replace('_', ' ')})"}


def move_view(m: Move, access, mask, rank: int | None = None, now: datetime | None = None) -> dict:
    private = set() if access.can("view_restricted") else {n for o in m.owners for n in o.get("private") or ()}

    def t(v):  # contact details masked; a person's free-text owner name only with view_restricted
        v = mask.text(v)
        return attr.mask_names(v, private) if private and v else v
    c = er.counts(m.evidence)
    items = {e.id: e for e in getattr(getattr(access, "case", None), "evidence_items", None) or []}
    evidence = [_seen_evidence(e, access, items) for e in m.evidence]
    return {
        "rank": rank, "key": m.key, "kind": m.kind, "kind_label": KIND_LABELS.get(m.kind, m.kind),
        "title": t(m.title), "text": t(m.text), "reason": t(m.reason), "href": m.href,
        "authority": ({"key": m.authority.key, "name": t(m.authority.name)} if m.authority is not None else None),
        "value": m.value, "value_fmt": money(m.value) if m.value else "—", "basis": t(m.basis),
        "expected": m.expected, "expected_fmt": money(m.expected) if m.expected else "—",
        "urgency": m.urgency, "urgency_why": [t(x) for x in m.urgency_why], "likelihood": m.likelihood,
        "likelihood_pct": round(m.likelihood * 100), "likelihood_why": t(m.likelihood_why), "effort": m.effort,
        "effort_why": m.effort_why, "score": m.score, "untouched": m.untouched, "actionable": m.actionable,
        "step": m.step, "step_label": m.step_label,
        # the request's status as Block status shows it (bs.BlockRow.status_text: one wording on every page), its
        # path step (the provider's process) in the tooltip
        "status_text": t(m.row.status_text) if m.row is not None else None,
        "status_tone": m.row.tone if m.row is not None else None,
        "route": (m.route or {}).get("kind"), "clock": ({"label": m.clock.get("label"), "due_at": m.clock["due_at"],
                                                         "due_fmt": _fmt(m.clock["due_at"]),
                                                         "passed": now is not None and m.clock["due_at"] <= now}
                                                        if m.clock else None),
        "evidence": [{k: e.get(k) for k in ("key", "label", "state", "state_label", "source", "how", "waiver", "matched", "suggested")}
                     | {"ids": e["ids"]} for e in evidence],
        "evidence_counts": c, "related": [t(x) for x in m.related],
        # the "Also:" line: a request move's other requests; a wallet move's wallets are its Owner line already
        "related_line": [t(x) for x in m.related] if m.row is not None else [],
        "moved_on": list(m.moved_on),
        "actions": [a for a in m.actions if may(access, a.get("perm", "view"))],
        "secured": m.secured, "owners": [{**o, "owner": t(o["owner"]), "text": t(o["text"]), "private": []}
                                         for o in m.owners],
    }


def view(plan: Plan, access) -> dict:
    mask = desk.contact_mask(access, None)
    restricted = access.can("view_restricted")
    moves = [m for m in plan.moves if restricted or not m.sensitive]
    tot = dict(plan.totals)
    nc = tot.get("next_clock")
    tot["next_clock"] = {"label": nc.get("label"), "due_fmt": _fmt(nc["due_at"])} if nc else None
    return {
        "moves": [move_view(m, access, mask, i, plan.generated_at) for i, m in enumerate(moves, 1)],
        "waiting": [move_view(m, access, mask, None, plan.generated_at) for m in plan.waiting],
        "secured": [{**s, "authority": mask.text(s["authority"]), "text": mask.text(s["text"])} for s in plan.secured],
        "done": [{**d, "authority": mask.text(d["authority"]), "text": mask.text(d["text"])} for d in plan.done],
        "totals": tot, "run": plan.run, "requester": plan.requester,
        "requester_label": REQUESTER_LABELS.get(plan.requester, plan.requester),
        "notes": [mask.text(n) for n in plan.notes],
        "generated_at": plan.generated_at, "generated_fmt": _fmt(plan.generated_at),
        "can_waive": access.can("manage_case"), "can_pack": may(access, "pack"),
        **owners_view(plan, access),
    }


def owners_view(plan: Plan, access) -> dict:
    """The "Who owns these wallets" panel: every wallet with money (then the rest), its owner, kind, confidence, the
    evidence lines and the next step; a person's note only with view_restricted."""
    notes = access.can("view_restricted")
    # the request gate's step for the wallet's letter (an open draft, a request already citing it, the follow-up, the
    # LE brief: plan.asks), never a second letter to the same provider
    rows = []
    for k, a in plan.owners.items():
        r = a.as_dict(notes)
        g = plan.asks.get(k)
        if g is not None:
            r["ask"] = {**r["ask"], "href": g["href"], "template": None, "text": g["text"]}
        r["step"] = {"label": (g or {}).get("label")}
        rows.append(r)
    money_rows = [r for r in rows if max(r["money_usd"], r["share_usd"]) >= attr.MONEY_MIN_USD or r["manual"]
                  or r["conflict"]]  # a tag the trace contradicts: a person checks it
    for r in rows:
        if not may(access, "draft_letter"):
            r["ask"] = {**r["ask"], "href": None}
        r["step"] = _ask_button(r["ask"], r["step"]["label"])  # the table's Next step: its button, the line beside
    return {"owners": money_rows, "owners_other": [r for r in rows if r not in money_rows],
            "owner_lookups": plan.owner_lookups, "owner_kinds": attr.KINDS,
            "can_mark": access.can("edit"), "can_lookup": access.can("poll_watch"),
            "can_manage_lookups": access.can("manage_case"),
            # the case's share (a service float's whole balance is never the case's money)
            "owners_unknown_usd": round(sum(r["share_usd"] for r in money_rows if not r["owner"]), 2)}


def _ask_button(ask: dict, label: str | None = None) -> dict:
    """The owners table's Next step: a button (`button`: `label`, the request gate's step, else one named after the
    link; None without a link) and the line beside it (`lead`: the ask's text without the label it starts with)."""
    text, href = str(ask.get("text") or ""), str(ask.get("href") or "")
    if not href or href.endswith("/recovery-plan#owners"):  # nothing to open but this panel (watch it, mark it)
        return {"button": None, "lead": text}
    if not label:
        label = ("Brief LE" if "template=le_cover" in href or "template=le_brief" in href else
                 "Open the stop order" if "/stop-orders/" in href else
                 "Draft the stop order" if "template=stop_order" in href else
                 "Open the draft" if "/correspondence/" in href or "/mail/" in href else
                 "Draft the letter" if "template=" in href else "Open")
    lead = text[len(label) + 2:] if text.startswith(f"{label}: ") else text
    return {"button": label, "lead": lead[:1].upper() + lead[1:]}


# --------------------------------------------------------------------------- the LE brief pack
class PackError(ValueError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _brief(db: Session, case, m: Move, counsel: bool = False) -> tuple[str | None, str, int | None]:
    """(markdown, source text, correspondence id) of the brief for move `m`: the LE / counsel brief linked to the request
    (newest), else a preview rendered now (not saved), else None. `counsel`: the counsel brief (court-order route), to
    the case's counsel or, with none on the case yet, addressed to "Counsel"."""
    r = m.row
    if counsel:
        if r is None:
            return None, "no request to brief counsel on yet: send the request first", None
        for ln in reversed(r.links):
            from app.db.models import Correspondence

            c = db.get(Correspondence, ln["id"])
            if ln.get("counsel") and c is not None and c.body_markdown:
                return c.body_markdown, f"{'sent' if ln.get('sent') else 'draft'} counsel brief #{c.id}", c.id
        from app import services
        from app.db.models import EntityCategory

        to = next((a for a in desk.case_authorities(db, case, include_prospects=False)
                   if a.category == EntityCategory.LEGAL_COUNSEL.value), None) or desk.Authority(
            key="counsel-preview", name="Counsel", category=EntityCategory.LEGAL_COUNSEL.value)
        try:
            _s, body, _r = desk.build_letter(db, case, to, "counsel_brief", ref=r.key, run=services.latest_run(db, case))
        except desk.DeskError as exc:
            return None, f"no counsel brief: {exc}", None
        return body, f"preview of the counsel brief to {to.name} (not saved)", None
    if r is not None:
        for ln in reversed(r.links):
            from app.db.models import Correspondence

            c = db.get(Correspondence, ln["id"])
            if c is not None and c.body_markdown:
                return c.body_markdown, f"{'sent' if ln.get('sent') else 'draft'} letter #{c.id} to {ln['authority']}", c.id
    st = r.path if r is not None else None
    le = st.le if st is not None and st.le is not None else None
    if le is None and m.route and m.route.get("le"):
        from app.domain import directory

        le = next((t for t in pathmod.le_targets([a for a in desk.case_authorities(db, case, include_prospects=False)
                                                   if a.is_le], directory.playbook_for) if t.name == m.route["le"]), None)
    if le is not None and not le.briefable:
        return None, f"{le.name} is a complaint intake: get a case agent assigned, then generate the brief", None
    if le is None:
        return None, "no LE authority on the case: add the case officer, then generate the brief", None
    try:
        tpl, ref = ("le_brief", r.key) if r is not None else ("le_cover", None)
        from app import services

        _subject, body, _refs = desk.build_letter(db, case, le.authority, tpl, ref=ref, run=services.latest_run(db, case))
    except desk.DeskError as exc:
        return None, f"no brief: {exc}", None
    return body, f"preview of the {'LE brief' if r is not None else 'LE cover letter'} to {le.name} (not saved)", None


def _csv(rows: list[list]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    for row in rows:
        w.writerow([("'" + str(v)) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else
                    ("" if v is None else v) for v in row])
    return buf.getvalue()


def pack(db: Session, access, key: str, *, now: datetime | None = None, counsel: bool = False) -> tuple[bytes, str, dict]:
    """The LE brief pack of move `key`: brief.md (the linked brief, else a preview), manifest.json / manifest.md (the
    evidence items the checklist names: ids, sha256, collected / verified dates; the sha256 of every file), movements.csv
    (the latest trace run) and freeze_readings.csv (the move's wallets). Nothing is stored; the route audits."""
    from app import services
    from app.blocks import freeze_board as fb
    from app.domain import evidence as ev
    from app.freeze import service as fz
    from app.tracing import export as tx

    case = access.case
    now = now or _now()
    # the plan without the duplicate drafts the freeze board flags (a draft repeating a freeze request already sent):
    # a sent request's pack is its own, with its brief, as the board links it; a duplicate's own move (this plan page
    # lists it) still has its pack
    m = build(db, case, now=now, keep=fb.without_duplicates).find(key)
    if m is None:
        m = build(db, case, now=now).find(key)
    if m is None or m.authority is None:
        raise PackError(404, "no such move in the recovery plan")
    files: dict[str, str] = {}
    brief, brief_src, brief_id = _brief(db, case, m, counsel)
    agent = (m.route or {}).get("agent")
    if brief and not counsel and brief_id is None and agent is not None and (m.route or {}).get("case_agent", True):
        # the move's fastest route is a case agent the brief's authority is not: say so beside the preview
        via = f" via {agent['via']}" if agent.get("via") else ""
        brief_src += (f"; the move's fastest route is a {agent['jur']} case agent{via}: once one is assigned, address "
                      "the brief to them")
    if brief:
        files["brief.md"] = brief
    run = services.latest_run(db, case)
    if run is not None:
        # an asserted link has no transaction hash yet: its synthetic id ("ASSERTED:…") never reads as one
        files["movements.csv"] = tx.movements_csv([
            replace(x, tx_hash="hash pending (asserted link)") if x.asserted and str(x.tx_hash).startswith("ASSERTED:")
            else x for x in tx.movements(db, run)])
    wallets = fz.wallet_rows(db, case)
    want = {_key(c, a) for c, a in _stake(m.authority, [], wallets, {}, now).addresses}
    readings = [["chain", "address", "issuer", "token", "blacklisted", "balance", "usd", "block", "checked_at",
                 "method", "raw_sha256"]]
    for w in wallets:
        if want and _key(w["chain"], w["address"]) not in want:
            continue
        for c in w["checks"]:
            if c.get("status") == "ok":
                readings.append([w["chain"], w["address"], c["issuer"], c["symbol"], c["blacklisted"], c["balance"],
                                 c["usd"], c["block_number"], c["checked_at"], c["method"], c["raw_sha256"]])
    files["freeze_readings.csv"] = _csv(readings)
    checklist = list(m.evidence)
    pb = m.row.playbook if m.row is not None else None
    if counsel and pb is not None:  # counsel's own court-order path: its evidence, never the LE route's
        c = (m.route or {}).get("counsel") or pathmod._counsel(pb, list((m.route or {}).get("acts_on") or []))
        cp = pb.path(c["path"]) if c else None
        if cp is not None:
            checklist = er.check(er.holdings(db, case, run=run, wallets=wallets), list(cp.evidence), access=access,
                                 addresses=_stake(m.authority, [], wallets, {}, now).addresses, cited=True,
                                 emits=er.EMITS["counsel_brief"])
    if run is not None:  # the same reading as the plan's page: movements.csv lists the transfers, not the report
        checklist = [{**e, "source": f"movements.csv of trace run #{run.id} in this pack lists the transfers; "
                                     "the report itself: Evidence tab → Snapshot trace report"}
                     if e["key"] == "trace_report_run" and e["state"] == "missing" else e for e in checklist]
    ids = {i for e in checklist for i in e["ids"]}
    from app.db.models import EvidenceFolder

    # the checklist's items, the LE folder and the chain reports, and the sender's authority instrument (the Letter
    # of Authorisation every brief lists as attached)
    items = [e for e in ev.visible_items(access) if e.id in ids or e.folder in (EvidenceFolder.LAW_ENFORCEMENT,
                                                                               EvidenceFolder.CHAIN_REPORTS)
             or e.source_type in er.TYPES["loa"]]
    req_by_item: dict[int, list[str]] = {}
    for e in checklist:
        for i in e["ids"]:
            req_by_item.setdefault(i, []).append(e["key"])
    mask = desk.contact_mask(access, None)
    manifest = {
        "case": case.reference, "generated_at": now.isoformat(timespec="seconds"),
        "aegis": f"recovery plan · {'counsel' if counsel else 'LE'} brief pack",
        "move": {"key": m.key, "title": mask.text(m.title), "authority": mask.text(m.authority.name),
                 "value_usd": m.value, "basis": mask.text(m.basis), "reason": mask.text(m.reason)},
        "brief": {"file": "brief.md" if brief else None, "source": mask.text(brief_src), "correspondence_id": brief_id},
        "trace_run": {"id": run.id, "label": run.label} if run is not None else None,
        "checklist": [{"key": e["key"], "label": e["label"], "state": e["state"], "evidence_ids": e["ids"]}
                      for e in checklist],
        "evidence": [{"id": e.id, "title": mask.text(e.title), "folder": e.folder.value, "source_type": e.source_type,
                      "sha256": e.sha256, "size_bytes": e.size_bytes, "storage": e.storage.value,
                      "classification": e.classification.value, "tlp": e.tlp,
                      "doc_date": e.doc_date.isoformat() if e.doc_date else None,
                      "collected_at": e.created_at.isoformat() if e.created_at else None,
                      "verified_at": e.verified_at.isoformat() if e.verified_at else None,
                      "integrity": ev.integrity_status(e), "requirements": req_by_item.get(e.id, [])} for e in items],
        "files": [{"name": n, "sha256": hashlib.sha256(b.encode("utf-8")).hexdigest(), "bytes": len(b.encode("utf-8"))}
                  for n, b in files.items()],
        "note": ("Evidence originals are not included: the manifest lists them by id and sha256 (the case's evidence "
                 "vault keeps them). Aegis never sends anything: a person reviews the brief and sends it to the officer."),
    }
    md = [f"# {'Counsel' if counsel else 'LE'} brief pack — {case.reference}", "",
          f"Move: **{mask.text(m.title)}** ({money(m.value)})", "",
          f"Reasoning: {mask.text(m.reason)}", "", f"Brief: {mask.text(brief_src)}", "", "## Checklist", ""]
    md += [f"- [{'x' if e['state'] in ('have', 'letter', 'waived') else ' '}] {e['label']} — {e['state_label']}"
           + (f" ({e['source']})" if e.get("source") else "") for e in checklist] or ["- (none listed)"]
    md += ["", "## Evidence items", "", "| id | folder | type | sha256 | verified |", "|---|---|---|---|---|"]
    md += [f"| {x['id']} | {x['folder']} | {x['source_type'] or ''} | `{x['sha256'] or '—'}` | "
           f"{(x['verified_at'] or '—')[:10]} |" for x in manifest["evidence"]]
    md += ["", "## Files", ""] + [f"- {f['name']}: sha256 `{f['sha256']}`" for f in manifest["files"]]
    files["manifest.md"] = "\n".join(md) + "\n"
    files["manifest.json"] = json.dumps(manifest, indent=2, default=str)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n in ("manifest.json", "manifest.md", "brief.md", "movements.csv", "freeze_readings.csv"):
            if n in files:
                z.writestr(n, files[n])
    stamp = now.strftime("%Y%m%d-%H%M")
    return buf.getvalue(), f"{case.reference}_{'counsel' if counsel else 'le'}-pack_{m.key}_{stamp}.zip", manifest
