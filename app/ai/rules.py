"""Deterministic, offline case checks: the assistant's fallback when no model may or can be called.

    derive(ctx, now)        -> computed figures and findings (part of every context, also sent)
    rule_summary(ctx)       -> the same shape the model returns (app.ai.assistant.CaseSummary)
    rule_answer(ctx, q)     -> a short text answer picked by keywords

Everything here reads only a context built by app.ai.context (normally the redacted one), so
its output carries no more than that context does. Each statement ends with a source tag in
square brackets naming the context section it comes from.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation

RULE_LABEL = "rule-based (AI not configured)"
RULE_LABEL_OFF = "rule-based (AI turned off for this case)"
RULE_LABEL_INVALID = "rule-based (AI response invalid)"
RULE_LABEL_UNAVAILABLE = "rule-based (AI unavailable)"
RULE_LABEL_UNCONFIRMED = "rule-based (full mode not confirmed for this AI provider)"
# reasons meaning "no model is configured" (labelled RULE_LABEL); any other reason is a failed call
NOT_CONFIGURED_REASONS = frozenset({None, "not_configured", "disabled", "provider_none", "host_not_allowed"})
PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def rule_label(reason: str | None = None) -> str:
    """The label of a rule-based result: AI switched off for the case, not configured, its response
    invalid (after one repair attempt), full mode unconfirmed, or the call failed."""
    if reason == "ai_mode_off":
        return RULE_LABEL_OFF
    if reason == "invalid_output":
        return RULE_LABEL_INVALID
    if reason == "full_mode_unconfirmed":
        return RULE_LABEL_UNCONFIRMED
    return RULE_LABEL if reason in NOT_CONFIGURED_REASONS else RULE_LABEL_UNAVAILABLE


DORMANT_MIN_USD = 1000.0
DORMANT_MIN_PCT = 1.0  # of the loss


def _short(addr: str | None) -> str:
    if not addr:
        return "?"
    if addr.endswith("_PENDING"):
        return addr
    return f"{addr[:6]}…{addr[-4:]}" if len(addr) > 14 else addr


def _kind(kind: str | None) -> str:
    return (kind or "preservation").replace("_", " ")


def _send_status(follow_up: dict) -> str:
    """'send a status request', or 'send the drafted status request (#N)' when one waits in draft."""
    n = follow_up.get("drafted_status_request_id")
    return f"send the drafted status request (#{n})" if n else "send a status request"


def _money(v: float | None) -> str:
    return "unknown" if v is None else f"${v:,.2f}"


def _upper(fp: dict) -> str:
    """', plus up to $X frozen with no amount reported (upper bound)' when some holds have no amount."""
    v = fp.get("frozen_upper_bound_usd")
    return f", plus up to {_money(v)} frozen with no amount reported (upper bound)" if v else ""


def _date(v: str | None) -> str:
    return (v or "")[:10] or "no date"


_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def day(v: str | None) -> str:
    """'2026-10-21…' -> '21 Oct 2026' (the app's own date format); anything else as given."""
    d = (v or "")[:10]
    try:
        y, m, dd = int(d[:4]), int(d[5:7]), int(d[8:10])
        return f"{dd} {_MONTHS[m - 1]} {y}"
    except (ValueError, IndexError):
        return d or "no date"


def qty(v) -> str:
    """An asset amount with thousands separators ('399,247.92'); as given when it is no number."""
    if v is None or v == "":
        return "?"
    try:
        return f"{Decimal(str(v)).normalize():,f}"
    except (InvalidOperation, ValueError):
        return str(v)


# what the context's enum keys mean, for the text a member reads
CATEGORY_TEXT = {
    "exchange": "exchange", "casino": "casino", "otc": "OTC desk", "swap_service": "swap service", "bridge": "bridge",
    "dex": "DEX / router (non-custodial)", "mixer": "mixer", "hosting": "hosting provider",
    "infra": "infrastructure provider", "stablecoin_issuer": "stablecoin issuer", "law_enforcement": "law enforcement",
    "pi_firm": "PI firm", "legal_counsel": "legal counsel", "regulator": "regulator", "unknown": "other",
}
KIND_TEXT = {"freeze": "freeze request", "preservation": "preservation request", "issuer_blacklist": "issuer blacklist",
             "info_request": "information request", "status_request": "status request", "le_cover": "LE cover letter"}


def category_text(v: str | None) -> str:
    return CATEGORY_TEXT.get(v or "", (v or "other").replace("_", " "))


def kind_text(v: str | None) -> str:
    return KIND_TEXT.get(v or "", (v or "preservation").replace("_", " "))


def folder_text(v: str | None) -> str:
    try:
        from app.domain.evidence import folder_label

        return folder_label(v or "other")
    except (KeyError, ValueError):
        return (v or "other").replace("_", " ")


# --------------------------------------------------------------------------- derived findings
def _frozen(orders: list[dict], cands: list[dict]) -> tuple[float, float]:
    """(confirmed frozen USD, upper bound for frozen recipients that reported no amount).

    Confirmed = the holds recorded on stop orders in state 'frozen' (amount × static price), per
    recipient capped at its candidate taint. A frozen order with no recorded amount (or an asset
    without a price) adds its recipient's candidate taint to the upper bound instead."""
    taint = {c["entity"]: c["total_taint_usd"] or 0 for c in cands if c.get("entity")}
    held: dict[str, float] = {}
    unknown: set[str] = set()
    for o in orders:
        hold = o.get("hold") or {}
        is_frozen = o.get("status") == "frozen" or hold.get("state") == "frozen"
        if not is_frozen:
            continue
        key = o.get("entity") or f"#{o.get('id')}"
        if hold.get("usd") is not None:
            held[key] = held.get(key, 0.0) + float(hold["usd"])
        else:
            unknown.add(key)
    confirmed = sum(min(v, taint[k]) if taint.get(k) else v for k, v in held.items())
    upper = sum(taint.get(k, 0) for k in unknown if k not in held)
    return confirmed, upper


MOVED_ON_SHARE = 0.9  # a wallet that sent on this share of what the trace put in holds nothing to blacklist


def _issuer_held(cands: list[dict], trace: dict) -> tuple[dict[str, float], list[str]]:
    """({issuer: traced USD still at its wallets}, [addresses the trace saw the funds leave]): an issuer can blacklist
    only what is still there, so a stablecoin wallet that forwarded (about) everything the trace put in counts nothing
    (the Recovery plan's "moved on" rule, app.blocks.recovery._moved_on). A candidate with identifiers left out of the
    context, or a context whose transfer list is cut, keeps its whole traced value (an upper bound)."""
    out_taint: dict[str, float] = {}
    for t in trace.get("tainted_transfers") or []:
        key = str(t.get("from") or "").lower()
        out_taint[key] = out_taint.get(key, 0.0) + float(t.get("taint_usd") or 0)
    held: dict[str, float] = {}
    gone: list[str] = []
    for c in cands:
        if c.get("kind") != "issuer_blacklist":
            continue
        total = float(c.get("total_taint_usd") or 0)
        if c.get("identifiers_omitted") or trace.get("tainted_transfers_omitted"):
            held[c["entity"]] = total
            continue
        stays = 0.0
        for i in c.get("identifiers") or []:
            taint = float(i.get("taint_usd") or 0)
            if taint > 0 and out_taint.get(str(i.get("address") or "").lower(), 0.0) >= MOVED_ON_SHARE * taint:
                gone.append(i["address"])
            else:
                stays += taint
        held[c["entity"]] = min(stays, total) if c.get("identifiers") else total
    return held, gone


def derive(ctx: dict, now: datetime) -> dict:
    """Figures and findings computed from the other sections (no model involved)."""
    loss = (ctx.get("case") or {}).get("loss", {}).get("usd")
    trace = ctx.get("trace") or {}
    nodes = trace.get("nodes") or []
    cands = ctx.get("freeze_candidates") or []
    orders = ctx.get("stop_orders") or []
    corr = ctx.get("correspondence") or []

    traced = max((n["taint_usd"] or 0 for n in nodes), default=None) if nodes else None
    at_freezable = sum(c["total_taint_usd"] or 0 for c in cands if c["kind"] == "freeze")
    issuer_held, moved_on = _issuer_held(cands, trace)
    issuer_lever = sum(issuer_held.values())
    frozen, frozen_upper = _frozen(orders, cands)
    if traced is not None:
        at_freezable = min(at_freezable, traced)
        issuer_lever = min(issuer_lever, traced)
        frozen = min(frozen, traced)
        frozen_upper = min(frozen_upper, traced)

    threshold = max(DORMANT_MIN_USD, (loss or 0) * DORMANT_MIN_PCT / 100)
    dormant = [
        {"address": n["address"], "chain": n["chain"], "taint_usd": n["taint_usd"], "label": n["label"],
         "pending_input": "pending_input" in n["flags"], "trace_next": "trace_next" in n["flags"]}
        for n in nodes
        if "dormant" in n["flags"] and not n["terminal"] and (n["taint_usd"] or 0) >= threshold
    ]
    dormant_usd = sum(d["taint_usd"] or 0 for d in dormant if not d["pending_input"])
    if traced is not None:
        dormant_usd = min(dormant_usd, traced)

    unanswered = [
        {"stop_order_id": o["id"], "entity": o["entity"], "kind": o["kind"], "sent_at": o["sent_at"],
         "days_since_sent": o["days_since_sent"]}
        for o in orders if o["unanswered_over_7_days"]
    ]
    overdue = [
        {"type": "stop_order", "id": o["id"], "entity": o["entity"], "kind": o["kind"], "due": o["response_due_at"]}
        for o in orders if o["overdue"]
    ] + [
        # a note with a due date is the team's own follow-up task ("internal"), not a reply anybody owes us
        {"type": "correspondence", "id": c["id"], "entity": c["entity"] or c["le_agency"], "kind": c["kind"],
         "due": c["due_at"], "direction": c["direction"], "internal": c["direction"] == "note"}
        for c in corr if c["overdue"]
    ]
    upcoming = [
        {"type": "stop_order", "id": o["id"], "entity": o["entity"], "kind": o["kind"], "due": o["response_due_at"]}
        for o in orders if o["response_due_at"] and not o["answered"] and not o["overdue"]
        and o["status"] not in ("draft", "superseded")
    ] + [
        {"type": "correspondence", "id": c["id"], "entity": c["entity"] or c["le_agency"], "kind": c["kind"],
         "due": c["due_at"], "direction": c["direction"]}
        for c in corr if c["due_at"] and not c["answered"] and not c["overdue"]
        and not c.get("tracked_by_stop_order")
    ]
    pending_seeds = [{"role": s["role"], "chain": s["chain"]} for s in ctx.get("seeds") or [] if s["pending"]]
    pending_nodes = [{"address": n["address"], "label": n["label"]} for n in nodes if "pending_input" in n["flags"]]
    transfers = trace.get("tainted_transfers") or []
    candidates_without_order = [c["entity"] for c in cands if not c["stop_order_ids"]]
    drafts = [{"stop_order_id": o["id"], "entity": o["entity"], "kind": o["kind"]}
              for o in orders if o["status"] == "draft"]
    sweep = [{"address": n["address"], "entity": n["entity"]} for n in nodes if "sweep_imminent" in n["flags"]]
    unack = sum(1 for a in (ctx.get("watch") or {}).get("recent_alerts") or [] if not a["acknowledged"])
    run = trace.get("run") or None
    based_on = ({"run_id": run.get("id"), "label": run.get("label"), "status": run.get("status"),
                 "provider_mode": run.get("provider_mode"), "at": run.get("finished_at") or run.get("started_at"),
                 "latest": True} if run else None)
    # holds the recipients confirmed, with no release / return-of-funds request on file yet
    release_kinds = {(c.get("stop_order_id"), c.get("kind")) for c in corr}
    holds_to_release = [
        {"stop_order_id": o["id"], "entity": o["entity"], "kind": o["kind"], "hold": o.get("hold")}
        for o in orders
        if (o.get("status") == "frozen" or ((o.get("hold") or {}).get("state") == "frozen"))
        and o.get("status") != "released" and (o["id"], "release_request") not in release_kinds
    ]
    # sent stop orders past response_due_at with no answer and no status request since the due date
    # (a drafted status request does not count as sent: the step then says to send the draft)
    status_sent: dict = {}
    status_drafted: dict = {}
    for c in corr:
        if c.get("kind") != "status_request" or c.get("stop_order_id") is None:
            continue
        if c.get("status") == "draft":
            status_drafted.setdefault(c["stop_order_id"], c)
        elif (c.get("occurred_at") or "") >= (status_sent.get(c["stop_order_id"], {}).get("occurred_at") or ""):
            status_sent[c["stop_order_id"]] = c
    follow_ups = []
    for o in orders:
        if not o.get("overdue"):
            continue
        sr = status_sent.get(o["id"])
        if sr is not None and (sr.get("occurred_at") is None or (o.get("response_due_at") or "") <= sr["occurred_at"]):
            continue  # a status request was sent after the reply fell due
        draft = status_drafted.get(o["id"])
        follow_ups.append({"stop_order_id": o["id"], "entity": o["entity"], "kind": o["kind"],
                           "due": o["response_due_at"], "days_since_sent": o["days_since_sent"],
                           "drafted_status_request_id": draft.get("id") if draft else None,
                           # their answer so far as Block status reads it ("Acknowledged"), if any
                           "reply_status_label": o.get("reply_status_label") if o.get("answered") else None})
    engaged_earlier = [a["name"] for a in ctx.get("authorities") or [] if a.get("engaged_earlier")]
    return {
        "funds_position": {
            "based_on_run": based_on,
            "loss_usd": loss, "traced_usd": traced, "at_freezable_services_usd": round(at_freezable, 2),
            "issuer_blacklist_lever_usd": round(issuer_lever, 2),
            "issuer_held_usd": {k: round(v, 2) for k, v in sorted(issuer_held.items())},
            "issuer_moved_on": sorted(set(moved_on)), "frozen_usd": round(frozen, 2),
            "frozen_upper_bound_usd": round(frozen_upper, 2),
            "dormant_self_custody_usd": round(dormant_usd, 2),
            "method": (f"based on trace run #{run.get('id')} (the latest run); " if run else "no trace run yet; ")
                      + "traced = largest taint carried by one address (≤ loss); at freezable services = freeze "
                      "candidates of kind 'freeze' (exchanges, casinos, OTC); issuer-blacklist lever = what the trace "
                      "left at stablecoin wallets an issuer can blacklist (a wallet that forwarded what it received "
                      "counts nothing: the funds moved on); frozen = the amounts recipients "
                      "reported holding on stop orders marked 'frozen' (priced statically, capped at that "
                      "recipient's traced taint); frozen upper bound = the traced taint of frozen recipients that "
                      "reported no amount; dormant = untouched non-VASP addresses holding ≥ "
                      f"{_money(threshold)}.",
        },
        "unanswered_stop_orders_over_7_days": unanswered,
        "status_request_due": follow_ups,
        "holds_to_release": holds_to_release,
        "engaged_outside_latest_trace": engaged_earlier,
        "overdue": overdue,
        "upcoming_deadlines": upcoming,
        "dormant_large_balances": dormant,
        "pending_inputs": {"seeds": pending_seeds, "nodes": pending_nodes,
                           "asserted_transfers": sum(1 for t in transfers if t["asserted"]),
                           "unknown_amount_transfers": sum(1 for t in transfers if t["amount"] is None)},
        "candidates_without_stop_order": candidates_without_order,
        "draft_stop_orders": drafts,
        "sweep_imminent": sweep,
        "trace_next": [n["address"] for n in nodes if "trace_next" in n["flags"]],
        "unacknowledged_alerts": unack,
        "has_trace": bool(trace.get("run")),
    }


# --------------------------------------------------------------------------- summary
def _fact_candidate(c: dict, fp: dict) -> str:
    """'Freeze candidate Circle (USDC issuer) — stablecoin issuer, issuer blacklist: …' with the issuer's value as the
    trace leaves it (what moved on counts nothing: `_issuer_held`)."""
    value = _money(c["total_taint_usd"])
    if c.get("kind") == "issuer_blacklist":
        held = (fp.get("issuer_held_usd") or {}).get(c["entity"])
        if held is not None and held < 1 and (c.get("total_taint_usd") or 0) >= 1:
            value = (f"{_money(c['total_taint_usd'])} passed through, then moved on (nothing left at its wallets to "
                     "blacklist on the trace's evidence)")
        elif held is not None and held < (c.get("total_taint_usd") or 0) - 0.5:
            value = f"{_money(held)} still at its wallets ({_money(c['total_taint_usd'])} passed through)"
    return (f"Freeze candidate {c['entity']} — {category_text(c['category'])}, {kind_text(c['kind'])}: {value} "
            f"(priority {c['priority']}) [freeze_candidates]")


def _move_priority(m: dict) -> str:
    """A Recovery plan move as the summary's priority: money at stake with a clock passed or ≥ $1,000 is high, any
    money or a passed clock medium, the rest (a route to start, nothing traced there) low. The order stays the plan's."""
    value = m.get("value") or 0
    if value >= 1000 or (value >= 1 and m.get("clock_passed")):
        return "high"
    if value >= 1 or m.get("clock_passed"):
        return "medium"
    return "low"


def _next_text(text: str | None) -> str:
    """A next-action text without its leading 'Reply overdue:' (the deadline says it already)."""
    t = (text or "").strip()
    for lead in ("Reply overdue: ", "Reply overdue — "):
        if t.startswith(lead):
            t = t[len(lead):]
            return t[:1].upper() + t[1:]
    return t


def _request_deadlines(requests: list[dict]) -> list[dict]:
    """The requests waiting for an answer, as Block status shows them: overdue first, then by due date."""
    rows = [r for r in requests if r.get("waiting") and r.get("due")]
    rows.sort(key=lambda r: (not r.get("overdue"), r.get("due") or ""))
    out = []
    for r in rows:
        nxt = _next_text(r.get("next"))
        what = f"{r['authority']} — {r['title']}"
        if r.get("overdue"):
            why = f"OVERDUE — {r['label']}" + (f". Next: {nxt}" if nxt else "")
        else:
            why = f"{r['label']}" + (f". Next: {nxt}" if nxt else "")
        out.append({"what": what, "due": _date(r["due"]),
                    "why": why + (f" [stop_orders#{r['order_id']}]" if r.get("order_id") else " [block_status]")})
    return out


def rule_summary(ctx: dict, state: dict | None = None) -> dict:
    """A deterministic status summary in the CaseSummary shape.

    `state` (app.ai.casestate.case_state: the case's Block status rows and Recovery plan moves, as the Block status and
    Recovery plan pages show them) makes the deadlines, the open items and the next steps those pages' own: a reply
    state is Block status's (an acknowledgement is an answer, its next step a status request quoting their ticket),
    "overdue" is counted as Block status counts it (the team's own follow-up notes are named apart) and the next steps
    are the Recovery plan's moves in its order. Without it (no member to build them for) the summary reads the
    context alone."""
    d = ctx.get("derived") or {}
    fp = d.get("funds_position") or {}
    case = ctx.get("case") or {}
    trace = ctx.get("trace") or {}
    graph = trace.get("graph") or {}
    cands = ctx.get("freeze_candidates") or []
    orders = ctx.get("stop_orders") or []
    evidence = ctx.get("evidence_index") or []
    loss = case.get("loss") or {}
    state = state or {}
    requests = state.get("requests")
    moves = state.get("moves")

    sent = [o for o in orders if o["sent_at"]]
    internal_over = [x for x in d.get("overdue") or [] if x.get("internal")]
    key_facts = [
        (f"Loss: {qty(loss.get('amount'))} {loss.get('asset') or ''} ({_money(loss.get('usd'))}) on "
         f"{day(case.get('fraud_date'))} [case.loss]"),
    ]
    if d.get("has_trace"):
        run = trace["run"]
        data = "offline fixture data" if run.get("provider_mode") == "fixture" else "live chain data"
        key_facts.append(
            f"Latest trace (run #{run['id']}, {run['status']}, {data}): {graph.get('nodes', 0)} addresses over "
            f"{graph.get('max_hop', 0)} hops on {', '.join(graph.get('chains') or []) or 'no chain'}, "
            f"{graph.get('vasp_touchpoints', 0)} VASP touchpoints [trace.graph]")
    for c in cands[:5]:
        key_facts.append(_fact_candidate(c, fp))
    if case.get("complaints"):
        key_facts.append("Complaints filed with: " + "; ".join(
            f"{c['authority']}" + (f" ({day(c['filed_at'])})" if c.get("filed_at") else "")
            for c in case["complaints"]) + " [case.complaints]")
    if requests is not None:
        reqs = [r for r in requests if r.get("sent")]
        key_facts.append(f"Requests sent: {len(reqs)} ({sum(1 for r in reqs if r.get('waiting'))} waiting for an "
                         f"answer, {sum(1 for r in reqs if r.get('overdue'))} with the reply overdue) [block_status]")
    else:
        key_facts.append(f"Stop orders: {len(orders)} on file, {len(sent)} sent [stop_orders]")
    if evidence:
        folders: dict[str, int] = {}
        for e in evidence:
            label = folder_text(e["folder"])
            folders[label] = folders.get(label, 0) + 1
        key_facts.append("Evidence on file: " + ", ".join(f"{k} {v}" for k, v in sorted(folders.items()))
                         + " [evidence_index]")

    open_items: list[str] = []
    if requests is not None:
        for r in requests:
            if r.get("confirm"):
                open_items.append(f"{r['authority']} — {r['title']}: {r['label']} (to confirm) [block_status]")
            elif r.get("review"):
                open_items.append(f"{r['authority']} — {r['title']}: a reply to read [block_status]")
            elif r.get("our_action"):
                open_items.append(f"{r['authority']} — {r['title']}: {r['label']}"
                                  + (f"; next: {_next_text(r.get('next'))}" if r.get("next") else "") + " [block_status]")
            elif r.get("status") == "not_sent":
                open_items.append(f"{r['authority']} — {r['title']} is drafted, not sent yet [block_status]")
    else:
        for u in d.get("unanswered_stop_orders_over_7_days") or []:
            open_items.append(f"{u['entity']} has not answered the {_kind(u['kind'])} request sent {day(u['sent_at'])} "
                              f"({u['days_since_sent']} days) [stop_orders#{u['stop_order_id']}]")
        for o in d.get("draft_stop_orders") or []:
            open_items.append(f"Draft {_kind(o['kind'])} request to {o['entity']} not yet sent "
                              f"[stop_orders#{o['stop_order_id']}]")
        for name in d.get("candidates_without_stop_order") or []:
            open_items.append(f"No stop order on file for freeze candidate {name} [freeze_candidates]")
    pi = d.get("pending_inputs") or {}
    for s in pi.get("seeds") or []:
        open_items.append(f"Seed '{s['role'].replace('_', ' ')}' ({s['chain']}) is still a placeholder [seeds]")
    if d.get("unacknowledged_alerts"):
        open_items.append(f"{d['unacknowledged_alerts']} movement alert(s) not acknowledged [watch]")
    for h in d.get("holds_to_release") or []:
        open_items.append(f"Hold confirmed by {h['entity']}: no release request yet [stop_orders#{h['stop_order_id']}]")
    if d.get("engaged_outside_latest_trace") and d.get("has_trace"):
        open_items.append("Engaged earlier but not reached by the latest trace (run "
                          f"#{trace['run']['id']}): {', '.join(d['engaged_outside_latest_trace'])} [authorities]")

    deadlines = []

    def what(item: dict) -> str:
        if item.get("direction") == "note":
            return f"Internal follow-up task{' on ' + item['entity'] if item['entity'] else ''} (team note)"
        return f"{item['entity'] or 'Recipient'} reply ({_kind(item['kind'])})"

    def src(item: dict) -> str:
        return f"[{'stop_orders' if item['type'] == 'stop_order' else 'correspondence'}#{item['id']}]"

    def keep(item: dict) -> bool:  # with Block status, the requests come from its rows; only the team's notes from here
        return requests is None or bool(item.get("internal")) or item.get("direction") == "note"

    if requests is not None:
        deadlines += _request_deadlines(requests)
    for item in sorted(d.get("overdue") or [], key=lambda x: x["due"] or ""):
        if not keep(item):
            continue
        if item.get("internal"):
            why = f"Past its date: the team's own task, not a reply anybody owes us {src(item)}"
        else:
            why = f"OVERDUE — nothing recorded as done or answered {src(item)}"
        deadlines.append({"what": what(item), "due": _date(item["due"]), "why": why})
    for item in sorted(d.get("upcoming_deadlines") or [], key=lambda x: x["due"] or ""):
        if not keep(item):
            continue
        deadlines.append({"what": what(item), "due": _date(item["due"]), "why": f"Due date recorded {src(item)}"})
    for s in d.get("sweep_imminent") or []:
        deadlines.append({"what": f"Freeze at {s['entity'] or _short(s['address'])}", "due": "now",
                          "why": "Deposit within the service's typical sweep window [trace.nodes]"})

    steps: list[dict] = []
    if not d.get("has_trace"):
        steps.append({"action": "Run a trace from the case seeds", "owner_role": "investigator", "priority": "high",
                      "rationale": "No trace run exists, so no freeze candidates can be derived [trace]"})
    if moves is not None:
        # the Recovery plan's moves, in its order (the board and the To do list follow the same ranking)
        for m in moves[:12]:
            steps.append({"action": m["title"], "owner_role": "investigator", "priority": _move_priority(m),
                          "rationale": (m.get("reason") or "") + " [recovery_plan]",
                          "next": m.get("lead") or m.get("text") or "",
                          "rank": m.get("rank"), "key": m.get("key"), "value": m.get("value_fmt") or "—",
                          "clock": m.get("clock") or ""})
    else:
        steps += _context_steps(d, cands)
    for s in pi.get("seeds") or []:
        steps.append({"action": f"Supply the real {s['role'].replace('_', ' ')} ({s['chain']})", "owner_role": "investigator",
                      "priority": "medium", "rationale": "Placeholder seeds keep the origin hop unverifiable [seeds]"})
    if pi.get("asserted_transfers"):
        steps.append({"action": "Verify the asserted hops on-chain (live trace)", "owner_role": "investigator",
                      "priority": "medium",
                      "rationale": f"{pi['asserted_transfers']} transfers are asserted, not observed; amounts downstream "
                                   "are upper bounds [trace.tainted_transfers]"})
    if d.get("unacknowledged_alerts"):
        steps.append({"action": "Review and acknowledge the movement alerts", "owner_role": "investigator",
                      "priority": "high", "rationale": "Unreviewed movement may close a freeze window [watch]"})
    if moves is None:
        steps.sort(key=lambda x: PRIORITY_ORDER.get(x["priority"], len(PRIORITY_ORDER)))  # stable: high, medium, low

    risks: list[str] = []
    if d.get("sweep_imminent"):
        risks.append("Deposits within a sweep window: funds may be moved to omnibus wallets imminently [trace.nodes]")
    if d.get("dormant_large_balances"):
        risks.append(f"{_money(fp.get('dormant_self_custody_usd'))} sits in self-custody addresses that can move "
                     "without notice [derived.dormant_large_balances]")
    if requests is not None:
        if any(r.get("overdue") for r in requests):
            risks.append("Replies overdue: the recipient may not have applied a hold [block_status]")
    elif d.get("unanswered_stop_orders_over_7_days"):
        risks.append("Unanswered requests: the recipient may not have applied a hold [stop_orders]")
    if any("rapid_forward" in n["flags"] for n in trace.get("nodes") or []):
        risks.append("Rapid forwarding observed: the perpetrators move funds within minutes [trace.nodes]")

    gaps: list[str] = []
    if pi.get("asserted_transfers"):
        gaps.append(f"{pi['asserted_transfers']} tainted transfers are asserted (hash pending) [trace.tainted_transfers]")
    if pi.get("unknown_amount_transfers"):
        gaps.append(f"{pi['unknown_amount_transfers']} tainted transfers have no observed amount [trace.tainted_transfers]")
    for n in pi.get("nodes") or []:
        gaps.append(f"Placeholder address {_short(n['address'])}: real destination still to be supplied [trace.nodes]")
    if d.get("has_trace") and (trace["run"].get("provider_mode") == "fixture"):
        gaps.append("The latest trace ran on the offline fixture, not live chain data [trace.run]")
    if any(o["sent_at"] and not o["response_due_at"] for o in orders):
        gaps.append("Some sent stop orders have no response due date recorded [stop_orders]")
    if not evidence:
        gaps.append("No evidence items are indexed for this case [evidence_index]")

    based = fp.get("based_on_run") or {}
    if requests is not None:
        reqs = [r for r in requests if r.get("sent")]
        n_over = sum(1 for r in reqs if r.get("overdue"))
        asks = (f"{len(reqs)} requests sent: {sum(1 for r in reqs if r.get('waiting'))} waiting for an answer, "
                f"{n_over} with the reply overdue")
    else:
        n_unans = len(d.get("unanswered_stop_orders_over_7_days") or [])
        n_over = sum(1 for x in d.get("overdue") or [] if not x.get("internal"))
        asks = f"{len(sent)} stop orders sent ({n_unans} unanswered > 7 days, {n_over} overdue)"
    internal = (f"; {len(internal_over)} internal follow-up task{'s' if len(internal_over) != 1 else ''} past "
                f"{'their' if len(internal_over) != 1 else 'its'} date" if internal_over else "")
    status = (f"{_money(fp.get('traced_usd'))} traced of a {_money(fp.get('loss_usd'))} loss"
              + (f" (trace run #{based['run_id']})" if based.get("run_id") else "") + "; "
              f"{_money(fp.get('at_freezable_services_usd'))} reached freezable services, "
              f"{_money(fp.get('frozen_usd'))} frozen (recorded holds){_upper(fp)}. {len(cands)} freeze candidates, "
              f"{asks}{internal}.")
    if not d.get("has_trace"):
        status = "No trace run yet; run a trace to derive freeze candidates."
    unknown_bits = []
    if fp.get("dormant_self_custody_usd"):
        unknown_bits.append(f"{_money(fp['dormant_self_custody_usd'])} dormant in self-custody")
    if pi.get("asserted_transfers"):
        unknown_bits.append("asserted hops make downstream amounts upper bounds")
    if fp.get("frozen_upper_bound_usd"):
        unknown_bits.append(f"up to {_money(fp['frozen_upper_bound_usd'])} more may be frozen at recipients that "
                            "reported no amount (upper bound)")
    return {
        "status_summary": status,
        "key_facts": key_facts,
        "funds_position": {
            "traced_usd": fp.get("traced_usd"), "at_freezable_services_usd": fp.get("at_freezable_services_usd"),
            "frozen_usd": fp.get("frozen_usd"), "based_on_run": fp.get("based_on_run"),
            "unknown": "; ".join(unknown_bits) or "No unresolved positions identified by the rule checks.",
        },
        "open_items": open_items,
        "deadlines": deadlines,
        "next_steps": steps,
        "risks": risks,
        "data_gaps": gaps,
    }


def _context_steps(d: dict, cands: list[dict]) -> list[dict]:
    """The next steps read from the context alone (no Block status / Recovery plan to follow): chase the overdue
    replies, release confirmed holds, ask the candidates nobody asked yet, watch the dormant balances."""
    steps: list[dict] = []
    follow = {f["stop_order_id"]: f for f in d.get("status_request_due") or []}
    for u in d.get("unanswered_stop_orders_over_7_days") or []:
        f = follow.pop(u["stop_order_id"], None)
        if f is not None:  # past its response_due_at: the follow-up is a status request
            steps.append({"action": f"Chase {u['entity']}: {_send_status(f)} on the {_kind(u['kind'])} request "
                                    f"(stop order #{u['stop_order_id']})", "owner_role": "investigator",
                          "priority": "high",
                          "rationale": f"Sent {u['days_since_sent']} days ago; the reply was due {day(f['due'])} and "
                                       f"none is recorded [stop_orders#{u['stop_order_id']}]"})
            continue
        steps.append({"action": f"Chase {u['entity']} on the {_kind(u['kind'])} request (stop order #{u['stop_order_id']})",
                      "owner_role": "investigator", "priority": "high",
                      "rationale": f"Sent {u['days_since_sent']} days ago with no response [stop_orders]"})
    for f in follow.values():  # overdue within the first week (a short reply deadline), or acknowledged only
        steps.append({"action": f"{_send_status(f).capitalize()} to {f['entity']} on the {_kind(f['kind'])} request "
                                f"(stop order #{f['stop_order_id']})", "owner_role": "investigator",
                      "priority": "high",
                      "rationale": f"The reply was due {day(f['due'])} and no answer to the request is recorded "
                                   f"[stop_orders#{f['stop_order_id']}]"})
    for h in d.get("holds_to_release") or []:
        held = h.get("hold") or {}
        amount = f"{held['amount']} {held.get('asset') or ''}".strip() if held.get("amount") else "the funds"
        steps.append({"action": f"Send a release / return-of-funds request to {h['entity']} "
                                f"(stop order #{h['stop_order_id']})", "owner_role": "investigator",
                      "priority": "high",
                      "rationale": f"{h['entity']} confirmed a hold of {amount}; no release request is on file "
                                   f"[stop_orders#{h['stop_order_id']}]"})
    by_name = {c["entity"]: c for c in cands}
    held_by = (d.get("funds_position") or {}).get("issuer_held_usd") or {}
    for name in d.get("candidates_without_stop_order") or []:
        c = by_name.get(name) or {}
        value = held_by.get(name, c.get("total_taint_usd")) if c.get("kind") == "issuer_blacklist" else \
            c.get("total_taint_usd")
        steps.append({"action": f"Ask {name} ({_kind(c.get('kind'))})",
                      "owner_role": "investigator", "priority": "high" if (c.get("priority") or 0) >= 50
                      and (value or 0) >= 1 or (value or 0) >= 10000 else "medium",
                      "rationale": f"{_money(value)} of traced funds at it [freeze_candidates]"})
    for dm in d.get("dormant_large_balances") or []:
        if dm["pending_input"]:
            continue
        steps.append({"action": f"Monitor and extend the trace from dormant {_short(dm['address'])} ({dm['chain']})",
                      "owner_role": "investigator", "priority": "high",
                      "rationale": f"{_money(dm['taint_usd'])} of tainted value with no onward movement observed; "
                                   "it can move at any time [derived.dormant_large_balances]"})
    return steps


# --------------------------------------------------------------------------- Q&A
_TOPICS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("status", "summary", "summarise", "summarize", "overview", "situation", "where are we", "update"), "status"),
    (("deadline", "due", "overdue", "late", "chase", "answer", "respond", "reply"), "deadlines"),
    (("fund", "money", "usd", "balance", "where", "frozen", "freeze", "traced", "position"), "funds"),
    (("next", "should", "todo", "to do", "action", "priority", "plan"), "next_steps"),
    (("risk", "danger", "sweep", "move"), "risks"),
    (("gap", "missing", "unknown", "pending", "verify", "assert"), "data_gaps"),
)


def rule_answer(ctx: dict, question: str, *, reason: str | None = None, label: str = RULE_LABEL,
                state: dict | None = None, header: bool = True) -> str:
    """A deterministic answer: the rule summary section(s) matching the question's keywords. `state`: as
    rule_summary. `header`: open with the label in brackets (the chat shows the label above the message instead)."""
    s = rule_summary(ctx, state)
    q = (question or "").lower()
    topics = [t for words, t in _TOPICS if any(w in q for w in words)] or ["status"]
    if header:
        lines = [f"[{label}]" + (f" {reason}" if reason else ""),
                 "This answer comes from fixed checks over the case data, not from a language model."]
    else:
        lines = ["_This answer comes from Aegis's fixed checks over the case data, not from a language model"
                 + (f" ({reason[:1].lower() + reason[1:].rstrip('.')})" if reason else "") + "._", ""]
    for t in topics:
        if t == "deadlines":
            over = [x for x in s["deadlines"] if x["why"].startswith("OVERDUE")]
            rest = [x for x in s["deadlines"] if not x["why"].startswith("OVERDUE")]
            lead = (f"{len(over)} overdue" if over else "None overdue") + (
                f"; {len(rest)} upcoming or open" if rest else "; nothing else due")
            lines.append(f"Deadlines: {lead}. [derived.overdue]")
            lines += [f"- {x['what']}: {x['due']} — {x['why']}" for x in over + rest]
        elif t == "funds":
            fp = s["funds_position"]
            run_note = f" Based on trace run #{fp['based_on_run']['run_id']}." if fp.get("based_on_run") else ""
            lines.append(f"Funds: traced {_money(fp['traced_usd'])}; at freezable services "
                         f"{_money(fp['at_freezable_services_usd'])}; frozen {_money(fp['frozen_usd'])} "
                         f"(recorded holds).{run_note} {fp['unknown']} "
                         "[derived.funds_position]")
        elif t == "next_steps":
            lines.append("Next steps:")
            lines += [f"- ({x['priority']}, {x['owner_role']}) {x['action']} — {x['rationale']}"
                      for x in s["next_steps"]] or ["- none identified"]
        elif t == "risks":
            lines.append("Risks:")
            lines += [f"- {x}" for x in s["risks"]] or ["- none identified"]
        elif t == "data_gaps":
            lines.append("Data gaps:")
            lines += [f"- {x}" for x in s["data_gaps"]] or ["- none identified"]
        elif t == "status":
            fp = s["funds_position"]
            lines.append(f"Status: {s['status_summary']}")
            lines.append(f"Funds: traced {_money(fp['traced_usd'])}; at freezable services "
                         f"{_money(fp['at_freezable_services_usd'])}; frozen {_money(fp['frozen_usd'])} "
                         "(recorded holds) [derived.funds_position]")
            if len(topics) == 1:
                lines += [f"- {x}" for x in s["key_facts"]]
                if s["next_steps"]:
                    lines.append("Next moves (the Recovery plan's order):" if state and state.get("moves") is not None
                                 else "Next steps:")
                    lines += [f"- {x['action']}" + (f": {x['next']}" if x.get("next") else "")
                              for x in s["next_steps"][:5]]
    return "\n".join(lines)
