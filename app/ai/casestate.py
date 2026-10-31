"""The case's live state as the rest of the app shows it, for the assistant's rule-based answers.

    state = case_state(db, case, access)     # {"requests", "moves", "waiting", "totals", "failed"}
    clean = reply_cleaner(db, case, rows)     # text -> text: names and reply details masked (shown vs sent)

/summary, /next-steps and the free-text fallback read the same sources as the Block status page (app.blocks.status:
each request's reply state, "overdue", its next action) and the Recovery plan (app.blocks.recovery: the ranked moves,
whose provider steps are the freeze & stop-order board's rows), so the assistant never contradicts them: an
acknowledgement counts as an answer (its next step a status request quoting their ticket), overdue is counted as Block
status counts it, and the next moves come in the plan's order.

Every text here is *marked* (app.ai.context.masked): a name the redactor would replace, and what a reply says (their
ticket, the URLs, wallets and ids it names) while "AI reads mailbox replies" is off, carries both the real value (the
member's screen) and the placeholder (the model). Resolve with app.ai.context.unmask before showing or sending.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.ai.context import mask_terms, masked, redactor_for
from app.ai.display import first_sentence

log = logging.getLogger(__name__)


def reply_terms(rows: list) -> dict[str, str]:
    """What the requests' replies say beyond their status (block rows: their tickets, the URLs, wallets, accounts and
    order ids they name), value -> placeholder: masked for the model unless a case admin switched on "AI reads mailbox
    replies" (app.blocks.classify_ai)."""
    terms: dict[str, str] = {}
    for r in rows:
        for t in [r.ticket, *(rv.ticket for rv in r.replies)]:
            if t:
                terms[t] = "[THEIR_TICKET]"
        for rv in r.replies:
            for u in rv.urls:
                if u.get("value"):
                    terms[u["value"]] = "[URL_FROM_REPLY]"
        intel = r.intel
        for i in intel.get("identifiers") or []:  # wallets / UIDs / tx a reply names, in full and shortened
            val = i.get("value") or ""
            if val and not i.get("known"):
                ph = "[ID_FROM_REPLY]" if i.get("kind") in ("account", "order_id") else "[WALLET_FROM_REPLY]"
                terms[val] = ph
                if len(val) > 14:
                    terms[f"{val[:6]}…{val[-4:]}"] = ph
        for c in intel.get("channels") or []:
            if c.get("value"):
                terms[c["value"]] = "[URL_FROM_REPLY]"
        for t in intel.get("tickets") or []:
            if t.get("value"):
                terms[t["value"]] = "[THEIR_TICKET]"
        sug = r.suggestion
        if sug is not None and sug.get("amount") and sug.get("source") != "onchain":
            # the amount a reply states, in a suggested outcome ("suggests Frozen (12,633.77 USDT)")
            from app.blocks import status as bs

            terms[bs.suggestion_text(sug)] = bs.suggestion_text(sug, amount=False) + " (amount stated in the reply)"
    return terms


def reply_cleaner(db: Session, case: Any, rows: list) -> Callable[[str | None], str]:
    """text -> marked text: the case's redactor (marking) over it, after the replies' details (`reply_terms`) while the
    model may not read replies."""
    from app.blocks import classify_ai

    red = redactor_for(db, case, marking=True)
    terms = {} if classify_ai.is_enabled(case) else reply_terms(rows)

    def clean(text: str | None) -> str:
        return red(mask_terms(text or "", terms)) or ""

    return clean


def status_text(r: Any, replies_ok: bool, clean: Callable[[str | None], str]) -> str:
    """A block row's status as Block status shows it, marked (`clean`: reply_cleaner): the amount a reply states (in a
    status read from it, or in a suggested outcome) goes to the model only while it may read replies."""
    from app.blocks import status as bs

    shown = r.status_text if r.status != "redirected" else r.label
    if replies_ok:
        return clean(shown)
    sent = shown
    if r.source in ("rules", "ai") and r.amount:
        sent = f"{r.label} (amount stated in the reply)"
    if r.suggestion is not None and r.suggestion.get("source") != "onchain":
        sent = (f"{r.label} — suggests {bs.suggestion_text(r.suggestion, amount=False)}, needs confirmation"
                + (" (amount stated in the reply)" if r.suggestion.get("amount") else ""))
    return clean(shown) if sent == shown else masked(clean(shown), clean(sent))


def _iso(v: datetime | None) -> str | None:
    if v is None:
        return None
    v = v if v.tzinfo else v.replace(tzinfo=UTC)
    return v.astimezone(UTC).isoformat().replace("+00:00", "Z")


def case_state(db: Session, case: Any, access: Any, *, now: datetime | None = None) -> dict:
    """{"requests": [...], "moves": [...], "waiting": [...], "totals": {...}, "failed": [...]}, marked (module doc).

    requests: one per Block status row (letters and stop orders; no on-chain-only or Outlook rows): {authority, title,
    order_id, kind, status, label, overdue, due, waiting, sent, our_action, review, confirm, next}. moves: the Recovery
    plan's ranked moves as the member sees them on the plan (rp.view): {rank, key, title, text, reason, value,
    value_fmt, clock, clock_passed}; a move built from what a reply names travels to the screen only while the model
    may not read replies. `access` None (no member): requests only."""
    from app.blocks import classify_ai
    from app.blocks import recovery as rp
    from app.blocks import status as bs

    now = now or datetime.now(tz=UTC)
    out: dict[str, Any] = {"requests": None, "moves": None, "waiting": [], "totals": {}, "failed": []}
    try:
        rows = bs.case_blocks(db, case, now=now)
    except Exception as err:  # noqa: BLE001 - the answer falls back to the context alone
        log.warning("assistant: block status failed for case %s (%s)", case.id, type(err).__name__)
        out["failed"].append("block_status")
        return out
    replies_ok = classify_ai.is_enabled(case)
    clean = reply_cleaner(db, case, rows)
    reqs = []
    for r in rows:
        if r.kind in ("onchain", "outlook"):
            continue
        reqs.append({
            "authority": clean(r.authority.name), "title": r.title, "order_id": r.order.id if r.order else None,
            "kind": r.kind, "status": r.status, "label": status_text(r, replies_ok, clean), "overdue": bool(r.overdue),
            "due": _iso(r.due_at), "waiting": r.status in bs.WAITING and r.status != bs.NOT_SENT,
            "sent": r.status != bs.NOT_SENT, "our_action": r.status in bs.OUR_ACTION, "review": bool(r.needs_review),
            "confirm": bool(r.needs_confirmation), "next": clean((r.next_action or {}).get("text")),
        })
    out["requests"] = reqs
    if access is None:
        return out
    try:
        plan = rp.build(db, case, now=now)
        v = rp.view(plan, access)
    except Exception as err:  # noqa: BLE001 - the next steps fall back to the context alone
        log.warning("assistant: recovery plan failed for case %s (%s)", case.id, type(err).__name__)
        out["failed"].append("recovery_plan")
        return out
    hidden = set() if replies_ok else {m.key for m in plan.moves + plan.waiting if m.sensitive}

    def only_shown(text: str, key: str) -> str:  # a move from what a reply names: never to the model
        return masked(text, "") if key in hidden and text else text

    moves = []
    for m in v["moves"]:
        clock = f"{m['clock']['label']} {m['clock']['due_fmt']}" if m["clock"] else ""
        text = clean(m["text"])
        moves.append({"rank": m["rank"], "key": m["key"], "title": only_shown(clean(m["title"]), m["key"]),
                      "text": only_shown(text, m["key"]), "lead": only_shown(first_sentence(text), m["key"]),
                      "reason": only_shown(clean(m["reason"]), m["key"]), "value": m["value"],
                      "value_fmt": m["value_fmt"], "clock": clock,
                      "clock_passed": bool(m["clock"] and m["clock"].get("passed"))})
    out["moves"] = moves
    out["waiting"] = [{"title": only_shown(clean(m["title"]), m["key"]), "text": only_shown(clean(m["text"]), m["key"]),
                       "clock": f"{m['clock']['label']} {m['clock']['due_fmt']}" if m["clock"] else ""}
                      for m in v["waiting"]]
    out["totals"] = v["totals"]
    out["notes"] = [clean(n) for n in v["notes"]]
    out["hidden"] = sorted(hidden)
    return out


__all__ = ["case_state", "reply_cleaner", "reply_terms", "status_text"]
