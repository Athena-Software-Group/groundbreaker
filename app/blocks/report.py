"""The Block status page data and its exports (.md / .csv / .docx), as one member may see them.

    v = page_view(db, access, status="open", kind=None, authority_type=None, overdue=False, review=False)
    body, media, filename = export(db, access, "md" | "csv" | "docx")

What each role sees (the rules of the authorities desk): read-only members see every request, its
status, dates and next action, but LE / PI contact details masked (`desk.contact_mask`) and no reply
quotes (a reply is R3: `view_restricted`, investigators and up). The exports follow the same rules and
are meant for law enforcement or a PI firm: they say which statuses a person confirmed and which were
only read from a reply (advisory). E-mails sent from Outlook that the mailbox sync could not tie to one
letter ("Sent from Outlook — needs review") are on the page for the team to resolve, but never in an
export: they are not requests until a person ties them to one (the .md export counts them). CSV cells
that a spreadsheet would run as a formula are prefixed with an apostrophe (reply text is untrusted).
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.blocks import classify_ai
from app.blocks import classify_rules as rules
from app.blocks import extract as ex
from app.blocks import path as pathmod
from app.blocks import status as bs
from app.domain import correspondence as desk
from app.reports.stop_orders import _docx_document, md_escape

DOCX_MEDIA = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
FILTERS = {
    "all": "All requests",
    "open": "Open (waiting / to act on)",
    "action": "Needs action (confirm, review, overdue, resend)",
    "resolved": "Resolved (frozen, returned, declined)",
    "not_sent": "Not sent",
}
SOURCE_TEXT = {"recorded": "recorded on the stop order", "human": "confirmed by a team member",
               "ai": "read from the reply (rules + AI, advisory)", "rules": "read from the reply (rules, advisory)",
               "onchain": "read on-chain (issuer blacklist)", "resent": "sent again after their reply",
               "le_route": "LE briefed after their reply (linked LE brief)", "none": ""}
DISCLAIMER = ("Statuses marked 'read from the reply' are Aegis's reading and advisory until a team member confirms "
              "them; 'recorded on the stop order' and 'confirmed' statuses were set by a person. Aegis never reports a "
              "hold, freeze or return by itself: one read from a reply or on-chain is shown as a suggestion until a "
              "person confirms it, and the held / frozen totals count confirmed outcomes only.")


def _fmt_dt(v: datetime | None) -> str:
    return v.astimezone(UTC).strftime("%d %b %Y %H:%M UTC") if v else "—"


def _fmt_day(v: datetime | None) -> str:
    return v.astimezone(UTC).strftime("%d %b %Y") if v else "—"


def _filter(rows: list[bs.BlockRow], status: str | None) -> list[bs.BlockRow]:
    if not status or status == "all":
        return rows
    if status == "open":
        return [r for r in rows if r.status in bs.WAITING]
    if status == "action":
        return [r for r in rows if r.needs_confirmation or r.needs_review or r.overdue
                or r.status in (rules.REDIRECTED, rules.DELIVERY_FAILED, rules.INFO_REQUESTED, rules.LE_PROCESS_REQUIRED,
                                bs.NOT_SENT)]  # an Outlook e-mail to review: needs_review (never a probable copy)
    if status == "resolved":
        return [r for r in rows if r.status in bs.RESOLVED]
    if status in bs.BLOCK_STATUSES:
        return [r for r in rows if r.status == status]
    return rows


def tie_options(db: Session, case, row: bs.BlockRow) -> list[tuple[str, str]]:
    """For a "Sent from Outlook — needs review" row: the letters it may have carried (app.mail.sync_outbound
    .tie_candidates: the sync's candidates first, never one another e-mail already carries), as (key, label)."""
    from app.mail import sync_outbound

    if row.kind != "outlook" or row.letter is None:
        return []
    try:
        mm = sync_outbound.review_row_for_entry(db, case, row.letter.id)
    except sync_outbound.ReviewError:
        return []
    out = []
    for x in sync_outbound.tie_candidates(db, mm)[:20]:
        if x.corr is not None and x.order is not None and x.corr.kind.value == "stop_order":
            what = f"Stop order #{x.order.id}"
        elif x.corr is not None:
            what = f"{bs.KIND_LABELS.get(x.corr.kind.value, 'Letter')} #{x.corr.id}"
            if x.corr.stop_order_id:
                what += f" (stop order #{x.corr.stop_order_id})"
        else:
            what = f"Stop order #{x.order.id}"
        out.append((x.id, f"{what} — {'not sent' if x.is_draft else 'sent'}"))
    return out


_WATCH_CHAIN = {"tron": "tron", "evm": "ethereum"}


def intel_view(row: bs.BlockRow, access, case, mask, watched: set[str] | None = None) -> dict | None:
    """What the replies say beyond their status (app.blocks.extract via BlockRow.intel) as this member may see it:
    every member sees the ticket, the instrument, the asks and the deadlines (no quotes); with view_restricted the
    quotes, the channels, the identifiers (each new wallet with its one-click freeze-watch proposal) and, unless LE /
    PI contacts are masked, the contacts (with their "add as LE contact" proposal). None when there is nothing."""
    x = row.intel
    quotes = access.can("view_restricted")
    q = (lambda v: mask.text(v) if quotes and v else None)

    def day(v: str | None) -> str | None:
        try:
            return datetime.fromisoformat(v).strftime("%d %b %Y") if v else None
        except ValueError:
            return None

    def due_fmt(d: dict) -> str:
        if d.get("ambiguous"):
            a, b = (day(c) for c in d.get("candidates") or [None, None])
            return f"{a} or {b}?"
        if not d.get("due"):
            return "—"
        dt = datetime.fromisoformat(d["due"])
        return dt.strftime("%d %b %Y") if d.get("date") else _fmt_dt(dt if dt.tzinfo else dt.replace(tzinfo=UTC))

    ins = x["instrument"]
    out = {
        "tickets": [{"value": t["value"], "system": t.get("system"), "source": t.get("source", "rules")}
                    for t in x["tickets"]],
        "instrument": ({"label": ins["label"], "type": ins["type"], "jur": list(ins.get("issuer_jurisdictions") or []),
                        "jur_from": ins.get("jurisdictions_from"), "via": ins.get("via"), "quote": q(ins.get("quote")),
                        "ai_label": (x["ai_instrument"] or {}).get("label")} if ins else None),
        "asks": [{"label": a["label"], "kind": a["kind"], "req_key": a["req_key"], "quote": q(a.get("quote")),
                  "source": a.get("source", "rules")} for a in x["asks"]],
        "deadlines": [{"label": d["label"], "what": d["what"], "due_fmt": due_fmt(d), "ambiguous": d.get("ambiguous"),
                       "auto": d.get("auto"), "approx": d.get("approx"), "starts": d.get("starts"),
                       "suggestion": bool(d.get("suggestion") or d.get("ambiguous")), "quote": q(d.get("quote")),
                       "source": d.get("source", "rules")} for d in x["deadlines"]],
        "contacts": [], "identifiers": [], "channels": [], "disagree": list(x["disagree"]),
        "can_watch": access.can("edit"), "can_contact": access.can("manage_le_contacts"),
        "can_trace": access.can("run_trace"),
    }
    if quotes:
        if not mask.party:
            out["contacts"] = [{**{k: c.get(k) for k in ("agency", "name", "role", "email", "phone", "reference",
                                                          "system")},
                                "quote": q(c.get("quote")), "source": c.get("source", "rules"),
                                "agency_default": c.get("agency") or row.authority.name,
                                "note": f"named in reply c{c['reply_id']}"} for c in x["contacts"]]
        for i in x["identifiers"]:
            watched_now = ex_norm(i["value"]) in (watched or set())
            out["identifiers"].append({**{k: i.get(k) for k in ("kind", "chain", "value", "known")},
                                       "watch": bool(i.get("watch")) and not watched_now, "watched": watched_now,
                                       "watch_chain": _WATCH_CHAIN.get(i.get("chain") or ""),
                                       "source_note": f"named in reply c{i['reply_id']}",
                                       "source": i.get("source", "rules")})
        out["channels"] = [{"value": mask.value(c["value"]) if mask.party else c["value"],
                            "class": c["class"], "class_label": ex.CLASS_LABELS.get(c["class"], c["class"]),
                            "le_only": c.get("le_only"), "tenant": c.get("tenant"), "org": c.get("org"),
                            "pick": c.get("pick")} for c in x["channels"]]
    out["any"] = any(out[k] for k in ("tickets", "instrument", "asks", "deadlines", "contacts", "identifiers",
                                       "channels"))
    return out if out["any"] else None


def path_view(row: bs.BlockRow, access, mask) -> dict | None:
    """The request's path step (app.blocks.path) as this member may see it: LE / counsel names through the contact
    mask, like the next action."""
    st = row.path
    if st is None or st.step is None:
        return None
    route = st.route or {}
    ins = st.instrument or {}
    sug = st.suggests_label
    return {"step": st.step, "label": st.label, "outcome": st.outcome,
            # "suggests frozen" (never "suggests Outcome: frozen")
            "suggests": sug.removeprefix("Outcome: ") if sug else None,
            # the instrument LE would send; "requires" only when the provider acts on LE process only (its reply or
            # its playbook says so: pathmod.le_only), the same reading as the Recovery plan's likelihood line
            "instrument": ins.get("label"), "requires": ins.get("label") if pathmod.le_only(st, row.playbook) else None,
            "jur": list(ins.get("issuer_jurisdictions") or []),
            "route": route.get("kind"), "route_text": mask.text(route.get("text")) if route.get("text") else None,
            "le": mask.text(st.le.name) if st.le is not None else None, "handoff": st.handoff,
            "evidence": [e["label"] for e in st.evidence],
            "links": [{"id": x["id"], "authority": mask.text(x["authority"]), "sent": x["sent"],
                       "at_fmt": _fmt_day(x["at"]) if x.get("at") else None} for x in st.links],
            "confirmed": ({"step": st.confirmed.get("step"), "outcome": st.confirmed.get("outcome"),
                           "at": st.confirmed.get("at")} if st.confirmed else None),
            "can_step": access.can("log_correspondence"),
            "steps": [(k, pathmod.STEP_LABELS[k]) for k in pathmod.CONFIRM_STEPS if k != "outcome"],
            "outcomes": [(k, pathmod.OUTCOMES[k]) for k in pathmod.CONFIRM_OUTCOMES]}


def ex_norm(v: str) -> str:
    return ex.norm_id(v).lower()


def row_view(row: bs.BlockRow, access, case, tie: list[tuple[str, str]] | None = None,
             watched: set[str] | None = None) -> dict:
    """A row as this member may see it (masked contacts, quotes only with view_restricted)."""
    mask = desk.contact_mask(access, row.authority)
    quotes = access.can("view_restricted")
    d = row.deciding
    replies = []
    for r in row.replies:
        replies.append({
            "id": r.corr.id, "at": r.at, "at_fmt": _fmt_dt(r.at), "status": r.status, "label": r.label,
            "source": r.source, "confidence": r.confidence, "quote": mask.text(r.quote) if quotes and r.quote else None,
            "ticket": r.ticket, "needs_review": r.needs_review, "note": r.note, "suggestion": r.suggestion,
            "outcome_suggestion": _sug_view(r.outcome_suggestion, mask, quotes),
            "suggestion_label": rules.LABELS.get(r.suggestion) if r.suggestion else None,
            "untrusted": r.untrusted, "sender_domain_ok": r.sender_domain_ok, "suspicious": r.suspicious,
            "risky": r.risky, "disputed": r.disputed,
            "subject": mask.text(r.corr.subject) if quotes else None,
            "addresses": [mask.value(a["value"]) for a in r.addresses] if quotes or not mask.party else [],
            "ai": ({"status": r.ai.get("status"), "label": rules.LABELS.get(r.ai.get("status"), r.ai.get("status")),
                    "verified": bool(r.ai.get("quote")), "quote_dropped": bool(r.ai.get("quote_dropped")),
                    "quote_blocked": bool(r.ai.get("quote_blocked")),
                    "model": r.ai.get("served_model") or r.ai.get("model"),
                    "rationale": mask.text(r.ai.get("rationale")) if quotes else None} if r.ai else None),
            "human": r.human, "href": f"/cases/{case.id}/authorities/{row.authority.key}#c{r.corr.id}",
        })
    status_text = row.status_text
    detail = row.detail
    next_text = row.next_action.get("text") or ""
    if mask.active:
        status_text, next_text, detail = mask.text(status_text), mask.text(next_text), mask.text(detail)
        if mask.party:
            for addr in dict.fromkeys([x for x in [row.resend_to, *row.to] if x]):
                masked = str(mask.value(addr))
                status_text, next_text = status_text.replace(addr, masked), next_text.replace(addr, masked)
                detail = detail.replace(addr, masked) if detail else detail
    oc = None
    if row.onchain:
        oc = {"frozen": row.onchain.get("frozen") or [], "lever": row.onchain.get("unfrozen_balance") or [],
              "lifted": row.onchain.get("lifted") or [], "moved": row.onchain.get("moved") or [],
              "enabled": row.onchain.get("enabled")}
    # never the AI's reading of a suspicious or disputed reply: the rules' reading, or unclear (the AI's shows
    # as text with a warning)
    risky = bs.risky_reply(row)  # the deciding reply, or a later one (the same rule as bs.confirm's tick)
    confirm_status = d.confirm_status if d is not None else row.status
    if confirm_status and confirm_status not in bs.CONFIRMABLE:
        confirm_status = rules.UNCLEAR if risky is not None else rules.ACKNOWLEDGED
    # a person chooses every positive outcome: nothing is preselected for one, nor while one is suggested, and the
    # amount field is never prefilled (the suggested amount is shown next to it as text)
    if row.suggestion is not None or confirm_status in bs.POSITIVE:
        confirm_status = ""
    sug = _sug_view(row.suggestion, mask, quotes)
    sug_reply = row.suggestion_reply
    to = [str(v) for v in mask.values(row.to)]
    if not to and row.order is not None and row.requested_at is not None:
        # an imported / portal request without an e-mail address: who it went to, as the stop order records it
        # ("Compliance / Legal Team (named contact on file …)": the part before its note)
        named = str((row.order.identifiers or {}).get("recipient") or "").split(" (")[0].strip()
        if named:
            to = [mask.text(named[:80])]
    source_text = SOURCE_TEXT.get(row.source, row.source)
    if row.resent and row.resent_at:
        source_text = f"resent {_fmt_day(row.resent_at)}" + (f" to {', '.join(to)}" if to else "") + " after their reply"
        if d is not None:
            source_text += f" ({d.label.lower()})"
    if row.status == bs.SENT_REVIEW:
        source_text = "found in the mailbox's Sent Items" + (
            f": {(row.review or {}).get('reason')}" if (row.review or {}).get("reason") else "")
    return {
        "key": row.key, "authority": {"key": row.authority.key, "name": row.authority.name,
                                      "type": row.authority.type_label, "category": row.authority.category},
        "request": row.title, "kind": row.kind, "kind_label": row.kind_label,
        # the kind shown next to the request only when the title does not already say it
        "kind_note": None if row.kind in ("stop_order", "onchain") or row.title.startswith(row.kind_label)
        else row.kind_label,
        "href": (f"/cases/{case.id}/stop-orders/{row.order.id}" if row.order is not None else
                 f"/cases/{case.id}/authorities/correspondence/{row.letter.id}" if row.letter is not None else
                 f"/cases/{case.id}/authorities/{row.authority.key}"),
        "sent": row.requested_at, "sent_fmt": _fmt_dt(row.requested_at), "channel": row.channel,
        "to": to, "first_to": [str(v) for v in mask.values(row.first_to)],
        "last_outbound": row.last_outbound_at, "last_outbound_fmt": _fmt_dt(row.last_outbound_at),
        "resent": row.resent, "resent_at": row.resent_at, "resent_fmt": _fmt_day(row.resent_at),
        "last_reply": replies[-1] if replies else None, "replies": replies,
        "status": row.status, "label": row.label, "status_text": status_text, "detail": detail, "tone": row.tone,
        "source": row.source, "source_text": source_text, "recorded": row.recorded,
        "quote": (mask.text(d.quote) if quotes and d is not None and d.quote else None),
        "amount": row.amount, "amount_fmt": bs.fmt_amount(row.amount, row.asset) if row.amount else None,
        "asset": row.asset,
        "ticket": row.ticket, "days_waiting": row.days_waiting, "due": row.due_at, "due_fmt": _fmt_day(row.due_at),
        "overdue": row.overdue, "needs_confirmation": row.needs_confirmation, "needs_review": row.needs_review,
        # the "to confirm" tag next to the status text, unless the text already says it (a suggested outcome)
        "confirm_tag": row.needs_confirmation and not row.confirm_in_text,
        "applied": row.applied, "proposal": row.proposal,
        "next_action": {**row.next_action, "text": next_text}, "onchain": oc,
        "intel": intel_view(row, access, case, mask, watched),
        "next_deadline": ({"label": row.next_deadline["label"], "due": row.next_deadline["due_at"],
                           "due_fmt": _fmt_dt(row.next_deadline["due_at"]), "action": row.next_deadline.get("action"),
                           "source": row.next_deadline.get("source")} if row.next_deadline else None),
        "hold_expires": row.hold_expires_at, "hold_expires_fmt": _fmt_dt(row.hold_expires_at),
        "path": path_view(row, access, mask),
        # an Outlook e-mail under review is not a request until a person ties it to a letter: no Confirm status
        "can_confirm": row.kind not in ("onchain", "outlook") and access.can("log_correspondence")
                       and (d is not None or (row.order is not None and access.can("manage_case"))),
        "can_apply": row.order is not None and access.can("manage_case"),
        "outlook": ({"action": f"/cases/{case.id}/blocks/{row.key}/outlook", "letters": tie or []}
                    if row.kind == "outlook" and access.can("send_letter") else None),
        "suggestion": sug, "suggestion_text": mask.text(row.suggestion_text) if row.suggestion else None,
        "confirm_default": {"status": confirm_status,
                            # the reply that suggests the outcome (else the deciding one)
                            "reply_id": (sug_reply.corr.id if sug_reply is not None else d.corr.id if d is not None
                                         else None),
                            "amount": "", "asset": "",
                            "amount_hint": (f"{bs.fmt_amount(sug['amount'], sug['asset'])} {sug['asset'] or ''}".strip()
                                            if sug and sug.get("amount") else None),
                            "risky": risky is not None,
                            "ai_reading": (rules.LABELS.get(risky.suggestion, risky.suggestion)
                                           if risky is not None and risky.suggestion else None),
                            "rules_reading": (rules.LABELS.get(risky.rules_held, risky.rules_held)
                                              if risky is not None and risky.rules_held else None),
                            "why": (None if risky is None else
                                    f"{'the reply' if risky is d else f'their reply of {_fmt_dt(risky.at)}'} "
                                    "contains text addressed to an AI / assistant" if risky.suspicious else
                                    "the rules and the AI read "
                                    f"{'this reply' if risky is d else f'their reply of {_fmt_dt(risky.at)}'} "
                                    "differently")},
    }


def _sug_view(sug: dict | None, mask, quotes: bool) -> dict | None:
    """A suggested outcome as this member may see it: its quote (and the amount it states) only with view_restricted;
    the warnings always (they quote nothing)."""
    if not sug:
        return None
    # (the amount shows as the status text shows it to every member; the quote only with view_restricted)
    return {"status": sug.get("status"), "label": sug.get("label") or bs.LABELS.get(sug.get("status")),
            "text": bs.suggestion_text(sug), "source": sug.get("source"),
            "source_text": {"rules": "read by the rules", "ai": "read by the AI", "onchain": "read on-chain"}.get(
                sug.get("source"), sug.get("source")),
            "quote": mask.text(sug.get("quote")) if quotes and sug.get("quote") else None,
            "amount": sug.get("amount"), "asset": sug.get("asset"),
            "warnings": list(sug.get("warnings") or [])}


def page_view(db: Session, access, *, status: str | None = None, authority_type: str | None = None,
              overdue: bool = False, review: bool = False, for_export: bool = False) -> dict:
    case = access.case
    all_rows = bs.case_blocks(db, case)
    n_outlook = sum(1 for r in all_rows if r.kind == "outlook")
    summary = bs.summary(all_rows)  # the same counts on the page, the exports and /block-status
    if for_export:  # not requests (module doc): counted, never listed
        all_rows = [r for r in all_rows if r.kind != "outlook"]
    rows = _filter(all_rows, status)
    if authority_type:
        rows = [r for r in rows if r.authority.category == authority_type]
    if overdue:
        rows = [r for r in rows if r.overdue]
    if review:
        rows = [r for r in rows if r.needs_review or r.needs_confirmation]
    types = sorted({(r.authority.category, r.authority.type_label) for r in all_rows}, key=lambda t: t[1].lower())
    ai = classify_ai.setting(case)
    if ai.get("by"):
        from app.db.models import User

        who = db.get(User, int(ai["by"])) if str(ai["by"]).isdigit() else None
        ai = {**ai, "by_name": who.display_name if who is not None else None}
    watched: set[str] = set()
    if access.can("view_restricted"):
        from app.freeze import service as freeze_service

        try:
            watched = {ex_norm(w.address) for w in freeze_service.watched(db, case)}
        except Exception:  # noqa: BLE001 - the freeze tables never break the status page
            watched = set()
    return {
        "rows": [row_view(r, access, case, tie_options(db, case, r) if r.kind == "outlook" else None, watched)
                 for r in rows],
        "summary": summary,
        "n_all": len(all_rows), "n_outlook_review": n_outlook, "filters": FILTERS, "types": types,
        "f": {"status": status or "all", "type": authority_type or "", "overdue": overdue, "review": review},
        "statuses": [(s, rules.LABELS.get(s, s)) for s in bs.CONFIRMABLE],
        "ai": ai, "ai_enabled": bool(ai.get("enabled")), "disclaimer": DISCLAIMER,
        "generated_at": datetime.now(tz=UTC),
    }


# --------------------------------------------------------------------------- exports
_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _csv_cell(v: Any) -> str:
    s = "" if v is None else str(v)
    s = " ".join(s.split())
    return "'" + s if s.startswith(_FORMULA) else s


CSV_HEAD = ["authority", "authority_type", "request", "kind", "sent_at_utc", "channel", "to", "last_reply_at_utc",
            "status", "status_detail", "status_source", "needs_confirmation", "amount", "asset", "their_ticket",
            "days_waiting", "reply_due", "overdue", "next_action", "evidence_quote", "suggested_outcome",
            "path_step", "instrument", "next_deadline", "hold_expires_at", "tickets"]


def to_csv(view: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_HEAD)
    for r in view["rows"]:
        lr = r["last_reply"]
        w.writerow([_csv_cell(x) for x in (
            r["authority"]["name"], r["authority"]["type"], r["request"], r["kind_label"],
            r["sent"].astimezone(UTC).isoformat(timespec="minutes") if r["sent"] else "", r["channel"],
            "; ".join(r["to"]), lr["at"].astimezone(UTC).isoformat(timespec="minutes") if lr else "",
            r["label"], r["status_text"], r["source_text"], "yes" if r["needs_confirmation"] else "no",
            r["amount"] or "", r["asset"] or "", r["ticket"] or "", r["days_waiting"] if r["days_waiting"] is not None
            else "", r["due_fmt"] if r["due"] else "", "yes" if r["overdue"] else "no", r["next_action"].get("text"),
            r["quote"] or "",
            (f"{r['suggestion']['text']} ({r['suggestion']['source_text']}, not confirmed)" if r.get("suggestion")
             else ""), *_path_cells(r))])
    return buf.getvalue()


def _instrument(r: dict) -> str:
    """What the provider requires: the path's instrument when the provider acts on LE process only (its reply or its
    playbook says so: path_view "requires"), else the instrument their reply names; '' for a provider that may act on
    our notice."""
    pv, iv = r.get("path") or {}, (r.get("intel") or {}).get("instrument") or {}
    return pv.get("requires") or iv.get("label") or ""


def _tickets(r: dict) -> str:
    vals = [t["value"] for t in (r.get("intel") or {}).get("tickets") or []]
    return "; ".join(dict.fromkeys(([r["ticket"]] if r.get("ticket") else []) + vals))


def _path_cells(r: dict) -> list[str]:
    nd = r.get("next_deadline")
    return [(r.get("path") or {}).get("label") or "", _instrument(r),
            f"{nd['label']} {nd['due'].astimezone(UTC).isoformat(timespec='minutes')}" if nd else "",
            r["hold_expires"].astimezone(UTC).isoformat(timespec="minutes") if r.get("hold_expires") else "",
            _tickets(r)]


def _e(v: Any) -> str:
    return str(md_escape("" if v is None else v)).replace("|", "\\|").replace("\n", " ")


def to_markdown(view: dict, case, *, for_docx: bool = False) -> str:
    s = view["summary"]
    h1, h2 = ("### ", "### ") if for_docx else ("# ", "## ")  # (the .docx builder knows "### " only)
    out = [f"{h1}Block status — {_e(case.reference)}", ""]
    out += [f"Generated {_fmt_dt(view['generated_at'])} by Aegis (Athena Software Group, Inc.). {_e(DISCLAIMER)}", "",
            f"- Requests: {s['total']} ({s['awaiting']} waiting, {s['not_sent']} not sent, {s['overdue']} overdue)",
            (f"- Statuses to confirm: {s['needs_confirmation']}; to review: {s['to_review']} ({s['needs_review']} "
             f"replies / Outlook e-mails to review, {s['our_action']} requests waiting on our action)")]
    if view.get("n_outlook_review"):
        n = view["n_outlook_review"]
        out.append(f"- E-mails sent from Outlook not yet tied to a request (reviewed in Aegis, not listed): {n}")
    if s["frozen"]:
        out.append("- Held / frozen (confirmed by a person): " + ", ".join(
            f"{bs.fmt_amount(v, k)} {_e(k)}" for k, v in s["frozen"].items()))
    out.append("")
    if not for_docx:
        out += ["| Authority | Request | Sent | To | Last reply | Status | Days waiting | Next action |",
                "|---|---|---|---|---|---|---|---|"]
        for r in view["rows"]:
            lr = r["last_reply"]
            out.append("| " + " | ".join([
                _e(r["authority"]["name"]), _e(r["request"]), _e(r["sent_fmt"]), _e(", ".join(r["to"]) or "—"),
                _e(lr["at_fmt"] if lr else "—"), _e(r["status_text"]) + (" (to confirm)" if r["confirm_tag"] else ""),
                _e(r["days_waiting"] if r["days_waiting"] is not None else "—"), _e(r["next_action"].get("text"))]) + " |")
        out.append("")
    out.append(f"{h2}Requests")
    for r in view["rows"]:
        out.append("")
        out.append(f"**{_e(r['authority']['name'])} — {_e(r['request'])}**"
                   + (f" ({_e(r['kind_note'])})" if r.get("kind_note") else ""))
        out.append(f"- Status: **{_e(r['status_text'])}**" + (f" — {_e(r['source_text'])}" if r["source_text"] else "")
                   + (" — to confirm" if r["confirm_tag"] else ""))
        first = r.get("first_to") or r["to"]  # where it went first, also once they answered the resend
        out.append(f"- Sent: {_e(r['sent_fmt'])}" + (f" via {_e(r['channel'])}" if r["channel"] else "")
                   + (f" to {_e(', '.join(first))}" if first else ""))
        if (r.get("resent") or r.get("first_to")) and r.get("resent_at"):
            out.append(f"- Resent: {_e(r['resent_fmt'])}" + (f" to {_e(', '.join(r['to']))}" if r["to"] else "")
                       + " after their reply")
        if r.get("suggestion"):
            sg = r["suggestion"]
            out.append(f"- Suggested outcome (not confirmed): {_e(sg['text'])}, {_e(sg['source_text'])}"
                       + (f"; warnings: {_e('; '.join(sg['warnings']))}" if sg["warnings"] else ""))
        if r["ticket"]:
            out.append(f"- Their reference: {_e(r['ticket'])}")
        if r.get("path"):
            pv = r["path"]
            out.append(f"- Path: {_e(pv['label'])}" + (f" (suggests {_e(pv['suggests'])}, to confirm)" if pv["suggests"]
                                                       else "") + (f"; requires {_e(_instrument(r))}" if _instrument(r)
                                                                   else ""))
            if pv.get("route_text"):
                out.append(f"- Route: {_e(pv['route_text'])}")
        if _tickets(r) and _tickets(r) != (r["ticket"] or ""):
            out.append(f"- Tickets: {_e(_tickets(r))}")
        if r.get("next_deadline"):
            nd = r["next_deadline"]
            out.append(f"- Next deadline: {_e(nd['label'])} {_e(nd['due_fmt'])}" + (f" — {_e(nd['action'])}"
                                                                                    if nd.get("action") else ""))
        if r.get("hold_expires"):
            out.append(f"- Hold expires: {_e(r['hold_expires_fmt'])}")
        if r["last_reply"]:
            out.append(f"- Last reply: {_e(r['last_reply']['at_fmt'])} ({len(r['replies'])} repl"
                       f"{'y' if len(r['replies']) == 1 else 'ies'})")
        if r["quote"]:
            out.append(f"- Evidence: \u201c{_e(r['quote'])}\u201d")
        if r["days_waiting"] is not None:
            out.append(f"- Waiting: {r['days_waiting']} day{'s' if r['days_waiting'] != 1 else ''}"
                       + (f"; reply due {_e(r['due_fmt'])}" if r["due"] else "") + (" (overdue)" if r["overdue"] else ""))
        if r["onchain"] and (r["onchain"]["frozen"] or r["onchain"]["lever"]):
            for e in r["onchain"]["frozen"]:
                out.append(f"- On-chain: `{e['address']}` ({_e(e['chain_label'])}) blacklisted by the issuer, "
                           f"{_e(e['balance_label'])} {_e(e['symbol'])}")
            for e in r["onchain"]["lever"]:
                out.append(f"- On-chain: `{e['address']}` ({_e(e['chain_label'])}) holds {_e(e['balance_label'])} "
                           f"{_e(e['symbol'])}, not blacklisted")
        out.append(f"- Next action: {_e(r['next_action'].get('text'))}")
    if not view["rows"]:
        out.append("")
        out.append("No requests yet.")
    return "\n".join(out) + "\n"


def export(db: Session, access, fmt: str, **filters) -> tuple[bytes, str, str]:
    case = access.case
    view = page_view(db, access, for_export=True, **filters)
    stamp = view["generated_at"].strftime("%Y%m%d")
    name = f"{case.reference}_block-status_{stamp}"
    if fmt == "csv":
        return to_csv(view).encode("utf-8"), "text/csv; charset=utf-8", f"{name}.csv"
    if fmt == "md":
        return to_markdown(view, case).encode("utf-8"), "text/markdown; charset=utf-8", f"{name}.md"
    if fmt == "docx":
        body = to_markdown(view, case, for_docx=True)
        doc = _docx_document(f"Block status — {case.reference}", body, case.reference)
        doc.core_properties.comments = "Block status report generated by Aegis (powered by Athena Software Group, Inc.)"
        doc.core_properties.content_status = "Report"
        buf = io.BytesIO()
        doc.save(buf)
        return buf.getvalue(), DOCX_MEDIA, f"{name}.docx"
    raise ValueError(fmt)
