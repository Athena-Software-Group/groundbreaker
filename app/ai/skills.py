"""Assistant skills: the slash commands of the Assistant tab's chat, and the chat turn itself.

    result = run_skill(db, access, "stop-orders", "")          # -> SkillResult
    turn = chat_turn(db, access, "/analyze-flow")               # persisted user + assistant AiMessage rows
    turn = chat_turn(db, access, "Which wallets are still dormant?")   # free text -> the model (or rules)

Registry
--------
Each `Skill` has a name, its slash command, a title and description, the minimum case role
(`min_role`, enforced here: `SkillError(403)`), `needs_ai` (the skill asks the model when the case's
AI mode and the server allow it and falls back to its own rule-based output, clearly labelled,
otherwise) and `drafts` (it can create DRAFT letters, which needs `draft_letter`, investigator+).
`handler(db, case, actor, args) -> SkillResult(markdown, actions, suggested_commands)`; `actor` is
the member's CaseAccess.

Rules every skill keeps
-----------------------
* Grounded: the rule-based part reads the redacted local context (`app.ai.context.local_context`,
  marked) and the latest trace run; labels from the database (address labels, entity / service names,
  recipients) pass through the case's redactor (marking), so the model's copy of a skill's output never
  carries more than the redacted context does (it may be sent back to the model as history; turns
  generated in full mode are sent back only while the case is still in full mode, see `model_history`).
  Free-text notes, letter bodies and evidence content are never quoted.
* Shown vs sent: each redacted value travels as a mask (app.ai.context.masked), so one rendering gives
  the member's screen — the real names, tickets and amounts for a member with view_restricted, who sees
  them on the case's pages anyway; placeholders for anyone else — and the model's copy (placeholders,
  `meta.model_content` of the stored turn). Source tags ("[trace.nodes]") ground the model's copy and are
  hidden on the screen (app.ai.display).
* Consistent: statuses, "overdue", next steps and the order of the next moves come from the pages that
  own them — Block status, the freeze & stop-order board (through the request gate) and the Recovery
  plan (app.ai.casestate) — never from a parallel rule.
* Nothing is ever sent: /stop-orders, /follow-ups and /le-update only create DRAFT correspondence
  through `app.domain.correspondence.generate_letter` (audited as CREATE, like the authorities
  routes). A human reviews each draft, sends it and clicks "Mark sent" on its page.
* Suggestions (`suggested_commands`, the model's included) are validated against this registry and
  the member's role before they are shown; a model suggestion never carries arguments that create
  drafts.

The chat history lives in `ai_messages` (one conversation per member per case); the audit log keeps
only AI_QUERY metadata (app.ai.assistant.model_chat) and CREATE rows for drafts.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from app import services
from app.ai import assistant as ai
from app.ai import casestate, display
from app.ai.context import authority_type, local_context, masked, redactor_for, unmask_obj
from app.ai.rules import (
    NOT_CONFIGURED_REASONS,
    day,
    kind_text,
    qty,
    rule_answer,
    rule_label,
    rule_summary,
)
from app.core.audit import CREATE, audit
from app.core.permissions import INVESTIGATOR, READ_ONLY, CaseAccess, role_at_least
from app.db.models import (
    Address,
    AiMessage,
    AIMode,
    CaseRole,
    Correspondence,
    StopOrderOrigin,
    StopOrderStatus,
    TraceEdge,
    TraceNode,
    Transfer,
)
from app.domain import correspondence as desk
from app.domain import evidence as ev
from app.reports.stop_orders import md_escape
from app.tracing.annotate import cited_addresses
from app.tracing.freeze import freeze_candidates
from app.tracing.heuristics import FLAG_TEXT

log = logging.getLogger(__name__)

DISCLAIMER = "AI can make mistakes. Please double-check important information before acting on it."
RULE_NOTE = ("No AI is used here: answers come from Aegis's fixed checks over the case data (Block status, the "
             "freeze & stop-order board, the Recovery plan).")
NEVER_SENT = ("Nothing has been sent. Each letter above is a **draft**: review it, send it yourself through the "
              "recipient's channel, then click **Mark sent** on its page so Aegis starts the reply clock. The "
              "assistant never sends letters and never marks anything sent.")
RULE_SKILL_LABEL = "rule-based (Aegis skill, no AI used)"
MAX_HISTORY_MESSAGES = 200  # shown on the tab
MODEL_HISTORY_MESSAGES = 12  # earlier turns sent with a free-text question
MAX_SUGGESTIONS = 5
MAX_TABLE_ROWS = 40
ARGS_RE = re.compile(r"[A-Za-z0-9 _.:/#@-]{0,120}")
ADDRESS_RE = re.compile(r"[A-Za-z0-9_]{6,128}")
DRAFT_WORDS = ("draft", "create", "generate")


class SkillError(Exception):
    """A request the chat refuses: `status` 400 (bad input), 403 (role), 404 (unknown object)."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class SkillBusy(Exception):
    """The model provider is busy / rate-limiting (HTTP 429 to the browser, which offers a retry)."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass
class SkillResult:
    markdown: str
    actions: list[dict] = field(default_factory=list)  # {"label", "command"} | {"label", "href"}
    suggested_commands: list[str] = field(default_factory=list)
    source: str = "rule_based"  # ai | rule_based
    label: str = RULE_SKILL_LABEL
    generated_by: str | None = None  # "<served model> via <data path>" when a model wrote it
    served_model: str | None = None
    reason: str | None = None  # why no model answered (app.ai.assistant.REASON_TEXT)
    findings: str | None = None  # Aegis's own computed findings, shown under an AI answer
    drafts: list[dict] = field(default_factory=list)  # {"id", "kind", "to", "href"}: drafts created by this run
    mode: str | None = None
    model_markdown: str | None = None  # the model's copy of `markdown` (placeholders, source tags): `_finalize`
    revealed: bool = False  # `markdown` shows real values the model's copy masks (view_restricted)


Handler = Callable[[Session, Any, CaseAccess, str], SkillResult]


@dataclass(frozen=True)
class Skill:
    name: str
    command: str  # without the slash
    title: str
    description: str
    min_role: CaseRole
    needs_ai: bool  # asks the model when allowed; rule-based fallback otherwise
    handler: Handler
    args_hint: str = ""
    drafts: bool = False  # can create draft letters (draft_letter: investigator+)

    @property
    def slash(self) -> str:
        return f"/{self.command}"

    def allowed(self, access: CaseAccess) -> bool:
        return role_at_least(access.role, self.min_role)

    def as_dict(self, access: CaseAccess | None = None) -> dict:
        return {"name": self.name, "command": self.slash, "title": self.title, "description": self.description,
                "args": self.args_hint, "min_role": self.min_role.value, "ai": self.needs_ai,
                "drafts": self.drafts and (access is None or access.can("draft_letter")),
                "allowed": True if access is None else self.allowed(access)}


SKILLS: dict[str, Skill] = {}


def skill(command: str, title: str, description: str, *, min_role: CaseRole = READ_ONLY, needs_ai: bool = False,
          args: str = "", drafts: bool = False) -> Callable[[Handler], Handler]:
    def register(fn: Handler) -> Handler:
        SKILLS[command] = Skill(name=command.replace("-", "_"), command=command, title=title, description=description,
                                min_role=min_role, needs_ai=needs_ai, handler=fn, args_hint=args, drafts=drafts)
        return fn

    return register


def available_skills(access: CaseAccess) -> list[Skill]:
    return [s for s in SKILLS.values() if s.allowed(access)]


# --------------------------------------------------------------------------- small helpers
def _md(v: Any) -> str:
    return str(md_escape("" if v is None else v))


def _short(addr: str | None) -> str:
    if not addr:
        return "?"
    return f"{addr[:6]}…{addr[-4:]}" if len(addr) > 14 and not addr.endswith("_PENDING") else addr


def _code(addr: str | None) -> str:
    return f"`{addr}`" if addr else "?"


def _money(v: float | None) -> str:
    return "unknown" if v is None else f"${v:,.2f}"


STABLECOINS = frozenset({"USDT", "USDC", "DAI", "BUSD", "TUSD", "USDP", "PYUSD", "FDUSD", "USDE", "EURC", "EURT"})


def _amount(v: Any, asset: str | None = None) -> str:
    """A token amount for display: up to 6 decimals for a stablecoin (cent-pegged, 6 on-chain decimals for
    USDT/USDC), up to 8 for anything else (BTC's satoshi; ETH and the rest rounded there too), trailing
    zeros dropped. A swap's asset ("USDC→ETH") counts as its output. The stored value, and every export,
    keeps its full precision."""
    d = Decimal(v)
    sym = (asset or "").split("→")[-1].strip().upper()
    q = Decimal("0.000001") if sym in STABLECOINS else Decimal("0.00000001")
    out = f"{d.quantize(q).normalize():f}"
    return "0" if out == "-0" else out


def _day(v: str | None) -> str:
    """An ISO date / timestamp as the app writes dates ('21 Oct 2026')."""
    return day(v) if v else "—"


def _when(v: str | None) -> str:
    return (v or "")[:16].replace("T", " ") or "—"


def _cell(v: Any) -> str:
    return _md(v).replace("|", "\\|").replace("\n", " ")


def _table(head: list[str], rows: list[list[str]], only_shown: set[int] | frozenset = frozenset()) -> str:
    """A Markdown table; the rows at the indexes `only_shown` are on the member's screen only (left out of the model's
    copy: a move built from what a reply names while "AI reads mailbox replies" is off)."""
    out = "| " + " | ".join(head) + " |\n|" + "---|" * len(head)
    for i, r in enumerate(rows):
        line = "\n| " + " | ".join(r) + " |"
        out += masked(line, "") if i in only_shown else line
    return out


def _red(db: Session, case: Any) -> Callable[[str | None], str | None]:
    """The case's redactor, marking (shown vs sent: app.ai.context.masked)."""
    return redactor_for(db, case, marking=True)


def _ctx(db: Session, case: Any) -> dict:
    """The redacted local context, marked (its redacted values masked: the screen gets them back)."""
    return local_context(db, case, marked=True)


TYPE_TEXT = {"eoa": "wallet", "contract": "contract", "deposit": "deposit address", "hot_wallet": "hot wallet",
             "victim": "victim wallet", "perpetrator": "perpetrator wallet", "unknown": "address"}
TERMINAL_TEXT = {"vasp": "at a custodial service (exchange / casino)", "vasp_omnibus": "a service's hot wallet",
                 "swap_service": "a swap / bridge service", "max_hops": "the trace's hop limit", "context": "context",
                 "dormant": "no onward movement"}


def _type_text(v: str | None) -> str:
    return TYPE_TEXT.get(v or "", (v or "address").replace("_", " "))


def _link(case_id: int, path: str) -> str:
    return f"/cases/{case_id}{path}"


def _wants_draft(args: str) -> tuple[bool, str]:
    """('draft …' given, the rest of the arguments)."""
    head, _, rest = (args or "").strip().partition(" ")
    if head.lower() in DRAFT_WORDS:
        return True, rest.strip()
    return False, (args or "").strip()


def _require_drafting(access: CaseAccess, command: str) -> None:
    if not access.can("draft_letter"):
        raise SkillError(403, f"/{command} can create draft letters only for investigators and admins; your role on "
                              f"this case is {access.role.value.replace('_', ' ')}.")


def _audit_draft(db: Session, access: CaseAccess, corr: Correspondence, template: str, run_id: int | None,
                 command: str) -> None:
    corr.meta = {**(corr.meta or {}), "created_via": f"assistant:/{command}"}
    db.commit()
    if corr.stop_order is not None and template == "stop_order":
        audit(db, access, CREATE, access.case, corr.stop_order, origin="generated", run_id=run_id,
              template_key=template, via="assistant")
    audit(db, access, CREATE, access.case, corr, template_key=template, kind=corr.kind.value,
          stop_order_id=corr.stop_order_id, run_id=run_id, via="assistant")


def _draft_row(case_id: int, corr: Correspondence, to: str) -> dict:
    return {"id": corr.id, "kind": corr.kind.value, "to": to,
            "href": _link(case_id, f"/authorities/correspondence/{corr.id}")}


def _drafts_md(drafts: list[dict]) -> str:
    lines = ["**Drafts created (not sent):**"]
    for d in drafts:
        lines.append(f"- [Draft #{d['id']} — {_md(d['kind'].replace('_', ' '))} to {_md(d['to'])}]({d['href']})")
    return "\n".join(lines) + "\n\n" + NEVER_SENT


# --------------------------------------------------------------------------- the stop-order plan
STATUS_TEXT = {
    "recommended": "Recommended now — no stop order on file",
    "draft": "Draft on file — not sent yet",
    "requested": "Already requested",
    "overdue": "Requested — reply overdue",
    "frozen": "Hold confirmed",
    "declined": "Declined",
    "released": "Released",
    "info_request": "Non-custodial — send an information request instead",
}
STATUS_ORDER = ("recommended", "overdue", "draft", "requested", "declined", "frozen", "released", "info_request")


def _addresses(order: Any) -> frozenset[str]:
    """The full addresses a stop order cites (lower-cased): the graph's rule (annotate.cited_addresses),
    so the plan, /wallet and the fund-flow graph agree on which wallets a request covers."""
    ids = order.identifiers if isinstance(order.identifiers, dict) else None
    return cited_addresses(ids, order.body_markdown, imported=order.origin == StopOrderOrigin.IMPORTED)


def stop_order_plan(db: Session, case: Any, run: Any = None) -> dict:
    """Which services (and their wallets) should get a stop order now, and which were already asked.

    Rows: {key, entity, category, kind, priority, taint_usd, status (STATUS_ORDER), status_text,
    wallets [{address, chain, label, taint_usd}], uncovered (wallets of the latest trace not cited by
    the request on file), orders [{id, status, sent_at, due, overdue}], draft_ids}. Also usable by the
    fund-flow graph to mark recommended / requested wallets (`wallet_status`)."""
    run = run if run is not None else services.latest_run(db, case)
    cands = freeze_candidates(db, run) if run is not None else []
    now = datetime.now(tz=UTC)
    rows = []
    for a in desk.case_authorities(db, case, run=run, cands=cands):
        if a.entity is None or a.is_le or a.is_adviser:
            continue
        orders = [o for o in a.stop_orders if desk.order_state(o) != "superseded"]
        if a.candidate is None and not orders:
            continue
        drafts = [o for o in orders if o.status == StopOrderStatus.DRAFT]
        active = sorted((o for o in orders if o.status != StopOrderStatus.DRAFT),
                        key=lambda o: (o.sent_at or o.created_at or now, o.id))
        states = {desk.order_state(o) for o in active}
        overdue = any(desk.awaiting_response(o) and (desk.response_due(o) or now) < now for o in active)
        if "frozen" in states:
            status = "frozen"
        elif overdue:
            status = "overdue"
        elif states & {"sent", "acknowledged"}:
            status = "requested"
        elif "released" in states:
            status = "released"
        elif "declined" in states:
            status = "declined"
        elif drafts:
            status = "draft"
        elif a.non_custodial:
            status = "info_request"
        else:
            status = "recommended"
        cand = a.candidate
        wallets = [{"address": i.address, "chain": i.chain, "label": i.label, "taint_usd": float(i.taint_usd or 0),
                    "type": i.address_type} for i in (cand.identifiers if cand else [])]
        cited = set().union(*[_addresses(o) for o in orders]) if orders else set()
        uncovered = [w["address"] for w in wallets if active and w["address"].lower() not in cited]
        rows.append({
            "key": a.key, "entity": a.name, "category": a.category, "kind": cand.kind if cand else
            (active[-1].kind if active else None), "priority": cand.priority if cand else 0,
            "taint_usd": float(cand.total_taint_usd) if cand else None, "status": status,
            "status_text": STATUS_TEXT[status], "wallets": wallets, "uncovered": uncovered,
            "orders": [{"id": o.id, "status": desk.order_state(o), "sent_at": o.sent_at, "due": desk.response_due(o),
                        "overdue": desk.awaiting_response(o) and (desk.response_due(o) or now) < now} for o in active],
            "draft_ids": [o.id for o in drafts],
            "can_draft": status in ("recommended", "declined") and cand is not None and run is not None,
        })
    rows.sort(key=lambda r: (STATUS_ORDER.index(r["status"]), -(r["priority"] or 0), -(r["taint_usd"] or 0),
                             r["entity"].lower()))
    return {"run_id": run.id if run is not None else None, "rows": rows}


def wallet_status(db: Session, case: Any, run: Any = None) -> dict[str, dict]:
    """address (lower-case) -> {"status", "entity", "key", "category"}: the stop-order plan per wallet."""
    out: dict[str, dict] = {}
    for r in stop_order_plan(db, case, run)["rows"]:
        for w in r["wallets"]:
            out.setdefault(w["address"].lower(), {"status": r["status"], "entity": r["entity"], "key": r["key"],
                                                  "category": r.get("category")})
    return out


def _board_targets(db: Session, case: Any, access: CaseAccess) -> dict[str, Any]:
    """authority key -> the freeze & stop-order board's row (app.blocks.freeze_board.Target: its status, step, value at
    stake; every step through the request gate); {} when the board cannot be read (the plan's own status then)."""
    from app.blocks import freeze_board as fb

    try:
        return {t.key: t for t in fb.build(db, case, access).targets}
    except Exception as err:  # noqa: BLE001 - the skill still answers from the plan
        log.warning("assistant: freeze board failed for case %s (%s)", case.id, type(err).__name__)
        return {}


# --------------------------------------------------------------------------- AI wrapper for needs_ai skills
def _commands_for(access: CaseAccess) -> list[str]:
    return [s.slash + (f" {s.args_hint}" if s.args_hint else "") for s in available_skills(access)]


def _with_ai(db: Session, access: CaseAccess, sk: Skill, args: str, instruction: str, base: SkillResult) -> SkillResult:
    """Ask the model to answer `instruction` with `base.markdown` as Aegis's findings. Falls back to
    `base` (labelled why) when no model may or can answer."""
    prompt = f"{sk.slash} {args}".strip() + f"\n{instruction}"
    # the findings as the model may read them: placeholders (never the masks' real values), source tags kept
    res = ai.model_chat(db, access.case, prompt, actor=access, findings=display.sent(base.markdown),
                        commands=_commands_for(access), kind="skill", skill=sk.command)
    base.mode = res.mode
    if res.output is None:
        base.reason = res.reason
        base.label = rule_label(res.reason)
        if res.reason not in NOT_CONFIGURED_REASONS and res.reason not in ("ai_mode_off", "full_mode_unconfirmed"):
            note = ai.reason_text(res.reason) or "The AI request failed."
            base.markdown = f"_{_md(note)} Showing Aegis's rule-based result instead._\n\n" + base.markdown
            base.actions = [{"label": "Retry with AI", "command": f"{sk.slash} {args}".strip()}, *base.actions]
        return base
    answer = res.output["answer"]
    model_sugg = validate_suggestions(res.output.get("suggested_commands") or [], access, from_model=True)
    return SkillResult(markdown=answer, actions=base.actions, suggested_commands=model_sugg or base.suggested_commands,
                       source="ai", label=res.label, generated_by=res.generated_by, served_model=res.served_model,
                       findings=base.markdown, drafts=base.drafts, mode=res.mode)


# --------------------------------------------------------------------------- skills
@skill("help", "Help", "List the assistant's skills and how to use them.")
def _help(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    rows = []
    for s in available_skills(actor):
        what = s.description + (" Uses the AI when allowed, otherwise rule-based." if s.needs_ai else "")
        rows.append([f"`{s.slash}{(' ' + s.args_hint) if s.args_hint else ''}`", what.replace("|", "\\|")])
    md = ("**Skills** — type a command (start with `/` to see the list as you type) or press a button in the skills "
          "palette. Anything else you type is a question about the case.\n\n" + _table(["Command", "What it does"], rows)
          + "\n\nDraft-creating skills (`/stop-orders draft …`, `/follow-ups draft`, `/le-update <authority>`) need the "
            "investigator role and only ever create **drafts**; a person sends each letter and clicks **Mark sent**.")
    return SkillResult(markdown=md, suggested_commands=["/summary", "/analyze-flow", "/stop-orders"])


def _due(v: str | None) -> str:
    """A deadline's date as the app writes dates ('21 Oct 2026'); 'now' and the like as given."""
    v = str(v or "")
    return day(v) if re.match(r"\d{4}-\d{2}-\d{2}", v) else (v or "—")


def _summary_md(s: dict) -> str:
    fp = s.get("funds_position") or {}
    out = [f"**Status:** {_md(s.get('status_summary'))}", "",
           (f"- Traced: **{_money(fp.get('traced_usd'))}** · at freezable services: "
           f"**{_money(fp.get('at_freezable_services_usd'))}** · frozen: **{_money(fp.get('frozen_usd'))}**")]
    if fp.get("unknown"):
        out.append(f"- Not established: {_md(fp['unknown'])}")
    if s.get("key_facts"):
        out += ["", "**Key facts**"] + [f"- {_md(f)}" for f in s["key_facts"][:12]]
    if s.get("deadlines"):
        out += ["", "**Deadlines**", _table(["What", "Due", "Why"], [[_cell(d.get("what")), _cell(_due(d.get("due"))),
                                                                      _cell(d.get("why"))] for d in s["deadlines"][:15]])]
    steps = s.get("next_steps") or []
    ranked = [n for n in steps if n.get("rank") is not None]
    if ranked:  # the Recovery plan's moves, in its order (rule-based)
        out += ["", "**Next moves** (the Recovery plan's order)",
                _table(["#", "Move", "At stake", "Next step"],
                       [[str(n["rank"]), _cell(n.get("action")), _cell(n.get("value") or "—"),
                         _cell(n.get("next") or "—")] for n in ranked[:12]])]
        rest = [n for n in steps if n.get("rank") is None]
        if rest:
            out += ["", "**Also**"] + [f"- {_md(n.get('action'))} — {_md(n.get('rationale'))}" for n in rest[:6]]
    elif steps:
        out += ["", "**Next steps**", _table(["Priority", "Action", "Owner"],
                                             [[_cell(n.get("priority")), _cell(n.get("action")),
                                               _cell(str(n.get("owner_role") or "").replace("_", " "))]
                                              for n in steps[:12]])]
    for key, title in (("risks", "Risks"), ("data_gaps", "Data gaps")):
        if s.get(key):
            out += ["", f"**{title}**"] + [f"- {_md(x)}" for x in s[key][:10]]
    return "\n".join(out)


@skill("summary", "Status summary", "The case status summary: funds position, deadlines, next steps, risks. "
       "Investigators generate a fresh one (stored on the Status summary sub-tab); read-only members see the latest.",
       needs_ai=True)
def _summary(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    sub = [{"label": "Open the Status summary sub-tab", "href": _link(case.id, "?tab=assistant&sub=summary")}]
    sugg = ["/next-steps", "/analyze-flow", "/stop-orders"]
    if actor.can("ai_summarize"):
        out = ai.summarize_case(db, case, actor=actor, keep_marked=True)
        meta = out.get("meta") or {}
        # a rule-based summary with its masks (shown resolved for the member), else the model's own text
        summary = out.get("_marked") or {k: v for k, v in out.items() if k not in ("meta", "_marked")}
        res = SkillResult(markdown=_summary_md(summary), actions=sub, suggested_commands=sugg,
                          source=meta.get("source") or "rule_based", label=meta.get("label") or RULE_SKILL_LABEL,
                          generated_by=meta.get("generated_by_model"), served_model=meta.get("served_model"),
                          reason=meta.get("reason"), mode=meta.get("mode"))
        if meta.get("reason") == "rate_limited":
            res.markdown = f"_{_md(ai.reason_text('rate_limited'))} Showing the rule-based summary._\n\n" + res.markdown
            res.actions = [{"label": "Retry with AI", "command": "/summary"}, *sub]
        return res
    stored = ai.stored_summary(case)
    if stored is not None and (stored.get("mode") != AIMode.FULL.value or actor.can("view_restricted")):
        when = _when(stored.get("generated_at"))
        body = stored.get("summary_full") if actor.can("view_restricted") and stored.get("summary_full") else \
            stored["summary"]
        md = f"_Latest stored summary ({_md(stored.get('label'))}, {when} UTC)._\n\n" + _summary_md(body)
        return SkillResult(markdown=md, actions=sub, suggested_commands=sugg, source=stored.get("source") or "rule_based",
                           label=stored.get("label") or RULE_SKILL_LABEL, generated_by=stored.get("generated_by_model"),
                           served_model=stored.get("served_model"), mode=stored.get("mode"))
    md = ("_No summary you can view is stored yet; this one is computed now by Aegis's rule-based checks (generating "
          "an AI summary needs the investigator role)._\n\n"
          + _summary_md(rule_summary(_ctx(db, case), casestate.case_state(db, case, actor))))
    return SkillResult(markdown=md, actions=sub, suggested_commands=sugg)


SPLIT_MIN_RECIPIENTS = 3  # /analyze-flow lists a wallet as a split when it sends tainted funds to this many wallets


@skill("analyze-flow", "Analyze fund flow", "Where the funds sit now: largest balances, VASP touchpoints, peel "
       "chains, dormant vs moving wallets and the gaps in the latest trace.", needs_ai=True)
def _analyze_flow(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    ctx = _ctx(db, case)
    trace, d = ctx.get("trace") or {}, ctx.get("derived") or {}
    if not trace.get("run"):
        return SkillResult(markdown="No trace run exists yet, so there is no fund flow to analyse. An investigator can "
                                    "run a trace from the Fund flow tab. [trace]", suggested_commands=["/next-steps"])
    run, nodes, fp = trace["run"], trace.get("nodes") or [], d.get("funds_position") or {}
    plan = wallet_status(db, case)
    targets = _board_targets(db, case, actor)
    loss = (ctx.get("case") or {}).get("loss") or {}
    data = "offline fixture data" if run.get("provider_mode") == "fixture" else "live chain data"
    gone = fp.get("issuer_moved_on") or []
    out = [f"**Fund flow — trace run #{run['id']}**" + (f" ({_md(run.get('label'))})" if run.get("label") else "")
           + f", {run.get('status')}, {data} [trace.run]", "",
           (f"- Loss {_money(loss.get('usd'))}; traced {_money(fp.get('traced_usd'))}; at freezable services "
           f"{_money(fp.get('at_freezable_services_usd'))}; issuer-blacklist lever "
           f"{_money(fp.get('issuer_blacklist_lever_usd'))}; frozen {_money(fp.get('frozen_usd'))} [derived.funds_position]"),
           (f"- {trace.get('graph', {}).get('nodes', 0)} addresses over {trace.get('graph', {}).get('max_hop', 0)} hops on "
           f"{', '.join(trace.get('graph', {}).get('chains') or []) or '—'} [trace.graph]")]
    if gone:
        out.insert(3, (f"- The trace saw the stablecoin leave {', '.join(_code(_short(a)) for a in gone[:4])}: nothing is "
                       "left there for its issuer to blacklist, so it counts nothing in the issuer lever "
                       "[derived.funds_position]"))

    def where(n: dict) -> str:
        st = plan.get(n["address"].lower())
        t = targets.get(st["key"]) if st else None
        if t is not None:  # the freeze & stop-order board's row for its service
            return t.status_label + (f" — next: {t.step.label}" if t.step.label else "")
        return STATUS_TEXT[st["status"]] if st else ("watch / trace next" if "trace_next" in n["flags"] else "—")

    resting = [n for n in nodes if n["terminal"] or "dormant" in n["flags"] or "pending_input" in n["flags"]]
    resting.sort(key=lambda n: -(n["taint_usd"] or 0))
    if resting:
        out += ["", "**Where the funds sit now** (end points of the trace, largest first)",
                _table(["Wallet", "Chain", "Holder / label", "Tainted USD", "State", "Stop order"],
                       [[_code(_short(n["address"])), _cell(n["chain"]), _cell(n["entity"] or n["label"]
                                                                                 or _type_text(n["type"])),
                         _money(n["taint_usd"]),
                         "dormant" if "dormant" in n["flags"] else ("pending input" if "pending_input" in n["flags"]
                                                                    else ("at service" if n["terminal"] else "—")),
                         _cell(where(n))] for n in resting[:15]])]
    vasp = [n for n in nodes if n["terminal"] and (n.get("terminal_reason") == "vasp" or n["entity"])]
    if vasp:
        out += ["", "**Terminal VASP / service touchpoints** [trace.nodes]"]
        out += [f"- {_md(n['entity'] or n['label'])}: {_code(_short(n['address']))} "
                + (f"received up to {_money(n['taint_usd'])}" if (n["taint_usd"] or 0) > 0
                   else "on the path, no tainted USD attributed")
                + (" — " + FLAG_TEXT["vasp_deposit"] if "vasp_deposit" in n["flags"] else "")
                for n in vasp[:10]]
    moving = [n for n in nodes if "rapid_forward" in n["flags"]]
    dormant = [n for n in nodes if "dormant" in n["flags"]]
    out += ["", "**Dormant vs moving**",
            (f"- Moving: {len(moving)} wallet(s) forwarded funds within minutes of receiving them (rapid forwarding) "
            "[trace.nodes]"),
            (f"- Dormant: {len(dormant)} wallet(s) show no onward movement; {_money(fp.get('dormant_self_custody_usd'))} "
            "sits in dormant self-custody and can move at any time [derived.dormant_large_balances]")]
    for n in d.get("dormant_large_balances") or []:
        if not n["pending_input"]:
            out.append(f"  - {_code(_short(n['address']))} ({_cell(n['chain'])}) {_money(n['taint_usd'])}"
                       + (" — trace next" if n["trace_next"] else ""))
    peel = [n for n in nodes if "peel_chain" in n["flags"] or "high_fanout" in n["flags"]]
    out += ["", "**Peel chains and splits**"]
    out += [f"- {_code(_short(n['address']))}" + (f" ({_md(n['entity'] or n['label'])})" if n["entity"] or n["label"]
                                                   else "") + ": "
            + "; ".join(FLAG_TEXT[f] for f in ("peel_chain", "high_fanout", "rapid_forward") if f in n["flags"])
            + " [trace.nodes]" for n in peel[:8]]
    # splits seen in the graph itself, whether or not a heuristic flag was raised: a wallet that sends tainted
    # funds on to several wallets
    fan: dict[str, set[str]] = {}
    for t in trace.get("tainted_transfers") or []:
        fan.setdefault(t["from"].lower(), set()).add(t["to"].lower())
    by_addr = {n["address"].lower(): n for n in nodes}
    flagged = {n["address"].lower() for n in peel}
    splits = sorted(((a, len(tos)) for a, tos in fan.items() if len(tos) >= SPLIT_MIN_RECIPIENTS and a not in flagged),
                    key=lambda x: (-x[1], x[0]))
    for i, (a, k) in enumerate(splits[:8]):
        n = by_addr.get(a) or {}
        name = n.get("entity") or n.get("label")
        rapid = "rapid_forward" in (n.get("flags") or [])
        # the widest split is the distribution hub; a split within minutes of arrival is a rapid split
        what = ("distribution hub" if i == 0 else "split") + (", rapid split" if rapid else "")
        out.append(f"- {_code(_short(a))}" + (f" ({_md(name)})" if name else "")
                   + f": **{what}** — sends tainted funds on to {k} wallets"
                   + (" (" + FLAG_TEXT["rapid_forward"][0].lower() + FLAG_TEXT["rapid_forward"][1:].rstrip(".") + ")"
                      if rapid else "")
                   + " [trace.tainted_transfers" + (", trace.nodes" if rapid else "") + "]")
    peel_outflows = sum(1 for n in nodes if "peel" in (n.get("label") or "").lower())
    if peel_outflows:
        out.append(f"- {peel_outflows} wallet(s) are labelled as peel outflows [trace.nodes]")
    if not peel and not splits and not peel_outflows:
        out.append(f"- No peel-chain or fan-out flag was raised, and no listed wallet sends tainted funds on to "
                   f"{SPLIT_MIN_RECIPIENTS} or more wallets [trace.nodes]")
    elif not peel:
        out.append("- No peel_chain or high_fanout flag was raised by the heuristics (no split reached the fan-out "
                   "limit); the splits above come from the transfers [trace.nodes]")
    pi = d.get("pending_inputs") or {}
    gaps = []
    if pi.get("asserted_transfers"):
        gaps.append(f"{pi['asserted_transfers']} transfers are asserted, not yet observed on-chain; amounts downstream "
                    "are upper bounds [trace.tainted_transfers]")
    if pi.get("unknown_amount_transfers"):
        gaps.append(f"{pi['unknown_amount_transfers']} transfers have no observed amount [trace.tainted_transfers]")
    gaps += [f"Placeholder {_code(n['address'])}: {_md(n['label'])} [trace.nodes]" for n in pi.get("nodes") or []]
    if trace.get("nodes_omitted"):
        gaps.append(f"{trace['nodes_omitted']} smaller addresses are not listed here [trace]")
    if run.get("provider_mode") == "fixture":
        gaps.append("The run used the offline fixture, not live chain data [trace.run]")
    out += ["", "**Gaps**"] + ([f"- {g}" for g in gaps] or ["- None identified by the rule checks"])
    actions = [{"label": "Open the fund-flow graph", "href": _link(case.id, "?tab=fund_flow")}]
    top = next((n for n in d.get("dormant_large_balances") or [] if not n["pending_input"]), None)
    sugg = ["/stop-orders", "/next-steps"] + ([f"/wallet {top['address']}"] if top else []) + ["/timeline"]
    base = SkillResult(markdown="\n".join(out), actions=actions, suggested_commands=sugg)
    return _with_ai(db, actor, SKILLS["analyze-flow"], args,
                    "Analyse the fund flow for the case team: where the funds sit now, the largest balances, terminal "
                    "VASP touchpoints, peel chains, dormant versus moving wallets, and the gaps. Lead with what can "
                    "still be frozen and how urgently. Use the findings and the context; do not invent movements.",
                    base)


@skill("stop-orders", "Stop orders", "Which wallets and services should get a stop order now and which were already "
       "asked; investigators can create DRAFT letters (draft all, or draft <name>). Nothing is sent.",
       args="[draft all, or draft <name>]", drafts=True)
def _stop_orders(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    draft, target = _wants_draft(args)
    plan = stop_order_plan(db, case)
    targets = _board_targets(db, case, actor)
    rows = _without_pointless(db, case, plan["rows"], targets)
    red = _red(db, case)
    if plan["run_id"] is None:
        return SkillResult(markdown="No trace run yet: stop orders are built from the latest trace's freeze candidates. "
                                    "Run a trace on the Fund flow tab first. [trace]", suggested_commands=["/next-steps"])
    if draft:
        _require_drafting(actor, "stop-orders")
        return _draft_stop_orders(db, actor, rows, target or "all", plan["run_id"], red)
    out = [(f"**Stop-order plan** (trace run #{plan['run_id']}; statuses and next steps as on the freeze & stop-order "
           "board) [freeze_candidates] [stop_orders]"), ""]
    names = {r["key"]: _draft_arg(rows, r) for r in rows}
    rows = _shown_rows(rows, red)
    recommended = [r for r in rows if r["status"] in DRAFTABLE and r["can_draft"]]
    asks = [r for r in recommended if not r.get("notice")]
    notices = [r for r in recommended if r.get("notice")]
    waiting = [r for r in rows if r["status"] == "draft"]

    def line(r: dict) -> str:
        t = targets.get(r["key"])
        ws = ", ".join(_code(_short(w["address"])) for w in r["wallets"][:4])
        more = f" (+{len(r['wallets']) - 4} more)" if len(r["wallets"]) > 4 else ""
        step = f" — the move: **{_md(red(t.step.label))}**" if r.get("notice") and t is not None and t.step.label else ""
        return (f"- **{_md(r['entity'])}** ({_md(kind_text(r['kind']))}, at stake {_at_stake(t, r)}){step} — wallets "
                f"{ws}{more}" + (" — an earlier request was declined" if r["status"] == "declined" else ""))

    if asks:
        out += ["**Send a stop order now to:**", *(line(r) for r in asks), ""]
    if notices:
        out += [("**Acts on LE process only** — the LE route is the move (its step below); a notice letter flags the "
                 "wallets in parallel:"), *(line(r) for r in notices), ""]
    if waiting:
        out += [_drafts_waiting(case.id, waiting), ""]
    if not recommended and not waiting:
        out += [("No new stop order to send: every freeze candidate of the latest trace was asked already, or its next "
                "step is another one (a follow-up, the LE route): see the table."), ""]
    table = []
    for r in rows:
        t = targets.get(r["key"])
        last = r["orders"][-1] if r["orders"] else None
        detail = (f"#{last['id']} sent {_dmy(last['sent_at'])}" + (f", reply due {_dmy(last['due'])}" if last["due"]
                                                                    else "")) if last else (
            f"draft #{r['draft_ids'][0]}" if r["draft_ids"] else "—")
        if r["uncovered"]:
            detail += f" ({len(r['uncovered'])} wallet(s) of the latest trace not cited)"
        if t is not None:
            status = t.status_label + (f" ({red(t.detail)})" if t.detail else "")
            label, lead = red(t.step.label) or "", red(t.step.lead) or ""
            nxt = f"**{_cell(label)}**: {_cell(lead)}" if label and lead else _cell(label or lead or "—")
        else:
            status, nxt = r["status_text"], "—"
        if r["status"] in ("gated", "pointless"):  # the request gate's / board's reason, naming the row's step
            status = r["status_text"]
        table.append([_cell(r["entity"]), _cell(status), _cell(detail), _cell(_at_stake(t, r)), nxt])
    out.append(_table(["Service", "Status", "Request on file", "At stake", "Next step"], table[:MAX_TABLE_ROWS]))
    dormant = [n for n in (_ctx(db, case).get("derived") or {}).get("dormant_large_balances") or []
               if not n["pending_input"]]
    if dormant:
        out += ["", ("**Self-custody wallets** (no custodian to freeze; watch them and extend the trace; a stablecoin "
                    "balance there can be blacklisted by its issuer):")]
        out += [f"- {_code(_short(n['address']))} {_money(n['taint_usd'])} — {_md(red(n['label']) or '')}"
                for n in dormant[:6]]
    actions: list[dict] = []
    if actor.can("draft_letter") and recommended:
        if len(recommended) > 1:
            actions.append({"label": _draft_all_label(len(asks), len(notices)), "command": "/stop-orders draft all"})
        actions += [{"label": f"Draft the {'notice' if r.get('notice') else 'stop order'} to {r['entity']}",
                     "command": f"/stop-orders draft {names[r['key']]}"} for r in recommended[:4]]
    elif recommended:
        out += ["", "_Drafting letters needs the investigator role._"]
    actions += _draft_review_actions(case.id, waiting)[:4]
    actions.append({"label": "Open Authorities", "href": _link(case.id, "?tab=authorities")})
    out += ["", ("_The assistant only prepares drafts. Sending is always a person's step: review the draft, send it, "
                "then click **Mark sent** on its page._")]
    sugg = (["/follow-ups"] if any(r["status"] == "overdue" for r in rows) else []) + ["/recovery-plan", "/next-steps"]
    return SkillResult(markdown="\n".join(out), actions=actions, suggested_commands=sugg)


def _draft_all_label(asks: int, notices: int) -> str:
    """'Draft all 3 stop orders' / 'Draft 2 notices to LE-only issuers' / 'Draft 1 stop order + 2 notices' (the board's
    generator counts them the same way)."""
    if not notices:
        return f"Draft all {asks} stop orders"
    if not asks:
        return f"Draft {notices} notice{'s' if notices != 1 else ''} to LE-only issuers"
    return f"Draft {asks} stop order{'s' if asks != 1 else ''} + {notices} notice{'s' if notices != 1 else ''}"


def _dmy(v: datetime | None) -> str:
    """A date as the app writes it ('19 Oct 2026')."""
    return f"{v.day} {v:%b %Y}" if v else "—"


def _at_stake(t: Any, r: dict) -> str:
    """The value at stake as the board (and the Recovery plan) counts it: what the trace left there (a stablecoin wallet
    whose funds moved on counts nothing); the plan row's traced value when the board has no row for it."""
    if t is None:
        return _money(r["taint_usd"]) if r["taint_usd"] is not None else "—"
    if t.value:
        return f"${t.value:,.0f}"
    return "none left (the funds moved on)" if "moved on" in (t.basis or "") else "—"


def _draft_arg(rows: list[dict], r: dict) -> str:
    """What `/stop-orders draft …` names the row by: the first word of its name when that names it alone
    (`_match_service`), else its key."""
    word = re.split(r"[^A-Za-z0-9]+", r["entity"].strip())[0].lower() if r["entity"] else ""
    if len(word) >= MIN_NAME_MATCH:
        try:
            if _match_service(rows, word, word) is r:
                return word
        except SkillError:
            pass
    return r["key"]


DRAFTABLE = ("recommended", "declined")  # plan rows /stop-orders may draft a letter for
MIN_NAME_MATCH = 3  # characters of a service name `/stop-orders draft <name>` needs


def _shown_rows(rows: list[dict], red: Callable[[str | None], str | None]) -> list[dict]:
    """Plan rows for display: the service names through the case's redactor (the plan keeps the real
    names, which the graph matches on)."""
    return [{**r, "entity": red(r["entity"]) or r["entity"]} for r in rows]


def _match_service(rows: list[dict], t: str, target: str,
                   red: Callable[[str | None], str | None] | None = None) -> dict:
    """The one plan row `draft <target>` names: its key exactly, else its name exactly, else the only
    name that starts with (or, failing that, contains) `target`, which needs MIN_NAME_MATCH characters.
    Several matches are refused with the list, so a typo never drafts a batch of letters."""
    for hit in ([r for r in rows if r["key"] == t], [r for r in rows if r["entity"].lower() == t]):
        if len(hit) == 1:
            return hit[0]
    if len(t) < MIN_NAME_MATCH:
        raise SkillError(400, f"{target!r} is too short to name a service: give its key (e.g. "
                              f"{rows[0]['key'] if rows else 'entity-1'}) or at least {MIN_NAME_MATCH} letters of its "
                              "name. Run /stop-orders to see the list.")
    hits = [r for r in rows if r["entity"].lower().startswith(t)] or [r for r in rows if t in r["entity"].lower()]
    if not hits:
        raise SkillError(404, f"No service matching {target!r} in the stop-order plan. Run /stop-orders to see the "
                              "list.")
    if len(hits) > 1:
        names = "; ".join(f"{(red or str)(r['entity'])} ({r['key']})" for r in hits[:8])
        raise SkillError(400, f"{target!r} matches {len(hits)} services: {names}. Name one by its key, e.g. "
                              f"/stop-orders draft {hits[0]['key']}.")
    return hits[0]


def _without_pointless(db: Session, case: Any, rows: list[dict], targets: dict | None = None) -> list[dict]:
    """The plan rows through the request gate (app.domain.request_gate), as the board's rows: the drafts it calls
    pointless (request_gate.State.pointless: the provider answered LE only / declined, its playbook gates us) left out
    — never "waiting to be sent" nor linked for review; a row left with no draft says why, naming its row's step. A
    row the plan would recommend (no stop order on file, or one declined) that the gate gives no stop order (LE only,
    the playbook's LE-only gate, a request already out: only its follow-up) is no stop order to draft: its status says
    what the gate says instead (its row's step), never "Draft for <name>" nor counted in "all N recommended". So is one
    the board (`targets`: authority key -> its freeze-board row) does not draft (its generator's rule); one it drafts
    as a notice (an issuer acting on LE process only: the LE route is the move, the letter flags the wallets) keeps
    `notice` True."""
    from app.domain import request_gate as rg

    out = []

    def board(r: dict) -> dict:
        """A row the plan would recommend, as the board's generator reads it (after the request gate)."""
        t = (targets or {}).get(r["key"])
        if t is None or not (r["status"] in DRAFTABLE and r["can_draft"]):
            return r
        if not t.draftable:
            step = t.step.label or t.step.lead
            return {**r, "status": "gated", "can_draft": False,
                    "status_text": f"{t.status_label}: no new letter" + (f"; next step “{step}”" if step else "")}
        return {**r, "notice": True} if t.notice_only else r

    for r in rows:
        todo = r["status"] in DRAFTABLE and r["can_draft"]
        if not r["draft_ids"] and not todo:
            out.append(r)
            continue
        try:
            a = desk.get_authority(db, case, r["key"])
            st = rg.state(db, case, a) if a is not None else None
        except rg.Unavailable:
            st = None
        if st is None:
            out.append(board(r))
            continue
        d = rg.decide(st, "stop_order")
        label = st.step or (d.label() if d.href and not d.allowed else "")
        step = f": next step on its row “{label}”" if label else ", see its row"
        if todo:
            fo = rg.freeze_over_records(st) if d.kind == rg.OPEN_EXISTING else None
            if fo is not None and d.key == fo["key"]:  # the stop order replacing a records-only draft (its row's step)
                out.append({**r, "status": "gated", "can_draft": False,
                            "status_text": f"Draft {fo['no']} asks for records only: “{fo['label']}” on its row"})
                continue
            if d.kind in (rg.LE_BRIEF_ONLY, rg.FOLLOW_UP_ONLY):
                why = (f"Answered {st.le_only}: brief LE" if st.le_only else "LE requests only: brief LE" if st.gated
                       and d.kind == rg.LE_BRIEF_ONLY else
                       f"Already asked (request {d.no}): follow it up" if d.no else "Already asked: follow it up")
                out.append({**r, "status": "gated", "status_text": f"{why}{step}", "can_draft": False})
                continue
        gone = {x.order.id for x in st.pointless if x.order is not None}
        if not gone & set(r["draft_ids"]):
            out.append(board(r))
            continue
        left = [i for i in r["draft_ids"] if i not in gone]
        why = (f"answered {st.le_only}" if st.le_only else "LE requests only" if st.gated else "drafted before "
               "their reply")
        out.append(board({**r, "draft_ids": left, **({} if left or r["status"] != "draft" else {
            "status": "pointless", "status_text": f"Draft pointless ({why}): brief LE{step}"})}))
    return out


def _drafts_waiting(case_id: int, rows: list[dict]) -> str:
    """'Drafts are waiting to be reviewed and sent for: …' with a link to each draft."""
    parts = []
    for r in rows:
        links = ", ".join(f"[stop order #{i}]({_link(case_id, f'/stop-orders/{i}')})" for i in r["draft_ids"])
        parts.append(f"{_md(r['entity'])}" + (f" ({links})" if links else ""))
    return ("Drafts are waiting to be reviewed and sent for: " + "; ".join(parts) + ". A draft is not a request: "
            "until it is sent and marked sent, these services are still recommended.")


def _draft_review_actions(case_id: int, rows: list[dict]) -> list[dict]:
    return [{"label": f"Review draft stop order #{i}", "href": _link(case_id, f"/stop-orders/{i}")}
            for r in rows for i in r["draft_ids"]][:6]


def _gate_reason(db: Session, access: CaseAccess, authority) -> str | None:
    """Why no stop order is drafted for `authority` (the request gate, app.domain.request_gate: one open request per
    provider), naming the board row's own next step (the whole board: a Recovery plan owner move can be a contacted
    service's step); freeze_board.GATE_ERROR when its requests cannot be read; None when one may be drafted."""
    from app.blocks import freeze_board
    from app.domain import request_gate as rg

    try:
        st = rg.state(db, access.case, authority)
    except rg.Unavailable:
        return freeze_board.GATE_ERROR
    d = rg.decide(st, "stop_order")
    if d.allowed:
        return None
    fo = rg.freeze_over_records(st) if d.kind == rg.OPEN_EXISTING else None
    if fo is not None and d.key == fo["key"]:  # a records-only draft: the stop order replacing it leads, never "send it"
        return f"{fo['text']} Next step on its row: “{fo['label']}” (on its authority page)."
    if st is not None:
        st.step = freeze_board.row_step(db, access.case, access, authority) or st.step
    return rg.with_step(d, st).text


def _draft_stop_orders(db: Session, access: CaseAccess, rows: list[dict], target: str, run_id: int,
                       red: Callable[[str | None], str | None]) -> SkillResult:
    case = access.case
    t = target.strip().lower()
    draftable = [r for r in rows if r["can_draft"] and r["status"] in DRAFTABLE]
    if t in ("", "all"):
        chosen = draftable
        if not chosen:
            waiting = [r for r in rows if r["status"] == "draft"]
            return SkillResult(markdown=("Nothing to draft: " + (_drafts_waiting(case.id, _shown_rows(waiting, red))
                                                                 if waiting else
                                         "every freeze candidate already has a stop order on file.")),
                               actions=_draft_review_actions(case.id, waiting),
                               suggested_commands=["/stop-orders", "/follow-ups"])
    else:
        row = _match_service(rows, t, target, red)
        if row not in draftable:
            if row["status"] == "draft":
                msg = _drafts_waiting(case.id, _shown_rows([row], red))
            else:
                # the request gate's reason (an open draft, a request already out: its follow-up, LE only: the LE
                # brief) naming the board row's own next step, else the plan's status; never a second request
                from app.blocks import freeze_board

                authority = desk.get_authority(db, case, row["key"], run=services.latest_run(db, case))
                why = _gate_reason(db, access, authority) if authority is not None else None
                last = row["orders"][-1] if row["orders"] else None
                if why == freeze_board.GATE_ERROR:  # never drafted blind
                    reason = f"Not drafted: {_md(why)}."
                elif why and row["status"] == "gated":  # the plan would recommend it; the gate refuses a stop order
                    reason = f"Not drafted: {_md(red(why))}"
                elif why:
                    reason = f"{_md(red(why))} Nothing drafted."
                else:
                    reason = (_md(row["status_text"])
                              + (f" (stop order #{last['id']}, {_md(last['status'])})" if last else "")
                              + ". Nothing drafted: a follow-up is a status request on that request (/follow-ups), "
                                "and a target that answered LE only gets the LE brief (its row on the Authorities "
                                "tab).")
                msg = f"{_md(red(row['entity']))}: {reason}"
            return SkillResult(markdown=msg, actions=_draft_review_actions(case.id, [row]),
                               suggested_commands=["/stop-orders", "/follow-ups"])
        chosen = [row]
    from app.blocks import freeze_board

    latest = services.latest_run(db, case)
    drafts, notes = [], []
    for r in chosen:
        authority = desk.get_authority(db, case, r["key"], run=latest)
        if authority is None:
            notes.append(f"{_md(red(r['entity']))}: no longer listed")
            continue
        # one open request per provider (app.domain.request_gate): never a second request to a target with a draft,
        # a request out (its follow-ups only), an LE-only / declined answer
        why = _gate_reason(db, access, authority)
        if why:
            notes.append(f"{_md(red(r['entity']))}: {_md(red(why))}")
            continue
        run = desk.letter_run(db, case, authority, latest)
        try:
            corr = desk.generate_letter(db, case, authority, "stop_order", actor=access.user, run=run)
        except desk.GateRefused as exc:
            notes.append(f"{_md(red(r['entity']))}: {_md(red(str(exc)))}")
            continue
        except desk.DeskError as exc:
            notes.append(f"{_md(red(r['entity']))}: {_md(red(str(exc)))}")
            continue
        _audit_draft(db, access, corr, "stop_order", run.id if run else run_id, "stop-orders")
        drafts.append(_draft_row(case.id, corr, red(r["entity"]) or r["entity"]))
    out = []
    if drafts:
        out.append(_drafts_md(drafts))
    if notes:
        out += ["", "**Not drafted:**"] + [f"- {n}" for n in notes]
    actions = [{"label": f"Review draft #{d['id']}", "href": d["href"]} for d in drafts[:6]]
    return SkillResult(markdown="\n".join(out).strip(), actions=actions, drafts=drafts,
                       suggested_commands=["/stop-orders", "/follow-ups", "/le-update"])


@skill("follow-ups", "Follow-ups", "Unanswered stop orders past their reply date; investigators can draft the status "
       "requests (/follow-ups draft). Nothing is sent.", args="[draft]", drafts=True)
def _follow_ups(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    draft, _rest = _wants_draft(args)
    d = _ctx(db, case).get("derived") or {}
    due = d.get("status_request_due") or []
    late_letters = [o for o in d.get("overdue") or [] if o["type"] == "correspondence" and o.get("direction") == "out"]
    if draft:
        _require_drafting(actor, "follow-ups")
        return _draft_follow_ups(db, actor, due)
    if not due and not late_letters:
        upcoming = d.get("upcoming_deadlines") or []
        # stop-order replies only: upcoming_deadlines also holds internal follow-up notes
        nxt = min((u["due"] for u in upcoming if u.get("due") and u.get("type") == "stop_order"), default=None)
        return SkillResult(markdown="No stop order is past its reply date without a status request. "
                                    + (f"The next stop-order reply falls due on {_day(nxt)}. " if nxt else "")
                                    + "[derived.status_request_due]",
                           suggested_commands=["/stop-orders", "/timeline", "/next-steps"])
    out = ["**Follow-ups due** [derived.status_request_due]"]
    rows = [[f"#{f['stop_order_id']}", _cell(f["entity"]), _cell(kind_text(f["kind"])), _day(f["due"]),
             _cell(f.get("reply_status_label") or "no answer yet"),
             str(f["days_since_sent"] if f["days_since_sent"] is not None else "—"),
             f"draft #{f['drafted_status_request_id']} waiting" if f.get("drafted_status_request_id") else "none"]
            for f in due]
    if rows:
        out.append(_table(["Stop order", "Recipient", "Kind", "Reply was due", "Their answer", "Days since sent",
                           "Status request"], rows))
    if late_letters:
        out += ["", "**Other letters past their reply date** [derived.overdue]"]
        out += [f"- {_md(o['entity'] or 'Recipient')}: {_md((o['kind'] or '').replace('_', ' '))} due {_day(o['due'])} "
                f"[correspondence#{o['id']}]" for o in late_letters]
    actions = []
    todo = [f for f in due if not f.get("drafted_status_request_id")]
    if actor.can("draft_letter") and todo:
        actions.append({"label": f"Draft {len(todo)} status request{'s' if len(todo) != 1 else ''}",
                        "command": "/follow-ups draft"})
    for f in due:
        if f.get("drafted_status_request_id"):
            actions.append({"label": f"Review draft #{f['drafted_status_request_id']}",
                            "href": _link(case.id, f"/authorities/correspondence/{f['drafted_status_request_id']}")})
    out += ["", "_Status requests are prepared as drafts only; a person sends each one and clicks **Mark sent**._"]
    return SkillResult(markdown="\n".join(out), actions=actions, suggested_commands=["/stop-orders", "/le-update",
                                                                                     "/timeline"])


def _draft_follow_ups(db: Session, access: CaseAccess, due: list[dict]) -> SkillResult:
    case = access.case
    latest = services.latest_run(db, case)
    red = _red(db, case)
    drafts, notes, existing = [], [], []
    for f in due:
        if f.get("drafted_status_request_id"):
            existing.append(f["drafted_status_request_id"])
            continue
        order = next((o for o in case.stop_orders if o.id == f["stop_order_id"]), None)
        if order is None or order.entity_id is None:
            notes.append(f"stop order #{f['stop_order_id']}: no recipient on file")
            continue
        authority = desk.get_authority(db, case, f"entity-{order.entity_id}", run=latest)
        ref = next((r["value"] for r in desk.sent_references(authority) if r["order"] is not None
                    and r["order"].id == order.id), None) if authority else None
        if authority is None or ref is None:
            notes.append(f"stop order #{order.id}: nothing sent to refer to")
            continue
        try:
            corr = desk.generate_letter(db, case, authority, "status_request", actor=access.user, run=latest, ref=ref)
        except desk.DeskError as exc:
            notes.append(f"stop order #{order.id}: {_md(exc)}")
            continue
        _audit_draft(db, access, corr, "status_request", latest.id if latest else None, "follow-ups")
        drafts.append(_draft_row(case.id, corr, red(authority.name) or authority.name))
    out = []
    if drafts:
        out.append(_drafts_md(drafts))
    if existing:
        out += ["", "Already drafted earlier (not sent): " + ", ".join(
            f"[#{i}]({_link(case.id, f'/authorities/correspondence/{i}')})" for i in existing)]
    if notes:
        out += ["", "**Not drafted:**"] + [f"- {n}" for n in notes]
    if not out:
        out = ["No stop order needs a status request right now. [derived.status_request_due]"]
    actions = [{"label": f"Review draft #{d['id']}", "href": d["href"]} for d in drafts[:6]]
    return SkillResult(markdown="\n".join(out).strip(), actions=actions, drafts=drafts,
                       suggested_commands=["/follow-ups", "/le-update", "/next-steps"])


@skill("next-steps", "Next steps", "The prioritised next actions for the case team, with who usually owns them.",
       needs_ai=True)
def _next_steps(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    state = casestate.case_state(db, case, actor)
    s = rule_summary(_ctx(db, case), state)
    steps = s["next_steps"]
    ranked = [n for n in steps if n.get("rank") is not None]
    rest = [n for n in steps if n.get("rank") is None]
    if state.get("moves") is not None:
        hidden = set(state.get("hidden") or ())
        lines = ["**Next moves** — the Recovery plan's order (the board and the To do list follow it) [recovery_plan]", ""]
        if ranked:
            rows = [[str(n["rank"]), _cell(n["action"]), _cell(n.get("value") or "—"), _cell(n.get("next") or "—"),
                     _cell(n.get("clock") or "—")] for n in ranked[:15]]
            lines.append(_table(["#", "Move", "At stake", "Next step", "Clock"], rows,
                                {i for i, n in enumerate(ranked[:15]) if n.get("key") in hidden}))
        else:
            lines.append("No move to make now: every target is waiting on someone else, secured or closed.")
        waiting = state.get("waiting") or []
        if waiting:
            lines += ["", f"_Waiting on others ({len(waiting)}): " + "; ".join(
                _md(w["title"]) + (f" ({_md(w['clock'])})" if w.get("clock") else "") for w in waiting[:8]) + "._"]
        if rest:
            lines += ["", "**Also**"] + [f"- {_md(n['action'])} — {_md(n['rationale'])}" for n in rest[:6]]
        md = "\n".join(lines)
    else:
        md = ("**Next steps** (Aegis's rule checks, highest priority first)\n\n"
              + (_table(["Priority", "Action", "Owner", "Why"], [[_cell(n["priority"]), _cell(n["action"]),
                                                                  _cell(n["owner_role"].replace("_", " ")),
                                                                  _cell(n["rationale"])] for n in steps[:15]])
                 if steps else "No open action identified by the rule checks."))
    sugg = ["/recovery-plan"]
    text = " ".join((n["action"] + " " + str(n.get("next") or "")).lower() for n in steps)
    if "stop order" in text:
        sugg.append("/stop-orders")
    if "chase" in text or "status request" in text:
        sugg.append("/follow-ups")
    if "trace" in text or "dormant" in text or "owner" in text:
        sugg.append("/analyze-flow")
    base = SkillResult(markdown=md, suggested_commands=sugg + ["/todo", "/evidence-gaps"],
                       actions=[{"label": "Open Recovery plan", "href": _link(case.id, "/recovery-plan")}])
    return _with_ai(db, actor, SKILLS["next-steps"], args,
                    "List the next moves for the case team in the order of Aegis's findings (the Recovery plan's "
                    "ranking), each with what to do and why, as a short table or list. Operational steps only, no legal "
                    "advice.", base)


def _node_rows(db: Session, run_id: int, address: str) -> list[TraceNode]:
    return db.scalars(select(TraceNode).join(Address, TraceNode.address_id == Address.id)
                      .where(TraceNode.run_id == run_id, func.lower(Address.address) == address.lower())).all()


def _owner_of(db: Session, case: Any, run: Any, a: Address) -> dict | None:
    from app.attribution import service as attr

    return attr.by_key(db, case, run=run).get(attr.key_of(a.chain.value, a.address))


def _owner_md(o: dict | None, red) -> list[str]:
    """Who owns the wallet (app.attribution; never a person's note) as one line."""
    if not o:
        return []
    return [(f"- Owner: **{_md(red(o['owner_label']))}** — {_md(o['kind_label'])}, confidence {o['confidence']} "
            f"({_md(o['source_label'])}); next: {_md(red((o.get('ask') or {}).get('text') or '—'))} [owners]")]


@skill("wallet", "Explain a wallet", "One wallet in the latest trace: its role, inflows and outflows, freeze status "
       "and what to do about it.", args="<address>", needs_ai=True)
def _wallet(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    addr = (args or "").strip().split(" ")[0]
    run = services.latest_run(db, case)
    if run is None:
        return SkillResult(markdown="No trace run yet, so no wallet can be explained. [trace]",
                           suggested_commands=["/next-steps"])
    red = _red(db, case)
    if not addr:
        nodes = sorted(run.nodes, key=lambda n: -(n.taint_usd or 0))[:10]
        md = ("Name a wallet: `/wallet <address>`. The ten wallets carrying the most traced value:\n\n"
              + _table(["Wallet", "Label", "Tainted USD"], [[_code(n.address.address), _cell(red(n.address.label) or "—"),
                                                              _money(float(n.taint_usd or 0))] for n in nodes]))
        return SkillResult(markdown=md, actions=[{"label": f"Explain {_short(n.address.address)}",
                                                  "command": f"/wallet {n.address.address}"} for n in nodes[:4]],
                           suggested_commands=["/analyze-flow"])
    if not ADDRESS_RE.fullmatch(addr):
        raise SkillError(400, "That does not look like a wallet address or placeholder.")
    found = _node_rows(db, run.id, addr)
    if not found:
        return SkillResult(markdown=f"{_code(addr)} is not part of trace run #{run.id}. Check the address, or extend "
                                    "the trace if it is new. [trace.nodes]", suggested_commands=["/wallet", "/analyze-flow"])
    node = found[0]
    a = node.address
    edges = db.scalars(select(TraceEdge).join(Transfer, TraceEdge.transfer_id == Transfer.id)
                       .where(TraceEdge.run_id == run.id,
                              or_(Transfer.from_address_id == a.id, Transfer.to_address_id == a.id))).all()
    edges.sort(key=lambda e: (e.transfer.timestamp, e.transfer.tx_hash))

    def leg(e: TraceEdge, other: Address) -> list[str]:
        t = e.transfer
        amount = f"{_amount(t.amount, t.asset)} {t.asset}" if t.amount is not None else f"? {t.asset}"
        return [_when(t.timestamp.isoformat()), _cell(amount), _money(float(t.amount_usd) if t.amount_usd is not None
                                                                      else None),
                f"{_code(_short(other.address))} {_cell(red(other.label) or '')}".strip(),
                "asserted" if t.tx_hash.startswith("ASSERTED:") else _code(_short(t.tx_hash))]

    ins = [leg(e, e.transfer.from_address) for e in edges if e.transfer.to_address_id == a.id]
    outs = [leg(e, e.transfer.to_address) for e in edges if e.transfer.from_address_id == a.id]
    flags = sorted(node.flags or [])
    status = wallet_status(db, case, run).get(a.address.lower())
    orders = [o for o in case.stop_orders if a.address.lower() in _addresses(o)
              and desk.order_state(o) != "superseded"]
    watched = any(w.active and w.address_id == a.id for w in case.watch_items)
    own = _owner_of(db, case, run, a)
    kind = (own or {}).get("kind") or "unknown"
    ask = (own or {}).get("ask") or {}
    out = [f"**Wallet {_code(a.address)}** ({a.chain.value}) — trace run #{run.id} [trace.nodes]", "",
           f"- Role: {_md(_type_text(a.address_type.value))}" + (f", {_md(red(a.entity.name))}" if a.entity else "")
           + (f" — {_md(red(a.label))}" if a.label else ""),
           *_owner_md(own, red),
           f"- Hop {node.hop}; traced value {_money(float(node.taint_usd or 0))}"
           + (f" ({node.taint_fraction * 100:.1f}% of the loss)" if node.taint_fraction else "")
           + (f"; the trace stops here ({_md(TERMINAL_TEXT.get(node.terminal_reason or '', 'end point'))})"
              if node.is_terminal else "")]
    out += [f"- {_md(FLAG_TEXT.get(f, f))}" for f in flags if f in FLAG_TEXT]
    out += ["", f"**Inflows** ({len(ins)} transfers in this run, asserted ones included)",
            _table(["When (UTC)", "Amount", "USD", "From", "Tx"], ins[:15]) if ins else "- none in this run"]
    out += ["", f"**Outflows** ({len(outs)} transfers in this run, asserted ones included)",
            _table(["When (UTC)", "Amount", "USD", "To", "Tx"], outs[:15]) if outs else "- none observed in this run"]
    out += ["", "**Freeze status**"]
    t = _board_targets(db, case, actor).get(status["key"]) if status else None
    if orders:
        out += [f"- Cited in stop order #{o.id} to {_md(red(o.entity.name) if o.entity else 'recipient')}"
                for o in orders]
    if t is not None:  # the freeze & stop-order board's row for the service: its status and next step
        out.append(f"- {_md(red(t.name))} on the freeze & stop-order board: {_md(t.status_label)}"
                   + (f" — next step: {_md(red(t.step.label))}" if t.step.label else ""))
    elif status and not orders:
        out.append(f"- {_md(red(status['entity']))}: {STATUS_TEXT[status['status']]}")
    elif not orders:
        out.append("- Not cited in any stop order on file")
    out.append(f"- Watch list: {'watched for movement' if watched else 'not watched'}")
    rec = []
    if own and (own.get("owner") or kind != "unknown") and ask.get("text"):
        rec.append(f"{_md(red(ask['text']))} (who owns it: {_md(red(own['owner_label']))}, {_md(own['kind_label'])}).")
    if t is not None and (t.step.label or t.step.lead):  # the board's own next step (through the request gate)
        rec.append(f"{_md(red(t.name))}: " + (f"**{_md(red(t.step.label))}**" if t.step.label else "")
                   + (" — " if t.step.label and t.step.lead else "") + _md(red(t.step.lead)))
    else:
        for o in orders:
            if desk.order_state(o) in ("sent", "acknowledged"):
                rec.append(f"Stop order #{o.id} to {_md(red(o.entity.name) if o.entity else 'the recipient')} is on "
                           f"file ({desk.order_state(o)}); chase it once the reply falls due (`/follow-ups`).")
    # an owner a person / an explorer names other than the trace's entity is the one asked (an issuer's blacklist
    # still applies whoever owns the wallet): never a second recipient
    named = (own or {}).get("owner")
    other = bool(named and status and str(named).casefold() != str(status.get("entity") or "").casefold()
                 and str(status.get("category") or "") != "stablecoin_issuer")
    if status and status["status"] in ("recommended", "declined") and not other and t is None:
        rec.append(f"Send a stop order to {_md(red(status['entity']))} (`/stop-orders`).")
    if "vasp_deposit" in flags and not orders and not status and not (own or {}).get("owner"):
        rec.append("Ask the service holding this deposit address to freeze it (`/stop-orders`).")
    if "sweep_imminent" in flags:
        rec.append("Act now: the service usually sweeps deposits within hours.")
    if "dormant" in flags and not node.is_terminal and kind in ("unhosted", "unknown"):
        rec.append("Self-custody and dormant: keep it on the watch list and extend the trace from here; a USDT/USDC "
                   "balance can be blacklisted by its issuer.")
    if "pending_input" in flags:
        rec.append("Placeholder: supply the real address or transaction so the trace can continue.")
    if "swap_service" in flags and kind not in ("non_custodial", "swap_bridge"):  # the owner's ask says what to do
        rec.append("Swap / bridge: request the order records (destination, IP, device) and follow the output chain.")
    if "asserted_link" in flags:
        rec.append("Verify the asserted hop on-chain (live trace) before citing it in a letter.")
    out += ["", "**Recommendation**"] + ([f"- {r}" for r in rec] or ["- No action flagged by the rule checks."])
    base = SkillResult(markdown="\n".join(out), suggested_commands=["/stop-orders", "/analyze-flow", "/timeline"],
                       actions=[{"label": "Open the fund-flow graph", "href": _link(case.id, "?tab=fund_flow")}])
    return _with_ai(db, actor, SKILLS["wallet"], a.address,
                    f"Explain wallet {a.address} to the case team: its role in the flow, what came in and went out, "
                    "whether a freeze or preservation request covers it, and what to do next.", base)


@skill("timeline", "Timeline", "The case in chronological order: the fraud, the traced transfers, complaints, stop "
       "orders, replies and alerts.")
def _timeline(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    ctx = _ctx(db, case)
    events: list[tuple[str, str, str]] = []
    c = ctx.get("case") or {}
    loss = c.get("loss") or {}
    if c.get("fraud_date"):
        events.append((c["fraud_date"], (f"Fraud: {qty(loss.get('amount'))} {loss.get('asset') or ''} "
                                        f"({_money(loss.get('usd'))}) left the victim wallet"), "case.loss"))
    for x in c.get("complaints") or []:
        if x.get("filed_at"):
            events.append((x["filed_at"], f"Complaint filed with {x['authority']}", "case.complaints"))
    trace = ctx.get("trace") or {}
    labels = {n["address"]: (n["entity"] or n["label"]) for n in trace.get("nodes") or []}
    for t in trace.get("tainted_transfers") or []:
        to = labels.get(t["to"])
        events.append((t["timestamp"], f"Hop {t['hop']}: {qty(t['amount'])} {t['asset']} {_short(t['from'])} → "
                                       f"{_short(t['to'])}" + (f" ({to})" if to else "")
                       + (" — asserted" if t["asserted"] else ""), "trace.tainted_transfers"))
    if trace.get("run"):
        r = trace["run"]
        events.append((r.get("finished_at") or r.get("started_at") or "", f"Trace run #{r['id']} {r['status']}",
                       "trace.run"))
    for o in ctx.get("stop_orders") or []:
        if o["sent_at"]:
            events.append((o["sent_at"], (f"Stop order #{o['id']} ({kind_text(o['kind'])}) sent to "
                                         f"{o['entity'] or 'recipient'}"), f"stop_orders#{o['id']}"))
        if o["responded_at"]:
            events.append((o["responded_at"], (f"{o['entity'] or 'Recipient'} answered stop order #{o['id']} "
                                              f"({(o.get('reply_status_label') or o['status'])})"),
                           f"stop_orders#{o['id']}"))
    for x in ctx.get("correspondence") or []:
        if x["occurred_at"] and not x.get("tracked_by_stop_order") and x["status"] != "draft":
            who = x["entity"] or x["le_agency"] or ("the case" if x["direction"] == "note" else "a counterparty")
            what = {"in": "Message from", "out": "Message to", "note": "Team note on"}.get(x["direction"], "Entry with")
            kind = (x["kind"] or "other").replace("_", " ")
            how = f"{kind}, {x['channel']}" if x["direction"] != "note" else kind
            events.append((x["occurred_at"], f"{what} {who}" + (f" ({how})" if how != "other" else ""),
                           f"correspondence#{x['id']}"))
    for al in (ctx.get("watch") or {}).get("recent_alerts") or []:
        events.append((al["created_at"] or "", f"Movement alert ({al['severity']})", "watch"))
    events = [e for e in events if e[0]]
    events.sort(key=lambda e: e[0])
    omitted = max(0, len(events) - 60)
    rows = [[_when(w), _cell(t), _cell(_source_text(s))] for w, t, s in events[-60:]]
    md = ("**Case timeline** (UTC)\n\n" + _table(["When", "Event", "Source"], rows)
          + (f"\n\n_{omitted} earlier events not shown._" if omitted else "")) if rows else "No dated events yet."
    return SkillResult(markdown=md, suggested_commands=["/analyze-flow", "/follow-ups", "/le-update"])


SOURCE_TEXT = {"case.loss": "Case", "case.complaints": "Complaint", "trace.tainted_transfers": "Trace",
               "trace.run": "Trace", "watch": "Watch list"}


def _source_text(src: str) -> str:
    """A timeline source key as the column shows it ('stop_orders#5' -> 'Stop order #5')."""
    head, _, n = src.partition("#")
    if head == "stop_orders" and n:
        return f"Stop order #{n}"
    if head == "correspondence" and n:
        return f"Authorities log #{n}"
    return SOURCE_TEXT.get(src, src.split(".")[0].replace("_", " ").capitalize())


EVIDENCE_CHECKS = (
    ("complaint", "Police / IC3 complaint reference on file", ("LE and most exchanges ask for an official report "
                                                               "number before acting")),
    ("police_doc", "Police report or complaint receipt in the evidence", "attach it to exchange and issuer requests"),
    ("chain_report", "Chain report (transfer table, graph) in the evidence", "Evidence tab → Snapshot trace report"),
    ("comms", "Communications with the perpetrators (chats, e-mails)", "shows the fraud, not just the transfers"),
    ("authority", "Authorisation to act for the victim (power of attorney / mandate)", ("exchanges ask who is "
                                                                                         "requesting and on whose behalf")),
    ("ownership", "Proof the victim controls the sending wallet / account", ("e.g. a signed message, exchange "
                                                                          "statement or wallet screenshot")),
    ("correspondence", "Copies of the stop orders and replies in the evidence", "keeps the LE file complete"),
)


@skill("evidence-gaps", "Evidence gaps", "What evidence is still missing for law-enforcement and exchange requests.",
       needs_ai=True)
def _evidence_gaps(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    ctx = _ctx(db, case)
    items = ev.visible_items(actor)
    folders = {getattr(e.folder, "value", e.folder) for e in items}
    types = {(e.source_type or "").lower() for e in items}
    tags = {str(t).lower() for e in items for t in (e.tags or [])}
    complaints = (ctx.get("case") or {}).get("complaints") or []
    have = {
        "complaint": any(x.get("reference_on_file") for x in complaints),
        "police_doc": bool(types & {"police_report", "complaint_receipt", "complaint"}) or "law_enforcement" in folders,
        "chain_report": "chain_reports" in folders or any(t.startswith("chain-report") for t in tags),
        "comms": bool(types & {"chat_export", "transcript", "eml", "email", "chat", "screenshot"})
        or "digital_artifacts" in folders,
        "authority": "legal" in folders or bool(types & {"power_of_attorney", "mandate", "authorisation"}),
        "ownership": bool(types & {"wallet_ownership", "exchange_statement", "bank_statement", "signed_message"}),
        "correspondence": "stop_orders_correspondence" in folders,
    }
    rows = [[("present" if have[k] else "**missing**"), _cell(title), _cell(why)] for k, title, why in EVIDENCE_CHECKS]
    gaps = rule_summary(ctx)["data_gaps"]
    md = ("**Evidence checklist for LE and exchange requests** [evidence_index] [case.complaints]\n\n"
          + _table(["", "Item", "Why / how"], rows)
          + f"\n\n_{len(items)} evidence item(s) visible to you were checked by type and folder only; contents are "
            "not read._")
    if gaps:
        md += "\n\n**Data gaps in the trace**\n" + "\n".join(f"- {_md(g)}" for g in gaps[:8])
    actions = [{"label": "Open Evidence", "href": _link(case.id, "?tab=evidence")}]
    base = SkillResult(markdown=md, actions=actions, suggested_commands=["/le-update", "/stop-orders", "/timeline"])
    return _with_ai(db, actor, SKILLS["evidence-gaps"], args,
                    "Say which evidence is still missing before the next law-enforcement update and exchange / issuer "
                    "requests, most important first, and how to obtain each item. Use the checklist in the findings.",
                    base)


@skill("le-update", "LE update", "Draft an update for the police / IC3 (law-enforcement cover letter with the "
       "identifiers, where the funds sit and every stop order's status). Draft only; never sent.",
       min_role=INVESTIGATOR, args="[authority]", drafts=True)
def _le_update(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    _require_drafting(actor, "le-update")
    latest = services.latest_run(db, case)
    les = [a for a in desk.case_authorities(db, case, run=latest) if a.is_le]

    def name(a: desk.Authority) -> str:
        return authority_type(a.name, a.jurisdiction, category=a.category) or a.type_label

    if not les:
        return SkillResult(markdown="No law-enforcement authority is on file for this case (complaints or LE contacts). "
                                    "Add the complaint on the case or an LE contact on the Evidence tab first.",
                           suggested_commands=["/evidence-gaps"])
    _, target = _wants_draft(args)
    t = target.strip().lower()
    if not t:
        md = ("Which authority should the update go to? Each draft is a law-enforcement cover letter summarising the "
              "identifiers, where the funds sit and every stop order's status.\n\n"
              + "\n".join(f"- {_md(name(a))} (`{a.key}`)" for a in les))
        return SkillResult(markdown=md, actions=[{"label": f"Draft update to {name(a)}", "command": f"/le-update {a.key}"}
                                                 for a in les[:5]], suggested_commands=["/evidence-gaps", "/timeline"])
    chosen = next((a for a in les if a.key == t), None) or next((a for a in les if t in name(a).lower()
                                                                 or t in a.name.lower()), None)
    if chosen is None:
        raise SkillError(404, f"No law-enforcement authority matching {target!r}. Run /le-update to see the list.")
    try:
        corr = desk.generate_letter(db, case, chosen, "le_cover", actor=actor.user, run=latest)
    except desk.DeskError as exc:
        raise SkillError(400, str(exc)) from None
    _audit_draft(db, actor, corr, "le_cover", latest.id if latest else None, "le-update")
    row = _draft_row(case.id, corr, name(chosen))
    return SkillResult(markdown=_drafts_md([row]), actions=[{"label": f"Review draft #{corr.id}", "href": row["href"]}],
                       drafts=[row], suggested_commands=["/evidence-gaps", "/follow-ups", "/timeline"])


# --------------------------------------------------------------------------- on-chain freeze status
@skill("freeze-status", "On-chain freeze status", "Which wallets Tether / Circle have blacklisted on-chain (amounts, "
       "freeze times, block, failing transfers), which are not checked yet, and what to do next. Read-only: it "
       "shows the stored readings and never queries the chain.")
def _freeze_status(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    from app.db.models import Entity
    from app.freeze.issuers import ISSUER_ENTITY
    from app.freeze.service import case_status

    st = case_status(db, case)
    red = _red(db, case)
    page = _link(case.id, "/freeze")
    actions: list[dict] = [{"label": "Open on-chain freeze status", "href": page}]

    def who(w: dict) -> str:
        """The trace's own name for a trace wallet (entity, else the address label); a watched wallet's
        free-text label is never shown here (it stays on the case's freeze page, whatever its TLP)."""
        if w.get("in_trace") and w.get("entity"):
            return _cell(red(w["entity"]))
        if w.get("in_trace") and w.get("label"):
            return _cell(red(w["label"]))
        if w.get("in_trace"):
            return "—"
        return "watched wallet" + (f" ({_cell(w['tlp'])})" if w.get("tlp") else "")

    out = ["**On-chain freeze status** — issuer blacklists read from the token contracts [freeze_checks]", ""]
    if st["deployment_disabled"]:
        out.append("On-chain freeze checks are switched off on this server.")
    elif not st["enabled"]:
        out.append("On-chain freeze checks are **off** for this case: Aegis has sent no wallet to any public "
                   "endpoint. A case admin can turn them on on the freeze page (it lists what each endpoint receives).")
    else:
        last = f"{st['last_run_at']:%Y-%m-%d %H:%M} UTC" if st["last_run_at"] else "not yet"
        out.append(f"Checks are **on**; last run {last} (every {st['interval_minutes']} min on the scheduler).")
    out += ["", f"- Wallets to check: {st['n_wallets']} ({st['n_checked']} checked, {len(st['unchecked'])} not yet)",
            f"- Frozen on-chain: {len(st['frozen'])} wallet(s), {_money(st['frozen_usd'])} in their balances"]
    steps: list[str] = []
    if st["frozen"]:
        rows = []
        for w in st["frozen"]:
            for c in w["checks"]:
                if not c["blacklisted"]:
                    continue
                basis = (f"blacklisted {_when(c['frozen_at'])}" if c["frozen_at_basis"] == "event"
                         else f"at or before {_when(c['frozen_at'])}")
                rows.append([_code(_short(w["address"])), _cell(w["chain_label"]), who(w), _cell(c["issuer"]),
                             _cell(f"{c['balance_label']} {c['symbol']}"), _cell(basis),
                             _code(_short(c["freeze_tx_hash"])) if c["freeze_tx_hash"] else "—",
                             str(c["block_number"] or "—"), str(c["failed_count"] or 0)])
                steps.append(f"{_md(c['issuer'])} froze {_code(_short(w['address']))} ({_md(c['balance_label'])} "
                             f"{_md(c['symbol'])}): send {_md(c['issuer'])} an LE-cover letter asking it to keep the "
                             "funds held for law enforcement / seizure, citing the freeze and the police reference.")
        out += ["", "**Blacklisted by the issuer**",
                _table(["Wallet", "Chain", "Label", "Issuer", "Balance", "Frozen", "Freeze tx", "Block", "Failed tx"],
                       rows[:MAX_TABLE_ROWS])]
        for issuer in sorted({c["issuer"] for w in st["frozen"] for c in w["checks"] if c["blacklisted"]}):
            ent = db.scalar(select(Entity).where(Entity.name == ISSUER_ENTITY.get(issuer, issuer)))
            if ent is not None:
                actions.append({"label": f"Open {issuer} (authority)", "href": _link(case.id, f"/authorities/entity-{ent.id}")})
    if st["failing"]:
        rows = [[_code(_short(w["address"])), _cell(w["chain_label"]), who(w),
                 _cell("; ".join(f"{c['issuer']} {c['symbol']}: {c['failed_count']} since {_when(c['first_failed_at'])}"
                                 for c in w["checks"] if c["failed_count"]))] for w in st["failing"]]
        out += ["", "**Transfers failing (not blacklisted)**", _table(["Wallet", "Chain", "Label", "Failed attempts"],
                                                                      rows[:MAX_TABLE_ROWS])]
        steps.append("Failing transfers without a blacklist usually mean too little balance or gas; re-check before "
                     "treating them as a freeze.")
    if st["unchecked"]:
        out += ["", f"**Not checked yet** ({len(st['unchecked'])}): "
                + ", ".join(f"{_code(_short(w['address']))} ({_md(w['chain_label'])})" for w in st["unchecked"][:15])]
        if st["enabled"]:
            steps.append("Press **Check freeze status now** on the Overview or the freeze page to read them.")
    if st["errors"]:
        out += ["", f"**Checks that failed** ({len(st['errors'])}): "
                + ", ".join(f"{_code(_short(w['address']))}" for w in st["errors"][:15]) + " — the next run retries."]
    if st.get("moved"):
        out += ["", "**Funds left these wallets** (the balance fell between two good readings)"]
        for w in st["moved"][:MAX_TABLE_ROWS]:
            for c in w["funds_left"]:
                f = c["funds_left"]
                out.append(f"- {_code(_short(w['address']))} ({_md(w['chain_label'])}): {_md(f['from_label'])} → "
                           f"{_md(f['to_label'])} {_md(c['symbol'])} between {_when(f['from_at'])} and {_when(f['at'])}")
        steps.insert(0, "Funds are moving: re-trace now and ask the next custodian or issuer (Recovery plan).")
    if st.get("stale"):
        out += ["", f"**Last attempt failed** ({len(st['stale'])}): "
                + "; ".join(f"{_code(_short(w['address']))}: {_md(c['stale_note'])}" for w in st["stale"][:10]
                            for c in w["stale"]) + " — the last good reading is shown."]
    clear = [w for w in st["wallets"] if w["state"] == "clear"]
    if clear:
        out += ["", f"Not blacklisted at the last check: {len(clear)} wallet(s)."]
    if st["not_visible"]:
        names = _md(", ".join(red(n) or n for n in st["not_visible"]))
        out += ["", (f"{names}: exchange / casino accounts cannot be seen on-chain; their freeze stays confirmed by "
                     "the recipient's reply (see /stop-orders).")]
    if not st["enabled"] and not st["deployment_disabled"]:
        steps.append("Ask a case admin to turn on on-chain freeze checks if the case's wallet addresses may be sent to "
                     "the public RPC / explorer endpoints.")
    if steps:
        out += ["", "**Next steps**"] + [f"{i}. {t}" for i, t in enumerate(dict.fromkeys(steps), 1)]
    return SkillResult(markdown="\n".join(out), actions=actions, suggested_commands=["/stop-orders", "/next-steps"])


@skill("block-status", "Block status", "What every authority answered to the blocks the case requested (stop orders, "
       "freeze and follow-up letters): status, days waiting and the next action per request, plus the issuers' "
       "on-chain readings. Read-only; reply text is never quoted.", needs_ai=True)
def _block_status(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    from app.blocks import classify_ai
    from app.blocks import status as bs

    rows = bs.case_blocks(db, case)
    red = _red(db, case)
    s = bs.summary(rows)
    # Reply-derived details (their ticket numbers, the addresses / portal URLs a reply names, the amounts a reply
    # states) reach the model's copy only when a case admin switched on "AI reads mailbox replies"; otherwise they are
    # masked there (placeholders, e-mail addresses always) and shown on the member's screen (casestate.reply_cleaner)
    replies_ok = classify_ai.is_enabled(case)
    clean = casestate.reply_cleaner(db, case, rows)
    if not replies_ok:
        s = dict(s)
        held: dict[str, Any] = {}
        for r in rows:
            if r.status in ("frozen", "hold_placed") and r.amount and r.kind != "onchain" \
                    and r.source not in ("rules", "ai"):
                held[r.asset or "?"] = held.get(r.asset or "?", 0) + (bs._dec(r.amount) or 0)
        s["frozen"] = {k: str(v) for k, v in held.items()}
    page = _link(case.id, "/blocks")
    out = ["**Block status** — every request across the authorities [stop_orders, correspondence]", "",
           (f"- Requests: {s['total']} ({s['awaiting']} waiting for an answer, {s['not_sent']} not sent, "
            f"{s['overdue']} overdue)"),
           (f"- To confirm: {s['needs_confirmation']} · to review: {s['to_review']} ({s['needs_review']} replies / "
            f"Outlook e-mails to review, {s['our_action']} requests waiting on our action)")]
    if s["frozen"]:
        out.append("- Held / frozen (confirmed by a person): " + ", ".join(
            f"{_md(bs.fmt_amount(v))} {_md(k)}" for k, v in s["frozen"].items()))
    table = []
    for r in rows[:MAX_TABLE_ROWS]:
        if r.kind == "onchain":
            continue
        status = casestate.status_text(r, replies_ok, clean)
        if r.overdue:
            status += " — reply overdue"
        if r.needs_confirmation:
            status += " (to confirm)"
        table.append([_cell(red(r.authority.name)), _cell(r.title), _cell(_dmy(r.requested_at)), _cell(status),
                      _cell(SOURCE_LABELS.get(r.source, r.source.replace("_", " "))),
                      str(r.days_waiting) if r.days_waiting is not None else "—",
                      _cell(clean((r.next_action or {}).get("text")) or "—")])
    if table:
        out += ["", _table(["Authority", "Request", "Sent", "Status", "Read from", "Days waiting", "Next action"], table)]
    else:
        out += ["", "No blocks requested yet: draft stop orders with /stop-orders."]
    levers = []
    for r in rows:
        oc = r.onchain or {}
        for e in oc.get("unfrozen_balance") or []:
            levers.append(f"{_md(red(r.authority.name))}: {_code(_short(e['address']))} ({_md(e['chain_label'])}) holds "
                          f"{_md(e['balance_label'])} {_md(e['symbol'])}, not blacklisted on-chain")
        for e in oc.get("frozen") or []:
            levers.append(f"{_md(red(r.authority.name))}: {_code(_short(e['address']))} ({_md(e['chain_label'])}) is "
                          f"blacklisted on-chain with {_md(e['balance_label'])} {_md(e['symbol'])}")
    if levers:
        out += ["", "**Issuers on-chain**"] + [f"- {x}" for x in dict.fromkeys(levers)]
    out += ["", ("_Statuses read from replies are advisory until a team member confirms them on the Block status "
                 "page._")]
    base = SkillResult(markdown="\n".join(out), actions=[{"label": "Open Block status", "href": page}],
                       suggested_commands=["/recovery-plan", "/follow-ups", "/freeze-status"])
    return _with_ai(db, actor, SKILLS["block-status"], args,
                    "Summarise the block status for the case team: which authorities froze or hold funds, which "
                    "need a resend, law-enforcement process or an answer, which are overdue, and the next action for "
                    "each, from Aegis's findings only. Statuses marked 'to confirm' are not confirmed yet.", base)


# where a request's status was read from (app.blocks.status.BlockRow.source), as the column says it
SOURCE_LABELS = {"recorded": "recorded by a person", "human": "confirmed by a person", "ai": "the reply (AI reading)",
                 "rules": "the reply (rules)", "onchain": "on-chain reading", "le_route": "the LE route", "none": "—"}


@skill("recovery-plan", "Recovery plan", "The ranked moves that trap the most money fastest: for each target (exchange, "
       "issuer, swap service, moving wallet) the value at stake, the clock, the provider's process for a letter from us, "
       "what it needs and the next step; the targets nobody has asked yet. Read-only and advisory.", needs_ai=True)
def _recovery_plan(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    from app.blocks import classify_ai
    from app.blocks import recovery as rp

    plan = rp.build(db, case)
    v = rp.view(plan, actor)
    # what replies said (their tickets, the portal URLs, wallets and ids they name) reaches the model's copy only when a
    # case admin switched on "AI reads mailbox replies" (as /block-status); a move built from what a reply names is on
    # the member's screen only
    clean = casestate.reply_cleaner(db, case, [m.row for m in plan.moves + plan.waiting if m.row is not None])
    hidden: set[str] = set()
    if not classify_ai.is_enabled(case):
        hidden = {m.key for m in plan.moves + plan.waiting if m.sensitive}

    t = v["totals"]
    out = [("**Recovery plan** — the moves that trap the most money fastest, best first [block_status, trace, "
           "freeze_checks, evidence]"), "",
           (f"- In play: {_money(t['in_play_usd'])} (traced values are upper bounds"
            f"{'; capped at the loss' if t.get('in_play_capped') else ''}) · expected (value × likelihood): "
            f"{_money(t['expected_usd'])}"),
           (f"- Not asked yet: {_money(t['untouched_usd'])} at {t['untouched']} target(s) · secured (confirmed by a "
           f"person / frozen on-chain): {_money(t['secured_usd'])}")]
    if t.get("next_clock"):
        out.append(f"- Next clock: {_md(t['next_clock']['label'])} {_md(t['next_clock']['due_fmt'])}")
    rows, only = [], set()
    for m in v["moves"][:MAX_TABLE_ROWS]:
        ev_open = m["evidence_counts"]["open"]
        if m["key"] in hidden:
            only.add(len(rows))
        rows.append([str(m["rank"]), _cell(clean(m["title"])), _cell(m["value_fmt"]), _cell(clean(m["reason"])),
                     _cell(f"{m['clock']['label']} {m['clock']['due_fmt']}" if m["clock"] else "—"),
                     _cell(f"{ev_open} to obtain: " + ", ".join(e["label"] for e in m["evidence"]
                                                                  if e["state"] in ("missing", "le", "unusable"))
                           if ev_open else "ready")])
    if rows:
        out += ["", _table(["#", "Move", "At stake", "Why", "Clock", "Evidence"], rows, only)]
    else:
        out += ["", "No move to make now: every target is waiting on someone else, secured or closed."]
    if v["waiting"]:
        lines = []
        for m in v["waiting"][:12]:
            line = (f"- {_md(clean(m['title']))}: {_md(clean(m['text']))}"
                    + (f" ({_md(m['clock']['label'])} {_md(m['clock']['due_fmt'])})" if m["clock"] else ""))
            lines.append(masked(line, "") if m["key"] in hidden else line)
        out += ["", "**Waiting on others**", *lines]
    left_out = sum(1 for x in v["moves"] + v["waiting"] if x["key"] in hidden)
    if left_out:  # never silently (for the model): the hottest lead can be one of them (a deposit address a reply names)
        out.append(masked("", f"\n_{left_out} move{'s' if left_out != 1 else ''} built from what replies name (a wallet, "
                              "a deposit address) are on the Recovery plan page, not shown here (\"AI reads mailbox "
                              "replies\" is off); the rank numbers skip them._"))
    for n in v["notes"]:
        out.append(f"\n_{_md(clean(n))}_")
    out += ["", ("_Advisory: Aegis's ranking from rules. A hold, freeze or return counts only once a person confirms it; "
                "a person drafts, reviews and sends every letter._")]
    base = SkillResult(markdown="\n".join(out), actions=[{"label": "Open Recovery plan",
                                                         "href": _link(case.id, "/recovery-plan")}],
                       suggested_commands=["/block-status", "/evidence-gaps", "/le-update"])
    return _with_ai(db, actor, SKILLS["recovery-plan"], args,
                    "Write a short narrative of the recovery plan for the case team: which moves to make first and why "
                    "(money at stake, the clocks, each provider's process for a letter from us, the jurisdiction route), "
                    "what each move still needs, and which targets nobody has asked yet. Use Aegis's findings only; "
                    "nothing is frozen until a person confirms it.", base)


@skill("todo", "To do", "The case's consolidated To do list, top items first: what should be done next (from the "
       "freeze & stop-order board, the Recovery plan, Block status, the mailbox, evidence and the case setup, plus the "
       "team's own tasks), with priority and due date. Read-only and advisory.", needs_ai=True)
def _todo(db: Session, case: Any, actor: CaseAccess, args: str) -> SkillResult:
    from app.blocks import classify_ai
    from app.domain import todo

    now = datetime.now(tz=UTC)
    tasks = todo.build(db, case, actor)
    red = _red(db, case)
    # a Recovery plan move built from what a reply names reaches the model's copy only when a case admin switched on "AI
    # reads mailbox replies" (as /recovery-plan): on the member's screen only; a task's "why" (it can quote a reply's
    # ticket) and a manual task's title (free text) are never quoted
    replies_ok = classify_ai.is_enabled(case)
    open_ = todo.open_tasks(tasks, now)
    hidden = 0 if replies_ok else sum(1 for t in open_ if t.sensitive)
    out = [(f"**To do** — {len(open_)} open, {todo.p1_open(tasks)} P1, "
           f"{sum(1 for t in open_ if t.overdue(now))} overdue [board, recovery_plan, block_status, mailbox, evidence, "
           "setup]"), ""]
    rows, only = [], set()
    for i, t in enumerate(open_[:MAX_TABLE_ROWS // 4], 1):
        what = f"manual task #{t.row.id}" if t.manual and t.row is not None else red(t.title) or ""
        due = (f"{t.due:%d %b %Y %H:%M} UTC ({todo.relative(t.due, now)})" if t.due else "—")
        if t.sensitive and not replies_ok:
            only.add(len(rows))
        rows.append([str(i), t.priority, _cell(what), _cell(due), _cell(t.source_label)])
    if rows:
        out.append(_table(["#", "Priority", "Task", "Due", "Source"], rows, only))
        if len(open_) > len(rows):
            out.append(f"\n_{len(open_) - len(rows)} more on the To do tab._")
    else:
        out.append("Nothing to do right now: every request is waiting on someone else, secured or closed.")
    if hidden:
        out.append(masked("", f"\n_{hidden} task{'s' if hidden != 1 else ''} built from what replies name are on the To "
                              "do tab, not shown here (\"AI reads mailbox replies\" is off)._"))
    if tasks.failed:
        out.append("\n_Could not read: " + ", ".join(todo.SOURCES.get(x, x) for x in tasks.failed) + "._")
    out += ["", ("_Advisory: Aegis's list from the case's state (rules). P1: overdue, due within 48 hours, or money at "
                 "stake with urgency; P2: due within 7 days, or money; P3: setup and optional. A person does every "
                 "step._")]
    base = SkillResult(markdown="\n".join(out), actions=[{"label": "Open To do", "href": _link(case.id, "?tab=todo")}],
                       suggested_commands=["/recovery-plan", "/block-status", "/evidence-gaps"])
    return _with_ai(db, actor, SKILLS["todo"], args,
                    "Say in a few sentences what the case team should do first and why (the P1 and overdue items, "
                    "then what is due this week), from Aegis's To do list only. Do not invent tasks.", base)


# --------------------------------------------------------------------------- suggestions
def validate_command(text: Any, access: CaseAccess, *, from_model: bool = False) -> str | None:
    """A shown suggestion: a registered command the member may run, with harmless arguments. Model
    suggestions never keep arguments that would create drafts."""
    if not isinstance(text, str):
        return None
    s = " ".join(text.strip().split())
    if not s:
        return None
    if not s.startswith("/"):
        s = "/" + s
    cmd, _, args = s[1:].partition(" ")
    sk = SKILLS.get(cmd.lower())
    if sk is None or not sk.allowed(access):
        return None
    if sk.drafts and (from_model or not access.can("draft_letter")):
        args = "" if _wants_draft(args)[0] or sk.command == "le-update" else args
    if args and not ARGS_RE.fullmatch(args):
        args = ""
    return sk.slash + (f" {args}" if args else "")


def validate_suggestions(items: list[Any], access: CaseAccess, *, from_model: bool = False,
                         limit: int = MAX_SUGGESTIONS) -> list[str]:
    out: list[str] = []
    for item in items or []:
        v = validate_command(item, access, from_model=from_model)
        if v and v not in out:
            out.append(v)
        if len(out) >= limit:
            break
    return out


_KEYWORDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("stop order", "freeze", "frozen", "preserv", "blacklist"), "/stop-orders"),
    (("overdue", "chase", "follow", "reply", "answer", "deadline"), "/follow-ups"),
    (("flow", "where", "fund", "balance", "dormant", "peel", "moving"), "/analyze-flow"),
    (("timeline", "when", "chronolog", "history"), "/timeline"),
    (("evidence", "document", "proof", "missing"), "/evidence-gaps"),
    (("police", "ic3", "law enforcement", "carabinieri", "fbi"), "/le-update"),
    (("next", "todo", "to do", "should", "plan", "priority"), "/next-steps"),
    (("summary", "status", "overview"), "/summary"),
)


def context_suggestions(db: Session, access: CaseAccess, text: str = "") -> list[str]:
    """Rule-based suggestions: keyword matches of `text` first, then what the case needs now."""
    d = local_context(db, access.case).get("derived") or {}
    low = (text or "").lower()
    out = [cmd for words, cmd in _KEYWORDS if any(w in low for w in words)]
    if d.get("status_request_due") or any(o["type"] == "stop_order" for o in d.get("overdue") or []):
        out.append("/follow-ups")
    if d.get("candidates_without_stop_order") or d.get("draft_stop_orders"):
        out.append("/stop-orders")
    out += ["/summary", "/analyze-flow"]
    top = next((n for n in d.get("dormant_large_balances") or [] if not n["pending_input"]), None)
    if top:
        out.append(f"/wallet {top['address']}")
    out += ["/next-steps", "/help"]
    return validate_suggestions(out, access)


# --------------------------------------------------------------------------- running skills and chat turns
def parse_command(text: str) -> tuple[str, str] | None:
    """('stop-orders', 'draft all') for '/stop-orders draft all'; None for free text."""
    s = (text or "").strip()
    if not s.startswith("/") or len(s) < 2:
        return None
    cmd, _, args = s[1:].partition(" ")
    return cmd.strip().lower(), " ".join(args.split())


def run_skill(db: Session, access: CaseAccess, command: str, args: str = "") -> SkillResult:
    """Run one skill for `access` (role-gated here, server side). Raises SkillError."""
    sk = SKILLS.get((command or "").lower().lstrip("/"))
    if sk is None:
        raise SkillError(404, f"Unknown command /{command}. Type /help for the list.")
    if not sk.allowed(access):
        raise SkillError(403, f"{sk.slash} needs the {sk.min_role.value.replace('_', ' ')} role on this case.")
    try:
        result = sk.handler(db, access.case, access, (args or "")[:200])
    except SkillError as exc:  # its message may name a service through the marking redactor
        exc.message = display.shown(exc.message, reveal=reveals(access))
        exc.args = (exc.message,)
        raise
    result.mode = result.mode or AIMode(access.case.ai_mode or AIMode.REDACTED).value
    result.suggested_commands = validate_suggestions(result.suggested_commands, access) or context_suggestions(db,
                                                                                                                access)
    result.actions = _valid_actions(result.actions, access)
    return _finalize(db, access, result)


def reveals(access: CaseAccess) -> bool:
    """May the member read, in the assistant's rule-based answers, the real names, references and reply details the
    model gets as placeholders? Those with view_restricted (investigators and admins), who see them on the case's own
    pages; everyone else reads the placeholders, as the model does."""
    return access.can("view_restricted")


def _finalize(db: Session, access: CaseAccess, result: SkillResult) -> SkillResult:
    """The result as the member reads it (masks resolved for them, source tags hidden) with its copy for the model
    (`model_markdown`: placeholders, tags kept); one label for every rule-based answer while no model may answer."""
    reveal = reveals(access)
    if result.model_markdown is None:
        result.model_markdown = display.sent(result.markdown)
    shown = display.shown(result.markdown, reveal=reveal)
    result.revealed = reveal and shown != display.shown(result.markdown, reveal=False)
    result.markdown = shown
    if result.findings:
        result.findings = display.shown(result.findings, reveal=reveal)
    result.actions = unmask_obj(result.actions, reveal=reveal)
    result.drafts = unmask_obj(result.drafts, reveal=reveal)
    if result.source == "rule_based" and result.label == RULE_SKILL_LABEL:
        _mode, provider, reason = ai._resolve(db, access.case)
        if provider is None:  # no model may answer at all: the label every rule-based answer has then
            result.label = rule_label(reason)
            result.reason = result.reason or reason
    return result


def _valid_actions(actions: list[dict], access: CaseAccess) -> list[dict]:
    out = []
    prefix = f"/cases/{access.case.id}"
    for a in actions or []:
        label = str(a.get("label") or "")[:80]
        if a.get("command"):
            cmd = validate_command(a["command"], access)
            if cmd and label:
                out.append({"label": label, "command": cmd})
        elif a.get("href") and label:
            href = str(a["href"])
            if href == prefix or href.startswith((prefix + "/", prefix + "?")):
                out.append({"label": label, "href": href})
    return out[:8]


def _free_text(db: Session, access: CaseAccess, text: str) -> SkillResult:
    past = model_history(db, access)
    res = ai.model_chat(db, access.case, text, past, actor=access, commands=_commands_for(access), kind="chat")
    if res.output is not None:
        sugg = validate_suggestions(res.output.get("suggested_commands") or [], access, from_model=True)
        return _finalize(db, access, SkillResult(
            markdown=res.output["answer"], suggested_commands=sugg or context_suggestions(db, access, text),
            source="ai", label=res.label, generated_by=res.generated_by, served_model=res.served_model, mode=res.mode))
    if res.reason == "rate_limited":
        raise SkillBusy(ai.reason_text("rate_limited") or "The AI service is busy.")
    label = rule_label(res.reason)
    # Block status and the Recovery plan as the member sees them: the same statuses, overdue and next moves
    answer = rule_answer(_ctx(db, access.case), text, reason=ai.reason_text(res.reason), label=label,
                         state=casestate.case_state(db, access.case, access), header=False)
    return _finalize(db, access, SkillResult(markdown=answer, suggested_commands=context_suggestions(db, access, text),
                                             label=label, reason=res.reason, mode=res.mode))


@dataclass
class ChatTurn:
    user: AiMessage
    assistant: AiMessage
    suggestions: list[str]


def chat_turn(db: Session, access: CaseAccess, text: str) -> ChatTurn:
    """One chat turn: a /command runs its skill, anything else is a question. Both messages are
    stored in ai_messages. Raises SkillError (400/403/404) or SkillBusy (provider busy)."""
    text = (text or "").strip()
    if not text:
        raise SkillError(400, "Type a question or a /command.")
    if len(text) > ai.MAX_QUESTION_CHARS:
        raise SkillError(400, f"Messages are limited to {ai.MAX_QUESTION_CHARS} characters.")
    parsed = parse_command(text)
    if parsed is not None:
        cmd, args = parsed
        if cmd not in SKILLS:
            result = SkillResult(markdown=f"Unknown command `/{_md(cmd)}`. Type `/help` for the list of skills.",
                                 suggested_commands=["/help", "/summary", "/analyze-flow"])
            result.suggested_commands = validate_suggestions(result.suggested_commands, access)
            skill_name = None
        else:
            result = run_skill(db, access, cmd, args)
            skill_name = cmd
    else:
        result = _free_text(db, access, text)
        skill_name = None
    mode = result.mode or AIMode(access.case.ai_mode or AIMode.REDACTED).value
    user_msg = AiMessage(case_id=access.case.id, user_id=access.user.id, role="user", content=text, skill=skill_name,
                         mode=mode, meta={})
    meta = {"label": result.label, "generated_by": result.generated_by, "reason": result.reason,
            "reason_text": ai.reason_text(result.reason) if result.reason and result.reason not in
            NOT_CONFIGURED_REASONS else None, "actions": result.actions, "suggested": result.suggested_commands,
            "findings": result.findings, "drafts": result.drafts}
    if result.model_markdown is not None and result.model_markdown != result.markdown:
        meta["model_content"] = result.model_markdown  # what the model may read back of this turn (`model_history`)
    if result.revealed:
        meta["revealed"] = True  # real values on screen: hidden from the member once they lose view_restricted
    bot = AiMessage(case_id=access.case.id, user_id=access.user.id, role="assistant", content=result.markdown,
                    skill=skill_name, source=result.source, served_model=result.served_model, mode=mode, meta=meta)
    db.add_all([user_msg, bot])
    db.commit()
    return ChatTurn(user=user_msg, assistant=bot, suggestions=result.suggested_commands)


def visible_messages(db: Session, access: CaseAccess, limit: int = MAX_HISTORY_MESSAGES) -> list[AiMessage]:
    """The member's own conversation on the case, oldest first. Turns generated in full mode, or showing the real
    values the model's copy masks (`meta.revealed`), stay hidden from a member who can no longer view restricted
    content; so do turns with no or an unknown stored mode (the same rule as `history_allowed`)."""
    rows = db.scalars(select(AiMessage).where(AiMessage.case_id == access.case.id, AiMessage.user_id == access.user.id)
                      .order_by(AiMessage.id.desc()).limit(limit)).all()
    full_ok = access.can("view_restricted")
    return [m for m in reversed(rows) if full_ok or m.mode in (AIMode.REDACTED.value, AIMode.OFF.value)
            and not (m.meta or {}).get("revealed")]


def history_allowed(stored_mode: str | None, current: AIMode | str | None) -> bool:
    """May a turn stored under `stored_mode` go back to the model under the case's current mode? In full
    mode every turn may; otherwise only turns generated without full content (redacted / off). A turn
    with no or an unknown stored mode is treated as full."""
    cur = AIMode(current or AIMode.REDACTED)
    if cur == AIMode.FULL:
        return True
    return stored_mode in (AIMode.REDACTED.value, AIMode.OFF.value)


def model_history(db: Session, access: CaseAccess) -> list[dict]:
    """Earlier turns sent with a free-text question (app.ai.assistant.clean_history trims them). Only
    turns the case's current AI mode allows go (`history_allowed`): after a switch from full to redacted,
    answers generated from full case content stay out of the model call, since the name redactor alone
    cannot mask quoted notes, letter bodies or evidence content."""
    msgs = visible_messages(db, access, MODEL_HISTORY_MESSAGES)
    cur = access.case.ai_mode
    return [{"role": m.role, "content": (m.meta or {}).get("model_content") or m.content} for m in msgs
            if m.role in ("user", "assistant") and m.content and history_allowed(m.mode, cur)]


def clear_history(db: Session, access: CaseAccess) -> int:
    """Delete the member's conversation on the case; returns how many messages went."""
    n = db.execute(delete(AiMessage).where(AiMessage.case_id == access.case.id,
                                           AiMessage.user_id == access.user.id)).rowcount or 0
    db.commit()
    return n


__all__ = [
    "DISCLAIMER", "RULE_NOTE", "SKILLS", "ChatTurn", "Skill", "SkillBusy", "SkillError", "SkillResult", "available_skills",
    "chat_turn", "clear_history", "context_suggestions", "parse_command", "run_skill", "stop_order_plan",
    "validate_command", "validate_suggestions", "visible_messages", "wallet_status",
]
