"""Block status engine: per case × authority × request, what was asked, what came back, what it means
and what to do next.

    rows = case_blocks(db, case)                 # list[BlockRow], no writes, no network
    rep  = refresh(db, case, actor=access)       # classify new replies (rules; AI when the case allows), store, notify
    on_reply_filed(db, case, corr)               # the e-mail desk's hook after it files a reply (never raises)
    res  = confirm(db, access, key, status=…, reply_id=…, amount=…, asset=…, apply=…)

**Requests.** Every stop order of an authority (superseded ones aside) is one request; its own letter
and the follow-ups linked to it (status requests, an Outlook answer the mailbox sync found in its
thread: `stop_order_id`) are its outbound messages. Every other outbound letter not tied to a stop
order (an information request, an LE cover letter, a release request, a logged e-mail) is a request of
its own, except an e-mail read back from Sent Items (`meta.source` "mailbox_sent"): one that answers in
the thread of a request (`in_reply_to_id` / `thread_key`) is an outbound message of that request, and
one the sync logged for review (`meta.needs_review`: several letters or none matched) is listed as
"Sent from Outlook — needs review" (`SENT_REVIEW`, kind "outlook"), never as a request, until a person
ties it to a letter; the drafts it may have carried say so. A draft is "Not sent". Issuers (Tether /
Circle) with on-chain readings but no request get a row too, so the on-chain lever shows.

**Replies.** Inbound correspondence of the authority (and automatic replies / bounces the mailbox
filed as notes, `meta.source == "mailbox"`), tied to a request by `stop_order_id`, `in_reply_to_id`
or `thread_key`; otherwise to the latest request sent before it (an open stop order first).

**Classification of a reply**, in this order: a person's (`human`: confirmed on the Block status page)
> the AI's (`ai`, only when its quote was verified and it agrees with the rules) > the rules
(`classify_rules`, always recomputed). AI and rules disagreeing gives `unclear` (needs review) with both
readings shown. Stored opinions live in `reply_classifications` (one row per mail message, migration
0010) and, with the details that table has no column for, in `correspondence.meta["block_status"]`
(also for replies logged by hand, which have no mail message).

**What a reply says beyond its status** (`ReplyView.extract`, `BlockRow.intel`; app.blocks.extract with the
authority's playbook, the AI's verified fields merged): tickets, the instrument it requires, the channels it names,
its asks, deadlines, LE contacts and identifiers, stored in `correspondence.meta["block_status"]["extract"]`.
Advisory: an unambiguous reply-by since our last letter only shortens the reply clock (`due_at`), the earliest
unambiguous deadline is `next_deadline`; an ambiguous date never changes a clock.

**Where it stands in the provider's process** (`BlockRow.path_step`, app.blocks.path: notice sent → acknowledged →
asks → temporary hold → LE process required → LE briefed → LE filed / order / cross-border → outcome), derived on every
read from the replies, the playbook, the recorded state and our LE / counsel briefs linked by `meta.follow_up_of`;
only the steps a person records are stored (`confirm_step`). "LE process required" is answered by a sent linked LE
brief (`ANSWERED_BY_LE_LINK`). The next action is the playbook's next step (`path.action`) with `evidence` and
`clock`; the playbook's clocks, `hold_expires_at` and `next_deadline` feed `check_clocks` (the scheduler's overdue
pass: provider_deadline / hold_expiring).

**A person confirms every positive outcome** (hold_placed, frozen, funds_returned: `POSITIVE`). A positive
reading of the rules or the AI, or an issuer blacklist read on-chain, never becomes a reply's or a request's status:
it is a suggestion (`ReplyView.outcome_suggestion`, `BlockRow.suggestion`: the outcome, the amount the reply
states, the quote, rules / ai / onchain, warnings from classify_rules.outcome_warnings), the reply reads unclear
(needs review), the request keeps its earlier non-positive state ("Reply received — suggests Frozen (2.1 ETH), needs
confirmation"), the held / frozen totals count only a person's outcomes (`HUMAN_SOURCES`), the Confirm form
preselects nothing for one and a hold / freeze needs the amount typed in (`AMOUNT_REQUIRED`), and the notification
says "reply needs review". Non-positive readings (acknowledged, redirected, LE process required, …) apply.

**Block status of a request** (`BLOCK_STATUSES`): the stop order's recorded status (a person set it on
the desk: acknowledged / frozen / declined / released) unless a later reply says something else, in
which case the reply's reading shows with "needs confirmation"; else the deciding reply (the latest
substantive one; an auto-reply or acknowledgement never hides an earlier outcome); else "Sent,
awaiting reply". A redirect / bounce / information request answered by a later outbound letter is
"awaiting" again. For issuers, a Tether / Circle blacklist read on-chain after the request was sent
is evidence of a freeze: a suggestion (source `onchain`) a person confirms.

**Confirm status.** Investigators confirm a reading (stored as `human`, a proposal when it maps to a
stop-order status); case admins confirm *and apply* it to the stop order through the desk
(`record_stop_order_status`: hold_placed / frozen → frozen with the amount held, declined /
declined_no_assets / declined_other → declined, acknowledged → acknowledged, funds_returned →
released, only from frozen). Both go on the authority's timeline and emit `block_status_changed`
(no PII: case reference, ids, the status and the amount). The routes audit.

Nothing here sends anything or imports the mail transport.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.blocks import classify_ai
from app.blocks import classify_rules as rules
from app.blocks import extract as ex
from app.blocks import path as pathmod
from app.core import events
from app.db.models import (
    Case,
    Correspondence,
    CorrespondenceDirection,
    CorrespondenceKind,
    CorrespondenceStatus,
    Entity,
    MailDirection,
    MailMessage,
    ReplyClassification,
    ReplySource,
    ReplyStatus,
    StopOrder,
    StopOrderStatus,
)
from app.domain import correspondence as desk
from app.domain import playbook as pbm

log = logging.getLogger(__name__)

NOT_SENT = "not_sent"
AWAITING = "awaiting"
SUPERSEDED = "superseded"
ONCHAIN_ONLY = "onchain_only"
SENT_REVIEW = "sent_review"  # an e-mail sent from Outlook that the mailbox sync could not tie to one letter
BLOCK_STATUSES: tuple[str, ...] = (
    NOT_SENT, SENT_REVIEW, AWAITING, rules.AUTO_REPLY, rules.REDIRECTED, rules.ACKNOWLEDGED, rules.LE_PROCESS_REQUIRED,
    rules.INFO_REQUESTED, rules.HOLD_PLACED, rules.FROZEN, rules.FUNDS_RETURNED, rules.DECLINED_NO_ASSETS,
    rules.DECLINED, rules.DELIVERY_FAILED, rules.UNCLEAR, ONCHAIN_ONLY,
)
LABELS = {
    NOT_SENT: "Not sent", SENT_REVIEW: "Sent from Outlook — needs review", AWAITING: "Sent, awaiting reply", rules.AUTO_REPLY: "Auto-reply",
    rules.REDIRECTED: "Redirected", rules.ACKNOWLEDGED: "Acknowledged", rules.LE_PROCESS_REQUIRED: "LE process required",
    rules.INFO_REQUESTED: "Info requested", rules.HOLD_PLACED: "Hold placed", rules.FROZEN: "Frozen",
    rules.FUNDS_RETURNED: "Funds returned", rules.DECLINED_NO_ASSETS: "Declined — no account / assets",
    rules.DECLINED: "Declined", rules.DELIVERY_FAILED: "Not delivered", rules.UNCLEAR: "Reply needs review",
    ONCHAIN_ONLY: "No request (on-chain only)",
}
TONES = {  # the badge colour (blocks.css)
    NOT_SENT: "amber", SENT_REVIEW: "amber", AWAITING: "blue", rules.AUTO_REPLY: "neutral", rules.REDIRECTED: "amber",
    rules.ACKNOWLEDGED: "blue", rules.LE_PROCESS_REQUIRED: "purple", rules.INFO_REQUESTED: "amber",
    rules.HOLD_PLACED: "green", rules.FROZEN: "green", rules.FUNDS_RETURNED: "gold", rules.DECLINED_NO_ASSETS: "red",
    rules.DECLINED: "red", rules.DELIVERY_FAILED: "red", rules.UNCLEAR: "amber", ONCHAIN_ONLY: "neutral",
}
SENT_COPY_LABEL = "Sent from Outlook — probably a copy"
UNCLEAR_CONFIRMED_LABEL = "Unclear (read by a person)"
# a positive outcome: only ever a person's (recorded on the desk, or confirmed on the Block status page); the rules,
# the AI and an on-chain reading only suggest one (`ReplyView.outcome_suggestion`, `BlockRow.suggestion`)
POSITIVE = rules.POSITIVE
HUMAN_SOURCES = frozenset({"recorded", "human"})
SUGGESTION_LABEL = "Reply received"  # an unclear reply that suggests an outcome (the badge before "— suggests …")
WEAK = frozenset({rules.AUTO_REPLY, rules.ACKNOWLEDGED, rules.UNCLEAR})
WAITING = frozenset({AWAITING, rules.AUTO_REPLY, rules.ACKNOWLEDGED, rules.REDIRECTED, rules.LE_PROCESS_REQUIRED,
                     rules.INFO_REQUESTED, rules.UNCLEAR, rules.DELIVERY_FAILED})
RESOLVED = frozenset({rules.FROZEN, rules.HOLD_PLACED, rules.FUNDS_RETURNED, rules.DECLINED, rules.DECLINED_NO_ASSETS})
# the authority waits for us: resend, answer their questions, file through LE, fix the address
OUR_ACTION = frozenset({rules.REDIRECTED, rules.DELIVERY_FAILED, rules.INFO_REQUESTED, rules.LE_PROCESS_REQUIRED})
# a later outbound letter answers these (we resent / answered): the request is awaiting again
ANSWERED_BY_OUTBOUND = frozenset({rules.REDIRECTED, rules.DELIVERY_FAILED, rules.INFO_REQUESTED})
# ... and these too, but only by a letter to an LE authority / counsel linked to the request (`meta.follow_up_of`: our LE
# brief): "LE process required" is answered by briefing LE, never by writing to the provider again
ANSWERED_BY_LE_LINK = frozenset({rules.LE_PROCESS_REQUIRED})
COMPATIBLE = (frozenset({rules.FROZEN, rules.HOLD_PLACED}), frozenset({rules.DECLINED, rules.DECLINED_NO_ASSETS}),
              frozenset({rules.AUTO_REPLY, rules.ACKNOWLEDGED}))
# Confirm status → stop-order status (desk.record_stop_order_status)
APPLY_MAP = {rules.HOLD_PLACED: "frozen", rules.FROZEN: "frozen", rules.DECLINED: "declined",
             rules.DECLINED_NO_ASSETS: "declined", rules.ACKNOWLEDGED: "acknowledged",
             rules.FUNDS_RETURNED: desk.RELEASED}
# the desk's recorded stop-order state → block status
RECORDED = {"acknowledged": rules.ACKNOWLEDGED, "frozen": rules.FROZEN, "declined": rules.DECLINED,
            desk.RELEASED: rules.FUNDS_RETURNED}
CONFIRMABLE = tuple(s for s in rules.REPLY_STATUSES if s != rules.DELIVERY_FAILED)
REVIEW_CONFIDENCE = 0.5
MAX_AI_CALLS_PER_REFRESH = 10
SNAPSHOT_KEY = "_block_status_snapshot"  # cases.facts: {request key: status}, for block_status_changed
KIND_LABELS = {"stop_order": "Stop order", "status_request": "Status request", "info_request": "Information request",
               "le_cover": "LE cover letter", "release_request": "Release request", "other": "Letter",
               "reply": "Letter", "onchain": "—", "outlook": "E-mail from Outlook"}
FIAT = frozenset({"USD", "EUR", "GBP", "CHF", "JPY", "CAD", "AUD"})


class BlockError(ValueError):
    """A confirm request that cannot be done: `status` 400 / 403 / 404 / 409."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _aware(v: datetime | None) -> datetime | None:
    return v if v is None or v.tzinfo else v.replace(tzinfo=UTC)


def _dec(v: Any) -> Decimal | None:
    if v is None or v == "":
        return None
    try:
        d = Decimal(str(v))
    except Exception:  # noqa: BLE001 - stored JSON / form text
        return None
    return d if d.is_finite() and d >= 0 else None


def compatible(a: str | None, b: str | None) -> bool:
    return a == b or any(a in g and b in g for g in COMPATIBLE)


# --------------------------------------------------------------------------- stored opinions
def _meta_store(corr: Correspondence) -> dict:
    return dict((corr.meta or {}).get("block_status") or {})


def _mail_id(db: Session, corr: Correspondence) -> int | None:
    mid = (corr.meta or {}).get("mail_message_id")
    if isinstance(mid, int):
        return mid
    return db.scalar(select(MailMessage.id).where(MailMessage.correspondence_id == corr.id,
                                                  MailMessage.direction == MailDirection.IN).limit(1))


def _table_row(db: Session, corr: Correspondence) -> ReplyClassification | None:
    row = db.scalar(select(ReplyClassification).where(ReplyClassification.correspondence_id == corr.id)
                    .order_by(ReplyClassification.id.desc()).limit(1))
    if row is None:
        mid = _mail_id(db, corr)
        if mid is not None:
            row = db.scalar(select(ReplyClassification).where(ReplyClassification.mail_message_id == mid))
    return row


def _exact(v: Any) -> str | None:
    """A Numeric read back (a float on SQLite) as the decimal it was written as (12 places at most)."""
    d = _dec(v)
    return None if d is None else format(d.quantize(Decimal("1e-12")).normalize(), "f")


def _row_dict(row: ReplyClassification) -> dict:
    return {"status": row.status.value if hasattr(row.status, "value") else str(row.status),
            "amount": _exact(row.amount), "asset": row.asset,
            "account_refs": list(row.account_refs or []), "quote": row.quote, "rationale": row.rationale,
            "confidence": row.confidence, "model": row.model, "source": row.source.value,
            "quote_verified": bool(row.quote), "by": row.confirmed_by,
            "at": (_aware(row.confirmed_at) or _aware(row.created_at)).isoformat(timespec="seconds")
            if (row.confirmed_at or row.created_at) else None, "applied": bool(row.applied), "from_table": True}


def opinions(db: Session, corr: Correspondence) -> dict:
    """{"ai": dict | None, "human": dict | None} for one reply (meta first: it has every detail)."""
    st = _meta_store(corr)
    out = {"ai": st.get("ai") if isinstance(st.get("ai"), dict) else None,
           "human": st.get("human") if isinstance(st.get("human"), dict) else None}
    if out["ai"] is None or out["human"] is None:
        row = _table_row(db, corr)
        if row is not None:
            if row.source == ReplySource.HUMAN and out["human"] is None:
                out["human"] = _row_dict(row)
            elif row.source == ReplySource.AI and out["ai"] is None:
                out["ai"] = _row_dict(row)
    return out


def _save(db: Session, case: Case, corr: Correspondence, source: str, data: dict, *, stop_order_id: int | None,
          entity_id: int | None, confirmed_by: int | None = None, applied: bool = False) -> None:
    """Store an opinion in corr.meta and, when the reply came through the mailbox, in reply_classifications
    (one row per mail message: a person's row is never overwritten by the rules or the AI). Flushes only."""
    meta = dict(corr.meta or {})
    st = dict(meta.get("block_status") or {})
    st[source] = data
    meta["block_status"] = st
    corr.meta = meta
    status = data.get("status")
    mid = _mail_id(db, corr)
    if mid is None or status not in ReplyStatus._value2member_map_:
        db.flush()
        return
    row = db.scalar(select(ReplyClassification).where(ReplyClassification.mail_message_id == mid))
    if row is not None and row.source == ReplySource.HUMAN and source != "human":
        db.flush()
        return
    if row is not None and row.source == ReplySource.AI and source == "rules":
        db.flush()
        return
    if row is None:
        row = ReplyClassification(case_id=case.id, mail_message_id=mid)
        db.add(row)
    row.correspondence_id, row.stop_order_id, row.entity_id = corr.id, stop_order_id, entity_id
    row.status = ReplyStatus(status)
    row.amount = _dec(data.get("amount"))
    row.asset = (data.get("asset") or None)
    row.account_refs = list(data.get("account_refs") or [])
    row.quote = data.get("quote")
    row.rationale = data.get("rationale")
    row.source = ReplySource({"rules": "rules", "ai": "ai", "human": "human"}[source])
    row.confidence = data.get("confidence")
    row.model = data.get("served_model") or data.get("model")
    if source == "human":
        row.confirmed_by, row.confirmed_at, row.applied = confirmed_by, _now(), applied
    try:
        with db.begin_nested():
            db.flush()
    except IntegrityError:  # another writer created the row for this mail message first: keep theirs
        log.info("reply classification for mail message %s written concurrently", mid)


# --------------------------------------------------------------------------- views
@dataclass
class ReplyView:
    corr: Correspondence
    at: datetime
    rules: rules.RuleResult
    ai: dict | None
    human: dict | None
    status: str
    source: str  # human | ai | rules
    confidence: float
    quote: str | None
    amount: str | None
    asset: str | None
    ticket: str | None
    addresses: list[dict]
    urls: list[dict]
    also: list[str]
    needs_review: bool
    note: str | None = None  # e.g. "rules: acknowledged · AI: frozen"
    suggestion: str | None = None  # the AI's status when it disagrees with the rules
    rules_held: str | None = None  # the rules' reading of a suspicious reply (any status), not used
    quoted_suspicious: bool = False  # the quoted part carries text addressed to an AI (classify_ai.quoted_injection)
    # a frozen / hold / returned reading of the rules or the AI: never the reply's status, only a suggestion a person
    # confirms ({"status", "label", "amount", "asset", "quote", "source", "confidence", "warnings"}: `_suggest`)
    outcome_suggestion: dict | None = None
    own: str = ""  # the sender's own text (classify_rules.split_quoted, our letters' echo cut)
    # app.blocks.extract: tickets, instrument, channels, asks, deadlines, contacts, identifiers (the rules', with the
    # AI's verified additions: extract.merge); None for a reply nothing of which is used (text addressed to an AI)
    extract: dict | None = None

    @property
    def label(self) -> str:
        return LABELS.get(self.status, self.status)

    @property
    def untrusted(self) -> bool:
        return bool((self.corr.meta or {}).get("untrusted_external") or (self.corr.meta or {}).get("source") == "mailbox")

    @property
    def sender_domain_ok(self) -> bool | None:
        return (self.corr.meta or {}).get("sender_domain_ok")

    @property
    def suspicious(self) -> bool:
        """Text addressed to an AI / assistant in the sender's own text (the rules) or in its quoted part (the AI
        reads the full text: classify_ai.quoted_injection)."""
        return self.rules.suspicious or self.quoted_suspicious

    @property
    def disputed(self) -> bool:
        """The rules and the AI read it differently (the AI's reading is a suggestion, never preselected)."""
        return self.human is None and self.suggestion is not None

    @property
    def risky(self) -> bool:
        """Flagged suspicious (text addressed to an AI) or disputed: a person confirms an outcome from it only
        after ticking that they read the reply themselves."""
        return self.human is None and (self.suspicious or self.disputed)

    @property
    def confirm_status(self) -> str:
        """The status the Confirm form preselects: never a positive outcome (frozen / hold / returned: "" — a person
        chooses it and enters the amount); a person's reading; for a risky reply never the AI's — the rules'
        reading, or unclear when the reply carries text addressed to an AI; else the reading shown."""
        if self.human is not None:
            pick = self.status
        elif self.outcome_suggestion is not None:
            return ""
        elif self.suspicious:
            pick = rules.UNCLEAR
        elif self.disputed:
            pick = self.rules.status
        else:
            pick = self.status
        return "" if pick in POSITIVE else pick


@dataclass
class BlockRow:
    key: str  # "o<stop order id>" | "c<correspondence id>" | "x<entity id>" (on-chain only)
    authority: desk.Authority
    kind: str
    order: StopOrder | None = None
    letter: Correspondence | None = None
    outbound: list[Correspondence] = field(default_factory=list)  # sent letters of this request, oldest first
    replies: list[ReplyView] = field(default_factory=list)
    requested_at: datetime | None = None
    channel: str | None = None
    to: list[str] = field(default_factory=list)
    last_outbound_at: datetime | None = None
    deciding: ReplyView | None = None
    status: str = NOT_SENT
    source: str = "none"  # recorded | human | ai | rules | onchain | none
    recorded: str | None = None  # the desk's stop-order state when a person recorded one
    needs_confirmation: bool = False
    needs_review: bool = False
    amount: str | None = None
    asset: str | None = None
    ticket: str | None = None
    due_at: datetime | None = None
    overdue: bool = False
    days_waiting: int | None = None
    resent: bool = False
    resent_at: datetime | None = None  # the latest follow-up sent after their redirect / bounce / question
    first_to: list[str] = field(default_factory=list)  # the request's first addressee, when a resend went elsewhere
    outbound_to: dict[int, list[str]] = field(default_factory=dict)  # outbound entry id -> its To
    review: dict | None = None  # SENT_REVIEW rows: {"reason", "candidates", "at"}
    next_action: dict = field(default_factory=dict)
    onchain: dict | None = None
    applied: bool = False
    proposal: dict | None = None  # an investigator's confirmed reading that awaits a case admin
    # a frozen / hold / returned outcome read from a reply (rules / AI) or on-chain that no person has confirmed:
    # shown as "suggests …, needs confirmation"; the status above stays non-positive (`_derive`)
    suggestion: dict | None = None
    suggestion_reply: ReplyView | None = None
    playbook: Any = None  # the authority's app.domain.playbook.Playbook (directory.playbook_for), or None
    org_key: str | None = None  # its catalogue organisation
    next_deadline: dict | None = None  # the earliest unambiguous future deadline: a reply's (since our last letter), a playbook clock
    recorded_at: datetime | None = None  # when the desk's recorded state was set
    links: list[dict] = field(default_factory=list)  # our letters to LE / counsel linked to this request (follow_up_of)
    path: Any = None  # app.blocks.path.PathState (derived on every read, never stored)
    clocks: list[dict] = field(default_factory=list)  # every clock of the request: the replies' and the playbook's
    hold_expires_at: datetime | None = None  # when a hold a person confirmed lapses (stated, else the playbook's)
    stated_holds: list[dict] = field(default_factory=list)  # the latest reply's own hold expiries, passed ones too

    @property
    def path_step(self) -> str | None:
        return self.path.step if self.path is not None else None

    @property
    def intel(self) -> dict:
        """What the replies say beyond their status (app.blocks.extract), newest first: {tickets, tickets_by_channel,
        instrument, ai_instrument, asks, deadlines, contacts, identifiers, channels, disagree}. The asks and deadlines
        are those of the replies since our last letter (a later letter answered the earlier ones)."""
        out: dict[str, Any] = {"tickets": [], "tickets_by_channel": {}, "instrument": None, "ai_instrument": None,
                               "asks": [], "deadlines": [], "contacts": [], "identifiers": [], "channels": [],
                               "disagree": []}
        since = self.last_outbound_at
        for r in reversed(self.replies):
            x = r.extract or {}
            if not x:
                continue
            open_ = since is None or r.at >= since
            for t in x.get("tickets") or []:
                if t["value"] not in {y["value"] for y in out["tickets"]}:
                    out["tickets"].append({**t, "reply_id": r.corr.id})
                    out["tickets_by_channel"].setdefault(t.get("channel") or "?", t["value"])
            if out["instrument"] is None and x.get("instrument"):
                out["instrument"] = {**x["instrument"], "reply_id": r.corr.id}
                out["ai_instrument"] = x.get("ai_instrument")
            for k, ident in (("asks", "req_key"), ("deadlines", "quote")):
                if open_:
                    seen = {y.get(ident) for y in out[k]}
                    out[k] += [{**y, "reply_id": r.corr.id} for y in x.get(k) or [] if y.get(ident) not in seen]
            for k, ident in (("contacts", "quote"), ("identifiers", "value"), ("channels", "value")):
                seen = {y.get(ident) for y in out[k]}
                out[k] += [{**y, "reply_id": r.corr.id} for y in x.get(k) or [] if y.get(ident) not in seen]
            out["disagree"] += [d for d in x.get("disagree") or [] if d not in out["disagree"]]
        return out

    @property
    def probable_copy(self) -> bool:
        """An Outlook e-mail whose candidate letters are all recorded as sent since (`_flag_possibly_sent`):
        nothing to review, so neither labelled nor counted as "needs review"."""
        return self.status == SENT_REVIEW and not self.needs_review

    @property
    def label(self) -> str:
        if self.probable_copy:
            return SENT_COPY_LABEL
        if self.status == rules.UNCLEAR and self.source == "human":
            return UNCLEAR_CONFIRMED_LABEL  # a person read it: no longer "needs review"
        if self.status == rules.UNCLEAR and self.suggestion is not None and self.deciding is not None \
                and self.deciding is self.suggestion_reply:
            return SUGGESTION_LABEL  # the badge; its status text: "Reply suggests Frozen (2.1 ETH): confirm"
        return LABELS.get(self.status, self.status)

    @property
    def suggestion_text(self) -> str:
        """'suggests Frozen (2.1 ETH)' (a reply) / 'on-chain: Frozen (5,000 USDT)' (an issuer blacklist), or ''."""
        if self.suggestion is None:
            return ""
        what = suggestion_text(self.suggestion)
        return f"on-chain: {what}" if self.suggestion.get("source") == "onchain" else f"suggests {what}"

    @property
    def tone(self) -> str:
        return "neutral" if self.probable_copy else TONES.get(self.status, "neutral")

    @property
    def kind_label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind.replace("_", " "))

    @property
    def title(self) -> str:
        if self.order is not None:
            return f"Stop order #{self.order.id}"
        if self.letter is not None:
            return f"{self.kind_label} #{self.letter.id}"
        return "On-chain readings"

    @property
    def last_reply(self) -> ReplyView | None:
        return self.replies[-1] if self.replies else None

    @property
    def status_text(self) -> str:
        """The badge text with its detail, one wording on every page (Overview, Authorities, the board, the Recovery
        plan, Block status and its exports): 'Frozen (12,633.77 USDT)', 'Redirected (resend to x@…)', 'Reply suggests
        Frozen (2.1 ETH): confirm', 'Acknowledged — reply suggests Frozen (2.1 ETH): confirm'. A text that ends in
        ": confirm" says what a "to confirm" tag would (`confirm_in_text`)."""
        base = self._status_text()
        if self.suggestion is None:
            return base
        if self.suggestion.get("source") == "onchain":
            return f"{base} — {self.suggestion_text}: confirm"
        if base == SUGGESTION_LABEL:
            return f"Reply {self.suggestion_text}: confirm"
        return f"{base} — reply {self.suggestion_text}: confirm"

    @property
    def confirm_in_text(self) -> bool:
        """The status text already asks a person to confirm (a suggested outcome): no separate "to confirm" tag."""
        return self.suggestion is not None

    def _status_text(self) -> str:
        if self.status in (rules.FROZEN, rules.HOLD_PLACED, rules.FUNDS_RETURNED) and self.amount:
            return f"{self.label} ({fmt_amount(self.amount, self.asset)} {self.asset or ''})".replace(" )", ")")
        if self.status == rules.REDIRECTED:
            target = self.resend_to
            return f"{self.label} (resend to {target})" if target else self.label
        if self.status == AWAITING and self.resent:
            where = f" to {', '.join(self.to)}" if self.first_to and self.to else ""
            return f"Sent (resent{where}), awaiting reply"
        if self.status == AWAITING and self.source == "le_route":
            return "LE briefed, awaiting LE process"
        return self.label

    @property
    def detail(self) -> str | None:
        """The badge's detail line: the amount held, where to resend, or where it was resent."""
        if self.suggestion is not None:
            what = suggestion_text(self.suggestion)
            return (f"On-chain: {what} — confirm" if self.suggestion.get("source") == "onchain"
                    else f"Reply suggests: {what} — confirm")
        if self.status in (rules.FROZEN, rules.HOLD_PLACED, rules.FUNDS_RETURNED) and self.amount:
            return f"{fmt_amount(self.amount, self.asset)} {self.asset or ''}".strip()
        if self.status == rules.REDIRECTED and self.resend_to:
            return f"resend to {self.resend_to}"
        if self.status == AWAITING and self.resent and self.first_to and self.to:
            return f"resent to {', '.join(self.to)}"
        return None

    @property
    def resend_to(self) -> str | None:
        if self.deciding is None:
            return None
        return pick_resend(self.deciding.addresses, self.kind) or next(
            (u["value"] for u in self.deciding.urls), None)

    @property
    def can_apply(self) -> bool:
        return self.order is not None


def fmt_amount(v: Any, asset: str | None = None) -> str:
    """An amount as shown: fiat (USD, EUR, …) to the cent; a crypto amount (or an unknown asset) exactly as
    stated, without trailing zeros (0.05683881 ETH, 1.23456789 BTC, 12,633.77 USDT), thousands separated."""
    d = _dec(v)
    if d is None:
        return str(v or "")
    if (asset or "").strip().upper() in FIAT:
        return f"{d.quantize(Decimal('0.01')):,}"
    if not d:
        return "0"
    return f"{d.normalize():,f}"


# the purpose of a request, for the address a redirect names (Circle: one inbox for freezes, one for subpoenas)
FREEZE_KINDS = frozenset({"stop_order", "status_request"})
LEGAL_KINDS = frozenset({"info_request", "le_cover"})
PURPOSE_ORDER = {
    "freeze": ("freeze", "compliance", "general", "le_request", "legal"),
    "legal": ("legal", "le_request", "compliance", "general", "freeze"),
    "other": ("compliance", "general", "freeze", "le_request", "legal"),
}


def purpose_of(kind: str | None) -> str:
    """"freeze" (a stop order and its status requests), "legal" (an information request, an LE cover letter:
    subpoena / legal process) or "other"."""
    return "freeze" if kind in FREEZE_KINDS else "legal" if kind in LEGAL_KINDS else "other"


def pick_resend(addresses: list[dict], kind: str) -> str | None:
    """The address a redirect names for this kind of request, keeping its purpose: a freeze address for a stop
    order (never the subpoena inbox while a freeze one is named), a legal / LE one for legal process, else the
    first."""
    if not addresses:
        return None
    for p in PURPOSE_ORDER[purpose_of(kind)]:
        for a in addresses:
            if a.get("purpose") == p:
                return a["value"]
    return addresses[0]["value"]


# --------------------------------------------------------------------------- reply reading
def _exclusions(case: Case, row: BlockRow, before: datetime | None = None) -> tuple[set[str], set[str]]:
    """(addresses, references) a reply's named channels never include: the ones the request had gone to when
    the reply came (`before`: never a later resend, so a redirect still names the address we resent to), the
    case mailbox, and our case reference."""
    from app.domain import sender as sender_mod

    addrs = {a.lower() for a in row.to}
    for c in row.outbound:
        at = _aware(c.occurred_at or c.created_at)
        if before is not None and at is not None and at > before:
            continue
        addrs |= {str(a).lower() for a in (c.recipients or []) + (c.cc or []) if a}
    if row.order is not None:
        addrs |= {str(a).lower() for a in [row.order.recipient_email, *(row.order.recipient_cc or [])] if a}
    try:
        mbx = sender_mod.case_mailbox()
    except Exception:  # noqa: BLE001 - configuration must not break the status page
        mbx = None
    if mbx:
        addrs.add(mbx.lower())
    refs = {case.reference} if case.reference else set()
    return addrs, refs


QUOTE_BLOCKED_NOTE = ("AI reading not used: the reply negates, asks about or makes conditional the outcome its "
                      "quote names.")


def _echo(row: BlockRow) -> list[str]:
    """The subjects and texts of the letters of this request: a ticket system's echo of one is cut from a reply."""
    out = [x for c in row.outbound for x in (c.subject, c.body_markdown) if x]
    if row.order is not None:
        out += [x for x in (row.order.subject, row.order.body_markdown) if x]
    return out


def _catalogue_domains() -> dict[str, str]:
    """domain -> catalogue organisation key (playbook own / sibling domains, homepages): a channel a reply names on
    another organisation's domain is third_party (app.blocks.extract)."""
    from app.domain import directory

    try:
        cat = directory.load_catalogue()
    except Exception:  # noqa: BLE001 - an invalid catalogue: every named channel reads unknown
        return {}
    hit = _DOMAINS_CACHE.get("v")
    if hit is not None and hit[0] is cat:
        return hit[1]
    out: dict[str, str] = {}
    for o in cat.orgs:
        pb = o.playbook
        for d in ([*pb.domains.own, *(x.domain for x in pb.domains.sibling)] if pb is not None else []):
            out.setdefault(d, o.key)
        host = ex._host(o.homepage) if o.homepage else None
        if host and "." in host:
            out.setdefault(host, o.key)
    _DOMAINS_CACHE["v"] = (cat, out)
    return out


_DOMAINS_CACHE: dict[str, tuple[Any, dict[str, str]]] = {}


def _playbook(a: desk.Authority) -> tuple[Any, str | None]:
    from app.domain import directory

    try:
        org = directory.org_for(a)
    except Exception:  # noqa: BLE001 - an invalid catalogue never breaks the status page
        return None, None
    return (org.playbook, org.key) if org is not None else (None, None)


def _known(row: BlockRow) -> set[str]:
    """The wallets / tx hashes / ids our own letters of this request cite: a reply naming one names nothing new."""
    out = ex.tokens(_echo(row))
    if row.order is not None:
        for a in (row.order.identifiers or {}).get("addresses") or []:
            v = a.get("address") if isinstance(a, dict) else a
            if v:
                out.add(ex.norm_id(str(v)))
    return out


def read_reply(db: Session, case: Case, corr: Correspondence, row: BlockRow) -> ReplyView:
    meta = corr.meta or {}
    at = _aware(corr.occurred_at or corr.created_at)
    excl, refs = _exclusions(case, row, before=at)
    echo = _echo(row)
    own = rules.strip_quoted(corr.body_markdown or "", echo)[0]
    r = rules.classify(corr.body_markdown or "", subject=corr.subject, auto_reply=bool(meta.get("auto_reply")),
                       bounce=bool(meta.get("bounce")), exclude_addresses=excl, exclude_refs=refs, echo=echo,
                       playbook=row.playbook, received_at=at, known=_known(row), org_key=row.org_key,
                       others=_catalogue_domains())
    op = opinions(db, corr)
    ai, human = op["ai"], op["human"]
    quoted_hit = classify_ai.quoted_injection(corr.body_markdown or "") or bool((ai or {}).get("quoted_injection"))
    suspicious = r.suspicious or quoted_hit
    problem = (classify_ai.quote_problem(ai["quote"], str(ai.get("status")), own)
               if ai is not None and ai.get("quote") else None)
    if problem is not None:
        # (a reading stored before the guard): a quote the rules' negation / conditional / question guard blocks
        ai = {**ai, "quote": None, "quote_verified": False, "quote_dropped": True,
              **({"quote_blocked": True} if problem == "guard" else {})}
    base: dict[str, Any] = {"status": r.status, "source": "rules", "confidence": r.confidence, "quote": r.quote,
                            "amount": r.amount, "asset": r.asset, "ticket": r.ticket or corr.external_ref,
                            "addresses": r.addresses, "urls": r.urls, "also": r.also}
    note = suggestion = rules_held = None
    if human is not None and human.get("status") in rules.REPLY_STATUSES:
        base.update(status=human["status"], source="human", confidence=1.0,
                    amount=human.get("amount") or base["amount"], asset=human.get("asset") or base["asset"])
        review = False
    elif ai is not None and ai.get("quote") and ai.get("status") in rules.REPLY_STATUSES:
        if compatible(ai["status"], r.status) and not suspicious:
            amount, asset = r.amount or ai.get("amount"), r.asset or ai.get("asset")
            differs = bool(r.amount and ai.get("amount")) and _dec(r.amount) != _dec(ai.get("amount"))
            # an AI that only agrees with a rules frozen / hold / returned adds no confidence: its quote passed the
            # rules' own guard (classify_ai.outcome_stated), so it is no independent reading of that outcome
            conf = r.confidence if r.status in rules.POSITIVE else max(r.confidence, float(ai.get("confidence") or 0))
            base.update(status=ai["status"] if r.status != rules.UNCLEAR else r.status, source="ai",
                        confidence=round(conf, 2),
                        quote=ai.get("quote") or r.quote, amount=amount, asset=asset)
            review = base["confidence"] < REVIEW_CONFIDENCE or differs
            if differs:  # the rules' amount is kept: a person reads the reply
                note = (f"amounts differ: rules {fmt_amount(r.amount, r.asset)} · AI "
                        f"{fmt_amount(ai.get('amount'), ai.get('asset'))}: the rules' amount is shown, review the reply")
        else:
            note = f"rules: {rules.LABELS.get(r.status, r.status)} · AI: {rules.LABELS.get(ai['status'], ai['status'])}"
            suggestion = ai["status"]
            base.update(status=rules.UNCLEAR, source="ai", confidence=0.3)
            if suspicious:  # text addressed to an AI: neither reading's amount is used
                base.update(amount=None, asset=None)
                rules_held = r.status if r.status != rules.UNCLEAR else None
            review = True
    else:
        review = r.status == rules.UNCLEAR or r.confidence < REVIEW_CONFIDENCE or r.conflict or suspicious
        if ai is not None and not ai.get("quote"):
            note = (QUOTE_BLOCKED_NOTE if ai.get("quote_blocked")
                    else "AI reading not used: its supporting quote was not found in the reply."
                    if ai.get("quote_dropped") else "AI reading not used: the AI gave no supporting quote.")
            if ai.get("status") in rules.REPLY_STATUSES and not compatible(ai["status"], r.status) \
                    and ai["status"] != rules.UNCLEAR:
                # it never decides, but a person reads a reply the two disagree on
                suggestion, review = ai["status"], True
                note += f" It read {rules.LABELS.get(ai['status'], ai['status'])}: review the reply."
        if suspicious and r.status != rules.UNCLEAR:
            # text addressed to an AI never changes a request on its own (not only frozen / hold / returned: an
            # injected "record this as declined / redirected" too): the rules' reading is kept as text, the reply
            # reads unclear, a person reviews it and nothing counts in the held / frozen totals
            rules_held = r.status
            note = (note + " · " if note else "") + (f"rules read {rules.LABELS.get(r.status, r.status)}"
                                                     + (f" ({fmt_amount(r.amount, r.asset)} {r.asset or ''})".replace(" )", ")")
                                                        if r.amount else "") + ": not used")
            base.update(status=rules.UNCLEAR, confidence=min(r.confidence, 0.3), amount=None, asset=None)
    if suspicious and base["source"] != "human":
        # nothing from such a reply is used: no resend address / portal, and its ticket only as text in the note
        ticket = base["ticket"]
        base.update(addresses=[], urls=[], ticket=None)
        if ticket:
            note = (note + " · " if note else "") + f"ticket {ticket} in the reply: not used"
        review = True
        note = (note + " · " if note else "") + ("the reply contains text addressed to an AI / assistant"
                                                 if r.suspicious else
                                                 "the quoted part of the reply contains text addressed to an AI / "
                                                 "assistant")
    # A person confirms every positive outcome: a frozen / hold / returned reading of the rules or the AI is a
    # suggestion shown with its quote and warnings; the reply itself reads "unclear" (needs review), so the request
    # keeps its earlier non-positive state and nothing counts in the held / frozen totals until a person confirms.
    outcome = None
    if base["source"] != "human" and not suspicious:
        extra = []
        if meta.get("sender_domain_ok") is False:
            extra.append("the reply did not come from the authority's own domain")
        if r.conflict:
            others = [rules.LABELS.get(x, x) for x in r.also if x not in POSITIVE and x in rules.SUBSTANTIVE]
            extra.append("the reply also reads as " + (" / ".join(others) if others else "another outcome"))
        if base["status"] in POSITIVE:
            outcome = _suggest(base["status"], amount=base["amount"], asset=base["asset"], quote=base["quote"],
                               source=base["source"], confidence=base["confidence"], own=own,
                               extra=extra + ([note] if note and note.startswith("amounts differ") else []))
        elif suggestion is not None and (ai or {}).get("quote") and suggestion in POSITIVE:
            # the AI's verified reading of an outcome the rules read otherwise
            outcome = _suggest(suggestion, amount=ai.get("amount"), asset=ai.get("asset"), quote=ai.get("quote"),
                               source="ai", confidence=float(ai.get("confidence") or 0), own=own,
                               extra=extra + [f"the rules read it as {rules.LABELS.get(r.status, r.status)}"])
        elif suggestion is not None and r.status in POSITIVE:
            # the rules' reading of an outcome the AI reads otherwise
            outcome = _suggest(r.status, amount=r.amount, asset=r.asset, quote=r.quote, source="rules",
                               confidence=r.confidence, own=own,
                               extra=extra + [f"the AI read it as {rules.LABELS.get(suggestion, suggestion)}"])
        if outcome is not None:
            base.update(status=rules.UNCLEAR, amount=None, asset=None, quote=outcome["quote"] or base["quote"])
            review = True
    # what the reply says beyond its status: the rules' extraction with the AI's verified additions; nothing of a
    # reply carrying text addressed to an AI is used (as its ticket and channels above)
    extracted = None
    if r.extract is not None and not (suspicious and base["source"] != "human"):
        extracted = ex.merge(r.extract, (ai or {}).get("extract") if ai is not None else None, exclude_refs=refs,
                             known=_known(row))
        sender = str(corr.sender or "").strip().lower() or None
        extracted["tickets"] = [{**t, "channel": sender} for t in extracted.get("tickets") or []]
    return ReplyView(corr=corr, at=at or _now(), rules=r, ai=ai, human=human,
                     needs_review=review, note=note, suggestion=suggestion, rules_held=rules_held,
                     quoted_suspicious=quoted_hit, outcome_suggestion=outcome, own=own, extract=extracted, **base)


def _suggest(status: str, *, amount: Any, asset: str | None, quote: str | None, source: str, confidence: float,
             own: str, extra: list[str] | tuple[str, ...] = ()) -> dict:
    """A positive reading as a suggestion: the outcome, the amount the reply states, the supporting quote, who read it
    (rules / ai / onchain) and the warnings (classify_rules.outcome_warnings: the guard's signals as text)."""
    keys = rules.outcome_warnings(own, quote, status) if own or quote else []
    return {"status": status, "label": LABELS.get(status, status), "amount": _exact(amount) if amount else None,
            "asset": asset or None, "quote": quote, "source": source, "confidence": round(float(confidence or 0), 2),
            "warning_keys": keys, "warnings": [rules.WARNING_TEXT[k] for k in keys] + [x for x in extra if x]}


def suggestion_text(sug: dict | None, *, amount: bool = True) -> str:
    """'Frozen (2.1 ETH)': the suggested outcome with the amount the reply states (`amount=False`: without it)."""
    if not sug:
        return ""
    label = LABELS.get(sug.get("status"), sug.get("status") or "")
    if amount and sug.get("amount"):
        return f"{label} ({fmt_amount(sug['amount'], sug.get('asset'))} {sug.get('asset') or ''})".replace(" )", ")")
    return label


# --------------------------------------------------------------------------- requests
def _is_reply(c: Correspondence) -> bool:
    if c.direction == CorrespondenceDirection.IN:
        return True
    return c.direction == CorrespondenceDirection.NOTE and (c.meta or {}).get("source") == "mailbox"


def _sent(c: Correspondence) -> bool:
    return c.direction == CorrespondenceDirection.OUT and c.status == CorrespondenceStatus.SENT


def _mail_to(db: Session, key: str) -> tuple[list[str], str | None]:
    """(To, transport) of the e-mail that carried letter `key` (o<id> / c<id>), if one was sent / recorded."""
    mm = db.scalar(select(MailMessage).where(MailMessage.letter_key == key, MailMessage.direction == MailDirection.OUT,
                                             MailMessage.status.in_(("sent", "sent_external")))
                   .order_by(MailMessage.id.desc()).limit(1))
    if mm is None:
        return [], None
    return [str(a) for a in (mm.to_addrs or []) if a], ("e-mail (Outlook)" if mm.status.value == "sent_external"
                                                          else "e-mail (sent from Aegis)")


def _from_sent_items(c: Correspondence) -> bool:
    """An outbound entry the mailbox sync logged from Sent Items (app.mail.sync_outbound), not a letter."""
    return (c.meta or {}).get("source") == "mailbox_sent"


def _under_review(c: Correspondence) -> bool:
    return _from_sent_items(c) and bool((c.meta or {}).get("needs_review"))


def _outbound_to(db: Session, c: Correspondence) -> list[str]:
    """The To of an outbound entry: the e-mail that carried it when there is one, else its recipients."""
    from app.domain.mail_compose import letter_key

    to, _ = _mail_to(db, letter_key(c))
    return to or [str(x) for x in (c.recipients or []) if x]


def _requests(db: Session, case: Case, a: desk.Authority) -> list[BlockRow]:
    rows: list[BlockRow] = []
    by_letter: dict[int, BlockRow] = {}  # outbound entry id -> its request
    pb, org_key = _playbook(a)
    for o in sorted(a.stop_orders, key=lambda x: x.id):
        if o.status == StopOrderStatus.SUPERSEDED:
            continue
        letters = sorted([c for c in a.correspondence if c.stop_order_id == o.id and c.direction ==
                          CorrespondenceDirection.OUT], key=lambda c: (_aware(c.occurred_at or c.created_at), c.id))
        main = next((c for c in letters if c.kind == CorrespondenceKind.STOP_ORDER), None)
        row = BlockRow(key=f"o{o.id}", authority=a, kind="stop_order", order=o, letter=main,
                       outbound=[c for c in letters if _sent(c)], playbook=pb, org_key=org_key)
        row.requested_at = _aware(o.sent_at)
        row.channel = o.sent_via or (main.channel.value if main is not None and main.channel else None)
        row.to = [x for x in [o.recipient_email] if x] or (list(main.recipients or []) if main is not None else []) \
            or [str(x) for x in [(o.identifiers or {}).get("recipient")] if x and "@" in str(x) and " " not in str(x)]
        mail_to, transport = _mail_to(db, row.key)
        if mail_to:
            row.to = mail_to
        if transport:
            row.channel = transport
        for c in letters:
            by_letter[c.id] = row
        rows.append(row)
    pending: list[Correspondence] = []  # Sent Items entries: placed once the thread they answer is known
    for c in sorted(a.correspondence, key=lambda x: x.id):
        if c.direction != CorrespondenceDirection.OUT or c.stop_order_id is not None and c.stop_order in a.stop_orders:
            continue
        if c.status not in (CorrespondenceStatus.SENT, CorrespondenceStatus.DRAFT):
            continue
        if c.status == CorrespondenceStatus.DRAFT and ((c.meta or {}).get("superseded_by")
                                                       or (c.meta or {}).get("superseded_by_letter")
                                                       or (c.meta or {}).get("discarded")):
            continue  # a draft a newer letter replaced (the authority page's "replaces draft #N"), or one a case admin
            # discarded (the board's pointless draft: freeze_board.discard_letter): no request
        if _from_sent_items(c):
            if (c.meta or {}).get("tied_to") or (c.meta or {}).get("dismissed"):
                continue  # a person tied it to its letter (that letter carries it now) or dismissed it
            pending.append(c)
            continue
        row = _letter_row(db, a, c)
        row.playbook, row.org_key = pb, org_key
        by_letter[c.id] = row
        rows.append(row)
    # replies → requests, and Sent Items entries → the request whose thread they answer (in time order: an
    # authority's answer to an Outlook follow-up lands on the request the follow-up belongs to)
    by_order = {r.order.id: r for r in rows if r.order is not None}
    threads = {c.thread_key: by_letter[c.id] for c in a.correspondence if c.id in by_letter and c.thread_key}
    by_reply: dict[int, BlockRow] = {}
    items = [c for c in a.correspondence if _is_reply(c)] + pending
    for c in sorted(items, key=lambda c: (_aware(c.occurred_at or c.created_at) or _now(), c.id)):
        if c.direction == CorrespondenceDirection.OUT:  # a Sent Items entry
            target = by_letter.get(c.in_reply_to_id) or by_reply.get(c.in_reply_to_id) \
                or (threads.get(c.thread_key) if c.thread_key else None)
            if target is None and (c.meta or {}).get("follow_up_of"):
                target = next((r for r in rows if r.key == c.meta["follow_up_of"]), None)
            if target is None:
                meta = c.meta or {}
                if _under_review(c) and not meta.get("candidates"):
                    continue  # no letter matched: not a request (on the authority's timeline and /admin/mail/mailbox)
                row = _letter_row(db, a, c)
                row.playbook, row.org_key = pb, org_key
                if _under_review(c):
                    row.kind = "outlook"
                    row.review = {"reason": meta.get("review_reason"), "candidates": list(meta.get("candidates") or []),
                                  "at": _aware(c.occurred_at)}
                rows.append(row)
                target = row
            elif _sent(c) and c not in target.outbound:
                target.outbound.append(c)
            by_letter[c.id] = target
            if c.thread_key:
                threads.setdefault(c.thread_key, target)
            continue
        reply = c
        target = None
        if reply.stop_order_id and reply.stop_order_id in by_order:
            target = by_order[reply.stop_order_id]
        elif reply.in_reply_to_id and reply.in_reply_to_id in by_letter:
            target = by_letter[reply.in_reply_to_id]
        elif reply.in_reply_to_id and reply.in_reply_to_id in by_reply:
            target = by_reply[reply.in_reply_to_id]
        elif reply.thread_key and reply.thread_key in threads:
            target = threads[reply.thread_key]
        else:
            at = _aware(reply.occurred_at or reply.created_at)
            sent = [r for r in rows if r.requested_at is not None and r.kind != "outlook"
                    and (at is None or r.requested_at <= at)]
            if sent:
                target = max(sent, key=lambda r: (r.order is not None and desk.order_open(r.order), r.requested_at))
        if target is not None:
            target.replies.append(read_reply(db, case, reply, target))
            by_reply[reply.id] = target
    for r in rows:
        r.outbound.sort(key=lambda c: (_aware(c.occurred_at or c.created_at) or _now(), c.id))
        r.outbound_to = {c.id: _outbound_to(db, c) for c in r.outbound}
        stamps = [_aware(c.occurred_at) for c in r.outbound if c.occurred_at]
        if r.requested_at:
            stamps.append(r.requested_at)
        r.last_outbound_at = max(stamps) if stamps else None
        if r.requested_at is None and stamps:
            r.requested_at = min(stamps)
    return rows


def _letter_row(db: Session, a: desk.Authority, c: Correspondence) -> BlockRow:
    """A request of its own: an outbound letter not tied to a stop order."""
    row = BlockRow(key=f"c{c.id}", authority=a, kind=c.kind.value, letter=c, outbound=[c] if _sent(c) else [])
    row.requested_at = _aware(c.occurred_at) if _sent(c) else None
    row.channel = c.channel.value if c.channel else None
    row.to = list(c.recipients or [])
    mail_to, transport = _mail_to(db, row.key)
    if mail_to:
        row.to = mail_to
    if transport:
        row.channel = transport
    elif _from_sent_items(c):
        row.channel = "e-mail (Outlook)"
    return row


# --------------------------------------------------------------------------- on-chain
def _issuer_of(a: desk.Authority) -> str | None:
    from app.freeze.issuers import ISSUER_ENTITY

    if a.entity is None:
        return None
    return next((k for k, v in ISSUER_ENTITY.items() if v == a.entity.name), None)


def onchain_by_issuer(db: Session, case: Case) -> dict[str, dict]:
    """issuer -> {"frozen": [...], "unfrozen_balance": [...], "frozen_total", "enabled", "last_run_at"} from
    the stored freeze readings (app.freeze; no network)."""
    try:
        from app.freeze.service import case_status

        st = case_status(db, case)
    except Exception as err:  # noqa: BLE001
        log.warning("block status: freeze readings failed for case %s (%s)", case.id, type(err).__name__)
        return {}
    out: dict[str, dict] = {}
    for w in st["wallets"]:
        for c in w["checks"]:
            if c.get("status") != "ok":
                continue
            d = out.setdefault(c["issuer"], {"frozen": [], "unfrozen_balance": [], "lifted": [], "moved": [],
                                             "frozen_total": {}, "enabled": st["enabled"],
                                             "last_run_at": st["last_run_at"]})
            # the latest good reading (a failed attempt after it never shadows it: stale_note says so)
            entry = {"chain": w["chain"], "chain_label": w["chain_label"], "address": w["address"],
                     "short": w["short"], "symbol": c["symbol"], "balance": c["balance"],
                     "balance_label": c["balance_label"], "frozen_at": c["frozen_at"],
                     "frozen_at_basis": c["frozen_at_basis"], "usd": c["usd"], "stale_note": c.get("stale_note"),
                     "funds_left": c.get("funds_left")}
            if c.get("funds_left"):
                d["moved"].append(entry)
            if c["blacklisted"]:
                d["frozen"].append(entry)
                bal = _dec(c["balance"]) or Decimal(0)
                d["frozen_total"][c["symbol"]] = str((_dec(d["frozen_total"].get(c["symbol"])) or Decimal(0)) + bal)
            elif c.get("unfrozen"):
                d["lifted"].append(entry)
            elif (_dec(c["balance"]) or Decimal(0)) >= Decimal(1):  # dust (poisoning) is not a lever
                d["unfrozen_balance"].append(entry)
    return out


def _cited(order: StopOrder | None) -> set[str]:
    if order is None:
        return set()
    ids = order.identifiers or {}
    out = {str(a.get("address") if isinstance(a, dict) else a).lower() for a in ids.get("addresses") or []}
    body = (order.body_markdown or "").lower()
    return {a for a in out if a} | ({body} if body else set())


def _onchain_frozen_for(row: BlockRow, oc: dict) -> list[dict]:
    cited = _cited(row.order)
    if not cited:
        return []
    out = []
    for e in oc.get("frozen") or []:
        addr = e["address"].lower()
        if not any(addr == c or addr in c for c in cited):
            continue
        at = e.get("frozen_at")
        try:
            when = datetime.fromisoformat(at) if at else None
        except ValueError:
            when = None
        when = _aware(when)
        if row.requested_at is None or when is None or when >= row.requested_at:
            out.append(e)
    return out


# --------------------------------------------------------------------------- derivation
def _recorded(order: StopOrder | None) -> tuple[str | None, datetime | None, dict]:
    if order is None:
        return None, None, {}
    state = desk.order_state(order)
    st = RECORDED.get(state)
    if st is None:
        return None, None, {}
    at = None
    for h in reversed((order.identifiers or {}).get("status_history") or []):
        if h.get("status") == state:
            try:
                at = _aware(datetime.fromisoformat(h["at"]))
            except (KeyError, ValueError, TypeError):
                at = None
            break
    return st, at or _aware(order.responded_at), desk.hold_state(order)


def _pick(replies: list[ReplyView]) -> ReplyView | None:
    """The deciding reply: the latest substantive one (an auto-reply / acknowledgement never hides an earlier
    outcome), else the latest; a readable reply rather than an unclear one."""
    strong = [r for r in replies if r.status not in WEAK]
    deciding = strong[-1] if strong else (replies[-1] if replies else None)
    if deciding is not None and deciding.status == rules.UNCLEAR:  # prefer a readable weak reply
        readable = [r for r in replies if r.status != rules.UNCLEAR]
        deciding = readable[-1] if readable else deciding
    return deciding


def _later_out(row: BlockRow, at: datetime) -> list[Correspondence]:
    return [c for c in row.outbound if c.occurred_at and _aware(c.occurred_at) > at]


def _own_text(r: ReplyView) -> str:
    return " ".join(r.own.lower().split())


def _named(r: ReplyView) -> set[str]:
    """Every address a redirect's own text names, the ones we had already written to included (the reply's
    `addresses` leave those out, so a redirect logged after our resend still names where we resent)."""
    return {a["value"].lower() for a in rules.find_channels(r.own)[0]} | {
        str(a.get("value") or "").lower() for a in r.addresses}


def _answer_outs(row: BlockRow, r: ReplyView, original: set[str]) -> list[Correspondence]:
    """The letters that answered a redirect / bounce / question: the ones sent after it, and for a redirect also a
    resend that had already gone to the address it names (a redirect logged by hand after we forwarded the letter
    there, e.g. an auto-reply logged by hand minutes after the forward)."""
    out = _later_out(row, r.at)
    if r.status != rules.REDIRECTED:
        return out
    named = _named(r) - original
    if not named:
        return out
    before = [c for c in row.outbound if c.occurred_at and _aware(c.occurred_at) <= r.at
              and {str(x).lower() for x in (row.outbound_to.get(c.id) or c.recipients or [])} & named]
    return before + out


def _settled(row: BlockRow, replies: list[ReplyView], original: set[str]) -> set[int]:
    """The redirects that no longer decide the request (ids of their views): a hand-logged copy of another reply
    on record (same own text), one naming an address our resend had already gone to before it, and one answered
    by a later reply from the address it names. The request then reads what came after (their answer from the new
    address, or "resent, awaiting reply"), never "resend to" the address the letter already went to."""
    out: set[int] = set()
    for i, r in enumerate(replies):
        if r.status != rules.REDIRECTED:
            continue
        text = _own_text(r)
        logged = (r.corr.meta or {}).get("source") != "mailbox"
        if text and any(_own_text(e) == text and (logged or (e.corr.meta or {}).get("source") != "mailbox")
                        for e in replies[:i]):
            out.add(id(r))
            continue
        if any(_aware(c.occurred_at) <= r.at for c in _answer_outs(row, r, original)):
            out.add(id(r))
            continue
        named = _named(r) - original
        if named and any(str(e.corr.sender or "").strip().lower() in named for e in replies[i + 1:]):
            out.add(id(r))
    return out


def _derive(row: BlockRow, now: datetime, overdue_days: int, oc: dict | None) -> None:
    replies = row.replies
    original = {a.lower() for a in row.to} | (
        {str(row.order.recipient_email).lower()} if row.order is not None and row.order.recipient_email else set())
    # a redirect already answered (a hand-logged copy, one naming where we had resent, one their reply from the new
    # address answered) never decides; the others do
    settled = _settled(row, replies, original)
    live = [r for r in replies if id(r) not in settled]
    deciding = _pick(live)
    # a redirect / bounce / question we answered with a letter (a resend): the latest one, whichever reply ends up
    # deciding, so the row keeps showing where the request went once they answer the resend
    resend_of = next((r for r in reversed(replies) if r.status in ANSWERED_BY_OUTBOUND
                      and _answer_outs(row, r, original)), None)
    if resend_of is not None and (deciding is None or deciding.at <= resend_of.at):
        first_after = min(_aware(c.occurred_at) for c in _answer_outs(row, resend_of, original))
        after = [r for r in live if r.at > first_after]
        if after:  # their answer to the resend decides (even an acknowledgement of it)
            deciding = _pick(after)
        elif deciding is None:  # only answered redirects: the request was resent and awaits their answer
            deciding = resend_of
    row.deciding = deciding
    row.needs_review = any(r.needs_review for r in replies if deciding is None or r.at >= deciding.at)
    row.ticket = next((r.ticket for r in reversed(replies) if r.ticket), None) or (
        row.order.external_ref if row.order is not None else None)
    rec, rec_at, hold = _recorded(row.order)
    row.recorded, row.recorded_at = rec, rec_at
    draft = (row.order is not None and row.order.status == StopOrderStatus.DRAFT) or (
        row.order is None and row.letter is not None and row.letter.status == CorrespondenceStatus.DRAFT)

    if row.kind == "outlook":  # not a request until a person ties it to a letter
        row.status, row.source, row.needs_review = SENT_REVIEW, "none", True
        return
    if draft:
        row.status, row.source = NOT_SENT, "none"
    elif rec is not None and (deciding is None or rec_at is None or deciding.at <= rec_at
                              or deciding.status in WEAK or compatible(deciding.status, rec)):
        row.status, row.source = rec, "recorded"
        row.amount, row.asset = hold.get("amount"), hold.get("asset")
    elif deciding is not None:
        row.status, row.source = deciding.status, deciding.source
        row.amount, row.asset = deciding.amount, deciding.asset
        row.needs_confirmation = row.order is not None and deciding.status in RESOLVED and deciding.source != "human" \
            or (rec is not None and not compatible(deciding.status, rec))
        if deciding.human is not None:
            row.applied = bool(deciding.human.get("applied"))
            if not row.applied and deciding.status in RESOLVED and row.order is not None:
                row.proposal = deciding.human
                row.needs_confirmation = True
        later_out = _answer_outs(row, deciding, original)
        if deciding.status in ANSWERED_BY_OUTBOUND and later_out:
            row.status, row.resent, row.source = AWAITING, True, "resent"
        elif deciding.status in ANSWERED_BY_LE_LINK and any(
                ln.get("sent") and ln.get("at") and ln["at"] > deciding.at for ln in row.links):
            row.status, row.source = AWAITING, "le_route"  # our LE brief answered it: LE files now
    else:
        row.status, row.source = AWAITING, "none"
    if not draft:
        # the latest outcome suggested by a reply (rules / AI) that no person answered since (a confirmation of that
        # reply or a later one, or a stop-order status recorded after it): "suggests …, needs confirmation"
        sug = next((r for r in reversed(replies) if r.outcome_suggestion is not None), None)
        if sug is not None:
            answered = any(r.human is not None and r.at >= sug.at for r in replies) or (
                rec is not None and rec_at is not None and rec_at >= sug.at)
            if not answered:
                row.suggestion, row.suggestion_reply = dict(sug.outcome_suggestion), sug
                row.needs_confirmation = row.needs_review = True
    if resend_of is not None:
        # where the request went after their redirect / bounce / question: shown even once they answered it
        later_out = _answer_outs(row, resend_of, original)
        last = max(later_out, key=lambda c: (_aware(c.occurred_at), c.id))
        row.resent_at = _aware(last.occurred_at)
        to = row.outbound_to.get(last.id) or []
        if to and [x.lower() for x in to] != [x.lower() for x in row.to]:
            row.first_to, row.to = list(row.to), list(to)

    # issuer freeze read on-chain after the request: evidence of a freeze
    if oc is not None:
        row.onchain = oc
        hits = _onchain_frozen_for(row, oc)
        if hits and row.status in WAITING and row.suggestion is None:
            # evidence of a freeze, never the status itself: a person confirms it (and enters the amount)
            total: dict[str, Decimal] = {}
            for e in hits:
                total[e["symbol"]] = total.get(e["symbol"], Decimal(0)) + (_dec(e["balance"]) or Decimal(0))
            sym, amt = max(total.items(), key=lambda kv: kv[1])
            row.suggestion = _suggest(rules.FROZEN, amount=str(amt), asset=sym, quote=None, source="onchain",
                                      confidence=1.0, own="")
            row.needs_confirmation = True

    # the reply clock
    if row.order is not None and row.order.sent_at:
        row.due_at = desk.response_due(row.order, overdue_days)
        chased = _chase_due(row.order, row.due_at)
        if chased is not None:  # we chased it (a status request sent after the reply was due): its own reply clock
            row.due_at = chased
    elif row.letter is not None and row.letter.due_at:
        row.due_at = _aware(row.letter.due_at)
    # after a resend, the date the desk shows (desk.Authority due items): a stop order still awaiting its first
    # response keeps response_due_at (its card); otherwise the clock of the letter sent after their reply
    if resend_of is not None and (row.order is None or not desk.awaiting_response(row.order)):
        later = [_aware(c.due_at) for c in _answer_outs(row, resend_of, original) if c.due_at]
        if later:
            row.due_at = max(later)
    # a deadline a reply since our last letter states: an unambiguous reply-by shortens the reply clock (never
    # lengthens it); the earliest unambiguous one in the future is the request's next deadline. An ambiguous date
    # (03/04) or a hold expiry never changes a clock by itself: it shows as a suggestion (extract.py)
    since = row.last_outbound_at
    stated = []
    # a hold expiry the provider states stays its word on the hold after we answered, and after it passed (the lapse
    # reads that date, never the playbook's default): the latest reply that states one
    for r in reversed(replies):
        holds = []
        for d in (r.extract or {}).get("deadlines") or []:
            try:
                due = datetime.fromisoformat(d["due"]) if d.get("due") else None
            except ValueError:
                due = None
            if due is not None and not d.get("ambiguous") and d.get("what") in pathmod.HOLD_WHAT:
                holds.append({**d, "due_at": _aware(due), "start_at": r.at, "source": d.get("source") or "reply"})
        if holds:
            row.stated_holds = holds
            break
    for r in replies:
        if since is not None and r.at < since:
            continue
        for d in (r.extract or {}).get("deadlines") or []:
            try:
                due = datetime.fromisoformat(d["due"]) if d.get("due") else None
            except ValueError:
                due = None
            if due is not None and not d.get("ambiguous") and due > now:
                stated.append((_aware(due), {**d, "start_at": r.at}))  # the reply's date: the alert's lead
            if due is not None and d.get("auto") and d.get("what") == "reply_by" and row.due_at is not None \
                    and _aware(due) < row.due_at and (row.requested_at is None or _aware(due) > row.requested_at):
                row.due_at = _aware(due)
    row.clocks = [{**d, "due_at": due, "source": d.get("source") or "reply"} for due, d in stated]
    if stated:
        due, d = min(stated, key=lambda x: x[0])
        row.next_deadline = {**d, "due_at": due}
    waiting = row.status in WAITING and row.status != NOT_SENT
    start = row.last_outbound_at if resend_of is not None else row.requested_at
    if row.source == "le_route":
        # the provider answered and our LE brief went out: we wait on LE now, on the brief's own clock (never the
        # provider letter's old reply date)
        ln = max((x for x in row.links if x.get("sent") and x.get("at") and deciding is not None
                  and x["at"] > deciding.at), key=lambda x: (x["at"], x["id"]), default=None)
        if ln is not None:
            row.due_at, start = ln.get("due_at"), ln["at"]
    row.days_waiting = max(0, (now - start).days) if waiting and start else None
    _set_overdue(row, now)


def _chase_due(order: StopOrder, due: datetime | None) -> datetime | None:
    """The reply-by date of the latest status request sent on `order` once its reply was due (`due`): chasing an
    overdue reply restarts the clock (as app.ai.rules: "no status request since the due date"). None: no such chase,
    or its date is not later."""
    if due is None:
        return None
    best = None
    for c in order.correspondence or []:
        if c.direction != CorrespondenceDirection.OUT or c.status != CorrespondenceStatus.SENT \
                or c.kind != CorrespondenceKind.STATUS_REQUEST or c.due_at is None or c.occurred_at is None:
            continue
        if _aware(c.occurred_at) >= due and _aware(c.due_at) > due and (best is None or _aware(c.due_at) > best):
            best = _aware(c.due_at)
    return best


def _set_overdue(row: BlockRow, now: datetime) -> None:
    waiting = row.status in WAITING and row.status != NOT_SENT
    # an unclear reply is still their answer (a person reads it): never "overdue" on the old reply date
    row.overdue = bool(waiting and row.due_at is not None and row.due_at < now and row.suggestion is None
                       and (row.status in (AWAITING, rules.AUTO_REPLY, rules.ACKNOWLEDGED)
                            or row.status == rules.UNCLEAR and row.deciding is None))


# --------------------------------------------------------------------------- paths and clocks
def _links(auths: list[desk.Authority]) -> dict[str, list[dict]]:
    """request key -> our letters to an LE authority / counsel that follow it up (`meta.follow_up_of`: the LE / counsel
    brief), sent or drafted, oldest first."""
    out: dict[str, list[dict]] = {}
    for a in auths:
        if not (a.is_le or a.is_adviser):
            continue
        for c in a.correspondence:
            key = (c.meta or {}).get("follow_up_of")
            if c.direction != CorrespondenceDirection.OUT or not isinstance(key, str) or c.status not in (
                    CorrespondenceStatus.SENT, CorrespondenceStatus.DRAFT):
                continue
            out.setdefault(key, []).append({
                "id": c.id, "authority": a.name, "authority_key": a.key, "counsel": a.is_adviser and not a.is_le,
                "template": (c.meta or {}).get("template_key"), "sent": c.status == CorrespondenceStatus.SENT,
                "at": _aware(c.occurred_at) if c.status == CorrespondenceStatus.SENT else None,
                "due_at": _aware(c.due_at)})
    for v in out.values():
        v.sort(key=lambda x: (x["at"] or _now(), x["id"]))
    return out


def confirmed_steps(case: Case) -> dict[str, list[dict]]:
    """request key -> the path steps a person recorded (cases.facts[path.PATH_KEY]), oldest first."""
    raw = (case.facts or {}).get(pathmod.PATH_KEY)
    return {k: [x for x in v if isinstance(x, dict)] for k, v in raw.items() if isinstance(v, list)} \
        if isinstance(raw, dict) else {}


def _org(key: str | None):
    from app.domain import directory

    try:
        return directory.load_catalogue().by_key.get(key) if key else None
    except Exception:  # noqa: BLE001 - an invalid catalogue: no channel labels
        return None


def _advance(row: BlockRow, case: Case, *, requester: str, le: list, confirmed: dict, now: datetime) -> None:
    """The request's path step, its playbook clocks, the reply clock they shorten and the next deadline (app.blocks
    .path). Advisory: an ambiguous date never changes a clock; a hold expiry only once a person confirmed the hold."""
    if row.kind in ("onchain", "outlook") or row.authority.is_le or row.authority.is_adviser:
        return
    org = _org(row.org_key)
    st = pathmod.advance(row, row.playbook, requester=requester, links=row.links, confirmed=confirmed.get(row.key),
                         le=le, now=now, org=org, victim_jur=pbm.jurisdiction_code(case.victim_jurisdiction),
                         fact_known=case.fraud_date)
    row.path = st
    pclock = pathmod.reply_clock(row, st)
    if pclock is not None and row.due_at is not None and pclock < row.due_at and row.status in (
            AWAITING, rules.AUTO_REPLY, rules.ACKNOWLEDGED) and row.source != "le_route" and not row.resent:
        row.due_at = pclock
    hold_stated = row.stated_holds or [c for c in row.clocks if c.get("what") in pathmod.HOLD_WHAT]
    pclocks = [c for c in st.clocks if c["what"] != "reply_by"]
    if st.hold_at is not None and hold_stated:
        # the reply's own expiry wins over the playbook's default: one hold expiry (KuCoin says 30 days; its 7-day
        # restraint default no longer runs, is never a lapse and never a brief's live date)
        row.hold_expires_at = min(c["due_at"] for c in hold_stated)
        pclocks = [{**c, "met": True, "superseded": "the provider's reply states the hold's expiry"}
                   if c["what"] in pathmod.HOLD_WHAT and c.get("starts") == "hold_confirmed" else c for c in pclocks]
    else:
        row.hold_expires_at = st.hold_expires_at
    st.hold_expires_at = row.hold_expires_at
    row.clocks = sorted(row.clocks + pclocks, key=lambda c: c["due_at"])
    live = [c for c in row.clocks if c["due_at"] > now and not c.get("met")
            and (c["what"] not in pathmod.HOLD_WHAT or st.hold_at is not None)]  # a hold's expiry once confirmed
    row.next_deadline = None
    if live:
        c = live[0]
        row.next_deadline = {**c, "label": c.get("label") or pathmod.CLOCK_LABELS.get(c["what"], c["what"])}
    st.lapsed = pathmod.lapsed(row, st, now)  # the hold may be gone: its lapse / our deadline passed
    _set_overdue(row, now)


def _le_authorities(all_auth: list[desk.Authority]) -> list[desk.Authority]:
    return [a for a in all_auth if a.is_le]


def next_action(case: Case, row: BlockRow, le: list[desk.Authority], now: datetime | None = None) -> dict:
    """{"kind", "text", "href", "evidence", "clock"}: what to do next for this request. The provider playbook's next
    step for the request's path step (app.blocks.path.action: brief LE with the pack, the cross-border route, the hold's
    clock, …) when it has one, else the status's generic text. `evidence`: what that step needs (playbook EVIDENCE
    keys with labels); `clock`: the next deadline ({} when none)."""
    base = _generic_action(case, row, le)
    st, nd = row.path, row.next_deadline
    act = None
    if st is not None and base.get("kind") not in ("review", "send", "check"):
        act = pathmod.action(case.id, row, st, name=row.authority.name, pb=row.playbook, org=_org(row.org_key),
                             requester=st.requester, next_clock=nd, now=now)
    out = dict(act or base)
    if act is None and nd is not None and out.get("kind") == "confirm":
        out["text"] += pathmod.clock_text(nd)
    if act is None and out.get("kind") == "confirm" and st is not None and (row.suggestion or {}).get("status") == \
            rules.HOLD_PLACED:
        out["text"] += _hold_preview(row, st, now or _now())
    out.setdefault("evidence", list(st.evidence) if st is not None and (act is not None or out.get("kind") == "answer")
                   else [])
    out["clock"] = ({k: nd.get(k) for k in ("what", "label", "due_at", "action", "source", "starts", "by")}
                    if nd is not None else {})
    return out


def _hold_preview(row: BlockRow, st, now: datetime) -> str:
    """What follows once a person confirms the hold a reply reports: its stated lapse and the playbook's next step
    (KuCoin: lifted after 30 days unless a freezing order stating the duration arrives)."""
    lapse = min((c["due_at"] for c in row.clocks if c.get("what") in pathmod.HOLD_WHAT and c["due_at"] > now),
                default=None)
    t = st.target
    if lapse is None and t is None:
        return ""
    # the instrument the next action and the LE brief name (their reply's, else the LE path's)
    ask = pathmod.ask_label(st) if st.instrument else (pathmod._label(t.instrument.type) if t is not None
                                                        else "an LE order")
    dur = " stating the freeze duration" if t is not None and "freeze_duration_stmt" in t.evidence else ""
    sign = ", not digitally signed" if t is not None and t.instrument.signing == "not_digital" else ""
    return (" Once confirmed:" + (f" the hold lapses {lapse:%d %b %Y} (their reply);" if lapse else "")
            + f" then brief LE for {ask}{dur}{sign}" + (" before it lapses." if lapse else "."))


def _generic_action(case: Case, row: BlockRow, le: list[desk.Authority]) -> dict:
    cid, key = case.id, row.authority.key
    auth_url = f"/cases/{cid}/authorities/{key}"
    item_url = (f"/cases/{cid}/stop-orders/{row.order.id}" if row.order is not None
                else f"/cases/{cid}/authorities/correspondence/{row.letter.id}" if row.letter is not None else auth_url)
    reply_url = f"{auth_url}#c{row.deciding.corr.id}" if row.deciding is not None else auth_url
    ticket = f" quoting their ticket {row.ticket}" if row.ticket else ""
    st = row.status
    if st == SENT_REVIEW:
        cands = [x for x in (row.review or {}).get("candidates") or [] if isinstance(x, str)]
        entry = f"/cases/{cid}/authorities/correspondence/{row.letter.id}" if row.letter is not None else auth_url
        if cands:
            names = " / ".join(("stop order #" if x[0] == "o" else "letter #") + x[1:] for x in cands[:4])
            return {"kind": "review", "text": f"Tie it to {names}: mark the letter it carried as sent (the draft's "
                                              f"Mark sent), or leave it if it was none of them.", "href": entry}
        return {"kind": "review", "text": "Check it: if it carried a letter, mark that letter sent; if it was not a "
                                          "request, nothing to do.", "href": entry}
    if st == NOT_SENT:
        return {"kind": "send", "text": "Send it: open the draft's e-mail editor (text, Cc / Bcc, attachments); a case admin "
                                        "presses Send now and it goes out from the case mailbox.",
                "href": item_url}
    if st == ONCHAIN_ONLY:
        oc = row.onchain or {}
        lever = oc.get("unfrozen_balance") or []
        if lever:
            top = max(lever, key=lambda e: _dec(e["balance"]) or Decimal(0))
            return {"kind": "request", "text": f"Ask {row.authority.name} to freeze {top['short']} ({top['balance_label']} "
                                               f"{top['symbol']}, not blacklisted on-chain).",
                    "href": f"{auth_url}?template=stop_order#generate"}
        return {"kind": "none", "text": "Nothing to request: no unfrozen balance at this issuer's contracts.", "href": None}
    if row.suggestion is not None:
        what = suggestion_text(row.suggestion)
        if row.suggestion.get("source") == "onchain":
            text = (f"The issuer's blacklist shows the cited wallet frozen on-chain ({what}): check it and confirm the "
                    "freeze yourself (choose the status and enter the amount held).")
        else:
            text = (f"Their reply suggests {what}: read it and confirm the outcome yourself (choose the status and "
                    "enter the amount held). Until a person confirms it, it counts nowhere.")
        return {"kind": "confirm", "text": text, "href": f"/cases/{cid}/blocks#{row.key}"}
    if row.needs_confirmation and row.order is not None and st in RESOLVED:
        what = "confirm the on-chain freeze" if row.source == "onchain" else "confirm what it says"
        if row.proposal is not None:
            return {"kind": "confirm", "text": "A case admin applies the proposed status to the stop order.",
                    "href": f"/cases/{cid}/blocks#{row.key}"}
        return {"kind": "confirm", "text": f"Read the reply and {what}: Confirm status updates the stop order.",
                "href": f"/cases/{cid}/blocks#{row.key}"}
    if st == rules.REDIRECTED:
        target = row.resend_to
        warn = ""
        if row.deciding is not None and row.deciding.sender_domain_ok is False:
            warn = " The reply did not come from their own domain: verify the address first."
        # a resend is a new letter linked to the request (a follow-up): "one e-mail per letter" never resends
        # the letter itself, and the request reads "awaiting" again once the follow-up went out
        follow_up = f"{auth_url}?template=status_request#generate" if row.order is not None else reply_url
        if target:
            return {"kind": "resend", "text": f"Resend to {target} (named in their reply; check it against their "
                                              f"published channels): write a follow-up letter and e-mail it there."
                                              f"{warn}", "href": follow_up}
        return {"kind": "resend", "text": "Resend through the channel their reply names (see the reply)." + warn,
                "href": reply_url}
    intel = row.intel
    clock = pathmod.clock_text(row.next_deadline)
    if st == rules.LE_PROCESS_REQUIRED:
        names = " / ".join(a.name for a in le[:2]) or "the police / IC3"
        href = f"/cases/{cid}/authorities/{le[0].key}?template=le_cover#generate" if le else auth_url
        portal = next((u["value"] for u in (row.deciding.urls if row.deciding else [])), None)
        via = f" through {portal}" if portal else " through their law-enforcement channel"
        ins = intel["instrument"]
        need = ""
        if ins:
            jur = " / ".join(ins.get("issuer_jurisdictions") or [])
            need = f" They require {ins['label']}" + (f" ({jur})" if jur and ins["type"] != "us_or_fr_court_order"
                                                      else "") + (f"; quote their ticket {row.ticket}" if row.ticket
                                                                  else "") + "."
        return {"kind": "le", "text": f"Send an LE cover letter asking {names} to file the request{via}.{need}{clock}",
                "href": href}
    if st == rules.INFO_REQUESTED:
        asks = ", ".join(a["label"] for a in intel["asks"][:6])
        what = f" ({asks})" if asks else ""
        return {"kind": "answer", "text": f"Answer their questions{ticket}: reply with the information they asked "
                                          f"for{what}.{clock}", "href": reply_url}
    if st == rules.DELIVERY_FAILED:
        return {"kind": "resend", "text": "The e-mail bounced: check the address on the contact card and send again.",
                "href": auth_url}
    if st == rules.HOLD_PLACED:
        names = ", ".join(a.name for a in le[:2]) or "law enforcement"
        return {"kind": "le", "text": f"Hold in place: ask {names} for a freezing / seizure order before the hold lapses."
                                      f"{clock}",
                "href": f"/cases/{cid}/authorities/{le[0].key}?template=le_cover#generate" if le else auth_url}
    if st == rules.FROZEN:
        return {"kind": "le", "text": "Frozen: send the LE cover letter so the funds stay held for seizure; request "
                                      "release when the victim's claim is accepted.",
                "href": f"/cases/{cid}/authorities/{le[0].key}?template=le_cover#generate" if le else
                f"{auth_url}?template=release_request#generate"}
    if st == rules.FUNDS_RETURNED:
        return {"kind": "close", "text": "Confirm receipt with the victim and close the request.", "href": item_url}
    if st in (rules.DECLINED, rules.DECLINED_NO_ASSETS):
        return {"kind": "close", "text": "Declined: close the request, or escalate through law enforcement if funds "
                                         "are still there.", "href": auth_url}
    if st == rules.UNCLEAR and row.source == "human":
        return {"kind": "chase", "text": f"A person read their reply as unclear: ask {row.authority.name} what it "
                                         f"means (status request{ticket}).",
                "href": f"{auth_url}?template=status_request#generate"}
    if st == rules.UNCLEAR:
        return {"kind": "review", "text": "Read the reply and confirm what it says.", "href": reply_url}
    # awaiting / auto-reply / acknowledged
    if row.overdue:
        return {"kind": "chase", "text": f"Reply overdue: send a status request{ticket}.",
                "href": f"{auth_url}?template=status_request#generate"}
    due = f" (reply due {row.due_at:%d %b %Y})" if row.due_at else ""
    if st == rules.AUTO_REPLY:
        return {"kind": "wait", "text": f"Only an automatic reply so far: wait for the substantive answer{due}.",
                "href": reply_url}
    if st == rules.ACKNOWLEDGED:
        extra = " Confirm status records the acknowledgement on the stop order." if row.needs_confirmation else ""
        return {"kind": "wait", "text": f"Acknowledged{(' — ticket ' + row.ticket) if row.ticket else ''}: wait for "
                                        f"their answer{due}.{extra}", "href": reply_url}
    if row.resent and row.resent_at:
        return {"kind": "wait", "text": f"Sent again on {row.resent_at:%d %b %Y} after their reply: wait for the "
                                        f"answer{due}.", "href": item_url}
    return {"kind": "wait", "text": f"Wait for the reply{due}.", "href": item_url}


def case_blocks(db: Session, case: Case, *, now: datetime | None = None,
                authorities: list[desk.Authority] | None = None) -> list[BlockRow]:
    """Every request of the case with its derived status and next action (read-only)."""
    from app.domain import directory, notify
    from app.domain import sender as sender_mod

    now = now or _now()
    auths = authorities if authorities is not None else desk.case_authorities(db, case, include_prospects=False)
    days = notify.overdue_days(db, case)
    oc_all = onchain_by_issuer(db, case)
    le = _le_authorities(auths)
    links, confirmed = _links(auths), confirmed_steps(case)
    targets = pathmod.le_targets(le, directory.playbook_for)
    requester = sender_mod.requester_kind(db, case)
    rows: list[BlockRow] = []
    seen_issuers: set[str] = set()
    for a in auths:
        issuer = _issuer_of(a)
        reqs = _requests(db, case, a)
        for r in reqs:
            r.links = links.get(r.key, [])
            _derive(r, now, days, oc_all.get(issuer) if issuer else None)
            _advance(r, case, requester=requester, le=targets, confirmed=confirmed, now=now)
            r.next_action = next_action(case, r, le, now)
        if issuer and issuer in oc_all:
            seen_issuers.add(issuer)
            if not reqs:
                rows.append(_onchain_row(case, a, oc_all[issuer], le))
        rows.extend(reqs)
    # issuers with readings that the case has not engaged yet
    from app.freeze.issuers import ISSUER_ENTITY

    for issuer, oc in oc_all.items():
        if issuer in seen_issuers or not (oc["frozen"] or oc["unfrozen_balance"]):
            continue
        ent = db.scalar(select(Entity).where(Entity.name == ISSUER_ENTITY.get(issuer, issuer)))
        if ent is None:
            continue
        a = desk.Authority(key=f"entity-{ent.id}", name=ent.name, category=ent.category.value, entity=ent)
        rows.append(_onchain_row(case, a, oc, le))
    _flag_possibly_sent(case, rows)
    order = {s: i for i, s in enumerate((SENT_REVIEW, rules.UNCLEAR, rules.REDIRECTED, rules.DELIVERY_FAILED, rules.INFO_REQUESTED,
                                         rules.LE_PROCESS_REQUIRED, rules.HOLD_PLACED, rules.FROZEN, AWAITING,
                                         rules.ACKNOWLEDGED, rules.AUTO_REPLY, NOT_SENT, ONCHAIN_ONLY,
                                         rules.FUNDS_RETURNED, rules.DECLINED_NO_ASSETS, rules.DECLINED))}
    rows.sort(key=lambda r: (not r.needs_confirmation, not r.overdue, order.get(r.status, 99),
                             -(r.requested_at.timestamp() if r.requested_at else 0), r.key))
    return rows


def _flag_possibly_sent(case: Case, rows: list[BlockRow]) -> None:
    """A draft that an Outlook e-mail awaiting review may have carried: check before sending it again. An
    e-mail whose candidate drafts have all been marked sent since needs nothing more."""
    seen: dict[str, BlockRow] = {}
    for r in rows:
        if r.status == SENT_REVIEW and r.review:
            for x in r.review.get("candidates") or []:
                seen.setdefault(str(x), r)
    if not seen:
        return
    open_review: set[str] = set()
    for r in rows:
        if r.status != NOT_SENT:
            continue
        ids = {r.key} | ({f"c{r.letter.id}"} if r.letter is not None else set())
        hit = next((seen[i] for i in ids if i in seen), None)
        if hit is None or hit.letter is None:
            continue
        open_review.add(hit.key)
        when = f" on {hit.review['at']:%d %b %Y}" if hit.review.get("at") else ""
        r.next_action = {"kind": "check", "text": f"Possibly already sent from Outlook{when} (entry #{hit.letter.id}): "
                                                  "check before sending.",
                         "href": f"/cases/{case.id}/authorities/correspondence/{hit.letter.id}"}
    for r in rows:
        if r.status == SENT_REVIEW and (r.review or {}).get("candidates") and r.key not in open_review:
            r.needs_review = False
            r.next_action = {"kind": "none", "text": "Its candidate letters are recorded as sent since: nothing to do, "
                                                     "unless it carried another letter.",
                             "href": r.next_action.get("href")}


def _onchain_row(case: Case, a: desk.Authority, oc: dict, le: list[desk.Authority]) -> BlockRow:
    row = BlockRow(key=f"x{a.entity.id if a.entity else 0}", authority=a, kind="onchain", status=ONCHAIN_ONLY,
                   source="onchain", onchain=oc)
    if oc["frozen"]:
        sym, amt = max(((s, _dec(v) or Decimal(0)) for s, v in oc["frozen_total"].items()), key=lambda kv: kv[1])
        row.amount, row.asset = str(amt), sym
    row.next_action = next_action(case, row, le)
    return row


def find_row(rows: list[BlockRow], key: str) -> BlockRow | None:
    return next((r for r in rows if r.key == key), None)


def summary(rows: list[BlockRow]) -> dict:
    """Counts for the Overview card and the skill."""
    by: dict[str, int] = {}
    for r in rows:
        by[r.status] = by.get(r.status, 0) + 1
    frozen: dict[str, Decimal] = {}
    for r in rows:
        # only what a person confirmed (recorded on the stop order, or confirmed here): never a suggestion
        if r.status in (rules.FROZEN, rules.HOLD_PLACED) and r.amount and r.kind != "onchain" \
                and r.source in HUMAN_SOURCES:
            frozen[r.asset or "?"] = frozen.get(r.asset or "?", Decimal(0)) + (_dec(r.amount) or Decimal(0))
    return {"total": sum(1 for r in rows if r.kind not in ("onchain", "outlook")), "by_status": by,
            # Outlook e-mails to review (not the probable copies: their candidates are recorded as sent since)
            "sent_review": sum(1 for r in rows if r.status == SENT_REVIEW and r.needs_review),
            "needs_confirmation": sum(1 for r in rows if r.needs_confirmation),
            "suggested": sum(1 for r in rows if r.suggestion is not None),
            "needs_review": sum(1 for r in rows if r.needs_review),
            # the "to review" tile (page, Overview card, exports, /block-status): replies and Outlook e-mails to
            # review, plus requests waiting on our action (resend, answer, LE process, a bounce)
            "our_action": sum(1 for r in rows if r.kind != "onchain" and r.status in OUR_ACTION),
            "to_review": sum(1 for r in rows if r.kind != "onchain" and (r.needs_review or r.status in OUR_ACTION)),
            "overdue": sum(1 for r in rows if r.overdue),
            "awaiting": sum(1 for r in rows if r.status in WAITING and r.status != NOT_SENT),
            "not_sent": by.get(NOT_SENT, 0),
            "frozen": {k: str(v) for k, v in frozen.items()},
            "frozen_fmt": [f"{fmt_amount(v, k)} {k}" for k, v in frozen.items()]}


# --------------------------------------------------------------------------- refresh (classify + notify)
@dataclass
class RefreshReport:
    replies: int = 0
    rules_stored: int = 0
    ai_calls: int = 0
    ai_ok: int = 0
    ai_skipped: str | None = None  # why no AI call was made (classify_ai.REASON_TEXT key)
    changed: list[str] = field(default_factory=list)  # request keys whose status changed

    def counts(self) -> dict:
        return {"replies": self.replies, "rules_stored": self.rules_stored, "ai_calls": self.ai_calls,
                "ai_ok": self.ai_ok, "ai_skipped": self.ai_skipped, "changed": len(self.changed)}


def refresh(db: Session, case: Case, *, actor: Any = None, use_ai: bool = True, only_ids: set[int] | None = None,
            provider: Any | None = None, notify_changes: bool = True) -> RefreshReport:
    """Classify the case's replies with the rules (stored), ask the AI for the ones it has not read when
    the case allows it (at most MAX_AI_CALLS_PER_REFRESH), then emit block_status_changed for every
    request whose status changed since the last refresh (the first refresh only records the snapshot)."""
    rep = RefreshReport()
    rows = case_blocks(db, case)
    ai_ok_to_call = False
    if use_ai:
        from app.ai import providers as ai_providers

        provider = provider if provider is not None else (ai_providers.get_provider()
                                                          if classify_ai.is_enabled(case) else None)
        ai_ok_to_call, rep.ai_skipped = classify_ai.may_call(case, provider)
    for row in rows:
        for rv in row.replies:
            if only_ids is not None and rv.corr.id not in only_ids:
                continue
            rep.replies += 1
            entity_id = row.authority.entity.id if row.authority.entity else None
            so_id = row.order.id if row.order else None
            stored_rules = _meta_store(rv.corr).get("rules") or {}
            if stored_rules.get("version") != rules.RULES_VERSION or stored_rules.get("status") != rv.rules.status:
                data = rv.rules.as_dict()
                data["at"] = _now().isoformat(timespec="seconds")
                _save(db, case, rv.corr, "rules", data, stop_order_id=so_id, entity_id=entity_id)
                rep.rules_stored += 1
            _save_extract(db, rv)
            if ai_ok_to_call and rv.ai is None and rv.human is None and rep.ai_calls < MAX_AI_CALLS_PER_REFRESH \
                    and rv.rules.status != rules.DELIVERY_FAILED and _from_mailbox(db, rv) and _ai_retry_ok(rv.corr):
                rep.ai_calls += 1
                result, why = classify_ai.classify_reply(db, case, rv.corr, actor=actor, request_kind=row.kind,
                                                         provider=provider)
                if result is not None:
                    rep.ai_ok += 1
                    _save(db, case, rv.corr, "ai", result, stop_order_id=so_id, entity_id=entity_id)
                else:
                    _note_ai_error(rv.corr, why)
    db.commit()
    if notify_changes:
        rep.changed = _notify_changes(db, case)
    return rep


def _save_extract(db: Session, rv: ReplyView) -> None:
    """correspondence.meta block_status extract: what the reply says beyond its status (app.blocks.extract, the
    AI's verified additions merged), written when it changed. Flushes only."""
    st = _meta_store(rv.corr)
    data = rv.extract
    old = {k: v for k, v in (st.get("extract") or {}).items() if k != "at"}
    if data is None and not old or data is not None and old == data:
        return
    meta = dict(rv.corr.meta or {})
    st = dict(meta.get("block_status") or {})
    if data is None:
        st.pop("extract", None)
    else:
        st["extract"] = {**data, "at": _now().isoformat(timespec="seconds")}
    meta["block_status"] = st
    rv.corr.meta = meta
    db.flush()


TRANSIENT_AI_ERRORS = frozenset({"rate_limited", "timeout", "connection_error", "api_error_502", "api_error_503",
                                 "api_error_504", "api_error_500"})
MAX_AI_ATTEMPTS = 3


def _from_mailbox(db: Session, rv: ReplyView) -> bool:
    """"AI reads mailbox replies": only replies read from the case mailbox (or imported from it), never a
    note an investigator typed."""
    return rv.untrusted or _mail_id(db, rv.corr) is not None


def _ai_retry_ok(corr: Correspondence) -> bool:
    """A failed AI reading is retried on a later refresh only when the failure was transient."""
    err = _meta_store(corr).get("ai_error") or {}
    if not err:
        return True
    return err.get("reason") in TRANSIENT_AI_ERRORS and int(err.get("n") or 0) < MAX_AI_ATTEMPTS


def _note_ai_error(corr: Correspondence, reason: str | None) -> None:
    meta = dict(corr.meta or {})
    st = dict(meta.get("block_status") or {})
    prev = st.get("ai_error") or {}
    st["ai_error"] = {"reason": reason, "n": int(prev.get("n") or 0) + 1, "at": _now().isoformat(timespec="seconds")}
    meta["block_status"] = st
    corr.meta = meta


def _snap(row: BlockRow) -> str:
    """A request's state in the snapshot: its status, and whether an outcome waits for a person ("…|suggests")."""
    return row.status + ("|suggests" if row.suggestion is not None else "")


def _notify_changes(db: Session, case: Case) -> list[str]:
    rows = case_blocks(db, case)
    snap = {r.key: _snap(r) for r in rows if r.kind not in ("onchain", "outlook")}
    facts = dict(case.facts or {})
    old = facts.get(SNAPSHOT_KEY)
    changed: list[str] = []
    if isinstance(old, dict):
        for r in rows:
            if r.kind in ("onchain", "outlook") or old.get(r.key) == _snap(r) or (
                    r.key not in old and r.status in (NOT_SENT, AWAITING) and r.suggestion is None):
                continue
            if r.status == rules.DELIVERY_FAILED:
                continue  # the e-mail desk already raised a warning for the bounce (app.mail.ingest.persist_to_case)
            changed.append(r.key)
            _emit(db, case, r, confirmed=False)
    facts[SNAPSHOT_KEY] = snap
    case.facts = facts
    db.commit()
    return changed


def _emit(db: Session, case: Case, row: BlockRow, *, confirmed: bool, applied: bool = False,
          proposal: bool = False) -> None:
    from app.providers.prices import to_usd

    usd = None
    if row.amount and row.asset:
        try:
            usd = to_usd(row.asset, _dec(row.amount))
        except Exception:  # noqa: BLE001 - an unpriced asset has no USD figure
            usd = None
    what = row.title
    if row.suggestion is not None and not confirmed:
        # an outcome only a person confirms: the notification says "needs review", never the outcome or its amount
        onchain = row.suggestion.get("source") == "onchain"
        label = "on-chain reading needs review" if onchain else "reply needs review"
        events.emit(db, case, events.BLOCK_STATUS_CHANGED, severity="warning",
                    title=f"{case.reference}: {what} — {label}",
                    body=(f"{what} has {'an issuer reading on-chain' if onchain else 'a reply'} that needs review: a "
                          "person reads it and confirms the outcome on the Block status page."),
                    link=f"/cases/{case.id}/blocks#{row.key}",
                    payload={"request": row.key, "status": row.status, "source": row.source, "needs_review": True,
                             "stop_order_id": row.order.id if row.order else None,
                             "correspondence_id": row.suggestion_reply.corr.id if row.suggestion_reply else None,
                             "confirmed": False, "applied": False}, commit=False)
        return
    amount = f" ({fmt_amount(row.amount, row.asset)} {row.asset or ''})".replace(" )", ")") if row.amount and row.status in (
        rules.FROZEN, rules.HOLD_PLACED, rules.FUNDS_RETURNED) else ""
    how = ("confirmed by a case admin and applied to the stop order" if applied else
           "proposed by an investigator: a case admin confirms and applies it" if proposal else
           "confirmed by a team member" if confirmed else
           "read from the reply (not confirmed yet)" if row.source in ("rules", "ai") else
           "read on-chain (not confirmed yet)" if row.source == "onchain" else
           "sent again after their reply" if row.source == "resent" else
           "LE briefed after their reply" if row.source == "le_route" else "recorded on the desk")
    severity = {rules.FROZEN: "high", rules.HOLD_PLACED: "high", rules.FUNDS_RETURNED: "high",
                rules.DECLINED: "warning", rules.DECLINED_NO_ASSETS: "warning", rules.DELIVERY_FAILED: "warning",
                rules.REDIRECTED: "warning", rules.LE_PROCESS_REQUIRED: "warning"}.get(row.status, "info")
    events.emit(db, case, events.BLOCK_STATUS_CHANGED, usd=usd, severity=severity,
                title=f"{case.reference}: {what} — {row.label}{amount}",
                body=f"Block status of {what.lower()}: {row.label}{amount}, {how}.",
                link=f"/cases/{case.id}/blocks#{row.key}",
                payload={"request": row.key, "status": row.status, "source": row.source,
                         "stop_order_id": row.order.id if row.order else None,
                         "correspondence_id": row.deciding.corr.id if row.deciding else None,
                         "confirmed": confirmed, "applied": applied}, commit=False)


def on_reply_filed(db: Session, case: Case, corr: Correspondence, *, actor: Any = None) -> RefreshReport | None:
    """Hook for the e-mail desk after it filed a reply on `case` (ingest / import / triage): classify it
    (rules; AI when the case allows) and notify a status change. Never raises."""
    try:
        return refresh(db, case, actor=actor, only_ids={corr.id})
    except Exception as err:  # noqa: BLE001 - the error text of a DB failure carries bound parameters
        db.rollback()
        log.warning("block status refresh failed for case %s reply %s (%s)", case.id, corr.id, type(err).__name__)
        return None


# --------------------------------------------------------------------------- clocks (the scheduler)
CLOCK_KEY = "_block_clocks"  # cases.facts: {"<request>|<clock>|ahead|due": due ISO}: each alert once per due date
CLOCK_GRACE = timedelta(days=3)  # a clock that passed longer ago than this is not announced any more


def check_clocks(db: Session, case: Case, now: datetime | None = None) -> list:
    """Emit provider_deadline / hold_expiring (high) for every clock of the case's requests that falls due soon
    (`path.lead`: half its span, at most three days) or has just passed: a provider's stated submit-by, a playbook clock
    (MEXC's 48 hours from its temporary freeze), a confirmed hold's expiry (KuCoin's 30-day auto-lift). Their own reply
    clocks are response_overdue's. Rules only (no AI, no network); each alert once per due date. Returns the
    notifications. Called by desk.check_overdue (the scheduler's overdue pass)."""
    now = now or _now()
    facts = dict(case.facts or {})
    seen = dict(facts.get(CLOCK_KEY) or {})
    out = []
    fired: dict[tuple[str, str], list[datetime]] = {}
    for row in case_blocks(db, case, now=now):
        for c in row.clocks:
            if c.get("what") == "reply_by" or c.get("met"):
                continue
            hold = c["what"] in pathmod.HOLD_WHAT
            if hold and (row.path is None or row.path.hold_at is None):
                continue  # a hold expiry counts once a person confirmed the hold
            due = c["due_at"]
            phase = "due" if due <= now else "ahead" if now >= due - pathmod.lead(c) else None
            if phase is None or phase == "due" and now - due > CLOCK_GRACE:
                continue
            mark = f"{row.key}|{c.get('key') or c['what'] + '@' + c.get('source', '')}|{phase}"
            done = seen.get(mark) == due.isoformat()
            seen[mark] = due.isoformat()
            near = fired.setdefault((row.key, phase, "hold" if hold else c["what"]), [])
            if done or any(abs((due - d).total_seconds()) < 7200 for d in near):
                near.append(due)
                continue  # announced already, or the same deadline read twice (their reply and the playbook)
            near.append(due)
            hours = max(0, int((due - now).total_seconds() // 3600))
            when = f"in {hours}h" if phase == "ahead" else "passed"
            what = c.get("label") or c["what"]
            et = events.HOLD_EXPIRING if hold else events.PROVIDER_DEADLINE
            title = (f"{case.reference}: {row.title} — hold lapses {when}" if hold
                     else f"{case.reference}: {row.title} — deadline {what} {when}")
            body = (f"{row.title}: {what} {due:%d %b %Y %H:%M} UTC"
                    + (f" ({c['span']} after {c['starts_label']})" if c.get("span") else " (stated in the reply)")
                    + ". Open the Block status page for the next step.")
            note = events.emit(db, case, et, severity="high", title=title, body=body,
                               link=f"/cases/{case.id}/blocks#{row.key}",
                               payload={"request": row.key, "clock": c.get("key") or c["what"], "phase": phase,
                                        "due_at": due.isoformat(), "stop_order_id": row.order.id if row.order else None},
                               commit=False)
            if note is not None:
                out.append(note)
    if seen != (facts.get(CLOCK_KEY) or {}):
        facts[CLOCK_KEY] = seen
        case.facts = facts
    db.commit()
    return out


# --------------------------------------------------------------------------- path steps a person records
def confirm_step(db: Session, access: Any, key: str, *, step: str, outcome: str | None = None,
                 note: str | None = None) -> dict:
    """Record a path step only a person knows (app.blocks.path.CONFIRM_STEPS: LE filed, order obtained, cross-border
    request under way, outcome funds moved on / declined for good) on a request, or `step` "undo" to remove the latest
    one. Investigators+. Stored in cases.facts[path.PATH_KEY]; on the authority's timeline."""
    case = access.case
    if not access.can("log_correspondence"):
        raise BlockError(403, "Recording a path step needs an investigator or a case admin.")
    if step != "undo" and step not in pathmod.CONFIRM_STEPS:
        raise BlockError(400, f"unknown step {step!r}")
    if step == "outcome" and outcome not in pathmod.CONFIRM_OUTCOMES:
        raise BlockError(400, "Record frozen / funds returned with Confirm status (with the amount held).")
    row = find_row(case_blocks(db, case), key)
    if row is None or row.kind in ("onchain", "outlook") or row.path is None or row.path_step is None:
        raise BlockError(404, "request not found")
    facts = dict(case.facts or {})
    store = {k: list(v) for k, v in (facts.get(pathmod.PATH_KEY) or {}).items()}
    items = store.get(key, [])
    if step == "undo":
        if not items:
            raise BlockError(409, "No recorded step to undo.")
        items.pop()
        label = "Path step removed"
    else:
        items.append({"step": step, "outcome": outcome if step == "outcome" else None, "by": access.user.id,
                      "at": _now().isoformat(timespec="seconds"), "note": (note or "").strip()[:500] or None})
        label = "Path step recorded: " + (f"Outcome: {pathmod.OUTCOMES[outcome]}" if step == "outcome"
                                          else pathmod.STEP_LABELS[step])
    store[key] = items
    facts[pathmod.PATH_KEY] = store
    case.facts = facts
    entry = desk.log_entry(db, case, row.authority, actor=access.user, direction="note", channel="other", kind="other",
                           subject=f"{label} ({row.title})", body=(note or "").strip()[:2000] or None,
                           body_format="text", stop_order=row.order, classification="R2")
    entry.meta = {**(entry.meta or {}), "source": "block_path", "step": step, "outcome": outcome, "request": key}
    db.commit()
    return {"step": step, "outcome": outcome, "timeline_id": entry.id}


# --------------------------------------------------------------------------- confirm
@dataclass
class ConfirmResult:
    row_key: str
    status: str
    applied: bool
    proposal: bool
    stop_order_status: str | None = None
    timeline_id: int | None = None
    message: str = ""


READ_MYSELF_STATUSES = frozenset({rules.FROZEN, rules.HOLD_PLACED, rules.FUNDS_RETURNED})
AMOUNT_REQUIRED = frozenset({rules.FROZEN, rules.HOLD_PLACED})
AMOUNT_REQUIRED_TEXT = ("Enter the amount held (and its asset) to confirm a hold or freeze: Aegis never takes it from "
                        "the reply.")
READ_MYSELF_TEXT = ("This reply is flagged (text addressed to an AI, or the rules and the AI read it differently): "
                    "tick \"I read the reply myself\" to confirm a hold, freeze or return from it.")


def risky_reply(row: BlockRow, reply: ReplyView | None = None) -> ReplyView | None:
    """The risky reply (suspicious or disputed: `ReplyView.risky`) that makes a hold / freeze / return confirmed
    from `reply` (default: the deciding one) need "I read the reply myself": that reply, the deciding one, or any
    reply of the request that came after the earlier of the two — so a form naming an earlier, harmless reply
    (an acknowledgement) never gets past the tick while a later reply is the suspicious one."""
    chosen = [r for r in (reply, row.deciding) if r is not None]
    if not chosen:
        return None
    for r in chosen:
        if r.risky:
            return r
    pivot = min(r.at for r in chosen)
    return next((r for r in reversed(row.replies) if r.at >= pivot and r.risky), None)


def confirm(db: Session, access: Any, key: str, *, status: str, reply_id: int | None = None,
            amount: str | None = None, asset: str | None = None, apply: bool = False,
            note: str | None = None, read_myself: bool = False) -> ConfirmResult:
    """Confirm a request's status (see the module doc). Investigators+ confirm (a proposal when it maps to
    a stop-order status); `apply` needs a case admin and moves the stop order through the desk. Confirming a
    hold / freeze / return from a risky reply (suspicious, or rules and AI disagree) needs `read_myself`."""
    case = access.case
    if not access.can("log_correspondence"):
        raise BlockError(403, "Confirming a block status needs an investigator or a case admin.")
    if apply and not access.can("manage_case"):
        raise BlockError(403, "Only a case admin can apply a status to the stop order.")
    if status not in CONFIRMABLE:
        raise BlockError(400, f"unknown status {status!r}")
    rows = case_blocks(db, case)
    row = find_row(rows, key)
    if row is None or row.kind == "onchain":
        raise BlockError(404, "request not found")
    if row.kind == "outlook":
        raise BlockError(409, "This e-mail from Outlook is not tied to a request yet: mark the letter it carried as "
                              "sent first.")
    reply = None
    if reply_id is not None:
        reply = next((r for r in row.replies if r.corr.id == reply_id), None)
        if reply is None:
            raise BlockError(404, "that reply does not belong to this request")
    elif row.deciding is not None:
        reply = row.deciding
    if status in READ_MYSELF_STATUSES and risky_reply(row, reply) is not None and not read_myself:
        raise BlockError(400, READ_MYSELF_TEXT)
    try:
        amt = desk.parse_amount(amount)
    except desk.DeskError as exc:
        raise BlockError(400, str(exc)) from None
    asset = (asset or "").strip().upper()[:16] or None
    # the amount of a hold / freeze is the person's own entry: never taken from the reply or an on-chain reading
    if amt is None and status in AMOUNT_REQUIRED:
        raise BlockError(400, AMOUNT_REQUIRED_TEXT)
    if amt is not None and status not in (rules.FROZEN, rules.HOLD_PLACED, rules.FUNDS_RETURNED, rules.ACKNOWLEDGED):
        raise BlockError(400, "an amount only applies to hold placed / frozen / funds returned / acknowledged")
    if reply is None and not (apply and row.order is not None):
        raise BlockError(409, "There is no reply to confirm yet; a case admin can record the status on the stop order.")
    user = access.user
    mapped = APPLY_MAP.get(status) if row.order is not None else None
    applied = False
    order_status = None
    if apply and mapped is not None:
        order = row.order
        if mapped == desk.RELEASED and desk.order_state(order) != "frozen":
            raise BlockError(409, "Funds returned can be applied only to a stop order recorded as frozen: record the "
                                  "hold first (Frozen, with the amount that was held), then confirm the return.")
        ref = (reply.ticket if reply is not None else None) or None
        evidence = [reply.corr.evidence_item_id] if reply is not None and reply.corr.evidence_item_id else None
        text = f"Confirmed on the Block status page from reply #{reply.corr.id}." if reply is not None else \
            "Confirmed on the Block status page."
        if note and note.strip():
            text += " " + note.strip()[:500]
        try:
            desk.record_stop_order_status(
                db, case, order, mapped, actor=user,
                amount_held=amt if mapped in ("frozen", desk.RELEASED, "acknowledged") else None, asset=asset,
                external_ref=ref if ref and not order.external_ref else None, note=text,
                authority_key=row.authority.key, evidence_ids=evidence)
        except desk.DeskError as exc:
            db.rollback()
            raise BlockError(409, str(exc)) from None
        applied, order_status = True, mapped
    data = {"status": status, "amount": str(amt) if amt is not None else None, "asset": asset, "by": user.id,
            "role": access.role.value, "at": _now().isoformat(timespec="seconds"), "applied": applied,
            "applied_status": order_status, "source": "human"}
    if reply is not None:
        _save(db, case, reply.corr, "human", data, stop_order_id=row.order.id if row.order else None,
              entity_id=row.authority.entity.id if row.authority.entity else None, confirmed_by=user.id,
              applied=applied)
        db.commit()
    proposal = mapped is not None and not applied
    timeline_id = None
    if not applied:  # an applied status logs its own timeline entry (the desk)
        label = LABELS.get(status, status)
        amount_txt = f" ({fmt_amount(amt, asset)} {asset or ''})".replace(" )", ")") if amt is not None else ""
        verb = "proposed" if proposal else "confirmed"
        subject = f"Block status {verb}: {label}{amount_txt}" + (f" (reply #{reply.corr.id})" if reply else "") \
            + (" — a case admin applies it to the stop order" if proposal else "")
        entry = desk.log_entry(db, case, row.authority, actor=user, direction="note", channel="other", kind="other",
                               subject=subject, body=(note or "").strip()[:2000] or None, body_format="text",
                               stop_order=row.order, in_reply_to=reply.corr if reply else None,
                               classification="R2")
        entry.meta = {**(entry.meta or {}), "source": "block_status", "status": status, "request": key,
                      "proposal": proposal}
        db.commit()
        timeline_id = entry.id
    # notify with the confirmed reading
    row.status, row.amount, row.asset, row.source = status, (str(amt) if amt is not None else None), asset, "human"
    _emit(db, case, row, confirmed=True, applied=applied, proposal=proposal)
    facts = dict(case.facts or {})
    snap = dict(facts.get(SNAPSHOT_KEY) or {})
    snap[key] = status
    facts[SNAPSHOT_KEY] = snap
    case.facts = facts
    db.commit()
    msg = ("Applied to the stop order." if applied else
           "Proposed: a case admin can apply it to the stop order." if proposal else "Status confirmed.")
    return ConfirmResult(row_key=key, status=status, applied=applied, proposal=proposal,
                         stop_order_status=order_status, timeline_id=timeline_id, message=msg)
