"""Freeze & stop-order board: one row per target (a provider, issuer, swap service, casino or host the trace or a
request names) with where it stands and the ONE next step, for the Authorities tab ("Freeze & stop-order actions").

    board = build(db, case, access)              # Board: targets, groups (Act now first); no writes, no network
    names, skipped = generator_plan(board)       # what the generator ("Draft freeze requests") drafts / skips
    t = target_for(db, case, access, a)          # one counterparty's row from its own rows only (cheap)
    groups = order_groups(case.stop_orders)      # the Stop orders table: superseded drafts folded into their successor

**One open request per provider.** Whether a letter or a stop order to a provider may be created at all is the request
gate's (app.domain.request_gate): every generator and page goes through it, and the board's buttons follow its
decisions (`_gate_board`: a row the generator would draft for gets a stop order only when the gate allows one, else
the open draft, the follow-up or the LE brief; a button linking a letter follows the gate). The gate reads its
state from `target_for`'s rows.

**One source of truth for a provider's next step.** `provider_target` is THE per-provider row derivation: the row from
its block rows and its Recovery plan move (`_target`; the move's reading of the request's next action, rp._row_move,
is what the row follows), then the request gate over the provider's state (`_gate_target`). The board's row and the
Recovery plan's move for that provider (rp.build, `_provider_steps`: its primary action, href, kind and whether it is
actionable) both come from it; the plan keeps only its value, score, urgency and evidence. A pointless draft
(request_gate.State.pointless) is never a button anywhere, and is never e-mailed (compose, Send and the stop order's
e-mail route refuse it, as they refuse a duplicate draft: `letter_flag`, `order_flag`, `draft_flags`); "Redraft from trace #N" only where the gate lets a stop order replace that draft (never one whose
e-mail is prepared or may be out, nor a pointless one).

**Read-only over the case's state.** The board reads the latest trace's freeze candidates (app.tracing.freeze), the
counterparties (app.domain.correspondence) and the block requests (app.blocks.status.case_blocks: status, ticket,
reply clock, path step, next action) once, or takes them from the caller (the Authorities tab passes its run,
candidates and counterparties; its Block status column reuses `Board.rows`). The Recovery plan (app.blocks.recovery
.build over those same rows: the move per target, its value and score) still re-reads the run, candidates,
counterparties and wallets itself (it takes only `rows=`). Then the on-chain freeze readings (app.freeze.service
.wallet_rows: the latest good reading per wallet and contract) and the prepared e-mails waiting for Send
(app.domain.mail_send.awaiting_send). Nothing here drafts, sends or stores anything; `discard` (a route's) writes.
A target whose only requests are unsent drafts is still untouched for the board's Recovery plan (its move keeps the
LE route). `target_for` builds one target from that counterparty's rows alone (no plan, no readings): the status,
skip and duplicates a page about it needs, at a cost that does not grow with the case's targets.

**Status of a target** (`STATUSES`) comes from its deciding request (the Recovery plan's move picks the most actionable
one; a duplicate draft never decides, and the Status column links the deciding request, never a duplicate): not
contacted, draft ready, prepared e-mail, sent — awaiting reply, sent — LE hand-off due, overdue, acknowledged (ticket),
info requested, redirected / bounced, reply to read, reply to confirm, LE only / court order, LE / court route in
progress, held, frozen, declined, released, not applicable (nothing to freeze, nobody asked). A positive outcome counts only once a person confirmed it
(app.blocks.status); an issuer blacklist read on-chain is "frozen" with "Confirm the freeze" while a request still awaits
that confirmation, and on an issuer nobody asked yet it is frozen but not claimed: the step is the case's notice (an
LE-only issuer: its LE route first, the notice second, also once the notice is drafted: "notice #N drafted, not yet
sent"; the Recovery plan has no move for it, so the LE route is the one its untouched move would take).

**Freeze and stop orders first.** An issuer whose playbook acts on LE process only (Circle, Tether) leads with the LE
route (a case agent, the LE cover letter or brief) and offers the notice (it flags the wallets) as the second button.
One rule (`_le_first`, after every state's own branch) keeps it so whatever the notice's state — not contacted,
drafted, prepared, sent, overdue, acknowledged, answered LE only, frozen on-chain but unclaimed: the LE step is the
primary step; the notice's own actions ("Open & send notice", "Chase"), the pack and the counsel pack are extras. The
LE step follows the LE letter's own state (the newest LE cover letter / brief to that LE contact, case-wide or about
this target; for a cover letter, else the newest case-wide one to any LE contact of the case): none yet, the route's
start; drafted, "Send LE cover letter #N"; sent, "LE cover letter #N sent <date> to
<LE>: follow up with the officer" (the button only once the officer's reply is nearly due, "Chase the officer" once it
is overdue; with the notice out: the LE / court route in progress). An LE letter to a contact
with no officer or e-mail on file is "Add the officer's contact", with the same letter to the reachable LE as the
second button. The same LE-letter rule holds once a person confirmed the freeze / hold of such an issuer
(`_le_secured`): the row stays frozen / held, in its group. The Recovery plan the board (and the pack route) builds
leaves out the duplicate drafts (`without_duplicates`): a target's move, score and LE / counsel brief packs stay the
sent request's. A target with funds
traced whose only request asked for records (an information request) still gets "Draft freeze request". A
temporary hold or a freeze with a lapse clock whose next step is LE's is Act now from the day it is confirmed ("LE must
act by …"), never parked under Secured. A follow-up (a status request linked to the request) is offered only when the
reply is nearly due; an overdue one is "Chase".

**Wallet owners** (app.attribution, through the Recovery plan): each row names who owns its move's wallets (owner,
kind, confidence). The plan's owner moves ("Ask <exchange> to freeze the account behind <deposit>", the address
prefilled; an LE brief for a service acting on LE requests only) are the step of a service nobody asked yet — a row of
its own when it is no counterparty of the case yet (Aegis has no form to add one by name: the step says so, and the
row ranks below the Act now rows that have a button) — and of a contacted one whose own step is only the reply it
waits for, or whose own move the owner move outranks (Act now, the owner move's value and basis); else the first
extra (`_owner_targets`); an uncontacted service whose identified deposit outweighs its own traced value leads with
the owner letter (its value), and every generator's stop order cites that deposit too (the tab's and the API's:
`owner_addresses`; the authority page's and the assistant's: rp.owner_deposits). The owner moves follow the request
gate (their `cites`): a service with an open draft that does not cite the wallet gets "Add <wallet> to draft #N" (one
POST: the address into that draft, never a second letter), then "Open & send draft"; a draft or a sent request already
citing it leaves the row to that request (its status and next step); an LE-only / declined answer keeps the row's LE
brief, naming the wallet (a declined row with no step of its own gets it too), and a draft to that provider (a
follow-up or owner letter drafted before the answer, a first-contact draft while its playbook gates us) is flagged
pointless (`Target.pointless`: a case admin discards it), never its step; so is a draft follow-up made before the
provider's latest reply to the request it follows (request_gate `stale`: "drafted before their reply of …" — the
reply's own step, the answer to their questions, a release request, a new deposit's follow-up, is the row's). A swap
order's records at a service nobody asked yet fold into its stop order (it cites the address and asks for the order
records: `_folds`, `owner_addresses`), and a records-only draft to a provider holding funds nobody asked to freeze
leads with the stop order replacing it (request_gate.freeze_over_records): the freeze ask is never behind a records
letter. A draft whose e-mail may be out (sending,
unknown, an open Outlook checklist) is opened, never added to. A sent owner letter is a freeze request
(`_asks_freeze`: a deposit's `meta.freeze`, a hot wallet's `meta.asks_freeze`): the target is contacted, the
generators skip it. The identified wallets are always named on the row. A person's free-text owner name is masked below
view_restricted.

**Groups**, in order: Act now (an uncontacted target with money, a draft ready, a prepared e-mail, an overdue reply,
an LE hand-off due, their questions to answer, a reply to read / confirm, a hold LE must turn into an order), ranked by
the Recovery plan score (value × urgency × likelihood ÷ effort); Frozen — confirm or claim it (an issuer blacklist read
on-chain that a person confirms, or that the case's notice ties to this victim); Waiting on them (money targets, then
the records / takedown requests in a collapsed sub-list); Secured (frozen / held, confirmed, nothing urgent left for
us); LE / court route in progress; Nothing to do (no funds, declined, closed).

**Duplicates.** The request gate creates none; a case can still hold one from before it: a generated stop-order draft
for a target that already has a sent freeze request (a stop order or an owner letter: an outgoing letter asking to
freeze a deposit address; a records-only information request asks for no freeze) is flagged — on the board, in the
Stop orders table and on the stop-order page (no Prepare e-mail, no "sent" there; a sent request marked superseded
afterwards still counts as the one it repeats):
"Draft #N duplicates request #M (already answered: LE only)", with the prepared
e-mail that carries it, if any; a case admin discards it (POST /cases/{id}/stop-orders/{oid}/discard: only an order the
board flags; superseded, its prepared e-mails cancelled, its draft letter marked discarded, the order's status history
and the audit log record it). The generators (the tab's button, POST /api/cases/{id}/stop-orders, the assistant's
/stop-orders draft) never draft for a contacted target (a sent stop order marked superseded afterwards still counts):
the request gate refuses it (a follow-up is a status request linked to the earlier request, an LE-only target gets the
LE brief) and the flash names why (`gate_skip`). The bulk button never replaces a draft; one from an earlier trace gets
its row's own "Redraft from trace #N" (`redraft_keys`: the gate's `replace`); the authority page's template says it
replaces draft #N (`replace_offer`) and its POST must confirm that. Without a board (a source failed) the generators
draft nothing, the authority page's provider letters are closed (its POST a 503) and the assistant says so.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from urllib.parse import parse_qs, urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.blocks import classify_rules as rules
from app.blocks import path as pathmod
from app.blocks import recovery as rp
from app.blocks import status as bs
from app.db.models import (
    CorrespondenceDirection,
    CorrespondenceKind,
    CorrespondenceStatus,
    StopOrder,
    StopOrderOrigin,
    StopOrderStatus,
)
from app.domain import correspondence as desk

log = logging.getLogger(__name__)

NOT_CONTACTED, DRAFT_READY, PREPARED = "not_contacted", "draft_ready", "prepared"
AWAITING, OVERDUE, ACKNOWLEDGED, INFO_REQUESTED = "awaiting", "overdue", "acknowledged", "info_requested"
HANDOFF = "handoff"
RESEND, REVIEW, TO_CONFIRM = "resend", "review", "to_confirm"
LE_ONLY, LE_ROUTE = "le_only", "le_route"
HELD, FROZEN, DECLINED, RELEASED, CLOSED = "held", "frozen", "declined", "released", "closed"
NOT_APPLICABLE = "not_applicable"
STATUSES = {  # status -> (label, tone: blocks.css bk-<tone>)
    NOT_CONTACTED: ("Not contacted", "amber"), DRAFT_READY: ("Draft ready", "amber"),
    PREPARED: ("Prepared e-mail — awaiting Send", "amber"), AWAITING: ("Sent — awaiting reply", "blue"),
    HANDOFF: ("Sent — LE hand-off due", "purple"),
    OVERDUE: ("Reply overdue", "red"), ACKNOWLEDGED: ("Acknowledged", "blue"),
    INFO_REQUESTED: ("Info requested", "amber"), RESEND: ("Redirected — resend", "amber"),
    REVIEW: ("Reply to read", "amber"), TO_CONFIRM: ("Reply to confirm", "amber"),
    LE_ONLY: ("LE only / court order", "purple"), LE_ROUTE: ("LE / court route in progress", "purple"),
    HELD: ("Held", "green"), FROZEN: ("Frozen", "green"), DECLINED: ("Declined", "red"),
    RELEASED: ("Released / returned", "gold"), CLOSED: ("Closed", "neutral"),
    NOT_APPLICABLE: ("Not applicable", "neutral"),
}
ACT, CLAIM, WAITING, SECURED, LE_GROUP, NOTHING = "act", "claim", "waiting", "secured", "le", "nothing"
GROUPS = (
    (ACT, "Act now", ("a target with money nobody has asked yet, a draft to send, a reply that is late or waits "
                      "for us, an LE hand-off, a hold LE must turn into an order before it lapses")),
    (CLAIM, "Frozen — confirm or claim it", ("the issuer froze the wallets on-chain: a person confirms the freeze, "
                                             "or the case's notice ties it to this victim")),
    (WAITING, "Waiting on them", "the request is out; nothing to do before the reply is due"),
    (SECURED, "Secured", ("frozen or held, confirmed by a person; nothing urgent left for us (any LE follow-up is "
                          "on the row)")),
    (LE_GROUP, "LE / court route in progress", "LE is briefed or the order is under way: follow up with LE"),
    (NOTHING, "Nothing to do", "no funds traced here, declined, released or closed"),
)
HOLD_SOON = timedelta(days=3)  # a confirmed hold lapsing within this window (or lapsed): "Brief LE before it lapses"
FOLLOW_UP_SOON = timedelta(days=2)  # a follow-up is offered once the reply is due within this window
# the letters a duplicate draft repeats, and that close a target with traced funds to a new freeze request: a freeze /
# preservation ask (a records-only information request asks for no freeze; the freeze request is still to send). An
# outgoing letter asking to freeze a deposit address (an owner letter: `meta["freeze"]`) is one too: `_asks_freeze`
FIRST_CONTACT = frozenset({"stop_order"})
# a target with funds whose only request asked for records: the freeze request is the step (or an extra, when the
# reply waits for something of ours first)
FREEZE_OPEN = frozenset({AWAITING, ACKNOWLEDGED, OVERDUE, HANDOFF, INFO_REQUESTED, RESEND, REVIEW})
FREEZE_FIRST = frozenset({AWAITING, ACKNOWLEDGED, OVERDUE})
LE_STEPS = frozenset({"le_route_open", "le_filed", "binding_instrument", "cross_border"})
LE_KINDS = frozenset({"le", "cross_border"})
HELD_BS = frozenset({rules.HOLD_PLACED, rules.FROZEN})
SHORT_ANSWER = {rules.LE_PROCESS_REQUIRED: "LE only", rules.DECLINED: "declined",
                rules.DECLINED_NO_ASSETS: "declined (no account / assets)", rules.FROZEN: "frozen",
                rules.HOLD_PLACED: "held", rules.FUNDS_RETURNED: "funds returned", rules.ACKNOWLEDGED: "acknowledged",
                rules.INFO_REQUESTED: "they asked for more", rules.REDIRECTED: "redirected"}
# why the generator ("Draft freeze requests") left a target out (the flash message; {ref}: the request number);
# "sent" gets the row's own next step appended (skip_text)
SKIP_TEXT = {
    "sent": "already contacted (request {ref})",
    "prepared": "a prepared e-mail for {ref} waits for a case admin to press Send",
    "le_only": "answered LE only / court order (request {ref}): brief LE instead of writing again",
    "le_route": "the LE / court route is open (request {ref})",
    "declined": "declined (request {ref})",
    "released": "funds returned (request {ref})",
    "closed": "closed (request {ref})",
    "frozen": "already frozen",
    "held": "the funds are held (request {ref})",
    "gated": "acts on LE requests only: brief LE instead",
    "refused": "the letter generator drafted nothing for it (its playbook or the trace gives it no request): see "
               "its row",
    "draft": "draft {ref} from this trace is ready to send",
    "draft_old": "draft {ref} from an earlier trace is ready to send (or redraft it from this trace on its row)",
    "no_lever": "nothing to request (no funds traced here, or no letter applies)",
    "unknown": "not a freeze candidate of the latest trace",
}
SKIP_CODE = {LE_ONLY: "le_only", LE_ROUTE: "le_route", DECLINED: "declined", FROZEN: "frozen", HELD: "held",
             RELEASED: "released", CLOSED: "closed", PREPARED: "prepared"}
COURT = frozenset({"court_order", "us_or_fr_court_order", "freezing_order", "seizure_warrant", "seizure_order"})
REF_RE = re.compile(r"[oc]\d{1,12}")
_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")  # sentence ends (never a colon: "Fastest: get …")
_DRAFT_HREF = re.compile(r"/authorities/correspondence/(\d{1,12})")
# an LE step's sentence that blocks it (a brief still a draft, no officer on file) leads; else the first instruction
_BLOCKER = re.compile(r"is still a draft|has no named officer or e-mail on file|Add the case's LE contact")
_NO_OFFICER = re.compile(r"has no named officer or e-mail on file: add one to the LE contact, or brief (.+?) "
                         r"\(reachable\) instead")
_IMPERATIVE = re.compile(r"(?:Fastest: )?(?:brief|get|send|add|ask|answer|chase|instruct|start|file)\b",
                         re.IGNORECASE)
HANDOFF_TEXT = " acts on LE process only"  # the Recovery plan's untouched move for an issuer whose playbook hands off


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _aware(v: datetime | None) -> datetime | None:
    return v if v is None or v.tzinfo else v.replace(tzinfo=UTC)


def _key(chain: str | None, address: str | None) -> tuple[str, str]:
    a = (address or "").strip()
    return (chain or ""), (a if chain == "tron" else a.lower())


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "x"


def req_no(r) -> str:
    """'#12' (a stop order) / 'letter #5' (a letter not tied to one): how a request is named on the board."""
    if r.order is not None:
        return f"#{r.order.id}"
    return f"letter #{r.letter.id}" if r.letter is not None else r.key


def ref_text(ref: str | None) -> str:
    """'o12' -> '#12', 'c5' -> 'letter #5' (a validated block-status key from the flash query)."""
    if not ref or not REF_RE.fullmatch(ref):
        return "—"
    return f"#{ref[1:]}" if ref[0] == "o" else f"letter #{ref[1:]}"


def _item_url(cid: int, r) -> str:
    if r.order is not None:
        return f"/cases/{cid}/stop-orders/{r.order.id}"
    if r.letter is not None:
        return f"/cases/{cid}/authorities/correspondence/{r.letter.id}"
    return f"/cases/{cid}/authorities/{r.authority.key}"


# --------------------------------------------------------------------------- the board
@dataclass
class Step:
    """The one next step: a button (`href`: a link; `post`: a form posting `fields`) or, without a label, a line of
    text only (waiting, nothing to do)."""

    kind: str
    label: str = ""
    text: str = ""
    href: str | None = None
    post: str | None = None
    fields: dict = field(default_factory=dict)
    perm: str = "draft_letter"
    alts: list = field(default_factory=list)  # the row's secondary buttons this step brings (the reachable LE)
    le: str | None = None  # an LE step blocked on a contact with no officer on file: that LE contact's key

    @property
    def lead(self) -> str:
        """The text's first sentence (shown); `more`: the rest (behind a toggle)."""
        return _SENTENCE.split(self.text.strip(), maxsplit=1)[0] if self.text else ""

    @property
    def more(self) -> str:
        parts = _SENTENCE.split(self.text.strip(), maxsplit=1) if self.text else []
        return parts[1] if len(parts) > 1 else ""


@dataclass
class Target:
    key: str  # the authority key ("entity-5"), or "cand-<slug>" for a candidate with no entity row
    name: str
    category: str
    authority: Any = None
    candidate: Any = None  # the trace's FreezeCandidate, or None
    kind: str | None = None  # freeze | preservation | issuer_blacklist (the candidate's)
    jurisdiction: str | None = None
    status: str = NOT_CONTACTED
    detail: str = ""  # the status's detail: the block status text, a ticket, the amount held
    group: str = NOTHING
    step: Step = field(default_factory=lambda: Step("none"))
    extra: list[Step] = field(default_factory=list)  # secondary links (the pack, a follow-up)
    deadline: datetime | None = None
    deadline_label: str = ""
    traced_usd: float | None = None
    onchain: dict | None = None  # {usd, frozen_usd, checked_at, wallets, unread}
    held: str | None = None  # "12,000.00 USDT held (confirmed)"
    value: float | None = None
    basis: str = ""
    score: float = 0.0
    requests: list[dict] = field(default_factory=list)  # newest first: {key, no, title, status, tone, href, at, draft,
    #                                                         duplicate}
    duplicates: list[dict] = field(default_factory=list)  # {order_id, no, of, of_key, answer, prepared, text}
    # drafts to a provider that answered LE only / declined, or whose playbook gates us (request_gate.State.pointless):
    # {key, kind (order | letter), id, no, text, prepared, busy, post (the discard route)}
    pointless: list[dict] = field(default_factory=list)
    ticket: str | None = None
    primary: Any = None  # the deciding bs.BlockRow
    move: Any = None  # the Recovery plan's rp.Move
    skip: tuple[str, str | None] | None = None  # (SKIP_TEXT code, request key): the generator leaves it out
    draftable: bool = False  # the generator drafts it
    notice_only: bool = False  # an issuer that acts on LE process only: the generator's letter is a notice
    sent_ref: str | None = None  # the newest sent request's key (a new stop order would repeat it)
    freeze_open: bool = False  # funds traced, a records-only request out, no freeze asked yet
    le_letter: dict | None = None  # the LE letter the LE step stands on: {id, noun, sent, at, due_at, le, le_key}
    # who owns the move's wallets (app.attribution, the Recovery plan's "Owner" line): [{short, owner, kind,
    # kind_label, confidence, source, known, text, private}]
    owners: list[dict] = field(default_factory=list)
    owner_moves: list = field(default_factory=list)  # the plan's owner moves ("owner:…") this row carries
    owner_led: bool = False  # a contacted service whose step is the plan's owner move (its value / basis are the move's)
    rows: list = field(default_factory=list, repr=False)  # its block rows (the request gate's state: request_gate)
    prepared: dict = field(default_factory=dict, repr=False)  # the prepared e-mails (_prepared)
    board: Any = field(default=None, repr=False, compare=False)  # the board it belongs to (its LE contacts)

    @property
    def status_label(self) -> str:
        return STATUSES[self.status][0]

    @property
    def tone(self) -> str:
        return STATUSES[self.status][1]

    @property
    def deciding(self) -> dict | None:
        """The request the row's status comes from (the Status column's link); else the newest one that is not a
        duplicate draft. A duplicate draft is only ever listed in its own warning."""
        live = [r for r in self.requests if not r["duplicate"]]
        key = self.primary.key if self.primary is not None else None
        return next((r for r in live if r["key"] == key), live[0] if live else None)

    @property
    def earlier(self) -> list[dict]:
        top = self.deciding
        return [r for r in self.requests if r is not top and not r["duplicate"]]

    @property
    def rationale(self) -> list[str]:
        return list(self.candidate.rationale) if self.candidate is not None else []

    @property
    def identifiers(self) -> list:
        return list(self.candidate.identifiers) if self.candidate is not None else []


@dataclass
class Board:
    case_id: int
    targets: list[Target] = field(default_factory=list)
    run: Any = None
    now: datetime = field(default_factory=_now)
    can_act: bool = False  # buttons at all (investigators and up)
    can_pack: bool = False
    can_discard: bool = False  # case admins
    can_send: bool = False
    rows: list = field(default_factory=list)  # bs.case_blocks (the tab's Block status column reuses them)
    pack_keys: frozenset = frozenset()  # the Recovery plan moves an LE brief pack exists for
    le_keys: dict = field(default_factory=dict)  # LE authority name -> key (a reachable LE the text names)
    le_auths: dict = field(default_factory=dict)  # LE authority key -> desk.Authority (its letters: the LE step)
    le_route: Any = None  # authority -> {route, href} for an issuer acting on LE process only, else None (lazy)
    _le_targets: dict | None = None  # LE key -> app.blocks.path.LETarget (briefable, reachable), read lazily
    # the Recovery plan the board was built from (rp.build, steps=False): its moves that are no provider's row (the
    # re-trace, funds-left, watch and identify moves) are read by the case's To do list (app.domain.todo)
    plan: Any = field(default=None, repr=False, compare=False)

    def le_target(self, key: str | None):
        """The LE contact `key` as a recipient of our letters (app.blocks.path.LETarget: `briefable`, `reachable`: a
        named officer or e-mail on file), or None."""
        if self._le_targets is None:
            from app.domain import directory

            try:
                self._le_targets = {x.authority.key: x for x in pathmod.le_targets(list(self.le_auths.values()),
                                                                                  directory.playbook_for)}
            except Exception as err:  # noqa: BLE001 - no LE playbooks: no reachable LE to offer
                log.warning("freeze board: LE contacts failed for case %s (%s)", self.case_id, type(err).__name__)
                self._le_targets = {}
        return self._le_targets.get(key) if key else None

    @property
    def groups(self) -> list[dict]:
        """[{key, label, hint, targets, main, records}]: Waiting on them lists its money targets in `main` and the
        records / takedown requests (no funds traced) in `records` (a collapsed sub-list); other groups: main only."""
        out = []
        for key, label, hint in GROUPS:
            rows = [t for t in self.targets if t.group == key]
            if rows:
                records = [t for t in rows if not (t.traced_usd or t.value)] if key == WAITING else []
                out.append({"key": key, "label": label, "hint": hint, "targets": rows,
                            "main": [t for t in rows if t not in records], "records": records})
        return out

    @property
    def draftable(self) -> list[Target]:
        return [t for t in self.targets if t.draftable]

    @property
    def generate_label(self) -> tuple[str, bool]:
        """(the generator button's label, primary): freeze requests and notices (an LE-only issuer's letter) counted
        apart; only notices: not the primary button (each row's primary is its LE route)."""
        todo = self.draftable
        notices = sum(1 for t in todo if t.notice_only)
        asks = len(todo) - notices
        if not todo:
            return "Draft freeze requests", False
        if not asks:
            return f"Draft notice{'s' if notices != 1 else ''} to LE-only issuers ({notices})", False
        if not notices:
            return f"Draft freeze request{'s' if asks != 1 else ''} ({asks})", True
        return (f"Draft {asks} freeze request{'s' if asks != 1 else ''} + {notices} notice"
                f"{'s' if notices != 1 else ''}"), True

    def find(self, key: str) -> Target | None:
        return next((t for t in self.targets if t.key == key), None)

    @property
    def duplicates(self) -> int:
        return sum(len(t.duplicates) for t in self.targets)


def build(db: Session, case, access=None, *, run: Any = ..., cands: list | None = None,
          authorities: list | None = None, now: datetime | None = None, awaiting: list | None = None,
          rows: list | None = None) -> Board:
    """The board (module doc). `run` / `cands` / `authorities`: what the caller already has (the Authorities tab:
    services.latest_run, freeze_candidates, desk.case_authorities with them); `awaiting`: the prepared e-mails; `rows`:
    the case's block rows when the caller already has them (bs.case_blocks: the Overview's cards share one pass)."""
    from app import services
    from app.tracing.freeze import freeze_candidates

    now = now or _now()
    if run is ...:
        run = services.latest_run(db, case)
    if cands is None:
        cands = freeze_candidates(db, run) if run is not None else []
    auths = authorities if authorities is not None else desk.case_authorities(db, case, run=run, cands=cands)
    rows = rows if rows is not None else bs.case_blocks(db, case, now=now, authorities=auths)
    # a target whose only requests are unsent drafts is still untouched for the Recovery plan: its move keeps the LE
    # route of an issuer acting on LE process only (the draft is a notice; the LE step stays the row's primary). The
    # plan the pack route builds has the draft's own move: its pack key is the draft's
    contacted = {r.authority.key for r in rows if r.kind == "outlook" or (r.kind != "onchain" and r.status != bs.NOT_SENT)}
    drafts_only = [r for r in rows if r.kind not in ("onchain", "outlook") and r.authority.key not in contacted
                   and not r.authority.is_le and not r.authority.is_adviser]
    # a duplicate draft (one that repeats a freeze request already sent) is never the target's move: the move, its score
    # and its packs stay the sent request's (the pack route builds its plan the same way)
    plan = rp.build(db, case, now=now, rows=without_duplicates([r for r in rows if r not in drafts_only]),
                    gate_rows=rows, steps=False)
    readings = _readings(db, case)
    if awaiting is None:
        awaiting = _awaiting(db, case, access)
    board = Board(case_id=case.id, run=run, now=now, rows=rows,
                  pack_keys=frozenset([*(m.key for m in plan.moves + plan.waiting if m.authority is not None),
                                       *(r.key for r in drafts_only)]),
                  le_keys={a.name: a.key for a in auths if a.is_le}, le_auths={a.key: a for a in auths if a.is_le})
    board.le_route = _le_routes(db, case, auths)
    board.plan = plan
    if access is not None:
        board.can_act = access.can("draft_letter")
        board.can_pack = rp.may(access, "pack")
        board.can_discard = access.can("manage_case")
        board.can_send = access.can("send_email")

    by_auth: dict[str, list] = {}
    for r in rows:
        if r.kind != "outlook":
            by_auth.setdefault(r.authority.key, []).append(r)
    moves = {m.authority.key: m for m in plan.moves + plan.waiting if m.authority is not None and ":" not in m.key}
    prepared = _prepared(case, awaiting)

    seen: dict[str, desk.Authority] = {}
    for a in auths:
        if a.is_le or a.is_adviser or a.virtual or a.key in seen:
            continue
        if a.candidate is not None or a.stop_orders or a.correspondence or a.in_trace:
            seen[a.key] = a
    for r in rows:  # issuers with readings the case has not engaged (case_blocks' on-chain rows)
        if r.kind == "onchain" and r.authority.key not in seen:
            seen[r.authority.key] = r.authority
    cand_by_ent = {c.entity.id: c for c in cands if c.entity is not None}
    for a in seen.values():
        if a.candidate is None and a.entity is not None:
            a.candidate = cand_by_ent.get(a.entity.id)
        st = plan.gate.get(a) if plan.gate is not None else None
        t = provider_target(case.id, a, by_auth.get(a.key, []), moves.get(a.key), readings, prepared, board, now, st)
        board.targets.append(t)
    for c in cands:  # a candidate with no entity row (an issuer missing from the entity table)
        if c.entity is None:
            t = Target(key=f"cand-{_slug(c.entity_name)}", name=c.entity_name, category=c.category, candidate=c,
                       kind=c.kind, traced_usd=float(c.total_taint_usd), value=float(c.total_taint_usd))
            t.basis = f"{rp.money(t.value)} traced (upper bound)"
            t.step = Step("none", text="No counterparty record for it yet: add the entity to write to it.")
            t.group = ACT if t.value else NOTHING
            board.targets.append(t)
    _owner_targets(case.id, board, plan.owner_moves())
    _gate_board(case.id, board, plan.gate)  # the owner steps through the gate too
    if access is not None and not access.can("view_restricted"):  # a person's free-text owner name: restricted
        private = {n for x in (plan.owners or {}).values() for n in x.private_names}
        if private:
            for t in board.targets:
                _mask_names(t, private)
    rank = {g[0]: i for i, g in enumerate(GROUPS)}
    far = now + timedelta(days=3650)
    # Act now / Secured by score (in Act now, a row with a button before one whose step is text only: a service that
    # is no counterparty yet); Waiting: money targets before records / takedown requests with no funds traced
    board.targets.sort(key=lambda t: (rank[t.group], 1 if t.group == ACT and not t.step.label else 0,
                                      -t.score if t.group in (ACT, CLAIM, SECURED) else 0,
                                      1 if t.group == WAITING and not (t.traced_usd or t.value) else 0,
                                      t.deadline or far, -(t.value or 0), t.name.lower()))
    return board


def _prepared(case, awaiting: list) -> dict[tuple[str, int], Any]:
    """("c", letter id) / ("o", stop order id) -> the prepared MailMessage waiting for Send."""
    corr_order = {c.id: c.stop_order_id for c in case.correspondence}
    out: dict[tuple[str, int], Any] = {}
    for mm in awaiting:
        if mm.correspondence_id:
            out.setdefault(("c", mm.correspondence_id), mm)
            if corr_order.get(mm.correspondence_id):
                out.setdefault(("o", corr_order[mm.correspondence_id]), mm)
    return out


OWNER_CATEGORY = {"exchange_deposit": "exchange", "exchange_hot_wallet": "exchange", "casino": "casino",
                  "swap_bridge": "swap_service"}
# a row the plan's owner move leads: nobody asked that service yet (its own row has no request out)
OWNER_LEADS = frozenset({NOT_CONTACTED, NOT_APPLICABLE})


def _owner_targets(cid: int, board: Board, moves: list) -> None:
    """The Recovery plan's owner moves (app.attribution puts a wallet at a service no move of that service covers:
    "Ask <exchange> to freeze the account behind <deposit>", the address prefilled; an LE brief when it takes LE
    requests only) on the board, per service, best score first. A service nobody asked yet: the move is its row's
    step (a row of its own when it is no counterparty of the case yet); its own untouched move keeps the step and the
    owner move is the next button, unless the identified deposit outweighs it (the owner letter leads, with its value;
    the stop order the bulk generator drafts cites the deposit too: `owner_addresses`). A service already contacted:
    the owner letter (it quotes the earlier request) is the row's step when the row's own step is only text (the reply
    it waits for) or the owner move outranks the row's own move — Act now, the move's value and basis, the row's own
    step the next button (or its text after the owner letter's) — else the first extra. The owner moves already passed
    the request gate (app.domain.request_gate, their `cites`): a draft citing the wallet is "Open & send draft" (the
    row's step), an open draft lacking it "Add <wallet> to draft #N" (one POST to the authority page's letters route,
    which adds it), a sent request citing it leaves the row to that request's own status and next step, an LE-only
    answer keeps the row's LE brief (naming the wallet: `about=`). The owner moves' wallets are always named on the row.
    Nothing is drafted here."""
    by: dict[str, list] = {}
    for m in sorted(moves, key=lambda m: -m.score):
        owner = next((o.get("owner") for o in m.owners if o.get("known")), None)
        # a service that is no counterparty yet: its key never spells the name (a person's name may be restricted)
        k = m.authority.key if m.authority is not None else "owner-" + hashlib.sha256(
            (owner or m.key).casefold().encode()).hexdigest()[:12]
        by.setdefault(k, []).append(m)
    for key, every in by.items():
        found = _owners_of(every)
        t = board.find(key)
        # a request already out for the wallet: its own row (status, next step) says what is next; its draft when the
        # row's own step already sends it (the deciding request): that step, with the owner move's value
        same = [m for m in every if m.cites and m.cites["state"] == "draft" and t is not None and t.primary is not None
                and t.primary.key == m.cites["key"] and t.step.kind == "send"]
        # LE only: the row's own LE step already is the brief (it names the wallet too); a request citing the wallet:
        # its own status and next step
        le_own = [m for m in every if m.cites and m.cites["state"] == "le" and t is not None
                  and t.step.kind in LE_KINDS and t.step.label]
        for m in le_own:
            t.step.href = _about_href(t.step.href, m)
        ms = [m for m in every if not (m.cites and m.cites["state"] == "sent") and m not in same and m not in le_own]
        # a swap order's records at a row nobody asked yet whose own step is the freeze request: that stop order cites
        # its address and asks for its records (`owner_addresses`): one letter, the freeze ask first, never behind a
        # records-only letter; the wallet is named on the row, its evidence the next button
        folded = [m for m in ms if t is not None and _folds(cid, t, m)]
        if folded:
            t.owners = _merge_owners(found, t.owners)
            t.owner_moves = every
            have = {x.href for x in t.extra if x.href}
            for m in folded:
                for e in _owner_step(cid, m).alts:
                    if e.href not in have:
                        t.extra.append(e)
                        have.add(e.href)
            _owner_detail(t, found)
            ms = [m for m in ms if m not in folded]
            if not ms:
                _dedupe(t)
                continue
        if t is not None and (same or not ms):
            t.owners = _merge_owners(found, t.owners)
            t.owner_moves = every
            best = (same or every)[0]
            if (best.value or 0) > (t.value or 0):  # the identified deposit's money is what the request is about
                t.value, t.basis = best.value, best.basis
            if same:
                t.owner_led, t.group, t.score = True, ACT, max(t.score, best.score)
            _owner_detail(t, found)
        if not ms:
            continue
        top = ms[0]
        if t is None:
            a = top.authority
            o = top.owners[0] if top.owners else {}
            t = Target(key=key, name=a.name if a is not None else (o.get("owner") or "Unknown service"),
                       category=a.category if a is not None else OWNER_CATEGORY.get(o.get("kind"), "service"),
                       authority=a, jurisdiction=a.jurisdiction if a is not None else None, status=NOT_APPLICABLE)
            board.targets.append(t)
        t.owner_moves = every
        steps = [_owner_step(cid, m) for m in ms]
        untouched = t.status in OWNER_LEADS and t.primary is None
        if untouched and (t.move is None or not t.move.actionable or (top.value or 0) > (t.value or 0)):
            own = t.step if t.move is not None and t.move.actionable and t.step.label else None
            t.status, t.group, t.skip = NOT_CONTACTED, ACT, t.skip if own is not None else None
            if own is None:
                t.move = top
            t.owner_led = own is not None
            t.value, t.basis, t.score = top.value, top.basis, max(t.score, top.score)
            t.owners = _merge_owners(found[:4], t.owners if own is not None else [])
            t.detail = "nobody has asked yet · " + ("identified as the owner of " + ", ".join(
                o["short"] for o in found[:4]) if found else "a wallet owner")
            t.step = steps[0]
            t.extra = [*steps[0].alts, *([own] if own is not None else []), *(s for s in steps[1:] if s.label),
                       *(s for s in t.extra if s is not own)]  # the evidence, its own stop order, other wallets
            if t.authority is None:
                rest = t.step.text.replace(rp.outside_aegis(t.name), "").strip()
                t.step.text = f"{rp.outside_aegis(t.name)} {rest}".strip()
            _dedupe(t)
            continue
        # a request is out (or its own move leads): the newly identified wallets are named on the row first
        t.owners = _merge_owners(found, t.owners)
        lead = steps[0]
        own = t.score
        if t.primary is not None and lead.label and (not t.step.label or top.score > own and t.step.kind != "confirm"
                                                     or lead.kind == "send" and t.step.kind != "send"
                                                     or lead.kind == "add"):
            old = t.step
            t.step = lead
            if not old.label and old.text and t.primary is not None:  # the reply it waits for: after the owner letter
                lead.text = f"{lead.text} Request {req_no(t.primary)}: {old.text[:1].lower()}{old.text[1:]}".strip()
            t.extra = [*lead.alts, *([old] if old.label else []), *(s for s in steps[1:] if s.label),
                       *(s for s in t.extra if s is not old)]
            t.group, t.owner_led = ACT, True
            t.value, t.basis, t.score = top.value, top.basis, max(own, top.score)
            _owner_detail(t, found)
            _dedupe(t)
            continue
        t.extra = [*(s for s in steps if s.label), *t.extra]
        t.score = max(t.score, top.score)
        if t.group == NOTHING and t.status in OWNER_LEADS:
            t.group = ACT
        _dedupe(t)


def _folds(cid: int, t: Target, m) -> bool:
    """A records-only owner move (rp.uncited_records: a swap order's records) that the row's own freeze request covers:
    nobody asked the service yet and the row's step drafts its stop order (the generator cites the address too)."""
    return (rp.uncited_records(m) and not m.cites and t.status in OWNER_LEADS and t.primary is None and t.draftable
            and t.candidate is not None and t.step.post == f"/cases/{cid}/stop-orders" and bool(t.step.label))


def _gate_board(cid: int, board: Board, states) -> None:
    """Every row's buttons pass the request gate (app.domain.request_gate, the plan's per-provider states):
    `_gate_target` per row."""
    if states is None:
        return
    for t in board.targets:
        st = states.get(t.authority) if t.authority is not None else None
        if st is not None:
            _gate_target(cid, t, st)


def _gate_target(cid: int, t: Target, st) -> None:
    """One row's buttons through the request gate over its provider's state `st`: a row the generator would draft for
    gets a stop order only when the gate allows one (else its decision: the open draft, the follow-up, the LE brief, and
    the generator's skip reason); "Redraft from trace #N" only when the gate lets a stop order replace that draft (never
    a held draft — its e-mail prepared or under way — nor a pointless one); a button linking a letter to the provider
    follows the gate (an open draft → send it, a request out → its follow-up, LE only → the LE brief). Idempotent (the
    board runs it again over the owner steps)."""
    from app.domain import request_gate as rg

    gen = f"/cases/{cid}/stop-orders"
    if t.draftable and t.candidate is not None:
        d = rg.decide(st, "stop_order")
        if not d.allowed:
            t.draftable = False
            t.skip = gate_skip(d)
            instead = Step({rg.OPEN_EXISTING: "send", rg.ADD_TO_DRAFT: "send", rg.FOLLOW_UP_ONLY: "follow_up",
                            rg.LE_BRIEF_ONLY: "le"}.get(d.kind, "none"), d.label() if d.href else "",
                           text=d.text, href=d.href)
            if t.step.post == gen and "redraft" not in t.step.fields:
                t.step = instead
            t.extra = [s for s in t.extra if not (s.post == gen and "redraft" not in s.fields)]
    redo = next((s for s in [t.step, *t.extra] if s.kind == "redraft"), None)
    if redo is not None:
        key = t.skip[1] if t.skip is not None and t.skip[0] == "draft_old" else None
        d = rg.decide(st, "stop_order", replace={key} if key else set())
        if key is None or not d.allowed:  # the generator would refuse it (so_skip): never offered
            t.extra = [s for s in t.extra if s is not redo]
            if t.step is redo:
                t.step = Step("none", text=d.text)
            if key is not None:
                t.skip = gate_skip(d) if not d.allowed else ("draft", key)
    held = st.open if st.open is not None and st.open.busy is not None else None
    if held is not None and t.step.kind == "send" and t.step.href == held.href:  # its e-mail may be out
        d = rg.decide(st, "stop_order")
        if d.kind == rg.OPEN_EXISTING and d.request is held:
            t.step = Step("send", d.label(), text=d.text, href=d.href, perm="view")
    fo = rg.freeze_over_records(st)
    # a follow-up drafted before their reply whose e-mail is prepared or under way: it stays the open request (the
    # gate refuses the answer next to it), so its e-mail leads: send it as it is, or cancel it and discard the draft
    late = st.open if st.open is not None and st.open.late and st.open.held else None
    if late is not None and t.step.href != late.held_href:
        d = rg.decide(st, "info_response")
        if d.kind == rg.OPEN_EXISTING and d.request is late:
            old = t.step
            mid = late.prepared or getattr(late.busy, "id", None)
            t.step = Step("send", f"Open e-mail #{mid} (draft {late.no}, drafted before their reply)", text=d.text,
                          href=late.held_href, perm="prepare_email")
            if old.label:
                t.extra.insert(0, old)
    for s in [t.step, *t.extra]:
        if not s.href or (fo is not None and s.href == fo["href"] and s.label == fo["label"]):
            continue  # the stop order replacing the records-only draft (below) is the gate's own offer
        d, alt = rg.gated_link(st, s.href)
        if alt is not None:  # a request already asks about it: its follow-up
            s.label, s.href = (d.label(), alt["follow"]) if alt["kind"] == "wait" else (alt["label"], alt["href"])
    # a records-only draft to a provider holding funds that nobody asked to freeze: the stop order replacing it
    # leads (the freeze ask is never behind a records letter); sending the draft as it is, the next button
    if fo is not None and t.step.kind == "send" and t.step.href == st.open.href:
        old = t.step
        t.step = Step("draft", fo["label"], text=fo["text"], href=fo["href"], perm="draft_letter")
        t.extra = [old, *(x for x in t.extra if x.href != fo["href"])]
        t.freeze_open = True
    _gate_le(cid, t, st)
    _dedupe(t)


def provider_target(cid: int, a, arows: list, move, readings: dict, prepared: dict, board: Board, now: datetime,
                    st=None) -> Target:
    """THE per-provider row: its status, step and buttons from its block rows and its Recovery plan move (`_target`),
    then the request gate over the provider's state `st` (`_gate_target`). The board's row and the Recovery plan's
    move for that provider (rp.build: its primary action, href, kind, whether it is actionable) both come from it; the
    plan keeps only its own value, score, urgency and evidence. The board then lays the owner moves over it
    (`_owner_targets`)."""
    t = _target(cid, a, arows, move, readings, prepared, board, now)
    if st is not None:
        _gate_target(cid, t, st)
    return t


def _gate_le(cid: int, t: Target, st) -> None:
    """A provider that answered LE only / court order or declined, or whose playbook gates our requester: its open
    drafts are pointless (request_gate.State.pointless: flagged, a case admin discards them), never the row's step or
    a button; a row left with no step (a declined answer) gets the gate's LE step (the LE brief naming it)."""
    from app.domain import request_gate as rg

    gone = st.pointless
    if not gone and not st.le_only:
        return
    hrefs = {x for r in gone for x in (r.href, r.mail_href, r.held_href) if x}
    keys = {r.key for r in gone}
    t.pointless = pointless_flags(cid, st)
    d = rg.decide(st, "stop_order")
    le = Step("le", d.label() if d.href else "", text=d.text, href=d.href)
    if d.kind != rg.LE_BRIEF_ONLY:
        return
    # a button of a pointless draft (send it, add the wallet to it) is never offered: the LE step instead
    def drafts_to_it(x: Step) -> bool:  # sends a pointless draft, or adds an address to one
        return x.href in hrefs or x.kind == "add" or (x.post or "").endswith(f"/authorities/{t.key}/letters")

    if drafts_to_it(t.step) or (t.primary is not None and t.primary.key in keys):
        t.step = le if le.label else Step("le", text=d.text)
    t.extra = [x for x in t.extra if not drafts_to_it(x)]
    if not t.step.label and le.label:  # declined: nothing left on the row but the LE brief
        le.text = f"{t.step.text} {le.text}".strip() if t.step.text and t.step.text not in le.text else le.text
        t.step = le


def pointless_flags(cid: int, st) -> list[dict]:
    """The board's flag for each pointless draft of a provider (request_gate.State.pointless): {key, kind (order |
    letter), id, no, text, prepared, busy, post (its discard route), why}."""
    if st is None or not st.pointless:
        return []
    name = st.authority.name
    out = []
    by_key = {x.key: x for x in st.requests}
    for r in st.pointless:
        of = by_key.get(r.follows)
        why = (f"{name} answered {st.le_only} (request {st.sent.no}): only LE acts now" if st.le_only else
               f"{r.stale} on request {of.no if of is not None else r.follows}: answer that reply instead"
               if r.stale else f"{st.gated}: no letter from us to {name}")
        kind, oid = ("order", r.order.id) if r.order is not None else ("letter", r.letter.id)
        text = f"Draft {r.no} is pointless: {why} — discard?"
        if r.prepared is not None:
            text += f" Prepared e-mail #{r.prepared} for it awaits Send: discarding cancels it."
        elif r.busy is not None:
            text += (f" Its e-mail #{r.busy.id} may already be out: settle it first (record it as sent, or cancel / "
                     "retire it), then discard the draft.")
        out.append({"key": r.key, "kind": kind, "id": oid, "no": r.no, "text": text, "prepared": r.prepared,
                    "busy": r.busy.id if r.busy is not None else None, "why": why,
                    "post": (f"/cases/{cid}/stop-orders/{oid}/discard" if kind == "order" else
                             f"/cases/{cid}/authorities/correspondence/{oid}/discard")})
    return out


def duplicate_flags(cid: int, t) -> list[dict]:
    """The board's flag for each duplicate draft of a target (`Target.duplicates`: a legacy generated stop order
    repeating a freeze request already sent), in the shape of `pointless_flags` (`duplicate`: True, `of`: the request
    it repeats). Never e-mailed either (compose and Send refuse it: `letter_flag`)."""
    out = []
    for d in (t.duplicates if t is not None else []):
        oid = d["order_id"]
        out.append({"key": f"o{oid}", "kind": "order", "id": oid, "no": d["no"], "of": d["of"], "of_key": d["of_key"],
                    "text": d["text"], "prepared": d["prepared"], "busy": None, "duplicate": True,
                    "why": f"it duplicates request {d['of']}", "post": f"/cases/{cid}/stop-orders/{oid}/discard"})
    return out


def draft_flags(cid: int, st) -> list[dict]:
    """Every draft of a provider the board says to discard, never to send (request gate state `st`): its pointless
    drafts (`pointless_flags`) and its duplicate drafts (`duplicate_flags` over `st.target`, the board's row)."""
    if st is None:
        return []
    return pointless_flags(cid, st) + duplicate_flags(cid, getattr(st, "target", None))


def _state_now(db: Session, case, authority):
    from app.domain import request_gate as rg

    try:
        return rg.state(db, case, authority)
    except rg.Unavailable:
        return None


def pointless_flag(db: Session, case, authority, key: str) -> dict | None:
    """The board's pointless flag for draft `key` ("o12" / "c5") of that provider, read now (request_gate.state), or
    None (not pointless, or the requests cannot be read: nothing is discarded blind)."""
    return next((f for f in pointless_flags(case.id, _state_now(db, case, authority)) if f["key"] == key), None)


def order_flag(db: Session, case, authority, key: str) -> dict | None:
    """The board's pointless or duplicate flag for draft `key` of that provider, read now (`draft_flags`), or None: a
    draft never e-mailed (the stop order's e-mail route refuses it)."""
    return next((f for f in draft_flags(case.id, _state_now(db, case, authority)) if f["key"] == key), None)


def _letter_keys(db: Session, case, corr, authority=None):
    """(the provider, the keys a flag of this outgoing draft letter may carry: c<id>, and o<id> of its draft stop
    order), or None when it is no draft or not to a provider."""
    from app.domain import request_gate as rg

    if (corr is None or corr.direction != CorrespondenceDirection.OUT or corr.status != CorrespondenceStatus.DRAFT
            or discarded(corr)):
        return None
    order = corr.stop_order
    if authority is None:
        eid = corr.entity_id or (order.entity_id if order is not None else None)
        authority = desk.get_authority(db, case, f"entity-{eid}") if eid else None
    if not rg.is_provider(authority):
        return None
    keys = {f"c{corr.id}"}
    if order is not None and order.status == StopOrderStatus.DRAFT:
        keys.add(f"o{order.id}")
    return authority, keys


def letter_pointless(db: Session, case, corr, authority=None) -> dict | None:
    """The board's pointless flag (`pointless_flag`) for an outgoing draft letter: its own key (c<id>), or its draft
    stop order's (o<id>) when it is that order's letter. None when it is no draft, not to a provider, not pointless,
    or the provider's requests cannot be read."""
    got = _letter_keys(db, case, corr, authority)
    if got is None:
        return None
    return next((f for f in pointless_flags(case.id, _state_now(db, case, got[0])) if f["key"] in got[1]), None)


def letter_duplicate(db: Session, case, corr, authority=None) -> dict | None:
    """The board's duplicate flag (`duplicate_flags`) for an outgoing draft letter: the letter of a duplicate draft
    stop order. None otherwise (or when the provider's requests cannot be read)."""
    got = _letter_keys(db, case, corr, authority)
    if got is None:
        return None
    st = _state_now(db, case, got[0])
    return next((f for f in duplicate_flags(case.id, st.target if st is not None else None) if f["key"] in got[1]),
                None)


def letter_flag(db: Session, case, corr, authority=None) -> dict | None:
    """The board's pointless or duplicate flag for an outgoing draft letter (`letter_pointless`, `letter_duplicate`),
    from one read of the provider's state: such a draft is never e-mailed (compose and Send refuse it)."""
    got = _letter_keys(db, case, corr, authority)
    if got is None:
        return None
    return next((f for f in draft_flags(case.id, _state_now(db, case, got[0])) if f["key"] in got[1]), None)


def pointless_text(flag: dict | None) -> str | None:
    """A person's message refusing to e-mail a pointless or duplicate draft (compose, Send)."""
    if flag is None:
        return None
    if flag.get("duplicate"):
        return (f"Draft {flag['no']} duplicates request {flag['of']}; discard it (a case admin, on its page or the "
                "Authorities tab).")
    return f"Draft {flag['no']} is pointless: {flag['why']}; discard it (a case admin, on its page or the Authorities tab)."


def _owner_detail(t: Target, found: list[dict]) -> None:
    what = "identified as the owner of " + ", ".join(o["short"] for o in found[:3]) if found else ""
    if what and what not in t.detail:
        t.detail = f"{t.detail} · {what}" if t.detail else what


def _dedupe(t: Target) -> None:
    """One button per link: an extra linking the step's own page (the draft the owner move sends) is dropped."""
    seen = {t.step.href} if t.step.href else set()
    out = []
    for s in t.extra:
        if s.href and s.href in seen:
            continue
        if s.href:
            seen.add(s.href)
        out.append(s)
    t.extra = out


def _owners_of(moves: list) -> list[dict]:
    """The owner lines of the owner moves' own wallets (the identified deposit), once each."""
    return _merge_owners([o for m in moves for o in m.owners], [])


def _merge_owners(first: list[dict], rest: list[dict]) -> list[dict]:
    seen: set = set()
    out = []
    for o in [*first, *rest]:
        k = o.get("short") or o.get("text")
        if k not in seen:
            seen.add(k)
            out.append(o)
    return out


def _about_href(href: str | None, m) -> str | None:
    """An LE brief / cover-letter link naming the owner move's wallet too (`about=`: the brief names the address)."""
    from app.domain import request_gate as rg

    return rg._with_about(href, [f"{c}:{a}" for c, a in m.wallets[:1]]) if href else href


def _owner_step(cid: int, m) -> Step:
    """One owner move as a step: its letter (the freeze request to the service, the address prefilled; the LE cover
    letter when the service acts on LE requests only), or text only when the service is no counterparty yet (the
    move's link is the tab itself); `alts`: "Who owns it (evidence)" (the row's next button)."""
    primary = next((x for x in m.actions if x.get("primary") and x.get("href")), None)
    href = primary["href"] if primary is not None else m.href
    text = f"{m.title}. {m.text}".strip()
    evidence = [Step("evidence", x["label"], href=x["href"], perm=x.get("perm") or "view") for x in m.actions
                if not x.get("primary") and x.get("href") and str(x.get("label")).startswith("Who owns it")]
    if m.cites:  # the request gate points at a request of the service (app.domain.request_gate): never a second letter
        state = m.cites["state"]
        if state == "sent":  # a request already cites the wallet: wait on it (its own next step chases it)
            return Step("owner", "", text=text, alts=evidence)
        if state == "add":  # its open draft lacks the wallet: add it there (one POST), then send that draft
            from app.domain import request_gate as rg

            p = rg.parse_link(m.cites["href"]) or {}
            q = parse_qs(urlparse(m.cites["href"]).query)
            fields = {"template": p.get("template") or "info_request", "about": ",".join(p.get("about") or []),
                      "ref": p.get("ref") or "", "freeze_address": (q.get("freeze") or [""])[0],
                      "extra_note": (q.get("note") or [""])[0]}
            return Step("add", m.cites["label"], text=text, post=f"/cases/{cid}/authorities/{p.get('key')}/letters",
                        fields={k: v for k, v in fields.items() if v}, perm="draft_letter", alts=evidence)
        if state == "le":
            return Step("le", m.cites["label"], text=text, href=m.cites["href"], perm="draft_letter", alts=evidence)
        return Step("send", m.cites["label"] or "Open & send draft", text=text, href=m.cites["href"],
                    perm="prepare_email" if "/mail/" in (m.cites["href"] or "") else "draft_letter", alts=evidence)
    if not href or href.startswith(f"/cases/{cid}?tab="):
        return Step("owner", "", text=text, alts=evidence)
    label = (primary or {}).get("label") or ("Open the LE cover letter" if m.kind == "le" else "Open the letter")
    return Step("le" if m.kind == "le" else "draft", label, text=text, href=href,
                perm=(primary or {}).get("perm") or "draft_letter", alts=evidence)


def _mask_names(t: Target, names: set) -> None:
    """A person's free-text owner names (possibly a private individual) masked on the row (view_restricted only)."""
    from app.attribution import service as attr

    def m(v):
        return attr.mask_names(v, names) if v else v
    if t.authority is None:
        t.name = m(t.name)
    t.basis, t.detail = m(t.basis), m(t.detail)
    for s in [t.step, *t.step.alts, *t.extra]:
        s.label, s.text = m(s.label), m(s.text)
    t.owners = [{**o, "owner": m(o.get("owner")), "text": m(o.get("text")), "private": []} for o in t.owners]


def step_board(db: Session, case, *, run, rows: list, auths: list, now: datetime) -> Board:
    """The board context `provider_target` reads (the case's LE contacts and their routes, the trace run, the block
    rows), without the board's own targets or a member's access: the Recovery plan's provider moves take their step
    from it (rp.build, `_provider_steps`)."""
    board = Board(case_id=case.id, run=run, now=now, rows=rows, can_act=True, can_send=True,
                  le_keys={a.name: a.key for a in auths if a.is_le}, le_auths={a.key: a for a in auths if a.is_le})
    board.le_route = _le_routes(db, case, auths)
    return board


def _le_routes(db: Session, case, auths: list):
    """authority -> {route, href, le} for an issuer whose playbook acts on LE process only (the test the Recovery
    plan's untouched move uses: our path expects "LE process required" and never a hold), else None. For a target the
    plan has no move for (an issuer that froze the wallets on-chain on its own): the LE route the untouched move would
    take, started by a case agent's complaint or the LE cover letter. Read lazily, once per authority."""
    cache: dict[str, dict | None] = {}
    ctx: dict[str, Any] = {}

    def route_for(a) -> dict | None:
        if a is None:
            return None
        if a.key not in cache:
            cache[a.key] = None
            try:
                cache[a.key] = _le_route(db, case, a, auths, ctx)
            except Exception as err:  # noqa: BLE001 - no LE route: the row keeps the notice
                log.warning("freeze board: LE route failed for %s on case %s (%s)", a.key, case.id,
                            type(err).__name__)
        return cache[a.key]

    return route_for


def _le_route(db: Session, case, a, auths: list, ctx: dict) -> dict | None:
    from app.domain import directory
    from app.domain import playbook as pbm
    from app.domain import sender as sender_mod

    pb, org_key = bs._playbook(a)
    if pb is None:
        return None
    if "requester" not in ctx:
        ctx["requester"] = sender_mod.requester_kind(db, case)
        ctx["targets"] = pathmod.le_targets([x for x in auths if x.is_le], directory.playbook_for)
    requester, targets = ctx["requester"], ctx["targets"]
    our = pathmod.our_path(pb, requester)
    exp = set(getattr(our, "expected_replies", ()) or ()) | set(getattr(our, "outcomes", ()) or ())
    if our is None or rules.LE_PROCESS_REQUIRED not in exp or exp & rp.HELD:
        return None
    st = pathmod.PathState(path=our, requester=requester, victim_jur=pbm.jurisdiction_code(case.victim_jurisdiction))
    chains = {i.chain for i in (a.candidate.identifiers if a.candidate is not None else []) if i.chain}
    st.target = pathmod._target(pb, our, None, chains)
    if st.target is not None:
        ti = st.target.instrument
        st.instrument = {"type": ti.type, "label": pathmod._label(ti.type),
                         "issuer_jurisdictions": list(ti.issuer_jurisdictions), "source": "playbook"}
    route, le = pathmod._route(pb, st, targets, org_key)
    if route is None and le is not None:
        route = {"kind": None, "le": le.name, "options": []}
    if le is not None and not le.briefable:  # only a complaint intake (IC3) on the case: it files nothing
        le = None
    actions = ([{"label": f"LE cover letter to {le.name}",
                 "href": f"/cases/{case.id}/authorities/{le.authority.key}?template=le_cover#generate"}]
               if le is not None else [])
    href = _handoff_href(case.id, type("_Route", (), {"route": route, "actions": actions})())
    return {"route": route, "href": href, "le": le.name if le is not None else None}


def target_for(db: Session, case, access, authority, *, now: datetime | None = None) -> Target | None:
    """One target from that authority's own block rows and the case's LE contacts only (no Recovery plan, no
    on-chain readings): its status, skip, duplicates and next step as the board gives them, for a page about that
    one counterparty (the request gate's state, app.domain.request_gate.state; the stop-order page's duplicate
    warning, the discard route). The LE contacts give its block rows the board's LE path and route (the step a skip text
    names is the row's own button) and its LE step the LE letters on file. None for LE / advisers / virtual rows."""
    from app import services

    if authority is None or authority.is_le or authority.is_adviser or authority.virtual:
        return None
    now = now or _now()
    # the case's LE contacts (engaged counterparties only, no trace read: the cost does not grow with the targets)
    les = [x for x in desk.case_authorities(db, case, include_prospects=False) if x.is_le]
    auths = [authority, *les]
    rows = bs.case_blocks(db, case, now=now, authorities=auths)
    board = Board(case_id=case.id, run=services.latest_run(db, case), now=now, rows=rows,
                  le_keys={x.name: x.key for x in les}, le_auths={x.key: x for x in les})
    board.le_route = _le_routes(db, case, auths)
    arows = [r for r in rows if r.kind != "outlook" and r.authority.key == authority.key]
    return _target(case.id, authority, arows, None, {}, _prepared(case, _awaiting(db, case, access)), board, now)


# why nothing is drafted for a target when its rows cannot be read (app.domain.request_gate.Unavailable): without
# them nobody can tell whether it was already asked or has a draft ready
GATE_ERROR = ("the freeze board could not be read (it says whether this target was already asked or has a draft "
              "ready), so nothing is drafted: try again shortly")


def row_step(db: Session, case, access, authority) -> str | None:
    """The next step the board's row for this counterparty shows (the whole board: a Recovery plan owner move can be a
    contacted service's step), for a person's message (the assistant's /stop-orders draft <target>); None when the
    board cannot be built."""
    try:
        t = build(db, case, access).find(authority.key)
    except Exception as err:  # noqa: BLE001 - the request gate's own text stands
        log.warning("freeze board: board failed for case %s (%s)", case.id, type(err).__name__)
        return None
    return t.step.label or None if t is not None else None


def replace_offer(st) -> dict | None:
    """The authority page's "Stop order — replaces draft #N" (request gate state `st`): the open draft a stop order
    generated there would supersede (a letter draft: `meta.superseded_by`, its `about` carried into the stop order),
    when the gate allows the stop order once that draft is replaced; never over a prepared e-mail. {key, no, text}."""
    from app.domain import request_gate as rg

    d = st.open if st is not None else None
    if d is None or d.held or d.follow_up_of or not st.candidate:
        return None
    if not rg.decide(st, "stop_order", replace={x.key for x in st.drafts}).allowed:
        return None
    t = st.target
    redo = next((s.label for s in t.extra if s.kind == "redraft"), None) if t is not None else None
    how = f" (or “{redo}” on its row on the Authorities tab)" if redo else ""
    what = " (a notice)" if t is not None and t.notice_only else ""
    carried = (f"; the addresses it cites ({', '.join(rg.short(a) for a in d.about[:3])}) are carried into the stop "
               "order" if d.order is None and d.about else "")
    text = (f"Draft {d.no}{what} is ready: open draft {d.no} and send it{how}. A stop order generated here replaces "
            f"it: draft {d.no} is superseded, with any edits made to it{carried}.")
    return {"key": d.key, "no": d.no, "text": text, "keys": [x.key for x in st.drafts]}


def _awaiting(db: Session, case, access) -> list:
    if access is not None and not access.can("prepare_email"):
        return []
    try:
        from app.domain.mail_send import awaiting_send

        return awaiting_send(db, case.id)
    except Exception as err:  # noqa: BLE001 - a broken mail setup only hides the "prepared e-mail" state
        log.warning("freeze board: prepared e-mails failed for case %s (%s)", case.id, type(err).__name__)
        return []


def _readings(db: Session, case, wallets: list | None = None) -> dict[tuple[str, str], list[dict]]:
    """(chain, address key) -> the latest GOOD reading per issuer contract of that wallet (app.freeze.service): the
    latest one, else the latest that succeeded when the latest failed. `wallets`: fz.wallet_rows when the caller has
    them (the Recovery plan)."""
    from app.freeze import service as fz

    if wallets is None:
        try:
            wallets = fz.wallet_rows(db, case)
        except Exception as err:  # noqa: BLE001 - no readings: the board shows the traced amounts
            log.warning("freeze board: freeze readings failed for case %s (%s)", case.id, type(err).__name__)
            return {}
    out: dict[tuple[str, str], list[dict]] = {}
    failed: set[tuple[str, str, str]] = set()
    for w in wallets:
        k = _key(w["chain"], w["address"])
        for c in w.get("checks") or []:
            if c.get("status") == "ok":
                out.setdefault(k, []).append({**c, "short": w["short"]})
            else:
                failed.add((w["chain"], w["address"], c.get("contract")))
    if failed:
        try:  # one query: the last good reading of each contract whose latest reading failed
            for (chain, addr, contract), row in fz._latest(db, case, ok_only=True).items():
                if (chain, addr, contract) in failed:
                    out.setdefault(_key(chain, addr), []).append({**fz._check_dict(row),
                                                                  "short": fz.short_address(addr)})
        except Exception as err:  # noqa: BLE001
            log.warning("freeze board: earlier readings failed for case %s (%s)", case.id, type(err).__name__)
    return out


def _onchain(a, reqs: list, readings: dict) -> dict | None:
    """The issuer's on-chain position for the case's wallets (the trace's identifiers and the addresses our requests
    cite): not frozen (≥ $1), frozen, when last read."""
    issuer = bs._issuer_of(a) if a is not None else None
    if issuer is None:
        return None
    keys = {_key(i.chain, i.address) for i in (a.candidate.identifiers if a.candidate is not None else [])}
    for r in reqs:
        idents = (r.order.identifiers or {}) if r.order is not None else {}
        for x in idents.get("addresses") or []:
            if isinstance(x, dict) and x.get("address"):
                keys.add(_key(x.get("chain") or idents.get("chain"), x["address"]))
    usd = frozen = 0.0
    at: datetime | None = None
    read = 0
    for k in keys:
        checks = [c for c in readings.get(k, []) if c.get("issuer") == issuer]
        if checks:
            read += 1
        for c in checks:
            v = float(c.get("usd") or 0)
            if c.get("blacklisted"):
                frozen += v
            elif v >= 1:
                usd += v
            ts = rp._iso(c.get("checked_at"))
            at = max(at, ts) if at is not None and ts is not None else (ts or at)
    if not keys:
        return None
    return {"usd": round(usd, 2), "frozen_usd": round(frozen, 2), "checked_at": at, "wallets": len(keys),
            "read": read, "unread": len(keys) - read}


def _pick(rows: list):
    return min(rows, key=lambda r: (rp.KIND_ORDER.index(r.next_action.get("kind"))
                                    if r.next_action.get("kind") in rp.KIND_ORDER else 50,
                                    -(r.requested_at.timestamp() if r.requested_at else 0), r.key))


def _held(reqs: list) -> str | None:
    for r in reqs:
        if r.status in HELD_BS and r.amount and r.source in bs.HUMAN_SOURCES:
            what = "frozen" if r.status == rules.FROZEN else "held"
            return f"{bs.fmt_amount(r.amount, r.asset)} {r.asset or ''} {what} (confirmed)".replace("  ", " ")
    return None


def _ghost_order(a) -> StopOrder | None:
    """A sent stop order marked superseded afterwards (it drops off Block status): the target was still contacted,
    and a generated draft still repeats it."""
    return max((o for o in (getattr(a, "stop_orders", None) or [])
                if o.status == StopOrderStatus.SUPERSEDED and o.sent_at is not None), key=lambda o: o.id, default=None)


def _asks_freeze(r) -> bool:
    """A freeze / preservation request: a stop order, or an outgoing letter asking to freeze an account (an owner
    letter: an information request whose `meta["freeze"]` holds the deposit address, or one recorded as a freeze ask,
    `meta["asks_freeze"]`: a hot wallet's "identify the account credited and freeze it", an address added to a draft,
    desk.generate_letter). A records-only request (swap order records, a host's preservation) asks for none."""
    letter = getattr(r, "letter", None)
    return getattr(r, "kind", None) in FIRST_CONTACT or (
        getattr(r, "order", None) is None and letter is not None and (
            bool(desk.freeze_address(letter)) or bool((letter.meta or {}).get("asks_freeze"))))


def _duplicate_map(reqs: list, ghost: StopOrder | None) -> dict[int, Any]:
    """id(row) -> the request it repeats, for one target's request rows (None: the newest sent freeze request, `first`):
    a generated stop-order draft for a target a freeze request already went to (a sent stop order or owner letter, or a
    stop order marked superseded after it was sent). The request gate (app.domain.request_gate) creates none any more;
    a case can still hold one from before it."""
    if ghost is not None or any(_asks_freeze(r) and r.status != bs.NOT_SENT for r in reqs):
        return {id(r): None for r in reqs if r.status == bs.NOT_SENT and r.order is not None
                and r.order.origin != StopOrderOrigin.IMPORTED}
    return {}


def _duplicates(reqs: list, ghost: StopOrder | None) -> list:
    """The drafts among one target's request rows that repeat a freeze request already made (`_duplicate_map`): the
    board flags them, and they never decide the row or its Recovery plan move."""
    dup = _duplicate_map(reqs, ghost)
    return [r for r in reqs if id(r) in dup]


def without_duplicates(rows: list) -> list:
    """The case's block rows (bs.case_blocks) without the duplicate drafts the board flags (`_duplicates`): the rows the
    board's Recovery plan is built from, and the pack route's (app.blocks.recovery.pack), so a target's move, its score
    and its LE / counsel brief pack stay the sent request's, never a draft the board says to discard."""
    by: dict[str, list] = {}
    for r in rows:
        if r.kind not in ("onchain", "outlook"):
            by.setdefault(r.authority.key, []).append(r)
    drop = {id(r) for reqs in by.values() for r in _duplicates(reqs, _ghost_order(reqs[0].authority))}
    return [r for r in rows if id(r) not in drop] if drop else list(rows)


def _target(cid: int, a, arows: list, move, readings: dict, prepared: dict, board: Board, now: datetime) -> Target:
    cand = a.candidate
    t = Target(key=a.key, name=a.name, category=a.category, authority=a, candidate=cand,
               kind=cand.kind if cand is not None else None, jurisdiction=a.jurisdiction, move=move, rows=arows,
               prepared=prepared, board=board)
    reqs = [r for r in arows if r.kind != "onchain"]
    onchain_rows = [r for r in arows if r.kind == "onchain"]
    t.traced_usd = float(cand.total_taint_usd) if cand is not None else None
    t.onchain = _onchain(a, reqs, readings)
    t.held = _held(reqs)
    if move is not None:
        t.value, t.basis, t.score = move.value, move.basis, move.score
        t.owners = list(move.owners or [])
    else:
        t.value = t.traced_usd
        t.basis = f"{rp.money(t.value)} traced (upper bound)" if t.value else ""

    ghost = _ghost_order(a)
    # requests: the sent first-contact ones a generated draft would repeat
    sent = [r for r in reqs if r.status != bs.NOT_SENT]
    first = sorted([r for r in sent if _asks_freeze(r)] + ([_Ghost(ghost)] if ghost is not None else []),
                   key=lambda r: (r.requested_at or now, r.key))
    dup_of = _duplicate_map(reqs, ghost)
    dups = [r for r in reqs if id(r) in dup_of]
    for d in dups:
        of = dup_of[id(d)] or first[-1]
        answer = (SHORT_ANSWER.get(of.status) if of.status != bs.NOT_SENT and (
            of.deciding is not None or of.source == "recorded") else None)
        answered = ("a draft, not sent yet" if of.status == bs.NOT_SENT else f"already answered: {answer}" if answer
                    else f"already sent {of.requested_at:%d %b %Y}" if of.requested_at else "already sent")
        mm = prepared.get(("o", d.order.id))
        text = f"Draft {req_no(d)} duplicates request {req_no(of)} ({answered}) — discard?"
        if mm is not None:
            text += f" Prepared e-mail #{mm.id} for it awaits Send: discarding cancels it."
        t.duplicates.append({"order_id": d.order.id, "no": req_no(d), "of": req_no(of), "of_key": of.key,
                             "answer": answer, "prepared": mm.id if mm is not None else None, "text": text})
    live = [r for r in reqs if r not in dups]
    p = move.row if move is not None and move.row in live else (_pick(live) if live else None)
    t.primary = p
    order = sorted(reqs, key=lambda r: ((r.requested_at or _aware(r.order.created_at if r.order is not None else
                                                                   r.letter.created_at if r.letter is not None
                                                                   else None) or now), r.key), reverse=True)
    t.requests = [{"key": r.key, "no": req_no(r), "title": r.title, "status": r.status_text, "tone": r.tone,
                   "href": _item_url(cid, r), "at": r.requested_at, "draft": r.status == bs.NOT_SENT,
                   "duplicate": r in dups} for r in order]
    t.ticket = p.ticket if p is not None else None

    oc = t.onchain or {}
    money = t.candidate is not None and (t.traced_usd or 0) > 0
    if ghost is not None and (p is None or p.status == bs.NOT_SENT):
        _ghost(cid, t, a, ghost)
    elif not sent and ghost is None and _claimable(oc):
        _claim(cid, t, a, p, oc, prepared, board)
    elif p is None:
        _uncontacted(cid, t, a, move, oc, onchain_rows, board)
    else:
        _contacted(cid, t, a, p, move, prepared, board, now)
        if money and t.status in FREEZE_OPEN and ghost is None and not any(
                _asks_freeze(r) and r.status != bs.NOT_SENT for r in reqs):
            _freeze_open(cid, t, [r for r in live if _asks_freeze(r) and r.status == bs.NOT_SENT])
    if t.step.kind != "open":  # a sent request marked superseded: its page is checked first (_ghost)
        _le_first(cid, t, a, p, move, board)
    if t.step.alts:
        t.extra = [*t.step.alts, *t.extra]
    if oc and (oc.get("unread") or not oc.get("read")) and t.group != NOTHING:
        t.extra.append(Step("check", "Check the balance on-chain", href=f"/cases/{cid}/freeze", perm="view"))
    _deadline(t, p, now)
    _skip(cid, t, sent, board.run)
    if ghost is not None and t.sent_ref is None:
        t.sent_ref = f"o{ghost.id}"
    if t.status in (FROZEN, HELD):  # the money is secured: never the plan's "balance 0: the funds left" basis
        t.basis = t.held or (f"{rp.money(oc['frozen_usd'])} frozen on-chain (issuer blacklist)"
                             if oc.get("frozen_usd") else t.basis)
    return t


def _le_label(route: dict | None, instrument: dict | None, kind: str | None = None, href: str | None = None) -> str:
    """The LE step's button, named after where it leads (`href`): the LE brief / cover letter template, a case agent
    (the complaint the agent comes through), the cross-border route, the LE contact page."""
    route, href = route or {}, href or ""
    if "template=le_brief" in href:
        return "Open the LE brief"
    if "template=le_cover" in href:
        return "Open the LE cover letter"
    if "template=release_request" in href:
        return "Open the release request"
    agent = route.get("agent")
    if agent is not None and route.get("case_agent", True):
        return f"Get a {agent['jur']} case agent" + (" or court order" if (instrument or {}).get("type") in COURT
                                                     else "")
    if kind == "cross_border" or route.get("kind") == "cross_border":
        return "Start the cross-border route"
    if (instrument or {}).get("type") in COURT:
        return "Brief LE for a court order"
    return "Brief LE"


def _lead_first(text: str) -> str:
    """An LE step's text with the operative sentence first (shown; the rest behind "more"): a blocker (the LE brief is
    still a draft, no officer on file), else the first instruction (who to brief), not the issuer-policy sentence."""
    parts = _SENTENCE.split(text.strip()) if text else []
    if len(parts) < 2:
        return text
    pick = next((i for i, x in enumerate(parts) if _BLOCKER.search(x)), None)
    if pick is None:
        pick = next((i for i, x in enumerate(parts) if _IMPERATIVE.match(x)), None)
    if not pick:
        return text
    return " ".join([parts[pick], *parts[:pick], *parts[pick + 1:]])


def _le_step(cid: int, route: dict | None, instrument: dict | None, kind: str | None, text: str,
             href: str | None, board: Board | None = None) -> tuple[Step, str | None]:
    """(the LE step, the status detail when the step is an LE brief already drafted). A link back to the tab itself
    is no button (text only). A brief to an LE contact with no officer or e-mail on file: the step adds the officer's
    contact, and the brief to the reachable LE the text names is the second button."""
    kind = kind if kind in LE_KINDS else "le"
    m = _DRAFT_HREF.search(href or "")
    if m:
        return (Step(kind, f"Send LE brief #{m.group(1)}", text=_lead_first(text), href=href),
                f"LE brief #{m.group(1)} drafted, not sent")
    if not href or href.startswith(f"/cases/{cid}?tab="):
        return Step(kind, "", text=_lead_first(text)), None
    blocked = _NO_OFFICER.search(text or "")
    if blocked and "/authorities/" in href and "template=le_brief" in href:
        le_key = href.split("/authorities/", 1)[1].split("?", 1)[0]
        anchor = f"ev-contact-{le_key[3:]}" if re.fullmatch(r"le-\d{1,12}", le_key) else "ev-contacts"
        # `le`: the LE letter's own state (`_le_letter_state`) reads that contact's letter and the reachable one's
        step = Step(kind, "Add the officer's contact", text=_lead_first(text),
                    href=f"/cases/{cid}?tab=evidence&folder=law_enforcement#{anchor}", perm="manage_le_contacts", le=le_key)
        reach = blocked.group(1)
        reach_key = board.le_keys.get(reach) if board is not None else None
        if reach_key and reach_key != le_key:
            step.alts.append(Step(kind, f"Brief {reach}",
                                  href=href.replace(f"/authorities/{le_key}?", f"/authorities/{reach_key}?", 1)))
        return step, None
    return Step(kind, _le_label(route, instrument, kind, href), text=_lead_first(text), href=href), None


def _pack(cid: int, key: str, board: Board) -> list[Step]:
    """The LE brief pack of the Recovery plan move `key` (a request "o12" / an untouched target "entity-5"), when the
    plan has that move."""
    if not board.can_pack or key not in board.pack_keys:
        return []
    return [Step("pack", "LE brief pack (.zip)", href=f"/cases/{cid}/recovery-plan/pack/{key}.zip", perm="pack")]


def _notice(cid: int, t: Target, label: str) -> Step:
    return Step("draft", label, post=f"/cases/{cid}/stop-orders", fields={"entity": t.candidate.entity_name})


def _counsel(t: Target, p, move, board: Board) -> None:
    """The court-order half of an LE-only answer: the Recovery plan's counsel brief pack for request `p`, when the
    plan offers one (counsel seeks the order; it does not wait for LE). The plan is built without the duplicate drafts
    (`without_duplicates`), so a sent request's move is its own."""
    if not board.can_pack or move is None or p is None or move.row is not p:
        return
    href = next((x["href"] for x in move.actions if str(x.get("label") or "").startswith("Instruct counsel")
                 and x.get("href")), None)
    if href is not None:
        t.extra.append(Step("pack", "Counsel brief pack (court order)", href=href, perm="pack"))


def _handoff_text(a, move, draft: str | None = None) -> str:
    """An LE-only issuer's text: start the LE route now (with a case agent: what to do on the complaint's page), the
    notice in parallel; then the move's own text without its first sentence, its "acts on LE process only … in
    parallel" sentence or (with the agent named here) its "Fastest LE route" sentence."""
    how = _agent_how(a, move.route)
    notice = (f"your notice {draft} flags the wallets: send it in parallel" if draft else
              "send the notice in parallel (it flags the wallets)")
    lead = f"{a.name} acts on LE process only: the LE route is what gets the wallets frozen, so start it now{how}; {notice}."
    parts = _SENTENCE.split((move.text or "").strip())[1:]
    rest = [x for x in parts if HANDOFF_TEXT not in x and not (how and x.startswith("Fastest LE route:"))]
    return " ".join([lead, *rest])


def _handoff_href(cid: int, move) -> str | None:
    """Where an LE-only issuer's LE route starts: the complaint a case agent comes through, else the LE cover letter."""
    route = move.route or {}
    agent = route.get("agent")
    if agent is not None and route.get("case_agent", True) and agent.get("via_key"):
        return f"/cases/{cid}/authorities/{agent['via_key']}"
    return next((x["href"] for x in move.actions if str(x.get("label") or "").startswith("LE cover letter to")
                 and x.get("href")), None)


# the states of an LE-only issuer's request in which the LE step is the row's primary step (_le_first): before the
# notice, drafted, prepared, sent, overdue, acknowledged, answered LE only, and frozen on-chain but not yet claimed
LE_FIRST = frozenset({NOT_CONTACTED, DRAFT_READY, PREPARED, AWAITING, HANDOFF, OVERDUE, ACKNOWLEDGED, LE_ONLY})
LE_CONTACTED = frozenset({AWAITING, HANDOFF, OVERDUE, ACKNOWLEDGED, LE_ONLY})  # the notice is out
_LE_TEMPLATE = re.compile(r"/authorities/((?:le|entity)-\d{1,12})\?template=(le_cover|le_brief)\b")


def _le_first(cid: int, t: Target, a, p, move, board: Board) -> None:
    """THE rule for a target that acts on LE process only (board.le_route(a), or its letter is a notice): whatever the
    notice's state (`LE_FIRST`), the row's primary step is the LE step and the notice's own actions (open & send it,
    chase it), the pack and the counsel pack are extras. The LE step reflects the LE letter's own state
    (`_le_letter_state`): none yet, the LE route's start (a case agent, the cover letter / brief); a contact with no
    officer on file, "Add the officer's contact" with the reachable LE's letter as the alternative; drafted, "Send LE
    cover letter #N"; sent, follow up with the officer. With no LE button at all (no LE contact on the case), the
    notice stays the one button and its text says who to brief."""
    in_claim = t.group == CLAIM and t.step.kind != "confirm"
    if t.status in (FROZEN, HELD) and not in_claim:
        _le_secured(cid, t, a, p, move, board)
        return
    if t.status not in LE_FIRST and not in_claim:
        return
    le = board.le_route(a) if board.le_route is not None else None
    if le is None and not t.notice_only:
        return
    route = (le or {}).get("route") or (move.route if move is not None else None) or (
        p.path.route if p is not None and p.path is not None else None)
    old = t.step
    step = old if old.kind in LE_KINDS and old.label else next(
        (s for s in t.extra if s.kind in LE_KINDS and s.label), None)
    if step is None:
        href = le["href"] if le is not None else (_handoff_href(cid, move) if move is not None else None)
        instrument = (p.path.instrument if p is not None and p.path is not None else None) or (
            (p.intel.get("instrument") or None) if p is not None else None)
        text = _le_only_text(a, route, p, t)
        step, _ = _le_step(cid, route, instrument, "le", text, href, board)
        step.text = text
        if not step.label:
            return  # no LE contact to start with yet: the row keeps the notice; its text says who to brief
    step = _no_officer(cid, step, route, board)
    if step is not old:
        t.extra = [s for s in t.extra if s is not step]
        if old.label and old.kind not in LE_KINDS:
            t.extra.insert(0, old)
        t.step = step
    if t.candidate is not None:
        t.notice_only = True  # the case's letter to it is a notice (it flags the wallets); LE's request freezes them
    if t.status in (AWAITING, OVERDUE):  # the notice's reply does not freeze the wallets: the LE hand-off is due
        bits = [f"reply to notice {req_no(p)} overdue" if t.status == OVERDUE else "",
                f"ticket {p.ticket}" if p.ticket and "ticket" not in t.detail else ""]
        t.status = HANDOFF
        t.detail = " · ".join(x for x in [t.detail, *bits] if x)
    if not in_claim:
        t.group = ACT
    _le_letter_state(cid, t, p, board)
    if not any(s.kind == "pack" and "/recovery-plan/pack/" in (s.href or "") for s in t.extra):
        t.extra += _pack(cid, p.key if p is not None else a.key, board)
    if p is not None and not any(s.label == "Counsel brief pack (court order)" for s in t.extra):
        _counsel(t, p, move, board)


def _le_secured(cid: int, t: Target, a, p, move, board: Board) -> None:
    """A freeze / hold a person confirmed at an issuer acting on LE process only, whose next step is LE's (the LE
    cover letter / brief so the funds stay held for seizure): the same LE-letter rule as `_le_first` — the route's LE
    contact with no officer on file, "Add the officer's contact" with the reachable LE's letter as the alternative; the
    letter drafted, "Send LE cover letter #N"; sent, follow up with the officer — keeping the frozen / held status and
    its group (`_secured`: Secured, or Act now on a lapse clock)."""
    step = t.step
    if (p is None or p.status not in HELD_BS or p.source not in bs.HUMAN_SOURCES or step.kind not in LE_KINDS
            or not step.label or board.le_route is None):
        return
    le = board.le_route(a)
    if le is None:
        return
    route = le.get("route") or (move.route if move is not None else None) or (
        p.path.route if p.path is not None else None)
    status, group = t.status, t.group
    t.step = _no_officer(cid, step, route, board)
    _le_letter_state(cid, t, p, board)
    t.status, t.group = status, group


def _le_only_text(a, route: dict | None, p, t: Target) -> str:
    """The LE step's text when the row's own branch gave none (the notice sent, overdue, acknowledged): start the LE
    route; the notice's state in a second sentence."""
    lead = (f"{a.name} acts on LE process only: the LE route is what gets the wallets frozen, so start it now"
            f"{_agent_how(a, route)}.")
    if p is None or p.status == bs.NOT_SENT:
        return f"{lead} Send the notice in parallel (it flags the wallets)."
    ticket = f" (ticket {p.ticket})" if p.ticket else ""
    if t.status == OVERDUE:
        return (f"{lead} The reply to notice {req_no(p)}{ticket} is overdue: chase it in parallel (a status request on "
                "it, never a new stop order).")
    return f"{lead} Notice {req_no(p)}{ticket} is out: its reply does not freeze the wallets."


def _no_officer(cid: int, step: Step, route: dict | None, board: Board) -> Step:
    """An LE letter (cover letter / brief) to an LE contact with no named officer or e-mail on file: "Add the officer's
    contact", with the same letter to a reachable LE as the alternative (the shape `_le_step` gives an LE brief the
    reply's path blocks). The reachable LE: the route's (`route["reachable"]`), else the route's own LE, else the first
    of the case's LE contacts that files with a provider itself and has an officer or e-mail on file. The step's LE
    contact need not be the route's (the request's next action names its own)."""
    m = _LE_TEMPLATE.search(step.href or "")
    if m is None or step.alts:
        return step
    le_key, tpl = m.groups()
    here = board.le_target(le_key)
    if here is None or here.reachable:
        return step
    reach_key = None
    for name in ((route or {}).get("reachable"), (route or {}).get("le")):
        k = board.le_keys.get(name) if name else None
        x = board.le_target(k)
        if k and k != le_key and x is not None and x.briefable and x.reachable:
            reach_key = k
            break
    if reach_key is None:
        reach_key = next((k for k in board.le_auths if k != le_key and board.le_target(k) is not None
                          and board.le_target(k).briefable and board.le_target(k).reachable), None)
    if reach_key is None:
        return step
    reach = board.le_auths[reach_key].name
    name = board.le_auths[le_key].name if le_key in board.le_auths else "The LE contact"
    anchor = f"ev-contact-{le_key[3:]}" if re.fullmatch(r"le-\d{1,12}", le_key) else "ev-contacts"
    what = "cover letter" if tpl == "le_cover" else "brief"
    out = Step(step.kind, "Add the officer's contact",
               text=(f"{name} has no named officer or e-mail on file: add one to the LE contact, or send the {what} "
                     f"to {reach} (reachable) instead. {step.text}").strip(),
               href=f"/cases/{cid}?tab=evidence&folder=law_enforcement#{anchor}", perm="manage_le_contacts", le=le_key)
    out.alts.append(Step(step.kind, f"Cover letter to {reach}" if tpl == "le_cover" else f"Brief {reach}",
                         href=step.href.replace(f"/authorities/{le_key}?", f"/authorities/{reach_key}?", 1)))
    return out


def _le_letter(board: Board, le_key: str | None, t: Target, *, case_wide: bool = False):
    """The newest outgoing LE cover letter / brief to LE contact `le_key` that concerns target `t` (a case-wide cover
    letter, or a brief that follows up one of its requests), drafted or sent; a discarded draft never counts.
    `case_wide`: a case-wide LE cover letter only (no `follow_up_of`)."""
    la = board.le_auths.get(le_key) if le_key else None
    if la is None:
        return None
    mine = {r["key"] for r in t.requests}
    best = None
    for c in la.correspondence:
        if (c.direction != CorrespondenceDirection.OUT or c.kind != CorrespondenceKind.LE_COVER
                or c.status == CorrespondenceStatus.RECEIVED or discarded(c)):
            continue
        ref = (c.meta or {}).get("follow_up_of")
        if isinstance(ref, str) and (case_wide or ref not in mine):
            continue
        if case_wide and (c.meta or {}).get("template_key") not in (None, "le_cover"):
            continue
        if best is None or c.id > best.id:
            best = c
    return best


def _le_letter_state(cid: int, t: Target, p, board: Board) -> None:
    """The LE step after the LE letter it starts (`_le_letter`): drafted, "Send LE cover letter #N" (its page); sent,
    "LE cover letter #N sent <date> to <LE>: follow up with the officer" (a status request to that LE contact). A
    blocked step (no officer on file) looks at the reachable LE's letter first; a draft to the contact with no officer
    on file keeps "Add the officer's contact" (and the reachable LE's letter) as the alternatives."""
    step = t.step
    m = _LE_TEMPLATE.search(step.href or "")
    keys: list[tuple[str, bool]] = []  # (LE key, reachable)
    if step.le:
        alt = next((_LE_TEMPLATE.search(s.href or "") for s in step.alts if _LE_TEMPLATE.search(s.href or "")), None)
        if alt is not None:
            keys.append((alt.group(1), True))
        keys.append((step.le, False))
    elif m is not None:
        keys.append((m.group(1), True))
    found = next(((c, k, r) for k, r in keys if (c := _le_letter(board, k, t)) is not None), None)
    tpls = {x.group(2) for x in (_LE_TEMPLATE.search(s.href or "") for s in [step, *step.alts]) if x is not None}
    if found is None and "le_cover" in tpls:
        # none to the step's LE contact(s): the newest case-wide LE cover letter to another LE contact of the case (the
        # letter the status layer follows once it is sent), never a second case-wide cover letter
        wide = [(c, k) for k in board.le_auths if (c := _le_letter(board, k, t, case_wide=True)) is not None]
        if wide:
            c, k = max(wide, key=lambda x: x[0].id)
            found = (c, k, True)
    if found is None:
        return
    c, le_key, reachable = found
    tpl = (c.meta or {}).get("template_key")
    noun = "LE brief" if tpl == "le_brief" else "LE cover letter" if tpl == "le_cover" or tpl is None else "LE letter"
    le_name = board.le_auths[le_key].name
    sent = c.status != CorrespondenceStatus.DRAFT
    at = _aware(c.occurred_at) if sent else None
    t.le_letter = {"id": c.id, "noun": noun, "sent": sent, "at": at, "due_at": _aware(c.due_at), "le": le_name,
                   "le_key": le_key}
    rest = step.text.replace(", so start it now", "")
    if reachable:  # the letter went to the reachable LE: the "no officer on file" blocker no longer applies
        rest = " ".join(x for x in _SENTENCE.split(rest) if "has no named officer or e-mail on file" not in x)
    if not sent:
        t.step = Step(step.kind, f"Send {noun} #{c.id}",
                      text=f"Your {noun} #{c.id} to {le_name} is still a draft: send it. {rest}".strip(),
                      href=f"/cases/{cid}/authorities/correspondence/{c.id}")
        if not reachable:  # drafted to the contact with no officer on file: add its contact, or the reachable LE
            t.step.alts = [Step(step.kind, step.label, href=step.href, perm=step.perm), *step.alts]
        what = f"{noun} #{c.id} drafted, not sent"
    else:
        when = f" {at:%d %b %Y}" if at is not None else ""
        claim = t.group == CLAIM  # frozen on-chain, not yet tied to this victim: the notice and LE's request claim it
        does = "it links the freeze to this case" if claim else "it flags the wallets"
        notice = ("" if p is not None and p.status != bs.NOT_SENT else
                  f" Send your notice {req_no(p)} in parallel ({does})." if p is not None else
                  f" Send the notice in parallel ({does}).")
        if claim:
            notice = " Until LE links the freeze to this victim, it is not claimed for this case." + notice
        t.step = _le_follow_up(cid, step, c, noun, le_name, le_key, reachable, board.now,
                               f"{noun} #{c.id} sent{when} to {le_name}", notice)
        what = f"{noun} #{c.id} sent{when}"
        if t.status in LE_CONTACTED:  # the notice is out and LE has the letter: the LE route is in progress
            t.status, t.group = LE_ROUTE, LE_GROUP
    t.detail = f"{t.detail} · {what}" if t.detail else what


def _le_follow_up(cid: int, step: Step, c, noun: str, le_name: str, le_key: str, reachable: bool, now: datetime,
                  head: str, notice: str) -> Step:
    """The LE step once the LE letter `c` is sent: the follow-up to the officer (a status request to that LE contact)
    only once the reply is nearly due (`FOLLOW_UP_SOON`, as a provider request's) or with no reply clock; "Chase the
    officer" once it is overdue; before that, the sent text only (no button). A letter that went to a contact with no
    officer or e-mail on file (by post, `reachable` False): following it up starts with "Add the officer's contact",
    the follow-up letter to that contact the alternative."""
    due = _aware(c.due_at)
    follow = f"/cases/{cid}/authorities/{le_key}?template=status_request#generate"
    if due is not None and due - now > FOLLOW_UP_SOON:
        return Step(step.kind, "", text=(f"{head}: the officer's reply is due {due:%d %b %Y}; follow up with the "
                                         f"officer then.{notice}"))
    late = due is not None and due < now
    label = "Chase the officer" if late else "Follow up with the officer"
    what = (f"{head}: the officer's reply was due {due:%d %b %Y}: chase the officer." if late else
            f"{head}: follow up with the officer.")
    if reachable:
        return Step(step.kind, label, text=f"{what}{notice}", href=follow)
    out = Step(step.kind, step.label, text=(f"{what} {le_name} has no named officer or e-mail on file: add the "
                                            f"officer's contact to follow up with them.{notice}"),
               href=step.href, perm=step.perm, le=le_key)
    out.alts = [Step(step.kind, f"Follow-up letter to {le_name}", href=follow)]
    return out


class _Ghost:
    """A sent stop order marked superseded afterwards, as the request a generated draft repeats (`first`)."""

    def __init__(self, o: StopOrder):
        self.order, self.letter, self.key = o, None, f"o{o.id}"
        self.requested_at = _aware(o.sent_at)
        self.deciding = self.source = self.status = None


def _claimable(oc: dict) -> bool:
    """Every wallet of the issuer read on-chain, blacklisted, nothing left unfrozen."""
    return bool(oc.get("frozen_usd") and not oc.get("usd") and not oc.get("unread"))


def _agent_how(a, route: dict | None) -> str:
    """': on the IC3 complaint, ask for a US case agent to be assigned …' when a case agent comes through a
    complaint on the case, else ''."""
    route = route or {}
    agent = route.get("agent")
    if agent is None or not route.get("case_agent", True) or not agent.get("via_key") or not agent.get("via"):
        return ""
    ref = f", quoting reference {agent['reference']}" if agent.get("reference") else ""
    return (f": on the {agent['via']} complaint, ask for a {agent['jur']} case agent to be assigned{ref} (the agent "
            f"asks {a.name} directly)")


def _claim(cid: int, t: Target, a, p, oc: dict, prepared: dict, board: Board) -> None:
    """Frozen on-chain by the issuer on its own, nobody asked yet (`p`: None, or the notice drafted and unsent):
    trapped, not claimed. The case's notice ties the freeze to this victim; an issuer acting on LE process only gets
    the LE route as the primary step (the officer's request is what links the freeze), the notice the second."""
    t.status, t.group = FROZEN, CLAIM
    frozen = rp.money(oc["frozen_usd"])
    le = board.le_route(a) if board.le_route is not None else None
    t.notice_only = le is not None and t.candidate is not None
    mm = None
    if p is None:
        t.detail = f"{frozen} frozen on-chain by the issuer — not yet claimed for this case"
        notice = _notice(cid, t, "Send notice (links the freeze to this case)") if t.candidate is not None else None
        t.draftable = notice is not None
        draft = ""
    else:
        mm = (prepared.get(("o", p.order.id)) if p.order is not None else None) or (
            prepared.get(("c", p.letter.id)) if p.letter is not None else None)
        if mm is not None:
            notice = Step("send", "Open & send e-mail (notice)" if board.can_send else "Open the prepared e-mail",
                          href=f"/cases/{cid}/mail/messages/{mm.id}", perm="prepare_email")
            t.detail = (f"{frozen} frozen on-chain by the issuer — notice {req_no(p)}: prepared e-mail #{mm.id} awaits "
                        "Send")
        else:
            notice = Step("send", "Open & send notice", href=_item_url(cid, p))
            t.detail = f"{frozen} frozen on-chain by the issuer — notice {req_no(p)} drafted, not yet sent"
        t.skip = ("prepared" if mm is not None else "draft", p.key)
        draft = f" {req_no(p)}"
    lead = (f"Frozen on-chain by {a.name}, but nobody has tied these funds to this case: a blacklist traps the money, "
            "it does not return it.")
    if le is not None:
        how = _agent_how(a, le["route"])
        text = (f"{lead} {a.name} acts on LE process only: brief LE{how} so the freeze is linked to this victim; send "
                f"the case's notice{draft} in parallel.")
        step, _ = _le_step(cid, le["route"], None, "le", text, le["href"], board)
        step.text = text
    else:
        text = f"{lead} Send {a.name} the case's notice{draft} and brief LE so the freeze is linked to this victim."
        step = Step("none", text=text)
    if step.label:
        t.step, t.extra = step, [notice] if notice is not None else []
    elif notice is not None:
        notice.text = text
        t.step = notice
    else:
        t.step = step
    t.extra += _pack(cid, p.key if p is not None else a.key, board)


def _uncontacted(cid: int, t: Target, a, move, oc: dict, onchain_rows: list, board: Board) -> None:
    t.status = NOT_CONTACTED
    if move is None or not move.untouched or not move.actionable:
        t.status, t.group = NOT_APPLICABLE, NOTHING
        why = ("Non-custodial: it holds no accounts or balances, so there is nothing to freeze."
               if a.non_custodial else "No funds traced here: nothing to request.")
        if onchain_rows and onchain_rows[0].next_action.get("text"):
            why = onchain_rows[0].next_action["text"]
        t.step = Step("none", text=why)
        return
    t.group = ACT
    if move.kind in LE_KINDS:  # the playbook's LE-only gate: the case officer asks
        t.detail = "acts on LE requests only"
        t.step, _ = _le_step(cid, move.route, None, move.kind, move.text, move.href, board)
        t.extra = _pack(cid, a.key, board)
        return
    generated = bool(move.href and "template=stop_order" in move.href and t.candidate is not None)
    if HANDOFF_TEXT in (move.text or "") and generated:
        # an issuer that acts on LE process only (Circle, Tether): the LE route freezes the funds; our letter is a
        # notice that flags the wallets (and may get a ticket the officer quotes), sent in parallel
        t.notice_only = t.draftable = True
        t.detail = "acts on LE process only: our letter is a notice"
        text = _handoff_text(a, move)
        step, _ = _le_step(cid, move.route, None, "le", text, _handoff_href(cid, move), board)
        step.text = text
        notice = _notice(cid, t, "Send notice (flags the wallets)")
        if step.label:
            t.step, t.extra = step, [notice, *_pack(cid, a.key, board)]
        else:  # no LE contact to start with yet: the notice is the one button, the text says who to brief
            notice.text = text
            t.step, t.extra = notice, _pack(cid, a.key, board)
        return
    t.detail = "nobody has asked yet"
    if generated:
        t.step = _notice(cid, t, "Draft request")
        t.step.text = move.text
        t.draftable = True
    else:
        t.step = Step("draft", "Draft request", text=move.text, href=move.href)


def _contacted(cid: int, t: Target, a, p, move, prepared: dict, board: Board, now: datetime) -> None:
    # the request's next action as the Recovery plan reads it (rp._row_move: an account of theirs their reply names is
    # a freeze ask, a drafted request after a sent one an escalation), else the block row's own
    na = (move.next_action if move is not None and move.row is p and move.next_action else None) or (
        p.next_action or {})
    st = p.status
    kind = na.get("kind")
    text = na.get("text") or ""
    href = na.get("href")
    path = p.path
    route = path.route if path is not None else None
    instrument = (path.instrument if path is not None else None) or (p.intel.get("instrument") or None)
    t.detail = p.status_text if p.status_text != bs.LABELS.get(st) else ""
    if st == bs.NOT_SENT:
        mm = (prepared.get(("o", p.order.id)) if p.order is not None else None) or (
            prepared.get(("c", p.letter.id)) if p.letter is not None else None)
        notice = (move is not None and move.untouched and HANDOFF_TEXT in (move.text or "")
                  and t.candidate is not None)
        if mm is not None:
            t.status, t.group = PREPARED, ACT
            until = f" (valid until {_aware(mm.expires_at):%d %b %H:%M} UTC)" if mm.expires_at else ""
            send = Step("send", ("Open & send e-mail" if board.can_send else "Open the prepared e-mail")
                        + (" (notice)" if notice else ""),
                        text=f"Prepared e-mail #{mm.id} for {req_no(p)} waits for a case admin to press Send{until}.",
                        href=f"/cases/{cid}/mail/messages/{mm.id}", perm="prepare_email")
        else:
            t.status, t.group = DRAFT_READY, ACT
            send = Step("send", "Open & send notice" if notice else "Open & send draft",
                        text=text or "Open the draft and send it.", href=_item_url(cid, p))
        if not notice:
            t.step = send
            return
        # an issuer acting on LE process only: the draft is its notice; the LE route stays the row's primary step
        t.notice_only = True
        t.detail = ("acts on LE process only: our letter is a notice ("
                    + ("prepared e-mail awaiting Send)" if mm is not None else "draft ready)"))
        text = _handoff_text(a, move, draft=req_no(p))
        le, _ = _le_step(cid, move.route, None, "le", text, _handoff_href(cid, move), board)
        le.text = text
        if le.label:
            t.step, t.extra = le, [send, *_pack(cid, p.key, board)]
        else:  # no LE contact to start with yet: the notice is the one button, the text says who to brief
            send.text = text
            t.step, t.extra = send, _pack(cid, p.key, board)
        return
    sug = p.suggestion
    if sug is not None:
        what = sug.get("status")
        noun = "hold" if what == rules.HOLD_PLACED else "freeze" if what == rules.FROZEN else "outcome"
        confirm = Step("confirm", f"Confirm the {noun}", text=text, href=f"/cases/{cid}/blocks#{p.key}",
                       perm="log_correspondence")
        if sug.get("source") == "onchain" and what == rules.FROZEN:  # trapped on-chain; a person confirms it
            t.status, t.group, t.step = FROZEN, CLAIM, confirm
            t.detail = f"on-chain: {bs.suggestion_text(sug)} — a person confirms it"
        else:
            t.status, t.group, t.step = TO_CONFIRM, ACT, confirm
        if kind == "answer" and href:  # their hold comes with a condition of ours (a receipt by a deadline): first
            confirm.text = ""
            t.step, t.extra = Step("answer", "Answer their questions", text=text, href=href), [confirm, *t.extra]
        return
    if st in HELD_BS and p.source not in bs.HUMAN_SOURCES:  # never a positive outcome nobody confirmed
        t.status, t.group = TO_CONFIRM, ACT
        t.step = Step("confirm", "Confirm their reply", text=text, href=f"/cases/{cid}/blocks#{p.key}",
                      perm="log_correspondence")
        return
    if st in HELD_BS:
        _secured(cid, t, p, kind, text, href, route, instrument, board, now)
        return
    if st == rules.FUNDS_RETURNED:
        t.status, t.group = RELEASED, NOTHING
        t.step = Step("none", text=text)
        return
    if st in (rules.DECLINED, rules.DECLINED_NO_ASSETS):
        t.status, t.group = DECLINED, NOTHING
        t.step = Step("none", text=text)
        if kind == "answer" and href:  # the funds went to an account of theirs their reply names: ask them to freeze it
            t.group, t.step = ACT, Step("answer", rp._primary_label(kind, href), text=text, href=href)
        elif kind in LE_KINDS and href:  # they hold the records (KYC, the withdrawal): LE asks for them
            t.step, _ = _le_step(cid, route, instrument, kind, text, href, board)
        return
    if st == rules.LE_PROCESS_REQUIRED:
        t.status, t.group = LE_ONLY, ACT
        t.step, drafted = _le_step(cid, route, instrument, move.kind if move is not None and move.row is p else kind,
                                   text, href, board)
        t.detail = drafted or ("LE hand-off due" + (f" · ticket {p.ticket}" if p.ticket else ""))
        t.extra = _pack(cid, p.key, board)
        _counsel(t, p, move, board)
        return
    if (st == bs.AWAITING and p.source == "le_route") or (path is not None and path.step in LE_STEPS):
        t.status, t.group = LE_ROUTE, LE_GROUP
        t.step = Step(kind or "wait", "", text=text)
        if kind in rp.ACTIONABLE and href:
            t.step.label = "Chase the officer" if kind == "chase" else rp._primary_label(kind, href)
            t.step.href = href
        t.extra = _pack(cid, p.key, board)
        return
    if st == rules.INFO_REQUESTED:
        t.status, t.group = INFO_REQUESTED, ACT
        t.step = Step("answer", "Answer their questions", text=text, href=href)
        return
    if st in (rules.REDIRECTED, rules.DELIVERY_FAILED):
        t.status, t.group = RESEND, ACT
        t.step = Step("resend", "Resend", text=text, href=href)
        return
    if st == rules.UNCLEAR and kind == "review":
        t.status, t.group = REVIEW, ACT
        t.step = Step("review", "Read their reply", text=text, href=href, perm="view")
        return
    if kind == "close":
        t.status, t.group = CLOSED, NOTHING
        t.step = Step("none", text=text)
        return
    if kind in LE_KINDS:  # sent; the playbook hands off to LE (an issuer acting on LE process only)
        t.status, t.group = HANDOFF, ACT
        t.step, drafted = _le_step(cid, route, instrument, kind, text, href, board)
        t.detail = drafted or (f"ticket {p.ticket}" if p.ticket else "")
        t.extra = _pack(cid, p.key, board)
        _counsel(t, p, move, board)
        return
    if p.overdue:
        t.status, t.group = OVERDUE, ACT
        t.step = Step("chase", "Chase", text=text, href=href)
        return
    t.status = ACKNOWLEDGED if st == rules.ACKNOWLEDGED else AWAITING
    if p.ticket:
        t.detail = f"ticket {p.ticket}"
    if kind in ("wait", None):
        t.group = WAITING
        t.step = Step("wait", "", text=text)
        follow = _follow_up(cid, a, p) if p.due_at is not None and p.due_at - now <= FOLLOW_UP_SOON else None
        if follow is not None:  # the reply is nearly due: a status request on the request (never a new stop order)
            t.extra.append(follow)
        return
    # anything else the request's next action asks of us (re-trace, check, chase on an unclear reply)
    t.group = ACT if kind in rp.ACTIONABLE else WAITING
    t.step = Step(kind, rp._primary_label(kind, href or "") if href else "", text=text, href=href)


def _secured(cid: int, t: Target, p, kind: str | None, text: str, href: str | None, route, instrument, board: Board,
             now: datetime) -> None:
    """A hold / freeze a person confirmed. With a step left for us it stays in Act now: a temporary hold (or a freeze
    with a lapse clock) LE must turn into an order, a deadline of theirs on our side, a lapsed hold to ask about."""
    frozen = p.status == rules.FROZEN
    t.status = FROZEN if frozen else HELD
    exp = p.hold_expires_at
    gone = p.path.lapsed if p.path is not None else None
    clock = exp is not None or gone is not None
    soon = gone is not None or (exp is not None and exp - now <= HOLD_SOON)
    if kind not in rp.ACTIONABLE or not href:
        t.group = SECURED
        t.step = Step("none", text=f"Nothing to do — {'frozen' if frozen else 'held'}." + (f" {text}" if text else ""))
        return
    le = kind in LE_KINDS
    # a freeze with no lapse clock is secured while LE prepares the order; a hold (or a lapsing freeze) is not
    t.group = SECURED if frozen and le and not clock else ACT
    drafted = None
    if le:
        t.step, drafted = _le_step(cid, route, instrument, kind, text, href, board)
        if soon and not drafted and t.step.label:
            t.step.label = "Brief LE before the hold lapses"
    elif gone is not None and kind in ("chase", "answer"):
        t.step = Step(kind, "Ask whether the hold still stands", text=text, href=href)
    else:
        t.step = Step(kind, rp._primary_label(kind, href), text=text, href=href)
    if gone is not None:
        t.detail = f"hold lapsed {gone['at']:%d %b}" + (f" · {drafted}" if drafted else "")
    elif exp is not None:
        t.detail = f"LE must act by {exp:%d %b %Y}" + (f" · {drafted}" if drafted else "")
    elif drafted:
        t.detail = drafted
    t.extra = _pack(cid, p.key, board)


def _ghost(cid: int, t: Target, a, o: StopOrder) -> None:
    """A stop order sent, then marked superseded: Block status no longer follows it, but the target was contacted."""
    t.status, t.group = AWAITING, ACT
    when = f" {o.sent_at:%d %b %Y}" if o.sent_at else ""
    t.detail = f"request #{o.id} sent{when}, then marked superseded"
    t.step = Step("open", f"Open request #{o.id}", href=f"/cases/{cid}/stop-orders/{o.id}", perm="view",
                  text=(f"Request #{o.id} to {a.name} was sent, then marked superseded, so Block status no longer "
                        f"follows it. Check its status on its page before writing to {a.name} again (a follow-up is a "
                        "status request on it, never a second stop order)."))
    t.skip = ("sent", f"o{o.id}")
    t.sent_ref = f"o{o.id}"


def _freeze_open(cid: int, t: Target, drafts: list) -> None:
    """Funds traced, but the only requests sent asked for records (an information request): no freeze was asked yet.
    The freeze request is the step while the reply is merely awaited, else the row's second button; a draft of it
    already made is opened, never drafted again."""
    t.freeze_open = True
    p = t.primary
    handoff = t.status == HANDOFF  # an issuer acting on LE process only: the letter is a notice
    text = (f"Only a records / information request went to {t.name} ({req_no(p)}): it asks for no freeze. Send "
            + ("the notice (it flags the wallets; LE's request freezes them)" if handoff else "the freeze request")
            + " from the latest trace.")
    if drafts:
        d = drafts[-1]
        ask = Step("send", f"Open & send {'notice' if handoff else 'freeze request'} {req_no(d)}", text=text,
                   href=_item_url(cid, d))
        t.skip = ("draft", d.key)
        t.notice_only = handoff
    else:
        ask = _notice(cid, t, "Send notice (flags the wallets)" if handoff else "Draft freeze request")
        ask.text = text
        t.draftable, t.notice_only = True, handoff
    t.detail = (t.detail + " · " if t.detail else "") + "no freeze asked yet"
    t.group = ACT
    if t.status in FREEZE_FIRST:
        old = t.step
        t.step = ask
        if old.label:
            t.extra.insert(0, old)
    else:
        t.extra.insert(0, ask)


def _follow_up(cid: int, a, p) -> Step | None:
    """'Draft a follow-up to request #12': the status request linked to that request (never a second stop order)."""
    if a is None or p.order is None and p.letter is None:
        return None
    refs = desk.sent_references(a)
    ref = next((r["value"] for r in refs if (p.order is not None and r["order"] is p.order)
                or (p.letter is not None and r["corr"] is p.letter)), None)
    if ref is None:
        return None
    return Step("follow_up", f"Draft a follow-up to request {req_no(p)}",
                text=f"A status request on request {req_no(p)} (not a new stop order).",
                href=f"/cases/{cid}/authorities/{a.key}?template=status_request&ref={ref}#generate")


def _deadline(t: Target, p, now: datetime) -> None:
    ln = t.le_letter
    if t.status == LE_ROUTE and ln is not None and ln["sent"] and ln["due_at"] is not None:  # the LE letter's reply
        t.deadline, t.deadline_label = ln["due_at"], "LE reply due"
        return
    if p is None:
        return
    gone = p.path.lapsed if p.path is not None else None
    if gone is not None:
        t.deadline = gone["at"]
        t.deadline_label = "hold lapsed" if gone.get("kind") == "hold_expired" else "deadline passed"
    elif t.status in (HELD, FROZEN) and p.hold_expires_at is not None:
        t.deadline, t.deadline_label = p.hold_expires_at, "hold lapses"
    elif p.next_deadline is not None:
        t.deadline = p.next_deadline["due_at"]
        t.deadline_label = p.next_deadline.get("label") or "deadline"
    elif t.status in (AWAITING, ACKNOWLEDGED, OVERDUE, HANDOFF, LE_ROUTE) and p.due_at is not None:
        t.deadline, t.deadline_label = p.due_at, ("LE reply due" if t.status == LE_ROUTE else "reply due")


def _skip(cid: int, t: Target, sent: list, run) -> None:
    """Whether the generator ("Draft freeze requests") drafts this target, and why not (`SKIP_TEXT`). With no freeze
    asked yet (`freeze_open`), a sent records request never counts as the request a new one would repeat. A draft is
    never replaced by the bulk button: one from an earlier trace gets its own "Redraft from trace #N" on the row."""
    if t.freeze_open:
        sent = [r for r in sent if _asks_freeze(r)]
    latest = max(sent, key=lambda r: (r.requested_at or datetime.min.replace(tzinfo=UTC), r.key)) if sent else None
    if latest is not None:
        t.sent_ref = latest.key
    if t.candidate is None or t.authority is None or t.skip is not None:
        return
    p = t.primary
    if p is None:  # nobody asked yet: the row's own step says whether a letter applies
        if not t.draftable:
            t.skip = ("gated", None) if t.step.kind in LE_KINDS else ("no_lever", None)
    elif t.status == PREPARED:
        t.skip = ("prepared", p.key)
    elif t.status in SKIP_CODE:
        t.skip = (SKIP_CODE[t.status], p.key)
    elif t.draftable:
        return
    elif latest is not None:
        t.skip = ("sent", latest.key)
    elif t.status == DRAFT_READY and p.order is not None and run is not None and p.order.trace_run_id != run.id:
        t.skip = ("draft_old", p.key)
        t.extra.append(Step("redraft", f"Redraft from trace #{run.id}", post=f"/cases/{cid}/stop-orders",
                            fields={"entity": t.candidate.entity_name, "redraft": "1"},
                            text=f"Replaces draft {req_no(p)} with one built from the latest trace."))
    elif t.status == DRAFT_READY:
        t.skip = ("draft", p.key)
    else:
        t.skip = ("no_lever", None)


def generator_plan(board: Board, only: str | list[str] | None = None, *, redraft: bool = False
                   ) -> tuple[list[str], list[tuple[Target | None, str, str | None]]]:
    """(candidate names the generator drafts, [(target, SKIP_TEXT code, request key)] it leaves out). `only`: the
    entity name(s) asked for (a row's Draft request; the API's `entities`); a name that is no candidate of the latest
    trace is skipped as "unknown". `redraft` (a row's "Redraft from trace #N", with `only`): a draft from an earlier
    trace is replaced too; never in bulk."""
    names: list[str] = []
    skipped: list[tuple[Target | None, str, str | None]] = []
    targets = [t for t in board.targets if t.candidate is not None and t.authority is not None]
    wanted = {x.strip() for x in ([only] if isinstance(only, str) else only or []) if x and x.strip()}
    if wanted:
        targets = [t for t in targets if t.candidate.entity_name in wanted]
        skipped += [(None, "unknown", None)] * len(wanted - {t.candidate.entity_name for t in targets})
    for t in targets:
        if t.draftable or (redraft and wanted and t.skip is not None and t.skip[0] == "draft_old"):
            names.append(t.candidate.entity_name)
        elif t.skip is not None:
            skipped.append((t, t.skip[0], t.skip[1]))
    return names, skipped


def redraft_keys(board: Board, names: list[str]) -> set[str]:
    """The drafts from an earlier trace a row's "Redraft from trace #N" replaces (the request gate's `replace`)."""
    return {t.skip[1] for t in board.targets if t.candidate is not None and t.candidate.entity_name in names
            and t.skip is not None and t.skip[0] == "draft_old" and t.skip[1]}




def owner_addresses(board: Board, names: list[str]) -> dict[str, list[tuple[str, ...]]]:
    """Candidate name -> the deposit addresses the Recovery plan's owner moves attribute to that service and no request
    cites yet ((chain, address)), and its swap / order addresses ((chain, address, "records"): their records asked
    for): the generator cites them in the same stop order (one letter covers both, the freeze ask first)."""
    out: dict[str, list[tuple[str, ...]]] = {}
    for t in board.targets:
        if t.candidate is None or t.candidate.entity_name not in names:
            continue
        for m in t.owner_moves:
            if rp.owner_cites(m):
                out.setdefault(t.candidate.entity_name, []).extend(rp.owner_cites(m))
    return out


def gate_skip(d) -> tuple[str, str | None]:
    """The generator flash's (SKIP_TEXT code, request key) for a request-gate decision that refused a stop order."""
    from app.domain import request_gate as rg

    if d is None:
        return "refused", None
    if d.kind in (rg.OPEN_EXISTING, rg.ADD_TO_DRAFT):
        return ("prepared" if d.request.prepared is not None else "draft"), d.key
    if d.kind == rg.FOLLOW_UP_ONLY:
        return "sent", d.key
    if d.kind == rg.LE_BRIEF_ONLY:
        if d.request is None:
            return "gated", None
        return ("declined" if d.request.status in (rules.DECLINED, rules.DECLINED_NO_ASSETS) else "le_only"), d.key
    return "refused", None


def generator_result(board: Board, names: list[str], created: list, gated: dict | None = None
                     ) -> tuple[list[tuple], list[Target]]:
    """After the generator ran on `names`: ([(target, code, key)] for each planned target it drafted nothing for — the
    request gate's reason (`gated`: candidate name -> its Decision, services.generate_stop_orders), else "refused"
    (its own playbook gate, no identifiers) —, [the drafted notice-only targets])."""
    made = {o.entity_id for o in created if o.entity_id is not None}
    refused: list[tuple] = []
    notices: list[Target] = []
    for t in board.targets:
        if t.candidate is None or t.candidate.entity_name not in names:
            continue
        ent = t.authority.entity if t.authority is not None else None
        if ent is None or ent.id not in made:
            refused.append((t, *gate_skip((gated or {}).get(t.candidate.entity_name))))
        elif t.notice_only:
            notices.append(t)
    return refused, notices


def skip_text(code: str, ref: str | None, t: Target | None = None) -> str:
    """One skipped target's reason (`ref`: a validated request key). Already contacted: the row's own next step (or
    the reply it waits for), never a button the row does not have."""
    text = SKIP_TEXT[code].format(ref=ref_text(ref))
    if code in ("le_only", "le_route") and t is not None and t.step.label:
        return f"{text}; next step on its row: “{t.step.label}”"
    if code != "sent" or t is None:
        return text
    if t.step.label:
        return f"{text}: next step on its row: “{t.step.label}”"
    if t.deadline is not None:
        return f"{text}: wait for the reply ({t.deadline_label or 'due'} {t.deadline:%d %b %Y})"
    return f"{text}: wait for the reply"


SKIP_PARAM_RE = re.compile(r"(entity-\d{1,12}|cand-[a-z0-9-]{1,40}|-):([a-z_]{1,20}):([oc]\d{1,12})?")
KEY_RE = re.compile(r"entity-\d{1,12}|cand-[a-z0-9-]{1,40}")


def skip_param(skipped: list[tuple[Target | None, str, str | None]]) -> str:
    """The flash query value: 'entity-5:le_only:o12,entity-4:sent:c7'."""
    return ",".join(f"{t.key if t is not None else '-'}:{code}:{ref or ''}" for t, code, ref in skipped)[:1500]


def skip_lines(raw: str, board: Board | None) -> list[str]:
    """The flash message's lines from the query value (validated: keys, codes and refs only; names and reasons come
    from the board and SKIP_TEXT, never from the query)."""
    out: list[str] = []
    for part in (raw or "").split(",")[:40]:
        m = SKIP_PARAM_RE.fullmatch(part.strip())
        if m is None or m.group(2) not in SKIP_TEXT:
            continue
        t = board.find(m.group(1)) if board is not None else None
        name = t.name if t is not None else "the selected target"
        out.append(f"{name}: {skip_text(m.group(2), m.group(3), t)}")
    return out


def notice_lines(raw: str, board: Board | None) -> list[str]:
    """The flash's lines for the drafted notice-only targets (the query names their keys; names from the board)."""
    out: list[str] = []
    for key in (raw or "").split(",")[:40]:
        t = board.find(key.strip()) if board is not None and KEY_RE.fullmatch(key.strip()) else None
        if t is not None and t.group == CLAIM:  # frozen on-chain already: the notice ties the freeze to this case
            out.append(f"{t.name}: drafted as a notice (it links the on-chain freeze to this case): {t.name} acts on "
                       "LE process only, so brief LE in parallel (its row)")
        elif t is not None:
            out.append(f"{t.name}: drafted as a notice only (it flags the wallets): {t.name} acts on LE process "
                       "only, so brief LE in parallel (its row)")
    return out


# --------------------------------------------------------------------------- the Stop orders table
def order_groups(orders: list[StopOrder]) -> list[tuple[StopOrder, list[StopOrder]]]:
    """[(order, earlier superseded drafts)] newest first: each superseded draft folds into the next order for the same
    entity (its successor); one discarded after the latest folds into the latest; an entity with only superseded
    drafts shows its newest. Sent orders always show."""
    by: dict[Any, list[StopOrder]] = {}
    for o in sorted(orders, key=lambda x: x.id):
        by.setdefault(o.entity_id if o.entity_id is not None else ("o", o.id), []).append(o)
    out: list[list] = []
    for items in by.values():
        pending: list[StopOrder] = []
        last: list | None = None
        for o in items:
            if o.status == StopOrderStatus.SUPERSEDED and o.sent_at is None:
                pending.append(o)
                continue
            last = [o, pending]
            out.append(last)
            pending = []
        if pending:
            if last is not None:
                last[1] = last[1] + pending
            else:
                out.append([pending[-1], pending[:-1]])
    out.sort(key=lambda x: -x[0].id)
    return [(o, sorted(e, key=lambda x: -x.id)) for o, e in out]


def discard(db: Session, case, order: StopOrder, *, duplicates: str | None, access,
            now: datetime | None = None, reason: str = "duplicate_draft", why: str | None = None) -> list:
    """Discard a generated draft the board flags as a duplicate (the route checks that): each prepared e-mail of its
    letters is cancelled first (app.domain.mail_send.cancel: nothing of it can be sent any more), the order is
    superseded with the reason kept on it (notes, `identifiers.discarded`, a status_history entry), and its draft
    letters are marked discarded (the letter page offers no E-mail / Mark sent for them). Returns the cancelled MailMessages. Raises ValueError (the
    route's 409). The route audits."""
    from app.db.models import MailDirection, MailMessage, MailStatus
    from app.domain import mail_send

    if order.status != StopOrderStatus.DRAFT:
        raise ValueError("only a draft can be discarded")
    if order.origin == StopOrderOrigin.IMPORTED:
        raise ValueError("an imported stop order is not a generated draft: change its status instead")
    from app import services

    busy = services.mail_pending(db, [order])
    if busy is not None and busy.status != MailStatus.PREPARED:  # sending / sent / unknown, an expired checklist
        raise ValueError(f"e-mail #{busy.id} of this draft may already be out: settle it first (record it as sent, or "
                         "cancel / retire it)")
    now = now or _now()
    ref = duplicates if duplicates and REF_RE.fullmatch(duplicates) else None
    letters = [c for c in order.correspondence if c.status == CorrespondenceStatus.DRAFT]
    cancelled: list = []
    if letters:
        for mm in db.scalars(select(MailMessage).where(MailMessage.correspondence_id.in_([c.id for c in letters]),
                                                       MailMessage.direction == MailDirection.OUT,
                                                       MailMessage.status == MailStatus.PREPARED)).all():
            try:
                cancelled.append(mail_send.cancel(db, access, mm))
            except (mail_send.SendError, LookupError) as err:
                raise ValueError(f"cancel prepared e-mail #{mm.id} first ({err})") from None
    order.status = StopOrderStatus.SUPERSEDED
    ids = dict(order.identifiers or {})
    ids["discarded"] = {"at": now.isoformat(timespec="seconds"), "duplicates": ref,
                        "cancelled_mail": [m.id for m in cancelled]}
    user = getattr(access, "user", None)
    ids["status_history"] = list(ids.get("status_history") or []) + [
        {"status": "superseded", "previous": "draft", "at": now.isoformat(), "by": getattr(user, "id", None),
         "reason": reason, "duplicates": ref}]
    if why:
        ids["discarded"]["why"] = why
    order.identifiers = ids
    note = f"Discarded {now:%d %b %Y %H:%M} UTC" + (f": duplicates request {ref_text(ref)}" if ref else
                                                    f": {why}" if why else "")
    order.notes = (order.notes + "\n" if order.notes else "") + note
    for c in letters:
        c.meta = {**(c.meta or {}), "discarded": {"at": now.isoformat(timespec="seconds"), "order": order.id,
                                                  "duplicates": ref}}
    db.commit()
    return cancelled


def discard_letter(db: Session, case, corr, *, access, why: str, now: datetime | None = None) -> list:
    """Discard a draft letter the board flags as pointless (`pointless_flag`: the provider answered LE only / declined,
    or its playbook gates us; the route checks that): each prepared e-mail of it is cancelled first
    (app.domain.mail_send.cancel), and the letter is marked `meta.discarded` (reason "pointless"): no request any more
    (app.blocks.status skips it), never e-mailed (mail_compose.superseded_text) nor marked sent. Returns the cancelled
    MailMessages. Raises ValueError (the route's 409): not a draft, or an e-mail of it that may be out. The route
    audits."""
    from app import services
    from app.db.models import CorrespondenceDirection, MailDirection, MailMessage, MailStatus
    from app.domain import mail_send

    if corr.status != CorrespondenceStatus.DRAFT or corr.direction != CorrespondenceDirection.OUT:
        raise ValueError("only an outbound draft can be discarded")
    busy = services.mail_pending(db, [], [corr])
    if busy is not None and not (busy.status == MailStatus.PREPARED and busy.transport != "manual"):
        raise ValueError(f"e-mail #{busy.id} of this draft may already be out: settle it first (record it as sent, or "
                         "cancel / retire it)")
    now = now or _now()
    cancelled: list = []
    for mm in db.scalars(select(MailMessage).where(MailMessage.correspondence_id == corr.id,
                                                   MailMessage.direction == MailDirection.OUT,
                                                   MailMessage.status == MailStatus.PREPARED)).all():
        try:
            cancelled.append(mail_send.cancel(db, access, mm))
        except (mail_send.SendError, LookupError) as err:
            raise ValueError(f"cancel prepared e-mail #{mm.id} first ({err})") from None
    user = getattr(access, "user", None)
    corr.meta = {**(corr.meta or {}), "discarded": {"at": now.isoformat(timespec="seconds"), "reason": "pointless",
                                                    "why": why, "by": getattr(user, "id", None),
                                                    "cancelled_mail": [m.id for m in cancelled]}}
    db.commit()
    return cancelled


def discarded(corr) -> bool:
    """A draft letter of a discarded duplicate stop order (never e-mailed or marked sent)."""
    return bool((getattr(corr, "meta", None) or {}).get("discarded"))


def fmt_usd(v: float | Decimal | None) -> str:
    return rp.money(float(v)) if v else "—"
