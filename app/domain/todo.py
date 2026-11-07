"""The case's To do list: everything that should be done for the case, one list, with priority and due date.

    tasks = build(db, case, access)              # list[Task]: derived + manual, each with its state (open first)
    open_ = open_tasks(tasks)                    # sorted: overdue → priority → due date
    row = create(db, access, title=…, priority="P2", due=…, assignee_id=…, note=…)   # a manual task
    row = apply(db, access, task, "snooze", days=3)    # done | reopen | snooze | dismiss | edit (the route audits)

**Derived tasks** are read from the case on every build (nothing is stored for them until a person acts on one), each
with a stable source key, a one-line why, a due date from its source clock (or none) and ONE action — a link or a
form post to an existing route, the same step the source page offers:

* **board** — the freeze & stop-order board (app.blocks.freeze_board, which passes every step through the request
  gate): each "Act now" / "Frozen — confirm or claim it" row (send a draft, chase an overdue reply, an LE hand-off, add
  the officer's contact, confirm a hold or a freeze), each row of the LE / court route with a step to take, and each
  duplicate or pointless draft the board flags (discard it).
* **plan** — the Recovery plan's actionable moves that are no provider's row: identify the wallets' owners, re-trace,
  funds-left alerts, watch-list moves, funds that just arrived at a provider (the plan the board was built from).
* **blocks** — Block status rows the board does not cover (letters to LE / counsel, Outlook e-mails to review): a
  reply to read or confirm, an overdue reply; and the path clocks (a provider's submit-by, a playbook clock, a
  confirmed hold's expiry) falling due within `CLOCK_AHEAD` or passed within `CLOCK_GRACE`.
* **mailbox** — inbound mail matched to the case waiting for triage, the system's unassigned queue (system admins), and
  old Outlook checklists to retire or record as sent.
* **evidence** — unconfirmed type suggestions (app.evidence_intel) and the evidence the next moves still lack.
* **setup** — no trace yet, no sender profile, a sender profile whose instrument has no authority document ("Sign the
  Letter of Authorisation and attach it as the sender profile's authority document": an unsigned draft may exist
  outside Aegis), an LE contact with no officer or e-mail, and the optional consents that are off (P3 suggestions).

**Manual tasks** are rows of `case_tasks` (migration 0012) with the key "manual:<id>".

**Priority** (derived; a person can override it, `priority_override`):
P1 — overdue, due within `P1_DUE` (48 h), or money at stake ≥ `P1_MONEY_USD` with urgency (the Recovery plan's urgency
≥ `URGENT`, a frozen balance to claim, a target nobody asked yet, a reply to confirm, an LE hand-off due); P2 — due
within `P2_DUE` (7 days) or money at stake ≥ `MONEY_USD`; P3 — the rest (setup, optional). Some sources raise their floor (a duplicate draft that could still be e-mailed, a reply
to triage, the authority document letters claim is attached: at least P2).

**State.** A person marks a task done, snoozes it (1 / 3 / 7 days), dismisses it (with a note) or edits its priority,
due date and assignee (and a manual task's title and note). A derived task's row keeps `fingerprint`, what its source
said then: a done / dismissed / snoozed derived task stays hidden until its state ends (the snooze lapses) or the
source changes materially (a new fingerprint: it reopens), and one whose source condition clears closes itself as
"done (resolved)" (`RESOLVED`, no `done_by`; never while its source failed to read). Those automatic transitions are
written by `build(persist=True)` (the tab and the Overview card) without an audit row; every person's action is
audited by the route (ids and field names only). The fingerprint is the source's own state, never the viewer's (no
action label, nothing that depends on Send, the pack or prepared e-mails being allowed), and only a viewer who sees a
task's whole source changes its row (`_full`: investigators and up; what the next moves lack, case admins): a
read-only member's view writes nothing, and a stored task the viewer could not have derived (a sensitive move below
view_restricted, the unassigned mail queue, evidence they may not see) is neither shown to them nor closed.

**Who sees what.** External members see nothing (the tab and routes need read_only). Read-only members see the list
without buttons; investigators and up act (`ACT_PERM`); each action button also needs its own permission (a Send, a
discard, the sender profile: case admins). Contact details and complaint references are masked below
manage_le_contacts (desk.contact_mask), a person's free-text owner name below view_restricted, and the Recovery plan's
moves built from reply content are left out below view_restricted (as on the plan).

Advisory and read-only over the case: nothing here drafts, sends or confirms anything; the action is the source's own.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import (
    AIMode,
    CaseMember,
    CaseTask,
    MailDirection,
    MailMessage,
    MailStatus,
    User,
)

log = logging.getLogger(__name__)

P1, P2, P3 = "P1", "P2", "P3"
PRIORITIES = (P1, P2, P3)
RANK = {P1: 0, P2: 1, P3: 2}
PRIORITY_LABELS = {P1: "P1 — now", P2: "P2 — this week", P3: "P3 — when there is time"}
P1_DUE = timedelta(hours=48)  # due within this (or overdue): P1
P2_DUE = timedelta(days=7)  # due within this: P2
P1_MONEY_USD = 10_000.0  # money at stake from which an urgent task is P1
MONEY_USD = 50.0  # money at stake from which a task is P2 (below: dust, rp.OWNER_MIN_USD)
URGENT = 2.0  # the Recovery plan's urgency (1–4) that makes money at stake P1
CLOCK_AHEAD = timedelta(days=14)  # a path clock falling due within this is a task
CLOCK_GRACE = timedelta(days=3)  # a passed clock stays a task this long (bs.CLOCK_GRACE)
RECENT = timedelta(days=14)  # "Done recently"
SNOOZE_DAYS = (1, 3, 7)
MAX_TITLE, MAX_NOTE, MAX_DISMISS_NOTE, MAX_WHY = 300, 4000, 500, 280
ACT_PERM = "edit"  # investigators and up act on the list (done / snooze / dismiss / edit / add)

OPEN, DONE, SNOOZED, DISMISSED, RESOLVED = "open", "done", "snoozed", "dismissed", "resolved"
STATUSES = (OPEN, DONE, SNOOZED, DISMISSED, RESOLVED)
STATUS_LABELS = {OPEN: "open", DONE: "done", SNOOZED: "snoozed", DISMISSED: "dismissed", RESOLVED: "done (resolved)"}
CLOSED = frozenset({DONE, DISMISSED, RESOLVED})
OPS = ("done", "reopen", "snooze", "dismiss", "edit")

BOARD, PLAN, BLOCKS, MAILBOX, EVIDENCE, SETUP, MANUAL = ("board", "plan", "blocks", "mailbox", "evidence", "setup",
                                                          "manual")
ROUTE = "route"
SOURCES = {ROUTE: "Getting the money back", BOARD: "Freeze & stop-order board", PLAN: "Recovery plan", BLOCKS: "Block status", MAILBOX: "Mailbox",
           EVIDENCE: "Evidence", SETUP: "Case setup", MANUAL: "Manual"}
MANUAL_PREFIX = "manual:"
KEY_RE = re.compile(r"[a-z]{3,10}:[A-Za-z0-9:._@+-]{1,240}")
_SAFE = re.compile(r"[^A-Za-z0-9:._@+-]+")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class TodoError(ValueError):
    """A refused change (HTTP 400; `status` 403 / 404 where it says so)."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _aware(v: datetime | None) -> datetime | None:
    return v if v is None or v.tzinfo else v.replace(tzinfo=UTC)


def _fp(*parts: Any) -> str:
    """A derived task's fingerprint: what its source says now (a change reopens a done / dismissed / snoozed task)."""
    return hashlib.sha256("|".join("" if p is None else str(p) for p in parts).encode()).hexdigest()[:32]


def _cut(text: str | None, n: int = MAX_WHY) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def _key(prefix: str, *parts: Any) -> str:
    raw = ":".join(str(p) for p in parts if p not in (None, ""))
    k = f"{prefix}:{_SAFE.sub('-', raw)}"
    return k if len(k) <= 200 else f"{prefix}:{hashlib.sha256(raw.encode()).hexdigest()[:40]}"


def anchor(key: str) -> str:
    """The task's row id on the To do tab (`#t-<anchor>`): keys carry colons and addresses."""
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def relative(at: datetime | None, now: datetime) -> str:
    """'in 5h', 'in 3 days', '2 days ago', 'today' — the due date relative to now."""
    if at is None:
        return ""
    h = (at - now).total_seconds() / 3600
    if abs(h) < 1:
        return "now"
    if h > 0:
        return f"in {round(h)}h" if h < 48 else f"in {round(h / 24)} days"
    return f"{round(-h)}h ago" if -h < 48 else f"{round(-h / 24)} days ago"


def derive_priority(*, due: datetime | None, value: float | None, urgent: bool, now: datetime,
                    floor: str = P3) -> str:
    """P1: overdue, due within P1_DUE, or ≥ P1_MONEY_USD at stake with urgency; P2: due within P2_DUE or ≥ MONEY_USD
    at stake; else P3 — never below `floor` (a source's own minimum)."""
    if due is not None and due <= now + P1_DUE or value and value >= P1_MONEY_USD and urgent:
        p = P1
    elif due is not None and due <= now + P2_DUE or value and value >= MONEY_USD:
        p = P2
    else:
        p = P3
    return p if RANK[p] <= RANK[floor] else floor


@dataclass
class Action:
    """The task's one-click action: a link (`href`) or a form (`post` with `fields`), shown to a member whose role
    allows `perm` (an app.core.permissions action, "pack" as on the board, "system_admin")."""

    label: str
    href: str | None = None
    post: str | None = None
    fields: dict = field(default_factory=dict)
    perm: str = "view"


@dataclass
class Task:
    key: str
    title: str
    source: str
    why: str = ""
    priority: str = P3  # effective (the person's override, else derived)
    derived_priority: str = P3
    due: datetime | None = None  # effective (the person's override, else the source clock)
    derived_due: datetime | None = None
    due_label: str = ""  # what the date is ("reply due", "hold lapses")
    action: Action | None = None
    value: float | None = None
    fingerprint: str = ""
    status: str = OPEN
    assignee_id: int | None = None
    assignee: str | None = None  # display name
    note: str | None = None
    snoozed_until: datetime | None = None
    dismissed_note: str | None = None
    done_at: datetime | None = None
    done_by: int | None = None
    row: Any = field(default=None, repr=False, compare=False)  # its CaseTask, if any
    sensitive: bool = False  # built from reply content (a Recovery plan move): never quoted to the model unless allowed
    full: bool = True  # this viewer derives it as every member who acts on the list does (`_full`): it may change its row
    overridden: tuple = ()  # the fields a person overrode: priority, due

    @property
    def manual(self) -> bool:
        return self.source == MANUAL

    @property
    def derived(self) -> bool:
        return not self.manual

    @property
    def anchor(self) -> str:
        return anchor(self.key)

    @property
    def source_label(self) -> str:
        return SOURCES.get(self.source, self.source)

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)

    @property
    def is_open(self) -> bool:
        return self.status == OPEN

    def overdue(self, now: datetime) -> bool:
        return self.due is not None and self.due < now


@dataclass
class _Ctx:
    db: Session
    case: Any
    access: Any
    now: datetime
    mask: Any
    tasks: list[Task] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    board: Any = None
    rows: list | None = None  # the case's block rows when the caller has them (the Overview's one pass)
    next_moves: list = field(default_factory=list)  # (move, task) of the board's and the plan's tasks: their evidence

    @property
    def cid(self) -> int:
        return self.case.id

    def add(self, t: Task) -> Task:
        t.title, t.why = _cut(self.mask.text(t.title), MAX_TITLE), _cut(self.mask.text(t.why))
        t.due = t.derived_due = _aware(t.due)
        if not any(x.key == t.key for x in self.tasks):
            self.tasks.append(t)
        return t

    def has(self, prefix: str) -> bool:
        return any(t.key.startswith(prefix) for t in self.tasks)


# --------------------------------------------------------------------------- derived: the freeze & stop-order board
def _step_action(s) -> Action | None:
    if s is None or not s.label or not (s.href or s.post):
        return None
    return Action(s.label, href=s.href, post=s.post, fields=dict(s.fields or {}), perm=s.perm or "draft_letter")


def _board(c: _Ctx) -> None:
    from app.blocks import freeze_board as fb

    board = c.board = c.board if c.board is not None else fb.build(c.db, c.case, c.access, now=c.now, rows=c.rows)
    for t in board.targets:
        s = t.step
        hot = t.group in (fb.ACT, fb.CLAIM) or (t.group == fb.LE_GROUP and bool(s.label))
        if hot and (s.label or s.text):
            value = t.value if t.value is not None else t.traced_usd  # an on-chain reading beats the traced bound
            urgent = t.group == fb.CLAIM or (t.move is not None and t.move.urgency >= URGENT) or t.status in (
                fb.NOT_CONTACTED, fb.TO_CONFIRM, fb.HANDOFF)
            money = (f"{fb.fmt_usd(t.value)} at stake" if t.value else
                     f"up to {fb.fmt_usd(t.traced_usd)} traced" if t.traced_usd else "")
            status = t.status_label + (f" ({t.detail})" if t.detail else "")
            lead = s.lead if s.label else ""
            if lead and lead.lower().startswith(t.status_label.lower()):
                status = t.detail  # "Reply overdue: send a status request" says the status itself
            why = " · ".join(x for x in (status, money, lead) if x)
            task = c.add(Task(
                key=_key(BOARD, t.key), source=BOARD, title=f"{t.name}: {s.label or s.lead or t.status_label}",
                why=why, due=t.deadline, due_label=t.deadline_label, value=value,
                action=_step_action(s) or Action("Open the board row", href=f"/cases/{c.cid}?tab=authorities#fb-{t.key}"),
                fingerprint=_fp(t.status, t.group, s.kind, t.primary.key if t.primary is not None else None, s.le)))
            task.derived_priority = derive_priority(due=task.due, value=value, urgent=urgent, now=c.now,
                                                    floor=P2 if t.group in (fb.ACT, fb.CLAIM) else P3)
            if t.move is not None:
                c.next_moves.append((t.move, task))
        for d in t.duplicates:
            task = c.add(Task(
                key=_key(BOARD, "dup", f"o{d['order_id']}"), source=BOARD,
                title=f"Discard duplicate draft {d['no']} ({t.name})", why=d.get("text") or "",
                action=Action("Discard", post=f"/cases/{c.cid}/stop-orders/{d['order_id']}/discard", perm="manage_case"),
                fingerprint=_fp("dup", d.get("of_key"), d.get("answer"))))
            task.derived_priority = P2  # it must never be e-mailed beside the request it repeats
        for d in t.pointless:
            act = None if d.get("busy") else Action("Discard", post=d.get("post"), perm="manage_case")
            task = c.add(Task(
                key=_key(BOARD, "pointless", f"{d.get('kind', 'x')[:1]}{d.get('id')}"), source=BOARD,
                title=f"Discard pointless draft {d.get('no')} ({t.name})",
                why=(d.get("text") or "") + (" Its e-mail may already be out: settle that e-mail first." if d.get("busy")
                                             else ""),
                action=act or Action("Open the board row", href=f"/cases/{c.cid}?tab=authorities#fb-{t.key}"),
                fingerprint=_fp("pointless", d.get("busy"), d.get("prepared"))))
            task.derived_priority = P2


# --------------------------------------------------------------------------- derived: the Recovery plan's own moves
def _plan(c: _Ctx) -> None:
    from app.blocks import recovery as rp

    plan = getattr(c.board, "plan", None)
    if plan is None:
        return
    restricted = c.access.can("view_restricted")
    for m in plan.moves:
        # a provider's move is its board row; an owner move is on the board too (its service's row, or one of its own)
        if m.key.startswith("owner:") or (m.authority is not None and ":" not in m.key) or not m.actionable:
            continue
        if m.sensitive and not restricted:
            continue
        v = rp.move_view(m, c.access, c.mask, None, c.now)
        primary = next((a for a in v["actions"] if a.get("primary")), v["actions"][0] if v["actions"] else None)
        act = (Action(primary["label"], href=primary.get("href"), post=primary.get("post"),
                      fields=dict(primary.get("fields") or {}), perm=primary.get("perm", "view"))
               if primary is not None and (primary.get("href") or primary.get("post")) else None)
        due = m.clock["due_at"] if m.clock else None
        # the move's own primary action (before move_view filters the actions by role): what every member's list says
        own = next((a for a in m.actions if a.get("primary")), m.actions[0] if m.actions else None) or {}
        task = c.add(Task(
            key=_key(PLAN, m.key), source=PLAN, title=v["title"], why=" · ".join(x for x in (
                _cut(v["text"], 160), v["basis"] if m.value else "") if x),
            due=due, due_label=(m.clock or {}).get("label") or "", value=m.value, sensitive=m.sensitive,
            action=act or Action("Open the Recovery plan", href=f"/cases/{c.cid}/recovery-plan#m-{m.key}"),
            fingerprint=_fp(m.kind, m.step, own.get("label"), own.get("perm"), (m.cites or {}).get("state"))))
        task.derived_priority = derive_priority(due=task.due, value=m.value, urgent=m.urgency >= URGENT, now=c.now)
        c.next_moves.append((m, task))


# --------------------------------------------------------------------------- derived: the route to the money
def _route(c: _Ctx) -> None:
    """The steps from a frozen balance to money returned (app.domain.recovery_route): a freeze alone returns nothing."""
    from app.domain import recovery_route as rr

    plan = getattr(c.board, "plan", None)
    frozen = float((getattr(plan, "totals", None) or {}).get("secured_usd") or 0)
    if frozen <= 0:
        return
    links = {"evidence": Action("Open the Recovery plan", href=f"/cases/{c.cid}/recovery-plan"),
             "issuer": Action("Open Authorities", href=f"/cases/{c.cid}?tab=authorities")}
    for i, step in enumerate(rr.steps(rr.holder(c.db, c.case))):
        task = c.add(Task(key=_key(ROUTE, step.key), source=ROUTE, title=step.title, why=step.why, value=frozen,
                          action=links.get(step.key), fingerprint=_fp(step.key)))
        task.derived_priority = P1 if i < 2 else P2


# --------------------------------------------------------------------------- derived: Block status rows and clocks
def _blocks(c: _Ctx) -> None:
    from app.blocks import status as bs

    board = c.board
    if board is None:
        return
    covered = {t.key for t in board.targets}
    le_letters = {t.le_letter["id"] for t in board.targets if t.le_letter and t.le_letter.get("id")}
    for r in board.rows:
        if r.kind == "onchain":
            continue
        name = r.authority.name
        link = Action("Open Block status", href=f"/cases/{c.cid}/blocks#{r.key}")
        title = why = None
        if r.status == bs.SENT_REVIEW:
            if not r.needs_review:
                continue
            at = (r.review or {}).get("at")
            title = f"Review an e-mail sent from Outlook to {name}" + (f" ({at:%d %b %Y})" if at else "")
            why = "The mailbox sync could not tie it to one letter: tie it to its letter, or dismiss it."
            href = (r.next_action or {}).get("href")
            link = Action("Review it", href=href or f"/cases/{c.cid}/blocks#{r.key}", perm="view")
        elif r.authority.key in covered:
            continue  # the board's row for that provider carries its step
        elif r.needs_confirmation or r.suggestion is not None:
            title = f"Confirm what {name} replied ({r.title})"
            why = f"{r.status_text}: a person confirms every hold, freeze or return."
        elif r.needs_review:
            title, why = f"Read the reply from {name} ({r.title})", r.status_text
        elif r.status in bs.OUR_ACTION:
            title, why = f"{name}: {r.status_text} ({r.title})", _cut((r.next_action or {}).get("text"), 200)
        elif r.overdue and not (r.letter is not None and r.letter.id in le_letters):
            title = f"Chase {name}: the reply to {r.title} is overdue"
            why = f"Sent {r.requested_at:%d %b %Y}" if r.requested_at else r.status_text
        if title is None:
            continue
        task = c.add(Task(key=_key(BLOCKS, r.key), source=BLOCKS, title=title, why=why or "", due=r.due_at,
                          due_label="reply due" if r.due_at else "", action=link,
                          fingerprint=_fp(r.status, r.needs_review, r.needs_confirmation,
                                          (r.suggestion or {}).get("status"), r.overdue)))
        task.derived_priority = derive_priority(due=task.due, value=None, urgent=False, now=c.now, floor=P2)
    _clocks(c)


def _clocks(c: _Ctx) -> None:
    """The path clocks (bs.check_clocks' set): a provider's submit-by, a playbook clock, a confirmed hold's expiry."""
    from app.blocks import path as pathmod

    board = c.board
    board_due = {t.key: t.deadline for t in board.targets if t.deadline is not None}
    seen: list[tuple[str, datetime]] = []
    for r in board.rows:
        if r.kind in ("onchain", "outlook"):
            continue
        for k in r.clocks:
            if k.get("what") == "reply_by" or k.get("met") or k.get("due_at") is None:
                continue
            hold = k["what"] in pathmod.HOLD_WHAT
            if hold and (r.path is None or r.path.hold_at is None):
                continue  # a hold expiry counts once a person confirmed the hold
            due = _aware(k["due_at"])
            if not (c.now - CLOCK_GRACE <= due <= c.now + CLOCK_AHEAD):
                continue
            same = board_due.get(r.authority.key)
            if same is not None and abs((same - due).total_seconds()) < 7200:
                continue  # the board's row carries this date
            if any(x == r.key and abs((d - due).total_seconds()) < 7200 for x, d in seen):
                continue  # the same deadline read twice (their reply and the playbook)
            seen.append((r.key, due))
            what = k.get("label") or k["what"].replace("_", " ")
            title = (f"{r.authority.name}: the hold lapses {due:%d %b %Y} — brief LE before it does" if hold
                     else f"{r.authority.name}: {what} by {due:%d %b %Y %H:%M} UTC")
            why = f"{r.title}: {what}" + (f" ({k['span']} after {k['starts_label']})" if k.get("span")
                                          and k.get("starts_label") else " (stated in the reply)")
            task = c.add(Task(key=_key(BLOCKS, "clock", r.key, k.get("key") or k["what"]), source=BLOCKS,
                              title=title, why=why, due=due, due_label="hold lapses" if hold else what,
                              action=Action("Open Block status", href=f"/cases/{c.cid}/blocks#{r.key}"),
                              fingerprint=_fp(due.isoformat())))
            task.derived_priority = derive_priority(due=due, value=None, urgent=False, now=c.now)


# --------------------------------------------------------------------------- derived: the mailbox
def _mailbox(c: _Ctx) -> None:
    from app.domain import mail_compose as compose

    n, last = c.db.execute(select(func.count(MailMessage.id), func.max(MailMessage.id)).where(
        MailMessage.direction == MailDirection.IN, MailMessage.case_id == c.cid,
        MailMessage.status == MailStatus.NEEDS_REVIEW)).one()
    if n:
        oldest = c.db.scalar(select(func.min(func.coalesce(MailMessage.received_at, MailMessage.created_at))).where(
            MailMessage.direction == MailDirection.IN, MailMessage.case_id == c.cid,
            MailMessage.status == MailStatus.NEEDS_REVIEW))
        task = c.add(Task(
            key=_key(MAILBOX, "review"), source=MAILBOX,
            title=f"Triage {n} inbound e-mail{'s' if n != 1 else ''} matched to this case",
            why="The mailbox sync matched them to the case but did not file them: a case admin accepts each on its "
                "authority (a reply can carry a freeze) or rejects it.",
            due=_aware(oldest) + timedelta(days=1) if oldest else None, due_label="triage by",
            action=Action("Review inbound mail", href=f"/cases/{c.cid}/mail/review", perm="triage_mail"),
            fingerprint=_fp(last)))
        task.derived_priority = derive_priority(due=task.due, value=None, urgent=False, now=c.now, floor=P2)
    if getattr(c.access.user, "is_system_admin", False):
        n, last = c.db.execute(select(func.count(MailMessage.id), func.max(MailMessage.id)).where(
            MailMessage.direction == MailDirection.IN, MailMessage.status == MailStatus.UNASSIGNED)).one()
        if n:
            task = c.add(Task(
                key=_key(MAILBOX, "unassigned"), source=MAILBOX,
                title=f"{n} inbound e-mail{'s' if n != 1 else ''} in the mailbox that no case claimed",
                why="Organisation-wide queue (system admins): assign each to its case, or ignore it.",
                action=Action("Open the unassigned queue", href="/admin/mail/unassigned", perm="system_admin"),
                fingerprint=_fp(last)))
            task.derived_priority = P2
    manual = compose.is_manual()
    rows = c.db.scalars(select(MailMessage).where(
        MailMessage.case_id == c.cid, MailMessage.direction == MailDirection.OUT, MailMessage.transport == "manual",
        MailMessage.status.in_(compose.CHECKLIST_OPEN)).order_by(MailMessage.id)).all()
    for mm in rows:
        if not compose.is_open_checklist(mm) or (manual and mm.status != MailStatus.EXPIRED):
            continue  # manual mode: a prepared checklist is the way to send (the board's "prepared" step)
        what = ("expired: if it went out from Outlook, record it as sent; else prepare the e-mail again" if manual else
                "from before Aegis sent e-mail itself: open it and retire it (not sent from Outlook) or record it as "
                "sent — nothing else of its letter goes out until then")
        task = c.add(Task(
            key=_key(MAILBOX, "checklist", mm.id), source=MAILBOX,
            title=f"Outlook checklist #{mm.id}: retire it or record it as sent", why=f"The checklist is {what}.",
            action=Action("Open the checklist", href=f"/cases/{c.cid}/mail/messages/{mm.id}", perm="send_email"),
            fingerprint=_fp(mm.status.value)))
        task.derived_priority = P2


# --------------------------------------------------------------------------- derived: evidence
EVIDENCE_HREFS = {"loa": "/sender-profile", "tx_list_copyable": "?tab=fund_flow", "balance_reading": "/freeze",
                  "freeze_check": "/freeze", "complaint_ref": "?tab=evidence&folder=law_enforcement#ev-contacts",
                  "police_report": "?tab=evidence&folder=law_enforcement#ev-contacts", "ic3_ref": "?tab=evidence&folder=law_enforcement#ev-contacts",
                  "incident_narrative": "?tab=assistant&sub=summary"}
EVIDENCE_PERMS = {"loa": "manage_sender_profile", "tx_list_copyable": "run_trace", "balance_reading": "poll_watch",
                  "freeze_check": "poll_watch", "incident_narrative": "ai_summarize"}


def _evidence(c: _Ctx) -> None:
    from app.domain import evidence as ev
    from app.domain import evidence_requirements as er
    from app.evidence_intel import rules as R
    from app.evidence_intel import service as intel

    # what the next moves still lack: {requirement key: [(evidence row, move, task)]}
    gaps: dict[str, list] = {}
    for m, task in c.next_moves:
        for e in m.evidence or []:
            if e.get("state") in ("missing", "unusable") and e.get("key") not in er.LETTER:
                gaps.setdefault(e["key"], []).append((e, m, task))
    wanted = {k: rows for k, rows in gaps.items()}
    for item in ev.visible_items(c.access):
        if {str(t).lower() for t in item.tags or []} & intel.SKIP_QUEUE_TAGS or (item.meta or {}).get("trace_run_id"):
            continue
        if intel.status(item) != "suggested":
            continue
        iv = intel.intel(item)
        a = iv.get("ai") or {}
        kind = (iv.get("rules") or {}).get("type") if (iv.get("rules") or {}).get("type") not in (None, "other") \
            else a.get("type")
        dt = R.type_of(kind)
        label = dt.label if dt is not None else str(kind or "document").replace("_", " ")
        covers = sorted(k for k in intel.suggested_keys(item) if k in wanted)
        task = c.add(Task(
            key=_key(EVIDENCE, "confirm", item.id), source=EVIDENCE,
            title=f"Confirm the type of evidence #{item.id}: it reads as a {label}",
            why=("Aegis read it and suggests the type; nothing counts until a person confirms it"
                 + (f" — it would cover {', '.join(er.label(k) for k in covers[:3])} for the next moves" if covers
                    else "") + "."),
            action=Action("Review & confirm", href=f"/cases/{c.cid}/evidence/{item.id}#ev-intel", perm="add_evidence"),
            fingerprint=_fp(kind)))
        task.derived_priority = P2 if covers else P3
        for k in covers:
            wanted.pop(k, None)  # the confirmation is the step for that requirement
    have_setup_loa = c.has("setup:sender_profile") or c.has("setup:authority_doc")
    for k, rows in wanted.items():
        if k == "loa" and have_setup_loa:
            continue  # the setup task (sign / attach the authority document) is that step
        e = rows[0][0]
        if e.get("suggested"):
            continue  # an item reads as one (restricted to this member): a case admin confirms its type
        names = list(dict.fromkeys(_cut(t.title, 60) for _, _, t in rows))
        money = max((m.value or 0) for _, m, _ in rows)
        hot = any(t.derived_priority == P1 for _, _, t in rows)
        state = "fails its integrity check" if e.get("state") == "unusable" else "missing"
        task = c.add(Task(
            key=_key(EVIDENCE, "need", k), source=EVIDENCE, title=f"Evidence {state}: {e.get('label') or er.label(k)}",
            sensitive=any(t.sensitive for _, _, t in rows),  # its why names the moves
            why=f"{e.get('how') or 'add it on the Evidence tab'} — for {', '.join(names[:3])}"
                + (f" (+{len(names) - 3} more)" if len(names) > 3 else ""),
            action=Action("Add it" if k not in EVIDENCE_HREFS else "Open", href=f"/cases/{c.cid}"
                          + EVIDENCE_HREFS.get(k, "?tab=evidence"), perm=EVIDENCE_PERMS.get(k, "add_evidence")),
            fingerprint=_fp(e.get("state"))))
        task.derived_priority = P2 if hot or money >= MONEY_USD else P3


# --------------------------------------------------------------------------- derived: case setup
# a board step that drafts or sends a letter (the LE route's and its pack too): the sender profile is due before it
LETTER_STEPS = frozenset({"draft", "redraft", "resend", "send", "open", "add", "request", "chase", "follow_up",
                          "answer", "le", "pack"})


def _setup(c: _Ctx) -> None:
    from app.attribution import service as attr
    from app.blocks import classify_ai
    from app.blocks import freeze_board as fb
    from app.domain import sender as sender_mod
    from app.evidence_intel import ai as ev_ai

    board = c.board
    pending = board is not None and any(t.step.label and (t.step.kind in LETTER_STEPS or t.group in (fb.ACT, fb.CLAIM))
                                        for t in board.targets)  # a letter (to a provider, LE) about to go out
    if board is not None and board.run is None:
        task = c.add(Task(key=_key(SETUP, "trace"), source=SETUP, title="Run the first trace",
                          why="No trace yet: the board and the Recovery plan do not know where the funds sit.",
                          action=Action("Open Fund flow", href=f"/cases/{c.cid}?tab=fund_flow", perm="run_trace"),
                          fingerprint=_fp("no_run")))
        task.derived_priority = P2
    profile = sender_mod.get_profile(c.db, c.case)
    if profile is None:
        task = c.add(Task(
            key=_key(SETUP, "sender_profile"), source=SETUP,
            title="Set up the sender profile (who the case's letters come from)",
            why=(f"Without one, new letters use the PI-firm block of the case facts; with one, they come from "
                 f"{sender_mod.org_name()} on behalf of the victim, under the victim's authority instrument."),
            action=Action("Open Sender profile", href=f"/cases/{c.cid}/sender-profile", perm="manage_sender_profile"),
            fingerprint=_fp("none")))
        task.derived_priority = P2 if pending else P3
    else:
        items = {e.id: e for e in c.case.evidence_items}
        docs = [items[i] for i in profile.authority_evidence_ids or [] if isinstance(i, int) and i in items]
        if not docs:
            inst = (profile.instrument or sender_mod.DEFAULT_INSTRUMENT).strip()
            task = c.add(Task(
                key=_key(SETUP, "authority_doc"), source=SETUP,
                title=f"Sign the {inst} and attach it as the sender profile's authority document",
                why=(f"The letters name the {inst} and say it is attached, but the sender profile has none: sign it (an "
                     "unsigned draft may exist outside Aegis), scan it to PDF, upload it under Evidence → Legal, then "
                     "tick it as the authority document on the Sender profile."),
                action=Action("Open Sender profile", href=f"/cases/{c.cid}/sender-profile",
                              perm="manage_sender_profile"),
                fingerprint=_fp(inst.lower())))
            task.derived_priority = P2
    if board is not None:
        blocked = {t.step.le for t in board.targets if t.step.le}
        for key, a in board.le_auths.items():
            x = board.le_target(key)
            if x is None or not x.briefable or x.reachable or key in blocked:
                continue  # a board row whose LE step is blocked on it carries "Add the officer's contact"
            anchor_ = f"ev-contact-{key[3:]}" if re.fullmatch(r"le-\d{1,12}", key) else "ev-contacts"
            task = c.add(Task(
                key=_key(SETUP, "le", key), source=SETUP, title=f"Add the officer's name or e-mail for {a.name}",
                why="An LE contact with no named officer or e-mail on file: Aegis cannot address an LE letter to it.",
                action=Action("Open LE contacts", href=f"/cases/{c.cid}?tab=evidence&folder=law_enforcement#{anchor_}",
                              perm="manage_le_contacts"),
                fingerprint=_fp("unreachable")))
            task.derived_priority = P3
    # the optional consents (P3 suggestions): each names its data path before a case admin agrees
    if not attr.setting(c.case).get("enabled") and not c.has("plan:identify"):
        c.add(Task(key=_key(SETUP, "owner_lookups"), source=SETUP, title="Consider turning on owner lookups",
                   why="Public explorer tags of the case's wallets name the exchanges behind deposit addresses "
                       "(optional; the endpoints are listed before you consent).",
                   action=Action("Owner lookups", href=f"/cases/{c.cid}/recovery-plan#owner-lookups",
                                 perm="manage_case"), fingerprint=_fp("off")))
    if c.case.ai_mode != AIMode.OFF:
        if not ev_ai.is_enabled(c.case):
            c.add(Task(key=_key(SETUP, "evidence_ai"), source=SETUP,
                       title="Consider letting the AI read evidence documents",
                       why="Optional: \"AI reads evidence\" suggests each document's type (advisory; a person "
                           "confirms). The data path is shown before you consent.",
                       action=Action("AI reads evidence", href=f"/cases/{c.cid}?tab=evidence#ev-intel-ai",
                                     perm="manage_case"), fingerprint=_fp("off")))
        if not classify_ai.is_enabled(c.case):
            c.add(Task(key=_key(SETUP, "mail_ai"), source=SETUP, title="Consider letting the AI read mailbox replies",
                       why="Optional: \"AI reads mailbox replies\" reads each reply's text with the rules (advisory; a "
                           "person confirms every hold or freeze). The data path is shown before you consent.",
                       action=Action("AI reads mailbox replies", href=f"/cases/{c.cid}/blocks#ai-setting",
                                     perm="manage_case"), fingerprint=_fp("off")))


SOURCE_STEPS = ((BOARD, _board), (PLAN, _plan), (ROUTE, _route), (BLOCKS, _blocks), (MAILBOX, _mailbox), (EVIDENCE, _evidence),
                (SETUP, _setup))


def derive(db: Session, case, access, *, now: datetime | None = None, rows: list | None = None,
           board: Any = None) -> tuple[list[Task], list[str]]:
    """Every derived task (one pass of each source) and the sources that failed to read (their tasks are missing, and
    their stored tasks are never closed as resolved meanwhile). `rows`: the case's block rows when the caller already
    has them (bs.case_blocks); `board`: the freeze board when the caller already has one (built for this member).
    External members: none."""
    from app.domain import correspondence as desk

    if access.is_external:
        return [], []
    c = _Ctx(db=db, case=case, access=access, now=now or _now(), mask=desk.contact_mask(access), rows=rows,
             board=board)
    for name, step in SOURCE_STEPS:
        if name in (PLAN, ROUTE, BLOCKS) and BOARD in c.failed:
            c.failed.append(name)  # both read the board's own pass
            continue
        try:
            step(c)
        except Exception as err:  # noqa: BLE001 - a broken source never takes the list down
            log.warning("to do: source %s failed for case %s (%s)", name, case.id, type(err).__name__)
            db.rollback()
            c.failed.append(name)
    for t in c.tasks:
        t.priority = t.derived_priority
    return c.tasks, c.failed


# --------------------------------------------------------------------------- merge with the stored state
def _names(db: Session, ids: set[int]) -> dict[int, str]:
    if not ids:
        return {}
    return {u.id: u.display_name for u in db.scalars(select(User).where(User.id.in_(ids)))}


def _overlay(t: Task, row: CaseTask, now: datetime | None = None) -> None:
    t.row, t.note, t.assignee_id = row, row.note, row.assignee_id
    if row.priority_override in PRIORITIES:
        t.priority = row.priority_override
        t.overridden += ("priority",)
    if row.due_override is not None:
        t.due = _aware(row.due_override)
        t.overridden += ("due",)
    # overdue (or due within P1_DUE) is P1: a manual task's priority and a derived task's own clock never keep a
    # task that is past its due date below P1; only a person's explicit priority on a derived task stands
    if now is not None and t.due is not None and t.due <= now + P1_DUE and \
            (t.source == MANUAL or "priority" not in t.overridden):
        t.priority = P1
    t.snoozed_until, t.dismissed_note = _aware(row.snoozed_until), row.dismissed_note
    t.done_at, t.done_by = _aware(row.done_at), row.done_by


def _manual(row: CaseTask, now: datetime) -> Task:
    t = Task(key=row.key, title=row.title, source=MANUAL, why=_cut(row.note, 160) if row.note else "",
             derived_priority=row.priority_override if row.priority_override in PRIORITIES else P2,
             fingerprint="manual")
    t.priority = t.derived_priority
    _overlay(t, row, now)
    t.status = row.status if row.status in STATUSES else OPEN
    if t.status == SNOOZED and (t.snoozed_until is None or t.snoozed_until <= now):
        t.status = OPEN
    return t


class Tasks(list):
    """build's result: the tasks (a list), and `failed`, the sources that could not be read this time."""

    def __init__(self, items=(), *, failed: list[str] | None = None):
        super().__init__(items)
        self.failed = list(failed or [])


UNASSIGNED_KEY = _key(MAILBOX, "unassigned")


def _derivable(access, key: str, sensitive: bool, visible) -> bool:
    """Whether `access` could have derived the task `key` at all: a sensitive Recovery plan move needs
    view_restricted, the unassigned mail queue a system admin, an evidence item's type suggestion the item itself
    (`visible()`: the ids of the evidence the member sees; the Financial folder needs view_financial). A stored task
    the viewer could not derive is neither shown to them nor closed by their build: its absence says nothing."""
    if sensitive and not access.can("view_restricted"):
        return False
    if key == UNASSIGNED_KEY:
        return bool(getattr(access.user, "is_system_admin", False))
    if key.startswith(f"{EVIDENCE}:confirm:"):
        tail = key.rsplit(":", 1)[-1]
        return tail.isdigit() and int(tail) in visible()
    return True


def _full(access, key: str, sensitive: bool, visible) -> bool:
    """Whether this build may change the stored state of the task `key` (reopen it on a new fingerprint, close it as
    resolved when it is gone, rewrite its title): only a member who acts on the list (ACT_PERM: a read-only member's
    view never writes, and their list is built from less — no prepared e-mails, no sensitive moves) and who derives
    the task as anyone on the case would (`_derivable`; what the next moves lack reads every item: view_financial)."""
    if not access.can(ACT_PERM) or not _derivable(access, key, sensitive, visible):
        return False
    return not key.startswith(f"{EVIDENCE}:need:") or access.can("view_financial")


def build(db: Session, case, access, *, now: datetime | None = None, persist: bool = True,
          rows: list | None = None, board: Any = None) -> Tasks:
    """The case's tasks as `access` may see them: every derived task (with its stored state), every manual task, and
    the derived tasks a person acted on whose source condition cleared (resolved). `persist`: write the automatic
    transitions (a snooze that lapsed, a source that changed materially: reopened; a source that cleared: resolved) —
    never an audit row; without it nothing is written (the tab bar's badge). Only a viewer who sees a task's whole
    source changes its row (`_full`): below that the stored state stands as a person set it (a read-only member's
    view writes nothing), and a stored task the viewer could not derive is left out, never closed. `rows` / `board`:
    the case's block rows / freeze board when the caller already has them (the Overview's one pass, the Authorities
    tab's board). External members: none."""
    from app.domain import correspondence as desk
    from app.domain import evidence as ev

    now = now or _now()
    if access.is_external:
        return Tasks()
    derived, failed = derive(db, case, access, now=now, rows=rows, board=board)
    stored = db.scalars(select(CaseTask).where(CaseTask.case_id == case.id)).all()
    by_key = {r.key: r for r in stored}
    changed = False
    seen: set[int] | None = None
    mask = desk.contact_mask(access)

    def visible() -> set[int]:
        nonlocal seen
        if seen is None:
            seen = {e.id for e in ev.visible_items(access)}
        return seen

    def put(row: CaseTask, write: bool, **values) -> None:
        nonlocal changed
        diff = {k: v for k, v in values.items() if getattr(row, k) != v}
        if diff and write:
            changed = True
            if persist:
                for k, v in diff.items():
                    setattr(row, k, v)

    out: list[Task] = []
    for t in derived:
        t.full = _full(access, t.key, t.sensitive, visible)
        row = by_key.pop(t.key, None)
        if row is None:
            out.append(t)
            continue
        _overlay(t, row, now)
        status = row.status if row.status in STATUSES else OPEN
        # a viewer who sees less of the source than the members who act on it: the state a person set stands
        same = row.fingerprint == t.fingerprint or not t.full or row.fingerprint is None
        if status == SNOOZED and same and t.snoozed_until is not None and t.snoozed_until > now:
            t.status = SNOOZED
        elif status in (DONE, DISMISSED) and same:
            t.status = status
        else:  # open; a snooze that lapsed, a source that changed materially, a task that came back: open again
            t.status = OPEN
            if status != OPEN:
                put(row, t.full, status=OPEN, snoozed_until=None, done_at=None, done_by=None, dismissed_note=None)
                t.snoozed_until = t.dismissed_note = t.done_at = t.done_by = None
        if t.status == OPEN or row.fingerprint is None:  # what its source says now (a closed task: what it said then)
            put(row, t.full, fingerprint=t.fingerprint, title=t.title[:MAX_TITLE], sensitive=t.sensitive)
        out.append(t)
    acts = access.can(ACT_PERM)
    for row in by_key.values():
        if row.key.startswith(MANUAL_PREFIX):
            t = _manual(row, now)
            if row.status == SNOOZED and t.status == OPEN:
                put(row, acts, status=OPEN, snoozed_until=None)
            out.append(t)
            continue
        if row.source in failed:
            continue  # its source could not be read: neither shown nor closed
        sensitive = bool(row.sensitive)
        if not _derivable(access, row.key, sensitive, visible):
            continue  # this viewer could not have derived it: it may still be on the list of one who sees more
        full = _full(access, row.key, sensitive, visible)
        if row.status in (OPEN, SNOOZED) and not full:
            continue  # whether its source cleared is for a member who sees the whole source to say
        t = Task(key=row.key, title=_cut(mask.text(row.title), MAX_TITLE),
                 source=row.source if row.source in SOURCES else BOARD,
                 status=row.status if row.status in STATUSES else RESOLVED, fingerprint=row.fingerprint or "",
                 sensitive=sensitive, full=full)
        _overlay(t, row)
        if row.status in (OPEN, SNOOZED):  # the source condition cleared: done (resolved)
            put(row, True, status=RESOLVED, done_at=now, done_by=None, snoozed_until=None)
            t.status, t.done_at, t.done_by, t.snoozed_until = RESOLVED, now, None, None
        out.append(t)
    if changed and persist:
        try:
            db.commit()
        except Exception as err:  # noqa: BLE001 - the list still renders; the next read tries again
            log.warning("to do: state update failed for case %s (%s)", case.id, type(err).__name__)
            db.rollback()
    names = _names(db, {t.assignee_id for t in out if t.assignee_id})
    for t in out:
        t.assignee = names.get(t.assignee_id) if t.assignee_id else None
    return Tasks(out, failed=failed)


def sort_key(t: Task, now: datetime) -> tuple:
    far = now + timedelta(days=36500)
    late = t.overdue(now)
    # among overdue tasks of one priority the money at stake leads (their dates have passed alike), the order the
    # Recovery plan ranks the same chases in; otherwise the earliest due date first
    return (not late, RANK.get(t.priority, 2), -(t.value or 0) if late else 0, t.due or far, -(t.value or 0),
            t.title.lower(), t.key)


def open_tasks(tasks: list[Task], now: datetime | None = None) -> list[Task]:
    """The open tasks, overdue first, then by priority, then (overdue) by money at stake, then by due date (none
    last), then money at stake."""
    now = now or _now()
    return sorted((t for t in tasks if t.status == OPEN), key=lambda t: sort_key(t, now))


def done_recently(tasks: list[Task], now: datetime | None = None) -> list[Task]:
    """Done, dismissed and resolved within RECENT, newest first."""
    now = now or _now()
    rows = [t for t in tasks if t.status in CLOSED and t.done_at is not None and t.done_at >= now - RECENT]
    return sorted(rows, key=lambda t: t.done_at, reverse=True)


def snoozed(tasks: list[Task]) -> list[Task]:
    return sorted((t for t in tasks if t.status == SNOOZED), key=lambda t: t.snoozed_until or _now())


def p1_open(tasks: list[Task]) -> int:
    return sum(1 for t in tasks if t.status == OPEN and t.priority == P1)


def find(tasks: list[Task], key: str) -> Task | None:
    return next((t for t in tasks if t.key == key), None)


def may(access, action: Action | None) -> bool:
    """Whether to show the task's action button: never to read-only members (they see the list without buttons), and
    only when the member's role allows the action itself (a Send, a discard, the sender profile: case admins)."""
    from app.blocks import recovery as rp
    from app.core.permissions import ACTIONS

    if action is None or not (action.href or action.post) or not access.can(ACT_PERM):
        return False
    if action.perm == "system_admin":
        return bool(getattr(access.user, "is_system_admin", False))
    if action.perm == "pack":
        return rp.may(access, "pack")
    return action.perm in ACTIONS and access.can(action.perm)


# --------------------------------------------------------------------------- a person's changes
def assignees(db: Session, case) -> list[dict]:
    """Who a task can be assigned to: the case's unexpired members who may act on the list (investigators and up)."""
    from app.core.permissions import role_at_least

    now = _now()
    rows = db.execute(select(CaseMember, User).join(User, User.id == CaseMember.user_id).where(
        CaseMember.case_id == case.id)).all()
    out = [{"id": u.id, "name": u.display_name} for m, u in rows
           if u.is_active and (m.expires_at is None or _aware(m.expires_at) > now)
           and role_at_least(m.role, "investigator")]
    return sorted(out, key=lambda x: x["name"].lower())


def _text(value: str | None, n: int, what: str, *, required: bool = False) -> str | None:
    s = str(value or "").replace("\r\n", "\n").strip()
    if not s:
        if required:
            raise TodoError(f"{what} is required")
        return None
    if _CONTROL.search(s):
        raise TodoError(f"{what}: control characters are not allowed")
    if len(s) > n:
        raise TodoError(f"{what} is longer than {n} characters")
    return s


def _priority(value: str | None, *, required: bool = False) -> str | None:
    v = str(value or "").strip().upper()
    if not v:
        if required:
            raise TodoError("priority is required")
        return None
    if v not in PRIORITIES:
        raise TodoError("priority must be P1, P2 or P3")
    return v


def parse_due(value: str | None) -> datetime | None:
    """'YYYY-MM-DD' (end of that day, UTC) or 'YYYY-MM-DDTHH:MM' (UTC); '' = none."""
    v = str(value or "").strip()
    if not v:
        return None
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
            return datetime.fromisoformat(v).replace(hour=23, minute=59, tzinfo=UTC)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", v):
            return datetime.fromisoformat(v).replace(tzinfo=UTC)
    except ValueError:
        pass
    raise TodoError("due date: use YYYY-MM-DD")


def _assignee(db: Session, case, value) -> int | None:
    v = str(value or "").strip()
    if not v:
        return None
    if not v.isdigit() or int(v) not in {a["id"] for a in assignees(db, case)}:
        raise TodoError("the assignee must be an investigator or admin of the case")
    return int(v)


def _require(access) -> None:
    if not access.can(ACT_PERM):
        raise TodoError("your role on this case does not allow changing the To do list", 403)


def create(db: Session, access, *, title: str, priority: str = P2, due: str | None = None, assignee_id=None,
           note: str | None = None) -> CaseTask:
    """A manual task (investigators and up). Commits; the route audits."""
    _require(access)
    row = CaseTask(case_id=access.case.id, key=f"{MANUAL_PREFIX}new-{secrets.token_hex(8)}",
                   source=MANUAL, title=_text(title, MAX_TITLE, "title", required=True),
                   note=_text(note, MAX_NOTE, "note"), priority_override=_priority(priority) or P2,
                   due_override=parse_due(due), assignee_id=_assignee(db, access.case, assignee_id), status=OPEN,
                   created_by=access.user.id, fingerprint="manual")
    db.add(row)
    db.flush()
    row.key = f"{MANUAL_PREFIX}{row.id}"
    db.commit()
    return row


def _row_for(db: Session, access, task: Task) -> CaseTask:
    """The task's row; a derived task's is created on first use (its key, source, title and fingerprint)."""
    row = task.row if task.row is not None else db.scalar(select(CaseTask).where(
        CaseTask.case_id == access.case.id, CaseTask.key == task.key))
    if row is None:
        row = CaseTask(case_id=access.case.id, key=task.key, source=task.source, title=task.title[:MAX_TITLE],
                       fingerprint=task.fingerprint if task.full else None, sensitive=task.sensitive, status=OPEN,
                       created_by=access.user.id)
        db.add(row)
        try:
            db.flush()
        except IntegrityError:  # another request created it meanwhile
            db.rollback()
            row = db.scalar(select(CaseTask).where(CaseTask.case_id == access.case.id, CaseTask.key == task.key))
            if row is None:
                raise
    if task.derived and task.full:  # a member who sees less of its source leaves the fingerprint to one who sees it all
        row.fingerprint, row.title, row.sensitive = task.fingerprint, task.title[:MAX_TITLE], task.sensitive
    return row


def apply(db: Session, access, task: Task, op: str, *, days: int | str | None = None, note: str | None = None,
          priority: str | None = None, due: str | None = None, assignee_id=None, title: str | None = None,
          now: datetime | None = None) -> tuple[CaseTask, list[str]]:
    """done | reopen | snooze (1 / 3 / 7 days) | dismiss (with a note) | edit (priority, due, assignee; a manual
    task's title and note). Returns the row and the names of the fields that changed. Commits; the route audits."""
    _require(access)
    if op not in OPS:
        raise TodoError("unknown change")
    now = now or _now()
    if op == "snooze":
        try:
            n = int(str(days or "").strip())
        except ValueError:
            n = 0
        if n not in SNOOZE_DAYS:
            raise TodoError("snooze for 1, 3 or 7 days")
    if op == "edit":  # validate everything before the row exists
        new = {"priority_override": _priority(priority), "due_override": parse_due(due),
               "assignee_id": _assignee(db, access.case, assignee_id)}
        if task.manual:
            new["title"] = _text(title, MAX_TITLE, "title", required=True) if title is not None else task.title
            new["priority_override"] = new["priority_override"] or P2
            new["note"] = _text(note, MAX_NOTE, "note")
        elif note is not None:
            new["note"] = _text(note, MAX_NOTE, "note")
    dismiss_note = _text(note, MAX_DISMISS_NOTE, "note") if op == "dismiss" else None
    row = _row_for(db, access, task)
    changed: list[str] = []

    def put(col: str, value) -> None:
        if getattr(row, col) != value:
            setattr(row, col, value)
            changed.append(col)

    if op == "done":
        put("status", DONE)
        put("done_at", now)
        put("done_by", access.user.id)
        put("snoozed_until", None)
    elif op == "reopen":
        put("status", OPEN)
        for col in ("done_at", "done_by", "snoozed_until", "dismissed_note"):
            put(col, None)
    elif op == "snooze":
        put("status", SNOOZED)
        put("snoozed_until", now + timedelta(days=n))
    elif op == "dismiss":
        put("status", DISMISSED)
        put("dismissed_note", dismiss_note)
        put("done_at", now)
        put("done_by", access.user.id)
    else:
        for col, value in new.items():
            put(col, value)
    db.commit()
    return row, changed
