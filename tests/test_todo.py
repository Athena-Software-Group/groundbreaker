"""The case's To do list (app.domain.todo; the "To do" tab, the Overview card, the tab bar's badge, the /todo skill, the
routes in app/web/routes_todo.py, migration 0012): derived tasks from every source with their priority, due date and
one-click action, closing themselves when the source clears; snooze / dismiss / done; manual tasks; roles; audit; one
pass of each source. The demo case (a fresh copy per test) plus synthetic states: every address, name and
number added here is made up. Offline."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from conftest import csrf_token, ensure_user, set_role
from sqlalchemy import event, select

from app import services
from app.ai import providers
from app.blocks import freeze_board as fb
from app.blocks import recovery as rp
from app.blocks import status as bs
from app.core.permissions import CaseAccess
from app.db.models import (
    AIMode,
    AuditEvent,
    CaseRole,
    CaseTask,
    Chain,
    EvidenceFolder,
    EvidenceItem,
    EvidenceStorage,
    LEContact,
    MailDirection,
    MailMessage,
    MailStatus,
)
from app.db.session import engine
from app.domain import correspondence as desk
from app.domain import evidence_requirements as er
from app.domain import sender as sender_mod
from app.domain import todo
from app.web import routes_todo

NOW = datetime.now(tz=UTC)
LOA = "Sign the Letter of Authorisation and attach it as the sender profile's authority document"


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


@pytest.fixture
def case(db, tmp_path):
    """A fresh copy of the demo case with a trace run (its own reference)."""
    from test_block_status import fresh_case

    c = fresh_case(db, tmp_path)
    services.run_trace(db, c, provider_mode="fixture")
    db.refresh(c)
    return c


def _acc(db, case, role="admin", email=None) -> CaseAccess:
    user = ensure_user(db, email or f"todo-{role}@tests.example")
    set_role(db, case, user, role)
    return CaseAccess(case=case, user=user, role=CaseRole(role), member=None)


def _build(db, case, acc, **kw) -> todo.Tasks:
    db.expire_all()
    return todo.build(db, case, acc, **kw)


def _task(tasks, key) -> todo.Task:
    t = todo.find(tasks, key)
    assert t is not None, (key, [x.key for x in tasks])
    return t


def _synthetic(db, admin):
    return services.create_case(
        db, reference=f"TODO-{datetime.now(tz=UTC).strftime('%H%M%S%f')}", title="Synthetic to do case",
        victim_name="Sam Example", victim_entity=None, loss_amount=1000, loss_asset="USDC", loss_usd=1000,
        fraud_date=None, chain=Chain.ETHEREUM, origin_tx=None, victim_wallet=None,
        perpetrator_wallet="0x" + "7d" * 20, created_by=admin)


# --------------------------------------------------------------------------- priority
@pytest.mark.parametrize(("due", "value", "urgent", "floor", "want"), [
    (-timedelta(hours=1), None, False, todo.P3, todo.P1),  # overdue
    (timedelta(hours=47), None, False, todo.P3, todo.P1),  # due within 48 h
    (timedelta(hours=49), None, False, todo.P3, todo.P2),  # due within 7 days
    (timedelta(days=8), None, False, todo.P3, todo.P3),
    (None, 25_000.0, True, todo.P3, todo.P1),  # money with urgency
    (None, 25_000.0, False, todo.P3, todo.P2),  # money without urgency
    (None, 60.0, True, todo.P3, todo.P2),  # below the P1 threshold
    (None, 10.0, False, todo.P3, todo.P3),  # dust
    (None, None, False, todo.P2, todo.P2),  # the source's floor
])
def test_derived_priority_rules(due, value, urgent, floor, want):
    at = NOW + due if due is not None else None
    assert todo.derive_priority(due=at, value=value, urgent=urgent, now=NOW, floor=floor) == want


# --------------------------------------------------------------------------- derived tasks, per source
def test_board_tasks_follow_the_board_rows(db, case):
    acc = _acc(db, case)
    tasks = _build(db, case, acc, now=NOW)
    board = fb.build(db, case, acc, now=NOW)
    hot = [t for t in board.targets if t.group in (fb.ACT, fb.CLAIM) and t.step.label]
    assert hot, "the demo board has Act now rows"
    for t in hot:
        task = _task(tasks, f"board:{t.key}")
        assert task.source == todo.BOARD and task.title.startswith(t.name) and t.step.label in task.title
        assert task.due == t.deadline and task.action.label == t.step.label
        assert (task.action.href or task.action.post) == (t.step.href or t.step.post)
        assert task.priority in (todo.P1, todo.P2)  # Act now: at least P2
    tether = _task(tasks, f"board:{next(t.key for t in hot if t.name == 'Tether (USDT issuer)')}")
    assert tether.title == "Tether (USDT issuer): Add the officer's contact" and tether.priority == todo.P2
    assert tether.action.perm == "manage_le_contacts" and "#ev-contact-" in tether.action.href
    assert board.plan is not None  # the board keeps the plan it was built from (the plan tasks read it)


def test_overdue_replies_are_p1_and_lead_the_list(db, case):
    acc = _acc(db, case)
    later = NOW + timedelta(days=3)  # every demo reply is overdue by then
    tasks = _build(db, case, acc, now=later, persist=False)
    chase = [t for t in tasks if t.source == todo.BOARD and t.title.endswith(": Chase")]
    assert {t.title for t in chase} >= {"KuCoin: Chase", "Rainbet: Chase"}
    for t in chase:
        assert t.priority == todo.P1 and t.overdue(later) and "template=status_request" in t.action.href
    ordered = todo.open_tasks(tasks, later)
    first_rest = next(i for i, t in enumerate(ordered) if not t.overdue(later))
    assert all(t.overdue(later) for t in ordered[:first_rest]) and ordered[0].priority == todo.P1
    rest = ordered[first_rest:]
    assert [todo.RANK[t.priority] for t in rest] == sorted(todo.RANK[t.priority] for t in rest)


def test_plan_tasks_are_the_moves_no_board_row_covers(db, case):
    acc = _acc(db, case)
    tasks = _build(db, case, acc, now=NOW)
    board = fb.build(db, case, acc, now=NOW)
    plan_keys = {f"plan:{m.key}" for m in board.plan.moves if m.actionable and not m.key.startswith("owner:")
                 and not (m.authority is not None and ":" not in m.key)}
    assert {"plan:identify", "plan:trace_next"} <= plan_keys
    assert plan_keys <= {t.key for t in tasks}
    ident = _task(tasks, "plan:identify")
    assert ident.title.startswith("Identify the owner of") and ident.priority == todo.P2  # money, no urgency
    # owner lookups are on by default: the move runs them (an investigator's action)
    assert ident.action.post == f"/cases/{case.id}/owners/lookup" and ident.action.perm == "poll_watch"
    assert _task(tasks, "plan:trace_next").action.perm == "run_trace"
    # a provider's own move is its board row, never a second task
    assert not [t for t in tasks if t.key.startswith("plan:entity-") or t.key.startswith("plan:o")]
    assert not todo.find(tasks, "setup:owner_lookups")  # on by default: nothing to switch on


def test_block_status_and_clock_tasks(db, case):
    acc = _acc(db, case)
    le = next(a for a in desk.case_authorities(db, case) if a.is_le and "Carabinieri" in a.name)
    corr = desk.log_entry(db, case, le, actor=None, direction="out", channel="email", kind="other",
                          subject="Case update for the station", body="Synthetic update.", body_format="text",
                          occurred_at=NOW - timedelta(days=10), due_days=2)
    db.commit()
    tasks = _build(db, case, acc, now=NOW)
    chase = _task(tasks, f"blocks:c{corr.id}")
    assert chase.source == todo.BLOCKS and chase.title.startswith(f"Chase {le.name}")
    assert chase.priority == todo.P1 and chase.overdue(NOW)
    assert chase.action.href == f"/cases/{case.id}/blocks#c{corr.id}"
    # the path clocks (a submit-by, a confirmed hold's expiry): within two weeks, never one the board row carries
    row = SimpleNamespace(key="o99", kind="stop_order", authority=SimpleNamespace(key="entity-99", name="Demo Exchange"),
                          title="Stop order #99", path=SimpleNamespace(hold_at=NOW - timedelta(days=1)), clocks=[
                              {"what": "hold_until", "key": "hold", "due_at": NOW + timedelta(hours=30),
                               "label": "hold lapses", "span": "7 days", "starts_label": "the hold"},
                              {"what": "submit_by", "key": "submit", "due_at": NOW + timedelta(days=5)},
                              {"what": "submit_by", "key": "far", "due_at": NOW + timedelta(days=30)},
                              {"what": "reply_by", "key": "reply", "due_at": NOW + timedelta(days=1)}])
    c = todo._Ctx(db=db, case=case, access=acc, now=NOW, mask=desk.contact_mask(acc),
                  board=SimpleNamespace(targets=[], rows=[row]))
    todo._clocks(c)
    got = {t.key: t for t in c.tasks}
    assert set(got) == {"blocks:clock:o99:hold", "blocks:clock:o99:submit"}
    hold = got["blocks:clock:o99:hold"]
    assert "the hold lapses" in hold.title and hold.derived_priority == todo.P1 and hold.due_label == "hold lapses"
    assert got["blocks:clock:o99:submit"].derived_priority == todo.P2
    c.tasks.clear()
    c.board.targets = [SimpleNamespace(key="entity-99", deadline=NOW + timedelta(hours=30, minutes=20))]
    todo._clocks(c)
    assert [t.key for t in c.tasks] == ["blocks:clock:o99:submit"]  # the board row carries the hold's date


def test_mailbox_tasks(db, case):
    adm, inv = _acc(db, case), _acc(db, case, "investigator")
    mm = MailMessage(case_id=case.id, direction=MailDirection.IN, status=MailStatus.NEEDS_REVIEW, transport="file",
                     mailbox="investigations@athena-demo.example", message_id="<todo-review@exchange-demo.example>",
                     subject="RE: request", received_at=NOW - timedelta(hours=30))
    ck = MailMessage(case_id=case.id, direction=MailDirection.OUT, status=MailStatus.EXPIRED, transport="manual",
                     mailbox="investigations@athena-demo.example", message_id="<todo-checklist@athena-demo.example>",
                     subject="Freeze request", prepared_at=NOW - timedelta(days=3))
    db.add_all([mm, ck])
    db.commit()
    tasks = _build(db, case, adm, now=NOW)
    review = _task(tasks, "mailbox:review")
    assert review.title == "Triage 1 inbound e-mail matched to this case" and review.priority == todo.P1  # a day old
    assert review.action.href == f"/cases/{case.id}/mail/review" and todo.may(adm, review.action)
    assert not todo.may(inv, review.action)  # triage is a case admin's
    checklist = _task(tasks, f"mailbox:checklist:{ck.id}")
    assert checklist.priority == todo.P2 and checklist.action.href == f"/cases/{case.id}/mail/messages/{ck.id}"
    mm.status, ck.status = MailStatus.RECEIVED, MailStatus.CANCELLED
    db.commit()
    tasks = _build(db, case, adm, now=NOW)
    assert not todo.find(tasks, "mailbox:review") and not todo.find(tasks, f"mailbox:checklist:{ck.id}")


def test_evidence_tasks(db, case):
    acc = _acc(db, case)
    item = EvidenceItem(case_id=case.id, folder=EvidenceFolder.OTHER, title="Scan (synthetic)",
                        storage=EvidenceStorage.INLINE, inline_text="synthetic", tags=[],
                        meta={"intel": {"rules": {"type": "police_report"}}})
    db.add(item)
    db.commit()
    tasks = _build(db, case, acc, now=NOW)
    sug = _task(tasks, f"evidence:confirm:{item.id}")
    assert sug.title.startswith(f"Confirm the type of evidence #{item.id}: it reads as a Police report")
    assert sug.action.href == f"/cases/{case.id}/evidence/{item.id}#ev-intel" and sug.action.perm == "add_evidence"
    # the evidence the next moves lack: one task per requirement, naming the moves
    board = fb.build(db, case, acc, now=NOW)
    missing = {e["key"] for t in board.targets if t.group in (fb.ACT, fb.CLAIM) and t.move is not None
               for e in t.move.evidence if e["state"] == "missing" and e["key"] not in er.LETTER
               and not e.get("suggested")}
    assert missing, "the demo's next moves lack evidence"
    for k in missing - {"loa"}:
        gap = todo.find(tasks, f"evidence:need:{k}")
        if gap is None:  # an item's type suggestion covers it: its confirmation is the step
            assert any(t.key.startswith("evidence:confirm:") and er.label(k) in t.why for t in tasks), k
            continue
        assert gap.source == todo.EVIDENCE and " — for " in gap.why and gap.priority in (todo.P2, todo.P3)
    item.meta = {"intel": {"rules": {"type": "police_report"}, "confirmed": {"type": "police_report"}}}
    db.commit()
    assert not todo.find(_build(db, case, acc, now=NOW), f"evidence:confirm:{item.id}")


def test_setup_tasks_on_a_new_case(db):
    admin = ensure_user(db, "todo-setup@tests.example")
    c = _synthetic(db, admin)
    acc = CaseAccess(case=c, user=admin, role=CaseRole.ADMIN, member=None)
    tasks = _build(db, c, acc, now=NOW)
    keys = {t.key for t in tasks}
    # a new case gets the default sender profile at creation: what is left is attaching its authority document
    assert "setup:owner_lookups" not in keys  # owner lookups are on by default
    assert {"setup:trace", "setup:authority_doc", "setup:evidence_ai",
            "setup:mail_ai"} <= keys and "setup:sender_profile" not in keys
    assert _task(tasks, "setup:trace").priority == todo.P2
    assert _task(tasks, "setup:authority_doc").priority == todo.P2  # the letters say the instrument is attached
    for k in ("setup:evidence_ai", "setup:mail_ai"):
        assert _task(tasks, k).priority == todo.P3 and _task(tasks, k).action.perm == "manage_case"
    # an LE contact with no officer or e-mail
    contact = LEContact(case_id=c.id, agency="Demo City Police (synthetic)", role="desk officer")
    db.add(contact)
    db.commit()
    tasks = _build(db, c, acc, now=NOW)
    le = next(t for t in tasks if t.key.startswith("setup:le:"))
    assert le.title == "Add the officer's name or e-mail for Demo City Police (synthetic)"
    assert le.action.perm == "manage_le_contacts" and "#ev-contact" in le.action.href
    contact.email = "desk@police-demo.example"
    db.commit()
    assert not [t for t in _build(db, c, acc, now=NOW) if t.key.startswith("setup:le:")]
    c.ai_mode = AIMode.OFF
    db.commit()
    keys = {t.key for t in _build(db, c, acc, now=NOW)}
    assert "setup:evidence_ai" not in keys and "setup:mail_ai" not in keys  # AI off for the case: no AI suggestions


def test_authority_document_task_appears_and_resolves_itself(db, case):
    acc = _acc(db, case)
    profile = sender_mod.get_profile(db, case)
    docs = list(profile.authority_evidence_ids)
    assert docs, "the demo profile has its authority document"
    assert not todo.find(_build(db, case, acc, now=NOW), "setup:authority_doc")
    profile.authority_evidence_ids = []
    db.commit()
    tasks = _build(db, case, acc, now=NOW)
    t = _task(tasks, "setup:authority_doc")
    assert t.title == LOA and t.priority == todo.P2 and t.source == todo.SETUP
    assert "unsigned draft may exist outside Aegis" in t.why and "Evidence → Legal" in t.why
    assert t.action.href == f"/cases/{case.id}/sender-profile" and t.action.perm == "manage_sender_profile"
    assert not todo.find(tasks, "evidence:need:loa")  # the setup task is that step
    todo.apply(db, acc, t, "edit", priority="P1")  # a person touched it: it has a row now
    tasks = _build(db, case, acc, now=NOW)
    assert _task(tasks, "setup:authority_doc").priority == todo.P1
    profile = sender_mod.get_profile(db, case)
    profile.authority_evidence_ids = docs
    db.commit()
    tasks = _build(db, case, acc, now=NOW)
    gone = _task(tasks, "setup:authority_doc")
    assert gone.status == todo.RESOLVED and gone.done_by is None and gone in todo.done_recently(tasks, NOW)
    assert gone not in todo.open_tasks(tasks, NOW)
    row = db.scalar(select(CaseTask).where(CaseTask.case_id == case.id, CaseTask.key == "setup:authority_doc"))
    assert row.status == todo.RESOLVED and row.done_at is not None


def test_snooze_dismiss_and_done_on_a_derived_task(db, case):
    acc = _acc(db, case)
    profile = sender_mod.get_profile(db, case)
    profile.authority_evidence_ids = []
    db.commit()
    t = _task(_build(db, case, acc, now=NOW), "setup:authority_doc")
    todo.apply(db, acc, t, "snooze", days=3, now=NOW)
    tasks = _build(db, case, acc, now=NOW)
    assert _task(tasks, "setup:authority_doc").status == todo.SNOOZED
    assert todo.find(todo.open_tasks(tasks, NOW), "setup:authority_doc") is None
    assert _task(_build(db, case, acc, now=NOW + timedelta(days=4)), "setup:authority_doc").status == todo.OPEN
    assert db.scalar(select(CaseTask.status).where(CaseTask.case_id == case.id,
                                                   CaseTask.key == "setup:authority_doc")) == todo.OPEN
    # dismissed: hidden while the source says the same; a material change of the source reopens it
    t = _task(_build(db, case, acc, now=NOW), "setup:authority_doc")
    todo.apply(db, acc, t, "dismiss", note="signed copy on its way by post", now=NOW)
    tasks = _build(db, case, acc, now=NOW)
    d = _task(tasks, "setup:authority_doc")
    assert d.status == todo.DISMISSED and d.dismissed_note == "signed copy on its way by post"
    assert d in todo.done_recently(tasks, NOW)
    profile = sender_mod.get_profile(db, case)
    profile.instrument = "Mandate"
    db.commit()
    t = _task(_build(db, case, acc, now=NOW), "setup:authority_doc")
    assert t.status == todo.OPEN and t.title.startswith("Sign the Mandate") and t.dismissed_note is None
    # done: hidden until the source changes; snoozed while the source changes: back at once
    todo.apply(db, acc, t, "done", now=NOW)
    assert _task(_build(db, case, acc, now=NOW), "setup:authority_doc").status == todo.DONE
    todo.apply(db, acc, _task(_build(db, case, acc, now=NOW), "setup:authority_doc"), "reopen")
    t = _task(_build(db, case, acc, now=NOW), "setup:authority_doc")
    assert t.status == todo.OPEN
    todo.apply(db, acc, t, "snooze", days=7, now=NOW)
    profile = sender_mod.get_profile(db, case)
    profile.instrument = "Letter of Authorisation"
    db.commit()
    assert _task(_build(db, case, acc, now=NOW), "setup:authority_doc").status == todo.OPEN
    with pytest.raises(todo.TodoError):
        todo.apply(db, acc, t, "snooze", days=2)


def test_a_source_that_fails_hides_its_tasks_but_never_resolves_them(db, case, monkeypatch):
    acc = _acc(db, case)
    t = _task(_build(db, case, acc, now=NOW), "plan:identify")
    todo.apply(db, acc, t, "edit", priority="P1")

    def boom(*_a, **_k):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(fb, "build", boom)
    tasks = _build(db, case, acc, now=NOW)
    assert set(tasks.failed) >= {todo.BOARD, todo.PLAN, todo.BLOCKS}
    assert not todo.find(tasks, "plan:identify")
    assert db.scalar(select(CaseTask.status).where(CaseTask.case_id == case.id,
                                                   CaseTask.key == "plan:identify")) == todo.OPEN
    assert todo.find(tasks, "setup:evidence_ai") is not None  # the other sources still read


# --------------------------------------------------------------------------- one state across roles
def _rows(db, case) -> dict:
    db.expire_all()
    return {r.key: (r.status, r.fingerprint, r.title, r.snoozed_until, r.done_by)
            for r in db.scalars(select(CaseTask).where(CaseTask.case_id == case.id))}


def test_a_dismissal_holds_whoever_opens_the_list(db, case):
    adm, inv, ro = _acc(db, case), _acc(db, case, "investigator"), _acc(db, case, "read_only")
    tasks = _build(db, case, adm, now=NOW)
    # owner lookups are on by default: investigators and admins both run them from the identify move
    assert _task(tasks, "plan:identify").action.label == _task(_build(db, case, inv, now=NOW), "plan:identify").action.label
    keys = [t.key for t in todo.open_tasks(tasks, NOW) if t.source in (todo.BOARD, todo.PLAN)]
    assert "plan:identify" in keys and any(k.startswith("board:") for k in keys)
    for k in keys:
        todo.apply(db, adm, _task(_build(db, case, adm, now=NOW), k), "dismiss", note="synthetic", now=NOW)
    before = _rows(db, case)
    assert all(before[k][0] == todo.DISMISSED for k in keys)
    for acc in (inv, ro, adm, ro, inv):
        tasks = _build(db, case, acc, now=NOW)  # persist=True, as the tab and the Overview build it
        for k in keys:
            t = todo.find(tasks, k)
            assert t is None or t.status == todo.DISMISSED, (acc.role, k, t.status)
        assert _rows(db, case) == before, acc.role  # no role's view rewrites another's state, title or fingerprint
    adm_view = _build(db, case, adm, now=NOW)
    assert all(_task(adm_view, k).status == todo.DISMISSED for k in keys)


def test_board_fingerprints_ignore_the_action_labels(db, case):
    """The labels a role changes ("Open & send e-mail" vs "Open the prepared e-mail") are not the source's state."""
    acc = _acc(db, case)

    def fps(board) -> dict:
        c = todo._Ctx(db=db, case=case, access=acc, now=NOW, mask=desk.contact_mask(acc), board=board)
        todo._board(c)
        return {t.key: t.fingerprint for t in c.tasks}

    board = fb.build(db, case, acc, now=NOW)
    first = fps(board)
    assert first
    for t in board.targets:
        if t.step.label:
            t.step.label = ("Open the prepared e-mail" if t.step.label.startswith("Open & send") else
                            t.step.label + " (case admin)")
    assert fps(board) == first


def test_a_read_only_view_writes_nothing(db, case, monkeypatch):
    adm, ro = _acc(db, case), _acc(db, case, "read_only")
    t = _task(_build(db, case, adm, now=NOW), "plan:trace_next")
    todo.apply(db, adm, t, "snooze", days=1, now=NOW)
    todo.create(db, adm, title="Synthetic manual task", priority="P3")
    manual = db.scalar(select(CaseTask).where(CaseTask.case_id == case.id, CaseTask.source == todo.MANUAL))
    todo.apply(db, adm, todo.find(_build(db, case, adm, now=NOW), manual.key), "snooze", days=1, now=NOW)
    before = _rows(db, case)
    later = NOW + timedelta(days=2)  # both snoozes lapsed: open again on the list, but only an investigator writes it
    tasks = _build(db, case, ro, now=later)
    assert _task(tasks, "plan:trace_next").status == todo.OPEN and _task(tasks, manual.key).status == todo.OPEN
    assert _rows(db, case) == before
    _build(db, case, adm, now=later)
    after = _rows(db, case)
    assert after["plan:trace_next"][0] == todo.OPEN and after[manual.key][0] == todo.OPEN


def test_a_sensitive_task_is_never_shown_or_closed_below_view_restricted(db, case, client_for):
    from test_block_status import _order
    from test_block_status import _reply as reply
    from test_recovery_plan import TRON_NEW

    order = _order(case, "KuCoin")
    reply(db, case, order, f"Please note the user also sent funds to the external address {TRON_NEW}.",
          at=NOW - timedelta(hours=2), mailbox=True)
    db.commit()
    key = f"plan:fwatch:tron:{TRON_NEW}"
    inv_c = client_for("investigator", case=case, email="todo-inv-sens@tests.example")
    ro_c = client_for("read_only", case=case, email="todo-ro-sens@tests.example")
    inv = CaseAccess(case=case, user=inv_c.user, role=CaseRole.INVESTIGATOR, member=None)
    ro = CaseAccess(case=case, user=ro_c.user, role=CaseRole.READ_ONLY, member=None)
    t = _task(_build(db, case, inv), key)
    assert t.sensitive and "for an issuer freeze" in t.title
    assert todo.find(_build(db, case, ro), key) is None  # below view_restricted: not derived
    todo.apply(db, inv, t, "snooze", days=3)
    db.expire_all()
    row = db.scalar(select(CaseTask).where(CaseTask.case_id == case.id, CaseTask.key == key))
    assert row.sensitive and row.status == todo.SNOOZED
    page = ro_c.get(f"/cases/{case.id}?tab=todo")
    assert page.status_code == 200 and t.title not in page.text and TRON_NEW[:6] not in page.text
    assert todo.find(_build(db, case, ro), key) is None
    assert all(x["key"] != key for x in ro_c.get(f"/api/cases/{case.id}/todo").json()["open"])
    db.expire_all()
    row = db.scalar(select(CaseTask).where(CaseTask.case_id == case.id, CaseTask.key == key))
    assert row.status == todo.SNOOZED and row.done_at is None  # never closed as resolved by a view that cannot see it
    assert _task(_build(db, case, inv), key).status == todo.SNOOZED
    assert t.title in inv_c.get(f"/cases/{case.id}?tab=todo").text  # the investigator's Snoozed list


def test_tasks_a_viewer_cannot_derive_stay_as_they_are(db, case):
    adm, inv = _acc(db, case), _acc(db, case, "investigator")
    # the system's unassigned queue (system admins) and an evidence item in the Financial folder (case admins)
    sysadm = ensure_user(db, "todo-sysadmin@tests.example", system_admin=True)
    set_role(db, case, sysadm, "admin")
    sa_acc = CaseAccess(case=case, user=sysadm, role=CaseRole.ADMIN, member=None)
    db.add(MailMessage(direction=MailDirection.IN, status=MailStatus.UNASSIGNED, transport="file",
                       mailbox="investigations@athena-demo.example", message_id="<todo-unassigned@demo.example>",
                       subject="Unclaimed (synthetic)", received_at=NOW - timedelta(hours=2)))
    item = EvidenceItem(case_id=case.id, folder=EvidenceFolder.FINANCIAL, title="Bank statement (synthetic)",
                        storage=EvidenceStorage.INLINE, inline_text="synthetic", tags=[],
                        meta={"intel": {"rules": {"type": "police_report"}}})
    db.add(item)
    db.commit()
    tasks = _build(db, case, sa_acc, now=NOW)
    for k in (todo.UNASSIGNED_KEY, f"evidence:confirm:{item.id}"):
        todo.apply(db, sa_acc, _task(tasks, k), "snooze", days=3, now=NOW)
    before = _rows(db, case)
    for acc in (inv, adm):
        tasks = _build(db, case, acc, now=NOW)
        assert todo.find(tasks, todo.UNASSIGNED_KEY) is None
        if acc is inv:
            assert todo.find(tasks, f"evidence:confirm:{item.id}") is None  # the Financial folder: case admins
    assert _rows(db, case) == before
    assert {_task(_build(db, case, sa_acc, now=NOW), k).status
            for k in (todo.UNASSIGNED_KEY, f"evidence:confirm:{item.id}")} == {todo.SNOOZED}


def test_sender_profile_is_p2_while_letters_wait_to_go_out(db, case):
    acc = _acc(db, case)
    db.delete(sender_mod.get_profile(db, case))
    db.commit()
    tasks = _build(db, case, acc, now=NOW)
    board = fb.build(db, case, acc, now=NOW)
    le = [t for t in board.targets if t.step.label and t.step.kind in ("le", "pack")]
    assert le or [t for t in board.targets if t.group in (fb.ACT, fb.CLAIM) and t.step.label]
    assert _task(tasks, "setup:sender_profile").priority == todo.P2


# --------------------------------------------------------------------------- manual tasks, roles, audit, pages
def _post(c, url, data, case_id):
    return c.post(url, data={**data, "csrf_token": csrf_token(c, f"/cases/{case_id}?tab=todo")},
                  follow_redirects=False)


def test_manual_tasks_crud_roles_and_audit(db, case, client_for):
    inv = client_for("investigator", case=case)
    adm = client_for("admin", case=case)
    ro = client_for("read_only", case=case)
    base = f"/cases/{case.id}/todo"
    r = _post(inv, f"{base}/add", {"title": "Call the KuCoin desk (synthetic)", "priority": "P1",
                                   "due": (NOW + timedelta(days=1)).strftime("%Y-%m-%d"),
                                   "assignee_id": str(adm.user.id), "note": "ask for the ticket"}, case.id)
    assert r.status_code == 303 and "tab=todo" in r.headers["location"] and "#t-" in r.headers["location"]
    db.expire_all()
    row = db.scalar(select(CaseTask).where(CaseTask.case_id == case.id, CaseTask.source == "manual"))
    assert row.key == f"manual:{row.id}" and row.priority_override == "P1" and row.assignee_id == adm.user.id
    ev = db.scalar(select(AuditEvent).where(AuditEvent.object_type == "case_tasks", AuditEvent.object_id == str(row.id),
                                            AuditEvent.action == "CREATE"))
    assert ev is not None and ev.detail["fields"] == ["title", "note", "due", "assignee"]
    assert "KuCoin" not in str(ev.detail) and "ticket" not in str(ev.detail)  # ids and field names only
    # the page: the task, the badge (an open P1), the controls for investigators and up only
    page = inv.get(f"/cases/{case.id}?tab=todo").text
    assert 'id="tab-todo"' in page and "Call the KuCoin desk (synthetic)" in page and 'class="todo-badge"' in page
    assert f'action="{base}/task"' in page and "Add task" in page
    ro_page = ro.get(f"/cases/{case.id}?tab=todo")
    assert ro_page.status_code == 200 and "Call the KuCoin desk (synthetic)" in ro_page.text
    assert f'action="{base}/task"' not in ro_page.text and f'action="{base}/add"' not in ro_page.text
    assert 'class="btn small primary"' not in ro_page.text.split('id="todo"')[1].split("Done recently")[0]
    assert _post(ro, f"{base}/add", {"title": "x"}, case.id).status_code == 403
    assert _post(ro, f"{base}/task", {"key": row.key, "op": "done"}, case.id).status_code == 403
    # edit, done, reopen, dismiss: each audited with the op and the changed field names
    r = _post(inv, f"{base}/task", {"key": row.key, "op": "edit", "title": "Call the desk again (synthetic)",
                                    "priority": "P3", "due": "", "assignee_id": "", "note": ""}, case.id)
    assert r.status_code == 303
    db.expire_all()
    row = db.get(CaseTask, row.id)
    assert (row.title, row.priority_override, row.due_override, row.assignee_id, row.note) == (
        "Call the desk again (synthetic)", "P3", None, None, None)
    for op in ("done", "reopen", "dismiss"):
        assert _post(inv, f"{base}/task", {"key": row.key, "op": op, "note": "synthetic"}, case.id).status_code == 303
    db.expire_all()
    assert db.get(CaseTask, row.id).status == todo.DISMISSED
    ops = [e.detail.get("op") for e in db.scalars(select(AuditEvent).where(
        AuditEvent.object_type == "case_tasks", AuditEvent.object_id == str(row.id),
        AuditEvent.action == "UPDATE").order_by(AuditEvent.id))]
    assert ops == ["edit", "done", "reopen", "dismiss"]
    edit = db.scalar(select(AuditEvent).where(AuditEvent.object_type == "case_tasks", AuditEvent.action == "UPDATE",
                                              AuditEvent.object_id == str(row.id)).order_by(AuditEvent.id))
    assert set(edit.detail["fields"]) == {"title", "priority_override", "due_override", "assignee_id", "note"}
    assert "synthetic" not in str(edit.detail)
    assert "Done recently" in inv.get(f"/cases/{case.id}?tab=todo").text
    # refused input
    assert _post(inv, f"{base}/add", {"title": ""}, case.id).status_code == 400
    assert _post(inv, f"{base}/add", {"title": "x", "priority": "P9"}, case.id).status_code == 400
    assert _post(inv, f"{base}/add", {"title": "x", "assignee_id": str(ro.user.id)}, case.id).status_code == 400
    assert _post(inv, f"{base}/add", {"title": "x", "due": "tomorrow"}, case.id).status_code == 400
    assert _post(inv, f"{base}/task", {"key": "board:entity-999999", "op": "done"}, case.id).status_code == 404
    assert _post(inv, f"{base}/task", {"key": row.key, "op": "explode"}, case.id).status_code == 400


def test_derived_task_actions_over_http(db, case, client_for):
    inv = client_for("investigator", case=case)
    tasks = _build(db, case, _acc(db, case), now=NOW)
    key = _task(tasks, "plan:trace_next").key
    r = _post(inv, f"/cases/{case.id}/todo/task", {"key": key, "op": "snooze", "days": "1"}, case.id)
    assert r.status_code == 303 and "done=snooze" in r.headers["location"]
    db.expire_all()
    row = db.scalar(select(CaseTask).where(CaseTask.case_id == case.id, CaseTask.key == key))
    assert row.status == todo.SNOOZED and row.source == todo.PLAN and row.fingerprint
    ev = db.scalar(select(AuditEvent).where(AuditEvent.object_type == "case_tasks", AuditEvent.action == "UPDATE",
                                            AuditEvent.object_id == str(row.id)))
    assert ev.detail["op"] == "snooze" and ev.detail["days"] == 1 and ev.detail["derived"] is True
    assert "key" not in ev.detail  # a plan key can carry a wallet address: never in the audit row
    page = inv.get(f"/cases/{case.id}?tab=todo").text
    assert "Snoozed" in page and "Wake now" in page


def test_externals_see_nothing_and_the_tab_sits_after_overview(db, case, client_for):
    from app.web.tabs import TABS

    assert [t.key for t in TABS][:2] == ["overview", "todo"]
    ext = client_for("external", case=case)
    page = ext.get(f"/cases/{case.id}?tab=todo").text
    assert 'id="tab-todo"' not in page and 'data-tab="todo"' not in page
    assert ext.get(f"/api/cases/{case.id}/todo").status_code == 403
    assert ext.get(f"/cases/{case.id}/todo", follow_redirects=False).status_code == 403
    outsider = client_for(None, case=case, email="todo-outsider@tests.example")
    assert outsider.get(f"/api/cases/{case.id}/todo").status_code == 404
    assert todo.build(db, case, CaseAccess(case=case, user=ext.user, role=CaseRole.EXTERNAL, member=None)) == []


def test_pages_render_overview_card_api_and_redirect(db, case, client_for):
    adm = client_for("admin", case=case)
    r = adm.get(f"/cases/{case.id}/todo", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/cases/{case.id}?tab=todo"
    page = adm.get(f"/cases/{case.id}?tab=todo")
    assert page.status_code == 200 and 'id="tab-todo"' in page.text and "To do" in page.text
    assert "<script>" not in page.text.split('id="tab-todo"')[1]  # no inline script (CSP)
    for flt in ("show=mine", "show=p1", "source=board", "source=nope"):
        assert adm.get(f"/cases/{case.id}?tab=todo&{flt}").status_code == 200
    assert 'src="/static/js/todo.js"' in page.text and adm.get("/static/js/todo.js").status_code == 200
    assert adm.get("/static/css/todo.css").status_code == 200
    ov = adm.get(f"/cases/{case.id}?tab=overview").text
    assert 'id="todo-card"' in ov and "Open To do" in ov
    card = ov.split('id="todo-card"')[1].split('</table>')[0]
    assert 'class="todo-table todo-card-table"' in card
    for col in ("Priority", "Task", "Due", "Source", "Assignee", "Next step"):
        assert f"<th>{col}</th>" in card
    assert 0 < card.count('class="todo-row') <= routes_todo.CARD_ROWS == 8
    api = adm.get(f"/api/cases/{case.id}/todo").json()
    assert api["case"] == case.reference and api["open"] and {"key", "priority", "due_at", "source"} <= set(api["open"][0])
    ro = client_for("read_only", case=case)
    assert all(x["action"] is None for x in ro.get(f"/api/cases/{case.id}/todo").json()["open"])


def test_todo_skill_lists_the_top_items(db, case):
    from app.ai import skills

    acc = _acc(db, case, "read_only")
    todo.create(db, _acc(db, case, "investigator"), title="Phone the victim (synthetic private note)", priority="P1")
    res = skills.run_skill(db, acc, "todo", "")
    assert res.source == "rule_based" and res.markdown.startswith("**To do**")
    assert "manual task #" in res.markdown and "synthetic private note" not in res.markdown  # free text never quoted
    assert any(a.get("href") == f"/cases/{case.id}?tab=todo" for a in res.actions)
    assert "todo" in skills.SKILLS and skills.SKILLS["todo"].needs_ai


# --------------------------------------------------------------------------- one pass of each source
def test_one_pass_of_each_source(db, case, monkeypatch):
    acc = _acc(db, case)
    calls: dict[str, int] = {}
    paused = [0]

    def wrap(mod, name):
        fn = getattr(mod, name)

        def inner(*a, **k):
            calls[f"{mod.__name__}.{name}"] = calls.get(f"{mod.__name__}.{name}", 0) + 1
            paused[0] += 1
            try:
                return fn(*a, **k)
            finally:
                paused[0] -= 1
        monkeypatch.setattr(mod, name, inner)

    for mod, name in ((fb, "build"), (bs, "case_blocks"), (rp, "build")):
        wrap(mod, name)
    count = [0]

    def on_query(*_a, **_k):
        if not paused[0]:
            count[0] += 1

    def own_queries() -> int:
        db.expire_all()
        count[0] = 0
        calls.clear()
        event.listen(engine, "before_cursor_execute", on_query)
        try:
            todo.build(db, case, acc, now=NOW)
        finally:
            event.remove(engine, "before_cursor_execute", on_query)
        # the board once, the Recovery plan inside it once, the block rows once
        assert calls == {"app.blocks.freeze_board.build": 1, "app.blocks.recovery.build": 1,
                         "app.blocks.status.case_blocks": 1}, calls
        return count[0]

    own_queries()  # warm
    base = own_queries()
    for i in range(6):
        todo.create(db, acc, title=f"Synthetic task {i}", priority="P3")
    assert own_queries() <= base + 1  # the manual tasks come in the one case_tasks read (and one users read)


def test_migration_0012_up_down_up(tmp_path):
    from sqlalchemy import create_engine, inspect, text
    from sqlalchemy.exc import IntegrityError
    from test_migrations import _cfg

    from alembic import command

    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "0012_case_tasks")
    with engine.connect() as conn:
        cols = {c["name"] for c in inspect(conn).get_columns("case_tasks")}
        assert {"id", "case_id", "key", "title", "note", "priority_override", "due_override", "assignee_id", "status",
                "snoozed_until", "dismissed_note", "created_by", "created_at", "updated_at", "done_at", "done_by",
                "source", "fingerprint", "sensitive"} <= cols
    insert = text("INSERT INTO cases (reference, title, status, facts, ai_mode) VALUES ('MIG-1', 't', 'open', '{}', "
                  "'redacted')")
    task = text("INSERT INTO case_tasks (case_id, key, title) VALUES (1, 'manual:1', 'synthetic')")
    with engine.begin() as conn:
        conn.execute(insert)
        conn.execute(task)
        row = conn.execute(text("SELECT status, source FROM case_tasks")).one()
        assert tuple(row) == ("open", "manual")  # the server defaults
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(task)  # one row per case and key
    with engine.begin() as conn:
        command.downgrade(_cfg(conn), "0011_wallet_attributions")
    with engine.connect() as conn:
        assert "case_tasks" not in inspect(conn).get_table_names()
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    with engine.connect() as conn:
        assert "case_tasks" in inspect(conn).get_table_names()
    engine.dispose()


def test_an_overdue_task_is_p1_whatever_priority_it_was_given(db, case):
    """A manual task past its due date, and a derived task whose due date a person moved into the past, are P1 (the
    module's rule: overdue is P1); a person's explicit priority on a derived task stands."""
    acc = _acc(db, case)
    past = (NOW - timedelta(days=2)).date().isoformat()
    todo.create(db, acc, title="Synthetic overdue manual task", priority="P3", due=past)
    t = next(x for x in _build(db, case, acc, now=NOW) if x.title == "Synthetic overdue manual task")
    assert t.priority == "P1"
    d = next(x for x in _build(db, case, acc, now=NOW) if x.source != todo.MANUAL and x.priority == "P3")
    todo.apply(db, acc, d, "edit", due=past, now=NOW)
    assert _task(_build(db, case, acc, now=NOW), d.key).priority == "P1"
    todo.apply(db, acc, _task(_build(db, case, acc, now=NOW), d.key), "edit", priority="P3", due=past, now=NOW)
    assert _task(_build(db, case, acc, now=NOW), d.key).priority == "P3"  # chosen by a person: it stands


def test_le_contact_links_open_the_law_enforcement_folder_where_the_contacts_are(db, case):
    acc = _acc(db, case)
    for t in _build(db, case, acc, now=NOW):
        href = (t.action.href if t.action else "") or ""
        if "#ev-contact" in href:
            assert "folder=law_enforcement" in href, (t.key, href)
