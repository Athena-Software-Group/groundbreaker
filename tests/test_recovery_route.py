"""The plain route from a frozen balance to money returned, on top of the To do tab (app.domain.recovery_route). It must
be honest: only frozen money gets steps, who does each step is stated, and a step ticked in the list shows as done."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace

import pytest
from sqlalchemy import delete

from app.core.permissions import CaseAccess
from app.db.models import CaseRole, FreezeSetting, FreezeWatch, NativeBalance
from app.domain import correspondence as desk
from app.domain import recovery_route as rr
from app.domain import todo
from app.freeze import service

WALLET = "0x" + "ef" * 20


def _clear(db):
    db.execute(delete(NativeBalance))
    db.execute(delete(FreezeWatch))
    db.execute(delete(FreezeSetting))
    db.commit()


@pytest.fixture(autouse=True)
def _clean(db):
    _clear(db)
    yield
    db.rollback()
    _clear(db)


def _tasks(*done):
    out = []
    for s in rr.steps("Tether"):
        key = f"{todo.ROUTE}:{s.key}"
        out.append(todo.Task(key=key, title=s.title, source=todo.ROUTE, value=100_000.0,
                             status=todo.DONE if s.key in done else todo.OPEN))
    return out


def _derived(db, case, frozen):
    access = CaseAccess(case=case, user=None, role=CaseRole.ADMIN, member=None)
    c = todo._Ctx(db=db, case=case, access=access, now=datetime.now(tz=UTC), mask=desk.contact_mask(access),
                  board=SimpleNamespace(plan=SimpleNamespace(totals={"secured_usd": frozen})))
    todo._route(c)
    return c.tasks


def test_the_steps_say_who_acts_and_never_promise_the_issuer():
    steps = rr.steps("Tether")
    assert [s.key for s in steps] == ["evidence", "issuer", "seizure", "return"]
    assert "Get law enforcement to contact Tether" == steps[1].title and "cannot release" in steps[1].why
    assert all(s.who for s in steps) and "Expect months" in steps[3].why


def test_with_no_issuer_the_steps_name_the_service():
    assert "the service holding the funds" in rr.steps(None)[1].title
    assert rr.steps(None)[1].why.startswith("The service")


def test_the_buckets_add_up_to_the_loss(db, case):
    pos = rr.position(db, case, 100_000.0)
    assert pos["frozen"] == 100_000.0 and pos["parked"] == 0 and pos["wallets"] == 0
    assert pos["elsewhere"] == pytest.approx(float(case.loss_usd) - 100_000.0)


def test_watched_eth_counts_as_parked_and_dust_does_not(db, case):
    service.set_enabled(db, case, None, True)
    big = service.add_watch(db, case, None, chain="ethereum", address=WALLET)
    dust = service.add_watch(db, case, None, chain="ethereum", address="0x" + "ee" * 20)
    db.add_all([NativeBalance(case_id=case.id, watch_id=big.id, chain="ethereum", address=WALLET, wei=str(10 * 10**18), nonce=0,
                              checked_at=datetime.now(tz=UTC)),
                NativeBalance(case_id=case.id, watch_id=dust.id, chain="ethereum", address=dust.address, wei=str(10**15), nonce=1,
                              checked_at=datetime.now(tz=UTC))])
    db.commit()
    pos = rr.position(db, case, 0.0)
    assert pos["wallets"] == 1 and pos["parked"] == 25_500.0


def test_the_buckets_never_go_negative(db, case):
    assert rr.position(db, case, float(case.loss_usd) * 2)["elsewhere"] == 0


def test_nothing_frozen_means_no_steps_and_no_tasks(db, case):
    assert rr.view(db, case, [])["steps"] == [] and _derived(db, case, 0) == []


def test_a_frozen_balance_makes_the_steps_tasks(db, case):
    tasks = _derived(db, case, 103_000.0)
    assert [t.key for t in tasks] == ["route:evidence", "route:issuer", "route:seizure", "route:return"]
    assert [t.derived_priority for t in tasks] == [todo.P1, todo.P1, todo.P2, todo.P2]
    assert all(t.source == todo.ROUTE and t.value == 103_000.0 for t in tasks)


def test_the_next_step_follows_what_was_ticked(db, case):
    first = rr.view(db, case, _tasks())["steps"]
    assert [s["next"] for s in first] == [True, False, False, False] and not any(s["done"] for s in first)
    later = rr.view(db, case, _tasks("evidence"))["steps"]
    assert later[0]["done"] and later[1]["next"] and not later[2]["next"]


def test_the_frozen_amount_comes_from_the_route_tasks(db, case):
    assert rr.view(db, case, _tasks())["frozen"] == 100_000.0


BUCKETS = {"loss": 1000.0, "parked": 0.0, "wallets": 0, "elsewhere": 900.0}


@pytest.mark.parametrize("route, wording", [
    ({**BUCKETS, "frozen": 0.0, "steps": []}, "Nothing is frozen yet"),
    ({**BUCKETS, "frozen": 100.0, "steps": [{"title": "Give the police the proof", "why": "w", "who": "You", "done": False,
                                             "next": True}]}, "Frozen money does not come back by itself")])
def test_the_todo_tab_leads_with_the_route(db, case, client_for, monkeypatch, route, wording):
    monkeypatch.setattr(rr, "view", lambda db, case, tasks: route)  # the demo case's state varies with the tests before
    page = client_for("investigator", case=case).get(f"/cases/{case.id}?tab=todo")
    assert page.status_code == 200 and "How you get your money back" in page.text and wording in page.text
    assert page.text.index("How you get your money back") < page.text.index('id="todo"')


def test_the_panel_says_it_is_not_legal_advice_when_there_are_steps():
    from pathlib import Path

    assert "not legal advice" in Path("app/web/templates/case/_recovery_route.html").read_text(encoding="utf-8")


def test_a_decimal_loss_is_handled(db, case):
    assert isinstance(rr.position(db, case, float(Decimal("1.50")))["elsewhere"], float)
