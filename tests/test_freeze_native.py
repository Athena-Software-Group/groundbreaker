"""The native-coin watch (app.freeze.native), offline: a mocked JSON-RPC node behind httpx.MockTransport. What matters
most is that a real movement is never missed, that dust raises no alarm, and that a watch that stopped reading shows."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import delete, select

from app.core.config import get_settings
from app.db.models import FreezeSetting, FreezeWatch, NativeBalance, Notification
from app.freeze import native, service

WALLET = "0x" + "cd" * 20
ETH = 10**18
T0 = datetime(2026, 11, 6, 12, tzinfo=UTC)
SETTINGS = get_settings().model_copy(update={
    "aegis_eth_rpc_url": "https://ethereum.publicnode.com", "aegis_freeze_retries": 0, "aegis_freeze_min_interval": 0.0,
    "aegis_freeze_checks_disabled": "", "aegis_freeze_explorer": "none"})


class Node:
    def __init__(self):
        self.wei, self.nonce, self.down, self.calls = 54 * ETH, 0, False, []

    def handler(self, request: httpx.Request) -> httpx.Response:
        method = json.loads(request.content)["method"]
        self.calls.append(method)
        if self.down:
            return httpx.Response(503)
        result = self.wei if method == "eth_getBalance" else self.nonce
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": hex(result)})


def _clear(db):
    db.execute(delete(NativeBalance))
    db.execute(delete(FreezeWatch))
    db.execute(delete(FreezeSetting))
    db.execute(delete(Notification).where(Notification.event_type == "wallet_movement"))
    db.commit()


@pytest.fixture(autouse=True)
def _clean(db):
    _clear(db)
    yield
    db.rollback()
    _clear(db)


@pytest.fixture
def node():
    return Node()


@pytest.fixture
def watch(db, case):
    service.set_enabled(db, case, None, True, settings=SETTINGS)
    row = service.add_watch(db, case, None, chain="ethereum", address=WALLET, label="Secret label from a tip")
    db.commit()
    return row


def _pass(db, node, at=T0):
    return native.run_all(db, settings=SETTINGS, transport=httpx.MockTransport(node.handler), now=at)


def _notes(db, case):
    return list(db.scalars(select(Notification).where(Notification.case_id == case.id,
                                                      Notification.event_type == "wallet_movement")))


def _row(db):
    db.expire_all()
    return db.scalar(select(NativeBalance))


def test_the_first_reading_sets_the_baseline_without_an_alert(db, case, watch, node):
    assert _pass(db, node)["wallets"] == 1
    row = _row(db)
    assert row.wei == str(54 * ETH) and row.nonce == 0 and row.checked_at is not None and _notes(db, case) == []


def test_eth_leaving_alerts_as_critical_and_names_no_label(db, case, watch, node):
    node.nonce = 3
    _pass(db, node)
    node.wei, node.nonce = 14 * ETH, 4
    assert _pass(db, node, T0 + timedelta(minutes=2))["moved"] == 1
    note, = _notes(db, case)
    assert note.severity == "critical" and "40.0000 ETH" in note.title and note.usd == Decimal("102000.00")
    assert "Secret label" not in f"{note.title} {note.body}" and WALLET not in f"{note.title} {note.body}"
    assert _row(db).moved_at is not None


def test_a_first_transaction_ever_alerts_however_small(db, case, watch, node):
    _pass(db, node)
    node.wei, node.nonce = 54 * ETH - 10**15, 1  # 0.001 ETH: a test payment
    _pass(db, node, T0 + timedelta(minutes=2))
    note, = _notes(db, case)
    assert note.severity == "critical" and "first transaction" in note.title
    assert note.usd == Decimal("137700.00")  # the balance at stake, so the rule's minimum cannot swallow it


def test_incoming_funds_and_a_steady_wallet_raise_nothing(db, case, watch, node):
    _pass(db, node)
    _pass(db, node, T0 + timedelta(minutes=2))
    node.wei += 10**12
    assert _pass(db, node, T0 + timedelta(minutes=4))["moved"] == 0
    assert _notes(db, case) == [] and _row(db).wei == str(54 * ETH + 10**12)


def test_a_small_spend_is_recorded_and_left_to_the_case_rule(db, case, watch, node):
    node.nonce = 5
    _pass(db, node)
    node.wei, node.nonce = 54 * ETH - 5 * 10**16, 6  # 0.05 ETH, under the default $1,000
    assert _pass(db, node, T0 + timedelta(minutes=2))["moved"] == 1
    assert _notes(db, case) == [] and _row(db).moved_at is not None and _row(db).nonce == 6


def test_a_failed_reading_keeps_the_last_good_one_and_flags_it_when_stale(db, case, watch, node):
    _pass(db, node)
    node.down = True
    assert _pass(db, node, T0 + timedelta(minutes=2))["errors"] == 1
    row = _row(db)
    assert row.wei == str(54 * ETH) and row.error and _notes(db, case) == []
    assert native.view(db, case, now=T0 + timedelta(minutes=10))[0]["stale"] is False
    stale = native.view(db, case, now=T0 + timedelta(minutes=45))[0]
    assert stale["stale"] is True and stale["error"] and stale["balance"] == 54
    node.down = False
    _pass(db, node, T0 + timedelta(minutes=46))
    assert _row(db).error is None


def test_a_movement_during_an_outage_alerts_when_reads_return(db, case, watch, node):
    node.nonce = 2
    _pass(db, node)
    node.down, node.wei, node.nonce = True, 0, 3
    _pass(db, node, T0 + timedelta(minutes=2))
    node.down = False
    assert _pass(db, node, T0 + timedelta(minutes=4))["moved"] == 1
    assert len(_notes(db, case)) == 1


def test_nothing_is_sent_while_the_checks_are_off(db, case, watch, node):
    service.set_enabled(db, case, None, False, settings=SETTINGS)
    db.commit()
    _pass(db, node)
    assert node.calls == []


def test_nothing_is_sent_to_a_host_the_admin_did_not_confirm(db, case, watch, node):
    moved = SETTINGS.model_copy(update={"aegis_eth_rpc_url": "https://other.publicnode.com"})
    native.run_all(db, settings=moved, transport=httpx.MockTransport(node.handler), now=T0)
    assert node.calls == []


def test_only_ethereum_wallets_are_read(db, case, node):
    service.set_enabled(db, case, None, True, settings=SETTINGS)
    service.add_watch(db, case, None, chain="tron", address="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
    db.commit()
    _pass(db, node)
    assert node.calls == [] and native.view(db, case) == []


def test_the_freeze_page_shows_the_balances(db, case, watch, node, client_for):
    _pass(db, node)
    page = client_for("admin", case=case).get(f"/cases/{case.id}/freeze")
    assert page.status_code == 200 and "ETH on watched wallets" in page.text and "54.0000 ETH" in page.text
