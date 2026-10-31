"""Verify round 9, the freeze checks and the Recovery plan on the demo case (offline chain mock; synthetic
readings): a deposit address only the behaviour profile identifies (it forwards everything to a known exchange hot
wallet within minutes) is swept into that exchange, never a high "funds left" alert; a swap service's payout wallet
(its float) draining is never the case's funds leaving, nor the plan's top move at the whole drop."""

from __future__ import annotations

import pytest
import test_freeze_checks as _fc
from sqlalchemy import select
from test_freeze_checks import USDT_ETH, USDT_TRON, enable

from app import services
from app.attribution import service as attr
from app.blocks import recovery as rp
from app.db.models import AddressType, Notification, TraceNode
from app.freeze import service
from app.freeze import transport as tp

_offline, chain, run = _fc._offline, _fc.chain, _fc.run  # the freeze tests' fixtures (offline chain mock)
KUCOIN_DEPOSIT = "0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2"


@pytest.fixture
def case(db, tmp_path):
    """A fresh copy of the demo case (these tests change its addresses: never the shared one)."""
    from test_block_status import fresh_case

    c = fresh_case(db, tmp_path)
    services.run_trace(db, c, provider_mode="fixture")
    db.refresh(c)
    return c


def _node(db, case, address: str) -> TraceNode:
    r = services.latest_run(db, case)
    return next(n for n in db.scalars(select(TraceNode).where(TraceNode.run_id == r.id))
                if n.address.address.lower() == address.lower())


def _movement_notes(db, case, ids):
    return [n for n in db.scalars(select(Notification).where(Notification.case_id == case.id,
                                                             Notification.event_type == "wallet_movement"))
            if (n.payload or {}).get("freeze_check_id") in ids]


def _two_readings(db, case, chain, key, before, after):
    enable(db, case)
    chain.balances[key] = before
    service.run_checks(db, case)
    tp.clear_cache()
    chain.balances[key] = after
    return service.run_checks(db, case)


def test_a_deposit_address_the_behaviour_profile_finds_is_swept_not_funds_left(db, case, run, chain):
    a = _node(db, case, KUCOIN_DEPOSIT).address
    was = (a.entity_id, a.address_type)
    a.entity_id, a.address_type = None, AddressType.EOA  # no trace entity, no explorer tag, no person's mark
    db.commit()
    try:
        att = attr.attribute(db, case, asks=False)[("ethereum", KUCOIN_DEPOSIT)]
        assert (att.owner, att.kind, att.source) == ("KuCoin", "exchange_deposit", "behaviour")
        service.add_watch(db, case, None, chain="ethereum", address=KUCOIN_DEPOSIT)
        db.commit()
        rep = _two_readings(db, case, chain, (USDT_ETH, KUCOIN_DEPOSIT), 20_000 * 10**6, 0)
        assert rep.swept and rep.funds_left == [] and _movement_notes(db, case, rep.swept) == []
        rows = {w["address"]: w for w in service.wallet_rows(db, case)}
        assert rows[KUCOIN_DEPOSIT]["funds_left"] == []
        assert any((c.get("swept") or {}).get("owner") == "KuCoin" for c in rows[KUCOIN_DEPOSIT]["checks"])
        assert KUCOIN_DEPOSIT not in [w["address"] for w in service.case_status(db, case)["moved"]]
        assert rp.build(db, case).find(f"left:ethereum:{KUCOIN_DEPOSIT}") is None
    finally:  # the address row is shared by every case of the session
        db.rollback()
        a.entity_id, a.address_type = was
        db.commit()


def test_a_swap_services_payout_wallet_draining_is_its_float_not_funds_left(db, case, run, chain):
    swft = next(n.address for n in db.scalars(select(TraceNode).where(TraceNode.run_id == run.id))
                if (n.address.label or "").startswith("SWFT payout wallet (TRON)"))
    rep = _two_readings(db, case, chain, (USDT_TRON, swft.address), 300_000 * 10**6, 0)
    assert rep.funds_left == [] and rep.float_moved and _movement_notes(db, case, rep.float_moved) == []
    assert not [n for n in db.scalars(select(Notification).where(
        Notification.case_id == case.id, Notification.event_type == "wallet_movement", Notification.severity == "high"))]
    row = next(w for w in service.wallet_rows(db, case) if w["address"] == swft.address)
    assert row["funds_left"] == [] and any((c.get("float_moved") or {}).get("owner") for c in row["checks"])
    plan = rp.build(db, case)
    assert plan.find(f"left:tron:{swft.address}") is None
    assert not plan.moves or (plan.moves[0].value or 0) < 300_000


def test_a_self_custody_wallet_draining_still_alerts(db, case, run, chain):
    self_ = "0x" + "d7" * 20
    service.add_watch(db, case, None, chain="ethereum", address=self_)
    db.commit()
    rep = _two_readings(db, case, chain, (USDT_ETH, self_), 20_000 * 10**6, 0)
    assert len(rep.funds_left) == 1 and len(_movement_notes(db, case, rep.funds_left)) == 1
