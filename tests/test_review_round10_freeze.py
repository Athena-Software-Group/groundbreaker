"""Verify round 10, the freeze checks and the Recovery plan on the demo case (offline chain mock; synthetic
readings): a credited exchange deposit address swept into its exchange raises no alert and stays the plan's freeze
target at what was credited; a wallet whose trace entity is no service (category unknown) owns no float, so its
balance draining is the case's funds leaving; an unnamed low-confidence behaviour guess never silences that alert."""

from __future__ import annotations

import pytest
import test_freeze_checks as _fc
from sqlalchemy import select
from test_freeze_checks import USDT_ETH, USDT_TRON, enable

from app import services
from app.attribution import service as attr
from app.blocks import recovery as rp
from app.db.models import Address, AddressType, Entity, EntityCategory, Notification
from app.freeze import service
from app.freeze import transport as tp

_offline, chain, run = _fc._offline, _fc.chain, _fc.run  # the freeze tests' fixtures (offline chain mock)
TRON_DEST = "TWdZZhGv7zqeRnmxWd65yQSE2YDZRteL77"
KUCOIN_DEPOSIT = "0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2"
KUCOIN_HOT = "0x45300136662dd4e58fc0df61e6290dffd992b785"


@pytest.fixture
def case(db, tmp_path):
    """A fresh copy of the demo case (these tests change its addresses: never the shared one)."""
    from test_block_status import fresh_case

    c = fresh_case(db, tmp_path)
    services.run_trace(db, c, provider_mode="fixture")
    db.refresh(c)
    return c


def _movement_notes(db, case, ids):
    return [n for n in db.scalars(select(Notification).where(Notification.case_id == case.id,
                                                             Notification.event_type == "wallet_movement"))
            if (n.payload or {}).get("freeze_check_id") in ids]


def _reading(db, case, chain, key, units):
    tp.clear_cache()
    chain.balances[key] = units
    return service.run_checks(db, case)


def test_a_swept_deposit_address_raises_no_alert_and_stays_the_freeze_target(db, case, run, chain):
    enable(db, case)
    attr.mark(db, case, None, chain="tron", address=TRON_DEST, owner="Binance", kind="exchange_deposit")
    service.add_watch(db, case, None, chain="tron", address=TRON_DEST)
    db.commit()
    plain = rp.build(db, case)
    _reading(db, case, chain, (USDT_TRON, TRON_DEST), 1360 * 10**6)
    held = rp.build(db, case)
    m = held.find(f"owner:tron:{TRON_DEST}")
    assert m is not None and m.value == pytest.approx(1359.9) and m.counts
    rep = _reading(db, case, chain, (USDT_TRON, TRON_DEST), 0)  # the sweep: the account was credited
    assert rep.swept and rep.funds_left == [] and _movement_notes(db, case, rep.swept) == []
    swept = rp.build(db, case)
    m = swept.find(f"owner:tron:{TRON_DEST}")
    assert m is not None and m.value == pytest.approx(1359.9) and m.counts and "swept" in m.basis
    assert swept.find(f"left:tron:{TRON_DEST}") is None
    assert swept.totals["in_play_sum_usd"] == pytest.approx(held.totals["in_play_sum_usd"])
    assert swept.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"])


def test_a_wallet_of_an_unknown_category_entity_draining_alerts(db, case, run, chain):
    a = db.scalar(select(Address).where(Address.address == KUCOIN_HOT))
    was = (a.entity_id, a.address_type)
    ent = db.scalar(select(Entity).where(Entity.name == "Demo Unknown Org")) or Entity(
        name="Demo Unknown Org", category=EntityCategory.UNKNOWN)
    db.add(ent)
    db.flush()
    a.entity_id, a.address_type = ent.id, AddressType.EOA  # a fixture / correspondence import's default category
    db.commit()
    try:
        enable(db, case)
        service.add_watch(db, case, None, chain="ethereum", address=KUCOIN_HOT)
        db.commit()
        _reading(db, case, chain, (USDT_ETH, KUCOIN_HOT), 20_000 * 10**6)
        rep = _reading(db, case, chain, (USDT_ETH, KUCOIN_HOT), 0)
        assert rep.float_moved == [] and len(rep.funds_left) == 1
        assert [n.severity for n in _movement_notes(db, case, rep.funds_left)] == ["high"]
    finally:  # the address row is shared by every case of the session
        db.rollback()
        a.entity_id, a.address_type = was
        db.commit()
        db.delete(ent)
        db.commit()


def test_an_unnamed_behaviour_guess_never_silences_the_alert(db, case, run, chain):
    rows = {x: db.scalar(select(Address).where(Address.address == x)) for x in (KUCOIN_DEPOSIT, KUCOIN_HOT)}
    was = {x: (a.entity_id, a.address_type) for x, a in rows.items()}
    for a in rows.values():
        a.entity_id, a.address_type = None, AddressType.EOA
    db.commit()
    try:
        attr.mark(db, case, None, chain="ethereum", address=KUCOIN_HOT, owner=None, kind="exchange_hot_wallet")
        enable(db, case)
        service.add_watch(db, case, None, chain="ethereum", address=KUCOIN_DEPOSIT)
        db.commit()
        guess = attr.attribute(db, case, asks=False)[("ethereum", KUCOIN_DEPOSIT)]
        assert (guess.kind, guess.owner, guess.confidence) == ("exchange_deposit", None, "L")
        _reading(db, case, chain, (USDT_ETH, KUCOIN_DEPOSIT), 20_000 * 10**6)
        rep = _reading(db, case, chain, (USDT_ETH, KUCOIN_DEPOSIT), 0)
        assert rep.swept == [] and len(rep.funds_left) == 1 and _movement_notes(db, case, rep.funds_left)
        plan = rp.build(db, case)  # the notification and the plan agree
        assert plan.find(f"left:ethereum:{KUCOIN_DEPOSIT}") is not None
    finally:  # the address rows are shared by every case of the session
        db.rollback()
        for x, a in rows.items():
            a.entity_id, a.address_type = was[x]
        db.commit()
