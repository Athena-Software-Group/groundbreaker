"""Verify round 8, the freeze checks: an exchange deposit address swept into its exchange (its balance falling to 0
between two good readings, the normal sweep: the account was credited) raises no "funds left" alert, move or Overview
line; a self-custody wallet draining still does. Synthetic addresses and readings on the demo case; offline."""

from __future__ import annotations

import test_freeze_checks as _fc
from sqlalchemy import select
from test_freeze_checks import USDT_ETH, enable

from app.attribution import service as attr
from app.blocks import recovery as rp
from app.db.models import Notification
from app.freeze import service
from app.freeze import transport as tp

_offline, chain, run = _fc._offline, _fc.chain, _fc.run  # the freeze tests' fixtures (offline chain mock)
DEP = "0x" + "d4" * 20
SELF = "0x" + "d6" * 20


def _drain(db, case, chain, *addresses):
    enable(db, case)
    for a in addresses:
        chain.balances[(USDT_ETH, a)] = 20_000 * 10**6
    service.run_checks(db, case)
    tp.clear_cache()
    for a in addresses:
        chain.balances[(USDT_ETH, a)] = 0
    return service.run_checks(db, case)


def test_a_swept_deposit_address_is_no_funds_left_alert(db, case, run, chain):
    for a in (DEP, SELF):
        service.add_watch(db, case, None, chain="ethereum", address=a)
    attr.mark(db, case, None, chain="ethereum", address=DEP, owner="KuCoin", kind="exchange_deposit")
    db.commit()
    rep = _drain(db, case, chain, DEP, SELF)
    assert len(rep.swept) == 1 and len(rep.funds_left) == 1
    notes = [n for n in db.scalars(select(Notification).where(Notification.case_id == case.id,
                                                              Notification.event_type == "wallet_movement"))
             if (n.payload or {}).get("freeze_check_id") in rep.swept + rep.funds_left]
    assert len(notes) == 1 and "d6d6d6" in notes[0].title  # the self-custody wallet only
    rows = {w["address"]: w for w in service.wallet_rows(db, case)}
    assert rows[DEP]["funds_left"] == [] and any(c.get("swept", {}).get("owner") == "KuCoin"
                                                  for c in rows[DEP]["checks"])
    assert rows[SELF]["funds_left"]
    plan = rp.build(db, case)
    assert plan.find(f"left:ethereum:{DEP}") is None and plan.find(f"left:ethereum:{SELF}") is not None
    moved = [w["address"] for w in service.case_status(db, case)["moved"]]
    assert DEP not in moved and SELF in moved


def test_a_hot_wallet_an_explorer_tag_names_is_a_float_not_funds_left(db, case, run, chain):
    service.add_watch(db, case, None, chain="ethereum", address=DEP)
    attr.mark(db, case, None, chain="ethereum", address=DEP, owner="KuCoin", kind="exchange_hot_wallet")
    db.commit()
    enable(db, case)
    chain.balances[(USDT_ETH, DEP)] = 2_000_000 * 10**6
    service.run_checks(db, case)
    tp.clear_cache()
    chain.balances[(USDT_ETH, DEP)] = 1_000_000 * 10**6
    rep = service.run_checks(db, case)
    assert rep.funds_left == []
