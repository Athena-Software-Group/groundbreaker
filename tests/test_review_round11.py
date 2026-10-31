"""Verify round 11 (wallet owners, the Recovery plan, evidence intel): traced money is counted once — a deposit tag on
a wallet the trace followed on through its own service's wallets, a service float read on-chain, an issuer reading at
a traced pass-through wallet, an asserted link's unquantified residual, a non-custodial router —; a credited deposit
address keeps every sweep it was read in; a chat export in any format never reads as the agency's own police report,
while a police report that pastes a chat export still does; a report's victim field labels name the victim. The
demo case plus synthetic tags, readings and documents (every address, number and name is made up)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from test_review_round10 import D4, TRON_DEST, _read, _tether
from test_wallet_owners import Explorers, _addr, _consent, _offline, _plan, _tag  # noqa: F401 - _offline: autouse

from app import services
from app.attribution import service as attr
from app.db.models import FreezeCheck
from app.evidence_intel import findings, rules
from app.freeze import service as fz

NOW = datetime.now(tz=UTC)
USDC_ETH = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
LOSS_TRACED = 399_247.92  # the demo's traced loss
V = "0x" + "ab12" * 10  # made-up addresses
W = "0x" + "cd34" * 10


@pytest.fixture
def ex():
    return Explorers()


@pytest.fixture
def case(db, tmp_path):
    from test_block_status import fresh_case

    c = fresh_case(db, tmp_path)
    services.run_trace(db, c, provider_mode="fixture")
    db.refresh(c)
    return c


def _usdc(db, case, address, balance, minutes=5):
    """A good USDC reading `minutes` after now (after the trace)."""
    db.add(FreezeCheck(case_id=case.id, chain="ethereum", address=address, issuer="Circle", token_symbol="USDC",
                       token_contract=USDC_ETH, status="ok", blacklisted=False, balance=Decimal(balance),
                       checked_at=datetime.now(tz=UTC) + timedelta(minutes=minutes), block_number=23_000_000 + minutes,
                       raw_sha256="cd" * 32, meta={"balance_raw": str(int(Decimal(balance) * 10**6))}))
    db.commit()


def _totals(plan) -> tuple[float, float]:
    return plan.totals["in_play_sum_usd"], plan.totals["expected_usd"]


def _same_totals(plan, plain):
    assert plan.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"], abs=0.01)
    assert plan.totals["expected_usd"] == pytest.approx(plain.totals["expected_usd"], abs=0.01)


def _counted(plan) -> list:
    return [m for m in plan.moves + plan.waiting if m.value and (m.counts or (m.authority is not None
                                                                               and ":" not in m.key))]


def _no_double(plan):
    """The money invariant (round 12): no counted move is valued at the whole traced loss; in play is at most the traced
    loss plus the labelled untraced finds; no counted move is larger than the total (its money is in it, at the move or
    at a larger one on the same funds)."""
    t = plan.totals
    assert not any(m.value == pytest.approx(LOSS_TRACED) for m in _counted(plan))
    assert t["in_play_usd"] <= t["traced_loss_usd"] + t["untraced_usd"] + 0.01
    assert t["in_play_sum_usd"] == pytest.approx(t["traced_usd"] + t["untraced_usd"], abs=0.01)
    assert all(m.value <= t["in_play_sum_usd"] + 0.01 for m in _counted(plan))
    assert plan.totals["in_play_sum_usd"] < LOSS_TRACED
    from test_review_round12 import _held

    _held(plan.ledger)


def _tag_and_look(db, case, ex, tags: dict):
    _consent(db, case)
    for k, (name, entity) in tags.items():
        ex.tags[k[1]], ex.info[k[1]] = [_tag(name, entity=entity)], {}
    attr.run_lookups(db, case, only=set(tags))


# --------------------------------------------------------------------------- a deposit tag the trace followed on
def test_two_consecutive_hops_tagged_with_the_same_exchange_count_the_money_once(db, case, ex):
    plain = _plan(db, case)
    r1, r2 = _addr(db, case, "Perpetrator relay #1"), _addr(db, case, "Perpetrator relay #2")
    _tag_and_look(db, case, ex, {r1: ("OKX: Deposit", "OKX"), r2: ("OKX: Deposit", "OKX")})
    plan = _plan(db, case)
    _same_totals(plan, plain)
    _no_double(plan)
    for k in (r1, r2):
        a = plan.owners[k]
        assert (a.owner, a.kind) == ("OKX", "exchange_deposit")
        assert a.conflict and "no service owns" in a.conflict  # the onward money reached a wallet no service owns
        m = plan.find(f"owner:{k[0]}:{k[1]}")
        # round 13: no value cut for another move's count; a move on the same funds says so (the totals count once)
        assert m is None or not m.value or "same funds as" in m.basis
    # downstream keeps its values
    assert {m.authority.name for m in _counted(plan) if m.authority is not None} >= {"Rainbet", "KuCoin"}


def test_a_deposit_tag_then_its_exchanges_hot_wallet_tag_count_the_money_once(db, case, ex):
    plain = _plan(db, case)
    r2, r3 = _addr(db, case, "Perpetrator relay #2"), _addr(db, case, "Perpetrator relay #3")
    _tag_and_look(db, case, ex, {r2: ("OKX: Deposit", "OKX"), r3: ("OKX 5", "OKX")})
    plan = _plan(db, case)
    _same_totals(plan, plain)
    _no_double(plan)
    a = plan.owners[r2]
    assert a.kind == "exchange_deposit" and a.share_usd == 0 and a.conflict
    assert plan.owners[r3].kind == "exchange_hot_wallet" and plan.owners[r3].share_usd == 0


def test_a_person_marking_a_deposit_and_its_hot_wallet_counts_the_money_once(db, case):
    plain = _plan(db, case)
    r2, r3 = _addr(db, case, "Perpetrator relay #2"), _addr(db, case, "Perpetrator relay #3")
    attr.mark(db, case, None, chain=r2[0], address=r2[1], owner="OKX", kind="exchange_deposit")
    attr.mark(db, case, None, chain=r3[0], address=r3[1], owner="OKX", kind="exchange_hot_wallet")
    db.commit()
    plan = _plan(db, case)
    _same_totals(plan, plain)
    _no_double(plan)
    m = plan.find(f"owner:{r2[0]}:{r2[1]}")
    assert m is None or not m.value
    assert plan.owners[r2].conflict


@pytest.mark.parametrize("second", ["OKX: Hot Wallet", "OKX: Deposit"])
def test_a_deposit_address_forwarding_to_its_services_wallet_the_trace_followed_is_not_credited(db, case, ex, second):
    plain = _plan(db, case)
    r1, r2 = _addr(db, case, "Perpetrator relay #1"), _addr(db, case, "Perpetrator relay #2")
    _tag_and_look(db, case, ex, {r1: ("OKX: Deposit", "OKX"), r2: (second, "OKX")})
    plan = _plan(db, case)
    a = plan.owners[r1]
    assert a.conflict
    m = plan.find(f"owner:{r1[0]}:{r1[1]}")
    assert m is None or not m.value or "same funds as" in m.basis  # round 13: counted once, in the totals
    _same_totals(plan, plain)
    _no_double(plan)
    assert not plan.totals["in_play_capped"]


def test_a_deposit_address_sweeping_to_its_services_wallet_the_trace_follows_on_counts_downstream_once(db, case):
    """The swap wallet marked an OKX deposit address, the hub (which the trace follows on to Rainbet and the other
    targets) OKX's hot wallet: what reached the hub is counted where it went, never again at the deposit address."""
    plain = _plan(db, case)
    sw, hub = _addr(db, case, "Perpetrator swap wallet"), _addr(db, case, "Distribution hub")
    attr.mark(db, case, None, chain=sw[0], address=sw[1], owner="OKX", kind="exchange_deposit")
    attr.mark(db, case, None, chain=hub[0], address=hub[1], owner="OKX", kind="exchange_hot_wallet")
    db.commit()
    plan = _plan(db, case)
    assert plan.owners[sw].share_usd == 0 and plan.owners[sw].conflict
    _same_totals(plan, plain)
    _no_double(plan)


def test_a_laundering_wallet_tagged_a_kucoin_deposit_leaves_what_it_paid_into_kucoins_deposit(db, case, ex):
    plain = _plan(db, case)
    lw, kd = _addr(db, case, "Laundering chain wallet"), _addr(db, case, "KuCoin deposit address")
    _tag_and_look(db, case, ex, {lw: ("KuCoin: Deposit", "KuCoin")})
    plan = _plan(db, case)
    a = plan.owners[lw]
    # round 13: what it paid into KuCoin's own deposit address is no longer cut from its value (the same service): the
    # totals count the two moves on the same funds once
    assert kd not in a.onward and a.share_usd == pytest.approx(a.wallet.taint_usd, abs=0.01)
    m = plan.find(f"owner:{lw[0]}:{lw[1]}")
    assert m is not None and m.value == pytest.approx(a.share_usd) and "same funds as" in m.basis
    # the group of moves on the same funds counts its largest: this wallet's (what reached it), not KuCoin's on top
    assert plan.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"] - 144.94 + m.value, abs=0.01)
    _no_double(plan)


def test_a_deposit_address_the_trace_stops_at_keeps_its_credit(db, case, ex):
    """The committed reading (5517587): a deposit address the trace saw hold its funds (or sweep them into its own
    service's float, KuCoin's) is credited what reached it, counted at its owner move."""
    plain = _plan(db, case)
    kucoin = plan_kucoin = plain.owners[_addr(db, case, "KuCoin deposit address")]
    assert kucoin.share_usd == pytest.approx(144.94) and not plan_kucoin.onward and not kucoin.conflict
    # the trace's own typed deposit addresses: their providers' moves ask them (no owner move on top)
    for label in ("KuCoin deposit address", "Rainbet deposit address"):
        k = _addr(db, case, label)
        assert plain.find(f"owner:{k[0]}:{k[1]}") is None
    h3 = _addr(db, case, "Hub outflow #3")
    _tag_and_look(db, case, ex, {h3: ("OKX: Deposit", "OKX")})
    plan = _plan(db, case)
    a = plan.owners[h3]
    m = plan.find(f"owner:{h3[0]}:{h3[1]}")
    assert a.share_usd == pytest.approx(a.wallet.taint_usd) and not a.conflict and not a.onward
    assert m is not None and m.counts and m.value == pytest.approx(a.wallet.taint_usd)
    assert plan.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"] + m.value, abs=0.01)


# --------------------------------------------------------------------------- asserted links
# design decision (r5): two claims are on the same funds ONLY at the same wallet or along the trace's ancestry; the
# destinations one hub's unquantified residual was asserted to are separate branches, each its own claim (the traced
# part of the total is capped at the traced loss)
def test_asserted_destinations_tagged_deposits_are_each_their_own_claim(db, case, ex):
    plain = _plan(db, case)
    s1, s2 = _addr(db, case, "SWFT order sender #1"), _addr(db, case, "SWFT order sender #2")
    _tag_and_look(db, case, ex, {s1: ("Binance: Deposit", "Binance"), s2: ("Bybit: Deposit", "Bybit")})
    plan = _plan(db, case)
    swft = next(m for m in plan.moves + plan.waiting if m.authority is not None and m.authority.name.startswith("SWFT"))
    owners = []
    for k in (s1, s2):
        a = plan.owners[k]
        assert a.kind == "exchange_deposit" and a.shared and "shared with 3 other asserted destinations" in a.shared
        assert "given in full to each" in a.share_basis
        m = plan.find(f"owner:{k[0]}:{k[1]}")
        # it keeps its value (ranking); its value leaves out what the trace saw it send on to SWFT's payout wallet
        # (its onward): SWFT's claim there is other money, never "the same funds" (round r6)
        assert m is not None and m.counts and "asserted link" in m.likelihood_why and "same funds as" not in m.basis
        assert "leave it" in m.basis
        owners.append(m)
    # the two senders are separate wallets (no ancestry between them): both count, and so does SWFT at its payout
    # wallet (below what the senders sent on, so in neither sender's value); Tether's smaller claim below SWFT's payout
    # wallet is SWFT's funds; Rainbet (another destination) still counts
    rainbet = next(m for m in plan.moves + plan.waiting if m.authority is not None and m.authority.name == "Rainbet")
    kucoin = next(m for m in plan.moves + plan.waiting if m.authority is not None and m.authority.name == "KuCoin")
    assert plan.totals["in_play_sum_usd"] > plain.totals["in_play_sum_usd"]
    assert plan.totals["in_play_sum_usd"] == pytest.approx(
        rainbet.value + kucoin.value + sum(m.value for m in owners) + swft.value, abs=0.01), (
        swft.value, plan.totals)
    assert "same funds as" in _tether(plan).basis and "same funds as" in swft.basis
    _no_double(plan)


@pytest.mark.parametrize("label", ["SWFT order sender #1", "SWFT order sender #2"])
def test_marking_one_asserted_destination_a_deposit_counts_it_with_swft_once(db, case, label):
    plain = _plan(db, case)
    k = _addr(db, case, label)
    attr.mark(db, case, None, chain=k[0], address=k[1], owner="Binance", kind="exchange_deposit")
    db.commit()
    plan = _plan(db, case)
    assert plan.owners[k].shared
    m = plan.find(f"owner:{k[0]}:{k[1]}")
    swft = next(x for x in plan.moves + plan.waiting if x.authority is not None and x.authority.name.startswith("SWFT"))
    # the sender's value leaves out what the trace saw it send on to SWFT's payout wallet (round r6): SWFT's claim
    # there is other money and both count; SWFT and Tether still share the payout wallet (counted once)
    assert "same funds as" not in m.basis and "leave it" in m.basis
    assert "same funds as" in swft.basis and "same funds as" in _tether(plan).basis
    assert plan.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"] + m.value, abs=0.01)
    _no_double(plan)


def test_an_asserted_residuals_destinations_are_separate_branches(db, case):
    """Rainbet and SWFT (through its senders) are two destinations of the hub's one asserted residual, Tether is at
    SWFT's payout: each keeps its own value; SWFT and Tether share a wallet (counted once), Rainbet counts on its own
    (siblings below one hub are not the same funds)."""
    plan = _plan(db, case)
    hub = plan.owners[_addr(db, case, "Distribution hub")].wallet
    residual = max(hub.asserted_out.values())
    names = ("Rainbet", "SWFT", "Tether")
    slice_moves = [m for m in _counted(plan) if m.authority is not None and m.authority.name.startswith(names)]
    assert {m.authority.name.split()[0] for m in slice_moves} >= {"Rainbet", "SWFT", "Tether"}
    rainbet = next(m for m in slice_moves if m.authority.name == "Rainbet")
    swft = next(m for m in slice_moves if m.authority.name.startswith("SWFT"))
    assert rainbet.value == pytest.approx(residual) and swft.value == pytest.approx(2617.02)
    assert _tether(plan).value == pytest.approx(1359.9)
    assert "same funds as" in swft.basis and "same funds as" in _tether(plan).basis
    assert "same funds as" not in rainbet.basis
    kucoin = next(m for m in _counted(plan) if m.authority is not None and m.authority.name == "KuCoin")
    assert plan.totals["in_play_sum_usd"] == pytest.approx(residual + swft.value + kucoin.value, abs=0.01)
    _no_double(plan)


def test_two_real_balances_on_separate_branches_below_one_hub_are_both_counted(db, case):
    """The r5 repro: good USDT readings of 60,000 at SWFT order sender #1 and at #2 (two asserted destinations of the
    hub, neither an ancestor of the other) are two balances: in play rises by 120,000 (it stayed at 63,906.63, the
    Tether move at $121k was counted zero times)."""
    from test_review_round12 import _invariant

    plain = _plan(db, case)
    for label in ("SWFT order sender #1", "SWFT order sender #2"):
        k = _addr(db, case, label)
        _read(db, case, k[0], k[1], 60000, 5)
    plan = _plan(db, case)
    tether = _tether(plan)
    assert tether.value == pytest.approx(121359.9)  # its own value unchanged
    assert plan.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"] + 120000, abs=0.01)
    assert tether.value <= plan.totals["in_play_sum_usd"]
    _invariant(plan)
    _no_double(plan)


# --------------------------------------------------------------------------- service floats read on-chain
def test_a_hot_wallet_tag_with_a_reading_on_a_wallet_the_trace_followed_on_counts_nothing_twice(db, case, ex):
    plain = _plan(db, case)
    r2 = _addr(db, case, "Perpetrator relay #2")
    _tag_and_look(db, case, ex, {r2: ("OKX: Hot Wallet", "OKX")})
    _usdc(db, case, r2[1], "2000000")
    plan = _plan(db, case)
    a = plan.owners[r2]
    assert a.kind == "exchange_hot_wallet" and a.share_usd == 0 and a.onward and a.conflict
    m = plan.find(f"owner:{r2[0]}:{r2[1]}")
    assert m is None or not m.value
    _same_totals(plan, plain)
    _no_double(plan)


def test_a_hub_marked_a_hot_wallet_with_a_reading_counts_nothing_twice(db, case):
    plain = _plan(db, case)
    hub = _addr(db, case, "Distribution hub")
    attr.mark(db, case, None, chain=hub[0], address=hub[1], owner="Binance", kind="exchange_hot_wallet")
    db.commit()
    _read(db, case, "ethereum", hub[1], "2000000", 5)
    plan = _plan(db, case)
    assert plan.owners[hub].share_usd == 0
    m = plan.find(f"owner:{hub[0]}:{hub[1]}")
    assert m is None or not m.value
    assert plan.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"], abs=0.01)
    # (a service's wallet on the issuer's list lowers the issuer's odds: its owner is asked first)
    assert plan.totals["expected_usd"] <= plain.totals["expected_usd"] + 0.01
    _no_double(plan)


def test_a_service_float_keeps_the_committed_share(db, case):
    """The committed reading (5517587): a float read on-chain that the trace saw hold its funds: the case's share is
    what was traced in, never the whole balance; a float the trace never saw: no share."""
    attr.mark(db, case, None, chain="tron", address=TRON_DEST, owner="Binance", kind="exchange_hot_wallet")
    db.commit()
    _read(db, case, "tron", TRON_DEST, "5000", 5)
    assert attr.attribute(db, case)[("tron", TRON_DEST)].share_usd == pytest.approx(1359.9)
    x = "0x" + "9e" * 20
    fz.add_watch(db, case, None, chain="ethereum", address=x)
    attr.mark(db, case, None, chain="ethereum", address=x, owner="KuCoin", kind="exchange_hot_wallet")
    db.commit()
    _read(db, case, "ethereum", x, "250000", 6)
    a = attr.attribute(db, case)[("ethereum", x)]
    assert a.share_usd == 0 and "the case's share unknown" in a.share_basis


# --------------------------------------------------------------------------- an issuer reading at a traced wallet
@pytest.mark.parametrize("label,balance", [("Perpetrator relay #2", "2500000"), ("Perpetrator relay #3", "2500000")])
def test_an_issuer_reading_at_a_traced_pass_through_wallet_is_not_the_cases_money(db, case, label, balance):
    """Far more than the trace put in: likely a service's float, valued at what the trace left there (here $0)."""
    plain = _plan(db, case)
    k = _addr(db, case, label)
    _usdc(db, case, k[1], balance)
    plan = _plan(db, case)
    circle = next(m for m in plan.moves + plan.waiting if m.authority is not None and ":" not in m.key
                  and m.authority.name.startswith("Circle"))
    assert not circle.value or circle.value < float(balance)
    assert "possibly an exchange / service hot wallet" in circle.basis  # the blacklist ask stays listed
    assert "the trace left $0 there" in circle.basis
    _same_totals(plan, plain)
    assert plan.totals["expected_usd"] < LOSS_TRACED / 2


def test_an_issuer_reading_past_what_a_pass_through_wallet_kept_is_an_untraced_find(db, case):
    """Round 13: a balance read at a wallet the trace saw empty is never counted zero times: the move keeps the
    reading (its rank), the totals add it once as a labelled untraced find (it is not the case's traced funds)."""
    plain = _plan(db, case)
    k = _addr(db, case, "Perpetrator relay #2")
    _usdc(db, case, k[1], "300000")
    plan = _plan(db, case)
    circle = next(m for m in plan.moves + plan.waiting if m.authority is not None and ":" not in m.key
                  and m.authority.name.startswith("Circle"))
    assert circle.value == pytest.approx(300000) and "not the case's traced funds" in circle.basis
    assert plan.totals["untraced_usd"] == pytest.approx(300000)
    assert plan.totals["in_play_usd"] == pytest.approx(plain.totals["in_play_usd"] + 300000, abs=0.01)
    assert plan.totals["traced_usd"] == pytest.approx(plain.totals["traced_usd"], abs=0.01)


def test_an_issuer_reading_at_the_hub_is_not_the_cases_money(db, case):
    plain = _plan(db, case)
    hub = _addr(db, case, "Distribution hub")
    _read(db, case, "ethereum", hub[1], "2000000", 5)
    plan = _plan(db, case)
    assert _tether(plan).value == pytest.approx(_tether(plain).value)
    _same_totals(plan, plain)


def test_an_issuer_reading_at_a_watched_wallet_the_trace_never_saw_counts_its_balance(db, case):
    """The committed reading: a wallet the trace never saw keeps its whole balance at the issuer."""
    plain = _plan(db, case)
    x = "0x" + "7e" * 20
    fz.add_watch(db, case, None, chain="ethereum", address=x)
    db.commit()
    _usdc(db, case, x, "40000")
    plan = _plan(db, case)
    assert plan.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"] + 40000, abs=0.01)


def test_a_non_custodial_router_read_on_chain_is_never_counted(db, case):
    plain = _plan(db, case)
    k = _addr(db, case, "Uniswap Universal Router")
    _usdc(db, case, k[1], "50000")
    plan = _plan(db, case)
    a = plan.owners[k]
    assert a.router and a.share_usd == 0
    m = plan.find(f"owner:{k[0]}:{k[1]}")
    assert m is None or (not m.value and not m.counts)
    _same_totals(plan, plain)


# --------------------------------------------------------------------------- sweeps
def _d4(db, case, ex):
    fz.add_watch(db, case, None, chain="ethereum", address=D4)
    db.commit()
    _tag_and_look(db, case, ex, {("ethereum", D4): ("Binance: Deposit", "Binance")})


@pytest.mark.parametrize("readings,values", [
    (("50000", "20000", "0"), (50000, 50000, 50000)),  # a partial sweep, then the rest
    (("50000", "0", "30000", "0"), (50000, 50000, 80000, 80000)),  # a second deposit, swept too
])
def test_a_watched_deposit_address_is_credited_every_sweep(db, case, ex, readings, values):
    _d4(db, case, ex)
    plain = _plan(db, case)
    for i, (bal, want) in enumerate(zip(readings, values, strict=True)):
        _read(db, case, "ethereum", D4, bal, 5 + i)
        plan = _plan(db, case)
        m = plan.find(f"owner:ethereum:{D4}")
        assert m is not None and m.value == pytest.approx(want) and m.counts, (bal, m and m.value)
        assert plan.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"] + want, abs=0.01)


def test_a_traced_deposit_address_keeps_the_balance_it_was_read_holding_after_the_sweep(db, case, ex):
    r2 = _addr(db, case, "Perpetrator relay #2")
    _tag_and_look(db, case, ex, {r2: ("OKX: Deposit", "OKX")})
    _usdc(db, case, r2[1], "50000", 5)
    held = _plan(db, case)
    m = held.find(f"owner:{r2[0]}:{r2[1]}")
    assert m is not None and m.value == pytest.approx(50000) and m.counts and held.owners[r2].conflict
    _usdc(db, case, r2[1], "0", 10)  # the exchange swept it
    swept = _plan(db, case)
    m = swept.find(f"owner:{r2[0]}:{r2[1]}")
    assert m is not None and m.value == pytest.approx(50000) and m.counts and "swept" in m.basis
    assert swept.totals["in_play_sum_usd"] == pytest.approx(held.totals["in_play_sum_usd"], abs=0.01)


def test_the_basis_says_swept_only_when_a_sweep_was_read(db, case, ex):
    h3 = _addr(db, case, "Hub outflow #3")
    _tag_and_look(db, case, ex, {h3: ("Binance: Deposit", "Binance")})
    _read(db, case, "ethereum", h3[1], "100000", 5)
    plan = _plan(db, case)
    a = plan.owners[h3]
    m = plan.find(f"owner:{h3[0]}:{h3[1]}")
    assert "swept" not in a.share_basis and "swept" not in m.basis
    assert "credited to the account behind it ($100,000 read there now)" in a.share_basis
    assert m.value == pytest.approx(a.wallet.taint_usd)  # the traced credit, no double count
    _read(db, case, "ethereum", h3[1], "0", 10)  # now it is swept
    a = _plan(db, case).owners[h3]
    assert a.share_basis.startswith("swept: the account was credited")


# --------------------------------------------------------------------------- chats are never the police's report
_WA = "\n".join(f"[01/09/2026, 10:0{i}:00] Anna: msg {i}" for i in range(1, 8))
CHATS = {
    "whatsapp, a multi-line first message": ("[01/09/2026, 10:00:00] Agent Smith: Hello\nINTERNATIONAL POLICE "
                                             "DEPARTMENT - CYBER UNIT\nReport number: 556677\n" + _WA),
    "whatsapp, an Italian letterhead in a message": ("[01/09/2026, 10:00:00] Maresciallo Rossi: Buongiorno\nComando "
                                                     "Stazione Carabinieri di Roma\nProt. n. 4417/2026\n" + _WA),
    "pasted without timestamps": ("Chat with the recovery agent\nAgent: Hello I am from the police department\nAgent: "
                                  "your report number: 12345\nMe: ok\nAgent: pay fee\nMe: ok\nAgent: now\nMe: done"),
    "signal, ISO timestamps": ("Signal conversation export\nAgent (Polizei Berlin): Aktenzeichen 123 Js 4567/26\n"
                               + "\n".join(f"2026-09-01 10:0{i} Anna: msg {i}" for i in range(8))),
    "signal, no banner": ("Agent (Polizei Berlin): Aktenzeichen 123 Js 4567/26\n"
                          + "\n".join(f"2026-09-01 10:0{i} Anna: msg {i}" for i in range(8))),
    "telegram desktop": ("Cyber Police Unit\n01.09.2026 10:00:00\nHello, this is the Police Department cyber unit. "
                         "Your case number: 2026-77881\nAnna\n01.09.2026 10:01:00\nok\nCyber Police Unit\n"
                         "01.09.2026 10:02:00\nTo release funds pay the fee\nAnna\n01.09.2026 10:03:00\nhow much\n"
                         "Cyber Police Unit\n01.09.2026 10:04:00\n5000 USDT"),
}


@pytest.mark.parametrize("name", list(CHATS))
def test_a_chat_export_in_any_format_is_never_the_agencys_police_report(name):
    r = rules.classify(CHATS[name], name="chat.txt", kind="text")
    assert not {"police_report", "complaint_ref"} & set(r["keys"]), (name, r)
    assert r["type"] != "police_report", (name, r)


_IOS = "\n".join(f"[01/09/2026, 10:{i:02d}:00] {'Anna' if i % 2 else 'Mario'}: msg {i}" for i in range(16))
# round 12: a document holding a chat is never read as the police's report by the rules (a scammer posing as police is
# indistinguishable by shape): chat_export with a note, a person confirms the type
REPORTS_WITH_CHAT = {
    "carabinieri, a pasted WhatsApp export with its banner": (
        "Comando Carabinieri di Demo\nProt. n. 4417/2026\nVerbale di denuncia\nLa persona offesa esibisce la "
        "seguente chat WhatsApp:\nMessages and calls are end-to-end encrypted. No one outside of this chat, not even "
        "WhatsApp, can read or listen to them.\n" + _IOS, "report.pdf", "pdf"),
    "springfield, chat lines with <Media omitted>": (
        "SPRINGFIELD POLICE DEPARTMENT\nIncident Report\nReport Number: 26-012345\nNarrative: chat copied:\n"
        + "\n".join(f"[01/09/2026, 10:{i:02d}:00] Anna: {'<Media omitted>' if i % 3 == 0 else f'msg {i}'}"
                    for i in range(10)), "report.pdf", "pdf"),
    "carabinieri, the chat without its banner": (
        "Comando Carabinieri di Demo\nProt. n. 4417/2026\nVerbale di denuncia\nLa persona offesa esibisce la "
        "seguente chat WhatsApp:\n" + _IOS, "report.pdf", "pdf"),
    "springfield, the chat without <Media omitted>": (
        "SPRINGFIELD POLICE DEPARTMENT\nIncident Report\nReport Number: 26-012345\nNarrative: chat copied:\n"
        + "\n".join(f"[01/09/2026, 10:{i:02d}:00] Anna: msg {i}" for i in range(10)), "report.pdf", "pdf"),
}
REPORTS = {
    "a plain denuncia": (
        ("Comando Carabinieri di Demo\nProt. n. 4417/2026\nVerbale di ricezione di denuncia-querela\nLa "
         "persona offesa dichiara di aver trasferito 12.500 USDT."), "denuncia.pdf", "pdf"),
    "an interview in questions and answers": (
        ("Polizeipräsidium Berlin\nAktenzeichen: 123 Js 4567/26\nVernehmung der Geschädigten\nF: Wann?\nA: Am 1.9.\n"
         "F: Wie viel?\nA: 40.000 USDT\nF: Wohin?\nA: Wallet"), "vernehmung.pdf", "pdf"),
    "a report's field labels": (
        ("SPRINGFIELD POLICE DEPARTMENT\nIncident Report\nReport Number: 26-012345\nOfficer: J. Doe\nVictim: Anna\n"
         "Suspect: unknown\nNarrative: the victim sent 40,000 USDT"), "report.pdf", "pdf"),
}


@pytest.mark.parametrize("name", list(REPORTS))
def test_a_police_report_without_a_chat_is_the_report(name):
    text, fname, kind = REPORTS[name]
    r = rules.classify(text, name=fname, kind=kind)
    assert r["type"] == "police_report" and {"police_report", "complaint_ref"} <= set(r["keys"]), (name, r)


@pytest.mark.parametrize("name", list(REPORTS_WITH_CHAT))
def test_a_police_report_that_pastes_a_chat_is_for_a_person_to_confirm(name):
    text, fname, kind = REPORTS_WITH_CHAT[name]
    r = rules.classify(text, name=fname, kind=kind)
    assert r["type"] == "chat_export" and r["note"] == rules.CHAT_NOTE and r["confidence"] != "H", (name, r)
    assert not {"police_report", "complaint_ref"} & set(r["keys"])
    assert "police_report" in {a["type"] for a in r["alternatives"]}  # offered for the person to pick


def test_the_committed_chat_and_mail_readings_stay():
    wa = "\n".join(f"[01/09/2026, 10:0{i}:00] {'Anna' if i % 2 else 'Bob'}: msg {i}" for i in range(9))
    assert rules.classify(wa, name="chat.txt", kind="text")["type"] == "chat_export"
    chat = "\n".join(f"[01/09/2026, 10:0{i}:00] Anna: ho fatto denuncia ai carabinieri, prot. n. 44{i}/2026"
                     for i in range(6))
    r = rules.classify(chat, name="chat.txt", kind="text")
    assert r["type"] == "chat_export" and "police_report" not in r["keys"]
    mail = ("From: support@demo.example\nTo: anna@example.com\nSubject: Your request\nDate: 1 Sep 2026\n\nDear "
            "Customer, we have received your request.")
    assert rules.classify(mail, name="reply.eml", kind="email")["type"] in ("email_export", "provider_reply")


# --------------------------------------------------------------------------- a report's victim field labels
# design decision (r5): wording never assigns a wallet's role; a report's field labels are shown as a hint next to the
# address, a person picks the role
@pytest.mark.parametrize("text,v_cue,w_cue", [
    (f"Victim: {V}\nScammer: {W}", "Victim", "Scammer"),
    (f"Vittima: {V}\nTruffatore: {W}", "Vittima", "Truffatore"),
    (f"Persona offesa: {V}\nIndagato: {W}", "Persona offesa", "Indagato"),
    (f"Portefeuille de la victime : {V}\nPortefeuille de l'escroc : {W}", "victime", "escroc"),
    (f"Wallet {V} des Opfers", "Opfers", None),
    (f"The wallet {V} (victim) was emptied", "victim", None),
])
def test_a_reports_role_words_are_a_hint_never_a_role(text, v_cue, w_cue):
    assert not hasattr(findings, "address_role")
    assert v_cue in (findings.address_hint(text, V) or "")
    if w_cue:
        assert w_cue in (findings.address_hint(text, W) or "") and v_cue not in findings.address_hint(text, W)
