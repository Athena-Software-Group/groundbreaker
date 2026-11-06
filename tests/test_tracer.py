from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal

from conftest import ungated
from sqlalchemy import select

from app.db.models import (
    Address,
    AddressType,
    Chain,
    DataSource,
    SeedRole,
    TraceEdge,
    TraceNode,
    TraceStatus,
    Transfer,
)
from app.providers.base import RawTransfer
from app.providers.fixture import FixtureProvider
from app.services import generate_stop_orders, latest_run, run_trace
from app.tracing.engine import Tracer
from app.tracing.freeze import freeze_candidates
from app.tracing.repository import REFUTED, ingest_transfer, outgoing_from_db

ORIGIN_TX = "0x70abbe14aa9080b572aa69881536e5c165097c0574c4791467e915b708bba814"
VICTIM = "0x7ac32c88e5489b4c406ffc1d6b835f4eba7b455b"
ROOT = "0x57de1021a507d46272d386995d5b58667ac1f8df"
RELAYS = [
    "0x300762e2ba1fdb1fc02ed4e4fcee0d6b93d51fb4",
    "0x0d0bdb37e6dd16e6fcf53cb0067e1df30e0fb23e",
    "0xba02b694e55f603fdfbb6e89abd5bafaf02246b5",
]
SWAP_WALLET = "0xe9449ba33c8dcf6f859c9bc476b8debab64a4b1b"
HUB = "0x54453e25e38b11009963361a123bde2b4457becb"
LOSS = Decimal("399247.92")


def _node(db, run, addr_fragment: str) -> TraceNode:
    return next(n for n in db.scalars(select(TraceNode).where(TraceNode.run_id == run.id))
                if addr_fragment.lower() in n.address.address.lower())


def _run(db, case):
    return latest_run(db, case) or run_trace(db, case, provider_mode="fixture")


def test_fixture_provider_resolves_origin_tx():
    detail = FixtureProvider(Chain.ETHEREUM).get_tx(ORIGIN_TX.upper().replace("0X", "0x"))
    assert detail is not None and len(detail.transfers) == 1
    t = detail.transfers[0]
    assert t.from_address.lower() == VICTIM and t.to_address.lower() == ROOT
    assert t.asset == "USDC" and t.amount == LOSS
    assert t.timestamp.isoformat() == "2026-10-12T10:49:47+00:00"


def test_seeds_point_at_the_true_root(case):
    seeds = {(s.role, s.value.lower()) for s in case.seeds}
    assert (SeedRole.ORIGIN_TX, ORIGIN_TX) in seeds
    assert (SeedRole.VICTIM_WALLET, VICTIM) in seeds
    assert (SeedRole.PERPETRATOR_WALLET, ROOT) in seeds
    assert {(SeedRole.KNOWN_DOWNSTREAM, HUB), (SeedRole.KNOWN_DOWNSTREAM, "0x25018daa80887e133ee16a0070986dd8d4de57e3")} <= seeds
    assert not any(s.value.endswith("_PENDING") for s in case.seeds)
    assert case.fraud_date.isoformat() == "2026-10-12T10:49:47+00:00"


def test_trace_completes_and_reaches_vasps(db, case):
    run = run_trace(db, case, provider_mode="fixture")
    assert run.status == TraceStatus.COMPLETE
    assert run.stats["terminal_vasp"] >= 2
    assert set(run.stats) >= {"nodes", "edges", "max_hop"}


def test_trace_roots_at_origin_and_first_hop_is_0x57de(db, case):
    run = _run(db, case)
    victim = _node(db, run, VICTIM)
    assert victim.hop == 0 and victim.address.address_type == AddressType.VICTIM
    root = _node(db, run, ROOT)
    assert root.hop == 1 and root.taint_usd == LOSS
    assert root.address.address_type == AddressType.PERPETRATOR
    origin_edge = db.scalar(
        select(TraceEdge).join(Transfer).where(TraceEdge.run_id == run.id, Transfer.tx_hash == ORIGIN_TX)
    )
    assert origin_edge is not None and origin_edge.hop == 0 and origin_edge.taint_usd == LOSS
    assert origin_edge.transfer.to_address.address == ROOT


def test_relay_path_into_swap_wallet(db, case):
    run = _run(db, case)
    for hop, addr in enumerate(RELAYS, start=2):
        n = _node(db, run, addr)
        assert n.hop == hop and n.taint_usd == LOSS
        assert n.address.address_type == AddressType.PERPETRATOR
        assert "asserted_link" in n.flags  # relay hashes pending verification
    swap = _node(db, run, SWAP_WALLET)
    assert swap.hop == 5 and swap.taint_usd == LOSS
    hub = _node(db, run, HUB)
    assert hub.hop == 6 and hub.taint_usd == LOSS


def test_swap_wallet_is_perpetrator_not_terminal(db, case):
    run = _run(db, case)
    swap = _node(db, run, SWAP_WALLET)
    assert swap.address.address_type == AddressType.PERPETRATOR
    assert swap.address.entity is None
    assert not swap.is_terminal and swap.terminal_reason is None
    assert "perpetrator swap wallet" in (swap.address.label or "").lower()


def test_taint_is_bounded_by_observed_amounts(db, case):
    run = _run(db, case)
    kucoin_dep = _node(db, run, "0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2")
    # 0.0568 ETH @ reference price — far below the loss; taint must not exceed the observed amount
    assert kucoin_dep.taint_usd < Decimal(200)
    big = _node(db, run, "0xc6a2b6d375e5c1fbaab2b4a8adbcef887225d5a1")
    assert Decimal(130000) < big.taint_usd < Decimal(140000)  # 53.94 ETH at the reference price
    assert "trace_next" in big.flags
    assert kucoin_dep.is_terminal and kucoin_dep.terminal_reason == "vasp"
    assert "vasp_deposit" in kucoin_dep.flags
    assert "pre_fraud_activity" in kucoin_dep.flags
    hot = _node(db, run, "0x45300136662dD4e58fc0DF61E6290DFfD992B785")
    assert hot.terminal_reason == "vasp_omnibus"


def test_cross_chain_legs_are_followed(db, case):
    run = _run(db, case)
    tron = _node(db, run, "TWdZZhGv7zqeRnmxWd65yQSE2YDZRteL77")
    btc = _node(db, run, "bc1pxnd9wrqg5yk4h4nvxmr5nmr4hne5yfpt4s6ec5hrm6ad9y9yv5jqsfknzn")
    assert tron.address.chain == Chain.TRON and tron.taint_usd == Decimal("1359.90")
    assert btc.address.chain == Chain.BITCOIN and btc.taint_usd > 0
    assert "stablecoin_freezable" in tron.flags
    swft = _node(db, run, "0xc1d13492285eb664951E201BF7C80c7c6318a1b5")
    assert swft.terminal_reason == "swap_service"


def test_asserted_links_are_labelled_not_hidden(db, case):
    run = _run(db, case)
    swft1 = _node(db, run, "0x1a456698F53732efe57503C867b2D1762F8dbf9E")
    assert "asserted_link" in swft1.flags and "unquantified_taint" in swft1.flags
    # the link the investigator asserted for 0xe535… is observed on-chain: no longer marked asserted
    e535 = _node(db, run, "0xe5351383dcb18c14c3a7c1b9674c6dd501e0a8ed")
    assert "asserted_link" not in e535.flags


def test_freeze_candidates_include_issuers_and_vasps(db, case):
    run = _run(db, case)
    names = {c.entity_name for c in freeze_candidates(db, run)}
    assert {"KuCoin", "Rainbet", "SWFT / Bridgers", "Tether (USDT issuer)", "Circle (USDC issuer)"} <= names
    # non-custodial routers cannot freeze or preserve anything: no candidate, no letter
    assert "Uniswap (Universal Router)" not in names


def test_stop_orders_render_with_hashes_and_demo_identities(db, case):
    run = _run(db, case)
    with ungated():  # the demo already asked KuCoin: the rendering is under test
        orders = generate_stop_orders(db, case, run, only=["KuCoin"])
    assert len(orders) == 1
    body = orders[0].body_markdown
    assert "0x580d3a804899ca7e084af17c13ecd2cb7af781e15572a62eaf604ff056c30293" in body
    assert "DEMO-IT-0000000000" in body and "IC3-DEMO-00000000" in body
    # the demo case's sender profile (app.domain.sender): Athena writes on behalf of the victim
    assert "Athena Software Group, Inc., on behalf of Northbridge Analytics, Inc. (Jordan Avery)" in body
    assert "Exempla Holding AG" in body
    assert "ASSERTED:" not in body  # asserted links are described, never cited as facts
    # the demo case has no compliance mailbox for this entity: the letter goes through its portal
    assert orders[0].recipient_email is None


def test_addresses_are_normalised(db, case):
    rows = db.scalars(select(Address).where(Address.chain == Chain.ETHEREUM)).all()
    assert all(a.address == a.address.lower() for a in rows if a.address.startswith("0x"))


def test_default_max_hops_reaches_the_kucoin_leg(db, case, monkeypatch):
    """Out of the box (no TRACE_MAX_HOPS anywhere) the desk must still draft the KuCoin request:
    the true root sits five relay hops before the hub, so KuCoin's deposit is at hop 9."""
    from app.core.config import Settings
    from app.tracing.engine import Tracer

    monkeypatch.delenv("TRACE_MAX_HOPS", raising=False)
    settings = Settings(_env_file=None)
    assert settings.trace_max_hops == Settings.model_fields["trace_max_hops"].default
    run = Tracer(db, case, settings=settings, provider_mode="fixture").run()
    db.commit()
    assert run.params["max_hops"] == settings.trace_max_hops
    names = {c.entity_name for c in freeze_candidates(db, run)}
    assert "KuCoin" in names, names
    assert run.stats["terminal_vasp"] >= 3


def test_circle_lever_names_the_observed_usdc_recipient_and_the_swap_wallet(db, case):
    run = _run(db, case)
    circle = next(c for c in freeze_candidates(db, run) if c.entity_name == "Circle (USDC issuer)")
    addrs = [i.address.lower() for i in circle.identifiers]
    assert sorted(addrs) == sorted([ROOT, SWAP_WALLET])  # relays (asserted in and out) are left out
    assert circle.total_taint_usd == LOSS  # same dollars on one path: never more than the loss
    text = " ".join(circle.rationale)
    assert "onward movement is asserted only" in text and "swapping out of USDC" in text
    assert "onward amounts unobserved" not in text
    root = next(i for i in circle.identifiers if i.address.lower() == ROOT)
    assert root.dwell_minutes is None  # never derived from an asserted hop's placeholder timestamp


def test_a_later_inflow_to_a_deposit_address_never_drops_an_earlier_sweep(db, monkeypatch):
    """Review: a second, later deposit reached the deposit address in fewer hops; its (later)
    arrival time hid the earlier sweep to the omnibus wallet, and the trace lost the hot wallet."""
    import uuid
    from datetime import UTC, datetime, timedelta

    from app import services
    from app.db.models import Entity, EntityCategory
    from app.providers.base import RawTransfer
    from app.tracing import engine
    from app.tracing.engine import Tracer
    from app.tracing.repository import get_or_create_address

    tag = uuid.uuid4().hex[:6]
    t0 = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)

    def addr(n: int) -> str:
        return "0x" + tag + f"{n:034x}"

    perp, x, y, deposit, hot = (addr(i) for i in range(1, 6))
    case = services.create_case(
        db, reference=f"TEST-REEXP-{tag}", title="re-expansion", victim_name="v", victim_entity=None,
        loss_amount=Decimal(1000), loss_asset="USDC", loss_usd=Decimal(1000), fraud_date=t0, chain=Chain.ETHEREUM,
        origin_tx=None, victim_wallet=None, perpetrator_wallet=perp)
    exchange = Entity(name=f"Test Exchange {tag}", category=EntityCategory.EXCHANGE)
    db.add(exchange)
    db.flush()
    get_or_create_address(db, Chain.ETHEREUM, deposit, address_type=AddressType.DEPOSIT, entity=exchange)
    get_or_create_address(db, Chain.ETHEREUM, hot, address_type=AddressType.HOT_WALLET, entity=exchange)
    db.commit()

    def tx(n, frm, to, at, amount):
        return RawTransfer(chain=Chain.ETHEREUM, tx_hash="0x" + tag + f"{n:058x}", sub_index=0, timestamp=at,
                           from_address=frm, to_address=to, asset="USDC", amount=Decimal(amount),
                           amount_usd=Decimal(amount))

    transfers = [
        tx(1, perp, x, t0 + timedelta(hours=1), 600),
        tx(2, x, y, t0 + timedelta(hours=2), 600),
        tx(3, y, deposit, t0 + timedelta(hours=3), 600),  # the early deposit, reached at hop 4
        tx(4, deposit, hot, t0 + timedelta(days=1), 600),  # its sweep to the omnibus wallet
        tx(5, perp, deposit, t0 + timedelta(days=5), 400),  # a later deposit, reached first (hop 2)
    ]

    class Stub:
        name = "fixture"

        def get_tx(self, h):
            return None

        def address_info(self, a):
            return None

        def outgoing_transfers(self, a, since=None, limit=200):
            return [t for t in transfers if t.from_address == a and (since is None or t.timestamp >= since)]

        def incoming_transfers(self, a, since=None, limit=200):
            return [t for t in transfers if t.to_address == a]

    monkeypatch.setattr(engine, "get_provider", lambda chain, mode=None: Stub())
    run = Tracer(db, case, provider_mode="fixture").run()
    assert run.status == TraceStatus.COMPLETE, run.error
    reached = {n.address.address for n in db.scalars(select(TraceNode).where(TraceNode.run_id == run.id))}
    assert deposit in reached and hot in reached  # the omnibus sweep is still followed
    sweep = db.scalar(select(Transfer).where(Transfer.tx_hash == transfers[3].tx_hash))
    assert db.scalar(select(TraceEdge).where(TraceEdge.run_id == run.id, TraceEdge.transfer_id == sweep.id))


def _asserted(tag: str) -> RawTransfer:
    return RawTransfer(chain=Chain.ETHEREUM, tx_hash=f"ASSERTED:{tag}", sub_index=0,
                       timestamp=datetime(2026, 10, 13, 12, tzinfo=UTC), from_address=f"0x{'a' * 39}1",
                       to_address=f"0x{'b' * 39}1", asset="ETH", amount=None, confidence=0.4)


def test_a_refuted_transfer_is_retired_for_good_and_never_walked(db):
    raw = _asserted("refuted-out")
    row = ingest_transfer(db, raw, DataSource.PI_REPORT)
    assert row in outgoing_from_db(db, row.from_address, None)
    ingest_transfer(db, replace(raw, confidence=REFUTED, notes="no such transfer on-chain"), DataSource.PI_REPORT)
    assert row.confidence == REFUTED and row.notes == "no such transfer on-chain"
    assert row not in outgoing_from_db(db, row.from_address, None)
    ingest_transfer(db, raw, DataSource.PI_REPORT)  # a later fixture that still asserts it does not bring it back
    assert row.confidence == REFUTED
    db.rollback()


def test_a_refuted_transfer_is_not_counted_as_incoming(db, case, monkeypatch):
    kept, refuted = _asserted("kept-in"), replace(_asserted("refuted-in"), confidence=REFUTED)

    class Stub:
        name = "fixture"

        def incoming_transfers(self, address, since=None, limit=200):
            return [kept, refuted]

    tracer = Tracer(db, case)
    monkeypatch.setattr(tracer, "_provider", lambda chain: Stub())
    addr = ingest_transfer(db, kept, DataSource.PI_REPORT).to_address
    assert [t.tx_hash for t in tracer._fetch_incoming(addr)] == [kept.tx_hash]
    db.rollback()
