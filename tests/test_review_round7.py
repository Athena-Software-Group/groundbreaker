"""Verify round 7 (wallet owners, the Recovery plan, freeze readings, reply rules, evidence matching): one address key
everywhere (Bitcoin base58 / Solana as written), the same owner ask on every page, the issuer of the token a wallet
holds, a service's wallet without a reading, mixers and DEX routers as non-custodial, a service float moving, a
temporary freeze, the Digital artifacts folder, the graph's hover card and click panel from one attribution pass,
consent forms that post what the admin saw, and a person's owner name kept out of the model. The demo case
plus synthetic tags and readings only."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from conftest import csrf_token
from sqlalchemy import event, select
from test_review_round6 import _check, _taint, _tether_wallet
from test_wallet_owners import Explorers, _Access, _addr, _consent, _offline, _plan, _tag, no_ai  # noqa: F401 - fixtures

from app import services
from app.ai.context import redactor_for
from app.attribution import explorer
from app.attribution import service as attr
from app.blocks import classify_rules as R
from app.blocks import recovery as rp
from app.blocks import status as bs
from app.db.models import Address, Chain, EvidenceFolder, FreezeCheck, TraceNode, WalletAttribution
from app.domain import evidence as ev
from app.domain import evidence_requirements as er
from app.domain.addresses import wallet_key
from app.freeze import service as fz

NOW = datetime.now(tz=UTC)
USDC_ETH = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"


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


def _node(db, case, prefix: str) -> TraceNode:
    run = services.latest_run(db, case)
    return next(n for n in db.scalars(select(TraceNode).where(TraceNode.run_id == run.id))
                if n.address.address.lower().startswith(prefix.lower()))


def _usdc(db, case, address: str, balance: str):
    db.add(FreezeCheck(case_id=case.id, chain="ethereum", address=address.lower(), issuer="Circle", token_symbol="USDC",
                       token_contract=USDC_ETH, status="ok", blacklisted=False, balance=Decimal(balance),
                       checked_at=NOW - timedelta(minutes=5), block_number=21_000_000, raw_sha256="cd" * 32,
                       meta={"balance_raw": str(int(Decimal(balance) * 10**6))}))
    db.commit()


# --------------------------------------------------------------------------- one address key
def test_one_address_key_keeps_base58_and_solana_as_written_and_bech32_lower_case():
    assert wallet_key("bitcoin", P2SH) == ("bitcoin", P2SH)
    assert wallet_key("bitcoin", "BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ") == (
        "bitcoin", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
    assert wallet_key(Chain.ETHEREUM, "0xAbC") == ("ethereum", "0xabc")
    assert wallet_key("solana", "So1AbC") == ("solana", "So1AbC")
    assert attr.key_of("bitcoin", P2SH) == rp._key("bitcoin", P2SH) == fz.wallet_key("bitcoin", P2SH)


def test_a_bitcoin_base58_deposit_counts_once_in_its_providers_move(db, case):
    before = _plan(db, case)
    a = db.get(Address, _node(db, case, "0x74e697c2").address_id)  # the Rainbet deposit address
    old = (a.chain, a.address)
    try:
        a.chain, a.address = Chain.BITCOIN, P2SH
        db.commit()
        plan = _plan(db, case)
        assert plan.find(f"owner:bitcoin:{P2SH}") is None  # Rainbet's own request covers it
        assert plan.totals["in_play_usd"] == pytest.approx(before.totals["in_play_usd"])
        rainbet = next(m for m in plan.moves + plan.waiting if m.authority is not None and m.authority.name == "Rainbet")
        assert any(o["owner"] == "Rainbet" for o in rainbet.owners)  # the Owner line finds the wallet
    finally:
        a = db.get(Address, a.id)
        a.chain, a.address = old
        db.commit()


def test_a_published_solana_wallet_is_kept_as_written():
    from test_playbook import _parse, _pb

    sol = "So11111111111111111111111111111111111111112"
    prov = {"source_ids": ["s1"], "basis": "D", "confidence": "H", "retrieved_at": "2026-10-20"}
    pb, _ = _parse(_pb(addresses=[{"chain": "solana", "address": sol, "kind": "exchange_hot_wallet", **prov}]))
    assert pb.addresses[0].address == sol


def test_the_funds_left_pass_reads_nothing_when_no_balance_fell(db, case):
    run = services.latest_run(db, case)
    stmts: list[str] = []

    def seen(conn, cursor, statement, *a):
        stmts.append(statement)

    event.listen(db.get_bind(), "before_cursor_execute", seen)
    try:
        assert rp._left_moves(db, case.id, run, fz.wallet_rows(db, case), NOW) == []
        n = len(stmts)
        rp._left_moves(db, case.id, run, [], NOW)
    finally:
        event.remove(db.get_bind(), "before_cursor_execute", seen)
    assert len(stmts) == n  # no query at all without a fall in balance


# --------------------------------------------------------------------------- the same ask on every page
def test_every_page_gives_a_usdc_wallet_the_plans_ask_to_circle(db, case, client_for):
    addr = _node(db, case, "0x57de1021").address.address
    _usdc(db, case, addr, "250000")
    k = attr.key_of("ethereum", addr)
    plan = _plan(db, case)
    panel = next(o for o in rp.owners_view(plan, _Access())["owners"] if o["address"] == k[1])
    circle = next(a for a in plan.moves if a.authority is not None and a.authority.name.startswith("Circle")).authority
    assert panel["ask"]["authority"] == circle.key and panel["ask"]["who"].startswith("Circle")
    assert "Tether" not in panel["ask"]["text"] and "USDC" in panel["ask"]["href"]
    assert panel["money_basis"] == "USDC balance read on-chain"
    page = attr.by_key(db, case)[k]  # the freeze page, the Overview, the graph and /wallet read this
    assert page["ask"] == panel["ask"]
    rows = attr.annotate_rows(db, case, fz.wallet_rows(db, case))
    assert next(r for r in rows if r["address"] == k[1])["owner"]["ask"] == panel["ask"]
    api = client_for("investigator", case=case).get(f"/api/cases/{case.id}/owners").json()
    got = next(o for o in api["wallets"] if o["address"] == k[1])
    assert got["ask"]["href"] == panel["ask"]["href"]


def test_a_kucoin_deposit_ask_links_the_counterparty_on_every_page(db, case):
    k = attr.key_of("ethereum", "0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2")
    o = attr.by_key(db, case)[k]
    assert o["ask"]["href"] and "add KuCoin as a counterparty" not in o["ask"]["text"]


def test_a_service_wallet_without_a_reading_halves_the_issuers_odds_and_names_its_owner(db, case):
    addr = _node(db, case, "0x57de1021").address.address
    before = _plan(db, case)
    circle = next(m for m in before.moves if m.authority is not None and m.authority.name.startswith("Circle"))
    attr.mark(db, case, None, chain="ethereum", address=addr, owner="Binance", kind="exchange_hot_wallet")
    db.commit()
    after = _plan(db, case).find(circle.key)
    assert after.likelihood == pytest.approx(circle.likelihood * 0.5, abs=0.02)
    assert "ask Binance" in after.basis and "its owner is asked first" in after.likelihood_why


# --------------------------------------------------------------------------- mixers, explorer lines, sweeps
@pytest.mark.parametrize("name", ["Tornado.Cash: Router", "Tornado.Cash: 100 ETH", "Tornado.Cash: Deposit",
                                  "Uniswap V3: Router 2", "Railgun: Relay"])
def test_a_mixer_or_dex_router_tag_is_non_custodial(name):
    assert explorer.classify([{"name": name, "type": "name"}])[1] == "non_custodial"


def test_a_mixer_tag_never_becomes_a_letter_and_a_stored_row_is_read_again(db, case, ex):
    k = _addr(db, case, "Peel outflow (0.75 ETH")
    _consent(db, case)
    ex.tags[k[1]] = [_tag("Tornado.Cash: Router")]
    ex.info[k[1]] = {}
    attr.run_lookups(db, case, only={k})
    att = attr.attribute(db, case)[k]
    assert att.kind == "non_custodial" and not att.service and "no account to freeze" in att.ask["text"]
    assert att.ask["href"] is None
    plan = _plan(db, case)
    assert plan.find(f"owner:{k[0]}:{k[1]}") is None
    row = db.scalars(select(WalletAttribution).where(WalletAttribution.case_id == case.id,
                                                     WalletAttribution.source == "explorer")).first()
    row.kind = "swap_bridge"  # a row stored before the mixer lexicon
    db.commit()
    assert attr.attribute(db, case)[k].kind == "non_custodial"


def test_a_tagged_wallet_gets_no_self_custody_line(db, case, ex):
    k = _addr(db, case, "Hub outflow #3")
    _consent(db, case)
    ex.tags[k[1]] = [_tag("KuCoin: Deposit", entity="KuCoin")]
    ex.info[k[1]] = {}
    attr.run_lookups(db, case, only={k})
    lines = " ".join(attr.attribute(db, case)[k].lines)
    assert "public tags: KuCoin: Deposit" in lines and "no public tag" not in lines and "self-custody" not in lines


def test_the_hot_wallet_a_deposit_swept_to_is_not_counted_again(db, case):
    atts = attr.attribute(db, case)
    hot = atts[attr.key_of("ethereum", "0x45300136662dd4e58fc0df61e6290dffd992b785")]
    dep = atts[attr.key_of("ethereum", "0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2")]
    assert hot.wallet.swept_float and hot.wallet.money_usd == 0 and dep.wallet.money_usd == pytest.approx(144.94)
    owners = rp.owners_view(_plan(db, case), _Access())["owners"]
    assert not any(o["address"] == hot.wallet.address for o in owners)


# --------------------------------------------------------------------------- a service float moving
def test_a_service_float_moving_is_no_funds_left_on_any_page(db, case):
    addr = _tether_wallet(db, case)
    _taint(db, case, addr, 1_000)
    t0 = datetime.now(tz=UTC) + timedelta(minutes=5)
    _check(db, case, addr, t0, balance="900000")
    _check(db, case, addr, t0 + timedelta(hours=1), balance="700000")
    st = fz.case_status(db, case)
    assert not any(w["address"] == addr for w in st["moved"])
    w = next(w for w in st["wallets"] if w["address"] == addr)
    assert w["funds_left"] == [] and any(c.get("float_moved") for c in w["checks"])
    assert not (bs.onchain_by_issuer(db, case).get("Tether") or {}).get("moved")
    assert fz.pooled_float(Decimal(900000), Decimal(700000), 1000.0) and not fz.pooled_float(
        Decimal(900000), Decimal(500), 1000.0) and not fz.pooled_float(Decimal(900000), Decimal(700000), 0.0)


# --------------------------------------------------------------------------- reply rules, evidence matching
def test_a_temporary_freeze_with_a_police_referral_is_a_hold_with_le_also():
    r = R.classify("We have temporarily frozen the account associated with the deposit address. Please report this "
                   "to your local police, who can then contact us with a formal request.")
    assert r.status == R.HOLD_PLACED and R.LE_PROCESS_REQUIRED in r.also
    assert R.classify("We have temporarily frozen the account associated with the deposit address.").status == \
        R.HOLD_PLACED


def test_the_digital_artifacts_folder_and_report_words_match_what_they_should(db, case):
    img = ev.add_note(db, case, title="IMG_2034.png", text="x", folder=EvidenceFolder.DIGITAL_ARTIFACTS)
    le = ev.add_note(db, case, title="Report 2026-10.pdf", text="x", folder=EvidenceFolder.LAW_ENFORCEMENT)
    inc = ev.add_note(db, case, title="Incident report.pdf", text="x", folder=EvidenceFolder.LAW_ENFORCEMENT)
    monthly = ev.add_note(db, case, title="Monthly report.pdf", text="x", folder=EvidenceFolder.INVESTIGATOR_REPORTS)
    forensic = ev.add_note(db, case, title="Forensic report.pdf", text="x", folder=EvidenceFolder.INVESTIGATOR_REPORTS)
    assert er.derived_keys(img) == {"comms_export"}
    assert "police_report" not in er.derived_keys(le) and "police_report" in er.derived_keys(inc)
    assert "trace_report_run" not in er.derived_keys(monthly) and "trace_report_run" in er.derived_keys(forensic)


# --------------------------------------------------------------------------- the graph: one owner view
def test_the_hover_card_names_the_owner_an_attribution_gives(db, case):
    from test_graph_hover import _hover

    addr = _node(db, case, "0x9cf83877").address.address
    attr.mark(db, case, None, chain="ethereum", address=addr, owner="Binance", kind="exchange_hot_wallet")
    db.commit()
    d = _hover(db, case)[addr.lower()]
    assert d["owner"]["owner"] == "Binance"
    o = d["hover"]["owner"]
    assert o["known"] and o["name"] == "Binance" and o["category"] == "exchange_hot_wallet"


# --------------------------------------------------------------------------- consent forms
def test_owner_lookups_consent_refuses_endpoints_the_admin_did_not_see(db, case, client_for):
    attr.set_enabled(db, case, None, False)  # off by a case admin (on by default): an explicit consent is asked
    adm = client_for("admin", case=case)
    tok = csrf_token(adm, f"/cases/{case.id}/recovery-plan")
    shown = ",".join(attr.consent_hosts(attr.egress_plan()))
    r = adm.post(f"/cases/{case.id}/owners/settings", data={"csrf_token": tok, "enabled": "1", "consent": "1",
                                                           "hosts": "eth.blockscout.com"}, follow_redirects=False)
    assert r.status_code == 409
    db.expire_all()
    assert not attr.setting(db.get(type(case), case.id)).get("enabled")
    r = adm.post(f"/cases/{case.id}/owners/settings", data={"csrf_token": tok, "enabled": "1", "consent": "1",
                                                           "hosts": shown}, follow_redirects=False)
    assert r.status_code == 303
    page = adm.get(f"/cases/{case.id}/recovery-plan").text
    assert 'name="hosts"' in page or "Turn owner lookups off" in page


# --------------------------------------------------------------------------- a person's owner name and the model
def test_a_persons_owner_name_never_reaches_the_model_but_a_catalogue_name_does(db, case):
    a = _node(db, case, "0x9cf83877").address.address
    b = _node(db, case, "0xc6a2b6d3").address.address
    attr.mark(db, case, None, chain="ethereum", address=a, owner="Sam Example", kind="unhosted")
    attr.mark(db, case, None, chain="ethereum", address=b, owner="Binance", kind="exchange_deposit")
    db.commit()
    red = redactor_for(db, case)
    assert red("Owner: Sam Example") == "Owner: [OWNER]" and red("Owner: Binance") == "Owner: Binance"
