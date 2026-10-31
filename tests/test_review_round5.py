"""Review round 5 of the provider playbooks / reply intelligence / request paths / Recovery plan: one regression per
verified major (the reply-lead cap that dropped a deposit address at a named exchange, US agencies read as LE, a missed
provider deadline and a lapsed hold that still counted as secured, the freezing order LE issues itself, the counsel
brief's own channel, the querela term) and the cheap minors. The demo case plus synthetic replies (every
address, ticket and number is made up). Offline: no model, no mail, no chain."""

from datetime import timedelta
from types import SimpleNamespace as N
from urllib.parse import unquote

import pytest
from test_playbook_review import _access
from test_review_round3 import (
    BINANCE_FO,
    CIRCLE_COURT,
    EVM_BINANCE,
    EVM_EXTERNAL,
    KUCOIN_HOLD,
    MEXC_TEMP,
    NOW,
    TETHER_ACK,
    TO_BINANCE,
    _cand,
    _ent,
    _le,
    _parsed,
    _plan,
    _reply,
    _row,
    _sent,
    _shipped,
)

from app import services
from app.ai import providers
from app.blocks import classify_rules as R
from app.blocks import path as pathmod
from app.blocks import recovery as rp
from app.blocks import status as bs
from app.db.models import EntityCategory, LEContact
from app.domain import correspondence as desk
from app.domain import directory
from app.domain import playbook as pbm


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


@pytest.fixture
def case(db, tmp_path):
    from test_block_status import fresh_case

    c = fresh_case(db, tmp_path)
    services.run_trace(db, c, provider_mode="fixture")
    db.refresh(c)
    return c


def _at(db, case, now) -> rp.Plan:
    db.expire_all()
    return rp.build(db, case, now=now)


LEADS = ("dest:", "fwatch:", "issuer:")


# --------------------------------------------------------------------------- major: the reply-lead cap
def test_an_earlier_multi_wallet_reply_never_pushes_out_a_deposit_address_at_a_named_exchange(db, case):
    okx = _ent(db, "OKX")
    wallets = ["0x" + f"{n:02x}" * 20 for n in range(0x31, 0x34)]
    oo = _sent(db, case, okx, "0x" + "f6" * 20, at=NOW - timedelta(days=2))
    _reply(db, case, oo, "The funds were withdrawn to " + ", ".join(wallets) + " on 19 Oct. We hold nothing now.",
           NOW - timedelta(hours=1))
    bybit = _ent(db, "Bybit")
    bo = _sent(db, case, bybit, "0x" + "b2" * 20, at=NOW - timedelta(days=3), amount="60,000 USDT")
    _reply(db, case, bo, TO_BINANCE, NOW - timedelta(hours=2))
    plan = _plan(db, case)
    dest = plan.find(f"dest:ethereum:{EVM_BINANCE}")
    assert dest is not None and "Binance" in dest.title
    # dest leads first; a wallet's watch + issuer moves count as one lead; the cap holds on every path
    leads = [m for m in plan.moves if m.key.startswith(LEADS)]
    groups = {m.key.split(":", 1)[1] for m in leads}
    assert len(groups) <= rp.MAX_WATCH and dest in leads
    assert all(plan.moves.index(dest) < plan.moves.index(m) for m in leads if m.key.startswith("fwatch:"))
    # a wallet kept keeps its pair: never a watch move without its issuer letter (the funds just left for it)
    for g in groups - {f"ethereum:{EVM_BINANCE}"}:
        assert plan.find(f"fwatch:{g}") is not None and plan.find(f"issuer:{g}") is not None


def test_many_deposit_addresses_still_cap_at_max_watch_leads(db, case):
    okx = _ent(db, "OKX")
    oo = _sent(db, case, okx, "0x" + "d3" * 20, at=NOW - timedelta(days=2), amount="80,000 USDT")
    wallets = ["0x" + f"{i:02x}" * 20 for i in range(0x40, 0x48)]
    _reply(db, case, oo, " ".join(f"The funds were withdrawn to {x}." for x in wallets), NOW - timedelta(hours=1))
    plan = _plan(db, case)
    groups = {m.key.split(":", 1)[1] for m in plan.moves if m.key.startswith(LEADS)}
    assert len(groups) == rp.MAX_WATCH


# --------------------------------------------------------------------------- major: US agencies are LE
@pytest.mark.parametrize("agency,role", [
    ("Federal Bureau of Investigation — Demo Field Office", "special agent"),
    ("Homeland Security Investigations (HSI)", ""),
    ("U.S. Attorney's Office, Southern District of New York", ""),
    ("U.S. Department of Justice", ""),
    ("New York County District Attorney", ""),
    ("IRS Criminal Investigation", ""),
    ("Demo County Sheriff's Office", "detective"),
])
def test_us_federal_and_state_agencies_are_law_enforcement(agency, role):
    assert desk.contact_category(N(agency=agency, role=role, entity_id=None)) == "law_enforcement"


def test_lawyers_and_pi_firms_stay_what_they_are():
    for agency, role, cat in (("Smith & Jones Attorneys", "", "legal_counsel"), ("Demo Law Firm", "attorney",
                              "legal_counsel"), ("Acme Private Investigations", "", "pi_firm"),
                              ("Marshall Partners", "", "unknown")):
        assert desk.contact_category(N(agency=agency, role=role, entity_id=None)) == cat, agency


def test_a_us_agent_added_under_the_agencys_full_name_is_briefed(db, case):
    circle = _ent(db, "Circle (USDC issuer)")
    addr = _cand(db, case, "Circle (USDC issuer)").identifiers[0].address
    order = _sent(db, case, circle, addr, at=NOW - timedelta(days=1), amount="399,247.92 USDC")
    _reply(db, case, order, CIRCLE_COURT + " Reference: CRC-20391", NOW - timedelta(hours=18))
    db.add(LEContact(case=case, agency="Federal Bureau of Investigation — Demo Field Office", role="special agent",
                     email="agent@le-demo.example", jurisdiction="USA"))
    db.commit()
    m = _plan(db, case).find(f"o{order.id}")
    assert m.title == "Brief Federal Bureau of Investigation — Demo Field Office about Circle (USDC issuer)"
    assert m.route["kind"] == "direct" and not m.route.get("agent")
    le = _le(db, case, "Federal Bureau")
    assert "template=le_brief" in m.actions[0]["href"] and f"/authorities/{le.key}?" in m.actions[0]["href"]


# --------------------------------------------------------------------------- major: a missed provider deadline
def _mexc(db, case):
    mexc = _ent(db, "MEXC")
    order = _sent(db, case, mexc, "0x" + "c2" * 20, at=NOW - timedelta(days=1), amount="250,000 USDT")
    reply = _reply(db, case, order, MEXC_TEMP, NOW - timedelta(hours=2))
    return order, reply


def test_mexcs_missed_deadline_is_an_overdue_answer_never_a_silent_hold(db, case):
    order, reply = _mexc(db, case)
    key = f"o{order.id}"
    later = NOW + timedelta(hours=50)  # both 48-hour clocks (from our submission, from their freeze) passed
    for confirmed in (False, True):
        if confirmed:
            bs.confirm(db, _access(case), key, status=R.HOLD_PLACED, reply_id=reply.id, amount="250000", asset="USDT")
        plan = _at(db, case, later)
        m = plan.find(key)
        assert m.kind == "answer" and "deadline passed" in m.title and "confirm the freeze still stands" in m.title
        assert "may already have lifted" in m.text and "Hold in place" not in m.text
        assert m.clock is not None and m.clock["due_at"] <= later and any("passed" in w for w in m.urgency_why)
        assert "template=info_response" in m.href
        # never secured while the provider's own condition for the hold is missed
        assert not any(s["key"] == m.authority.key for s in plan.secured) and plan.totals["secured_usd"] == 0
    # the earlier (governing) clock passed, the later one still ahead: said, and the hold still counts
    plan = _at(db, case, NOW + timedelta(hours=25))
    m = plan.find(key)
    assert m.kind == "answer" and "The earlier deadline" in m.text and "passed" in m.text
    assert any(s["key"] == m.authority.key for s in plan.secured)


def test_a_passed_clock_of_ours_with_no_reply_yet_still_goes_out_now(db, case):
    mexc = _ent(db, "MEXC")
    order = _sent(db, case, mexc, "0x" + "c2" * 20, at=NOW - timedelta(hours=50))
    row = _row(db, case, f"o{order.id}")
    na = row.next_action
    assert na["kind"] == "chase" and "deadline passed" in na["title"] and "send it at once" in na["text"]


# --------------------------------------------------------------------------- major: a lapsed hold
def test_a_lapsed_hold_is_no_longer_secured_and_is_chased(db, case):
    kucoin = _ent(db, "KuCoin")
    addr = _cand(db, case, "KuCoin").identifiers[0].address
    order = _sent(db, case, kucoin, addr, at=NOW - timedelta(days=1), amount="140 USDT")
    reply = _reply(db, case, order, KUCOIN_HOLD, NOW - timedelta(hours=2))
    key = f"o{order.id}"
    bs.confirm(db, _access(case), key, status=R.HOLD_PLACED, reply_id=reply.id, amount="140", asset="USDT")
    plan = _at(db, case, NOW + timedelta(days=1))
    assert any(s["key"] == f"entity-{kucoin.id}" for s in plan.secured)  # in place while it runs
    later = NOW + timedelta(days=31)
    plan = _at(db, case, later)
    m = plan.find(key)
    assert m.kind == "chase" and "hold lapsed" in m.title and "still held" in m.title
    assert "Hold in place" not in m.text and "before it lapses" not in m.text
    assert m.clock is not None and m.clock["due_at"] < later and "template=status_request" in m.href
    assert not any(s["key"] == f"entity-{kucoin.id}" for s in plan.secured)
    assert "lapsed?" in m.basis and m.value
    # an LE filing recorded after the hold: the hold is in LE's hands, no lapse
    db.expire_all()
    row = _row(db, case, key, now=later)
    assert row.path.lapsed is not None
    bs.confirm_step(db, _access(case), key, step="le_filed")
    row = _row(db, case, key, now=later)
    assert row.path.lapsed is None


# --------------------------------------------------------------------------- major: a freezing order LE issues
def test_a_freezing_order_law_enforcement_issues_is_no_court_application(db, case):
    binance = _ent(db, "Binance")
    order = _sent(db, case, binance, "0x" + "b1" * 20, at=NOW - timedelta(days=1))
    _reply(db, case, order, BINANCE_FO, NOW - timedelta(hours=3))
    key = f"o{order.id}"
    row = _row(db, case, key)
    assert row.path.instrument["type"] == "freezing_order" and pathmod.le_issued(row.path)
    _s, body, _r = desk.build_letter(db, case, _le(db, case, "Procura"), "le_brief", ref=key)
    request = body.split("### Request")[1].split("Attached")[0]
    assert "competent court" not in request and "send Binance a freezing order" in request and "Kodex" in request
    _s, body, _r = desk.build_letter(db, case, _le(db, case, "Carabinieri"), "le_brief", ref=key)
    assert "apply to the competent court" not in body.split("### Request")[1]
    # a reachable US agent on a US victim's case: briefed first, not the Italian prosecutor
    db.add(LEContact(case=case, agency="FBI Demo Field Office", role="case agent", name="SA Demo",
                     email="agent@fbi-demo.example", jurisdiction="USA"))
    db.commit()
    m = _plan(db, case).find(key)
    assert m.route["le"] == "FBI Demo Field Office" and "Brief FBI Demo Field Office" in m.text
    # MEXC's Order "from an authorised LE agency or judicial body": the same
    order2, _reply2 = _mexc(db, case)
    _s, body, _r = desk.build_letter(db, case, _le(db, case, "Procura"), "le_brief", ref=f"o{order2.id}")
    assert "competent court" not in body.split("### Request")[1]
    # a court instrument stays one (Circle: a US or French court order)
    circle = _ent(db, "Circle (USDC issuer)")
    co = _sent(db, case, circle, at=NOW - timedelta(days=1))
    _reply(db, case, co, CIRCLE_COURT, NOW - timedelta(hours=18))
    assert not pathmod.le_issued(_row(db, case, f"o{co.id}").path)


# --------------------------------------------------------------------------- major: the counsel brief's own route
def test_the_counsel_brief_names_counsels_channel_and_evidence_not_the_le_portal(db, case):
    binance = _ent(db, "Binance")
    order = _sent(db, case, binance, "0x" + "b1" * 20, at=NOW - timedelta(days=1))
    _reply(db, case, order, BINANCE_FO, NOW - timedelta(hours=3))
    key = f"o{order.id}"
    m = _plan(db, case).find(key)
    body, _src, _id = rp._brief(db, case, m, counsel=True)
    req = body.split("### 2. What it requires")[1].split("###")[0]
    assert "Binance Customer Service" in req and "Kodex" not in req and "LE only" not in req
    assert "reserved for law enforcement" not in req and "LE identity" not in req and "Court order" in req
    assert "### 3. Route" not in body  # LE's cross-border route is not counsel's
    # the LE brief keeps the LE channel
    _s, le_body, _r = desk.build_letter(db, case, _le(db, case, "Procura"), "le_brief", ref=key)
    assert "Kodex" in le_body.split("### 2. What it requires")[1].split("###")[0]


# --------------------------------------------------------------------------- major: the querela term
def test_the_querela_term_runs_from_the_fraud_date_and_reaches_the_plan(db, case):
    cat = directory.load_catalogue()
    for org in ("carabinieri", "procura"):
        pb = cat.by_key[org].playbook
        cs = pathmod.standing_clocks(pb, case.fraud_date)
        assert [c["key"].split(".")[1] for c in cs] == ["querela_term"], org
        assert cs[0]["due_at"].month == (case.fraud_date.month + 2) % 12 + 1
    assert pathmod.standing_clocks(cat.by_key["carabinieri"].playbook, None)[0]["due_at"] is None
    # the engine resolves the start (path.clocks)
    pb = cat.by_key["carabinieri"].playbook
    st = pathmod.PathState(path=pb.path("querela"), fact_known=case.fraud_date)
    row = N(requested_at=None, replies=[], outbound=[], letter=None)
    cs = pathmod.clocks(row, st, pb, now=NOW)
    assert any(c["key"] == "querela.querela_term" and not c["met"] for c in cs)
    notes = _plan(db, case).notes
    q = next(n for n in notes if n.startswith("Querela term"))
    assert "file the querela by" in q and "art. 124 c.p." in q and "Carabinieri" in q
    # past the term: said plainly
    q = next(n for n in _at(db, case, NOW + timedelta(days=120)).notes if n.startswith("Querela term"))
    assert "passed on" in q


def test_every_victim_side_clock_has_a_start_the_engine_resolves():
    for org in directory.load_catalogue().orgs:
        pb = org.playbook
        for p in getattr(pb, "paths", ()) or ():
            for d in p.timing.deadlines:
                if d.by in (None, *pathmod.PRIVATE_BY):
                    assert d.starts in pathmod.RESOLVED_STARTS, (org.key, p.key, d.key, d.starts)


# --------------------------------------------------------------------------- minors
def test_a_deposit_at_an_exchange_with_an_open_request_follows_that_request_up(db, case):
    binance = _ent(db, "Binance")
    bo = _sent(db, case, binance, "0x" + "b1" * 20, at=NOW - timedelta(days=4))
    bybit = _ent(db, "Bybit")
    yo = _sent(db, case, bybit, "0x" + "b2" * 20, at=NOW - timedelta(days=2), amount="60,000 USDT")
    _reply(db, case, yo, f"The funds were withdrawn on 19 Oct to {EVM_EXTERNAL}, a deposit address at Binance.",
           NOW - timedelta(hours=1))
    m = _plan(db, case).find(f"dest:ethereum:{EVM_EXTERNAL}")
    assert m is not None and not any("template=status_request" in (a.get("href") or "") for a in m.actions)
    follow = next(a for a in m.actions if a["label"].startswith(f"Write to Binance on request o{bo.id}"))
    # a freeze request of its own for the new deposit, quoting the open request (round 6: never a status request)
    assert "template=info_request" in follow["href"] and f"ref=o{bo.id}" in follow["href"]
    assert f"freeze=ethereum:{EVM_EXTERNAL}" in unquote(follow["href"])
    # Binance never holds on a private letter: the LE brief leads
    assert m.kind == "le" and next(a for a in m.actions if a.get("primary"))["label"].startswith("Brief LE")


def test_an_own_platform_destination_on_a_confirm_move_links_the_answer_letter(db, case):
    kraken = _ent(db, "Kraken")
    order = _sent(db, case, kraken, "0x" + "a1" * 20, at=NOW - timedelta(days=1))
    _reply(db, case, order, f"The funds were moved by internal transfer to sub-account deposit address {EVM_EXTERNAL}. "
                            "We have frozen the source account.", NOW - timedelta(hours=1))
    m = _plan(db, case).find(f"o{order.id}")
    assert "extend the hold" in m.text
    assert any(a["label"] == "Open the answer letter" and "template=info_response" in a["href"] for a in m.actions)


def test_an_unclear_reply_is_never_overdue(db, case):
    bybit = _ent(db, "Bybit")
    order = _sent(db, case, bybit, "0x" + "b3" * 20, at=NOW - timedelta(days=10), due=NOW - timedelta(days=3))
    _reply(db, case, order, "Thank you. Kindly note the matter.", NOW - timedelta(days=1))
    row = _row(db, case, f"o{order.id}")
    assert row.status == R.UNCLEAR and not row.overdue
    m = _plan(db, case).find(f"o{order.id}")
    assert "reply overdue" not in m.urgency_why


def test_the_skill_says_how_many_reply_leads_it_leaves_out(db, case, client_for):
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership

    bybit = _ent(db, "Bybit")
    bo = _sent(db, case, bybit, "0x" + "b2" * 20, at=NOW - timedelta(days=3), amount="60,000 USDT")
    _reply(db, case, bo, TO_BINANCE, NOW - timedelta(hours=2))
    inv = client_for("investigator", case=case, email="inv-r5-skill@tests.example")
    user = inv.user
    access = CaseAccess(case=case, user=user, role=effective_role(db, user, case), member=membership(db, user, case))
    res = skills.run_skill(db, access, "recovery-plan")
    # the model's copy leaves the lead out and says so; the investigator's screen shows it, as the Recovery plan does
    assert EVM_BINANCE not in res.model_markdown and "not shown here" in res.model_markdown
    assert "not shown here" not in res.markdown


def test_an_unreachable_le_target_names_the_reachable_one(db, case):
    tether = _ent(db, "Tether (USDT issuer)", EntityCategory.STABLECOIN_ISSUER)
    addr = _cand(db, case, "Tether (USDT issuer)").identifiers[0].address
    order = _sent(db, case, tether, addr, at=NOW - timedelta(days=1), chain="tron")
    _reply(db, case, order, TETHER_ACK, NOW - timedelta(hours=20))
    row = _row(db, case, f"o{order.id}")
    assert row.path.le is not None and not row.path.le.reachable and row.path.route["reachable"]
    assert f"or brief {row.path.route['reachable']} (reachable) instead" in row.next_action["text"]


def test_the_observed_fact_filter_reads_more_date_forms():
    for bad in ("reply on 2026.10.03", "reply 2026 10 03", "reply 2026-10-3", "on 3-10", "Tuesday the 3rd",
                "replied 2026‑10‑03", "replied 3 ottobre 2026", "3 Okt 2026", "3. Oktober", "replied 3 octobre",
                "3 de octubre"):
        assert pbm._day_date(bad), bad
    for ok in ("within 1-2 business days", "3-5 days", "the market 24 hours", "decision 2 of the board", "2026-10",
               "in 2026 10 exchanges", "mai"):
        assert not pbm._day_date(ok), ok


def test_a_trailing_dot_host_is_still_the_le_only_portal():
    pb = directory.load_catalogue().by_key["binance"].playbook
    assert pb.domain_class("https://app.kodexglobal.com./binance/signup") == "vendor_portal_le_only"
    assert pbm._portal_value(pb.domains, "https://APP.kodexglobal.com./binance/signup") is not None
    raw = _shipped("binance")
    raw["channels"][0]["value"] = "https://app.kodexglobal.com./binance/signup"
    raw["channels"][0]["who"] = "any"
    with pytest.raises(directory.CatalogueError):
        _parsed(raw)


def test_the_validator_refuses_overclaiming_and_wrong_route_paths():
    raw = _shipped("binance")
    raw["paths"][0]["outcomes"] = ["frozen"]  # victim_report
    with pytest.raises(directory.CatalogueError, match="at most to a hold"):
        _parsed(raw)
    raw = _shipped("binance")
    raw["reply_signals"].append({**raw["reply_signals"][0], "phrase": "we froze it", "means": "frozen",
                                 "path": "victim_report"})
    with pytest.raises(directory.CatalogueError, match="at most hold_placed"):
        _parsed(raw)
    raw = _shipped("binance")
    sup = next(c for c in raw["channels"] if c["key"] == "binance.support")
    sup["who"] = "victim_or_rep"
    next(p for p in raw["paths"] if p["key"] == "us_seizure").setdefault("channel_keys", []).append("binance.support")
    with pytest.raises(directory.CatalogueError, match="victim_or_rep"):
        _parsed(raw)
