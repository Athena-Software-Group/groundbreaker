"""Review round 6: the smoke-test findings (a failed freeze check never hides the last good reading, funds
draining between two good readings, folder-imported evidence, the evidence of the leading route, a drafted follow-up
after a sent request) and one regression per verified major of verify round 4 (an own-platform destination on an empty
account, counsel with an LE word in its role, a custodian named by "belongs to" / a parenthesis, MEXC's LE-side clock,
KuCoin's one hold expiry, the LE for a reply lead, a new deposit at an exchange with an open request, Bybit's VIP-only
hold) plus the cheap minors. The demo case plus synthetic readings, items and replies (every address, ticket and
number is made up). Offline: no model, no mail, no chain."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace as N

import pytest
from test_playbook_review import _access
from test_review_round3 import (
    EVM_BINANCE,
    KUCOIN_HOLD,
    MEXC_TEMP,
    NOW,
    _cand,
    _ent,
    _plan,
    _reply,
    _row,
    _sent,
)

from app import services
from app.ai import providers
from app.blocks import classify_rules as R
from app.blocks import path as pathmod
from app.blocks import recovery as rp
from app.blocks import status as bs
from app.db.models import EvidenceFolder, EvidenceItem, FreezeCheck, TraceNode
from app.domain import correspondence as desk
from app.domain import evidence_requirements as er
from app.freeze import service as fz

USDT_TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


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


def _tether_wallet(db, case) -> str:
    return _cand(db, case, "Tether (USDT issuer)").identifiers[0].address


def _taint(db, case, address, usd):
    run = services.latest_run(db, case)
    for n in db.query(TraceNode).filter(TraceNode.run_id == run.id).all():
        if n.address.address == address:
            n.taint_usd = Decimal(usd)
    db.commit()


def _check(db, case, address, at, *, balance=None, blacklisted=False, error=None):
    db.add(FreezeCheck(case_id=case.id, chain="tron", address=address, issuer="Tether", token_symbol="USDT",
                       token_contract=USDT_TRON, status="error" if error else "ok", error=error,
                       blacklisted=None if error else blacklisted,
                       balance=None if balance is None else Decimal(balance), checked_at=at,
                       block_number=None, raw_sha256=None if error else "ab" * 32,
                       meta={"host": "api.trongrid.io"} if error else
                       {"balance_raw": str(int(Decimal(balance) * 10**6))}))
    db.commit()


# --------------------------------------------------------------------------- 1. a failed check never hides a good one
def test_an_error_row_after_an_ok_reading_keeps_the_ok_reading_in_the_plan(db, case):
    addr = _tether_wallet(db, case)
    _taint(db, case, addr, 640_000)
    t0 = datetime.now(tz=UTC) + timedelta(minutes=5)
    _check(db, case, addr, t0, balance="640000")
    _check(db, case, addr, t0 + timedelta(minutes=30), error="host_unavailable")
    w = next(w for w in fz.wallet_rows(db, case) if w["address"] == addr)
    c = w["checks"][0]
    assert c["status"] == "ok" and c["balance_label"] == "640,000.00" and w["state"] == "clear"
    assert c["stale_note"].startswith("last checked OK") and "host_unavailable" in c["stale_note"]
    plan = rp.build(db, case, now=t0 + timedelta(hours=1))
    m = plan.find(f"entity-{_ent(db, 'Tether (USDT issuer)').id}")
    assert m is not None and m.value >= 640_000
    assert "$640,000 on-chain, not frozen" in m.basis and "last checked OK" in m.basis
    assert "balance read on-chain" in m.likelihood_why
    ev = {e["key"]: e["state"] for e in m.evidence}
    assert ev.get("balance_reading", "have") == "have"


def test_a_blacklisted_reading_stays_secured_through_an_outage(db, case):
    addr = _tether_wallet(db, case)
    _taint(db, case, addr, 100_000)
    t0 = datetime.now(tz=UTC) + timedelta(minutes=5)
    _check(db, case, addr, t0, balance="100000", blacklisted=True)
    _check(db, case, addr, t0 + timedelta(minutes=30), error="host_unavailable")
    plan = rp.build(db, case, now=t0 + timedelta(hours=1))
    sec = [s for s in plan.secured if s["authority"].startswith("Tether")]
    assert sec and sec[0]["usd"] == pytest.approx(100_000) and "frozen on-chain" in sec[0]["text"]
    assert fz.case_status(db, case)["frozen_usd"] == pytest.approx(100_000)


def test_a_balance_drained_between_two_good_readings_is_funds_moving(db, case):
    addr = _tether_wallet(db, case)
    _taint(db, case, addr, 12_600)
    t0 = datetime.now(tz=UTC) + timedelta(minutes=5)
    _check(db, case, addr, t0, balance="12600")
    _check(db, case, addr, t0 + timedelta(hours=2), balance="0.25")
    _check(db, case, addr, t0 + timedelta(hours=3), error="host_unavailable")
    now = t0 + timedelta(hours=4)
    plan = rp.build(db, case, now=now)
    left = plan.find(f"left:tron:{addr}")
    assert left is not None and left.kind == "retrace" and left.actionable
    assert left.title.startswith("Funds left ") and "re-trace now and ask the next custodian or issuer" in left.title
    assert "12,600.00 to 0.25" in left.text and left.urgency >= 3.0 and left.value == pytest.approx(12_599.75, rel=1e-3)
    assert left.actions[0]["post"].endswith("/trace")
    t = plan.find(f"entity-{_ent(db, 'Tether (USDT issuer)').id}")
    # nothing is left to blacklist there (0.25 USDT): the issuer's own move is gone, or ranked below the re-trace
    assert t is None or (any(w.startswith("funds left ") for w in t.urgency_why) and "funds left" in t.basis
                         and plan.moves.index(left) < plan.moves.index(t))
    # a re-trace after the drop resolves it: the move is gone
    run = services.latest_run(db, case)
    run.finished_at = now
    db.commit()
    assert rp.build(db, case, now=now + timedelta(minutes=5)).find(f"left:tron:{addr}") is None


def test_a_hot_wallets_float_moving_is_no_funds_left_alert(db, case):
    addr = _tether_wallet(db, case)
    _taint(db, case, addr, 1_000)
    t0 = datetime.now(tz=UTC) + timedelta(minutes=5)
    _check(db, case, addr, t0, balance="900000")
    _check(db, case, addr, t0 + timedelta(hours=1), balance="700000")
    plan = rp.build(db, case, now=t0 + timedelta(hours=2))
    assert plan.find(f"left:tron:{addr}") is None


# --------------------------------------------------------------------------- r4 major: counsel with an LE word in the role
@pytest.mark.parametrize("agency,role,cat", [
    ("Smith & Partners LLP", "Court-appointed counsel", "legal_counsel"),
    ("", "Legal Officer", "legal_counsel"),
    ("", "Chief Legal Officer", "legal_counsel"),
    ("Smith & Partners LLP", "Partner, former U.S. Attorney", "legal_counsel"),
    ("", "Assistant U.S. Attorney", "law_enforcement"),
    ("", "Deputy District Attorney", "law_enforcement"),
    ("", "Special Agent", "law_enforcement"),
    ("", "Detective, financial crimes", "law_enforcement"),
])
def test_counsel_is_never_law_enforcement_for_a_generic_le_word_in_the_role(agency, role, cat):
    assert desk.contact_category(N(agency=agency, role=role, entity_id=None)) == cat


# --------------------------------------------------------------------------- r4 major: the custodian a reply names
@pytest.mark.parametrize("text,org", [
    (f"The funds were withdrawn to {EVM_BINANCE}. This address belongs to OKX.", "OKX"),
    (f"The user withdrew the funds to {EVM_BINANCE} (Binance).", "Binance"),
    (f"The funds were withdrawn to {EVM_BINANCE}, an address owned by Kraken.", "Kraken"),
])
def test_belongs_to_and_a_bare_parenthesis_name_the_exchange_holding_the_deposit(db, case, text, org):
    bybit = _ent(db, "Bybit")
    order = _sent(db, case, bybit, "0x" + "b2" * 20, at=NOW - timedelta(days=3), amount="60,000 USDT")
    _reply(db, case, order, text, NOW - timedelta(hours=2))
    row = _row(db, case, f"o{order.id}")
    orgs, _ = rp._custodians(desk.case_authorities(db, case))
    d = pathmod.destinations(row, orgs)
    assert [(x["where"], (x["org"] or (None, None))[1]) for x in d] == [("other", org)]
    plan = _plan(db, case)
    assert plan.find(f"dest:ethereum:{EVM_BINANCE}") is not None
    assert plan.find(f"issuer:ethereum:{EVM_BINANCE}") is None and plan.find(f"fwatch:ethereum:{EVM_BINANCE}") is None


# --------------------------------------------------------------------------- r4 major: Bybit's hold is VIP-only
def test_bybits_general_path_expects_no_voluntary_hold_for_a_stranger(db, case):
    from app.domain import directory

    pb = directory.load_catalogue().by_key["bybit"].playbook
    for who in ("victim", "pi", "counsel"):
        p = pathmod.our_path(pb, who)
        assert p.key == "victim_report" and R.HOLD_PLACED not in {*p.outcomes, *p.expected_replies}
        assert p.expected_replies[0] == R.LE_PROCESS_REQUIRED and "VIP" in p.notes
    assert R.HOLD_PLACED in pb.path("vip_report").outcomes
    bybit = _ent(db, "Bybit")
    order = _sent(db, case, bybit, "0x" + "b2" * 20, at=NOW - timedelta(hours=6), amount="60,000 USDT")
    m = _plan(db, case).find(f"o{order.id}")
    assert "voluntary hold possible" not in m.likelihood_why and "LE process only" in m.likelihood_why


# --------------------------------------------------------------------------- r4 majors: a reply lead's LE and letter
def test_a_reply_lead_briefs_the_le_its_exchange_routes_to(db, case):
    from test_review_round3 import TO_BINANCE

    bybit = _ent(db, "Bybit")
    order = _sent(db, case, bybit, "0x" + "b2" * 20, at=NOW - timedelta(days=3), amount="300,000 USDT")
    _reply(db, case, order, TO_BINANCE, NOW - timedelta(hours=2))
    plan = _plan(db, case)
    m = plan.find(f"dest:ethereum:{EVM_BINANCE}")
    brief = next(a for a in m.actions if a["label"].startswith("Brief LE"))
    procura = next(a for a in desk.case_authorities(db, case) if a.is_le and "Procura" in a.name)
    assert f"/authorities/{procura.key}?template=le_cover" in brief["href"]  # reachable, issues to the VASPs
    assert brief["primary"] and m.href == brief["href"]
    done = next(d for d in plan.done if d["key"] == f"o{order.id}")  # minor: the done line points at the lead
    assert "the funds moved to 0x7e7e…7e7e (see the lead)" in done["text"]


def test_a_new_deposit_at_an_exchange_with_an_open_request_gets_a_freeze_request(db, case):
    mexc = _ent(db, "MEXC")
    om = _sent(db, case, mexc, "0x" + "c2" * 20, at=NOW - timedelta(days=2), amount="10,000 USDT")
    okx = _ent(db, "OKX")
    oo = _sent(db, case, okx, "0x" + "d4" * 20, at=NOW - timedelta(days=2), amount="200,000 USDT")
    new = "0x" + "5a" * 20
    _reply(db, case, oo, f"The funds (200,000 USDT) were withdrawn on 20 Oct to {new}, which is a deposit address at "
                         "MEXC. The account has no remaining balance.", NOW - timedelta(hours=1))
    m = _plan(db, case).find(f"dest:ethereum:{new}")
    act = next(a for a in m.actions if a["label"].startswith(f"Write to MEXC on request o{om.id}"))
    assert "template=info_request" in act["href"] and f"freeze=ethereum:{new}" in act["href"]
    assert "48 hours from the submission" in m.text and "urgent freeze request" in m.text
    latest = services.latest_run(db, case)
    a = desk.get_authority(db, case, f"entity-{mexc.id}", run=latest)
    subject, body, _ = desk.build_letter(db, case, a, "info_request", run=desk.letter_run(db, case, a, latest),
                                         ref=f"o{om.id}", freeze=f"ethereum:{new}")
    assert subject.startswith(f"Urgent: new deposit {new} – freeze – further to our letter of")
    assert "**new deposit**" in body and "freeze the account it credits" in body
    idents = body.split("On-chain identifiers", 1)[1]
    assert idents.index(new) < idents.index("Information requested") and "within 7 days" not in body


# --------------------------------------------------------------------------- r4 major: an own-platform destination
@pytest.mark.parametrize("name", ["Bybit", "OKX", "Kraken"])
def test_an_internal_transfer_on_an_empty_account_is_a_freeze_ask_never_a_closed_request(db, case, name):
    ent = _ent(db, name)
    order = _sent(db, case, ent, "0x" + "b2" * 20, at=NOW - timedelta(days=3), amount="60,000 USDT")
    dest = "0x" + "7e" * 20
    _reply(db, case, order, f"The user moved the funds by internal transfer to {dest}, a deposit address belonging to "
                            "UID 48213977. The reported account now has a zero balance.", NOW - timedelta(hours=2))
    row = _row(db, case, f"o{order.id}")
    assert [d["where"] for d in pathmod.destinations(row)] == ["own"]
    plan = _plan(db, case)
    m = plan.find(f"o{order.id}")
    assert m is not None and m.kind == "answer" and m.actionable
    assert "template=info_response" in m.href and "still at " + name in m.text and "48213977" in m.text
    assert "withdrawn to the wallet" not in m.text and "close the request" not in m.text
    assert not any(d["key"] == f"o{order.id}" for d in plan.done)


# --------------------------------------------------------------------------- r4 majors: the hold's clocks
def test_mexcs_le_side_clock_passing_lapses_the_hold(db, case):
    mexc = _ent(db, "MEXC")
    o = _sent(db, case, mexc, "0x" + "c2" * 20, at=NOW - timedelta(hours=8), amount="250,000 USDT")
    r = _reply(db, case, o, MEXC_TEMP, NOW - timedelta(hours=4))
    key = f"o{o.id}"
    bs.confirm(db, _access(case), key, status=R.HOLD_PLACED, reply_id=r.id, amount="250000", asset="USDT")
    latest = services.latest_run(db, case)
    a = desk.get_authority(db, case, f"entity-{mexc.id}", run=latest)
    ans = desk.generate_letter(db, case, a, "info_response", actor=None, ref=key, run=desk.letter_run(db, case, a, latest))
    desk.mark_sent(db, case, ans, actor=None, sent_at=NOW - timedelta(hours=1))
    db.expire_all()
    early = rp.build(db, case, now=NOW + timedelta(hours=30))
    assert any(s["authority"] == "MEXC" for s in early.secured) and early.find(key).clock is not None
    db.expire_all()
    plan = rp.build(db, case, now=NOW + timedelta(hours=50))
    m = plan.find(key)
    assert m.kind == "chase" and "LE deadline passed" in m.title and "extend" in m.title
    assert m.clock is not None and m.clock["source"] == "lapsed" and m.urgency > 2
    assert not any(s["authority"] == "MEXC" for s in plan.secured)
    assert "no longer counts as secured" in m.text and "lapsed?" in m.basis


def test_kucoins_hold_runs_on_one_expiry_the_one_its_reply_states(db, case):
    o = next(o for o in case.stop_orders if o.entity and o.entity.name == "KuCoin")
    r = _reply(db, case, o, KUCOIN_HOLD, NOW - timedelta(hours=3))
    bs.confirm(db, _access(case), f"o{o.id}", status=R.HOLD_PLACED, reply_id=r.id, amount="1000", asset="USDT")
    stated = r.occurred_at.replace(tzinfo=UTC) if r.occurred_at.tzinfo is None else r.occurred_at
    for days in (6.5, 8):
        now = NOW + timedelta(days=days)
        db.expire_all()
        m = rp.build(db, case, now=now).find(f"o{o.id}")
        assert m.clock["source"] == "reply" and m.clock["due_at"].date() == (stated + timedelta(days=30)).date()
        assert not any("hold lasts until" in w for w in m.urgency_why) and "hold lasts until" not in m.text.lower()
        row = _row(db, case, f"o{o.id}", now=now)
        assert row.path.lapsed is None and not [c for c in row.clocks if not c.get("met")
                                                and c["what"] in pathmod.HOLD_WHAT and c["source"] == "playbook"]
        a = next(x for x in desk.case_authorities(db, case) if x.is_le and "Procura" in x.name)
        _s, body, _r = desk.build_letter(db, case, a, "le_brief", ref=f"o{o.id}", now=now)
        assert "Hold lasts until" not in body.split("### 4. Clock", 1)[1][:600]
    # once the stated expiry passes, the lapse reads the stated date (never the playbook's 7 days)
    db.expire_all()
    m = rp.build(db, case, now=NOW + timedelta(days=31)).find(f"o{o.id}")
    assert m.kind == "chase" and f"lapsed {(stated + timedelta(days=30)):%d %b}" in m.title


# --------------------------------------------------------------------------- 3. folder-imported evidence
def _imported(db, case, folder, title, rule, ext="pdf", sha="ee"):
    item = EvidenceItem(case=case, folder=folder, title=title, source_type=ext, sha256=sha * 32,
                        meta={"ingest": "import:reference", "mapping_rule": rule, "reference_kind": "file",
                              "import_rel_path": f"{folder.value}/{title}.{ext}"})
    db.add(item)
    db.commit()
    return item


def test_imported_items_match_requirements_by_folder_and_title_for_a_person_to_check(db, case):
    F = EvidenceFolder
    police = _imported(db, case, F.LAW_ENFORCEMENT, "Denuncia-querela 14.10.2026", "law-enforcement keywords",
                       sha="e1")
    ic3 = _imported(db, case, F.LAW_ENFORCEMENT, "IC3 complaint confirmation", "law-enforcement keywords", sha="e2")
    trace = _imported(db, case, F.INVESTIGATOR_REPORTS, "Analyst report", "intelligence report", sha="e3")
    poa = _imported(db, case, F.LEGAL, "Investigator power of attorney", "power of attorney", sha="e4")
    bank = _imported(db, case, F.FINANCIAL, "Bank statement September", "'*Statement*'", sha="e5")
    dd = _imported(db, case, F.FINANCIAL, "Exchange Due Diligence", "'*Due Diligence*'", sha="e6")
    chat = _imported(db, case, F.DIGITAL_ARTIFACTS, "Chat with the scammer", "chat", ext="png", sha="e7")
    _imported(db, case, F.DIGITAL_ARTIFACTS, "IMG_0001", "default", ext="png", sha="e8")
    _imported(db, case, F.INVESTIGATOR_REPORTS, "PI intake form", "PI intake form", sha="e9")
    db.refresh(case)
    h = er.holdings(db, case, wallets=[])
    got = {e["key"]: e for e in er.check(h, ["police_report", "ic3_ref", "trace_report_run", "poa", "loa",
                                             "wire_details", "ownership_proof", "comms_export"])}
    # the demo case has complaint references on file (an explicit "have"): its reports match by folder / title too
    assert {"police_report", "complaint_ref"} <= er.derived_keys(police) and "ic3_ref" not in er.derived_keys(police)
    assert {"police_report", "complaint_ref", "ic3_ref"} <= er.derived_keys(ic3)
    assert got["police_report"]["state"] == "have" and got["ic3_ref"]["state"] == "have"
    assert {"poa", "loa"} <= er.derived_keys(poa)  # the demo's sender profile holds the authority documents
    assert "comms_export" in er.derived_keys(chat)  # the demo also holds a chat export of that type
    want = {"trace_report_run": trace, "wire_details": bank, "ownership_proof": bank}
    for key, item in want.items():
        e = got[key]
        assert e["state"] == "have" and e["matched"] == "folder / title", key
        assert item.id in e["ids"] and e["state_label"] == er.MATCHED_LABEL and "check" in e["source"], key
    assert dd.id in got["ownership_proof"]["ids"]
    img = next(i for i in case.evidence_items if i.title == "IMG_0001")
    # any Digital artifacts item counts as a chat / e-mail export by its folder (a match to check), as on main
    assert er.derived_keys(img) == {"comms_export"} and er.derived_keys(dd) == {"ownership_proof"}
    assert "trace_report_run" not in er.derived_keys(next(i for i in case.evidence_items if i.title == "PI intake form"))
    # an explicit type still wins (no "check")
    db.add(EvidenceItem(case=case, folder=F.LAW_ENFORCEMENT, title="Receipt", source_type="police_report",
                        sha256="ea" * 32))
    db.commit()
    db.refresh(case)
    e = er.check(er.holdings(db, case, wallets=[]), ["police_report"])[0]
    assert e["state"] == "have" and e["matched"] is None and e["state_label"] == "on file"


def test_a_case_admin_uses_an_item_for_a_requirement_from_the_checklist(db, case, client_for):
    from conftest import csrf_token

    from app.db.models import AuditEvent

    item = _imported(db, case, EvidenceFolder.LEGAL, "Scan 0042", "dir 'Legal Docs'", sha="eb")
    url = f"/cases/{case.id}/recovery-plan"
    inv = client_for("investigator", case=case, email="inv-r6-use@tests.example")
    r = inv.post(f"{url}/use-evidence", data={"csrf_token": csrf_token(inv, url), "key": "loa",
                                              "evidence_id": str(item.id)}, follow_redirects=False)
    assert r.status_code == 403
    adm = client_for("admin", case=case, email="adm-r6-use@tests.example")
    assert f'action="/cases/{case.id}/recovery-plan/use-evidence"' in adm.get(url).text
    r = adm.post(f"{url}/use-evidence", data={"csrf_token": csrf_token(adm, url), "key": "loa",
                                              "evidence_id": f"#{item.id}", "move": "entity-5"},
                 follow_redirects=False)
    assert r.status_code == 303 and "done=used" in r.headers["location"]
    db.expire_all()
    db.refresh(item)
    assert "loa" in item.tags
    ev = db.query(AuditEvent).filter(AuditEvent.case_id == case.id).order_by(AuditEvent.id.desc()).first()
    assert ev.detail.get("op") == "use_for_requirement" and ev.detail.get("requirement") == "loa"
    e = er.check(er.holdings(db, case, wallets=[]), ["loa"])[0]
    assert e["state"] == "have" and e["matched"] is None and item.id in e["ids"]
    for bad in ({"key": "not_a_key", "evidence_id": str(item.id)}, {"key": "loa", "evidence_id": "999999"}):
        assert adm.post(f"{url}/use-evidence", data={"csrf_token": csrf_token(adm, url), **bad}).status_code == 400


# --------------------------------------------------------------------------- 4. the evidence of the leading route
def test_circles_us_case_agent_move_lists_the_us_requests_evidence_not_the_cross_border_order(db, case):
    from test_review_round3 import CIRCLE_COURT

    circle = _ent(db, "Circle (USDC issuer)")
    addr = _cand(db, case, "Circle (USDC issuer)").identifiers[0].address
    order = _sent(db, case, circle, addr, at=NOW - timedelta(days=1), amount="399,247.92 USDC")
    _reply(db, case, order, CIRCLE_COURT, NOW - timedelta(hours=18))
    m = _plan(db, case).find(f"o{order.id}")
    assert m.title.startswith("Get a US case agent")
    keys = {e["key"] for e in m.evidence}
    assert "domestic_order" not in keys and keys
    from app.domain import directory

    urgent = directory.load_catalogue().by_key["circle"].playbook.path(m.route["urgent"]["path"])
    assert keys >= set(urgent.evidence) - {"domestic_order"}


# --------------------------------------------------------------------------- 5. a drafted follow-up after a sent request
def test_a_drafted_freeze_request_after_a_sent_preservation_one_follows_the_board_row(db, case):
    from app.db.models import StopOrder, StopOrderStatus

    bybit = _ent(db, "Bybit")
    sent = _sent(db, case, bybit, "0x" + "b4" * 20, at=NOW - timedelta(days=2), amount="60,000 USDT",
                 due=NOW + timedelta(days=5))
    sent.kind = "preservation"
    db.add(StopOrder(case=case, entity=bybit, kind="freeze", status=StopOrderStatus.DRAFT, subject="Freeze request",
                     body_markdown="Please freeze.", identifiers={"chain": "ethereum", "addresses": [
                         {"chain": "ethereum", "address": "0x" + "b4" * 20}]}))
    db.commit()
    m = next(x for x in _plan(db, case).moves if x.authority is not None and x.authority.name == "Bybit")
    prev = _row(db, case, f"o{sent.id}")  # the sent request's own reply clock (Bybit's playbook shortens it)
    assert m.clock is not None and m.clock["due_at"] == prev.due_at
    assert not m.untouched and "nobody has asked" not in " ".join(m.urgency_why)
    # round 13, one source of truth: the move's step is the freeze board's row (freeze_board.provider_target). A sent
    # stop order is a freeze ask there, so the drafted one repeats it (flagged: a case admin discards it); Bybit acts
    # on LE process only for us, so the LE route leads. No action of the move sends the flagged draft
    draft = next(o for o in case.stop_orders if o.entity_id == bybit.id and o.status == StopOrderStatus.DRAFT)
    assert m.target is not None and [d["order_id"] for d in m.target.duplicates] == [draft.id]
    assert m.kind in ("le", "cross_border") and m.href == m.target.step.href
    assert not any(f"/stop-orders/{draft.id}" in (x.get("href") or "") for x in m.actions), m.actions


# --------------------------------------------------------------------------- minors
GATE_GENERIC = ("Please be advised that this channel is for law enforcement only and is not intended for private "
                "parties. If you are a victim, please report to your local police, who can contact us.")


def test_a_generic_le_only_refusal_reads_as_le_process_required(db, case):
    assert R.classify(GATE_GENERIC).status == R.LE_PROCESS_REQUIRED
    gate = _ent(db, "Gate")
    order = _sent(db, case, gate, "0x" + "a7" * 20, at=NOW - timedelta(days=1))
    _reply(db, case, order, GATE_GENERIC, NOW - timedelta(hours=2))
    assert _row(db, case, f"o{order.id}").status == R.LE_PROCESS_REQUIRED
    m = _plan(db, case).find(f"o{order.id}")
    assert m.kind in ("le", "cross_border") and not m.title.startswith("Read ")


def test_a_playbook_answer_clock_is_their_process_not_their_deadline(db, case):
    mexc = _ent(db, "MEXC")
    o = _sent(db, case, mexc, "0x" + "c3" * 20, at=NOW - timedelta(days=1), amount="25,000 USDT")
    _reply(db, case, o, MEXC_TEMP, NOW - timedelta(hours=2))
    m = _plan(db, case).find(f"o{o.id}")
    assert m.kind == "answer" and m.clock["source"] == "playbook" and m.title.endswith("UTC (their process)")


@pytest.mark.parametrize("url", ["https://app.kodexglobal.com//binance/signup",
                                 "https://app.kodexglobal.com/%62inance/signup",
                                 "https://app.kodexglobal.com/./binance/signup"])
def test_an_encoded_or_dotted_portal_path_is_still_the_le_only_portal(url):
    from test_review_round3 import _parsed, _shipped

    from app.domain import directory
    from app.domain import playbook as pbm

    pb = directory.load_catalogue().by_key["binance"].playbook
    assert pb.domain_class(url) == "vendor_portal_le_only" and pbm._portal_value(pb.domains, url) is not None
    raw = _shipped("binance")
    raw["channels"][0]["value"], raw["channels"][0]["who"] = url, "any"
    with pytest.raises(directory.CatalogueError):
        _parsed(raw)


def test_the_answer_letter_answers_the_request_its_chosen_letter_belongs_to(db, case):
    from app.db.models import Correspondence, CorrespondenceDirection, CorrespondenceKind

    bybit = _ent(db, "Bybit")
    old = _sent(db, case, bybit, "0x" + "b5" * 20, at=NOW - timedelta(days=6), amount="10,000 USDT")
    new = _sent(db, case, bybit, "0x" + "b6" * 20, at=NOW - timedelta(days=2), amount="20,000 USDT")
    logged = Correspondence(case=case, entity=bybit, stop_order=old, direction=CorrespondenceDirection.OUT,
                            kind=CorrespondenceKind.STOP_ORDER, status=desk.CorrespondenceStatus.SENT,
                            subject="Freeze request", body_markdown="Please block.", occurred_at=old.sent_at)
    db.add(logged)
    db.commit()
    _reply(db, case, old, "Thank you, ticket BY-100 has been created for your request.", NOW - timedelta(days=5))
    _reply(db, case, new, "Thank you, ticket BY-200 has been created for your request.", NOW - timedelta(hours=3))
    a = desk.get_authority(db, case, f"entity-{bybit.id}")
    _s, body, refs = desk.build_letter(db, case, a, "info_response", ref=f"c{logged.id}")
    assert refs["references"] == f"o{old.id}" and "0x" + "b5" * 20 in body and "0x" + "b6" * 20 not in body
    with pytest.raises(desk.DeskError):
        desk.build_letter(db, case, a, "info_response", ref="c999999")
