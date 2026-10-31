"""Verify round 8 (the Recovery plan, wallet owners, evidence intel): the answer letter names the request whose reply
names the own-platform destination, a service float never inflates a move, owner moves never count the issuer's
upper bound twice, /wallet's recommendation follows the owner, a police report that describes a chat, a transfer
receipt's From / To, a 32-character IC3 id, exchange ledgers, instant-swap payout wallets, a person's owner name kept
from read-only members, a confirmed ID document never sent to the AI, a referenced original's AI detail not kept.
The demo case plus synthetic tags, readings, documents and replies (every address and number is made up)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace as N
from urllib.parse import parse_qs, urlsplit

import pytest
from test_evidence_intel import make_pdf
from test_review_round3 import _ent as _entity
from test_review_round3 import _reply, _row, _sent
from test_wallet_owners import Explorers, _Access, _addr, _consent, _offline, _plan, _tag, no_ai  # noqa: F401 - fixtures

from app import services
from app.ai import skills
from app.attribution import explorer
from app.attribution import service as attr
from app.blocks import path as pathmod
from app.blocks import recovery as rp
from app.db.models import CaseRole, EvidenceStorage, FreezeCheck
from app.domain import correspondence as desk
from app.domain import evidence as ev
from app.evidence_intel import findings, rules
from app.evidence_intel import service as intel
from app.freeze import service as fz

NOW = datetime.now(tz=UTC)
USDT_ETH = "0xdac17f958d2ee523a2206206994597c13d831ec7"


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


@pytest.fixture
def vault(tmp_path, monkeypatch):
    p = tmp_path / "vault"
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(p))
    return p


def _usdt(db, case, address, balance, at=None):
    db.add(FreezeCheck(case_id=case.id, chain="ethereum", address=address, issuer="Tether", token_symbol="USDT",
                       token_contract=USDT_ETH, status="ok", blacklisted=False, balance=Decimal(balance),
                       checked_at=at or NOW + timedelta(minutes=5), block_number=1, raw_sha256="ab" * 32,
                       meta={"balance_raw": str(int(Decimal(balance) * 10**6))}))
    db.commit()


def _access(db, case, role):
    from test_freeze_checks import access_for

    return access_for(db, case, role)


# --------------------------------------------------------------------------- majors
@pytest.mark.parametrize("text", [
    ("Thank you, we are reviewing it. Our records show the user moved the funds by internal transfer to {dest}, a "
     "deposit address belonging to UID 48213977."),
    ("The user moved the funds by internal transfer to {dest}, a deposit address belonging to UID 48213977. The "
     "reported account now has a zero balance."),
])
def test_the_answer_letter_names_the_request_whose_reply_names_the_own_platform_destination(db, case, text):
    ent = _entity(db, "Bybit")
    a_ = _sent(db, case, ent, "0x" + "b2" * 20, at=NOW - timedelta(days=3), amount="60,000 USDT")
    _reply(db, case, a_, text.format(dest="0x" + "7e" * 20), NOW - timedelta(hours=5))
    b_ = _sent(db, case, ent, "0x" + "b3" * 20, at=NOW - timedelta(hours=2), amount="10,000 USDT")
    assert any(d["where"] == "own" for d in pathmod.destinations(_row(db, case, f"o{a_.id}")))
    plan = _plan(db, case)
    m = next(m for m in plan.moves + plan.waiting if m.authority is not None and m.authority.name == "Bybit")
    hrefs = [x["href"] for x in m.actions if "template=info_response" in (x.get("href") or "")]
    hrefs += [m.href] if "template=info_response" in (m.href or "") else []
    assert hrefs
    run = services.latest_run(db, case)
    auth = desk.get_authority(db, case, f"entity-{ent.id}", run=run)
    for h in hrefs:
        ref = parse_qs(urlsplit(h).query)["ref"][0]
        assert ref == f"o{a_.id}" != f"o{b_.id}"
        desk.build_letter(db, case, auth, "info_response", run=desk.letter_run(db, case, auth, run), ref=ref)


def test_a_service_hot_wallet_float_never_becomes_the_moves_value(db, case):
    addr = "0x" + "ab12" * 10
    fz.add_watch(db, case, None, chain="ethereum", address=addr)
    _usdt(db, case, addr, "25000000")
    attr.mark(db, case, None, chain="ethereum", address=addr, owner="KuCoin", kind="exchange_hot_wallet")
    db.commit()
    plan = _plan(db, case)
    m = plan.find(f"owner:ethereum:{addr}")
    assert m is not None and not m.value and "the case's share unknown" in m.basis
    assert "25,000,000" not in rp.money(m.value)
    # traced in: the case's share only
    att = plan.owners[("ethereum", addr)]
    att.wallet.in_trace, att.wallet.taint_usd = True, 4_000.0
    assert att.share_usd == 4_000.0 and "the case's share" in att.share_basis


def test_owner_moves_downstream_of_an_issuer_wallet_are_not_counted_twice(db, case, ex):
    before = _plan(db, case)
    circle = next(m for m in before.moves + before.waiting if m.key.startswith("entity-") and "Circle" in m.title)
    _consent(db, case)
    h3, h2 = _addr(db, case, "Hub outflow #3"), _addr(db, case, "Hub outflow #2")
    ex.tags[h3[1]], ex.info[h3[1]] = [_tag("OKX: Deposit", entity="OKX")], {}
    ex.tags[h2[1]], ex.info[h2[1]] = [_tag("Demo Exchange: Deposit", entity="Demo Exchange")], {}
    attr.run_lookups(db, case, force=True)
    plan = _plan(db, case)
    owned = [m for m in plan.moves if m.key.startswith("owner:") and m.counts]
    assert len(owned) == 2
    c2 = plan.find(circle.key)
    # the Circle wallets forwarded everything on (verify round 9): no upper bound left there, so the deposits
    # downstream are counted once, at their owners' moves
    assert circle.value == 0 and c2.value == 0 and "moved on" in c2.basis
    assert plan.totals["in_play_sum_usd"] == pytest.approx(before.totals["in_play_sum_usd"]
                                                           + sum(m.value for m in owned), abs=1)
    loss = float(case.loss_usd)
    assert plan.totals["in_play_usd"] <= loss + 0.01
    if plan.totals["in_play_capped"]:
        assert any("capped at the loss" in n for n in plan.notes)


def test_the_wallet_skill_recommends_the_owners_ask_not_self_custody(db, case, ex):
    _consent(db, case)
    h3, h2 = _addr(db, case, "Hub outflow #3"), _addr(db, case, "Hub outflow #2")
    ex.tags[h3[1]], ex.info[h3[1]] = [_tag("OKX: Deposit", entity="OKX")], {}
    ex.tags[h2[1]], ex.info[h2[1]] = [_tag("Tornado.Cash: Router")], {}
    attr.run_lookups(db, case, force=True)
    acc = _access(db, case, CaseRole.INVESTIGATOR)
    md = skills.run_skill(db, acc, "wallet", h3[1]).markdown
    rec = md.split("**Recommendation**", 1)[1]
    assert "Ask OKX to freeze the account credited by deposit address" in rec and "Self-custody and dormant" not in rec
    rec = skills.run_skill(db, acc, "wallet", h2[1]).markdown.split("**Recommendation**", 1)[1]
    assert "no account to freeze" in rec and "Self-custody and dormant" not in rec
    uni = _addr(db, case, "Uniswap Universal")
    rec = skills.run_skill(db, acc, "wallet", uni[1]).markdown.split("**Recommendation**", 1)[1]
    assert "non-custodial router" in rec and "request the order records" not in rec


POLICE = ["CITY OF DEMOTOWN POLICE DEPARTMENT", "INCIDENT REPORT", "Report Number: 26-012345",
          "Date Reported: 10/14/2026", "Offense: Theft by Deception / Fraud",
          "Narrative: The victim stated that in August 2026 she was contacted on WhatsApp by a person claiming",
          "to be an investment advisor. The suspect moved the conversation to Telegram and, over several messages,",
          "directed her to send USDT to a wallet.", "Victim provided screenshots of the chat."]


def test_a_police_report_that_describes_a_chat_is_a_police_report(client_for, db, tmp_path, vault):
    r = rules.classify("\n".join(POLICE), name="Police_Report_26-012345.pdf", kind="pdf")
    assert r["type"] == "police_report" and r["confidence"] == "H"
    assert "a police agency and its report number" in r["reasons"]
    assert rules.classify("\n".join(POLICE), name="scan.pdf", kind="pdf")["type"] == "police_report"
    assert rules.classify("", name="Police_Report_26-012345.pdf")["type"] == "police_report"
    assert rules.classify("", name="Bank_Statement_Aug.pdf")["type"] == "bank_statement"
    # a real chat export still reads as one
    chat = "\n".join(f"[14/08/2026, 10:{d:02d}:00] Demo Contact: message {d} on WhatsApp" for d in range(10, 20))
    assert rules.classify(chat, name="chat.txt", kind="text")["type"] == "chat_export"
    from test_block_status import fresh_case
    from test_evidence_intel import _new_item, _upload

    c = fresh_case(db, tmp_path)
    data = make_pdf([POLICE])
    adm = client_for("admin", case=c)
    r = _upload(adm, c, "Police_Report_26-012345.pdf", data, "application/pdf")
    assert r.status_code == 303 and "Chat export" not in r.headers["location"]
    it = _new_item(db, c, data)
    assert intel.intel(it)["rules"]["type"] == "police_report"


def test_a_transfer_receipts_from_and_to_are_hints_and_a_person_picks_the_roles(client_for, db, tmp_path, vault):
    # design decision (r5): a receipt's From / To never assign a role (an incoming transfer's sender is the scammer):
    # they are shown as a hint, the person picks the role, only then are watch / seed offered
    a, b = "0x" + "a1" * 20, "0x" + "b2" * 20
    t = f"Transaction Details\nFrom: {a}\nTo: {b}\n"
    assert findings.address_hint(t, a) == "near “From:”" and findings.address_hint(t, b) == "near “To:”"
    assert findings.address_hint(f"Hop 4\n{a}\n", a) is None
    from test_block_status import fresh_case
    from test_evidence_intel import _new_item, _upload

    c = fresh_case(db, tmp_path)
    for s in list(c.seeds):
        db.delete(s)
    db.commit()
    adm = client_for("admin", case=c)
    data = make_pdf([["Transaction Details", "Status: Success", f"From: {a}", f"To: {b}", "Value: 40,000 USDT",
                      "Transaction Hash: 0x" + "c3" * 32]])
    _upload(adm, c, "transfer receipt.pdf", data, "application/pdf")
    it = _new_item(db, c, data)
    v = intel.view(db, _access(db, c, CaseRole.ADMIN), it)
    by = {i["value"]: i for i in v["ids"]}
    for w in (a, b):
        assert by[w]["role"] is None and by[w]["seed_role"] is None and not by[w]["watch"], w
    intel.pick_role(db, _access(db, c, CaseRole.ADMIN), it, a, "victim")
    intel.pick_role(db, _access(db, c, CaseRole.ADMIN), it, b, "perpetrator")
    db.commit()
    v = intel.view(db, _access(db, c, CaseRole.ADMIN), it)
    by = {i["value"]: i for i in v["ids"]}
    assert by[a]["seed_role"] == "victim_wallet" and not by[a].get("watch")
    assert by[b]["seed_role"] == "perpetrator_wallet" and by[b]["watch"]


def test_a_32_character_ic3_complaint_id_is_read():
    f = findings.find("Internet Crime Complaint Center\nComplaint ID: 6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d\n")
    assert [r["reference"] for r in f["refs"]] == ["6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"]


def test_exchange_ledgers_and_a_telegram_export_are_recognised():
    kraken = ('"txid","refid","time","type","subtype","aclass","asset","amount","fee","balance"\n'
              '"L1","R1","2026-08-15 10:00:00","deposit","","currency","ZUSD","40000","0","40000"\n'
              '"L3","R3","2026-08-15 12:00:00","withdrawal","","currency","USDT","-40000","2","0"\n')
    assert rules.classify(kraken, name="ledgers.csv", kind="text")["type"] == "exchange_statement"
    tg = "Exported Data\nDemo Contact\n14.08.2026 10:00:00\nHello\n14.08.2026 10:01:00\nSend\n14.08.2026 10:02:00\nok"
    r = rules.classify(tg, name="messages.html", kind="html")
    assert r["type"] == "chat_export" and r["confidence"] in ("H", "M")


def test_an_instant_swap_payout_wallet_is_a_swap_and_a_deposit_holds_a_customers_funds(db, case):
    assert explorer.classify([{"name": "FixedFloat: Payout", "type": "name"}])[1] == "swap_bridge"
    assert explorer.classify([{"name": "Demo Exchange: Hot Wallet", "type": "name"}])[1] == "exchange_hot_wallet"
    dep = _addr(db, case, "KuCoin deposit")[1]
    _usdt(db, case, dep, "5000")
    t = next(m for m in _plan(db, case).moves + _plan(db, case).waiting if m.key.startswith("entity-")
             and "Tether" in m.title)
    assert "credited to the depositor's account" in t.basis and "5,000, its float" not in t.basis


def test_an_owner_move_without_a_letter_says_to_write_outside_aegis(db, case, ex):
    _consent(db, case)
    h3 = _addr(db, case, "Hub outflow #3")
    ex.tags[h3[1]], ex.info[h3[1]] = [_tag("OKX: Deposit", entity="OKX")], {}
    attr.run_lookups(db, case, force=True)
    m = _plan(db, case).find(f"owner:{h3[0]}:{h3[1]}")
    # no counterparty yet and no form adds one by name: never a button promising to add it
    assert m.href is None and not any("as a counterparty" in x["label"] for x in m.actions)
    assert "written outside Aegis" in m.effort_why and "Aegis cannot add one by name" in m.text


def test_an_order_on_file_lifts_the_le_gate_of_the_owner_ask():
    w = attr.Wallet(chain="ethereum", address="0x" + "e1" * 20)
    att = attr.Attribution(wallet=w, owner="Demo Exchange", kind="exchange_deposit", org_key="demo")
    pb = N(gate=lambda req, held, name: N(reason=None if "court_order" in held else "LE requests only"))
    a = N(key="entity-9", name="Demo Exchange", entity=None, stop_orders=[], correspondence=[])
    kw = {"by_entity": {}, "by_org": {"demo": a}, "by_name": {}, "issuers": {}, "requester": "pi",
          "le_pick": lambda pb, k: ("/le", ""), "orgs": {"demo": N(playbook=pb)}}
    assert attr.ask_for(1, att, **kw, held=lambda a, o: frozenset())["gated"]
    ask = attr.ask_for(1, att, **kw, held=lambda a, o: frozenset({"court_order"}))
    assert not ask["gated"] and "freeze=ethereum:" in ask["href"]


def test_a_persons_owner_name_is_kept_from_read_only_members(db, case, client_for):
    k = _addr(db, case, "Hub outflow #3")
    attr.mark(db, case, None, chain=k[0], address=k[1], owner="Quentin Privatename", kind="unhosted")
    db.commit()
    att = attr.attribute(db, case)[k]
    assert "Quentin Privatename" in str(att.as_dict(True))
    masked = str(att.as_dict(False))
    assert "Quentin Privatename" not in masked and attr.PRIVATE_LABEL in masked
    ro = client_for("read_only", case=case)
    api = ro.get(f"/api/cases/{case.id}/owners")
    assert api.status_code == 200 and "Quentin Privatename" not in api.text
    assert "Quentin Privatename" not in ro.get(f"/cases/{case.id}/recovery-plan").text
    assert "Quentin Privatename" not in ro.get(f"/api/cases/{case.id}/graph").text
    assert "Quentin Privatename" in client_for("admin", case=case).get(f"/api/cases/{case.id}/owners").text


def test_a_drop_before_the_latest_trace_is_not_funds_left(db, case):
    addr = "0x" + "ab34" * 10
    fz.add_watch(db, case, None, chain="ethereum", address=addr)
    _usdt(db, case, addr, "9000", at=NOW - timedelta(days=2))
    _usdt(db, case, addr, "0", at=NOW - timedelta(days=1))
    w = next(w for w in fz.wallet_rows(db, case) if w["address"] == addr)
    assert w["funds_left"] == [] and any(c.get("left_before_trace") for c in w["checks"])
    assert not any(x["address"] == addr for x in fz.case_status(db, case)["moved"])


def test_the_readings_read_back_are_bounded(db, case):
    addr = "0x" + "ab56" * 10
    fz.add_watch(db, case, None, chain="ethereum", address=addr)
    for i in range(fz.HISTORY_ROWS + 10):
        _usdt(db, case, addr, "100", at=NOW - timedelta(hours=100 - i))
    ids = fz._history_ids(db, case)
    rows = [r for r in db.query(FreezeCheck).filter(FreezeCheck.id.in_(ids)) if r.address == addr]
    assert len(rows) == fz.HISTORY_ROWS
    assert fz.history(db, case)[("ethereum", addr, USDT_ETH)].ok.checked_at == max(r.checked_at for r in rows)


def test_a_type_a_person_confirmed_keeps_an_id_document_from_the_ai(db, tmp_path, monkeypatch):
    from test_block_status import fresh_case
    from test_evidence_intel import _enable

    from app.db.models import AIMode
    from app.evidence_intel import ai as eai

    monkeypatch.delenv("AEGIS_AI_DISABLED", raising=False)
    c = fresh_case(db, tmp_path)
    c.ai_mode = AIMode.REDACTED
    db.commit()
    _enable(db, c)
    item = ev.add_note(db, c, title="note", text="Holder: Demo Person\nNo. 12345 issued 2020")
    intel.read_item(db, item, use_ai=False)
    provider = object()
    monkeypatch.setattr(eai, "consent_matches", lambda st, p: True)
    assert eai.may_call(c, provider, item) == (True, None)
    intel.confirm(db, _access(db, c, CaseRole.INVESTIGATOR), item, "kyc_id_document")
    assert eai.may_call(c, provider, item) == (False, "personal_financial")


def test_a_referenced_originals_ai_detail_is_not_kept(db, tmp_path, monkeypatch, vault):
    from test_block_ai import Recorder
    from test_block_status import fresh_case
    from test_evidence_intel import DENUNCIA, _ai_answer, _enable, _use

    monkeypatch.delenv("AEGIS_AI_DISABLED", raising=False)
    c = fresh_case(db, tmp_path)
    _enable(db, c)
    _use(monkeypatch, Recorder(_ai_answer("police_report", "Verbale di ricezione di denuncia-querela")))
    src = tmp_path / "orig" / "denuncia.txt"
    src.parent.mkdir()
    src.write_text("\n".join(DENUNCIA), encoding="utf-8")
    item = ev.add_reference(db, c, str(src), folder="other", restrict_to_roots=False)
    assert item.storage == EvidenceStorage.REFERENCE
    iv = intel.read_item(db, item)
    assert iv["ai"]["detail"] is None
    assert not list(vault.rglob("*.ai.json"))
