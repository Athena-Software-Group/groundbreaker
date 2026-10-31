"""Verify round 10 (evidence intel, wallet owners, the Recovery plan): the words after a wallet never make the victim's
own wallet the scammer's; a chat naming the police stays a chat; a credited exchange deposit address stays a freeze
target after its sweep; traced money is counted once (a deposit address the trace followed on, an issuer wallet a
service holds, a swap service's payout); the ask names our letter, never its internal key; TLP-restricted watches
never go to the public explorers. The demo case plus synthetic tags, readings and documents (every address,
number and name is made up)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from test_evidence_intel import _access as _intel_access
from test_evidence_intel import _new_item, _upload, fcase, make_pdf, vault  # noqa: F401 - fixtures
from test_wallet_owners import (  # noqa: F401
    Explorers,
    _Access,
    _addr,
    _consent,
    _offline,
    _plan,
    _tag,
    no_ai,
)

from app import services
from app.attribution import service as attr
from app.blocks import recovery as rp
from app.db.models import CaseRole, FreezeCheck
from app.evidence_intel import rules
from app.evidence_intel import service as intel
from app.freeze import service as fz

NOW = datetime.now(tz=UTC)
KUCOIN_DEPOSIT = "0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2"
TRON_DEST = "TWdZZhGv7zqeRnmxWd65yQSE2YDZRteL77"  # the demo's USDT-TRON destination (SWFT order #1 payout)
USDT_ETH = "0xdac17f958d2ee523a2206206994597c13d831ec7"
USDT_TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
V = "0x" + "a1" * 20  # made-up addresses
W = "0x" + "22bb" * 10
D4 = "0xd4" + "5e" * 19  # a watched deposit address the trace never saw


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


def _read(db, case, chain, address, balance, minutes):
    """A good USDT reading `minutes` after now (after the trace; the clock at call time, not at import: in a long
    run the trace is made minutes after this module loads)."""
    tron = chain == "tron"
    db.add(FreezeCheck(case_id=case.id, chain=chain, address=address, issuer="Tether", token_symbol="USDT",
                       token_contract=USDT_TRON if tron else USDT_ETH, status="ok", blacklisted=False,
                       balance=Decimal(balance), checked_at=datetime.now(tz=UTC) + timedelta(minutes=minutes),
                       block_number=71_000_000 + minutes, raw_sha256="ab" * 32,
                       meta={"balance_raw": str(int(Decimal(balance) * 10**6))}))
    db.commit()


def _tether(plan):
    return next(m for m in plan.moves + plan.waiting if m.authority is not None and ":" not in m.key
                and m.authority.name.startswith("Tether"))


# --------------------------------------------------------------------------- evidence intel: wallet roles
def test_a_denuncia_never_offers_the_victims_own_wallet_as_the_perpetrator_seed(client_for, fcase, vault, db):  # noqa: F811
    for s in list(fcase.seeds):
        db.delete(s)
    db.commit()
    text = ["Comando Carabinieri di Demo", "Prot. n. 4417/2026",
            f"La persona offesa ha trasferito 12.500 USDT dal proprio wallet {V} al truffatore."]
    adm = client_for("admin", case=fcase)
    data = make_pdf([text])
    _upload(adm, fcase, "denuncia.pdf", data, "application/pdf")
    item = _new_item(db, fcase, data)
    v = intel.view(db, _intel_access(db, fcase, adm), item)
    p = next(i for i in v["ids"] if i["value"].lower() == V)
    # design decision (r5): no role from the text, nothing offered until a person picks one
    assert p["role"] is None and p.get("seed_role") is None and not p.get("watch")
    intel.pick_role(db, _intel_access(db, fcase, adm), item, p["value"], "victim")
    db.commit()
    p = next(i for i in intel.view(db, _intel_access(db, fcase, adm), item)["ids"] if i["value"].lower() == V)
    assert p.get("seed_role") == "victim_wallet" and not p.get("watch")  # never the victim's own wallet to watch


# --------------------------------------------------------------------------- evidence intel: chat vs police report
CHAT = ("Messages and calls are end-to-end encrypted.\n01/09/2026, 09:00 - Anna: my uncle works at the police "
        "department, report number: 12345\n" + "\n".join(f"01/09/2026, 10:0{i} - Anna: hi {i}" for i in range(8)))


def test_a_chat_naming_the_police_and_a_report_number_is_still_a_chat():
    r = rules.classify(CHAT, name="chat.txt", kind="text")
    # a chat reading with the note: `keys` are what confirming the type would count for; nothing applies before
    assert (r["type"], r["keys"], r["note"]) == ("chat_export", ["comms_export"], rules.CHAT_NOTE)
    # no export banner: the chat lines open the document, the agency sits inside a message
    bare = CHAT.split("\n", 1)[1]
    r = rules.classify(bare, name="chat.txt", kind="text")
    assert r["type"] == "chat_export" and "police_report" not in r["keys"] and "complaint_ref" not in r["keys"]
    # the committed readings: a WhatsApp export, a police report quoting a chat, a sheriff's offense report
    chat = "\n".join(f"[14/08/2026, 10:{d:02d}:00] Demo Contact: message {d} on WhatsApp" for d in range(10, 20))
    assert rules.classify(chat, name="chat.txt", kind="text")["type"] == "chat_export"
    police = ("CITY OF DEMOTOWN POLICE DEPARTMENT\nINCIDENT REPORT\nReport Number: 26-012345\nNarrative: the victim "
              "provided the chat:\n" + "\n".join(f"09/01/2026, 10:0{i} - Anna: hello {i}" for i in range(6)))
    # round 12: a police report quoting a chat holds a chat: the rules never read it as the report (a person confirms)
    r = rules.classify(police, name="report.pdf", kind="pdf")
    assert r["type"] == "chat_export" and r["note"] == rules.CHAT_NOTE and "police_report" not in r["keys"]
    r = rules.classify(police.split("\nNarrative")[0], name="report.pdf", kind="pdf")
    assert r["type"] == "police_report" and {"police_report", "complaint_ref"} <= set(r["keys"])
    sher = ("COUNTY SHERIFF'S OFFICE\nOffense Report\nCase Number: 2026-0045123\nNarrative:\n"
            + "\n".join(f"09/01/2026, 10:0{i} - Anna: hello {i}" for i in range(6)) + "\nDeputy J. Demo took the report.")
    assert rules.classify(sher, name="scan_0012.pdf", kind="pdf")["type"] == "chat_export"
    assert rules.classify(sher.split("\n09/01")[0], name="scan_0012.pdf", kind="pdf")["type"] == "police_report"
    # a weak police reading that is not the agency's own report: no "complaint on file"
    stmt = rules.classify("Statement of the victim. I met Anna on Telegram. She told me to send money to her wallet.",
                          name="Victim statement.docx", kind="docx")
    assert "police_report" not in stmt["keys"] and "complaint_ref" not in stmt["keys"]


def test_a_supplemental_narrative_and_a_form_cover_are_police_reports():
    # round 12: transcribed chat lines make it a document holding a chat (a person confirms the type); a report
    # number is still needed for the rules to count it as the police report
    sup = ("SPRINGFIELD POLICE DEPARTMENT\nSupplemental Narrative\nOfficer: J. Doe\nThe victim showed me her WhatsApp "
           "messages, transcribed below:\n" + "\n".join(f"[0{d}/08/2026, 10:0{d}] Anna: msg {d}" for d in range(1, 9)))
    r = rules.classify(sup, name="supplement.pdf")
    assert r["type"] == "chat_export" and r["note"] == rules.CHAT_NOTE and "police_report" not in r["keys"]
    r = rules.classify(sup.split("\nThe victim")[0].replace("Supplemental Narrative", "Supplemental Narrative\n"
                                                              "Report Number: 26-012345"), name="supplement.pdf")
    assert r["type"] == "police_report" and {"police_report", "complaint_ref"} <= set(r["keys"])
    form = ("Page 1 of 4\nForm PD-301\nRev. 2024\nCity of Springfield\nDepartment of Public Safety\nRecords Division\n"
            "Confidential\nFor official use only\nSection A\nSpringfield Police Department\nReport Number: 26-012345\n"
            "The victim provided these messages:\n"
            + "\n".join(f"[0{d}/08/2026, 10:0{d}] Anna: msg {d}" for d in range(1, 9)))
    r = rules.classify(form, name="report.pdf")
    assert r["type"] == "chat_export" and "police_report" not in r["keys"]
    r = rules.classify(form.split("\nThe victim")[0], name="report.pdf")  # the cover block alone: the agency on line 10
    assert r["type"] == "police_report" and "police_report" in r["keys"]


def test_a_bank_statement_listing_a_wire_proves_ownership():
    bank = ("Demo Bank\nAccount Statement\nStatement period 01/08/2026 - 31/08/2026\nOpening balance 50,000.00\n"
            "Outgoing wire transfer 40,000.00 to Demo Ltd\nClosing balance 10,000.00\nIBAN XX00 0000 0000 0000")
    r = rules.classify(bank, name="statement.pdf")
    assert r["type"] == "bank_statement" and {"ownership_proof", "wire_details"} <= set(r["keys"])
    # a wire confirmation is still one
    wire = "Wire Transfer Confirmation\nOrdering customer: Demo\nBeneficiary bank: Demo Bank\nAmount: 40,000.00 USD"
    assert rules.classify(wire, name="wire.pdf")["type"] == "wire_confirmation"


# --------------------------------------------------------------------------- deposit addresses: credited, once
def test_a_swept_deposit_address_stays_a_freeze_target(db, case):
    plain = _plan(db, case)
    k = ("tron", TRON_DEST)
    attr.mark(db, case, None, chain="tron", address=TRON_DEST, owner="Binance", kind="exchange_deposit")
    db.commit()
    _read(db, case, "tron", TRON_DEST, "1360", 5)
    held = _plan(db, case)
    m = held.find(f"owner:tron:{TRON_DEST}")
    assert m is not None and "Binance" in m.title and m.value == pytest.approx(1359.9) and m.counts
    tether = _tether(held)  # the issuer's move points at Binance; round 12: same funds, counted once in the totals
    assert tether.value == pytest.approx(1359.9) and "ask Binance" in tether.basis and "same funds as" in tether.basis
    _read(db, case, "tron", TRON_DEST, "0", 10)  # the exchange swept it: the account was credited
    swept = _plan(db, case)
    m = swept.find(f"owner:tron:{TRON_DEST}")
    assert m is not None and m.value == pytest.approx(1359.9) and m.counts and "swept: the account was credited" in m.basis
    # the account was credited what reached it: the traced 1,359.90, or the 1,360 read there before the sweep
    assert attr.attribute(db, case)[k].share_usd == pytest.approx(1359.9, abs=0.5)
    assert swept.find(f"left:tron:{TRON_DEST}") is None
    for t in ("in_play_sum_usd", "expected_usd"):
        assert held.totals[t] >= plain.totals[t] - 0.01, t
    assert swept.totals["in_play_sum_usd"] == pytest.approx(held.totals["in_play_sum_usd"])
    assert swept.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"])  # moved, not added


def test_a_watched_deposit_address_the_trace_never_saw_counts_once_and_survives_the_sweep(db, case, ex):
    fz.add_watch(db, case, None, chain="ethereum", address=D4)
    db.commit()
    plain = _plan(db, case)
    _consent(db, case)
    ex.tags[D4], ex.info[D4] = [_tag("Binance: Deposit", entity="Binance")], {}
    attr.run_lookups(db, case, only={("ethereum", D4)})
    _read(db, case, "ethereum", D4, "50000", 5)
    held = _plan(db, case)
    att = held.owners[("ethereum", D4)]
    assert (att.owner, att.kind) == ("Binance", "exchange_deposit")
    m = held.find(f"owner:ethereum:{D4}")
    assert m is not None and m.value == pytest.approx(50000) and m.counts
    assert held.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"] + 50000)
    _read(db, case, "ethereum", D4, "0", 10)
    swept = _plan(db, case)
    m = swept.find(f"owner:ethereum:{D4}")
    assert m is not None and m.value == pytest.approx(50000) and m.counts and "before the sweep" in m.basis
    assert swept.totals["in_play_sum_usd"] == pytest.approx(held.totals["in_play_sum_usd"])
    assert swept.find(f"left:ethereum:{D4}") is None


def test_the_cases_share_keeps_the_committed_readings(db, case):
    plan = _plan(db, case)
    kucoin = plan.owners[("ethereum", KUCOIN_DEPOSIT)]  # a typed deposit, no reading
    assert kucoin.kind == "exchange_deposit" and kucoin.share_usd == pytest.approx(144.94) == kucoin.wallet.money_usd
    assert "credited to the account behind it" in kucoin.share_basis and not kucoin.onward  # its sweep: KuCoin's own
    relay = plan.owners[_addr(db, case, "Perpetrator relay #2")]  # passed through: nothing held
    assert relay.share_usd == 0 == relay.wallet.money_usd
    # a deposit address reading more than the trace put in: its balance (one customer's account)
    _read(db, case, "tron", TRON_DEST, "5000", 5)
    attr.mark(db, case, None, chain="tron", address=TRON_DEST, owner="Binance", kind="exchange_deposit")
    db.commit()
    assert attr.attribute(db, case)[("tron", TRON_DEST)].share_usd == pytest.approx(5000)
    # a service float read on-chain: the case's share, never the whole balance
    attr.mark(db, case, None, chain="tron", address=TRON_DEST, owner="Binance", kind="exchange_hot_wallet")
    db.commit()
    assert attr.attribute(db, case)[("tron", TRON_DEST)].share_usd == pytest.approx(1359.9)


def test_a_swap_services_payout_counted_elsewhere_leaves_its_passed_through_value(db, case):
    plan = _plan(db, case)
    swft = next(m for m in plan.moves + plan.waiting if m.authority is not None and ":" not in m.key
                and m.authority.name.startswith("SWFT"))
    # round 12: the swap keeps what passed through, the payout destination its issuer's value: the same funds
    assert swft.value == pytest.approx(2617.02) and "same funds as" in swft.basis
    assert _tether(plan).value == pytest.approx(1359.9) and "same funds as" in _tether(plan).basis
    counted = [m for m in plan.moves + plan.waiting if m.value and (m.counts or (m.authority is not None
                                                                                and ":" not in m.key))]
    assert plan.totals["in_play_sum_usd"] < sum(m.value for m in counted)  # counted once, never the sum


def test_moved_on_reads_the_taint_a_transfer_carried():
    x = ("ethereum", "0x" + "77" * 20)
    mixed = attr.Attribution(wallet=attr.Wallet(chain="ethereum", address="0x" + "66" * 20, in_trace=True,
                                                taint_usd=100_000, out_to={x: 95_000}, out_taint={x: 10_000}))
    assert not rp._moved_on(mixed)  # 95k out, 10k of it the case's: case funds may still sit there
    gone = attr.Attribution(wallet=attr.Wallet(chain="ethereum", address="0x" + "66" * 20, in_trace=True,
                                               taint_usd=100_000, out_to={x: 95_000}, out_taint={x: 95_000}))
    assert rp._moved_on(gone)  # the committed reading: (about) everything forwarded


def test_an_unnamed_behaviour_guess_never_hides_funds_leaving(db, case):
    from sqlalchemy import select

    from app.db.models import Address, AddressType

    dep, hot = KUCOIN_DEPOSIT, "0x45300136662dd4e58fc0df61e6290dffd992b785"  # it sweeps into "KuCoin 17" in 7 min
    rows = {x: db.scalar(select(Address).where(Address.address == x)) for x in (dep, hot)}
    was = {x: (a.entity_id, a.address_type) for x, a in rows.items()}
    for a in rows.values():  # no trace entity, no tag, no person's mark: only the behaviour profile
        a.entity_id, a.address_type = None, AddressType.EOA
    db.commit()
    try:
        # a person calls "KuCoin 17" some service's hot wallet, naming no service
        attr.mark(db, case, None, chain="ethereum", address=hot, owner=None, kind="exchange_hot_wallet")
        db.commit()
        guess = attr.attribute(db, case)[("ethereum", dep)]
        assert (guess.kind, guess.owner, guess.source, guess.confidence) == ("exchange_deposit", None, "behaviour", "L")
        assert not fz.sure_service(guess)
        _read(db, case, "ethereum", dep, "20000", 5)
        _read(db, case, "ethereum", dep, "0", 10)
        m = _plan(db, case).find(f"left:ethereum:{dep}")
        assert m is not None and m.value == pytest.approx(144.94)  # the case's funds leaving: at most what was traced
    finally:  # the address rows are shared by every case of the session
        db.rollback()
        for x, a in rows.items():
            a.entity_id, a.address_type = was[x]
        db.commit()


def test_an_unknown_category_entity_owns_no_float():
    for cat, want in (("unknown", None), ("hosting", None), ("mixer", None), ("exchange", "Demo"), ("casino", "Demo"),
                      ("swap_service", "Demo"), ("bridge", "Demo"), ("otc", "Demo")):
        t = fz.Target("ethereum", W, None, in_trace=True, entity="Demo", entity_category=cat, taint_usd=1000.0,
                      address_type="eoa")
        assert fz.service_float(t, {}, ("ethereum", W)) == want, cat


# --------------------------------------------------------------------------- asks and the explorers
def test_the_wallet_skill_names_the_owners_ask_not_a_second_recipient(db, case):
    from test_review_round8 import _access

    from app.ai import skills

    for o in [o for o in case.stop_orders if o.entity is not None and o.entity.name == "KuCoin"]:
        for c in list(o.correspondence or []) if hasattr(o, "correspondence") else []:
            db.delete(c)
        db.delete(o)
    for c in [c for c in case.correspondence if c.entity is not None and c.entity.name == "KuCoin"] \
            if hasattr(case, "correspondence") else []:
        db.delete(c)
    db.commit()
    db.expire_all()
    row = next(r for r in skills.stop_order_plan(db, case)["rows"] if r["entity"] == "KuCoin")
    if row["status"] not in ("recommended", "declined"):
        pytest.skip(f"KuCoin's row is {row['status']} in this copy of the demo")
    attr.mark(db, case, None, chain="ethereum", address=KUCOIN_DEPOSIT, owner="Binance", kind="exchange_deposit")
    db.commit()
    acc = _access(db, case, CaseRole.INVESTIGATOR)
    rec = skills.run_skill(db, acc, "wallet", KUCOIN_DEPOSIT).markdown.split("**Recommendation**", 1)[1]
    assert "Ask Binance" in rec and "Send a stop order to KuCoin" not in rec
    # an issuer's blacklist still applies whoever owns the wallet
    attr.mark(db, case, None, chain="tron", address=TRON_DEST, owner="Binance", kind="exchange_deposit")
    db.commit()
    rec = skills.run_skill(db, acc, "wallet", TRON_DEST).markdown.split("**Recommendation**", 1)[1]
    # ... as its row on the freeze & stop-order board says (Tether acts on LE process only: its step is the LE route)
    assert "Ask Binance" in rec and "Tether (USDT issuer): **" in rec


def test_the_ask_names_our_letter_not_its_internal_key(db, case):
    import re

    rainbet = next(a for a in attr.attribute(db, case).values() if a.owner == "Rainbet" and a.kind in
                   attr.DEPOSIT_KINDS)
    text, href = rainbet.ask.get("text") or "", rainbet.ask.get("href") or ""
    if "&ref=" not in href:
        pytest.skip("no letter to Rainbet on file in this copy of the demo")
    ref = href.split("&ref=", 1)[1].split("#", 1)[0].split("&", 1)[0]
    assert ref not in re.findall(r"\b[co]\d+\b", text) and "quoting our letter of" in text


def test_a_tlp_restricted_watch_is_never_sent_to_the_explorers(db, case, ex):
    x = "0x" + "5c" * 20
    fz.add_watch(db, case, None, chain="ethereum", address=x, tlp="TLP:AMBER+STRICT")
    db.commit()
    _consent(db, case)
    rep = attr.run_lookups(db, case, only={("ethereum", x)})
    assert rep.looked_up == 0 and rep.skipped >= 1
    assert not any(x in str(c).lower() for c in ex.calls)
    y = "0x" + "5d" * 20  # a TLP:GREEN watch still is (the owner-lookup consent covers it)
    fz.add_watch(db, case, None, chain="ethereum", address=y, tlp="TLP:GREEN")
    db.commit()
    attr.run_lookups(db, case, only={("ethereum", y)})
    assert any(y in str(c).lower() for c in ex.calls)


# --------------------------------------------------------------------------- the hover card
def test_the_hover_card_reads_a_swap_services_deposit_typed_address_as_the_plan_does(db, case):
    from sqlalchemy import select
    from test_graph_hover import _hover

    from app.db.models import Address, AddressType

    a = db.scalar(select(Address).where(Address.address == "TJ4KeiGTvTX4wRUgLARiwr8rGLaurmVkdZ"))
    was = a.address_type
    a.address_type = AddressType.DEPOSIT  # a SWFT / Bridgers (swap service) address typed as a deposit
    db.commit()
    try:
        plan = _plan(db, case)
        k = ("tron", a.address)
        assert plan.owners[k].kind == "swap_bridge"
        o = _hover(db, case)[a.address.lower()]["hover"]["owner"]
        assert o["deposit"] is None  # never "credited to the depositor's account at SWFT"
        # the committed reading: an exchange's typed deposit address is a deposit on the card and in the plan
        kc = _hover(db, case)[KUCOIN_DEPOSIT]["hover"]["owner"]
        assert kc["deposit"] and "KuCoin" in kc["deposit"]
    finally:  # the address row is shared by every case of the session
        db.rollback()
        a.address_type = was
        db.commit()
