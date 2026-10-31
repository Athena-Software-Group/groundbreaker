"""Comms intelligence (app.blocks.extract, wired through classify_rules / classify_ai / status / report): golden
replies shaped like the providers' real ones (synthetic text: every address, reference, name and number is made up;
wallets are generated with valid checksums), multilingual dates and LE references, the ambiguous-date rule, the AI's
grounded fields, and the block page's proposals. Offline: no model, no mail, no chain."""

from datetime import UTC, datetime, timedelta

import pytest

from app.ai import providers
from app.blocks import classify_ai, report
from app.blocks import classify_rules as R
from app.blocks import extract as X
from app.blocks import status as bs
from app.db.models import Correspondence
from app.domain import directory
from app.freeze import abi

AT = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
TRON_NEW = abi.b58check_encode(bytes([0x41]) + bytes(range(1, 21)))
TRON_OURS = abi.b58check_encode(bytes([0x41]) + bytes(range(21, 41)))
EVM_NEW = "0x" + "ab12" * 10
TX = "0x" + "9f" * 32

TETHER_ACK = ("Thank you for contacting Tether Compliance.\n\nThis is an automated response. Your request has been "
              "received and ticket #482913 has been created. Tether will only act upon appropriate legal process "
              "submitted by a law enforcement agency.\n\nTether Compliance")
CIRCLE_COURT = ("Thank you for your message. Circle requires a valid court order from a US or French court before it "
                "can block an address holding USDC.")
BINANCE_LE = ("Binance is unable to unilaterally freeze any account without an appropriate official freezing order from "
              "law enforcement or a competent court. Law enforcement agencies can submit requests at "
              "https://app.kodexglobal.com/binance/signup .")
MEXC_TEMP = ("We have temporarily frozen the account linked to the deposit address you reported. Please provide proof "
             "of the police report within 48 hours, otherwise the temporary freeze will be lifted.")
KUCOIN_HOLD = ("We have placed a temporary hold on the account. The hold will be automatically lifted after 30 days "
               "unless a freezing order stating the freeze duration is received.")
NEW_DEPOSIT = (f"The funds were forwarded to a new deposit address {TRON_NEW} belonging to UID: 48213977, after "
               f"arriving at {TRON_OURS}. Please send us the transaction hash and proof of ownership.")


def pb(key):
    return directory.load_catalogue().by_key[key].playbook


def ext(text, key=None, **kw):
    return X.extract(text, playbook=pb(key) if key else None, received_at=AT, **kw).as_dict()


# --------------------------------------------------------------------------- golden replies
def test_tether_style_auto_ack_gives_its_ticket_and_the_le_instrument():
    x = ext(TETHER_ACK, "tether", exclude_refs={"DEMO-2026-001"})
    assert x["tickets"][0]["value"] == "482913" and x["tickets"][0]["system"] == "tether_support"
    assert "ticket #482913" in x["tickets"][0]["quote"]
    assert x["instrument"]["type"] == "le_request" and x["instrument"]["via"] == "playbook"
    assert any(s["phrase"] == "appropriate legal process" for s in x["signals"])
    r = R.classify(TETHER_ACK, playbook=pb("tether"), received_at=AT)
    assert r.ticket == "482913" and r.extract["instrument"]["type"] == "le_request"
    assert "extract" not in r.as_dict()  # stored apart (correspondence.meta block_status extract)


def test_circle_style_court_order_reads_us_or_french():
    x = ext(CIRCLE_COURT, "circle")
    ins = x["instrument"]
    assert ins["type"] == "us_or_fr_court_order" and ins["issuer_jurisdictions"] == ["US", "FR"]
    assert ins["jurisdictions_from"] == "reply" and ins["path"] == "court_order_us_fr"
    assert "US or French court" in ins["quote"]
    # without a playbook the lexicon reads the same
    assert ext(CIRCLE_COURT)["instrument"]["type"] == "us_or_fr_court_order"
    assert R.classify(CIRCLE_COURT).status == R.LE_PROCESS_REQUIRED


def test_binance_style_freezing_order_and_the_le_only_kodex_tenant():
    x = ext(BINANCE_LE, "binance")
    assert x["instrument"]["type"] == "freezing_order" and x["instrument"]["path"] == "le_request"
    ch = x["channels"][0]
    assert ch["class"] == "vendor_portal" and ch["le_only"] and ch["tenant"] == "binance" and not ch["pick"]


def test_mexc_style_temporary_freeze_with_48h_for_police_report_proof():
    x = ext(MEXC_TEMP)
    d = x["deadlines"][0]
    assert (d["what"], d["amount"], d["unit"], d["starts"]) == ("submit_by", 48.0, "hours", "reply")
    assert d["due"] == (AT + timedelta(hours=48)).isoformat(timespec="minutes") and d["auto"] and not d["ambiguous"]
    assert [a["req_key"] for a in x["asks"]] == ["police_report"]
    assert x["instrument"]["type"] == "police_report"


def test_kucoin_style_hold_with_30_day_auto_lift_is_applied_only_on_confirmation():
    x = ext(KUCOIN_HOLD, "kucoin")
    d = next(d for d in x["deadlines"] if d["what"] == "auto_lift")
    assert (d["amount"], d["unit"]) == (30.0, "days") and d["due"].startswith("2026-11-19")
    assert d["auto"] is False  # a hold expiry is applied when a person confirms the hold
    assert x["instrument"]["type"] == "freezing_order"
    assert X.extract("The hold expires 30 days from the date of the freeze.", received_at=AT).deadlines[0][
        "starts"] == "hold_confirmed"


def test_exchange_reply_naming_a_new_deposit_address_and_a_uid():
    x = ext(NEW_DEPOSIT, "binance", known=X.tokens([f"We ask you to freeze {TRON_OURS}."]))
    by = {i["value"]: i for i in x["identifiers"]}
    assert by[TRON_NEW]["chain"] == "tron" and by[TRON_NEW]["watch"] and not by[TRON_NEW]["known"]
    assert by[TRON_OURS]["known"] and not by[TRON_OURS]["watch"]
    assert by["48213977"]["kind"] == "account" and not by["48213977"]["watch"]
    assert {a["req_key"] for a in x["asks"]} == {"tx_list_copyable", "ownership_proof"}
    more = ext(f"Order ID: 7731552090. The funds left via {EVM_NEW} in transaction {TX}.")
    kinds = {i["value"]: (i["kind"], i["chain"]) for i in more["identifiers"]}
    assert kinds[EVM_NEW] == ("address", "evm") and kinds[TX] == ("tx", "evm")
    assert kinds["7731552090"] == ("order_id", None)
    assert not ext("Your reference T" + "1" * 33 + " was noted.")["identifiers"]  # not a valid TRON checksum


def test_italian_dates_and_references():
    x = ext("Si comunica che la denuncia è stata registrata con Prot. n. 1234/2026 (R.G.N.R. n. 5678/26). Il "
            "Maresciallo Demo Bianchi del Comando Carabinieri resta a disposizione. Si prega di inviare la "
            "documentazione entro il 15.11.2026. Tel. +39 000 0000000", "carabinieri")
    d = x["deadlines"][0]
    assert (d["what"], d["date"], d["ambiguous"], d["auto"]) == ("submit_by", "2026-11-15", False, True)
    c = x["contacts"][0]
    assert (c["reference"], c["system"], c["name"], c["role"]) == ("1234/2026", "protocollo", "Demo Bianchi",
                                                                   "Maresciallo")
    assert c["agency"] == "Comando Carabinieri" and c["phone"] == "+39 000 0000000"
    assert any(k["system"] == "rgnr" and k["reference"] == "5678/26" for k in x["contacts"])
    named = ext("Vi preghiamo di inviare la querela entro il 3 novembre 2026.")["deadlines"][0]
    assert (named["date"], named["auto"]) == ("2026-11-03", True)
    amb = ext("Si prega di inviare i documenti entro il 03/04/2027.")["deadlines"][0]
    assert amb["ambiguous"] and amb["candidates"] == ["2027-04-03", "2027-03-04"] and amb["likely"] == "dmy"
    assert amb["due"] is None and amb["auto"] is False


def test_german_dates_and_references():
    x = ext("Ihre Anzeige wurde unter dem Aktenzeichen 123 Js 456/26 erfasst. Bitte reichen Sie die Unterlagen bis "
            "zum 3. November 2026 ein. Die Sperre gilt bis 03.04.2027. Eine Antwort erhalten Sie innerhalb von 7 Tagen.")
    by = {d["what"]: d for d in x["deadlines"]}
    assert by["submit_by"]["date"] == "2026-11-03" and by["submit_by"]["auto"]
    hold = by["hold_until"]
    assert hold["ambiguous"] and hold["candidates"] == ["2027-04-03", "2027-03-04"] and not hold["auto"]
    assert by["reply_by"]["amount"] == 7.0 and by["reply_by"]["unit"] == "days"
    assert x["contacts"][0]["reference"] == "123 Js 456/26" and x["contacts"][0]["system"] == "verfahrensnummer"


def test_french_and_ic3_references():
    x = ext("Votre plainte est enregistrée sous le numéro de procédure 2026/004512. Merci de fournir les pièces "
            "jusqu'au 1er décembre 2026.")
    assert x["contacts"][0]["system"] == "procedure_fr" and x["contacts"][0]["reference"] == "2026/004512"
    assert x["deadlines"][0]["date"] == "2026-12-01"
    ic3 = ext("Thank you for submitting your complaint to the IC3. Your IC3 complaint ID is I2610DEMO4417.", "fbi-ic3")
    assert ic3["contacts"][0]["system"] == "ic3" and ic3["contacts"][0]["reference"] == "I2610DEMO4417"


def test_us_dates_ambiguous_ones_never_shorten_a_clock():
    amb = ext("Please reply by 03/04/2027 with the documents.")["deadlines"][0]
    assert amb["ambiguous"] and amb["likely"] is None and not amb["auto"]
    ok = ext("Please reply by 11/25/2026 with the documents.")["deadlines"][0]
    assert ok["date"] == "2026-11-25" and not ok["ambiguous"] and ok["auto"]
    assert ext("We will respond by November 5, 2026.")["deadlines"][0]["date"] == "2026-11-05"
    assert ext("We will respond within 5 business days.")["deadlines"][0]["due"].startswith("2026-10-27")
    # a date in the past is no deadline; a date without a year is approximate and never automatic
    assert not ext("On 3 October 2026 we froze the account.")["deadlines"]
    noyear = ext("Please submit the documents by 3 November.")["deadlines"][0]
    assert noyear["date"] == "2026-11-03" and noyear["approx"] and not noyear["auto"]


def test_channels_are_classified_and_third_parties_need_a_person():
    others = {"kraken.com": "kraken", "binance.com": "binance"}
    x = ext("Please write to support@binance.com, or see https://www.kraken.com/legal and https://unknown-demo.example/x",
            "binance", org_key="binance", others=others)
    by = {c["value"]: c for c in x["channels"]}
    assert by["support@binance.com"]["class"] == "own" and not by["support@binance.com"]["pick"]
    assert by["https://www.kraken.com/legal"]["class"] == "third_party" and by["https://www.kraken.com/legal"]["pick"]
    assert by["https://www.kraken.com/legal"]["org"] == "kraken"
    assert by["https://unknown-demo.example/x"]["class"] == "unknown" and by["https://unknown-demo.example/x"]["pick"]


def test_asks_only_where_asked_and_not_where_waived():
    assert not ext("No police report is required for this request.")["asks"]
    assert not ext("We received your police report yesterday.")["asks"]
    x = ext("Kindly provide a letter of authorization from the victim, in English, and state the freeze duration?")
    assert {a["req_key"] for a in x["asks"]} >= {"loa", "english_version", "freeze_duration_stmt"}


# --------------------------------------------------------------------------- the AI's reading
def test_ai_fields_are_kept_only_when_grounded_and_merge_never_overwrites():
    own = KUCOIN_HOLD + " Our ticket is 77120 and we need a court order from an Austrian court."
    data = {"status": "hold_placed", "quote": "We have placed a temporary hold on the account.", "confidence": 0.9,
            "rationale": "hold",
            "tickets": [{"value": "77120"}, {"value": "999999"}],
            "instrument": {"type": "court_order", "issuer_jurisdictions": ["AT", "US"],
                           "quote": "we need a court order from an Austrian court"},
            "asks": [{"req_key": "police_report", "quote": "not in the reply at all"},
                     {"req_key": "freeze_duration_stmt", "quote": "stating the freeze duration"}],
            "deadlines": [{"what": "auto_lift", "stated": "30 days",
                           "quote": "The hold will be automatically lifted after 30 days"},
                          {"what": "reply_by", "stated": "5 days", "quote": "made up"}],
            "contacts": [{"name": "Nobody Here", "quote": "invented"}],
            "identifiers": [{"kind": "address", "value": TRON_NEW}, {"kind": "account", "value": "77120"}]}
    out = classify_ai.verify(data, own, received_at=AT)
    x = out["extract"]
    assert [t["value"] for t in x["tickets"]] == ["77120"]
    assert x["instrument"]["type"] == "court_order" and x["instrument"]["issuer_jurisdictions"] == ["AT"]
    assert [a["req_key"] for a in x["asks"]] == ["freeze_duration_stmt"]
    assert len(x["deadlines"]) == 1 and x["deadlines"][0]["auto"] is False and x["deadlines"][0]["source"] == "ai"
    assert x["contacts"] == [] and [i["value"] for i in x["identifiers"]] == ["77120"]
    rules_x = ext(own, "kucoin")
    merged = X.merge(rules_x, x)
    assert merged["instrument"]["type"] == "freezing_order" and merged["ai_instrument"]["type"] == "court_order"
    assert merged["disagree"] == ["instrument"]
    assert X.merge({**rules_x, "instrument": None}, x)["instrument"]["via"] == "ai"
    # the rules' exclusions hold for the AI's additions: our case reference is never their ticket, and a wallet our
    # letters cite is known (no freeze-watch proposal)
    ai_x = {"tickets": [{"value": "DEMO-CASE-0042", "source": "ai"}],
            "identifiers": [{"kind": "address", "chain": "tron", "value": TRON_NEW, "known": False, "watch": True,
                             "source": "ai"}]}
    m = X.merge({**rules_x, "tickets": [], "identifiers": []}, ai_x, exclude_refs={"DEMO-CASE-0042"},
                known={TRON_NEW})
    assert m["tickets"] == [] and m["identifiers"][0]["known"] and not m["identifiers"][0]["watch"]
    assert "tickets" in classify_ai.SCHEMA["properties"] and "deadlines" in classify_ai.SCHEMA["properties"]


# --------------------------------------------------------------------------- the block page
@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


@pytest.fixture
def case(db, tmp_path):
    from test_block_status import fresh_case

    yield fresh_case(db, tmp_path)


def test_block_row_intel_clock_storage_and_page(db, case, client_for):
    from test_block_status import _Access, _order, _reply, _row

    order = _order(case, "KuCoin")
    reply = _reply(db, case, order, NEW_DEPOSIT, mailbox=True)
    row = _row(db, case, f"o{order.id}")
    assert row.playbook is not None and row.org_key == "kucoin"
    ids = {i["value"]: i for i in row.intel["identifiers"]}
    assert ids[TRON_NEW]["watch"] and ids[TRON_NEW]["reply_id"] == reply.id
    assert row.status == R.INFO_REQUESTED
    assert "proof of ownership" in row.next_action["text"] and "transaction hashes" in row.next_action["text"]
    view = report.row_view(row, _Access(), case)
    assert view["intel"]["identifiers"][0]["source_note"] == f"named in reply c{reply.id}"
    rep = bs.refresh(db, case, use_ai=False)
    assert rep.replies >= 1
    db.expire_all()
    stored = db.get(Correspondence, reply.id).meta["block_status"]["extract"]
    assert stored["version"] == X.VERSION and any(i["value"] == TRON_NEW for i in stored["identifiers"])
    c = client_for("investigator", case=case)
    page = c.get(f"/cases/{case.id}/blocks").text
    assert "Read from the reply" in page and "Watch for a freeze" in page and TRON_NEW in page
    assert f'value="named in reply c{reply.id}"' in page
    ro = client_for("read_only", case=case).get(f"/cases/{case.id}/blocks").text
    assert TRON_NEW not in ro and "Watch for a freeze" not in ro  # identifiers only with view_restricted


def test_a_stated_reply_date_shortens_the_clock_only_when_unambiguous(db, case):
    from test_block_status import _order, _reply, _row

    order = _order(case, "Hostinger")
    order.sent_at, order.response_due_at = datetime(2026, 3, 1, 9, 0), None
    for c in db.query(Correspondence).filter(Correspondence.stop_order_id == order.id):
        c.occurred_at, c.due_at = datetime(2026, 3, 1, 9, 0), None
    db.commit()
    now = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    base = _row(db, case, f"o{order.id}", now=now).due_at
    assert base > datetime(2026, 3, 3, 11, 0, tzinfo=UTC)
    # 03/02/2026: 2 March (US) would shorten the clock, 3 February (EU) is past: ambiguous, so neither applies
    _reply(db, case, order, "We will respond by 03/02/2026.", at=datetime(2026, 3, 1, 10, 0, tzinfo=UTC))
    row = _row(db, case, f"o{order.id}", now=now)
    assert row.due_at == base and row.next_deadline is None
    assert row.intel["deadlines"][0]["ambiguous"]
    _reply(db, case, order, "We have received your request and will respond within 2 days.",
           at=datetime(2026, 3, 1, 11, 0, tzinfo=UTC))
    row = _row(db, case, f"o{order.id}", now=now)
    assert row.due_at == datetime(2026, 3, 3, 11, 0, tzinfo=UTC) and row.next_deadline["what"] == "reply_by"
