"""Verify round 9 (wallet owners, the Recovery plan, the Fund flow hover card, evidence intel): a tagged deposit address
the funds passed through is asked of its exchange at the traced value; issuer wallets that forwarded everything on
never rank the issuer first; Tronscan user feedback never hides the exchange a public tag names; the hover card
names the owner the plan names; a provider reply asking for a police report is no police report; the roles a
document gives its wallets; orders never matched by an item number. The demo case plus synthetic tags,
readings and documents (every address, number and name is made up)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from conftest import csrf_token
from test_evidence_intel import _access as _intel_access
from test_evidence_intel import _new_item, _upload, fcase, make_pdf, vault  # noqa: F401 - fixtures
from test_wallet_owners import (  # noqa: F401
    KEY,
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
from app.attribution import explorer
from app.attribution import service as attr
from app.blocks import recovery as rp
from app.core.permissions import CaseAccess
from app.db.models import CaseRole, FreezeCheck
from app.domain import evidence as ev
from app.domain import evidence_requirements as er
from app.evidence_intel import findings, rules
from app.evidence_intel import service as intel

NOW = datetime.now(tz=UTC)
KUCOIN_DEPOSIT = "0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2"
TRON_DEST = "TWdZZhGv7zqeRnmxWd65yQSE2YDZRteL77"


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


def _usdt_tron(db, case, address, balance):
    db.add(FreezeCheck(case_id=case.id, chain="tron", address=address, issuer="Tether", token_symbol="USDT",
                       token_contract="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", status="ok", blacklisted=False,
                       balance=Decimal(balance), checked_at=NOW + timedelta(minutes=5), block_number=71_000_000,
                       raw_sha256="ab" * 32, meta={"balance_raw": str(int(Decimal(balance) * 10**6))}))
    db.commit()


def _hover(db, case):
    from test_graph_hover import _hover as hover

    return hover(db, case)


# --------------------------------------------------------------------------- wallet owners and the plan
def test_a_tagged_deposit_address_the_funds_passed_through_is_asked_of_its_exchange(db, case, ex):
    """The trace followed relay #2's funds on to 0xba02… (a wallet no service owns): they are counted downstream, never
    again at the tagged deposit address; its OKX move stays, uncounted, the tag flagged as conflicting with the trace
    (verify round 10: it counted the whole $399k a second time)."""
    k = _addr(db, case, "Perpetrator relay #2")  # 399k traced through, the trace saw it move on
    before = _plan(db, case)
    _consent(db, case)
    ex.tags[k[1]], ex.info[k[1]] = [_tag("OKX: Deposit", entity="OKX")], {}
    attr.run_lookups(db, case, only={k})
    plan = _plan(db, case)
    att = plan.owners[k]
    assert (att.owner, att.kind) == ("OKX", "exchange_deposit") and att.wallet.money_usd == 0
    assert att.share_usd == 0 and att.onward and "conflicts with the trace" in att.share_basis
    m = plan.find(f"owner:{k[0]}:{k[1]}")
    assert m is not None and "OKX" in m.title and not m.value and "conflicts with the trace" in m.basis
    assert plan.moves.index(m) > 0 and "no service owns" in m.likelihood_why
    for t in ("in_play_sum_usd", "in_play_usd", "expected_usd"):
        assert plan.totals[t] == pytest.approx(before.totals[t]), t
    for key in [x.key for x in before.moves + before.waiting if x.value]:  # every downstream value as before
        assert plan.find(key) is None or plan.find(key).value == pytest.approx(before.find(key).value), key
    row = next(r for r in rp.owners_view(plan, _Access())["owners"] if r["address"] == k[1])
    assert row["share_usd"] == 0 and "conflicts with the trace" in (row["conflict"] or "")


def test_issuer_wallets_that_forwarded_everything_never_rank_the_issuer_first(db, case):
    plan = _plan(db, case)
    circle = next(m for m in plan.moves if m.authority is not None and m.authority.name.startswith("Circle"))
    assert circle.value == 0 and "moved on" in circle.basis
    assert plan.moves.index(circle) > plan.moves.index(plan.find("identify"))
    assert plan.moves.index(circle) > plan.moves.index(plan.find("trace_next"))
    for k in ((m.wallets or [None])[0] for m in [circle]):
        assert k is None or plan.owners[k].ask["text"].startswith("Self-custody, and the funds moved on")


def test_user_feedback_never_hides_the_exchange_a_tronscan_tag_names(db, case, ex):
    settings = attr._settings().model_copy(update={"tronscan_api_key": KEY})
    _consent(db, case)
    attr.set_enabled(db, case, None, True, settings=settings)
    ex.tron[TRON_DEST] = {"publicTag": "Binance-Deposit", "feedbackRisk": True, "totalTransactionCount": 7}
    attr.run_lookups(db, case, settings=settings, only={("tron", TRON_DEST)})
    att = attr.attribute(db, case)[("tron", TRON_DEST)]
    assert (att.owner, att.kind) == ("Binance", "exchange_deposit")
    assert "Binance" in att.ask["text"] and "Tether" not in att.ask["text"]
    assert any("flagged it as risky" in line for line in att.lines)
    # an older row stored as unhosted (the user feedback hid the tag) is read again
    row = attr.stored(db, case)[("tron", TRON_DEST)]["explorer"]
    row.kind, row.owner = "unhosted", None
    db.commit()
    att = attr.attribute(db, case)[("tron", TRON_DEST)]
    assert (att.owner, att.kind) == ("Binance", "exchange_deposit")
    # a red tag / a scam word with no service tag still reads as the scammer's own wallet
    assert explorer.classify([{"name": "Scam", "type": "red"}]) == (None, "unhosted", "L")
    assert explorer.classify([{"name": "Binance-Deposit", "type": "public"}, {"name": "Scam", "type": "red"}])[:2] == (
        "Binance", "exchange_deposit")


def test_a_casino_hot_wallet_tag_is_its_float_not_a_deposit():
    assert explorer.classify([{"name": "Demo Casino: Hot Wallet", "type": "name"}])[1] == "exchange_hot_wallet"
    assert explorer.classify([{"name": "Demo Casino: Payout", "type": "name"}])[1] == "exchange_hot_wallet"
    assert explorer.classify([{"name": "Demo Casino: Deposit", "type": "name"}])[1] == "casino"


def test_the_owners_panel_counts_the_cases_share_of_a_service_float(db, case):
    _usdt_tron(db, case, TRON_DEST, "5000000")
    plan = _plan(db, case)
    att = plan.owners[("tron", TRON_DEST)]
    assert att.kind == "exchange_hot_wallet" and att.owner is None  # behaviour: far more than the trace put in
    v = rp.owners_view(plan, _Access())
    row = next(r for r in v["owners"] if r["address"] == TRON_DEST)
    assert row["money_usd"] == 5_000_000 and row["share_usd"] == pytest.approx(1359.9)
    assert v["owners_unknown_usd"] < 5_000_000


# --------------------------------------------------------------------------- the hover card
def test_the_hover_card_names_the_owner_the_plan_names(db, case):
    attr.mark(db, case, None, chain="ethereum", address=KUCOIN_DEPOSIT, owner="Binance", kind="exchange_deposit")
    hot = _addr(db, case, "KuCoin 17")
    attr.mark(db, case, None, chain=hot[0], address=hot[1], owner=None, kind="unhosted")
    db.commit()
    by = _hover(db, case)
    plan = _plan(db, case)
    o = by[KUCOIN_DEPOSIT]["hover"]["owner"]
    assert o["name"] == "Binance" == plan.owners[("ethereum", KUCOIN_DEPOSIT)].owner and o["float"] is None
    assert "deposit address of Binance" in o["deposit"]
    names = [a["name"] for a in by[KUCOIN_DEPOSIT]["hover"]["authorities"]]
    assert "Binance" in names and not any("KuCoin" in n for n in names)
    h = by[hot[1]]["hover"]["owner"]
    assert h["category"] == "unhosted" and h["name"] is None and h["float"] is None
    for addr, d in by.items():  # every named owner on the card is the plan's
        if addr == "_edges" or not (d.get("hover") or {}).get("owner"):
            continue
        k = attr.key_of(d["chain"], d["address"])
        if k in plan.owners and plan.owners[k].source == "manual":
            assert d["hover"]["owner"]["name"] == plan.owners[k].owner


def test_a_deposit_addresses_balance_is_no_service_float_on_the_card(db, case):
    _usdt_tron(db, case, TRON_DEST, "50000")
    attr.mark(db, case, None, chain="tron", address=TRON_DEST, owner="KuCoin", kind="exchange_deposit")
    db.commit()
    o = _hover(db, case)[TRON_DEST.lower()]["hover"]["owner"]
    assert o["float"] is None and "credited to the depositor's account at KuCoin" in o["deposit"]


def test_the_graph_api_shows_a_persons_owner_name_to_view_restricted(db, case, client_for):
    k = _addr(db, case, "Distribution hub")
    attr.mark(db, case, None, chain=k[0], address=k[1], owner="Zebulon Quixley", kind="unhosted")
    db.commit()
    run = services.latest_run(db, case)
    adm = client_for("admin", case=case)
    g = adm.get(f"/api/cases/{case.id}/trace/{run.id}/graph").json()
    assert "Zebulon Quixley" in str(g)


# --------------------------------------------------------------------------- evidence intel
REPLY = ("Dear Customer,\nThank you for contacting Demo Exchange Support. Case Number: 12345678\n"
         "We have received your request regarding the transfer. Our compliance team has reviewed it.\n"
         "Please file a police report and have the police department submit a request through our law enforcement "
         "portal.\nKind regards, Demo Exchange Support")


def test_a_provider_reply_asking_for_a_police_report_is_no_police_report(db, case, vault):  # noqa: F811
    for kind in ("pdf", "email"):
        r = rules.classify(REPLY, name="reply.pdf", kind=kind, provider_named=True)
        assert r["type"] == "provider_reply" and "police_report" not in r["keys"], kind
    item = ev.add_note(db, case, title="Reply", text=REPLY)
    db.commit()
    intel.read_item(db, item, use_ai=False)
    db.commit()
    assert intel.intel(item)["rules"]["type"] == "provider_reply"
    assert not {"police_report", "complaint_ref"} & intel.suggested_keys(item)
    got = er.check(er.holdings(db, case, wallets=[]), ["police_report", "complaint_ref"])
    assert all(item.id not in e["ids"] for e in got)


def test_sheriff_and_uk_police_reports_and_exchange_exports():
    sher = ("COUNTY SHERIFF'S OFFICE\nOffense Report\nCase Number: 2026-0045123\nNarrative:\n"
            + "\n".join(f"09/01/2026, 10:0{i} - Anna: hello {i}" for i in range(6)) + "\nDeputy J. Demo took the report.")
    r = rules.classify(sher, name="scan_0012.pdf", kind="pdf")  # round 12: it quotes a chat: a person confirms
    assert r["type"] == "chat_export" and r["note"] == rules.CHAT_NOTE and "police_report" not in r["keys"]
    r = rules.classify(sher.split("\n09/01")[0], name="scan_0012.pdf", kind="pdf")
    assert r["type"] == "police_report" and r["confidence"] == "H"
    for t in ("Metropolitan Police Service\nCrime reference number: 1234567/26\nAction Fraud report.",
              "Action Fraud\nThank you for your report. Your crime reference number is NFRC261012345678."):
        assert rules.classify(t, name="x.pdf", kind="pdf")["type"] == "police_report", t
    stmt = rules.classify("Statement of the victim. I met Anna on Telegram. She told me to send money to her wallet.",
                          name="Victim statement.docx", kind="docx")
    assert "police_report" not in stmt["keys"] and "complaint_ref" not in stmt["keys"]
    csv = ("Date(UTC),Coin,Network,Amount,TransactionFee,Address,TXID,Status\n"
           "2026-09-20 10:00:00,USDT,TRX,40000,1,TXYZ,abc,Completed")
    r = rules.classify(csv, name="export.csv", kind="text")
    assert r["type"] == "exchange_statement" and "ownership_proof" in r["keys"]


W = "0x" + "22bb" * 10
V = "0x" + "a1" * 20


@pytest.mark.parametrize("text,addr,want", [
    ((f"La persona offesa ha trasferito 12.500 USDT dal proprio wallet MetaMask all'indirizzo {W} indicato dal "
      "truffatore."), W, "perpetrator"),
    # round 13: a bare destination ("to <address>", "an die Adresse", "vers l'adresse") is no role cue: the sender
    # may be the victim withdrawing to their own wallet, or the scammer paying a fake profit (role unknown)
    (f"Anna: Send to our platform wallet {W}", W, None),
    (f"our company wallet address: {W}", W, None),
    (f"The victim used his Ledger to send 2 BTC to address {W}", W, None),
    (f"transferred funds from her Exodus wallet into {W}", W, None),
    (f"Der Geschädigte überwies von seiner MetaMask-Wallet an die Adresse {W}", W, None),
    (f"La victime a envoyé depuis son portefeuille Ledger vers l'adresse {W}", W, None),
    # round 12: a cue counts only on the address's own line (a wrapped line: role unknown, a person chooses)
    (f"The victim sent 40,000 USDT to the suspect's\nwallet {W}", W, None),
    (f"He then moved it to his own wallet {W}", W, None),
    (f"I sent the funds from my MetaMask {W}.", W, "victim"),
    # verify round 10: a destination after the address, or the next line's label, is never the address's owner
    (f"I sent from my MetaMask {V} to the scammer", V, "victim"),
    (f"The victim sent USDT from her wallet {V} to the fraudster", V, "victim"),
    (f"Il querelante ha inviato dal proprio wallet {V} al truffatore", V, "victim"),
    (f"Victim wallet address: {V}\nSuspect wallet address: {W}", V, "victim"),
    (f"Victim wallet address: {V}\nSuspect wallet address: {W}", W, "perpetrator"),
    (f"Wallet della vittima: {V}\nWallet del truffatore: {W}", V, "victim"),
    (f"Wallet della vittima: {V}\nWallet del truffatore: {W}", W, "perpetrator"),
    (f"Sending address: {V}\nScammer address: {W}", V, "victim"),
    (f"Sending address: {V}\nScammer address: {W}", W, "perpetrator"),
    (f"La persona offesa ha trasferito 12.500 USDT dal proprio wallet {V} al truffatore.", V, "victim"),
    # an ownership connector / a bracketed apposition after the address still names its owner; a victim cue before
    # it wins over the words after it
    (f"The funds went to {W} of the scammer", W, "perpetrator"),
    (f"Gli importi sono confluiti su {W}, indicato dal truffatore", W, "perpetrator"),
    (f"The wallet {W} (scammer) received 2 BTC", W, "perpetrator"),
    (f"I paid from my MetaMask {V} (the scammer told me to)", V, None),  # round 13: the other role's word vetoes
    # the committed (5517587) readings: a receipt's labels, "from … to …", a bracketed wallet name
    (f"Transaction Details\nFrom: {V}\nTo: {W}\n", V, "victim"),
    (f"Transaction Details\nFrom: {V}\nTo: {W}\n", W, "perpetrator"),
    (f"Transaction from {V} to {W}", V, "victim"),
    (f"Transaction from {V} to {W}", W, None),  # round 13: a bare "to" is no cue
    (f"Recipient wallet address {W}; my wallet address {V}", V, "victim"),
    (f"Recipient wallet address {W}; my wallet address {V}", W, "perpetrator"),
    (f"The victim sent 40,000 USDT from her own wallet {V} (MetaMask) to the suspect's wallet {W}.", V, "victim"),
    (f"The victim sent 40,000 USDT from her own wallet {V} (MetaMask) to the suspect's wallet {W}.", W, "perpetrator"),
    (f"{V} (MetaMask)", V, "victim"),
])
def test_the_text_never_gives_a_wallet_a_role_only_a_hint(text, addr, want):
    # design decision (r5): `want` is what the wording rules of rounds 9-13 read; none of it is applied any more. The
    # text gives a hint (its cue words, never another word of the document, never the address); a person picks
    assert not hasattr(findings, "address_role")
    h = findings.address_hint(text, addr)
    assert h is None or (h.startswith("near “") and addr not in h and len(h) < 80), h


def test_a_denuncia_offers_the_scammers_wallet_as_the_perpetrator_seed_once_a_person_picks_it(client_for, fcase, vault, db):  # noqa: F811
    for s in list(fcase.seeds):
        db.delete(s)
    db.commit()
    text = ["Comando Carabinieri di Demo", "Prot. n. 4417/2026",
            (f"La persona offesa ha trasferito 12.500 USDT dal proprio wallet MetaMask all'indirizzo {W} indicato "
             "dal truffatore.")]
    adm = client_for("admin", case=fcase)
    data = make_pdf([text])
    _upload(adm, fcase, "denuncia.pdf", data, "application/pdf")
    item = _new_item(db, fcase, data)
    v = intel.view(db, _intel_access(db, fcase, adm), item)
    p = next(i for i in v["ids"] if i["value"].lower() == W)
    # no role from the text ("indicato dal truffatore" is only a hint): nothing to watch or seed until a person picks
    assert p["role"] is None and p.get("seed_role") is None and not p["watch"] and "truffatore" in p["hint"]
    intel.pick_role(db, _intel_access(db, fcase, adm), item, p["value"], "perpetrator")
    db.commit()
    p = next(i for i in intel.view(db, _intel_access(db, fcase, adm), item)["ids"] if i["value"].lower() == W)
    assert p["role"] == "perpetrator" and p.get("seed_role") == "perpetrator_wallet" and p["watch"]


# --------------------------------------------------------------------------- orders and the answer letter
def test_use_evidence_never_tags_an_order(db, case, client_for):
    item = ev.add_note(db, case, title="Denuncia Binance", text="Denuncia querela, Carabinieri, Binance.")
    db.commit()
    acc = CaseAccess(case=case, user=None, role=CaseRole.ADMIN, member=None)
    for key in ("court_order", "seizure_warrant", "le_agency_identity"):
        with pytest.raises(er.WaiverError):
            er.use_item(db, acc, key, item.id)
    adm = client_for("admin", case=case)
    url = f"/cases/{case.id}/recovery-plan"
    r = adm.post(f"{url}/use-evidence", data={"csrf_token": csrf_token(adm, url), "key": "court_order",
                                              "evidence_id": str(item.id)}, follow_redirects=False)
    assert r.status_code == 400
    db.refresh(item)
    assert "court_order" not in (item.tags or [])
    assert er.check(er.holdings(db, case, wallets=[]), ["court_order"])[0]["instrument"]


def test_the_answer_letter_defaults_to_the_latest_reply_not_the_newest_letter(db, case, client_for):
    from test_review_round3 import MEXC_TEMP, _reply, _sent
    from test_review_round3 import _ent as _entity

    mexc = _entity(db, "MEXC")
    mo = _sent(db, case, mexc, "0x" + "c3" * 20, at=NOW - timedelta(hours=8))
    _reply(db, case, mo, MEXC_TEMP, NOW - timedelta(hours=4))
    later = _sent(db, case, mexc, "0x" + "c4" * 20, at=NOW - timedelta(hours=1))  # newer, no reply yet
    inv = client_for("investigator", case=case, email="inv-r9-answer@tests.example")
    base = f"/cases/{case.id}/authorities/entity-{mexc.id}"
    page = inv.get(f"{base}?template=info_response").text
    box = page.split('data-for="info_response"')[1].split("</select>")[0]
    assert '<option value="" selected>their latest reply</option>' in box and f'value="o{later.id}"' in box
    tok = csrf_token(inv, base)
    r = inv.post(f"{base}/letters", data={"csrf_token": tok, "template": "info_response", "ref": ""},
                 follow_redirects=False)
    assert r.status_code == 303
    r = inv.post(f"{base}/letters", data={"csrf_token": tok, "template": "info_response", "ref": f"o{later.id}"},
                 follow_redirects=False)
    assert r.status_code in (400, 409, 422)  # an explicit letter with no reply is never answered as another one
