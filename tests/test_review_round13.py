"""Verify round 13: the three heuristics, made simple and conservative (their failure mode is "unknown / you choose",
never a confident wrong answer).

* findings.address_role: removed in round r5 (design decision): a person picks every wallet's role, the text only
  hints (findings.address_hint); every sentence of rounds 9-13 and r5 is checked to give no role.
* rules.classify: any chat-shaped content (WhatsApp's time-first copy, Telegram Desktop's copy header, "Forwarded
  from", "[Voice message]", an SMS / iMessage stamp, standalone message times, "name - message" lines, a bare rank
  alternating with a name, one message time on a screenshot) keeps the official types and their keys away; a police
  report's agency stands on a letterhead line of its own.
* the Recovery plan's money: a balance read past what the trace left at a wallet is never counted zero times (the
  move keeps the reading, the totals add it once, labelled); a service float is valued at what the trace left there.

The demo case plus synthetic readings and documents (every address, number and name is made up)."""

from __future__ import annotations

import pytest
from test_evidence_intel import _access, _new_item, _upload, vault  # noqa: F401 - vault: a fixture
from test_review_round10 import D4
from test_review_round11 import _tag_and_look, _usdc
from test_review_round12 import GENUINE, _by, _invariant
from test_wallet_owners import Explorers, _addr, _offline, _plan  # noqa: F401 - _offline: autouse

from app import services
from app.evidence_intel import findings, rules
from app.evidence_intel import service as intel
from app.freeze import service as fz

V = "0x" + "ab12" * 10  # made-up addresses: V the victim's, W the scammer's
W = "0x" + "cd34" * 10


# --------------------------------------------------------------------------- 1. a wallet's role
# the victim's own wallet: never "perpetrator" (it would be proposed as the perpetrator's seed, and watched)
NEVER_PERPETRATOR = [
    # ordinary phrases with "to" are no destination
    "Address belonging to the complainant: {V}", "Wallet belonging to Ms Rossi: {V}",
    "Address registered to the complainant: {V}", "Wallet used by the victim prior to the fraud: {V}",
    "Victim's address, according to Etherscan: {V}", "Victim's wallet, linked to Coinbase: {V}",
    "Customer wallet, prior to transfer: {V}", "Complainant's wallet, used to pay: {V}",
    # a bare destination: the victim withdrawing to their own wallet, a fake profit / refund / test amount
    "Victim: Anna, refund to: {V}", "I was able to withdraw 200 USDT to {V} at first, so I trusted the platform.",
    "On 3 September I withdrew 500 USDT to {V}", "The platform paid a first 'profit' of 300 USDT to {V}",
    "The scammer sent a test amount to {V}", "The fraudster returned 500 USDT to {V}",
    "The scammers sent a fake refund to the victim at {V}", "Il truffatore ha restituito 500 USDT al wallet {V}",
    "Ho prelevato 200 USDT verso {V}", "Der Betrüger überwies 50 USDT an die Adresse {V} als Lockvogel",
    # a receipt label with the victim named on the line
    "Recipient (victim): {V}", "Beneficiary (victim): {V}", "Victim (receiving): {V}",
    "Recipient address (victim's): {V}", "Recipient: victim's Binance {V}", "Recipient: {V} (the victim's)",
    "Recipient: {V}, the victim's own wallet", "To: {V} (victim's own wallet)", "Payee: {V} - the victim",
    "Receiving address {V} belongs to the victim", "Recipient {V} is the victim's", "Beneficiary: the victim, {V}",
    "Recipient: {V} (victim)", "From (victim): {V}",
    # the victim receiving
    "The exchange returned 1,000 USDT to the complainant {V}", "Funds should be returned to the victim at {V}",
    "Restituire alla vittima all'indirizzo {V}", "Destination address of the refund (victim): {V}",
    "I transferred my savings from Binance to {V}, my Ledger", "I withdrew from Coinbase to the address {V}",
    "Wallet belonging to the victim: {V}", "Der Täter schickte 1 USDT an die Adresse {V} des Opfers",
]
# the scammer's wallet: never "victim" (it would never be watched, and be offered as the victim's wallet)
NEVER_VICTIM = [
    # the other role named in the clause
    "Funds were sent from {W} by the scammer", "Funds were withdrawn from {W} by the scammer",
    "From: {W} — scammer refund", "From: {W} (the scammer's refund wallet)", "Origin: {W} (scammer's hot wallet)",
    "Sender {W} is the scammer", "{W} used by the victim to pay the scammer", "{W} of the victim funds",
    "{W} von Opfergeldern gespeist", "Sender: {W} (scammer)", "Suspect's sending address: {W}",
    # a victim word after a destination word names who received the address, not its owner
    "Indirizzo indicato alla vittima: {W}", "Indirizzo fornito alla vittima: {W}",
    "Wallet comunicato alla persona offesa: {W}", "Adresse donnée à la victime : {W}",
    "Adresse communiquée à la victime : {W}", "Adresse an das Opfer: {W}",
    # who speaks / an incoming transfer's sender
    "Agent: my wallet: {W}", "[01/09/2026, 10:00] Agent: My USDT address: {W}",
    "Agent: Sender wallet for the refund: {W}", "Received from: {W}",
    "I received in my Trust Wallet 500 USDT from {W}", "In my MetaMask I received a refund from {W}",
    "My MetaMask received 0.01 ETH from {W} (dusting by the scammer)",
    "Ho ricevuto sul mio wallet MetaMask 50 USDT da {W}", "In my Trust Wallet app the sender was {W}",
    "La vittima ha ricevuto dal truffatore sul wallet {W}", "Il truffatore ha inviato dal suo wallet {W}",
    # a wallet brand somewhere on the line
    "The scammer also asked me to install Trust Wallet and showed {W}", "Exodus support said that {W}",
]


# round r5's repros: the receipt labels and the wording read them backwards; none of it is a role any more
R5 = [
    "Received\n+500 USDT\nFrom: {W}\nTo: {V}", "Receive USDT\nStatus: Completed\nSender: {W}\nRecipient: {V}",
    "Fake profit payment (the platform's first payout):\nFrom: {W}\nTo: {V}", "Recipient: {V} (my own Ledger)",
    "Address that received the funds from the victim: {W}", "Indirizzo indicato dalla persona offesa: {W}",
    "Address provided by the victim: {W}", "{W} of the victim's broker", "Victim Refund wallet: {W}", "{W} (MetaMask)",
    'He wrote "my wallet: {W}"', "Poisoned address that looked like my wallet: {W}", "Wallet svuotato dal truffatore: {V}",
    "Withdrawal\nAmount: 40,000 USDT\nTo: {V}\nNetwork: ERC20", "Agent Lee\nonline\nMy USDT address: {W}\n10:05 ✓✓",
]


@pytest.mark.parametrize("text", NEVER_PERPETRATOR + NEVER_VICTIM + R5)
def test_no_wording_gives_a_wallet_a_role(text):
    """Design decision (r5): nothing a heuristic says about a wallet's owner is applied; the text gives a hint (its
    lexicon cue words next to the address), a person picks the role."""
    assert not hasattr(findings, "address_role")
    t = text.format(V=V, W=W)
    for addr in (V, W):
        if addr in t:
            h = findings.address_hint(t, addr)
            assert h is None or (h.startswith("near “") and V not in h and W not in h), (t, h)


def test_a_hint_names_the_cue_words_as_they_are():
    assert findings.address_hint(f"Received\n+500 USDT\nFrom: {W}\nTo: {V}", W) == "near “From:”"
    assert findings.address_hint(f"Sender {V} -> scammer {W}", W) == "near “scammer”"
    assert findings.address_hint(f"Indirizzo indicato dalla persona offesa: {W}", W) == "near “persona offesa”"
    assert findings.address_hint(f"Plain line {W}", W) is None


def test_a_fake_profit_paid_to_the_victims_wallet_is_never_offered_as_the_perpetrators_seed(client_for, db, tmp_path,
                                                                                             vault):  # noqa: F811
    from test_block_status import fresh_case

    c = fresh_case(db, tmp_path)
    for s in list(c.seeds):
        db.delete(s)
    db.commit()
    adm = client_for("admin", case=c)
    data = (f"Complaint narrative. The platform paid a first 'profit' of 300 USDT to {V}, so I trusted it. Later I "
            f"withdrew 200 USDT to {V} again.").encode()
    _upload(adm, c, "narrative.txt", data, "text/plain")
    v = intel.view(db, _access(db, c, adm), _new_item(db, c, data))
    p = next(i for i in v["ids"] if i["value"] == V)
    assert p["role"] is None and p.get("seed_role") is None and not p.get("watch")  # a person picks the role


# --------------------------------------------------------------------------- 2. chats are never the police's report
CHATS = {
    "a Telegram copy, two-digit years": (
        ("Polizia Postale, [01.09.26 10:05]\nBuongiorno, sono l'ispettore Rossi della Polizia Postale. Prot. n. "
         "4417/2026\nAnna, [01.09.26 10:06]\nok\nPolizia Postale, [01.09.26 10:07]\nDeve pagare la cauzione\nAnna, "
         "[01.09.26 10:08]\nva bene"), "chat.txt", "text"),
    "a Telegram copy, one message": (
        ("Metropolitan Police, [01.09.26 10:05]\nThis is DC Brown. Your crime reference number is NFRC2026091234\n"
        "Anna, [01.09.26 10:06]\nok"), "chat.txt", "text"),
    "a Telegram copy, four-digit years": (
        ("Det. Rossi, [01.09.2026 10:05]\nPolizia Postale, report number: 26-1234 we found your funds\n\nAnna, "
        "[01.09.2026 10:06]\nreally?"), "chat.txt", "text"),
    "a screenshot of one message": (
        "Polizia Postale\nProt. n. 4417/2026\nDenuncia a suo carico. Paghi 500 USDT per archiviare.\n10:05",
        "IMG_2.jpg", "image"),
    "a screenshot of one message, AM": (
        "Metropolitan Police\nCrime reference number: NFRC2026091234\nPay the release fee today\n10:05 AM",
        "IMG_3.jpg", "image"),
    "a screenshot, the time at a line's end": (
        "Polizia Postale\nGentile signora, Prot. n. 2026/1234, abbiamo recuperato i suoi fondi. 10:07\n", "IMG_9.jpg",
        "image"),
    "an SMS screenshot": (
        ("Text Message\nToday 10:05\nMetropolitan Police: crime reference number NFRC2026091234. Pay the fee at "
        "http://x"), "IMG_4.jpg", "image"),
    "an SMS pasted as text": (
        ("Text Message\nToday 10:05\nMetropolitan Police: crime reference number NFRC2026091234. Pay the fee at "
        "http://x"), "sms.txt", "text"),
    "a forwarded message": (
        "Forwarded from Polizia Postale\nProt. n. 4417/2026\nDenuncia: paghi la cauzione di 500 USDT", "IMG_5.jpg",
        "image"),
    "Messenger's name / time / message": (
        ("Officer Smith\n10:05\nMetropolitan Police, crime reference number NFRC2026091234\nAnna\n10:06\nok\n"
        "Officer Smith\n10:07\npay"), "chat.txt", "text"),
    "an iMessage export": (
        ("Sep 1, 2026 10:05:00 AM\nFrom: Officer Smith\nMetropolitan Police, report number 26-1234\nSep 1, 2026 "
        "10:06:00 AM\nFrom: Me\nok"), "sms.txt", "text"),
    "an exporter's columns": (
        ("2026-09-01 10:05:00 | Officer Smith | Springfield Police Department, report number 26-012345\n"
        "2026-09-01 10:06:00 | Anna | ok"), "chat.txt", "text"),
    "'name - message' lines": (
        "Agent - Springfield Police Department: report number 26-012345\nAnna - ok\nAgent - pay\nAnna - ok",
        "chat.txt", "text"),
    "a voice-message marker": (
        "Polizia Postale\nProt. n. 4417/2026 denuncia a suo carico\n[Voice message]\nAnna: ok", "chat.txt", "text"),
    "a bare 'Deputy' speaker": (
        ("Deputy: This is the Sheriff's Office\nAnna: ok\nDeputy: Case number: 2026-1234\nAnna: ok\nDeputy: pay the "
        "bond in USDT\nAnna: ok"), "chat.txt", "text"),
    "a bare 'Officer' speaker, a screenshot": (
        ("Officer: Metropolitan Police here\nAnna: hi\nOfficer: crime reference number NFRC2026091234\nAnna: ok\n"
        "Officer: pay the fee\nAnna: ok"), "IMG_1.png", "image"),
    "'Officer' and 'Victim' alternating": (
        ("Officer: Metropolitan Police here\nVictim: hi\nOfficer: crime reference number NFRC2026091234\nVictim: ok\n"
        "Officer: pay the fee\nVictim: ok"), "notes.txt", "text"),
    "WhatsApp's copy, the time first": (
        "\n".join(f"[10:0{i}, 01/09/2026] {'Anna' if i % 2 else 'Det. Rossi'}: "
                  + ("Polizia di Stato - Polizia Postale. Prot. n. 2026/1234. We recovered your funds." if i == 0 else
                     "yes, police report number: 26-1234, pay the release fee" if i == 2 else f"msg {i}")
                  for i in range(6)), "chat.txt", "text"),
    "WhatsApp's copy, one message, AM": (
        "[10:05 AM, 9/1/2026] Det. Rossi: Polizia Postale, Prot. n. 2026/1234, pay the release fee", "chat.txt",
        "text"),
    "three lines A / B / A under a letterhead": (
        ("Springfield Police Department\nReport Number: 26-012345\nOfficer Jones: we found your funds\nAnna: really?\n"
        "Officer Jones: pay the fee\n"), "notes.txt", "text"),
}


@pytest.mark.parametrize("name", list(CHATS))
def test_any_chat_shaped_content_is_never_an_official_document(name):
    text, fname, kind = CHATS[name]
    r = rules.classify(text, name=fname, kind=kind)
    assert r["type"] in ("chat_export", "other") and r["type"] not in rules._OFFICIAL, (name, r)
    assert not {"police_report", "complaint_ref", "ic3_ref", "court_order", "seizure_warrant"} & set(r["keys"])
    assert r["note"] == rules.CHAT_NOTE and r["confidence"] != "H", (name, r)
    assert r["keys"] in ([], ["comms_export"])  # what confirming would count for: nothing applies before


def test_an_impostor_chat_is_on_the_checklist_only_as_a_suggestion(db, tmp_path, vault):  # noqa: F811
    """Design decision (r5): no reading applies by itself; an impostor 'police' chat never puts a complaint on file,
    and even its chat_export reading is only "suggested: chat export — confirm" until a person confirms it."""
    from test_block_status import fresh_case

    from app.domain import evidence as ev
    from app.domain import evidence_requirements as er

    c = fresh_case(db, tmp_path)
    text, _fname, _kind = CHATS[next(iter(CHATS))]
    item = ev.add_note(db, c, title="chat", text=text)
    db.commit()
    intel.read_item(db, item, use_ai=False)
    db.commit()
    rows = {e["key"]: e for e in er.check(er.holdings(db, c, wallets=[]), ["police_report", "comms_export"])}
    assert item.id not in rows["police_report"]["ids"] and not rows["police_report"].get("suggested")
    assert rows["comms_export"]["state_label"] == "suggested: chat export — confirm" or (
        rows["comms_export"]["state"] == "have" and item.id not in rows["comms_export"]["ids"])


def test_an_interview_transcribed_in_a_report_reads_as_a_chat_to_confirm():
    """The intended conservative failure: a report transcribing an interview line by line holds chat-shaped content,
    so the rules leave the type to a person (chat_export with the note), never a confident police report."""
    for text in (("Metropolitan Police\nCrime reference number: NFRC2026091234\nInterview record\nDet. Brown: when?\n"
                 "Ms Rossi: on 1 September\nDet. Brown: how much?\nMs Rossi: 40,000 USDT"),
                 ("Metropolitan Police\nCrime reference number: NFRC2026091234\nOfficer: when?\nVictim: on 1 September\n"
                 "Officer: how much?\nVictim: 40,000 USDT")):
        r = rules.classify(text, name="interview.pdf", kind="pdf")
        assert r["type"] == "chat_export" and r["note"] == rules.CHAT_NOTE and "police_report" not in r["keys"]


@pytest.mark.parametrize("text,name,kind", [
    # a photographed verbale's "alle ore 10:05" is no message time
    (("Comando Carabinieri di Demo\nProt. n. 4417/2026\nVerbale di ricezione di denuncia-querela\nalle ore "
     "10:05\nchiuso alle ore 11:30"), "IMG_scan.jpg", "image"),
    # a Polizia di Stato online receipt's "Denuncia n. …" is a report number
    ("Polizia di Stato - Commissariato di PS online\nDenuncia n. 2026/123456\nRicevuta di presentazione",
     "receipt.pdf", "pdf"),
    *((t, "scan.pdf", "pdf") for t in GENUINE.values()),
])
def test_a_genuine_police_report_still_reads_as_one(text, name, kind):
    r = rules.classify(text, name=name, kind=kind)
    assert r["type"] == "police_report" and {"police_report", "complaint_ref"} <= set(r["keys"]) and not r["note"]


def test_the_agency_must_stand_on_a_letterhead_line_of_its_own():
    assert rules._letterhead(["SPRINGFIELD POLICE DEPARTMENT", "Incident Report"])
    for line in ("Buongiorno, sono l'ispettore Rossi della Polizia Postale", "This is DC Brown, Metropolitan Police",
                 "Metropolitan Police here", "Is this the Polizia Postale?", "Polizia Postale, [01.09.26 10:05]"):
        assert not rules._letterhead([line]), line


def test_a_ledger_with_timestamped_columns_is_not_a_chat():
    led = ("Deposit history\n2026-09-20 10:00:00 | Withdrawal | USDT | 40000 | TXYZ\n"
           "2026-09-21 10:00:00 | Deposit | USDT | 100 | TXYZ")
    assert rules.classify(led, name="export.txt", kind="text")["type"] == "exchange_statement"
    wa = "\n".join(f"[14/08/2026, 10:{d:02d}:00] Demo Contact: message {d} on WhatsApp" for d in range(10, 20))
    r = rules.classify(wa, name="chat.txt", kind="text")
    assert r["type"] == "chat_export" and r["keys"] == ["comms_export"] and not r["note"]


# --------------------------------------------------------------------------- 3. money: never counted zero times
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


def test_a_reading_at_a_pass_through_wallet_is_added_once_and_labelled(db, case):
    """The round-13 repro: 300,000 USDC read at 'Perpetrator relay #2' (the trace saw all its funds leave) gave Circle
    $0 and nothing in the totals. The move keeps the reading (its rank), the totals add it once as an untraced find."""
    plain = _plan(db, case)
    r2 = _addr(db, case, "Perpetrator relay #2")
    _usdc(db, case, r2[1], "300000")
    plan = _plan(db, case)
    circle = _by(plan, "Circle")
    assert circle.value == pytest.approx(300000) and "the trace left $0 of the case's funds there" in circle.basis
    assert plan.moves[0] is circle  # ranked on its own value
    t = plan.totals
    assert t["untraced_usd"] == pytest.approx(300000)
    assert t["in_play_usd"] == pytest.approx(plain.totals["in_play_usd"] + 300000, abs=0.01)
    assert t["traced_usd"] == pytest.approx(plain.totals["traced_usd"], abs=0.01)
    assert any("untraced finds" in n and r2[1][-4:] in n for n in plan.notes)
    _invariant(plan)


def test_a_reading_at_the_candidates_own_pass_through_wallet_is_labelled_the_same_way(db, case):
    plain = _plan(db, case)
    fr = _addr(db, case, "Perpetrator first-receiving")
    _usdc(db, case, fr[1], "20000")
    plan = _plan(db, case)
    assert plan.totals["untraced_usd"] == pytest.approx(20000)
    assert plan.totals["in_play_usd"] == pytest.approx(plain.totals["in_play_usd"] + 20000, abs=0.01)
    _invariant(plan)


def test_a_watched_wallet_the_trace_never_saw_and_a_pass_through_reading_both_count(db, case):
    plain = _plan(db, case)
    fz.add_watch(db, case, None, chain="ethereum", address=D4)
    db.commit()
    _usdc(db, case, D4, "40000")
    _usdc(db, case, _addr(db, case, "Perpetrator relay #2")[1], "300000")
    plan = _plan(db, case)
    assert plan.totals["untraced_usd"] == pytest.approx(340000)
    assert plan.totals["in_play_usd"] == pytest.approx(plain.totals["in_play_usd"] + 340000, abs=0.01)
    _invariant(plan)


@pytest.mark.parametrize("label", ["Perpetrator first-receiving", "Perpetrator relay #2"])
def test_a_pooled_reading_is_valued_at_what_the_trace_left(db, case, label):
    """A wallet holding far more than the trace put in (a service's float): the case's share is what the trace left
    there ($0 for a pass-through), never the whole traced inflow; nothing is counted twice."""
    plain = _plan(db, case)
    k = _addr(db, case, label)
    _usdc(db, case, k[1], "5000000")
    plan = _plan(db, case)
    circle = _by(plan, "Circle")
    assert not circle.value and "possibly an exchange / service hot wallet" in circle.basis
    t = plan.totals
    assert t["traced_usd"] <= t["traced_loss_usd"] + 0.01 and not t["in_play_capped"]
    assert t["in_play_usd"] == pytest.approx(plain.totals["in_play_usd"], abs=0.01)
    _invariant(plan)


def test_a_service_hot_wallet_tag_is_valued_at_its_share_and_its_basis_names_no_count_elsewhere(db, case, ex):
    plain = _plan(db, case)
    sw = _addr(db, case, "Perpetrator swap wallet")
    _tag_and_look(db, case, ex, {sw: ("Binance 14", "Binance")})
    _usdc(db, case, sw[1], "5000000")
    plan = _plan(db, case)
    a = plan.owners[sw]
    assert a.share_usd == 0 and "counted there" not in a.share_basis and "leave it" in a.share_basis
    assert all("counted there" not in m.basis for m in plan.moves + plan.waiting)
    t = plan.totals
    assert t["traced_usd"] <= t["traced_loss_usd"] + 0.01
    assert t["in_play_usd"] == pytest.approx(plain.totals["in_play_usd"], abs=0.01)
    _invariant(plan)
