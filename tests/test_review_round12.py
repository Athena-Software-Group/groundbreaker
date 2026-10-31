"""Verify round 12: the three heuristics that did not converge, replaced by simple, conservative rules whose failure
mode is "unknown / you choose", never a confident wrong answer.

* findings.address_role (removed in round r5: a person picks every wallet's role; the text only hints).
* rules.classify: a document holding any chat is never read as a police report, complaint, LE letter or order (a
  note asks a person to confirm the type); a police report needs its agency in the letterhead and a report number.
* the Recovery plan's money: no move's value is cut because another move counts the same funds; moves on the same
  funds say so; the totals count each traced dollar once, capped at the traced loss, plus labelled untraced finds.

The demo case plus synthetic readings and documents (every address, number and name is made up)."""

from __future__ import annotations

import pytest
from test_review_round10 import D4, _read, _tether
from test_review_round11 import LOSS_TRACED, _counted, _no_double, _tag_and_look, _usdc
from test_wallet_owners import Explorers, _addr, _offline, _plan  # noqa: F401 - _offline: autouse

from app import services
from app.evidence_intel import findings, rules
from app.freeze import service as fz

V = "0x" + "ab12" * 10  # made-up addresses
W = "0x" + "cd34" * 10
EVM = "0x" + "ef56" * 10


# --------------------------------------------------------------------------- 1. a wallet's role
# every sentence of the earlier rounds: the right role or None, never the opposite one
HISTORIC = [
    # verify rounds 7-11 (test_review_round8 / 9 / 11, test_evidence_intel)
    (f"Transaction Details\nFrom: {V}\nTo: {W}\n", "victim", "perpetrator"),
    (f"Transaction from {V} to {W}", "victim", "perpetrator"),
    (f"Recipient wallet address {W}; my wallet address {V}", "victim", "perpetrator"),
    (f"The victim sent 40,000 USDT from her own wallet {V} (MetaMask) to the suspect's wallet {W}.", "victim",
     "perpetrator"),
    (f"I sent from my MetaMask {V} to the scammer", "victim", None),
    (f"The victim sent USDT from her wallet {V} to the fraudster", "victim", None),
    (f"Il querelante ha inviato dal proprio wallet {V} al truffatore", "victim", None),
    (f"La persona offesa ha trasferito 12.500 USDT dal proprio wallet {V} al truffatore.", "victim", None),
    (f"Victim wallet address: {V}\nSuspect wallet address: {W}", "victim", "perpetrator"),
    (f"Wallet della vittima: {V}\nWallet del truffatore: {W}", "victim", "perpetrator"),
    (f"Sending address: {V}\nScammer address: {W}", "victim", "perpetrator"),
    (f"Victim: {V}\nScammer: {W}", "victim", "perpetrator"),
    (f"Vittima: {V}\nTruffatore: {W}", "victim", "perpetrator"),
    (f"Opfer-Wallet: {V}\nTäter-Wallet: {W}", "victim", "perpetrator"),
    (f"Portefeuille de la victime : {V}\nPortefeuille de l'escroc : {W}", "victim", "perpetrator"),
    (f"Sender {V} -> scammer {W}", "victim", "perpetrator"),
    (f"Persona offesa: {V}\nIndagato: {W}", "victim", "perpetrator"),
    (f"Wallet {V} des Opfers", "victim", None),
    (f"Il wallet {V} della vittima riceveva dal truffatore", "victim", None),
    (f"Le portefeuille {V} de la victime", "victim", None),
    (f"The wallet {V} (victim) was emptied", "victim", None),
    (f"I paid from my MetaMask {V} (the scammer told me to)", "victim", None),
    (f"I sent the funds from my MetaMask {V}.", "victim", None),
    (f"{V} (MetaMask)", "victim", None),
    (f"The funds went to {W} of the scammer", None, "perpetrator"),
    (f"Gli importi sono confluiti su {W}, indicato dal truffatore", None, "perpetrator"),
    (f"The wallet {W} (scammer) received 2 BTC", None, "perpetrator"),
    (f"Anna: Send to our platform wallet {W}", None, "perpetrator"),
    (f"The victim used his Ledger to send 2 BTC to address {W}", None, "perpetrator"),
    (f"transferred funds from her Exodus wallet into {W}", None, "perpetrator"),
    (f"Der Geschädigte überwies von seiner MetaMask-Wallet an die Adresse {W}", None, "perpetrator"),
    (f"La victime a envoyé depuis son portefeuille Ledger vers l'adresse {W}", None, "perpetrator"),
    ((f"La persona offesa ha trasferito 12.500 USDT dal proprio wallet MetaMask all'indirizzo {W} indicato dal "
      "truffatore."), None, "perpetrator"),
    (f"The victim sent 40,000 USDT to the suspect's\nwallet {W}", None, "perpetrator"),  # a wrapped line: None
    # verify round 12 (the round-4 repros): the previous line's trailing label is never the next address's
    (f"{V} - victim\n{W} - scammer", "victim", "perpetrator"),
    (f"{V}: victim's wallet\n{W}: scammer's wallet", "victim", "perpetrator"),
    (f"{V} – vittima\n{W} – truffatore", "victim", "perpetrator"),
    (f"{V} — Opfer\n{W} — Täter", "victim", "perpetrator"),
    (f"Wallet {V} of the victim\nWallet {W} of the scammer", "victim", "perpetrator"),
    (f"{V} victim\n{W} suspect", "victim", "perpetrator"),
    (f"{V} sender\n{W} recipient", "victim", "perpetrator"),
    # the next line's label never applies to the address before it
    (f"Victim wallet address: {V}\nSuspect wallet address: {W}\nVictim: Anna", "victim", "perpetrator"),
    (f"{V}\nScammer wallet: {W}", "victim", "perpetrator"),
]


@pytest.mark.parametrize("text,v,w", HISTORIC)
def test_no_sentence_gives_a_wallet_a_role_only_a_hint(text, v, w):
    """Design decision (r5): the wording rules did not converge over five rounds; `v` / `w` are what they read, none
    of it is applied. The text gives a hint (cue words from a fixed lexicon, never the address or another word of
    the document); a person picks the role."""
    assert not hasattr(findings, "address_role")
    for addr in (V, W):
        if addr in text:
            h = findings.address_hint(text, addr)
            assert h is None or (h.startswith("near “") and V not in h and W not in h and "Anna" not in h), (text, h)


def test_a_hint_reads_only_the_addresss_own_line():
    assert findings.address_hint(f"Victim wallet:\n{V}", V) is None
    assert findings.address_hint(f"{V} - victim\n{W} - scammer", W) == "near “scammer”"
    assert findings.address_hint(f"Hop 4\n{V}\n{W}", W) is None


# --------------------------------------------------------------------------- 2. chats are never the police's report
IMPOSTORS = {
    "an impostor 'officer' chat, a screenshot": (
        ("Officer Smith: Metropolitan Police here\nAnna: hi\nOfficer Smith: crime reference number NFRC2026091234\n"
         "Anna: ok\nOfficer Smith: pay the fee\nAnna: ok"), "IMG_0042.png", "image"),
    "an impostor 'deputy' chat, a screenshot": (
        ("Deputy Jones: Metropolitan Police here\nAnna: hi\nDeputy Jones: crime reference number NFRC2026091234\n"
         "Anna: ok\nDeputy Jones: pay the fee\nAnna: ok"), "IMG_0043.png", "image"),
    "an impostor chat, pasted as text": (
        ("Officer Smith: Metropolitan Police here\nAnna: hi\nOfficer Smith: crime reference number NFRC2026091234\n"
         "Anna: ok\nOfficer Smith: pay the fee\nAnna: ok"), "notes.txt", "text"),
    "a chat screenshot's OCR (times, ticks, 'online')": (
        ("Metropolitan Police\nonline\nHello, this is DC Brown from Action Fraud\n10:05\nYour crime reference number "
         "is NFRC2026091234\n10:06\nOk thanks\n10:07 ✓✓"), "Screenshot_2026.png", "image"),
    "a chat whose last message pastes a fake report": (
        ("\n".join(f"[01/09/2026, 10:0{i}:00] {'Anna' if i % 2 else 'Agent'}: msg {i}" for i in range(6))
         + "\n[01/09/2026, 10:09:00] Agent: SPRINGFIELD POLICE DEPARTMENT\nIncident Report\nReport Number: "
           "26-012345\nOfficer: J. Doe\nNarrative: pay the release fee"), "chat.txt", "text"),
    "one message pasting a fake report": (
        ("[01/09/2026, 10:09:00] Agent: SPRINGFIELD POLICE DEPARTMENT\nIncident Report\nReport Number: 26-012345\n"
         "Officer: J. Doe"), "chat.txt", "text"),
    "one message pasting a fake court order": (
        ("[01/09/2026, 10:09:00] Agent: IN THE HIGH COURT OF DEMO. FREEZING ORDER. It is hereby ordered that your "
         "assets be frozen until you pay."), "chat.txt", "text"),
    "the WhatsApp banner": (
        ("Messages and calls are end-to-end encrypted.\n01/09/2026, 09:00 - Anna: my uncle works at the police "
         "department, report number: 12345\n" + "\n".join(f"01/09/2026, 10:0{i} - Anna: hi {i}" for i in range(8))),
        "chat.txt", "text"),
}


@pytest.mark.parametrize("name", list(IMPOSTORS))
def test_a_document_holding_a_chat_is_never_an_official_document(name):
    text, fname, kind = IMPOSTORS[name]
    r = rules.classify(text, name=fname, kind=kind)
    assert r["type"] in ("chat_export", "other") and r["type"] not in rules._OFFICIAL, (name, r)
    assert not {"police_report", "complaint_ref", "ic3_ref", "court_order", "seizure_warrant"} & set(r["keys"])
    assert r["note"] == rules.CHAT_NOTE and r["confidence"] != "H", (name, r)


GENUINE = {
    "springfield": ("SPRINGFIELD POLICE DEPARTMENT\nIncident Report\nReport Number: 26-012345\nOfficer: J. Doe\n"
                    "Victim: Anna\nSuspect: unknown\nNarrative: the victim sent 40,000 USDT"),
    "carabinieri": ("Comando Carabinieri di Demo\nProt. n. 4417/2026\nVerbale di ricezione di denuncia-"
                    "querela\nLa persona offesa dichiara di aver trasferito 12.500 USDT."),
    "polizei, an interview": ("Polizeipräsidium Berlin\nAktenzeichen: 123 Js 4567/26\nVernehmung der Geschädigten\n"
                              "F: Wann?\nA: Am 1.9.\nF: Wie viel?\nA: 40.000 USDT\nF: Wohin?\nA: Wallet"),
    "gendarmerie": ("Gendarmerie nationale\nBrigade de Demo\nProcès-verbal de plainte\nPV n° 01234/2026\n"
                    "La victime déclare avoir envoyé 40 000 USDT."),
    "action fraud": "Action Fraud\nThank you for your report. Your crime reference number is NFRC261012345678.",
    "a form's cover block": ("Page 1 of 4\nForm PD-301\nRev. 2024\nCity of Springfield\nDepartment of Public Safety\n"
                             "Records Division\nConfidential\nFor official use only\nSection A\nSpringfield Police "
                             "Department\nReport Number: 26-012345\nThe victim reported a fraud."),
}


@pytest.mark.parametrize("name", list(GENUINE))
def test_a_genuine_police_report_still_reads_as_one(name):
    r = rules.classify(GENUINE[name], name="scan.pdf", kind="pdf")
    assert r["type"] == "police_report" and {"police_report", "complaint_ref"} <= set(r["keys"]), (name, r)
    assert not r["note"]


def test_a_police_report_needs_its_letterhead_and_a_report_number():
    for text in ("Récépissé de dépôt de plainte, commissariat de Demo",  # no report number
                 "Summary\n" * 12 + "Springfield Police Department\nReport Number: 26-1",  # the agency past the head
                 ""):
        r = rules.classify(text, name="Police_Report.pdf", kind="pdf")
        # the note asks the person to confirm; `keys` count only once a person confirms the type
        assert r["type"] == "police_report" and r["note"] == rules.REPORT_NOTE, (text, r)


def test_a_statement_with_timestamped_rows_is_not_a_chat():
    csv = ("Date(UTC),Coin,Network,Amount,TransactionFee,Address,TXID,Status\n"
           "2026-09-20 10:00:00,USDT,TRX,40000,1,TXYZ,abc,Completed")
    assert rules.classify(csv, name="export.csv", kind="text")["type"] == "exchange_statement"


# --------------------------------------------------------------------------- 3. money: each traced dollar once
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


def _by(plan, name):
    return next(m for m in plan.moves + plan.waiting if m.authority is not None and ":" not in m.key
                and m.authority.name.startswith(name))


def _invariant(plan):
    """in play ≤ the traced loss + the labelled untraced finds; nothing counted zero times (no counted move is larger
    than the total: its money is in it, at the move or at a larger one on the same funds)."""
    t = plan.totals
    assert t["in_play_usd"] <= t["traced_loss_usd"] + t["untraced_usd"] + 0.01
    assert t["in_play_usd"] == pytest.approx(min(t["traced_usd"], t["traced_loss_usd"]) + t["untraced_usd"], abs=0.01)
    assert all(m.value <= t["in_play_sum_usd"] + 0.01 for m in _counted(plan))
    assert t["expected_usd"] <= t["in_play_usd"] + 0.01
    if t["untraced_usd"]:
        assert any("untraced finds" in n for n in plan.notes)
    _held(plan.ledger)


def _below(src: dict, k, top: frozenset, stop: frozenset) -> bool:
    """Wallet `k` is one of `top`, or the trace saw its funds come from one of them, never through `stop`."""
    seen, todo = set(), [k] if k not in stop else []
    while todo:
        x = todo.pop()
        if x in top:
            return True
        seen.add(x)
        todo += [p for p in src.get(x, ()) if p not in seen and p not in stop]
    return False


def _held(ledger: dict) -> None:
    """Nothing counted zero times (checked claim by claim, independently of _count's own rule): every claim of a dollar
    or more is counted, or a counted claim at least as large holds it: on the same wallet, or an upper bound of what
    reached a wallet it descends from that does not leave out the path to it (a service wallet's onward), and never
    another piece of the same move."""
    claims, picked, src = ledger["claims"], ledger["picked"], ledger["sources"]
    for i, c in enumerate(claims):
        if i in picked or c.traced < 1:
            continue
        j = ledger["cover"].get(i)
        assert j is not None and j in picked, f"claim {i} ({c.move.key}, ${c.traced:,.2f}) counted nowhere"
        p = claims[j]
        assert p.traced >= c.traced - 0.01
        assert not (p.move is c.move and (p.extra or c.extra))
        if p.wallets & c.wallets:
            continue
        down = p.flow and any(_below(src, k, p.wallets, p.stop) for k in c.wallets)
        up = c.flow and any(_below(src, k, c.wallets, c.stop) for k in p.wallets)
        assert down or up, f"claim {i} ({c.move.key}) is held by {p.move.key}, not on its funds"


def test_the_demo_moves_keep_their_values_and_the_totals_count_each_overlap_once(db, case):
    plan = _plan(db, case)
    rainbet, swft, kucoin, tether = _by(plan, "Rainbet"), _by(plan, "SWFT"), _by(plan, "KuCoin"), _tether(plan)
    assert rainbet.value == pytest.approx(63761.69) and swft.value == pytest.approx(2617.02)
    assert tether.value == pytest.approx(1359.9) and kucoin.value == pytest.approx(144.94)
    # design decision (r5): the same funds ONLY at the same wallet or along the trace's ancestry. SWFT and Tether share
    # SWFT's payout wallet (counted once, the larger); Rainbet is another branch below the hub: counted on its own
    for m in (swft, tether):
        assert "same funds as" in m.basis
    assert "same funds as" not in kucoin.basis and "same funds as" not in rainbet.basis
    assert plan.totals["in_play_usd"] == pytest.approx(63761.69 + 2617.02 + 144.94, abs=0.01)
    assert plan.totals["traced_loss_usd"] == pytest.approx(LOSS_TRACED)
    _invariant(plan)
    _no_double(plan)


def test_money_found_elsewhere_is_counted_and_cuts_no_other_move(db, case):
    """The round-4 repro: a 50,000 USDT reading at a traced hub outflow adds 50,000 to in play and leaves Rainbet's
    value alone (it was cut to 11,144.67 and in play stayed at 63,906.63). Round r5: SWFT, on another branch, counts
    too (66,523.65 without the reading)."""
    plain = _plan(db, case)
    h3 = _addr(db, case, "Hub outflow #3")
    _read(db, case, "ethereum", h3[1], "50000", 5)
    plan = _plan(db, case)
    assert _by(plan, "Rainbet").value == pytest.approx(63761.69)
    assert plan.totals["in_play_usd"] == pytest.approx(116523.65, abs=0.01)
    assert plan.totals["in_play_usd"] == pytest.approx(plain.totals["in_play_usd"] + 50000, abs=0.01)
    assert _tether(plan).value == pytest.approx(51359.9)
    _invariant(plan)


def test_a_balance_the_trace_never_saw_is_added_and_labelled(db, case):
    plain = _plan(db, case)
    fz.add_watch(db, case, None, chain="ethereum", address=D4)
    db.commit()
    _usdc(db, case, D4, "40000")
    plan = _plan(db, case)
    assert plan.totals["untraced_usd"] == pytest.approx(40000)
    assert plan.totals["in_play_usd"] == pytest.approx(plain.totals["in_play_usd"] + 40000, abs=0.01)
    assert any("untraced finds" in n and D4[-4:] in n for n in plan.notes)
    _invariant(plan)


def test_in_play_is_capped_at_the_traced_loss_plus_the_untraced_finds(db, case):
    for label in ("Hub outflow #2", "Hub outflow #3"):
        k = _addr(db, case, label)
        _read(db, case, "ethereum", k[1], "90000", 5)
    fz.add_watch(db, case, None, chain="ethereum", address=D4)
    db.commit()
    _usdc(db, case, D4, "40000")
    case.loss_usd = 100000  # the case reports less than the trace saw: the smaller is the cap
    db.commit()
    plan = _plan(db, case)
    t = plan.totals
    assert t["traced_loss_usd"] == pytest.approx(100000) and t["in_play_capped"]
    assert t["in_play_usd"] == pytest.approx(100000 + 40000, abs=0.01)
    assert any("capped at the traced loss" in n for n in plan.notes)
    _invariant(plan)


def test_a_deposit_tag_on_a_relay_the_trace_followed_on_adds_nothing(db, case, ex):
    """Round 3: 'Perpetrator relay #2' tagged an OKX deposit address (the trace saw all of it go on to a wallet no
    service owns) is never a move valued at the whole traced loss, and the totals do not move."""
    plain = _plan(db, case)
    r2 = _addr(db, case, "Perpetrator relay #2")
    _tag_and_look(db, case, ex, {r2: ("OKX: Deposit", "OKX")})
    plan = _plan(db, case)
    m = plan.find(f"owner:{r2[0]}:{r2[1]}")
    assert m is None or not m.value
    assert plan.totals["in_play_usd"] == pytest.approx(plain.totals["in_play_usd"], abs=0.01)
    _invariant(plan)
    _no_double(plan)


def test_a_swept_deposit_keeps_its_move_and_its_issuer_move_is_the_same_funds(db, case):
    from app.attribution import service as attr

    plain = _plan(db, case)
    attr.mark(db, case, None, chain="tron", address=_addr(db, case, "USDT-TRON destination")[1], owner="Binance",
              kind="exchange_deposit")
    db.commit()
    k = _addr(db, case, "USDT-TRON destination")
    _read(db, case, "tron", k[1], "1360", 5)
    _read(db, case, "tron", k[1], "0", 10)
    plan = _plan(db, case)
    m = plan.find(f"owner:tron:{k[1]}")
    assert m is not None and m.value == pytest.approx(1359.9) and "swept: the account was credited" in m.basis
    assert plan.totals["in_play_usd"] == pytest.approx(plain.totals["in_play_usd"], abs=0.01)
    _invariant(plan)


def test_an_issuer_reading_past_what_the_trace_left_is_not_the_cases_money(db, case):
    """Round 13: not the case's traced funds, still counted once: an untraced find, added and labelled."""
    plain = _plan(db, case)
    r2 = _addr(db, case, "Perpetrator relay #2")
    _usdc(db, case, r2[1], "300000")
    plan = _plan(db, case)
    circle = _by(plan, "Circle")
    assert circle.value == pytest.approx(300000) and "not the case's traced funds" in circle.basis
    assert plan.totals["in_play_usd"] == pytest.approx(plain.totals["in_play_usd"] + 300000, abs=0.01)
    assert any("untraced finds" in n and r2[1][-4:] in n for n in plan.notes)
    _invariant(plan)
