"""Review round 4 of the provider playbooks / reply intelligence / request paths / Recovery plan: one regression per
verified major (the wallet a reply names: withdrawn out vs on the provider's own platform, chain / wallet product names,
the exchange named in the next sentence, an address already in the trace; MEXC's clock with no reply yet; the deep
links' letter template; MEXC's LE brief after a temporary freeze; a late hold reply's stale reply-due clock; the freeze
request a deposit address gets) and the cheap minors. The demo case plus synthetic replies (every address,
ticket and number is made up). Offline: no model, no mail, no chain."""

import re
from datetime import timedelta
from types import SimpleNamespace as N
from urllib.parse import unquote

import pytest
from test_review_round3 import (
    EVM_EXTERNAL,
    MEXC_TEMP,
    NOW,
    _cand,
    _ent,
    _le,
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
from app.db.models import EvidenceFolder, EvidenceItem
from app.domain import correspondence as desk
from app.domain import evidence_requirements as er
from app.domain import playbook as pbm

EVM_A = "0x" + "11" * 20
EVM_NEXT = "0x" + "7a" * 20


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


def _dest(text: str, org: str = "kraken") -> dict:
    orgs, _ = rp._custodians([])
    row = N(replies=[N(extract={"identifiers": [{"value": EVM_A, "chain": "evm", "watch": True, "kind": "address"}]},
                       own=text, corr=N(id=7))], org_key=org)
    return pathmod.destinations(row, orgs)[0]


def _keys(plan) -> list[str]:
    return [m.key for m in plan.moves + plan.waiting]


# --------------------------------------------------------------------------- major: withdrawn out vs own platform
def test_a_wallet_the_account_holder_withdrew_to_is_external_not_on_the_providers_platform(db, case):
    assert _dest(f"The account holder (UID 12345678) withdrew all funds to {EVM_A} on 3 May.")["where"] == "unknown"
    assert _dest(f"The funds were withdrawn to {EVM_A}, an address belonging to the account holder.")["where"] == \
        "unknown"
    # the wallet itself at the provider: still "own"
    assert _dest(f"The funds were moved by internal transfer to sub-account deposit address {EVM_A}.")["where"] == "own"
    assert _dest(f"The funds were forwarded to a new deposit address {EVM_A} belonging to UID: 48213977.")["where"] \
        == "own"
    bybit = _ent(db, "Bybit")
    bo = _sent(db, case, bybit, "0x" + "e5" * 20, at=NOW - timedelta(days=2), amount="60,000 USDT")
    _reply(db, case, bo, f"The account holder (UID 41000001) withdrew the funds to {EVM_EXTERNAL} on 18 October. The "
                         "account balance is now zero.", NOW - timedelta(hours=2))
    plan = _plan(db, case)
    assert plan.find(f"fwatch:ethereum:{EVM_EXTERNAL}") is not None
    assert plan.find(f"issuer:ethereum:{EVM_EXTERNAL}") is not None
    texts = [m.text for m in plan.moves + plan.waiting] + [d["text"] for d in plan.done]
    assert not any("extend the hold" in t or "on its own platform" in t for t in texts)


# --------------------------------------------------------------------------- major: chain / wallet product names
def test_a_chain_or_self_custody_wallet_named_after_an_exchange_is_no_deposit_address_there(db, case):
    for text in (f"The funds were withdrawn to {EVM_A} via BEP20 (Binance Smart Chain).",
                 f"The user withdrew to {EVM_A} (Coinbase Wallet).",
                 f"The funds were sent out to {EVM_A} on BSC."):
        d = _dest(text)
        assert d["where"] == "unknown" and d["org"] is None, text
    # custody context next to the name: another exchange's deposit address
    assert _dest(f"The funds were withdrawn to {EVM_A}, a deposit address at Binance.")["org"][1] == "Binance"
    assert _dest(f"The funds were transferred to the Binance account UID 55512345 via its deposit address {EVM_A}."
                 )["org"][1] == "Binance"
    bybit = _ent(db, "Bybit")
    bo = _sent(db, case, bybit, "0x" + "e5" * 20, at=NOW - timedelta(days=2), amount="60,000 USDT")
    _reply(db, case, bo, f"The funds were withdrawn to the external address {EVM_EXTERNAL} via BEP20 (Binance Smart "
                         "Chain). The account balance is now zero.", NOW - timedelta(hours=2))
    plan = _plan(db, case)
    dest = plan.find(f"dest:ethereum:{EVM_EXTERNAL}")
    assert dest is None or "Binance" not in dest.title
    assert plan.find(f"fwatch:ethereum:{EVM_EXTERNAL}") is not None
    assert plan.find(f"issuer:ethereum:{EVM_EXTERNAL}") is not None


# --------------------------------------------------------------------------- major: the exchange in the next sentence
def test_the_exchange_named_in_the_next_sentence_gets_the_freeze_request(db, case):
    assert _dest(f"The funds were withdrawn on 19 Oct to {EVM_A}. Our records show this is a deposit address at "
                 "Binance.")["org"][1] == "Binance"
    # a later sentence about something else is no reference back
    assert _dest(f"The funds were withdrawn to {EVM_A}. Binance support may help you.")["where"] == "unknown"
    okx = _ent(db, "OKX")
    oo = _sent(db, case, okx, "0x" + "d3" * 20, at=NOW - timedelta(days=2), amount="80,000 USDT")
    _reply(db, case, oo, f"We no longer hold any balance for this user. The funds were withdrawn on 19 Oct to "
                         f"{EVM_NEXT}. Our records show this is a deposit address at Binance.", NOW - timedelta(hours=1))
    plan = _plan(db, case)
    dest = plan.find(f"dest:ethereum:{EVM_NEXT}")
    assert dest is not None and "Binance" in dest.title
    assert plan.find(f"issuer:ethereum:{EVM_NEXT}") is None and plan.find(f"fwatch:ethereum:{EVM_NEXT}") is None


# --------------------------------------------------------------------------- major: an address already in the trace
def test_funds_moved_to_an_address_already_in_the_trace_reach_the_provider_that_holds_it(db, case):
    kucoin = _cand(db, case, "KuCoin")
    addr = kucoin.identifiers[-1].address
    okx = _ent(db, "OKX")
    oo = _sent(db, case, okx, "0x" + "d3" * 20, at=NOW - timedelta(days=2), amount="80,000 USDT")
    _reply(db, case, oo, f"The funds were withdrawn yesterday to {addr}, a deposit address at another exchange. The "
                         "account balance is now zero.", NOW - timedelta(hours=1))
    plan = _plan(db, case)
    chain = "tron" if kucoin.identifiers[-1].chain == "tron" else "ethereum"
    m = plan.find(f"dest:{chain}:{addr}")
    assert m is not None and m.authority is not None and m.authority.name == "KuCoin"
    assert "funds just arrived from OKX (their reply)" in m.urgency_why and m.value
    primary = next(a for a in m.actions if a.get("primary"))
    # the address is one KuCoin's open request already cites (its own identifier): the request gate
    # (app.domain.request_gate) makes the step that request's follow-up, never a second letter for the same address
    ko = next(o for o in case.stop_orders if o.entity_id == m.authority.entity.id and o.sent_at is not None)
    assert "template=status_request" in primary["href"] and f"ref=o{ko.id}" in primary["href"]
    ku = next(x for x in plan.moves + plan.waiting if x.authority is not None and x.authority.name == "KuCoin"
              and ":" not in x.key)
    assert "funds just arrived from OKX (their reply)" in ku.urgency_why


# --------------------------------------------------------------------------- major: MEXC's clock with no reply yet
def test_mexc_with_no_reply_is_asked_for_the_receipt_proactively_never_answered(db, case):
    mexc = _ent(db, "MEXC")
    mo = _sent(db, case, mexc, "0x" + "b2" * 20, at=NOW - timedelta(hours=10))
    row = _row(db, case, f"o{mo.id}")
    na = row.next_action
    assert na["kind"] != "answer" and "template=info_response" not in (na["href"] or "")
    assert "asks for Send" not in na["text"] and "unfreezes" in na["text"] and na["text"].count("unfreezes") == 1
    assert "template=status_request" in na["href"] and f"ref=o{mo.id}" in na["href"]
    m = _plan(db, case).find(f"o{mo.id}")
    assert m.actionable and not m.title.startswith("Answer") and "police receipt" in m.title
    # an acknowledgement with no ask: still no "asks for <the playbook's sentence>"
    _reply(db, case, mo, "Thank you, we have received your request and our team is reviewing it. Ticket: MX-1",
           NOW - timedelta(hours=8))
    na = _row(db, case, f"o{mo.id}").next_action
    assert "asks for Send" not in na["text"] and "template=info_response" not in (na["href"] or "")


# --------------------------------------------------------------------------- major: the deep link's letter template
def test_a_deep_link_preselects_its_letter_template(db, case, client_for):
    mexc = _ent(db, "MEXC")
    mo = _sent(db, case, mexc, "0x" + "c2" * 20, at=NOW - timedelta(hours=8))
    _reply(db, case, mo, MEXC_TEMP, NOW - timedelta(hours=4))
    inv = client_for("investigator", case=case, email="inv-r4-tpl@tests.example")
    base = f"/cases/{case.id}/authorities/entity-{mexc.id}"

    def selected(html: str) -> str | None:
        sel = html.split('id="letter-template"')[1].split("</select>")[0]
        m = re.search(r'<option value="(\w+)"[^>]*\bselected\b', sel)
        return m.group(1) if m else None

    assert selected(inv.get(f"{base}?template=info_response&ref=o{mo.id}").text) == "info_response"
    # MEXC was asked already: the information request about a new deposit is the follow-up quoting that request
    page = inv.get(f"{base}?template=info_request&freeze=ethereum:{EVM_A}&ref=o{mo.id}&note=hello").text
    assert selected(page) == "info_request" and EVM_A in page
    assert selected(inv.get(f"{base}?template=status_request&ref=o{mo.id}").text) == "status_request"
    # an unavailable template is never preselected
    assert selected(inv.get(f"{base}?template=le_brief").text) is None


# --------------------------------------------------------------------------- major: MEXC's LE brief after a freeze
def test_mexc_le_brief_after_a_temporary_freeze_lists_what_le_s_order_needs(db, case):
    mexc = _ent(db, "MEXC")
    mo = _sent(db, case, mexc, "0x" + "c2" * 20, at=NOW - timedelta(hours=8), amount="120,000 USDT")
    _reply(db, case, mo, MEXC_TEMP, NOW - timedelta(hours=4))
    _subject, body, _r = desk.build_letter(db, case, _le(db, case, "Procura"), "le_brief", ref=f"o{mo.id}")
    assert "how long the restriction lasts" in body and "not to inform the account holder" in body
    assert "Victim's ID" not in body and "Letter of authority" not in body


# --------------------------------------------------------------------------- major: a late hold reply's reply-due
def test_a_late_hold_reply_never_ranks_on_its_passed_reply_due_date(db, case):
    bitget = _ent(db, "Bitget")
    bo = _sent(db, case, bitget, "0x" + "a7" * 20, at=NOW - timedelta(days=10), amount="60,000 USDT",
               due=NOW - timedelta(days=3))
    _reply(db, case, bo, "Hello, we have placed a temporary hold on the account pending your documents.",
           NOW - timedelta(hours=1))
    m = _plan(db, case).find(f"o{bo.id}")
    assert m is not None and not any("reply due" in w for w in m.urgency_why)
    assert m.clock is None or m.clock.get("label") != "reply due"


# --------------------------------------------------------------------------- major: the freeze request letter
def test_a_deposit_address_at_another_exchange_gets_a_freeze_request_naming_it(db, case):
    from test_review_round3 import EVM_BINANCE, TO_BINANCE

    binance = _ent(db, "Binance")
    bo = _sent(db, case, binance, "0x" + "b1" * 20, at=NOW - timedelta(days=3))
    okx = _ent(db, "OKX")
    oo = _sent(db, case, okx, "0x" + "d3" * 20, at=NOW - timedelta(days=2), amount="80,000 USDT")
    _reply(db, case, oo, TO_BINANCE, NOW - timedelta(hours=1))
    m = _plan(db, case).find(f"dest:ethereum:{EVM_BINANCE}")
    # Binance acts on LE process only (its victim intake never holds): the LE brief leads, the address prefilled; the
    # letter to Binance follows up the request already open, naming the new deposit (round 5)
    primary = [a for a in m.actions if a.get("primary")]
    assert len(primary) == 1 and primary[0]["label"].startswith("Brief LE") and EVM_BINANCE in unquote(
        primary[0]["href"])
    assert m.kind == "le" and "acts on LE process only" in m.text
    follow = next(a for a in m.actions if a["label"].startswith("Write to Binance on request"))
    assert "template=info_request" in follow["href"] and EVM_BINANCE in unquote(follow["href"])  # round 6
    a = desk.get_authority(db, case, f"entity-{binance.id}")
    # Binance was asked already: the letter is the follow-up quoting that request (the request gate refuses it
    # without the ref: never a second request)
    with pytest.raises(desk.GateRefused):
        desk.generate_letter(db, case, a, "info_request", actor=None, freeze=f"ethereum:{EVM_BINANCE}")
    letter = desk.generate_letter(db, case, a, "info_request", actor=None, freeze=f"ethereum:{EVM_BINANCE}",
                                  extra_note="note", ref=f"o{bo.id}")
    assert letter.subject.startswith("Urgent: new deposit") and EVM_BINANCE in letter.subject
    body = letter.body_markdown
    ids = body.split("On-chain identifiers")[1]
    assert EVM_BINANCE in ids.split("\n- ")[1] and "freeze the account it credits" in body
    assert body.index("freeze the account it credits") < body.index("cannot compel disclosure")
    # the LE action speaks to LE, not to the exchange
    le = next((x for x in m.actions if x["label"].startswith("Brief LE")), None)
    assert le is None or "We ask you to request Binance" in unquote(le["href"])


# --------------------------------------------------------------------------- minors
def test_answer_letter_minors_le_wording_their_deadline_and_the_custodian_map(db, case):
    mexc = _ent(db, "MEXC")
    mo = _sent(db, case, mexc, "0x" + "c2" * 20, at=NOW - timedelta(hours=8))
    _reply(db, case, mo, MEXC_TEMP, NOW - timedelta(hours=4))
    a = desk.get_authority(db, case, f"entity-{mexc.id}")
    b = desk.generate_letter(db, case, a, "info_response", actor=None, ref=f"o{mo.id}").body_markdown
    assert "has been asked" not in b and "We are briefing law enforcement now" in b
    assert "You asked for this by" not in b and "within the time your process allows" in b
    # a UID at another exchange is never "on your platform" in the answer letter either
    _reply(db, case, mo, f"The funds were transferred to the Binance account UID 55512345 via its deposit address "
                         f"{EVM_A}.", NOW - timedelta(hours=2))
    b = desk.generate_letter(db, case, a, "info_response", actor=None, ref=f"o{mo.id}").body_markdown
    assert "on your platform" not in b


def test_an_order_naming_one_provider_opens_only_its_paths_and_whole_words_only(db, case):
    db.add(EvidenceItem(case=case, folder=EvidenceFolder.LEGAL, title="Order – Circle",
                        description="Issued to investigate the fraud.", source_type="court_order",
                        storage="reference", classification="R3"))
    db.commit()
    db.refresh(case)
    assert er.held_instruments(case) == {"court_order"}
    assert er.held_instruments(case, ["Circle (USDC issuer)"]) == {"court_order"}
    assert er.held_instruments(case, ["Gate", "Gate.io"]) == frozenset()


def test_an_unconditional_imminent_lift_still_warns():
    assert "lifted" in R.outcome_warnings("We froze the account. The account will be unfrozen within 24 hours.", None,
                                          R.FROZEN)
    assert "lifted" not in R.outcome_warnings("We placed a temporary hold. The hold will be lifted after 30 days unless "
                                              "a freezing order is received.", None, R.HOLD_PLACED)


def test_the_day_date_filter_matches_dates_not_words():
    for ok in ("responds within the market 24 hours", "decision 2 of the board", "augmented 3 times", "mayor 5"):
        assert not pbm._DAY_DATE.search(ok), ok
    for bad in ("Replied 3 Oct", "replied October 3", "replied 2026-10-03", "replied 03-10-2026",
                "replied 2026-10-03T09:12Z", "replied 3-Oct-2026", "replied 20261003"):
        assert pbm._DAY_DATE.search(bad), bad


def test_dest_moves_are_capped(db, case):
    okx = _ent(db, "OKX")
    oo = _sent(db, case, okx, "0x" + "d3" * 20, at=NOW - timedelta(days=2), amount="80,000 USDT")
    addrs = ["0x" + f"{i:02x}" * 20 for i in range(0x20, 0x20 + 12)]
    _reply(db, case, oo, " ".join(f"The funds were withdrawn to {x}, a deposit address at Binance." for x in addrs),
           NOW - timedelta(hours=1))
    plan = _plan(db, case)
    assert sum(1 for k in _keys(plan) if k.startswith(("dest:", "fwatch:", "issuer:"))) <= rp.MAX_WATCH


def test_kucoin_confirmed_hold_names_one_instrument_in_action_and_brief(db, case):
    from test_block_status import _order
    from test_review_round3 import KUCOIN_HOLD

    order = _order(case, "KuCoin")
    _reply(db, case, order, KUCOIN_HOLD, NOW - timedelta(hours=6))
    row = _row(db, case, f"o{order.id}")
    ins = row.path.instrument["label"]
    # round 6: one label helper (pathmod.ask_label) for the hold preview and the post-confirm action
    lab = pathmod.ask_label(row.path)
    assert row.path.instrument["source"] == "reply" and f"brief LE for {lab}" in row.next_action["text"]
    _subject, body, _r = desk.build_letter(db, case, _le(db, case, "Procura"), "le_brief", ref=f"o{order.id}")
    assert ins in body and "no court application first" in body




def test_binance_handoff_lists_only_the_case_le_s_channels(db, case):
    from test_review_round3 import BINANCE_FO

    binance = _ent(db, "Binance")
    bo = _sent(db, case, binance, "0x" + "b1" * 20, at=NOW - timedelta(days=1))
    row = _row(db, case, f"o{bo.id}")
    text = (row.next_action or {}).get("text") or ""
    assert "mainland China" not in text and "Binance.US" not in text
    _reply(db, case, bo, BINANCE_FO, NOW - timedelta(hours=10))
    text = _row(db, case, f"o{bo.id}").next_action["text"]
    assert "mainland China" not in text and "Binance.US" not in text


def _parsed_with(key: str, change) -> None:
    from test_review_round3 import _parsed, _shipped

    raw = _shipped(key)
    change(raw)
    _parsed(raw)


def test_the_validator_closes_the_le_only_loopholes():
    from app.domain import directory

    def purpose_override(b):
        b["channels_ext"]["binance.le"] = {"who": "any", "purpose": "general", "source_ids": ["b1"], "basis": "D",
                                           "confidence": "H", "retrieved_at": "2026-10-20"}

    def portal_case(b):
        b["channels"][0].update(value="https://app.kodexglobal.com/Binance/signup", who="any", purpose="general")

    def portal_no_slash(b):
        b["channels"][0].update(value="https://app.kodexglobal.com/binance", who="any", purpose="general")

    for change, needle in ((purpose_override, "keeps its purpose"), (portal_case, "LE-only vendor portal"),
                           (portal_no_slash, "LE-only vendor portal")):
        with pytest.raises(directory.CatalogueError, match=needle):
            _parsed_with("binance", change)
    pb = directory.load_catalogue().by_key["binance"].playbook
    assert pb.portal_for("https://app.kodexglobal.com/BINANCE/signup") is not None


def test_observed_facts_carry_no_date_in_any_field_or_format():
    from app.domain import directory

    def note(text):
        return lambda c: c["channels_ext"]["circle.blocklisting"].__setitem__("notes", text)

    def entity(c):
        oid = next(s["id"] for s in c["sources"] if s.get("observed"))
        c["entities"] = [*(c.get("entities") or []), {"key": "zz", "name": "Z", "source_ids": [oid],
                                                       "notes": "replied 2026-10-03 from jane@circle-demo.example"}]

    for change in (note("Replied 03-10-2026"), note("replied 2026-10-03T09:12Z"), note("replied 3-Oct-2026"), entity):
        with pytest.raises(directory.CatalogueError, match="day-level date"):
            _parsed_with("circle", change)
    _parsed_with("circle", note("responds within the market 24 hours"))  # a word is no date


def test_bybit_prefers_its_general_intake_over_the_vip_portal_whatever_the_file_order():
    from test_review_round3 import _parsed, _shipped

    raw = _shipped("bybit")
    raw["paths"][0], raw["paths"][1] = raw["paths"][1], raw["paths"][0]
    pb = _parsed(raw).by_key["bybit"].playbook
    assert pathmod.our_path(pb, "victim").key == "victim_report"


def test_mexc_freeze_clock_cites_the_stolen_funds_article_and_the_eu_execution_term_is_general():
    from app.domain import directory

    cat = directory.load_catalogue()
    ds = {d.key: d for d in cat.by_key["mexc"].playbook.path("victim_report").timing.deadlines}
    # round 6: mx2's 48 hours is the LE request's (le_request); the police-acceptance clock is an inference from mx3
    assert list(ds["police_acceptance"].prov.source_ids) == ["mx3"] and list(ds["le_request"].prov.source_ids) == ["mx2"]
    assert ds["police_acceptance"].prov.basis == "I" and ds["le_request"].prov.basis == "D"
    for key in ("carabinieri", "procura"):
        pb = cat.by_key[key].playbook
        acts = [d.action for p in pb.paths for d in p.timing.deadlines if d.key == "execution"]
        assert acts and all("Art. 9(4)" in a for a in acts)
