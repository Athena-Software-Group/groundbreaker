"""Verify round r6 (suggestion-only design kept): the money counted zero times, the unchecked "file it" box, and three
type suggestions a person would have to reject.

* recovery._count: the part of an issuer move's value beyond its readings (a person-held / frozen amount) never
  excludes the same move's own readings; a service wallet's claim that leaves out what the trace saw it send on never
  covers the wallets below those onward wallets.
* the confirm route: a missing / empty "move" field (an unchecked box) files nothing.
* rules.classify: a two-line handle chat, a messenger screenshot with a "Support (verified)" contact, a provider
  asking for an order are suggested as chats / a reply, never as an order.

The demo case plus synthetic readings and documents (every address, number and name is made up)."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace as NS

import pytest
from conftest import csrf_token
from sqlalchemy import select
from test_block_status import _reply
from test_evidence_intel import (  # noqa: F401 - client, fcase, vault: fixtures
    DENUNCIA,
    _new_item,
    _tok,
    _upload,
    client,
    fcase,
    make_eml,
    make_pdf,
    vault,
)
from test_review_round10 import _read, _tether
from test_review_round11 import _no_double, _tag_and_look
from test_review_round12 import _by, _held, _invariant
from test_wallet_owners import Explorers, _addr, _offline, _plan  # noqa: F401 - _offline: autouse

from app import services
from app.attribution import service as attr
from app.blocks import recovery as rp
from app.blocks import status as bs
from app.db.models import Entity, EvidenceFolder, EvidenceItem, StopOrder, StopOrderStatus
from app.domain import evidence_requirements as er
from app.evidence_intel import rules
from app.evidence_intel import service as intel

A, B = ("ethereum", "0x" + "a1" * 20), ("ethereum", "0x" + "b2" * 20)
V = "0x" + "ab12" * 10
W = "0x" + "cd34" * 10
X = "0x" + "ef56" * 10


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


# --------------------------------------------------------------------------- 1. a held amount above the readings
def test_a_person_held_amount_above_an_issuers_readings_counts_the_whole_move():
    """Issuer move: a reading at A (1,000 traced), B unread (2,000 traced in, an upper bound), a person recorded 10,000
    held: the move's 10,000 is all counted, the readings never dropped for the move's own remainder."""
    st = rp.Stake(usd=10000.0)
    st.addresses = [A, B]
    st.parts = [{"k": A, "traced": 1000.0, "untraced": 0.0, "flow": False},
                {"k": B, "traced": 2000.0, "untraced": 0.0, "flow": True}]
    m = rp.Move(key="entity-1", kind="request", title="Tether", authority=NS(key="entity-1", name="Tether"),
                value=10000.0, likelihood=0.5)
    t = rp._count([m], {"entity-1": st}, {}, cap=400000.0)
    assert t["in_play"] == pytest.approx(10000)
    assert "same funds as" not in m.basis
    _held(t["ledger"])


def test_a_frozen_amount_confirmed_above_the_readings_is_counted_with_the_readings(db, case, client_for):
    """The r6 repro: a 60,000 USDT reading at SWFT's sender, a sent Tether order naming it, a reply, a person confirms
    200,000 frozen: in play holds the Tether move's 200,000 plus Rainbet and KuCoin (it held 202,546.73)."""
    k = _addr(db, case, "SWFT order sender #1")
    _read(db, case, k[0], k[1], 60000, 5)
    tether = db.scalar(select(Entity).where(Entity.name == "Tether (USDT issuer)"))
    order = StopOrder(case=case, entity=tether, status=StopOrderStatus.SENT, subject="Freeze request",
                      body_markdown=f"Please blacklist {k[1]}.", identifiers={"addresses": [{"address": k[1]}]},
                      sent_at=datetime.now(tz=UTC), sent_via="email", recipient_email="compliance@tether-demo.example")
    db.add(order)
    db.commit()
    reply = _reply(db, case, order, "We have frozen 200,000 USDT on the addresses you reported.")
    bs.refresh(db, case)
    inv = client_for("investigator", case=case, email="inv-held@tests.example")
    r = inv.post(f"/cases/{case.id}/blocks/o{order.id}/confirm", data={
        "status": "frozen", "reply_id": str(reply.id), "amount": "200000", "asset": "USDT",
        "csrf_token": csrf_token(inv, f"/cases/{case.id}/blocks")}, follow_redirects=False)
    assert r.status_code in (200, 303)
    plan = _plan(db, case)
    tm = _tether(plan)
    assert tm.value == pytest.approx(200000)
    rest = _by(plan, "Rainbet").value + _by(plan, "KuCoin").value
    assert plan.totals["in_play_sum_usd"] >= 200000 + rest - 0.01
    _invariant(plan)


# --------------------------------------------------------------------------- 2. a deposit tag the trace followed on
def test_a_deposit_tag_on_a_wallet_the_trace_followed_on_never_hides_the_money_below_it(db, case, ex):
    """The r6 repro: 'Peel wallet' tagged a Binance deposit (its move leaves out the 9,515 the trace saw leave it), a
    3,000 USDT reading at 'Peel outflow (1.48 ETH)' (its direct onward child): in play gains the 3,000 and KuCoin
    (below Peel over the laundering chain) still counts. Untagged, the same reading counts the same way."""
    plain = _plan(db, case)
    kucoin = _by(plain, "KuCoin").value
    peel, out = _addr(db, case, "Peel wallet"), _addr(db, case, "Peel outflow (1.48 ETH")
    _tag_and_look(db, case, ex, {peel: ("Binance: Deposit", "Binance")})
    tagged = _plan(db, case)
    owner = tagged.find(f"owner:{peel[0]}:{peel[1]}")
    assert owner is not None and owner.counts and tagged.owners[peel].onward
    assert "same funds as" not in _by(tagged, "KuCoin").basis
    assert tagged.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"] + owner.value, abs=0.01)
    _invariant(tagged)
    _no_double(tagged)
    _read(db, case, out[0], out[1], 3000, 5)
    read = _plan(db, case)
    assert "$3,000 on-chain" in _tether(read).basis
    assert read.totals["in_play_sum_usd"] == pytest.approx(tagged.totals["in_play_sum_usd"] + 3000, abs=0.01)
    assert _by(read, "KuCoin").value == pytest.approx(kucoin)
    _invariant(read)


def test_a_person_marking_the_peel_wallet_a_deposit_counts_the_same(db, case):
    plain = _plan(db, case)
    peel = _addr(db, case, "Peel wallet")
    attr.mark(db, case, None, chain=peel[0], address=peel[1], owner="Binance", kind="exchange_deposit")
    db.commit()
    plan = _plan(db, case)
    owner = plan.find(f"owner:{peel[0]}:{peel[1]}")
    assert plan.totals["in_play_sum_usd"] == pytest.approx(plain.totals["in_play_sum_usd"] + owner.value, abs=0.01)
    _invariant(plan)


def test_the_check_catches_money_counted_nowhere():
    """_held fails on a claim neither counted nor held by a counted claim on its funds."""
    m1 = rp.Move(key="a", kind="request", title="a", value=100.0)
    m2 = rp.Move(key="b", kind="request", title="b", value=50.0)
    c1, c2 = rp._Claim(m1, frozenset([A]), 100.0, stop=frozenset([B])), rp._Claim(m2, frozenset([B]), 50.0)
    ledger = {"claims": [c1, c2], "picked": [0], "cover": {1: 0}, "sources": {B: frozenset([A])}}
    with pytest.raises(AssertionError):
        _held(ledger)
    _held({**ledger, "claims": [rp._Claim(m1, frozenset([A]), 100.0), c2]})  # not net of B: B's money is in it


# --------------------------------------------------------------------------- 3. the "file it" box
@pytest.mark.parametrize("fields", [{}, {"move": ""}])
def test_an_unchecked_file_it_box_leaves_the_folder_alone(client, fcase, vault, db, fields):  # noqa: F811
    data = make_pdf([DENUNCIA])
    _upload(client, fcase, "scan.pdf", data, "application/pdf")
    item = _new_item(db, fcase, data)
    r = client.post(f"/cases/{fcase.id}/evidence/{item.id}/intel/confirm",
                    data={"csrf_token": _tok(client, fcase), "doc_type": "police_report", **fields},
                    follow_redirects=False)
    assert r.status_code == 303 and "filed+under" not in r.headers["location"]
    db.expire_all()
    item = db.get(EvidenceItem, item.id)
    assert item.folder == EvidenceFolder.OTHER
    assert "police_report" in intel.confirmed_keys(item)  # the type is confirmed, the item stays where it was


def test_a_checked_file_it_box_files_the_item(client, fcase, vault, db):  # noqa: F811
    data = make_pdf([DENUNCIA])
    _upload(client, fcase, "scan.pdf", data, "application/pdf")
    item = _new_item(db, fcase, data)
    r = client.post(f"/cases/{fcase.id}/evidence/{item.id}/intel/confirm",
                    data={"csrf_token": _tok(client, fcase), "doc_type": "police_report", "move": "1"},
                    follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    assert db.get(EvidenceItem, item.id).folder == EvidenceFolder.LAW_ENFORCEMENT


# --------------------------------------------------------------------------- 4. type suggestions
DISCORD = ("Discord #support\nmod_jenny: hi, this is the official Interpol liaison. A freezing order was issued by the "
           f"High Court. Pay the bond to {X}.\nme: I will pay from {V}")
SCREENSHOT = ["Screenshot 2026-09-03 at 14.02", "Telegram", "Binance Support (verified)",
              "LAW ENFORCEMENT REQUEST - Court order No. 4471/2026",
              f"Your account is frozen. Deposit 5,000 USDT to {W} to lift the freeze order."]
PROVIDER = ("Dear investigator,\nThank you for your request about the wallet " + W + ". We are unable to act on "
            "requests from private parties. Please file a complaint with IC3 (ic3.gov) or your local police and have "
            "law enforcement send us a court order or a seizure warrant.\nRegards, Compliance Team, Demo Exchange")


@pytest.mark.parametrize(("name", "kind", "text", "want"), [
    ("discord.txt", "text", DISCORD, "chat_export"),
    ("screenshot.pdf", "pdf", "\n".join(SCREENSHOT), "chat_export"),
    ("provider.eml", "email", PROVIDER, "provider_reply"),
])
def test_impostor_chats_and_a_provider_asking_for_an_order_are_never_suggested_as_orders(name, kind, text, want):
    r = rules.classify(text, name=name, kind=kind)
    assert r["type"] == want, r
    assert r["type"] not in {"freezing_order", "court_order", "seizure_warrant", "ic3_complaint"}


@pytest.mark.parametrize(("name", "kind", "body"), [
    ("discord.txt", "txt", DISCORD), ("screenshot.pdf", "pdf", SCREENSHOT), ("provider.eml", "eml", PROVIDER)])
def test_the_checklist_shows_no_order_suggestion_for_them(client, fcase, vault, db, name, kind, body):  # noqa: F811
    data, mime = ((make_pdf([body]), "application/pdf") if kind == "pdf" else
                  (make_eml(body, subject="Re: your request"), "message/rfc822") if kind == "eml" else
                  (body.encode(), "text/plain"))
    _upload(client, fcase, name, data, mime)
    item = _new_item(db, fcase, data)
    assert intel.intel(item)["rules"]["type"] not in {"freezing_order", "court_order", "seizure_warrant"}
    db.expire_all()
    c = db.get(type(fcase), fcase.id)
    for row in er.check(er.holdings(db, c, wallets=[]), ["court_order", "freezing_order", "seizure_warrant"]):
        assert item.id not in row["ids"] and "suggested:" not in (row.get("state_label") or ""), row


def test_a_two_line_report_field_pair_is_not_a_chat():
    """A report's own labels stay fields (no handle): "Agent: …" / "Victim: …" two lines are no chat."""
    text = ("Demo City Police Department\nINCIDENT REPORT\nReport Number: 26-004417\nAgent: Det. J. Doe\n"
            "Victim: A. Example\nOffense: Theft by deception")
    assert rules.classify(text, name="report.pdf", kind="pdf")["type"] == "police_report"


@pytest.mark.parametrize(("text", "want"), [
    (("IN THE HIGH COURT OF JUSTICE\nFREEZING ORDER\nClaim No. HC-2026-000117\nPenal notice\nThe Respondent must not "
      f"dispose of the assets held at {W}. The Applicant shall serve this order on the Respondent."), "freezing_order"),
    (("UNITED STATES DISTRICT COURT\nSEIZURE WARRANT\nCase No. 26-mj-0417\nTO: any authorized law enforcement officer\n"
      f"YOU ARE COMMANDED to seize the funds held at {W} on or before 11/04/2026."), "seizure_warrant"),
])
def test_a_genuine_order_still_reads_as_one(text, want):
    assert rules.classify(text, name="order.pdf", kind="pdf")["type"] == want
