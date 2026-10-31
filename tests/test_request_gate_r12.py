"""r12 review regressions for the request gate (app.domain.request_gate: one open request per provider).

* a draft follow-up (a status request tied to the sent stop order, a deposit follow-up quoting the request, a status
  request on a sent letter) drafted before the provider's latest reply is STALE: no open request — never "open it and
  send it", never the draft a new deposit is added to. The board flags it ("drafted before their reply of …", a case
  admin discards it) and the follow-up the reply calls for is allowed: the answer to their questions, the release
  request, a new deposit's follow-up quoting the request — on every surface: the gate's text, the POST, the board's
  step, the Recovery plan's move, the owners panel;
* a draft follow-up made after the reply stays the open request;
* a records-only request answered "no account / no assets": no stop order (rule (c)'s records exception ends there);
* a swap order identified at a provider nobody asked yet: the stop order leads and cites the swap address (its records
  asked for too), never behind a records-only letter; a records-only draft made anyway is replaced by the stop order
  (the board's and the plan's first step).

The demo case plus synthetic data (every address and number is made up). Offline."""

from datetime import timedelta
from decimal import Decimal

import pytest
from conftest import csrf_token
from test_freeze_board import (
    FROZEN_REPLY,
    NOW,
    _access,
    _board,
    _gate,
    _generate,
    _hrefs,
    _letter_reply,
    _order,
    _owned,
    _reply,
    _t,
    _uncontacted_kucoin,
)
from test_request_gate import _kucoin, _panel_link, _post_link, _requests

from app import services
from app.ai import providers
from app.blocks import recovery as rp
from app.db.models import Correspondence, StopOrderStatus
from app.domain import correspondence as desk
from app.domain import request_gate as rg

INFO_Q = "Please provide the transaction hash and a copy of the police report so we can review your request."
NO_ASSETS = "We have no account associated with the addresses you provided; no assets are held by us."


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


def _post(client, case, key, **data):
    tok = csrf_token(client, f"/cases/{case.id}/authorities/{key}")
    return client.post(f"/cases/{case.id}/authorities/{key}/letters", data={"csrf_token": tok, **data},
                       follow_redirects=False)


def _cid(r) -> int:
    return int(r.headers["location"].split("?")[0].rsplit("/", 1)[1])


def _owner_link(case, key, chain, address, ref=None):
    return (f"/cases/{case.id}/authorities/{key}?template=info_request&freeze={chain}:{address}"
            + (f"&ref={ref}" if ref else "") + "#generate")


def _buttons(t) -> list:
    return [t.step, *t.extra]


def _kuc_moves(db, case):
    plan = rp.build(db, case)
    return plan, [m for m in plan.moves + plan.waiting if m.authority is not None and m.authority.name == "KuCoin"]


def _answer(db, case, which):
    """KuCoin's answer to its sent stop order, after our draft: their questions, an unclear freeze, a recorded freeze."""
    o = _order(case, "KuCoin")
    if which == "info":
        _reply(db, case, o, INFO_Q, NOW - timedelta(minutes=20))
    elif which == "unclear":
        _reply(db, case, o, FROZEN_REPLY, NOW - timedelta(minutes=20))
    else:
        desk.record_stop_order_status(db, case, o, "frozen", actor=None, amount_held=Decimal(250000), asset="USDT")
        db.commit()


# --------------------------------------------------------------------------- a follow-up drafted before their reply
@pytest.mark.parametrize("deposit", [False, True], ids=["no_deposit", "deposit"])
@pytest.mark.parametrize("draft", ["status_request", "deposit_follow_up"])
@pytest.mark.parametrize("which", ["info", "unclear", "frozen"])
def test_a_follow_up_drafted_before_their_reply_is_stale_never_the_open_request(client_for, db, case, which, draft,
                                                                                deposit):
    o = _order(case, "KuCoin")
    key = _t(_board(db, case), "KuCoin").key
    inv = client_for("investigator", case=case, email=f"r12-{which}-{draft}-{deposit}@tests.example")
    if draft == "status_request":  # from /follow-ups or the Chase step: tied to the sent stop order
        r = _post(inv, case, key, template="status_request", ref=f"o{o.id}")
    else:  # a deposit identified, its follow-up quoting the request (a standalone letter)
        c0, a0 = _owned(db, case, "KuCoin", kind="exchange_deposit", i=0)
        r = _post_link(inv, case, _owner_link(case, key, c0, a0, ref=f"o{o.id}"))
    assert r.status_code == 303, r.text[:300]
    cid = _cid(r)
    db.expire_all()
    _answer(db, case, which)
    chain, address = (_owned(db, case, "KuCoin", kind="exchange_deposit", i=0 if draft != "status_request" else 1)
                      if deposit else (None, None))
    body = db.get(Correspondence, cid).body_markdown
    # the gate: the draft is stale, no open request; the follow-up their reply calls for is allowed
    st = rg.state(db, case, _kucoin(db, case))
    assert [d.key for d in st.stale] == [f"c{cid}"] and st.open is None and not st.drafts, st
    assert st.stale[0].stale.startswith("drafted before their reply of ")
    assert [d.key for d in st.pointless] == [f"c{cid}"]
    follow = {"info": "info_response", "unclear": "status_request", "frozen": "release_request"}[which]
    for tpl in {follow, "status_request"}:
        d = _gate(db, case, key, tpl, ref=f"o{o.id}")
        assert d.kind == rg.ALLOW, (tpl, d.kind, d.text)
    d = _gate(db, case, key, "stop_order")
    assert d.kind == rg.FOLLOW_UP_ONLY and "open it and send it" not in d.text, (d.kind, d.text)
    if deposit:  # a new deposit: its follow-up quoting the request, never added to the stale draft
        d = _gate(db, case, key, "info_request", about=[f"{chain}:{address}"])
        assert d.kind == rg.FOLLOW_UP_ONLY and d.about and f"ref=o{o.id}" in d.href, (d.kind, d.text)
        assert _gate(db, case, key, "info_request", about=[f"{chain}:{address}"], ref=f"o{o.id}").allowed
    # the board: no button sends the stale draft or adds to it; the reply's own step stays; the draft is flagged
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert f"/authorities/correspondence/{cid}" not in _hrefs(t), _hrefs(t)
    assert not any(s.kind == "add" or (s.label or "").startswith("Add ") for s in _buttons(t)), _buttons(t)
    labels = [s.label for s in _buttons(t)]
    if which == "info":
        assert "Answer their questions" in labels, labels
        if draft == "status_request" and not deposit:
            assert t.step.kind == "answer", t.step
    elif which == "unclear":
        assert t.step.label == "Confirm the freeze", labels
    assert [(p["key"], p["kind"]) for p in t.pointless] == [(f"c{cid}", "letter")]
    assert "drafted before their reply of" in t.pointless[0]["text"], t.pointless
    # the Recovery plan: no move sends the stale draft or adds the deposit to it
    plan, moves = _kuc_moves(db, case)
    for m in plan.moves + plan.waiting:
        if m.authority is not None and m.authority.name == "KuCoin":
            assert not any(f"/correspondence/{cid}" in (x.get("href") or "") for x in m.actions), m.key
            assert not any(str(x.get("label", "")).startswith("Add ") for x in m.actions), m.key
            assert not m.title.startswith("Add "), m.title
    if which == "info":
        assert any(m.kind == "answer" and m.title == "Answer KuCoin's questions" for m in moves), \
            [(m.key, m.kind, m.title) for m in moves]
    if deposit:
        m = plan.find(f"owner:{chain}:{address}")
        assert m is not None and m.kind != "send" and not m.title.startswith("Add "), (m.kind, m.title)
        href, text = _panel_link(inv, case, address)  # the owners panel: the follow-up quoting the request
        assert not text.startswith("Add ") and "template=info_request" in href and "ref=" in href, (href, text)
    # the POST: the answer their reply calls for is drafted (never a 409 on the stale draft)
    r = _post(inv, case, key, template=follow, ref=f"o{o.id}")
    assert r.status_code == 303, r.text[:300]
    new = _cid(r)
    assert new != cid and (db.get(Correspondence, new).meta or {}).get("template_key") == follow
    if deposit:  # the deposit, once that answer is drafted, goes into it (the one open request), never the stale one
        d = _gate(db, case, key, "info_request", about=[f"{chain}:{address}"], ref=f"o{o.id}")
        assert d.kind == rg.ADD_TO_DRAFT and d.key == f"c{new}", (d.kind, d.text)
    db.expire_all()
    assert db.get(Correspondence, cid).body_markdown == body  # nothing added to the stale draft
    # the tab renders the flag; only a case admin discards it ("drafted before their reply")
    tab = inv.get(f"/cases/{case.id}?tab=authorities").text
    assert f"Draft letter #{cid} is pointless" in tab and "drafted before their reply of" in tab
    tok = csrf_token(inv, f"/cases/{case.id}?tab=authorities")
    assert inv.post(f"/cases/{case.id}/authorities/correspondence/{cid}/discard", data={"csrf_token": tok},
                    follow_redirects=False).status_code == 403
    admin = client_for("admin", case=case, email=f"r12-adm-{which}-{draft}-{deposit}@tests.example")
    tok = csrf_token(admin, f"/cases/{case.id}?tab=authorities")
    r = admin.post(f"/cases/{case.id}/authorities/correspondence/{cid}/discard", data={"csrf_token": tok},
                   follow_redirects=False)
    assert r.status_code == 303, r.text[:300]
    db.expire_all()
    assert (db.get(Correspondence, cid).meta or {}).get("discarded")
    assert not rg.state(db, case, _kucoin(db, case)).stale


def test_the_info_response_page_offers_the_answer_not_the_stale_status_request(client_for, db, case):
    o = _order(case, "KuCoin")
    key = _t(_board(db, case), "KuCoin").key
    inv = client_for("investigator", case=case, email="r12-page@tests.example")
    cid = _cid(_post(inv, case, key, template="status_request", ref=f"o{o.id}"))
    db.expire_all()
    _answer(db, case, "info")
    page = inv.get(f"/cases/{case.id}/authorities/{key}?template=info_response&ref=o{o.id}").text
    assert f"Open &amp; send draft letter #{cid}" not in page and f"Draft letter #{cid} to KuCoin is not sent" not in page


def test_a_status_request_on_a_sent_letter_is_stale_after_their_reply(client_for, db, case):
    """A standalone follow-up (a status request quoting a sent owner letter, no stop order) drafted before the reply."""
    _uncontacted_kucoin(db, case)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=0)
    key = _t(_board(db, case), "KuCoin").key
    inv = client_for("investigator", case=case, email="r12-letter@tests.example")
    r = _post_link(inv, case, _owner_link(case, key, chain, address))
    assert r.status_code == 303, r.text[:300]
    letter = db.get(Correspondence, _cid(r))
    desk.mark_sent(db, case, letter, actor=None, sent_at=NOW - timedelta(hours=30), channel="email")
    r = _post(inv, case, key, template="status_request", ref=f"c{letter.id}")
    assert r.status_code == 303, r.text[:300]
    cid = _cid(r)
    assert (db.get(Correspondence, cid).meta or {}).get("references") == f"c{letter.id}"
    assert _gate(db, case, key, "status_request", ref=f"c{letter.id}").kind == rg.OPEN_EXISTING  # not stale yet
    _letter_reply(db, case, "KuCoin", letter, INFO_Q, NOW - timedelta(minutes=20))
    db.commit()
    st = rg.state(db, case, _kucoin(db, case))
    assert [d.key for d in st.stale] == [f"c{cid}"] and st.open is None
    assert _gate(db, case, key, "info_response", ref=f"c{letter.id}").allowed
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert f"/authorities/correspondence/{cid}" not in _hrefs(t) and t.step.label, (t.step, _hrefs(t))
    assert [p["key"] for p in t.pointless] == [f"c{cid}"]
    assert _post(inv, case, key, template="info_response", ref=f"c{letter.id}").status_code == 303


@pytest.mark.parametrize("draft", ["status_request", "info_response"])
def test_a_follow_up_drafted_after_their_reply_stays_the_open_request(client_for, db, case, draft):
    o = _order(case, "KuCoin")
    key = _t(_board(db, case), "KuCoin").key
    _answer(db, case, "info")
    inv = client_for("investigator", case=case, email=f"r12-after-{draft}@tests.example")
    r = _post(inv, case, key, template=draft, ref=f"o{o.id}")
    assert r.status_code == 303, r.text[:300]
    cid = _cid(r)
    st = rg.state(db, case, _kucoin(db, case))
    assert not st.stale and st.open is not None and st.open.key == f"c{cid}"
    other = "info_response" if draft == "status_request" else "status_request"
    d = _gate(db, case, key, other, ref=f"o{o.id}")
    assert d.kind == rg.OPEN_EXISTING and d.key == f"c{cid}", (d.kind, d.text)
    assert not _t(_board(db, case, access=_access(case, "admin")), "KuCoin").pointless


# --------------------------------------------------------------------------- records only, then "no assets"
def test_no_stop_order_after_a_records_only_request_answered_no_assets(client_for, db, case):
    _uncontacted_kucoin(db, case)
    a = _kucoin(db, case)
    c = desk.generate_letter(db, case, a, "info_request", actor=None, run=services.latest_run(db, case),
                             extra_note="Please preserve the order records and say where the payout went.",
                             about=["ethereum:0x" + "cd" * 20])
    desk.mark_sent(db, case, c, actor=None, sent_at=NOW - timedelta(hours=30), channel="email")
    key = _t(_board(db, case), "KuCoin").key
    assert _gate(db, case, key, "stop_order").allowed  # unanswered: the freeze ask it lacked
    _letter_reply(db, case, "KuCoin", c, NO_ASSETS, NOW - timedelta(minutes=20))
    db.commit()
    st = rg.state(db, case, _kucoin(db, case))
    assert st.answer == "declined_no_assets" and st.money and not st.freeze_asked
    d = _gate(db, case, key, "stop_order")
    assert d.kind == rg.FOLLOW_UP_ONLY and "no account / no assets" in d.text and d.key == f"c{c.id}", d.text
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert not t.draftable and not any((s.post or "").endswith("/stop-orders") for s in _buttons(t))
    inv = client_for("investigator", case=case, email="r12-noassets@tests.example")
    before = _requests(db, case)
    r = _post(inv, case, key, template="stop_order")
    assert r.status_code == 409 and "no account / no assets" in r.json()["detail"]
    assert _requests(db, case) == before
    assert _gate(db, case, key, "status_request", ref=f"c{c.id}").allowed  # its follow-up stays open


# --------------------------------------------------------------------------- a swap order at an uncontacted provider
def test_a_swap_order_at_an_uncontacted_provider_leads_with_the_stop_order_citing_it(client_for, db, case):
    _uncontacted_kucoin(db, case)
    chain, address = _owned(db, case, "KuCoin", kind="swap_bridge", i=0)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    # the board: the stop order is the step, no records-only letter on the row; the swap address named
    assert t.step.post == f"/cases/{case.id}/stop-orders" and t.draftable, t.step
    assert "template=info_request" not in _hrefs(t), _hrefs(t)
    assert any(o.get("short") == rp._short(address) for o in t.owners), t.owners
    # the plan: one move, the stop order (the records move folded into it)
    plan, moves = _kuc_moves(db, case)
    assert [m.key for m in moves] == [t.key] and "template=stop_order" in (moves[0].href or "")
    assert rp._short(address) in moves[0].text and "order records" in moves[0].text
    assert not any(m.key == f"owner:{chain}:{address}" for m in plan.moves + plan.waiting)
    assert any(m.key == f"owner:{chain}:{address}" for m in plan.owner_moves())
    inv = client_for("investigator", case=case, email="r12-swap@tests.example")
    href, text = _panel_link(inv, case, address)  # the owners panel: the stop order too
    assert "template=stop_order" in href and "order records" in text, (href, text)
    # the generator's stop order cites the swap address, its records asked for
    r = _generate(inv, case, entity="KuCoin")
    assert r.status_code == 303, r.text[:300]
    db.expire_all()
    o = next(o for o in _kucoin(db, case).stop_orders if o.status == StopOrderStatus.DRAFT)
    ident = next(x for x in o.identifiers["addresses"] if str(x.get("address")).lower() == address.lower())
    assert "order records" in ident["label"] and address.lower() in o.body_markdown.lower()
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert t.step.kind == "send" and "template=info_request" not in _hrefs(t), (t.step, _hrefs(t))


def test_a_records_only_draft_never_holds_the_freeze_ask_back(client_for, db, case):
    _uncontacted_kucoin(db, case)
    a = _kucoin(db, case)
    swap = "ethereum:0x" + "cd" * 20
    c = desk.generate_letter(db, case, a, "info_request", actor=None, run=services.latest_run(db, case),
                             extra_note="Please preserve the order records and say where the payout went.",
                             about=[swap])
    key = _t(_board(db, case), "KuCoin").key
    st = rg.state(db, case, _kucoin(db, case))
    fo = rg.freeze_over_records(st)
    assert fo is not None and fo["key"] == f"c{c.id}"
    # the board: the stop order replacing the draft leads, sending the draft as it is the next button
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert t.step.label == f"Draft freeze request (replaces draft letter #{c.id})", t.step
    assert t.step.href == f"/cases/{case.id}/authorities/{key}?template=stop_order#generate"
    assert any(s.kind == "send" and s.href.endswith(f"/correspondence/{c.id}") for s in t.extra), t.extra
    # the plan: the same first action
    _plan, moves = _kuc_moves(db, case)
    m = next(m for m in moves if m.key == f"c{c.id}")
    assert m.actions[0]["label"] == t.step.label and m.href == t.step.href and m.kind == "request"
    # the page's "replaces draft" option: the stop order cites the swap address, its records asked for
    inv = client_for("investigator", case=case, email="r12-replace@tests.example")
    page = inv.get(f"/cases/{case.id}/authorities/{key}?template=stop_order").text
    assert f"replaces draft letter #{c.id}" in page
    r = _post(inv, case, key, template="stop_order", replace_draft=f"c{c.id}")
    assert r.status_code == 303, r.text[:300]
    db.expire_all()
    assert (db.get(Correspondence, c.id).meta or {}).get("superseded_by")
    o = next(o for o in _kucoin(db, case).stop_orders if o.status == StopOrderStatus.DRAFT)
    ident = next(x for x in o.identifiers["addresses"] if str(x.get("address")).lower() == swap.split(":")[1])
    assert "order records" in ident["label"]
    assert rg.freeze_over_records(rg.state(db, case, _kucoin(db, case))) is None


def test_a_freeze_asking_draft_is_never_replaced_by_the_records_rule(db, case):
    _uncontacted_kucoin(db, case)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=0)
    a = _kucoin(db, case)
    desk.generate_letter(db, case, a, "info_request", actor=None, run=services.latest_run(db, case),
                         freeze=f"{chain}:{address}")
    assert rg.freeze_over_records(rg.state(db, case, _kucoin(db, case))) is None
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert not t.step.label.startswith("Draft freeze request (replaces"), t.step
