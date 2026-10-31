"""r11 review regressions for the request gate (app.domain.request_gate: one open request per provider).

* an LE-only / court-order / declined answer (and the playbook's LE-only gate) decides before any open draft: a
  follow-up or owner letter drafted before the answer is pointless (flagged on the board, a case admin discards it),
  never "open it and send it" nor the draft a new deposit is added to — on every surface: the gate's text, the board's
  step, the Recovery plan's owner move, the owners panel and the POST;
* a declined row shows the gate's LE step (the LE brief), as an LE-only one does;
* an owner letter for a hot wallet (or a deposit) is a freeze ask (`meta.asks_freeze` / `meta.freeze`): once it is
  sent no generator drafts a stop order next to it, and the board waits on it;
* a draft whose e-mail is busy (sending, unknown outcome, an expired "Draft — you send" checklist) is never edited:
  OPEN_EXISTING, never ADD_TO_DRAFT;
* the authority page's follow-up link (a hot wallet quoting the request out) says it is that follow-up, not another
  template's refusal.

The demo case plus synthetic data (every address and number is made up). Offline."""

import re
from datetime import timedelta

import pytest
from conftest import csrf_token
from test_freeze_board import (
    CIRCLE_COURT,
    NOW,
    TETHER_LOCAL_LE,
    _access,
    _board,
    _gate,
    _generate,
    _hrefs,
    _order,
    _owned,
    _reply,
    _t,
    _uncontacted_kucoin,
)
from test_request_gate import DECLINE, _kucoin, _panel_link, _post_link, _requests, _skill

from app import services
from app.ai import providers
from app.blocks import freeze_board as fb
from app.blocks import recovery as rp
from app.db.models import Correspondence, MailMessage, StopOrder, StopOrderStatus
from app.domain import correspondence as desk
from app.domain import mail_compose as compose
from app.domain import request_gate as rg

ANSWERS = {"court": CIRCLE_COURT.replace("Circle", "KuCoin"), "declined": DECLINE,
           "le_local": TETHER_LOCAL_LE.replace("Tether", "KuCoin")}


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


def _letters_to_draft(t) -> list:
    """The row's buttons that send, add to or draft a letter to the provider itself."""
    return [s for s in [t.step, *t.extra] if s.kind in ("send", "add") or (s.post or "").endswith("/letters")
            or f"/authorities/{t.key}?template=" in (s.href or "")]


# --------------------------------------------------------------------------- LE only / declined before the draft
@pytest.mark.parametrize("deposit", [False, True], ids=["no_deposit", "deposit"])
@pytest.mark.parametrize("draft", ["status_request", "owner_letter"])
@pytest.mark.parametrize("answer", list(ANSWERS))
def test_an_le_only_or_declined_answer_makes_a_draft_drafted_before_it_pointless(client_for, db, case, answer, draft,
                                                                                 deposit):
    o = _order(case, "KuCoin")
    key = _t(_board(db, case), "KuCoin").key
    inv = client_for("investigator", case=case, email=f"r11-le-{answer}-{draft}-{deposit}@tests.example")
    if draft == "status_request":  # a follow-up drafted before the answer (tied to the sent stop order)
        r = _post(inv, case, key, template="status_request", ref=desk.sent_references(_kucoin(db, case))[0]["value"])
    else:  # a deposit identified, its owner letter drafted (a standalone follow-up quoting the request)
        c0, a0 = _owned(db, case, "KuCoin", kind="exchange_deposit", i=0)
        r = _post_link(inv, case, _owner_link(case, key, c0, a0, ref=f"o{o.id}"))
    assert r.status_code == 303, r.text[:300]
    cid = _cid(r)
    db.expire_all()
    _reply(db, case, _order(case, "KuCoin"), ANSWERS[answer], NOW - timedelta(minutes=30))
    # the newly identified deposit (the first wallet left to identify once the owner letter's own is marked)
    chain, address = (_owned(db, case, "KuCoin", kind="exchange_deposit", i=0 if draft == "owner_letter" else 1)
                      if deposit else (None, None))
    body = db.get(Correspondence, cid).body_markdown
    st = rg.state(db, case, _kucoin(db, case))
    assert st.le_only and [d.key for d in st.pointless] == [f"c{cid}"]
    # the gate: the LE brief for every template, the draft named pointless (never "open it and send it")
    for tpl in ("stop_order", "info_request", "status_request"):
        d = _gate(db, case, key, tpl, about=[f"{chain}:{address}"] if deposit and tpl == "info_request" else None)
        assert d.kind == rg.LE_BRIEF_ONLY and d.key == f"o{o.id}", (tpl, d.kind, d.text)
        assert f"letter #{cid}" in d.text and "pointless" in d.text and "open it and send it" not in d.text
    if deposit:
        d = _gate(db, case, key, "info_request", about=[f"{chain}:{address}"])
        assert "/authorities/le-" in d.href, d.href
        if "?template=" in d.href:  # the LE brief names the address; a court order's LE route is its own page
            assert "about=" in d.href and address.lower() in d.href.lower(), d.href
        else:
            assert d.href == _t(_board(db, case, access=_access(case, "admin")), "KuCoin").step.href, d.href
    # the board: the LE step, no button sending / adding to / drafting a letter to KuCoin; the draft flagged
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert t.step.kind in fb.LE_KINDS and t.step.label, (t.step, t.status)
    assert not _letters_to_draft(t), _hrefs(t)
    assert f"/authorities/correspondence/{cid}" not in _hrefs(t)
    assert [(p["key"], p["kind"], p["post"]) for p in t.pointless] == [
        (f"c{cid}", "letter", f"/cases/{case.id}/authorities/correspondence/{cid}/discard")]
    assert not t.draftable and t.skip[0] in ("le_only", "declined")
    # the Recovery plan: no move sends the draft or adds the deposit to it
    plan = rp.build(db, case)
    for m in plan.moves + plan.waiting:
        if m.authority is not None and m.authority.name == "KuCoin" or m.key.startswith("owner:"):
            assert m.kind != "send" and not any(str(x.get("label", "")).startswith("Add ") for x in m.actions), m.key
            assert not any(f"/correspondence/{cid}" in (x.get("href") or "") for x in m.actions), m.key
    if deposit:
        m = plan.find(f"owner:{chain}:{address}")
        assert m is None or (m.kind == "le" and m.cites["state"] == "le")
        href, text = _panel_link(inv, case, address)  # the owners panel: the LE brief, never "Add … to draft"
        assert "/authorities/le-" in href and not text.startswith("Add "), (href, text)
        before = _requests(db, case)
        r = _post_link(inv, case, _owner_link(case, key, chain, address, ref=f"o{o.id}"))  # the bookmarked link
        assert r.status_code == 409 and "brief LE instead" in r.json()["detail"]
        assert _requests(db, case) == before
    db.expire_all()
    assert db.get(Correspondence, cid).body_markdown == body  # nothing added to the pointless draft
    # the tab renders the flag; only a case admin discards it
    tab = inv.get(f"/cases/{case.id}?tab=authorities").text
    assert f"Draft letter #{cid} is pointless" in tab and "a case admin can discard it" in tab
    tok = csrf_token(inv, f"/cases/{case.id}?tab=authorities")
    assert inv.post(f"/cases/{case.id}/authorities/correspondence/{cid}/discard", data={"csrf_token": tok},
                    follow_redirects=False).status_code == 403


@pytest.mark.parametrize("answer", list(ANSWERS))
def test_a_case_admin_discards_the_pointless_draft_and_it_is_never_sent(client_for, db, case, answer):
    key = _t(_board(db, case), "KuCoin").key
    inv = client_for("investigator", case=case, email=f"r11-disc-inv-{answer}@tests.example")
    cid = _cid(_post(inv, case, key, template="status_request",
                     ref=desk.sent_references(_kucoin(db, case))[0]["value"]))
    db.expire_all()
    _reply(db, case, _order(case, "KuCoin"), ANSWERS[answer], NOW - timedelta(minutes=30))
    adm = client_for("admin", case=case, email=f"r11-disc-adm-{answer}@tests.example")
    page = adm.get(f"/cases/{case.id}/authorities/correspondence/{cid}").text
    assert 'id="draft-pointless"' in page and f'action="/cases/{case.id}/authorities/correspondence/{cid}/discard"' in page
    tab = adm.get(f"/cases/{case.id}?tab=authorities").text
    assert f'action="/cases/{case.id}/authorities/correspondence/{cid}/discard"' in tab
    tok = csrf_token(adm, f"/cases/{case.id}?tab=authorities")
    r = adm.post(f"/cases/{case.id}/authorities/correspondence/{cid}/discard", data={"csrf_token": tok},
                 follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("#freeze")
    db.expire_all()
    c = db.get(Correspondence, cid)
    assert c.meta["discarded"]["reason"] == "pointless" and compose.superseded_text(c)
    assert not _t(_board(db, case, access=_access(case, "admin")), "KuCoin").pointless
    assert not rg.state(db, case, _kucoin(db, case)).drafts
    path = f"/cases/{case.id}/authorities/correspondence/{cid}"
    assert adm.post(f"{path}/sent", data={"csrf_token": csrf_token(adm, path)},
                    follow_redirects=False).status_code == 409
    # a letter the board does not flag is never discarded here
    assert adm.post(f"{path}/discard", data={"csrf_token": tok}, follow_redirects=False).status_code == 409


def test_a_pointless_stop_order_draft_is_discarded_through_the_stop_order_route(client_for, db, case):
    """A stop-order draft to a provider that answered LE only (made past the gate, as a case could hold one): the
    board flags it pointless, a case admin discards it (superseded, audited reason "pointless_draft")."""
    o = _order(case, "KuCoin")
    _reply(db, case, o, ANSWERS["court"], NOW - timedelta(minutes=30))
    dup = services.generate_stop_orders(db, case, services.latest_run(db, case), only=["KuCoin"], gate=False)[0]
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    flagged = {d["order_id"] for d in t.duplicates} | {p["id"] for p in t.pointless if p["kind"] == "order"}
    assert dup.id in flagged
    adm = client_for("admin", case=case, email="r11-so-disc@tests.example")
    page = adm.get(f"/cases/{case.id}/stop-orders/{dup.id}").text
    assert f'/stop-orders/{dup.id}/discard"' in page
    tok = csrf_token(adm, f"/cases/{case.id}?tab=authorities")
    r = adm.post(f"/cases/{case.id}/stop-orders/{dup.id}/discard", data={"csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    assert db.get(StopOrder, dup.id).status == StopOrderStatus.SUPERSEDED


def test_the_playbook_gate_decides_before_an_open_first_contact_draft(db, case):
    """A provider whose playbook acts on LE requests only for our requester: a first-contact draft to it is pointless
    (the LE brief, never "send it" or "add to it"); a follow-up draft on a letter already sent stays open."""
    o = _uncontacted_kucoin(db, case, draft=True)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    st = rg.state(db, case, _kucoin(db, case))
    st.gated = "KuCoin acts on law-enforcement requests only"
    for tpl in ("stop_order", "info_request"):
        d = rg.decide(st, tpl, about=[f"{chain}:{address}"] if tpl == "info_request" else None)
        assert d.kind == rg.LE_BRIEF_ONLY and "pointless" in d.text, (tpl, d.kind)
    assert [d.key for d in st.pointless] == [f"o{o.id}"]
    assert rg.decide(st, "status_request").kind == rg.OPEN_EXISTING  # a follow-up is no first contact


@pytest.mark.parametrize("which", ["declined", "court"])
def test_a_declined_row_shows_the_gates_le_step(client_for, db, case, which):
    _reply(db, case, _order(case, "KuCoin"), ANSWERS[which], NOW - timedelta(minutes=30))
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    st = rg.state(db, case, _kucoin(db, case))
    d = rg.decide(st, "stop_order")
    assert t.step.kind in fb.LE_KINDS and t.step.label, (t.status, t.step)
    if which == "declined":
        assert t.status == fb.DECLINED and t.group == fb.NOTHING
        assert t.step.label == d.label() == "Open the LE brief" and t.step.href == st.le_href
        plan = rp.build(db, case)
        m = next(m for m in plan.moves + plan.waiting if m.authority is not None and m.authority.name == "KuCoin")
        assert m.kind == "le" and t.step.href in [x.get("href") for x in m.actions]
        inv = client_for("investigator", case=case, email="r11-declined@tests.example")
        tab = inv.get(f"/cases/{case.id}?tab=authorities").text
        row = tab.split(f'id="fb-{t.key}"', 1)[1].split("</tr>", 1)[0]
        assert "Open the LE brief" in row


# --------------------------------------------------------------------------- hot wallet: a freeze ask
def test_a_sent_hot_wallet_letter_is_a_freeze_ask_no_generator_repeats(client_for, db, case):
    _uncontacted_kucoin(db, case)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_hot_wallet", i=1)
    adm = _access(case, "admin")
    t = _t(_board(db, case, access=adm), "KuCoin")
    href = next(s.href for s in [t.step, *t.extra] if s.href and "template=info_request" in s.href)
    inv = client_for("investigator", case=case, email="r11-hw@tests.example")
    r = _post_link(inv, case, href)
    assert r.status_code == 303, r.text[:300]
    cid = _cid(r)
    db.expire_all()
    c = db.get(Correspondence, cid)
    assert c.meta["asks_freeze"] is True and c.meta["about"] == [f"{chain}:{address}"]
    desk.mark_sent(db, case, c, actor=None, sent_at=NOW - timedelta(hours=3), channel="email")
    board = _board(db, case, access=adm)
    t = _t(board, "KuCoin")
    assert not t.draftable and not t.freeze_open and t.status in (fb.AWAITING, fb.ACKNOWLEDGED)
    assert not any(s.post == f"/cases/{case.id}/stop-orders" and "redraft" not in s.fields
                   for s in [t.step, *t.extra]), [(s.kind, s.label) for s in [t.step, *t.extra]]
    assert "Draft freeze request" not in [s.label for s in [t.step, *t.extra]]
    assert rg.state(db, case, _kucoin(db, case)).freeze_asked
    assert _gate(db, case, t.key, "stop_order").kind == rg.FOLLOW_UP_ONLY
    # the Recovery plan waits on it as well
    plan = rp.build(db, case)
    m = next(m for m in plan.moves + plan.waiting if m.authority is not None and m.authority.name == "KuCoin")
    assert m.key == f"c{cid}" and "Waiting on KuCoin" in m.title
    # the row, bulk, API and assistant generators draft nothing
    before = _requests(db, case)
    q = _generate(inv, case, entity="KuCoin").headers["location"]
    assert "so_n=0" in q and f"{t.key}%3Asent%3Ac{cid}" in q
    _generate(inv, case)
    tok = csrf_token(inv, f"/cases/{case.id}?tab=authorities")
    r = inv.post(f"/api/cases/{case.id}/stop-orders", json=["KuCoin"], headers={"X-CSRF-Token": tok})
    assert r.json() == []
    assert not _skill(db, case, inv).drafts
    assert _post(inv, case, t.key, template="stop_order").status_code == 409
    assert _requests(db, case) == before


def test_a_records_only_letter_is_no_freeze_ask(db, case):
    _uncontacted_kucoin(db, case)
    a = _kucoin(db, case)
    c = desk.generate_letter(db, case, a, "info_request", actor=None, run=services.latest_run(db, case),
                             extra_note="Please preserve the order records and say where the payout went.",
                             about=["ethereum:0x" + "cd" * 20])
    assert not (c.meta or {}).get("asks_freeze")
    assert desk.asks_freeze("info_request", a, ["ethereum:0x" + "cd" * 20],
                            note="Identify the customer account they were credited to, freeze it.")
    assert desk.asks_freeze("info_request", a, [], freeze="ethereum:0x" + "cd" * 20)
    assert not desk.asks_freeze("status_request", a, ["ethereum:0x" + "cd" * 20], note="freeze it")
    assert not desk.asks_freeze("info_request", a, ["ethereum:0x" + "cd" * 20], note="see the blockchain records")


# --------------------------------------------------------------------------- busy drafts are never edited
@pytest.mark.parametrize("status", ["unknown", "sending", "expired_manual"])
def test_a_draft_whose_e_mail_may_be_out_is_never_added_to(client_for, db, case, status):
    o = _uncontacted_kucoin(db, case, draft=True)
    corr, _ = compose.ensure_correspondence(db, o, _kucoin(db, case), None)
    manual = status == "expired_manual"
    mm = MailMessage(case_id=case.id, correspondence_id=corr.id, letter_key=f"o{o.id}", direction="out",
                     status="expired" if manual else status, transport="manual" if manual else "graph",
                     mailbox="cases@aegis-demo.example", message_id=f"<r11-{status}-{corr.id}@aegis-demo.example>",
                     subject="Freeze request", to_addrs=["desk@provider-demo.example"],
                     expires_at=NOW - timedelta(hours=2))
    db.add(mm)
    db.commit()
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    key = _t(_board(db, case), "KuCoin").key
    body = db.get(StopOrder, o.id).body_markdown
    d = _gate(db, case, key, "info_request", about=[f"{chain}:{address}"])
    assert d.kind == rg.OPEN_EXISTING and d.key == f"o{o.id}" and f"#{mm.id}" in d.text, (d.kind, d.text)
    assert d.href == f"/cases/{case.id}/mail/messages/{mm.id}" and "follow-up once it is out" in d.text
    assert _gate(db, case, key, "stop_order", replace={f"o{o.id}"}).kind == rg.OPEN_EXISTING  # never replaced either
    inv = client_for("investigator", case=case, email=f"r11-busy-{status}@tests.example")
    before = _requests(db, case)
    r = _post_link(inv, case, _owner_link(case, key, chain, address))
    assert r.status_code == 409 and f"#{mm.id}" in r.json()["detail"], r.text[:300]
    assert _requests(db, case) == before
    db.expire_all()
    o = db.get(StopOrder, o.id)
    assert o.body_markdown == body and address not in str(o.identifiers)
    # the board: open that e-mail (settle it), never "add the deposit to the draft"
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert t.step.href == f"/cases/{case.id}/mail/messages/{mm.id}" and t.step.label.startswith(f"Open e-mail #{mm.id}")
    assert not any(s.kind == "add" for s in [t.step, *t.extra])
    # a stale ADD_TO_DRAFT decision (read before the e-mail existed) is refused by add_to_draft itself
    st = rg.state(db, case, _kucoin(db, case))
    stale = rg.Decision(rg.ADD_TO_DRAFT, request=st.open, about=[f"{chain}:{address}"])
    with pytest.raises(ValueError, match="nothing is added"):
        rg.add_to_draft(db, case, _kucoin(db, case), stale)


# --------------------------------------------------------------------------- the authority page's follow-up link
def test_the_follow_up_link_says_it_is_the_follow_up_not_the_stop_orders_refusal(client_for, db, case):
    _owned(db, case, "KuCoin", kind="exchange_hot_wallet", i=1)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    href = next(s.href for s in [t.step, *t.extra] if s.href and "template=info_request" in s.href)
    o = _order(case, "KuCoin")
    inv = client_for("investigator", case=case, email="r11-page@tests.example")
    page = inv.get(href).text
    gate = re.search(r'id="request-gate"[^>]*>(.*?)</div>', page, re.DOTALL)
    assert gate is not None
    text = re.sub(r"<[^>]+>", " ", gate.group(1))
    assert f"This is the follow-up to request #{o.id}" in text and "never a second request; wait" not in text
    assert re.search(r'<option value="info_request"\s+selected', page)
    assert _post_link(inv, case, href).status_code == 303
    # a stop order is still refused there, by its own POST
    assert _post(inv, case, t.key, template="stop_order").status_code == 409
