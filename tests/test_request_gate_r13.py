"""Review round 13 of the request gate (app.domain.request_gate) as regressions: ONE source of truth for a provider's
next step — the Recovery plan's move for a provider takes its primary action, href, kind and whether it is actionable
from the freeze board's row for it (freeze_board.provider_target); a POINTLESS draft (the provider answered LE only /
court order / declined, a follow-up drafted before their reply, a first contact its playbook gates) is never e-mailed —
compose, Send and the stop order's e-mail route refuse it, the awaiting-Send banner leaves it out, no page links it as
"send"; "Redraft from trace #N" only where the gate lets a stop order replace that draft; a follow-up whose e-mail is
prepared stays the open request (held, never stale). Plus the invariant: over a matrix of provider states, the board
row's step and the plan's provider move have the same action (href or form) and kind. The demo case plus
synthetic replies (every address, ticket and number is made up). Offline."""

import html
from datetime import timedelta
from types import SimpleNamespace

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
    _letter,
    _order,
    _owned,
    _reply,
    _t,
    _uncontacted_kucoin,
)
from test_mail_compose_send import FakeSettings, FakeTransport, _send
from test_request_gate import DECLINE, _kucoin, _panel_link, _requests, _skill
from test_request_gate_r12 import INFO_Q

from app import services
from app.ai import providers
from app.blocks import freeze_board as fb
from app.blocks import recovery as rp
from app.db.models import Correspondence, MailMessage, MailStatus
from app.domain import correspondence as desk
from app.domain import mail_compose as compose
from app.domain import mail_send
from app.domain import playbook as pbm
from app.domain import request_gate as rg

ANSWERS = {"court": CIRCLE_COURT.replace("Circle", "KuCoin"), "le_only": TETHER_LOCAL_LE.replace("Tether", "KuCoin"),
           "declined": DECLINE, "stale": INFO_Q}


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


@pytest.fixture
def mail(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(tmp_path / "vault"))
    settings, transport = FakeSettings(), FakeTransport()
    monkeypatch.setattr(mail_send, "_settings", lambda: settings)
    monkeypatch.setattr(mail_send, "_transport", lambda: transport)
    return SimpleNamespace(settings=settings, transport=transport)


def _gate_kucoin(monkeypatch):
    """KuCoin's playbook acts on LE requests only for our requester (a real Playbook.gate answer, other providers
    as they are)."""
    real = pbm.Playbook.gate

    def gate(self, requester, held=(), name="this provider"):
        if "kucoin" in self.key.lower():
            return pbm.Gate(open=(), le_only=True, needs=(),
                            reason=f"{pbm.LE_ONLY_REASON}: {name} acts only on requests from law enforcement")
        return real(self, requester, held, name=name)

    monkeypatch.setattr(pbm.Playbook, "gate", gate)


def _post(client, case, key, **data):
    tok = csrf_token(client, f"/cases/{case.id}/authorities/{key}")
    return client.post(f"/cases/{case.id}/authorities/{key}/letters", data={"csrf_token": tok, **data},
                       follow_redirects=False)


def _cid(r) -> int:
    return int(r.headers["location"].split("?")[0].rsplit("/", 1)[1])


def _compose_form(client, case, corr) -> dict:
    page = client.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email")
    assert page.status_code == 200, page.text[:400]
    import re

    return {"csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1),
            "draft_hash": re.search(r'name="draft_hash" value="([^"]+)"', page.text).group(1),
            "subject": (corr.subject or "Request")[:200], "to_other": "desk@provider-demo.example",
            "attach": ["letter"]}


def _prepare(client, db, case, corr) -> MailMessage:
    r = client.post(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email",
                    data=_compose_form(client, case, corr), follow_redirects=False)
    assert r.status_code == 303 and "/mail/messages/" in r.headers["location"], r.text[:400]
    db.expire_all()
    return db.get(MailMessage, int(r.headers["location"].rsplit("/", 1)[1]))


def _plan_move(plan, name="KuCoin"):
    """The provider's own move in the plan (not an owner / wallet move)."""
    ms = [m for m in plan.moves + plan.waiting if m.authority is not None and m.authority.name == name
          and ":" not in m.key]
    assert len(ms) == 1, [(m.key, m.kind, m.title) for m in ms]
    return ms[0]


def _primary(m) -> dict | None:
    return next((x for x in m.actions if x.get("primary")), None)


def _same_step(t, m) -> None:
    """THE invariant: the board row's step and the plan's provider move are one action (href or form) and one kind."""
    s = t.step
    kind = rp.step_kind(s.kind)
    assert m.target is not None, m.key
    if kind in fb.LE_KINDS:
        assert m.kind in fb.LE_KINDS, (s, m.kind, m.title)
    else:
        assert m.kind == kind, (s, m.kind, m.title)
    if s.label and (s.href or s.post):
        p = _primary(m)
        assert m.actionable and p is not None, (s, m.actions)
        if s.href:
            assert p.get("href") == s.href and m.href == s.href, (s, p, m.href)
        else:
            assert p.get("post") == s.post and p.get("fields") == s.fields, (s, p)
    else:
        assert not m.actionable and _primary(m) is None, (s, m.actions)


# --------------------------------------------------------------------------- a pointless draft is never e-mailed
@pytest.mark.parametrize("why", ["stale", "court", "le_only", "declined", "gated"])
def test_a_pointless_draft_is_never_prepared_or_e_mailed(client_for, db, case, mail, monkeypatch, why):
    inv = client_for("investigator", case=case, email=f"r13-pl-{why}@tests.example")
    if why == "gated":  # a first-contact stop order to a provider whose playbook gates our requester
        o = _uncontacted_kucoin(db, case, draft=True)
        corr, _ = compose.ensure_correspondence(db, o, _kucoin(db, case), None)
        _gate_kucoin(monkeypatch)
        key = f"o{o.id}"
    else:  # a status request on the sent stop order, then their answer
        o = _order(case, "KuCoin")
        r = _post(inv, case, _t(_board(db, case), "KuCoin").key, template="status_request", ref=f"o{o.id}")
        corr = db.get(Correspondence, _cid(r))
        db.expire_all()
        _reply(db, case, _order(case, "KuCoin"), ANSWERS[why], NOW - timedelta(minutes=10))
        key = f"c{corr.id}"
    st = rg.state(db, case, _kucoin(db, case))
    assert [p.key for p in st.pointless] == [key], st.pointless
    # the letter page: the warning, no "Edit & send e-mail"
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}").text
    assert 'id="draft-pointless"' in page and f"/correspondence/{corr.id}/email" not in page
    # compose: the page and every button (save, prepare, send now) refused, nothing prepared
    url = f"/cases/{case.id}/authorities/correspondence/{corr.id}/email"
    r = inv.get(url)
    assert r.status_code == 409 and "is pointless" in r.text and "discard it" in r.text, r.text[:300]
    tok = csrf_token(inv, f"/cases/{case.id}/authorities/correspondence/{corr.id}")
    for action in ("", "save", "prepare"):
        r = inv.post(url, data={"csrf_token": tok, "draft_hash": compose.draft_hash(corr), "action": action,
                                "to_other": "desk@provider-demo.example", "subject": "x", "attach": ["letter"]},
                     follow_redirects=False)
        assert r.status_code == 409 and "is pointless" in r.text, (action, r.status_code, r.text[:300])
    assert not db.query(MailMessage).filter(MailMessage.correspondence_id == corr.id).count()
    if why == "gated":  # the stop order's own e-mail route and page: no e-mail either
        r = inv.post(f"/cases/{case.id}/stop-orders/{o.id}/email",
                     data={"csrf_token": csrf_token(inv, f"/cases/{case.id}/stop-orders/{o.id}")},
                     follow_redirects=False)
        assert r.status_code == 409 and "is pointless" in r.text, r.text[:300]
        page = inv.get(f"/cases/{case.id}/stop-orders/{o.id}").text
        assert 'id="draft-pointless"' in page and f"/stop-orders/{o.id}/email" not in page


@pytest.mark.parametrize("why", ["court", "le_only", "declined", "gated"])
def test_send_refuses_a_prepared_e_mail_whose_draft_became_pointless(client_for, client, db, case, mail, monkeypatch,
                                                                     why):
    inv = client_for("investigator", case=case, email=f"r13-send-{why}@tests.example")
    if why == "gated":
        o = _uncontacted_kucoin(db, case, draft=True)
        corr, _ = compose.ensure_correspondence(db, o, _kucoin(db, case), None)
    else:
        o = _order(case, "KuCoin")
        r = _post(inv, case, _t(_board(db, case), "KuCoin").key, template="status_request", ref=f"o{o.id}")
        corr = db.get(Correspondence, _cid(r))
    mm = _prepare(inv, db, case, corr)
    assert mm.status == MailStatus.PREPARED
    if why == "gated":
        _gate_kucoin(monkeypatch)
    else:
        _reply(db, case, _order(case, "KuCoin"), ANSWERS[why], NOW - timedelta(minutes=10))
    assert compose.pointless_text(db, db.get(Correspondence, corr.id))
    # the e-mail's page says so and has no Send form; the Authorities tab never invites it
    page = client.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    assert 'id="mail-pointless"' in page and "is pointless" in page
    tab = client.get(f"/cases/{case.id}?tab=authorities").text
    assert f"e-mail #{mm.id} for letter #{corr.id}" not in tab
    # Send: refused, nothing goes out
    db.expire_all()
    r = _send(client, case, db.get(MailMessage, mm.id), ack_sender="1", ack_sender_reason="reviewed by the admin")
    assert r.status_code == 409 and "is pointless" in r.text, (r.status_code, r.text[:300])
    assert mail.transport.sent == []
    db.expire_all()
    assert db.get(MailMessage, mm.id).status == MailStatus.PREPARED
    with pytest.raises(mail_send.SendError) as err:
        mail_send._check_preconditions(db, SimpleNamespace(case=case), db.get(MailMessage, mm.id), {})
    assert err.value.args and "is pointless" in str(err.value)


def test_a_draft_that_is_not_pointless_is_still_prepared_and_sent(client_for, client, db, case, mail):
    o = _order(case, "KuCoin")
    inv = client_for("investigator", case=case, email="r13-send-ok@tests.example")
    r = _post(inv, case, _t(_board(db, case), "KuCoin").key, template="status_request", ref=f"o{o.id}")
    corr = db.get(Correspondence, _cid(r))
    assert compose.pointless_text(db, corr) is None
    mm = _prepare(inv, db, case, corr)
    tab = client.get(f"/cases/{case.id}?tab=authorities").text
    assert f"e-mail #{mm.id} for letter #{corr.id}" in tab
    r = _send(client, case, mm, ack_sender="1", ack_sender_reason="reviewed by the admin")
    assert r.status_code == 303 and "r=sent" in r.headers["location"], r.text[:300]
    assert len(mail.transport.sent) == 1


# --------------------------------------------------------------------------- a prepared stale follow-up is held
def test_a_follow_up_whose_e_mail_is_prepared_stays_the_open_request_after_their_reply(client_for, db, case, mail):
    o = _order(case, "KuCoin")
    key = _t(_board(db, case), "KuCoin").key
    inv = client_for("investigator", case=case, email="r13-held@tests.example")
    corr = db.get(Correspondence, _cid(_post(inv, case, key, template="status_request", ref=f"o{o.id}")))
    mm = _prepare(inv, db, case, corr)
    _reply(db, case, _order(case, "KuCoin"), INFO_Q, NOW - timedelta(minutes=10))
    st = rg.state(db, case, _kucoin(db, case))
    assert not st.stale and not st.pointless and st.open is not None and st.open.key == f"c{corr.id}"
    assert st.open.late and st.open.late.startswith("drafted before their reply")
    d = _gate(db, case, key, "info_response", ref=f"o{o.id}")
    assert d.kind == rg.OPEN_EXISTING and d.key == f"c{corr.id}" and f"cancel e-mail #{mm.id}" in d.text, d.text
    before = _requests(db, case)
    r = _post(inv, case, key, template="info_response", ref=f"o{o.id}")
    assert r.status_code == 409 and _requests(db, case) == before
    # the board and the plan lead with that e-mail (the answer the gate refuses beside it is the next button)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert t.step.href == f"/cases/{case.id}/mail/messages/{mm.id}" and "drafted before their reply" in t.step.label
    assert any(s.label == "Answer their questions" for s in t.extra), t.extra
    _same_step(t, _plan_move(rp.build(db, case)))
    # its e-mail cancelled: the draft is stale (pointless) and the answer their reply calls for is drafted
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    mm.status = MailStatus.CANCELLED
    db.commit()
    st = rg.state(db, case, _kucoin(db, case))
    assert [p.key for p in st.pointless] == [f"c{corr.id}"]
    assert _post(inv, case, key, template="info_response", ref=f"o{o.id}").status_code == 303


# --------------------------------------------------------------------------- the redraft only where the gate allows
@pytest.mark.parametrize("held", ["unknown", "prepared"])
def test_redraft_is_never_offered_over_a_draft_whose_e_mail_may_be_out(client_for, db, case, held):
    o = _uncontacted_kucoin(db, case, draft=True)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert any(s.kind == "redraft" for s in t.extra), t.extra  # control: an earlier trace's draft, nothing out
    corr, _ = compose.ensure_correspondence(db, o, _kucoin(db, case), None)
    db.add(MailMessage(case_id=case.id, correspondence_id=corr.id, letter_key=f"o{o.id}", direction="out",
                       status=held, transport="graph", mailbox="cases@aegis-demo.example",
                       message_id=f"<r13-{corr.id}@aegis-demo.example>", subject="Freeze request",
                       to_addrs=["desk@provider-demo.example"],
                       expires_at=NOW + timedelta(hours=2 if held == "prepared" else -2)))
    db.commit()
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert not any(s.kind == "redraft" or "redraft" in s.fields for s in [t.step, *t.extra]), [t.step, *t.extra]
    assert t.skip is not None and t.skip[0] != "draft_old", t.skip
    m = _plan_move(rp.build(db, case))
    assert not any("redraft" in (x.get("fields") or {}) for x in m.actions), m.actions
    inv = client_for("investigator", case=case, email=f"r13-redraft-{held}@tests.example")
    before = _requests(db, case)
    r = _generate(inv, case, entity="KuCoin", redraft="1")
    assert r.status_code == 303 and "so_skip=" in r.headers["location"] and _requests(db, case) == before


# --------------------------------------------------------------------------- a playbook-gated provider's draft
def test_a_gated_providers_draft_is_never_sent_nor_redrafted_on_any_surface(client_for, db, case, monkeypatch):
    _gate_kucoin(monkeypatch)
    o = _uncontacted_kucoin(db, case, draft=True)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    st = rg.state(db, case, _kucoin(db, case))
    assert st.gated and [p.key for p in st.pointless] == [f"o{o.id}"]
    draft = f"/cases/{case.id}/stop-orders/{o.id}"
    # the board: the LE step, the draft flagged, never sent nor redrafted
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert t.step.kind in fb.LE_KINDS and t.step.label, t.step
    assert draft not in _hrefs(t) and not any(s.kind == "redraft" for s in t.extra), [t.step, *t.extra]
    assert [p["key"] for p in t.pointless] == [f"o{o.id}"]
    # the plan: the same LE step; no action links the draft; the owner move is the LE step too
    plan = rp.build(db, case)
    m = _plan_move(plan)
    assert m.kind in fb.LE_KINDS and not m.title.startswith("Send the drafted"), (m.kind, m.title)
    assert not any(draft in (x.get("href") or "") for x in m.actions) and m.href != draft, m.actions
    own = plan.find(f"owner:{chain}:{address}")
    assert own is not None and own.kind == "le" and not any(draft in (x.get("href") or "") for x in own.actions)
    inv = client_for("investigator", case=case, email="r13-gated@tests.example")
    page = inv.get(f"/cases/{case.id}/recovery-plan").text
    assert f'href="{draft}"' not in page and "Send the drafted request to KuCoin" not in page
    # the owners panel and the assistant: the LE step, no draft of KuCoin's
    href, _text = _panel_link(inv, case, address)
    assert "template=le_" in href or "/authorities/le-" in href, href
    res = _skill(db, case, inv)
    assert not res.drafts and f"stop-orders/{o.id}" not in res.markdown, res.markdown
    before = _requests(db, case)
    r = _generate(inv, case, entity="KuCoin", redraft="1")
    assert "so_skip=" in r.headers["location"] and _requests(db, case) == before


# --------------------------------------------------------------------------- records-only request sent, funds traced
@pytest.mark.parametrize("name", ["KuCoin", "Circle (USDC issuer)"])
def test_a_sent_records_request_leads_with_the_stop_order_on_the_board_and_the_plan(client_for, db, case, name):
    if name == "KuCoin":
        _uncontacted_kucoin(db, case)
    _letter(db, case, name, "info_request")
    t = _t(_board(db, case, access=_access(case, "admin")), name)
    m = _plan_move(rp.build(db, case), name)
    _same_step(t, m)
    if name == "KuCoin":
        assert t.step.label == "Draft freeze request" and t.step.post == f"/cases/{case.id}/stop-orders", t.step
        assert m.actionable and m.kind == "request" and m.title == "Send a stop order to KuCoin", (m.kind, m.title)
        assert _gate(db, case, t.key, "stop_order").allowed
        inv = client_for("investigator", case=case, email="r13-records@tests.example")
        page = html.unescape(inv.get(f"/cases/{case.id}/recovery-plan").text)
        assert f'action="/cases/{case.id}/stop-orders"' in page and 'value="KuCoin"' in page
        # drafted: both send that stop order
        r = _generate(inv, case, entity="KuCoin")
        assert r.status_code == 303 and "so_n=1" in r.headers["location"], r.headers["location"]
        t = _t(_board(db, case, access=_access(case, "admin")), name)
        m = _plan_move(rp.build(db, case), name)
        assert t.step.kind == "send" and "/stop-orders/" in t.step.href, t.step
        _same_step(t, m)


# --------------------------------------------------------------------------- the invariant
def _prepared_mail(db, case, corr, status="prepared"):
    mm = MailMessage(case_id=case.id, correspondence_id=corr.id, letter_key=f"c{corr.id}", direction="out",
                     status=status, transport="graph", mailbox="cases@aegis-demo.example",
                     message_id=f"<r13-inv-{corr.id}@aegis-demo.example>", subject="Request",
                     to_addrs=["desk@provider-demo.example"], expires_at=NOW + timedelta(hours=2))
    db.add(mm)
    db.commit()
    return mm


def _make(db, case, client, state, monkeypatch):
    """KuCoin in `state`."""
    if state == "uncontacted":
        _uncontacted_kucoin(db, case)
    elif state in ("draft", "draft_prepared", "draft_busy", "gated_draft"):
        o = _uncontacted_kucoin(db, case, draft=True)
        if state != "draft":
            corr, _ = compose.ensure_correspondence(db, o, _kucoin(db, case), None)
            if state == "gated_draft":
                _gate_kucoin(monkeypatch)
            else:
                _prepared_mail(db, case, corr, "prepared" if state == "draft_prepared" else "unknown")
    elif state in ("records_sent", "records_draft"):
        _uncontacted_kucoin(db, case)
        if state == "records_sent":
            _letter(db, case, "KuCoin", "info_request")
        else:
            desk.generate_letter(db, case, _kucoin(db, case), "info_request", actor=None,
                                 run=services.latest_run(db, case), extra_note="Please preserve the order records.",
                                 about=["ethereum:0x" + "cd" * 20])
    elif state == "sent":
        pass  # the demo's sent stop order, awaiting the reply
    elif state == "overdue":
        o = _order(case, "KuCoin")
        o.response_due_at = NOW - timedelta(days=1)
        db.commit()
    elif state in ANSWERS:
        _reply(db, case, _order(case, "KuCoin"), ANSWERS[state], NOW - timedelta(minutes=30))
    elif state == "stale_follow_up":
        o = _order(case, "KuCoin")
        _post(client, case, _t(_board(db, case), "KuCoin").key, template="status_request", ref=f"o{o.id}")
        _reply(db, case, _order(case, "KuCoin"), INFO_Q, NOW - timedelta(minutes=10))
    elif state == "follow_up_draft":
        o = _order(case, "KuCoin")
        _post(client, case, _t(_board(db, case), "KuCoin").key, template="status_request", ref=f"o{o.id}")
    else:
        raise AssertionError(state)


STATES = ("uncontacted", "draft", "draft_prepared", "draft_busy", "gated_draft", "records_sent", "records_draft",
          "sent", "overdue", "court", "le_only", "declined", "stale", "stale_follow_up", "follow_up_draft")


@pytest.mark.parametrize("state", STATES)
def test_the_board_row_and_the_plan_move_of_a_provider_are_one_step(client_for, db, case, monkeypatch, state):
    inv = client_for("investigator", case=case, email=f"r13-inv-{state}@tests.example")
    _make(db, case, inv, state, monkeypatch)
    board = _board(db, case, access=_access(case, "admin"))
    plan = rp.build(db, case)
    for name in ("KuCoin", "Circle (USDC issuer)", "Tether (USDT issuer)"):
        t = _t(board, name)
        if t.owner_led:  # an owner move leads the row: the plan has that owner move of its own
            continue
        ms = [m for m in plan.moves + plan.waiting if m.authority is not None and m.authority.name == name
              and ":" not in m.key]
        if not ms:  # no plan move (closed, nothing to do): nothing to compare
            continue
        _same_step(t, ms[0])
    # no surface links a pointless draft as "send"
    st = rg.state(db, case, _kucoin(db, case))
    gone = {x for r in st.pointless for x in (r.href, r.mail_href) if x}
    t = _t(board, "KuCoin")
    assert not ({s.href for s in [t.step, *t.extra] if s.href} & gone), (gone, [t.step, *t.extra])
    for m in plan.moves + plan.waiting:
        assert not ({x.get("href") for x in m.actions} & gone), (m.key, m.actions)


@pytest.mark.parametrize("kind", ["exchange_deposit", "exchange_hot_wallet"])
def test_a_sent_records_request_then_an_identified_deposit_never_leaves_the_plan_waiting(client_for, db, case, kind):
    _uncontacted_kucoin(db, case)
    key = _t(_board(db, case), "KuCoin").key
    inv = client_for("investigator", case=case, email=f"r13-q8-{kind}@tests.example")
    corr = db.get(Correspondence, _cid(_post(inv, case, key, template="info_request")))
    desk.mark_sent(db, case, corr, actor=None, sent_at=NOW - timedelta(days=1), channel="email")
    _owned(db, case, "KuCoin", kind=kind, i=1)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    plan = rp.build(db, case)
    m = _plan_move(plan)
    # the provider's own move: the stop order (a records-only request asked for no freeze), never "Waiting on KuCoin"
    assert m.actionable and m.kind == "request" and not m.title.startswith("Waiting"), (m.kind, m.title)
    assert _gate(db, case, key, "stop_order").allowed
    # the board row's step is one of the plan's moves (the provider's own, or the owner move that leads the row)
    firsts = [(_primary(x) or {}) for x in plan.moves]
    assert any((p.get("href") == t.step.href if t.step.href else p.get("post") == t.step.post) and p
               for p in firsts), (t.step, firsts[:6])
    if not t.owner_led:
        _same_step(t, m)
