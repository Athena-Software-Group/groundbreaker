"""Review round 14 of the request gate (app.domain.request_gate) as regressions: a DUPLICATE draft the board flags (a
legacy generated stop order for a provider a freeze request already went to) is refused at prepare and Send time like a
pointless one (the stop order's e-mail route, compose, Send: "Draft #N duplicates request #M; discard it"), and its
prepared e-mail is no call to Send; the provider's authority page never offers to e-mail a pointless or duplicate
draft (no "Edit & send e-mail", no "e-mail awaiting Send" tag: the board's flag and its discard instead); the
assistant's /stop-orders never recommends a stop order the gate refuses (a playbook-gated provider: its row's LE
step); a move whose kind the board's step changed keeps no text of the old kind; every surface names one LE for a
provider's LE step; a held follow-up drafted before their reply keeps that warning when an owner deposit leads the row.
The demo case plus synthetic replies (every address, ticket and number is made up). Offline."""

import html
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
    _le_only,
    _legacy,
    _order,
    _owned,
    _reply,
    _t,
    _uncontacted_kucoin,
)
from test_mail_compose_send import _send
from test_request_gate import DECLINE, _kucoin, _panel_link
from test_request_gate_r12 import INFO_Q
from test_request_gate_r13 import _cid, _gate_kucoin, _plan_move, _post, _prepare, _prepared_mail

from app import services
from app.ai import providers
from app.blocks import freeze_board as fb
from app.blocks import recovery as rp
from app.db.models import Correspondence, MailMessage, MailStatus
from app.domain import correspondence as desk
from app.domain import mail_compose as compose
from app.domain import mail_send
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
    from types import SimpleNamespace

    from test_mail_compose_send import FakeSettings, FakeTransport

    monkeypatch.setenv("AEGIS_VAULT_DIR", str(tmp_path / "vault"))
    settings, transport = FakeSettings(), FakeTransport()
    monkeypatch.setattr(mail_send, "_settings", lambda: settings)
    monkeypatch.setattr(mail_send, "_transport", lambda: transport)
    return SimpleNamespace(settings=settings, transport=transport)


def _article(page: str, anchor: str) -> str:
    """The timeline entry `anchor` ("c12") of an authority page."""
    art = next((a for a in page.split("<article")[1:] if f'id="{anchor}"' in a.split(">", 1)[0]), None)
    assert art is not None, anchor
    return art.split("</article>", 1)[0]


def _run(db, case, client, skill, arg=""):
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership

    access = CaseAccess(case=case, user=client.user, role=effective_role(db, client.user, case),
                        member=membership(db, client.user, case))
    return skills.run_skill(db, access, skill, arg)


# --------------------------------------------------------------------------- a duplicate draft is never e-mailed
@pytest.mark.parametrize("name", ["KuCoin", "Circle (USDC issuer)"])
def test_a_duplicate_draft_is_never_e_mailed(client_for, client, db, case, mail, name):
    if name != "KuCoin":  # Circle answered with a court order: LE only (a second letter is pointless as well)
        _le_only(db, case)
    sent = _order(case, name)
    dup = _legacy(db, case, name)
    t = _t(_board(db, case, access=_access(case, "admin")), name)
    assert [d["order_id"] for d in t.duplicates] == [dup.id] and sent.status.value == "sent"
    adm = client_for("admin", case=case, email=f"r14-dup-{len(name)}@tests.example")
    # the stop order's e-mail route: refused, no letter made for it
    r = adm.post(f"/cases/{case.id}/stop-orders/{dup.id}/email",
                 data={"csrf_token": csrf_token(adm, f"/cases/{case.id}/stop-orders/{dup.id}")},
                 follow_redirects=False)
    assert r.status_code == 409 and f"Draft #{dup.id} duplicates request #{sent.id}" in r.text, r.text[:300]
    assert "discard it" in r.text
    # its letter (a legacy case may hold one): compose refuses the page and every button
    authority = desk.get_authority(db, case, t.key)
    corr, _ = compose.ensure_correspondence(db, dup, authority, None)
    flag = fb.letter_duplicate(db, case, corr)
    assert flag is not None and flag["of"] == f"#{sent.id}" and fb.letter_flag(db, case, corr) == flag, flag
    url = f"/cases/{case.id}/authorities/correspondence/{corr.id}/email"
    r = adm.get(url)
    assert r.status_code == 409 and "duplicates request" in r.text, r.text[:300]
    tok = csrf_token(adm, f"/cases/{case.id}/authorities/correspondence/{corr.id}")
    for action in ("", "save", "prepare", "send_now"):
        r = adm.post(url, data={"csrf_token": tok, "draft_hash": compose.draft_hash(corr), "action": action,
                                "to_other": "desk@provider-demo.example", "subject": "x", "attach": ["letter"]},
                     follow_redirects=False)
        assert r.status_code == 409, (action, r.status_code, r.text[:300])
    assert not db.query(MailMessage).filter(MailMessage.correspondence_id == corr.id).count()
    # the letter page: the board's flag with its discard, no e-mail link
    page = adm.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}").text
    assert 'id="draft-pointless"' in page and f"/correspondence/{corr.id}/email" not in page
    assert f"/stop-orders/{dup.id}/discard" in page
    # an e-mail prepared before the guard (a legacy case): no call to Send anywhere, and Send refuses it
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(fb, "letter_flag", lambda *a, **k: None)
        mm = _prepare(adm, db, case, corr)
    assert mm.status == MailStatus.PREPARED
    tab = client.get(f"/cases/{case.id}?tab=authorities").text
    assert f"e-mail #{mm.id} for letter #{corr.id}" not in tab
    page = adm.get(f"/cases/{case.id}/authorities/{t.key}").text
    art = _article(page, f"c{corr.id}")
    assert "awaiting Send" not in art and f"/correspondence/{corr.id}/email" not in art, art[:1500]
    assert f"/stop-orders/{dup.id}/discard" in art and "duplicates request" in art
    page = client.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    assert 'id="mail-pointless"' in page and "duplicates request" in page
    db.expire_all()
    r = _send(client, case, db.get(MailMessage, mm.id), ack_sender="1", ack_sender_reason="reviewed by the admin")
    assert r.status_code == 409 and "duplicates request" in r.text, (r.status_code, r.text[:300])
    assert mail.transport.sent == []
    db.expire_all()
    with pytest.raises(mail_send.SendError) as err:
        mail_send._check_preconditions(db, type("A", (), {"case": case})(), db.get(MailMessage, mm.id), {})
    assert "duplicates request" in str(err.value)


# --------------------------------------------------------------------------- the authority page
def _pointless_draft(db, case, inv, why, monkeypatch, *, prepare=False):
    """KuCoin with a draft that is pointless for `why` (its letter, its key); `prepare`: its e-mail prepared first."""
    if why == "gated":  # a first-contact stop order to a provider whose playbook gates our requester
        o = _uncontacted_kucoin(db, case, draft=True)
        corr, _ = compose.ensure_correspondence(db, o, _kucoin(db, case), None)
        if prepare:
            _prepare(inv, db, case, corr)
        _gate_kucoin(monkeypatch)
        return corr, f"o{o.id}"
    o = _order(case, "KuCoin")  # a status request on the sent stop order, then their answer
    corr = db.get(Correspondence, _cid(_post(inv, case, _t(_board(db, case), "KuCoin").key,
                                             template="status_request", ref=f"o{o.id}")))
    if prepare:
        _prepare(inv, db, case, corr)
    db.expire_all()
    _reply(db, case, _order(case, "KuCoin"), ANSWERS[why], NOW - timedelta(minutes=10))
    return corr, f"c{corr.id}"


@pytest.mark.parametrize("why", ["stale", "court", "le_only", "declined", "gated"])
def test_the_authority_page_never_offers_to_e_mail_a_pointless_draft(client_for, db, case, mail, monkeypatch, why):
    inv = client_for("investigator", case=case, email=f"r14-auth-{why}@tests.example")
    corr, key = _pointless_draft(db, case, inv, why, monkeypatch)
    st = rg.state(db, case, _kucoin(db, case))
    assert [p.key for p in st.pointless] == [key], st.pointless
    page = inv.get(f"/cases/{case.id}/authorities/{_t(_board(db, case), 'KuCoin').key}").text
    art = _article(page, f"c{corr.id}")
    assert f"/correspondence/{corr.id}/email" not in page, art[:1500]
    assert f'id="flag-c{corr.id}"' in art and "is pointless" in art, art[:1500]


@pytest.mark.parametrize("why", ["court", "declined", "gated"])
def test_the_authority_page_never_tags_a_pointless_drafts_e_mail_as_awaiting_send(client_for, db, case, mail,
                                                                                monkeypatch, why):
    inv = client_for("investigator", case=case, email=f"r14-tag-{why}@tests.example")
    corr, key = _pointless_draft(db, case, inv, why, monkeypatch, prepare=True)
    assert key in [p.key for p in rg.state(db, case, _kucoin(db, case)).pointless]
    page = inv.get(f"/cases/{case.id}/authorities/{_t(_board(db, case), 'KuCoin').key}").text
    art = _article(page, f"c{corr.id}")
    assert "awaiting Send" not in art and f"/correspondence/{corr.id}/email" not in art, art[:1500]
    assert "discarding cancels it" in art


def test_the_authority_page_still_offers_to_e_mail_a_draft_that_is_not_pointless(client_for, db, case, mail):
    o = _order(case, "KuCoin")
    inv = client_for("investigator", case=case, email="r14-auth-ok@tests.example")
    key = _t(_board(db, case), "KuCoin").key
    corr = db.get(Correspondence, _cid(_post(inv, case, key, template="status_request", ref=f"o{o.id}")))
    art = _article(inv.get(f"/cases/{case.id}/authorities/{key}").text, f"c{corr.id}")
    assert f"/correspondence/{corr.id}/email" in art and 'id="flag-' not in art
    _prepare(inv, db, case, corr)
    art = _article(inv.get(f"/cases/{case.id}/authorities/{key}").text, f"c{corr.id}")
    assert "e-mail awaiting Send" in art


# --------------------------------------------------------------------------- the assistant's /stop-orders
def test_the_assistant_never_recommends_a_stop_order_the_playbook_gate_refuses(client_for, db, case, monkeypatch):
    _uncontacted_kucoin(db, case)
    inv = client_for("investigator", case=case, email="r14-skill@tests.example")
    res = _run(db, case, inv, "stop-orders")
    labels = [a.get("label") for a in res.actions]
    assert "Draft the stop order to KuCoin" in labels, labels  # control: ungated, KuCoin is a stop order to draft
    n = sum(1 for x in labels if x.startswith("Draft the "))  # one button per letter to draft (stop order / notice)
    _gate_kucoin(monkeypatch)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert t.step.kind in fb.LE_KINDS and t.step.label == "Open the LE cover letter", t.step
    res = _run(db, case, inv, "stop-orders")
    labels = [a.get("label") for a in res.actions]
    assert "Draft the stop order to KuCoin" not in labels, labels
    assert sum(1 for x in labels if x.startswith("Draft the ")) == n - 1, (n, labels)
    row = next(ln for ln in res.markdown.splitlines() if ln.startswith("| KuCoin"))
    assert "Recommended now" not in row and "LE requests only" in row and f"“{t.step.label}”" in row, row
    assert "**KuCoin**" not in res.markdown.split("| Service", 1)[0], res.markdown


def test_a_gated_drafts_assistant_row_names_the_gate_not_an_le_only_answer(client_for, db, case, monkeypatch):
    _gate_kucoin(monkeypatch)
    _uncontacted_kucoin(db, case, draft=True)
    inv = client_for("investigator", case=case, email="r14-skill-draft@tests.example")
    res = _run(db, case, inv, "stop-orders")
    row = next(ln for ln in res.markdown.splitlines() if ln.startswith("| KuCoin"))
    assert "LE requests only" in row and "LE only / declined" not in row, row


# --------------------------------------------------------------------------- a move's text follows its new kind
def test_a_move_the_gate_turns_into_an_le_step_drops_the_drafts_effort(client_for, db, case, monkeypatch):
    o = _uncontacted_kucoin(db, case, draft=True)
    compose.ensure_correspondence(db, o, _kucoin(db, case), None)
    _gate_kucoin(monkeypatch)
    m = _plan_move(rp.build(db, case))
    assert m.kind in fb.LE_KINDS and not m.effort_why.startswith("send the draft"), (m.kind, m.effort_why)
    assert m.effort_why == rp._effort(m.kind, m.evidence)[1]
    inv = client_for("investigator", case=case, email="r14-effort@tests.example")
    page = html.unescape(inv.get(f"/cases/{case.id}/recovery-plan").text)
    assert "LE requests only · send the draft" not in page


def test_a_draft_whose_e_mail_may_be_out_is_settled_never_sent_from_the_editor(db, case):
    o = _uncontacted_kucoin(db, case, draft=True)
    corr, _ = compose.ensure_correspondence(db, o, _kucoin(db, case), None)
    mm = _prepared_mail(db, case, corr, "unknown")
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert t.step.href == f"/cases/{case.id}/mail/messages/{mm.id}", t.step
    m = _plan_move(rp.build(db, case))
    assert m.href == t.step.href and "settle it" in m.text, m.text
    assert "open the draft's e-mail editor" not in m.text and not m.effort_why.startswith("send the draft"), m.text


# --------------------------------------------------------------------------- one LE for a provider's LE step
def test_every_surface_names_one_le_for_a_gated_providers_step(client_for, db, case, monkeypatch):
    _gate_kucoin(monkeypatch)
    _uncontacted_kucoin(db, case, draft=True)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert t.step.kind in fb.LE_KINDS and "template=le_cover" in (t.step.href or ""), t.step
    le = t.step.href
    plan = rp.build(db, case)
    m = _plan_move(plan)
    own = plan.find(f"owner:{chain}:{address}")
    assert m.href == le and own is not None and own.href == le, (le, m.href, own and own.href)
    assert rg.gate(db, case, _kucoin(db, case), "stop_order").href == le
    inv = client_for("investigator", case=case, email="r14-le@tests.example")
    href, _text = _panel_link(inv, case, address)
    assert href == le, (href, le)
    # the LE it names is reachable (an officer or e-mail on file), never one the plan says to add a contact to
    key = re.search(r"/authorities/(le-\d+)\?", le).group(1)
    assert t.board.le_target(key) is None or t.board.le_target(key).reachable, key


def test_a_gated_uncontacted_providers_gate_link_is_its_rows_le_step(db, case, monkeypatch):
    _uncontacted_kucoin(db, case)
    _gate_kucoin(monkeypatch)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    d = rg.gate(db, case, _kucoin(db, case), "stop_order")
    assert d.kind == rg.LE_BRIEF_ONLY and d.href == t.step.href, (d.href, t.step)
    assert _plan_move(rp.build(db, case)).href == t.step.href


# --------------------------------------------------------------------------- a late held draft keeps its warning
def test_a_late_held_follow_up_keeps_its_warning_when_an_owner_deposit_leads(client_for, db, case, mail):
    o = _order(case, "KuCoin")
    key = _t(_board(db, case), "KuCoin").key
    inv = client_for("investigator", case=case, email="r14-late@tests.example")
    corr = db.get(Correspondence, _cid(_post(inv, case, key, template="status_request", ref=f"o{o.id}")))
    mm = _prepared_mail(db, case, corr, "prepared")
    _reply(db, case, _order(case, "KuCoin"), INFO_Q, NOW - timedelta(minutes=10))
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert t.step.href == f"/cases/{case.id}/mail/messages/{mm.id}", t.step
    assert "drafted before their reply" in t.step.label, t.step.label
    own = rp.build(db, case).find(f"owner:{chain}:{address}")
    assert own is not None and "drafted before their reply" in own.title, own and own.title
    assert "drafted before their reply" in next(x["label"] for x in own.actions if x.get("primary"))
