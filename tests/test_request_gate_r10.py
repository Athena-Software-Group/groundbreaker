"""r10 review probes as regressions for the request gate (app.domain.request_gate: one open request per provider).

* a confirmed "replaces draft #N" never takes a draft whose e-mail is prepared: not from a stale authority-page form
  (loaded before the e-mail was prepared), not from a forged `replace_draft` field, not through the generators; a letter
  that was superseded anyway is never sent (mail_send) nor prepared (mail_compose);
* a draft follow-up tied to a sent stop order (a status request quoting it) is the provider's open request: no second
  status request, no other letter; a new address goes into it; the board and the Recovery plan point at it;
* a superseded stop order is never revived (draft) or recorded as sent, on its page or through the API.

The demo case plus synthetic data (every address and number is made up). Offline."""

import contextlib
import re
from datetime import timedelta
from types import SimpleNamespace

import pytest
from conftest import csrf_token
from test_freeze_board import (
    NOW,
    _access,
    _board,
    _order,
    _owned,
    _post_owner_letter,
    _t,
    _uncontacted_kucoin,
)
from test_freeze_board import _prepared as _prepared_row
from test_mail_compose_send import FakeSettings, FakeTransport, _compose, _send
from test_mail_compose_send import _prepared as _prepared_mm
from test_request_gate import _kucoin, _requests

from app import services
from app.ai import providers
from app.blocks import recovery as rp
from app.db.models import Correspondence, MailMessage, MailStatus, StopOrder, StopOrderStatus
from app.domain import correspondence as desk
from app.domain import mail_compose as compose
from app.domain import mail_send
from app.domain import request_gate as rg

NEW_ADDRESS = "ethereum:0x" + "ab" * 20


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


@contextlib.contextmanager
def _past_the_gate():
    """The gate's decision allows (as one read before the e-mail was prepared); the generators' own belt still holds."""
    real = rg.decide
    rg.decide = lambda *a, **k: rg.Decision(rg.ALLOW)
    try:
        yield
    finally:
        rg.decide = real


def _post(client, case, key, **data):
    tok = csrf_token(client, f"/cases/{case.id}/authorities/{key}")
    return client.post(f"/cases/{case.id}/authorities/{key}/letters", data={"csrf_token": tok, **data},
                       follow_redirects=False)


def _status(client, case, order, status):
    path = f"/cases/{case.id}/stop-orders/{order.id}"
    return client.post(f"{path}/status", data={"csrf_token": csrf_token(client, path), "status": status},
                       follow_redirects=False)


def _orders(db, case) -> list[tuple[int, str]]:
    return sorted((o.id, o.status.value) for o in _kucoin(db, case).stop_orders)


# --------------------------------------------------------------------------- replace over a prepared e-mail
def test_a_stale_replace_form_never_supersedes_a_draft_whose_e_mail_was_prepared_meanwhile(client_for, client, db,
                                                                                            case, mail):
    o = _uncontacted_kucoin(db, case, draft=True)
    corr, _ = compose.ensure_correspondence(db, o, _kucoin(db, case), None)
    key = _t(_board(db, case), "KuCoin").key
    inv = client_for("investigator", case=case, email="r10-stale@tests.example")
    page = inv.get(f"/cases/{case.id}/authorities/{key}?template=stop_order").text
    assert re.search(r'name="replace_draft" value="([^"]*)"', page).group(1) == f"o{o.id}"  # offered: no e-mail yet
    tok = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    mm = _prepared_mm(db, _compose(inv, case, corr))  # meanwhile the e-mail is prepared
    before = _requests(db, case)
    r = inv.post(f"/cases/{case.id}/authorities/{key}/letters",
                 data={"csrf_token": tok, "template": "stop_order", "replace_draft": f"o{o.id}"}, follow_redirects=False)
    assert r.status_code == 409 and f"Prepared e-mail #{mm.id}" in r.json()["detail"]
    assert _requests(db, case) == before and _orders(db, case)[-1] == (o.id, "draft")
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    assert mm.status == MailStatus.PREPARED
    _send(client, case, mm, ack_sender="1", ack_sender_reason="reviewed the letter, profile changed later")
    assert len(mail.transport.sent) == 1  # the one request went out; no second draft waits next to it
    assert [s for _i, s in _orders(db, case) if s == "draft"] == []


def test_a_forged_replace_field_never_supersedes_a_prepared_draft(client_for, db, case):
    o = _uncontacted_kucoin(db, case, draft=True)
    corr, _ = compose.ensure_correspondence(db, o, _kucoin(db, case), None)
    mm = _prepared_row(db, case, corr)
    key = _t(_board(db, case), "KuCoin").key
    before = _requests(db, case)
    inv = client_for("investigator", case=case, email="r10-forged@tests.example")
    r = _post(inv, case, key, template="stop_order", replace_draft=f"o{o.id}")
    assert r.status_code == 409 and _requests(db, case) == before
    db.expire_all()
    assert db.get(StopOrder, o.id).status == StopOrderStatus.DRAFT and db.get(MailMessage, mm.id).status == "prepared"
    st = rg.state(db, case, _kucoin(db, case))
    assert rg.decide(st, "stop_order", replace={f"o{o.id}"}).kind == rg.OPEN_EXISTING  # the gate itself refuses


def test_a_forged_replace_field_never_supersedes_a_prepared_owner_letter(client_for, db, case):
    _uncontacted_kucoin(db, case)
    _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    inv = client_for("investigator", case=case, email="r10-forged-letter@tests.example")
    cid = int(_post_owner_letter(inv, case, t.step.href).headers["location"].rsplit("/", 1)[1])
    db.expire_all()
    _prepared_row(db, case, db.get(Correspondence, cid))
    before = _requests(db, case)
    r = _post(inv, case, t.key, template="stop_order", replace_draft=f"c{cid}")
    assert r.status_code == 409 and _requests(db, case) == before
    db.expire_all()
    assert not (db.get(Correspondence, cid).meta or {}).get("superseded_by_letter")


def test_only_the_offered_draft_can_be_replaced(client_for, db, case):
    """A replace_draft key the page does not offer (another request, a made-up key) counts for nothing."""
    o = _uncontacted_kucoin(db, case, draft=True)
    sent = _order(case, "Hostinger")
    key = _t(_board(db, case), "KuCoin").key
    before = _requests(db, case)
    inv = client_for("investigator", case=case, email="r10-offer@tests.example")
    for forged in (f"o{sent.id}", "o99999", f"o{sent.id},o99999"):
        r = _post(inv, case, key, template="stop_order", replace_draft=forged)
        assert r.status_code == 409 and "replaces" in r.json()["detail"], forged
    assert _requests(db, case) == before
    r = _post(inv, case, key, template="stop_order", replace_draft=f"o{o.id}")  # the offered one: replaced
    assert r.status_code == 303
    db.expire_all()
    assert db.get(StopOrder, o.id).status == StopOrderStatus.SUPERSEDED


def test_the_generators_never_supersede_a_draft_whose_e_mail_waits_for_send(db, case):
    o = _uncontacted_kucoin(db, case, draft=True)
    a = _kucoin(db, case)
    corr, _ = compose.ensure_correspondence(db, o, a, None)
    mm = _prepared_row(db, case, corr)
    run = services.latest_run(db, case)
    refused: dict = {}
    assert services.generate_stop_orders(db, case, run, only=[a.candidate.entity_name], gate=False,
                                         refused=refused) == []
    assert refused[a.candidate.entity_name].kind == rg.OPEN_EXISTING and f"#{mm.id}" in refused[
        a.candidate.entity_name].text
    with _past_the_gate(), pytest.raises(desk.GateRefused) as exc:  # past the gate (as a read before the e-mail was)
        desk.generate_letter(db, case, _kucoin(db, case), "stop_order", actor=None, run=run, replace={f"o{o.id}"})
    assert f"#{mm.id}" in str(exc.value)
    db.expire_all()
    assert db.get(StopOrder, o.id).status == StopOrderStatus.DRAFT and db.get(MailMessage, mm.id).status == "prepared"
    # an expired preview is never sent: it holds nothing back
    db.get(MailMessage, mm.id).expires_at = NOW - timedelta(minutes=1)
    db.commit()
    assert services.mail_pending(db, [db.get(StopOrder, o.id)]) is None


def test_the_generators_never_supersede_an_owner_letter_whose_e_mail_waits_for_send(client_for, db, case):
    _uncontacted_kucoin(db, case)
    _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    inv = client_for("investigator", case=case, email="r10-gen-letter@tests.example")
    cid = int(_post_owner_letter(inv, case, t.step.href).headers["location"].rsplit("/", 1)[1])
    db.expire_all()
    _prepared_row(db, case, db.get(Correspondence, cid))
    before = _requests(db, case)
    with _past_the_gate(), pytest.raises(desk.GateRefused):
        desk.generate_letter(db, case, _kucoin(db, case), "stop_order", actor=None,
                             run=services.latest_run(db, case), replace={f"c{cid}"})
    assert _requests(db, case) == before


def test_a_superseded_letter_is_never_sent_or_prepared(client_for, client, db, case, mail):
    """The belt: a letter whose stop order was superseded (or that a newer letter replaced) with an e-mail prepared
    before: Send refuses it, and no e-mail of it is prepared again."""
    o = _uncontacted_kucoin(db, case, draft=True)
    corr, _ = compose.ensure_correspondence(db, o, _kucoin(db, case), None)
    inv = client_for("investigator", case=case, email="r10-belt@tests.example")
    mm = _prepared_mm(db, _compose(inv, case, corr))
    db.get(StopOrder, o.id).status = StopOrderStatus.SUPERSEDED  # as a generator before this fix left it
    db.commit()
    _send(client, case, mm, ack_sender="1", ack_sender_reason="reviewed the letter, profile changed later")
    db.expire_all()
    assert mail.transport.sent == [] and db.get(MailMessage, mm.id).status == MailStatus.PREPARED
    with pytest.raises(mail_send.SendError) as exc:
        mail_send._check_preconditions(db, SimpleNamespace(case=case), db.get(MailMessage, mm.id), {})
    assert exc.value.args[0].startswith(f"Stop order #{o.id} was superseded")
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email")
    assert page.status_code == 409 and "superseded" in page.text  # no e-mail of it is prepared again
    letter = db.get(Correspondence, corr.id)
    letter.meta = {**(letter.meta or {}), "superseded_by_letter": 1}
    assert compose.superseded_text(letter).startswith("A newer letter (#1) replaced")


# --------------------------------------------------------------------------- a drafted follow-up is the open request
def test_a_drafted_follow_up_is_the_open_request_on_every_path(client_for, db, case):
    o = _order(case, "KuCoin")
    o.response_due_at = NOW - timedelta(days=1)  # overdue: its row chases it
    db.commit()
    adm = _access(case, "admin")
    t = _t(_board(db, case, access=adm), "KuCoin")
    assert t.step.label == "Chase" and "template=status_request" in t.step.href
    inv = client_for("investigator", case=case, email="r10-follow@tests.example")
    r = _post(inv, case, t.key, template="status_request", ref=f"o{o.id}")
    assert r.status_code == 303
    cid = int(r.headers["location"].rsplit("/", 1)[1])
    draft = f"/cases/{case.id}/authorities/correspondence/{cid}"
    db.expire_all()
    assert db.get(Correspondence, cid).stop_order_id == o.id  # tied to the sent order: no block row of its own
    st = rg.state(db, case, _kucoin(db, case))
    assert [d.key for d in st.drafts] == [f"c{cid}"] and st.open.follow_up_of == f"o{o.id}"
    for tpl in sorted(rg.FOLLOW_UPS) + ["info_request", "stop_order"]:
        d = rg.decide(st, tpl, ref=f"o{o.id}")
        assert d.kind == rg.OPEN_EXISTING and d.href == draft, tpl
    assert rg.decide(st, "stop_order", replace={f"c{cid}"}).kind == rg.OPEN_EXISTING  # never replaced: send it
    before = _requests(db, case)
    letters = {c.id for c in _kucoin(db, case).correspondence if c.direction.value == "out"}
    for tpl, extra in (("status_request", {"ref": f"o{o.id}"}), ("info_request", {}), ("stop_order", {}),
                       ("release_request", {}), ("stop_order", {"replace_draft": f"c{cid}"})):
        r = _post(inv, case, t.key, template=tpl, **extra)
        assert r.status_code == 409 and f"letter #{cid}" in r.json()["detail"], (tpl, r.text[:200])
    # a new address quoting the request goes into the drafted follow-up, never a second letter
    r = _post(inv, case, t.key, template="info_request", ref=f"o{o.id}", freeze_address=NEW_ADDRESS)
    assert r.status_code == 303 and r.headers["location"].startswith(f"{draft}?added=")
    db.expire_all()
    assert _requests(db, case) == before
    assert {c.id for c in _kucoin(db, case).correspondence if c.direction.value == "out"} == letters
    assert NEW_ADDRESS.rsplit(":", 1)[1] in db.get(Correspondence, cid).body_markdown
    # the board and the plan point at the draft, never at a new status request
    t = _t(_board(db, case, access=adm), "KuCoin")
    hrefs = [s.href for s in [t.step, *t.extra] if s.href]
    assert t.step.href == draft and t.step.label == f"Open & send draft letter #{cid}", (t.step.label, hrefs)
    assert not any("template=status_request" in h for h in hrefs), hrefs
    moves = [m for m in rp.build(db, case).moves + rp.build(db, case).waiting
             if m.authority is not None and m.authority.name == "KuCoin"]
    actions = [x.get("href") or "" for m in moves for x in m.actions]
    assert moves and draft in actions and not any("template=status_request" in h for h in actions), actions
    # the assistant names the draft too
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership

    access = CaseAccess(case=case, user=inv.user, role=effective_role(db, inv.user, case),
                        member=membership(db, inv.user, case))
    res = skills.run_skill(db, access, "follow-ups", "")
    assert any(a.get("href", "").endswith(f"/authorities/correspondence/{cid}") for a in res.actions), res.actions
    assert _requests(db, case) == before


# --------------------------------------------------------------------------- a superseded stop order stays superseded
def test_a_superseded_stop_order_is_never_revived_or_marked_sent(client_for, db, case):
    o = _uncontacted_kucoin(db, case, draft=True)
    key = _t(_board(db, case), "KuCoin").key
    adm = client_for("admin", case=case, email="r10-revive@tests.example")
    assert _post(adm, case, key, template="stop_order", replace_draft=f"o{o.id}").status_code == 303
    db.expire_all()
    assert db.get(StopOrder, o.id).status == StopOrderStatus.SUPERSEDED
    orders = _orders(db, case)
    page = adm.get(f"/cases/{case.id}/stop-orders/{o.id}").text
    assert 'value="sent"' not in page and 'name="status"' not in page and 'id="so-superseded"' in page
    for status in ("sent", "draft", "acknowledged"):
        assert _status(adm, case, o, status).status_code == 400, status
    tok = csrf_token(adm, f"/cases/{case.id}?tab=authorities")
    for status in ("draft", "sent", "superseded"):
        r = adm.patch(f"/api/cases/{case.id}/stop-orders/{o.id}", json={"status": status},
                      headers={"X-CSRF-Token": tok})
        assert r.status_code == 400, (status, r.text[:200])
    assert _orders(db, case) == orders
    new = next(i for i, s in orders if s == "draft")
    page = adm.get(f"/cases/{case.id}/stop-orders/{new}").text
    assert 'value="sent"' in page  # the draft that carries the request can be recorded as sent
    assert _status(adm, case, db.get(StopOrder, new), "superseded").status_code == 400  # never by hand
    with pytest.raises(desk.DeskError):
        desk.record_stop_order_status(db, case, db.get(StopOrder, o.id), "sent", actor=None)
    # the mailbox found it in Sent Items: it did go out, so that fact is recorded
    desk.record_stop_order_status(db, case, db.get(StopOrder, o.id), "sent", actor=None, observed=True)
    assert db.get(StopOrder, o.id).status == StopOrderStatus.SENT


def test_the_api_never_records_a_duplicate_draft_as_sent(client_for, db, case, monkeypatch):
    from app.web import routes_authorities

    o = _uncontacted_kucoin(db, case, draft=True)
    inv = client_for("investigator", case=case, email="r10-api-dup@tests.example")
    monkeypatch.setattr(routes_authorities, "_duplicate", lambda db, access, order: {"order_id": order.id})
    tok = csrf_token(inv, f"/cases/{case.id}?tab=authorities")
    r = inv.patch(f"/api/cases/{case.id}/stop-orders/{o.id}", json={"status": "sent"}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 409
    db.expire_all()
    assert db.get(StopOrder, o.id).status == StopOrderStatus.DRAFT
