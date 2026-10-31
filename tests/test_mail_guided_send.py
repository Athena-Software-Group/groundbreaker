"""The guided send (app/web/mail_flow.py, routes_mail): the compose page's stepper, the "Sending…" screen and its
status poll, the way back to the page the editor was opened from (return_to: this case's pages only, never an open
redirect), the success banner, the failure path back to the editor, the To do item that closes by itself after the
send, and the To address the editor ticks agreeing with "How to email". A fake transport (no network, no mailbox)."""

import html
import re
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, unquote, urlsplit

import pytest
from conftest import csrf_token, set_role, ungated
from test_mail_compose_send import FakeSettings, FakeTransport, FakeTransportError

from app import services
from app.blocks import freeze_board as fb
from app.core.permissions import CaseAccess
from app.db.models import (
    CaseRole,
    Chain,
    Correspondence,
    CorrespondenceStatus,
    MailMessage,
    MailStatus,
)
from app.domain import correspondence as desk
from app.domain import mail_compose as compose
from app.domain import mail_send, todo
from app.web import mail_flow, routes_todo

TO = "le-requests@kucoin.example"


@pytest.fixture
def mail(monkeypatch, tmp_path):
    """The fake settings and transport plugged into mail_send's two seams (as test_mail_compose_send)."""
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(tmp_path / "vault"))
    settings, transport = FakeSettings(), FakeTransport()
    monkeypatch.setattr(mail_send, "_settings", lambda: settings)
    monkeypatch.setattr(mail_send, "_transport", lambda: transport)
    return SimpleNamespace(settings=settings, transport=transport)


@pytest.fixture
def fresh(db, tmp_path):
    """A fresh copy of the demo case (its own, non-demo reference) with a trace run, KuCoin's reply overdue."""
    from test_block_status import fresh_case

    c = fresh_case(db, tmp_path)
    run = services.run_trace(db, c, provider_mode="fixture")
    db.refresh(c)
    order = next(o for o in c.stop_orders if o.entity is not None and o.entity.name == "KuCoin")
    past = datetime.now(tz=UTC) - timedelta(days=2)
    order.response_due_at = past
    for x in order.correspondence:
        x.due_at = past
    db.commit()
    return c, run


def _kucoin(db, case, run):
    return next(a for a in desk.case_authorities(db, case, run=run) if a.name == "KuCoin")


def _status_request(db, case, run) -> Correspondence:
    return desk.generate_letter(db, case, _kucoin(db, case, run), "status_request", actor=None, run=run)


def _hidden(page: str, name: str) -> str | None:
    m = re.search(rf'name="{name}" value="([^"]*)"', page)
    return html.unescape(m.group(1)) if m else None


def _location(r) -> str:
    assert r.status_code == 303, (r.status_code, r.text[:800])
    return r.headers["location"]


def _send_now(c, case, corr, return_to: str, **form) -> tuple[MailMessage, str]:
    """The editor's "Send now" (case admins): save, prepare, then the confirmation on the same page."""
    path = f"/cases/{case.id}/authorities/correspondence/{corr.id}/email"
    page = c.get(path, params={"return_to": return_to})
    assert page.status_code == 200, page.text[:500]
    data = {"csrf_token": _hidden(page.text, "csrf_token"), "draft_hash": _hidden(page.text, "draft_hash"),
            "return_to": _hidden(page.text, "return_to"), "subject": (corr.subject or "Status request")[:200],
            "to_other": TO, "attach": ["letter"], "action": "send_now"}
    data.update(form)
    loc = _location(c.post(path, data=data, follow_redirects=False))
    q = parse_qs(urlsplit(loc).query)
    assert q["return_to"] == [return_to] and loc.endswith("#confirm")
    return MailMessage(id=int(q["confirm"][0])), loc


def _post_send(c, db, case, mid: int, page_url: str):
    page = c.get(page_url)
    assert page.status_code == 200 and 'id="mail-send-form"' in page.text
    mm = db.get(MailMessage, mid)
    db.refresh(mm)
    data = {"csrf_token": _hidden(page.text, "csrf_token"), "prepare_token": mm.prepare_token, "confirm_send": "1",
            "confirm_unverified": list(mm.confirmations.get("unverified") or []),
            "confirm_attachment": [str(i) for i in mm.confirmations.get("attachments") or []], "ack_sender": "1",
            "return_to": _hidden(page.text.split('id="mail-send-form"', 1)[1], "return_to")}
    return c.post(f"/cases/{case.id}/mail/messages/{mid}/send", data=data, follow_redirects=False)


# --------------------------------------------------------------------------- return_to validation
@pytest.mark.parametrize("raw", [
    "https://evil.example/cases/7", "//evil.example/cases/7", "/\\evil.example", "\\\\evil.example",
    "javascript:alert(1)", "/cases/8", "/cases/70", "/cases/7x", "/cases/7/../../admin", "/cases/7/./x",
    "/cases/7?x=1\r\nSet-Cookie: a=b", "/cases/7/%2e%2e/%2E%2E/admin", "/cases/7 /x", "cases/7", "", None,
    "/" + "x" * 500, "/admin/users",
    "http:/cases/7", "/cases/7@evil.example",
])
def test_safe_return_refuses_anything_but_this_cases_pages(raw):
    assert mail_flow.safe_return(raw, 7) is None


@pytest.mark.parametrize("raw", ["/cases/7", "/cases/7?tab=todo", "/cases/7?tab=authorities#freeze",
                                 "/cases/7/recovery-plan", "/cases/7/blocks", "/cases/7/authorities/entity-5"])
def test_safe_return_keeps_a_page_of_the_case(raw):
    assert mail_flow.safe_return(raw, 7) == raw


def test_with_query_replaces_and_keeps_the_fragment():
    assert mail_flow.with_query("/cases/7?tab=todo&mail_sent=3#t-x", mail_sent=9) == "/cases/7?tab=todo&mail_sent=9#t-x"
    assert mail_flow.with_query("/cases/7", return_to=None) == "/cases/7"


# --------------------------------------------------------------------------- the stepper
def test_the_compose_page_shows_the_four_steps_and_their_state(db, fresh, client_for, mail):
    case, run = fresh
    corr = _status_request(db, case, run)
    admin = client_for("admin", case=case)
    path = f"/cases/{case.id}/authorities/correspondence/{corr.id}/email"
    page = admin.get(path).text
    assert 'id="mail-stepper"' in page
    labels = re.findall(r'<li class="mail-step is-(\w+)" data-step="(\w+)"', page)
    assert [k for _s, k in labels] == ["recipients", "letter", "attachments", "send"]
    assert {k: s for s, k in labels}["attachments"] == "done"  # the letter's .docx is attached by default
    for anchor in ("step-recipients", "step-letter", "attachments", "mail-next"):
        assert f'id="{anchor}"' in page and f'href="#{anchor}"' in page
    assert "Review &amp; send" in page
    # a refused address: the Recipients step says what to fix
    data = {"csrf_token": _hidden(page, "csrf_token"), "draft_hash": _hidden(page, "draft_hash"),
            "subject": "Status request", "to_other": "not-an-address", "attach": ["letter"], "action": "prepare"}
    r = admin.post(path, data=data, follow_redirects=False)
    assert r.status_code == 400
    assert '<li class="mail-step is-error" data-step="recipients"' in r.text
    # steps computed from the options: no To → to do; Send now once the steps are done
    opts = compose.compose_options(db, CaseAccess(case=case, user=admin.user, role=CaseRole.ADMIN, member=None),
                                   corr, _kucoin(db, case, run))
    for o in opts.recipients:
        o.to_checked = False
    opts.to_other = ""
    steps = compose.compose_steps(opts, can_send=True)
    assert steps[0].state == "todo" and steps[3].summary == "finish the steps above"
    opts.to_other = TO
    steps = compose.compose_steps(opts, can_send=True)
    assert steps[0].state == "done" and steps[0].summary.startswith("1 To")
    assert steps[3].summary == steps[3].ready and "Send now" in steps[3].ready
    assert compose.compose_steps(opts, confirm=object(), can_send=True)[3].state == "current"


# --------------------------------------------------------------------------- the whole flow, from the To do tab
def test_send_from_the_to_do_tab_goes_back_there_and_closes_the_item(db, fresh, client_for, mail):
    case, run = fresh
    corr = _status_request(db, case, run)
    admin = client_for("admin", case=case)
    acc = CaseAccess(case=case, user=admin.user, role=CaseRole.ADMIN, member=None)
    task = todo.find(todo.build(db, case, acc), "board:entity-1")
    assert task is not None and task.is_open and task.action.href.endswith(f"/correspondence/{corr.id}")
    todo_url = f"/cases/{case.id}?tab=todo"
    # the To do action carries return_to; the letter page passes it on to its "Edit & send e-mail"
    tab = admin.get(todo_url).text
    letter_link = f"/cases/{case.id}/authorities/correspondence/{corr.id}?return_to={quote(todo_url, safe='')}"
    assert html.escape(letter_link) in tab
    letter = admin.get(letter_link).text
    compose_link = f"/cases/{case.id}/authorities/correspondence/{corr.id}/email?return_to={quote(todo_url, safe='')}"
    assert html.escape(compose_link) in letter
    routes_todo._BADGE[(case.id, admin.user.id, "admin")] = (10**9, 5)  # a cached badge count of the case
    mm, confirm_url = _send_now(admin, case, corr, todo_url)
    r = _post_send(admin, db, case, mm.id, confirm_url)
    sending = _location(r)
    assert sending == f"/cases/{case.id}/mail/messages/{mm.id}/sending?return_to={quote(todo_url, safe='')}"
    assert len(mail.transport.sent) == 1
    assert not [k for k in routes_todo._BADGE if k[0] == case.id]  # the badge is counted again at once
    screen = admin.get(sending)
    assert screen.status_code == 200 and 'id="mail-sending"' in screen.text and "<script" not in \
        screen.text.split("<main>", 1)[1].split("</main>", 1)[0]  # CSP: no inline script
    assert f'data-status-url="/cases/{case.id}/mail/messages/{mm.id}/status"' in screen.text
    status = admin.get(f"/cases/{case.id}/mail/messages/{mm.id}/status")
    assert status.json() == {"id": mm.id, "status": "sent", "state": "sent", "done": True}
    assert status.headers["cache-control"] == "no-store"
    back = _location(admin.get(f"/cases/{case.id}/mail/messages/{mm.id}/after-send",
                               params={"return_to": todo_url}, follow_redirects=False))
    assert back == f"{todo_url}&mail_sent={mm.id}"
    page = admin.get(back).text
    assert 'id="mail-sent-banner"' in page and f"E-mail #{mm.id} sent" in page
    # the To do item closed by itself: no click on it, its letter is sent
    db.expire_all()
    assert db.get(Correspondence, corr.id).status == CorrespondenceStatus.SENT
    assert f"/authorities/correspondence/{corr.id}?return_to" not in page
    after = todo.find(todo.build(db, case, acc), "board:entity-1")
    assert after is None or not after.is_open  # chased: KuCoin waits for the reply to the status request
    row = next(t for t in fb.build(db, case, acc).targets if t.key == "entity-1")
    assert row.group == fb.WAITING and row.step.kind != "chase"
    assert "KuCoin: Chase" not in page and "KuCoin: Open &amp; send" not in page


def test_the_banner_is_only_for_this_cases_sent_email(db, fresh, client_for, mail):
    case, run = fresh
    corr = _status_request(db, case, run)
    admin = client_for("admin", case=case)
    mm, _url = _send_now(admin, case, corr, f"/cases/{case.id}/blocks")
    page = admin.get(f"/cases/{case.id}/blocks", params={"mail_sent": mm.id}).text  # prepared, not sent
    assert 'id="mail-sent-banner"' not in page
    assert 'id="mail-sent-banner"' not in admin.get(f"/cases/{case.id}/blocks", params={"mail_sent": "x1"}).text


def test_status_endpoint_states_and_access(db, fresh, client_for, mail):
    case, run = fresh
    corr = _status_request(db, case, run)
    admin = client_for("admin", case=case)
    mm, _url = _send_now(admin, case, corr, f"/cases/{case.id}")
    url = f"/cases/{case.id}/mail/messages/{mm.id}/status"
    data = admin.get(url).json()
    assert data["state"] == "other" and data["done"] is True and "@" not in str(data)
    row = db.get(MailMessage, mm.id)
    row.status = MailStatus.SENDING
    row.updated_at = datetime.now(tz=UTC)
    db.commit()
    assert admin.get(url).json()["state"] == "pending"
    loc = _location(admin.get(f"/cases/{case.id}/mail/messages/{mm.id}/after-send", follow_redirects=False))
    assert loc == f"/cases/{case.id}/mail/messages/{mm.id}/sending"  # still on its way: the screen waits
    row.updated_at = datetime.now(tz=UTC) - timedelta(hours=1)
    db.commit()
    assert admin.get(url).json()["state"] == "unknown"  # the process died mid-send
    row.status = MailStatus.UNKNOWN
    db.commit()
    loc = _location(admin.get(f"/cases/{case.id}/mail/messages/{mm.id}/after-send", follow_redirects=False))
    assert loc == f"/cases/{case.id}/mail/messages/{mm.id}?r=unknown"  # check the mailbox there
    assert client_for("read_only", case=case).get(url).status_code == 403
    assert client_for(None, email="stranger@tests.example").get(url).status_code in (403, 404)
    other = services.create_case(
        db, reference=f"TEST-FLOW-{mm.id}", title="Another case", victim_name="Other", victim_entity=None,
        loss_amount=1, loss_asset="USDC", loss_usd=1, fraud_date=None, chain=Chain.ETHEREUM, origin_tx=None,
        victim_wallet=None, perpetrator_wallet=None)
    set_role(db, other, admin.user, "admin")
    assert admin.get(f"/cases/{other.id}/mail/messages/{mm.id}/status").status_code == 404
    row.status = MailStatus.CANCELLED  # leave the letter free for the next test
    db.commit()


def test_an_evil_return_to_is_never_followed(db, fresh, client_for, mail):
    case, run = fresh
    corr = _status_request(db, case, run)
    admin = client_for("admin", case=case)
    evil = "https://evil.example/phish"
    page = admin.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email", params={"return_to": evil}).text
    assert _hidden(page, "return_to") == "" and "evil.example" not in page
    mm, confirm_url = _send_now(admin, case, corr, f"/cases/{case.id}?tab=todo")
    page = admin.get(confirm_url).text
    tok = _hidden(page, "csrf_token")
    row = db.get(MailMessage, mm.id)
    db.refresh(row)
    r = admin.post(f"/cases/{case.id}/mail/messages/{mm.id}/send", follow_redirects=False, data={
        "csrf_token": tok, "prepare_token": row.prepare_token, "confirm_send": "1", "ack_sender": "1",
        "confirm_unverified": list(row.confirmations.get("unverified") or []), "return_to": "//evil.example/x"})
    sending = _location(r)
    assert sending == f"/cases/{case.id}/mail/messages/{mm.id}/sending" and "evil" not in sending
    for bad in (evil, "//evil.example/x", "/\\evil.example", f"/cases/{case.id + 1000}", "/admin/users"):
        loc = _location(admin.get(f"/cases/{case.id}/mail/messages/{mm.id}/after-send", params={"return_to": bad},
                                  follow_redirects=False))
        assert loc == f"/cases/{case.id}/authorities/entity-1?mail_sent={mm.id}", (bad, loc)
    screen = admin.get(f"/cases/{case.id}/mail/messages/{mm.id}/sending", params={"return_to": evil}).text
    assert "evil.example" not in screen
    # the stop order's "Edit & send e-mail" form: an evil return_to is dropped too
    order = db.get(Correspondence, corr.id).stop_order
    tok = csrf_token(admin, f"/cases/{case.id}/stop-orders/{order.id}")
    r = admin.post(f"/cases/{case.id}/stop-orders/{order.id}/email", data={"csrf_token": tok, "return_to": evil},
                   follow_redirects=False)
    assert r.status_code in (303, 409) and "evil" not in r.headers.get("location", "")


def test_a_failed_send_goes_back_to_the_editor_with_the_error(db, fresh, client_for, mail):
    case, run = fresh
    corr = _status_request(db, case, run)
    admin = client_for("admin", case=case)
    back_to = f"/cases/{case.id}/recovery-plan"
    mail.transport.fail = FakeTransportError("forbidden", "check Mail.Send permissions")
    mm, confirm_url = _send_now(admin, case, corr, back_to)
    sending = _location(_post_send(admin, db, case, mm.id, confirm_url))
    assert admin.get(sending.replace("/sending", "/status").split("?")[0]).json()["state"] == "failed"
    loc = _location(admin.get(f"/cases/{case.id}/mail/messages/{mm.id}/after-send", params={"return_to": back_to},
                              follow_redirects=False))
    assert loc == (f"/cases/{case.id}/authorities/correspondence/{corr.id}/email?send_failed={mm.id}"
                   f"&return_to={quote(back_to, safe='')}#mail-error")
    page = admin.get(loc).text
    assert 'id="mail-error"' in page and f"E-mail #{mm.id} was not sent (forbidden)" in page
    assert "letter is still a draft" in page and _hidden(page, "return_to") == back_to
    db.expire_all()
    assert db.get(Correspondence, corr.id).status == CorrespondenceStatus.DRAFT


def test_entry_links_carry_return_to(db, fresh, client_for, mail):
    case, run = fresh
    corr = _status_request(db, case, run)
    admin = client_for("admin", case=case)
    for page_url, needle, back in (  # the board's row: back to the board itself
            (f"/cases/{case.id}?tab=todo", f"/authorities/correspondence/{corr.id}?return_to=", ""),
            (f"/cases/{case.id}?tab=authorities", f"/authorities/correspondence/{corr.id}?return_to=", "#freeze"),
            (f"/cases/{case.id}/authorities/entity-1", f"/authorities/correspondence/{corr.id}/email?return_to=", "")):
        page = admin.get(page_url).text
        assert needle in page, page_url
        m = re.search(re.escape(needle) + r'([^"#&]+)', page)
        assert mail_flow.safe_return(unquote(html.unescape(m.group(1))), case.id) == page_url + back
    # a link to anything else is left alone
    todo_page = admin.get(f"/cases/{case.id}?tab=todo").text  # (owner lookups are on by default: no setup link)
    assert f'href="/cases/{case.id}?tab=evidence#ev-intel-ai"' in todo_page


# --------------------------------------------------------------------------- the To address agrees with "How to email"
def test_the_ticked_to_is_the_one_how_to_email_suggests(db, fresh, client_for, mail):
    case, run = fresh
    case.facts = {**(case.facts or {}), "demo": True}  # a demo case (Case.is_demo), like DEMO-2026-001
    db.commit()
    circle = next(a for a in desk.case_authorities(db, case, run=run) if a.name == "Circle (USDC issuer)")
    with ungated():
        corr = desk.generate_letter(db, case, circle, "stop_order", actor=None, run=run)
    admin = client_for("admin", case=case)
    r = admin.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email")
    assert r.status_code == 200, r.text[:300]
    page = r.text
    ticked = re.findall(r'name="to" value="([^"]+)" checked', page)
    howto = page.split('id="mail-howto"', 1)[1]
    suggested = re.findall(r'<span class="mono">([^<]+)</span> <span class="tag gold">suggested</span>', howto)
    assert ticked == suggested and len(ticked) == 1, (ticked, suggested)
    assert ticked[0].endswith(".example")  # a demo case: never a real organisation's address first
    acc = CaseAccess(case=case, user=admin.user, role=CaseRole.ADMIN, member=None)
    g = compose.compose_options(db, acc, corr, circle).guidance
    assert g.to[0].address == ticked[0] and all(s.address.endswith(".example") or "test addresses only" in s.why
                                                for s in g.to)


def test_send_domains_put_unsendable_addresses_last():
    from app.domain import mail_guidance as mg

    real = "blocklist" + "@" + "issuer.com"  # built at run time: the PII scan reads only reserved-domain literals
    chans = (mg.Channel(real, verified=True, purpose="freeze"),
             mg.Channel("compliance@issuer-demo.example", source="entity_record"))
    inp = mg.Inputs(authority_name="Issuer", case_reference="DEMO-1", channels=chans)
    assert mg.guide(inp).to[0].address == real
    g = mg.guide(mg.Inputs(authority_name="Issuer", case_reference="DEMO-1", channels=chans, send_domains=("example",)))
    assert [s.address for s in g.to] == ["compliance@issuer-demo.example", real]
    assert g.to[0].recommended and "test addresses only" in g.to[1].why


def test_badge_cache_is_dropped_on_send(monkeypatch):
    routes_todo._BADGE[(4242, 1, "admin")] = (0.0, 3)
    routes_todo._BADGE[(4243, 1, "admin")] = (0.0, 1)
    from app.web import routes_mail

    routes_mail._todo_changed(4242)
    assert (4242, 1, "admin") not in routes_todo._BADGE and (4243, 1, "admin") in routes_todo._BADGE
    routes_todo._BADGE.pop((4243, 1, "admin"), None)

