"""The mailbox sync and the block status working together:

* one sync records a letter sent from Outlook (Sent Items is read first) and files the authority's reply to it,
  and the reply's block-status reading is stored at filing time (`ingest.block_status_hook`);
* a reply that arrived after a message was sent never makes that message "a reply";
* several matching letters are narrowed by time (a letter sent days before is not this send);
* the test-only Graph / login override (APP_ENV=local, 127.0.0.1 only; fail closed otherwise);
* the review page preselects the authority the sync matched; the compose page shows (and, from the
  authority's own domain, types in) the address a redirecting reply named;
* small formatting: amounts below 1, the auto-reply subject.

No network: Graph is the httpx.MockTransport of tests/test_mailbox_sync.py; no model is called.
"""

# ruff: noqa: F811  (the `mbx` fixture is imported from test_mailbox_sync and used as a parameter)
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select
from test_block_status import CIRCLE_LIKE, _authority, _order, _reply, fresh_case
from test_mailbox_sync import NOW, RECENT, _auth, _freemail, _rows, eml, make_case, mbx  # noqa: F401 (fixtures)

from app.ai import providers
from app.blocks import status as bs
from app.db import models as M
from app.domain import correspondence as desk
from app.mail import graph as graph_mod
from app.mail.config import MailSettings
from app.mail.graph import GraphClient, GraphTransport
from app.mail.ingest import _auto_subject
from app.mail.transport import TransportError


@pytest.fixture(autouse=True)
def _no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


# --------------------------------------------------------------------------- one sync: letter, then its reply
def test_one_sync_records_the_letter_then_files_its_reply_with_a_reading(db, mbx):
    w = make_case(db)
    sent = eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=f"Please freeze {w.wallet}.",
               msgid_domain="athena-mbx-demo.example")
    mbx.fake.add("sentitems", sent, at=RECENT, conversation=f"conv-{w.tag}")
    sent_id = str(mbx.fake.folders["sentitems"][-1]["internetMessageId"])
    reply = eml(from_=w.to, to=mbx.mailbox, subject=f"RE: {w.subject}", in_reply_to=sent_id, headers=_auth(w.domain),
                body="Further to your request, we have frozen 1,000 USDC held at the address.")
    mbx.fake.add("inbox", reply, at=NOW, conversation=f"conv-{w.tag}")
    report = mbx.sync(db)
    assert report.folders == ["sentitems", "inbox"], report
    assert report.sent["recorded"] == 1 and report.received == 1 and report.needs_review == 0, report
    db.expire_all()
    letter = db.get(M.Correspondence, w.corr.id)
    assert letter.status == M.CorrespondenceStatus.SENT
    filed = db.scalars(select(M.MailMessage).where(M.MailMessage.mailbox == mbx.mailbox,
                                                   M.MailMessage.direction == M.MailDirection.IN)).one()
    corr = db.get(M.Correspondence, filed.correspondence_id)
    assert corr.in_reply_to_id == letter.id
    # the block-status reading was stored when the reply was filed (rules; no AI: the setting is off)
    rc = db.scalars(select(M.ReplyClassification).where(M.ReplyClassification.mail_message_id == filed.id)).one()
    assert rc.source == M.ReplySource.RULES and rc.status.value == "frozen"
    assert (corr.meta or {}).get("block_status", {}).get("rules", {}).get("status") == "frozen"
    row = bs.find_row(bs.case_blocks(db, db.get(M.Case, w.case.id)), f"o{w.order.id}")
    # the rules' "frozen" is a suggestion a person confirms: the request reads "Reply received — suggests …"
    assert row.status == "unclear" and row.suggestion["status"] == "frozen" and row.needs_confirmation
    assert row.order.status == M.StopOrderStatus.SENT


def test_a_reply_received_after_the_letter_was_sent_does_not_make_it_a_reply(db, mbx):
    """An earlier sync stored the authority's reply (it waits for review); the letter itself is read later. The
    stored reply is in the same conversation but arrived after the letter went out: the letter is recorded."""
    w = make_case(db)
    sent = eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=f"Please freeze {w.wallet}.",
               msgid_domain="athena-mbx-demo.example")
    mbx.fake.add("inbox", eml(from_=w.to, to=mbx.mailbox, subject=f"RE: {w.subject}", headers=_auth(w.domain),
                              body=f"About {w.wallet}: we are looking into it."), at=NOW, conversation=f"conv-{w.tag}")
    first = mbx.sync(db)
    assert first.needs_review == 1, first
    mbx.fake.add("sentitems", sent, at=RECENT, conversation=f"conv-{w.tag}")
    second = mbx.sync(db)
    assert second.sent["recorded"] == 1 and second.sent["logged"] == 0, second
    db.expire_all()
    assert db.get(M.StopOrder, w.order.id).status == M.StopOrderStatus.SENT


def test_several_matching_letters_are_narrowed_by_time(db, mbx):
    """A new draft stop order to an authority that had a similar letter sent days before: the Sent Items
    message is the new one (a later message is not the earlier send)."""
    w = make_case(db, second_order=True)
    desk.mark_sent(db, w.case, w.corr, actor=None, sent_at=RECENT - timedelta(days=5), channel="email")
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body="Please act."), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["recorded"] == 1 and report.sent["logged"] == 0, report
    db.expire_all()
    assert db.get(M.StopOrder, w.order2.id).status == M.StopOrderStatus.SENT
    (mm,) = _rows(db, mbx.mailbox)
    assert mm.letter_key == f"o{w.order2.id}"


# --------------------------------------------------------------------------- Outlook answers in a request's thread
def _sent_id(mbx, folder: str = "sentitems") -> str:
    return str(mbx.fake.folders[folder][-1]["internetMessageId"])


def test_outlook_answer_in_the_thread_is_a_follow_up_and_their_freeze_lands_on_the_stop_order(db, mbx, client_for):
    """Stop order recorded from Sent Items → they ask for information → the investigator answers from Outlook in
    the thread → they reply "We have frozen 1,000 USDC". One request (the stop order): Frozen, to confirm, and
    Confirm & apply works; no separate "Letter" row."""
    w = make_case(db)
    t0 = NOW - timedelta(hours=3)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=f"Please freeze {w.wallet}."),
                 at=t0)
    letter_id = _sent_id(mbx)
    mbx.fake.add("inbox", eml(from_=w.to, to=mbx.mailbox, subject=f"RE: {w.subject}", in_reply_to=letter_id,
                              headers=_auth(w.domain), body="Please provide the police report and the victim's ID."),
                 at=t0 + timedelta(hours=1))
    first = mbx.sync(db)
    assert first.sent["recorded"] == 1 and first.received == 1, first
    asked = db.scalars(select(M.MailMessage).where(M.MailMessage.mailbox == mbx.mailbox,
                                                   M.MailMessage.direction == M.MailDirection.IN)).one()
    row = bs.find_row(bs.case_blocks(db, db.get(M.Case, w.case.id)), f"o{w.order.id}")
    assert row.status == "info_requested"
    # the investigator answers from Outlook, in the thread
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=f"RE: {w.subject}", in_reply_to=asked.message_id,
                                  body="Please find the police report attached."), at=t0 + timedelta(hours=2))
    answer_id = _sent_id(mbx)
    second = mbx.sync(db)
    assert second.sent["logged"] == 1, second
    db.expire_all()
    out = db.scalars(select(M.MailMessage).where(M.MailMessage.mailbox == mbx.mailbox,
                                                 M.MailMessage.folder == "sentitems")
                     .order_by(M.MailMessage.id.desc())).first()
    follow = db.get(M.Correspondence, out.correspondence_id)
    assert follow.stop_order_id == w.order.id and follow.direction == M.CorrespondenceDirection.OUT
    assert follow.meta["follow_up_of"] == f"o{w.order.id}" and not follow.meta["needs_review"]
    assert follow.thread_key == db.get(M.Correspondence, asked.correspondence_id).thread_key
    row = bs.find_row(bs.case_blocks(db, db.get(M.Case, w.case.id)), f"o{w.order.id}")
    assert row.status == bs.AWAITING and row.resent and follow in row.outbound
    # their answer to the Outlook message (In-Reply-To / References name only that message)
    mbx.fake.add("inbox", eml(from_=w.to, to=mbx.mailbox, subject=f"RE: {w.subject}", in_reply_to=answer_id,
                              headers=_auth(w.domain), body="Thank you. We have frozen 1,000 USDC on the account."),
                 at=NOW)
    third = mbx.sync(db)
    assert third.received == 1 and third.needs_review == 0, third
    db.expire_all()
    rows = bs.case_blocks(db, db.get(M.Case, w.case.id))
    assert [r.key for r in rows] == [f"o{w.order.id}"]  # one request, no "Letter #…" row
    row = rows[0]
    assert row.status == "unclear" and row.amount is None
    assert (row.suggestion["amount"], row.suggestion["asset"]) == ("1000", "USDC")
    assert row.needs_confirmation and row.can_apply
    adm = client_for("admin", case=db.get(M.Case, w.case.id), email=f"adm-thread-{w.tag}@tests.example")
    from conftest import csrf_token

    tok = csrf_token(adm, f"/cases/{w.case.id}/blocks")
    r = adm.post(f"/cases/{w.case.id}/blocks/o{w.order.id}/confirm", follow_redirects=False,
                 data={"csrf_token": tok, "status": "frozen", "amount": "1000", "asset": "USDC", "apply": "1"})
    assert r.status_code == 303, r.text[:500]
    db.expire_all()
    assert db.get(M.StopOrder, w.order.id).status == M.StopOrderStatus.FROZEN


def test_outlook_send_matching_two_drafts_needs_review_and_is_no_request(db, mbx, client_for):
    """One Outlook send matched two drafts: listed as "Sent from Outlook — needs review" (counted in needs_review,
    never a request), the drafts say it may already have gone, the exports leave it out, and the authority's
    authenticated reply to it waits for review instead of being filed."""
    w = make_case(db, second_order=True)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body="Please act."), at=RECENT)
    sent_id = _sent_id(mbx)
    assert mbx.sync(db).sent["logged"] == 1
    db.expire_all()
    case = db.get(M.Case, w.case.id)
    rows = bs.case_blocks(db, case)
    review = [r for r in rows if r.status == bs.SENT_REVIEW]
    assert len(review) == 1 and review[0].kind == "outlook" and review[0].needs_review
    assert "letter #" in review[0].next_action["text"] and review[0].next_action["kind"] == "review"
    drafts = {r.key: r for r in rows if r.status == bs.NOT_SENT}
    assert set(drafts) == {f"o{w.order.id}", f"o{w.order2.id}"}
    for r in drafts.values():
        assert r.next_action["kind"] == "check" and "Possibly already sent from Outlook" in r.next_action["text"]
    s = bs.summary(rows)
    assert s["total"] == 2 and s["sent_review"] == 1 and s["needs_review"] == 1 and s["awaiting"] == 0
    inv = client_for("investigator", case=case, email=f"inv-review-{w.tag}@tests.example")
    page = inv.get(f"/cases/{case.id}/blocks?status=action")
    assert page.status_code == 200 and "Sent from Outlook — needs review" in page.text
    md = inv.get(f"/cases/{case.id}/blocks/export.md").text
    assert "Sent from Outlook — needs review" not in md and "not yet tied to a request" in md
    csv_text = inv.get(f"/cases/{case.id}/blocks/export.csv").text
    assert "E-mail from Outlook" not in csv_text and csv_text.count("\n") == 3  # header + the two drafts
    # their authenticated reply to that message: never filed automatically
    mbx.fake.add("inbox", eml(from_=w.to, to=mbx.mailbox, subject=f"RE: {w.subject}", in_reply_to=sent_id,
                              headers=_auth(w.domain), body="We have frozen 1,000 USDC."), at=NOW)
    later = mbx.sync(db)
    assert later.received == 0 and later.needs_review == 1, later
    # a person marks the draft it carried sent: nothing left to review on Block status
    desk.mark_sent(db, case, db.get(M.Correspondence, w.corr.id), actor=None, channel="email")
    db.expire_all()
    rows = bs.case_blocks(db, db.get(M.Case, w.case.id))
    review = next(r for r in rows if r.status == bs.SENT_REVIEW)
    assert review.needs_review  # the second stop order is still a candidate draft
    desk.record_stop_order_status(db, db.get(M.Case, w.case.id), db.get(M.StopOrder, w.order2.id), "sent", actor=None)
    db.expire_all()
    review = next(r for r in bs.case_blocks(db, db.get(M.Case, w.case.id)) if r.status == bs.SENT_REVIEW)
    assert not review.needs_review and review.next_action["kind"] == "none"


def test_outlook_e_mail_matching_no_letter_is_not_listed_as_a_request(db, mbx):
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=f"legal@{w.domain}", subject="Phone call tomorrow?",
                                  body=f"About {w.case.reference}: can we talk tomorrow?"), at=RECENT)
    assert mbx.sync(db).sent["logged"] == 1
    db.expire_all()
    rows = bs.case_blocks(db, db.get(M.Case, w.case.id))
    assert [r.key for r in rows] == [f"o{w.order.id}"] and rows[0].status == bs.NOT_SENT


# --------------------------------------------------------------------------- the local-only Graph override
def _settings(**kw) -> MailSettings:
    base = {"aegis_mail_transport": "graph", "aegis_mail_from": "desk@athena-mbx-demo.example",
            "aegis_m365_tenant_id": "00000000-0000-0000-0000-000000000000",
            "aegis_m365_client_id": "00000000-0000-0000-0000-000000000001",
            "aegis_m365_client_secret": "test-client-secret-not-real", "app_env": "local"}
    base.update(kw)
    return MailSettings(_env_file=None, **base)


MOCK = {"aegis_m365_test_graph_base": "http://127.0.0.1:9160/v1.0", "aegis_m365_test_login_host": "http://127.0.0.1:9160"}


def test_test_override_is_honoured_only_locally_and_on_127_0_0_1():
    s = _settings(**MOCK)
    assert s.host_problem is None and s.graph_problem() is None
    assert s.graph_base == "http://127.0.0.1:9160/v1.0" and s.login_base == "http://127.0.0.1:9160"
    assert s.graph_link_allowed("http://127.0.0.1:9160/v1.0/users/x/mailFolders/inbox/messages/delta?$deltatoken=1")
    assert not s.graph_link_allowed("http://127.0.0.1:9999/v1.0/users/x")  # another port
    assert not s.graph_link_allowed("https://graph.microsoft.com/v1.0/users/x")  # never the real host meanwhile
    for bad in ({"app_env": "production"}, {"app_env": "staging"}, {"app_env": "Local"}, {"app_env": " local "},
                {"aegis_m365_test_graph_base": "http://localhost:9160/v1.0"},
                {"aegis_m365_test_graph_base": "http://10.0.0.5:9160/v1.0"},
                {"aegis_m365_test_graph_base": "http://127.0.0.1/v1.0"},  # no port
                {"aegis_m365_test_graph_base": "http://user:pw@127.0.0.1:9160/v1.0"},
                {"aegis_m365_test_login_host": ""},  # both or none
                {"aegis_m365_test_login_host": "ftp://127.0.0.1:9160"}):
        s = _settings(**{**MOCK, **bad})
        assert s.host_problem and s.graph_problem() == s.host_problem, bad
        # fail closed: neither the mock nor the real hosts are used while a refused override is set
        assert not s.graph_link_allowed("https://graph.microsoft.com/v1.0/users/x"), bad
    plain = _settings()
    assert plain.host_problem is None and plain.graph_base == "https://graph.microsoft.com/v1.0"
    assert plain.graph_link_allowed("https://graph.microsoft.com/v1.0/users/x/messages")
    assert not plain.graph_link_allowed("http://127.0.0.1:9160/v1.0/users/x")


def test_graph_client_talks_only_to_the_override_and_follows_its_links():
    graph_mod.clear_token_cache()
    seen: list[str] = []
    base = "http://127.0.0.1:9160/v1.0/users/desk@athena-mbx-demo.example/mailFolders/inbox/messages/delta"

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.url.scheme}://{request.url.host}:{request.url.port}{request.url.path}")
        if request.url.path.endswith("/oauth2/v2.0/token"):
            return httpx.Response(200, json={"access_token": "opaque", "expires_in": 3599})
        if "skiptoken" in str(request.url):
            return httpx.Response(200, json={"value": [{"id": "b"}], "@odata.deltaLink": f"{base}?$deltatoken=2"})
        return httpx.Response(200, json={"value": [{"id": "a"}], "@odata.nextLink": f"{base}?$skiptoken=p2"})

    client = GraphClient(_settings(**MOCK), client=httpx.Client(transport=httpx.MockTransport(handler)),
                         sleep=lambda s: None)
    rows, link = client.delta(None)
    assert [r["id"] for r in rows] == ["a", "b"] and link == f"{base}?$deltatoken=2"
    assert seen and all(u.startswith("http://127.0.0.1:9160/") for u in seen)
    graph_mod.clear_token_cache()
    refused = GraphTransport(_settings(**{**MOCK, "app_env": "production"}),
                             client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert refused.graph.settings.graph_problem()
    seen.clear()
    with pytest.raises(TransportError):
        refused.graph.token()
    assert seen == []  # nothing was requested anywhere


# --------------------------------------------------------------------------- review page / compose page
def test_review_page_preselects_the_authority_and_letter_the_sync_matched(db, client_for, tmp_path):
    case = fresh_case(db, tmp_path)
    order = _order(case, "Rainbet")
    letter = next(c for c in case.correspondence if c.stop_order_id == order.id
                  and c.direction == M.CorrespondenceDirection.OUT)
    key = f"entity-{order.entity_id}"
    mm = M.MailMessage(case_id=case.id, direction=M.MailDirection.IN, status=M.MailStatus.NEEDS_REVIEW, transport="graph",
                       mailbox="desk@athena-mbx-demo.example", message_id=f"<{uuid.uuid4().hex}@rainbet-demo.example>",
                       subject=f"Re: {letter.subject}", from_addr="compliance@rainbet-demo.example", authority_key=key,
                       body_text="We have frozen 0.05 ETH.", match={"method": "sender_cited", "case_id": case.id},
                       received_at=datetime.now(tz=UTC), folder="inbox", match_method="sender_cited", meta={})
    db.add(mm)
    db.commit()
    c = client_for("admin", case=case, email=f"admin-{uuid.uuid4().hex[:6]}@tests.example")
    page = c.get(f"/cases/{case.id}/mail/review")
    assert page.status_code == 200
    form = page.text[page.text.index(f"/mail/review/{mm.id}/accept"):]
    form = form[:form.index("</form>")]
    assert f'<option value="{key}" selected>' in form and f'<option value="{letter.id}" selected>' in form


def _redirected(db, case, *, sender_ok: bool):
    order = _order(case, "KuCoin")
    reply = _reply(db, case, order, CIRCLE_LIKE, mailbox=True, auto=True)
    reply.sender = "compliance@kucoin-demo.example"
    reply.meta = {**(reply.meta or {}), "sender_domain_ok": sender_ok}
    db.commit()
    follow_up = desk.generate_letter(db, case, _authority(db, case, order), "status_request", actor=None)
    assert follow_up.stop_order_id == order.id
    return order, follow_up


def test_compose_page_types_in_the_address_a_redirecting_reply_named(db, client_for, tmp_path):
    case = fresh_case(db, tmp_path)
    order, follow_up = _redirected(db, case, sender_ok=True)
    c = client_for("admin", case=case, email=f"admin-{uuid.uuid4().hex[:6]}@tests.example")
    page = c.get(f"/cases/{case.id}/authorities/correspondence/{follow_up.id}/email")
    assert page.status_code == 200, page.text[:300]
    assert "mail-redirect" in page.text and "asset-freeze@kucoin-demo.example" in page.text
    assert 'name="to_other" class="mono" value="asset-freeze@kucoin-demo.example' in page.text
    # the redirect is a hint: Block status still says "redirected" until the follow-up is sent
    assert bs.find_row(bs.case_blocks(db, case), f"o{order.id}").status == "redirected"


def test_compose_page_only_shows_a_redirect_from_an_unexpected_domain(db, client_for, tmp_path):
    case = fresh_case(db, tmp_path)
    _, follow_up = _redirected(db, case, sender_ok=False)
    c = client_for("admin", case=case, email=f"admin-{uuid.uuid4().hex[:6]}@tests.example")
    page = c.get(f"/cases/{case.id}/authorities/correspondence/{follow_up.id}/email")
    assert page.status_code == 200
    assert "mail-redirect" in page.text and "It is not filled in" in page.text
    assert 'value="asset-freeze@kucoin-demo.example' not in page.text


# --------------------------------------------------------------------------- formatting
def test_amounts_and_auto_reply_subjects():
    assert [bs.fmt_amount(v) for v in ("0.05", "0.050000", "0.000599", "1234.5", "0")] == \
        ["0.05", "0.05", "0.000599", "1,234.5", "0"]
    # crypto exactly as stated (never rounded); fiat to the cent
    assert bs.fmt_amount("0.05683881", "ETH") == "0.05683881" and bs.fmt_amount("1.23456789", "BTC") == "1.23456789"
    assert bs.fmt_amount("12633.770", "USDT") == "12,633.77" and bs.fmt_amount("1000", "USDC") == "1,000"
    assert bs.fmt_amount("1234.5", "USD") == "1,234.50" and bs.fmt_amount("0.5", "EUR") == "0.50"
    assert _auto_subject("Automatic reply: Urgent - X") == "Urgent - X"
    assert _auto_subject("Out of Office: Re: Y") == "Re: Y"
    assert _auto_subject("RE: Z") == "RE: Z" and _auto_subject(None) == "(no subject)"


def test_guidance_moves_a_redirected_address_aside_and_offers_the_named_one():
    from app.domain import mail_guidance as g

    base = {"authority_name": "Issuer", "case_reference": "MBX-1", "letter_kind": "status_request",
            "sent": (g.SentLetter(at=datetime(2026, 10, 19, tzinfo=UTC), to=("compliance@issuer-demo.example",)),),
            "manual": False}
    redirect = g.Redirect(away="compliance@issuer-demo.example", to="blocklisting@issuer-demo.example",
                          at=datetime(2026, 10, 19, 9, 20, tzinfo=UTC), trusted=True)
    out = g.guide(g.Inputs(**base, redirects=(redirect,)))
    assert out.to[0].address == "blocklisting@issuer-demo.example" and "named in their reply" in out.to[0].why
    assert "compliance@issuer-demo.example" not in [s.address for s in out.to]
    assert "not the channel" in (out.why_for("compliance@issuer-demo.example") or "")
    assert any(w.code == "redirected" for w in out.warnings)
    # from another domain: a warning only, the ranking is unchanged
    spoofed = g.Redirect(away="compliance@issuer-demo.example", to="freeze@elsewhere-demo.example",
                         at=redirect.at, trusted=False)
    out = g.guide(g.Inputs(**base, redirects=(spoofed,)))
    assert [s.address for s in out.to] == ["compliance@issuer-demo.example"]
    assert any(w.code == "redirected" and "verify" in w.text for w in out.warnings)


def test_authority_page_guidance_reads_the_redirect(db, client_for, tmp_path):
    case = fresh_case(db, tmp_path)
    order, _ = _redirected(db, case, sender_ok=True)
    c = client_for("admin", case=case, email=f"admin-{uuid.uuid4().hex[:6]}@tests.example")
    page = c.get(f"/cases/{case.id}/authorities/entity-{order.entity_id}")
    assert page.status_code == 200
    assert "is not the channel to use and names asset-freeze@kucoin-demo.example" in page.text
