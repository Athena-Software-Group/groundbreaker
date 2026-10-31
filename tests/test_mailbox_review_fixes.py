"""Review fixes of the mailbox sync (round 1): a Sent Items message is recorded as a letter only when a To recipient
is that letter's authority; letters already carried by another e-mail, or recorded as sent after the message, are
never its candidates; "Dismiss / tie to letter" for the Outlook entries logged for review; delivery-status reports
from any domain matched by the original Message-ID they carry; replies from unknown domains to a subject we sent.

Offline: the fake Microsoft Graph of tests/test_mailbox_sync.py (httpx.MockTransport); reserved *-demo.example
domains; every case is created by the test itself.
"""

# ruff: noqa: F811  (the `mbx` fixture is imported from test_mailbox_sync and used as a parameter)
from __future__ import annotations

import uuid
from datetime import timedelta
from email import policy
from email.parser import BytesParser

from conftest import csrf_token
from sqlalchemy import select
from test_mailbox_sync import FREEMAIL, NOW, RECENT, _auth, _freemail, _rows, eml, make_case, mbx  # noqa: F401 (fixtures)

from app.db import models as M
from app.mail import sync_outbound


def _msgid(raw: bytes) -> str:
    return str(BytesParser(policy=policy.default).parsebytes(raw)["Message-ID"])


# --------------------------------------------------------------------------- MAJOR 1: the letter's authority as To
def test_subject_and_wallet_alone_never_record_a_letter_sent_to_someone_else(db, mbx):
    """The reviewer's case: the letter's subject and the stop order's wallet, but sent to a colleague's free-mail
    address. Never recorded as sent: logged for review with "no recipient is the letter's authority"."""
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=f"colleague.{w.tag}@{FREEMAIL}", subject=w.subject,
                                  body=f"FYI, this is what I am sending: please freeze {w.wallet}."), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["recorded"] == 0 and report.sent["logged"] == 1, report
    db.expire_all()
    assert db.get(M.Correspondence, w.corr.id).status == M.CorrespondenceStatus.DRAFT
    assert db.get(M.StopOrder, w.order.id).status == M.StopOrderStatus.DRAFT
    (mm,) = _rows(db, mbx.mailbox)
    assert mm.meta["needs_review"] and mm.meta["review_reason"] == "no recipient is the letter's authority"
    assert mm.meta["candidates"][0] in (f"c{w.corr.id}", f"o{w.order.id}") and mm.letter_key is None


def test_subject_and_wallet_to_another_organisation_is_not_the_letter(db, mbx):
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to="desk@other-org-mbx-demo.example", subject=w.subject,
                                  body=f"Please freeze {w.wallet}."), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["recorded"] == 0 and report.sent["logged"] == 1, report
    db.expire_all()
    assert db.get(M.StopOrder, w.order.id).status == M.StopOrderStatus.DRAFT


def test_a_tag_sent_to_someone_else_is_not_the_letter(db, mbx):
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=f"colleague.{w.tag}@{FREEMAIL}",
                                  subject=f"{w.subject} [Aegis {w.case.reference} #{w.corr.id}]", body=w.wallet),
                 at=RECENT)
    report = mbx.sync(db)
    assert report.sent["recorded"] == 0, report
    db.expire_all()
    assert db.get(M.Correspondence, w.corr.id).status == M.CorrespondenceStatus.DRAFT


def test_another_address_on_the_authoritys_own_domain_still_records(db, mbx):
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=f"freeze-desk@{w.domain}", subject=w.subject,
                                  body=f"Please freeze {w.wallet}."), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["recorded"] == 1, report


def test_the_letter_to_among_several_recipients_records(db, mbx):
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=f"colleague.{w.tag}@{FREEMAIL}, {w.to}", subject=w.subject,
                                  body=f"Please freeze {w.wallet}."), at=RECENT)
    assert mbx.sync(db).sent["recorded"] == 1


def test_addressed_to_authority_unit(db):
    w = make_case(db)
    from app.mail import inbound, matching

    mat = matching.case_material(db, w.case)
    letters, _ = sync_outbound.case_letters(db, w.case, None, mat)
    letter = letters[0]

    def parsed(*to):
        return inbound.ParsedEmail(subject=w.subject, to=list(to))

    assert sync_outbound.addressed_to_authority(letter, parsed(w.to), mat)
    assert sync_outbound.addressed_to_authority(letter, parsed(f"x@sub.{w.domain}"), mat)
    assert not sync_outbound.addressed_to_authority(letter, parsed(f"x@{FREEMAIL}"), mat)
    assert not sync_outbound.addressed_to_authority(letter, parsed(), mat)


# --------------------------------------------------------------------------- minor (f): eligible candidates
def test_a_letter_already_carried_by_another_sent_items_message_is_no_candidate(db, mbx):
    """Two draft stop orders with the same subject and recipient: the first Outlook e-mail is tagged (recorded on
    letter #1); a second untagged one would have matched both, but letter #1 is already carried, so it is #2."""
    w = make_case(db, second_order=True)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=f"{w.subject} [Aegis {w.case.reference} "
                                  f"#{w.corr.id}]", body=w.wallet), at=RECENT - timedelta(minutes=30))
    assert mbx.sync(db).sent["recorded"] == 1
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=w.wallet2), at=RECENT)
    second = mbx.sync(db)
    assert second.sent["recorded"] == 1 and second.sent["logged"] == 0, second
    db.expire_all()
    assert db.get(M.StopOrder, w.order2.id).status == M.StopOrderStatus.SENT


def test_a_letter_recorded_as_sent_after_the_message_is_no_candidate(db, mbx):
    from app.domain import correspondence as desk

    w = make_case(db)
    desk.mark_sent(db, w.case, w.corr, actor=None, sent_at=NOW + timedelta(days=3), channel="email")
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=w.wallet), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["linked"] == 0 and report.sent["logged"] == 1, report
    (mm,) = _rows(db, mbx.mailbox)
    assert mm.meta["review_reason"] == "no letter of the case matches"
    # a send recorded by hand a few hours after the Outlook e-mail is still that send
    w2 = make_case(db)
    desk.mark_sent(db, w2.case, w2.corr, actor=None, sent_at=NOW + timedelta(hours=3), channel="email")
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w2.to, subject=w2.subject, body=w2.wallet), at=RECENT)
    assert mbx.sync(db).sent["linked"] == 1


# --------------------------------------------------------------------------- minor (f): Dismiss / tie to letter
def _logged_review(db, mbx, *, second=False):
    w = make_case(db, second_order=second)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body="Please act."), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["logged"] == 1, report
    (mm,) = _rows(db, mbx.mailbox)
    return w, mm


def test_tie_a_review_entry_to_its_draft_records_the_letter(db, mbx, client_for):
    from app.blocks import status as bs

    w, mm = _logged_review(db, mbx, second=True)
    entry_id = mm.correspondence_id
    rows = bs.case_blocks(db, db.get(M.Case, w.case.id))
    assert any(r.kind == "outlook" for r in rows)
    adm = client_for("admin", case=w.case, email=f"adm-tie-{w.tag}@tests.example")
    url = f"/cases/{w.case.id}/blocks/c{entry_id}/outlook"
    tok = csrf_token(adm, f"/cases/{w.case.id}/blocks")
    page = adm.get(f"/cases/{w.case.id}/blocks").text
    assert f'action="{url}"' in page and "Tie to letter" in page and "Dismiss" in page
    ro = client_for("read_only", case=w.case, email=f"ro-tie-{w.tag}@tests.example")
    assert ro.post(url, data={"action": "tie", "letter": f"o{w.order2.id}",
                              "csrf_token": csrf_token(ro, f"/cases/{w.case.id}/blocks")}).status_code == 403
    assert adm.post(url, data={"action": "tie", "letter": "o999999", "csrf_token": tok}).status_code == 400
    r = adm.post(url, data={"action": "tie", "letter": f"o{w.order2.id}", "csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303, r.text[:500]
    db.expire_all()
    order2 = db.get(M.StopOrder, w.order2.id)
    assert order2.status == M.StopOrderStatus.SENT and order2.sent_via == sync_outbound.MAILBOX_SENT_VIA
    assert db.get(M.StopOrder, w.order.id).status == M.StopOrderStatus.DRAFT
    mm = db.get(M.MailMessage, mm.id)
    assert not mm.meta["needs_review"] and mm.meta["tied_to"] == f"o{order2.id}" and mm.letter_key == f"o{order2.id}"
    letter = db.get(M.Correspondence, mm.correspondence_id)
    assert letter.stop_order_id == order2.id and letter.evidence_item_id == mm.eml_evidence_id
    assert letter.thread_key == mm.internet_message_id
    old = db.get(M.Correspondence, entry_id)
    assert old.meta["tied_to"] == f"o{order2.id}" and not old.meta["needs_review"]
    rows = bs.case_blocks(db, db.get(M.Case, w.case.id))
    assert not any(r.kind == "outlook" for r in rows)
    assert bs.find_row(rows, f"o{order2.id}").status == bs.AWAITING
    assert sync_outbound.needs_review(db) == [] or all(x.id != mm.id for x in sync_outbound.needs_review(db))
    ev = db.scalars(select(M.AuditEvent).where(M.AuditEvent.action == "MAIL_SENT_FOUND")
                    .order_by(M.AuditEvent.id.desc())).first()
    assert ev.detail["result"] == "tied" and ev.detail["letter"] == f"o{order2.id}"
    # the authority's reply in that thread lands on the stop order it carried
    reply = eml(from_=w.to, to=mbx.mailbox, subject=f"RE: {w.subject}", body="We have placed a hold.",
                in_reply_to=mm.message_id, headers=_auth(w.domain))
    mbx.fake.add("inbox", reply, at=NOW)
    assert mbx.sync(db).received == 1
    db.expire_all()
    filed = db.scalars(select(M.MailMessage).where(M.MailMessage.mailbox == mbx.mailbox,
                                                   M.MailMessage.direction == M.MailDirection.IN)).one()
    assert db.get(M.Correspondence, filed.correspondence_id).stop_order_id == order2.id


def test_dismiss_a_review_entry(db, mbx, client_for):
    from app.blocks import status as bs

    w, mm = _logged_review(db, mbx, second=True)
    adm = client_for("admin", case=w.case, email=f"adm-dis-{w.tag}@tests.example")
    tok = csrf_token(adm, f"/cases/{w.case.id}/blocks")
    r = adm.post(f"/cases/{w.case.id}/blocks/c{mm.correspondence_id}/outlook",
                 data={"action": "dismiss", "csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    rows = bs.case_blocks(db, db.get(M.Case, w.case.id))
    assert not any(r.kind == "outlook" for r in rows)
    assert {r.key for r in rows} == {f"o{w.order.id}", f"o{w.order2.id}"}
    assert all(r.status == bs.NOT_SENT for r in rows) and all(r.next_action["kind"] == "send" for r in rows)
    mm = db.get(M.MailMessage, mm.id)
    assert mm.meta["dismissed"] and not mm.meta["needs_review"]
    assert all(x.id != mm.id for x in sync_outbound.needs_review(db))


def test_admin_mailbox_page_dismisses_and_ties(db, mbx, client_for):
    w, mm = _logged_review(db, mbx, second=True)
    admin = client_for(None, system_admin=True, email=f"sysadmin-tie-{w.tag}@tests.example")
    page = admin.get("/admin/mail/mailbox").text
    assert f"/admin/mail/mailbox/sent/{mm.id}/tie" in page and f"/admin/mail/mailbox/sent/{mm.id}/dismiss" in page
    tok = csrf_token(admin, "/admin/mail/mailbox")
    r = admin.post(f"/admin/mail/mailbox/sent/{mm.id}/tie", data={"letter": f"c{w.corr.id}", "csrf_token": tok},
                   follow_redirects=False)
    assert r.status_code == 303, r.text[:400]
    db.expire_all()
    assert db.get(M.Correspondence, w.corr.id).status == M.CorrespondenceStatus.SENT
    # a metadata-only row can only be dismissed (nothing of it is on a case)
    other = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=f"kyc@{other.domain}", subject="Another matter",
                                  body="Nothing of the case."), at=RECENT)
    assert mbx.sync(db).sent["metadata_only"] == 1
    meta_row = next(r for r in _rows(db, mbx.mailbox) if (r.meta or {}).get("metadata_only"))
    bad = admin.post(f"/admin/mail/mailbox/sent/{meta_row.id}/tie", data={"letter": f"c{other.corr.id}",
                                                                          "csrf_token": tok})
    assert bad.status_code == 409
    ok = admin.post(f"/admin/mail/mailbox/sent/{meta_row.id}/dismiss", data={"csrf_token": tok},
                    follow_redirects=False)
    assert ok.status_code == 303
    db.expire_all()
    assert db.get(M.MailMessage, meta_row.id).meta["dismissed"]


# --------------------------------------------------------------------------- minor (a): delivery-status reports
def _dsn(*, from_: str, to: str, original_id: str, subject: str = "Undeliverable: Preservation request") -> bytes:
    """A remote MTA's RFC 3464 report (multipart/report; report-type=delivery-status) returning the original."""
    b = uuid.uuid4().hex
    return (f"From: {from_}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: Tue, 20 Oct 2026 10:00:00 +0000\r\n"
            f"Message-ID: <{uuid.uuid4().hex}@remote-mta-demo.example>\r\nMIME-Version: 1.0\r\n"
            f"Content-Type: multipart/report; report-type=delivery-status; boundary=\"{b}\"\r\n\r\n"
            f"--{b}\r\nContent-Type: text/plain\r\n\r\nDelivery to the following recipient failed permanently.\r\n"
            f"--{b}\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mx.remote-mta-demo.example\r\n"
            f"\r\nFinal-Recipient: rfc822; x@remote-mta-demo.example\r\nAction: failed\r\nStatus: 5.1.1\r\n"
            f"--{b}\r\nContent-Type: text/rfc822-headers\r\n\r\nMessage-ID: {original_id}\r\n"
            f"Subject: Preservation request\r\n--{b}--\r\n").encode()


def test_a_bounce_from_any_domain_is_matched_by_the_original_message_id(db, mbx):
    w = make_case(db)
    raw = eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=f"Please freeze {w.wallet}.")
    mbx.fake.add("sentitems", raw, at=RECENT)
    assert mbx.sync(db).sent["recorded"] == 1
    bounce = _dsn(from_="MAILER-DAEMON@remote-mta-demo.example", to=mbx.mailbox, original_id=_msgid(raw))
    pid = mbx.fake.add("inbox", bounce, at=NOW)
    report = mbx.sync(db)
    assert report.not_related == 0 and mbx.fake.downloads(pid) == 1, report
    filed = [r for r in _rows(db, mbx.mailbox) if r.direction == M.MailDirection.IN]
    assert len(filed) == 1 and filed[0].case_id == w.case.id and filed[0].meta["bounce"]


def test_a_report_with_a_plain_sender_and_subject_is_found_by_its_content_type(db, mbx):
    w = make_case(db)
    raw = eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=f"Please freeze {w.wallet}.")
    mbx.fake.add("sentitems", raw, at=RECENT)
    assert mbx.sync(db).sent["recorded"] == 1
    bounce = _dsn(from_="notifications@remote-mta-demo.example", to=mbx.mailbox, original_id=_msgid(raw),
                  subject="Notification")
    pid = mbx.fake.add("inbox", bounce, at=NOW)
    report = mbx.sync(db)
    assert report.not_related == 0 and mbx.fake.downloads(pid) == 1, report


def test_a_bounce_for_mail_we_never_stored_is_read_then_dropped(db, mbx):
    make_case(db)
    bounce = _dsn(from_="postmaster@remote-mta-demo.example", to=mbx.mailbox,
                  original_id=f"<{uuid.uuid4().hex}@elsewhere-demo.example>",
                  subject="Delivery Status Notification (Failure)")
    pid = mbx.fake.add("inbox", bounce, at=NOW)
    report = mbx.sync(db)
    assert report.not_related == 1 and mbx.fake.downloads(pid) == 1, report
    assert [r for r in _rows(db, mbx.mailbox) if r.direction == M.MailDirection.IN] == []


def test_dsn_like_metadata():
    from app.mail import ingest

    assert ingest.dsn_like({"from_addr": "mailer-daemon@x-demo.example", "subject": "Hi"})
    assert ingest.dsn_like({"from_addr": "someone@x-demo.example", "subject": "Undeliverable: Freeze request"})
    assert ingest.dsn_like({"from_addr": "a@x-demo.example", "subject": "Mail delivery failed: returning message"})
    assert ingest.dsn_like({"from_addr": "a@x-demo.example", "subject": "Unzustellbar: Anfrage"})
    assert not ingest.dsn_like({"from_addr": "news@x-demo.example", "subject": "Our delivery options"})


# --------------------------------------------------------------------------- minor (b): unknown domains replying to us
def test_reply_from_an_unknown_domain_to_a_subject_we_sent_goes_to_triage_metadata_only(db, mbx):
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=w.wallet), at=RECENT)
    assert mbx.sync(db).sent["recorded"] == 1
    mbx.fake.add("inbox", eml(from_="analyst@forwarded-to-demo.example", to=mbx.mailbox, subject=f"AW: {w.subject}",
                              body="Wir prüfen das."), at=NOW)
    report = mbx.sync(db)
    assert report.triage == 1 and report.not_related == 0, report
    row = next(r for r in _rows(db, mbx.mailbox) if r.direction == M.MailDirection.IN)
    assert row.status == M.MailStatus.UNASSIGNED and row.meta["metadata_only"] and row.body_text is None
    assert row.mime_path is None and row.case_id is None and w.case.id in row.match["candidate_case_ids"]


def test_mail_from_an_unknown_domain_citing_the_case_reference_goes_to_triage(db, mbx):
    w = make_case(db)
    mbx.fake.add("inbox", eml(from_="officer@unknown-agency-demo.example", to=mbx.mailbox,
                              subject=f"Your reference {w.case.reference}", body="Please call me."), at=NOW)
    report = mbx.sync(db)
    assert report.triage == 1, report


def test_unrelated_mail_from_unknown_domains_is_still_dropped(db, mbx):
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=w.wallet), at=RECENT)
    mbx.sync(db)
    mbx.fake.add("inbox", eml(from_="news@shop-demo.example", to=mbx.mailbox, subject="Re: your order",
                              body="Thanks"), at=NOW)
    mbx.fake.add("inbox", eml(from_="news@shop-demo.example", to=mbx.mailbox, subject=w.subject[:20],
                              body="Not a reply"), at=NOW)
    report = mbx.sync(db)
    assert report.not_related == 2 and report.triage == 0, report

