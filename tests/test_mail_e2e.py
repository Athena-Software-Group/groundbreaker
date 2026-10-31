"""End to end with the file transport: an admin prepares and sends a letter through the web, the
.eml lands in the outbox, `scripts.mail_demo_reply` turns it into a reply in the inbox, a sync puts
the reply in the case's review queue (the file transport authenticates no sender), the case admin
accepts it, and it shows on the authority's timeline linked to the letter. Offline: no network."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

pytest.importorskip("app.domain.mail_send")
routes_mail = pytest.importorskip("app.web.routes_mail")

from conftest import csrf_token

from app.db import models

RECIPIENT = "le-requests@exchange.example"


@pytest.fixture(autouse=True)
def mail_routers():
    """Both mail routers are included by app.main; this fixture only hands the app over."""
    from app.main import app

    return app


@pytest.fixture
def file_mail(tmp_path, monkeypatch):
    dirs = {k: tmp_path / k for k in ("vault", "outbox", "inbox")}
    dirs["inbox"].mkdir()
    mailbox = f"case-desk-{uuid.uuid4().hex[:8]}@aegis.example"
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(dirs["vault"]))
    for k, v in {"AEGIS_MAIL_TRANSPORT": "file", "AEGIS_MAIL_FROM": mailbox, "AEGIS_MAIL_OUTBOX_DIR": str(dirs["outbox"]),
                 "AEGIS_MAIL_INBOX_DIR": str(dirs["inbox"]), "AEGIS_MAIL_INBOUND": "on"}.items():
        monkeypatch.setenv(k, v)
    return {**dirs, "mailbox": mailbox}


def draft_letter(db, case):
    from app.domain import correspondence as desk
    from app.domain import sender

    profile = sender.get_profile(db, case)
    signed = f"{profile.org_name}, on behalf of {profile.on_behalf_of}"  # the sender of record

    authority = next(a for a in desk.case_authorities(db, case, include_prospects=False)
                     if a.entity is not None and not a.is_le and not a.non_custodial)
    corr = models.Correspondence(case=case, entity=authority.entity, direction=models.CorrespondenceDirection.OUT,
                                 channel=models.CorrespondenceChannel.EMAIL, kind=models.CorrespondenceKind.STATUS_REQUEST,
                                 status=models.CorrespondenceStatus.DRAFT,
                                 subject=f"Status request {uuid.uuid4().hex[:6]}",
                                 body_markdown=f"Dear compliance team,\n\nPlease confirm the hold.\n\nYours "
                                               f"faithfully,\n\n{signed}\n",
                                 recipients=[RECIPIENT], cc=[], classification=models.Classification.R3, meta={})
    db.add(corr)
    db.commit()
    return authority, corr


def test_send_reply_sync_timeline(db, case, client_for, file_mail):
    from app.domain import mail_compose, mail_send
    from scripts import mail_demo_reply

    authority, corr = draft_letter(db, case)
    admin = client_for("admin", case=case)
    tok = csrf_token(admin, f"/cases/{case.id}?tab=overview")
    compose_url = f"/cases/{case.id}/authorities/correspondence/{corr.id}/email"
    assert compose_url in admin.get(f"/cases/{case.id}/authorities/{authority.key}").text  # timeline "Prepare e-mail"

    r = admin.post(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email", data={
        "csrf_token": tok, "draft_hash": mail_compose.draft_hash(corr), "to_other": RECIPIENT,
        "subject": corr.subject, "attach": "letter"}, follow_redirects=False)
    assert r.status_code == 303, r.text[:2000]
    mid = int(r.headers["location"].rstrip("/").split("/")[-1])
    db.expire_all()
    mm = db.get(models.MailMessage, mid)
    assert mm.status == models.MailStatus.PREPARED and mm.to_addrs == [RECIPIENT]

    expected = mail_send.expected_confirmations(mm)
    form = {"csrf_token": tok, "prepare_token": mm.prepare_token, "confirm_send": "1", "due_days": "7",
            "confirm_unverified": list(expected["unverified"]),
            "confirm_attachment": [str(i) for i in expected.get("attachments", [])]}
    for role in ("investigator", "read_only"):  # only case admins press Send
        other = client_for(role, case=case)
        r = other.post(f"/cases/{case.id}/mail/messages/{mid}/send",
                       data={**form, "csrf_token": csrf_token(other, f"/cases/{case.id}?tab=overview")},
                       follow_redirects=False)
        assert r.status_code == 403, (role, r.status_code)
    assert not list(file_mail["outbox"].glob("*.eml"))
    r = admin.post(f"/cases/{case.id}/mail/messages/{mid}/send", data=form, follow_redirects=False)
    assert r.status_code in (200, 303), r.text[:2000]
    db.expire_all()
    mm = db.get(models.MailMessage, mid)
    assert mm.status == models.MailStatus.SENT, (mm.status, mm.error_message)
    sent_files = list(file_mail["outbox"].glob("*.eml"))
    assert len(sent_files) == 1
    assert hashlib.sha256(sent_files[0].read_bytes()).hexdigest() == mm.mime_sha256
    letter = db.get(models.Correspondence, corr.id)
    assert letter.status == models.CorrespondenceStatus.SENT and letter.thread_key == mm.internet_message_id

    assert mail_demo_reply.main(["--outbox", str(file_mail["outbox"]), "--inbox", str(file_mail["inbox"])]) == 0
    assert len(list(file_mail["inbox"].glob("*.eml"))) == 1
    r = admin.post(f"/cases/{case.id}/mail/sync", data={"csrf_token": tok})  # "Check mailbox now", then the tab
    assert r.status_code == 200 and "Mailbox checked: 0 replies filed on this case, 1 waiting for review." in r.text
    db.expire_all()
    waiting = db.scalars(select(models.MailMessage).where(models.MailMessage.mailbox == file_mail["mailbox"],
                                                          models.MailMessage.direction == models.MailDirection.IN)).one()
    assert waiting.status == models.MailStatus.NEEDS_REVIEW and waiting.match["method"] == "header"
    review = admin.get(f"/cases/{case.id}/mail/review")
    assert review.status_code == 200 and f"E-mail #{waiting.id}" in review.text
    r = admin.post(f"/cases/{case.id}/mail/review/{waiting.id}/accept",
                   data={"csrf_token": tok, "authority_key": authority.key, "in_reply_to": str(corr.id)},
                   follow_redirects=False)
    assert r.status_code == 303, r.text[:500]

    db.expire_all()
    reply = db.scalars(select(models.Correspondence).where(models.Correspondence.in_reply_to_id == corr.id)).one()
    assert reply.direction == models.CorrespondenceDirection.IN and reply.meta["source"] == "mailbox"
    assert "SYNTHETIC DEMO REPLY" in reply.body_markdown and reply.sender == RECIPIENT
    inbound_mm = db.get(models.MailMessage, reply.meta["mail_message_id"])
    assert inbound_mm.match["method"] == "header" and inbound_mm.status == models.MailStatus.ASSIGNED
    assert inbound_mm.match["sender_domain_ok"] is True and inbound_mm.match["sender_domain_checked_for"] == authority.key
    assert any(a["filename"] == "demo-hold-confirmation.txt" and a["evidence_id"] for a in inbound_mm.attachments)

    page = admin.get(f"/cases/{case.id}/authorities/{authority.key}")
    assert page.status_code == 200
    assert f"c{reply.id}" in page.text and reply.subject in page.text
    assert datetime.now(tz=UTC)  # the timeline rendered with the reply
