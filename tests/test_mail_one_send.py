"""E-mail desk, review round 1: one e-mail per letter (the uncertain-send and parallel-send
reproductions), the sender of record, received files as attachments, and the inbound fixes (attachment
cap, sender domain on manual filing, the triage page of a filed message, the authority-document picker).

Fakes and helpers come from test_mail_compose_send (mock transport and settings; no network)."""

from __future__ import annotations

import io
import re
import threading
import uuid
from datetime import UTC, datetime, timedelta
from email import policy
from email.message import EmailMessage
from types import SimpleNamespace

import pytest
from conftest import csrf_token
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from test_mail_compose_send import (
    MAILBOX,
    FakeSettings,
    FakeTransport,
    _compose,
    _draft,
    _prepared,
    _send,
)

from app import services
from app.db.models import (
    AuditEvent,
    Correspondence,
    CorrespondenceKind,
    CorrespondenceStatus,
    EvidenceItem,
    MailDirection,
    MailMessage,
    MailStatus,
    SenderProfile,
)
from app.domain import correspondence as desk
from app.domain import evidence as ev
from app.domain import mail_compose as compose
from app.domain import mail_send


@pytest.fixture
def mail(monkeypatch, tmp_path):
    """The fake mail settings and transport plugged into mail_send's seams (as in test_mail_compose_send)."""
    vault = tmp_path / "vault"
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(vault))
    # the test DB is shared by the whole run: sends of other tests count in the hourly limits
    settings = FakeSettings(aegis_mail_send_per_hour=10_000, aegis_mail_send_per_hour_global=10_000)
    transport = FakeTransport()
    monkeypatch.setattr(mail_send, "_settings", lambda: settings)
    monkeypatch.setattr(mail_send, "_transport", lambda: transport)
    return SimpleNamespace(settings=settings, transport=transport, vault=vault)


@pytest.fixture
def run(db, case):
    return services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")


def _sent_rows(db, corr_id):
    db.expire_all()
    return db.scalars(select(MailMessage).where(MailMessage.correspondence_id == corr_id,
                                                MailMessage.status == MailStatus.SENT)).all()


# --------------------------------------------------------------------------- one e-mail per letter
def test_two_previews_of_one_letter_sent_in_parallel_send_once(db, case, run, client, client_for, mail, monkeypatch):
    """Reproduction 2: two previews of one letter, Send pressed on both at the same moment (two
    admins, two tabs). Both pass every precondition before either claims; the partial unique index
    lets exactly one claim through."""
    inv = client_for("investigator", case=case)
    corr = _draft(db, case, run)
    a = _prepared(db, _compose(inv, case, corr))
    b = _prepared(db, _compose(inv, case, corr))
    assert a.letter_key == b.letter_key == f"c{corr.id}"
    other_admin = client_for("admin", case=case)
    forms = []
    for c, mm in ((client, a), (other_admin, b)):
        path = f"/cases/{case.id}/mail/messages/{mm.id}"
        forms.append((c, f"{path}/send", {
            "csrf_token": csrf_token(c, path), "prepare_token": mm.prepare_token, "confirm_send": "1",
            "confirm_unverified": list(mm.confirmations.get("unverified") or []), "due_days": "5"}))
    barrier = threading.Barrier(2, timeout=15)
    real_claim = mail_send._claim

    def racing_claim(db_, mm, user_id, *, from_status):
        barrier.wait()  # both requests passed the preconditions: now they race for the claim
        return real_claim(db_, mm, user_id, from_status=from_status)

    monkeypatch.setattr(mail_send, "_claim", racing_claim)
    results: list = [None, None]

    def go(i):
        c, url, data = forms[i]
        results[i] = c.post(url, data=data, follow_redirects=False)

    threads = [threading.Thread(target=go, args=(i,)) for i in (0, 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert all(r is not None for r in results)
    assert len(mail.transport.sent) == 1  # exactly one e-mail left
    codes = sorted(r.status_code for r in results)
    winner = next(r for r in results if r.status_code == 303 and r.headers["location"].endswith("?r=sent"))
    loser = next(r for r in results if r is not winner)
    assert codes[0] in (303, 409) and (loser.status_code == 409 or loser.headers["location"].endswith("?r=already"))
    if loser.status_code == 409:
        assert "nothing was sent" in loser.text or "already went out" in loser.text
    assert len(_sent_rows(db, corr.id)) == 1
    states = sorted(db.get(MailMessage, m.id).status.value for m in (a, b))
    assert states == ["cancelled", "sent"]  # the losing preview is retired, never sendable later
    assert db.get(Correspondence, corr.id).status == CorrespondenceStatus.SENT


def test_the_database_refuses_a_second_in_flight_row_per_letter(db, case, run, client_for, mail):
    inv = client_for("investigator", case=case)
    corr = _draft(db, case, run)
    a = _prepared(db, _compose(inv, case, corr))
    b = _prepared(db, _compose(inv, case, corr))
    a.status = MailStatus.UNKNOWN
    db.commit()
    b.status = MailStatus.SENDING
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
    b = db.get(MailMessage, b.id)
    b.status = MailStatus.FAILED  # failed / expired / cancelled rows never hold the letter
    db.commit()
    a.status = MailStatus.FAILED
    db.commit()


def test_a_sent_letter_is_never_prepared_or_sent_again(db, case, run, client, client_for, mail, monkeypatch):
    """Filing failed after the send (the letter is still a draft): Prepare and Send are refused."""
    inv = client_for("investigator", case=case)
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(inv, case, corr))
    monkeypatch.setattr(ev, "store_upload", lambda *a, **kw: (_ for _ in ()).throw(OSError("disk full")))
    assert _send(client, case, mm).headers["location"].endswith("?r=sent")
    db.expire_all()
    assert db.get(Correspondence, corr.id).status == CorrespondenceStatus.DRAFT  # filing failed
    r = _compose(inv, case, corr)
    assert r.status_code == 400 and "already went out as e-mail" in r.text
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email").text
    assert 'id="mail-letter-busy"' in page and "Prepare e-mail →</button>" not in page
    assert len(mail.transport.sent) == 1


@pytest.mark.usefixtures("past_duplicates")  # a stop order past the gate to a provider already asked
def test_a_stop_orders_letter_is_one_letter_across_draft_rows(db, case, run, client, client_for, mail):
    """Two draft rows of one stop order's letter share the letter key: once one went out, the other
    cannot be e-mailed."""
    inv = client_for("investigator", case=case)
    corr = _draft(db, case, run, template="stop_order")
    twin = Correspondence(case=case, entity=corr.entity, direction=corr.direction, channel=corr.channel,
                          kind=CorrespondenceKind.STOP_ORDER, status=CorrespondenceStatus.DRAFT, subject=corr.subject,
                          body_markdown=corr.body_markdown, recipients=list(corr.recipients or []), cc=[],
                          stop_order=corr.stop_order, classification=corr.classification, meta={})
    db.add(twin)
    db.commit()
    assert compose.letter_key(corr) == compose.letter_key(twin) == f"o{corr.stop_order_id}"
    mm = _prepared(db, _compose(inv, case, corr))
    assert _send(client, case, mm).headers["location"].endswith("?r=sent")
    r = _compose(inv, case, db.get(Correspondence, twin.id))
    assert r.status_code == 400 and "already went out" in r.text and len(mail.transport.sent) == 1


# --------------------------------------------------------------------------- sender of record
def _drop_profile(db, case):
    for p in db.scalars(select(SenderProfile).where(SenderProfile.case_id == case.id)).all():
        db.delete(p)
    db.commit()


def test_no_sender_profile_is_a_note_not_a_send_blocker(db, case, run, client, client_for, mail):
    """No sender profile: a one-line note with the link to set it up, nothing to acknowledge (a
    simplification: it used to block Send until a case admin acknowledged it with a reason)."""
    _drop_profile(db, case)
    corr = _draft(db, case, run)  # rendered with the PI-firm / signed-in user block
    check = compose.sender_check(db, case, corr, mail.settings)
    assert check.problem == "no_profile" and not check.needs_ack and not check.fixable
    inv = client_for("investigator", case=case)
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email").text
    assert 'id="mail-sender-note"' in page and "no sender profile" in page and 'id="mail-sender-warning"' not in page
    assert "who signs, on whose behalf, contact e-mail" in page and f"/cases/{case.id}/sender-profile" in page
    assert "acknowledge" not in page.split('id="mail-sender-note"')[1].split("</div>")[0]
    mm = _prepared(db, _compose(inv, case, corr))
    assert mm.meta["sender_problem"] == "no_profile"
    preview = client.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    assert 'id="mail-sender-note"' in preview and 'name="ack_sender"' not in preview
    assert 'name="ack_sender_reason"' not in preview
    r = _send(client, case, mm)  # no acknowledgement needed
    assert r.headers["location"].endswith("?r=sent") and len(mail.transport.sent) == 1
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    assert "sender_ack" not in mm.meta and not any(h["status"] == "sender_acknowledged" for h in mm.meta["history"])
    audit = db.scalars(select(AuditEvent).where(AuditEvent.action == "LETTER_SENT",
                                                AuditEvent.object_id == str(corr.id))).all()[-1]
    assert audit.detail["sender_problem"] == "no_profile" and audit.detail["sender_mismatch_acknowledged"] is False


def test_letter_rendered_before_the_profile_needs_one_tick_or_the_profile_signature(db, case, run, client, client_for,
                                                                                    mail):
    from app.services import seed_from_fixture

    _drop_profile(db, case)
    old = _draft(db, case, run)
    seed_from_fixture(db)  # the profile is set up again (the fixture's sender_profile section)
    db.expire_all()
    check = compose.sender_check(db, case, db.get(Correspondence, old.id), mail.settings)
    assert check.problem == "body_mismatch" and check.needs_ack and check.fixable
    assert "another firm's block" in check.text and "Use the sender profile's signature" in check.text
    inv = client_for("investigator", case=case)
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{old.id}/email").text
    assert 'id="mail-sender-warning"' in page and 'id="mail-use-signature"' in page
    assert 'class="mail-help-tip" title="The sender of record is who a letter says it comes from' in page
    mm = _prepared(db, _compose(inv, case, db.get(Correspondence, old.id)))
    preview = client.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    assert 'name="ack_sender"' in preview and 'name="ack_sender_reason"' not in preview  # one tick, no Reason
    r = _send(client, case, mm)
    assert r.status_code == 409 and "was not written with this case" in r.text and not mail.transport.sent
    r = _send(client, case, mm, ack_sender="1")  # the one tick: no reason asked
    assert r.headers["location"].endswith("?r=sent") and len(mail.transport.sent) == 1
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    ack = mm.meta["sender_ack"]
    assert ack["problem"] == "body_mismatch" and ack["by"] == client.user.id and "reason" not in ack
    assert any(h["status"] == "sender_acknowledged" for h in mm.meta["history"])
    audit = db.scalars(select(AuditEvent).where(AuditEvent.action == "LETTER_SENT",
                                                AuditEvent.object_id == str(old.id))).all()[-1]
    assert audit.detail["sender_problem"] == "body_mismatch" and audit.detail["sender_mismatch_acknowledged"] is True
    assert "acknowledged sender mismatch" in client.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    fresh = _draft(db, case, run)  # generated again: signed by the sender of record
    assert compose.sender_check(db, case, fresh, mail.settings).ok
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{fresh.id}/email").text
    assert 'id="mail-sender-warning"' not in page and 'id="mail-sender-note"' not in page
    mm2 = _prepared(db, _compose(inv, case, fresh))
    assert _send(client, case, mm2).headers["location"].endswith("?r=sent")


def test_from_name_that_differs_from_the_profile_is_a_mismatch(db, case, run, mail):
    corr = _draft(db, case, run)
    assert compose.sender_check(db, case, corr, mail.settings).ok
    mail.settings.aegis_mail_from_name = "Some Other Firm Ltd"
    check = compose.sender_check(db, case, corr, mail.settings)
    assert check.problem == "from_name" and "Some Other Firm Ltd" in check.text


# --------------------------------------------------------------------------- received files as attachments
def _inbound_item(db, case, *, dangerous=False, name="hold.txt"):
    item = ev.store_upload(db, case, io.BytesIO(b"received bytes " + uuid.uuid4().hex.encode()), filename=name,
                           folder="stop_orders_correspondence", title="Attachment 1 of e-mail #1",
                           source_type="email_attachment", classification="R3",
                           tags=["aegis-mail", "email-attachment"] + (["dangerous"] if dangerous else []), actor=None)
    item.meta = {**(item.meta or {}), "dangerous": dangerous}
    db.commit()
    return item


def test_received_files_are_blocked_until_an_admin_marks_them_safe(db, case, run, client, client_for, mail):
    received = _inbound_item(db, case)
    active = _inbound_item(db, case, dangerous=True, name="macro.docm")
    tagged = ev.add_note(db, case, title="note tagged dangerous", text="synthetic", folder="other")
    tagged.tags = ["dangerous"]
    db.commit()
    inv = client_for("investigator", case=case)
    corr = _draft(db, case, run)
    # the reply it came with was filed on the letter's own authority (correspondence goes only there)
    authority = next(a for a in desk.case_authorities(db, case, run=run) if corr in a.correspondence)
    desk.log_entry(db, case, authority, actor=None, direction="in", channel="email", kind="reply",
                   subject="RE: hold", body="see attached", evidence_ids=[received.id])
    assert compose.is_inbound(received) and not compose.marked_mail_safe(received)
    assert compose.is_dangerous(active) and compose.is_dangerous(tagged)
    url = f"/cases/{case.id}/authorities/correspondence/{corr.id}/email"
    page = client.get(url).text
    for item, text in ((received, compose.BLOCK_TEXT["inbound"]), (active, compose.BLOCK_TEXT["dangerous"]),
                       (tagged, compose.BLOCK_TEXT["dangerous"])):
        assert re.search(rf'value="evidence:{item.id}"[^>]*disabled', page)
        assert text.split(":")[0] in page
    r = _compose(inv, case, corr, attach=["letter", f"evidence:{received.id}"])
    assert r.status_code == 400 and "mark it safe" in r.text
    assert f'form="mail-safe-{received.id}"' in page and f'form="mail-safe-{active.id}"' not in page
    tok = csrf_token(client, url)
    assert inv.post(f"/cases/{case.id}/evidence/{received.id}/mail-safe",
                    data={"csrf_token": csrf_token(inv, url)}).status_code == 403
    assert client.post(f"/cases/{case.id}/evidence/{active.id}/mail-safe", data={"csrf_token": tok},
                       follow_redirects=False).status_code == 409
    r = client.post(f"/cases/{case.id}/evidence/{received.id}/mail-safe", data={"csrf_token": tok, "back": url},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == url
    db.expire_all()
    assert db.get(EvidenceItem, received.id).meta["mail_safe"]["by"] == client.user.id
    mm = _prepared(db, _compose(inv, case, corr, attach=["letter", f"evidence:{received.id}"]))
    # withdrawn after the preview: Send refuses the attachment again
    client.post(f"/cases/{case.id}/evidence/{received.id}/mail-safe", data={"csrf_token": tok, "safe": "0"})
    r = _send(client, case, mm, confirm_attachment=[str(received.id)])
    assert r.status_code == 409 and "no longer marked safe" in r.text and not mail.transport.sent


# --------------------------------------------------------------------------- inbound: cap, domain, triage, picker
def test_inbound_attachments_are_capped(db, case):
    from app.mail import inbound

    msg = EmailMessage()
    msg["From"] = "le-requests@exchange.example"
    msg["To"] = MAILBOX
    msg["Subject"] = "many files"
    msg["Message-ID"] = f"<{uuid.uuid4().hex}@exchange.example>"
    msg.set_content("see attached")
    for i in range(inbound.MAX_ATTACHMENTS + 5):
        msg.add_attachment(f"file {i}".encode(), maintype="text", subtype="plain", filename=f"f{i}.txt")
    p = inbound.parse(msg.as_bytes(policy=policy.SMTP))
    assert len(p.attachments) == inbound.MAX_ATTACHMENTS and p.attachments_omitted == 5 and p.attachments_truncated
    big = EmailMessage()
    big["From"], big["To"], big["Subject"] = "a@exchange.example", MAILBOX, "big"
    big.set_content("x")
    chunk = b"\0" * (inbound.MAX_ATTACHMENT_TOTAL // 2 + 1)
    for i in range(3):
        big.add_attachment(chunk, maintype="application", subtype="octet-stream", filename=f"b{i}.bin")
    p = inbound.parse(big.as_bytes(policy=policy.SMTP))
    assert len(p.attachments) == 1 and p.attachments_omitted == 2


def test_attachment_cap_is_flagged_when_filed(db, case, monkeypatch, tmp_path):
    from app.mail import inbound, ingest
    from app.mail.config import MailSettings
    from app.mail.transport import FileTransport

    monkeypatch.setattr(inbound, "MAX_ATTACHMENTS", 2)
    vault, inbox, outbox = tmp_path / "vault", tmp_path / "inbox", tmp_path / "outbox"
    inbox.mkdir()
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(vault))
    mailbox = f"case-desk-{uuid.uuid4().hex[:8]}@aegis.example"
    settings = MailSettings(_env_file=None, aegis_mail_transport="file", aegis_mail_from=mailbox,
                            aegis_mail_inbox_dir=str(inbox), aegis_mail_outbox_dir=str(outbox), aegis_mail_inbound=True)
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "x@unrelated.example", mailbox, "files"
    msg["Message-ID"] = f"<{uuid.uuid4().hex}@unrelated.example>"
    msg.set_content("three files")
    for i in range(3):
        msg.add_attachment(f"f{i}".encode(), maintype="text", subtype="plain", filename=f"f{i}.txt")
    (inbox / "m.eml").write_bytes(msg.as_bytes(policy=policy.SMTP))
    report = ingest.sync_mailbox(db, trigger="scheduler", settings=settings, transport=FileTransport(settings))
    assert report.unassigned == 1
    mm = db.scalars(select(MailMessage).where(MailMessage.mailbox == mailbox)).one()
    assert mm.meta["attachments_truncated"] is True and mm.meta["attachments_omitted"] == 1
    assert len(mm.attachments) == 2


def test_manual_filing_checks_the_sender_domain_of_the_chosen_authority(db, case, client, monkeypatch, tmp_path):
    from test_mail_inbound import eml, sent_letter

    from app.domain import correspondence as desk
    from app.mail import ingest
    from app.mail.ingest import write_raw

    monkeypatch.setenv("AEGIS_VAULT_DIR", str(tmp_path / "vault"))
    authority, _order, corr, _mm = sent_letter(db, case)
    other = next(a for a in desk.case_authorities(db, case, include_prospects=False)
                 if a.key != authority.key and a.entity is not None and not a.is_le)

    def row(from_addr):
        # neutral text: the demo case is shared, and a reply that reads as an outcome would change later tests' board
        raw = eml(from_=from_addr, subject="unrelated subject", body="Noted, thank you.")
        import hashlib

        mm = MailMessage(direction=MailDirection.IN, status=MailStatus.UNASSIGNED, transport="file",
                         mailbox="case-desk@aegis.example", message_id=f"<{uuid.uuid4().hex}@x.example>",
                         from_addr=from_addr, to_addrs=["case-desk@aegis.example"], cc_addrs=[], attachments=[],
                         match={"method": "none"}, mime_path=write_raw(raw), mime_sha256=hashlib.sha256(raw).hexdigest(),
                         mime_size=len(raw), meta={}, received_at=datetime.now(tz=UTC) - timedelta(minutes=1))
        db.add(mm)
        db.commit()
        return mm

    good = row("le-requests@exchange.example")  # the domain the letter went to
    filed = ingest.assign(db, good, case, authority_key=authority.key, in_reply_to_id=corr.id)
    assert good.match["sender_domain_ok"] is True and filed.meta["sender_domain_ok"] is True
    wrong = row("le-requests@exchange.example")
    filed = ingest.assign(db, wrong, case, authority_key=other.key)  # filed on another authority
    assert wrong.match["sender_domain_ok"] is False and filed.meta["sender_domain_ok"] is False
    page = client.get(f"/cases/{case.id}/authorities/correspondence/{filed.id}").text
    assert 'id="mail-domain-warning"' in page and "sender domain not expected" in page


def test_triage_page_of_a_filed_message_links_to_where_it_was_filed(db, case, client_for, monkeypatch, tmp_path):
    from test_mail_inbound import eml, sent_letter

    from app.mail import ingest
    from app.mail.ingest import write_raw

    monkeypatch.setenv("AEGIS_VAULT_DIR", str(tmp_path / "vault"))
    authority, _order, corr, _mm = sent_letter(db, case)
    raw = eml(subject="filed already")
    import hashlib

    mm = MailMessage(direction=MailDirection.IN, status=MailStatus.UNASSIGNED, transport="file",
                     mailbox="case-desk@aegis.example", message_id=f"<{uuid.uuid4().hex}@x.example>",
                     from_addr="le-requests@exchange.example", to_addrs=[], cc_addrs=[], attachments=[],
                     match={"method": "none"}, mime_path=write_raw(raw), mime_sha256=hashlib.sha256(raw).hexdigest(),
                     mime_size=len(raw), meta={}, received_at=datetime.now(tz=UTC))
    db.add(mm)
    db.commit()
    filed = ingest.assign(db, mm, case, authority_key=authority.key, in_reply_to_id=corr.id)
    sysadmin = client_for(None, system_admin=True)
    r = sysadmin.get(f"/admin/mail/unassigned/{mm.id}")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert 'id="mail-filed"' in r.text and f"/cases/{case.id}/authorities/correspondence/{filed.id}" in r.text
    assert 'id="mail-assign"' not in r.text
    assert sysadmin.get("/admin/mail/unassigned/999999").status_code == 404


def test_authority_document_picker_lists_likely_documents(db, case, client, mail):
    eml_item = ev.store_upload(db, case, io.BytesIO(b"From: a@b.example\r\n\r\nx"), filename="mail.eml",
                               folder="legal", title="Some e-mail filed in Legal", source_type="eml",
                               classification="R3", tags=[], actor=None)
    pdf = ev.store_upload(db, case, io.BytesIO(b"%PDF-1.4 synthetic"), filename="authority.pdf", folder="other",
                          title="Signed instrument (PDF)", source_type="upload", classification="R3", tags=[], actor=None)
    note = ev.add_note(db, case, title="Chain note in Other", text="synthetic", folder="other")
    db.commit()
    page = client.get(f"/cases/{case.id}/sender-profile").text
    assert f'value="{pdf.id}"' in page and f'value="{eml_item.id}"' not in page and f'value="{note.id}"' not in page
    profile = db.scalars(select(SenderProfile).where(SenderProfile.case_id == case.id)).one()
    for eid in profile.authority_evidence_ids:  # the chosen documents always stay listed
        assert f'value="{eid}"' in page
    assert "other item" in page and "?docs=all" in page
    wide = client.get(f"/cases/{case.id}/sender-profile?docs=all").text
    assert f'value="{note.id}"' in wide and f'value="{eml_item.id}"' not in wide
