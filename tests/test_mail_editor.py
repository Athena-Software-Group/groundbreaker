"""The in-app e-mail editor: edit the letter text, To / Cc / Bcc, subject and attachments (incl. files uploaded from
the computer) on the compose page, "Send now" with its confirmation on the same page, Edit from the prepared state,
an old manual-mode checklist once Aegis sends (retire it or record it), and the status updates after the send.

Fakes and helpers come from test_mail_compose_send (fake settings and transport plugged into mail_send's seams: no
network, no real mailbox)."""

from __future__ import annotations

import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from types import SimpleNamespace

import pytest
from conftest import csrf_token, ungated
from docx import Document
from sqlalchemy import select
from test_mail_compose_send import (
    MAILBOX,
    TO,
    FakeSettings,
    FakeTransport,
    _compose,
    _draft,
    _prepared,
    _send,
)

from app import services
from app.blocks import status as block_status
from app.db.models import (
    AuditEvent,
    Correspondence,
    CorrespondenceStatus,
    EvidenceItem,
    MailMessage,
    MailStatus,
    StopOrder,
    StopOrderStatus,
)
from app.domain import correspondence as desk
from app.domain import mail_compose as compose
from app.domain import mail_send

# the stop orders drafted here past the request gate repeat a request the shared demo case already sent (duplicates):
# e-mailed all the same (conftest.past_duplicates)
pytestmark = pytest.mark.usefixtures("past_duplicates")

BCC = "audit@athena.example"
MARKER = "EDITOR-MARKER: please keep the hold on account 42 in place."


@dataclass
class BccTransport(FakeTransport):
    """The fake transport, recording the Bcc addresses handed over beside the MIME bytes."""
    bcc_calls: list = field(default_factory=list)

    def send_mime(self, raw, *, message_id, bcc=None):
        self.bcc_calls.append(list(bcc or []))
        return super().send_mime(raw, message_id=message_id)


@pytest.fixture
def mail(monkeypatch, tmp_path):
    vault = tmp_path / "vault"
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(vault))
    # the test DB is shared by the whole run: sends of other tests count in the hourly limits
    settings = FakeSettings(aegis_mail_send_per_hour=10_000, aegis_mail_send_per_hour_global=10_000)
    transport = BccTransport()
    monkeypatch.setattr(mail_send, "_settings", lambda: settings)
    monkeypatch.setattr(mail_send, "_transport", lambda: transport)
    return SimpleNamespace(settings=settings, transport=transport, vault=vault)


@pytest.fixture
def run(db, case):
    return services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")


def _path(case, corr) -> str:
    return f"/cases/{case.id}/authorities/correspondence/{corr.id}/email"


def _editor(c, case, corr, *, action, files=None, query="", **form):
    """POST the compose page's form with an editor button (`action`), as the browser does."""
    page = c.get(_path(case, corr) + query)
    assert page.status_code == 200, page.text[:500]
    data = {"csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1),
            "draft_hash": re.search(r'name="draft_hash" value="([^"]+)"', page.text).group(1),
            "subject": corr.subject[:200], "to_other": TO, "attach": ["letter"], "action": action}
    data.update(form)
    return c.post(_path(case, corr), data=data, files=files, follow_redirects=False)


def _msg(raw: bytes):
    return BytesParser(policy=policy.default).parsebytes(raw)


def _mm_from_confirm(db, r) -> MailMessage:
    assert r.status_code == 303, r.text[:1500]
    m = re.search(r"\?confirm=(\d+)(?:&[a-z_]+=\w+)*#confirm$", r.headers["location"])
    assert m, r.headers["location"]
    db.expire_all()
    return db.get(MailMessage, int(m.group(1)))


def _audits(db, action, object_type, object_id):
    return db.scalars(select(AuditEvent).where(AuditEvent.action == action, AuditEvent.object_type == object_type,
                                               AuditEvent.object_id == str(object_id))).all()


# --------------------------------------------------------------------------- body, fields, reopen
def test_edited_text_is_saved_with_a_version_and_goes_into_both_parts(db, case, run, client_for, mail):
    corr = _draft(db, case, run)
    old_body = corr.body_markdown
    body = old_body.rstrip() + f"\n\n{MARKER}\n"
    inv = client_for("investigator", case=case)
    page = inv.get(_path(case, corr)).text
    assert 'name="body_markdown"' in page and 'name="bcc_other"' in page and 'name="upload"' in page
    assert 'id="mail-send-now"' not in page and 'value="prepare"' in page  # investigators prepare for review
    r = _editor(inv, case, corr, action="save", body_markdown=body.replace("\n", "\r\n"),
                subject="Edited subject – urgent", cc_other="Ops@Kucoin.example", bcc_other=BCC)
    assert r.status_code == 303 and r.headers["location"].endswith("?done=saved#editor")
    db.expire_all()
    corr = db.get(Correspondence, corr.id)
    assert corr.body_markdown == body and corr.status == CorrespondenceStatus.DRAFT
    versions = corr.meta["versions"]
    assert len(versions) == 1 and versions[0]["body"] == old_body and versions[0]["by"] == inv.user.id
    assert versions[0]["sha256"] == hashlib.sha256(old_body.encode()).hexdigest()
    saved = corr.meta["mail_draft"]
    assert saved["bcc_other"] == BCC and saved["subject"] == "Edited subject – urgent" and saved["attach"] == ["letter"]
    upd = _audits(db, "UPDATE", "correspondence", corr.id)[-1].detail
    assert "body_markdown" in upd["fields"] and upd["n_bcc"] == 1 and "@" not in json.dumps(upd)
    assert MARKER not in json.dumps(upd)
    # reopening the page shows every saved field
    page = inv.get(_path(case, corr)).text
    assert MARKER in page and f'name="bcc_other" class="mono" value="{BCC}"' in page
    assert 'value="Edited subject – urgent"' in page and "Ops@Kucoin.example" in page
    assert "<p>" + MARKER in page  # the server-rendered preview of the text
    # a second save without a change keeps the one version
    r = _editor(inv, case, corr, action="save", body_markdown=body, bcc_other=BCC)
    db.expire_all()
    assert r.status_code == 303 and len(db.get(Correspondence, corr.id).meta["versions"]) == 1
    # prepare: the MIME carries the edited text in both parts and in the .docx; Bcc is no header
    corr = db.get(Correspondence, corr.id)
    mm = _prepared(db, _editor(inv, case, corr, action="prepare", body_markdown=body,
                               subject="Edited subject – urgent", bcc_other=f"{BCC}, {TO}"))
    raw = compose.read_raw(mm, db)
    msg = _msg(raw)
    assert MARKER in msg.get_body(("plain",)).get_content() and MARKER in msg.get_body(("html",)).get_content()
    assert msg["Subject"] == f"[Aegis {case.reference} #{corr.id}] Edited subject - urgent"
    assert msg["Bcc"] is None and BCC.encode() not in raw and b"bcc:" not in raw.lower()
    assert mm.to_addrs == [TO] and compose.bcc_of(mm) == [BCC]  # the To address typed again as Bcc is dropped
    assert BCC in mm.confirmations["unverified"]
    docx = next(p for p in msg.iter_attachments() if p.get_filename().endswith(".docx"))
    assert MARKER in "\n".join(p.text for p in Document(io.BytesIO(docx.get_payload(decode=True))).paragraphs)
    created = _audits(db, "CREATE", "mail_messages", mm.id)[-1].detail
    assert created["n_bcc"] == 1 and "@" not in json.dumps(created)
    preview = inv.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    assert 'id="mail-bcc-row"' in preview and BCC in preview and 'id="mail-edit"' in preview


def test_live_preview_escapes_everything(db, case, run, client_for, mail):
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    token = csrf_token(inv, _path(case, corr))
    r = inv.post(_path(case, corr) + "/preview", data={
        "csrf_token": token, "body_markdown": "<script>alert(1)</script> **bold** [x](javascript:alert(1)) ![i](http://a/b)"})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    html = r.json()["html"]
    assert "<script" not in html and "&lt;script&gt;" in html and "<strong>bold</strong>" in html
    assert 'href="javascript' not in html and "<img" not in html
    assert inv.post(_path(case, corr) + "/preview", data={"body_markdown": "x"}).status_code == 403  # no CSRF
    ro = client_for("read_only", case=case)
    assert ro.post(_path(case, corr) + "/preview", data={"csrf_token": csrf_token(ro, f"/cases/{case.id}"),
                                                         "body_markdown": "x"}).status_code == 403


# --------------------------------------------------------------------------- Send now: confirm on the page, status
def test_send_now_confirms_on_the_page_then_sends_with_bcc_and_updates_the_status(db, case, run, client, client_for,
                                                                                  mail):
    corr = _draft(db, case, run, template="stop_order")
    order_id = corr.stop_order_id
    inv = client_for("investigator", case=case)
    assert _editor(inv, case, corr, action="send_now").status_code == 403  # only case admins send
    page = client.get(_path(case, corr)).text
    assert 'id="mail-send-now"' in page
    body = corr.body_markdown.rstrip() + f"\n\n{MARKER}\n"
    r = _editor(client, case, corr, action="send_now", body_markdown=body, cc_other="Ops@Kucoin.example",
                bcc_other=BCC)
    mm = _mm_from_confirm(db, r)
    assert mm.status == MailStatus.PREPARED and not mail.transport.sent  # nothing goes out before the confirmation
    confirm = client.get(r.headers["location"].split("#")[0]).text
    assert 'id="confirm"' in confirm and 'id="mail-send-form"' in confirm and mm.prepare_token in confirm
    assert BCC in confirm and f"{mm.mime_size:,} bytes" in confirm and "Ops@kucoin.example" in confirm
    assert f'name="confirm_unverified" value="{BCC}"' in confirm
    r = _send(client, case, mm)
    assert r.status_code == 303 and r.headers["location"].endswith("?r=sent")
    db.expire_all()
    mm, corr, order = db.get(MailMessage, mm.id), db.get(Correspondence, corr.id), db.get(StopOrder, order_id)
    assert mail.transport.bcc_calls == [[BCC]] and len(mail.transport.sent) == 1
    raw = mail.transport.sent[0]
    assert BCC.encode() not in raw and _msg(raw)["Bcc"] is None and MARKER in _msg(raw).get_body(("plain",)).get_content()
    assert mm.status == MailStatus.SENT and mm.meta["finalized"] and mm.meta["bcc"] == [BCC]
    assert corr.status == CorrespondenceStatus.SENT and corr.meta["sent_via"] == "aegis_mail" and corr.meta["bcc"] == [BCC]
    assert order.status == StopOrderStatus.SENT and order.sent_via == "email" and order.sent_at is not None
    assert MARKER in order.body_markdown
    row = next(r for r in block_status.case_blocks(db, case) if r.order is not None and r.order.id == order_id)
    assert row.status == block_status.AWAITING
    assert block_status.SNAPSHOT_KEY in (db.get(type(case), case.id).facts or {})  # the refresh ran after the send
    sent = _audits(db, "LETTER_SENT", "correspondence", corr.id)[-1].detail
    assert sent["n_bcc"] == 1 and sent["bcc_domains"] == ["athena.example"] and "@" not in json.dumps(sent)
    landing = client.get(r.headers["location"]).text
    assert 'id="mail-blocks-link"' in landing and f"/cases/{case.id}/blocks" in landing
    assert "its stop order too" in landing
    # one send per letter: a second Send, the editor and Send now again all refuse
    assert _send(client, case, mm).status_code == 303 and len(mail.transport.sent) == 1
    r = client.get(_path(case, corr), follow_redirects=False)  # the editor of a sent letter: the e-mail that sent it
    assert r.status_code == 303 and r.headers["location"] == f"/cases/{case.id}/mail/messages/{mm.id}"
    n_rows = len(db.scalars(select(MailMessage).where(MailMessage.correspondence_id == corr.id)).all())
    for action in ("save", "send_now"):
        r = client.post(_path(case, corr), data={"csrf_token": csrf_token(client, f"/cases/{case.id}"), "action": action,
                                                 "draft_hash": compose.draft_hash(corr), "subject": "again",
                                                 "to_other": TO, "body_markdown": "changed"}, follow_redirects=False)
        assert r.status_code == 400 and "only an outbound draft" in r.text
    db.expire_all()
    assert len(db.scalars(select(MailMessage).where(MailMessage.correspondence_id == corr.id)).all()) == n_rows
    assert MARKER in db.get(Correspondence, corr.id).body_markdown and len(mail.transport.sent) == 1
    assert client.get(f"/cases/{case.id}/blocks").status_code == 200
    assert client.get(f"/cases/{case.id}/recovery-plan").status_code == 200


def test_the_sent_items_sync_knows_the_message_as_ours(db, case, run, client, mail):
    from app.mail import sync_outbound

    corr = _draft(db, case, run)
    mm = _mm_from_confirm(db, _editor(client, case, corr, action="send_now", bcc_other=BCC))
    assert _send(client, case, mm).status_code == 303
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    ctx = SimpleNamespace(db=db)
    assert sync_outbound._known(ctx, [mm.internet_message_id]).id == mm.id  # Sent Items copy: no duplicate row


# --------------------------------------------------------------------------- uploads
def test_upload_from_computer_is_filed_attached_and_removable(db, case, run, client, client_for, mail):
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    pdf = b"%PDF-1.4\n% synthetic test statement\n" + b"0" * 2000
    r = _editor(inv, case, corr, action="upload", files=[("upload", ("bank statement.pdf", pdf, "application/pdf")),
                                                         ("upload", ("notes.txt", b"plain notes\n", "text/plain"))])
    assert r.status_code == 303 and r.headers["location"].endswith("?done=uploaded#attachments")
    db.expire_all()
    corr = db.get(Correspondence, corr.id)
    ids = corr.meta["mail_uploads"]
    items = [db.get(EvidenceItem, i) for i in ids]
    assert len(items) == 2 and set(ids) <= set(corr.meta["evidence_ids"])
    item = next(i for i in items if i.mime == "application/pdf")
    assert item.sha256 == hashlib.sha256(pdf).hexdigest() and item.size_bytes == len(pdf)
    assert item.folder.value == "stop_orders_correspondence" and item.classification.value == "R3"
    assert item.meta["mail_upload_for"] == corr.id and "mail-upload" in item.tags
    assert corr.meta["mail_draft"]["attach"] == ["letter", *[f"evidence:{i}" for i in ids]]
    made = _audits(db, "CREATE", "evidence_items", item.id)[-1].detail
    assert made["via"] == "mail_compose" and made["correspondence_id"] == corr.id
    page = inv.get(_path(case, corr)).text
    assert f'value="evidence:{item.id}" checked' in page and "uploaded</span>" in page
    # prepared with the upload: a neutral file name, the exact bytes
    mm = _prepared(db, _editor(inv, case, corr, action="prepare", attach=["letter", f"evidence:{item.id}"]))
    att = next(a for a in mm.attachments if a.get("evidence_id") == item.id)
    assert att["sha256"] == item.sha256 and att["filename"] == f"{case.reference}_evidence-{item.id}.pdf"
    part = next(p for p in _msg(compose.read_raw(mm, db)).iter_attachments() if p.get_filename() == att["filename"])
    assert part.get_payload(decode=True) == pdf and "bank" not in att["filename"]
    # unticked = removed from the e-mail (the upload stays filed)
    db.expire_all()
    corr = db.get(Correspondence, corr.id)
    mm2 = _prepared(db, _editor(inv, case, corr, action="prepare", attach=["letter"]))
    assert [a["kind"] for a in mm2.attachments] == ["letter_docx"] and db.get(EvidenceItem, item.id) is not None
    assert db.get(MailMessage, mm.id).status == MailStatus.CANCELLED  # the earlier preview was superseded
    # an upload linked to this letter never goes to another authority
    other = next(a for a in desk.case_authorities(db, case, run=run) if a.name != "KuCoin" and a.entity is not None)
    with ungated():  # the shared demo case: `other` may hold an earlier test's open draft
        corr2 = desk.generate_letter(db, case, other, "info_request", actor=None, run=run)
    page2 = client.get(_path(case, corr2)).text
    assert re.search(rf'value="evidence:{item.id}"[^>]*disabled', page2)


@pytest.mark.parametrize("name, data, needle", [
    ("tool.exe", b"anything", "active content"),
    ("macro.docm", b"PK\x03\x04", "active content"),
    ("renamed.txt", b"MZ\x90\x00 executable", "active content"),
    ("script.pdf", b"#!/bin/sh\nrm -rf /\n", "active content"),
    ("reply.eml", b"From: a@b.example\r\n\r\nx", "e-mail files"),
    ("empty.pdf", b"", "empty"),
])
def test_blocked_uploads_are_refused_and_nothing_is_stored(db, case, run, client_for, mail, name, data, needle):
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    before = db.scalar(select(EvidenceItem.id).order_by(EvidenceItem.id.desc()).limit(1))
    r = _editor(inv, case, corr, action="upload", files=[("upload", ("ok.pdf", b"%PDF-1.4 fine", "application/pdf")),
                                                         ("upload", (name, data, "application/octet-stream"))])
    assert r.status_code == 400 and needle in r.text, r.text[:300]
    db.expire_all()
    assert db.scalar(select(EvidenceItem.id).order_by(EvidenceItem.id.desc()).limit(1)) == before
    assert "mail_uploads" not in (db.get(Correspondence, corr.id).meta or {})


def test_an_upload_too_large_for_the_message_is_refused(db, case, run, client_for, mail):
    mail.settings.aegis_mail_max_message_bytes = 4000
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    r = _editor(inv, case, corr, action="upload", files=[("upload", ("big.pdf", b"%PDF" + b"x" * 3500,
                                                                     "application/pdf"))])
    assert r.status_code == 400 and "a file may be up to" in r.text


# --------------------------------------------------------------------------- Edit from the prepared state
def test_edit_from_prepared_cancels_the_preview_and_keeps_every_field(db, case, run, client, client_for, mail):
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    mm = _prepared(db, _compose(inv, case, corr, cc_other="Ops@Kucoin.example", bcc_other=BCC))
    assert compose.bcc_of(mm) == [BCC]
    pending = mail.vault / mm.mime_path
    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    assert 'id="mail-edit"' in inv.get(path).text
    r = inv.post(f"{path}/edit", data={"csrf_token": csrf_token(inv, path)}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("/email?done=edit#editor")
    db.expire_all()
    old = db.get(MailMessage, mm.id)
    assert old.status == MailStatus.CANCELLED and old.mime_path is None and not pending.exists()
    assert old.meta["history"][-1]["reason"] == "reopened for editing"
    page = inv.get(r.headers["location"].split("#")[0]).text
    assert 'id="mail-notice"' in page and TO in page and "Ops@kucoin.example" in page
    assert f'name="bcc_other" class="mono" value="{BCC}"' in page and 'value="letter" checked' in page
    # the cancelled preview can never be sent
    assert _send(client, case, old).status_code == 303 and not mail.transport.sent
    assert _audits(db, "MAIL_CANCELLED", "mail_messages", mm.id)[-1].detail["reason"] == "edit"
    # another member's prepared e-mail: only its author or a case admin reopens it
    db.expire_all()
    corr = db.get(Correspondence, corr.id)
    mm2 = _prepared(db, _compose(client, case, corr))
    path2 = f"/cases/{case.id}/mail/messages/{mm2.id}"
    assert 'id="mail-edit"' not in inv.get(path2).text
    assert inv.post(f"{path2}/edit", data={"csrf_token": csrf_token(inv, path2)}).status_code == 403
    db.expire_all()
    assert db.get(MailMessage, mm2.id).status == MailStatus.PREPARED
    # saving in the editor cancels the member's own prepared previews (an admin's save: every one)
    corr = db.get(Correspondence, corr.id)
    mm3 = _prepared(db, _compose(inv, case, corr))
    assert _editor(inv, case, corr, action="save").status_code == 303
    db.expire_all()
    assert db.get(MailMessage, mm3.id).status == MailStatus.CANCELLED and db.get(MailMessage, mm3.id).meta["edited_away"]
    assert db.get(MailMessage, mm2.id).status == MailStatus.PREPARED
    assert _editor(client, case, db.get(Correspondence, corr.id), action="save").status_code == 303
    db.expire_all()
    assert db.get(MailMessage, mm2.id).status == MailStatus.CANCELLED


def test_a_stale_editor_form_is_refused(db, case, run, client_for, mail):
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    page = inv.get(_path(case, corr)).text
    data = {"csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', page).group(1),
            "draft_hash": re.search(r'name="draft_hash" value="([^"]+)"', page).group(1),
            "subject": corr.subject, "to_other": TO, "attach": ["letter"], "action": "save",
            "body_markdown": corr.body_markdown + "\nmine\n"}
    desk.update_draft(db, corr, subject=corr.subject, body=corr.body_markdown + "\ntheirs\n",
                      recipients=corr.recipients, cc=corr.cc)  # another tab saved meanwhile
    r = inv.post(_path(case, corr), data=data, follow_redirects=False)
    assert r.status_code == 400 and "changed while you were editing" in r.text
    db.expire_all()
    assert "mine" not in db.get(Correspondence, corr.id).body_markdown


# --------------------------------------------------------------------------- manual-mode checklist → retired, then sent
def _retire(c, case, mm):
    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    return c.post(f"{path}/retire-checklist", data={"csrf_token": csrf_token(c, path)}, follow_redirects=False)


def test_an_old_checklist_is_retired_then_the_letter_goes_out_from_aegis(db, case, run, client, client_for, mail):
    mail.settings.aegis_mail_transport = "manual"
    corr = _draft(db, case, run, template="stop_order")
    mm = _prepared(db, _compose(client, case, corr, bcc_other=BCC))
    assert mm.transport == "manual"
    manual_msg = _msg(compose.read_raw(mm, db))
    assert manual_msg["X-Unsent"] == "1" and manual_msg["Bcc"] == BCC  # an Outlook draft: the client strips it
    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    assert 'id="retire-checklist"' not in client.get(path).text  # still manual: nothing to retire
    mail.settings.aegis_mail_transport = "file"  # Aegis sends now
    page = client.get(path).text
    assert 'id="mail-retire-form"' in page and "I did not send it from Outlook — retire it" in page
    assert 'id="mail-record-form"' in page  # … or Record as sent: the only two actions
    assert 'id="mail-edit"' not in page and 'id="renew"' not in page and "Cancel this e-mail" not in page
    inv = client_for("investigator", case=case)
    assert "a case admin chooses" in inv.get(path).text.lower()
    assert _retire(inv, case, mm).status_code == 403
    r = _retire(client, case, mm)
    assert r.status_code == 303 and f"/correspondence/{corr.id}/email?done=retired" in r.headers["location"]
    old = db.get(MailMessage, mm.id)
    db.refresh(old)
    assert old.status == MailStatus.CANCELLED and old.mime_path is None
    assert old.meta["not_sent_confirmed"]["by"] == client.user.id and "retired" in old.meta["history"][-1]["reason"]
    assert _audits(db, "MAIL_CANCELLED", "mail_messages", mm.id)[-1].detail["reason"] == "retired_not_sent"
    editor = client.get(r.headers["location"].split("#")[0]).text
    assert "checklist was retired" in editor and 'id="mail-checklist-open"' not in editor
    assert f'name="bcc_other" class="mono" value="{BCC}"' in editor  # its fields are loaded
    new = _mm_from_confirm(db, _editor(client, case, db.get(Correspondence, corr.id), action="send_now",
                                       bcc_other=BCC))
    assert new.transport == "file" and compose.bcc_of(new) == [BCC] and new.to_addrs == mm.to_addrs
    raw = compose.read_raw(new, db)
    assert _msg(raw)["X-Unsent"] is None and _msg(raw)["Bcc"] is None and BCC.encode() not in raw
    assert new.subject.startswith(f"[Aegis {case.reference} #{corr.id}]")
    assert _send(client, case, new).status_code == 303
    db.expire_all()
    assert db.get(MailMessage, new.id).status == MailStatus.SENT and mail.transport.bcc_calls == [[BCC]]
    assert db.get(Correspondence, corr.id).status == CorrespondenceStatus.SENT
    assert _send(client, case, old).status_code == 303 and len(mail.transport.sent) == 1  # never a second send
    assert _retire(client, case, old).status_code == 409  # retired once


# --------------------------------------------------------------------------- refusals: injection, limits, roles
@pytest.mark.parametrize("form, needle", [
    ({"bcc_other": "audit@athena.example\r\nBcc: x@evil.example"}, "line breaks"),
    ({"bcc_other": "audit@athena.example\nBcc: x@evil.example"}, "bare address"),
    ({"cc_other": "ops@kucoin.example\rTo: x@evil.example"}, "line breaks"),
    ({"subject": "Hello\r\nBcc: x@evil.example"}, "line breaks"),
    ({"bcc_other": "Name <audit@athena.example>"}, "bare address"),
    ({"bcc_other": MAILBOX}, "mailbox cannot be a recipient"),
    ({"bcc_other": ", ".join(f"b{i}@athena.example" for i in range(11))}, "at most 10 Bcc"),
    ({"cc_other": ", ".join(f"c{i}@kucoin.example" for i in range(8)),
      "bcc_other": ", ".join(f"b{i}@athena.example" for i in range(7))}, "at most 15 recipients"),
    ({"body_markdown": "Dear team,\x00\nhidden"}, "control characters"),
    ({"body_markdown": "   "}, "cannot be empty"),
])
def test_editor_refusals(db, case, run, client, mail, form, needle):
    corr = _draft(db, case, run)
    r = _editor(client, case, corr, action="send_now", **form)
    assert r.status_code == 400 and needle in r.text, (form, r.text[:400])
    assert not mail.transport.sent
    db.expire_all()
    assert not db.scalars(select(MailMessage).where(MailMessage.correspondence_id == corr.id,
                                                    MailMessage.status == MailStatus.PREPARED)).all()


def test_bcc_counts_in_the_local_domain_limit(db, case, run, client, mail):
    mail.settings.aegis_mail_transport = "graph"
    mail.settings.aegis_mail_dev_allowed_domains = "example.com"
    corr = _draft(db, case, run)
    r = _editor(client, case, corr, action="prepare", to_other="desk@test.example.com", bcc_other=BCC)
    assert r.status_code == 400 and "AEGIS_MAIL_DEV_ALLOWED_DOMAINS" in r.text


def test_non_ascii_subject_survives_the_header(db, case, run, client, mail):
    corr = _draft(db, case, run)
    subject = "Solicitud de congelación – cuenta Ñandú “urgente” " + "x" * 120
    mm = _prepared(db, _editor(client, case, corr, action="prepare", subject=subject))
    raw = compose.read_raw(mm, db)
    head = raw.split(b"\r\n\r\n", 1)[0]
    assert all(len(line) <= 998 for line in head.split(b"\r\n"))
    assert all(len(w) <= 75 for w in re.findall(rb"=\?utf-8\?[qb]\?[^?]*\?=", head, flags=re.IGNORECASE))
    expected = f"[Aegis {case.reference} #{corr.id}] " + compose.ascii_header(subject).strip()
    assert _msg(raw)["Subject"] == expected == mm.subject
    assert "Ñandú" in expected and '"urgente"' in expected and " - cuenta" in expected


def test_old_forms_without_an_action_still_prepare(db, case, run, client_for, mail):
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    before = corr.body_markdown
    mm = _prepared(db, _compose(inv, case, corr))
    db.expire_all()
    corr = db.get(Correspondence, corr.id)
    assert mm.status == MailStatus.PREPARED and corr.body_markdown == before and "mail_draft" not in (corr.meta or {})


def test_the_editor_routes_are_csrf_forms_and_only_the_send_route_sends():
    from test_mail_no_ai_send import _all_routes

    from app.main import app

    want = {("POST", "/cases/{case_id}/authorities/correspondence/{corr_id}/email"),
            ("POST", "/cases/{case_id}/authorities/correspondence/{corr_id}/email/preview"),
            ("POST", "/cases/{case_id}/mail/messages/{mid}/edit"),
            ("POST", "/cases/{case_id}/mail/messages/{mid}/retire-checklist")}
    found = set()
    for r in _all_routes(app.routes):
        for m in getattr(r, "methods", None) or set():
            if (m, getattr(r, "path", "")) in want:
                deps = {getattr(d.call, "__name__", "") for d in r.dependant.dependencies}
                assert deps & {"require_csrf", "require_csrf_capped"}, r.path  # capped: require_csrf_form
                found.add((m, r.path))
    assert found == want
    from pathlib import Path

    assert "send_mime" not in Path(compose.__file__).read_text(encoding="utf-8")  # composing never transmits


# --------------------------------------------------------------------------- review fixes: the letter while it is out
def _vault_files(vault) -> set[str]:
    """Evidence files in the vault (pending MIME excluded)."""
    if not vault.exists():
        return set()
    return {str(p.relative_to(vault)) for p in vault.rglob("*") if p.is_file() and compose.PENDING_DIR not in p.parts}


@pytest.mark.parametrize("state", ["sending", "unknown", "sent_unfiled"])
def test_the_letter_cannot_change_while_an_e_mail_of_it_is_out(db, case, run, client, client_for, mail, monkeypatch,
                                                               state):
    """Sending, unknown outcome, or sent with filing failed: the letter is still a draft, but its text, fields and
    uploads stay what the e-mail carries (the compose page, the preview's Edit and the letter page all refuse)."""
    from test_mail_compose_send import FakeTransportError

    from app.domain import evidence as ev

    corr = _draft(db, case, run, template="stop_order")
    inv = client_for("investigator", case=case)
    spare = _prepared(db, _compose(inv, case, corr))  # an earlier preview: cancelled by the admin's Send now
    original = corr.body_markdown
    mm = _mm_from_confirm(db, _editor(client, case, corr, action="send_now"))
    assert db.get(MailMessage, spare.id).status == MailStatus.CANCELLED
    if state == "sending":
        mm.status = MailStatus.SENDING
        db.commit()
    elif state == "unknown":
        mail.transport.fail = FakeTransportError("unknown_outcome", "timeout", outcome_unknown=True)
        assert _send(client, case, mm).headers["location"].endswith("?r=unknown")
    else:
        real = ev.store_upload
        monkeypatch.setattr(ev, "store_upload", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
        assert _send(client, case, mm).headers["location"].endswith("?r=sent")
        monkeypatch.setattr(ev, "store_upload", real)
    db.expire_all()
    mm, corr = db.get(MailMessage, mm.id), db.get(Correspondence, corr.id)
    assert corr.status == CorrespondenceStatus.DRAFT and mm.status.value == {"sent_unfiled": "sent"}.get(state, state)
    page = client.get(_path(case, corr)).text
    assert 'id="mail-editor-locked"' in page and '<fieldset class="mail-lock" disabled>' in page
    assert 'name="upload"' not in page and re.search(r'<textarea name="body_markdown"[^>]*readonly', page)
    before = _vault_files(mail.vault)
    n_items = db.scalar(select(EvidenceItem.id).order_by(EvidenceItem.id.desc()).limit(1))
    r = _editor(client, case, corr, action="upload", body_markdown="TOTALLY DIFFERENT TEXT",
                files=[("upload", ("x.pdf", b"%PDF-1.4 small", "application/pdf"))])
    assert r.status_code == 400 and f"e-mail #{mm.id}" in r.text.lower()
    for action in ("save", "prepare", "send_now"):
        assert _editor(client, case, corr, action=action, body_markdown="TOTALLY DIFFERENT TEXT").status_code == 400
    path = f"/cases/{case.id}/mail/messages/{spare.id}"
    r = client.post(f"{path}/edit", data={"csrf_token": csrf_token(client, path)}, follow_redirects=False)
    assert r.status_code == 409 and f"e-mail #{mm.id}" in r.text.lower()
    letter = f"/cases/{case.id}/authorities/correspondence/{corr.id}"
    r = client.post(letter, data={"csrf_token": csrf_token(client, letter), "subject": "changed",
                                  "body_markdown": "TOTALLY DIFFERENT TEXT", "recipients": TO, "cc": ""})
    assert r.status_code == 409
    db.expire_all()
    corr = db.get(Correspondence, corr.id)
    assert corr.body_markdown == original and corr.stop_order.body_markdown == original
    assert "TOTALLY" not in json.dumps(corr.meta) and _vault_files(mail.vault) == before
    assert db.scalar(select(EvidenceItem.id).order_by(EvidenceItem.id.desc()).limit(1)) == n_items
    assert db.get(MailMessage, spare.id).status == MailStatus.CANCELLED


@dataclass
class HookTransport(BccTransport):
    """Runs `hook` while the message is "on the wire" (inside send_mime)."""
    hook: object = None

    def send_mime(self, raw, *, message_id, bcc=None):
        if self.hook is not None:
            self.hook()
        return super().send_mime(raw, message_id=message_id, bcc=bcc)


@pytest.mark.parametrize("who", ["cancel", "reopen", "supersede", "retire"])
def test_a_cancel_never_overwrites_a_send_that_claimed_the_row(db, case, run, client, mail, monkeypatch, who):
    """Another session loaded the e-mail while it was prepared and cancels it while the Send is on the wire: the
    compare-and-swap leaves the sending row (and its pending MIME) alone, so the send is filed and the letter
    marked sent."""
    from app.core.permissions import CaseAccess, effective_role, membership
    from app.db.models import Case, User
    from app.db.session import SessionLocal

    transport = HookTransport()
    monkeypatch.setattr(mail_send, "_transport", lambda: transport)
    corr = _draft(db, case, run)
    mm = _mm_from_confirm(db, _editor(client, case, corr, action="send_now"))
    pending = mail.vault / mm.mime_path
    other = SessionLocal()
    mm_b, corr_b = other.get(MailMessage, mm.id), other.get(Correspondence, corr.id)
    assert mm_b.status == MailStatus.PREPARED  # loaded before the Send claims it
    user = other.get(User, client.user.id)
    case_b = other.get(Case, case.id)
    access_b = CaseAccess(case=case_b, user=user, role=effective_role(other, user, case_b),
                          member=membership(other, user, case_b))
    seen = {}

    def cancel_now():
        seen["pending_before"] = pending.exists()
        try:
            if who == "cancel":
                mail_send.cancel(other, access_b, mm_b)
            elif who == "reopen":
                compose.reopen_for_edit(other, access_b, mm_b, corr_b)
            elif who == "supersede":  # selects the prepared rows afresh: the sending one is not among them
                seen["result"] = compose.supersede_prepared(other, access_b, corr_b, reason="edited") or None
            else:
                seen["result"] = compose.retire_prepared(other, mm_b, by=user.id)
                other.commit()
        except (compose.ComposeError, mail_send.SendError) as e:
            seen["refused"] = str(e)
            other.rollback()
        seen["pending_after"] = pending.exists()

    transport.hook = cancel_now
    try:
        assert _send(client, case, mm).headers["location"].endswith("?r=sent")
    finally:
        other.close()
    assert seen["pending_before"] and seen["pending_after"]  # the MIME was never deleted mid-send
    assert seen.get("refused") or seen.get("result", "x") is None
    db.expire_all()
    mm, corr = db.get(MailMessage, mm.id), db.get(Correspondence, corr.id)
    assert mm.status == MailStatus.SENT and mm.meta.get("finalized") and mm.eml_evidence_id
    assert "finalize_error" not in mm.meta and corr.status == CorrespondenceStatus.SENT
    assert compose.letter_in_flight(db, corr) is not None and len(transport.sent) == 1


# --------------------------------------------------------------------------- review fixes: the confirmation panel
def test_the_confirmation_locks_the_editor_and_shows_the_frozen_text(db, case, run, client, mail):
    corr = _draft(db, case, run)
    body = corr.body_markdown.rstrip() + f"\n\n{MARKER}\n"
    mm = _mm_from_confirm(db, _editor(client, case, corr, action="send_now", body_markdown=body))
    page = client.get(_path(case, corr) + f"?confirm={mm.id}").text
    panel = page[page.index('id="confirm"'):page.index('id="mail-compose-form"')]
    assert 'id="confirm-text"' in panel and MARKER in panel  # the text/plain as frozen
    assert 'id="confirm-edit"' in panel and f"/mail/messages/{mm.id}/edit" in panel
    assert '<fieldset class="mail-lock" disabled>' in page and 'id="mail-editor-locked"' in page
    assert re.search(r'<textarea name="body_markdown"[^>]*readonly', page)
    # Edit: the prepared e-mail is cancelled, the editor reopens with every field; the old bytes never go out
    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    r = client.post(f"{path}/edit", data={"csrf_token": csrf_token(client, path)}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("?done=edit#editor")
    db.expire_all()
    assert db.get(MailMessage, mm.id).status == MailStatus.CANCELLED
    editor = client.get(r.headers["location"].split("#")[0]).text
    assert "mail-lock\" disabled" not in editor and 'name="upload"' in editor
    assert _send(client, case, db.get(MailMessage, mm.id)).status_code == 303 and not mail.transport.sent


# --------------------------------------------------------------------------- review fixes: an old manual checklist
def _manual_checklist(db, case, run, client, mail, **form):
    mail.settings.aegis_mail_transport = "manual"
    corr = _draft(db, case, run, template="stop_order")
    mm = _prepared(db, _compose(client, case, corr, **form))
    mail.settings.aegis_mail_transport = "file"  # Aegis sends now
    return corr, mm


def test_retire_is_refused_while_an_outlook_send_waits_for_review(db, case, run, client, mail):
    corr, mm = _manual_checklist(db, case, run, client, mail)
    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    page = client.get(path).text
    assert 'id="mail-checklist-open"' in page and 'id="mail-outlook-checklist"' in page  # the Outlook steps fold away
    seen = _outlook_send_waiting(db, case, mm)
    try:
        r = _retire(client, case, mm)
        assert r.status_code == 409 and "waiting for review" in r.text and f"e-mail #{seen.id}" in r.text
        assert 'id="mail-outlook-suspected"' in r.text and f"/cases/{case.id}/blocks" in r.text
        assert [(m.id, m.status) for m in _letter_mails(db, corr)] == [(mm.id, MailStatus.PREPARED)]
        # once reviewed (dismissed: not this letter), it goes ahead
        seen = db.get(MailMessage, seen.id)
        seen.meta = {**seen.meta, "needs_review": False}
        db.commit()
        assert _retire(client, case, mm).status_code == 303
        assert _letter_mails(db, corr)[0].status == MailStatus.CANCELLED
    finally:
        db.delete(db.get(MailMessage, seen.id))
        db.commit()


def test_retire_keeps_the_fields_for_the_editor(db, case, run, client, mail):
    corr, mm = _manual_checklist(db, case, run, client, mail, cc_other="Ops@Kucoin.example", bcc_other=BCC)
    r = _retire(client, case, mm)
    assert r.status_code == 303
    db.expire_all()
    saved = db.get(Correspondence, corr.id).meta["mail_draft"]
    assert saved["to"] == [TO] and saved["cc"] == ["Ops@kucoin.example"] and saved["bcc_other"] == BCC
    assert saved["from_message"] == mm.id and saved["attach"] == ["letter"]
    page = client.get(r.headers["location"].split("#")[0]).text
    assert TO in page and "Ops@kucoin.example" in page and f'name="bcc_other" class="mono" value="{BCC}"' in page


# --------------------------------------------------------------------------- review fixes: uploads
@pytest.mark.parametrize("name", ["page.html;", "tool.exe;", "x.html\u200b", "report.pdf.", "page.htm\u00ad"])
def test_upload_names_with_a_disguised_extension_are_refused(db, case, run, client_for, mail, name):
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    before = _vault_files(mail.vault)
    r = _editor(inv, case, corr, action="upload", files=[("upload", (name, b"<html><script>x()</script>", "text/html"))])
    assert r.status_code == 400 and "unusual extension" in r.text, r.text[:300]
    assert _vault_files(mail.vault) == before


def test_evidence_named_as_active_content_is_never_attached(db, case, run, client, mail):
    from app.domain import evidence as ev

    corr = _draft(db, case, run)
    item = ev.store_upload(db, case, io.BytesIO(b"<svg onload='x()'/>"), filename="diagram.svg", folder="other")
    db.commit()
    assert not compose.is_dangerous(item)  # not tagged: the extension it would go out under decides
    page = client.get(_path(case, corr)).text
    assert re.search(rf'value="evidence:{item.id}"[^>]*disabled', page)
    r = _editor(client, case, corr, action="prepare", attach=["letter", f"evidence:{item.id}"])
    assert r.status_code == 400 and "active content" in r.text


def test_a_failed_upload_leaves_no_bytes_in_the_vault(db, case, run, client_for, mail, monkeypatch):
    from app.domain import evidence as ev

    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    real, calls = ev.store_upload, []

    def second_fails(*a, **k):
        calls.append(1)
        if len(calls) == 2:
            raise ev.EvidenceError("the vault is full")
        return real(*a, **k)

    monkeypatch.setattr(ev, "store_upload", second_fails)
    before = _vault_files(mail.vault)
    last = db.scalar(select(EvidenceItem.id).order_by(EvidenceItem.id.desc()).limit(1))
    r = _editor(inv, case, corr, action="upload", files=[("upload", ("a.pdf", b"%PDF-1.4 a", "application/pdf")),
                                                         ("upload", ("b.pdf", b"%PDF-1.4 b", "application/pdf"))])
    assert r.status_code == 400 and "could not be stored" in r.text and len(calls) == 2
    assert _vault_files(mail.vault) == before
    db.expire_all()
    assert db.scalar(select(EvidenceItem.id).order_by(EvidenceItem.id.desc()).limit(1)) == last


def test_an_unticked_upload_is_not_evidence_of_the_sent_letter(db, case, run, client, mail):
    corr = _draft(db, case, run)
    r = _editor(client, case, corr, action="upload", files=[("upload", ("wrong.pdf", b"%PDF-1.4 w", "application/pdf"))])
    assert r.status_code == 303
    db.expire_all()
    corr = db.get(Correspondence, corr.id)
    up = corr.meta["mail_uploads"][0]
    page = client.get(_path(case, corr)).text
    assert f'sent as <span class="mono">{case.reference}_evidence-{up}.pdf</span>' in page
    mm = _mm_from_confirm(db, _editor(client, case, corr, action="send_now", attach=["letter"]))
    assert _send(client, case, mm).headers["location"].endswith("?r=sent")
    db.expire_all()
    corr = db.get(Correspondence, corr.id)
    assert up not in corr.meta["evidence_ids"] and corr.meta["unsent_uploads"] == [up]
    assert db.get(EvidenceItem, up) is not None  # it stays filed
    letter = client.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}").text
    assert "wrong.pdf" not in letter


# --------------------------------------------------------------------------- review fixes: status, two editors, wording
def test_reconcile_and_retry_filing_refresh_block_status(db, case, run, client, mail, monkeypatch):
    from test_mail_compose_send import FakeTransportError

    calls = []
    real = mail_send.refresh_status
    monkeypatch.setattr(mail_send, "refresh_status", lambda db, mm, actor=None: (calls.append(mm.id),
                                                                                    real(db, mm, actor)))
    corr = _draft(db, case, run)
    mm = _mm_from_confirm(db, _editor(client, case, corr, action="send_now"))
    mail.transport.fail = FakeTransportError("unknown_outcome", "timeout", outcome_unknown=True)
    _send(client, case, mm)
    assert calls == []
    c = db.get(type(case), case.id)
    c.facts = {k: v for k, v in (c.facts or {}).items() if k != block_status.SNAPSHOT_KEY}
    db.commit()
    mail.transport.fail, mail.transport.lookup_state = None, "sent"
    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    assert client.post(f"{path}/reconcile", data={"csrf_token": csrf_token(client, path)}).status_code == 200
    db.expire_all()
    assert db.get(MailMessage, mm.id).meta.get("finalized") and calls == [mm.id]
    assert block_status.SNAPSHOT_KEY in (db.get(type(case), case.id).facts or {})
    # a scheduler pass over an already filed e-mail refreshes nothing again
    mail_send.reconcile_unknown_all(db)
    assert calls == [mm.id]


def test_the_letter_page_edit_wins_over_the_editors_saved_fields(db, case, run, client, mail):
    corr = _draft(db, case, run)
    assert _editor(client, case, corr, action="save", subject="Editor subject", bcc_other=BCC).status_code == 303
    letter = f"/cases/{case.id}/authorities/correspondence/{corr.id}"
    db.expire_all()
    corr = db.get(Correspondence, corr.id)
    r = client.post(letter, data={"csrf_token": csrf_token(client, letter), "subject": "Letter page subject",
                                  "body_markdown": corr.body_markdown, "recipients": "other@kucoin.example", "cc": ""},
                    follow_redirects=False)
    assert r.status_code == 303
    page = client.get(_path(case, corr)).text
    assert 'value="Letter page subject"' in page and "Editor subject" not in page
    assert "other@kucoin.example" in page and f'name="bcc_other" class="mono" value="{BCC}"' in page


def test_the_entry_points_name_the_editor(db, case, run, client, client_for):
    corr = _draft(db, case, run)
    letter = f"/cases/{case.id}/authorities/correspondence/{corr.id}"
    assert "Edit &amp; send e-mail" in client.get(letter).text
    inv = client_for("investigator", case=case).get(letter).text
    assert "Edit e-mail" in inv and "Edit &amp; send e-mail" not in inv


# --------------------------------------------------------------------------- review round 2: old checklists after go-live
def _outlook_send_waiting(db, case, mm):
    """A message the Sent Items sync logged after the checklist, ambiguous: waiting for review."""
    from datetime import UTC, datetime

    seen = MailMessage(case_id=case.id, direction=mm.direction, status=MailStatus.SENT_EXTERNAL, transport="graph",
                       mailbox=MAILBOX, message_id=f"<outlook-{mm.id}@example.com>", folder="sentitems",
                       outside_sent=True, authority_key=mm.meta["authority_key"], sent_at=datetime.now(tz=UTC),
                       to_addrs=[], cc_addrs=[], attachments=[], meta={"needs_review": True, "review_reason": "x"})
    db.add(seen)
    db.commit()
    return seen


def _letter_mails(db, corr):
    db.expire_all()
    return db.scalars(select(MailMessage).where(MailMessage.correspondence_id == corr.id)
                      .order_by(MailMessage.id)).all()


def test_a_manual_checklist_is_never_offered_or_sent_through_the_live_transport(db, case, run, client, mail):
    corr, mm = _manual_checklist(db, case, run, client, mail, bcc_other=BCC)
    assert mm.transport == "manual" and mm.message_id == "" and mm.status == MailStatus.PREPARED
    page = client.get(_path(case, corr) + f"?confirm={mm.id}").text
    assert 'id="mail-send-form"' not in page and mm.prepare_token not in page
    assert 'id="mail-checklist-open"' in page and "no longer waiting" not in page
    r = _send(client, case, mm)  # the token posted straight to the Send route
    assert r.status_code == 409 and 'id="mail-checklist-open"' in r.text and "retire it" in r.text
    db.expire_all()
    assert db.get(MailMessage, mm.id).status == MailStatus.PREPARED and not mail.transport.sent


CHECKLIST_TEXT = "from before Aegis sent e-mail itself. Open it and choose: I did not send it from Outlook — retire it"


@pytest.mark.parametrize("action", ["send_now", "save", "upload", "prepare", ""])
def test_the_editor_refuses_everything_while_an_old_checklist_is_open(db, case, run, client, mail, action):
    corr, mm = _manual_checklist(db, case, run, client, mail)
    page = client.get(_path(case, corr)).text
    assert 'id="mail-checklist-open"' in page and f'href="/cases/{case.id}/mail/messages/{mm.id}"' in page
    assert CHECKLIST_TEXT in page and 'mail-lock" disabled' in page and 'id="mail-send-now"' not in page
    files = [("upload", ("a.pdf", b"%PDF-1.4 a", "application/pdf"))] if action == "upload" else None
    r = _editor(client, case, corr, action=action, files=files, body_markdown=corr.body_markdown + "\nmine\n")
    assert r.status_code == 409 and f"Outlook checklist (#{mm.id})" in r.text
    assert [(m.id, m.status) for m in _letter_mails(db, corr)] == [(mm.id, MailStatus.PREPARED)]
    corr = db.get(Correspondence, corr.id)
    assert "mine" not in corr.body_markdown and not (corr.meta or {}).get("mail_uploads") and not mail.transport.sent


def test_edit_cancel_and_prepare_again_on_an_open_checklist_are_refused(db, case, run, client, mail):
    corr, mm = _manual_checklist(db, case, run, client, mail, cc_other="Ops@Kucoin.example")
    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    for action in ("edit", "cancel"):
        r = client.post(f"{path}/{action}", data={"csrf_token": csrf_token(client, path)}, follow_redirects=False)
        assert r.status_code == 409 and 'id="mail-checklist-open"' in r.text and "retire it" in r.text, action
    assert [(m.id, m.status) for m in _letter_mails(db, corr)] == [(mm.id, MailStatus.PREPARED)]
    # expired: still open (it may have gone out); Prepare again is not offered and refused, retire is offered
    row = db.get(MailMessage, mm.id)
    row.status = MailStatus.EXPIRED
    db.commit()
    page = client.get(path).text
    assert 'id="renew"' not in page and 'id="mail-retire-form"' in page and "may still have been sent" in page
    r = client.post(f"{path}/renew", data={"csrf_token": csrf_token(client, path)}, follow_redirects=False)
    assert r.status_code == 409 and 'id="mail-checklist-open"' in r.text
    assert [(m.id, m.status) for m in _letter_mails(db, corr)] == [(mm.id, MailStatus.EXPIRED)]
    # retired: the letter is free again
    assert _retire(client, case, mm).status_code == 303
    r = _editor(client, case, db.get(Correspondence, corr.id), action="")
    assert r.status_code == 303
    rows = _letter_mails(db, corr)
    assert rows[0].status == MailStatus.CANCELLED and rows[1].status == MailStatus.PREPARED
    assert rows[1].transport == "file"


def test_retire_takes_the_case_mailbox_out_of_cc(db, case, run, client, mail):
    corr, mm = _manual_checklist(db, case, run, client, mail, cc=[MAILBOX])
    assert MAILBOX in mm.cc_addrs  # manual mode: the case mailbox may be copied
    r = _retire(client, case, mm)
    assert r.status_code == 303 and "dropped=1" in r.headers["location"]
    assert "taken out of Cc" in client.get(r.headers["location"].split("#")[0]).text
    saved = db.get(Correspondence, corr.id).meta["mail_draft"]
    assert MAILBOX not in [a.lower() for a in saved["cc"]] and MAILBOX not in saved["bcc_other"]
    new = _mm_from_confirm(db, _editor(client, case, db.get(Correspondence, corr.id), action="send_now",
                                       cc=saved["cc"]))
    assert MAILBOX not in [a.lower() for a in new.cc_addrs]
    # typed in on the editor while Aegis sends: the refusal names the field
    p2 = f"/cases/{case.id}/mail/messages/{new.id}"
    client.post(f"{p2}/edit", data={"csrf_token": csrf_token(client, p2)})
    r = _editor(client, case, db.get(Correspondence, corr.id), action="send_now", cc_other=MAILBOX)
    assert r.status_code == 400 and f"remove {MAILBOX} from Cc" in r.text


def test_a_second_save_after_the_stale_refusal_is_refused_again(db, case, run, client, mail):
    corr = _draft(db, case, run)
    page = client.get(_path(case, corr)).text
    data = {"csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', page).group(1),
            "draft_hash": re.search(r'name="draft_hash" value="([^"]+)"', page).group(1),
            "subject": corr.subject, "to_other": TO, "attach": ["letter"], "action": "save",
            "body_markdown": corr.body_markdown + "\nmine\n"}
    desk.update_body(db, corr, corr.body_markdown + "\nOTHER-MEMBER-EDIT\n", actor=None, source="test")
    db.commit()
    r = client.post(_path(case, corr), data=data, follow_redirects=False)
    assert r.status_code == 400 and 'id="mail-stale-letter"' in r.text and "OTHER-MEMBER-EDIT" in r.text
    data["draft_hash"] = re.search(r'name="draft_hash" value="([^"]+)"', r.text).group(1)
    r = client.post(_path(case, corr), data=data, follow_redirects=False)
    assert r.status_code == 400 and "changed while you were editing" in r.text
    db.expire_all()
    body = db.get(Correspondence, corr.id).body_markdown
    assert "OTHER-MEMBER-EDIT" in body and "mine" not in body


def test_the_compose_page_names_waiting_e_mails_and_what_a_save_cancelled(db, case, run, client, client_for, mail):
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    mm = _prepared(db, _compose(inv, case, corr))
    page = client.get(_path(case, corr)).text
    assert 'id="mail-waiting"' in page and f"/mail/messages/{mm.id}" in page and "cancels it" in page
    assert "tracking tag at the start of the subject" in page or 'id="mail-howto"' not in page
    assert "Other To addresses (comma-separated)" in page and 'id="mail-subject-letter-note"' in page
    r = _editor(client, case, corr, action="save")
    assert r.status_code == 303 and f"cancelled={mm.id}" in r.headers["location"]
    page = client.get(r.headers["location"].split("#")[0]).text
    assert f"#{mm.id} was cancelled" in page and 'id="mail-waiting"' not in page


def test_an_expired_preview_is_not_named_as_waiting(db, case, run, client, mail):
    from datetime import UTC, datetime, timedelta

    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(client, case, corr))
    mm.expires_at = datetime.now(tz=UTC) - timedelta(minutes=1)  # past its 30 minutes, not yet swept to expired
    db.commit()
    assert 'id="mail-waiting"' not in client.get(_path(case, corr)).text
    page = client.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    assert "Expired — nothing was sent" in page and "valid until" not in page


def test_bcc_rows_of_the_send_form_say_hidden_recipient(db, case, run, client, mail):
    corr = _draft(db, case, run)
    mm = _mm_from_confirm(db, _editor(client, case, corr, action="send_now", bcc_other=BCC))
    page = client.get(_path(case, corr) + f"?confirm={mm.id}").text
    assert f'value="{BCC}"' in page and "is an intended hidden (Bcc) recipient" in page


def test_the_sender_alert_tells_a_case_admin_how_to_send(db, case, run, client, client_for, mail):
    from test_mail_one_send import _drop_profile

    from app.services import seed_from_fixture

    _drop_profile(db, case)
    corr = _draft(db, case, run)
    page = client.get(_path(case, corr)).text  # no profile: a note, nothing to acknowledge
    assert 'id="mail-sender-note"' in page and 'id="mail-sender-ack-needed"' not in page and 'id="mail-send-now"' in page
    seed_from_fixture(db)  # the profile again: the letter (the PI-firm block) is a mismatch
    db.expire_all()
    page = client.get(_path(case, corr)).text
    assert 'id="mail-sender-ack-needed"' in page and "tick the acknowledgement" in page and 'id="mail-send-now"' in page
    inv = client_for("investigator", case=case).get(_path(case, corr)).text
    assert "a case admin ticks the acknowledgement" in inv and "Send stays blocked" not in inv


def test_record_as_sent_keeps_the_bcc_on_the_letter(db, case, run, client, mail):
    from test_mail_manual import _record

    mail.settings.aegis_mail_transport = "manual"
    corr = _draft(db, case, run, template="stop_order")
    mm = _prepared(db, _compose(client, case, corr, bcc_other=BCC))
    r = _record(client, case, mm)
    assert r.status_code == 303, r.text[:800]
    db.expire_all()
    letter = db.get(Correspondence, corr.id)
    assert letter.status == CorrespondenceStatus.SENT and letter.meta["bcc"] == [BCC]


@pytest.fixture(autouse=True)
def _retire_left_over_checklists(db):
    """The test DB is shared by the whole run: an Outlook checklist a test leaves open would (rightly) stop later
    tests from regenerating that entity's stop order (services.generate_stop_orders), so each is cancelled after."""
    yield
    from app.db.models import MailMessage as _MM
    from app.db.models import MailStatus as _MS

    db.rollback()
    for m in db.query(_MM).filter(_MM.transport == "manual", _MM.status.in_((_MS.PREPARED, _MS.EXPIRED))).all():
        m.status = _MS.CANCELLED
    db.commit()


@pytest.mark.parametrize("closing", ["Yours respectfully,\nJ. Smith\nAcme Investigations Ltd",
                                     "Respectfully,\nJ. Smith, Acme Investigations Ltd",
                                     "Thank you,\nJ. Smith"])
def test_profile_signature_replaces_a_closing_that_shares_its_paragraph_with_the_name(closing):
    out = compose.with_profile_signature(f"Dear X,\n\nWe write as Acme.\n\nPlease freeze it.\n\n{closing}\n",
                                         "We write as Athena.", "Yours faithfully,\n\nAthena Investigations")
    assert "J. Smith" not in out and out.rstrip().endswith("Athena Investigations")
