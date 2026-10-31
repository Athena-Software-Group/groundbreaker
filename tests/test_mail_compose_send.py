"""E-mail desk: compose → prepare → preview → send → filing, against a fake transport and fake settings
plugged into app.domain.mail_send's two seams (no app.mail import, no network, no real mailbox)."""

import hashlib
import io
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from email import policy
from email.parser import BytesParser
from types import SimpleNamespace

import pytest
from conftest import csrf_token, ungated
from docx import Document
from sqlalchemy import select

from app import services
from app.db.models import (
    AuditEvent,
    Chain,
    Correspondence,
    CorrespondenceStatus,
    EvidenceItem,
    MailMessage,
    MailStatus,
    StopOrderStatus,
)
from app.domain import correspondence as desk
from app.domain import evidence as ev
from app.domain import mail_compose as compose
from app.domain import mail_send
from app.domain import sender as sender_mod

MAILBOX = "case-desk@aegis.example"
TO = "le-requests@kucoin.example"


# --------------------------------------------------------------------------- fakes (the §7 contract)
@dataclass
class FakeSettings:
    aegis_mail_transport: str = "file"
    aegis_mail_from: str = MAILBOX
    aegis_mail_from_name: str = "Athena Software Group, Inc."
    aegis_mail_max_message_bytes: int = 2_900_000
    aegis_mail_send_per_hour: int = 20
    aegis_mail_send_per_hour_global: int = 60
    aegis_mail_dev_allowed_domains: str = "example.com,example.org,example.net,example"
    aegis_mail_live_sending: bool = False

    @property
    def mail_from(self):
        return self.aegis_mail_from.strip().lower()

    @property
    def mail_domain(self):
        return self.mail_from.rpartition("@")[2]

    @property
    def from_name(self):
        return self.aegis_mail_from_name

    @property
    def max_message_bytes(self):
        return self.aegis_mail_max_message_bytes

    @property
    def dev_allowed_domains(self):
        return {d.strip() for d in self.aegis_mail_dev_allowed_domains.split(",") if d.strip()}


class FakeTransportError(Exception):
    def __init__(self, reason, message="", *, outcome_unknown=False, provider_message_id=None):
        super().__init__(message or reason)
        self.reason, self.message = reason, message or reason
        self.outcome_unknown, self.provider_message_id = outcome_unknown, provider_message_id


@dataclass
class FakeTransport:
    name: str = "file"
    configured: bool = True
    sent: list = field(default_factory=list)
    fail: Exception | None = None
    lookup_state: str = "sent"
    deleted: list = field(default_factory=list)  # delete_drafts calls (message_id, provider_message_id)
    delete_fail: Exception | None = None
    delete_result: str = "deleted"

    def status(self):
        return SimpleNamespace(name=self.name, configured=self.configured,
                               reason="ok" if self.configured else "Sending is disabled (AEGIS_MAIL_TRANSPORT=none)",
                               mailbox=MAILBOX)

    def _result(self, message_id):
        return SimpleNamespace(transport=self.name, message_id=message_id, internet_message_id=message_id,
                               provider_message_id=f"file:{uuid.uuid4().hex[:8]}.eml", conversation_id="conv-1",
                               sent_at=datetime.now(tz=UTC), detail={})

    def send_mime(self, raw, *, message_id):
        self.sent.append(raw)
        if self.fail is not None:
            raise self.fail
        return self._result(message_id)

    def lookup_sent(self, *, message_id, provider_message_id):
        res = self._result(message_id) if self.lookup_state == "sent" else None
        if self.lookup_state == "draft":
            res = SimpleNamespace(**{**vars(self._result(message_id)), "provider_message_id": provider_message_id})
        return SimpleNamespace(state=self.lookup_state, result=res)

    def delete_drafts(self, *, message_id, provider_message_id):
        self.deleted.append((message_id, provider_message_id))
        if self.delete_fail is not None:
            raise self.delete_fail
        if self.delete_result == "deleted":
            self.lookup_state = "missing"
        return self.delete_result



@pytest.fixture
def mail(monkeypatch, tmp_path):
    vault = tmp_path / "vault"
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(vault))
    settings, transport = FakeSettings(), FakeTransport()
    monkeypatch.setattr(mail_send, "_settings", lambda: settings)
    monkeypatch.setattr(mail_send, "_transport", lambda: transport)
    return SimpleNamespace(settings=settings, transport=transport, vault=vault)


@pytest.fixture
def emitted(monkeypatch):
    calls = []
    real = desk.events.emit

    def spy(db, case, event_type, **kw):
        calls.append({"type": event_type, **kw})
        return real(db, case, event_type, **kw)

    monkeypatch.setattr(desk.events, "emit", spy)
    return calls


@pytest.fixture
def run(db, case):
    return services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")


def _auth(db, case, name, run=None):
    db.expire_all()
    return next(a for a in desk.case_authorities(db, case, run=run) if a.name == name)


def _draft(db, case, run, template="info_request", name="KuCoin"):
    """A draft letter to `name` of the shared demo case, one test after another (past the request gate: conftest
    .ungated)."""
    with ungated():
        return desk.generate_letter(db, case, _auth(db, case, name, run), template, actor=None, run=run)


def _compose(c, case, corr, **form):
    path = f"/cases/{case.id}/authorities/correspondence/{corr.id}/email"
    page = c.get(path)
    assert page.status_code == 200, page.text[:500]
    data = {"csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1),
            "draft_hash": re.search(r'name="draft_hash" value="([^"]+)"', page.text).group(1),
            "subject": corr.subject[:200], "to_other": TO, "attach": ["letter"]}
    data.update(form)
    return c.post(path, data=data, follow_redirects=False)


def _prepared(db, response) -> MailMessage:
    assert response.status_code == 303, response.text[:2000]
    db.expire_all()
    return db.get(MailMessage, int(response.headers["location"].split("?")[0].rsplit("/", 1)[1]))


def _send(c, case, mm, **extra):
    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    data = {"csrf_token": csrf_token(c, path), "prepare_token": mm.prepare_token, "confirm_send": "1",
            "confirm_unverified": list(mm.confirmations.get("unverified") or []),
            "confirm_attachment": [str(i) for i in mm.confirmations.get("attachments") or []], "due_days": "5"}
    data.update(extra)
    return c.post(f"{path}/send", data=data, follow_redirects=False)


def _other_case(db):
    return services.create_case(
        db, reference=f"TEST-MAIL-{uuid.uuid4().hex[:8]}", title="Another case", victim_name="Other Victim",
        victim_entity=None, loss_amount=Decimal(1), loss_asset="USDC", loss_usd=Decimal(1), fraud_date=None,
        chain=Chain.ETHEREUM, origin_tx=None, victim_wallet=None, perpetrator_wallet=None)


# --------------------------------------------------------------------------- prepare
def test_prepare_builds_the_exact_message(db, case, run, client_for, mail):
    corr = _draft(db, case, run)
    profile = sender_mod.get_profile(db, case)
    auth_id = profile.authority_evidence_ids[0]
    inv = client_for("investigator", case=case)
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email").text
    assert f"[Aegis {case.reference} #{corr.id}]" in page and f'value="authority:{auth_id}" checked' in page
    r = _compose(inv, case, corr, cc_other="Ops@Kucoin.example", attach=["letter", f"authority:{auth_id}"])
    mm = _prepared(db, r)
    assert mm.status == MailStatus.PREPARED and mm.created_by == inv.user.id and mm.transport == "file"
    assert mm.subject == f"[Aegis {case.reference} #{corr.id}] {compose.ascii_header(corr.subject[:200])}"
    assert mm.to_addrs == [TO] and mm.cc_addrs == ["Ops@kucoin.example"]
    assert mm.expires_at - mm.prepared_at == timedelta(minutes=30) and len(mm.prepare_token) >= 40
    raw = compose.read_raw(mm, db)
    assert hashlib.sha256(raw).hexdigest() == mm.mime_sha256 and len(raw) == mm.mime_size
    assert (mail.vault / mm.mime_path).stat().st_mode & 0o777 == 0o600
    assert ((mail.vault / mm.mime_path).parent.stat().st_mode & 0o777) == 0o700
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    assert msg["From"] == f'"Athena Software Group, Inc." <{MAILBOX}>' and msg["Reply-To"] == msg["From"]
    assert msg["To"] == TO and msg["Cc"] == "Ops@kucoin.example" and msg["Bcc"] is None
    assert msg["Message-ID"] == mm.message_id and mm.message_id.endswith("@aegis.example>")
    assert msg["Subject"] == mm.subject and msg.get_content_type() == "multipart/mixed"
    assert not [k for k in msg if k.lower().startswith("x-")]  # no X-headers carrying case data
    assert "Jordan Avery" not in str(msg["From"]) and "Northbridge" not in str(msg["From"])
    text = msg.get_body(("plain",)).get_content()
    html = msg.get_body(("html",)).get_content()
    assert "We write as Athena Software Group, Inc., on behalf of Northbridge Analytics, Inc. (Jordan Avery)" in text
    assert "**" not in text and "###" not in text and "Review before sending" not in text
    assert '<meta charset="utf-8">' in html and "<script" not in html and "<img" not in html and "http" not in \
        html.split("<body")[0].replace('content="width=device-width"', "")
    atts = {p.get_filename(): p for p in msg.iter_attachments()}
    ref = case.reference
    assert set(atts) == {f"{ref}_letter-{corr.id}.docx", f"{ref}_authority-{auth_id}.txt"}  # neutral names
    doc = Document(io.BytesIO(atts[f"{ref}_letter-{corr.id}.docx"].get_payload(decode=True)))
    body = "\n".join(p.text for p in doc.paragraphs)
    assert doc.core_properties.content_status == "Final"
    assert doc.core_properties.comments == "Sent by Athena Software Group, Inc. via Aegis"
    assert "Information and preservation request" in body and "Draft generated by Aegis" not in body
    assert f"case {ref}" not in body.split("\n")[0] and "Sent: not sent" not in body  # no internal filing header
    assert atts[f"{ref}_authority-{auth_id}.txt"].get_payload(decode=True) == \
        db.get(EvidenceItem, auth_id).inline_text.encode()
    assert [m["kind"] for m in mm.attachments] == ["letter_docx", "authority_doc"]
    assert mm.confirmations == {"unverified": [TO, "Ops@kucoin.example"], "attachments": []}
    audit = db.scalars(select(AuditEvent).where(AuditEvent.object_type == "mail_messages",
                                                AuditEvent.object_id == str(mm.id))).first()
    assert audit.action == "CREATE" and audit.detail["n_to"] == 1 and audit.detail["n_attachments"] == 2
    assert "@" not in json.dumps(audit.detail)
    preview = inv.get(f"/cases/{case.id}/mail/messages/{mm.id}")
    assert preview.status_code == 200 and "Only case admins can send" in preview.text
    assert mm.message_id.replace("<", "&lt;").replace(">", "&gt;") in preview.text and mm.mime_sha256 in preview.text
    assert "HTML version" in preview.text and "generated from the same letter text" in preview.text


def test_prepare_refusals(db, case, run, client_for, mail):
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    ic3 = next(e for e in case.evidence_items if e.title.startswith("IC3 complaint receipt"))  # TLP:AMBER
    r = _compose(inv, case, corr, attach=["letter", f"evidence:{ic3.id}"])
    assert r.status_code == 400 and "TLP" in r.text
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email").text
    assert re.search(rf'value="evidence:{ic3.id}"[^>]*disabled', page)
    foreign = ev.add_note(db, _other_case(db), title="foreign", text="synthetic", folder="other")
    db.commit()
    assert _compose(inv, case, corr, attach=["letter", f"evidence:{foreign.id}"]).status_code == 404
    for form, needle in (({"subject": "Hello\r\nBcc: x@evil.example"}, "line breaks"),
                         ({"subject": "Hello\u2028Bcc: x@evil.example"}, "line breaks"),
                         ({"subject": "Hello\u2029x"}, "control characters"),
                         ({"subject": "Hello\x85x"}, "control characters"),
                         ({"subject": "Hello\x0bx"}, "control characters"),
                         ({"subject": "Hello\x0cx"}, "control characters"),
                         ({"to_other": "Name <someone@kucoin.example>"}, "bare address"),
                         ({"to_other": "not-an-address"}, "not an e-mail"),
                         ({"to_other": MAILBOX}, "mailbox cannot be a recipient"),
                         ({"to_other": ""}, "at least one To"),
                         ({"to_other": ", ".join(f"a{i}@kucoin.example" for i in range(11))}, "at most 10 To")):
        r = _compose(inv, case, corr, **form)
        assert r.status_code == 400 and needle in r.text, (form, r.text[:300])
    mail.settings.aegis_mail_max_message_bytes = 4000
    r = _compose(inv, case, corr)
    assert r.status_code == 400 and "Aegis sends up to 0.0 MB" in r.text and "recipient&#39;s portal" in r.text
    mail.settings.aegis_mail_max_message_bytes = 2_900_000
    assert not db.scalars(select(MailMessage).where(MailMessage.correspondence_id == corr.id)).all()


def test_prepare_needs_the_vault_and_a_draft(db, case, run, client_for, mail, monkeypatch):
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    monkeypatch.delenv("AEGIS_VAULT_DIR")
    r = _compose(inv, case, corr)
    assert r.status_code == 400 and "AEGIS_VAULT_DIR must be set: every sent e-mail is filed as evidence" in r.text
    assert client_for("read_only", case=case).get(
        f"/cases/{case.id}/authorities/correspondence/{corr.id}/email").status_code == 403
    sent = next(c for c in case.correspondence if c.status == CorrespondenceStatus.SENT and c.direction.value == "out")
    r = inv.get(f"/cases/{case.id}/authorities/correspondence/{sent.id}/email", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/cases/{case.id}/authorities/correspondence/{sent.id}"


def test_local_graph_mode_restricts_recipient_domains(db, case, run, client_for, mail):
    mail.settings.aegis_mail_transport = "graph"
    mail.settings.aegis_mail_dev_allowed_domains = "example.com"  # tests use reserved domains only
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    r = _compose(inv, case, corr, to_other="compliance@exchange.example")
    assert r.status_code == 400 and "AEGIS_MAIL_DEV_ALLOWED_DOMAINS" in r.text
    assert _compose(inv, case, corr, to_other="desk@test.example.com").status_code == 303


def test_live_sending_lifts_the_local_domain_limit(db, case, run, client_for, mail):
    mail.settings.aegis_mail_transport = "graph"
    mail.settings.aegis_mail_dev_allowed_domains = "example.com"
    mail.settings.aegis_mail_live_sending = True  # AEGIS_MAIL_LIVE_SENDING=1: the deployment went live
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    assert _compose(inv, case, corr, to_other="compliance@exchange.example").status_code == 303


# --------------------------------------------------------------------------- send
@pytest.mark.usefixtures("past_duplicates")  # a stop order past the gate to a provider already asked
def test_send_files_the_email_and_marks_the_stop_order_sent(db, case, run, client, client_for, mail, emitted):
    corr = _draft(db, case, run, template="stop_order")
    order = corr.stop_order
    ic3 = next(e for e in case.evidence_items if e.title.startswith("Chat excerpt"))  # an evidence attachment (no TLP)
    mm = _prepared(db, _compose(client_for("investigator", case=case), case, corr,
                                attach=["letter", f"evidence:{ic3.id}"]))
    assert mm.confirmations["attachments"] == [ic3.id]
    inv = client_for("investigator", case=case)
    assert _send(inv, case, mm).status_code == 403  # investigators prepare; only case admins send
    assert not mail.transport.sent
    r = _send(client, case, mm, confirm_unverified=[])
    assert r.status_code == 400 and TO in r.text and not mail.transport.sent  # the unverified address needs its tick
    r = _send(client, case, mm, confirm_attachment=[])
    assert r.status_code == 400 and f"#{ic3.id}" in r.text and not mail.transport.sent
    r = _send(client, case, mm, confirm_send="")
    assert r.status_code == 400 and not mail.transport.sent
    r = _send(client, case, mm)
    assert r.status_code == 303 and r.headers["location"].endswith("?r=sent")
    landing = r.headers["location"]
    db.expire_all()
    mm, corr, order = db.get(MailMessage, mm.id), db.get(Correspondence, corr.id), db.get(type(order), order.id)
    assert mm.status == MailStatus.SENT and mm.sent_by == client.user.id and (mm.meta or {}).get("finalized")
    assert len(mail.transport.sent) == 1 and hashlib.sha256(mail.transport.sent[0]).hexdigest() == mm.mime_sha256
    assert corr.status == CorrespondenceStatus.SENT and corr.channel.value == "email"
    assert corr.thread_key == mm.internet_message_id and corr.sender == MAILBOX and corr.recipients == [TO]
    assert corr.meta["sent_via"] == "aegis_mail" and corr.meta["mail_message_id"] == mm.id
    assert order.status == StopOrderStatus.SENT and order.sent_via == "email"
    assert order.response_due_at == order.sent_at + timedelta(days=5)
    item = db.get(EvidenceItem, mm.eml_evidence_id)
    assert corr.evidence_item_id == item.id and item.sha256 == mm.mime_sha256
    assert ev.read_verified(item) == mail.transport.sent[0]
    assert item.folder.value == "stop_orders_correspondence" and item.classification.value == "R3"
    assert item.source_type == "eml" and "sent-email" in item.tags and mm.mime_path is None
    assert not list((mail.vault / "mail-pending").rglob("*.eml"))
    types = [c["type"] for c in emitted]
    assert "correspondence_out" in types and "stop_order_status" in types
    sent_audit = db.scalars(select(AuditEvent).where(AuditEvent.action == "LETTER_SENT",
                                                     AuditEvent.object_id == str(corr.id))).all()[-1]
    d = sent_audit.detail
    assert d["via"] == "email" and d["mail_message_id"] == mm.id and d["eml_evidence_id"] == item.id
    assert d["attachment_evidence_ids"] == [ic3.id] and d["n_unverified_confirmed"] == 1
    assert d["mime_sha256"] == mm.mime_sha256 and "@" not in json.dumps(d) and corr.subject not in json.dumps(d)
    page = client.get(landing).text
    assert "E-mail sent and filed" in page and f"/evidence/{item.id}" in page
    letter = client.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}").text
    assert "E-mail history" in letter and f"/mail/messages/{mm.id}" in letter
    # a second POST (double click, second tab) never sends again
    r = _send(client, case, mm)
    assert r.status_code == 303 and len(mail.transport.sent) == 1


def test_draft_changes_expiry_and_cancel(db, case, run, client, client_for, mail):
    inv = client_for("investigator", case=case)
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(inv, case, corr))
    desk.update_draft(db, corr, subject=corr.subject, body=corr.body_markdown + "\nOne more line.\n",
                      recipients=corr.recipients, cc=corr.cc)
    r = _send(client, case, mm)
    assert r.status_code == 409 and "changed after the preview" in r.text and not mail.transport.sent
    corr2 = _draft(db, case, run)
    mm2 = _prepared(db, _compose(inv, case, corr2))
    mm2.expires_at = datetime.now(tz=UTC) - timedelta(minutes=1)
    db.commit()
    r = _send(client, case, mm2)
    db.expire_all()
    assert r.status_code == 409 and "expired" in r.text and db.get(MailMessage, mm2.id).status == MailStatus.EXPIRED
    assert db.get(MailMessage, mm2.id).mime_path is None and not mail.transport.sent
    corr3 = _draft(db, case, run)
    mm3 = _prepared(db, _compose(inv, case, corr3))
    r = inv.post(f"/cases/{case.id}/mail/messages/{mm3.id}/cancel",
                 data={"csrf_token": csrf_token(inv, f"/cases/{case.id}/mail/messages/{mm3.id}")}, follow_redirects=False)
    db.expire_all()
    assert r.status_code == 303 and db.get(MailMessage, mm3.id).status == MailStatus.CANCELLED
    # the scheduler hook expires stale previews
    corr4 = _draft(db, case, run)
    mm4 = _prepared(db, _compose(inv, case, corr4))
    path = mail.vault / mm4.mime_path
    mm4.expires_at = datetime.now(tz=UTC) - timedelta(seconds=1)
    db.commit()
    assert mail_send.expire_prepared(db) >= 1 and not path.exists()


def test_transport_none_disables_send_but_allows_the_eml(db, case, run, client, client_for, mail):
    mail.transport.configured = False
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(client_for("investigator", case=case), case, corr))
    page = client.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    assert "Sending is not available" in page and 'id="mail-send-form"' not in page
    eml = client.get(f"/cases/{case.id}/mail/messages/{mm.id}/eml")
    assert eml.status_code == 200 and eml.content == compose.read_raw(mm, db)
    assert eml.headers["content-type"].startswith("message/rfc822")
    assert f"{case.reference}_email-{corr.id}-{mm.id}.eml" in eml.headers["content-disposition"]
    audit = db.scalars(select(AuditEvent).where(AuditEvent.action == "DOWNLOAD",
                                                AuditEvent.object_id == str(mm.id))).first()
    assert audit.detail["mode"] == "eml"
    assert client_for("investigator", case=case).get(f"/cases/{case.id}/mail/messages/{mm.id}/eml").status_code == 403
    r = _send(client, case, mm)
    assert r.status_code == 409 and not mail.transport.sent


def test_failure_keeps_the_draft(db, case, run, client, client_for, mail):
    mail.transport.fail = FakeTransportError("forbidden", "check Mail.Send permissions")
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(client_for("investigator", case=case), case, corr))
    r = _send(client, case, mm)
    assert r.status_code == 303 and r.headers["location"].endswith("?r=failed")
    db.expire_all()
    mm, corr = db.get(MailMessage, mm.id), db.get(Correspondence, corr.id)
    assert mm.status == MailStatus.FAILED and mm.error_reason == "forbidden" and corr.status == CorrespondenceStatus.DRAFT
    assert db.scalars(select(AuditEvent).where(AuditEvent.action == "MAIL_SEND_FAILED",
                                               AuditEvent.object_id == str(mm.id))).first() is not None


@pytest.mark.parametrize("state", ["sent", "draft", "missing"])
def test_unknown_outcome_and_reconcile(db, case, run, client, client_for, mail, state):
    pid = f"AAMk-immutable-{state}"
    mail.transport.fail = FakeTransportError("unknown_outcome", "read timeout on send", outcome_unknown=True,
                                             provider_message_id=pid)
    corr = _draft(db, case, run)
    inv = client_for("investigator", case=case)
    mm = _prepared(db, _compose(inv, case, corr))
    spare = _prepared(db, _compose(inv, case, corr))  # a second preview of the same letter, prepared earlier
    r = _send(client, case, mm)
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    assert r.headers["location"].endswith("?r=unknown") and mm.status == MailStatus.UNKNOWN
    assert mm.provider_message_id == pid and mm.letter_key == f"c{corr.id}"
    page = client.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    assert "do not resend manually" in page and "Check the mailbox now" in page and "Retry send" not in page
    assert db.get(Correspondence, corr.id).status == CorrespondenceStatus.DRAFT
    tok = csrf_token(client, f"/cases/{case.id}/mail/messages/{mm.id}")
    assert client.post(f"/cases/{case.id}/mail/messages/{mm.id}/resend", data={"csrf_token": tok},
                       follow_redirects=False).status_code in (404, 405)  # no manual resend route
    # reproduction 1: unknown outcome, then prepare the (still draft) letter again → refused
    mail.transport.fail = None
    r = _compose(inv, case, corr)
    assert r.status_code == 400 and "may already have been sent" in r.text and f"e-mail #{mm.id}" in r.text
    assert "Check the mailbox now" in inv.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email").text
    # … and the preview prepared before the uncertain send cannot be sent either
    r = _send(client, case, db.get(MailMessage, spare.id))
    assert r.status_code == 409 and "may already have been sent" in r.text
    assert len(mail.transport.sent) == 1
    mail.transport.lookup_state = state
    r = client.post(f"/cases/{case.id}/mail/messages/{mm.id}/reconcile", data={"csrf_token": tok},
                    follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    if state == "sent":
        assert mm.status == MailStatus.SENT and mm.eml_evidence_id and mm.meta.get("finalized")
        assert db.get(Correspondence, corr.id).status == CorrespondenceStatus.SENT
        assert db.get(MailMessage, spare.id).status == MailStatus.CANCELLED  # retired once the letter went out
    else:
        # within the grace period nothing is decided: still unknown, still nothing else sent
        assert mm.status == MailStatus.UNKNOWN and mm.meta.get("last_reconcile") == state
        assert bool(mm.meta.get("mailbox_draft")) == (state == "draft")
        assert _compose(inv, case, corr).status_code == 400
        mm.meta = {**mm.meta, "send_started_at": (datetime.now(tz=UTC) - timedelta(minutes=20)).isoformat()}
        db.commit()
        client.post(f"/cases/{case.id}/mail/messages/{mm.id}/reconcile", data={"csrf_token": tok},
                    follow_redirects=False)
        db.expire_all()
        mm = db.get(MailMessage, mm.id)
        assert mm.status == MailStatus.FAILED
        assert mm.error_reason == ("unsent_draft" if state == "draft" else "not_found")
        # an unsent draft is deleted from the mailbox before the e-mail is marked failed
        assert mail.transport.deleted == ([(mm.message_id, pid)] if state == "draft" else [])
        assert bool(mm.meta.get("draft_deleted")) == (state == "draft") and not mm.meta.get("mailbox_draft")
        # failed for certain: the letter may be prepared and sent again, once
        again = _prepared(db, _compose(inv, case, corr))
        assert _send(client, case, again).headers["location"].endswith("?r=sent")
        assert len(mail.transport.sent) == 2
    assert len(mail.transport.sent) == (1 if state == "sent" else 2)
    db.expire_all()
    assert mail_send.reconcile_unknown_all(db) == 0


def test_rate_limit(db, case, run, client, client_for, mail):
    mail.settings.aegis_mail_send_per_hour = 0
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(client_for("investigator", case=case), case, corr))
    r = _send(client, case, mm)
    assert r.status_code == 429 and "limit" in r.text and not mail.transport.sent


def test_filing_failure_keeps_sent_and_offers_retry(db, case, run, client, client_for, mail, monkeypatch):
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(client_for("investigator", case=case), case, corr))
    real = ev.store_upload

    def broken(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(ev, "store_upload", broken)
    r = _send(client, case, mm)
    assert r.headers["location"].endswith("?r=sent")
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    assert mm.status == MailStatus.SENT and "disk full" in mm.meta["finalize_error"] and not mm.eml_evidence_id
    page = client.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    assert "Retry filing" in page
    monkeypatch.setattr(ev, "store_upload", real)
    tok = csrf_token(client, f"/cases/{case.id}/mail/messages/{mm.id}")
    r = client.post(f"/cases/{case.id}/mail/messages/{mm.id}/finalize", data={"csrf_token": tok},
                    follow_redirects=False)
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    assert r.status_code == 303 and mm.status == MailStatus.SENT and mm.eml_evidence_id
    assert "finalize_error" not in mm.meta and db.get(Correspondence, corr.id).status == CorrespondenceStatus.SENT
    assert mail_send.reconcile_unknown_all(db) == 0 and len(mail.transport.sent) == 1


@pytest.mark.usefixtures("past_duplicates")  # a stop order past the gate to a provider already asked
def test_stop_order_without_a_letter_row_gets_one(db, case, run, client_for, mail):
    with ungated():  # the shared demo case's Rainbet was asked already
        order = services.generate_stop_orders(db, case, run, only=["Rainbet"])[0]
    assert not order.correspondence
    inv = client_for("investigator", case=case)
    tok = csrf_token(inv, f"/cases/{case.id}/stop-orders/{order.id}")
    r = inv.post(f"/cases/{case.id}/stop-orders/{order.id}/email", data={"csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("/email")
    db.expire_all()
    corr = db.get(Correspondence, int(r.headers["location"].split("/")[-2]))
    assert corr.stop_order_id == order.id and corr.kind.value == "stop_order" and corr.status.value == "draft"
    assert corr.classification.value == "R3" and corr.entity_id == order.entity_id
    page = inv.get(r.headers["location"]).text
    assert "compliance@rainbet-demo.example" in page  # the entity record's channel is offered (unverified)


def test_status_api_has_no_addresses(db, case, run, client_for, mail):
    inv = client_for("investigator", case=case)
    mm = _prepared(db, _compose(inv, case, _draft(db, case, run)))
    data = inv.get(f"/api/cases/{case.id}/mail/messages/{mm.id}").json()
    assert data["status"] == "prepared" and data["n_to"] == 1 and "@" not in json.dumps(data)
    other = _other_case(db)
    assert inv.get(f"/api/cases/{other.id}/mail/messages/{mm.id}").status_code == 404


def test_prepared_mail_is_announced_listed_and_prepared_again(db, case, run, client, client_for, mail, emitted):
    """Investigators prepare, case admins send: the admins hear about it, the tab and the timeline list
    it, an expired preview is prepared again in one click, and sending one retires the other previews."""
    inv = client_for("investigator", case=case)
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(inv, case, corr))
    notes = [c for c in emitted if c["type"] == "mail_prepared"]
    assert len(notes) == 1 and notes[0]["link"] == f"/cases/{case.id}/mail/messages/{mm.id}"
    assert "@" not in notes[0]["title"] + notes[0]["body"] and corr.subject not in notes[0]["title"]
    tab = client.get(f"/cases/{case.id}?tab=authorities").text
    assert re.search(r"E-mail awaiting Send \(\d+\)", tab) and f"/cases/{case.id}/mail/messages/{mm.id}" in tab
    key = _auth(db, case, "KuCoin", run).key
    assert "e-mail awaiting Send" in client.get(f"/cases/{case.id}/authorities/{key}").text
    _prepared(db, _compose(client, case, corr))  # an admin preparing is not announced to the admins
    assert len([c for c in emitted if c["type"] == "mail_prepared"]) == 1

    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    mm.expires_at = datetime.now(tz=UTC) - timedelta(minutes=1)
    db.commit()
    page = client.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    assert "Prepare again" in page and 'id="mail-send-form"' not in page
    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    r = inv.post(f"{path}/renew", data={"csrf_token": csrf_token(inv, path)}, follow_redirects=False)
    renewed = _prepared(db, r)
    old = db.get(MailMessage, mm.id)
    assert old.status == MailStatus.EXPIRED and renewed.id != old.id and renewed.status == MailStatus.PREPARED
    assert renewed.to_addrs == old.to_addrs and renewed.subject == old.subject
    assert [a["kind"] for a in renewed.attachments] == [a["kind"] for a in old.attachments]
    assert len([c for c in emitted if c["type"] == "mail_prepared"]) == 2
    # only an expired / failed / cancelled e-mail is prepared again
    r = inv.post(f"/cases/{case.id}/mail/messages/{renewed.id}/renew",
                 data={"csrf_token": csrf_token(inv, path)}, follow_redirects=False)
    assert r.status_code == 409

    others = db.scalars(select(MailMessage).where(MailMessage.correspondence_id == corr.id,
                                                  MailMessage.status == MailStatus.PREPARED,
                                                  MailMessage.id != renewed.id)).all()
    assert others  # the admin's own preview
    assert _send(client, case, renewed).status_code == 303
    db.expire_all()
    for o in others:
        o = db.get(MailMessage, o.id)
        assert o.status == MailStatus.CANCELLED and o.mime_path is None
        assert "superseded" in o.meta["history"][-1]["reason"]
    waiting = {m.id for m in mail_send.awaiting_send(db, case.id)}
    assert renewed.id not in waiting and not waiting & {o.id for o in others}


def test_check_mailbox_now_is_disabled_without_inbound(db, case, client, monkeypatch):
    monkeypatch.setenv("AEGIS_MAIL_INBOUND", "off")
    monkeypatch.setenv("AEGIS_MAIL_TRANSPORT", "file")  # a sending transport: the button shows, disabled
    tab = client.get(f"/cases/{case.id}?tab=authorities").text
    assert "Check mailbox now" in tab and f'action="/cases/{case.id}/mail/sync"' not in tab
    assert "Inbound mail: inbound mail is off" in tab
    # "Draft — you send" (the default): replies come in through Import reply, no dead button
    monkeypatch.setenv("AEGIS_MAIL_TRANSPORT", "manual")
    tab = client.get(f"/cases/{case.id}?tab=authorities").text
    assert "Check mailbox now" not in tab and f'href="/cases/{case.id}/mail/import"' in tab


def test_long_non_ascii_subject_round_trips_exactly():
    """Python <= 3.13 adds a stray space when it folds a long non-ASCII header (CI and Docker run 3.12).
    Generated subjects are made ASCII (`ascii_header`), and SEND_POLICY never folds, so the Subject the
    authority receives is exactly what was previewed."""
    from email.message import EmailMessage as _Msg
    from email.parser import BytesParser as _Parser

    typographic = ("Urgent Preservation & Risk-Control Request – Fraud proceeds deposited to KuCoin accounts – "
                   "Ref DEMO-2026-001 – a few more words so the header would normally fold “quoted”…")
    plain = compose.ascii_header(typographic)
    assert plain.isascii() and " - Ref DEMO-2026-001 - " in plain and '"quoted"...' in plain
    for subject in (plain, "Rückfrage zu Ihrem Schreiben – Zürich " + "x" * 120):  # ASCII, and a typed accented one
        m = _Msg(policy=compose.SEND_POLICY)
        m["Subject"] = subject
        m.set_content("x")
        assert str(_Parser(policy=policy.default).parsebytes(m.as_bytes())["Subject"]) == subject
