"""E-mail desk, follow-up round: stale Graph drafts are deleted before an e-mail is marked failed
(and the letter stays blocked while one may remain), siblings are retired by letter, neutral states for
discarded previews, restricted attachments on the preview, correspondence items only to their own
authority, received raw e-mails never attachable, and the Letter of Authorisation check.

Fakes and helpers come from test_mail_compose_send (mock transport and settings; no network)."""

from __future__ import annotations

import io
import re
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from conftest import csrf_token
from sqlalchemy import select
from test_mail_compose_send import (
    FakeSettings,
    FakeTransport,
    FakeTransportError,
    _auth,
    _compose,
    _draft,
    _prepared,
    _send,
)

from app import services
from app.db.models import (
    Correspondence,
    CorrespondenceKind,
    CorrespondenceStatus,
    EvidenceItem,
    MailMessage,
    MailStatus,
)
from app.domain import correspondence as desk
from app.domain import evidence as ev
from app.domain import mail_compose as compose
from app.domain import mail_send


@pytest.fixture
def mail(monkeypatch, tmp_path):
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


def _page(c, case, mm) -> str:
    r = c.get(f"/cases/{case.id}/mail/messages/{mm.id}")
    assert r.status_code == 200
    return r.text


def _reconcile(c, case, mm):
    tok = csrf_token(c, f"/cases/{case.id}/mail/messages/{mm.id}")
    return c.post(f"/cases/{case.id}/mail/messages/{mm.id}/reconcile", data={"csrf_token": tok},
                  follow_redirects=False)


def _age(db, mm, minutes=20):
    mm.meta = {**(mm.meta or {}), "send_started_at": (datetime.now(tz=UTC) - timedelta(minutes=minutes)).isoformat()}
    db.commit()


def _unknown(db, case, run, client, inv, mail, pid=None):
    pid = pid or f"AAMk-draft-{uuid.uuid4().hex[:8]}="  # unique per mailbox in the shared test DB
    mail.transport.fail = FakeTransportError("unknown_outcome", "read timeout on send", outcome_unknown=True,
                                             provider_message_id=pid)
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(inv, case, corr))
    assert _send(client, case, mm).headers["location"].endswith("?r=unknown")
    mail.transport.fail = None
    db.expire_all()
    return corr, db.get(MailMessage, mm.id)


# --------------------------------------------------------------------------- 3. stale Graph drafts
def test_an_unsent_draft_that_cannot_be_deleted_keeps_the_letter_blocked(db, case, run, client, client_for, mail):
    inv = client_for("investigator", case=case)
    corr, mm = _unknown(db, case, run, client, inv, mail)
    pid = mm.provider_message_id
    mail.transport.lookup_state = "draft"
    mail.transport.delete_fail = FakeTransportError("server", "Graph server error (503)")
    _age(db, mm)
    assert _reconcile(client, case, mm).status_code == 303
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    assert mm.status == MailStatus.UNKNOWN and mm.error_reason == "draft_not_deleted"
    assert "503" in mm.meta["draft_delete_error"] and mm.meta.get("mailbox_draft") is True
    assert mail.transport.deleted == [(mm.message_id, pid)]
    page = _page(client, case, mm)
    assert 'id="mail-draft-not-deleted"' in page and "could not delete it" in page and "Check the mailbox now" in page
    # never prepared again while the draft may still be in the mailbox
    r = _compose(inv, case, corr)
    assert r.status_code == 400 and "may already have been sent" in r.text
    # the scheduler retries; a repeated failure adds no second history line
    n_hist = len(mm.meta["history"])
    db.expire_all()
    mail_send.reconcile_unknown_all(db)
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    assert mm.status == MailStatus.UNKNOWN and len(mm.meta["history"]) == n_hist and len(mail.transport.deleted) == 2
    # the deletion goes through: failed for certain, nothing was sent, the letter can be prepared again
    mail.transport.delete_fail = None
    _reconcile(client, case, mm)
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    assert mm.status == MailStatus.FAILED and mm.error_reason == "unsent_draft" and mm.meta["draft_deleted"] is True
    assert "draft_delete_error" not in mm.meta and any(h["status"] == "draft_deleted" for h in mm.meta["history"])
    page = _page(client, case, mm)
    assert 'id="mail-not-sent"' in page and "Aegis deleted the unsent draft" in page
    assert "no longer available" not in page
    again = _prepared(db, _compose(inv, case, corr))
    assert again.status == MailStatus.PREPARED


def test_a_draft_found_sent_while_deleting_is_filed_as_sent(db, case, run, client, client_for, mail):
    inv = client_for("investigator", case=case)
    corr, mm = _unknown(db, case, run, client, inv, mail)
    mail.transport.lookup_state = "draft"
    mail.transport.delete_result = "sent"
    real = mail.transport.delete_drafts

    def sent_meanwhile(**kw):
        mail.transport.lookup_state = "sent"
        return real(**kw)

    mail.transport.delete_drafts = sent_meanwhile
    _age(db, mm)
    _reconcile(client, case, mm)
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    assert mm.status == MailStatus.SENT and mm.meta.get("finalized") and mm.eml_evidence_id
    assert db.get(Correspondence, corr.id).status == CorrespondenceStatus.SENT


def test_a_transport_that_cannot_delete_drafts_never_marks_them_failed(db, case, run, client, client_for, mail):
    inv = client_for("investigator", case=case)
    _corr, mm = _unknown(db, case, run, client, inv, mail)
    mail.transport.lookup_state = "draft"
    mail.transport.delete_drafts = None  # e.g. a transport without the capability
    _age(db, mm)
    assert mail_send.reconcile(db, mm, client.user) == "draft"
    assert mm.status == MailStatus.UNKNOWN and "cannot delete drafts" in mm.meta["draft_delete_error"]


def test_a_failed_email_that_left_a_draft_blocks_prepare_until_it_is_deleted(db, case, run, client, client_for,
                                                                              mail):
    """An e-mail marked failed by the earlier reconcile (the draft was left in the mailbox) keeps the
    letter blocked: Check the mailbox now (or the scheduler) deletes the draft first."""
    inv = client_for("investigator", case=case)
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(inv, case, corr))
    mail.transport.fail = FakeTransportError("invalid", "refused")
    _send(client, case, mm)
    mail.transport.fail = None
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    old_pid = f"AAMk-old-{uuid.uuid4().hex[:8]}="
    mm.error_reason, mm.provider_message_id = "unsent_draft", old_pid
    mm.meta = {**mm.meta, "mailbox_draft": True}
    db.commit()
    assert compose.stale_draft_left(mm)
    r = _compose(inv, case, corr)
    assert r.status_code == 400 and "left an unsent draft" in r.text
    page = _page(client, case, mm)
    assert 'id="mail-stale-draft"' in page and "Check the mailbox now" in page and "Prepare again</button>" not in page
    mail.transport.delete_fail = FakeTransportError("network", "could not reach Microsoft")
    _reconcile(client, case, mm)
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    assert compose.stale_draft_left(mm) and "could not reach" in mm.meta["draft_delete_error"]
    assert _compose(inv, case, corr).status_code == 400
    mail.transport.delete_fail = None
    db.expire_all()
    assert mail_send.reconcile_unknown_all(db) >= 1  # the scheduler pass deletes it as well
    db.expire_all()
    mm = db.get(MailMessage, mm.id)
    assert not compose.stale_draft_left(mm) and mm.meta["draft_deleted"] is True
    assert mail.transport.deleted[-1] == (mm.message_id, old_pid)
    assert _prepared(db, _compose(inv, case, corr)).status == MailStatus.PREPARED


# --------------------------------------------------------------------------- 6 + 7. siblings by letter, neutral states
@pytest.mark.usefixtures("past_duplicates")  # a stop order past the gate to a provider already asked
def test_siblings_are_retired_by_letter_and_shown_as_superseded(db, case, run, client, client_for, mail):
    inv = client_for("investigator", case=case)
    corr = _draft(db, case, run, template="stop_order")
    twin = Correspondence(case=case, entity=corr.entity, direction=corr.direction, channel=corr.channel,
                          kind=CorrespondenceKind.STOP_ORDER, status=CorrespondenceStatus.DRAFT, subject=corr.subject,
                          body_markdown=corr.body_markdown, recipients=list(corr.recipients or []), cc=[],
                          stop_order=corr.stop_order, classification=corr.classification, meta={})
    db.add(twin)
    db.commit()
    other = _prepared(db, _compose(inv, case, db.get(Correspondence, twin.id)))  # the same letter, another row
    mm = _prepared(db, _compose(inv, case, corr))
    assert other.letter_key == mm.letter_key and other.correspondence_id != mm.correspondence_id
    assert _send(client, case, mm).headers["location"].endswith("?r=sent")
    db.expire_all()
    other = db.get(MailMessage, other.id)
    assert other.status == MailStatus.CANCELLED and other.meta["superseded_by"] == mm.id and other.mime_path is None
    page = _page(client, case, other)
    assert 'id="mail-discarded"' in page and f"e-mail #{mm.id}</a>" in page and "Superseded by" in page
    assert "no longer available" not in page and 'class="alert critical"' not in page
    assert 'id="mail-bytes-discarded"' in page


def test_cancelled_and_expired_previews_are_neutral(db, case, run, client, client_for, mail):
    inv = client_for("investigator", case=case)
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(inv, case, corr))
    tok = csrf_token(inv, f"/cases/{case.id}/mail/messages/{mm.id}")
    inv.post(f"/cases/{case.id}/mail/messages/{mm.id}/cancel", data={"csrf_token": tok})
    page = _page(inv, case, db.get(MailMessage, mm.id))
    assert "Cancelled — nothing was sent." in page and "no longer available" not in page
    assert 'class="alert critical"' not in page
    late = _prepared(db, _compose(inv, case, corr))
    late.expires_at = datetime.now(tz=UTC) - timedelta(minutes=1)
    db.commit()
    assert mail_send.expire_prepared(db) >= 1
    page = _page(inv, case, db.get(MailMessage, late.id))
    assert "Expired — nothing was sent." in page and "no longer available" not in page
    assert 'class="alert critical"' not in page


# --------------------------------------------------------------------------- 2. restricted attachments
def test_preview_counts_attachments_the_viewer_may_not_see(db, case, run, client, client_for, mail):
    secret_title = f"Bank statement {uuid.uuid4().hex[:6]}"
    item = ev.add_note(db, case, title=secret_title, text="synthetic statement", folder="financial")
    db.commit()
    corr = _draft(db, case, run)
    mm = _prepared(db, _compose(client, case, corr, attach=["letter", f"evidence:{item.id}"]))
    name = next(a["filename"] for a in mm.attachments if a.get("evidence_id") == item.id)
    admin_page = _page(client, case, mm)
    assert secret_title in admin_page and name in admin_page and "restricted attachment" not in admin_page
    inv = client_for("investigator", case=case)
    page = _page(inv, case, mm)
    assert "1 restricted attachment" in page
    assert secret_title not in page and name not in page and f"/evidence/{item.id}" not in page
    assert f"#{item.id}" not in page


# --------------------------------------------------------------------------- 4. correspondence only to its authority
def _sent_eml(db, case, authority, *, link=True):
    """A sent .eml evidence item of a letter to `authority` (as mail_send.finalize files it)."""
    letter = desk.log_entry(db, case, authority, actor=None, direction="out", channel="email", kind="other",
                            subject=f"Earlier letter {uuid.uuid4().hex[:6]}", body="x", recipients=[])
    item = ev.store_upload(db, case, io.BytesIO(b"From: x\r\n\r\nsent " + uuid.uuid4().hex.encode()),
                           filename="letter.eml", folder="stop_orders_correspondence", title="E-mail as sent",
                           source_type="eml", classification="R3", tags=["aegis-mail", "sent-email"], actor=None)
    if link:
        letter.evidence_item_id = item.id
        letter.meta = {**(letter.meta or {}), "evidence_ids": [item.id]}
    db.commit()
    return item


def test_correspondence_items_go_only_to_the_authority_they_came_from(db, case, run, client, client_for, mail):
    inv = client_for("investigator", case=case)
    kucoin = _auth(db, case, "KuCoin", run)
    other_auth = next(a for a in desk.case_authorities(db, case, run=run)
                      if a.key != kucoin.key and a.entity is not None and not a.virtual)
    own = _sent_eml(db, case, kucoin)
    foreign = _sent_eml(db, case, other_auth)
    orphan = _sent_eml(db, case, kucoin, link=False)
    corr = _draft(db, case, run)  # a letter to KuCoin
    url = f"/cases/{case.id}/authorities/correspondence/{corr.id}/email"
    page = client.get(url).text
    assert not re.search(rf'value="evidence:{own.id}"[^>]*disabled', page)
    for item in (foreign, orphan):
        assert re.search(rf'value="evidence:{item.id}"[^>]*disabled', page)
    assert compose.BLOCK_TEXT["other_authority"].split(":")[0] in page
    for item in (foreign, orphan):
        r = _compose(inv, case, corr, attach=["letter", f"evidence:{item.id}"])
        assert r.status_code == 400 and "another authority" in r.text
    mm = _prepared(db, _compose(inv, case, corr, attach=["letter", f"evidence:{own.id}"]))
    assert any(a.get("evidence_id") == own.id for a in mm.attachments)
    # the item is linked to another authority after the preview: Send refuses it
    later = desk.log_entry(db, case, _auth(db, case, other_auth.name, run), actor=None, direction="note",
                           channel="email", kind="other", subject="forwarded", body="x", evidence_ids=[own.id])
    assert later.id
    r = _send(client, case, db.get(MailMessage, mm.id))
    assert r.status_code == 409 and "another authority" in r.text and not mail.transport.sent


def test_authority_documents_are_never_correspondence_of_one_authority(db, case, run):
    from app.domain import sender as sender_mod

    profile = sender_mod.get_profile(db, case)
    auth_id = profile.authority_evidence_ids[0]
    item = db.get(EvidenceItem, auth_id)
    other = next(a for a in desk.case_authorities(db, case, run=run) if a.entity is not None)
    assert compose.authority_block_reason(db, item, other, exempt={auth_id}) is None


# --------------------------------------------------------------------------- 8. received raw e-mails
def test_a_received_raw_email_is_never_attachable(db, case, run, client, mail):
    raw = ev.store_upload(db, case, io.BytesIO(b"From: le@exchange.example\r\n\r\nhi " + uuid.uuid4().hex.encode()),
                          filename="in.eml", folder="stop_orders_correspondence", title="E-mail received",
                          source_type="eml", classification="R3", tags=["aegis-mail", "received-email"], actor=None)
    fwd = ev.store_upload(db, case, io.BytesIO(b"From: a@b.example\r\n\r\nfwd " + uuid.uuid4().hex.encode()),
                          filename="forwarded-1.eml", folder="stop_orders_correspondence",
                          title="Attachment 1 of e-mail #1", source_type="email_attachment", classification="R3",
                          tags=["aegis-mail", "email-attachment"], actor=None)
    fwd.meta = {**(fwd.meta or {}), "original_filename": "forwarded-1.eml"}
    db.commit()
    corr = _draft(db, case, run)
    url = f"/cases/{case.id}/authorities/correspondence/{corr.id}/email"
    tok = csrf_token(client, url)
    for item in (raw, fwd):
        assert compose.is_received_email(item)
        r = client.post(f"/cases/{case.id}/evidence/{item.id}/mail-safe", data={"csrf_token": tok},
                        follow_redirects=False)
        assert r.status_code == 409 and "never attached" in r.text
        # even with the flag forced on, it stays blocked
        item.meta = {**(item.meta or {}), "mail_safe": {"by": 1, "at": "2026-01-01"}}
        db.commit()
        assert compose.static_block_reason(SimpleNamespace(case=case), item) == "received_email"
    page = client.get(url).text
    for item in (raw, fwd):
        assert re.search(rf'value="evidence:{item.id}"[^>]*disabled', page)
        assert f'form="mail-safe-{item.id}"' not in page
    r = _compose(client, case, corr, attach=["letter", f"evidence:{raw.id}"])
    assert r.status_code == 400 and "never attached" in r.text


# --------------------------------------------------------------------------- 4b. Letter of Authorisation wording
def test_preview_warns_when_the_letter_says_its_authorisation_is_attached_but_it_is_not(db, case, run, client,
                                                                                        client_for, mail):
    from app.domain import sender as sender_mod

    corr = _draft(db, case, run)
    profile = sender_mod.get_profile(db, case)
    text = compose.markdown_to_text(corr.body_markdown)
    assert profile.instrument in text and "(attached)" in text  # the generated letter says so
    inv = client_for("investigator", case=case)
    bare = _prepared(db, _compose(inv, case, corr, attach=["letter"]))
    page = _page(client, case, bare)
    assert 'id="mail-loa-warning"' in page and f"says the {profile.instrument} is attached" in page
    auth_id = profile.authority_evidence_ids[0]
    full = _prepared(db, _compose(inv, case, corr, attach=["letter", f"authority:{auth_id}"]))
    assert 'id="mail-loa-warning"' not in _page(client, case, full)
    # a letter that does not mention the instrument as attached: no warning
    plain = SimpleNamespace(body_markdown="Dear team,\n\nPlease confirm the hold.\n")
    assert compose.authorisation_warning(db, case, plain, []) is None
    assert compose.authorisation_warning(db, case, SimpleNamespace(
        body_markdown="We enclose the Letter of Authorisation."), []) is not None



# --------------------------------------------------------------------------- 4 + 8. provenance, not editable metadata
def _edit_away(c, case, item):
    """An investigator re-files an item through the evidence edit form: another folder, a neutral
    source type and no tags (as the probe of the review did)."""
    tok = csrf_token(c, f"/cases/{case.id}/evidence/{item.id}")
    return c.post(f"/cases/{case.id}/evidence/{item.id}/edit", data={
        "csrf_token": tok, "folder": "other", "title": "Scan", "classification": "R3",
        "source_type": "document", "tags": "", "description": ""}, follow_redirects=False)


def _mail_row(db, case, direction, eml_item):
    from app.db.models import MailDirection

    mm = MailMessage(case_id=case.id, direction=direction,
                     status=MailStatus.ASSIGNED if direction == MailDirection.IN else MailStatus.SENT,
                     transport="file", mailbox="case-desk@aegis.example", message_id=f"<{uuid.uuid4().hex}@x.example>",
                     from_addr="le@exchange.example", to_addrs=[], cc_addrs=[], attachments=[], match={}, meta={},
                     eml_evidence_id=eml_item.id)
    db.add(mm)
    db.flush()
    return mm


def test_editing_the_metadata_never_lifts_the_mail_attachment_rules(db, case, run, client, client_for, mail):
    """Items 8 and 4 rest on provenance the edit form cannot change: the mail tags and source type
    are kept by ev.update_item, and the checks also read meta.mail_message_id (set by ingest) and
    MailMessage.eml_evidence_id, so stripping the tags in the database changes nothing either."""
    from app.db.models import EvidenceFolder, MailDirection

    inv = client_for("investigator", case=case)
    kucoin = _auth(db, case, "KuCoin", run)
    other_auth = next(a for a in desk.case_authorities(db, case, run=run)
                      if a.key != kucoin.key and a.entity is not None and not a.virtual)
    raw = ev.store_upload(db, case, io.BytesIO(b"From: le@exchange.example\r\n\r\nhi " + uuid.uuid4().hex.encode()),
                          filename="in.eml", folder="stop_orders_correspondence", title="E-mail received",
                          source_type="eml", classification="R3", tags=["aegis-mail", "received-email"], actor=None)
    inbound_mm = _mail_row(db, case, MailDirection.IN, raw)
    raw.meta = {**(raw.meta or {}), "mail_message_id": inbound_mm.id}
    att = ev.store_upload(db, case, io.BytesIO(b"%PDF-1.4 received " + uuid.uuid4().hex.encode()),
                          filename="statement.pdf", folder="stop_orders_correspondence",
                          title=f"Attachment 1 of e-mail #{inbound_mm.id}", source_type="email_attachment",
                          classification="R3", tags=["aegis-mail", "email-attachment"], actor=None)
    att.meta = {**(att.meta or {}), "original_filename": "statement.pdf", "mail_message_id": inbound_mm.id}
    foreign = _sent_eml(db, case, other_auth)
    _mail_row(db, case, MailDirection.OUT, foreign)
    db.commit()

    for item in (raw, att, foreign):
        r = _edit_away(inv, case, item)
        assert r.status_code == 303, r.text[:300]
    db.expire_all()
    raw, att, foreign = (db.get(EvidenceItem, i.id) for i in (raw, att, foreign))
    assert raw.folder == EvidenceFolder.OTHER and raw.title == "Scan"  # the edit itself applied
    assert {"aegis-mail", "received-email"} <= set(raw.tags) and raw.source_type == "eml"
    assert {"aegis-mail", "email-attachment"} <= set(att.tags) and att.source_type == "email_attachment"
    assert {"aegis-mail", "sent-email"} <= set(foreign.tags) and foreign.source_type == "eml"
    page = inv.get(f"/cases/{case.id}/evidence/{raw.id}").text
    assert "its mail tags" in page  # the form says the mail tags are kept

    # even with every editable field stripped (an older edit, a direct change), provenance decides
    for item in (raw, att, foreign):
        item.tags, item.source_type, item.folder = [], "document", EvidenceFolder.OTHER
    db.commit()
    access = SimpleNamespace(case=case)
    assert compose.is_received_email(raw) and compose.static_block_reason(access, raw) == "received_email"
    assert compose.is_inbound(att) and not compose.is_received_email(att)
    assert compose.static_block_reason(access, att) == "inbound"
    assert compose.is_correspondence_item(foreign) and compose.is_mail_item(foreign)
    assert compose.authority_block_reason(db, foreign, kucoin) == "other_authority"

    corr = _draft(db, case, run)  # a letter to KuCoin
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email").text
    for item in (raw, att, foreign):
        assert re.search(rf'value="evidence:{item.id}"[^>]*disabled', page)
    for item, why in ((raw, "never attached"), (att, "mark it safe"), (foreign, "another authority")):
        r = _compose(inv, case, corr, attach=["letter", f"evidence:{item.id}"])
        assert r.status_code == 400 and why in r.text, (item.title, r.status_code)
    assert not db.scalars(select(MailMessage).where(MailMessage.correspondence_id == corr.id)).all()


def test_a_correspondence_item_is_never_a_sender_profile_authority_document(db, case, run, client, client_for, mail):
    """A sent .eml (or anything correspondence) cannot be saved as an authority document, which would
    exempt it from 'same authority only'; one an older profile still lists is not exempt."""
    from app.domain import sender as sender_mod

    kucoin = _auth(db, case, "KuCoin", run)
    other_auth = next(a for a in desk.case_authorities(db, case, run=run)
                      if a.key != kucoin.key and a.entity is not None and not a.virtual)
    foreign = _sent_eml(db, case, other_auth)
    profile = sender_mod.get_profile(db, case)
    original = list(profile.authority_evidence_ids or [])
    page = client.get(f"/cases/{case.id}/sender-profile?docs=all").text
    assert f'name="authority_evidence_ids" value="{foreign.id}"' not in page  # e-mails are never offered
    letter = ev.add_note(db, case, title=f"Stop order letter {uuid.uuid4().hex[:6]}", text="To the exchange",
                         folder="stop_orders_correspondence")
    db.commit()
    page = client.get(f"/cases/{case.id}/sender-profile?docs=all").text
    assert re.search(rf'name="authority_evidence_ids" value="{letter.id}"[^>]*disabled', page)
    tok = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    form = {"csrf_token": tok, "org_name": profile.org_name, "on_behalf_of": profile.on_behalf_of,
            "signatory_name": profile.signatory_name or "", "signatory_title": profile.signatory_title or "",
            "contact_email": profile.contact_email or "", "instrument": profile.instrument,
            "authority_evidence_ids": [str(i) for i in original] + [str(foreign.id)]}
    r = client.post(f"/cases/{case.id}/sender-profile", data=form)
    assert r.status_code == 400 and "cannot be attached (correspondence)" in r.text
    db.expire_all()
    assert list(sender_mod.get_profile(db, case).authority_evidence_ids) == original
    # an older profile that lists it: offered as an authority document, but blocked for KuCoin
    profile = sender_mod.get_profile(db, case)
    profile.authority_evidence_ids = [*original, foreign.id]
    db.commit()
    try:
        assert compose.authority_block_reason(db, foreign, kucoin, exempt={foreign.id}) == "other_authority"
        assert compose.authority_block_reason(db, db.get(EvidenceItem, original[0]), kucoin,
                                              exempt=set(original)) is None
        corr = _draft(db, case, run)
        inv = client_for("investigator", case=case)
        page = inv.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}/email").text
        assert re.search(rf'value="authority:{foreign.id}"[^>]*disabled', page)
        r = _compose(inv, case, corr, attach=["letter", f"authority:{foreign.id}"])
        assert r.status_code == 400 and "another authority" in r.text
    finally:
        profile = sender_mod.get_profile(db, case)
        profile.authority_evidence_ids = original
        db.commit()
