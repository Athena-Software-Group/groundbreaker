"""Review round: while a letter has an open old "Draft — you send" checklist (prepared or expired) and Aegis sends
itself, nothing prepares or sends a live e-mail of it (the two verifier repros: a live → manual → live switch, and
an investigator's way past it before an admin's Send while an Outlook send waits for review); the checklist's only
ways out (retire it after a Sent Items read, or Record as sent); the upload allowlist, and small editor fixes (Enter,
suggestions).

Helpers and fixtures come from test_mail_editor / test_mail_compose_send (fake settings and transport: no network)."""

from __future__ import annotations

import io
import re
import zipfile

import pytest
import test_mail_editor
from conftest import csrf_token
from docx import Document
from sqlalchemy import select
from test_mail_compose_send import _compose, _draft, _prepared, _send
from test_mail_editor import (
    _audits,
    _editor,
    _letter_mails,
    _manual_checklist,
    _mm_from_confirm,
    _outlook_send_waiting,
    _path,
    _retire,
)

from app.db.models import Correspondence, EvidenceItem, MailMessage, MailStatus
from app.domain import mail_compose as compose

# the stop orders drafted here past the request gate repeat a request the shared demo case already sent (duplicates):
# e-mailed all the same (conftest.past_duplicates)
pytestmark = pytest.mark.usefixtures("past_duplicates")

mail = test_mail_editor.mail  # fixtures: fake settings and transport, the case's trace run
run = test_mail_editor.run


def _cancel(client, case, mm):
    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    return client.post(f"{path}/cancel", data={"csrf_token": csrf_token(client, path)}, follow_redirects=False)


# --------------------------------------------------------------------------- the two verifier repros
def test_live_then_manual_then_live_never_sends_past_the_open_checklist(db, case, run, client, mail):
    """Aegis sent itself, then manual mode, then again: the live preview prepared first must not go out while the
    checklist prepared in manual mode may have been sent from Outlook."""
    corr = _draft(db, case, run, template="stop_order")
    live = _prepared(db, _compose(client, case, corr))  # an older form (prepare only): the preview waits for Send
    assert live.transport == "file" and live.status == MailStatus.PREPARED
    mail.settings.aegis_mail_transport = "manual"
    checklist = _prepared(db, _compose(client, case, db.get(Correspondence, corr.id)))
    assert checklist.transport == "manual"
    mail.settings.aegis_mail_transport = "file"  # Aegis sends again
    text = compose.checklist_text(checklist)
    assert f"Outlook checklist (#{checklist.id})" in text
    # the compose page's ?confirm panel: no Send form, the checklist notice with its link
    page = client.get(_path(case, corr) + f"?confirm={live.id}").text
    assert 'id="mail-send-form"' not in page and live.prepare_token not in page
    assert text in page and f'href="/cases/{case.id}/mail/messages/{checklist.id}"' in page
    # the live preview: its Send is not offered, and refused when posted anyway (the choke point)
    lpath = f"/cases/{case.id}/mail/messages/{live.id}"
    assert 'id="mail-send-form"' not in client.get(lpath).text
    r = _send(client, case, live)
    assert r.status_code == 409 and text in r.text and f"/mail/messages/{checklist.id}" in r.text
    # nor does anything prepare a new live e-mail of the letter
    for action in ("send_now", "prepare", "save"):
        assert _editor(client, case, db.get(Correspondence, corr.id), action=action).status_code == 409, action
    assert client.post(f"{lpath}/edit", data={"csrf_token": csrf_token(client, lpath)},
                       follow_redirects=False).status_code == 409
    assert [(m.id, m.status) for m in _letter_mails(db, corr)] == [(live.id, MailStatus.PREPARED),
                                                                   (checklist.id, MailStatus.PREPARED)]
    assert not mail.transport.sent
    # retired: the live preview may go out (once)
    assert _retire(client, case, db.get(MailMessage, checklist.id)).status_code == 303
    assert _send(client, case, db.get(MailMessage, live.id)).status_code == 303 and len(mail.transport.sent) == 1


def test_investigator_then_admin_send_with_an_outlook_send_waiting_sends_nothing(db, case, run, client, client_for,
                                                                                 mail):
    """An investigator can no longer retire the checklist (Send from Aegis is gone, retire is a case admin's); the
    admin's Send of the investigator's preview is refused while the checklist is open, and so is the admin's retire
    while the Sent Items sync has an Outlook send that may be the letter waiting for review."""
    inv = client_for("investigator", case=case)
    corr = _draft(db, case, run, template="stop_order")
    live = _prepared(db, _compose(inv, case, corr))  # prepared for review, before the switch to manual mode
    mail.settings.aegis_mail_transport = "manual"
    checklist = _prepared(db, _compose(inv, case, db.get(Correspondence, corr.id)))
    mail.settings.aegis_mail_transport = "file"
    path = f"/cases/{case.id}/mail/messages/{checklist.id}"
    r = inv.post(f"{path}/send-from-aegis", data={"csrf_token": csrf_token(inv, path), "confirm_not_sent": "1"},
                 follow_redirects=False)
    assert r.status_code in (404, 405)
    assert _retire(inv, case, checklist).status_code == 403
    assert _editor(inv, case, db.get(Correspondence, corr.id), action="prepare").status_code == 409
    seen = _outlook_send_waiting(db, case, checklist)
    try:
        r = _send(client, case, live)
        assert r.status_code == 409 and compose.checklist_text(checklist) in r.text
        r = _retire(client, case, checklist)
        assert r.status_code == 409 and "waiting for review" in r.text and f"e-mail #{seen.id}" in r.text
        assert 'id="mail-outlook-suspected"' in r.text
        r = _editor(client, case, db.get(Correspondence, corr.id), action="send_now")
        assert r.status_code == 409
        assert [(m.id, m.status) for m in _letter_mails(db, corr)] == [(live.id, MailStatus.PREPARED),
                                                                       (checklist.id, MailStatus.PREPARED)]
        assert not mail.transport.sent
    finally:
        db.delete(db.get(MailMessage, seen.id))
        db.commit()


def test_the_rule_counts_prepared_and_expired_checklists_only(db, case, run, client, mail):
    """A checklist cancelled in manual mode (its Cancel, an editor Save) is no longer open; one still open cannot be
    cancelled once Aegis sends (retire it, or record it)."""
    corr, mm = _manual_checklist(db, case, run, client, mail)
    assert compose.open_checklist(db, corr).id == mm.id
    r = _cancel(client, case, mm)
    assert r.status_code == 409 and "retire it" in r.text
    mail.settings.aegis_mail_transport = "manual"
    assert compose.open_checklist(db, corr).id == mm.id  # open, but manual mode guards nothing
    assert _cancel(client, case, mm).status_code == 303
    mail.settings.aegis_mail_transport = "file"
    assert compose.open_checklist(db, db.get(Correspondence, corr.id)) is None
    new = _mm_from_confirm(db, _editor(client, case, db.get(Correspondence, corr.id), action="send_now"))
    assert _send(client, case, new).status_code == 303 and len(mail.transport.sent) == 1


def test_outlook_send_suspected_filters_by_case_and_time_not_a_window(db, case, run, client, mail):
    from datetime import timedelta

    _corr, mm = _manual_checklist(db, case, run, client, mail)
    seen = _outlook_send_waiting(db, case, mm)
    noise = [MailMessage(case_id=None, direction=mm.direction, status=MailStatus.SENT_EXTERNAL, transport="graph",
                         mailbox=mm.mailbox or "x@aegis.example", message_id=f"<noise-{mm.id}-{i}@example.com>",
                         folder="sentitems", outside_sent=True, sent_at=seen.sent_at, to_addrs=[], cc_addrs=[],
                         attachments=[], meta={}) for i in range(520)]
    db.add_all(noise)
    db.commit()
    try:
        assert compose.outlook_send_suspected(db, mm).id == seen.id  # 520 newer Sent Items rows do not hide it
        seen.sent_at = mm.prepared_at - timedelta(minutes=5)  # sent before the checklist was prepared: not it
        db.commit()
        assert compose.outlook_send_suspected(db, mm) is None
    finally:
        for row in [*noise, seen]:
            db.delete(row)
        db.commit()


# --------------------------------------------------------------------------- the Sent Items read before retiring
def _sync_result(monkeypatch, **flags):
    from types import SimpleNamespace

    from app.mail import config, ingest

    monkeypatch.setattr(config, "mail_settings", lambda: SimpleNamespace(aegis_mail_inbound=True))
    if flags.get("raise"):
        def boom(db, **kw):
            raise RuntimeError("graph 503")
        monkeypatch.setattr(ingest, "sync_mailbox", boom)
    else:
        monkeypatch.setattr(ingest, "sync_mailbox", lambda db, **kw: ingest.SyncReport(trigger=kw["trigger"], **flags))


SENT_BOX = "retire-sent-items@aegis.example"


@pytest.fixture
def sent_box(db):
    """SENT_BOX's Sent Items folder row is removed afterwards (the test DB is shared by the run)."""
    yield SENT_BOX
    from app.db.models import MailSyncFolder

    db.rollback()
    fs = db.get(MailSyncFolder, (SENT_BOX, "sentitems"))
    if fs is not None:
        db.delete(fs)
        db.commit()


def _sent_items_read(db, monkeypatch, mm, *, since_delta, folders=("inbox", "sentitems"), sent_errors=0):
    """A graph sync that read `folders`; Sent Items' backfill start is `since_delta` after the checklist's
    preparation (mail_sync_folders.since)."""
    from app.db.models import MailSyncFolder

    fs = db.get(MailSyncFolder, (SENT_BOX, "sentitems"))
    if fs is None:
        fs = MailSyncFolder(mailbox=SENT_BOX, folder="sentitems", last_result={})
        db.add(fs)
    fs.since = mm.prepared_at + since_delta
    db.commit()
    from app.mail.ingest import SENT_KEYS

    sent = dict.fromkeys(SENT_KEYS, 0) | {"errors": sent_errors}
    _sync_result(monkeypatch, mailbox=SENT_BOX, folders=list(folders), sent=sent)


@pytest.mark.parametrize("flag", ["too_soon", "busy"])
def test_a_sync_that_cannot_run_now_refuses_to_retire_the_checklist(db, case, run, client, mail, monkeypatch, flag):
    corr, mm = _manual_checklist(db, case, run, client, mail)
    _sync_result(monkeypatch, **{flag: True})
    r = _retire(client, case, mm)
    assert r.status_code == 409 and "press the button again" in r.text and "Nothing was retired" in r.text
    assert [(m.id, m.status) for m in _letter_mails(db, corr)] == [(mm.id, MailStatus.PREPARED)]


def test_a_sync_that_read_sent_items_retires_quietly(db, sent_box, case, run, client, mail, monkeypatch):
    from datetime import timedelta

    _corr, mm = _manual_checklist(db, case, run, client, mail)
    _sent_items_read(db, monkeypatch, mm, since_delta=-timedelta(days=30))  # read from before it was prepared
    assert "reads the mailbox's Sent Items first" in client.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    r = _retire(client, case, mm)
    assert r.status_code == 303 and "done=retired#" in r.headers["location"]
    page = client.get(r.headers["location"].split("#")[0]).text
    assert "could not read" not in page and "yourself" not in page


@pytest.mark.parametrize("how", ["error", "raise"])
def test_a_sync_that_did_not_read_sent_items_retires_with_a_warning(db, case, run, client, mail, monkeypatch, how):
    corr, mm = _manual_checklist(db, case, run, client, mail)
    if how == "error":
        _sync_result(monkeypatch, error="graph 503")
    elif how == "raise":
        _sync_result(monkeypatch, **{"raise": True})
    r = _retire(client, case, mm)
    assert r.status_code == 303 and "done=retired_unchecked" in r.headers["location"]
    page = client.get(r.headers["location"].split("#")[0]).text
    assert "could not read the mailbox" in page and 'id="mail-send-now"' in page
    assert _letter_mails(db, corr)[0].status == MailStatus.CANCELLED


def test_with_inbound_off_the_retire_says_aegis_does_not_read_the_mailbox(db, case, run, client, mail):
    """AEGIS_MAIL_INBOUND off (the default): no Sent Items read, said as such (not "just now", a passing fault)."""
    corr, mm = _manual_checklist(db, case, run, client, mail)
    panel = client.get(f"/cases/{case.id}/mail/messages/{mm.id}").text
    assert "AEGIS_MAIL_INBOUND is off" in panel and "reads the mailbox's Sent Items first" not in panel
    r = _retire(client, case, mm)
    assert r.status_code == 303 and "done=retired_no_inbound#" in r.headers["location"]
    page = client.get(r.headers["location"].split("#")[0]).text
    assert "does not read this mailbox (AEGIS_MAIL_INBOUND is off)" in page and "just now" not in page
    assert "check Sent Items in Outlook yourself" in page and 'id="mail-send-now"' in page
    assert _letter_mails(db, corr)[0].status == MailStatus.CANCELLED


@pytest.mark.parametrize("how", ["since_after_prepared", "no_sent_items_folder", "sent_items_errors"])
def test_a_sync_that_could_not_see_the_outlook_send_retires_with_a_warning(db, sent_box, case, run, client, mail, monkeypatch,
                                                                           how):
    """Sent Items is read only from its backfill start (AEGIS_MAIL_INBOUND_SINCE, the first sync): a checklist prepared
    and sent from Outlook before it is skipped as old, so a clean sync proves nothing; nor does one that read no Sent
    Items (a file / demo inbound transport) or whose Sent Items read failed."""
    from datetime import timedelta

    corr, mm = _manual_checklist(db, case, run, client, mail)
    if how == "since_after_prepared":
        _sent_items_read(db, monkeypatch, mm, since_delta=timedelta(days=6))
    elif how == "no_sent_items_folder":
        _sent_items_read(db, monkeypatch, mm, since_delta=-timedelta(days=30), folders=("inbox",))
    else:
        _sent_items_read(db, monkeypatch, mm, since_delta=-timedelta(days=30), sent_errors=1)
    r = _retire(client, case, mm)
    assert r.status_code == 303 and "done=retired_not_covered#" in r.headers["location"]
    page = client.get(r.headers["location"].split("#")[0]).text
    assert "an Outlook send of it would not have been seen" in page and "Check Sent Items in Outlook yourself" in page
    assert _letter_mails(db, corr)[0].status == MailStatus.CANCELLED
    assert _audits(db, "MAIL_CANCELLED", "mail_messages", mm.id)[-1].detail["sent_items"] in ("before_cutover",
                                                                                               "no_sent_items")


def test_sent_items_coverage_compares_the_folder_backfill_start_with_the_checklist(db, sent_box, case, run, client, mail):
    from datetime import timedelta

    from app.db.models import MailSyncFolder
    from app.mail.ingest import SyncReport

    _corr, mm = _manual_checklist(db, case, run, client, mail)
    report = SyncReport(mailbox=SENT_BOX, folders=["inbox", "sentitems"])
    fs = db.get(MailSyncFolder, (SENT_BOX, "sentitems")) or MailSyncFolder(mailbox=SENT_BOX, folder="sentitems",
                                                                          last_result={})
    db.add(fs)
    for delta, want in ((timedelta(0), "ok"), (-timedelta(days=1), "ok"), (timedelta(seconds=1), "before_cutover")):
        fs.since = mm.prepared_at + delta
        db.commit()
        assert compose.sent_items_coverage(db, report, mm) == want, delta
    fs.since = None
    db.commit()
    assert compose.sent_items_coverage(db, report, mm) == "before_cutover"
    assert compose.sent_items_coverage(db, SyncReport(mailbox=SENT_BOX, folders=["inbox"]), mm) == "no_sent_items"
    assert compose.sent_items_coverage(db, SyncReport(mailbox="other@aegis.example", folders=["sentitems"]),
                                       mm) == "no_sent_items"


def test_an_expired_checklist_of_a_letter_recorded_as_sent_is_never_retired(db, case, run, client, mail):
    """The Sent Items sync recorded the letter as sent (only prepared siblings are retired then): a stale tab's
    retire of the expired checklist must not record "not sent from Outlook" against that record."""
    from datetime import UTC, datetime

    from app.db.models import CorrespondenceStatus, MailDirection

    corr, mm = _manual_checklist(db, case, run, client, mail)
    path = f"/cases/{case.id}/mail/messages/{mm.id}"
    token = csrf_token(client, path)  # the stale tab, opened before the sync
    mm.status = MailStatus.EXPIRED
    corr = db.get(Correspondence, corr.id)
    corr.status, corr.occurred_at = CorrespondenceStatus.SENT, datetime.now(tz=UTC)
    sent = MailMessage(case_id=case.id, correspondence_id=corr.id, direction=MailDirection.OUT,
                       status=MailStatus.SENT_EXTERNAL, transport="graph", mailbox="x@aegis.example",
                       message_id=f"<recorded-{mm.id}@example.com>", folder="sentitems", outside_sent=True,
                       sent_at=datetime.now(tz=UTC), to_addrs=[], cc_addrs=[], attachments=[], meta={})
    db.add(sent)
    db.commit()
    try:
        assert compose.is_open_checklist(db.get(MailMessage, mm.id))  # still "open": the guard alone does not stop it
        r = client.post(f"{path}/retire-checklist", data={"csrf_token": token}, follow_redirects=False)
        assert r.status_code == 409 and "already sent or recorded as sent" in r.text and "nothing was retired" in r.text
        db.expire_all()
        old = db.get(MailMessage, mm.id)
        assert old.status == MailStatus.EXPIRED and "not_sent_confirmed" not in (old.meta or {})
        assert not [a for a in _audits(db, "MAIL_CANCELLED", "mail_messages", mm.id)
                    if a.detail.get("reason") == "retired_not_sent"]
        # the domain choke point refuses it too (a caller that skips the route's check)
        from app.core.permissions import ADMIN, CaseAccess

        access = CaseAccess(case=case, user=client.user, role=ADMIN, member=None)
        with pytest.raises(compose.ComposeError, match="already sent"):
            compose.retire_checklist(db, access, old, db.get(Correspondence, corr.id))
        db.rollback()
        assert db.get(MailMessage, mm.id).status == MailStatus.EXPIRED
    finally:  # the test DB is shared by the run: the letter goes back to a draft, its checklist closed
        db.rollback()
        db.delete(db.get(MailMessage, sent.id))
        db.get(MailMessage, mm.id).status = MailStatus.CANCELLED
        db.get(Correspondence, corr.id).status = CorrespondenceStatus.DRAFT
        db.commit()


def test_the_sync_before_a_letter_check_bypasses_the_manual_interval(db, tmp_path, monkeypatch):
    from datetime import UTC, datetime, timedelta

    from app.mail.config import MailSettings
    from app.mail.ingest import get_state, sync_mailbox

    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(tmp_path / "vault"))
    box = f"letter-check-{tmp_path.name[-8:]}@aegis.example"
    settings = MailSettings(_env_file=None, aegis_mail_transport="file", aegis_mail_from=box,
                            aegis_mail_inbox_dir=str(inbox), aegis_mail_outbox_dir=str(tmp_path / "out"),
                            aegis_mail_inbound=True)
    assert not sync_mailbox(db, trigger="case_admin", settings=settings).too_soon
    state = get_state(db, box, "file")
    state.last_started_at = datetime.now(tz=UTC) - timedelta(seconds=10)
    db.commit()
    assert sync_mailbox(db, trigger="case_admin", settings=settings).too_soon  # 60 s for a person's sync
    assert not sync_mailbox(db, trigger="letter_check", settings=settings).too_soon  # 5 s before a letter check
    assert sync_mailbox(db, trigger="letter_check", settings=settings).too_soon


# --------------------------------------------------------------------------- uploads: an allowlist, by content
def _zip(entries: dict[str, bytes], first: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        if first:
            z.writestr(first, entries.pop(first))
        for k, v in entries.items():
            z.writestr(k, v)
    return buf.getvalue()


def _docx() -> bytes:
    buf = io.BytesIO()
    d = Document()
    d.add_paragraph("statement")
    d.save(buf)
    return buf.getvalue()


def _with(data: bytes, name: str, payload: bytes) -> bytes:
    buf = io.BytesIO(data)
    with zipfile.ZipFile(buf, "a") as z:
        z.writestr(name, payload)
    return buf.getvalue()


MZ = b"MZ\x90\x00" + b"\x00" * 60
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 200


@pytest.mark.parametrize("name, data", [
    ("statements.zip", _zip({"invoice.exe": MZ})),
    ("viewer.msix", _zip({"AppxManifest.xml": b"<x/>"})),
    ("app.appx", _zip({"AppxManifest.xml": b"<x/>"})),
    ("old.doc", OLE), ("old.xls", OLE), ("old.ppt", OLE),
    ("letter.rtf", b"{\\rtf1\\ansi {\\object\\objemb}}"),
    ("page.mht", b"MIME-Version: 1.0\r\n\r\n<html>"), ("page.mhtml", b"x"), ("page.shtml", b"<html>"),
    ("page.xhtm", b"<html>"), ("q.iqy", b"WEB\r\n1\r\nhttp://x"), ("t.ps1xml", b"<x/>"), ("m.wasm", b"\x00asm"),
    ("run.command", b"open -a Calculator\n"), ("run.terminal", b"<plist/>"), ("snap.msc", b"<x/>"),
    ("c.cab", b"MSCF\x00\x00"), ("w.wsc", b"<scriptlet/>"), ("s.sct", b"<scriptlet/>"), ("x.xbap", b"x"),
    ("j.jnlp", b"<jnlp/>"), ("a.7z", b"7z\xbc\xaf\x27\x1c"), ("a.rar", b"Rar!\x1a\x07"), ("a.tar", b"x" * 600),
    ("a.gz", b"\x1f\x8b\x08"),
    # an allowed extension whose content is not that type, or carries active content
    ("macro.docx", _with(_docx(), "word/vbaProject.bin", OLE)),
    ("ole.docx", _with(_docx(), "word/embeddings/oleObject1.bin", OLE)),
    ("payload.docx", _with(_docx(), "word/media/tool.exe", MZ)),
    ("renamed.docx", _zip({"invoice.exe": MZ})),
    ("renamed.xlsx", _docx()),  # a Word document named as a workbook
    ("statement.pdf", b"\x89PNG\r\n\x1a\n" + b"0" * 50),
    ("photo.png", b"%PDF-1.4 not an image"),
    ("notes.txt", b"text\x00with a NUL"),
    ("calc.ods", _zip({"mimetype": b"application/vnd.oasis.opendocument.text", "content.xml": b"<x/>"},
                      first="mimetype")),
    ("macro.odt", _zip({"mimetype": b"application/vnd.oasis.opendocument.text", "Basic/Standard/m.xml": b"<x/>"},
                       first="mimetype")),
])
def test_uploads_outside_the_allowlist_or_not_matching_their_type_are_refused(name, data):
    with pytest.raises(compose.ComposeError) as e:
        compose.check_upload(name, data, 2_900_000)
    assert e.value.field == "upload" and "cannot be attached" in str(e.value)


@pytest.mark.parametrize("name, data", [
    ("statement.pdf", b"%PDF-1.7\n" + b"0" * 100),
    ("shot.png", b"\x89PNG\r\n\x1a\n" + b"0" * 50), ("shot.jpg", b"\xff\xd8\xff\xe0" + b"0" * 50),
    ("shot.gif", b"GIF89a" + b"0" * 20), ("shot.tiff", b"II*\x00" + b"0" * 20),
    ("shot.webp", b"RIFF\x10\x00\x00\x00WEBPVP8 "), ("shot.heic", b"\x00\x00\x00\x18ftypheic" + b"0" * 20),
    ("tx.csv", b"date,amount\n2026-01-01,5\n"), ("notes.txt", "Grüße\n".encode()),
    ("utf16.txt", "hi".encode("utf-16")), ("data.json", b'{"a": 1}'),
    ("letter.docx", _docx()),
    ("book.xlsx", _zip({"[Content_Types].xml": b"<Types/>", "xl/workbook.xml": b"<workbook/>",
                        "xl/printerSettings/printerSettings1.bin": b"\x00\x01"})),
    ("calc.ods", _zip({"mimetype": b"application/vnd.oasis.opendocument.spreadsheet", "content.xml": b"<x/>",
                       "Object 1/content.xml": b"<chart/>"}, first="mimetype")),
])
def test_plain_documents_images_and_data_files_are_uploaded(name, data):
    assert compose.check_upload(name, data, 2_900_000) == name


def test_a_zip_holding_a_program_is_refused_on_the_editor_and_nothing_is_stored(db, case, run, client, mail):
    corr = _draft(db, case, run)
    before = db.scalar(select(EvidenceItem.id).order_by(EvidenceItem.id.desc()).limit(1))
    page = client.get(_path(case, corr)).text
    assert 'accept=".pdf,' in page and "archives (.zip" in page
    r = _editor(client, case, corr, action="upload", files=[
        ("upload", ("statements.zip", _zip({"invoice.exe": MZ}), "application/zip")),
        ("upload", ("viewer.msix", _zip({"AppxManifest.xml": b"<x/>"}), "application/octet-stream")),
        ("upload", ("old.doc", OLE, "application/msword"))])
    assert r.status_code == 400 and "cannot be attached" in r.text
    db.expire_all()
    assert db.scalar(select(EvidenceItem.id).order_by(EvidenceItem.id.desc()).limit(1)) == before


def test_too_many_upload_parts_are_refused_before_they_are_read(db, case, run, client, mail):
    corr = _draft(db, case, run)
    before = db.scalar(select(EvidenceItem.id).order_by(EvidenceItem.id.desc()).limit(1))
    files = [("upload", (f"f{i}.pdf", b"%PDF-1.4 x", "application/pdf")) for i in range(compose.UPLOAD_MAX_FILES + 2)]
    r = _editor(client, case, corr, action="upload", files=files)
    assert r.status_code == 400
    db.expire_all()
    assert db.scalar(select(EvidenceItem.id).order_by(EvidenceItem.id.desc()).limit(1)) == before


# --------------------------------------------------------------------------- the form: Enter, suggestions
def test_enter_in_a_field_submits_nothing_and_suggestions_can_be_added(db, case, run, client, mail):
    corr = _draft(db, case, run, template="stop_order")
    page = client.get(_path(case, corr)).text
    form = page[page.index('id="mail-compose-form"'):]
    first = re.search(r"<button[^>]*type=\"submit\"[^>]*>", form).group(0)
    assert "disabled" in first and 'name="action"' not in first  # the default button: implicit submission is off
    howto = page[page.index('id="mail-howto"'):] if 'id="mail-howto"' in page else ""
    addresses = re.findall(r'data-mail-add="mail-(?:to|cc)-other" data-address="([^"]+)"', howto)
    listed = {a.lower() for a in re.findall(r'name="to" value="([^"]+)"', page)}
    assert addresses and 'data-mail-add="mail-cc-other"' in howto  # the demo stop order's Cc suggestion
    assert all(a.lower() not in listed for a in addresses)  # only addresses the recipients table lacks


# --------------------------------------------------------------------------- review round: form caps, the footer
def test_the_live_preview_takes_text_only_and_refuses_file_parts(db, case, run, client, mail, monkeypatch):
    """The preview needs `body_markdown` only: its CSRF dependency parses the form itself with no file part allowed
    (FastAPI would otherwise parse, and spool, every part with Starlette's defaults before the route runs)."""
    from starlette.formparsers import MultiPartParser

    corr = _draft(db, case, run)
    token = csrf_token(client, _path(case, corr))
    ok = client.post(_path(case, corr) + "/preview", data={"csrf_token": token, "body_markdown": "**hi**"})
    assert ok.status_code == 200 and "<strong>hi</strong>" in ok.json()["html"]
    caps = []
    real = MultiPartParser.__init__

    def spy(self, *a, **kw):
        caps.append((kw.get("max_files"), kw.get("max_fields")))
        real(self, *a, **kw)

    monkeypatch.setattr(MultiPartParser, "__init__", spy)
    r = client.post(_path(case, corr) + "/preview", data={"csrf_token": token, "body_markdown": "x"},
                    files=[("upload", (f"f{i}.pdf", b"%PDF-1.4 " + b"x" * 1000, "application/pdf")) for i in range(3)])
    assert r.status_code == 400 and caps == [(0, 5)]  # parsed once, with the caps
    r = client.post(_path(case, corr) + "/preview", data={"csrf_token": token, "body_markdown": "x",
                                                          **{f"f{i}": "y" for i in range(6)}})
    assert r.status_code == 400  # too many fields
    assert client.post(_path(case, corr) + "/preview", data={"body_markdown": "x"}).status_code == 403  # no CSRF


def test_the_editor_form_caps_its_file_parts_where_it_is_parsed(db, case, run, client, mail, monkeypatch):
    from starlette.formparsers import MultiPartParser

    corr = _draft(db, case, run)
    caps = []
    real = MultiPartParser.__init__

    def spy(self, *a, **kw):
        caps.append(kw.get("max_files"))
        real(self, *a, **kw)

    monkeypatch.setattr(MultiPartParser, "__init__", spy)
    files = [("upload", (f"f{i}.pdf", b"%PDF-1.4 x", "application/pdf")) for i in range(compose.UPLOAD_MAX_FILES + 2)]
    r = _editor(client, case, corr, action="upload", files=files)
    assert r.status_code == 400 and caps == [compose.UPLOAD_MAX_FILES + 1]  # the parser refused it: never spooled


def test_the_provenance_footer_is_never_sent_even_with_text_after_it(db, case, run, client, mail):
    footer = "\n\n* * *\n\n*Draft generated by Aegis on 1 Oct 2026 for case X. Review before sending.*"
    assert compose.outbound_markdown("Dear team,\n\nRegards" + footer) == "Dear team,\n\nRegards\n"
    assert compose.outbound_markdown("Dear team,\n\nRegards" + footer + "\n\nP.S. one more\n") == \
        "Dear team,\n\nRegards\n\nP.S. one more\n"
    gen = "\r\n\r\n* * *\r\n\r\n*Generated by Aegis on 21.10.2026 from trace run #1 for case X. Described, not cited.*"
    assert compose.outbound_markdown("Regards" + gen + "\r\nNote: see the annex.") == "Regards\n\nNote: see the annex.\n"
    # a separator of the member's own is kept: only the Aegis footer goes
    assert compose.outbound_markdown("A\n\n* * *\n\nB") == "A\n\n* * *\n\nB\n"
    # the e-mail itself (the KuCoin stop order, a P.S. typed after the footer): neither part carries it
    corr = _draft(db, case, run, template="stop_order")
    assert "Generated by Aegis" in corr.body_markdown or "Draft generated by Aegis" in corr.body_markdown
    body = corr.body_markdown.rstrip() + "\n\nP.S. E2E-MARKER keep the hold in place.\n"
    mm = _mm_from_confirm(db, _editor(client, case, corr, action="send_now", body_markdown=body))
    msg = test_mail_editor._msg(compose.read_raw(mm, db))
    for part in ("plain", "html"):
        content = msg.get_body((part,)).get_content()
        assert "E2E-MARKER" in content and "Generated by Aegis" not in content and "Draft generated" not in content
    assert "Generated by Aegis" not in compose.preview(db, mm, db.get(Correspondence, corr.id)).text
    assert _send(client, case, mm).status_code == 303
    sent = test_mail_editor._msg(mail.transport.sent[-1])
    assert "Generated by Aegis" not in sent.get_body(("plain",)).get_content()


def test_regenerating_stop_orders_never_replaces_a_draft_with_an_open_checklist(db, case, run, client, mail):
    """A regenerated stop order is a new letter (a new letter key): it would slip past the old checklist's guard,
    so the generator leaves that entity alone while the checklist may still have gone out from Outlook."""
    from app import services
    from app.db.models import StopOrder, StopOrderStatus

    corr, mm = _manual_checklist(db, case, run, client, mail)
    order = db.get(StopOrder, corr.stop_order_id)
    created = services.generate_stop_orders(db, case, run)
    db.expire_all()
    assert db.get(StopOrder, order.id).status == StopOrderStatus.DRAFT
    assert not [o for o in created if o.entity_id == order.entity_id]
    assert compose.is_open_checklist(db.get(MailMessage, mm.id))


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
