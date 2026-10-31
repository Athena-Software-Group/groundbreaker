"""/admin/mail (system admins): transport and inbound cards, token / mailbox tests, test send, manual
sync and reset; and the scheduler's mail pass. Graph runs over httpx.MockTransport; nothing reaches
the network. The fake secret is a low-entropy placeholder that must never appear in a page."""

from __future__ import annotations

import base64
import json
import uuid

import httpx
import pytest
from conftest import csrf_token
from sqlalchemy import select

from app.db import models

if not hasattr(models, "MailMessage"):
    pytest.skip("waiting for migration 0008", allow_module_level=True)

SECRET = "test-client-secret-not-real"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def refuse(self, request):
        raise AssertionError(f"a test tried to reach the network: {request.url.host}")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", refuse)
    from app.mail import graph

    graph.clear_token_cache()
    yield
    graph.clear_token_cache()


@pytest.fixture(autouse=True)
def mail_routes():
    """The mail admin router is included by app.main; this fixture only hands the app over."""
    from app.main import app

    return app


@pytest.fixture
def file_mail(tmp_path, monkeypatch):
    outbox, inbox = tmp_path / "outbox", tmp_path / "inbox"
    inbox.mkdir()
    mailbox = f"case-desk-{uuid.uuid4().hex[:8]}@aegis.example"
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(tmp_path / "vault"))
    for k, v in {"AEGIS_MAIL_TRANSPORT": "file", "AEGIS_MAIL_FROM": mailbox, "AEGIS_MAIL_OUTBOX_DIR": str(outbox),
                 "AEGIS_MAIL_INBOX_DIR": str(inbox), "AEGIS_MAIL_INBOUND": "on"}.items():
        monkeypatch.setenv(k, v)
    return {"outbox": outbox, "inbox": inbox, "mailbox": mailbox}


def graph_env(monkeypatch):
    for k, v in {"AEGIS_MAIL_TRANSPORT": "graph", "AEGIS_MAIL_FROM": "case-desk@aegis.example",
                 "AEGIS_M365_TENANT_ID": "00000000-0000-0000-0000-000000000000",
                 "AEGIS_M365_CLIENT_ID": "00000000-0000-0000-0000-0000000000ab",
                 "AEGIS_M365_CLIENT_SECRET": SECRET}.items():
        monkeypatch.setenv(k, v)


def mock_graph(monkeypatch, handler):
    """Make the admin routes build their Graph transport over a MockTransport."""
    from app.mail.config import mail_settings
    from app.mail.graph import GraphTransport
    from app.web import routes_mail_admin

    def factory(settings=None):
        s = settings or mail_settings()
        return GraphTransport(s, client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)

    monkeypatch.setattr(routes_mail_admin, "get_transport", factory)


def jwt(roles):
    def seg(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")

    return f"{seg({'alg': 'none'})}.{seg({'roles': roles})}.x"


def last_audit(db, action):
    db.expire_all()
    return db.scalars(select(models.AuditEvent).where(models.AuditEvent.action == action)
                      .order_by(models.AuditEvent.id.desc())).first()


def test_system_admin_only(client_for, case, file_mail):
    admin = client_for("admin", case=case)
    for path in ("/admin/mail", "/admin/mail/unassigned"):
        assert admin.get(path).status_code == 403
    tok = csrf_token(admin, f"/cases/{case.id}?tab=overview")
    for path in ("/admin/mail/sync", "/admin/mail/test-send", "/admin/mail/reset-sync", "/admin/mail/token-test",
                 "/admin/mail/mailbox-test"):
        assert admin.post(path, data={"csrf_token": tok, "to": "a@example.com", "confirm": "1"}).status_code == 403
    sysadmin = client_for(None, system_admin=True)
    r = sysadmin.get("/admin/mail")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert "Transport" in r.text and "Inbound" in r.text and "Queues" in r.text and "Recent outbound" in r.text
    assert file_mail["mailbox"] in r.text
    assert str(file_mail["outbox"]) not in r.text and str(file_mail["inbox"]) not in r.text  # paths never shown


def test_page_never_shows_the_secret(client_for, monkeypatch):
    graph_env(monkeypatch)
    sysadmin = client_for(None, system_admin=True)
    r = sysadmin.get("/admin/mail")
    assert r.status_code == 200
    assert SECRET not in r.text and "00000000-0000-0000-0000-0000000000ab" not in r.text
    assert "0000…00ab" in r.text and "configured" in r.text


def test_token_and_mailbox_tests_are_mocked_and_audited(client_for, db, monkeypatch):
    graph_env(monkeypatch)
    token = jwt(["Mail.ReadWrite", "Mail.Send"])
    seen: list[str] = []

    def handler(request):
        seen.append(request.url.path)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": token, "expires_in": 3599})
        if request.url.path.endswith("/mailFolders/inbox"):
            return httpx.Response(200, json={"id": "x", "displayName": "Inbox", "totalItemCount": 3,
                                             "unreadItemCount": 1})
        return httpx.Response(404)

    mock_graph(monkeypatch, handler)
    sysadmin = client_for(None, system_admin=True)
    tok = csrf_token(sysadmin, "/admin/mail")
    assert sysadmin.post("/admin/mail/token-test", data={}).status_code in (400, 403)  # CSRF
    r = sysadmin.post("/admin/mail/token-test", data={"csrf_token": tok})
    assert r.status_code == 200 and "token OK" in r.text and "Mail.Send" in r.text and "3599" in r.text
    assert token not in r.text and SECRET not in r.text
    a = last_audit(db, "MAIL_TOKEN_TEST")
    assert a.detail == {"ok": True, "reason": None, "transport": "graph", "n_roles": 2}
    r = sysadmin.post("/admin/mail/mailbox-test", data={"csrf_token": tok})
    assert "mailbox OK" in r.text and "3 messages, 1 unread" in r.text
    assert last_audit(db, "MAIL_MAILBOX_TEST").detail["ok"] is True
    assert any(p.endswith("/users/case-desk@aegis.example/mailFolders/inbox") for p in seen)


def test_token_test_failure_is_explained(client_for, monkeypatch):
    graph_env(monkeypatch)
    mock_graph(monkeypatch, lambda request: httpx.Response(401, json={"error": "invalid_client",
                                                                       "error_codes": [7000215]}))
    sysadmin = client_for(None, system_admin=True)
    r = sysadmin.post("/admin/mail/token-test", data={"csrf_token": csrf_token(sysadmin, "/admin/mail")})
    assert "token test failed" in r.text and "invalid_client" in r.text and SECRET not in r.text


def test_file_mailbox_test_checks_the_folders(client_for, file_mail):
    sysadmin = client_for(None, system_admin=True)
    r = sysadmin.post("/admin/mail/mailbox-test", data={"csrf_token": csrf_token(sysadmin, "/admin/mail")})
    assert "AEGIS_MAIL_INBOX_DIR" in r.text and "does not exist yet" in r.text  # outbox not created yet
    file_mail["outbox"].mkdir()
    r = sysadmin.post("/admin/mail/mailbox-test", data={"csrf_token": csrf_token(sysadmin, "/admin/mail")})
    assert r.text.count("tag green\">OK</span>") >= 2


def test_test_send_writes_to_the_outbox_validated_and_rate_limited(client_for, db, file_mail, monkeypatch):
    from app.web import routes_mail_admin

    sysadmin = client_for(None, system_admin=True)
    tok = csrf_token(sysadmin, "/admin/mail")
    for bad in ("", "Name <a@example.com>", "a@example.com\r\nBcc: x@example.com", "a@[127.0.0.1]", "a@localhost",
                "a@example.com, b@example.com", "ä@example.com"):
        r = sysadmin.post("/admin/mail/test-send", data={"csrf_token": tok, "to": bad})
        assert r.status_code == 400, bad
    assert not file_mail["outbox"].exists()
    already = routes_mail_admin._test_sends_last_hour(db)
    monkeypatch.setenv("AEGIS_MAIL_TEST_SENDS_PER_HOUR", str(already + 1))
    r = sysadmin.post("/admin/mail/test-send", data={"csrf_token": tok, "to": "Me@Example.COM"})
    assert r.status_code == 200 and "sent" in r.text, r.text
    files = list(file_mail["outbox"].glob("*.eml"))
    assert len(files) == 1
    raw = files[0].read_bytes()
    assert b"Subject: Aegis test message" in raw and b"Test message from Aegis (no case data)." in raw
    assert b"To: Me@example.com" in raw and file_mail["mailbox"].encode() in raw
    a = last_audit(db, "MAIL_TEST_SEND")
    assert a.detail == {"ok": True, "reason": None, "transport": "file", "recipient_domain": "example.com"}
    r = sysadmin.post("/admin/mail/test-send", data={"csrf_token": tok, "to": "me@example.com"})
    assert r.status_code == 429 and "test messages per hour" in r.text
    assert len(list(file_mail["outbox"].glob("*.eml"))) == 1


def test_test_send_through_graph_respects_the_dev_allow_list(client_for, monkeypatch):
    graph_env(monkeypatch)
    monkeypatch.setenv("AEGIS_MAIL_DEV_ALLOWED_DOMAINS", "example.com")
    mock_graph(monkeypatch, lambda request: httpx.Response(500))
    sysadmin = client_for(None, system_admin=True)
    r = sysadmin.post("/admin/mail/test-send", data={"csrf_token": csrf_token(sysadmin, "/admin/mail"),
                                                     "to": "someone@counterparty.example"})
    assert r.status_code == 400 and "AEGIS_MAIL_DEV_ALLOWED_DOMAINS" in r.text


def test_sync_and_reset_are_audited(client_for, db, file_mail):
    sysadmin = client_for(None, system_admin=True)
    tok = csrf_token(sysadmin, "/admin/mail")
    (file_mail["inbox"] / "x.eml").write_bytes(
        b"From: a@exchange.example\r\nTo: x@aegis.example\r\nSubject: hello\r\nMessage-ID: <" +
        uuid.uuid4().hex.encode() + b"@exchange.example>\r\n\r\nhi\r\n")
    r = sysadmin.post("/admin/mail/sync", data={"csrf_token": tok})
    assert r.status_code == 200 and "mailbox checked" in r.text and "unassigned=1" in r.text
    a = last_audit(db, "MAIL_SYNC")
    assert a.detail["trigger"] == "admin" and a.detail["unassigned"] == 1 and a.detail["fetched"] == 1
    r = sysadmin.post("/admin/mail/sync", data={"csrf_token": tok})
    assert r.status_code == 429 and "less than a minute ago" in r.text
    assert sysadmin.post("/admin/mail/reset-sync", data={"csrf_token": tok}).status_code == 400
    r = sysadmin.post("/admin/mail/reset-sync", data={"csrf_token": tok, "confirm": "1"})
    assert r.status_code == 200 and "reset" in r.text
    assert last_audit(db, "MAIL_SYNC_RESET").detail == {"had_delta": False}
    state = db.get(models.MailSyncState, file_mail["mailbox"])
    assert state.delta_link is None and state.since is not None
    page = sysadmin.get("/admin/mail/unassigned")
    assert page.status_code == 200 and "hello" in page.text


def test_sync_refused_while_inbound_is_off(client_for, file_mail, monkeypatch):
    monkeypatch.setenv("AEGIS_MAIL_INBOUND", "off")
    sysadmin = client_for(None, system_admin=True)
    r = sysadmin.post("/admin/mail/sync", data={"csrf_token": csrf_token(sysadmin, "/admin/mail")})
    assert "Inbound mail is off" in r.text


# --------------------------------------------------------------------------- scheduler
def test_scheduler_runs_the_mail_pass_isolated(file_mail, monkeypatch):
    from scripts import poll_watch, run_scheduler

    monkeypatch.setattr(poll_watch, "poll_all", lambda *a, **k: (0, 0))
    monkeypatch.setattr(run_scheduler, "check_overdue_all", lambda: 0)
    (file_mail["inbox"] / "s.eml").write_bytes(
        b"From: a@exchange.example\r\nTo: x@aegis.example\r\nSubject: sched\r\nMessage-ID: <" +
        uuid.uuid4().hex.encode() + b"@exchange.example>\r\n\r\nhi\r\n")
    result = run_scheduler.run_once()
    assert "mail" in result and result["mail"]["unassigned"] == 1 and "mail_error" not in result
    assert "expire_prepared" in result["mail"] or run_scheduler._load_mail_send() is None

    def boom():
        raise RuntimeError("mail down")

    monkeypatch.setattr(run_scheduler, "mail_pass", boom)
    result = run_scheduler.run_once()
    assert result["mail_error"] is True and result["overdue"] == 0 and result["alerts"] == 0
    assert run_scheduler.main(["--once"]) == 1


def test_scheduler_mail_pass_is_off_without_inbound(monkeypatch):
    from scripts import run_scheduler

    monkeypatch.setattr(run_scheduler, "_load_mail_send", lambda: None)
    assert run_scheduler.mail_pass() is None
