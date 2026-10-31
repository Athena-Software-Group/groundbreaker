"""Mail transports: settings, the none / file transports, Microsoft Graph over httpx.MockTransport.

No test reaches the network: `_no_network` makes every real httpx transport fail, and Graph is
driven through `httpx.MockTransport`. Fake credentials are low-entropy placeholders.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import stat
from urllib.parse import parse_qs

import httpx
import pytest
from conftest import REPO_ROOT, TEST_TMP

from app.core.logging import redact
from app.mail import graph as graph_mod
from app.mail.config import MailSettings, describe, mask_id
from app.mail.graph import GraphClient, GraphTransport, _jwt_roles
from app.mail.transport import (
    FileTransport,
    NoneTransport,
    TransportError,
    get_transport,
)

SECRET = "test-client-secret-not-real"
TENANT = "00000000-0000-0000-0000-000000000000"
CLIENT = "00000000-0000-0000-0000-000000000001"
MAILBOX = "case-desk@aegis.example"
RAW = (b"From: Athena <case-desk@aegis.example>\r\nTo: compliance@exchange.example\r\nSubject: [Aegis DEMO #1] x\r\n"
       b"Message-ID: <aegis.demo.1.abc@aegis.example>\r\n\r\nHello\r\n")
MID = "<aegis.demo.1.abc@aegis.example>"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def refuse(self, request):
        raise AssertionError(f"a test tried to reach the network: {request.url.host}")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", refuse)
    graph_mod.clear_token_cache()
    yield
    graph_mod.clear_token_cache()


def settings(**kw) -> MailSettings:
    base = {"aegis_mail_transport": "graph", "aegis_mail_from": MAILBOX, "aegis_m365_tenant_id": TENANT,
            "aegis_m365_client_id": CLIENT, "aegis_m365_client_secret": SECRET}
    base.update(kw)
    return MailSettings(_env_file=None, **base)


def fake_jwt(roles) -> str:
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{seg({'alg': 'none', 'typ': 'JWT'})}.{seg({'roles': roles, 'aud': 'https://graph.microsoft.com'})}.sig"


class FakeGraph:
    """A scripted Graph + identity platform. `queue[(method, suffix)]` holds responses to hand out in
    order (the last one repeats); every request is recorded."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.queue: dict[tuple[str, str], list] = {}
        self.token = fake_jwt(["Mail.ReadWrite", "Mail.Send"])
        self.draft = {"id": "AAMk-immutable-1=", "internetMessageId": MID, "conversationId": "conv-1",
                      "isDraft": True}

    def on(self, method: str, suffix: str, *responses):
        self.queue[(method, suffix)] = list(responses)

    def _pop(self, method, path):
        for (m, suffix), items in self.queue.items():
            if m == method and path.endswith(suffix) and items:
                return items.pop(0) if len(items) > 1 else items[0]
        return None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        scripted = self._pop(request.method, path)
        if isinstance(scripted, Exception):
            raise scripted
        if isinstance(scripted, httpx.Response):
            return scripted
        if path.endswith("/oauth2/v2.0/token"):
            return httpx.Response(200, json={"access_token": self.token, "expires_in": 3599, "token_type": "Bearer"})
        if request.method == "POST" and path.endswith("/messages"):
            return httpx.Response(201, json=self.draft)
        if request.method == "POST" and path.endswith("/send"):
            return httpx.Response(202)
        if request.method == "GET" and "/messages/" in path:
            return httpx.Response(200, json={**self.draft, "isDraft": False, "sentDateTime": "2026-10-19T10:00:00Z"})
        return httpx.Response(404, json={"error": {"code": "ResourceNotFound", "message": "nope"}})

    def calls(self, method: str, suffix: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and r.url.path.endswith(suffix)]


@pytest.fixture
def fake():
    return FakeGraph()


def make_transport(fake, *, sleeps=None, **kw) -> GraphTransport:
    sleeps = sleeps if sleeps is not None else []
    client = httpx.Client(transport=httpx.MockTransport(fake))
    return GraphTransport(settings(**kw), client=client, sleep=sleeps.append)


# --------------------------------------------------------------------------- settings
def test_settings_parsing(monkeypatch):
    monkeypatch.setenv("AEGIS_MAIL_TRANSPORT", "FILE")
    monkeypatch.setenv("AEGIS_MAIL_INBOUND", "on")
    monkeypatch.setenv("AEGIS_MAIL_FROM", " Case-Desk@Aegis.Example ")
    monkeypatch.setenv("AEGIS_MAIL_DEV_ALLOWED_DOMAINS", "example.com, @Example.org ,")
    s = MailSettings(_env_file=None)
    assert s.aegis_mail_transport == "file" and s.aegis_mail_inbound is True
    assert s.mail_from == "case-desk@aegis.example" and s.mail_domain == "aegis.example"
    assert s.dev_allowed_domains == {"example.com", "example.org"}
    assert s.max_message_bytes == 2_900_000 and s.from_name == "Athena Software Group, Inc."
    monkeypatch.setenv("AEGIS_MAIL_INBOUND", "off")
    assert MailSettings(_env_file=None).aegis_mail_inbound is False


@pytest.mark.parametrize("field, value", [
    ("aegis_m365_graph_base", "https://graph.evil.example/v1.0"),
    ("aegis_m365_graph_base", "http://graph.microsoft.com/v1.0"),
    ("aegis_m365_login_host", "https://login.evil.example"),
    ("aegis_m365_login_host", "https://user:pw" + "@login.microsoftonline.com"),
])
def test_host_allow_list(field, value):
    s = settings(**{field: value})
    assert s.host_problem and "host not allowed" in s.host_problem
    st = GraphTransport(s).status()
    assert not st.configured and "host not allowed" in st.reason


def test_graph_status_needs_every_setting_and_no_cert():
    assert GraphTransport(settings()).status().configured
    st = GraphTransport(settings(aegis_m365_client_secret="")).status()
    assert not st.configured and "AEGIS_M365_CLIENT_SECRET" in st.reason
    st = GraphTransport(settings(aegis_m365_client_cert_path="/abs/cert.pem")).status()
    assert not st.configured and "cryptography" in st.reason


def test_get_transport_per_setting():
    assert isinstance(get_transport(settings(aegis_mail_transport="none")), NoneTransport)
    assert isinstance(get_transport(settings(aegis_mail_transport="file")), FileTransport)
    assert isinstance(get_transport(settings()), GraphTransport)
    assert isinstance(get_transport(), NoneTransport)  # conftest pops every AEGIS_MAIL_* variable


def test_describe_never_shows_the_secret():
    info = describe(settings())
    assert SECRET not in json.dumps(info, default=str)
    assert info["secret_configured"] is True and info["tenant"] == "0000…0000" and info["client"] == "0000…0001"
    assert mask_id("") == "—"


def test_none_transport_raises_disabled():
    t = NoneTransport(settings(aegis_mail_transport="none"))
    st = t.status()
    assert not st.configured and st.reason == "Sending is disabled (AEGIS_MAIL_TRANSPORT=none)"
    for call in (lambda: t.send_mime(RAW, message_id=MID), lambda: t.lookup_sent(message_id=MID, provider_message_id=None)):
        with pytest.raises(TransportError) as e:
            call()
        assert e.value.reason == "disabled"


# --------------------------------------------------------------------------- file transport
def test_file_transport_writes_0600_eml(tmp_path):
    outbox = tmp_path / "outbox"
    t = FileTransport(settings(aegis_mail_transport="file", aegis_mail_outbox_dir=str(outbox)))
    assert t.status().configured
    res = t.send_mime(RAW, message_id=MID)
    assert res.transport == "file" and res.internet_message_id == MID and res.provider_message_id.startswith("file:")
    files = list(outbox.glob("*.eml"))
    assert len(files) == 1 and files[0].read_bytes() == RAW
    assert stat.S_IMODE(os.stat(files[0]).st_mode) == 0o600
    assert files[0].name.endswith(".eml") and files[0].name.split("_")[1][:12] == res.provider_message_id[-16:-4]
    assert t.lookup_sent(message_id=MID, provider_message_id=res.provider_message_id).state == "sent"
    assert t.lookup_sent(message_id=MID, provider_message_id=None).state == "sent"  # found by Message-ID header
    assert t.lookup_sent(message_id="<other@x>", provider_message_id="file:nope.eml").state == "missing"
    assert not hasattr(t, "resend_draft")  # no manual resend after an uncertain send: reconcile only


@pytest.mark.parametrize("where", ["relative", "repo", "vault"])
def test_file_transport_refuses_bad_outbox(where, tmp_path, monkeypatch):
    vault = tmp_path / "vault"
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(vault))
    path = {"relative": "outbox", "repo": str(REPO_ROOT / "outbox"), "vault": str(vault / "outbox")}[where]
    t = FileTransport(settings(aegis_mail_transport="file", aegis_mail_outbox_dir=path))
    assert not t.status().configured
    with pytest.raises(TransportError) as e:
        t.send_mime(RAW, message_id=MID)
    assert e.value.reason == "not_configured"
    assert not (REPO_ROOT / "outbox").exists()


def test_file_transport_needs_a_sender(tmp_path):
    t = FileTransport(settings(aegis_mail_transport="file", aegis_mail_from="", aegis_mail_outbox_dir=str(tmp_path)))
    st = t.status()
    assert not st.configured and "AEGIS_MAIL_FROM" in st.reason


def test_file_inbound_reads_and_moves(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "a.eml").write_bytes(RAW)
    (inbox / "notes.txt").write_bytes(b"ignored")
    os.symlink(inbox / "a.eml", inbox / "link.eml")
    t = FileTransport(settings(aegis_mail_transport="file", aegis_mail_inbox_dir=str(inbox)))
    items = list(t.fetch_inbound(None))
    assert [i.provider_id for i in items] == ["file:a.eml"]  # no symlinks, only *.eml
    assert items[0].load() == RAW
    t.ack(items[0])
    assert not (inbox / "a.eml").exists() and (inbox / "processed" / "a.eml").read_bytes() == RAW


# --------------------------------------------------------------------------- graph
def test_token_request_and_cache(fake):
    t = make_transport(fake)
    t.send_mime(RAW, message_id=MID)
    t.send_mime(RAW, message_id=MID)
    tokens = fake.calls("POST", "/oauth2/v2.0/token")
    assert len(tokens) == 1  # cached in-process
    req = tokens[0]
    assert req.url.host == "login.microsoftonline.com" and f"/{TENANT}/oauth2/v2.0/token" in req.url.path
    form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
    assert form == {"client_id": CLIENT, "client_secret": SECRET, "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials"}
    graph_calls = [r for r in fake.requests if r.url.host == "graph.microsoft.com"]
    assert all(r.headers["Authorization"] == f"Bearer {fake.token}" for r in graph_calls)


def test_create_draft_then_send(fake):
    sleeps: list[float] = []
    t = make_transport(fake, sleeps=sleeps)
    res = t.send_mime(RAW, message_id=MID)
    create = fake.calls("POST", f"/users/{MAILBOX}/messages")[0]
    assert create.url.path == f"/v1.0/users/{MAILBOX}/messages"
    assert create.headers["Content-Type"] == "text/plain"
    assert create.headers["Prefer"] == 'IdType="ImmutableId"'
    assert base64.b64decode(create.content) == RAW
    send = fake.calls("POST", "/send")
    assert len(send) == 1 and "/messages/AAMk-immutable-1=/send" in send[0].url.path
    assert res.transport == "graph" and res.provider_message_id == "AAMk-immutable-1="
    assert res.internet_message_id == MID and res.conversation_id == "conv-1" and res.sent_at is not None
    assert not res.detail.get("ids_pending") and sleeps == []


def test_429_waits_for_retry_after(fake):
    sleeps: list[float] = []
    fake.on("POST", "/messages", httpx.Response(429, headers={"Retry-After": "3"}), httpx.Response(201, json=fake.draft))
    res = make_transport(fake, sleeps=sleeps).send_mime(RAW, message_id=MID)
    assert sleeps == [3.0] and res.provider_message_id == fake.draft["id"]
    assert len(fake.calls("POST", f"/users/{MAILBOX}/messages")) == 2


def test_429_retry_after_is_capped(fake):
    sleeps: list[float] = []
    fake.on("POST", "/messages", httpx.Response(429, headers={"Retry-After": "600"}), httpx.Response(201, json=fake.draft))
    make_transport(fake, sleeps=sleeps).send_mime(RAW, message_id=MID)
    assert sleeps == [60.0]


def test_503_is_retried_then_server_error(fake):
    sleeps: list[float] = []
    fake.on("POST", "/messages", httpx.Response(503), httpx.Response(201, json=fake.draft))
    make_transport(fake, sleeps=sleeps).send_mime(RAW, message_id=MID)
    assert len(sleeps) == 1 and 1.0 <= sleeps[0] <= 1.5
    fake2 = FakeGraph()
    fake2.on("POST", "/messages", httpx.Response(503))
    fake2.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": []}))  # no draft listed (yet)
    sleeps2: list[float] = []
    with pytest.raises(TransportError) as e:
        make_transport(fake2, sleeps=sleeps2).send_mime(RAW, message_id=MID)
    assert len(fake2.calls("POST", f"/users/{MAILBOX}/messages")) == 4 and len(sleeps2) == 3
    # Graph answered: an attempt may have stored a draft it does not list yet, so the empty listing
    # proves nothing and the outcome is unknown (reconcile checks again after MISSING_GRACE)
    assert e.value.outcome_unknown and e.value.reason == "unknown_outcome" and e.value.provider_message_id is None
    assert "Graph server error (503)" in str(e.value) and "created late" in str(e.value)


def test_401_refreshes_the_token_once(fake):
    fake.on("POST", "/messages", httpx.Response(401), httpx.Response(201, json=fake.draft))
    make_transport(fake).send_mime(RAW, message_id=MID)
    assert len(fake.calls("POST", "/oauth2/v2.0/token")) == 2
    graph_mod.clear_token_cache()
    fake2 = FakeGraph()
    fake2.on("POST", "/messages", httpx.Response(401))
    with pytest.raises(TransportError) as e:
        make_transport(fake2).send_mime(RAW, message_id=MID)
    assert e.value.reason == "auth" and len(fake2.calls("POST", "/oauth2/v2.0/token")) == 2


def test_403_maps_to_the_permissions_message(fake):
    fake.on("POST", "/messages", httpx.Response(403, json={"error": {"code": "ErrorAccessDenied", "message": "denied"}}))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID)
    assert e.value.reason == "forbidden"
    assert "Mail.Send / Mail.ReadWrite" in str(e.value) and "application access policy" in str(e.value)


@pytest.mark.parametrize("status, code, reason", [
    (400, "ErrorInvalidMimeContent", "invalid"), (404, "ErrorInvalidUser", "mailbox_not_found"),
    (413, None, "too_large"),
])
def test_error_mapping(fake, status, code, reason):
    body = {"error": {"code": code, "message": "x" * 1000}} if code else {}
    fake.on("POST", "/messages", httpx.Response(status, json=body))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID)
    assert e.value.reason == reason and len(str(e.value)) < 512
    if reason == "mailbox_not_found":
        assert "AEGIS_MAIL_FROM" in str(e.value)


def test_read_timeout_on_send_is_an_unknown_outcome(fake):
    fake.on("POST", "/send", httpx.ReadTimeout("timed out"))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID)
    assert e.value.outcome_unknown and e.value.reason == "unknown_outcome"
    assert e.value.provider_message_id == fake.draft["id"]
    assert len(fake.calls("POST", "/send")) == 1  # never retried


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_5xx_on_send_is_an_unknown_outcome_never_retried(fake, status):
    """A gateway 5xx on /send does not mean nothing was sent: a retry would get 404 (the draft moved
    to Sent Items), be taken for a plain failure and lead to a second letter."""
    sleeps: list[float] = []
    fake.on("POST", "/send", httpx.Response(status),
            httpx.Response(404, json={"error": {"code": "ErrorItemNotFound", "message": "gone"}}))
    with pytest.raises(TransportError) as e:
        make_transport(fake, sleeps=sleeps).send_mime(RAW, message_id=MID)
    assert e.value.reason == "unknown_outcome" and e.value.outcome_unknown is True
    assert e.value.provider_message_id == fake.draft["id"]
    assert len(fake.calls("POST", "/send")) == 1 and sleeps == []


def test_404_on_a_retried_send_is_an_unknown_outcome(fake):
    fake.on("POST", "/send", httpx.Response(429, headers={"Retry-After": "1"}),
            httpx.Response(404, json={"error": {"code": "ErrorItemNotFound", "message": "gone"}}))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID)
    assert e.value.outcome_unknown and e.value.reason == "unknown_outcome"
    assert len(fake.calls("POST", "/send")) == 2


def test_429_on_send_is_retried(fake):
    sleeps: list[float] = []
    fake.on("POST", "/send", httpx.Response(429, headers={"Retry-After": "2"}), httpx.Response(202))
    res = make_transport(fake, sleeps=sleeps).send_mime(RAW, message_id=MID)
    assert res.provider_message_id == fake.draft["id"] and sleeps == [2.0]
    assert len(fake.calls("POST", "/send")) == 2


def test_read_timeout_on_create_is_retried(fake):
    sleeps: list[float] = []
    fake.on("POST", "/messages", httpx.ReadTimeout("timed out"), httpx.Response(201, json=fake.draft))
    res = make_transport(fake, sleeps=sleeps).send_mime(RAW, message_id=MID)
    assert res.provider_message_id == fake.draft["id"] and len(sleeps) == 1


def test_connect_error_is_retried_then_network(fake):
    fake.on("POST", "/messages", httpx.ConnectError("refused"))
    fake.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": []}))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID)
    assert e.value.reason == "network" and len(fake.calls("POST", f"/users/{MAILBOX}/messages")) == 4
    # no attempt reached Graph, so the empty listing is proof: a plain failure, not an unknown outcome
    assert not e.value.outcome_unknown and "no draft was left" in str(e.value)


# --------------------------------------------------------------------------- no unsent draft left behind
NOT_FOUND = {"error": {"code": "ErrorItemNotFound", "message": "gone"}}


def test_a_create_that_timed_out_and_failed_deletes_the_draft_it_may_have_left(fake):
    """A timed-out create may have stored a draft before the final failure: it is found by our
    Message-ID and deleted before the e-mail is reported failed."""
    stray = {**fake.draft, "id": "AAMk-stray-2="}
    fake.on("POST", "/messages", httpx.ReadTimeout("timed out"))
    fake.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": [stray]}),
            httpx.Response(200, json={"value": []}))
    fake.on("POST", "/messages/AAMk-stray-2=/permanentDelete", httpx.Response(204))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID)
    assert e.value.reason == "network" and not e.value.outcome_unknown
    assert "draft was removed" in str(e.value)
    assert len(fake.calls("POST", "/messages/AAMk-stray-2=/permanentDelete")) == 1 and not fake.calls("POST", "/send")


def test_a_failed_draft_cleanup_turns_the_failure_into_an_unknown_outcome(fake):
    fake.on("POST", "/messages", httpx.Response(503))
    fake.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(403, json={"error": {"code": "ErrorAccessDenied"}}))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID)
    assert e.value.outcome_unknown and e.value.reason == "unknown_outcome"
    assert "could not confirm that the unsent draft was removed" in str(e.value)


def test_a_refused_send_deletes_the_draft(fake):
    fake.on("POST", "/send", httpx.Response(403, json={"error": {"code": "ErrorAccessDenied", "message": "no"}}))
    fake.on("GET", "/messages/AAMk-immutable-1=", httpx.Response(200, json=fake.draft))  # still a draft
    fake.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": [fake.draft]}),
            httpx.Response(200, json={"value": []}))
    fake.on("POST", "/messages/AAMk-immutable-1=/permanentDelete", httpx.Response(204))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID)
    assert e.value.reason == "forbidden" and not e.value.outcome_unknown
    assert len(fake.calls("POST", "/messages/AAMk-immutable-1=/permanentDelete")) == 1  # once, though listed twice


def test_a_refused_send_whose_draft_cannot_be_deleted_is_an_unknown_outcome(fake):
    fake.on("POST", "/send", httpx.Response(400, json={"error": {"code": "ErrorInvalidRecipients"}}))
    fake.on("GET", "/messages/AAMk-immutable-1=", httpx.Response(200, json=fake.draft))
    fake.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": [fake.draft]}))
    fake.on("POST", "/messages/AAMk-immutable-1=/permanentDelete", httpx.Response(503))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID)
    assert e.value.outcome_unknown and e.value.reason == "unknown_outcome"
    assert e.value.provider_message_id == fake.draft["id"]


def test_delete_drafts(fake):
    t = make_transport(fake)
    # the immutable id is a draft, a second draft carries the same Message-ID: both deleted
    other = {**fake.draft, "id": "AAMk-dup-3="}
    fake.on("GET", "/messages/AAMk-immutable-1=", httpx.Response(200, json=fake.draft))
    fake.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": [fake.draft, other]}),
            httpx.Response(200, json={"value": []}))
    fake.on("POST", "/messages/AAMk-immutable-1=/permanentDelete", httpx.Response(204))
    fake.on("POST", "/messages/AAMk-dup-3=/permanentDelete", httpx.Response(404, json=NOT_FOUND))  # already gone: fine
    assert t.delete_drafts(message_id=MID, provider_message_id="AAMk-immutable-1=") == "deleted"
    deletes = [r for r in fake.requests if r.url.path.endswith("/permanentDelete")]
    assert all(r.method == "POST" for r in deletes) and not [r for r in fake.requests if r.method == "DELETE"]
    assert [r.url.path.rsplit("/", 2)[1] for r in deletes] == ["AAMk-immutable-1=", "AAMk-dup-3="]
    assert all(r.url.host == "graph.microsoft.com" and f"/users/{MAILBOX}/messages/" in r.url.path for r in deletes)
    # sent meanwhile: nothing is deleted
    fake2 = FakeGraph()
    fake2.on("GET", "/messages/AAMk-immutable-1=", httpx.Response(200, json={**fake2.draft, "isDraft": False}))
    assert make_transport(fake2).delete_drafts(message_id=MID, provider_message_id="AAMk-immutable-1=") == "sent"
    assert not [r for r in fake2.requests if r.url.path.endswith("/permanentDelete")]
    # a draft that survives the deletion: an error, never "deleted"
    fake3 = FakeGraph()
    fake3.on("GET", "/messages/AAMk-immutable-1=", httpx.Response(404, json=NOT_FOUND))
    fake3.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": [fake3.draft]}))
    fake3.on("POST", "/messages/AAMk-immutable-1=/permanentDelete", httpx.Response(204))
    with pytest.raises(TransportError):
        make_transport(fake3).delete_drafts(message_id=MID, provider_message_id="AAMk-immutable-1=")
    # a 404 for the mailbox itself is not "already gone"
    fake4 = FakeGraph()
    fake4.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": [fake4.draft]}))
    fake4.on("POST", "/messages/AAMk-immutable-1=/permanentDelete", httpx.Response(404, json={"error": {"code": "ErrorInvalidUser"}}))
    with pytest.raises(TransportError) as e:
        make_transport(fake4).delete_drafts(message_id=MID, provider_message_id=None)
    assert e.value.reason == "mailbox_not_found"


class MailboxGraph(FakeGraph):
    """A Graph whose /messages listing reflects state: DELETE /messages/{id} moves an item to Deleted
    Items (still a draft, still listed, as in Exchange), permanentDelete removes it."""

    def __init__(self, items):
        super().__init__()
        self.items = {i["id"]: dict(i) for i in items}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/oauth2/v2.0/token"):
            return super().__call__(request)
        self.requests.append(request)
        prefix = f"/v1.0/users/{MAILBOX}/messages"
        if request.method == "GET" and path == prefix:
            return httpx.Response(200, json={"value": [dict(i) for i in self.items.values()]})
        pid = path[len(prefix) + 1:].split("/", 1)[0] if path.startswith(prefix + "/") else ""
        if pid not in self.items:
            return httpx.Response(404, json=NOT_FOUND)
        if request.method == "GET":
            return httpx.Response(200, json=dict(self.items[pid]))
        if request.method == "DELETE":
            self.items[pid]["parentFolderId"] = "AAMk-deleteditems"
            return httpx.Response(204)
        if request.method == "POST" and path.endswith("/permanentDelete"):
            del self.items[pid]
            return httpx.Response(204)
        return httpx.Response(400, json={"error": {"code": "BadRequest"}})


def test_drafts_are_deleted_permanently_and_a_soft_deleted_one_is_purged_too():
    """DELETE would leave the draft in Deleted Items, where /messages still lists it as a draft, so
    the deletion could never be confirmed: drafts are removed with permanentDelete, including one an
    earlier soft delete (or a user) moved to Deleted Items."""
    draft = {"id": "AAMk-immutable-1=", "internetMessageId": MID, "isDraft": True, "parentFolderId": "AAMk-drafts"}
    binned = {**draft, "id": "AAMk-binned-4=", "parentFolderId": "AAMk-deleteditems"}
    g = MailboxGraph([draft, binned])
    assert make_transport(g).delete_drafts(message_id=MID, provider_message_id="AAMk-immutable-1=") == "deleted"
    assert g.items == {} and not [r for r in g.requests if r.method == "DELETE"]
    assert sorted(r.url.path.rsplit("/", 2)[1] for r in g.requests if r.url.path.endswith("/permanentDelete")) \
        == ["AAMk-binned-4=", "AAMk-immutable-1="]
    # a refused /send against the same mailbox: the e-mail is failed (not unknown) after one pass
    g2 = MailboxGraph([])
    t = make_transport(g2)

    def create(raw):
        g2.items[draft["id"]] = dict(draft)
        return dict(draft)

    def refuse(pid):
        raise TransportError("forbidden", "Graph answered 403: ErrorAccessDenied", status=403)

    t.graph.create_mime_draft, t.graph.send_draft = create, refuse
    with pytest.raises(TransportError) as e:
        t.send_mime(RAW, message_id=MID)
    assert e.value.reason == "forbidden" and not e.value.outcome_unknown and g2.items == {}


def test_a_draft_still_listed_in_deleted_items_is_never_reported_deleted():
    """Should a deletion only move the draft to Deleted Items (where it is still a draft), the check
    afterwards still finds it: an error (the e-mail stays unknown), never "deleted"."""
    draft = {"id": "AAMk-immutable-1=", "internetMessageId": MID, "isDraft": True, "parentFolderId": "AAMk-drafts"}
    g = MailboxGraph([draft])
    t = make_transport(g)
    t.graph.delete_message = lambda pid: g.items[pid].update(parentFolderId="AAMk-deleteditems") or True
    with pytest.raises(TransportError):
        t.delete_drafts(message_id=MID, provider_message_id=None)


def test_a_timed_out_create_with_nothing_listed_is_an_unknown_outcome(fake):
    """A create that timed out may have stored a draft Graph does not list yet: an empty listing
    proves nothing, so the e-mail is not failed (and the letter not prepared again) until
    reconcile has looked again after MISSING_GRACE."""
    fake.on("POST", "/messages", httpx.ReadTimeout("timed out"))
    fake.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": []}))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID)
    assert e.value.outcome_unknown and e.value.reason == "unknown_outcome" and e.value.provider_message_id is None
    assert "created late" in str(e.value) and not fake.calls("POST", "/send")


def test_message_headers(fake):
    fake.on("GET", "/messages/AAMk-in-9=", httpx.Response(200, json={"internetMessageHeaders": [
        {"name": "X-MS-Exchange-CrossTenant-Id", "value": TENANT}, {"name": "Received", "value": "x" * 5000}]}))
    rows = make_transport(fake).message_headers("AAMk-in-9=")
    assert rows[0] == {"name": "X-MS-Exchange-CrossTenant-Id", "value": TENANT} and len(rows[1]["value"]) == 2000
    req = fake.calls("GET", "/messages/AAMk-in-9=")[0]
    assert "internetMessageHeaders" in str(req.url)


def test_ids_pending_when_graph_has_not_moved_the_message(fake):
    sleeps: list[float] = []
    fake.on("GET", "/messages/AAMk-immutable-1=", httpx.Response(404, json={"error": {"code": "ErrorItemNotFound"}}))
    res = make_transport(fake, sleeps=sleeps).send_mime(RAW, message_id=MID)
    assert res.detail.get("ids_pending") is True and res.internet_message_id == MID
    assert sleeps == [1.0, 1.0]  # three reads, 1 s apart


def test_lookup_sent_states(fake):
    t = make_transport(fake)
    assert t.lookup_sent(message_id=MID, provider_message_id="AAMk-immutable-1=").state == "sent"
    fake.on("GET", "/messages/AAMk-immutable-1=", httpx.Response(200, json={**fake.draft, "isDraft": True}))
    assert t.lookup_sent(message_id=MID, provider_message_id="AAMk-immutable-1=").state == "draft"
    fake.on("GET", "/messages/AAMk-immutable-1=", httpx.Response(404, json={"error": {"code": "ErrorItemNotFound"}}))
    fake.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": []}))
    assert t.lookup_sent(message_id=MID, provider_message_id="AAMk-immutable-1=").state == "missing"
    # the immutable id no longer resolves, but Sent Items holds the Message-ID: sent
    fake.on("GET", "/messages/AAMk-immutable-1=", httpx.Response(404, json={"error": {"code": "ErrorItemNotFound"}}))
    fake.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": [{**fake.draft, "isDraft": False}]}))
    assert t.lookup_sent(message_id=MID, provider_message_id="AAMk-immutable-1=").state == "sent"
    assert not fake.calls("POST", "/send") and not hasattr(t, "resend_draft")
    # without an immutable id: found by internetMessageId in the mailbox
    fake.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": [{**fake.draft, "isDraft": False}]}))
    assert t.lookup_sent(message_id=MID, provider_message_id=None).state == "sent"
    query = fake.calls("GET", f"/users/{MAILBOX}/messages")[-1]
    assert "internetMessageId" in str(query.url)


def test_token_info_reads_roles_without_the_token(fake):
    info = make_transport(fake).token_info()
    assert info == {"ok": True, "expires_in": 3599, "roles": ["Mail.ReadWrite", "Mail.Send"]}
    assert _jwt_roles("not-a-jwt") == []


def test_token_errors_name_the_code_not_the_secret(fake):
    fake.on("POST", "/oauth2/v2.0/token", httpx.Response(401, json={
        "error": "invalid_client", "error_description": f"AADSTS7000215: Invalid client secret {SECRET}",
        "error_codes": [7000215]}))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID)
    assert e.value.reason == "auth" and "invalid_client" in str(e.value) and "AADSTS7000215" in str(e.value)
    assert SECRET not in str(e.value)


def test_secret_never_in_errors_or_logs(fake, caplog):
    caplog.set_level(logging.DEBUG)
    fake.on("POST", "/messages", httpx.Response(400, json={"error": {"code": "x", "message": "bad"}}))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID)
    assert SECRET not in str(e.value) and SECRET not in repr(e.value.__dict__)
    assert fake.token not in str(e.value)
    for record in caplog.records:
        assert SECRET not in record.getMessage() and fake.token not in record.getMessage()


def test_delta_pages_follow_links_and_skip_removed(fake):
    page1 = {"value": [{"id": "m1", "receivedDateTime": "2026-10-19T10:00:00Z"}, {"id": "gone", "@removed": {}}],
             "@odata.nextLink": "https://graph.microsoft.com/v1.0/users/x/mailFolders/inbox/messages/delta?$skiptoken=a"}
    page2 = {"value": [{"id": "m2"}],
             "@odata.deltaLink": "https://graph.microsoft.com/v1.0/users/x/mailFolders/inbox/messages/delta?$deltatoken=b"}
    fake.on("GET", "/messages/delta", httpx.Response(200, json=page1), httpx.Response(200, json=page2))
    client = GraphClient(settings(), client=httpx.Client(transport=httpx.MockTransport(fake)), sleep=lambda s: None)
    messages, delta = client.delta(None)
    assert [m["id"] for m in messages] == ["m1", "m2"] and delta.endswith("deltatoken=b")
    first = fake.calls("GET", "/messages/delta")[0]
    assert "odata.maxpagesize=50" in first.headers["Prefer"] and 'IdType="ImmutableId"' in first.headers["Prefer"]
    assert "$select=" in str(first.url)


def test_delta_refuses_links_to_other_hosts(fake):
    fake.on("GET", "/messages/delta", httpx.Response(200, json={"value": [], "@odata.nextLink": "https://evil.example/x"}))
    client = GraphClient(settings(), client=httpx.Client(transport=httpx.MockTransport(fake)), sleep=lambda s: None)
    with pytest.raises(TransportError) as e:
        client.delta(None)
    assert e.value.reason == "invalid"


def test_get_mime_is_capped(fake):
    fake.on("GET", "/$value", httpx.Response(200, content=b"x" * 5000))
    client = GraphClient(settings(aegis_mail_max_inbound_bytes=1000),
                         client=httpx.Client(transport=httpx.MockTransport(fake)), sleep=lambda s: None)
    with pytest.raises(TransportError) as e:
        client.get_mime("m1")
    assert e.value.reason == "too_large"
    fake.on("GET", "/$value", httpx.Response(200, content=RAW))
    assert GraphClient(settings(), client=httpx.Client(transport=httpx.MockTransport(fake))).get_mime("m1") == RAW


# --------------------------------------------------------------------------- log redaction
@pytest.mark.parametrize("text, leaked", [
    (f"client_id=abc&client_secret={SECRET}&scope=x", SECRET),
    ("client_assertion=eyJabc.def.ghi&x=1", "eyJabc"),
    ("grant_type=refresh_token&refresh_token=0.ARsecretvalue", "0.ARsecretvalue"),
    ("access_token=opaque-token-value", "opaque-token-value"),
    ('{"token_type": "Bearer", "access_token" : "opaque-json-token"}', "opaque-json-token"),
])
def test_redaction_patterns(text, leaked):
    assert leaked not in redact(text)


def test_redaction_masks_jwt_shapes():
    token = fake_jwt(["Mail.Send"])
    out = redact(f"token was {token} end")
    assert token not in out and "eyJ***" in out and out.endswith(" end")


def test_test_tmp_is_outside_the_repo():
    assert not TEST_TMP.is_relative_to(REPO_ROOT)


# --------------------------------------------------------------------------- Bcc (the e-mail editor)
def test_bcc_goes_on_the_draft_as_bcc_recipients_never_in_the_mime(fake):
    """Graph's MIME docs say nothing about a Bcc header: the MIME carries none, the hidden recipients are set on
    the draft (PATCH bccRecipients, JSON), checked, and only then is the draft sent."""
    bcc = ["audit@athena.example", "Second@Athena.example"]
    echoed = {**fake.draft, "bccRecipients": [{"emailAddress": {"address": a}} for a in bcc]}
    fake.on("PATCH", "/messages/AAMk-immutable-1=", httpx.Response(200, json=echoed))
    res = make_transport(fake).send_mime(RAW, message_id=MID, bcc=bcc)
    assert res.internet_message_id == MID
    order = [(r.method, r.url.path.rsplit("/", 1)[-1]) for r in fake.requests if "/oauth2/" not in r.url.path]
    assert order[:3] == [("POST", "messages"), ("PATCH", "AAMk-immutable-1="), ("POST", "send")]
    created = base64.b64decode(fake.calls("POST", f"/users/{MAILBOX}/messages")[0].content)
    assert created == RAW and b"bcc" not in created.lower() and b"audit@athena.example" not in created
    patch = fake.calls("PATCH", "/messages/AAMk-immutable-1=")[0]
    assert patch.headers["Content-Type"] == "application/json"
    assert json.loads(patch.content) == {"bccRecipients": [{"emailAddress": {"address": a}} for a in bcc]}


def test_without_bcc_nothing_is_patched(fake):
    make_transport(fake).send_mime(RAW, message_id=MID)
    assert not fake.calls("PATCH", "/messages/AAMk-immutable-1=")


@pytest.mark.parametrize("answer", [
    httpx.Response(200, json={"id": "AAMk-immutable-1=", "isDraft": True, "bccRecipients": []}),  # not kept
    httpx.Response(400, json={"error": {"code": "ErrorInvalidRecipients", "message": "no"}}),
])
def test_bcc_not_kept_deletes_the_draft_and_sends_nothing(fake, answer):
    fake.on("PATCH", "/messages/AAMk-immutable-1=", answer)
    fake.on("GET", "/messages/AAMk-immutable-1=", httpx.Response(200, json=fake.draft))  # still a draft
    fake.on("GET", f"/users/{MAILBOX}/messages", httpx.Response(200, json={"value": [fake.draft]}),
            httpx.Response(200, json={"value": []}))
    fake.on("POST", "/messages/AAMk-immutable-1=/permanentDelete", httpx.Response(204))
    with pytest.raises(TransportError) as e:
        make_transport(fake).send_mime(RAW, message_id=MID, bcc=["audit@athena.example"])
    assert not e.value.outcome_unknown and not fake.calls("POST", "/send")
    assert len(fake.calls("POST", "/messages/AAMk-immutable-1=/permanentDelete")) == 1


def test_file_transport_keeps_bcc_beside_the_message(tmp_path):
    outbox = tmp_path / "outbox"
    t = FileTransport(settings(aegis_mail_transport="file", aegis_mail_outbox_dir=str(outbox)))
    res = t.send_mime(RAW, message_id=MID, bcc=["audit@athena.example"])
    name = res.detail["file"]
    assert (outbox / name).read_bytes() == RAW
    assert (outbox / f"{name}.bcc").read_text() == "audit@athena.example\n"
    assert stat.S_IMODE(os.stat(outbox / f"{name}.bcc").st_mode) == 0o600
    assert t.lookup_sent(message_id=MID, provider_message_id=res.provider_message_id).state == "sent"


def test_file_transport_writes_the_bcc_before_the_message(tmp_path, monkeypatch):
    """The .bcc goes first: when it cannot be written, no .eml is left that lookup_sent would report as sent."""
    outbox = tmp_path / "outbox"
    t = FileTransport(settings(aegis_mail_transport="file", aegis_mail_outbox_dir=str(outbox)))
    real_open = os.open

    def refuse_bcc(path, *a, **k):
        if str(path).endswith(".bcc"):
            raise PermissionError("read-only")
        return real_open(path, *a, **k)

    monkeypatch.setattr(os, "open", refuse_bcc)
    with pytest.raises(TransportError):
        t.send_mime(RAW, message_id=MID, bcc=["audit@athena.example"])
    assert not list(outbox.glob("*.eml"))
    assert t.lookup_sent(message_id=MID, provider_message_id=None).state == "missing"


def test_bcc_echo_accepts_an_in_tenant_alias_resolved_to_its_primary_address(fake):
    """Exchange may answer a Bcc to an alias of a mailbox in the tenant with its primary address: accepted when the
    echoed and the asked-for addresses are both on the case mailbox's own domain and the count matches; any other
    replacement is refused."""
    from app.mail.graph import bcc_echo_problem

    own = MAILBOX.rpartition("@")[2]
    assert bcc_echo_problem(["a@x.example"], {"a@x.example"}, own) is None
    assert bcc_echo_problem([f"alias@{own}"], {f"primary@{own}"}, own) is None
    # an outside Bcc dropped while an in-tenant address is echoed: the record would name someone who never gets it
    assert bcc_echo_problem(["person@external.example"], {f"someone@{own}"}, own)
    assert bcc_echo_problem(["alias@other-tenant.example"], {f"primary@{own}"}, own)
    assert "kept 0" in bcc_echo_problem(["a@x.example"], {"b@x.example"}, own)
    assert bcc_echo_problem(["a@x.example", "b@x.example"], {"a@x.example"}, own)  # one dropped
    assert bcc_echo_problem(["a@x.example"], {"a@x.example", f"c@{own}"}, own)  # one added
    assert bcc_echo_problem([f"alias@{own}"], {f"primary@{own}"}, None)  # no own domain known: exact only
    fake.on("PATCH", "/messages/AAMk-immutable-1=", httpx.Response(200, json={
        **fake.draft, "bccRecipients": [{"emailAddress": {"address": f"primary@{own}"}}]}))
    res = make_transport(fake).send_mime(RAW, message_id=MID, bcc=[f"alias@{own}"])
    assert res.internet_message_id == MID and len(fake.calls("POST", "/send")) == 1
