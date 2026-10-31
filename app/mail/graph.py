"""Microsoft 365 through Microsoft Graph: client-credentials token, MIME draft + send, folder delta.

    client = GraphClient(settings)                      # tests: client=httpx.Client(transport=MockTransport(h))
    draft  = client.create_mime_draft(raw)              # POST /users/{mbx}/messages (text/plain, base64 MIME) -> 201
    client.set_bcc(draft["id"], ["a@b.example"])        # PATCH /users/{mbx}/messages/{id} {bccRecipients} -> 200
    client.send_draft(draft["id"])                      # POST /users/{mbx}/messages/{id}/send -> 202
    client.get_message(id)                              # isDraft, internetMessageId, conversationId, sentDateTime
    client.delta(link_or_none)                          # inbox delta pages -> (messages, delta_link)
    client.delta_pages(link, folder="sentitems", since=dt)   # Inbox / Sent Items delta, paged (mailbox sync)
    client.get_mime(id)                                 # GET /users/{mbx}/messages/{id}/$value (streamed, capped)
    client.get_headers(id)                              # internetMessageHeaders (inbound bounces)
    client.delete_message(id)                           # POST /users/{mbx}/messages/{id}/permanentDelete (stale drafts)

Why a draft and then send (D2): the bytes Graph stores are exactly the MIME bytes Aegis built and
files as evidence; the ids (immutable id, internetMessageId, conversationId) are known before the
send; and after a timeout on /send an immutable id lets `lookup_sent` tell "sent" (isDraft=false)
from "still a draft" (no immutable id, or a 404: the Message-ID is looked up instead, Sent Items
included); mail_send then marks the e-mail sent, or failed once its grace period has passed (never
a manual resend). A timeout while *creating* the draft is retried: at worst a duplicate draft
is left in Drafts, which sends nothing; a send that ends `failed` deletes every draft with our
Message-ID first (`GraphTransport.delete_drafts`; when that cannot be confirmed the outcome is
reported unknown instead, as it is when a create that may have reached Graph failed and the
listing shows no draft yet), and reconcile deletes a stale unsent draft before it marks the e-mail
failed, so a letter is never prepared again while a Graph draft of it may still exist. Drafts are
deleted with permanentDelete (a DELETE leaves them, still drafts, in Deleted Items).

**Bcc.** Microsoft's MIME documentation (Send Outlook messages in MIME format; user: sendMail;
user: Create message) does not say what becomes of a `Bcc:` header in uploaded MIME, so Aegis does not
rely on it: the MIME never carries one. Hidden recipients are set on the draft through the documented
`bccRecipients` property (`PATCH /messages/{id}`, JSON; recipients are updatable while isDraft is
true) and the answer is checked before /send: when Graph does not echo exactly those addresses, or
the PATCH fails, the draft is deleted and nothing is sent (one exception, `bcc_echo_problem`: an address
echoed in place of a requested one, both on the case mailbox's own domain, as Exchange answers an alias
of a mailbox in the tenant with its primary address). Exchange delivers `bccRecipients` without
a Bcc header in what the recipients get; the mailbox's Sent Items copy lists them.

Permissions: Mail.Send + Mail.ReadWrite (application), restricted to the one shared case mailbox by
an Exchange Application Access Policy (docs/m365-setup.md).

**Mailbox sync** (app.mail.ingest): `GraphTransport.fetch_folder(folder, state)` reads the well-known
folders `inbox` and `sentitems` with a delta query (`GET /users/{mbx}/mailFolders/{folder}/messages/delta`,
`Prefer: odata.maxpagesize=50, IdType="ImmutableId"`), following @odata.nextLink pages (on the Graph host
only) to the @odata.deltaLink, which the caller stores per folder once the whole batch went through. The
first request of a folder (no delta link yet: the initial backfill, or "Backfill since <date>") carries
`$filter=receivedDateTime ge <since>`: the delta function filters on receivedDateTime only, for Sent Items
too (a sent item's receivedDateTime is its submission time), and the caller re-checks `sentDateTime` for Sent
Items. The returned deltaLink keeps the filter. Only metadata comes with the delta pages (ids, subject,
From / To / Cc, dates); the raw MIME (`$value`, capped at AEGIS_MAIL_MAX_INBOUND_BYTES) is downloaded per
message when the caller asks for it, and kept in memory unless the message is case-related
(docs/data-handling.md §6.4).

Retries: at most 4 attempts and a 90 s budget per call; 429 waits for Retry-After (seconds or an
HTTP date, capped at 60 s); 500/502/503/504 back off 1, 2, 4 s plus up to 0.5 s jitter; connection
errors are retried (nothing was sent). On **/send** only a 429 (not processed) and a failed connect
are retried: a 5xx (a gateway 502 / 504 does not mean the message stayed unsent), a read timeout
or a dropped connection is an **unknown outcome**, never retried, and the caller reconciles from the
draft's isDraft state. A 401 drops the cached token and retries once.

The token is cached in-process per (login host, tenant, client) until 5 minutes before it expires.
It is never logged, stored or shown; error messages come only from the HTTP status and Graph's
error code / message, never from request headers or bodies.
"""

from __future__ import annotations

import base64
import json
import random
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import quote

import httpx

from app.core.logging import redact
from app.mail.config import MailSettings, mail_settings
from app.mail.transport import (
    InboundBatch,
    InboundItem,
    LookupResult,
    SendResult,
    TransportError,
    TransportStatus,
)

SCOPE = "https://graph.microsoft.com/.default"
PREFER_IMMUTABLE = 'IdType="ImmutableId"'
MAX_ATTEMPTS = 4
BUDGET_S = 90.0
RETRY_AFTER_CAP_S = 60.0
TOKEN_SLACK_S = 300
RETRY_STATUSES = {500, 502, 503, 504}
MESSAGE_SELECT = "id,internetMessageId,conversationId,isDraft,sentDateTime,parentFolderId"
DELTA_SELECT = "id,internetMessageId,conversationId,subject,from,receivedDateTime,hasAttachments,isDraft"
FOLDER_DELTA_SELECT = ("id,internetMessageId,conversationId,subject,from,toRecipients,ccRecipients,receivedDateTime,"
                       "sentDateTime,hasAttachments,isDraft")
FOLDERS = ("inbox", "sentitems")  # the well-known folders the mailbox sync reads
FORBIDDEN_TEXT = ("Graph refused the request (403): check Mail.Send / Mail.ReadWrite application permissions, "
                  "admin consent and the Exchange application access policy for this mailbox")
MAILBOX_CODES = {"ErrorInvalidUser", "MailboxNotEnabledForRESTAPI", "MailboxNotFound", "ErrorNonExistentMailbox",
                 "ResourceNotFound", "Request_ResourceNotFound"}

# (login base, tenant, client id) -> (access token, expires at [epoch s])
_TOKEN_CACHE: dict[tuple[str, str, str], tuple[str, float]] = {}
_TOKEN_LOCK = threading.Lock()


def clear_token_cache() -> None:
    with _TOKEN_LOCK:
        _TOKEN_CACHE.clear()


def _jwt_roles(token: str) -> list[str]:
    """The `roles` claim of a JWT access token, read by base64 decoding only (no verification)."""
    parts = token.split(".")
    if len(parts) < 2:
        return []
    seg = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(seg.encode("ascii")))
    except (ValueError, UnicodeError):
        return []
    roles = payload.get("roles") if isinstance(payload, dict) else None
    return sorted(str(r)[:64] for r in roles)[:50] if isinstance(roles, list) else []


def _graph_error(resp: httpx.Response) -> tuple[str, str]:
    """(code, message) from a Graph error body; message truncated and redacted."""
    try:
        err = resp.json().get("error") or {}
    except (ValueError, AttributeError):
        return "", ""
    if not isinstance(err, dict):
        return "", ""
    code = str(err.get("code") or "")[:64]
    message = redact(str(err.get("message") or "").replace("\r", " ").replace("\n", " "))[:300]
    return code, message


def _parse_dt(value) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class GraphClient:
    def __init__(self, settings: MailSettings | None = None, *, client: httpx.Client | None = None,
                 sleep: Callable[[float], None] = time.sleep, now: Callable[[], float] = time.time,
                 jitter: Callable[[], float] | None = None):
        self.settings = settings or mail_settings()
        self._client = client
        self._own_client = client is None
        self.sleep = sleep
        self.now = now
        self.jitter = jitter or (lambda: random.uniform(0.0, 0.5))
        self.mailbox = self.settings.mail_from

    # ------------------------------------------------------------------ plumbing
    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.settings.aegis_mail_timeout, follow_redirects=False)
        return self._client

    def close(self) -> None:
        if self._own_client and self._client is not None:
            self._client.close()
            self._client = None

    def _cache_key(self) -> tuple[str, str, str]:
        s = self.settings
        return (s.login_base, s.aegis_m365_tenant_id.strip(), s.aegis_m365_client_id.strip())

    def _user_url(self, suffix: str) -> str:
        if not self.mailbox:
            raise TransportError("not_configured", "AEGIS_MAIL_FROM is not set")
        return f"{self.settings.graph_base}/users/{quote(self.mailbox, safe='@')}{suffix}"

    @staticmethod
    def _id(message_id: str) -> str:
        if not message_id or any(c in message_id for c in "\r\n\x00/?#"):
            raise TransportError("invalid", "invalid Graph message id")
        return quote(message_id, safe="=-_")

    def _check_graph_url(self, url: str) -> str:
        """nextLink / deltaLink must stay on the Graph host (never follow a link elsewhere)."""
        if not self.settings.graph_link_allowed(url):
            raise TransportError("invalid", "Graph returned a link to another host; refusing to follow it")
        return url

    # ------------------------------------------------------------------ token
    def token(self, *, force: bool = False) -> str:
        key = self._cache_key()
        with _TOKEN_LOCK:
            cached = _TOKEN_CACHE.get(key)
            if cached and not force and cached[1] > self.now():
                return cached[0]
            _TOKEN_CACHE.pop(key, None)
        problem = self.settings.graph_problem()
        if problem:
            raise TransportError("not_configured", problem)
        s = self.settings
        url = f"{s.login_base}/{quote(s.aegis_m365_tenant_id.strip(), safe='')}/oauth2/v2.0/token"
        form = {"client_id": s.aegis_m365_client_id.strip(),
                "client_secret": s.aegis_m365_client_secret.get_secret_value(),
                "scope": SCOPE, "grant_type": "client_credentials"}
        resp = self._send_retrying(lambda: self.client.build_request("POST", url, data=form), op="token")
        if resp.status_code != 200:
            raise self._error(resp) if resp.status_code == 429 or resp.status_code >= 500 else self._token_error(resp)
        try:
            body = resp.json()
            access = str(body["access_token"])
            expires_in = int(body.get("expires_in") or 3599)
        except (ValueError, KeyError, TypeError):
            raise TransportError("auth", "the token endpoint returned an unexpected response") from None
        with _TOKEN_LOCK:
            _TOKEN_CACHE[key] = (access, self.now() + max(0, expires_in - TOKEN_SLACK_S))
        self._last_expires_in = expires_in
        return access

    @staticmethod
    def _token_error(resp: httpx.Response) -> TransportError:
        code, aadsts = "", ""
        try:
            body = resp.json()
            code = str(body.get("error") or "")[:64]
            codes = body.get("error_codes") or []
            aadsts = f" AADSTS{int(codes[0])}" if codes else ""
        except (ValueError, AttributeError, TypeError, IndexError):
            pass
        return TransportError("auth", f"token request refused ({resp.status_code}{': ' + code if code else ''}"
                                      f"{aadsts}): check the tenant id, client id and client secret",
                              status=resp.status_code)

    def token_info(self) -> dict:
        """For the admin diagnostic: {ok, expires_in, roles}. Never the token itself."""
        self._last_expires_in = None
        access = self.token(force=True)
        return {"ok": True, "expires_in": self._last_expires_in, "roles": _jwt_roles(access)}

    # ------------------------------------------------------------------ requests
    def _send_retrying(self, build: Callable[[], httpx.Request], *, op: str, stream: bool = False) -> httpx.Response:
        """Send with the retry policy. Returns the final response (any status); raises TransportError
        on exhausted network errors and on an unknown send outcome."""
        start, slept = self.now(), 0.0
        last_status: int | None = None
        reached = False  # some attempt may have reached Graph (it answered, or the connection was open)
        for attempt in range(MAX_ATTEMPTS):
            wait: float | None = None
            try:
                resp = self.client.send(build(), stream=stream)
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout):
                last_status, wait = None, 2.0 ** attempt
                reason = "network"
            except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.RemoteProtocolError, httpx.ReadError,
                    httpx.WriteError):
                reached = True
                if op == "send":
                    raise TransportError("unknown_outcome", "the send request timed out or the connection dropped "
                                         "before Graph answered: the outcome is unknown",
                                         outcome_unknown=True) from None
                last_status, wait, reason = None, 2.0 ** attempt, "network"
            except httpx.HTTPError:
                raise TransportError("network", "the request to Microsoft failed") from None
            else:
                reached = True
                if resp.status_code == 429:
                    wait, reason = self._retry_after(resp, attempt), "throttled"
                elif op == "send" and (resp.status_code >= 500 or (attempt > 0 and resp.status_code == 404)):
                    status = resp.status_code
                    resp.close()
                    raise TransportError("unknown_outcome", f"Graph answered {status} to the send request: the "
                                         "outcome is unknown", outcome_unknown=True, status=status)
                    # (a 404 on a retried /send: the draft may already have moved to Sent Items)
                elif resp.status_code in RETRY_STATUSES:
                    wait, reason = 2.0 ** attempt + self.jitter(), "server"
                else:
                    return resp
                last_status = resp.status_code
                if attempt == MAX_ATTEMPTS - 1 or (self.now() - start) + slept + wait > BUDGET_S:
                    return resp
                resp.close()
            if attempt == MAX_ATTEMPTS - 1 or (self.now() - start) + slept + wait > BUDGET_S:
                break
            self.sleep(wait)
            slept += wait
        if reason == "network":
            err = TransportError("network", "could not reach Microsoft (connection failed after retries)",
                                 retryable=True)
            err.reached_server = reached
            raise err
        raise TransportError(reason, f"Graph answered {last_status} after retries", status=last_status)

    def _retry_after(self, resp: httpx.Response, attempt: int) -> float:
        value = (resp.headers.get("Retry-After") or "").strip()
        wait: float | None = None
        if value:
            try:
                wait = float(value)
            except ValueError:
                try:
                    wait = (parsedate_to_datetime(value) - datetime.now(tz=UTC)).total_seconds()
                except (TypeError, ValueError, IndexError):
                    wait = None
        if wait is None or wait < 0:
            wait = 2.0 ** attempt
        return min(wait, RETRY_AFTER_CAP_S)

    def _call(self, method: str, url: str, *, op: str, headers: dict | None = None, content: bytes | None = None,
              expect: tuple[int, ...] = (200,), allow_404: bool = False, stream_limit: int | None = None):
        """One authenticated Graph call. Returns (status, parsed JSON | bytes | None)."""
        refreshed = False
        while True:
            token = self.token(force=refreshed)

            def build(token=token) -> httpx.Request:
                h = {"Authorization": f"Bearer {token}", **(headers or {})}
                return self.client.build_request(method, url, headers=h, content=content)

            resp = self._send_retrying(build, op=op, stream=stream_limit is not None)
            if resp.status_code == 401 and not refreshed:
                resp.close()
                refreshed = True
                continue
            break
        try:
            if resp.status_code in expect:
                if stream_limit is not None:
                    return resp.status_code, self._read_capped(resp, stream_limit)
                if not resp.content:
                    return resp.status_code, None
                try:
                    return resp.status_code, resp.json()
                except ValueError:
                    return resp.status_code, None
            if stream_limit is not None:
                resp.read()
            if resp.status_code == 404 and allow_404:
                return 404, None
            raise self._error(resp)
        finally:
            resp.close()

    @staticmethod
    def _read_capped(resp: httpx.Response, limit: int) -> bytes:
        declared = resp.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise TransportError("too_large", "the message is larger than AEGIS_MAIL_MAX_INBOUND_BYTES")
        buf, size = bytearray(), 0
        try:
            for chunk in resp.iter_bytes():
                size += len(chunk)
                if size > limit:
                    raise TransportError("too_large", "the message is larger than AEGIS_MAIL_MAX_INBOUND_BYTES")
                buf.extend(chunk)
        except httpx.HTTPError:
            raise TransportError("network", "the download from Microsoft was interrupted", retryable=True) from None
        return bytes(buf)

    @staticmethod
    def _error(resp: httpx.Response) -> TransportError:
        status = resp.status_code
        code, message = _graph_error(resp)
        if status == 400:
            return TransportError("invalid", f"Graph rejected the request (400{': ' + code if code else ''})"
                                  f"{': ' + message if message else ''}", status=status)
        if status == 401:
            return TransportError("auth", "Graph refused the access token (401) after a refresh: check the app "
                                  "registration and admin consent", status=status)
        if status == 403:
            return TransportError("forbidden", FORBIDDEN_TEXT, status=status)
        if status == 404:
            if code and code not in MAILBOX_CODES:
                return TransportError("invalid", f"Graph could not find the item (404: {code})", status=status)
            return TransportError("mailbox_not_found", "Graph could not find the mailbox (404): check AEGIS_MAIL_FROM",
                                  status=status)
        if status == 413:
            return TransportError("too_large", "Graph refused the message as too large (413)", status=status)
        if status == 429:
            return TransportError("throttled", "Graph is throttling requests (429)", status=status)
        if status >= 500:
            return TransportError("server", f"Graph server error ({status})", status=status)
        return TransportError("invalid", f"Graph answered {status}{': ' + code if code else ''}", status=status)

    # ------------------------------------------------------------------ endpoints
    def create_mime_draft(self, raw: bytes) -> dict:
        body = base64.b64encode(raw)
        _, data = self._call("POST", self._user_url("/messages"), op="create",
                             headers={"Content-Type": "text/plain", "Prefer": PREFER_IMMUTABLE},
                             content=body, expect=(201,))
        if not isinstance(data, dict) or not data.get("id"):
            raise TransportError("server", "Graph created the draft but returned no id")
        return data

    def set_bcc(self, message_id: str, addresses: list[str]) -> dict:
        """Set a draft's hidden recipients (bccRecipients). Returns the updated message."""
        body = json.dumps({"bccRecipients": [{"emailAddress": {"address": a}} for a in addresses]}).encode()
        url = self._user_url(f"/messages/{self._id(message_id)}")
        _, data = self._call("PATCH", url, op="patch", content=body, expect=(200,),
                             headers={"Content-Type": "application/json", "Prefer": PREFER_IMMUTABLE})
        return data if isinstance(data, dict) else {}

    def send_draft(self, message_id: str) -> None:
        try:
            self._call("POST", self._user_url(f"/messages/{self._id(message_id)}/send"), op="send",
                       content=b"", expect=(202,))
        except TransportError as e:
            e.provider_message_id = message_id
            raise

    def get_message(self, message_id: str) -> dict | None:
        """The message's state, or None when Graph answers 404."""
        url = self._user_url(f"/messages/{self._id(message_id)}") + f"?$select={MESSAGE_SELECT}"
        status, data = self._call("GET", url, op="get", headers={"Prefer": PREFER_IMMUTABLE}, allow_404=True)
        return data if status == 200 and isinstance(data, dict) else None

    def get_headers(self, message_id: str) -> list[dict]:
        """The message's internetMessageHeaders ([{name, value}, …], topmost first); [] on a 404."""
        url = self._user_url(f"/messages/{self._id(message_id)}") + "?$select=internetMessageHeaders"
        status, data = self._call("GET", url, op="get", headers={"Prefer": PREFER_IMMUTABLE}, allow_404=True)
        rows = data.get("internetMessageHeaders") if status == 200 and isinstance(data, dict) else None
        return [{"name": str(h.get("name") or "")[:200], "value": str(h.get("value") or "")[:2000]}
                for h in (rows if isinstance(rows, list) else [])[:500] if isinstance(h, dict)]

    def delete_message(self, message_id: str) -> bool:
        """POST /users/{mbx}/messages/{id}/permanentDelete: True when deleted, False when the item was
        already gone (404 ErrorItemNotFound). A 404 for the mailbox itself, or any other error, raises.
        Not DELETE /messages/{id}: that only moves the item to Deleted Items, where it is still a draft
        (and still listed by /messages, so a deletion could never be confirmed)."""
        try:
            self._call("POST", self._user_url(f"/messages/{self._id(message_id)}/permanentDelete"), op="delete",
                       content=b"", expect=(204, 200))
        except TransportError as e:
            if e.status == 404 and e.reason == "invalid":
                return False
            raise
        return True

    def drafts_by_internet_message_id(self, internet_message_id: str) -> list[dict]:
        """Every message with that internetMessageId (drafts and sent), at most 25."""
        value = internet_message_id.replace("'", "''")
        url = (self._user_url("/messages") + "?$filter=" + quote(f"internetMessageId eq '{value}'", safe="")
               + f"&$select={MESSAGE_SELECT}&$top=25")
        _, data = self._call("GET", url, op="get", headers={"Prefer": PREFER_IMMUTABLE})
        rows = (data or {}).get("value") if isinstance(data, dict) else None
        return [r for r in rows or [] if isinstance(r, dict)]

    def find_by_internet_message_id(self, internet_message_id: str) -> dict | None:
        value = internet_message_id.replace("'", "''")
        url = (self._user_url("/messages") + "?$filter=" + quote(f"internetMessageId eq '{value}'", safe="")
               + f"&$select={MESSAGE_SELECT}&$top=5")
        _, data = self._call("GET", url, op="get", headers={"Prefer": PREFER_IMMUTABLE})
        rows = (data or {}).get("value") if isinstance(data, dict) else None
        if not rows:
            return None
        sent = [r for r in rows if isinstance(r, dict) and r.get("isDraft") is False]
        return (sent or rows)[0]

    def mailbox_check(self) -> dict:
        url = self._user_url("/mailFolders/inbox") + "?$select=id,displayName,totalItemCount,unreadItemCount"
        _, data = self._call("GET", url, op="get")
        data = data if isinstance(data, dict) else {}
        return {"ok": True, "display_name": str(data.get("displayName") or "")[:64],
                "total": data.get("totalItemCount"), "unread": data.get("unreadItemCount")}

    def delta_url(self, folder: str = "inbox", since: datetime | None = None, *, select: str = DELTA_SELECT) -> str:
        """The first delta request of a folder: its $select, and `$filter=receivedDateTime ge <since>`
        (UTC, second precision) when a backfill start is given."""
        if folder not in FOLDERS:
            raise TransportError("invalid", "unknown mailbox folder")
        url = self._user_url(f"/mailFolders/{folder}/messages/delta") + f"?$select={select}"
        if since is not None:
            at = (since if since.tzinfo else since.replace(tzinfo=UTC)).astimezone(UTC)
            url += "&$filter=" + quote(f"receivedDateTime ge {at:%Y-%m-%dT%H:%M:%SZ}", safe="")
        return url

    def delta_pages(self, link: str | None, *, folder: str = "inbox", since: datetime | None = None,
                    select: str = DELTA_SELECT):
        """Yield ("page", [messages]) per page, then ("delta", delta_link) at the end. Without `link` the
        folder's delta starts afresh (`delta_url`); a stored link continues where the last sync ended."""
        url = self._check_graph_url(link) if link else self.delta_url(folder, since, select=select)
        headers = {"Prefer": f"odata.maxpagesize=50, {PREFER_IMMUTABLE}"}
        for _ in range(10_000):  # hard stop against a link loop
            _, data = self._call("GET", url, op="get", headers=headers)
            data = data if isinstance(data, dict) else {}
            rows = [m for m in (data.get("value") or []) if isinstance(m, dict) and "@removed" not in m]
            yield "page", rows
            if data.get("@odata.nextLink"):
                url = self._check_graph_url(str(data["@odata.nextLink"]))
                continue
            delta = data.get("@odata.deltaLink")
            yield "delta", self._check_graph_url(str(delta)) if delta else None
            return
        raise TransportError("server", "Graph delta paging did not end")

    def delta(self, link: str | None) -> tuple[list[dict], str | None]:
        """All pages at once: (messages, delta_link)."""
        messages, delta_link = [], None
        for kind, value in self.delta_pages(link):
            if kind == "page":
                messages.extend(value)
            else:
                delta_link = value
        return messages, delta_link

    def get_text_body(self, message_id: str, limit: int = 200 * 1024) -> str:
        """The message's body as plain text (Graph converts HTML), without attachments, at most `limit`
        characters; "" on a 404. Read in memory only (the Sent Items citation check)."""
        url = self._user_url(f"/messages/{self._id(message_id)}") + "?$select=body"
        status, data = self._call("GET", url, op="get", allow_404=True,
                                  headers={"Prefer": f'outlook.body-content-type="text", {PREFER_IMMUTABLE}'})
        body = data.get("body") if status == 200 and isinstance(data, dict) else None
        return str((body or {}).get("content") or "")[:limit] if isinstance(body, dict) else ""

    def get_mime(self, message_id: str) -> bytes:
        _, data = self._call("GET", self._user_url(f"/messages/{self._id(message_id)}/$value"), op="get",
                             headers={"Prefer": PREFER_IMMUTABLE}, stream_limit=self.settings.max_inbound_bytes)
        return data or b""


def bcc_echo_problem(asked: list[str], got: set[str], own_domain: str | None) -> str | None:
    """Why Graph's answer to the Bcc PATCH does not hold the Bcc recipients asked for, or None. Exchange may answer
    an address in the mailbox's own tenant with that mailbox's primary address (an alias of a colleague's mailbox,
    a likely Bcc): an echoed address that was not asked for is accepted in place of one that is missing only when
    both are on the case mailbox's own domain and the counts match. Anything else (a recipient dropped or added, an
    outside address replaced by an in-tenant one, or anything replaced by an outside address) refuses the send:
    the letter's record (meta.bcc) must name who Exchange delivers it to."""
    want = set(asked)
    missing, extra = want - got, got - want
    if not missing and not extra:
        return None
    own = (own_domain or "").strip().lower()
    if own and len(got) == len(want) and len(missing) == len(extra) and all(
            a.rpartition("@")[2] == own for a in extra | missing):
        return None
    return f"asked for {len(want)}, it kept {len(want) - len(missing)} of them" + (
        f" and {len(extra)} other address{'es' if len(extra) != 1 else ''}" if extra else "")


class GraphTransport:
    name = "graph"

    def __init__(self, settings: MailSettings | None = None, *, client: httpx.Client | None = None,
                 sleep: Callable[[float], None] = time.sleep, now: Callable[[], float] = time.time,
                 graph: GraphClient | None = None):
        self.settings = settings or mail_settings()
        self.graph = graph or GraphClient(self.settings, client=client, sleep=sleep, now=now)
        self.sleep = self.graph.sleep

    def status(self) -> TransportStatus:
        problem = self.settings.graph_problem()
        mailbox = self.settings.mail_from or None
        if problem:
            return TransportStatus("graph", False, problem, mailbox)
        return TransportStatus("graph", True, "Microsoft 365 via Microsoft Graph (shared case mailbox)", mailbox)

    def _require(self) -> None:
        st = self.status()
        if not st.configured:
            raise TransportError("not_configured", st.reason)

    def _result(self, message_id: str, msg: dict | None, draft: dict | None = None) -> SendResult:
        msg = msg or {}
        draft = draft or {}
        imid = msg.get("internetMessageId") or draft.get("internetMessageId")
        detail: dict = {}
        if not imid or msg.get("isDraft") is not False:
            detail["ids_pending"] = True
        return SendResult(transport="graph", message_id=message_id, internet_message_id=str(imid or message_id),
                          provider_message_id=msg.get("id") or draft.get("id"),
                          conversation_id=msg.get("conversationId") or draft.get("conversationId"),
                          sent_at=_parse_dt(msg.get("sentDateTime")), detail=detail)

    def _settle(self, provider_id: str) -> dict | None:
        """After /send: read the message back (up to 3 tries 1 s apart; a 404 during the move to Sent
        Items is tolerated)."""
        msg = None
        for i in range(3):
            try:
                msg = self.graph.get_message(provider_id)
            except TransportError:
                msg = None
            if msg and msg.get("isDraft") is False:
                return msg
            if i < 2:
                self.sleep(1.0)
        return msg

    def send_mime(self, raw: bytes, *, message_id: str, bcc: list[str] | None = None) -> SendResult:
        """Create the MIME draft, set its Bcc recipients when there are any (checked; module doc), then
        send it. No unsent draft of the letter is left behind with a
        `failed` outcome: when creating fails ambiguously (network / server error after retries) or
        /send is refused outright (a 4xx), every draft with our Message-ID is deleted; when that
        cleanup cannot be confirmed the error is raised as an unknown outcome instead (the row then
        waits for reconcile, which deletes the draft before marking the e-mail failed)."""
        self._require()
        if len(raw) > self.settings.max_message_bytes:
            raise TransportError("too_large", "the message is larger than AEGIS_MAIL_MAX_MESSAGE_BYTES")
        try:
            draft = self.graph.create_mime_draft(raw)
        except TransportError as e:
            if e.reason in ("network", "server"):  # a timed-out attempt may have created a draft
                # nothing found by our Message-ID proves nothing when an attempt may have reached
                # Graph: a just-created draft can be listed late (only connect failures are certain)
                self._cleanup_after_failure(e, message_id, None,
                                            listing_proves_none=not getattr(e, "reached_server", True))
            raise
        provider_id = str(draft["id"])
        if bcc:
            self._set_bcc(provider_id, message_id, list(bcc))
        try:
            self.graph.send_draft(provider_id)
        except TransportError as e:
            if not e.outcome_unknown:  # refused (nothing sent): the draft must not stay in the mailbox
                self._cleanup_after_failure(e, message_id, provider_id)
            raise
        return self._result(message_id, self._settle(provider_id), draft)

    def _set_bcc(self, provider_id: str, message_id: str, bcc: list[str]) -> None:
        """bccRecipients on the unsent draft, verified; on any failure the draft is deleted (nothing was
        sent: a PATCH never sends) and the error raised."""
        try:
            updated = self.graph.set_bcc(provider_id, bcc)
            rows = updated.get("bccRecipients") if isinstance(updated.get("bccRecipients"), list) else []
            got = {str((r.get("emailAddress") or {}).get("address") or "").strip().lower()
                   for r in rows if isinstance(r, dict)}
            problem = bcc_echo_problem([a.strip().lower() for a in bcc], got, self.settings.mail_domain)
            if updated.get("isDraft") is False:
                problem = "the draft was no longer a draft"
            if problem:
                raise TransportError("invalid", f"Graph did not keep the Bcc recipients on the draft ({problem}); "
                                                "nothing was sent")
        except TransportError as e:
            e.outcome_unknown = False
            if not e.message.startswith("Graph did not keep the Bcc"):  # Graph refused the Bcc PATCH itself
                e.message = (f"Graph refused the Bcc recipients ({e.message}); nothing was sent: check or remove "
                             "the Bcc addresses")[:512]
            self._cleanup_after_failure(e, message_id, provider_id)
            raise

    def _cleanup_after_failure(self, err: TransportError, message_id: str, provider_id: str | None, *,
                               listing_proves_none: bool = True) -> None:
        """Delete the drafts a failed send left; on failure turn `err` into an unknown outcome. Without
        a draft id, a listing that finds no draft at all is only proof when `listing_proves_none`
        (else the outcome stays unknown: reconcile checks again once MISSING_GRACE has passed)."""
        found = 0
        try:
            state, found = self._delete_drafts(message_id=message_id, provider_message_id=provider_id)
        except TransportError:
            state = None
        if state == "deleted" and not found and provider_id is None and not listing_proves_none:
            state = "unconfirmed"
        if state == "deleted":
            note = "the unsent draft was removed from the mailbox" if found else "no draft was left in the mailbox"
            err.message = (err.message + "; " + note)[:512]
            return
        err.outcome_unknown = True
        err.reason = "unknown_outcome"
        err.provider_message_id = provider_id
        why = {None: "Aegis could not confirm that the unsent draft was removed from the mailbox",
               "unconfirmed": "Graph may still list a draft it created late: Aegis checks the mailbox again "
                              "before the e-mail is marked failed",
               "sent": "the mailbox shows the message as sent"}[state]
        err.message = (err.message + "; " + why)[:512]

    def delete_drafts(self, *, message_id: str, provider_message_id: str | None) -> str:
        """Delete (permanently) every unsent draft of this message: the immutable id and every draft
        carrying our internetMessageId (a retried create may have left more than one; one an earlier
        soft delete moved to Deleted Items is still a draft). Returns "deleted" (none is left) or
        "sent" (the mailbox shows it sent: nothing was deleted). Raises TransportError when a
        deletion fails or drafts remain afterwards."""
        return self._delete_drafts(message_id=message_id, provider_message_id=provider_message_id)[0]

    def _delete_drafts(self, *, message_id: str, provider_message_id: str | None) -> tuple[str, int]:
        """delete_drafts, and how many drafts were found (and deleted)."""
        self._require()
        ids: list[str] = []
        if provider_message_id and not provider_message_id.startswith("file:"):
            msg = self.graph.get_message(provider_message_id)
            if msg is not None:
                if msg.get("isDraft") is False:
                    return "sent", 0
                ids.append(str(msg.get("id") or provider_message_id))
        rows = self.graph.drafts_by_internet_message_id(message_id)
        if any(r.get("isDraft") is False for r in rows):
            return "sent", 0
        ids += [str(r["id"]) for r in rows if r.get("id") and r.get("isDraft") is True]
        ids = list(dict.fromkeys(ids))
        for pid in ids:
            self.graph.delete_message(pid)
        left = [r for r in self.graph.drafts_by_internet_message_id(message_id) if r.get("isDraft") is not False]
        if left:
            raise TransportError("server", f"{len(left)} draft(s) of this message are still in the mailbox")
        return "deleted", len(ids)

    def message_headers(self, provider_id: str) -> list[dict]:
        """internetMessageHeaders of an inbound message (app.mail.matching.exchange_generated)."""
        self._require()
        return self.graph.get_headers(provider_id)

    def lookup_sent(self, *, message_id: str, provider_message_id: str | None) -> LookupResult:
        self._require()
        msg = self.graph.get_message(provider_message_id) if provider_message_id else None
        if msg is None:  # no immutable id, or it no longer resolves: look for the Message-ID (Sent Items included)
            msg = self.graph.find_by_internet_message_id(message_id)
        if msg is None:
            return LookupResult("missing")
        if msg.get("isDraft") is True:
            return LookupResult("draft", self._result(message_id, msg))
        return LookupResult("sent", self._result(message_id, msg))

    # diagnostics
    def token_info(self) -> dict:
        self._require()
        return self.graph.token_info()

    def mailbox_check(self) -> dict:
        self._require()
        return self.graph.mailbox_check()

    # inbound
    def fetch_inbound(self, state=None) -> InboundBatch:
        self._require()
        link = getattr(state, "delta_link", None) if not isinstance(state, dict) else state.get("delta_link")

        def items(batch: InboundBatch):
            for kind, value in self.graph.delta_pages(link):
                if kind == "delta":
                    batch.delta_link = value
                    continue
                for m in value:
                    if m.get("isDraft") is True or not m.get("id"):
                        continue
                    pid = str(m["id"])
                    yield InboundItem(
                        provider_id=pid, received_at=_parse_dt(m.get("receivedDateTime")),
                        meta={"internet_message_id": m.get("internetMessageId"),
                              "conversation_id": m.get("conversationId"),
                              "has_attachments": bool(m.get("hasAttachments"))},
                        loader=lambda pid=pid: self.graph.get_mime(pid))

        return InboundBatch(items)

    def fetch_folder(self, folder: str, state=None) -> InboundBatch:
        """One folder of the mailbox sync (module doc): continue from `state.delta_link`, or start a
        backfill from `state.since`. Items carry metadata only; `item.load()` downloads the raw MIME."""
        self._require()
        if folder not in FOLDERS:
            raise TransportError("invalid", "unknown mailbox folder")
        link = getattr(state, "delta_link", None)
        since = None if link else _aware_dt(getattr(state, "since", None))

        def items(batch: InboundBatch):
            for kind, value in self.graph.delta_pages(link, folder=folder, since=since, select=FOLDER_DELTA_SELECT):
                if kind == "delta":
                    batch.delta_link = value
                    continue
                for m in value:
                    if m.get("isDraft") is True or not m.get("id"):
                        continue
                    pid = str(m["id"])
                    yield InboundItem(provider_id=pid, received_at=_parse_dt(m.get("receivedDateTime")),
                                      meta=folder_meta(m, folder), loader=lambda pid=pid: self.graph.get_mime(pid))

        return InboundBatch(items)

    def get_mime(self, provider_id: str) -> bytes:
        """The raw MIME of one message (an admin opening a metadata-only triage row)."""
        self._require()
        return self.graph.get_mime(provider_id)

    def thread_headers(self, provider_id: str) -> tuple[list[str], list[str]]:
        """(In-Reply-To ids, References ids) from the message's internetMessageHeaders, without its body."""
        from app.mail.inbound import message_ids

        self._require()
        rows = self.graph.get_headers(provider_id)
        irt = " ".join(h["value"] for h in rows if h["name"].lower() == "in-reply-to")
        refs = " ".join(h["value"] for h in rows if h["name"].lower() == "references")
        return message_ids(irt), message_ids(refs)

    def text_body(self, provider_id: str) -> str:
        self._require()
        return self.graph.get_text_body(provider_id)

    def ack(self, item: InboundItem) -> None:
        return None


def _aware_dt(v) -> datetime | None:
    if not isinstance(v, datetime):
        return None
    return v if v.tzinfo else v.replace(tzinfo=UTC)


def _recipient(r) -> str | None:
    addr = ((r or {}).get("emailAddress") or {}).get("address") if isinstance(r, dict) else None
    addr = str(addr or "").strip().lower()[:254]
    return addr if "@" in addr and not any(c in addr for c in " \r\n<>") else None


def folder_meta(m: dict, folder: str) -> dict:
    """The metadata of a delta row the sync may look at before (or without) downloading the message."""
    def recips(key: str) -> list[str]:
        rows = m.get(key) if isinstance(m.get(key), list) else []
        return [a for a in (_recipient(r) for r in rows[:100]) if a]

    sender = _recipient(m.get("from"))
    return {"folder": folder, "internet_message_id": m.get("internetMessageId"),
            "conversation_id": m.get("conversationId"), "subject": m.get("subject"), "from_addr": sender,
            "to": recips("toRecipients"), "cc": recips("ccRecipients"),
            "sent_at": _parse_dt(m.get("sentDateTime")), "has_attachments": bool(m.get("hasAttachments"))}
