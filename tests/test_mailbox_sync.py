"""Mailbox sync (Inbox + Sent Items) over a mocked Microsoft Graph: backfill since a date, delta continuation,
paging, throttling, data minimisation, outside-sent letters (unique / ambiguous / none), idempotency, threading
of replies against Sent Items, the triage queue and the admin page.

No network: Graph is an httpx.MockTransport (`FakeGraph`). Every address is on a reserved *-demo.example domain
and every case is created by the test itself (its own reference, entity, domain and wallets), so the demo case
and other tests' rows never interfere.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import format_datetime, getaddresses

import httpx
import pytest
from conftest import csrf_token
from sqlalchemy import select

from app.db import models as M
from app.mail import graph as graph_mod
from app.mail import ingest, matching
from app.mail.config import MailSettings
from app.mail.graph import GraphTransport

SINCE = "2026-10-01T00:00:00Z"
GRAPH = "https://graph.microsoft.com/v1.0"
FREEMAIL = "freemail-mbx-demo.example"  # stands in for a free-mail provider (no test names a real mailbox)


@pytest.fixture(autouse=True)
def _freemail(monkeypatch):
    monkeypatch.setattr(matching, "SHARED_DOMAINS", matching.SHARED_DOMAINS | {FREEMAIL})


# --------------------------------------------------------------------------- a fake Microsoft Graph
def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeGraph:
    """Two folders of messages, a delta function with paging and continuation, $value, headers and body."""

    def __init__(self, mailbox: str, page_size: int = 2):
        self.mailbox = mailbox
        self.folders: dict[str, list[dict]] = {"inbox": [], "sentitems": []}
        self.raw: dict[str, bytes] = {}
        self.calls: list[str] = []
        self.filters: dict[str, list[str | None]] = {"inbox": [], "sentitems": []}
        self.throttle: dict[str, int] = {}
        self.page_size = page_size
        self._pages: dict[str, list[dict]] = {}
        self.sleeps: list[float] = []
        self.prefer: list[tuple[str, str]] = []  # (path, Prefer header) of every Graph call

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)

    def add(self, folder: str, raw: bytes, *, at: datetime, conversation: str | None = None) -> str:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
        pid = f"AAMk{uuid.uuid4().hex}="

        def rcpts(h):
            return [{"emailAddress": {"address": a}} for _, a in getaddresses([str(msg.get(h) or "")]) if a]

        frm = getaddresses([str(msg.get("From") or "")])
        row = {"id": pid, "internetMessageId": str(msg.get("Message-ID")), "conversationId": conversation,
               "subject": str(msg.get("Subject") or ""), "from": {"emailAddress": {"address": frm[0][1]}} if frm else None,
               "toRecipients": rcpts("To"), "ccRecipients": rcpts("Cc"), "receivedDateTime": _iso(at),
               "sentDateTime": _iso(at - timedelta(seconds=5)), "hasAttachments": False, "isDraft": False}
        self.folders[folder].append(row)
        self.raw[pid] = raw
        return pid

    def downloads(self, pid: str) -> int:
        return sum(1 for c in self.calls if c.startswith("GET ") and f"/messages/{pid}/$value" in c)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(f"{request.method} {path}?{request.url.query.decode()}")
        self.prefer.append((path, request.headers.get("Prefer", "")))
        for key, n in list(self.throttle.items()):
            if key in path and n > 0:
                self.throttle[key] = n - 1
                return httpx.Response(429, headers={"Retry-After": "2"}, json={"error": {"code": "TooManyRequests"}})
        if path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "opaque-test-token", "expires_in": 3599})
        m = re.search(r"/mailFolders/(\w+)/messages/delta$", path)
        if m:
            return self._delta(m.group(1), request.url.params)
        m = re.search(r"/messages/([^/]+)/\$value$", path)
        if m:
            raw = self.raw.get(m.group(1))
            return httpx.Response(200, content=raw) if raw is not None else httpx.Response(
                404, json={"error": {"code": "ErrorItemNotFound"}})
        m = re.search(r"/messages/([^/]+)$", path)
        if m and m.group(1) in self.raw:
            msg = BytesParser(policy=policy.default).parsebytes(self.raw[m.group(1)])
            select_ = request.url.params.get("$select", "")
            if "internetMessageHeaders" in select_:
                return httpx.Response(200, json={"internetMessageHeaders": [
                    {"name": k, "value": str(v)} for k, v in msg.items()]})
            if "body" in select_:
                part = msg.get_body(preferencelist=("plain",))
                return httpx.Response(200, json={"body": {"contentType": "text",
                                                          "content": part.get_content() if part else ""}})
        return httpx.Response(404, json={"error": {"code": "ErrorItemNotFound"}})

    def _delta(self, folder: str, params) -> httpx.Response:
        base = f"{GRAPH}/users/{self.mailbox}/mailFolders/{folder}/messages/delta"
        if "$skiptoken" in params:
            rows = self._pages.pop(params["$skiptoken"])
        elif "$deltatoken" in params:
            rows = self.folders[folder][int(params["$deltatoken"]):]
        else:
            flt = params.get("$filter")
            self.filters[folder].append(flt)
            since = flt.split(" ge ")[1] if flt else ""
            rows = [r for r in self.folders[folder] if r["receivedDateTime"] >= since]
        page, rest = rows[:self.page_size], rows[self.page_size:]
        body: dict = {"value": page}
        if rest:
            token = uuid.uuid4().hex
            self._pages[token] = rest
            body["@odata.nextLink"] = f"{base}?$skiptoken={token}"
        else:
            body["@odata.deltaLink"] = f"{base}?$deltatoken={len(self.folders[folder])}"
        return httpx.Response(200, json=body)


# --------------------------------------------------------------------------- fixtures
@pytest.fixture
def mbx(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(tmp_path / "vault"))
    graph_mod.clear_token_cache()
    mailbox = f"investigations-{uuid.uuid4().hex[:8]}@athena-mbx-demo.example"
    fake = FakeGraph(mailbox)

    def settings(**kw):
        base = {"aegis_mail_transport": "graph", "aegis_mail_from": mailbox, "aegis_mail_inbound": True,
                "aegis_mail_inbound_since": SINCE, "aegis_m365_tenant_id": "00000000-0000-0000-0000-000000000000",
                "aegis_m365_client_id": "00000000-0000-0000-0000-000000000001",
                "aegis_m365_client_secret": "test-client-secret-not-real"}
        base.update(kw)
        return MailSettings(_env_file=None, **base)

    def transport(**kw):
        return GraphTransport(settings(**kw), client=httpx.Client(transport=httpx.MockTransport(fake.handler)),
                              sleep=fake.sleep)

    def sync(db, trigger="scheduler", **kw):
        return ingest.sync_mailbox(db, trigger=trigger, settings=settings(**kw), transport=transport(**kw))

    class Env:
        pass

    env = Env()
    env.mailbox, env.fake, env.settings, env.transport, env.sync = mailbox, fake, settings, transport, sync
    yield env
    graph_mod.clear_token_cache()


class World:
    """A case of its own: one entity authority with a draft stop order (+ its draft letter row)."""


def make_case(db, *, second_order: bool = False) -> World:
    tag = uuid.uuid4().hex[:8]
    w = World()
    w.tag, w.domain = tag, f"issuer-{tag}-demo.example"
    w.to = f"compliance@{w.domain}"
    w.wallet = "0x" + secrets.token_hex(20)
    w.case = M.Case(reference=f"MBX-{tag.upper()}", title="Mailbox sync test", status="open", facts={})
    w.entity = M.Entity(name=f"Issuer {tag}", compliance_email=w.to)
    ids = {"addresses": [{"chain": "ethereum", "address": w.wallet,
                          "inbound": [{"asset": "USDC", "amount": "1000", "amount_usd": "1000"}]}]}
    w.order = M.StopOrder(case=w.case, entity=w.entity, kind="freeze", status=M.StopOrderStatus.DRAFT,
                          subject=f"Preservation request {tag}", body_markdown=f"Please freeze {w.wallet}.",
                          identifiers=ids, recipient_email=w.to)
    w.corr = M.Correspondence(case=w.case, entity=w.entity, direction=M.CorrespondenceDirection.OUT,
                              kind=M.CorrespondenceKind.STOP_ORDER, status=M.CorrespondenceStatus.DRAFT,
                              subject=w.order.subject, body_markdown=w.order.body_markdown, recipients=[w.to],
                              stop_order=w.order, classification=M.Classification.R3, meta={})
    db.add_all([w.case, w.entity, w.order, w.corr])
    if second_order:
        w.wallet2 = "0x" + secrets.token_hex(20)
        ids2 = {"addresses": [{"chain": "ethereum", "address": w.wallet2,
                               "inbound": [{"asset": "USDC", "amount": "1000", "amount_usd": "1000"}]}]}
        w.order2 = M.StopOrder(case=w.case, entity=w.entity, kind="freeze", status=M.StopOrderStatus.DRAFT,
                               subject=f"Preservation request {tag}", body_markdown=f"Please freeze {w.wallet2}.",
                               identifiers=ids2, recipient_email=w.to)
        db.add(w.order2)
    db.commit()
    w.subject = (f"URGENT - Preservation & Risk-Control Request - Issuer {tag} - USDC 1,000.00 - "
                 f"Ref {w.case.reference}")
    return w


def eml(*, from_: str, to: str, subject: str, body: str = "Hello.", cc: str | None = None,
        in_reply_to: str | None = None, headers: dict | None = None, msgid_domain: str = "mbx-demo.example",
        date: datetime | None = None) -> bytes:
    msg = EmailMessage()
    msg["From"] = from_
    msg["To"] = to
    if cc:
        msg["Cc"] = cc
    msg["Subject"] = subject
    msg["Date"] = format_datetime(date or datetime.now(tz=UTC))
    msg["Message-ID"] = f"<{uuid.uuid4().hex}@{msgid_domain}>"
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = in_reply_to
    for k, v in (headers or {}).items():
        msg[k] = v
    msg.set_content(body)
    return msg.as_bytes(policy=policy.SMTP)


def _auth(domain: str) -> dict:
    return {"Authentication-Results": f"spf=pass smtp.mailfrom={domain}; dmarc=pass action=none header.from={domain}; "
                                      "compauth=pass reason=100"}


def _rows(db, mailbox):
    return db.scalars(select(M.MailMessage).where(M.MailMessage.mailbox == mailbox).order_by(M.MailMessage.id)).all()


NOW = datetime.now(tz=UTC)
RECENT = NOW - timedelta(hours=2)


# --------------------------------------------------------------------------- backfill, delta, paging, throttling
def test_backfill_reads_both_folders_since_the_date(db, mbx):
    w = make_case(db)
    old = datetime(2026, 9, 20, tzinfo=UTC)
    mbx.fake.add("inbox", eml(from_=w.to, to=mbx.mailbox, subject=f"Re: {w.case.reference}",
                              body=f"About {w.wallet}"), at=old)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=f"Freeze {w.wallet}"), at=old)
    report = mbx.sync(db)
    assert report.ok and report.folders == ["sentitems", "inbox"], report
    # the first request of each folder asks Graph only for mail since AEGIS_MAIL_INBOUND_SINCE
    assert mbx.fake.filters == {"inbox": ["receivedDateTime ge 2026-10-01T00:00:00Z"],
                                "sentitems": ["receivedDateTime ge 2026-10-01T00:00:00Z"]}
    assert report.fetched == 0 and report.sent["fetched"] == 0 and _rows(db, mbx.mailbox) == []
    states = ingest.folder_states(db, mbx.mailbox)
    assert set(states) == {"inbox", "sentitems"} and all(s.delta_link for s in states.values())
    assert all(s.since == datetime(2026, 10, 1, tzinfo=UTC) for s in states.values())
    every = [c for c in mbx.fake.calls if "/messages/delta" in c]
    assert every and all("toRecipients" in c and "sentDateTime" in c for c in every)
    graph_calls = [(path, pref) for path, pref in mbx.fake.prefer if "/users/" in path]
    assert graph_calls and all('IdType="ImmutableId"' in pref for _, pref in graph_calls)
    assert all("odata.maxpagesize=50" in pref for path, pref in graph_calls if path.endswith("/delta"))
    db.refresh(w.corr)
    assert w.corr.status == M.CorrespondenceStatus.DRAFT


def test_delta_continuation_and_paging(db, mbx):
    w = make_case(db)
    for n in range(3):  # three replies to the authority's own domain, citing the case: page size 2
        mbx.fake.add("inbox", eml(from_=w.to, to=mbx.mailbox, subject=f"Ticket {n} {w.case.reference}"), at=RECENT)
    first = mbx.sync(db)
    assert first.fetched == 3 and first.errors == 0, first
    assert any("$skiptoken" in c for c in mbx.fake.calls)  # followed the nextLink page
    link = ingest.folder_states(db, mbx.mailbox)["inbox"].delta_link
    assert link and "$deltatoken=3" in link
    assert db.get(M.MailSyncState, mbx.mailbox).delta_link == link  # mirrored for older readers
    mbx.fake.add("inbox", eml(from_=w.to, to=mbx.mailbox, subject=f"Ticket 3 {w.case.reference}"), at=NOW)
    mbx.fake.calls.clear()
    second = mbx.sync(db)
    assert second.fetched == 1 and second.errors == 0, second
    delta_calls = [c for c in mbx.fake.calls if "/inbox/messages/delta" in c]
    assert len(delta_calls) == 1 and "$deltatoken=3" in delta_calls[0] and "$filter" not in delta_calls[0]
    assert len([r for r in _rows(db, mbx.mailbox) if r.direction == M.MailDirection.IN]) == 4


def test_throttling_waits_for_retry_after(db, mbx):
    w = make_case(db)
    mbx.fake.add("inbox", eml(from_=w.to, to=mbx.mailbox, subject=f"Ticket {w.case.reference}"), at=RECENT)
    mbx.fake.throttle = {"/inbox/messages/delta": 2, "/$value": 1}
    report = mbx.sync(db)
    assert report.errors == 0 and report.fetched == 1, report
    assert mbx.fake.sleeps.count(2.0) == 3  # Retry-After honoured on the delta (twice) and the download
    assert ingest.folder_states(db, mbx.mailbox)["inbox"].delta_link


def test_a_failed_download_keeps_the_folders_delta_link(db, mbx):
    w = make_case(db)
    pid = mbx.fake.add("inbox", eml(from_=w.to, to=mbx.mailbox, subject=f"Ticket {w.case.reference}"), at=RECENT)
    del mbx.fake.raw[pid]  # $value answers 404
    report = mbx.sync(db)
    assert report.errors == 1 and report.error
    states = ingest.folder_states(db, mbx.mailbox)
    assert states["inbox"].delta_link is None and states["inbox"].last_error  # replayed next time
    assert states["sentitems"].delta_link  # the other folder went through


# --------------------------------------------------------------------------- data minimisation
def test_unrelated_mail_is_counted_never_stored_or_downloaded(db, mbx):
    make_case(db)
    a = mbx.fake.add("inbox", eml(from_="newsletter@shop-mbx-demo.example", to=mbx.mailbox, subject="Autumn sale"),
                     at=RECENT)
    b = mbx.fake.add("inbox", eml(from_=f"someone@{FREEMAIL}", to=mbx.mailbox, subject="Lunch?"), at=RECENT)
    c = mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to="friend@other-mbx-demo.example", subject="Invoice",
                                      body="Unrelated business."), at=RECENT)
    report = mbx.sync(db)
    assert report.not_related == 2 and report.sent["not_related"] == 1 and report.errors == 0, report
    assert _rows(db, mbx.mailbox) == []
    assert mbx.fake.downloads(a) == mbx.fake.downloads(b) == mbx.fake.downloads(c) == 0  # bodies never fetched
    # a copy of our own outbound message in the Inbox (the mailbox Cc'd) is never stored either
    mbx.fake.add("inbox", eml(from_=mbx.mailbox, to="x@issuer-mbx-demo.example", subject="[Aegis MBX-X #1] copy"),
                 at=NOW)
    again = mbx.sync(db)
    assert again.not_related == 1 and _rows(db, mbx.mailbox) == []


def test_free_mail_domain_never_matches_by_domain(db, mbx):
    w = make_case(db)
    le = M.LEContact(case=w.case, agency=f"Police {w.tag}", email=f"officer.{w.tag}@{FREEMAIL}")
    db.add(le)
    db.commit()
    stranger = mbx.fake.add("inbox", eml(from_=f"stranger@{FREEMAIL}", to=mbx.mailbox, subject="hello"), at=RECENT)
    officer = mbx.fake.add("inbox", eml(from_=f"officer.{w.tag}@{FREEMAIL}", to=mbx.mailbox, subject="hi"), at=RECENT)
    report = mbx.sync(db)
    assert report.not_related == 1 and report.triage == 1, report
    assert mbx.fake.downloads(stranger) == 0 and mbx.fake.downloads(officer) == 1
    (row,) = _rows(db, mbx.mailbox)
    assert row.from_addr == f"officer.{w.tag}@{FREEMAIL}" and row.meta["metadata_only"] is True


def test_authority_mail_citing_nothing_goes_to_triage_with_metadata_only(db, mbx, client_for, monkeypatch):
    w = make_case(db)
    pid = mbx.fake.add("inbox", eml(from_=f"support@{w.domain}", to=mbx.mailbox, subject="Your account",
                                    body="Private details of someone else."), at=RECENT)
    report = mbx.sync(db)
    assert report.triage == 1 and report.unassigned == 1, report
    (mm,) = _rows(db, mbx.mailbox)
    assert mm.status == M.MailStatus.UNASSIGNED and mm.case_id is None and mm.folder == "inbox"
    assert (mm.from_addr, mm.subject, mm.received_at is not None) == (f"support@{w.domain}", "Your account", True)
    assert mm.body_text is None and mm.mime_path is None and mm.mime_sha256 is None
    assert mm.to_addrs == [] and mm.cc_addrs == [] and mm.attachments == []
    assert mm.match_method == "triage" and mm.match["candidate_case_ids"] == [w.case.id]
    # a system admin opens it: only now is the message read from the mailbox and stored
    monkeypatch.setattr(ingest, "inbound_transport", lambda settings: (mbx.transport(), None))
    admin = client_for(None, system_admin=True, email="sysadmin-mbx-triage@tests.example")
    page = admin.get(f"/admin/mail/unassigned/{mm.id}")
    assert page.status_code == 200 and "Metadata only" in page.text and "Private details" not in page.text
    token = csrf_token(admin, f"/admin/mail/unassigned/{mm.id}")
    r = admin.post(f"/admin/mail/unassigned/{mm.id}/load", data={"csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303
    db.refresh(mm)
    assert mm.body_text == "Private details of someone else." and mm.mime_path and not mm.meta["metadata_only"]
    assert mbx.fake.downloads(pid) == 2  # the decision (in memory, discarded), then the admin's open
    assert "Private details" in admin.get(f"/admin/mail/unassigned/{mm.id}").text
    ev = db.scalars(select(M.AuditEvent).where(M.AuditEvent.action == "MAIL_TRIAGE_OPENED")
                    .order_by(M.AuditEvent.id.desc())).first()
    assert ev is not None and ev.detail.get("mail_message_id") == mm.id


def test_assigning_a_metadata_only_row_reads_it_and_is_audited(db, mbx, client_for, monkeypatch):
    w = make_case(db)
    mbx.fake.add("inbox", eml(from_=f"support@{w.domain}", to=mbx.mailbox, subject="Your account",
                              body="An answer without a reference."), at=RECENT)
    assert mbx.sync(db).triage == 1
    (mm,) = _rows(db, mbx.mailbox)
    monkeypatch.setattr(ingest, "inbound_transport", lambda settings: (mbx.transport(), None))
    admin = client_for(None, system_admin=True, email="sysadmin-mbx-assign@tests.example")
    token = csrf_token(admin, f"/admin/mail/unassigned/{mm.id}")
    r = admin.post(f"/admin/mail/unassigned/{mm.id}/assign", follow_redirects=False,
                   data={"csrf_token": token, "case_id": str(w.case.id), "authority_key": f"entity-{w.entity.id}"})
    assert r.status_code == 303, r.text[:500]
    opened = db.scalars(select(M.AuditEvent).where(M.AuditEvent.action == "MAIL_TRIAGE_OPENED")).all()
    assert [e.detail.get("mail_message_id") for e in opened].count(mm.id) == 1


def test_a_database_error_never_reaches_last_error_with_its_parameters():
    from sqlalchemy.exc import IntegrityError

    err = IntegrityError("INSERT INTO mail_messages (subject) VALUES (?)", ("Secret subject of a client",),
                         Exception("UNIQUE constraint failed"))
    text = ingest.sanitize_error(err)
    assert text == "IntegrityError: database error (details withheld)" and "Secret" not in text


def test_authority_mail_citing_a_traced_wallet_waits_for_review_on_the_case(db, mbx):
    w = make_case(db)
    mbx.fake.add("inbox", eml(from_=w.to, to=mbx.mailbox, subject="Our findings", body=f"We hold {w.wallet}."),
                 at=RECENT)
    report = mbx.sync(db)
    assert report.needs_review == 1 and report.received == 0, report
    (mm,) = _rows(db, mbx.mailbox)
    assert mm.case_id == w.case.id and mm.status == M.MailStatus.NEEDS_REVIEW and mm.mime_path
    assert mm.match_method == "sender_cited" and mm.authority_key == f"entity-{w.entity.id}"


# --------------------------------------------------------------------------- Sent Items: letters sent from Outlook
def test_outside_sent_letter_is_recorded_on_its_letter(db, mbx):
    w = make_case(db)
    raw = eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=f"Please freeze {w.wallet}.",
              msgid_domain="athena-mbx-demo.example")
    sent_pid = mbx.fake.add("sentitems", raw, at=RECENT, conversation=f"conv-{w.tag}")
    sent_row = mbx.fake.folders["sentitems"][-1]
    report = mbx.sync(db)
    assert report.sent["recorded"] == 1 and report.sent["errors"] == 0, report
    db.expire_all()
    corr, order = db.get(M.Correspondence, w.corr.id), db.get(M.StopOrder, w.order.id)
    sent_at = datetime.fromisoformat(sent_row["sentDateTime"].replace("Z", "+00:00"))
    assert corr.status == M.CorrespondenceStatus.SENT and corr.occurred_at == sent_at
    assert corr.recipients == [w.to] and corr.sender == mbx.mailbox
    assert order.status == M.StopOrderStatus.SENT and order.sent_at == sent_at
    assert order.sent_via == "email (investigations mailbox)" and order.response_due_at == sent_at + timedelta(days=7)
    (mm,) = _rows(db, mbx.mailbox)
    assert (mm.direction, mm.status, mm.folder, mm.outside_sent) == (M.MailDirection.OUT, M.MailStatus.SENT_EXTERNAL,
                                                                       "sentitems", True)
    assert mm.correspondence_id == corr.id and mm.letter_key == f"o{order.id}" and mm.provider_message_id == sent_pid
    assert mm.graph_conversation_id == f"conv-{w.tag}" and mm.authority_key == f"entity-{w.entity.id}"
    item = db.get(M.EvidenceItem, mm.eml_evidence_id)
    assert item.classification == M.Classification.R3 and item.sha256 == hashlib.sha256(raw).hexdigest()
    assert corr.evidence_item_id == item.id
    # the authority's reply threads against the Sent Items copy and is filed on the letter
    reply = eml(from_=w.to, to=mbx.mailbox, subject=f"RE: {w.subject}", body="We have placed a hold.",
                in_reply_to=mm.message_id, headers=_auth(w.domain))
    mbx.fake.add("inbox", reply, at=NOW)
    second = mbx.sync(db)
    assert second.received == 1, second
    db.expire_all()
    filed = db.scalars(select(M.MailMessage).where(M.MailMessage.mailbox == mbx.mailbox,
                                                   M.MailMessage.direction == M.MailDirection.IN)).one()
    reply_corr = db.get(M.Correspondence, filed.correspondence_id)
    assert reply_corr.in_reply_to_id == corr.id and db.get(M.StopOrder, w.order.id).responded_at is not None


def test_tagged_sent_item_names_its_letter(db, mbx):
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=f"desk@{w.domain}", subject=f"Something else [Aegis "
                                  f"{w.case.reference} #{w.corr.id}]"), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["recorded"] == 1, report
    db.expire_all()
    assert db.get(M.Correspondence, w.corr.id).status == M.CorrespondenceStatus.SENT


def test_ambiguous_sent_item_is_logged_for_review(db, mbx):
    w = make_case(db, second_order=True)  # two draft letters, same subject and recipient
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body="Please act."), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["logged"] == 1 and report.sent["recorded"] == 0, report
    db.expire_all()
    assert db.get(M.StopOrder, w.order.id).status == M.StopOrderStatus.DRAFT
    assert db.get(M.StopOrder, w.order2.id).status == M.StopOrderStatus.DRAFT
    assert db.get(M.Correspondence, w.corr.id).status == M.CorrespondenceStatus.DRAFT
    (mm,) = _rows(db, mbx.mailbox)
    assert mm.meta["needs_review"] is True and "letters match" in mm.meta["review_reason"]
    assert mm.letter_key is None and mm.eml_evidence_id
    logged = db.get(M.Correspondence, mm.correspondence_id)
    assert logged.direction == M.CorrespondenceDirection.OUT and logged.entity_id == w.entity.id
    assert logged.meta["needs_review"] is True and logged.meta["source"] == "mailbox_sent" and logged.due_at is None
    assert sorted(mm.meta["candidates"]) == sorted([f"c{w.corr.id}", f"o{w.order2.id}"])


def test_sent_item_matching_no_letter_is_logged_for_review(db, mbx):
    """It cites the case (a traced wallet) but matches no letter: stored on the case for review."""
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=f"legal@{w.domain}", subject="Meeting next week",
                                  body=f"Can we talk on Tuesday about {w.case.reference}?"), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["logged"] == 1, report
    (mm,) = _rows(db, mbx.mailbox)
    assert mm.meta["review_reason"] == "no letter of the case matches" and mm.case_id == w.case.id
    db.expire_all()
    assert db.get(M.Correspondence, w.corr.id).status == M.CorrespondenceStatus.DRAFT


def _no_trace_on_the_case(db, w, mm):
    assert mm.case_id is None and mm.correspondence_id is None and mm.eml_evidence_id is None
    assert mm.mime_sha256 is None and mm.mime_path is None and mm.body_text is None
    assert mm.to_addrs == [] and mm.cc_addrs == [] and mm.in_reply_to is None
    assert mm.meta["metadata_only"] and mm.meta["needs_review"]
    assert db.scalars(select(M.EvidenceItem).where(M.EvidenceItem.case_id == w.case.id)).all() == []
    assert db.scalars(select(M.Correspondence).where(M.Correspondence.case_id == w.case.id,
                                                     M.Correspondence.id != w.corr.id)).all() == []


def test_sent_item_to_an_authority_domain_about_another_matter_keeps_metadata_only(db, mbx):
    """Another client's matter, sent to someone on the authority's domain, citing nothing of the case: only
    subject, recipient domains and date are kept; nothing reaches the case; the authority's authenticated
    reply in that thread is not filed on the case either."""
    w = make_case(db)
    raw = eml(from_=mbx.mailbox, to=f"kyc-team@{w.domain}", subject="Other client matter: account closure",
              body="Dear team, please close the account of our client (account 4471-2290-18). Regards.")
    mbx.fake.add("sentitems", raw, at=RECENT)
    report = mbx.sync(db)
    assert report.sent["metadata_only"] == 1 and report.sent["logged"] == 0, report
    (mm,) = _rows(db, mbx.mailbox)
    _no_trace_on_the_case(db, w, mm)
    assert mm.meta["recipient_domains"] == [w.domain] and mm.meta["candidate_case_ids"] == [w.case.id]
    assert mm.subject == "Other client matter: account closure"
    sent_id = str(BytesParser(policy=policy.default).parsebytes(raw)["Message-ID"])
    reply = eml(from_=f"kyc-team@{w.domain}", to=mbx.mailbox, subject="RE: Other client matter: account closure",
                body="We have frozen 5000 USDT on that account.", in_reply_to=sent_id, headers=_auth(w.domain))
    mbx.fake.add("inbox", reply, at=NOW)
    second = mbx.sync(db)
    assert second.received == 0 and second.needs_review == 0, second
    db.expire_all()
    filed = db.scalars(select(M.MailMessage).where(M.MailMessage.mailbox == mbx.mailbox,
                                                   M.MailMessage.direction == M.MailDirection.IN)).all()
    assert all(r.case_id is None and r.correspondence_id is None for r in filed)
    from app.blocks import status as bs

    assert [r.key for r in bs.case_blocks(db, db.get(M.Case, w.case.id))] == [f"o{w.order.id}"]


def test_personal_mail_to_an_officers_exact_free_mail_address_keeps_metadata_only(db, mbx):
    w = make_case(db)
    officer = f"officer.{w.tag}@{FREEMAIL}"
    db.add(M.LEContact(case_id=w.case.id, agency="Demo City Police (demo)", name="Officer (demo)", email=officer))
    db.commit()
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=officer, subject="Dinner Friday?",
                                  body="Are you free on Friday evening?"), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["metadata_only"] == 1 and report.sent["logged"] == 0, report
    (mm,) = _rows(db, mbx.mailbox)
    _no_trace_on_the_case(db, w, mm)
    assert mm.meta["recipient_domains"] == [FREEMAIL]


def test_sent_item_to_an_authority_matching_its_letter_is_still_recorded(db, mbx):
    """Recipient-only, but the letter matches (subject and To): recorded in full as before."""
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body="Please see the attached."),
                 at=RECENT)
    report = mbx.sync(db)
    assert report.sent["recorded"] == 1, report


def test_sent_item_citing_a_wallet_to_an_unknown_recipient_is_case_related(db, mbx):
    w = make_case(db)
    pid = mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to="analyst@newvasp-mbx-demo.example",
                                        subject="Question", body=f"Did {w.wallet} deposit with you?"), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["not_related"] == 0 and mbx.fake.downloads(pid) == 1, report
    (mm,) = _rows(db, mbx.mailbox)
    assert mm.case_id == w.case.id and mm.match_method == "cited" and mm.meta["needs_review"]


def test_reply_from_the_mailbox_is_not_taken_for_the_letter(db, mbx):
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=f"RE: {w.subject}", body=w.wallet), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["logged"] == 1 and report.sent["recorded"] == 0, report
    db.expire_all()
    assert db.get(M.Correspondence, w.corr.id).status == M.CorrespondenceStatus.DRAFT


def test_inbox_copy_of_a_letter_never_marks_it_sent(db, mbx):
    w = make_case(db)
    mbx.fake.add("inbox", eml(from_=mbx.mailbox, to=w.to, cc=mbx.mailbox,
                              subject=f"{w.subject} [Aegis {w.case.reference} #{w.corr.id}]", body=w.wallet), at=RECENT)
    mbx.fake.add("inbox", eml(from_=f"someone@{w.domain}", to=mbx.mailbox, cc=w.to,
                              subject=f"{w.subject} [Aegis {w.case.reference} #{w.corr.id}]", body=w.wallet), at=RECENT)
    report = mbx.sync(db)
    assert report.errors == 0, report
    db.expire_all()
    assert db.get(M.Correspondence, w.corr.id).status == M.CorrespondenceStatus.DRAFT
    assert db.get(M.StopOrder, w.order.id).status == M.StopOrderStatus.DRAFT
    assert all(r.direction == M.MailDirection.IN for r in _rows(db, mbx.mailbox))


def test_letter_already_marked_sent_is_linked_not_changed(db, mbx):
    from app.domain import correspondence as desk

    w = make_case(db)
    marked = datetime(2026, 10, 10, 9, 0, tzinfo=UTC)
    desk.mark_sent(db, w.case, w.corr, actor=None, sent_at=marked, channel="email")
    raw = eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=w.wallet)
    mbx.fake.add("sentitems", raw, at=RECENT)
    report = mbx.sync(db)
    assert report.sent["linked"] == 1, report
    db.expire_all()
    corr = db.get(M.Correspondence, w.corr.id)
    assert corr.occurred_at == marked and db.get(M.StopOrder, w.order.id).sent_at == marked
    (mm,) = _rows(db, mbx.mailbox)
    assert mm.correspondence_id == corr.id and mm.letter_key == f"o{w.order.id}" and mm.meta["sent_time_differs"]


def test_idempotent_backfill_records_once(db, mbx, client_for, monkeypatch):
    w = make_case(db)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=w.wallet), at=RECENT)
    mbx.fake.add("inbox", eml(from_=w.to, to=mbx.mailbox, subject=f"About {w.case.reference}"), at=RECENT)
    first = mbx.sync(db)
    assert first.sent["recorded"] == 1 and first.needs_review == 1, first
    n_rows = len(_rows(db, mbx.mailbox))
    n_evidence = len(db.scalars(select(M.EvidenceItem).where(M.EvidenceItem.case_id == w.case.id)).all())
    ingest.request_backfill(db, mbx.mailbox, datetime(2026, 10, 1, tzinfo=UTC))
    assert all(s.delta_link is None for s in ingest.folder_states(db, mbx.mailbox).values())
    again = mbx.sync(db, trigger="backfill")
    assert again.duplicates == 1 and again.sent["duplicates"] == 1 and again.sent["recorded"] == 0, again
    assert len(_rows(db, mbx.mailbox)) == n_rows
    assert len(db.scalars(select(M.EvidenceItem).where(M.EvidenceItem.case_id == w.case.id)).all()) == n_evidence
    # the database refuses a second row for the same message in the same folder
    mm = next(r for r in _rows(db, mbx.mailbox) if r.folder == "sentitems")
    dup = M.MailMessage(direction=M.MailDirection.OUT, status=M.MailStatus.SENT_EXTERNAL, transport="graph",
                        mailbox=mbx.mailbox, message_id=mm.message_id, internet_message_id=mm.internet_message_id,
                        folder="sentitems", to_addrs=[], cc_addrs=[], attachments=[], match={}, meta={})
    db.add(dup)
    with pytest.raises(Exception):  # noqa: B017 - IntegrityError, whatever the driver wraps it in
        db.commit()
    db.rollback()


def test_message_aegis_sent_itself_is_known(db, mbx):
    w = make_case(db)
    mid = f"<aegis.{uuid.uuid4().hex}@athena-mbx-demo.example>"
    own = M.MailMessage(case_id=w.case.id, correspondence_id=w.corr.id, direction=M.MailDirection.OUT,
                        status=M.MailStatus.SENT, transport="graph", mailbox=mbx.mailbox, message_id=mid,
                        internet_message_id=mid, to_addrs=[w.to], cc_addrs=[], attachments=[], match={}, meta={})
    db.add(own)
    db.commit()
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"], msg["Message-ID"] = mbx.mailbox, w.to, w.subject, mid
    msg.set_content("letter")
    mbx.fake.add("sentitems", msg.as_bytes(policy=policy.SMTP), at=RECENT, conversation="conv-own")
    report = mbx.sync(db)
    assert report.sent["known"] == 1 and report.sent["recorded"] == 0, report
    db.refresh(own)
    assert own.graph_conversation_id == "conv-own" and len(_rows(db, mbx.mailbox)) == 1


# --------------------------------------------------------------------------- matching helpers
def test_case_index_rules(db):
    w = make_case(db)
    idx = matching.build_index(db, mailbox="investigations@athena-mbx-demo.example")
    mat = idx.cases[w.case.id]
    assert w.to in mat.authorities[f"entity-{w.entity.id}"].addresses
    assert w.domain in mat.authorities[f"entity-{w.entity.id}"].domains
    assert matching.norm_token(w.wallet.upper().replace("0X", "0x")) in mat.tokens
    assert idx.address_matches([f"anyone@sub.{w.domain}"]) == [(w.case.id, f"entity-{w.entity.id}")]
    assert idx.address_matches([f"x@{FREEMAIL}", "y@athena-mbx-demo.example"]) == []
    assert w.case.id in idx.citing(f"Ref {w.case.reference.lower()}", "")
    assert w.case.id not in idx.citing(f"Ref {w.case.reference}X", "")
    assert matching.is_reply_subject("RE: AW: x") and not matching.is_reply_subject("Follow-up: x")
    assert matching.normalise_subject("Re: URGENT – Hold [Aegis MBX-1 #2]") == "urgent - hold"


# --------------------------------------------------------------------------- admin page, scheduler
def test_admin_mailbox_page_and_backfill(db, mbx, client_for, monkeypatch):
    make_case(db)
    for k, v in {"AEGIS_MAIL_TRANSPORT": "graph", "AEGIS_MAIL_FROM": mbx.mailbox, "AEGIS_MAIL_INBOUND": "on",
                 "AEGIS_MAIL_INBOUND_SINCE": SINCE, "AEGIS_M365_TENANT_ID": "00000000-0000-0000-0000-000000000000",
                 "AEGIS_M365_CLIENT_ID": "00000000-0000-0000-0000-000000000001",
                 "AEGIS_M365_CLIENT_SECRET": "test-client-secret-not-real"}.items():
        monkeypatch.setenv(k, v)
    real = ingest.sync_mailbox
    monkeypatch.setattr(ingest, "sync_mailbox", lambda db, **kw: real(db, **{**kw, "transport": mbx.transport()}))
    admin = client_for(None, system_admin=True, email="sysadmin-mbx-page@tests.example")
    page = admin.get("/admin/mail/mailbox")
    assert page.status_code == 200 and "Sent Items" in page.text and "Backfill since this date" in page.text
    assert 'value="2026-10-01"' in page.text and "deltatoken" not in page.text
    token = csrf_token(admin, "/admin/mail/mailbox")
    bad = admin.post("/admin/mail/mailbox/backfill", data={"csrf_token": token, "since": "2026-10-01"})
    assert bad.status_code == 400 and "Tick the confirmation" in bad.text
    ok = admin.post("/admin/mail/mailbox/backfill", data={"csrf_token": token, "since": "2026-10-01", "confirm": "1"})
    assert ok.status_code == 200 and "backfill started" in ok.text, ok.text[:2000]
    assert mbx.fake.filters["sentitems"] == ["receivedDateTime ge 2026-10-01T00:00:00Z"]
    ev = db.scalars(select(M.AuditEvent).where(M.AuditEvent.action == "MAIL_BACKFILL")
                    .order_by(M.AuditEvent.id.desc())).first()
    assert ev.detail["since"] == "2026-10-01"
    now = admin.post("/admin/mail/mailbox/sync", data={"csrf_token": token})
    assert now.status_code in (200, 429)
    nobody = client_for("admin", case=None, email="not-sysadmin-mbx@tests.example")
    assert nobody.get("/admin/mail/mailbox").status_code == 403


def test_scheduler_reads_the_mailbox_every_sync_minutes(db, mbx, monkeypatch):
    from scripts import run_scheduler

    settings = mbx.settings()
    assert run_scheduler.mail_sync_due(db, settings)  # never synced
    mbx.sync(db)
    monkeypatch.setenv("AEGIS_MAIL_SYNC_MINUTES", "15")
    assert not run_scheduler.mail_sync_due(db, settings)
    assert run_scheduler.mail_sync_due(db, settings, now=datetime.now(tz=UTC) + timedelta(minutes=16))
    monkeypatch.setenv("AEGIS_MAIL_SYNC_MINUTES", "60")
    assert not run_scheduler.mail_sync_due(db, settings, now=datetime.now(tz=UTC) + timedelta(minutes=16))
    monkeypatch.setenv("AEGIS_MAIL_SYNC_MINUTES", "nonsense")
    assert run_scheduler.mail_sync_minutes() == 15


def test_pages_render_rows_found_in_sent_items(db, mbx, client_for):
    """The case's e-mail page, the authority page and the timeline entry render a recorded and a logged row."""
    w = make_case(db, second_order=True)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body="Please act."), at=RECENT)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=f"Freeze request [Aegis {w.case.reference} #{w.corr.id}]",
                                  body=w.wallet), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["logged"] == 1 and report.sent["recorded"] == 1, report
    c = client_for("admin", case=w.case, email=f"admin-{w.tag}@tests.example")
    shown = []
    for mm in _rows(db, mbx.mailbox):
        assert c.get(f"/cases/{w.case.id}/mail/messages/{mm.id}").status_code == 200
        entry = c.get(f"/cases/{w.case.id}/authorities/correspondence/{mm.correspondence_id}")
        assert entry.status_code == 200 and "mail-ext-banner" not in entry.text  # our own message, not external mail
        shown.append("mail-sent-review" in entry.text if mm.meta.get("needs_review") else "mail-sent-found" in entry.text)
    assert shown == [True, True]
    assert c.get(f"/cases/{w.case.id}/authorities/entity-{w.entity.id}").status_code == 200


def test_draft_stop_order_without_a_letter_row_is_recorded(db, mbx):
    w = make_case(db)
    db.delete(w.corr)  # a generated stop order, never opened on the desk
    db.commit()
    db.expire_all()  # (the session keeps loaded collections across commits)
    mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=w.to, subject=w.subject, body=f"Freeze {w.wallet}"), at=RECENT)
    report = mbx.sync(db)
    assert report.sent["recorded"] == 1, report
    db.expire_all()
    order = db.get(M.StopOrder, w.order.id)
    assert order.status == M.StopOrderStatus.SENT and order.sent_via == "email (investigations mailbox)"
    (mm,) = _rows(db, mbx.mailbox)
    corr = db.get(M.Correspondence, mm.correspondence_id)
    assert corr.stop_order_id == order.id and corr.status == M.CorrespondenceStatus.SENT
    assert corr.recipients == [w.to] and corr.evidence_item_id == mm.eml_evidence_id


def test_sent_item_to_an_authority_of_two_open_cases_keeps_metadata_only(db, mbx):
    a, b = make_case(db), make_case(db)
    shared = f"compliance@shared-{a.tag}-demo.example"
    for w in (a, b):
        w.order.recipient_email = shared
    db.commit()
    pid = mbx.fake.add("sentitems", eml(from_=mbx.mailbox, to=shared, subject="Hello", body="General question."),
                       at=RECENT)
    report = mbx.sync(db)
    assert report.sent["metadata_only"] == 1, report
    (mm,) = _rows(db, mbx.mailbox)
    assert mm.case_id is None and mm.eml_evidence_id is None and mm.mime_sha256 is None and mm.correspondence_id is None
    assert mm.meta["metadata_only"] and sorted(mm.meta["candidate_case_ids"]) == sorted([a.case.id, b.case.id])
    assert mbx.fake.downloads(pid) == 1  # read once to decide, never stored
