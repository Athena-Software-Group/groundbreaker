"""Block status (app.blocks.status / report, app/web/routes_blocks.py): status derivation and next actions,
Confirm status and its role gating, the report exports, notifications, the on-chain issuer readings, the
Overview card, the Authorities column and the /block-status skill. Offline: no model, no mail, no chain."""

import csv
import io
import re
import zipfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from conftest import csrf_token, ungated
from sqlalchemy import select

from app.ai import providers
from app.blocks import classify_rules as R
from app.blocks import report
from app.blocks import status as bs
from app.db.models import (
    AuditEvent,
    Correspondence,
    CorrespondenceDirection,
    Entity,
    FreezeCheck,
    MailDirection,
    MailMessage,
    MailStatus,
    Notification,
    ReplyClassification,
    ReplySource,
    StopOrder,
    StopOrderStatus,
)
from app.domain import correspondence as desk

# A Circle-style legacy-inbox auto-reply (synthetic, demo addresses)
CIRCLE_LIKE = ("This is an automated response. Please note that compliance@kucoin-demo.example is a legacy inbox and "
               "is no longer monitored. Please contact the following:\nFreeze requests: "
               "asset-freeze@kucoin-demo.example\nLegal process: legal-process@kucoin-demo.example")
FROZEN = ("Dear Investigator, further to your request we can confirm that the funds have been frozen. "
          "A total of 12,633.77 USDT is currently held on the account.")


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


@pytest.fixture
def case(db, tmp_path):
    """A fresh copy of the demo case per test (its own reference): replies, confirmations and stop-order
    changes of one test never reach another."""
    yield fresh_case(db, tmp_path)


def fresh_case(db, tmp_path):
    import json
    import uuid

    from conftest import TEST_FIXTURE  # the demo fixture with its workspace clock kept current

    from app.services import seed_from_fixture

    data = json.loads(TEST_FIXTURE.read_text(encoding="utf-8"))
    data["case"]["reference"] = f"BLK-{uuid.uuid4().hex[:8].upper()}"
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return seed_from_fixture(db, path)


def _order(case, name: str) -> StopOrder:
    return next(o for o in case.stop_orders if o.entity is not None and o.entity.name == name
                and o.status != StopOrderStatus.SUPERSEDED)


def _authority(db, case, order):
    return desk.get_authority(db, case, f"entity-{order.entity_id}")


def _reply(db, case, order, text, *, at=None, subject="RE: Urgent request", mailbox=False, auto=False):
    at = at or (order.sent_at.replace(tzinfo=UTC) + timedelta(days=1))
    corr = desk.log_entry(db, case, _authority(db, case, order), actor=None, direction="in", channel="email",
                          kind="reply", subject=subject, body=text, body_format="text", occurred_at=at,
                          stop_order=order, classification="R3")
    meta = dict(corr.meta or {})
    if mailbox:
        mm = MailMessage(case_id=case.id, correspondence_id=corr.id, direction=MailDirection.IN,
                         status=MailStatus.RECEIVED, transport="file", mailbox="investigations@athena-demo.example",
                         message_id=f"<reply-{corr.id}@exchange-demo.example>", subject=subject,
                         from_addr="compliance@exchange-demo.example", received_at=at)
        db.add(mm)
        db.flush()
        meta.update(source="mailbox", untrusted_external=True, mail_message_id=mm.id, auto_reply=auto,
                    sender_domain_ok=True)
    corr.meta = meta
    db.commit()
    return corr


class _Access:
    """Enough of a CaseAccess for report.row_view: an investigator (no masking)."""

    is_external = False
    user = None

    def can(self, _perm: str) -> bool:
        return True

    def at_least(self, _role) -> bool:
        return True


def _row(db, case, key, **kw) -> bs.BlockRow:
    db.expire_all()  # routes write through their own session
    row = bs.find_row(bs.case_blocks(db, case, **kw), key)
    assert row is not None, key
    return row


def _notes(db, case):
    return db.scalars(select(Notification).where(Notification.case_id == case.id,
                                                 Notification.event_type == "block_status_changed")
                      .order_by(Notification.id)).all()


# --------------------------------------------------------------------------- derivation
def test_demo_case_rows_and_the_rainbet_auto_acknowledgement(db, case):
    rows = bs.case_blocks(db, case)
    assert {r.authority.name for r in rows} >= {"Rainbet", "KuCoin", "SWFT / Bridgers", "Hostinger"}
    rb = next(r for r in rows if r.authority.name == "Rainbet")
    assert rb.status == R.ACKNOWLEDGED and rb.source == "rules" and rb.ticket
    assert not rb.needs_confirmation  # an acknowledgement can be confirmed, but is not flagged "to confirm"
    assert "wait" == rb.next_action["kind"]
    ku = next(r for r in rows if r.authority.name == "KuCoin")
    assert ku.status == bs.AWAITING and ku.requested_at is not None
    assert rb.to  # the address the letter went to


def test_redirect_reply_gives_resend_address_then_awaiting_after_resend(db, case):
    order = _order(case, "KuCoin")
    order.recipient_email = "compliance@kucoin-demo.example"  # the legacy inbox the reply names
    db.commit()
    reply = _reply(db, case, order, CIRCLE_LIKE)
    row = _row(db, case, f"o{order.id}")
    assert row.status == R.REDIRECTED
    assert row.resend_to == "asset-freeze@kucoin-demo.example"
    assert "resend to asset-freeze@kucoin-demo.example" in row.status_text
    assert row.next_action["kind"] == "resend" and "asset-freeze@kucoin-demo.example" in row.next_action["text"]
    assert row.days_waiting is not None
    # a follow-up letter linked to the stop order, sent after the redirect: awaiting again
    a = _authority(db, case, order)
    follow = desk.log_entry(db, case, a, actor=None, direction="out", channel="email", kind="status_request",
                            subject="Follow-up to the new address", body="Resent.", stop_order=order,
                            occurred_at=reply.occurred_at.replace(tzinfo=UTC) + timedelta(hours=2),
                            recipients=["asset-freeze@kucoin-demo.example"], due_days=7)
    assert follow.id
    row = _row(db, case, f"o{order.id}")
    assert row.status == bs.AWAITING and row.resent and row.source == "resent"
    # the request now sits with the new address: shown with the resend's date; the desk's reply clock
    assert row.to == ["asset-freeze@kucoin-demo.example"] and row.first_to == ["compliance@kucoin-demo.example"]
    assert row.resent_at == follow.occurred_at.replace(tzinfo=UTC)
    # the desk's date: the stop order has a response, so the follow-up's clock (as the desk's due list shows)
    assert row.due_at == follow.due_at.replace(tzinfo=UTC)
    # a redirect logged as an automatic-reply note (no response recorded): the stop order's own reply date
    db.refresh(order)
    order.responded_at = None
    db.commit()
    assert _row(db, case, f"o{order.id}").due_at == desk.response_due(order, 7)
    view = report.row_view(row, _Access(), case)
    assert view["source_text"].startswith("resent ") and "asset-freeze@kucoin-demo.example" in view["source_text"]
    assert "read from the reply" not in view["source_text"]
    assert "Sent again on" in row.next_action["text"]


def test_frozen_reply_suggests_frozen_with_amount_to_confirm(db, case):
    order = _order(case, "SWFT / Bridgers")
    _reply(db, case, order, FROZEN)
    row = _row(db, case, f"o{order.id}")
    # a person confirms every positive outcome: the rules' reading is a suggestion, the status stays non-positive
    assert row.status == R.UNCLEAR and row.amount is None and row.source == "rules"
    assert row.suggestion["status"] == R.FROZEN and (row.suggestion["amount"], row.suggestion["asset"]) == (
        "12633.77", "USDT") and row.suggestion["source"] == "rules" and row.suggestion["warnings"] == []
    assert row.needs_confirmation and row.needs_review and row.next_action["kind"] == "confirm"
    assert row.status_text == "Reply suggests Frozen (12,633.77 USDT): confirm"
    assert row.detail == "Reply suggests: Frozen (12,633.77 USDT) — confirm"
    assert bs.summary(bs.case_blocks(db, case))["frozen"] == {}  # counts in no total
    assert order.status == StopOrderStatus.SENT  # advisory: nothing changed on the stop order


def test_le_process_required_points_to_the_le_authorities(db, case):
    order = _order(case, "KuCoin")
    _reply(db, case, order, "Please submit via our law enforcement portal (Kodex). We require a valid court order.")
    row = _row(db, case, f"o{order.id}")
    assert row.status == R.LE_PROCESS_REQUIRED
    # (the playbook release: the LE brief, linked to this request, replaces the generic LE cover letter)
    assert row.next_action["kind"] == "le" and "template=le_brief" in row.next_action["href"]
    assert f"ref=o{order.id}" in row.next_action["href"] and row.path_step == "le_only_redirect"
    assert "Carabinieri" in row.next_action["text"] or "IC3" in row.next_action["text"]


def test_overdue_and_status_request_next_action(db, case):
    order = _order(case, "Hostinger")
    later = order.sent_at.replace(tzinfo=UTC) + timedelta(days=30)
    row = _row(db, case, f"o{order.id}", now=later)
    assert row.overdue and row.days_waiting == 30
    assert row.next_action["kind"] == "chase" and "template=status_request" in row.next_action["href"]


def test_auto_reply_never_hides_an_earlier_outcome(db, case, client_for):
    order = _order(case, "SWFT / Bridgers")
    first = _reply(db, case, order, FROZEN)
    _reply(db, case, order, "I am out of the office until Monday.", at=first.occurred_at.replace(tzinfo=UTC)
           + timedelta(hours=3))
    row = _row(db, case, f"o{order.id}")
    # the suggested outcome stays on the request (to confirm) behind a later auto-reply
    assert row.suggestion["status"] == R.FROZEN and "suggests Frozen (12,633.77 USDT)" in row.status_text
    inv = client_for("investigator", case=case, email="inv-autohide@tests.example")
    assert inv.post(f"/cases/{case.id}/blocks/o{order.id}/confirm", data={
        "status": "frozen", "reply_id": str(first.id), "amount": "12633.77", "asset": "USDT",
        "csrf_token": csrf_token(inv, f"/cases/{case.id}/blocks")}).status_code == 200
    row = _row(db, case, f"o{order.id}")
    assert row.status == R.FROZEN and row.source == "human" and row.suggestion is None  # a person's outcome stays


def test_draft_is_not_sent(db, case):
    a = desk.get_authority(db, case, f"entity-{_order(case, 'Groq').entity_id}")
    with ungated():  # the demo already asked Groq: a draft's row is under test
        corr = desk.generate_letter(db, case, a, "info_request", actor=None)
    row = _row(db, case, f"c{corr.id}")
    assert row.status == bs.NOT_SENT and row.next_action["kind"] == "send"


def test_recorded_status_wins_over_an_older_reply(db, case, client_for):
    order = _order(case, "KuCoin")
    _reply(db, case, order, "We have received your request and are reviewing it.")
    desk.record_stop_order_status(db, case, order, "declined", actor=None)
    row = _row(db, case, f"o{order.id}")
    assert row.status == R.DECLINED and row.source == "recorded" and not row.needs_confirmation


# --------------------------------------------------------------------------- confirm & role gating
def test_confirm_role_gating_and_apply(db, case, client_for):
    order = _order(case, "SWFT / Bridgers")
    reply = _reply(db, case, order, FROZEN)
    key = f"o{order.id}"
    url = f"/cases/{case.id}/blocks/{key}/confirm"
    form = {"status": "frozen", "reply_id": str(reply.id), "amount": "12633.77", "asset": "USDT"}

    ro = client_for("read_only", case=case, email="ro-blocks@tests.example")
    assert ro.post(url, data={**form, "csrf_token": csrf_token(ro, f"/cases/{case.id}/blocks")}).status_code == 403

    inv = client_for("investigator", case=case, email="inv-blocks@tests.example")
    tok = csrf_token(inv, f"/cases/{case.id}/blocks")
    assert inv.post(url, data=form).status_code == 403  # no CSRF token
    r = inv.post(url, data={**form, "apply": "1", "csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 403  # investigators propose; only a case admin applies
    db.refresh(order)
    assert order.status == StopOrderStatus.SENT
    r = inv.post(url, data={**form, "csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303 and "msg=proposed" in r.headers["location"]
    db.expire_all()
    assert db.get(StopOrder, order.id).status == StopOrderStatus.SENT
    row = _row(db, case, key)
    assert row.status == R.FROZEN and row.proposal is not None and row.needs_confirmation
    note = db.scalars(select(Correspondence).where(Correspondence.stop_order_id == order.id,
                                                   Correspondence.direction == CorrespondenceDirection.NOTE)
                      .order_by(Correspondence.id.desc())).first()
    assert note.subject.startswith("Block status proposed: Frozen")
    assert _notes(db, case)[-1].payload["confirmed"] is True

    admin = client_for("admin", case=case, email="admin-blocks@tests.example")
    tok = csrf_token(admin, f"/cases/{case.id}/blocks")
    r = admin.post(url, data={**form, "apply": "1", "csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303 and "msg=applied" in r.headers["location"]
    db.expire_all()
    order = db.get(StopOrder, order.id)
    assert order.status == StopOrderStatus.FROZEN
    assert Decimal(desk.hold_state(order)["amount"]) == Decimal("12633.77") and desk.hold_state(order)["asset"] == "USDT"
    row = _row(db, case, key)
    assert row.status == R.FROZEN and row.source == "recorded" and not row.needs_confirmation
    n = _notes(db, case)[-1]
    assert n.payload["applied"] is True and n.severity == "high" and "12,633.77 USDT" in n.title
    assert "SWFT" not in n.title and "SWFT" not in (n.body or "")  # no counterparty names in events
    audits = db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id, AuditEvent.object_type == "block_status")
                        .order_by(AuditEvent.id)).all()
    assert [a.outcome for a in audits][-3:] == ["denied", "allowed", "allowed"]
    assert audits[-1].detail["applied"] is True and "quote" not in str(audits[-1].detail)


def test_funds_returned_needs_a_frozen_order(db, case, client_for):
    order = _order(case, "KuCoin")
    reply = _reply(db, case, order, "The funds have been returned to the originating wallet (500 USDT).")
    admin = client_for("admin", case=case, email="admin2-blocks@tests.example")
    tok = csrf_token(admin, f"/cases/{case.id}/blocks")
    r = admin.post(f"/cases/{case.id}/blocks/o{order.id}/confirm", data={
        "status": "funds_returned", "reply_id": str(reply.id), "apply": "1", "csrf_token": tok})
    assert r.status_code == 409 and "frozen" in r.text
    db.expire_all()
    assert db.get(StopOrder, order.id).status == StopOrderStatus.SENT


def test_confirm_non_order_status_is_recorded_on_the_timeline(db, case, client_for):
    order = _order(case, "KuCoin")
    reply = _reply(db, case, order, "Some long reply nobody can classify.")
    inv = client_for("investigator", case=case, email="inv2-blocks@tests.example")
    tok = csrf_token(inv, f"/cases/{case.id}/blocks")
    r = inv.post(f"/cases/{case.id}/blocks/o{order.id}/confirm",
                 data={"status": "le_process_required", "reply_id": str(reply.id), "csrf_token": tok},
                 follow_redirects=False)
    assert r.status_code == 303 and "msg=confirmed" in r.headers["location"]
    row = _row(db, case, f"o{order.id}")
    assert row.status == R.LE_PROCESS_REQUIRED and row.source == "human" and not row.needs_confirmation
    assert bad_status(inv, case, order, tok).status_code == 400


def bad_status(client, case, order, tok):
    return client.post(f"/cases/{case.id}/blocks/o{order.id}/confirm", data={"status": "mark-as-frozen",
                                                                             "csrf_token": tok})


def test_page_access(db, case, client_for):
    assert client_for(None, case=case, email="nobody-blocks@tests.example").get(
        f"/cases/{case.id}/blocks").status_code == 404
    assert client_for("external", case=case, email="ext-blocks@tests.example").get(
        f"/cases/{case.id}/blocks").status_code == 403
    ro = client_for("read_only", case=case, email="ro2-blocks@tests.example")
    page = ro.get(f"/cases/{case.id}/blocks")
    assert page.status_code == 200 and "Block status" in page.text
    assert "bk-confirm-form" not in page.text and "Classify replies now" not in page.text
    assert "<script>" not in page.text  # CSP: no inline scripts


def test_filters(db, case, client_for):
    order = _order(case, "SWFT / Bridgers")
    _reply(db, case, order, FROZEN)
    adm = client_for("admin", case=case, email="admin3-blocks@tests.example")
    page = adm.get(f"/cases/{case.id}/blocks?status=resolved")
    assert page.status_code == 200 and "SWFT" not in page.text  # a suggested freeze resolves nothing
    page = adm.get(f"/cases/{case.id}/blocks?status=action")
    assert page.status_code == 200 and "SWFT" in page.text
    page = adm.get(f"/cases/{case.id}/blocks?status=bogus&type=exchange")
    assert page.status_code == 200 and "KuCoin" in page.text and "Hostinger" not in page.text


# --------------------------------------------------------------------------- report exports
def test_exports_contents_and_masking(db, case, client_for):
    order = _order(case, "SWFT / Bridgers")
    _reply(db, case, order, FROZEN)
    _reply(db, case, _order(case, "KuCoin"), "=HYPERLINK(\"http://evil.example\") We have received your request.")
    inv = client_for("investigator", case=case, email="inv3-blocks@tests.example")
    r = inv.get(f"/cases/{case.id}/blocks/export.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"] and case.reference in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    sw = next(x for x in rows if x["authority"] == "SWFT / Bridgers")
    assert sw["status"] == "Reply received" and sw["amount"] == "" and sw["needs_confirmation"] == "yes"
    assert sw["suggested_outcome"] == "Frozen (12,633.77 USDT) (read by the rules, not confirmed)"
    assert "funds have been frozen" in sw["evidence_quote"]
    assert all(not v.startswith(("=", "+", "@")) for x in rows for v in x.values())  # formula injection
    md = inv.get(f"/cases/{case.id}/blocks/export.md")
    assert md.status_code == 200 and md.text.startswith("# Block status — ") and "Frozen (12,633.77 USDT)" in md.text
    assert "Suggested outcome (not confirmed): Frozen (12,633.77 USDT)" in md.text and "Held / frozen" not in md.text
    assert "advisory" in md.text and "funds have been frozen" in md.text
    docx = inv.get(f"/cases/{case.id}/blocks/export.docx")
    assert docx.status_code == 200
    with zipfile.ZipFile(io.BytesIO(docx.content)) as z:
        xml = z.read("word/document.xml").decode()
    assert "Block status" in xml and "SWFT" in xml
    assert inv.get(f"/cases/{case.id}/blocks/export.pdf").status_code == 404
    ro = client_for("read_only", case=case, email="ro3-blocks@tests.example")
    ro_csv = ro.get(f"/cases/{case.id}/blocks/export.csv").text
    assert "funds have been frozen" not in ro_csv  # reply text is R3
    ex = db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id, AuditEvent.action == "EXPORT",
                                             AuditEvent.object_type == "block_status")).all()
    assert {e.detail["format"] for e in ex} >= {"csv", "md", "docx"}


def test_api_json(db, case, client_for):
    _reply(db, case, _order(case, "SWFT / Bridgers"), FROZEN)
    r = client_for("read_only", case=case, email="ro4-blocks@tests.example").get(f"/api/cases/{case.id}/blocks")
    assert r.status_code == 200
    data = r.json()
    assert data["case"] == case.reference and data["summary"]["total"] >= 6
    sw = next(x for x in data["rows"] if x["authority"]["name"] == "SWFT / Bridgers")
    assert sw["status"] == "unclear" and sw["quote"] is None  # read-only: no reply text
    assert sw["suggestion"]["status"] == "frozen" and sw["suggestion"]["quote"] is None
    assert data["summary"]["frozen"] == {} and data["summary"]["suggested"] >= 1


# --------------------------------------------------------------------------- refresh, storage, notifications
def test_refresh_stores_rules_rows_and_notifies_changes(db, case, client_for):
    first = bs.refresh(db, case)
    assert first.changed == [] and not _notes(db, case)  # the first refresh only records the snapshot
    order = _order(case, "KuCoin")
    reply = _reply(db, case, order, FROZEN, mailbox=True)
    rep = bs.refresh(db, case)
    assert f"o{order.id}" in rep.changed and rep.ai_skipped == "setting_off" and rep.ai_calls == 0
    n = _notes(db, case)[-1]
    # the notification says "reply needs review", never the outcome the reply may state
    assert n.payload["status"] == "unclear" and n.payload["needs_review"] and n.payload["confirmed"] is False
    assert n.link.endswith(f"#o{order.id}") and "reply needs review" in n.title
    assert "frozen" not in (n.title + (n.body or "")).lower() and "12,633" not in n.title
    assert "KuCoin" not in n.title and "@" not in (n.body or "")
    row = db.scalar(select(ReplyClassification).where(ReplyClassification.correspondence_id == reply.id))
    assert row.source == ReplySource.RULES and row.status.value == "frozen" and bs._exact(row.amount) == "12633.77"
    assert row.stop_order_id == order.id and not row.applied
    assert bs.refresh(db, case).changed == []  # no change, no new notification
    # a person's confirmation overwrites the row; the rules never overwrite it again
    inv = client_for("investigator", case=case, email="inv4-blocks@tests.example")
    tok = csrf_token(inv, f"/cases/{case.id}/blocks")
    assert inv.post(f"/cases/{case.id}/blocks/o{order.id}/confirm", data={
        "status": "hold_placed", "reply_id": str(reply.id), "csrf_token": tok}).status_code == 400  # no amount
    assert inv.post(f"/cases/{case.id}/blocks/o{order.id}/confirm", data={
        "status": "hold_placed", "reply_id": str(reply.id), "amount": "12633.77", "asset": "USDT",
        "csrf_token": tok}).status_code == 200
    bs.refresh(db, case)
    db.expire_all()
    row = db.scalar(select(ReplyClassification).where(ReplyClassification.correspondence_id == reply.id))
    assert row.source == ReplySource.HUMAN and row.status.value == "hold_placed" and row.confirmed_by == inv.user.id


def test_on_reply_filed_hook_never_raises(db, case, monkeypatch):
    order = _order(case, "KuCoin")
    reply = _reply(db, case, order, FROZEN, mailbox=True)
    assert bs.on_reply_filed(db, case, reply) is not None

    def boom(*a, **k):
        raise RuntimeError("x")

    monkeypatch.setattr(bs, "case_blocks", boom)
    assert bs.on_reply_filed(db, case, reply) is None


def test_refresh_route_roles(db, case, client_for):
    ro = client_for("read_only", case=case, email="ro5-blocks@tests.example")
    assert ro.post(f"/cases/{case.id}/blocks/refresh",
                   data={"csrf_token": csrf_token(ro, f"/cases/{case.id}/blocks")}).status_code == 403
    inv = client_for("investigator", case=case, email="inv5-blocks@tests.example")
    r = inv.post(f"/cases/{case.id}/blocks/refresh", data={"csrf_token": csrf_token(inv, f"/cases/{case.id}/blocks")},
                 follow_redirects=False)
    assert r.status_code == 303 and "done=refreshed" in r.headers["location"]


# --------------------------------------------------------------------------- on-chain issuer readings
def _check(db, case, address, *, blacklisted, balance, issuer="Tether", at=None, chain="tron"):
    db.add(FreezeCheck(case_id=case.id, chain=chain, address=address, issuer=issuer, token_symbol="USDT",
                       token_contract="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", status="ok", blacklisted=blacklisted,
                       balance=Decimal(balance), checked_at=at or datetime.now(tz=UTC),
                       meta={"balance_raw": str(int(Decimal(balance) * 10**6))},
                       frozen_at=at if blacklisted else None, frozen_at_basis="event" if blacklisted else None))
    db.commit()


def test_issuer_without_request_shows_the_on_chain_lever(db, case):
    _check(db, case, "TDemoWalletNotFrozen00000000000001", blacklisted=False, balance="12633.77")
    _check(db, case, "TDemoDust0000000000000000000000002", blacklisted=False, balance="0.000599")
    tether = db.scalar(select(Entity).where(Entity.name == "Tether (USDT issuer)"))
    row = _row(db, case, f"x{tether.id}")
    assert row.status == bs.ONCHAIN_ONLY and row.kind == "onchain"
    assert "12,633.77 USDT" in row.next_action["text"] and "not blacklisted" in row.next_action["text"]
    assert len(row.onchain["unfrozen_balance"]) == 1  # poisoning dust is not a lever


def test_on_chain_blacklist_after_the_request_is_evidence_of_a_freeze(db, case):
    tether = db.scalar(select(Entity).where(Entity.name == "Tether (USDT issuer)"))
    addr = "TDemoWalletFrozen0000000000000003"
    sent = datetime(2026, 10, 19, 9, 0, tzinfo=UTC)
    order = StopOrder(case=case, entity=tether, status=StopOrderStatus.SENT, subject="Freeze request",
                      body_markdown=f"Please blacklist {addr}.", identifiers={"addresses": [{"address": addr}]},
                      sent_at=sent, sent_via="email", recipient_email="compliance@tether-demo.example")
    db.add(order)
    db.commit()
    _check(db, case, addr, blacklisted=True, balance="7450.25", at=sent + timedelta(hours=5))
    row = _row(db, case, f"o{order.id}")
    # evidence of a freeze, never the status: a person confirms it
    assert row.status == bs.AWAITING and row.amount is None and row.needs_confirmation
    assert row.suggestion["source"] == "onchain" and row.suggestion["status"] == R.FROZEN
    assert (row.suggestion["amount"], row.suggestion["asset"]) == ("7450.25", "USDT")
    assert row.status_text == "Sent, awaiting reply — on-chain: Frozen (7,450.25 USDT): confirm"
    assert row.next_action["kind"] == "confirm" and bs.summary([row])["frozen"] == {}


# --------------------------------------------------------------------------- overview, authorities, skill
def test_overview_card_and_authorities_column(db, case, client_for):
    _reply(db, case, _order(case, "SWFT / Bridgers"), FROZEN)
    adm = client_for("admin", case=case, email="admin4-blocks@tests.example")
    ov = adm.get(f"/cases/{case.id}?tab=overview")
    assert ov.status_code == 200 and 'id="block-status"' in ov.text and "Block status report" in ov.text
    assert "Frozen (12,633.77 USDT)" in ov.text
    au = adm.get(f"/cases/{case.id}?tab=authorities")
    assert au.status_code == 200 and "bk-col" in au.text and f"/cases/{case.id}/blocks#o" in au.text
    ext = client_for("external", case=case, email="ext2-blocks@tests.example").get(f"/cases/{case.id}?tab=authorities")
    assert ext.status_code == 200 and "bk-col" not in ext.text


def test_block_status_skill(db, case, client_for):
    from app.ai import skills
    from app.core.permissions import CaseAccess

    _reply(db, case, _order(case, "SWFT / Bridgers"), FROZEN)
    assert "block-status" in skills.SKILLS and skills.SKILLS["block-status"].needs_ai
    user = client_for("read_only", case=case, email="ro6-blocks@tests.example").user
    from app.core.permissions import effective_role, membership

    access = CaseAccess(case=case, user=user, role=effective_role(db, user, case), member=membership(db, user, case))
    res = skills.run_skill(db, access, "block-status")
    assert res.source == "rule_based" and "Block status" in res.markdown and "Frozen" in res.markdown
    assert "funds have been frozen" not in res.markdown  # reply text is never quoted
    assert any(a.get("href", "").endswith("/blocks") for a in res.actions)


def test_report_view_masks_contacts_for_read_only(db, case, client_for):
    user = client_for("read_only", case=case, email="ro7-blocks@tests.example").user
    from app.core.permissions import CaseAccess, effective_role, membership

    access = CaseAccess(case=case, user=user, role=effective_role(db, user, case), member=membership(db, user, case))
    v = report.page_view(db, access)
    assert v["rows"] and all(r["quote"] is None for r in v["rows"])
    assert not any(re.search(r"@[a-z0-9-]+\.example", " ".join(r["to"])) and r["authority"]["category"]
                   in ("law_enforcement", "pi_firm") for r in v["rows"])
