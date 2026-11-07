"""Team management, notifications (rules, channels, PII-free payloads, inbox), audit log pages and the
scheduler. No network: SMTP and Slack are replaced by fakes (and guarded so a real call fails)."""

from __future__ import annotations

import re
import secrets
import sys
import types
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import ClassVar

import pytest
from conftest import TEST_PASSWORD, anon_client, csrf_token, ensure_user, login
from sqlalchemy import select

from app import services
from app.core import events
from app.db.models import (
    Alert,
    AuditEvent,
    Case,
    CaseMember,
    CaseRole,
    Chain,
    EntityCategory,
    Notification,
    NotificationRule,
    Transfer,
    User,
)
from app.domain import notify


# --------------------------------------------------------------------------- helpers / guards
class FakeSMTP:
    sent: ClassVar[list] = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        pass

    def login(self, user, password):
        pass

    def send_message(self, msg, to_addrs=None):
        FakeSMTP.sent.append((msg, list(to_addrs or [])))


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """No channel is configured unless a test says so, and any real SMTP / HTTP call fails loudly."""
    for var in ("SMTP_HOST", "SMTP_FROM", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_PORT", "SMTP_SSL",
                "SMTP_STARTTLS", "SLACK_WEBHOOK_URL", "APP_BASE_URL"):
        monkeypatch.delenv(var, raising=False)

    def refuse(*a, **k):
        raise AssertionError("network call in a test")

    monkeypatch.setattr(notify.smtplib, "SMTP", refuse)
    monkeypatch.setattr(notify.smtplib, "SMTP_SSL", refuse)
    monkeypatch.setattr(notify.httpx, "post", refuse)
    FakeSMTP.sent = []


@pytest.fixture
def channels_on(monkeypatch):
    """SMTP and Slack configured, both faked. Returns the list Slack posts are recorded in."""
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_FROM", "aegis-alerts@example.com")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example.com/services/T000/B000/XXXX")
    monkeypatch.setenv("APP_BASE_URL", "https://aegis.example.com")
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    posts: list = []

    class Resp:
        def raise_for_status(self):
            pass

    def fake_post(url, json=None, timeout=None):
        posts.append({"url": url, "json": json})
        return Resp()

    monkeypatch.setattr(notify.httpx, "post", fake_post)
    return posts


def fresh_case(db, creator: User | None, *, loss_usd: str = "100000") -> Case:
    return services.create_case(
        db, reference=f"TEST-{secrets.token_hex(4).upper()}", title="Team/notify test case",
        victim_name="Casey Testperson", victim_entity="Testco Example Ltd", loss_amount=Decimal(loss_usd),
        loss_asset="USDC", loss_usd=Decimal(loss_usd), fraud_date=None, chain=Chain.ETHEREUM,
        origin_tx="0x" + "ab" * 32, victim_wallet=None, perpetrator_wallet=None, created_by=creator,
    )


def _emit(db, case, event_type=events.WALLET_MOVEMENT, usd=None, **kw):
    kw.setdefault("title", "Watched wallet moved funds")
    kw.setdefault("body", None)
    kw.setdefault("link", f"/cases/{case.id}?tab=fund_flow")
    return events.emit(db, case, event_type, usd=usd, **kw)


# --------------------------------------------------------------------------- rules & thresholds
def test_default_rules_match_the_spec():
    d = notify.DEFAULT_RULES
    assert d["wallet_movement"]["min_usd"] == Decimal(1000) and d["wallet_movement"]["min_pct_of_loss"] == 1.0
    assert d["vasp_deposit"]["enabled"] and d["vasp_deposit"].get("min_usd") is None
    assert d["sweep_imminent"]["enabled"] and notify.SEVERITY_FLOOR["sweep_imminent"] == "critical"
    assert d["response_overdue"]["overdue_days"] == 7
    assert not d["ai_summary"]["enabled"]
    for et in ("stop_order_status", "correspondence_in", "evidence_added", "trace_completed"):
        assert d[et]["enabled"], et


def test_thresholds_either_usd_or_share_of_loss():
    rule = notify.RuleSpec.default(events.WALLET_MOVEMENT)  # ≥ $1,000 or ≥ 1 % of loss
    loss = Decimal(50000)  # 1 % = $500
    assert notify.passes_thresholds(rule, Decimal(600), loss)  # share of loss
    assert notify.passes_thresholds(rule, Decimal(1000), Decimal(1000000))  # USD
    assert not notify.passes_thresholds(rule, Decimal("499.99"), loss)
    assert not notify.passes_thresholds(rule, None, loss)  # unpriced (e.g. a poisoning token): quiet
    assert notify.passes_thresholds(rule, Decimal(1000), None)  # no loss figure: USD threshold only
    assert notify.passes_thresholds(notify.RuleSpec.default(events.VASP_DEPOSIT), None, loss)  # any amount


def test_emit_applies_case_defaults_thresholds_and_severity(db, client_for):
    owner = ensure_user(db, "owner.thresholds@tests.example")
    case = fresh_case(db, owner, loss_usd="100000")  # 1 % = $1,000
    # create_case writes the built-in defaults as the case's own rows
    rows = db.scalars(select(NotificationRule).where(NotificationRule.case_id == case.id)).all()
    assert {r.event_type for r in rows} == set(events.EVENT_TYPES)
    assert _emit(db, case, usd="999.99") is None
    note = _emit(db, case, usd="1000")
    assert note is not None and note.usd == Decimal("1000.00") and note.payload["rule"] == "case"
    assert note.payload["recipient_user_ids"] == [owner.id]
    assert _emit(db, case, events.AI_SUMMARY, title="Status summary") is None  # off by default
    dep = _emit(db, case, events.VASP_DEPOSIT, usd="5", title="Funds reached KuCoin", severity="high")
    assert dep.severity == "critical"  # freeze window: always critical
    assert [d["channel"] for d in dep.deliveries] == ["in_app", "email", "slack"]
    assert {d["status"] for d in dep.deliveries[1:]} == {"not_configured"}


def test_case_rule_beats_global_rule_beats_default(db, case):
    other = fresh_case(db, None)
    for row in db.scalars(select(NotificationRule).where(NotificationRule.case_id == other.id)):
        db.delete(row)  # no case rows: the global row applies
    glob = NotificationRule(case_id=None, event_type=events.TRACE_COMPLETED, enabled=False, channels=["in_app"],
                            recipient_roles=["admin"])
    db.add(glob)
    db.commit()
    try:
        assert notify.effective_rule(db, other, events.TRACE_COMPLETED).source == "global"
        assert _emit(db, other, events.TRACE_COMPLETED, title="Trace completed") is None
        # the demo fixture's own wallet_movement rule (min $500) wins over the $1,000 default
        rule = notify.effective_rule(db, case, events.WALLET_MOVEMENT)
        assert rule.source == "case" and rule.min_usd == Decimal("500.00") and rule.min_pct_of_loss is None
        assert _emit(db, case, usd="600") is not None
    finally:
        db.delete(glob)
        db.commit()


def test_seed_default_rules_is_idempotent(db):
    case = fresh_case(db, None)  # create_case already seeded the defaults
    assert notify.seed_default_rules(db, case) == 0
    db.commit()
    assert notify.seed_default_rules(db, case) == 0
    rows = {r.event_type: r for r in db.scalars(select(NotificationRule).where(NotificationRule.case_id == case.id))}
    assert set(rows) == set(events.EVENT_TYPES) and rows["wallet_movement"].min_usd == Decimal("1000.00")
    rows["wallet_movement"].min_usd = Decimal(5)
    db.commit()
    assert notify.seed_default_rules(db, case, overwrite=True) == len(events.EVENT_TYPES)
    db.commit()
    db.refresh(rows["wallet_movement"])
    assert rows["wallet_movement"].min_usd == Decimal("1000.00")
    assert notify.overdue_days(db, case) == 7


# --------------------------------------------------------------------------- channels
def test_channels_absent_record_not_configured_without_network(db, case):
    note = _emit(db, case, events.VASP_DEPOSIT, usd="2500", title="Funds reached KuCoin", severity="critical")
    by = {d["channel"]: d for d in note.deliveries}
    assert by["in_app"]["status"] == "delivered"
    assert by["email"]["status"] == "not_configured"  # the demo rule routes vasp_deposit to in_app + email
    assert notify.channel_status() == {"in_app": True, "email": False, "slack": False}


def test_channels_present_send_email_and_slack(db, case, channels_on):
    rule = db.scalar(select(NotificationRule).where(NotificationRule.case_id == case.id,
                                                   NotificationRule.event_type == events.VASP_DEPOSIT))
    rule.channels = ["in_app", "email", "slack"]
    db.commit()
    note = _emit(db, case, events.VASP_DEPOSIT, usd="2500", title="Funds reached KuCoin: 0.58 ETH",
                 body="0x0a17000000000000000000000000000000058e2a deposit", severity="critical")
    by = {d["channel"]: d for d in note.deliveries}
    assert by["email"]["status"] == "sent" and by["slack"]["status"] == "sent"
    msg, to = FakeSMTP.sent[-1]
    recipients = notify.recipients(db, case, ["admin", "investigator"])
    assert sorted(to) == sorted(u.email for u in recipients) and by["email"]["recipients"] == len(to)
    assert msg["To"] == "aegis-alerts@example.com"  # members are Bcc'd, never listed to each other
    assert case.reference in msg["Subject"] and "VASP deposit" in msg["Subject"]
    text = channels_on[-1]["json"]["text"]
    assert f"https://aegis.example.com/cases/{case.id}?tab=" in text and "$2,500.00" in text
    assert "0x0a1700…058e2a" in text  # long addresses shortened
    # delivery log: no addresses, URLs or text
    assert "hooks.example.com" not in str(note.deliveries) and "@" not in str(note.deliveries)


def test_failed_channel_is_logged_and_the_event_kept(db, case, channels_on, monkeypatch):
    def boom(*a, **k):
        raise ConnectionError("https://hooks.example.com/secret-path")

    monkeypatch.setattr(notify.httpx, "post", boom)
    rule = db.scalar(select(NotificationRule).where(NotificationRule.case_id == case.id,
                                                   NotificationRule.event_type == events.SWEEP_IMMINENT))
    rule.channels = ["in_app", "slack"]
    db.commit()
    note = _emit(db, case, events.SWEEP_IMMINENT, usd="100", title="Sweep imminent at KuCoin")
    slack = next(d for d in note.deliveries if d["channel"] == "slack")
    assert slack == {"channel": "slack", "status": "failed", "at": slack["at"], "error": "ConnectionError"}
    assert db.get(Notification, note.id) is not None


# --------------------------------------------------------------------------- PII
def test_notification_text_is_scrubbed_of_case_pii(db, case, channels_on):
    rule = db.scalar(select(NotificationRule).where(NotificationRule.case_id == case.id,
                                                   NotificationRule.event_type == events.VASP_DEPOSIT))
    rule.channels = ["in_app", "email", "slack"]
    db.commit()
    victim, persona = case.victim_name, case.facts["persona"]
    note = _emit(db, case, events.VASP_DEPOSIT, usd="1500",
                 title=f"{victim}'s funds reached KuCoin",
                 body=(f"Persona {persona} · contact victim@northbridge.example or +41 00 000 00 00 · "
                       f"Kestrel Ridge Investigations GmbH, Mara Lindqvist · ref DEMO-IT-0000000000 · "
                       "0x7AC32c88e5489B4c406fFc1d6B835f4EBa7B455b"),
                 payload={"stop_order_id": 7, "note": "free text with spaces", "who": "a@b.example"})
    stored = f"{note.title}\n{note.body}"
    for leaked in (victim, persona, "Adrian Example", "victim@northbridge.example", "+41 00 000 00 00",
                   "Kestrel Ridge", "Mara Lindqvist", "DEMO-IT-0000000000",
                   "0x7AC32c88e5489B4c406fFc1d6B835f4EBa7B455b"):
        assert leaked not in stored, leaked
    assert "0x7AC32c…7B455b" in note.body and "KuCoin" in note.title
    assert notify.pii_findings(stored, case) == []
    assert note.payload == {"stop_order_id": 7, "recipient_user_ids": note.payload["recipient_user_ids"],
                            "rule": "case"}
    outbound = channels_on[-1]["json"]["text"] + str(FakeSMTP.sent[-1][0])
    assert notify.pii_findings(outbound.split("\n\n", 1)[-1], case) == []
    assert victim not in outbound and "northbridge" not in outbound.lower()


def _vasp_and_plain_transfers(db, case):
    rows = db.scalars(select(Transfer).where(Transfer.amount.is_not(None))).all()
    vasp = next(t for t in rows if t.to_address.entity is not None
                and t.to_address.entity.category in notify.VASP_CATEGORIES)
    plain = next(t for t in rows if t.to_address.entity is None and t.amount_usd is not None
                 and t.amount_usd >= 1000)
    return vasp, plain


def test_watch_alerts_emit_wallet_movement_and_vasp_deposit(db, case, monkeypatch):
    vasp_t, plain_t = _vasp_and_plain_transfers(db, case)
    rule = db.scalar(select(NotificationRule).where(NotificationRule.case_id == case.id,
                                                   NotificationRule.event_type == events.VASP_DEPOSIT))
    rule.min_usd = None  # the demo fixture asks for ≥ $1,000; the built-in default is any amount
    db.commit()
    alerts = []
    for t, sev in ((vasp_t, "critical"), (plain_t, "high")):
        item = services.add_watch(db, case, t.from_address)
        a = Alert(watch_item=item, severity=sev, tx_hash=t.tx_hash, message="moved")
        db.add(a)
        alerts.append(a)
    db.commit()

    monkeypatch.setattr(services, "poll_watch_items", lambda db_, case_, mode=None: alerts)
    got, notes = notify.poll_and_notify(db, case)
    assert got == alerts
    by_type = {n.event_type: n for n in notes}
    assert set(by_type) == {"vasp_deposit", "wallet_movement"}
    dep = by_type["vasp_deposit"]
    assert dep.severity == "critical" and vasp_t.to_address.entity.name in dep.title
    assert dep.payload["alert_id"] == alerts[0].id and dep.link == f"/cases/{case.id}?tab=fund_flow"
    assert case.reference in dep.body and vasp_t.from_address.short() in dep.body
    assert notify.pii_findings(dep.title + dep.body, case) == []
    # idempotent: the same alerts never notify twice
    assert notify.emit_watch_alerts(db, case, alerts) == []


def test_scrub_handles_none_and_shortens_chain_ids():
    assert notify.scrub(None) is None
    out = notify.scrub("TWdZZhGvAAAAAAAAAAAAAAAAAAAAAAAL77 and bc1pxnd9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaknzn")
    assert "TWdZZhGv…AAAL77" in out and "bc1pxnd9…aaknzn" in out


# --------------------------------------------------------------------------- inbox
def test_inbox_unread_badge_and_mark_read(db, case, client, client_for):
    note = _emit(db, case, events.STOP_ORDER_STATUS, title=f"Inbox test {secrets.token_hex(3)}")
    assert client.user.id in note.payload["recipient_user_ids"]
    before = client.get("/notifications/unread-count").json()["unread"]
    assert before >= 1
    page = client.get("/notifications")
    assert page.status_code == 200 and note.title in page.text
    token = csrf_token(client, "/notifications")
    r = client.post(f"/notifications/{note.id}/read", data={"csrf_token": token, "next": "link"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == note.link
    assert client.get("/notifications/unread-count").json()["unread"] == before - 1
    db.refresh(note)
    assert client.user.id in note.read_by

    # an outsider never sees the row and cannot mark it read
    outsider = client_for(None, email="outsider.inbox@tests.example")
    assert note.title not in outsider.get("/notifications").text
    t2 = csrf_token(outsider, "/notifications")
    assert outsider.post(f"/notifications/{note.id}/read", data={"csrf_token": t2}).status_code == 404


def test_inbox_only_shows_addressed_roles(db, case, client_for):
    reader = client_for("read_only", case=case, email="reader.inbox@tests.example")
    note = _emit(db, case, events.VASP_DEPOSIT, usd="5000", title=f"Deposit inbox {secrets.token_hex(3)}")
    assert reader.user.id not in note.payload["recipient_user_ids"]  # rule: admin + investigator
    assert note.title not in reader.get("/notifications").text
    # …but the case tab (read_only may view case notifications) lists it
    assert note.title in reader.get(f"/cases/{case.id}?tab=notifications").text


def test_case_tab_mark_all_read(db, case, client):
    _emit(db, case, events.EVIDENCE_ADDED, title="Evidence added: chain export")
    page = client.get(f"/cases/{case.id}?tab=notifications")
    assert page.status_code == 200 and "Rules" in page.text
    token = csrf_token(client, f"/cases/{case.id}?tab=notifications")
    r = client.post(f"/cases/{case.id}/notifications/read-all", data={"csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303
    unread = [n for n in db.scalars(select(Notification).where(Notification.case_id == case.id))
              if client.user.id not in (n.read_by or [])]
    assert unread == []


# --------------------------------------------------------------------------- rule editor & gating
def test_rule_editor_updates_and_audits(db, case, client):
    token = csrf_token(client, f"/cases/{case.id}?tab=notifications")
    r = client.post(f"/cases/{case.id}/notifications/rules/wallet_movement", data={
        "csrf_token": token, "enabled": "on", "min_usd": "2,500", "min_pct_of_loss": "2",
        "channels": ["email", "slack", "bogus"], "recipient_roles": ["admin", "external", "read_only"]},
        follow_redirects=False)
    assert r.status_code == 303 and "saved=wallet_movement" in r.headers["location"]
    rule = notify.effective_rule(db, case, "wallet_movement")
    assert rule.source == "case" and rule.min_usd == Decimal("2500.00") and rule.min_pct_of_loss == 2.0
    assert rule.channels == ["in_app", "email", "slack"] and rule.recipient_roles == ["admin", "read_only"]
    ev = db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id, AuditEvent.object_type ==
                                             "notification_rules").order_by(AuditEvent.id.desc())).first()
    assert ev.action == "UPDATE" and ev.detail["event_type"] == "wallet_movement"

    bad = client.post(f"/cases/{case.id}/notifications/rules/wallet_movement",
                      data={"csrf_token": token, "min_pct_of_loss": "250"}, follow_redirects=False)
    assert "rule_error=pct" in bad.headers["location"]
    assert client.post(f"/cases/{case.id}/notifications/rules/nope", data={"csrf_token": token}).status_code == 404

    r = client.post(f"/cases/{case.id}/notifications/rules/reset", data={"csrf_token": token},
                    follow_redirects=False)
    assert r.status_code == 303
    assert notify.effective_rule(db, case, "wallet_movement").min_usd == Decimal("1000.00")


def test_rule_api(case, basic_client):
    r = basic_client.get(f"/api/cases/{case.id}/notifications/rules")
    assert r.status_code == 200 and len(r.json()["rules"]) == len(events.EVENT_TYPES)
    r = basic_client.put(f"/api/cases/{case.id}/notifications/rules/response_overdue",
                         json={"enabled": True, "overdue_days": 10, "channels": ["in_app", "email"]})
    assert r.status_code == 200 and r.json()["overdue_days"] == 10 and r.json()["source"] == "case"
    assert basic_client.put(f"/api/cases/{case.id}/notifications/rules/response_overdue",
                            json={"channels": ["sms"]}).status_code == 422
    assert basic_client.get(f"/api/cases/{case.id}/notifications").status_code == 200


@pytest.mark.parametrize("role,expected", [("read_only", 403), ("investigator", 403), (None, 404)])
def test_rule_editing_needs_case_admin(db, case, client_for, role, expected):
    c = client_for(role, case=case, email=f"rules.{role}@tests.example")
    token = csrf_token(c, "/notifications")
    r = c.post(f"/cases/{case.id}/notifications/rules/vasp_deposit",
               data={"csrf_token": token, "enabled": "on"}, follow_redirects=False)
    assert r.status_code == expected


@pytest.mark.parametrize("role,expected", [("read_only", 403), ("investigator", 403), ("external", 403),
                                           (None, 404)])
def test_team_changes_need_case_admin(db, case, client_for, role, expected):
    c = client_for(role, case=case, email=f"team.{role}@tests.example")
    token = csrf_token(c, "/notifications")
    r = c.post(f"/cases/{case.id}/team/members", data={"csrf_token": token, "email": "x@tests.example",
                                                        "display_name": "X", "role": "admin"},
               follow_redirects=False)
    assert r.status_code == expected
    assert db.scalar(select(User).where(User.email == "x@tests.example")) is None


def test_read_only_sees_team_without_controls(db, case, client_for):
    c = client_for("read_only", case=case, email="team.viewer@tests.example")
    page = c.get(f"/cases/{case.id}?tab=team")
    assert page.status_code == 200 and "Demo Case Admin" in page.text
    assert "/team/members" not in page.text and "Add or invite" not in page.text
    ext = client_for("external", case=case, email="team.ext@tests.example")
    assert ext.get(f"/api/cases/{case.id}/team").status_code == 403
    assert 'id="team"' not in ext.get(f"/cases/{case.id}?tab=team").text  # tab falls back for externals


# --------------------------------------------------------------------------- team management
def _member(db, case, email) -> CaseMember:
    db.expire_all()
    return db.scalar(select(CaseMember).join(User, User.id == CaseMember.user_id).where(CaseMember.case_id == case.id, User.email == email))


def test_invite_new_user_shows_one_time_password_once(db, case, client_for):
    client = client_for(None, system_admin=True)  # only system admins create accounts
    email = f"invitee.{secrets.token_hex(3)}@tests.example"
    token = csrf_token(client, f"/cases/{case.id}?tab=team")
    r = client.post(f"/cases/{case.id}/team/members", data={
        "csrf_token": token, "email": email.upper(), "display_name": "New Invitee", "role": "investigator"})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    otp = re.search(r"data-team-otp>([^<]+)<", r.text).group(1)
    assert len(otp) >= 16
    m = _member(db, case, email)
    assert m.role == CaseRole.INVESTIGATOR and m.added_by == client.user.id and m.expires_at is None
    # shown once: not on the next render, not in the audit log
    assert otp not in client.get(f"/cases/{case.id}?tab=team").text
    assert not [e for e in db.scalars(select(AuditEvent)) if otp in str(e.detail)]
    grant = db.scalars(select(AuditEvent).where(AuditEvent.action == "ROLE_GRANT", AuditEvent.case_id == case.id)
                       .order_by(AuditEvent.id.desc())).first()
    assert grant.detail["invited"] is True and grant.detail["role"] == "investigator"
    # the invitee can sign in with it and open the case
    c = anon_client()
    assert login(c, email, otp).status_code == 303
    assert c.get(f"/cases/{case.id}").status_code == 200


def test_add_existing_user_and_external_expiry(db, case, client):
    user = ensure_user(db, f"existing.{secrets.token_hex(3)}@tests.example")
    token = csrf_token(client, f"/cases/{case.id}?tab=team")
    r = client.post(f"/cases/{case.id}/team/members", data={"csrf_token": token, "email": user.email,
                                                             "role": "external"}, follow_redirects=False)
    assert r.status_code == 303 and "team_saved=submitted" in r.headers["location"]
    m = _member(db, case, user.email)
    assert m.role == CaseRole.EXTERNAL
    assert timedelta(days=29) < m.expires_at - datetime.now(tz=UTC) <= timedelta(days=30)  # default time box

    again = client.post(f"/cases/{case.id}/team/members", data={"csrf_token": token, "email": user.email,
                                                                 "role": "admin"}, follow_redirects=False)
    assert "team_error=already_member" in again.headers["location"]

    # set an explicit expiry, then promote (non-external members carry no expiry)
    day = (datetime.now(tz=UTC) + timedelta(days=60)).date().isoformat()
    r = client.post(f"/cases/{case.id}/team/members/{m.id}", data={"csrf_token": token, "role": "external",
                                                                    "expires_at": day}, follow_redirects=False)
    assert r.status_code == 303
    assert _member(db, case, user.email).expires_at.date().isoformat() == day
    past = client.post(f"/cases/{case.id}/team/members/{m.id}", data={
        "csrf_token": token, "role": "external", "expires_at": "2020-01-01"}, follow_redirects=False)
    assert "team_error=bad_expiry" in past.headers["location"]
    far = client.post(f"/cases/{case.id}/team/members/{m.id}", data={
        "csrf_token": token, "role": "external", "expires_at": "9999-12-31"}, follow_redirects=False)
    assert "team_error=expiry_too_far" in far.headers["location"]
    assert _member(db, case, user.email).expires_at.date().isoformat() == day
    client.post(f"/cases/{case.id}/team/members/{m.id}", data={"csrf_token": token, "role": "read_only"})
    m = _member(db, case, user.email)
    assert m.role == CaseRole.READ_ONLY and m.expires_at is None

    r = client.post(f"/cases/{case.id}/team/members/{m.id}/remove", data={"csrf_token": token},
                    follow_redirects=False)
    assert r.status_code == 303 and _member(db, case, user.email) is None
    revoke = db.scalars(select(AuditEvent).where(AuditEvent.action == "ROLE_REVOKE").order_by(
        AuditEvent.id.desc())).first()
    assert revoke.detail["user_id"] == user.id


def test_need_display_name_to_invite(case, client_for):
    client = client_for(None, system_admin=True)
    token = csrf_token(client, f"/cases/{case.id}?tab=team")
    r = client.post(f"/cases/{case.id}/team/members", data={"csrf_token": token, "email": "nobody.new@tests.example",
                                                             "role": "read_only"}, follow_redirects=False)
    assert "team_error=need_name" in r.headers["location"]
    page = client.get(r.headers["location"])
    assert "give a display name" in page.text


def test_last_admin_cannot_be_removed_or_demoted(db, client_for):
    c = client_for(None, email="sole.admin@tests.example")
    case = fresh_case(db, c.user)
    m = _member(db, case, "sole.admin@tests.example")
    assert m.role == CaseRole.ADMIN
    token = csrf_token(c, f"/cases/{case.id}?tab=team")
    page = c.get(f"/cases/{case.id}?tab=team").text
    assert "last admin" in page
    r = c.post(f"/cases/{case.id}/team/members/{m.id}", data={"csrf_token": token, "role": "investigator"},
               follow_redirects=False)
    assert "team_error=last_admin" in r.headers["location"]
    r = c.post(f"/cases/{case.id}/team/members/{m.id}/remove", data={"csrf_token": token}, follow_redirects=False)
    assert "team_error=last_admin" in r.headers["location"]
    assert _member(db, case, "sole.admin@tests.example").role == CaseRole.ADMIN

    import base64
    api = anon_client()
    api.headers["Authorization"] = "Basic " + base64.b64encode(
        f"sole.admin@tests.example:{TEST_PASSWORD}".encode()).decode()
    r = api.patch(f"/api/cases/{case.id}/team/{m.id}", json={"role": "read_only"})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "last_admin"
    assert api.delete(f"/api/cases/{case.id}/team/{m.id}").status_code == 409

    # a case admin cannot create accounts, and the answer does not say whether one exists
    r = api.post(f"/api/cases/{case.id}/team", json={"email": "second.admin@tests.example",
                                                     "display_name": "Second Admin", "role": "admin"})
    assert r.status_code == 202 and "one_time_password" not in r.json()
    assert db.scalar(select(User).where(User.email == "second.admin@tests.example")) is None
    # with a second admin (an existing account) the first may step down
    ensure_user(db, "second.admin@tests.example")
    r2 = api.post(f"/api/cases/{case.id}/team", json={"email": "second.admin@tests.example",
                                                      "display_name": "ignored", "role": "admin"})
    assert r2.status_code == 202 and r2.json() == r.json()
    assert api.patch(f"/api/cases/{case.id}/team/{m.id}", json={"role": "investigator"}).status_code == 200
    assert _member(db, case, "sole.admin@tests.example").role == CaseRole.INVESTIGATOR


def test_member_from_another_case_is_404(db, case, client):
    other = fresh_case(db, ensure_user(db, "other.owner@tests.example"))
    foreign = _member(db, other, "other.owner@tests.example")
    token = csrf_token(client, f"/cases/{case.id}?tab=team")
    r = client.post(f"/cases/{case.id}/team/members/{foreign.id}/remove", data={"csrf_token": token})
    assert r.status_code == 404


# --------------------------------------------------------------------------- audit pages & user admin
def test_case_audit_log_for_admins_with_filters(db, case, client, client_for):
    r = client.get(f"/cases/{case.id}/audit")
    assert r.status_code == 200 and "hash chain intact" in r.text
    r = client.get(f"/cases/{case.id}/audit?action=ACCESS_DENIED&outcome=denied")
    assert r.status_code == 200
    rows = re.findall(r'<span class="tag[^"]*">([A-Z_]+)</span></td>', r.text)
    assert set(rows) <= {"ACCESS_DENIED"}
    assert client.get(f"/cases/{case.id}/audit?since=nope").status_code == 400
    assert client.get(f"/api/cases/{case.id}/audit?action=ROLE_GRANT").status_code == 200
    inv = client_for("investigator", case=case, email="audit.inv@tests.example")
    assert inv.get(f"/cases/{case.id}/audit").status_code == 403
    assert inv.get("/admin/audit").status_code == 403
    viewed = db.scalars(select(AuditEvent).where(AuditEvent.action == "VIEW_AUDIT")).all()
    assert viewed


def test_global_audit_and_user_admin_need_system_admin(db, client, client_for):
    assert client.get("/admin/users").status_code == 403
    sa = client_for(None, system_admin=True)
    assert sa.get("/admin/audit").status_code == 200
    page = sa.get("/admin/users")
    assert page.status_code == 200 and "New account" in page.text
    token = csrf_token(sa, "/admin/users")
    email = f"created.{secrets.token_hex(3)}@tests.example"
    r = sa.post("/admin/users", data={"csrf_token": token, "email": email, "display_name": "Created User"})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    otp = re.search(r"data-team-otp>([^<]+)<", r.text).group(1)
    assert login(anon_client(), email, otp).status_code == 303
    user = db.scalar(select(User).where(User.email == email))
    # deactivate: sessions end; self-lockout is refused
    r = sa.post(f"/admin/users/{user.id}", data={"csrf_token": token, "display_name": "Created User"},
                follow_redirects=False)
    assert r.status_code == 303
    db.refresh(user)
    assert user.is_active is False
    r = sa.post(f"/admin/users/{sa.user.id}", data={"csrf_token": token, "is_active": "on"}, follow_redirects=False)
    assert "error=self" in r.headers["location"]


# --------------------------------------------------------------------------- scheduler
def test_scheduler_once_runs_poll_and_guarded_overdue(monkeypatch):
    from scripts import poll_watch, run_scheduler

    calls = []
    monkeypatch.setattr(poll_watch, "poll_all", lambda mode=None, verbose=True: (calls.append(mode) or (2, 1)))
    monkeypatch.delitem(sys.modules, "app.domain.correspondence", raising=False)
    monkeypatch.setattr(run_scheduler, "_load_check_overdue", lambda: None)
    r = run_scheduler.run_once("fixture")
    assert calls == ["fixture"] and r["alerts"] == 2 and r["notifications"] == 1 and r["overdue"] is None

    seen = []
    fake = types.ModuleType("app.domain.correspondence")

    def check_overdue(db, case, now=None, *, default_days=None):
        assert default_days == notify.overdue_days(db, case)
        seen.append(case.id)
        return [1]

    fake.check_overdue = check_overdue
    monkeypatch.setitem(sys.modules, "app.domain.correspondence", fake)
    monkeypatch.setattr(run_scheduler, "_load_check_overdue", lambda: fake.check_overdue)
    r = run_scheduler.run_once()
    assert r["overdue"] == len(seen) and seen
    assert run_scheduler.run_forever(0, max_passes=2) == 2


def test_scheduler_loader_is_guarded(monkeypatch):
    from scripts import run_scheduler

    monkeypatch.setitem(sys.modules, "app.domain.correspondence", None)  # import raises ImportError
    assert run_scheduler._load_check_overdue() is None


def test_scheduler_runs_the_real_overdue_check_when_present(db, case):
    from scripts import run_scheduler

    if run_scheduler._load_check_overdue() is None:
        pytest.skip("app.domain.correspondence.check_overdue not installed")
    assert isinstance(run_scheduler.check_overdue_all(), int)


def test_poll_watch_script_emits_through_rules(db, case, monkeypatch):
    from scripts import poll_watch

    monkeypatch.setattr(poll_watch, "poll_and_notify", lambda db_, case_, mode=None: ([], []))
    assert poll_watch.poll_all("fixture", verbose=False) == (0, 0)


def test_unknown_event_and_category_constants():
    assert EntityCategory.EXCHANGE in notify.VASP_CATEGORIES
    with pytest.raises(ValueError):
        events.emit(None, None, "nope", title="x", body=None, link=None)  # type: ignore[arg-type]


def test_case_admins_cannot_mint_or_probe_accounts(db, case, client_for):
    """Review: a case admin (e.g. the creator of a throw-away case) could create global accounts with
    one-time passwords and tell which addresses have accounts. Now: same answer either way."""
    c = client_for("admin", case=case, email="probe.admin@tests.example")
    known = ensure_user(db, f"known.{secrets.token_hex(3)}@tests.example", name="Known Person")
    token = csrf_token(c, f"/cases/{case.id}?tab=team")
    answers = []
    for email in (known.email, f"unknown.{secrets.token_hex(3)}@tests.example"):
        r = c.post(f"/cases/{case.id}/team/members", data={"csrf_token": token, "email": email,
                                                           "display_name": "New", "role": "read_only"},
                   follow_redirects=False)
        answers.append((r.status_code, r.headers.get("location")))
    assert answers[0] == answers[1] and "team_saved=submitted" in answers[0][1]
    assert db.scalar(select(User).where(User.email.like("unknown.%@tests.example"))) is None
    page = c.get(answers[0][1]).text
    assert "If an active account exists" in page and "data-team-otp" not in page


def test_notification_emails_end_with_the_mail_footer(monkeypatch):
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    cfg = types.SimpleNamespace(smtp_from="aegis-alerts@example.com", smtp_ssl=False, smtp_host="smtp.example.com",
                          smtp_port=587, smtp_starttls=False, smtp_username="", smtp_password="")
    monkeypatch.setenv("AEGIS_MAIL_FOOTER", "Sent from Aegis, the case desk")
    notify.send_email(cfg, ["a@example.com"], "Alert", "Funds moved.")
    notify.send_email(cfg, ["a@example.com"], "Alert", "Funds moved.\n\nSent from Aegis, the case desk")
    first, second = (m.get_content() for m, _ in FakeSMTP.sent[-2:])
    assert first.rstrip().endswith("Sent from Aegis, the case desk") and first.startswith("Funds moved.")
    assert second.count("Sent from Aegis") == 1
    monkeypatch.setenv("AEGIS_MAIL_FOOTER", "")
    notify.send_email(cfg, ["a@example.com"], "Alert", "Funds moved.")
    assert "Sent from Aegis" not in FakeSMTP.sent[-1][0].get_content()
