"""Cross-feature wiring: the overview tab, the header, the dev sign-in link, the API routes that now
go through the feature domains (trace events, stop-order desk, watch notifications), the R3 gate on
stop-order letters, default notification rules and the redacted assistant context."""

from __future__ import annotations

import pytest
from conftest import anon_client, csrf_token, ensure_user, ungated
from sqlalchemy import select

from app import services
from app.core import events
from app.core.config import get_settings
from app.db.models import (
    EvidenceItem,
    Notification,
    StopOrder,
    StopOrderOrigin,
    StopOrderStatus,
    TraceRun,
)


def _imported(case, key: str) -> StopOrder:
    return next(o for o in case.stop_orders if o.origin == StopOrderOrigin.IMPORTED
                and (o.identifiers or {}).get("fixture_key") == key)


# --------------------------------------------------------------------------- overview & header
def test_overview_shows_case_status_blocks(client, case):
    r = client.get(f"/cases/{case.id}?tab=overview")
    assert r.status_code == 200
    html = r.text
    for anchor in ('id="funds"', 'id="status"', 'id="open-orders"', 'id="overdue"', 'id="latest-notifications"',
                   'id="alerts"'):
        assert anchor in html, anchor
    assert "At freezable services" in html and "Open stop orders" in html
    # the six imported letters are open (sent) stop orders, linked to their authority pages
    assert html.count(f"/cases/{case.id}/authorities/entity-") >= 6
    assert "KuCoin" in html and "Rainbet" in html


def test_overview_shows_the_latest_assistant_summary(client, case, monkeypatch):
    import app.ai.providers as ai_providers

    monkeypatch.setattr(ai_providers, "get_provider", lambda: None)
    token = csrf_token(client, f"/cases/{case.id}?tab=assistant")
    r = client.post(f"/cases/{case.id}/assistant/summary", data={"csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303
    html = client.get(f"/cases/{case.id}?tab=overview").text
    assert "rule-based (AI not configured)" in html and "Next steps" in html


def test_overview_read_only_has_no_forms(client_for, case):
    c = client_for("read_only", case=case, email="ro.overview@tests.example")
    html = c.get(f"/cases/{case.id}?tab=overview").text
    assert 'id="funds"' in html and "/watch/poll" not in html and "/seeds" not in html


def test_header_badge_powered_by_and_admin_links(client, client_for, db, case):
    me = client.user
    db.add(Notification(case_id=case.id, event_type=events.TRACE_COMPLETED, title=f"{case.reference}: test",
                        severity="info", payload={"recipient_user_ids": [me.id]}, deliveries=[], read_by=[]))
    db.commit()
    html = client.get("/").text
    assert "powered by" in html and "Athena Software Group, Inc." in html
    assert 'id="nav-inbox"' in html and "data-inbox-count" in html
    assert 'href="/admin/users"' not in html  # case admins are not system admins
    sysadmin = client_for(None, system_admin=True)
    page = sysadmin.get("/").text
    assert 'href="/admin/users"' in page and 'href="/admin/audit"' in page


# --------------------------------------------------------------------------- dev sign-in link
def test_dev_login_is_off_by_default(db, case):
    ensure_user(db, "dev.user@tests.example")
    r = anon_client().get("/dev/login", params={"token": "x" * 40, "email": "dev.user@tests.example"},
                          follow_redirects=False)
    assert r.status_code == 404


@pytest.fixture
def dev_token(monkeypatch):
    token = "dev-login-token-" + "y" * 32
    monkeypatch.setenv("AEGIS_DEV_LOGIN_TOKEN", token)
    get_settings.cache_clear()
    yield token
    monkeypatch.delenv("AEGIS_DEV_LOGIN_TOKEN")
    get_settings.cache_clear()


def test_dev_login_needs_local_env_and_works_once_per_email(db, case, dev_token, monkeypatch):
    from app.web import routes_auth

    monkeypatch.setattr(routes_auth, "_dev_logins_used", set())
    ensure_user(db, "dev.once@tests.example")
    c = anon_client()
    assert c.get("/dev/login", params={"token": "wrong" + dev_token, "email": "dev.once@tests.example"},
                 follow_redirects=False).status_code == 404
    r = c.get("/dev/login", params={"token": dev_token, "email": "dev.once@tests.example", "next": "/"},
              follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert c.get("/", follow_redirects=False).status_code == 200  # signed in
    again = anon_client().get("/dev/login", params={"token": dev_token, "email": "dev.once@tests.example"},
                              follow_redirects=False)
    assert again.status_code == 404  # one use per e-mail per process
    monkeypatch.setenv("APP_ENV", "production")
    get_settings.cache_clear()
    try:
        ensure_user(db, "dev.prod@tests.example")
        r = anon_client().get("/dev/login", params={"token": dev_token, "email": "dev.prod@tests.example"},
                              follow_redirects=False)
        assert r.status_code == 404  # never outside APP_ENV=local
    finally:
        monkeypatch.setenv("APP_ENV", "local")
        get_settings.cache_clear()


# --------------------------------------------------------------------------- API wiring
def test_api_trace_takes_a_label_emits_trace_completed_and_refuses_unknown_modes(client, db, case):
    assert client.post(f"/api/cases/{case.id}/trace", params={"mode": "livee"}).status_code == 400
    r = client.post(f"/api/cases/{case.id}/trace", params={"mode": "fixture", "label": "api re-run"})
    assert r.status_code == 200
    run_id = r.json()["id"]
    run = db.get(TraceRun, run_id)
    assert run.label == "api re-run"
    note = db.scalar(select(Notification).where(Notification.case_id == case.id,
                                                Notification.event_type == events.TRACE_COMPLETED)
                     .order_by(Notification.id.desc()))
    assert note is not None and note.payload.get("trace_run_id") == run_id


def test_api_stop_order_status_goes_through_the_desk(client, db, case):
    order = _imported(case, "kucoin-preservation-1")
    r = client.patch(f"/api/cases/{case.id}/stop-orders/{order.id}", json={"status": "frozen", "notes": "hold"})
    assert r.status_code == 200 and r.json()["status"] == "frozen"
    db.expire_all()
    order = db.get(StopOrder, order.id)
    logged = [c for c in order.correspondence if (c.meta or {}).get("source") == "stop_order_status"]
    assert logged and order.responded_at is not None
    assert db.scalar(select(Notification).where(Notification.case_id == case.id,
                                                Notification.event_type == events.STOP_ORDER_STATUS))
    # released is a real status now (migration 0004)
    r = client.patch(f"/api/cases/{case.id}/stop-orders/{order.id}", json={"status": "released"})
    assert r.status_code == 200 and r.json()["status"] == "released"
    db.expire_all()
    assert db.get(StopOrder, order.id).status == StopOrderStatus.RELEASED
    bad = client.patch(f"/api/cases/{case.id}/stop-orders/{order.id}", json={"status": "teleported"})
    assert bad.status_code == 400


def test_watch_poll_route_notifies(client, db, case, monkeypatch):
    calls = []

    def fake_poll(db_, case_, provider_mode=None):
        calls.append(provider_mode)
        return [], []

    from app.domain import notify

    monkeypatch.setattr(notify, "poll_and_notify", fake_poll)
    token = csrf_token(client, f"/cases/{case.id}?tab=overview")
    r = client.post(f"/cases/{case.id}/watch/poll", data={"csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303 and "tab=overview" in r.headers["location"]
    r = client.post(f"/api/cases/{case.id}/watch/poll")
    assert r.status_code == 200 and r.json() == {"new_alerts": [], "notifications": []}
    assert len(calls) == 2
    assert client.post(f"/api/cases/{case.id}/watch/poll", params={"mode": "nope"}).status_code == 400


# --------------------------------------------------------------------------- R3 gate on letters
def test_stop_order_letter_is_restricted_for_read_only(client, client_for, case):
    order = _imported(case, "rainbet-preservation-1")
    ro = client_for("read_only", case=case, email="ro.letters@tests.example")
    page = ro.get(f"/cases/{case.id}/stop-orders/{order.id}")
    assert page.status_code == 200
    assert "restricted (R3)" in page.text and order.body_markdown[:60] not in page.text
    assert ro.get(f"/api/cases/{case.id}/stop-orders/{order.id}/docx").status_code == 403
    full = client.get(f"/cases/{case.id}/stop-orders/{order.id}")
    assert "Authority timeline" in full.text and 'id="copy-md"' in full.text


# --------------------------------------------------------------------------- rules, letters, assistant
def test_new_cases_get_the_default_notification_rules(client, db):
    from app.db.models import NotificationRule

    client.user.can_create_cases = True
    db.merge(client.user)
    db.commit()

    token = csrf_token(client, "/cases/new")
    r = client.post("/cases/new", data={
        "csrf_token": token, "reference": "INTEG-0001", "title": "Integration case", "victim_name": "Test Victim",
        "loss_amount": "1000", "loss_asset": "USDC", "perpetrator_wallet": "0x" + "12" * 20,
    }, follow_redirects=False)
    assert r.status_code == 303
    cid = int(r.headers["location"].rsplit("/", 1)[-1])
    types = set(db.scalars(select(NotificationRule.event_type).where(NotificationRule.case_id == cid)))
    assert types == set(events.EVENT_TYPES)


def test_generated_swft_letter_cites_the_swap_order_id(db, case):
    run = services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")
    with ungated():  # the demo already asked SWFT: the letter's content is under test
        orders = services.generate_stop_orders(db, case, run, only=["SWFT / Bridgers"])
    assert orders and "demo0swf_t000_0000_0000_000000000001" in orders[0].body_markdown
    assert orders[0].identifiers["order_ids"] == ["demo0swf_t000_0000_0000_000000000001"]


def test_redacted_context_withholds_titles_taken_from_file_names(db, case):
    from app.ai.context import build_context

    item = EvidenceItem(case=case, folder=case.evidence_items[0].folder, title="Original_Filename_Of_Victim.pdf",
                        source_type="document", storage=case.evidence_items[0].storage,
                        classification=case.evidence_items[0].classification,
                        meta={"ingest": "import:reference", "import_rel_path": "x/Original_Filename_Of_Victim.pdf"})
    db.add(item)
    db.commit()
    try:
        ctx = build_context(db, case, "redacted")
        row = next(e for e in ctx["evidence_index"] if e["id"] == item.id)
        assert "Original_Filename" not in row["title"] and row["title"].startswith("[file title withheld")
        full = build_context(db, case, "full")
        assert next(e for e in full["evidence_index"] if e["id"] == item.id)["title"] == item.title
    finally:
        db.delete(item)
        db.commit()


def test_reseed_keeps_internal_facts(db, case):
    facts = dict(case.facts or {})
    facts["_reseed_probe"] = {"kept": True}
    case.facts = facts
    db.commit()
    try:
        again = services.seed_from_fixture(db)
        assert again.facts["_reseed_probe"] == {"kept": True} and again.facts.get("persona")
    finally:
        case.facts = {k: v for k, v in case.facts.items() if k != "_reseed_probe"}
        db.commit()


def test_evidence_integrity_event_is_registered():
    from app.domain import notify

    assert events.EVIDENCE_INTEGRITY in events.EVENT_TYPES
    assert notify.RuleSpec.default(events.EVIDENCE_INTEGRITY).enabled
