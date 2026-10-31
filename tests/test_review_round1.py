"""Regression tests for the fixes of review round 1 (permissions, letters, assistant figures, alerts,
exports, headers). Feature-specific regressions live next to their features (test_evidence,
test_authorities, test_assistant, test_auth, test_security, test_team_notify, test_tracer)."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from conftest import TEST_PASSWORD, anon_client, csrf_token
from docx import Document
from sqlalchemy import select

from app import services
from app.ai.context import local_context
from app.ai.rules import _frozen, rule_answer, rule_summary
from app.db.models import (
    Alert,
    CaseMember,
    Chain,
    Correspondence,
    CorrespondenceDirection,
    CorrespondenceKind,
    CorrespondenceStatus,
    Entity,
    EntityCategory,
    StopOrder,
    StopOrderStatus,
    User,
)
from app.domain import correspondence as desk
from app.tracing.repository import get_or_create_address

SWFT_ORDER = "demo0swf_t000_0000_0000_000000000001"  # the demo swap-order reference


@pytest.fixture
def run(db, case):
    return services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")


def _by_name(db, case, name, run=None):
    db.expire_all()
    return next(a for a in desk.case_authorities(db, case, run=run) if a.name == name)


def _iso_case(db, tag: str | None = None):
    tag = tag or uuid.uuid4().hex[:8]
    return services.create_case(
        db, reference=f"TEST-R1-{tag}", title="review round 1", victim_name="Test Victim", victim_entity=None,
        loss_amount=Decimal(1000), loss_asset="USDC", loss_usd=Decimal(1000), fraud_date=None, chain=Chain.ETHEREUM,
        origin_tx=None, victim_wallet=None, perpetrator_wallet="0x" + "ab" * 20)


# --------------------------------------------------------------------------- funds position
def test_frozen_counts_the_recorded_hold_not_the_candidate_taint():
    cands = [{"entity": "Rainbet", "total_taint_usd": 63761.69}, {"entity": "KuCoin", "total_taint_usd": 144.94}]
    partial = [{"id": 5, "entity": "Rainbet", "status": "frozen",
                "hold": {"state": "frozen", "amount": "12.5", "asset": "ETH", "usd": 31875.0}}]
    assert _frozen(partial, cands) == (31875.0, 0)
    # a hold larger than the traced taint is capped at the taint
    big = [{**partial[0], "hold": {**partial[0]["hold"], "usd": 99999.0}}]
    assert _frozen(big, cands) == (63761.69, 0)
    # frozen without a reported amount: nothing confirmed, the taint is only an upper bound
    unknown = [{"id": 6, "entity": "KuCoin", "status": "frozen", "hold": {"state": "frozen", "usd": None}}]
    assert _frozen(unknown, cands) == (0, 144.94)
    assert _frozen([{"id": 7, "entity": "Rainbet", "status": "sent", "hold": None}], cands) == (0, 0)


def test_overview_and_assistant_report_the_held_amount(db, client_for):
    case = _iso_case(db)
    casino = Entity(name=f"Casino {case.reference}", category=EntityCategory.CASINO)
    db.add(casino)
    order = StopOrder(case=case, entity=casino, kind="freeze", status=StopOrderStatus.SENT, subject="Freeze",
                      body_markdown="x", sent_at=datetime.now(tz=UTC) - timedelta(days=1))
    db.add(order)
    db.commit()
    desk.record_stop_order_status(db, case, order, "frozen", actor=None, amount_held=Decimal("12.5"), asset="ETH")
    ctx = local_context(db, case)
    row = next(o for o in ctx["stop_orders"] if o["id"] == order.id)
    assert row["hold"]["amount"] == "12.5" and row["hold"]["usd"] == 31875.0
    assert ctx["derived"]["funds_position"]["frozen_usd"] == 31875.0  # 12.5 ETH × 2,550, not a taint figure
    page = client_for("read_only", case=case, email=f"ov.{case.reference.lower()}@tests.example").get(
        f"/cases/{case.id}?tab=overview").text
    assert "$31,875.00" in page and "Frozen (confirmed holds)" in page


# --------------------------------------------------------------------------- movement alerts
def test_acknowledging_alerts_clears_the_assistant_step(db, client_for):
    case = _iso_case(db)
    addr = get_or_create_address(db, Chain.ETHEREUM, "0x" + uuid.uuid4().hex[:8] + "cd" * 16)
    item = services.add_watch(db, case, addr)
    db.add_all([Alert(watch_item_id=item.id, severity="high", tx_hash="0x" + "1" * 64, message="moved"),
                Alert(watch_item_id=item.id, severity="high", tx_hash="0x" + "2" * 64, message="moved again")])
    db.commit()
    steps = [x["action"] for x in rule_summary(local_context(db, case))["next_steps"]]
    assert "Review and acknowledge the movement alerts" in steps
    ro = client_for("read_only", case=case, email=f"ro.{case.reference.lower()}@tests.example")
    tok = csrf_token(ro, f"/cases/{case.id}?tab=overview")
    assert ro.post(f"/cases/{case.id}/watch/alerts/ack-all", data={"csrf_token": tok}).status_code == 403
    inv = client_for("investigator", case=case, email=f"inv.{case.reference.lower()}@tests.example")
    page = inv.get(f"/cases/{case.id}?tab=overview").text
    assert "Acknowledge all" in page and "/watch/alerts/" in page
    one = db.scalars(select(Alert).where(Alert.watch_item_id == item.id).order_by(Alert.id)).first()
    tok = csrf_token(inv, f"/cases/{case.id}?tab=overview")
    r = inv.post(f"/cases/{case.id}/watch/alerts/{one.id}/ack", data={"csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303
    r = inv.post(f"/cases/{case.id}/watch/alerts/ack-all", data={"csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    assert all(a.acknowledged for a in db.scalars(select(Alert).where(Alert.watch_item_id == item.id)))
    s = rule_summary(local_context(db, case))
    assert "Review and acknowledge the movement alerts" not in [x["action"] for x in s["next_steps"]]
    assert not any("not acknowledged" in x for x in s["open_items"])
    # an alert of another case is 404
    other = _iso_case(db)
    assert inv.post(f"/cases/{other.id}/watch/alerts/{one.id}/ack", data={"csrf_token": tok}).status_code == 404


# --------------------------------------------------------------------------- letters
def test_swap_order_ids_and_reply_state_reach_every_letter(db, case, run):
    swft = _by_name(db, case, "SWFT / Bridgers", run)
    _, body, _ = desk.build_letter(db, case, swft, "status_request", run=run)
    assert f"`{SWFT_ORDER}`" in body
    rainbet = _by_name(db, case, "Rainbet", run)
    if any(desk.order_state(o) == "sent" for o in rainbet.stop_orders):
        _, rb, _ = desk.build_letter(db, case, rainbet, "status_request", run=run)
        assert "RB-DEMO-0001" in rb  # their ticket from the auto-acknowledgement
    ic3 = _by_name(db, case, "FBI Internet Crime Complaint Center (IC3)", run)
    _, cover, _ = desk.build_letter(db, case, ic3, "le_cover", run=run)
    assert f"`{SWFT_ORDER}`" in cover
    rb_line = next(line for line in cover.splitlines() if line.startswith("- **Rainbet**"))
    if "request sent" in rb_line:
        assert "receipt acknowledged" in rb_line and "no reply yet" not in rb_line, rb_line


def test_a_status_request_keeps_its_clock_after_the_order_is_answered(db):
    case = _iso_case(db)
    ex = Entity(name=f"Exchange {case.reference}", category=EntityCategory.EXCHANGE)
    db.add(ex)
    sent = datetime.now(tz=UTC) - timedelta(days=3)
    order = StopOrder(case=case, entity=ex, kind="freeze", status=StopOrderStatus.SENT, subject="Freeze",
                      body_markdown="x", sent_at=sent)
    db.add(order)
    db.flush()
    status_req = Correspondence(
        case=case, entity=ex, direction=CorrespondenceDirection.OUT, kind=CorrespondenceKind.STATUS_REQUEST,
        status=CorrespondenceStatus.SENT, subject="Status request", occurred_at=sent + timedelta(days=1),
        due_at=datetime.now(tz=UTC) + timedelta(days=4), stop_order=order)
    db.add(status_req)
    db.commit()
    desk.record_stop_order_status(db, case, order, "frozen", actor=None)  # the order itself is answered
    authority = next(a for a in desk.case_authorities(db, case) if a.entity is not None and a.entity.id == ex.id)
    assert ("correspondence", status_req.id) in [(k, i) for k, i, _ in authority.awaiting()]
    ctx = local_context(db, case)
    from app.ai.rules import derive

    upcoming = derive(ctx, datetime.now(tz=UTC))["upcoming_deadlines"]
    assert any(u["type"] == "correspondence" and u["id"] == status_req.id for u in upcoming)


def test_stop_order_docx_starts_with_a_filing_header(db, case, tmp_path):
    from app.reports.stop_orders import export_markdown, to_docx

    order = next(o for o in case.stop_orders if o.sent_at and o.recipient_email)
    md = export_markdown(order)
    assert md.startswith(f"**Stop order #{order.id}**") and "**Sent:** " in md and "**To:** " in md
    path = to_docx(order, tmp_path / "x.docx")
    text = "\n".join(p.text for p in Document(str(path)).paragraphs)
    assert f"Stop order #{order.id}" in text and "Sent: " in text and case.reference in text
    assert "UTC" in text.split("Dear", 1)[0]


# --------------------------------------------------------------------------- role-based exposure
def test_read_only_gets_no_letter_text_through_the_api(client_for, case):
    ro = client_for("read_only", case=case, email="api.ro@tests.example")
    rows = ro.get(f"/api/cases/{case.id}/stop-orders").json()
    assert rows and all(r["body_markdown"] is None and r["restricted"] for r in rows)
    allowed = {"entity", "chain", "addresses", "tx_hashes", "amounts", "order_ids", "prior_deposit_dates",
               "theft_time", "hold"}
    assert all(set(r["identifiers"]) <= allowed for r in rows)
    inv = client_for("investigator", case=case, email="api.inv@tests.example")
    assert any(r["body_markdown"] for r in inv.get(f"/api/cases/{case.id}/stop-orders").json())


def test_case_list_api_hides_victim_and_loss_from_externals(client_for, case):
    ext = client_for("external", case=case, email="api.ext@tests.example")
    row = next(r for r in ext.get("/api/cases").json() if r["id"] == case.id)
    assert row["role"] == "external" and row["victim_name"] is None and row["loss_usd"] is None
    ro = client_for("read_only", case=case, email="api.ro2@tests.example")
    row = next(r for r in ro.get("/api/cases").json() if r["id"] == case.id)
    assert row["victim_name"] == case.victim_name and row["role"] == "read_only"


def test_overview_masks_complaint_references_below_investigator(client_for, case):
    ro = client_for("read_only", case=case, email="ov.ro@tests.example")
    page = ro.get(f"/cases/{case.id}?tab=overview").text
    assert "DEMO-IT-0000000000" not in page and "DEMO-IT-******00" in page
    inv = client_for("investigator", case=case, email="ov.inv@tests.example")
    assert "DEMO-IT-0000000000" in inv.get(f"/cases/{case.id}?tab=overview").text


# --------------------------------------------------------------------------- input validation & headers
@pytest.mark.parametrize("field,value", [("role", "bogus"), ("chain", "dogecoin")])
def test_invalid_seed_input_is_a_400(client_for, case, field, value):
    inv = client_for("investigator", case=case, email="seed.inv@tests.example")
    data = {"csrf_token": csrf_token(inv, f"/cases/{case.id}"), "role": "known_downstream", "chain": "ethereum",
            "value": "0x" + "3" * 40, field: value}
    assert inv.post(f"/cases/{case.id}/seeds", data=data, follow_redirects=False).status_code == 400


def test_hsts_is_sent_outside_local(monkeypatch):
    from app.core.config import get_settings

    assert "strict-transport-security" not in anon_client().get("/login").headers
    monkeypatch.setattr(type(get_settings()), "is_local", property(lambda self: False))
    assert "max-age=" in anon_client().get("/login").headers["strict-transport-security"]


# --------------------------------------------------------------------------- CLI
def test_create_user_time_boxes_external_members(db, case, monkeypatch):
    from scripts import create_user

    monkeypatch.setenv("R1_PW", TEST_PASSWORD)
    email = f"cli.ext.{uuid.uuid4().hex[:6]}@tests.example"
    assert create_user.main([email, "CLI External", "--password-env", "R1_PW", "--case", case.reference,
                             "--role", "external"]) == 0
    db.expire_all()
    user = db.scalar(select(User).where(User.email == email))
    m = db.scalar(select(CaseMember).where(CaseMember.case_id == case.id, CaseMember.user_id == user.id))
    assert timedelta(days=29) < m.expires_at - datetime.now(tz=UTC) <= timedelta(days=30)
    with pytest.raises(SystemExit):
        create_user.main([email, "CLI External", "--case", case.reference, "--role", "external",
                          "--expires", "9999-12-31"])
    with pytest.raises(SystemExit):
        create_user.main([email, "CLI External", "--case", case.reference, "--role", "investigator",
                          "--expires", "2026-12-31"])


# --------------------------------------------------------------------------- rule-based Q&A
def test_rule_answers_lead_with_status_and_the_overdue_count(db, case):
    ctx = local_context(db, case)
    a = rule_answer(ctx, "What is the status and what should we do next?")
    assert "Status: " in a and "Next steps:" in a and "Funds: traced" in a
    o = rule_answer(ctx, "Which stop orders are overdue?")
    lead = next(line for line in o.splitlines() if line.startswith("Deadlines:"))
    assert re.match(r"Deadlines: (None overdue|\d+ overdue)", lead), lead
