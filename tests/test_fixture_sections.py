"""Optional fixture sections (docs/fixture-schema.md): team, imported letters, correspondence,
LE contacts, evidence, notification rules. Loaded idempotently; unknown sections are ignored."""

import hashlib
import json

import pytest
from conftest import DEMO_FIXTURE, anon_client, login
from sqlalchemy import select

from app.core.security import verify_password
from app.db.models import (
    Case,
    CaseRole,
    CorrespondenceDirection,
    EvidenceStorage,
    NotificationRule,
    StopOrderOrigin,
    User,
)
from app.fixture_sections import SeedReport
from app.services import generate_stop_orders, run_trace, seed_from_fixture

SWFT_ORDER = "demo0swf_t000_0000_0000_000000000001"  # the demo swap-order reference


@pytest.fixture
def workspace_fixture(tmp_path):
    data = json.loads(DEMO_FIXTURE.read_text(encoding="utf-8"))
    data["case"]["reference"] = "TEST-FIX-001"
    original = tmp_path / "original-statement.txt"  # stands in for an original kept outside the repo
    original.write_bytes(b"exchange account statement (synthetic)\n")
    data["team"] = [
        {"email": "fix-admin@tests.example", "display_name": "Fixture Admin", "role": "admin",
         "password_env": "AEGIS_TEST_FIX_ADMIN_PW"},
        {"email": "fix-reader@tests.example", "display_name": "Fixture Reader", "role": "read_only"},
    ]
    data["stop_orders_imported"] = [{
        "key": "kucoin-preservation-1", "entity": "KuCoin", "kind": "preservation", "status": "sent",
        "subject": "Preservation request — KuCoin deposit 0x0a17…58e2", "body_markdown": "Dear compliance team, …",
        "recipient_email": "compliance@kucoin.example", "sent_at": "2026-10-15T09:00:00Z", "sent_via": "email",
        "external_ref": "KC-DEMO-0001", "response_due_at": "2026-10-18T09:00:00Z",
        "identifiers": {"addresses": ["0x0a17…58e2"]},
    }, {
        "key": "swft-info-1", "entity": "SWFT / Bridgers", "kind": "info_request", "subject": "SWFT order records",
        "body": f"Please preserve order {SWFT_ORDER}.", "sent_at": "2026-10-16T10:00:00Z", "sent_via": "portal",
        "log_correspondence": False,
    }]
    data["correspondence"] = [
        {"key": "kc-ack", "entity": "KuCoin", "direction": "in", "channel": "email", "kind": "reply",
         "subject": "Re: Preservation request", "body_markdown": "Ticket opened.", "sender": "compliance@kucoin.example",
         "occurred_at": "2026-10-15T15:00:00Z", "stop_order_key": "kucoin-preservation-1",
         "external_ref": "KC-DEMO-0001", "shared_with_external": True},
        {"key": "kc-note", "direction": "note", "channel": "phone", "subject": "Follow-up call",
         "occurred_at": "2026-10-16T08:00:00Z", "in_reply_to_key": "kc-ack", "classification": "C1"},
    ]
    data["le_contacts"] = [{"agency": "Demo Police", "unit": "Cyber unit", "reference": "DEMO-REF-1",
                            "jurisdiction": "CH"}]
    data["evidence"] = [
        {"folder": "chain_reports", "title": "Hub outflow note", "storage": "inline", "inline_text": "156.611 ETH",
         "classification": "C1", "tags": ["hub"]},
        {"folder": "financial", "title": "Account statement", "storage": "reference", "source_path": str(original),
         "mime": "text/plain", "tlp": "TLP:AMBER"},
    ]
    data["notification_rules"] = [{"event_type": "vasp_deposit", "min_usd": 250, "channels": ["in_app", "slack"]}]
    data["some_future_section"] = {"ignored": True}
    path = tmp_path / "case.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path, original


def test_sections_load_idempotently(db, workspace_fixture, monkeypatch):
    path, original = workspace_fixture
    monkeypatch.setenv("AEGIS_TEST_FIX_ADMIN_PW", "fixture-admin-password")
    report = SeedReport()
    case = seed_from_fixture(db, path, report=report)
    assert report.counts == {"team": 2, "le_contacts": 1, "evidence": 2, "stop_orders_imported": 2,
                             "correspondence": 2, "notification_rules": 1}
    # passwords: from the named env var, else generated and reported once
    assert [e for e, _ in report.generated_passwords] == ["fix-reader@tests.example"]
    admin = db.scalar(select(User).where(User.email == "fix-admin@tests.example"))
    assert verify_password("fixture-admin-password", admin.password_hash)
    assert {(m.user.email, m.role) for m in case.members} >= {
        ("fix-admin@tests.example", CaseRole.ADMIN), ("fix-reader@tests.example", CaseRole.READ_ONLY)}

    imported = sorted((o for o in case.stop_orders if o.origin == StopOrderOrigin.IMPORTED), key=lambda o: o.id)
    kc, swft = imported
    assert kc.entity.name == "KuCoin" and kc.status.value == "sent" and kc.sent_via == "email"
    assert kc.response_due_at.isoformat() == "2026-10-18T09:00:00+00:00"
    assert SWFT_ORDER in swft.body_markdown and not swft.correspondence
    out = [c for c in kc.correspondence if c.direction == CorrespondenceDirection.OUT]
    assert len(out) == 1 and out[0].kind.value == "stop_order" and out[0].classification.value == "R3"

    ack = next(c for c in case.correspondence if c.subject == "Re: Preservation request")
    note = next(c for c in case.correspondence if c.subject == "Follow-up call")
    assert ack.stop_order_id == kc.id and ack.shared_with_external and ack.status.value == "received"
    assert note.in_reply_to_id == ack.id and note.classification.value == "C1"

    inline = next(e for e in case.evidence_items if e.storage == EvidenceStorage.INLINE)
    assert inline.sha256 == hashlib.sha256(b"156.611 ETH").hexdigest()
    ref = next(e for e in case.evidence_items if e.storage == EvidenceStorage.REFERENCE)
    assert ref.sha256 == hashlib.sha256(original.read_bytes()).hexdigest() and ref.source_path == str(original)
    assert ref.classification.value == "R3" and ref.tlp == "TLP:AMBER" and ref.verified_at

    assert case.le_contacts[0].classification.value == "R3"
    rule = db.scalar(select(NotificationRule).where(NotificationRule.case_id == case.id))
    assert rule.channels == ["in_app", "slack"] and str(rule.min_usd) == "250.00"

    counts = (len(case.stop_orders), len(case.correspondence), len(case.evidence_items), len(case.le_contacts),
              len(case.members))
    again = SeedReport()
    case = seed_from_fixture(db, path, report=again)
    db.refresh(case)
    assert (len(case.stop_orders), len(case.correspondence), len(case.evidence_items), len(case.le_contacts),
            len(case.members)) == counts
    assert again.generated_passwords == []  # existing users keep their password


def test_generated_drafts_do_not_supersede_imported_letters(db, workspace_fixture):
    path, _ = workspace_fixture
    case = seed_from_fixture(db, path)
    run = run_trace(db, case, provider_mode="fixture")
    generate_stop_orders(db, case, run)
    db.refresh(case)
    imported = [o for o in case.stop_orders if o.origin == StopOrderOrigin.IMPORTED]
    assert imported and all(o.status.value == "sent" for o in imported)


def test_reference_evidence_needs_an_absolute_path(db, workspace_fixture, tmp_path):
    path, _ = workspace_fixture
    data = json.loads(path.read_text())
    data["evidence"] = [{"folder": "other", "title": "relative", "storage": "reference", "source_path": "x.pdf"}]
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="absolute"):
        seed_from_fixture(db, bad)
    db.rollback()


def test_demo_fixture_team_and_sections(db, case):
    roles = {m.user.email: m.role.value for m in case.members}
    assert roles["case.admin@aegis.example"] == "admin"
    assert roles["mara.lindqvist@kestrel-ridge.example"] == "investigator"
    assert roles["analyst@aegis.example"] == "read_only"
    assert roles["liaison@le-demo.example"] == "external"
    assert {c.reference for c in case.le_contacts} == {"DEMO-IT-0000000000", "IC3-DEMO-00000000"}
    assert {r.event_type for r in db.scalars(select(NotificationRule).where(NotificationRule.case_id == case.id))} >= {
        "vasp_deposit", "response_overdue"}
    # an imported letter is never shown as created after it was sent (the seed time): created_at = sent_at
    imported = [o for o in case.stop_orders if o.origin == StopOrderOrigin.IMPORTED]
    assert len(imported) == 6 and all(o.created_at is not None and o.created_at == o.sent_at for o in imported)
    # the demo SWFT order reference is a chain/service reference (kept in letters); the old placeholder is gone
    raw = DEMO_FIXTURE.read_text(encoding="utf-8")
    assert SWFT_ORDER in raw and "swft-order-DEMO" not in raw


def test_demo_team_member_can_sign_in_with_env_password(db, monkeypatch):
    monkeypatch.setenv("AEGIS_DEMO_ANALYST_PASSWORD", "analyst-demo-password")
    seed_from_fixture(db)  # an operator-set variable becomes the current password
    c = anon_client()
    assert login(c, "analyst@aegis.example", "analyst-demo-password").status_code == 303
    demo = db.scalar(select(Case).where(Case.reference == "DEMO-2026-001"))
    assert c.get(f"/cases/{demo.id}").status_code == 200
    page = c.get(f"/cases/{demo.id}?tab=overview").text
    assert f'action="/cases/{demo.id}/watch/poll"' not in page  # read_only: no mutating buttons
