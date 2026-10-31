"""Sender of record: the case's sender profile ("Athena Software Group, Inc., on behalf of …") in new
letters and stop orders, who may change it, and the PI-firm block when there is none."""

import json
import re

import pytest
from conftest import REPO_ROOT, ungated
from sqlalchemy import select

from app import services
from app.db.models import AuditEvent, Correspondence, SenderProfile, StopOrderOrigin
from app.domain import correspondence as desk
from app.domain import evidence as ev
from app.domain import sender as sender_mod
from app.services import generate_stop_orders, seed_from_fixture

ATHENA = "Athena Software Group, Inc., on behalf of Northbridge Analytics, Inc. (Jordan Avery)"
PI_OPENING = ("Kestrel Ridge Investigations GmbH is a private investigations and intelligence firm based in "
              "Switzerland. We act on the instructions of Jordan Avery (CEO, Northbridge Analytics, Inc.), USA, who lost "
              "approximately USD 399,247.92 (399,247.92 USDC) in a cryptocurrency investment fraud on 12 October 2026")
PI_SIGNATURE = ("Yours respectfully,\n\nMara Lindqvist — Director\n\nKestrel Ridge Investigations GmbH\n\n"
                "Beispielweg 10, CH-0000 Musterstadt, Switzerland\n\nT. +41 00 000 00 00\n\n"
                "mara.lindqvist@kestrel-ridge.example\n\n"
                "Cc: investigations@kestrel-ridge.example, victim@northbridge.example\n\n")


@pytest.fixture
def run(db, case):
    return services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")


@pytest.fixture
def restore_profile(db, case):
    yield
    db.rollback()
    seed_from_fixture(db)  # the fixture's sender_profile section upserts the demo profile again


def _auth(db, case, name, run=None):
    return next(a for a in desk.case_authorities(db, case, run=run) if a.name == name)


def _form(c, case, **values) -> dict:
    page = c.get(f"/cases/{case.id}/sender-profile")
    assert page.status_code == 200
    tok = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    profile = {"org_name": "Athena Software Group, Inc.", "on_behalf_of": "Northbridge Analytics, Inc. (Jordan Avery)",
               "signatory_name": "Athena Investigations", "signatory_title": "", "contact_email": "",
               "instrument": "Letter of Authorisation",
               "cc_default": "victim@northbridge.example"}  # as seeded: empty contact = case mailbox
    docs = re.findall(r'name="authority_evidence_ids" value="(\d+)" checked', page.text)  # as the browser submits
    return {"csrf_token": tok, **profile, "authority_evidence_ids": docs, **values}


def test_demo_fixture_seeds_the_profile_with_its_authority_document(db, case):
    p = sender_mod.get_profile(db, case)
    assert p is not None and p.on_behalf_of == "Northbridge Analytics, Inc. (Jordan Avery)"
    assert p.org_name == "Athena Software Group, Inc." and p.instrument == "Letter of Authorisation"
    docs = [db.get(ev.EvidenceItem, i) for i in p.authority_evidence_ids]
    assert len(docs) == 1 and docs[0].folder.value == "legal" and docs[0].tlp is None
    assert docs[0].classification.value == "R3" and docs[0].tags == ["authority", "synthetic"]
    text = (REPO_ROOT / "data/fixtures/demo_evidence/letter_of_authorisation.txt").read_text(encoding="utf-8")
    assert docs[0].inline_text == text and text.startswith("SYNTHETIC DEMO ARTIFACT")
    data = json.loads((REPO_ROOT / "data/fixtures/demo_case.json").read_text(encoding="utf-8"))
    assert data["sender_profile"]["authority_evidence_titles"] == [docs[0].title]


def test_an_empty_contact_email_names_the_case_mailbox(db, case, monkeypatch):
    p = sender_mod.get_profile(db, case)
    assert p.contact_email is None  # the demo fixture leaves it to the configured mailbox
    monkeypatch.setenv("AEGIS_MAIL_FROM", "Case-Desk@Athena.example")
    assert sender_mod.profile_sender(p)["email"] == "case-desk@athena.example"
    monkeypatch.delenv("AEGIS_MAIL_FROM")
    assert sender_mod.profile_sender(p)["email"] is None
    monkeypatch.setenv("AEGIS_MAIL_FROM", "cases@athena.example")
    p.contact_email = "desk@athena.example"  # an explicit contact wins (not flushed: the session is rolled back)
    assert sender_mod.profile_sender(p)["email"] == "desk@athena.example"
    db.rollback()


def test_only_admins_save_and_the_rules_hold(db, case, client_for, restore_profile):
    inv = client_for("investigator", case=case)
    assert inv.get(f"/cases/{case.id}/sender-profile").status_code == 200
    assert client_for("read_only", case=case).get(f"/cases/{case.id}/sender-profile").status_code == 403
    assert inv.post(f"/cases/{case.id}/sender-profile", data=_form(inv, case)).status_code == 403
    admin = client_for("admin", case=case)
    r = admin.post(f"/cases/{case.id}/sender-profile", data=_form(admin, case, signatory_title="Head of recovery"),
                   follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    assert sender_mod.get_profile(db, case).signatory_title == "Head of recovery"
    audit = db.scalars(select(AuditEvent).where(AuditEvent.object_type == "sender_profiles")
                       .order_by(AuditEvent.id.desc())).first()
    assert audit.detail["fields"] == ["signatory_title"] and "@" not in json.dumps(audit.detail)
    page = admin.get(f"/cases/{case.id}/sender-profile").text
    assert "Head of recovery" in page and "Letter preview" in page and "We write as Athena Software Group" in page
    # a Power of Attorney only when confirmed as literally the instrument on file
    r = admin.post(f"/cases/{case.id}/sender-profile", data=_form(admin, case, instrument="Power of Attorney"))
    assert r.status_code == 400 and "Power of Attorney" in r.text
    r = admin.post(f"/cases/{case.id}/sender-profile",
                   data=_form(admin, case, instrument="Power of Attorney", instrument_is_poa="1"), follow_redirects=False)
    assert r.status_code == 303
    # a bad contact address, a TLP-marked document, another case's evidence
    assert admin.post(f"/cases/{case.id}/sender-profile",
                      data=_form(admin, case, contact_email="Desk <x@aegis.example>")).status_code == 400
    ic3 = next(e for e in case.evidence_items if (e.tlp or "").startswith("TLP:AMBER"))
    r = admin.post(f"/cases/{case.id}/sender-profile", data={**_form(admin, case), "authority_evidence_ids": [str(ic3.id)]})
    assert r.status_code == 400 and "cannot be attached" in r.text
    foreign = ev.add_note(db, other_case(db), title="Other case's authority", text="synthetic", folder="legal")
    db.commit()
    r = admin.post(f"/cases/{case.id}/sender-profile",
                   data={**_form(admin, case), "authority_evidence_ids": [str(foreign.id)]})
    assert r.status_code == 404


def other_case(db):
    import uuid
    from decimal import Decimal

    from app.db.models import Chain

    return services.create_case(
        db, reference=f"TEST-MAIL-{uuid.uuid4().hex[:8]}", title="Another case", victim_name="Other Victim",
        victim_entity=None, loss_amount=Decimal(1), loss_asset="USDC", loss_usd=Decimal(1), fraud_date=None,
        chain=Chain.ETHEREUM, origin_tx=None, victim_wallet=None, perpetrator_wallet=None)


def test_new_letters_carry_the_athena_block(db, case, run, monkeypatch):
    monkeypatch.setenv("AEGIS_MAIL_FROM", "case-desk@aegis.example")  # empty profile contact = the case mailbox
    hostinger = _auth(db, case, "Hostinger", run)
    with ungated():  # the shared demo case asked Hostinger already: the sender block is under test
        corr = desk.generate_letter(db, case, hostinger, "info_request", actor=None, run=run)
    body = corr.body_markdown
    assert f"We write as {ATHENA}, USA" in body
    assert "acting under the victim's Letter of Authorisation (attached)" in body
    assert "Yours faithfully,\n\nAthena Investigations\n\n" + ATHENA in body
    assert "case-desk@aegis.example" in body and corr.sender == "case-desk@aegis.example"
    assert "Kestrel Ridge" not in body and "Power of Attorney" not in body
    db.delete(corr)
    db.commit()


def test_stop_order_uses_the_profile_and_falls_back_to_the_pi_block(db, case, run, restore_profile, monkeypatch):
    monkeypatch.setenv("AEGIS_MAIL_FROM", "case-desk@aegis.example")  # empty profile contact = the case mailbox
    with ungated():  # the demo already asked KuCoin: the sender block is under test
        with_profile = generate_stop_orders(db, case, run, only=["KuCoin"])[0].body_markdown
    assert f"We write as {ATHENA}, USA, acting under the victim's Letter of Authorisation (attached)." in with_profile
    assert "Please contact the undersigned at case-desk@aegis.example" in with_profile
    assert "Yours faithfully,\n\nAthena Investigations\n\n" + ATHENA in with_profile
    assert "Kestrel Ridge" not in with_profile and "Yours respectfully" not in with_profile
    db.query(SenderProfile).filter(SenderProfile.case_id == case.id).delete()
    db.commit()
    db.expire_all()
    with ungated():
        without = generate_stop_orders(db, case, run, only=["KuCoin"])[0].body_markdown
    assert PI_OPENING in without and PI_SIGNATURE in without and "Athena" not in without
    assert "- Power of Attorney\n" in without and "victim@northbridge.example" in without
    # everything outside the sender's own paragraphs is the same letter
    strip = re.compile(r"(We write as|Kestrel Ridge Investigations GmbH is a|We can supply supporting|Yours )[^\n]*")
    common = lambda b: [ln for ln in strip.sub("", b.split("Attached / to follow:")[0]).splitlines()
                        if "Generated by Aegis" not in ln]
    assert common(with_profile) == common(without)


def test_imported_letters_are_not_rerendered(db, case):
    data = json.loads((REPO_ROOT / "data/fixtures/demo_case.json").read_text(encoding="utf-8"))
    bodies = {o["key"]: o["body_markdown"] for o in data["stop_orders_imported"]}
    imported = [o for o in case.stop_orders if o.origin == StopOrderOrigin.IMPORTED]
    assert imported
    for o in imported:  # kept exactly as imported (the demo text as logged): never the profile's template text
        assert o.body_markdown == bodies[o.identifiers["fixture_key"]]
        assert "Attached / Info:" in o.body_markdown and "Attached / to follow:" not in o.body_markdown
    by_id = {o.id: o for o in imported}
    rows = db.scalars(select(Correspondence).where(Correspondence.case_id == case.id,
                                                   Correspondence.stop_order_id.in_(list(by_id)))).all()
    rows = [r for r in rows if r.kind.value == "stop_order" and r.direction.value == "out"
            and (r.meta or {}).get("fixture_key") == by_id[r.stop_order_id].identifiers["fixture_key"]]  # the letters'
    assert rows and all(r.body_markdown == by_id[r.stop_order_id].body_markdown for r in rows)


def test_authorities_tab_links_the_profile(client, db, case):
    tab = client.get(f"/cases/{case.id}?tab=authorities").text
    assert "Sender profile: <b>Athena Software Group, Inc.</b> on behalf of" in tab
    assert f'/cases/{case.id}/sender-profile' in tab and "Import reply" in tab  # manual mode (the default)
