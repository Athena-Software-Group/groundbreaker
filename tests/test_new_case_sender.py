"""A new case gets its sender of record when it is opened (the default model of app.domain.sender): Athena
Investigations, writing as Athena Software Group, Inc. on behalf of the client, under the client's Letter of
Authorisation, the client's contact e-mail as the default Cc; and scripts.ensure_sender_profiles gives older cases
the same profile without ever touching an existing one."""

import json
import uuid
from decimal import Decimal

import pytest
from conftest import csrf_token, ungated
from sqlalchemy import select

from app import services
from app.db.models import AuditEvent, Case, Chain, SenderProfile
from app.domain import correspondence as desk
from app.domain import mail_compose
from app.domain import sender as sender_mod
from scripts import ensure_sender_profiles

ROOT = "0x57de1021A507d46272d386995d5B58667Ac1F8df"  # the demo's first perpetrator wallet: the fixture trace reaches services


def _ref(prefix: str = "TEST-NEWCASE") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _form(c, **values) -> dict:
    return {"csrf_token": csrf_token(c, "/cases/new"), "reference": _ref(), "title": "Impersonation — test",
            "victim_name": "Jane Doe", "victim_entity": "Acme Robotics Ltd", "loss_amount": "1000",
            "perpetrator_wallet": ROOT, **values}


def _new_case(db, **kw) -> Case:
    args = {"reference": _ref(), "title": "t", "victim_name": "Jane Doe", "victim_entity": None,
            "loss_amount": Decimal(1000), "loss_asset": "USDC", "loss_usd": Decimal(1000), "fraud_date": None,
            "chain": Chain.ETHEREUM, "origin_tx": None, "victim_wallet": None, "perpetrator_wallet": ROOT, **kw}
    return services.create_case(db, **args)


def test_opening_a_case_creates_the_owner_model_profile(db, client_for, monkeypatch):
    monkeypatch.setenv("AEGIS_MAIL_FROM", "Investigations@Athena-Desk.example")
    c = client_for(None, email="opener.sender@tests.example", can_create_cases=True)
    form = _form(c, client_email="Jane.Doe@Acme-Robotics.example")
    r = c.post("/cases/new", data=form, follow_redirects=False)
    assert r.status_code == 303, r.text
    case = db.scalar(select(Case).where(Case.reference == form["reference"]))
    p = sender_mod.get_profile(db, case)
    assert p is not None and p.org_name == "Athena Software Group, Inc."
    assert p.signatory_name == "Athena Investigations" and p.signatory_title is None
    assert p.on_behalf_of == "Acme Robotics Ltd (Jane Doe)"
    assert p.instrument == "Letter of Authorisation" and p.authority_evidence_ids == []
    assert p.contact_email == "investigations@athena-desk.example"  # the case mailbox
    assert p.cc_default == ["Jane.Doe@acme-robotics.example"]  # the client's contact e-mail (domain lower-cased)
    assert p.created_by == c.user.id
    ev = db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id, AuditEvent.object_type == "sender_profiles"))
    ev = ev.one()
    assert ev.action == "CREATE" and ev.detail["source"] == "case_created" and ev.detail["n_cc"] == 1
    assert "cc_default" in ev.detail["fields"] and "@" not in json.dumps(ev.detail) and "Jane" not in json.dumps(ev.detail)
    # the Overview's setup line, until the signed Letter of Authorisation is attached
    page = c.get(f"/cases/{case.id}").text
    assert "Sender of record set: <b>Athena Investigations</b> on behalf of <b>Acme Robotics Ltd (Jane Doe)</b>" in page
    assert f'<a href="/cases/{case.id}/sender-profile">attach the signed Letter of Authorisation</a>' in page
    # the profile page shows it as saved, editable by the creator (the case admin)
    profile_page = c.get(f"/cases/{case.id}/sender-profile").text
    assert "We write as Athena Software Group, Inc., on behalf of Acme Robotics Ltd (Jane Doe)" in profile_page


def test_the_setup_line_goes_once_the_letter_of_authorisation_is_attached(db, client_for):
    from app.domain import evidence as ev

    c = client_for(None, email="opener.attach@tests.example", can_create_cases=True)
    form = _form(c, victim_entity="", authority_instrument="Letter of Engagement")
    assert c.post("/cases/new", data=form, follow_redirects=False).status_code == 303
    case = db.scalar(select(Case).where(Case.reference == form["reference"]))
    p = sender_mod.get_profile(db, case)
    assert p.on_behalf_of == "Jane Doe" and p.instrument == "Letter of Engagement" and p.cc_default == []
    assert "attach the signed Letter of Engagement" in c.get(f"/cases/{case.id}").text
    doc = ev.add_note(db, case, title="Letter of engagement (signed)", text="synthetic", folder="legal")
    p.authority_evidence_ids = [doc.id]
    db.commit()
    assert "Sender of record set" not in c.get(f"/cases/{case.id}").text


def test_an_invalid_client_email_or_instrument_is_refused_and_nothing_is_created(db, client_for):
    c = client_for(None, email="opener.invalid@tests.example", can_create_cases=True)
    for values in ({"client_email": "Jane <jane@acme.example>"}, {"client_email": "not-an-address"},
                   {"client_email": "jane@localhost"}, {"authority_instrument": "Power of Attorney"}):
        form = _form(c, **values)
        r = c.post("/cases/new", data=form, follow_redirects=False)
        assert r.status_code == 400, (values, r.status_code)
        assert db.scalar(select(Case).where(Case.reference == form["reference"])) is None
    with pytest.raises(sender_mod.SenderError):
        _new_case(db, client_email="two@acme.example, three@acme.example")
    api = c.post("/api/cases", json={"reference": _ref(), "title": "t", "victim_name": "v", "loss_amount": "1",
                                     "loss_usd": "1", "client_email": "bad address"})
    assert api.status_code == 422


def test_the_api_creates_the_profile_too(db, client_for):
    c = client_for(None, email="opener.api@tests.example", can_create_cases=True)
    ref = _ref()
    r = c.post("/api/cases", json={"reference": ref, "title": "t", "victim_name": "Jane Doe", "loss_amount": "1",
                                   "loss_usd": "1", "client_email": "jane@acme-robotics.example"})
    assert r.status_code == 201, r.text
    p = sender_mod.get_profile(db, db.scalar(select(Case).where(Case.reference == ref)))
    assert p.signatory_name == "Athena Investigations" and p.cc_default == ["jane@acme-robotics.example"]


def test_defaults_follow_the_owner_model(db, case, monkeypatch):
    monkeypatch.delenv("AEGIS_MAIL_FROM", raising=False)
    d = sender_mod.defaults(case)
    assert d["org_name"] == "Athena Software Group, Inc." and d["signatory_name"] == "Athena Investigations"
    assert d["on_behalf_of"] == "Northbridge Analytics, Inc. (Jordan Avery)" and d["contact_email"] is None
    assert d["instrument"] == "Letter of Authorisation" and d["cc_default"] == []
    monkeypatch.setenv("AEGIS_MAIL_FROM", "desk@athena.example")
    assert sender_mod.defaults(case)["contact_email"] == "desk@athena.example"
    assert sender_mod.defaults(case, client_email="a@b.example")["cc_default"] == ["a@b.example"]


def test_the_demo_fixture_has_the_same_default_profile(db, case):
    p = sender_mod.get_profile(db, case)
    assert p.signatory_name == "Athena Investigations" and p.signatory_title is None
    assert p.on_behalf_of == sender_mod.client_label(case) and p.org_name == sender_mod.ORG_NAME
    assert p.contact_email is None  # the case mailbox, read when a letter is rendered
    assert p.cc_default == [case.facts["victim_contact"]["email"]]  # the client's contact e-mail


def test_letters_on_a_new_case_are_written_for_the_client_and_pass_the_sender_check(db, case, monkeypatch):
    monkeypatch.setenv("AEGIS_MAIL_FROM", "investigations@athena-desk.example")
    case = _new_case(db, victim_entity="Acme Robotics Ltd", client_email="jane@acme-robotics.example")
    run = services.run_trace(db, case, provider_mode="fixture")
    authority = next(a for a in desk.case_authorities(db, case, run=run) if not a.is_le)
    with ungated():  # the shared demo data may have asked this provider already: the sender block is under test
        corr = desk.generate_letter(db, case, authority, "info_request", actor=None, run=run)
    body = corr.body_markdown
    assert "We write as Athena Software Group, Inc., on behalf of Acme Robotics Ltd (Jane Doe)" in body
    assert "acting under the victim's Letter of Authorisation (attached)" in body
    assert "Yours faithfully,\n\nAthena Investigations\n\nAthena Software Group, Inc., on behalf of Acme Robotics Ltd " \
           "(Jane Doe)\n\ninvestigations@athena-desk.example" in body
    assert "jane@acme-robotics.example" in corr.cc
    check = mail_compose.sender_check(db, case, corr)
    assert check.ok, check.text
    # the client's address is offered as the Cc it was given for, never warned about
    from app.domain import mail_guidance as mg

    g = mg.guide(mg.Inputs(authority_name=authority.name, case_reference=case.reference, letter_kind="info_request",
                           profile_cc=("jane@acme-robotics.example",), victim_addresses=("jane@acme-robotics.example",),
                           draft_cc=("jane@acme-robotics.example",)))
    assert "jane@acme-robotics.example" in [s.address for s in g.cc]
    assert "victim_cc" not in {w.code for w in g.warnings}


def test_ensure_script_creates_missing_profiles_only_and_is_idempotent(db, case, monkeypatch):
    monkeypatch.setenv("AEGIS_MAIL_FROM", "investigations@athena-desk.example")
    new = _new_case(db, victim_entity="Acme Robotics Ltd")
    new.facts = {"victim_contact": {"email": "jane@acme-robotics.example"}}
    db.query(SenderProfile).filter(SenderProfile.case_id == new.id).delete()
    db.commit()
    demo_before = {k: getattr(sender_mod.get_profile(db, case), k) for k in sender_mod.FIELDS}
    lines: list[str] = []
    # dry run: names the case, writes nothing
    counts = ensure_sender_profiles.ensure(db, reference=new.reference, dry_run=True, out=lines.append)
    db.rollback()
    assert counts == {"created": 1, "existing": 0, "skipped": 0} and "would create" in lines[-1]
    assert sender_mod.get_profile(db, new) is None
    counts = ensure_sender_profiles.ensure(db, reference=new.reference.lower(), cc_client=True, out=lines.append)
    assert counts == {"created": 1, "existing": 0, "skipped": 0}
    p = sender_mod.get_profile(db, new)
    assert p.signatory_name == "Athena Investigations" and p.on_behalf_of == "Acme Robotics Ltd (Jane Doe)"
    assert p.cc_default == ["jane@acme-robotics.example"] and p.contact_email == "investigations@athena-desk.example"
    audit = db.scalars(select(AuditEvent).where(AuditEvent.case_id == new.id,
                                                AuditEvent.object_type == "sender_profiles")).one()
    assert audit.detail["source"] == "ensure_script" and audit.actor_user_id is None
    # an existing profile is never overwritten, a second run creates nothing
    p.signatory_name = "Desk Lead"
    db.commit()
    for ref in (new.reference, case.reference):  # (never every case: the test database is shared)
        assert ensure_sender_profiles.ensure(db, reference=ref, out=lines.append) == {
            "created": 0, "existing": 1, "skipped": 0}
    db.expire_all()
    assert sender_mod.get_profile(db, new).signatory_name == "Desk Lead"
    assert {k: getattr(sender_mod.get_profile(db, case), k) for k in sender_mod.FIELDS} == demo_before
    assert db.scalars(select(AuditEvent).where(AuditEvent.case_id == new.id,
                                               AuditEvent.object_type == "sender_profiles")).all() == [audit]
    with pytest.raises(LookupError):
        ensure_sender_profiles.ensure(db, reference="NO-SUCH-CASE-REF", out=lines.append)


def test_ensure_script_never_ccs_the_client_on_file_unless_asked(db, case, monkeypatch):
    """Without --cc-client-on-file an older case's profile gets no default Cc (the victim's personal mailbox is never
    copied on letters silently)."""
    new = _new_case(db, victim_entity="Acme Robotics Ltd")
    new.facts = {"victim_contact": {"email": "jane@acme-robotics.example"}}
    db.query(SenderProfile).filter(SenderProfile.case_id == new.id).delete()
    db.commit()
    ensure_sender_profiles.ensure(db, reference=new.reference, out=lambda *_: None)
    assert sender_mod.get_profile(db, new).cc_default == []
