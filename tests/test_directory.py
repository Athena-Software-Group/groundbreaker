"""Contact directory: the shipped catalogue and its validator, authority → organisation matching, the
"How to contact" card (merge order, de-duplication, masking) and who may change channels."""

import json
import re

import pytest
from conftest import csrf_token
from sqlalchemy import select

from app.core.permissions import CaseAccess
from app.db.models import AuditEvent, CaseRole, EntityChannel
from app.domain import correspondence as desk
from app.domain import directory


@pytest.fixture
def clean_channels(db):
    before = set(db.scalars(select(EntityChannel.id)))
    yield
    db.rollback()
    for row in db.scalars(select(EntityChannel)):
        if row.id not in before:
            db.delete(row)
    db.commit()


def _auth(db, case, name):
    return next(a for a in desk.case_authorities(db, case) if a.name == name)


def _access(case, user, role):
    return CaseAccess(case=case, user=user, role=CaseRole(role), member=None)


def _user(db, email, **kw):
    from conftest import ensure_user

    return ensure_user(db, email, **kw)


# --------------------------------------------------------------------------- catalogue
def test_shipped_catalogue_is_valid_and_holds_no_addresses():
    cat = directory.load_catalogue()
    keys = {o.key for o in cat.orgs}
    assert {"kucoin", "rainbet", "swft", "tether", "circle", "coinbase", "kraken", "binance", "okx", "bybit",
            "hostinger", "supabase", "groq", "uniswap", "fbi-ic3", "carabinieri"} <= keys
    raw = json.loads(directory.CATALOGUE_PATH.read_text(encoding="utf-8"))
    assert not directory._forbidden_keys(raw)  # no verified / verified_by anywhere
    # No invented addresses: the only e-mail values are ones the organisation itself published to us
    # (reviewed one by one; each carries its source). Everything else stays "to be confirmed".
    published = {"circleblocklisting@circle.com": "circle", "subpoenas@circle.com": "circle",
                 "inforequests@tether.to": "tether"}  # Tether's LE inbox (Hadron LE page; named in Tether's replies)
    emails = {}
    for o in cat.orgs:
        for c in o.channels:
            if c.kind == "email" and c.value:
                emails[c.value] = o.key
                site = {"circle": "https://www.circle.com", "tether": "https://hadron.tether.to"}[o.key]
                assert c.source_url and c.source_url.startswith(site), c.key
                if o.key == "circle":
                    assert "auto-reply" in (c.notes or ""), c.key  # where the organisation published it
                else:
                    assert c.who == "le_only", c.key  # an LE inbox: never written to by a private party
            elif c.purpose in ("le_request", "compliance", "legal", "abuse") and c.kind != "webform":
                assert c.value is None, c.key  # "to be confirmed" from the organisation's own site
    assert emails == published
    found = set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", json.dumps(raw["orgs"])))
    assert found <= set(published) | {"compliance@circle.com"}  # the legacy inbox is only named as "do not use"
    ic3 = cat.by_key["fbi-ic3"]
    assert not any(c.kind == "email" for c in ic3.channels)
    assert ic3.portal_only and ic3.portal_url == "https://www.ic3.gov"
    uni = cat.by_key["uniswap"]
    assert uni.info_only and not uni.freeze_capable and not any(c.purpose == "le_request" for c in uni.channels)
    cara = {c.key: c for c in cat.by_key["carabinieri"].channels}
    assert cara["carabinieri.112"].value == "112" and cara["carabinieri.station"].value is None


def _cat(**channel):
    base = {"key": "acme.le", "kind": "email", "value": "compliance@acme.example", "purpose": "le_request",
            "source_url": "https://acme.example/law-enforcement"}
    base.update(channel)
    return {"version": 1, "orgs": [{"key": "acme", "name": "Acme", "aliases": [], "category": "exchange",
                                    "channels": [{k: v for k, v in base.items() if v is not ...}]}]}


def test_catalogue_validator_rules():
    assert directory.parse_catalogue(_cat()).by_key["acme"].channels[0].value == "compliance@acme.example"
    with pytest.raises(directory.CatalogueError, match="source_url"):
        directory.parse_catalogue(_cat(source_url=...))  # an invented address without its published source
    with pytest.raises(directory.CatalogueError, match="generic"):
        directory.parse_catalogue(_cat(value="jane.doe@acme.example"))  # a named person is never catalogued
    with pytest.raises(directory.CatalogueError, match="kind"):
        directory.parse_catalogue(_cat(kind="fax"))
    with pytest.raises(directory.CatalogueError, match="purpose"):
        directory.parse_catalogue(_cat(purpose="sales"))
    with pytest.raises(directory.CatalogueError, match="role"):
        directory.parse_catalogue(_cat(role_default="bcc"))
    with pytest.raises(directory.CatalogueError, match="'@'"):
        directory.parse_catalogue(_cat(kind="portal", value="https://x@acme.example"))
    with pytest.raises(directory.CatalogueError, match="verification"):
        directory.parse_catalogue(_cat(verified=True))
    dup = _cat()
    dup["orgs"][0]["channels"].append(dict(dup["orgs"][0]["channels"][0]))
    with pytest.raises(directory.CatalogueError, match="duplicate"):
        directory.parse_catalogue(dup)


def test_catalogue_is_cached_by_mtime(tmp_path):
    p = tmp_path / "channels.json"
    p.write_text(json.dumps(_cat(value=None)), encoding="utf-8")
    first = directory.load_catalogue(p)
    assert directory.load_catalogue(p) is first
    import os

    p.write_text(json.dumps({"version": 2, "orgs": []}), encoding="utf-8")
    st = p.stat()
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))
    assert directory.load_catalogue(p).version == 2
    assert directory.load_catalogue(tmp_path / "missing.json").orgs == ()


@pytest.mark.parametrize("bad", ["", "a@b", "Name <a@b.example>", '"a"@b.example', "a@[127.0.0.1]",
                                 "a@exämple.com", "a@b.example\r\nBcc: x@y.example", "x" * 65 + "@b.example",
                                 "a@" + "b" * 250 + ".example", "a@@b.example", "a@b..example", "a,b@c.example"])
def test_validate_address_refuses(bad):
    with pytest.raises(directory.DirectoryError):
        directory.validate_address(bad)


def test_validate_address_normalises_the_domain():
    assert directory.validate_address("  Compliance@Rainbet-Demo.EXAMPLE ") == "Compliance@rainbet-demo.example"


# --------------------------------------------------------------------------- matching
def test_org_for_matches_aliases_and_agencies(db, case):
    assert directory.org_for(_auth(db, case, "KuCoin")).key == "kucoin"
    assert directory.org_for(_auth(db, case, "SWFT / Bridgers")).key == "swft"
    assert directory.org_for(_auth(db, case, "FBI Internet Crime Complaint Center (IC3)")).key == "fbi-ic3"
    # the demo station is matched by the whole word "Carabinieri" in the agency name
    assert directory.org_for(_auth(db, case, "Carabinieri — Demo City station (demo)")).key == "carabinieri"
    # the prosecutor's office has its own (judicial) playbook
    assert directory.org_for(_auth(db, case, "Procura della Repubblica di Esempio (demo prosecutor's office)")).key == \
        "procura"


# --------------------------------------------------------------------------- the card
def test_card_merges_catalogue_entity_record_db_rows_and_case_recipients(db, case, clean_channels):
    admin = _user(db, "admin@tests.example")
    sysadmin = _user(db, "sysadmin@tests.example", system_admin=True)
    rainbet = _auth(db, case, "Rainbet")
    card = directory.channels_for(db, _access(case, admin, "admin"), rainbet)
    assert card.org.key == "rainbet"
    by_value = {}
    for e in card.entries:
        by_value.setdefault((e.kind, (e.value or "").lower()), []).append(e)
    assert all(len(v) == 1 for k, v in by_value.items() if k[1]), "de-duplicated on (kind, value)"
    assert [e.source for e in card.entries][:2] == ["catalogue", "catalogue"]  # catalogue first
    rec = by_value[("email", "compliance@rainbet-demo.example")][0]
    assert rec.source == "entity_record" and not rec.verified and rec.scope == "global"
    assert rec.meta["seen"]["in"] >= 1 and rec.meta["seen"]["out"] >= 1  # the auto-ack and the imported letter
    tbc = next(e for e in card.entries if e.catalogue_key == "rainbet.le")
    assert tbc.to_be_confirmed and tbc.group == "To be confirmed"
    # the letters' Cc (the PI firm, the victim) is never learned as the authority's contact
    assert ("email", "investigations@kestrel-ridge.example") not in by_value
    assert ("email", "victim@northbridge.example") not in by_value
    assert ("email", "case-desk@aegis.example") not in by_value  # the sender profile's own address is excluded
    # a global row verifying the entity record's address wins the merge; a case row is case-scoped
    directory.add_channel(db, _access(case, sysadmin, "admin"), rainbet, kind="email", value="compliance@rainbet-demo.example",
                          purpose="compliance", scope="global", verified=True, note="checked on rainbet.com")
    directory.add_channel(db, _access(case, admin, "admin"), rainbet, kind="email", value="kyc-desk@rainbet.example",
                          scope="case")
    db.commit()
    card = directory.channels_for(db, _access(case, admin, "admin"), rainbet)
    rec = [e for e in card.entries if (e.value or "").lower() == "compliance@rainbet-demo.example"]
    assert len(rec) == 1 and rec[0].verified and rec[0].scope == "global" and rec[0].id is not None
    row = next(e for e in card.entries if e.value == "kyc-desk@rainbet.example")
    assert row.scope == "case" and row.group == "This case only"
    stored = db.get(EntityChannel, row.id)
    assert stored.classification.value == "R2" and stored.case_id == case.id
    assert "compliance@rainbet-demo.example" in card.verified_addresses()


def test_card_masking_by_role(db, case, clean_channels):
    reader = _user(db, "read_only@tests.example")
    admin = _user(db, "admin@tests.example")
    rainbet = _auth(db, case, "Rainbet")
    directory.add_channel(db, _access(case, admin, "admin"), rainbet, kind="email", value="kyc-desk@rainbet.example")
    db.commit()
    card = directory.channels_for(db, _access(case, reader, "read_only"), rainbet)
    case_entries = [e for e in card.entries if e.scope == "case"]
    assert case_entries and all(e.masked for e in case_entries)
    assert "kyc-desk@rainbet.example" not in {e.value for e in card.entries}
    assert any(e.value == "k***@r***.example" for e in case_entries)
    assert any(e.value == "https://rainbet.com" for e in card.entries)  # catalogue / global stay readable
    assert not any(e.sendable for e in case_entries)
    ext = _user(db, "external@tests.example")
    hidden = directory.channels_for(db, _access(case, ext, "external"), rainbet)
    assert not hidden.visible and not hidden.entries


def test_info_only_and_portal_only_cards(client, db, case):
    from app import services

    run = services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")
    uni = next(a for a in desk.case_authorities(db, case, run=run) if a.name == "Uniswap (Universal Router)")
    ic3 = _auth(db, case, "FBI Internet Crime Complaint Center (IC3)")
    page = client.get(f"/cases/{case.id}/authorities/{ic3.key}").text
    assert "How to contact" in page and "Portal only" in page and "https://www.ic3.gov" in page
    assert "Non-custodial: information requests only" in client.get(f"/cases/{case.id}/authorities/{uni.key}").text


# --------------------------------------------------------------------------- permissions
def _post_channel(c, case, key, **data):
    tok = csrf_token(c, f"/cases/{case.id}/authorities/{key}")
    return c.post(f"/cases/{case.id}/authorities/{key}/channels", data={"csrf_token": tok, **data},
                  follow_redirects=False)


def test_who_may_add_and_verify_channels(db, case, client_for, clean_channels):
    kucoin = _auth(db, case, "KuCoin")
    form = {"kind": "email", "value": "lawenforcement@kucoin.example", "purpose": "le_request", "scope": "case"}
    inv = client_for("investigator", case=case)
    assert _post_channel(inv, case, kucoin.key, **form).status_code == 403
    admin = client_for("admin", case=case)
    r = _post_channel(admin, case, kucoin.key, **form)
    assert r.status_code == 303 and "ch_err" not in r.headers["location"]
    row = db.scalar(select(EntityChannel).where(EntityChannel.value == "lawenforcement@kucoin.example"))
    assert row.case_id == case.id and row.classification.value == "R2" and not row.verified
    assert _post_channel(admin, case, kucoin.key, **{**form, "scope": "global"}).status_code == 403
    # CSRF is required
    assert admin.post(f"/cases/{case.id}/authorities/{kucoin.key}/channels", data=form).status_code == 403
    # verify / unverify a case row: case admin yes, investigator no
    tok = csrf_token(admin, f"/cases/{case.id}/authorities/{kucoin.key}")
    assert admin.post(f"/cases/{case.id}/channels/{row.id}/verify",
                      data={"csrf_token": tok, "verified": "1", "back": kucoin.key},
                      follow_redirects=False).status_code == 303
    db.refresh(row)
    assert row.verified and row.verified_at is not None
    tok_i = csrf_token(inv, f"/cases/{case.id}/authorities/{kucoin.key}")
    assert inv.post(f"/cases/{case.id}/channels/{row.id}/verify",
                    data={"csrf_token": tok_i, "verified": "0"}).status_code == 403
    # catalogue verification and global rows: system admins only
    assert admin.post(f"/cases/{case.id}/channels/catalogue/kucoin.web/verify",
                      data={"csrf_token": tok, "verified": "1"}).status_code == 403
    sysadmin = client_for(None, system_admin=True)
    stok = csrf_token(sysadmin, "/directory")
    r = sysadmin.post("/directory/channels", data={"csrf_token": stok, "target": "org:kucoin", "kind": "portal",
                                                    "value": "https://www.kucoin.com/support", "purpose": "le_request",
                                                    "verified": "1"}, follow_redirects=False)
    assert r.status_code == 303 and "err=0" in r.headers["location"]
    glob = db.scalar(select(EntityChannel).where(EntityChannel.value == "https://www.kucoin.com/support"))
    assert glob.case_id is None and glob.org_key == "kucoin" and glob.verified and glob.classification.value == "I0"
    assert admin.post("/directory/channels", data={"csrf_token": tok, "target": "org:kucoin", "kind": "website",
                                                   "value": "https://x.example"}).status_code == 403
    r = sysadmin.post("/directory/channels/kucoin.web/verify", data={"csrf_token": stok, "verified": "1"},
                      follow_redirects=False)
    assert r.status_code == 303
    overlay = db.scalar(select(EntityChannel).where(EntityChannel.catalogue_key == "kucoin.web"))
    assert overlay.verified and overlay.case_id is None
    # a case admin cannot touch a global row from the case page either
    assert admin.post(f"/cases/{case.id}/channels/{glob.id}/disable",
                      data={"csrf_token": tok, "back": kucoin.key}).status_code == 403
    # audit rows: ids, kinds and domains only, never an address
    rows = db.scalars(select(AuditEvent).where(AuditEvent.object_type == "entity_channels")).all()
    assert rows and all("@" not in json.dumps(r.detail) for r in rows)
    page = sysadmin.get("/directory").text
    assert "KuCoin" in page and "https://www.kucoin.com/support" in page


def test_invalid_channel_values_are_refused(db, case, client_for, clean_channels):
    kucoin = _auth(db, case, "KuCoin")
    admin = client_for("admin", case=case)
    for kind, value in (("email", "Name <x@kucoin.example>"), ("portal", "http://insecure.example"),
                        ("phone", "+41 00 abc"), ("website", "javascript:alert(1)"), ("portal", "x@y.example")):
        r = _post_channel(admin, case, kucoin.key, kind=kind, value=value, scope="case")
        assert r.status_code == 303 and "ch_err=" in r.headers["location"], (kind, value)
    assert not db.scalars(select(EntityChannel).where(EntityChannel.case_id == case.id,
                                                      EntityChannel.entity_id == kucoin.entity.id)).all()


def test_touch_used_and_api(db, case, client_for, clean_channels):
    admin_user = _user(db, "admin@tests.example")
    kucoin = _auth(db, case, "KuCoin")
    row = directory.add_channel(db, _access(case, admin_user, "admin"), kucoin, kind="email",
                                value="lawenforcement@kucoin.example", scope="case", verified=True)
    db.commit()
    assert directory.touch_used(db, case, ["LawEnforcement@kucoin.example"]) == 1
    db.commit()
    assert db.get(EntityChannel, row.id).last_used_at is not None
    inv = client_for("investigator", case=case)
    data = inv.get(f"/api/cases/{case.id}/authorities/{kucoin.key}/channels").json()
    assert data["org"]["key"] == "kucoin"
    assert any(c["value"] == "lawenforcement@kucoin.example" and c["verified"] for c in data["channels"])
    assert client_for("read_only", case=case).get(
        f"/api/cases/{case.id}/authorities/{kucoin.key}/channels").status_code == 403
