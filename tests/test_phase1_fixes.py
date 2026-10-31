"""Phase 1 review fixes: contact masking on the authorities desk, the authorities union (engaged
earlier vs. latest trace), letters, seeding limits, rule-based next steps, AI context typing and
paths, evidence import (zip names, .rtfd members, walk order), evidence reference masking.

Every test works on its own copy of the demo case (reference DEMO-2026-9xx), seeded once per module,
so nothing here changes the shared demo case other tests use."""

from __future__ import annotations

import hashlib
import io
import json
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from conftest import DEMO_FIXTURE, TEST_FIXTURE, csrf_token, ungated
from sqlalchemy import select

from app import services
from app.ai import assistant
from app.ai.context import (
    authority_type,
    build_context,
    local_context,
    scrub_free_text,
    scrub_paths,
)
from app.ai.rules import RULE_LABEL, RULE_LABEL_OFF, derive, rule_summary
from app.core.permissions import CaseAccess
from app.db.models import (
    AIMode,
    Case,
    CaseRole,
    Chain,
    Classification,
    Correspondence,
    CorrespondenceKind,
    Entity,
    EvidenceFolder,
    LEContact,
    StopOrder,
    StopOrderStatus,
    TraceRun,
    TraceStatus,
)
from app.db.session import SessionLocal
from app.domain import correspondence as desk
from app.domain import evidence as ev
from app.fixture_sections import EXTERNAL_MAX_DAYS, SeedReport, _external_expiry
from app.reports.stop_orders import unescape_md

LE_EMAIL = "cybercrime@procura-esempio.example"  # fictional, from the demo fixture
PI_EMAIL = "mara.lindqvist@kestrel-ridge.example"
COMPLAINT_REF = "DEMO-IT-0000000000"


@pytest.fixture(scope="module")
def _fcase_id(tmp_path_factory):
    data = json.loads(TEST_FIXTURE.read_text(encoding="utf-8"))
    data["case"]["reference"] = f"DEMO-2026-9{uuid.uuid4().hex[:2].upper()}"
    path = tmp_path_factory.mktemp("fixfixture") / "case.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with SessionLocal() as s:
        case = services.seed_from_fixture(s, path)
        services.run_trace(s, case)
        return case.id


@pytest.fixture
def fcase(db, _fcase_id) -> Case:
    return db.get(Case, _fcase_id)


def _ro(client_for, case, tag="ro"):
    return client_for("read_only", case=case, email=f"fix.{tag}.{case.id}@tests.example")


def _auth(db, case, name: str) -> desk.Authority:
    return next(a for a in desk.case_authorities(db, case) if a.name == name)


# --------------------------------------------------------------------------- 1. LE contacts masked
def test_le_contact_details_are_masked_for_read_only_on_every_surface(db, fcase, client_for):
    procura = next(a for a in desk.case_authorities(db, fcase) if a.recipient_email == LE_EMAIL)
    assert procura.key.startswith("le-") and procura.is_contact_party
    corr = desk.log_entry(db, fcase, procura, actor=None, direction="in", channel="email", kind="reply",
                          subject="Assignment pending", body=f"Write to {LE_EMAIL} for the file.",
                          sender=LE_EMAIL, recipients=[PI_EMAIL], classification="R2")
    masked_le = ev.mask_email(LE_EMAIL)
    ro, inv = _ro(client_for, fcase), client_for("investigator", case=fcase, email=f"fix.inv.{fcase.id}@tests.example")

    page = ro.get(f"/cases/{fcase.id}/authorities/{procura.key}").text
    assert LE_EMAIL not in page and PI_EMAIL not in page and masked_le in page
    assert LE_EMAIL in inv.get(f"/cases/{fcase.id}/authorities/{procura.key}").text

    tl = ro.get(f"/api/cases/{fcase.id}/authorities/{procura.key}/timeline").json()
    row = next(i for i in tl["items"] if i["correspondence_id"] == corr.id)
    assert row["sender"] == masked_le and LE_EMAIL not in json.dumps(tl) and PI_EMAIL not in json.dumps(tl)
    assert masked_le in row["body"]
    rows = ro.get(f"/api/cases/{fcase.id}/authorities").json()
    assert LE_EMAIL not in json.dumps(rows) and any(r["recipient_email"] == masked_le for r in rows)

    exported = ro.get(f"/api/cases/{fcase.id}/authorities/correspondence/{corr.id}/md")
    assert exported.status_code == 200 and LE_EMAIL not in exported.text
    assert masked_le in unescape_md(exported.text)  # masked values are Markdown-escaped ('\\*')
    assert LE_EMAIL in inv.get(f"/api/cases/{fcase.id}/authorities/correspondence/{corr.id}/md").text


# --------------------------------------------------------------------------- 2. letter view, externals
def test_letter_view_masks_recipients_even_when_the_body_is_restricted(db, fcase, client_for):
    procura = next(a for a in desk.case_authorities(db, fcase) if a.recipient_email == LE_EMAIL)
    corr = desk.log_entry(db, fcase, procura, actor=None, direction="out", channel="email", kind="le_cover",
                          subject="Fund-flow summary", body="R3 body", recipients=[LE_EMAIL], cc=[PI_EMAIL],
                          classification="R3")
    page = _ro(client_for, fcase).get(f"/cases/{fcase.id}/authorities/correspondence/{corr.id}").text
    assert "Content restricted" in page and "R3 body" not in page
    assert LE_EMAIL not in page and PI_EMAIL not in page and ev.mask_email(LE_EMAIL) in page


def test_externals_see_stop_order_ids_only_for_shared_stop_orders(db, fcase, client_for):
    kucoin = _auth(db, fcase, "KuCoin")
    order = kucoin.stop_orders[0]
    desk.log_entry(db, fcase, kucoin, actor=None, direction="in", channel="email", kind="reply",
                   subject="Ticket opened", body="We are reviewing.", stop_order=order, shared_with_external=True)
    ext = client_for("external", case=fcase, email=f"fix.ext.{fcase.id}@tests.example")
    page = ext.get(f"/cases/{fcase.id}/authorities/{kucoin.key}").text
    assert "Ticket opened" in page and f"#{order.id}<" not in page and f"#o{order.id}" not in page
    own = next(c for c in order.correspondence if c.kind == CorrespondenceKind.STOP_ORDER)
    own.shared_with_external = True
    db.commit()
    try:
        page = ext.get(f"/cases/{fcase.id}/authorities/{kucoin.key}").text
        assert f'<span class="mono">#{order.id}</span>' in page and f"/stop-orders/{order.id}" not in page
    finally:
        own.shared_with_external = False
        db.commit()


# --------------------------------------------------------------------------- 3. the authorities union
def test_authorities_are_the_union_of_engaged_and_traced(db, fcase, client_for):
    traced = services.latest_run(db, fcase)
    cand_names = {c.entity_name for c in desk.freeze_candidates(db, traced)}
    facts = dict(fcase.facts)
    facts["complaints"] = [*facts["complaints"], {"authority": "Guardia di Finanza — Demo unit", "reference": None}]
    fcase.facts = facts
    empty = TraceRun(case=fcase, status=TraceStatus.COMPLETE, params={"provider_mode": "fixture"}, label="empty")
    db.add(empty)
    db.commit()
    try:
        rows = {a.name: a for a in desk.case_authorities(db, fcase)}
        engaged = [a for a in rows.values() if a.stop_orders and a.entity is not None and a.category not in ("hosting", "infra")]
        assert engaged and all(a.trace_label == "engaged earlier" and not a.in_trace for a in engaged)
        assert {"Supabase", "Groq", "Hostinger"} <= set(rows) and rows["Supabase"].trace_label is None
        gdf = rows["Guardia di Finanza — Demo unit"]
        assert gdf.key.startswith("complaint-") and gdf.is_le and gdf.virtual
        pi = rows["Kestrel Ridge Investigations GmbH"]
        assert pi.key == "pi-0" and pi.is_adviser and pi.category == "pi_firm"
        # a message logged on a virtual authority stays on it
        note = desk.log_entry(db, fcase, gdf, actor=None, direction="note", channel="phone", kind="other",
                              subject="Called the unit", body=None)
        assert note in desk.get_authority(db, fcase, gdf.key).correspondence
        # a stop order to a counterparty the latest run no longer reaches comes from the earlier run
        target = next(a for a in engaged if a.name in cand_names)
        latest = services.latest_run(db, fcase)
        assert latest.id == empty.id and target.candidate is None
        assert desk.letter_run(db, fcase, target, latest).id == traced.id and target.candidate is not None
        assert next(o for o in desk.template_options(target, traced) if o["key"] == "stop_order")["available"]
        # funds position and context say which run they use
        fp = derive(local_context(db, fcase), datetime.now(tz=UTC))["funds_position"]
        assert fp["based_on_run"]["run_id"] == empty.id and f"run #{empty.id}" in fp["method"]
        ctx = build_context(db, fcase, AIMode.REDACTED)
        by_name = {a["name"]: a for a in ctx["authorities"]}
        assert by_name[target.name]["engaged_earlier"] and not by_name[target.name]["in_latest_trace"]
        inv = client_for("investigator", case=fcase, email=f"fix.inv.{fcase.id}@tests.example")
        overview = inv.get(f"/cases/{fcase.id}?tab=overview").text
        assert f"funds position based on trace run <b>#{empty.id}</b>" in overview
        tab = inv.get(f"/cases/{fcase.id}?tab=authorities").text
        assert "engaged earlier" in tab and "Guardia di Finanza" in tab and "Kestrel Ridge Investigations GmbH" in tab
        # a second stop order to a target already contacted is refused (app.domain.request_gate: its follow-ups only)
        tok = csrf_token(inv, f"/cases/{fcase.id}/authorities/{target.key}")
        r = inv.post(f"/cases/{fcase.id}/authorities/{target.key}/letters",
                     data={"csrf_token": tok, "template": "stop_order"}, follow_redirects=False)
        assert r.status_code == 409 and "only a follow-up tied to it" in r.text
        # regenerating one through the desk for a target of the earlier run with only a draft (nobody asked yet) uses
        # that run and the additional paragraph (finding 4)
        fresh = next(a for a in desk.case_authorities(db, fcase, run=traced) if a.name in cand_names
                     and a.entity is not None and not a.contacted)
        draft = services.generate_stop_orders(db, fcase, traced, only=[fresh.candidate.entity_name])[0]
        target = desk.get_authority(db, fcase, fresh.key, run=latest)
        assert target is not None and target.candidate is None and target.stop_orders
        tok = csrf_token(inv, f"/cases/{fcase.id}/authorities/{target.key}")
        # one open request per provider: over its draft only when the form confirms it replaces that draft
        r = inv.post(f"/cases/{fcase.id}/authorities/{target.key}/letters",
                     data={"csrf_token": tok, "template": "stop_order", "extra_note": "Please confirm by phone."},
                     follow_redirects=False)
        assert r.status_code == 409 and f"open draft #{draft.id}" in r.text
        r = inv.post(f"/cases/{fcase.id}/authorities/{target.key}/letters",
                     data={"csrf_token": tok, "template": "stop_order", "extra_note": "Please confirm by phone.",
                           "replace_draft": f"o{draft.id}"}, follow_redirects=False)
        assert r.status_code == 303, r.text
        db.expire_all()
        corr = db.get(Correspondence, int(r.headers["location"].rsplit("/", 1)[1]))
        assert corr.meta["trace_run_id"] == traced.id and corr.stop_order.trace_run_id == traced.id
        body = corr.body_markdown
        assert "Please confirm by phone." in body
        assert body.index("Please confirm by phone.") < body.index("Yours faithfully,")  # the case's sender profile
        assert "Please confirm by phone." not in (corr.stop_order.notes or "")
    finally:
        db.rollback()
        for c in list(fcase.correspondence):
            if (c.meta or {}).get("authority_key", "").startswith("complaint-"):
                db.delete(c)
        db.delete(db.get(TraceRun, empty.id))
        fcase.facts = {**fcase.facts, "complaints": fcase.facts["complaints"][:-1]}
        db.commit()


def test_le_contact_that_is_a_pi_firm_is_not_law_enforcement(db, fcase):
    le = LEContact(case=fcase, agency="Acme Investigations Ltd", role="PI firm", jurisdiction="Switzerland",
                   classification=Classification.R3)
    other = LEContact(case=fcase, agency="Northwind Advisory", classification=Classification.R3)
    db.add_all([le, other])
    db.commit()
    try:
        assert desk.contact_category(le) == "pi_firm" and desk.contact_category(other) == "unknown"
        a = desk.get_authority(db, fcase, f"le-{le.id}")
        assert a.category == "pi_firm" and a.is_adviser and not a.is_le
        types = {r["agency"] for r in build_context(db, fcase, AIMode.REDACTED)["le_contacts"]}
        assert "PI firm (Switzerland)" in types and "Other organisation" in types
        assert authority_type("Acme Investigations Ltd", "Switzerland", category="pi_firm") == "PI firm (Switzerland)"
        assert authority_type("Carabinieri — Demo City station", None, category="law_enforcement") == "Carabinieri (Italy)"
        assert authority_type("Northwind Advisory", None, category="unknown") == "Other organisation"
    finally:
        db.delete(le)
        db.delete(other)
        db.commit()


# --------------------------------------------------------------------------- 4. additional paragraph
def test_additional_paragraph_goes_before_the_signature_of_every_letter(db, fcase):
    run = services.latest_run(db, fcase)
    kucoin = desk.get_authority(db, fcase, _auth(db, fcase, "KuCoin").key, run=run)
    for key in ("info_request", "status_request"):
        with ungated():  # KuCoin was asked already: the paragraph, not the request gate, is under test here
            corr = desk.generate_letter(db, fcase, kucoin, key, actor=None, run=run, extra_note="Extra *note* here.")
        body = corr.body_markdown
        assert "Extra \\*note\\* here." in body and body.index("Extra") < body.index("Yours faithfully,"), key
    assert desk.insert_before_signature("Dear X,\n\nText.\n", "Tail") == "Dear X,\n\nText.\n\nTail\n"


# --------------------------------------------------------------------------- 5. seeding limits
def test_seeder_clamps_external_expiry_to_ninety_days():
    now = datetime(2026, 10, 19, tzinfo=UTC)
    report = SeedReport()
    far = _external_expiry({"expires_at": "2027-06-30T00:00:00Z"}, 3, report, now)
    assert far == now + timedelta(days=EXTERNAL_MAX_DAYS) and report.notes and "team[3]" in report.notes[0]
    assert "@" not in report.notes[0]
    assert _external_expiry({"expires_in_days": 30}, 0, report, now) == now + timedelta(days=30)
    assert _external_expiry({}, 0, report, now) == now + timedelta(days=30)
    assert len(report.notes) == 1


def test_seeded_external_members_expire_within_ninety_days(fcase):
    limit = datetime.now(tz=UTC) + timedelta(days=EXTERNAL_MAX_DAYS)
    seeded = {m["email"] for m in json.loads(DEMO_FIXTURE.read_text(encoding="utf-8"))["team"]}
    externals = [m for m in fcase.members if m.role.value == "external" and m.user.email in seeded]
    assert externals and all(m.expires_at is not None and m.expires_at <= limit for m in externals)


# --------------------------------------------------------------------------- 7. rule-based next steps
def test_rule_steps_are_sorted_and_suggest_status_and_release_requests(db, fcase):
    swft = _auth(db, fcase, "SWFT / Bridgers")
    now = datetime.now(tz=UTC)
    late = StopOrder(case=fcase, entity=swft.entity, kind="freeze", status=StopOrderStatus.SENT, subject="Freeze",
                     body_markdown="x", sent_at=now - timedelta(days=3), response_due_at=now - timedelta(days=1))
    held = StopOrder(case=fcase, entity=swft.entity, kind="freeze", status=StopOrderStatus.SENT, subject="Freeze 2",
                     body_markdown="x", sent_at=now - timedelta(days=2), response_due_at=now + timedelta(days=5))
    db.add_all([late, held])
    db.commit()
    try:
        desk.record_stop_order_status(db, fcase, held, "frozen", actor=None, amount_held=Decimal("1.5"), asset="ETH")
        s = rule_summary(local_context(db, fcase))
        ranks = [{"high": 0, "medium": 1, "low": 2}[x["priority"]] for x in s["next_steps"]]
        assert ranks == sorted(ranks)
        actions = [x["action"] for x in s["next_steps"]]
        assert f"Send a status request to SWFT / Bridgers on the freeze request (stop order #{late.id})" in actions
        assert any(a.startswith("Send a release / return-of-funds request to SWFT / Bridgers") and f"#{held.id}" in a
                   for a in actions)
        # once a release request is on file the suggestion goes away
        authority = desk.get_authority(db, fcase, swft.key)
        desk.generate_letter(db, fcase, authority, "release_request", actor=None, ref=f"o{held.id}")
        actions = [x["action"] for x in rule_summary(local_context(db, fcase))["next_steps"]]
        assert not any(f"#{held.id}" in a and "release" in a for a in actions)
        # a drafted status request is not a sent one: the step asks to send the draft, until it is sent
        sr = desk.generate_letter(db, fcase, authority, "status_request", actor=None, ref=f"o{late.id}")
        assert sr.stop_order_id == late.id
        actions = [x["action"] for x in rule_summary(local_context(db, fcase))["next_steps"]]
        assert (f"Send the drafted status request (#{sr.id}) to SWFT / Bridgers on the freeze request "
                f"(stop order #{late.id})") in actions
        desk.mark_sent(db, fcase, sr, actor=None, sent_at=now, channel="email", external_ref="", due_days=7,
                       authority_key=swft.key)
        actions = [x["action"] for x in rule_summary(local_context(db, fcase))["next_steps"]]
        assert not any(f"stop order #{late.id}" in a and "status request" in a for a in actions)
    finally:
        db.rollback()
        for o in (late, held):
            for c in list(o.correspondence):
                db.delete(c)
            db.delete(o)
        db.commit()


def test_ai_off_is_labelled_differently_from_not_configured(db, fcase, monkeypatch):
    monkeypatch.setattr(assistant.ai_providers, "get_provider", lambda: None)
    fcase.ai_mode = AIMode.OFF
    db.commit()
    try:
        out = assistant.summarize_case(db, fcase)
        assert out["meta"]["label"] == RULE_LABEL_OFF and fcase.status_summary.endswith(RULE_LABEL_OFF)
        assert assistant.answer_question(db, fcase, "what next?").output.startswith(f"[{RULE_LABEL_OFF}]")
        fcase.ai_mode = AIMode.REDACTED
        db.commit()
        assert assistant.summarize_case(db, fcase)["meta"]["label"] == RULE_LABEL
    finally:
        fcase.ai_mode = AIMode.REDACTED
        db.commit()


# --------------------------------------------------------------------------- 8. paths in the context
@pytest.mark.parametrize("text", [
    "Original in Legal Docs/Demo Term Sheet.rtfd, signed", "see exports/addresses.tsv", "ACME Due Diligence/x.pdf",
    "Filed as Evidence/Bank statements/Statement March.pdf today", "Notes/sub dir/x y.docx",
])
def test_relative_evidence_paths_are_scrubbed(text):
    out = scrub_paths(text)
    assert "[PATH]" in out and "/" not in out and "Term Sheet" not in out and ".tsv" not in out
    assert "statements" not in out and "Statement" not in out and "sub dir" not in out and "Notes" not in out
    assert out.split("[PATH]")[0] == {"Orig": "Original in ", "see ": "see ", "ACME": "", "File": "Filed as ",
                                      "Note": ""}[text[:4]]


def test_paths_and_file_names_never_leave_in_descriptions(db, fcase):
    item = ev.add_note(db, fcase, title="Demo note", text="synthetic", folder="other",
                       description="Copy of Legal Docs/Demo Term Sheet.rtfd and the list wallets.tsv")
    db.commit()
    try:
        for mode in (AIMode.FULL, AIMode.REDACTED):
            row = next(e for e in build_context(db, fcase, mode)["evidence_index"] if e["id"] == item.id)
            text = json.dumps(row)
            assert "Term Sheet" not in text and "wallets.tsv" not in text, mode
        assert scrub_free_text("visit kucoin.com or rainbet.com") == "visit kucoin.com or rainbet.com"
        assert scrub_paths("https://example.com/a/b.pdf") == "https://example.com/a/b.pdf"
    finally:
        db.delete(item)
        db.commit()


# --------------------------------------------------------------------------- 9. linked letters in the folder
def test_stop_orders_folder_lists_linked_letters(fcase, client_for):
    page = _ro(client_for, fcase, "ro9").get(f"/cases/{fcase.id}?tab=evidence&folder=stop_orders_correspondence").text
    assert "linked stop order" in page and "linked letter" in page and "Nothing filed here yet" not in page
    assert f'id="ev-so-{fcase.stop_orders[0].id}"' in page and "linked stop order(s) &amp; letter(s)" in page
    tree = page.split('aria-label="Evidence folders"')[1].split("</aside>")[0]
    node = tree.split("folder=stop_orders_correspondence")[1].split("</a>")[0]
    assert '<span class="ev-count">0</span>' not in node


# --------------------------------------------------------------------------- 10. evidence import
def _clear_utf8_flag(data: bytes) -> bytes:
    out = bytearray(data)
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = out.find(sig)
        while i >= 0:
            flags = int.from_bytes(out[i + off:i + off + 2], "little") & ~0x800
            out[i + off:i + off + 2] = flags.to_bytes(2, "little")
            i = out.find(sig, i + 4)
    return bytes(out)


def test_zip_member_names_rtfd_files_and_walk_order(db, tmp_path):
    root = tmp_path / "case"
    (root / "Evidence").mkdir(parents=True)
    (root / "Evidence" / "z_loose.txt").write_bytes(b"same bytes")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Archive/Ricevuta_è.txt", b"receipt")
        zf.writestr("Archive/Flat note.rtfd", b"{\\rtf1 flat}")  # a flat file, not a bundle
        zf.writestr("Archive/copy.txt", b"same bytes")
    (root / "Evidence" / "a_archive.zip").write_bytes(_clear_utf8_flag(buf.getvalue()))
    with zipfile.ZipFile(root / "Evidence" / "a_archive.zip") as zf:
        assert not any(i.flag_bits & 0x800 for i in zf.infolist())

    cands = list(ev.walk_source(root))
    rels = [c.rel for c in cands]
    assert rels.index("Evidence/z_loose.txt") < rels.index("Evidence/a_archive.zip!Archive/copy.txt")
    by_rel = {c.rel: c for c in cands}
    named = by_rel["Evidence/a_archive.zip!Archive/Ricevuta_è.txt"]
    assert named.sha256 == hashlib.sha256(b"receipt").hexdigest()
    assert ev.hash_reference(ev.parse_reference(named.source_path))[0] == named.sha256
    flat = by_rel["Evidence/a_archive.zip!Archive/Flat note.rtfd"]
    assert flat.kind == "zip_member" and flat.sha256 == hashlib.sha256(b"{\\rtf1 flat}").hexdigest()
    assert ev.hash_reference(ev.parse_reference(flat.source_path))[0] == flat.sha256

    case = services.create_case(
        db, reference=f"TEST-FIX-{uuid.uuid4().hex[:8]}", title="import order", victim_name="Test Victim",
        victim_entity=None, loss_amount=Decimal(1), loss_asset="USDC", loss_usd=Decimal(1), fraud_date=None,
        chain=Chain.ETHEREUM, origin_tx=None, victim_wallet=None, perpetrator_wallet="0x" + "cd" * 20)
    report = ev.import_directory(db, case, root)
    db.commit()
    rows = {r.candidate.rel: r for r in report.rows}
    assert rows["Evidence/z_loose.txt"].action == "new"
    assert rows["Evidence/a_archive.zip!Archive/copy.txt"].action == "duplicate"


def test_zip_name_falls_back_to_cp437():
    info = zipfile.ZipInfo("été.txt")  # what zipfile decodes from raw cp437 bytes 0x82 't' 0x82
    info.flag_bits = 0
    assert ev.zip_name(info) == "été.txt"
    mojibake = zipfile.ZipInfo("Ricevuta_├¿.txt")  # UTF-8 'è' read as cp437
    mojibake.flag_bits = 0
    assert ev.zip_name(mojibake) == "Ricevuta_è.txt"


# --------------------------------------------------------------------------- 11. complaint refs in evidence
def test_evidence_metadata_masks_complaint_references_below_view_restricted(db, fcase, client_for):
    item = next(e for e in fcase.evidence_items if COMPLAINT_REF in (e.title or ""))
    ro = _ro(client_for, fcase, "ro11")
    masked = ev.mask_reference(COMPLAINT_REF)
    for url in (f"/cases/{fcase.id}?tab=evidence&folder=law_enforcement", f"/cases/{fcase.id}/evidence/{item.id}"):
        page = ro.get(url).text
        assert COMPLAINT_REF not in page and masked in page, url
    api = ro.get(f"/api/cases/{fcase.id}/evidence").json()
    assert COMPLAINT_REF not in json.dumps(api) and any(masked in r["title"] for r in api)
    ext = client_for("external", case=fcase, email=f"fix.ext11.{fcase.id}@tests.example")
    assert COMPLAINT_REF not in ext.get(f"/cases/{fcase.id}/evidence/{item.id}").text
    inv = client_for("investigator", case=fcase, email=f"fix.inv11.{fcase.id}@tests.example")
    assert COMPLAINT_REF in inv.get(f"/cases/{fcase.id}/evidence/{item.id}").text


def test_entity_lookup_helpers_are_stable(db, fcase):
    """The KuCoin authority keeps its key when the latest run changes (keys come from rows, not runs)."""
    kucoin = db.scalar(select(Entity).where(Entity.name == "KuCoin"))
    assert _auth(db, fcase, "KuCoin").key == f"entity-{kucoin.id}"
    assert desk.get_authority(db, fcase, "complaint-x") is None and desk.get_authority(db, fcase, "pi-99") is None
    assert EvidenceFolder.STOP_ORDERS_CORRESPONDENCE.value == "stop_orders_correspondence"


# --------------------------------------------------------------------------- 12. subjects, senders, exports masked
PI_NAME, PI_PHONE = "Mara Lindqvist", "+41 00 000 00 00"  # fictional, from the demo fixture


def _docx_text(data: bytes) -> str:
    from docx import Document

    return "\n".join(p.text for p in Document(io.BytesIO(data)).paragraphs)


def test_subjects_mask_contacts_and_references_on_every_surface(db, fcase, client_for):
    """A note naming the PI contact, her phone and the complaint reference: read-only and external
    members see it masked in the evidence folder, the page <title>, the timeline (page and API) and
    the .md / .docx exports; investigators see it in full."""
    procura = next(a for a in desk.case_authorities(db, fcase) if a.recipient_email == LE_EMAIL)
    subject = f"Call with {PI_NAME} re {COMPLAINT_REF} ({PI_PHONE})"
    corr = desk.log_entry(db, fcase, procura, actor=None, direction="note", channel="phone", kind="other",
                          subject=subject, body=f"Spoke to **{PI_NAME}** about {COMPLAINT_REF}.",
                          classification="R2", shared_with_external=True)
    raw = (PI_NAME, COMPLAINT_REF, PI_PHONE, "Lindqvist")
    try:
        ro = _ro(client_for, fcase, "ro12")
        ext = client_for("external", case=fcase, email=f"fix.ext12.{fcase.id}@tests.example")
        for who, c in (("read_only", ro), ("external", ext)):
            folder = c.get(f"/cases/{fcase.id}?tab=evidence&folder=stop_orders_correspondence").text
            assert f'id="ev-corr-{corr.id}"' in folder, who
            assert ev.mask_name(PI_NAME) in folder and ev.mask_reference(COMPLAINT_REF) in folder, who
            letter = c.get(f"/cases/{fcase.id}/authorities/correspondence/{corr.id}").text
            title = letter.split("<title>")[1].split("</title>")[0]
            assert ev.mask_name(PI_NAME) in title, (who, title)
            for page in (folder, letter, c.get(f"/cases/{fcase.id}/authorities/{procura.key}").text):
                assert not any(v in page for v in raw), who
        tl = ro.get(f"/api/cases/{fcase.id}/authorities/{procura.key}/timeline").json()
        row = next(i for i in tl["items"] if i["correspondence_id"] == corr.id)
        assert not any(v in json.dumps(tl) for v in raw)
        assert row["subject"] == (f"Call with {ev.mask_name(PI_NAME)} re {ev.mask_reference(COMPLAINT_REF)} "
                                  f"({ev.mask_phone(PI_PHONE)})")
        md = ro.get(f"/api/cases/{fcase.id}/authorities/correspondence/{corr.id}/md")
        assert md.status_code == 200 and not any(v in md.text for v in raw)
        assert "Lindqvist" not in md.headers["content-disposition"] and "0000000000" not in md.headers[
            "content-disposition"]
        docx = ro.get(f"/api/cases/{fcase.id}/authorities/correspondence/{corr.id}/docx")
        text = _docx_text(docx.content)
        assert not any(v in text for v in raw)
        assert ev.mask_name(PI_NAME) in text and ev.mask_reference(COMPLAINT_REF) in text  # asterisks kept
        inv = client_for("investigator", case=fcase, email=f"fix.inv12.{fcase.id}@tests.example")
        assert subject in inv.get(f"/cases/{fcase.id}/authorities/correspondence/{corr.id}").text
        assert subject in inv.get(f"/cases/{fcase.id}?tab=evidence&folder=stop_orders_correspondence").text
    finally:
        db.delete(corr)
        db.commit()


def test_le_contact_display_name_senders_and_name_variants_are_masked(db, fcase, client_for):
    """'Name <addr>' senders of an LE contact: both parts masked; a contact stored with a rank
    ('Brigadiere Tullio Esempione') is masked when a letter drops the rank or the first name."""
    name, email = "Brigadiere Tullio Esempione", "tullio.esempione@carabinieri-demo.example"
    le = LEContact(case_id=fcase.id, agency="Demo City police (test)", name=name, email=email,
                   classification=Classification.R3)
    db.add(le)
    db.commit()
    corr = None
    try:
        db.refresh(fcase)
        auth = desk.get_authority(db, fcase, f"le-{le.id}")
        assert auth is not None and auth.is_contact_party
        corr = desk.log_entry(db, fcase, auth, actor=None, direction="in", channel="email", kind="reply",
                              subject="Call with Tullio Esempione", sender=f"Tullio Esempione <{email}>",
                              body="Tullio Esempione confirms; Esempione calls back.", recipients=[PI_EMAIL],
                              classification="R2")
        ro = _ro(client_for, fcase, "ro13")
        tl = ro.get(f"/api/cases/{fcase.id}/authorities/{auth.key}/timeline").json()
        row = next(i for i in tl["items"] if i["correspondence_id"] == corr.id)
        assert row["sender"] == f"{ev.mask_name('Tullio Esempione')} <{ev.mask_email(email)}>"
        assert "Tullio" not in json.dumps(tl) and "Esempione" not in json.dumps(tl)
        for url in (f"/cases/{fcase.id}/authorities/{auth.key}", f"/cases/{fcase.id}/authorities/correspondence/{corr.id}"):
            page = ro.get(url).text
            assert "Tullio" not in page and "Esempione" not in page and "tullio.esempione" not in page, url
        mask = desk.contact_mask(CaseAccess(fcase, ro.user, CaseRole.READ_ONLY, None), auth)
        assert mask.value("Giulia Esempio <g.esempio@police-demo.example>") == "G. E***** <g***@p***.example>"
        assert mask.value(name) == ev.mask_name(name)
    finally:
        if corr is not None:
            db.delete(corr)
        db.delete(le)
        db.commit()


def test_pi_firm_addresses_and_contact_names_in_evidence_metadata_are_masked(db, fcase, client_for):
    generic = "info@kestrel-ridge.example"
    assert desk.contact_domains(fcase) == frozenset({"kestrel-ridge.example"})
    kucoin = _auth(db, fcase, "KuCoin")
    corr = desk.log_entry(db, fcase, kucoin, actor=None, direction="out", channel="email", kind="other",
                          subject="Follow-up", sender=f"Kestrel Ridge Investigations GmbH <{generic}>",
                          body=f"Reply to {generic}.", recipients=["compliance@kucoin-demo.example"],
                          classification="R2")
    item = ev.add_note(db, fcase, title="Call note", text="synthetic", folder="other",
                       description=f"Notes from {PI_NAME}", received_from=f"{PI_NAME} — Director")
    db.commit()
    try:
        ro = _ro(client_for, fcase, "ro14")
        for url in (f"/cases/{fcase.id}/authorities/correspondence/{corr.id}", f"/cases/{fcase.id}/authorities/{kucoin.key}",
                    f"/api/cases/{fcase.id}/authorities/{kucoin.key}/timeline"):
            page = ro.get(url).text
            assert generic not in page and ev.mask_email(generic) in page, url
            assert "compliance@kucoin-demo.example" in page, url  # a service's own desk stays visible
        for url in (f"/cases/{fcase.id}/evidence/{item.id}", f"/api/cases/{fcase.id}/evidence/{item.id}"):
            page = ro.get(url).text
            assert PI_NAME not in page and "Lindqvist" not in page and ev.mask_name(PI_NAME) in page, url
        inv = client_for("investigator", case=fcase, email=f"fix.inv14.{fcase.id}@tests.example")
        assert PI_NAME in inv.get(f"/cases/{fcase.id}/evidence/{item.id}").text
    finally:
        db.delete(corr)
        db.delete(item)
        db.commit()


def test_redactor_matches_whole_words_only():
    mask = ev.RefMask({"lindqvist": "L*****", "demo-it-0000000000": "DEMO-IT-******00"})
    assert mask("Lindqvist, DEMO-IT-0000000000.") == "L*****, DEMO-IT-******00."
    assert mask("Lindqvists and XDEMO-IT-0000000000") == "Lindqvists and XDEMO-IT-0000000000"
    assert mask("**Lindqvist**", md=True) == "**L\\*\\*\\*\\*\\***"


# --------------------------------------------------------------------------- review round 3 (masking minors)
def test_stop_orders_api_masks_subject_and_recipient_below_manage_le_contacts(db, fcase, client_for):
    """GET /api/cases/{id}/stop-orders: the subject goes through the ContactMask (contact names,
    phones, complaint references) and recipient_email through mask.value, like the HTML and the
    timeline API; investigators see both in full."""
    kucoin = db.scalar(select(Entity).where(Entity.name == "KuCoin"))
    subject = f"Preservation request re {COMPLAINT_REF}, contact {PI_NAME} ({PI_PHONE})"
    order = StopOrder(case=fcase, entity=kucoin, kind="preservation", status=StopOrderStatus.DRAFT, subject=subject,
                      body_markdown="synthetic", recipient_email=LE_EMAIL, identifiers={})
    db.add(order)
    db.commit()
    try:
        ro = _ro(client_for, fcase, "ro15")
        rows = ro.get(f"/api/cases/{fcase.id}/stop-orders").json()
        row = next(r for r in rows if r["id"] == order.id)
        assert row["restricted"] and row["body_markdown"] is None
        assert row["recipient_email"] == ev.mask_email(LE_EMAIL)
        assert row["subject"] == (f"Preservation request re {ev.mask_reference(COMPLAINT_REF)}, contact "
                                  f"{ev.mask_name(PI_NAME)} ({ev.mask_phone(PI_PHONE)})")
        text = json.dumps(rows)
        for raw in (LE_EMAIL, COMPLAINT_REF, PI_NAME, PI_PHONE, "Lindqvist"):
            assert raw not in text, raw
        inv = client_for("investigator", case=fcase, email=f"fix.inv15.{fcase.id}@tests.example")
        row = next(r for r in inv.get(f"/api/cases/{fcase.id}/stop-orders").json() if r["id"] == order.id)
        assert row["subject"] == subject and row["recipient_email"] == LE_EMAIL
    finally:
        db.delete(order)
        db.commit()


def test_contact_values_collect_complaint_contacts(db, fcase, client_for):
    """facts['complaints'][] e-mail / phone / name fields are masked like LE and PI contacts."""
    facts_before = dict(fcase.facts)
    facts = dict(fcase.facts)
    email, phone, officer = "denunce@stazione-demo.example", "+39 00 0000 0000", "Appuntato Rocco Esempietto"
    facts["complaints"] = [*facts["complaints"], {"authority": "Carabinieri — Demo test station",
                                                  "reference": "DEMO-IT-3333333333", "email": email,
                                                  "phone": phone, "officer": officer}]
    fcase.facts = facts
    db.commit()
    try:
        values = desk.contact_values(fcase)
        assert values[email] == ev.mask_email(email) and values[phone.lower()] == ev.mask_phone(phone)
        assert values[officer.lower()] == ev.mask_name(officer) and "rocco esempietto" in values
        kucoin = _auth(db, fcase, "KuCoin")
        corr = desk.log_entry(db, fcase, kucoin, actor=None, direction="note", channel="phone", kind="other",
                              subject=f"Station {email} / {phone} asked about Rocco Esempietto",
                              body="synthetic", classification="R2")
        try:
            ro = _ro(client_for, fcase, "ro16")
            tl = ro.get(f"/api/cases/{fcase.id}/authorities/{kucoin.key}/timeline").json()
            row = next(i for i in tl["items"] if i["correspondence_id"] == corr.id)
            assert email not in row["subject"] and phone not in row["subject"] and "Esempietto" not in row["subject"]
            assert ev.mask_email(email) in row["subject"]
        finally:
            db.delete(corr)
            db.commit()
    finally:
        fcase.facts = facts_before
        db.commit()
