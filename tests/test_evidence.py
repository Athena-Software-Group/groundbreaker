"""Evidence register: hashing, zip / .rtfd indexing, folder mapping, the vault guard, role rules,
LE-contact masking, integrity checks, the importer CLI and the synthetic demo artifacts."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
from conftest import REPO_ROOT, csrf_token
from sqlalchemy import select

from app import services
from app.db.models import (
    AuditEvent,
    Case,
    Chain,
    Classification,
    EvidenceFolder,
    EvidenceItem,
    EvidenceStorage,
    LEContact,
    Notification,
)
from app.domain import evidence as ev

DEMO_DIR = REPO_ROOT / "data" / "fixtures" / "demo_evidence"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _tok(client, case) -> str:
    return csrf_token(client, f"/cases/{case.id}?tab=evidence")


@pytest.fixture
def vault(tmp_path, monkeypatch):
    path = tmp_path / "vault"
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(path))
    return path


@pytest.fixture
def originals(tmp_path, monkeypatch, case):
    """The demo case's folder of 'originals' (<root>/<case reference>/) outside the repo; <root> is
    the web reference root."""
    root = tmp_path / "originals"
    (root / case.reference).mkdir(parents=True)
    monkeypatch.setenv("AEGIS_EVIDENCE_ROOTS", str(root))
    return root / case.reference


def _case_folder(root: Path) -> Path:
    """A miniature case folder shaped like a typical intake (synthetic names and bytes)."""
    (root / "Stop Orders" / "Preservation request DEMO.rtfd").mkdir(parents=True)
    (root / "Stop Orders" / "Preservation request DEMO.rtfd" / "TXT.rtf").write_bytes(b"{\\rtf1 demo letter}")
    (root / "Stop Orders" / "Preservation request DEMO.rtfd" / "image.png").write_bytes(PNG)
    (root / "Legal Docs").mkdir()
    (root / "Legal Docs" / "Term sheet DEMO.txt").write_text("term sheet")
    (root / "Exempla Due Diligence").mkdir()
    (root / "Exempla Due Diligence" / "Certificate 2026-03-20.txt").write_text("certificate")
    (root / "Evidence").mkdir()
    (root / "Evidence" / "Police_statement_DEMO.txt").write_text("statement")
    (root / "Evidence" / "IC3_receipt.txt").write_text("ic3")
    (root / "Evidence" / "WhatsApp chat export.txt").write_text("chat")
    (root / "Evidence" / "meeting.mp4").write_bytes(b"\x00\x00\x00\x18ftypmp42")
    (root / "Evidence" / "email from persona.png").write_bytes(PNG + b"email")
    (root / "Evidence" / "Fund Flow Graph.png").write_bytes(PNG + b"graph")
    (root / "Evidence" / "Invoice 001.txt").write_text("invoice")
    (root / "Evidence" / "misc.bin").write_bytes(b"misc")
    (root / "Evidence" / "copy of chat.txt").write_text("chat")  # same bytes as the WhatsApp export
    (root / "Evidence" / ".DS_Store").write_bytes(b"\x00Bud1")
    with zipfile.ZipFile(root / "Evidence" / "Screenshots.zip", "w") as zf:
        zf.writestr("Screenshots/", b"")
        zf.writestr("Screenshots/shot1.png", PNG + b"1")
        zf.writestr("Screenshots/.DS_Store", b"\x00Bud1")
        zf.writestr("__MACOSX/Screenshots/._shot1.png", b"apple double")
        zf.writestr("Screenshots/Note.rtfd/TXT.rtf", b"{\\rtf1 zipped note}")
        zf.writestr("Screenshots/Note.rtfd/attachment.png", PNG + b"att")
    return root


# --------------------------------------------------------------------------- hashing / walking
def test_sha256_of_files_streams_and_notes(tmp_path):
    data = b"x" * (3 * ev.CHUNK + 17)  # several chunks
    p = tmp_path / "big.bin"
    p.write_bytes(data)
    assert ev.sha256_file(p) == (_sha(data), len(data))
    assert ev.sha256_bytes(b"abc") == (_sha(b"abc"), 3)


def test_zip_members_are_indexed_without_extracting(tmp_path):
    root = _case_folder(tmp_path / "case")
    before = sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))
    cands = {c.rel: c for c in ev.walk_source(root)}
    after = sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))
    assert before == after  # nothing extracted or written next to the originals

    shot = cands["Evidence/Screenshots.zip!Screenshots/shot1.png"]
    assert shot.kind == "zip_member" and shot.sha256 == _sha(PNG + b"1") and shot.size == len(PNG) + 1
    assert shot.source_path.endswith("Screenshots.zip!Screenshots/shot1.png")
    container = (root / "Evidence" / "Screenshots.zip").read_bytes()
    assert shot.meta["container_sha256"] == _sha(container)
    # an .rtfd inside the zip is one item, hashed as its TXT.rtf; attachments, litter and __MACOSX skipped
    note = cands["Evidence/Screenshots.zip!Screenshots/Note.rtfd"]
    assert note.kind == "rtfd" and note.sha256 == _sha(b"{\\rtf1 zipped note}")
    assert not [r for r in cands if "__MACOSX" in r or r.endswith(".DS_Store") or "attachment.png" in r]
    assert "Evidence/Screenshots.zip" not in cands  # the archive itself is not an item


def test_rtfd_bundle_is_one_item_hashed_as_txt_rtf(tmp_path):
    root = _case_folder(tmp_path / "case")
    cands = {c.rel: c for c in ev.walk_source(root)}
    bundle = cands["Stop Orders/Preservation request DEMO.rtfd"]
    assert bundle.kind == "rtfd" and bundle.sha256 == _sha(b"{\\rtf1 demo letter}")
    assert bundle.meta["bundle_files"] == 1
    assert not [r for r in cands if r.startswith("Stop Orders/Preservation request DEMO.rtfd/")]
    assert not [r for r in cands if r.endswith(".DS_Store")]


def test_reference_hash_reads_zip_members_and_bundles(tmp_path):
    root = _case_folder(tmp_path / "case")
    member = ev.parse_reference(f"{root}/Evidence/Screenshots.zip!Screenshots/shot1.png")
    assert member.kind == "zip_member" and ev.hash_reference(member)[0] == _sha(PNG + b"1")
    bundle = ev.parse_reference(f"{root}/Stop Orders/Preservation request DEMO.rtfd")
    assert bundle.kind == "rtfd" and ev.hash_reference(bundle)[0] == _sha(b"{\\rtf1 demo letter}")


# --------------------------------------------------------------------------- mapping rules
@pytest.mark.parametrize("rel, folder, section", [
    ("Stop Orders/Urgent Preservation Request.rtfd", "stop_orders_correspondence", None),
    ("Legal Docs/Demo Term Sheet.rtfd", "legal", None),
    ("Legal Docs/Power of Attorney.pdf", "legal", None),  # folder rules win over keywords
    ("ACME Due Diligence/Bank/statement.pdf", "financial", None),
    ("ACME Due Diligence.zip!ACME Due Diligence/x.pdf", "financial", None),
    ("Evidence/Police_report_DEMO.pdf", "law_enforcement", "reports"),
    ("Evidence/IC3_complaint.pdf", "law_enforcement", "reports"),
    ("Evidence/Witness statement.docx", "law_enforcement", "reports"),
    ("Evidence/Power-of-Attorney signed.pdf", "law_enforcement", "reports"),
    ("Evidence/Power of Attorney.pdf", "law_enforcement", "reports"),
    ("Evidence/WhatsApp Chat - persona.zip!_chat.txt", "digital_artifacts", "messaging"),
    ("Evidence/call transcript.txt", "digital_artifacts", "recordings"),
    ("Evidence/Zoom meeting.mp4", "digital_artifacts", "recordings"),
    ("Evidence/recording.mp4", "digital_artifacts", "recordings"),
    ("Evidence/email from CFO.png", "digital_artifacts", "emails"),
    ("Evidence/Invoice 2026-10.pdf", "investigator_reports", None),
    ("Evidence/Work Product - tracing.pdf", "investigator_reports", None),
    ("Evidence/Intelligence Report.pdf", "investigator_reports", None),
    ("Evidence/Fund Flow Graph.png", "investigator_reports", None),
    ("Evidence/IMG_0001.jpeg", "digital_artifacts", "screenshots"),
    ("Evidence/notes.docx", "other", None),
    ("Evidence/management summary.pdf", "other", None),  # 'agent' matches whole words only
])
def test_default_mapping_rules(rel, folder, section):
    got_folder, got_section, _ = ev.Mapping().classify(rel)
    assert (got_folder.value, got_section) == (folder, section)


def test_custom_mapping_runs_before_defaults(tmp_path):
    path = tmp_path / "mapping.json"
    path.write_text(json.dumps({"rules": [
        {"glob": "*bank*", "folder": "financial", "tags": ["bank"], "classification": "R3"},
        {"ext": "eml", "folder": "digital_artifacts", "section": "emails"},
    ], "default_folder": "other", "exclude": ["*.tmp"]}))
    m = ev.load_mapping(path)
    assert m.classify("Evidence/bank police letter.pdf")[0] == EvidenceFolder.FINANCIAL
    assert m.classify("Evidence/x.eml")[:2] == (EvidenceFolder.DIGITAL_ARTIFACTS, "emails")
    assert m.classify("Evidence/IC3.pdf")[0] == EvidenceFolder.LAW_ENFORCEMENT  # defaults still apply
    path.write_text(json.dumps({"rules": [{"folder": "legal"}]}))
    with pytest.raises(ev.EvidenceError, match="no condition"):
        ev.load_mapping(path)


def test_import_dedupes_by_sha_and_is_idempotent(db, case, tmp_path):
    root = _case_folder(tmp_path / "case")
    report = ev.import_directory(db, case, root, mode="reference")
    db.commit()
    by_rel = {r.candidate.rel: r for r in report.rows}
    assert by_rel["Evidence/copy of chat.txt"].action == "duplicate"
    original = db.get(EvidenceItem, by_rel["Evidence/WhatsApp chat export.txt"].item_id)
    assert original.storage == EvidenceStorage.REFERENCE and "has-duplicate" in original.tags
    assert original.meta["duplicates"] == [str(root.resolve() / "Evidence" / "copy of chat.txt")]
    assert original.folder == EvidenceFolder.DIGITAL_ARTIFACTS and original.meta["section"] == "messaging"
    cert = db.get(EvidenceItem, by_rel["Exempla Due Diligence/Certificate 2026-03-20.txt"].item_id)
    assert cert.folder == EvidenceFolder.FINANCIAL and cert.doc_date.date().isoformat() == "2026-03-20"
    shot = db.get(EvidenceItem, by_rel["Evidence/Screenshots.zip!Screenshots/shot1.png"].item_id)
    assert shot.source_path.endswith(".zip!Screenshots/shot1.png") and shot.sha256 == _sha(PNG + b"1")
    assert ev.current_hash(shot)[0] == shot.sha256
    created = len(report.created)

    again = ev.import_directory(db, case, root, mode="reference")
    db.commit()
    assert not again.created and {r.action for r in again.rows} <= {"unchanged", "duplicate"}
    assert created == len(report.rows) - 1


def test_import_dry_run_writes_nothing(db, case, tmp_path):
    root = _case_folder(tmp_path / "case")
    (root / "Evidence" / "unique dry run.txt").write_text(f"unique {tmp_path}")
    (root / "Evidence" / "unique dry run copy.txt").write_text(f"unique {tmp_path}")
    n = len(case.evidence_items)
    report = ev.import_directory(db, case, root, dry_run=True)
    db.rollback()
    db.refresh(case)
    assert len(case.evidence_items) == n and not report.created
    actions = {r.candidate.rel: r.action for r in report.rows}
    assert actions["Evidence/unique dry run copy.txt"] == "new"  # walked first (sorted)
    assert actions["Evidence/unique dry run.txt"] == "duplicate"  # dedupe works within a dry run too


def test_import_cli(db, case, tmp_path, capsys):
    from scripts import import_evidence

    root = tmp_path / "cli"
    root.mkdir()
    (root / "IC3 receipt cli.txt").write_text("cli receipt")
    assert import_evidence.main(["--case", case.reference, "--source", str(root), "--dry-run"]) == 0
    assert "dry run: nothing written" in capsys.readouterr().out
    assert not db.scalar(select(EvidenceItem).where(EvidenceItem.sha256 == _sha(b"cli receipt")))
    assert import_evidence.main(["--case", case.reference, "--source", str(root)]) == 0
    item = db.scalar(select(EvidenceItem).where(EvidenceItem.sha256 == _sha(b"cli receipt")))
    assert item.folder == EvidenceFolder.LAW_ENFORCEMENT and item.storage == EvidenceStorage.REFERENCE
    note = db.scalars(select(Notification).where(Notification.case_id == case.id,
                                                 Notification.event_type == "evidence_added")
                      .order_by(Notification.id.desc())).first()
    assert note and "cli" not in note.title.lower() and "receipt" not in (note.body or "")


def test_import_refuses_sources_inside_the_repo(db, case):
    with pytest.raises(ev.EvidenceError, match="inside the repository"):
        ev.import_directory(db, case, REPO_ROOT / "docs", mode="reference")


# --------------------------------------------------------------------------- vault guard / upload
def test_upload_refused_when_vault_unset(client, case, monkeypatch):
    monkeypatch.delenv("AEGIS_VAULT_DIR", raising=False)
    n = len(case.evidence_items)
    r = client.post(f"/cases/{case.id}/evidence/upload", data={"csrf_token": _tok(client, case), "folder": "other"},
                    files={"file": ("x.txt", b"unset vault", "text/plain")}, follow_redirects=False)
    assert r.status_code == 303 and "ev_err=1" in r.headers["location"]
    assert "AEGIS_VAULT_DIR" in client.get(r.headers["location"]).text
    case_items = client.get(f"/api/cases/{case.id}/evidence").json()
    assert len(case_items) >= n and not [i for i in case_items if i["sha256"] == _sha(b"unset vault")]


def test_upload_refused_when_vault_inside_repo(client, case, monkeypatch):
    inside = REPO_ROOT / "data" / "vault-inside-repo-test"
    monkeypatch.setenv("AEGIS_VAULT_DIR", str(inside))
    with pytest.raises(ev.EvidenceError, match="inside the repository"):
        ev.vault_dir()
    r = client.post(f"/cases/{case.id}/evidence/upload", data={"csrf_token": _tok(client, case), "folder": "other"},
                    files={"file": ("x.txt", b"inside repo", "text/plain")}, follow_redirects=False)
    assert r.status_code == 303 and "ev_err=1" in r.headers["location"]
    assert not inside.exists()
    assert not [i for i in client.get(f"/api/cases/{case.id}/evidence").json() if i["sha256"] == _sha(b"inside repo")]
    monkeypatch.setenv("AEGIS_VAULT_DIR", "relative/vault")
    with pytest.raises(ev.EvidenceError, match="absolute"):
        ev.vault_dir()


def test_upload_stores_by_uuid_with_hash(client, case, vault, db):
    data = PNG + b"upload"
    r = client.post(f"/cases/{case.id}/evidence/upload",
                    data={"csrf_token": _tok(client, case), "folder": "digital_artifacts", "section": "screenshots",
                          "classification": "R2", "tags": "persona, upload", "doc_date": "2026-10-12"},
                    files={"file": ("Screenshot persona chat.png", data, "image/png")}, follow_redirects=False)
    assert r.status_code == 303 and "ev_err" not in r.headers["location"]
    item = db.scalar(select(EvidenceItem).where(EvidenceItem.sha256 == _sha(data)))
    assert item.storage == EvidenceStorage.VAULT and item.title == "Screenshot persona chat.png"
    assert item.size_bytes == len(data) and item.mime == "image/png" and item.tags == ["persona", "upload"]
    stored = list((vault / str(case.id)).iterdir())
    assert [p.name for p in stored if p.read_bytes() == data] == [item.vault_path.split("/")[-1]]
    assert all(len(p.name) == 32 and "persona" not in p.name for p in stored)  # uuid names only
    assert not vault.resolve().is_relative_to(REPO_ROOT)
    page = client.get(f"/cases/{case.id}/evidence/{item.id}")
    assert page.status_code == 200 and f"/evidence/{item.id}/content" in page.text  # image preview
    img = client.get(f"/cases/{case.id}/evidence/{item.id}/content")
    assert img.status_code == 200 and img.headers["content-type"] == "image/png" and img.content == data
    assert "sandbox" in img.headers["content-security-policy"]


# --------------------------------------------------------------------------- references via the web
def test_reference_is_hashed_never_copied_and_path_admin_only(client_for, case, originals, vault, db):
    original = originals / "Bank statement DEMO.txt"
    original.write_bytes(b"reference bytes")
    inv = client_for("investigator", case=case)
    r = inv.post(f"/cases/{case.id}/evidence/reference",
                 data={"csrf_token": _tok(inv, case), "source_path": str(original), "folder": "legal"},
                 follow_redirects=False)
    assert r.status_code == 303 and "ev_err" not in r.headers["location"], r.headers["location"]
    item = db.scalar(select(EvidenceItem).where(EvidenceItem.sha256 == _sha(b"reference bytes")))
    assert item.storage == EvidenceStorage.REFERENCE and item.source_path == str(original) and item.verified_at
    assert not any(vault.rglob("*")) if vault.exists() else True  # nothing copied
    assert "source_path" not in inv.get(f"/api/cases/{case.id}/evidence/{item.id}").json()
    assert str(original) not in inv.get(f"/cases/{case.id}/evidence/{item.id}").text
    admin = client_for("admin", case=case)
    assert admin.get(f"/api/cases/{case.id}/evidence/{item.id}").json()["source_path"] == str(original)
    assert str(original) in admin.get(f"/cases/{case.id}/evidence/{item.id}").text


@pytest.mark.parametrize("where", ["repo", "outside_roots", "relative"])
def test_reference_paths_are_restricted(client, case, originals, tmp_path, where):
    path = {"repo": str(REPO_ROOT / ".env.example"), "relative": "x.pdf",
            "outside_roots": str(tmp_path / "elsewhere.txt")}[where]
    (tmp_path / "elsewhere.txt").write_text("elsewhere")
    r = client.post(f"/cases/{case.id}/evidence/reference",
                    data={"csrf_token": _tok(client, case), "source_path": path, "folder": "other"},
                    follow_redirects=False)
    assert r.status_code == 303 and "ev_err=1" in r.headers["location"]


# --------------------------------------------------------------------------- role rules
@pytest.fixture
def role_items(db, case):
    def note(title, cls, folder="other", shared=False):
        item = ev.add_note(db, case, title=title, text=f"text of {title}", folder=folder, classification=cls)
        item.shared_with_external = shared
        return item

    items = {
        "r3": note("Role test R3 police receipt", "R3", "law_enforcement"),
        "r2": note("Role test R2 chat excerpt", "R2", "digital_artifacts"),
        "shared_r2": note("Role test shared R2", "R2", "law_enforcement", shared=True),
        "shared_r3": note("Role test shared R3", "R3", "law_enforcement", shared=True),
        "fin": note("Role test financial", "R3", "financial", shared=True),
    }
    db.commit()
    return items


def test_read_only_sees_metadata_but_not_r3_content(client_for, case, role_items):
    ro = client_for("read_only", case=case)
    ids = {i["id"] for i in ro.get(f"/api/cases/{case.id}/evidence").json()}
    assert {role_items[k].id for k in ("r3", "r2", "shared_r2", "shared_r3")} <= ids
    r3 = role_items["r3"]
    assert ro.get(f"/cases/{case.id}/evidence/{r3.id}/download").status_code == 403
    assert ro.get(f"/cases/{case.id}/evidence/{r3.id}/content").status_code == 403
    assert "inline_text" not in ro.get(f"/api/cases/{case.id}/evidence/{r3.id}").json()
    page = ro.get(f"/cases/{case.id}/evidence/{r3.id}")
    assert page.status_code == 200 and "text of Role test R3" not in page.text and "metadata only" in page.text
    r2 = role_items["r2"]
    assert "text of Role test R2" in ro.get(f"/cases/{case.id}/evidence/{r2.id}").text
    dl = ro.get(f"/cases/{case.id}/evidence/{r2.id}/download")
    assert dl.status_code == 200 and dl.content == b"text of Role test R2 chat excerpt"
    assert "attachment" in dl.headers["content-disposition"] and "Role" not in dl.headers["content-disposition"]
    # read-only cannot add evidence
    assert ro.post(f"/cases/{case.id}/evidence/note", data={"csrf_token": _tok(ro, case), "title": "x",
                                                           "text": "y"}).status_code == 403


def test_external_sees_only_shared_items(client_for, case, role_items):
    ext = client_for("external", case=case)
    ids = {i["id"] for i in ext.get(f"/api/cases/{case.id}/evidence").json()}
    assert role_items["shared_r2"].id in ids and role_items["shared_r3"].id in ids
    assert not ids & {role_items[k].id for k in ("r3", "r2", "fin")}
    assert ext.get(f"/cases/{case.id}/evidence/{role_items['r2'].id}").status_code == 404
    assert ext.get(f"/cases/{case.id}/evidence/{role_items['fin'].id}").status_code == 404
    assert ext.get(f"/cases/{case.id}/evidence/{role_items['shared_r2'].id}/download").status_code == 200
    assert ext.get(f"/cases/{case.id}/evidence/{role_items['shared_r3'].id}/download").status_code == 403
    tab = ext.get(f"/cases/{case.id}?tab=evidence")
    assert tab.status_code == 200 and "Role test shared R2" in tab.text and "Role test R2 chat" not in tab.text
    assert ext.get(f"/api/cases/{case.id}/evidence/le-contacts").status_code == 403


def test_financial_folder_is_admin_only(client_for, case, role_items):
    fin = role_items["fin"]
    inv = client_for("investigator", case=case)
    assert inv.get(f"/cases/{case.id}/evidence/{fin.id}").status_code == 404
    assert fin.id not in {i["id"] for i in inv.get(f"/api/cases/{case.id}/evidence").json()}
    tab = inv.get(f"/cases/{case.id}?tab=evidence&folder=financial")
    assert tab.status_code == 200 and "Role test financial" not in tab.text and "admin only" in tab.text
    admin = client_for("admin", case=case)
    assert admin.get(f"/cases/{case.id}/evidence/{fin.id}").status_code == 200
    assert "Role test financial" in admin.get(f"/cases/{case.id}?tab=evidence&folder=financial").text


def test_other_case_items_and_non_members_get_404(client_for, case, role_items, db):
    from app import services
    from app.db.models import Case, Chain

    other = db.scalar(select(Case).where(Case.reference == "EV-OTHER-001")) or services.create_case(
        db, reference="EV-OTHER-001", title="other", victim_name="x", victim_entity=None, loss_amount=1,
        loss_asset="USDC", loss_usd=1, fraud_date=None, chain=Chain.ETHEREUM, origin_tx="0x" + "1" * 64,
        victim_wallet=None, perpetrator_wallet=None)
    admin = client_for("admin", case=case)
    assert admin.get(f"/cases/{other.id}/evidence/{role_items['r2'].id}").status_code == 404
    nobody = client_for(None, case=case)
    assert nobody.get(f"/cases/{case.id}/evidence/{role_items['r2'].id}").status_code == 404


def test_downloads_are_audited(client_for, case, role_items, db):
    from app.db.models import AuditEvent

    inv = client_for("investigator", case=case)
    item = role_items["r3"]
    assert inv.get(f"/cases/{case.id}/evidence/{item.id}/download").status_code == 200
    row = db.scalars(select(AuditEvent).where(AuditEvent.action == "DOWNLOAD", AuditEvent.object_id == str(item.id))
                     .order_by(AuditEvent.id.desc())).first()
    assert row and row.outcome == "allowed" and row.detail["mode"] == "attachment"
    assert row.detail["classification"] == "R3" and "title" not in row.detail


# --------------------------------------------------------------------------- LE contacts
def test_masking_helpers():
    assert ev.mask_name("Mara Lindqvist") == "M. L*****"
    assert ev.mask_name("Mara") == "M*****"
    assert ev.mask_email("mara.lindqvist@kestrel-ridge.example") == "m***@k***.example"
    assert ev.mask_phone("+41 00 000 00 00") == "+41 *** *** 00"
    assert ev.mask_reference("DEMO-IT-0000000000") == "DEMO-IT-******00"
    assert ev.mask_name(None) is None and ev.mask_email("") == ""


def test_le_contacts_crud_and_masking(client_for, case, db):
    inv = client_for("investigator", case=case)
    data = {"csrf_token": _tok(inv, case), "agency": "Demo Cyber Police", "unit": "Cybercrime unit",
            "role": "investigating officer", "name": "Mara Lindqvist", "email": "mara.lindqvist@kestrel-ridge.example",
            "phone": "+41 00 000 00 00", "reference": "DEMO-IT-0000000000", "jurisdiction": "Italy",
            "notes": "masked-notes-marker"}
    r = inv.post(f"/cases/{case.id}/evidence/le-contacts", data=data, follow_redirects=False)
    assert r.status_code == 303 and "ev_err" not in r.headers["location"]
    contact = db.scalars(select(LEContact).where(LEContact.case_id == case.id, LEContact.name == "Mara Lindqvist")
                         .order_by(LEContact.id.desc())).first()
    assert contact.classification == Classification.R3

    full = {c["id"]: c for c in inv.get(f"/api/cases/{case.id}/evidence/le-contacts").json()}[contact.id]
    assert full["name"] == "Mara Lindqvist" and not full["masked"] and full["notes"] == "masked-notes-marker"

    ro = client_for("read_only", case=case)
    masked = {c["id"]: c for c in ro.get(f"/api/cases/{case.id}/evidence/le-contacts").json()}[contact.id]
    assert masked["masked"] and masked["name"] == "M. L*****" and masked["email"] == "m***@k***.example"
    assert masked["phone"] == "+41 *** *** 00" and masked["reference"] == "DEMO-IT-******00"
    assert masked["notes"] is None and masked["agency"] == "Demo Cyber Police"
    page = ro.get(f"/cases/{case.id}?tab=evidence&folder=law_enforcement&section=contacts").text
    assert "M. L*****" in page and "Mara Lindqvist" not in page and "masked-notes-marker" not in page
    assert "kestrel-ridge.example" not in page

    upd = dict(data, csrf_token=_tok(inv, case), role="prosecutor")
    assert inv.post(f"/cases/{case.id}/evidence/le-contacts/{contact.id}", data=upd,
                    follow_redirects=False).status_code == 303
    db.refresh(contact)
    assert contact.role == "prosecutor"
    assert ro.post(f"/cases/{case.id}/evidence/le-contacts/{contact.id}/delete",
                   data={"csrf_token": _tok(ro, case), "confirm": "yes"}).status_code == 403
    r = inv.post(f"/cases/{case.id}/evidence/le-contacts/{contact.id}/delete",
                 data={"csrf_token": _tok(inv, case)}, follow_redirects=False)
    assert "ev_err=1" in r.headers["location"]  # needs the confirmation box
    r = inv.post(f"/cases/{case.id}/evidence/le-contacts/{contact.id}/delete",
                 data={"csrf_token": _tok(inv, case), "confirm": "yes"}, follow_redirects=False)
    assert r.status_code == 303
    assert db.scalar(select(LEContact.id).where(LEContact.id == contact.id)) is None


# --------------------------------------------------------------------------- integrity
def test_integrity_mismatch_is_recorded_and_blocks_download(client_for, case, originals, db):
    original = originals / "Police receipt integrity.txt"
    original.write_bytes(b"original bytes")
    item = ev.add_reference(db, case, str(original), folder="law_enforcement", classification="R2")
    db.commit()
    inv = client_for("investigator", case=case)
    r = inv.post(f"/cases/{case.id}/evidence/{item.id}/verify", data={"csrf_token": _tok(inv, case)},
                 follow_redirects=False)
    assert r.status_code == 303 and "ev_err" not in r.headers["location"]
    db.refresh(item)
    assert item.meta["integrity"]["status"] == "ok"
    first_verified = item.verified_at

    original.write_bytes(b"tampered bytes")
    r = inv.post(f"/api/cases/{case.id}/evidence/{item.id}/verify")
    assert r.status_code == 200 and r.json()["status"] == "mismatch"
    assert r.json()["actual_sha256"] == _sha(b"tampered bytes") and r.json()["expected_sha256"] == _sha(b"original bytes")
    db.refresh(item)
    assert item.sha256 == _sha(b"original bytes") and item.verified_at == first_verified  # never rewritten
    assert inv.get(f"/cases/{case.id}/evidence/{item.id}/download").status_code == 409
    tab = inv.get(f"/cases/{case.id}?tab=evidence").text
    assert "Integrity check failed (mismatch)" in tab and f"/evidence/{item.id}" in tab

    original.unlink()
    assert inv.post(f"/api/cases/{case.id}/evidence/{item.id}/verify").json()["status"] == "missing"
    original.write_bytes(b"original bytes")
    assert inv.post(f"/api/cases/{case.id}/evidence/{item.id}/verify").json()["status"] == "ok"


def test_inline_integrity_and_vault_tamper(db, case, vault):
    note = ev.add_note(db, case, title="Integrity inline", text="hello", folder="other")
    assert ev.verify_integrity(db, note).status == "ok"
    note.inline_text = "changed"
    assert ev.verify_integrity(db, note).status == "mismatch"
    up = ev.store_upload(db, case, io.BytesIO(b"vault bytes"), filename="v.txt", folder="other")
    (vault / up.vault_path).write_bytes(b"vault bytes!")
    assert ev.verify_integrity(db, up).status == "mismatch"
    db.commit()


# --------------------------------------------------------------------------- tab, notes, events, trace report
def test_note_emits_evidence_added_without_pii(client, case, db):
    r = client.post(f"/cases/{case.id}/evidence/note",
                    data={"csrf_token": _tok(client, case), "title": "Adrian Example call note", "text": "call notes",
                          "folder": "digital_artifacts", "section": "recordings", "classification": "R2"},
                    follow_redirects=False)
    assert r.status_code == 303
    item = db.scalars(select(EvidenceItem).where(EvidenceItem.title == "Adrian Example call note")
                      .order_by(EvidenceItem.id.desc())).first()
    assert item.sha256 == _sha(b"call notes") and item.meta["section"] == "recordings"
    note = db.scalars(select(Notification).where(Notification.event_type == "evidence_added")
                      .order_by(Notification.id.desc())).first()
    assert note.case_id == case.id and item.id in note.payload["evidence_item_ids"]
    assert "Adrian" not in note.title + (note.body or "") and note.link.startswith(f"/cases/{case.id}?tab=evidence")


def test_post_without_csrf_is_rejected(client, case):
    r = client.post(f"/cases/{case.id}/evidence/note", data={"title": "x", "text": "y"}, follow_redirects=False)
    assert r.status_code == 403


@pytest.mark.parametrize("role", ["admin", "investigator", "read_only", "external"])
def test_tab_renders_for_every_role(client_for, case, role):
    c = client_for(role, case=case)
    for q in ("", "&folder=law_enforcement", "&folder=law_enforcement&section=contacts",
              "&folder=stop_orders_correspondence", "&folder=chain_reports", "&folder=nope"):
        r = c.get(f"/cases/{case.id}?tab=evidence{q}")
        assert r.status_code == 200, (role, q)
        assert "Digital artifacts" in r.text and "Law enforcement" in r.text
    add_forms = "/evidence/note" in c.get(f"/cases/{case.id}?tab=evidence").text
    assert add_forms == (role in ("admin", "investigator"))


def test_trace_report_saved_as_chain_report(client, case, db):
    from app import services

    if services.latest_run(db, case) is None:
        services.run_trace(db, case, provider_mode="fixture")
    r = client.post(f"/cases/{case.id}/evidence/trace-report", data={"csrf_token": _tok(client, case)},
                    follow_redirects=False)
    assert r.status_code == 303 and "folder=chain_reports" in r.headers["location"]
    item = db.scalars(select(EvidenceItem).where(EvidenceItem.case_id == case.id,
                                                 EvidenceItem.source_type == "trace_report")
                      .order_by(EvidenceItem.id.desc())).first()
    assert item.folder == EvidenceFolder.CHAIN_REPORTS and item.classification == Classification.C1
    assert "Freeze / preservation candidates" in item.inline_text and item.sha256 == _sha(item.inline_text.encode())


def test_edit_share_and_delete(client_for, case, db):
    item = ev.add_note(db, case, title="Editable note", text="edit me", folder="other")
    db.commit()
    inv = client_for("investigator", case=case)
    r = inv.post(f"/cases/{case.id}/evidence/{item.id}/edit",
                 data={"csrf_token": _tok(inv, case), "folder": "legal", "title": "Edited note", "classification": "R3",
                       "tags": "a, b, a"}, follow_redirects=False)
    assert r.status_code == 303
    db.refresh(item)
    assert (item.folder, item.title, item.classification, item.tags) == (
        EvidenceFolder.LEGAL, "Edited note", Classification.R3, ["a", "b"])
    assert item.sha256 == _sha(b"edit me")
    assert inv.post(f"/cases/{case.id}/evidence/{item.id}/edit",
                    data={"csrf_token": _tok(inv, case), "folder": "financial", "title": "x", "classification": "R3"},
                    follow_redirects=False).headers["location"].endswith("ev_err=1")
    assert inv.post(f"/cases/{case.id}/evidence/{item.id}/share",
                    data={"csrf_token": _tok(inv, case), "shared": "1"}).status_code == 403
    admin = client_for("admin", case=case)
    admin.post(f"/cases/{case.id}/evidence/{item.id}/share", data={"csrf_token": _tok(admin, case), "shared": "1"})
    db.refresh(item)
    assert item.shared_with_external
    assert inv.post(f"/cases/{case.id}/evidence/{item.id}/delete",
                    data={"csrf_token": _tok(inv, case), "confirm": "yes"}).status_code == 403
    admin.post(f"/cases/{case.id}/evidence/{item.id}/delete", data={"csrf_token": _tok(admin, case), "confirm": "yes"})
    assert db.scalar(select(EvidenceItem.id).where(EvidenceItem.id == item.id)) is None


# --------------------------------------------------------------------------- demo artifacts
def test_demo_artifacts_are_synthetic_and_import_inline(db, case):
    files = sorted(DEMO_DIR.glob("*.txt"))
    assert 3 <= len(files) <= 5  # + the synthetic letter of authorisation (the sender profile's authority document)
    texts = {f.name: f.read_text(encoding="utf-8") for f in files}
    assert all(t.startswith("SYNTHETIC DEMO ARTIFACT") for t in texts.values())
    joined = "\n".join(texts.values())
    assert "Adrian Example" in joined and "IC3-DEMO-00000000" in joined and "DEMO-IT-0000000000" in joined
    demo_mapping = ev.Mapping(exclude=("*.json",))
    report = ev.import_directory(db, case, DEMO_DIR, mode="inline", mapping=demo_mapping)
    db.commit()
    rows = {r.candidate.rel: r for r in report.rows}
    assert {r.action for r in rows.values()} <= {"new", "unchanged", "duplicate"}
    chat = db.get(EvidenceItem, rows["chat_excerpt.txt"].item_id)
    assert chat.storage == EvidenceStorage.INLINE and chat.folder == EvidenceFolder.DIGITAL_ARTIFACTS
    assert ev.section_of(chat) == "messaging" and chat.sha256 == _sha(texts["chat_excerpt.txt"].encode())
    ic3 = db.get(EvidenceItem, rows["ic3_receipt.txt"].item_id)
    assert ic3.folder == EvidenceFolder.LAW_ENFORCEMENT
    again = ev.import_directory(db, case, DEMO_DIR, mode="inline", mapping=demo_mapping)
    assert not again.created


def test_demo_fixture_section_matches_the_artifacts(db, case):
    from app.fixture_sections import SeedReport, load_evidence

    section = json.loads((DEMO_DIR / "fixture-section.json").read_text(encoding="utf-8"))["evidence"]
    fixture = json.loads((REPO_ROOT / "data" / "fixtures" / "demo_case.json").read_text(encoding="utf-8"))
    for entries in (section, fixture.get("evidence") or []):  # the demo fixture must agree with the files
        for e in entries:
            demo = (e.get("meta") or {}).get("demo_file")
            if demo:
                assert (REPO_ROOT / demo).is_file(), demo
            if demo and e.get("storage") == "inline":
                assert e["inline_text"] == (REPO_ROOT / demo).read_text(encoding="utf-8"), e["title"]
    assert {e["meta"]["demo_file"].rsplit("/", 1)[-1] for e in section} == {f.name for f in DEMO_DIR.glob("*.txt")}
    load_evidence(db, case, section, SeedReport())
    db.commit()
    db.refresh(case)
    rows = {e.title: e for e in case.evidence_items}
    police = rows["Carabinieri complaint receipt DEMO-IT-0000000000 (synthetic)"]
    assert police.storage == EvidenceStorage.INLINE and police.shared_with_external
    assert ev.section_of(police) == "reports" and police.classification == Classification.R3
    chat = rows["Chat excerpt with the 'Adrian Example, CFO' persona (synthetic)"]
    assert ev.section_of(chat) == "messaging" and chat.sha256 == _sha(chat.inline_text.encode())


def test_pathless_demo_references_resolve_to_the_synthetic_files(db, case, tmp_path):
    item = ev.add_note(db, case, title="demo ref probe", text="x", folder="other")
    item.storage, item.inline_text, item.sha256 = EvidenceStorage.REFERENCE, None, None
    item.meta = {"demo_file": "data/fixtures/demo_evidence/ic3_receipt.txt"}
    data = (DEMO_DIR / "ic3_receipt.txt").read_bytes()
    assert ev.verify_integrity(db, item).status == "unhashed" and item.sha256 == _sha(data)
    assert ev.verify_integrity(db, item).status == "ok" and ev.preview_kind(item)[0] == "text"
    item.meta = {"demo_file": ".env.example"}  # anything outside demo_evidence is never read
    assert ev.demo_file(item) is None and ev.verify_integrity(db, item).status == "missing"
    db.rollback()


# --------------------------------------------------------------------------- review fixes (round 1)
def test_lowering_a_classification_needs_a_case_admin_and_is_audited(client_for, case, db):
    item = ev.add_note(db, case, title="Declassify me", text="r3 text", folder="other", classification="R3")
    db.commit()
    inv = client_for("investigator", case=case)
    r = inv.post(f"/cases/{case.id}/evidence/{item.id}/edit",
                 data={"csrf_token": _tok(inv, case), "folder": "other", "title": "Declassify me",
                       "classification": "R2"}, follow_redirects=False)
    assert r.headers["location"].endswith("ev_err=1")
    db.refresh(item)
    assert item.classification == Classification.R3
    denied = db.scalars(select(AuditEvent).where(AuditEvent.action == "DECLASSIFY",
                                                 AuditEvent.object_id == str(item.id))).all()
    assert [e.outcome for e in denied] == ["denied"]
    admin = client_for("admin", case=case)
    r = admin.post(f"/cases/{case.id}/evidence/{item.id}/edit",
                   data={"csrf_token": _tok(admin, case), "folder": "other", "title": "Declassify me",
                         "classification": "R2"}, follow_redirects=False)
    assert "ev_err" not in r.headers["location"]
    db.refresh(item)
    assert item.classification == Classification.R2
    rows = db.scalars(select(AuditEvent).where(AuditEvent.action == "DECLASSIFY",
                                               AuditEvent.object_id == str(item.id))).all()
    assert [e.outcome for e in rows] == ["denied", "allowed"] and rows[-1].detail["previous"] == "R3"


def test_reference_roots_are_scoped_to_the_case(client_for, case, originals, db, tmp_path):
    other = db.scalar(select(Case).where(Case.reference == "EV-ROOTS-B")) or services.create_case(
        db, reference="EV-ROOTS-B", title="other", victim_name="x", victim_entity=None, loss_amount=1,
        loss_asset="USDC", loss_usd=1, fraud_date=None, chain=Chain.ETHEREUM, origin_tx=None,
        victim_wallet=None, perpetrator_wallet="0x" + "1" * 40, summary=None)
    secret = originals / "case A secret.txt"
    secret.write_bytes(b"secret of case A")
    (originals.parent / other.reference).mkdir(exist_ok=True)
    mine = originals.parent / other.reference / "b.txt"
    mine.write_bytes(b"case B file")
    bob = client_for("admin", case=other, email="roots.bob@tests.example")
    tok = csrf_token(bob, f"/cases/{other.id}?tab=evidence")

    def post(path):
        return bob.post(f"/cases/{other.id}/evidence/reference",
                        data={"csrf_token": tok, "source_path": str(path), "folder": "other",
                              "classification": "R2"}, follow_redirects=False)

    foreign, missing = post(secret), post(originals.parent / other.reference / "nope.txt")
    assert "ev_err=1" in foreign.headers["location"] and "ev_err=1" in missing.headers["location"]
    assert foreign.headers["location"] == missing.headers["location"]  # no existence oracle
    assert "ev_err" not in post(mine).headers["location"]
    # the vault is never a reference source, even when it sits under a root
    vault = originals.parent / other.reference / "vault"
    (vault / "1").mkdir(parents=True)
    (vault / "1" / "blob").write_bytes(b"vault bytes")
    import os

    os.environ["AEGIS_VAULT_DIR"] = str(vault)
    try:
        assert "ev_err=1" in post(vault / "1" / "blob").headers["location"]
    finally:
        os.environ.pop("AEGIS_VAULT_DIR", None)


def test_case_specific_root_entries(monkeypatch, case, tmp_path):
    d = tmp_path / "intake for this case"
    d.mkdir()
    monkeypatch.setenv("AEGIS_EVIDENCE_ROOTS", f"{case.reference}={d}:/{tmp_path.name}-unused")
    assert ev.case_evidence_roots(case)[0] == d.resolve()
    (d / "x.txt").write_text("x")
    assert ev.check_reference_path(str(d / "x.txt"), case=case).path == (d / "x.txt").resolve()


def test_symlinks_inside_the_roots_are_never_followed(client_for, case, originals, db, tmp_path):
    outside = tmp_path / "host-secret.txt"
    outside.write_bytes(b"host secret")
    bundle = originals / "x.rtfd"
    bundle.mkdir()
    (bundle / "TXT.rtf").symlink_to(outside)
    (originals / "link.txt").symlink_to(outside)
    inv = client_for("investigator", case=case)
    tok = _tok(inv, case)
    for path in (bundle, originals / "link.txt"):
        r = inv.post(f"/cases/{case.id}/evidence/reference",
                     data={"csrf_token": tok, "source_path": str(path), "folder": "other", "classification": "R2"},
                     follow_redirects=False)
        assert "ev_err=1" in r.headers["location"], path
    # a bundle that was fine at registration and is swapped for a link afterwards is refused at serve time
    good = originals / "good.rtfd"
    good.mkdir()
    (good / "TXT.rtf").write_bytes(b"{\\rtf1 fine}")
    item = ev.add_reference(db, case, str(good), folder="other", classification="R2")
    db.commit()
    (good / "TXT.rtf").unlink()
    (good / "TXT.rtf").symlink_to(outside)
    r = inv.get(f"/cases/{case.id}/evidence/{item.id}/download")
    assert r.status_code == 410 and b"host secret" not in r.content
    # the importer skips linked bundles too
    cands = list(ev.walk_source(originals))
    assert all(c.sha256 != _sha(b"host secret") for c in cands)


def test_page_preview_and_api_content_are_integrity_checked_and_audited(client_for, case, originals, db):
    original = originals / "le statement.txt"
    original.write_bytes(b"original statement text")
    item = ev.add_reference(db, case, str(original), folder="law_enforcement", classification="R3")
    item.mime = "text/plain"
    db.commit()
    admin = client_for("admin", case=case)
    page = admin.get(f"/cases/{case.id}/evidence/{item.id}")
    assert page.status_code == 200 and "original statement text" in page.text
    previews = db.scalars(select(AuditEvent).where(AuditEvent.action == "DOWNLOAD",
                                                   AuditEvent.object_id == str(item.id))).all()
    assert [(e.outcome, e.detail.get("mode")) for e in previews] == [("allowed", "preview")]
    original.write_bytes(b"TAMPERED text")
    page = admin.get(f"/cases/{case.id}/evidence/{item.id}")
    assert page.status_code == 200 and "TAMPERED" not in page.text and "Integrity mismatch" in page.text
    note = ev.add_note(db, case, title="api content", text="inline api text", folder="other", classification="R2")
    db.commit()
    body = admin.get(f"/api/cases/{case.id}/evidence/{note.id}").json()
    assert body["inline_text"] == "inline api text"
    rows = db.scalars(select(AuditEvent).where(AuditEvent.action == "DOWNLOAD",
                                               AuditEvent.object_id == str(note.id))).all()
    assert [e.detail.get("mode") for e in rows] == ["api"]


def _roots_case(db, reference, created_by=None):
    return db.scalar(select(Case).where(Case.reference == reference)) or services.create_case(
        db, reference=reference, title="roots", victim_name="x", victim_entity=None, loss_amount=1,
        loss_asset="USDC", loss_usd=1, fraud_date=None, chain=Chain.ETHEREUM, origin_tx=None,
        victim_wallet=None, perpetrator_wallet="0x" + "2" * 40, created_by=created_by)


def test_plain_roots_never_alias_another_case_directory(db, case, originals):
    """A case directory is matched by identity, not by text: a symlink or a differently-cased
    spelling of another case's folder is never this case's root."""
    (originals / "one.txt").write_bytes(b"case one file\n")
    root = originals.parent
    (root / "EV-ALIAS-001").symlink_to(originals, target_is_directory=True)
    alias = _roots_case(db, "EV-ALIAS-001")
    assert ev.case_evidence_roots(alias) == []
    with pytest.raises(ev.EvidenceError):
        ev.check_reference_path(str(root / "EV-ALIAS-001" / "one.txt"), case=alias)
    # a folder spelled with other case: on macOS (case-insensitive) root/EV-CASED-001 opens it
    (root / "Ev-Cased-001").mkdir()
    (root / "Ev-Cased-001" / "f.txt").write_bytes(b"not yours")
    cased = _roots_case(db, "EV-CASED-001")
    with pytest.raises(ev.EvidenceError):
        ev.check_reference_path(str(root / "EV-CASED-001" / "f.txt"), case=cased)
    # the demo case keeps its own folder
    assert ev.check_reference_path(str(originals / "one.txt"), case=case).path == (originals / "one.txt").resolve()


def test_plain_roots_serve_only_operator_opened_cases(db, client_for, originals):
    """A user who may only create cases cannot claim a folder already on disk by choosing its name."""
    root = originals.parent
    for ref in ("EV-CLAIM-001", "EV-SYSADM-001"):
        (root / ref).mkdir()
        (root / ref / "original.txt").write_bytes(b"pre-placed original")
    creator = client_for(None, email="claim.creator@tests.example", can_create_cases=True)
    claimed = _roots_case(db, "EV-CLAIM-001", created_by=creator.user)
    assert ev.case_evidence_roots(claimed) == []
    tok = csrf_token(creator, f"/cases/{claimed.id}?tab=evidence")
    r = creator.post(f"/cases/{claimed.id}/evidence/reference", follow_redirects=False,
                     data={"csrf_token": tok, "source_path": str(root / "EV-CLAIM-001" / "original.txt"),
                           "folder": "other", "classification": "R2"})
    assert "ev_err=1" in r.headers["location"]
    sysadmin = client_for(None, system_admin=True)
    own = _roots_case(db, "EV-SYSADM-001", created_by=sysadmin.user)
    assert ev.case_evidence_roots(own) == [(root / "EV-SYSADM-001").resolve()]
