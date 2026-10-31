"""Evidence tab: the evidence register by folder, law-enforcement contacts, integrity checks.

Owner: the evidence feature. Logic: app/domain/evidence.py. Partial: templates/case/_tab_evidence.html;
item page: templates/evidence_item.html (macros in evidence_macros.html); static: css/evidence.css,
js/evidence.js. CLI bulk import: scripts/import_evidence.py.

Page routes (forms post with CSRF and redirect back):

    GET  /cases/{id}/evidence                          -> 303 ?tab=evidence
    POST /cases/{id}/evidence/upload                   multipart; stored in AEGIS_VAULT_DIR (outside the repo); read
                                                       and typed by app.evidence_intel (a suggestion a person confirms)
    POST /cases/{id}/evidence/reference                register an existing file by path (never copied)
    POST /cases/{id}/evidence/note                     inline text note
    POST /cases/{id}/evidence/trace-report             save the latest trace run as a chain report
    POST /cases/{id}/evidence/verify-all               re-hash every visible item
    GET  /cases/{id}/evidence/{item_id}                item page (metadata, preview, actions)
    GET  /cases/{id}/evidence/{item_id}/content        inline bytes for the preview (audited)
    GET  /cases/{id}/evidence/{item_id}/download       attachment (audited)
    POST /cases/{id}/evidence/{item_id}/verify | edit | share | delete
    POST /cases/{id}/evidence/le-contacts              create; /{contact_id} update; /{contact_id}/delete

API: GET /api/cases/{id}/evidence, GET /api/cases/{id}/evidence/{item_id},
POST /api/cases/{id}/evidence/{item_id}/verify, GET /api/cases/{id}/evidence/le-contacts.

External members see only items shared with them; R3 content needs investigator or above;
the Financial folder is for case admins only (rules in app.domain.evidence).
"""

from __future__ import annotations

import logging
import mimetypes
import re
import zipfile
from collections.abc import Iterator
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import services
from app.core.audit import CREATE, DELETE, DOWNLOAD, SHARE, UPDATE, audit
from app.core.csrf import require_csrf
from app.core.permissions import (
    ADMIN,
    EXTERNAL,
    INVESTIGATOR,
    READ_ONLY,
    CaseAccess,
    get_case_object,
    require_case_role,
)
from app.core.security import require_user
from app.db.models import (
    Classification,
    Correspondence,
    EvidenceFolder,
    EvidenceItem,
    EvidenceStorage,
    LEContact,
)
from app.db.session import get_db
from app.domain import evidence as ev
from app.evidence_intel import service as intel
from app.web.tabs import tab_context
from app.web.templating import templates

log = logging.getLogger(__name__)
router = APIRouter(tags=["evidence"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]
VERIFY = "VERIFY_INTEGRITY"
READ_EVIDENCE = "READ_EVIDENCE"
DECLASSIFY = "DECLASSIFY"
SINGLE_READ_BYTES = 32 * 1024 * 1024  # served from one read whose bytes are the ones hashed


def fmt_size(n: int | None) -> str:
    if n is None:
        return "—"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _ui_helpers(access: CaseAccess) -> dict:
    return {
        "ev_fmt_size": fmt_size, "ev_section_of": ev.section_of, "ev_folder_label": ev.folder_label,
        "ev_source_label": ev.source_type_label,
        "ev_integrity": ev.integrity_status, "ev_folders": ev.FOLDERS, "ev_classifications": list(Classification),
        # complaint references in titles / descriptions / tags, masked below view_restricted
        "ev_text": ev.ref_mask(access),
    }


def _redirect(case_id: int, *, folder: str | None = None, section: str | None = None, msg: str | None = None,
              err: bool = False, anchor: str = "", item_id: int | None = None) -> RedirectResponse:
    """Back to the tab (or an item page) with a short, PII-free status message."""
    params: dict[str, str] = {}
    if item_id is None:
        params["tab"] = "evidence"
        if folder:
            params["folder"] = folder
        if section:
            params["section"] = section
    if msg:
        params["ev_msg"] = msg[:200]
    if err:
        params["ev_err"] = "1"
    base = f"/cases/{case_id}/evidence/{item_id}" if item_id is not None else f"/cases/{case_id}"
    query = f"?{urlencode(params)}" if params else ""
    return RedirectResponse(f"{base}{query}{('#' + anchor) if anchor else ''}", status_code=303)


def _item(db: Session, item_id: int, access: CaseAccess) -> EvidenceItem:
    item = get_case_object(db, EvidenceItem, item_id, access)
    if not ev.can_see(access, item):  # financial for non-admins: as if it did not exist
        raise HTTPException(404, "evidence_items not found")
    return item


# --------------------------------------------------------------------------- tab
@tab_context("evidence")
def evidence_tab(request: Request, db: Session, access: CaseAccess) -> dict:
    q = request.query_params
    flags = ev.flags_for(access)
    items = ev.visible_items(access)
    try:
        folder = EvidenceFolder(q.get("folder")) if q.get("folder") else None
    except ValueError:
        folder = None
    if folder == EvidenceFolder.FINANCIAL and not flags["financial"]:
        folder = None
    section = q.get("section") or None
    contacts = ev.contacts_for(access) if flags["contacts"] else []

    linked = ev.linked_entries(access)
    tree = []
    for spec in ev.FOLDERS:
        in_folder = [e for e in items if e.folder == spec.folder]
        sections = []
        for s in spec.sections:
            if s.key == "contacts":
                if flags["contacts"]:
                    sections.append({"key": s.key, "label": s.label, "count": len(contacts)})
                continue
            sections.append({"key": s.key, "label": s.label,
                             "count": sum(1 for e in in_folder if ev.section_of(e) == s.key)})
        n_linked = len(linked) if spec.folder == EvidenceFolder.STOP_ORDERS_CORRESPONDENCE else 0
        tree.append({"spec": spec, "key": spec.folder.value, "label": spec.label, "count": len(in_folder) + n_linked,
                     "linked": n_linked, "sections": sections, "locked": spec.admin_only and not flags["financial"]})

    shown = items
    if folder is not None:
        shown = [e for e in items if e.folder == folder]
        if section and section != "contacts":
            shown = [e for e in shown if ev.section_of(e) == section]
    by_folder = {f: [e for e in shown if e.folder == f] for f in EvidenceFolder}
    orders, corr = ev.linked_correspondence(access)
    uploads_ok, uploads_reason = ev.vault_status()
    run = services.latest_run(db, access.case) if flags["trace_report"] else None
    return {
        "evidence_by_folder": by_folder, "evidence_count": len(items), "ev_items": shown, "ev_tree": tree,
        "ev_folder": folder, "ev_spec": ev.FOLDER_SPEC.get(folder) if folder else None, "ev_section": section,
        "ev_flags": flags, "ev_contacts": contacts, "ev_alerts": ev.integrity_alerts(items),
        "ev_orders": orders, "ev_corr": corr, "ev_uploads_ok": uploads_ok, "ev_uploads_reason": uploads_reason,
        "ev_linked": linked if folder == EvidenceFolder.STOP_ORDERS_CORRESPONDENCE else [],
        "ev_reference_roots": bool(ev.case_evidence_roots(access.case)), "ev_run": run,
        "ev_msg": (q.get("ev_msg") or "")[:200], "ev_err": q.get("ev_err") == "1",
        "ev_intel": intel.tab_view(db, access) if not access.is_external else None,
        **_ui_helpers(access),
    }


@router.get("/cases/{case_id}/evidence")
def evidence_tab_page(case_id: int, access: CaseAccess = Depends(require_case_role(EXTERNAL))):
    return RedirectResponse(f"/cases/{case_id}?tab=evidence", status_code=303)


# --------------------------------------------------------------------------- add
def _meta_form(folder: str, section: str, title: str, description: str, source_type: str, doc_date: str,
               received_from: str, classification: str, tlp: str, tags: str) -> dict:
    return {"folder": folder, "section": section or None, "title": title, "description": description,
            "source_type": source_type, "doc_date": doc_date or None, "received_from": received_from,
            "classification": classification or None, "tlp": tlp, "tags": tags}


def _audit_read(db: Session, access: CaseAccess, item, iv: dict, how: str) -> None:
    audit(db, access, READ_EVIDENCE, access.case, item, via=how, text_status=(iv.get("text") or {}).get("status"),
          doc_type=(iv.get("rules") or {}).get("type"), ai=bool(iv.get("ai")), ai_skipped=iv.get("ai_skipped"))


def _read_new(db: Session, access: CaseAccess, item: EvidenceItem) -> str | None:
    """Read an item just added (app.evidence_intel: text, the rules' type, the AI's when the case consents): its
    one-line summary for the page. Reading is advisory: a failure never fails the upload."""
    try:
        iv = intel.read_item(db, item, actor=access)
    except Exception:
        log.exception("evidence intel: reading evidence #%s failed", item.id)
        db.rollback()
        return None
    _audit_read(db, access, item, iv, "add")
    return intel.summary_line(item)


def _added(db: Session, access: CaseAccess, item: EvidenceItem, how: str) -> RedirectResponse:
    audit(db, access, CREATE, access.case, item, storage=item.storage.value, folder=item.folder.value,
          classification=item.classification.value, sha256=item.sha256, size_bytes=item.size_bytes, via=how)
    ev.notify_added(db, access.case, [item])
    dup = (item.meta or {}).get("duplicate_of")
    read = _read_new(db, access, item) if how in ("upload", "reference", "note") else None
    msg = "Evidence added" + (f"; identical bytes already registered as item #{dup}" if dup else "")
    if read:
        return _redirect(access.case.id, folder=item.folder.value, msg=f"{msg}. {read}"[:200], anchor="ev-intel")
    return _redirect(access.case.id, folder=item.folder.value, msg=msg, anchor=f"ev-{item.id}")


@router.post("/cases/{case_id}/evidence/upload", dependencies=_csrf)
def upload_evidence(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
                    file: UploadFile = File(...), folder: str = Form("other"), section: str = Form(""),
                    title: str = Form(""), description: str = Form(""), source_type: str = Form(""),
                    doc_date: str = Form(""), received_from: str = Form(""), classification: str = Form("R3"),
                    tlp: str = Form(""), tags: str = Form("")):
    access.require("add_evidence")
    try:
        ev.vault_dir()  # refuse before touching the bytes when the vault is unset / inside the repo
        item = ev.store_upload(db, access.case, file.file, filename=file.filename or "upload", actor=access.user,
                               **_meta_form(folder, section, title, description, source_type, doc_date,
                                            received_from, classification, tlp, tags))
    except ev.EvidenceError as e:
        db.rollback()
        audit(db, access, CREATE, access.case, ("evidence_items", None), outcome="denied", via="upload",
              reason=str(e)[:120])
        return _redirect(access.case.id, msg=str(e), err=True, anchor="ev-add")
    finally:
        file.file.close()
    return _added(db, access, item, "upload")


@router.post("/cases/{case_id}/evidence/reference", dependencies=_csrf)
def reference_evidence(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                       db: Session = Depends(get_db), source_path: str = Form(...), folder: str = Form("other"),
                       section: str = Form(""), title: str = Form(""), description: str = Form(""),
                       source_type: str = Form(""), doc_date: str = Form(""), received_from: str = Form(""),
                       classification: str = Form("R3"), tlp: str = Form(""), tags: str = Form("")):
    access.require("add_evidence")
    try:
        item = ev.add_reference(db, access.case, source_path, actor=access.user,
                                **_meta_form(folder, section, title, description, source_type, doc_date,
                                             received_from, classification, tlp, tags))
    except (ev.EvidenceError, OSError) as e:
        db.rollback()
        reason = str(e) if isinstance(e, ev.EvidenceError) else "the file could not be read"
        audit(db, access, CREATE, access.case, ("evidence_items", None), outcome="denied", via="reference",
              reason=reason[:120])
        return _redirect(access.case.id, msg=reason, err=True, anchor="ev-add")
    return _added(db, access, item, "reference")


@router.post("/cases/{case_id}/evidence/note", dependencies=_csrf)
def note_evidence(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
                  title: str = Form(...), text: str = Form(...), folder: str = Form("other"), section: str = Form(""),
                  description: str = Form(""), source_type: str = Form("note"), doc_date: str = Form(""),
                  received_from: str = Form(""), classification: str = Form("R2"), tlp: str = Form(""),
                  tags: str = Form("")):
    access.require("add_evidence")
    try:
        item = ev.add_note(db, access.case, text=text, actor=access.user,
                           **_meta_form(folder, section, title, description, source_type, doc_date,
                                        received_from, classification, tlp, tags))
    except ev.EvidenceError as e:
        db.rollback()
        audit(db, access, CREATE, access.case, ("evidence_items", None), outcome="denied", via="note",
              reason=str(e)[:120])
        return _redirect(access.case.id, msg=str(e), err=True, anchor="ev-add")
    return _added(db, access, item, "note")


@router.post("/cases/{case_id}/evidence/trace-report", dependencies=_csrf)
def trace_report_evidence(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                          db: Session = Depends(get_db)):
    access.require("add_evidence")
    run = services.latest_run(db, access.case)
    if run is None:
        return _redirect(access.case.id, folder="chain_reports", msg="Run a trace first", err=True)
    item = ev.save_trace_report(db, access.case, run, actor=access.user)
    return _added(db, access, item, "trace_report")


# --------------------------------------------------------------------------- integrity
def _verify(db: Session, access: CaseAccess, item: EvidenceItem) -> ev.IntegrityResult:
    result = ev.verify_integrity(db, item)
    audit(db, access, VERIFY, access.case, item, result=result.status,
          outcome="allowed" if result.status in ("ok", "unhashed") else "denied")
    return result


@router.post("/cases/{case_id}/evidence/{item_id:int}/verify", dependencies=_csrf)
def verify_item(item_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                db: Session = Depends(get_db)):
    item = _item(db, item_id, access)
    result = _verify(db, access, item)
    msgs = {"ok": "Integrity verified: the hash matches", "unhashed": "Hash recorded (the item had none)",
            "mismatch": "INTEGRITY MISMATCH: the bytes no longer match the recorded sha256",
            "missing": "The original could not be read (moved, renamed or unavailable)"}
    return _redirect(access.case.id, item_id=item.id, msg=msgs[result.status],
                     err=result.status in ("mismatch", "missing"))


@router.post("/cases/{case_id}/evidence/verify-all", dependencies=_csrf)
def verify_all(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db)):
    counts: dict[str, int] = {}
    for item in ev.visible_items(access):
        status = ev.verify_integrity(db, item).status
        counts[status] = counts.get(status, 0) + 1
    audit(db, access, VERIFY, access.case, ("evidence_items", None), scope="all", **counts)
    bad = counts.get("mismatch", 0) + counts.get("missing", 0)
    msg = f"Verified {sum(counts.values())} item(s): {counts.get('ok', 0)} ok" + (
        f", {bad} FAILED" if bad else "")
    return _redirect(access.case.id, msg=msg, err=bool(bad))


# --------------------------------------------------------------------------- item page / content
@router.get("/cases/{case_id}/evidence/{item_id:int}", response_class=HTMLResponse)
def item_page(request: Request, item_id: int, access: CaseAccess = Depends(require_case_role(EXTERNAL)),
              db: Session = Depends(get_db)):
    item = _item(db, item_id, access)
    flags = ev.flags_for(access)
    can_open = ev.can_open(access, item)
    kind = mime = text = None
    text_status = None
    if can_open:
        kind, mime = ev.preview_kind(item)
        if kind == "text":
            # the in-page preview is a read like /content: re-hashed first and audited
            text, text_status = ev.preview_text(item)
            if text_status == "ok":
                audit(db, access, DOWNLOAD, access.case, item, mode="preview", storage=item.storage.value,
                      classification=item.classification.value, folder=item.folder.value)
            else:
                ev.verify_integrity(db, item)
                audit(db, access, DOWNLOAD, access.case, item, outcome="denied", mode="preview",
                      reason="integrity_mismatch" if text_status == "mismatch" else "missing")
    linked = [] if access.is_external else db.scalars(
        select(Correspondence).where(Correspondence.case_id == access.case.id,
                                     Correspondence.evidence_item_id == item.id)).all()
    derivatives = [e for e in access.case.evidence_items if e.parent_id == item.id and ev.can_see(access, e)]
    parent = next((e for e in access.case.evidence_items if e.id == item.parent_id and ev.can_see(access, e)), None)
    q = request.query_params
    return templates.TemplateResponse(request, "evidence_item.html", {
        "case": access.case, "access": access, "item": item, "ev_flags": flags, "can_open": can_open,
        "preview": kind, "preview_mime": mime, "preview_text": text, "preview_status": text_status, "linked": linked, "derivatives": derivatives,
        "parent": parent, "section": ev.section_of(item), "duplicates": list((item.meta or {}).get("duplicates") or []),
        "intel": intel.view(db, access, item),
        "ev_msg": (q.get("ev_msg") or "")[:200], "ev_err": q.get("ev_err") == "1", **_ui_helpers(access),
    })


def _filename(access: CaseAccess, item: EvidenceItem, mime: str | None) -> str:
    original = (item.meta or {}).get("original_filename") or ""
    ext = ""
    if "." in original:
        ext = "." + original.rsplit(".", 1)[-1]
    elif item.storage == EvidenceStorage.INLINE:
        ext = ".txt"
    else:
        ext = mimetypes.guess_extension(mime or "") or ""
    ext = re.sub(r"[^A-Za-z0-9.]", "", ext)[:10]
    ref = re.sub(r"[^A-Za-z0-9-]", "", access.case.reference)[:40]
    return f"{ref}-evidence-{item.id}{ext}"


def _serve(db: Session, access: CaseAccess, item: EvidenceItem, *, inline: bool) -> Response:
    mode = "inline" if inline else "attachment"
    if not ev.can_open(access, item):
        audit(db, access, DOWNLOAD, access.case, item, outcome="denied", mode=mode, reason="classification",
              classification=item.classification.value)
        raise HTTPException(403, "this item is restricted (R3): your role may see its metadata only")
    kind, mime = ev.preview_kind(item) if inline else (None, None)
    if inline and kind is None:
        raise HTTPException(415, "no inline preview for this file type; download it instead")
    # Small items are read once and the very bytes served are the ones hashed; larger ones are
    # hashed, then streamed from a second read-only open (both refuse symlinks and foreign roots).
    data: bytes | None = None
    try:
        if (item.size_bytes or 0) <= SINGLE_READ_BYTES:
            data = ev.read_verified(item)
        else:
            actual, _ = ev.current_hash(item)
            if item.sha256 and actual != item.sha256:
                raise ev.IntegrityError(item.id)
    except ev.IntegrityError:
        ev.verify_integrity(db, item)
        audit(db, access, DOWNLOAD, access.case, item, outcome="denied", mode=mode, reason="integrity_mismatch")
        raise HTTPException(409, "integrity mismatch: the bytes no longer match the recorded sha256") from None
    except (OSError, ev.EvidenceError, zipfile.BadZipFile, KeyError):
        ev.verify_integrity(db, item)
        audit(db, access, DOWNLOAD, access.case, item, outcome="denied", mode=mode, reason="missing")
        raise HTTPException(410, "the original could not be read (moved, renamed or unavailable)") from None
    media = mime or ("text/plain; charset=utf-8" if item.storage == EvidenceStorage.INLINE
                     else item.mime or "application/octet-stream")
    if media == "text/plain":
        media = "text/plain; charset=utf-8"
    csp = "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; frame-ancestors 'self'"
    if kind != "pdf":
        csp += "; sandbox"
    headers = {
        "Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store, private",
        "Content-Disposition": f'{mode}; filename="{_filename(access, item, media)}"',
        "X-Frame-Options": "SAMEORIGIN" if kind == "pdf" else "DENY",
    }
    audit(db, access, DOWNLOAD, access.case, item, mode=mode, storage=item.storage.value,
          classification=item.classification.value, folder=item.folder.value)
    if data is not None:
        return Response(data, media_type=media, headers=headers)
    return StreamingResponse(_chunks(ev.open_item(item)), media_type=media, headers=headers)


def _chunks(fh) -> Iterator[bytes]:
    with fh:
        yield from iter(lambda: fh.read(ev.CHUNK), b"")


@router.get("/cases/{case_id}/evidence/{item_id:int}/content")
def item_content(item_id: int, access: CaseAccess = Depends(require_case_role(EXTERNAL)),
                 db: Session = Depends(get_db)):
    return _serve(db, access, _item(db, item_id, access), inline=True)


@router.get("/cases/{case_id}/evidence/{item_id:int}/download")
def item_download(item_id: int, access: CaseAccess = Depends(require_case_role(EXTERNAL)),
                  db: Session = Depends(get_db)):
    return _serve(db, access, _item(db, item_id, access), inline=False)


# --------------------------------------------------------------------------- edit / share / delete
@router.post("/cases/{case_id}/evidence/{item_id:int}/edit", dependencies=_csrf)
def edit_item(item_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
              db: Session = Depends(get_db), folder: str = Form(...), section: str = Form(""),
              title: str = Form(...), description: str = Form(""), source_type: str = Form(""),
              doc_date: str = Form(""), received_from: str = Form(""), classification: str = Form(...),
              tlp: str = Form(""), tags: str = Form("")):
    item = _item(db, item_id, access)
    if folder == EvidenceFolder.FINANCIAL.value and not ev.allowed(access, "view_financial"):
        audit(db, access, UPDATE, access.case, item, outcome="denied", reason="financial_folder")
        return _redirect(access.case.id, item_id=item.id, msg="Only case admins can file items under Financial",
                         err=True)
    before = item.classification
    try:
        after = ev.as_classification(classification or None, before)
    except ev.EvidenceError as e:
        audit(db, access, UPDATE, access.case, item, outcome="denied", reason="bad_classification")
        return _redirect(access.case.id, item_id=item.id, msg=str(e), err=True)
    lowered = ev.CLASSIFICATION_RANK[after] < ev.CLASSIFICATION_RANK[before]
    if lowered and not access.can("declassify_evidence"):
        audit(db, access, DECLASSIFY, access.case, item, outcome="denied", reason="role",
              classification=before.value, requested=after.value)
        return _redirect(access.case.id, item_id=item.id, err=True,
                         msg="Only case admins can lower an item's classification")
    try:
        changed = ev.update_item(item, _meta_form(folder, section, title, description, source_type, doc_date,
                                                  received_from, classification, tlp, tags))
    except ev.EvidenceError as e:
        db.rollback()
        audit(db, access, UPDATE, access.case, item, outcome="denied", reason=str(e)[:120])
        return _redirect(access.case.id, item_id=item.id, msg=str(e), err=True)
    audit(db, access, UPDATE, access.case, item, fields=changed, folder=item.folder.value,
          classification=item.classification.value)
    if lowered:
        audit(db, access, DECLASSIFY, access.case, item, classification=after.value, previous=before.value)
    return _redirect(access.case.id, item_id=item.id, msg="Saved" if changed else "No changes")


@router.post("/cases/{case_id}/evidence/{item_id:int}/share", dependencies=_csrf)
def share_item(item_id: int, access: CaseAccess = Depends(require_case_role(ADMIN)), db: Session = Depends(get_db),
               shared: str = Form("")):
    access.require("share_external")
    item = _item(db, item_id, access)
    item.shared_with_external = shared in ("1", "true", "on", "yes")
    db.flush()
    audit(db, access, SHARE, access.case, item, shared_with_external=item.shared_with_external)
    return _redirect(access.case.id, item_id=item.id,
                     msg="Shared with external members" if item.shared_with_external else "No longer shared")


@router.post("/cases/{case_id}/evidence/{item_id:int}/delete", dependencies=_csrf)
def delete_item(item_id: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                db: Session = Depends(get_db), confirm: str = Form("")):
    item = _item(db, item_id, access)
    if not ev.allowed(access, "delete_evidence"):
        raise HTTPException(403, "only case admins can remove evidence")
    if confirm != "yes":
        return _redirect(access.case.id, item_id=item.id, msg="Tick the confirmation box to remove the item",
                         err=True)
    folder, ref = item.folder.value, ("evidence_items", item.id)
    detail = {"storage": item.storage.value, "sha256": item.sha256, "folder": folder}
    for c in db.scalars(select(Correspondence).where(Correspondence.evidence_item_id == item.id)):
        c.evidence_item_id = None
    for child in [e for e in access.case.evidence_items if e.parent_id == item.id]:
        child.parent_id = None
    db.delete(item)
    db.flush()
    audit(db, access, DELETE, access.case, ref, **detail)
    return _redirect(access.case.id, folder=folder,
                     msg="Removed from the register (a vault copy, if any, stays in the vault)")


# --------------------------------------------------------------------------- LE contacts
def _contact_values(agency, unit, role, name, email, phone, reference, jurisdiction, notes, classification) -> dict:
    return {"agency": agency, "unit": unit, "role": role, "name": name, "email": email, "phone": phone,
            "reference": reference, "jurisdiction": jurisdiction, "notes": notes, "classification": classification}


_CONTACTS = {"folder": "law_enforcement", "section": "contacts", "anchor": "ev-contacts"}


@router.post("/cases/{case_id}/evidence/le-contacts", dependencies=_csrf)
def create_contact(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
                   agency: str = Form(...), unit: str = Form(""), role: str = Form(""), name: str = Form(""),
                   email: str = Form(""), phone: str = Form(""), reference: str = Form(""),
                   jurisdiction: str = Form(""), notes: str = Form(""), classification: str = Form("R3")):
    access.require("manage_le_contacts")
    try:
        c = ev.save_contact(db, access.case, _contact_values(agency, unit, role, name, email, phone, reference,
                                                             jurisdiction, notes, classification), actor=access.user)
    except ev.EvidenceError as e:
        db.rollback()
        return _redirect(access.case.id, msg=str(e), err=True, **_CONTACTS)
    audit(db, access, CREATE, access.case, c, fields=[k for k in ev.CONTACT_FIELDS if getattr(c, k)])
    return _redirect(access.case.id, msg="Contact added", **_CONTACTS)


@router.post("/cases/{case_id}/evidence/le-contacts/{contact_id:int}", dependencies=_csrf)
def update_contact(contact_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                   db: Session = Depends(get_db), agency: str = Form(...), unit: str = Form(""),
                   role: str = Form(""), name: str = Form(""), email: str = Form(""), phone: str = Form(""),
                   reference: str = Form(""), jurisdiction: str = Form(""), notes: str = Form(""),
                   classification: str = Form("R3")):
    access.require("manage_le_contacts")
    c = get_case_object(db, LEContact, contact_id, access)
    before = {k: getattr(c, k) for k in ev.CONTACT_FIELDS}
    try:
        ev.save_contact(db, access.case, _contact_values(agency, unit, role, name, email, phone, reference,
                                                         jurisdiction, notes, classification), contact=c)
    except ev.EvidenceError as e:
        db.rollback()
        return _redirect(access.case.id, msg=str(e), err=True, **_CONTACTS)
    audit(db, access, UPDATE, access.case, c, fields=[k for k, v in before.items() if getattr(c, k) != v])
    return _redirect(access.case.id, msg="Contact saved", **_CONTACTS)


@router.post("/cases/{case_id}/evidence/le-contacts/{contact_id:int}/delete", dependencies=_csrf)
def delete_contact(contact_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                   db: Session = Depends(get_db), confirm: str = Form("")):
    access.require("manage_le_contacts")
    c = get_case_object(db, LEContact, contact_id, access)
    if confirm != "yes":
        return _redirect(access.case.id, msg="Tick the confirmation box to delete the contact", err=True,
                         **_CONTACTS)
    for row in db.scalars(select(Correspondence).where(Correspondence.le_contact_id == c.id)):
        row.le_contact_id = None
    db.delete(c)
    db.flush()
    audit(db, access, DELETE, access.case, ("le_contacts", contact_id))
    return _redirect(access.case.id, msg="Contact deleted", **_CONTACTS)


# --------------------------------------------------------------------------- JSON API
@router.get("/api/cases/{case_id}/evidence")
def api_list(access: CaseAccess = Depends(require_case_role(EXTERNAL))):
    mask = ev.ref_mask(access)
    return [ev.item_dict(access, e, mask=mask) for e in ev.visible_items(access)]


@router.get("/api/cases/{case_id}/evidence/le-contacts")
def api_contacts(access: CaseAccess = Depends(require_case_role(READ_ONLY))):
    return [ev.contact_dict(v) for v in ev.contacts_for(access)]


@router.get("/api/cases/{case_id}/evidence/{item_id:int}")
def api_item(item_id: int, access: CaseAccess = Depends(require_case_role(EXTERNAL)),
             db: Session = Depends(get_db)):
    item = _item(db, item_id, access)
    d = ev.item_dict(access, item)
    if item.storage == EvidenceStorage.INLINE and ev.can_open(access, item):
        # content in the API is a read like /content: integrity-checked and audited
        text, status = ev.preview_text(item)
        if status == "ok":
            d["inline_text"] = text
            audit(db, access, DOWNLOAD, access.case, item, mode="api", storage=item.storage.value,
                  classification=item.classification.value, folder=item.folder.value)
        else:
            d["inline_text"], d["content_error"] = None, status
            ev.verify_integrity(db, item)
            audit(db, access, DOWNLOAD, access.case, item, outcome="denied", mode="api", reason=status)
    return d


@router.post("/api/cases/{case_id}/evidence/{item_id:int}/verify")
def api_verify(item_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
               db: Session = Depends(get_db)):
    item = _item(db, item_id, access)
    result = _verify(db, access, item)
    return {"id": item.id, "status": result.status, "expected_sha256": result.expected,
            "actual_sha256": result.actual, "checked_at": result.checked_at.isoformat(),
            "verified_at": item.verified_at.isoformat() if item.verified_at else None}
