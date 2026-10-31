"""Evidence intel: what Aegis read in an evidence item, and a person's confirmation (app/evidence_intel).

Owner: the evidence feature. Partials: templates/evidence_intel_macros.html (the item page's panel, the Evidence tab's
"Unclassified / suggested" queue and the "AI reads evidence" setting).

    POST /cases/{id}/evidence/{item_id}/intel/read        read the item again (rules; the AI when the case consents)
    POST /cases/{id}/evidence/{item_id}/intel/confirm     confirm the type (or pick another): tag, keys, folder
    POST /cases/{id}/evidence/{item_id}/intel/wallet-role pick the role of a wallet the item names (audited): only
                                                          then are "Watch" and "Seed the trace" offered for it
    POST /cases/{id}/evidence/{item_id}/intel/complaint   record a complaint reference the item names
    POST /cases/{id}/evidence/{item_id}/intel/link        file the item as a provider's reply to a stop order
    POST /cases/{id}/evidence/intel/reread                case admins: read every item again (moves nothing)
    POST /cases/{id}/evidence/intel/ai-setting            case admins: the per-case "AI reads evidence" consent
    GET  /api/cases/{id}/evidence/{item_id}/intel         the reading as JSON
    GET  /api/cases/{id}/evidence/intel/queue             the queue as JSON

Watching a wallet, seeding the trace and adding an LE contact use their own routes (freeze/watch, seeds,
evidence/le-contacts). Audit rows carry the type, counts and ids only: never text, names or references.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.blocks.classify_ai import AISettingError, destination
from app.core.audit import CREATE, UPDATE, audit
from app.core.csrf import require_csrf
from app.core.permissions import ADMIN, EXTERNAL, INVESTIGATOR, CaseAccess, require_case_role
from app.core.security import require_user
from app.db.session import get_db
from app.domain import correspondence as desk
from app.domain import evidence as ev
from app.evidence_intel import ai
from app.evidence_intel import service as intel
from app.web.routes_evidence import READ_EVIDENCE, _audit_read, _item, _redirect

router = APIRouter(tags=["evidence"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]


@router.post("/cases/{case_id}/evidence/{item_id:int}/intel/read", dependencies=_csrf)
def read_one(item_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
             db: Session = Depends(get_db)):
    access.require("add_evidence")
    item = _item(db, item_id, access)
    iv = intel.read_item(db, item, actor=access)
    _audit_read(db, access, item, iv, "item")
    return _redirect(access.case.id, item_id=item.id, msg=intel.summary_line(item) or "Read")


@router.post("/cases/{case_id}/evidence/{item_id:int}/intel/confirm", dependencies=_csrf)
def confirm(item_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
            db: Session = Depends(get_db), doc_type: str = Form(...), move: str = Form(""),
            jurisdiction: str = Form(""), addressed_to: str = Form(""), doc_date: str = Form(""),
            back: str = Form("")):
    access.require("add_evidence")
    item = _item(db, item_id, access)
    before = item.folder.value
    try:
        changed = intel.confirm(db, access, item, doc_type, move=move in ("1", "on", "yes", "true"),
                                jurisdiction=jurisdiction, to=addressed_to, doc_date=doc_date)
    except intel.IntelError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from None
    note = "financial_admin" in changed
    changed = [c for c in changed if c != "financial_admin"]
    audit(db, access, UPDATE, access.case, item, setting="evidence_type", doc_type=doc_type, fields=changed,
          folder=item.folder.value, previous_folder=before if before != item.folder.value else None,
          source=(intel.intel(item).get("confirmed") or {}).get("source"))
    msg = f"Recorded as {intel.R.DOC_TYPES[doc_type].label}" + (
        f", filed under {ev.folder_label(item.folder)}" if "folder" in changed else "") + (
        "; a case admin can file it under Financial" if note else "")
    if back == "tab":
        return _redirect(access.case.id, msg=msg, anchor="ev-intel")
    return _redirect(access.case.id, item_id=item.id, msg=msg)


@router.post("/cases/{case_id}/evidence/{item_id:int}/intel/wallet-role", dependencies=_csrf)
def wallet_role(item_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                db: Session = Depends(get_db), value: str = Form(...), role: str = Form("")):
    """A person picks a wallet's role (victim / perpetrator / exchange or service / unknown; "" clears it). The audit
    row carries the role and the item, never the address."""
    access.require("edit")
    item = _item(db, item_id, access)
    if not ev.can_open(access, item) or not ev.allowed(access, "view_restricted"):
        raise HTTPException(403, "this item is restricted")
    try:
        intel.pick_role(db, access, item, value, role)
    except intel.IntelError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from None
    audit(db, access, UPDATE, access.case, item, setting="wallet_role", role=role or None,
          chain=next((i.get("chain") for i in (intel.intel(item).get("findings") or {}).get("identifiers") or []
                      if str(i.get("value") or "").lower() == value.strip().lower()), None))
    msg = (f"Recorded: {intel.WALLET_ROLES[role]}. You can now watch it or seed the trace with it" if role
           else "Role cleared")
    return _redirect(access.case.id, item_id=item.id, msg=msg, anchor="ev-intel")


@router.post("/cases/{case_id}/evidence/{item_id:int}/intel/complaint", dependencies=_csrf)
def add_complaint(item_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                  db: Session = Depends(get_db), authority: str = Form(...), reference: str = Form(...)):
    access.require("manage_le_contacts")
    item = _item(db, item_id, access)
    if not ev.can_open(access, item):
        raise HTTPException(403, "this item is restricted")
    try:
        intel.add_complaint(db, access.case, item, authority=authority, reference=reference)
    except intel.IntelError as exc:
        db.rollback()
        return _redirect(access.case.id, item_id=item.id, msg=str(exc), err=True)
    audit(db, access, UPDATE, access.case, ("cases", access.case.id), setting="complaint_reference_added",
          evidence_item_id=item.id)
    return _redirect(access.case.id, item_id=item.id, msg="Complaint reference recorded on the case")


@router.post("/cases/{case_id}/evidence/{item_id:int}/intel/link", dependencies=_csrf)
def link(item_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
         stop_order_id: int = Form(...), ticket: str = Form(""), record_ticket: str = Form(""),
         reply_date: str = Form("")):
    """File the item as the reply to a stop order the person picked; their ticket only when the person kept it
    ("record_ticket"), the reply's date as the person left it. The outcome it states stays a suggestion on Block
    status. Audit rows carry ids and flags only, never the ticket."""
    access.require("log_correspondence")
    item = _item(db, item_id, access)
    if not ev.can_open(access, item):
        raise HTTPException(403, "this item is restricted")
    was_typed = bool(intel.intel(item).get("confirmed"))
    before = item.folder.value
    try:
        corr = intel.link_reply(db, access, item, stop_order_id,
                                ticket=ticket if record_ticket in ("1", "on", "yes", "true") else None,
                                reply_date=reply_date)
    except (intel.IntelError, desk.DeskError) as exc:
        db.rollback()
        return _redirect(access.case.id, item_id=item.id, msg=str(exc), err=True)
    audit(db, access, CREATE, access.case, corr, direction="in", kind="reply", channel="other",
          stop_order_id=corr.stop_order_id, evidence_count=1, via="evidence_intel",
          ticket_recorded=bool(corr.external_ref))
    if not was_typed and intel.intel(item).get("confirmed"):
        audit(db, access, UPDATE, access.case, item, setting="evidence_type", doc_type="provider_reply",
              fields=["type"] + (["folder"] if item.folder.value != before else []), folder=item.folder.value,
              previous_folder=before if before != item.folder.value else None, source="link")
    return _redirect(access.case.id, item_id=item.id,
                     msg=f"Filed as the reply to stop order #{stop_order_id}. Block status now shows the outcome it "
                         "states as a suggestion: confirm it there")


@router.post("/cases/{case_id}/evidence/intel/reread", dependencies=_csrf)
def reread(access: CaseAccess = Depends(require_case_role(ADMIN)), db: Session = Depends(get_db)):
    if not ev.allowed(access, "delete_evidence"):
        raise HTTPException(403, "case admins only")
    counts = intel.reread_all(db, access)
    db.commit()
    audit(db, access, READ_EVIDENCE, access.case, ("evidence_items", None), scope="all", **counts)
    msg = (f"Read {counts['read']} item(s): {counts['suggested']} with a type, {counts['unclassified']} unclassified"
           + (f", {counts['no_text']} without text" if counts["no_text"] else "")
           + (f", {counts['ai']} read by the AI" if counts["ai"] else "") + ". Nothing was moved: confirm each type.")
    return _redirect(access.case.id, msg=msg, anchor="ev-intel")


@router.post("/cases/{case_id}/evidence/intel/ai-setting", dependencies=_csrf)
def ai_setting(access: CaseAccess = Depends(require_case_role(ADMIN)), db: Session = Depends(get_db),
               enabled: str = Form(""), consent: str = Form(""), destination_label: str = Form("", alias="destination"),
               model: str | None = Form(None)):
    access.require("manage_case")
    on = enabled in ("1", "on", "true", "yes")
    dest = destination()
    if on and (not destination_label.strip() or model is None):  # consent is always to what the admin was shown
        raise HTTPException(400, "Turning the AI reading on needs the destination and model the page showed: reload "
                                 "the page and confirm again.")
    if on and (destination_label.strip() != dest["label"] or model.strip() != (dest.get("model") or "")):
        raise HTTPException(409, "The AI destination changed while the page was open: reload and confirm again.")
    try:
        st = ai.set_enabled(db, access.case, access.user, on, consent=consent in ("1", "on", "yes"), dest=dest)
    except AISettingError as exc:
        db.rollback()
        audit(db, access, UPDATE, access.case, ("cases", access.case.id), outcome="denied", setting=ai.SETTING,
              enabled=on, reason="no_consent" if dest["provider"] != "none" else "no_provider")
        raise HTTPException(400, str(exc)) from None
    audit(db, access, UPDATE, access.case, ("cases", access.case.id), setting=ai.SETTING, enabled=on,
          consent=on or None, provider=st.get("provider") if on else None,
          confirmed_destination=st.get("destination") if on else None, model=st.get("model") if on else None)
    return RedirectResponse(f"/cases/{access.case.id}?tab=evidence&ev_msg=AI+reading+of+evidence+"
                            f"{'on' if on else 'off'}#ev-intel-ai", status_code=303)


# --------------------------------------------------------------------------- JSON
def _json_view(v: dict) -> dict:
    out = {k: v.get(k) for k in ("status", "rules", "confirmed", "text", "at")}
    a = v.get("ai") or {}
    out["ai"] = {k: a.get(k) for k in ("type", "label", "verified", "confidence", "quote", "summary", "parties",
                                       "dates", "amounts", "identifiers", "model", "at")} if a and v.get("deep") else (
        {k: a.get(k) for k in ("type", "label", "verified", "confidence")} if a else None)
    if v.get("deep"):
        f = v.get("findings") or {}
        out["findings"] = {k: f.get(k) for k in ("identifiers", "refs", "dates", "amounts", "providers", "doc_date")}
    return out


@router.get("/api/cases/{case_id}/evidence/{item_id:int}/intel")
def api_item(item_id: int, access: CaseAccess = Depends(require_case_role(EXTERNAL)), db: Session = Depends(get_db)):
    return _json_view(intel.view(db, access, _item(db, item_id, access)))


@router.get("/api/cases/{case_id}/evidence/intel/queue")
def api_queue(access: CaseAccess = Depends(require_case_role(EXTERNAL))):
    return [{"id": q["item"].id, "status": q["status"], "type": (q["rules"] or {}).get("type"),
             "folder": (q["rules"] or {}).get("folder"), "reasons": (q["rules"] or {}).get("reasons"),
             "ai_type": (q["ai"] or {}).get("type")} for q in intel.queue(access)]
