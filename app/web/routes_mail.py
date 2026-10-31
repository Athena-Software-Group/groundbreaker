"""E-mail desk: the contact directory, the sender profile, compose → preview → send, reconcile.

Owner: the mail feature. Logic: app/domain/directory.py, sender.py, mail_compose.py, mail_send.py
(transports and inbound mail: app/mail/, routes in app/web/routes_mail_admin.py).
Templates: directory.html, sender_profile.html, mail_compose.html, mail_preview.html,
case/_contact_card.html (included by authority_detail.html). Static: css/mail.css, js/mail.js.

Directory
    GET  /directory                                        catalogue + global rows (any signed-in user)
    POST /directory/channels                               add a global channel (system admins)
    POST /directory/channels/{key_or_id}/verify            verify / unverify a global row or catalogue channel
    POST /cases/{id}/authorities/{key}/channels            add (or verify) a channel for an authority (admin)
    POST /cases/{id}/channels/{cid}/verify                 verify / unverify (global rows: system admins)
    POST /cases/{id}/channels/catalogue/{catalogue_key}/verify   (system admins)
    POST /cases/{id}/channels/{cid}/disable                (admin; global rows: system admins)
    GET  /api/cases/{id}/authorities/{key}/channels        the contact card as JSON (investigator)
Sender profile
    GET|POST /cases/{id}/sender-profile                    view (investigator) / save (admin)
E-mail
    GET|POST /cases/{id}/authorities/correspondence/{cid}/email   the editor (investigator): text, To / Cc / Bcc,
                                                           subject, attachments + uploads; `action` save | upload |
                                                           prepare | send_now (admin: ?confirm=<mid> shows the Send
                                                           form on the page; Send itself is the preview's route);
                                                           a letter no longer a draft: 303 to the e-mail that sent it
    POST /cases/{id}/authorities/correspondence/{cid}/email/preview   live preview of the text (JSON; nothing saved)
    POST /cases/{id}/stop-orders/{oid}/email               a stop order's draft letter, then compose
    GET  /cases/{id}/mail/messages/{mid}                   preview, confirmations, status history
    GET  /cases/{id}/mail/messages/{mid}/eml               the exact .eml (admin; audited)
    POST /cases/{id}/mail/messages/{mid}/send              Send (admin)
    POST /cases/{id}/mail/messages/{mid}/reconcile | finalize   (admin; no manual resend: reconcile only)
    POST /cases/{id}/evidence/{eid}/mail-safe          mark an e-mail-received file safe to attach (admin)
    POST /cases/{id}/mail/messages/{mid}/cancel            (the member who prepared it, or an admin)
    POST /cases/{id}/mail/messages/{mid}/edit              back to the editor with every field (a prepared one is
                                                           cancelled: the member who prepared it, or an admin)
    POST /cases/{id}/mail/messages/{mid}/retire-checklist  an old manual-mode checklist once Aegis sends itself: "I
                                                           did not send it from Outlook — retire it" (admin; Sent Items
                                                           is read first), then back to the editor
    GET  /api/cases/{id}/mail/messages/{mid}               status JSON (no addresses, no body)
The guided send (app/web/mail_flow.py): the editor's stepper (1 Recipients → 2 Letter → 3 Attachments → 4 Review &
send) and `return_to` (the page the editor was opened from: validated, this case's pages only) carried by every form
of the flow. A Send posted with the field goes to the "Sending…" screen, which polls the status and then goes on:
    GET  /cases/{id}/mail/messages/{mid}/sending           the "Sending…" screen (hourglass; js/mail.js polls)
    GET  /cases/{id}/mail/messages/{mid}/status            {id, status, state: pending | sent | failed | unknown |
                                                           other, done} (investigator; read-only, no addresses)
    GET  /cases/{id}/mail/messages/{mid}/after-send        sent: 303 to return_to with ?mail_sent=<mid> (the banner);
                                                           failed: back to the editor with the error; unknown: the
                                                           preview (check the mailbox); still sending: the screen
Manual mode ("Draft — you send", AEGIS_MAIL_TRANSPORT=manual, the default): the preview is a
"Send it yourself" checklist (copy buttons in js/mail.js; nothing is sent from Aegis)
    GET  /cases/{id}/mail/messages/{mid}/draft.eml         the editable Outlook draft (X-Unsent: 1; admin; audited)
    GET  /cases/{id}/mail/messages/{mid}/attachments.zip   every attachment (admin; audited)
    GET  /cases/{id}/mail/messages/{mid}/attachments/{n}   one attachment, 1-based (admin; audited)
    POST /cases/{id}/mail/messages/{mid}/record-sent       record the send made outside Aegis (admin)
    GET|POST /cases/{id}/mail/import                       import a reply (.eml / .msg) for review (investigator)
Jinja global `mail_guidance_for(authority)`: the "How to email" panel (mail_guidance.html) included by
case/_contact_card.html on the authority page.

There is deliberately no API route that sends: Send needs the browser session and the form's CSRF
token. Audit rows carry ids, counts, kinds and domains only, never addresses, subjects or bodies.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from jinja2 import pass_context
from markupsafe import Markup
from sqlalchemy import select
from sqlalchemy.orm import Session, object_session

from app.core.audit import CREATE, DOWNLOAD, LETTER_SENT, UPDATE, audit
from app.core.csrf import require_csrf, require_csrf_form
from app.core.permissions import ADMIN, INVESTIGATOR, CaseAccess, get_case_object, require_case_role
from app.core.security import require_system_admin, require_user
from app.db.models import (
    Correspondence,
    CorrespondenceStatus,
    Entity,
    EvidenceItem,
    MailDirection,
    MailMessage,
    MailStatus,
    StopOrder,
    User,
)
from app.db.session import get_db
from app.domain import correspondence as desk
from app.domain import directory, mail_guidance, mail_import, mail_send
from app.domain import evidence as ev
from app.domain import mail_compose as compose
from app.domain import sender as sender_mod
from app.web import mail_flow
from app.web.templating import templates

log = logging.getLogger(__name__)

router = APIRouter(tags=["mail"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]
KINDS = directory.KINDS
PURPOSES = directory.PURPOSES
SOURCES_ADD = ("manual", "case_correspondence", "le_contact", "entity_record")
SEND_RESULT_TEXT = {"sent": "E-mail sent and filed as evidence.", "failed": "Sending failed; the letter is still a draft.",
                    "unknown": mail_send.UNKNOWN_TEXT, "already": "Nothing was sent again.",
                    "filed": "Filed as evidence.", "cancelled": "The prepared e-mail was cancelled.",
                    "reconciled": "Checked with the mailbox.",
                    "sent_external": "Recorded as sent outside Aegis: the letter is marked sent and the reply clock "
                                     "runs. Import the reply when it arrives."}


@pass_context
def mail_guidance_for(ctx, authority):
    """Jinja global: the "How to email <authority>" guidance for the page's member (None when the
    member may not see restricted content, or on any error: advice never breaks a page)."""
    access = ctx.get("access")
    if access is None or authority is None or access.is_external or not access.can("view_restricted"):
        return None
    try:
        db = object_session(access.case)
        if db is None:
            return None
        card = ctx.get("card")
        return mail_guidance.for_authority(db, access, authority, card=card if card is not None and card.visible else None)
    except Exception:  # noqa: BLE001 - a guidance panel must never break the authority page
        return None


templates.env.globals["mail_guidance_for"] = mail_guidance_for


def _authority_of(db: Session, access: CaseAccess, corr: Correspondence) -> desk.Authority | None:
    for a in desk.case_authorities(db, access.case, shared_only=access.is_external, include_prospects=False):
        if corr in a.correspondence:
            return a
    return None


def _authority_or_404(db: Session, access: CaseAccess, key: str) -> desk.Authority:
    authority = desk.get_authority(db, access.case, key, shared_only=access.is_external)
    if authority is None:
        raise HTTPException(404, "authority not found")
    return authority


def _back(case_id: int, key: str | None, anchor: str = "contact") -> str:
    if key and desk.KEY_RE.fullmatch(key):
        return f"/cases/{case_id}/authorities/{key}#{anchor}"
    return f"/cases/{case_id}?tab=authorities"


def _domains(addresses) -> list[str]:
    return sorted({str(a).rpartition("@")[2].lower() for a in addresses or [] if "@" in str(a)})


# --------------------------------------------------------------------------- directory page
@router.get("/directory", response_class=HTMLResponse)
def directory_page(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    error = None
    try:
        orgs = directory.global_directory(db)
        cat = directory.load_catalogue()
    except directory.CatalogueError as e:
        orgs, cat, error = [], directory.Catalogue(version=0, orgs=()), str(e)
    entities = list(db.scalars(select(Entity).order_by(Entity.name))) if user.is_system_admin else []
    q = request.query_params
    return templates.TemplateResponse(request, "directory.html", {
        "orgs": orgs, "catalogue": cat, "entities": entities, "is_sysadmin": user.is_system_admin,
        "kinds": KINDS, "purposes": PURPOSES, "error": error, "msg": (q.get("msg") or "")[:200],
        "msg_err": q.get("err") == "1"})


def _dir_redirect(msg: str, err: bool = False, anchor: str = "") -> RedirectResponse:
    from urllib.parse import urlencode

    return RedirectResponse(f"/directory?{urlencode({'msg': msg[:200], 'err': '1' if err else '0'})}"
                            + (f"#{anchor}" if anchor else ""), status_code=303)


@router.post("/directory/channels", dependencies=_csrf)
def directory_add(me: User = Depends(require_system_admin), db: Session = Depends(get_db), target: str = Form(...),
                  kind: str = Form(...), value: str = Form(""), purpose: str = Form("general"),
                  role_default: str = Form("to"), label: str = Form(""), notes: str = Form(""),
                  verified: str = Form(""), note: str = Form("")):
    org_key, entity_id = None, None
    if target.startswith("org:"):
        org_key = target[4:]
    elif target.startswith("entity:") and target[7:].isdigit():
        entity_id = int(target[7:])
        if db.get(Entity, entity_id) is None:
            raise HTTPException(404, "entity not found")
    try:
        row = directory.add_global_channel(db, me, org_key=org_key, entity_id=entity_id, kind=kind, value=value,
                                           purpose=purpose, role_default=role_default, label=label, notes=notes,
                                           verified=verified == "1", note=note)
    except directory.DirectoryForbidden as e:
        raise HTTPException(403, str(e)) from None
    except directory.DirectoryError as e:
        db.rollback()
        return _dir_redirect(str(e), True)
    audit(db, me, CREATE, None, row, scope="global", kind=row.kind.value, purpose=row.purpose.value,
          org_key=row.org_key, entity_id=row.entity_id, verified=row.verified)
    return _dir_redirect("Channel added.", anchor=f"org-{org_key or entity_id}")


@router.post("/directory/channels/{key_or_id}/verify", dependencies=_csrf)
def directory_verify(key_or_id: str, me: User = Depends(require_system_admin), db: Session = Depends(get_db),
                     verified: str = Form("1"), note: str = Form("")):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key_or_id):
        raise HTTPException(404, "channel not found")
    try:
        row = directory.verify_channel(db, None, key_or_id, verified=verified == "1", note=note, user=me)
    except LookupError:
        raise HTTPException(404, "channel not found") from None
    except directory.DirectoryForbidden as e:
        raise HTTPException(403, str(e)) from None
    except directory.DirectoryError as e:
        db.rollback()
        return _dir_redirect(str(e), True)
    audit(db, me, UPDATE, row.case_id, row, fields=["verified"], verified=row.verified,
          catalogue_key=row.catalogue_key)
    return _dir_redirect("Verification saved.", anchor=f"org-{row.org_key or row.entity_id}")


# --------------------------------------------------------------------------- case channels
def _case_channel_error(e: Exception, back: str) -> RedirectResponse:
    from urllib.parse import quote

    sep = "&" if "?" in back.split("#")[0] else "?"
    path, _, anchor = back.partition("#")
    return RedirectResponse(f"{path}{sep}ch_err={quote(str(e)[:200])}" + (f"#{anchor}" if anchor else ""),
                            status_code=303)


@router.post("/cases/{case_id}/authorities/{key}/channels", dependencies=_csrf)
def case_channel_add(key: str, access: CaseAccess = Depends(require_case_role(ADMIN)), db: Session = Depends(get_db),
                     kind: str = Form(...), value: str = Form(""), purpose: str = Form("general"),
                     role_default: str = Form("to"), label: str = Form(""), notes: str = Form(""),
                     scope: str = Form("case"), verified: str = Form(""), note: str = Form(""),
                     source: str = Form("manual")):
    authority = _authority_or_404(db, access, key)
    back = _back(access.case.id, authority.key)
    if source not in SOURCES_ADD:
        raise HTTPException(400, "unknown source")
    try:
        row = directory.add_channel(db, access, authority, kind=kind, value=value, purpose=purpose,
                                    role_default=role_default, label=label, notes=notes, scope=scope,
                                    verified=verified == "1", note=note, source=source)
    except directory.DirectoryForbidden as e:
        db.rollback()
        raise HTTPException(403, str(e)) from None
    except directory.DirectoryError as e:
        db.rollback()
        return _case_channel_error(e, back)
    audit(db, access, CREATE, access.case if scope == "case" else None, row, scope=scope, kind=row.kind.value,
          purpose=row.purpose.value, source=row.source.value, verified=row.verified, authority_key=authority.key,
          domain=(row.value or "").rpartition("@")[2].lower() if row.kind.value == "email" else None)
    return RedirectResponse(back, status_code=303)


@router.post("/cases/{case_id}/channels/catalogue/{catalogue_key}/verify", dependencies=_csrf)
def case_catalogue_verify(catalogue_key: str, access: CaseAccess = Depends(require_case_role(ADMIN)),
                          db: Session = Depends(get_db), verified: str = Form("1"), note: str = Form(""),
                          back: str = Form("")):
    if not access.user.is_system_admin:
        raise HTTPException(403, "only system administrators may verify catalogue channels")
    if getattr(access.case, "is_demo", False):  # the global directory is never changed from a demo / training case
        raise HTTPException(409, "demo case: catalogue channels are verified from the directory, not from a demo case")
    try:
        row = directory.verify_catalogue(db, access.user, catalogue_key, verified=verified == "1", note=note)
    except directory.DirectoryForbidden as e:
        raise HTTPException(403, str(e)) from None
    except directory.DirectoryError as e:
        db.rollback()
        if str(e) == "unknown catalogue channel":
            raise HTTPException(404, "channel not found") from None
        return _case_channel_error(e, _back(access.case.id, back))
    audit(db, access, UPDATE, None, row, fields=["verified"], verified=row.verified, catalogue_key=catalogue_key)
    return RedirectResponse(_back(access.case.id, back), status_code=303)


@router.post("/cases/{case_id}/channels/{channel_id}/verify", dependencies=_csrf)
def case_channel_verify(channel_id: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                        db: Session = Depends(get_db), verified: str = Form("1"), note: str = Form(""),
                        back: str = Form("")):
    try:
        row = directory.verify_channel(db, access, channel_id, verified=verified == "1", note=note)
    except LookupError:
        raise HTTPException(404, "channel not found") from None
    except directory.DirectoryForbidden as e:
        db.rollback()
        raise HTTPException(403, str(e)) from None
    except directory.DirectoryError as e:
        db.rollback()
        return _case_channel_error(e, _back(access.case.id, back))
    audit(db, access, UPDATE, access.case if row.case_id else None, row, fields=["verified"], verified=row.verified,
          scope="case" if row.case_id else "global")
    return RedirectResponse(_back(access.case.id, back), status_code=303)


@router.post("/cases/{case_id}/channels/{channel_id}/disable", dependencies=_csrf)
def case_channel_disable(channel_id: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                         db: Session = Depends(get_db), back: str = Form(""), enable: str = Form("")):
    try:
        row = directory.disable_channel(db, access, channel_id, disabled=enable != "1")
    except LookupError:
        raise HTTPException(404, "channel not found") from None
    except directory.DirectoryForbidden as e:
        db.rollback()
        raise HTTPException(403, str(e)) from None
    audit(db, access, UPDATE, access.case if row.case_id else None, row, fields=["disabled"], disabled=row.disabled,
          scope="case" if row.case_id else "global")
    return RedirectResponse(_back(access.case.id, back), status_code=303)


@router.get("/api/cases/{case_id}/authorities/{key}/channels")
def api_channels(key: str, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                 db: Session = Depends(get_db)):
    authority = _authority_or_404(db, access, key)
    card = directory.channels_for(db, access, authority)
    org = card.org
    return {"authority": authority.key,
            "org": {"key": org.key, "name": org.name, "info_only": org.info_only, "freeze_capable": org.freeze_capable,
                    "portal_only": org.portal_only, "portal_url": org.portal_url} if org else None,
            "channels": [e.as_dict() for e in card.entries if not e.disabled or card.can_manage]}


# --------------------------------------------------------------------------- sender profile
def _profile_preview(case, profile) -> str:
    intro, sig = sender_mod.letter_parts(case, profile)
    return f"{intro}\n\n…\n\n{sig}\n"


AUTHORITY_DOC_FOLDERS = ("legal", "law_enforcement")


def _is_eml(e: EvidenceItem) -> bool:
    name = str((e.meta or {}).get("original_filename") or "").lower()
    return (e.source_type or "") == "eml" or name.endswith(".eml") or (e.mime or "").startswith("message/rfc822")


def _likely_authority_doc(e: EvidenceItem) -> bool:
    """The picker's default list: Legal / Law-enforcement documents and PDFs; never an e-mail
    (.eml) or a file received by e-mail."""
    if _is_eml(e) or compose.is_inbound(e):
        return False
    name = str((e.meta or {}).get("original_filename") or "").lower()
    return e.folder.value in AUTHORITY_DOC_FOLDERS or (e.mime or "").startswith("application/pdf") \
        or name.endswith(".pdf")


def _render_profile(request: Request, db: Session, access: CaseAccess, *, error: str | None = None,
                    values: dict | None = None, status: int = 200, saved: bool = False) -> HTMLResponse:
    profile = sender_mod.get_profile(db, access.case)
    settings = None
    try:
        settings = mail_send._settings()
    except Exception:  # noqa: BLE001 - the page works without the mail transport package
        settings = None
    current = values or ({k: getattr(profile, k) for k in sender_mod.FIELDS} if profile is not None
                         else sender_mod.defaults(access.case, settings))
    if values is None and profile is not None:
        current["cc_default"] = ", ".join(profile.cc_default or [])
        current["authority_evidence_ids"] = list(profile.authority_evidence_ids or [])
    elif values is None:
        current["cc_default"] = ""
    chosen = {int(i) for i in current.get("authority_evidence_ids") or [] if str(i).isdigit()}
    mask = ev.ref_mask(access)
    show_all = request.query_params.get("docs") == "all"
    visible = sorted(ev.visible_items(access), key=lambda e: e.id)
    offered = [e for e in visible if e.id in chosen or (
        (_likely_authority_doc(e) or show_all) and not _is_eml(e) and not compose.is_inbound(e))]
    docs = [{"id": e.id, "title": mask(e.title), "folder": ev.folder_label(e.folder),
             "classification": e.classification.value, "tlp": e.tlp,
             "blocked": sender_mod.authority_doc_problem(access, e), "checked": e.id in chosen}
            for e in offered]
    response = templates.TemplateResponse(request, "sender_profile.html", {
        "case": access.case, "access": access, "profile": profile, "values": current, "docs": docs, "error": error,
        "saved": saved or request.query_params.get("saved") == "1",
        "preview_md": _profile_preview(access.case, profile) if profile is not None else None,
        "can_edit": access.can("manage_sender_profile"), "fields": sender_mod.FIELDS,
        "docs_all": show_all, "docs_hidden": len(visible) - len(offered),
        "block_text": compose.BLOCK_TEXT, "sender_help": sender_mod.SENDER_OF_RECORD_HELP,
        "org_default": sender_mod.org_name(), "instrument_default": sender_mod.DEFAULT_INSTRUMENT,
        "signatory_default": sender_mod.signatory_name()}, status_code=status)
    return response


@router.get("/cases/{case_id}/sender-profile", response_class=HTMLResponse)
def sender_profile_page(request: Request, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                        db: Session = Depends(get_db)):
    return _render_profile(request, db, access)


@router.post("/cases/{case_id}/sender-profile", dependencies=_csrf, response_class=HTMLResponse)
async def sender_profile_save(request: Request, access: CaseAccess = Depends(require_case_role(ADMIN)),
                              db: Session = Depends(get_db)):
    form = await request.form()
    values = {k: form.get(k) for k in sender_mod.FIELDS}
    values["cc_default"] = form.get("cc_default") or ""
    values["instrument_is_poa"] = form.get("instrument_is_poa") or ""
    values["authority_evidence_ids"] = [str(v) for v in form.getlist("authority_evidence_ids")]
    existed = sender_mod.get_profile(db, access.case) is not None
    try:
        row, changed = sender_mod.save_profile(db, access, values)
    except sender_mod.SenderForbidden as e:
        db.rollback()
        raise HTTPException(403, str(e)) from None
    except LookupError:
        db.rollback()
        raise HTTPException(404, "evidence item not found") from None
    except sender_mod.SenderError as e:
        db.rollback()
        return _render_profile(request, db, access, error=str(e), values=values, status=400)
    audit(db, access, UPDATE if existed else CREATE, access.case, row, fields=sorted(changed),
          n_authority_docs=len(row.authority_evidence_ids or []), n_cc=len(row.cc_default or []))
    return RedirectResponse(f"/cases/{access.case.id}/sender-profile?saved=1", status_code=303)


# --------------------------------------------------------------------------- compose / prepare
def _corr_for_mail(db: Session, access: CaseAccess, corr_id: int) -> tuple[Correspondence, desk.Authority]:
    corr = get_case_object(db, Correspondence, corr_id, access)
    authority = _authority_of(db, access, corr)
    if authority is None:
        raise HTTPException(409, "this letter is not tied to one counterparty; open it from the authority's page")
    return corr, authority


def _return_to(access: CaseAccess, raw) -> str:
    """The validated `return_to` of the guided send (app/web/mail_flow.py), '' when none or not this case's page."""
    return mail_flow.safe_return(raw, access.case.id) or ""


def _rt(return_to: str) -> str:
    """`&return_to=…` for a redirect inside the flow ('' when none)."""
    return f"&{urlencode({'return_to': return_to})}" if return_to else ""


def _render_compose(request: Request, db: Session, access: CaseAccess, corr, authority, *, form: dict | None = None,
                    error: compose.ComposeError | None = None, status: int = 200,
                    confirm: MailMessage | None = None, notice: str | None = None,
                    return_to: str | None = None, failed: str | None = None) -> HTMLResponse:
    opts = compose.compose_options(db, access, corr, authority, form)
    stale = False
    if error is not None and error.field == "checklist" and opts.checklist is not None:
        error = None  # the page's checklist notice says exactly this, with the link
    if error is not None:
        opts.errors = {error.field: str(error)}
        if error.field == "draft" and form is not None and "body_markdown" in form:
            # the letter changed meanwhile: the page keeps the member's text with the hash it was based on, so a
            # second Save is refused again instead of replacing the other edit; the current text is shown beside it
            opts.draft_hash = str(form.get("draft_hash") or "")
            stale = True
    st, problem = mail_send.transport_status()
    ctx = {"case": access.case, "access": access, "corr": corr, "authority": authority, "opts": opts,
           "transport_problem": problem, "transport": st, "vault": ev.vault_status(), "error": str(error) if error else None,
           "mask": desk.contact_mask(access, authority, corr),
           "body_preview": Markup(compose.body_html(opts.body)),  # markdown-it, raw HTML disabled: escaped
           "can_send": access.can("send_email"), "can_edit_body": access.can("draft_letter"),
           "can_upload": access.can("add_evidence"), "upload_max_files": compose.UPLOAD_MAX_FILES,
           "upload_max_mb": int(opts.max_bytes * 0.74) / 1e6, "notice": notice, "confirm": None,
           "upload_types": compose.UPLOAD_ALLOWED_TEXT, "sender_help": sender_mod.SENDER_OF_RECORD_HELP,
           "upload_accept": ",".join(f".{e}" for e in compose.UPLOAD_ALLOWED),
           "stale_body": (corr.body_markdown or "") if stale and desk.can_view_body(access, corr) else None,
           "return_to": return_to if return_to is not None else _return_to(access, request.query_params.get("return_to"))}
    if failed and not ctx["error"]:
        ctx["error"] = failed
    if confirm is not None and opts.checklist is None:  # an open old checklist: no Send form (Send refuses it too)
        ctx.update(_send_context(db, access, confirm, corr, authority))
        ctx["confirm"] = confirm
    ctx["steps"] = compose.compose_steps(opts, confirm=ctx["confirm"], can_send=ctx["can_send"],
                                         transport_problem=problem)
    return templates.TemplateResponse(request, "mail_compose.html", ctx, status_code=status)


def _attachment_context(db: Session, access: CaseAccess, mm: MailMessage, pv) -> dict:
    """The attachments of an e-mail as this member may see them: evidence it may not see is counted, never named."""
    att_evidence = {}
    restricted: set[int] = set()
    for m in mm.attachments or []:
        if m.get("evidence_id"):
            item = db.get(EvidenceItem, int(m["evidence_id"]))
            if item is not None and item.case_id == access.case.id and ev.can_see(access, item):
                att_evidence[item.id] = item
            else:
                restricted.add(int(m["evidence_id"]))
    visible_atts = [a for a in pv.attachments if not (a.get("evidence_id") and int(a["evidence_id"]) in restricted)]
    return {"att_evidence": att_evidence, "visible_atts": visible_atts, "n_restricted": len(restricted)}


def _send_context(db: Session, access: CaseAccess, mm: MailMessage, corr, authority) -> dict:
    """What the Send form (_mail_send_form.html) needs, on the preview and on the compose page's confirmation."""
    card = directory.channels_for(db, access, authority) if authority is not None else None
    pv = compose.preview(db, mm, corr)
    return {"mm": mm, "pv": pv, **_attachment_context(db, access, mm, pv),
            "confirm_rows": _confirm_rows(mm, card, authority.name if authority else "the recipient"),
            "ev_text": ev.ref_mask(access), "bcc": compose.bcc_of(mm),
            "sender_check": compose.sender_check(db, access.case, corr) if corr is not None else None,
            "sender_help": sender_mod.SENDER_OF_RECORD_HELP, "default_due_days": desk.DEFAULT_RESPONSE_DAYS,
            "busy_send": compose.letter_in_flight(db, corr, exclude_id=mm.id) if corr is not None else None}


def _pending_confirm(db: Session, access: CaseAccess, corr, raw: str | None) -> MailMessage | None:
    """The prepared e-mail the compose page's "Send now" confirmation is for (?confirm=<id>), when it is still
    this letter's, prepared and unexpired, and the member may send (never in manual mode; Send refuses whatever the
    page shows while the letter has an open old checklist: mail_send._check_preconditions)."""
    if not raw or not raw.isdigit() or not access.can("send_email") or compose.is_manual():
        return None
    mm = db.get(MailMessage, int(raw))
    if mm is None or mm.case_id != access.case.id or mm.direction != MailDirection.OUT or \
            mm.correspondence_id != corr.id or mm.status != MailStatus.PREPARED or mm.expires_at is None:
        return None
    expires = mm.expires_at if mm.expires_at.tzinfo else mm.expires_at.replace(tzinfo=UTC)
    return mm if datetime.now(tz=UTC) < expires else None


COMPOSE_NOTICES = {"saved": "Saved: the letter text and the e-mail fields are kept with the draft.",
                   "uploaded": "Uploaded: the files are filed as evidence (Stop orders & correspondence) and attached.",
                   "signature": "The letter now opens and closes with the sender profile's wording (“… on behalf of "
                                "…” and its signature). Saved: the previous text is kept as a version of the letter.",
                   "signature_same": "The letter already opens and closes with the sender profile's wording: nothing "
                                     "changed.",
                   "edit": "The prepared e-mail was cancelled (nothing was sent): edit it below, then prepare or send it "
                           "again.",
                   "edit_loaded": "The e-mail's fields are loaded below: edit them, then prepare or send it.",
                   "retired": "The Outlook checklist was retired (recorded: not sent from Outlook). Its fields are "
                              "loaded below: Aegis sends the letter from here.",
                   "retired_unchecked": "The Outlook checklist was retired (recorded: not sent from Outlook), but Aegis "
                                        "could not read the mailbox's Sent Items just now: check Sent Items in Outlook "
                                        "yourself before you send. Its fields are loaded below.",
                   "retired_no_inbound": "The Outlook checklist was retired (recorded: not sent from Outlook). Aegis "
                                         "does not read this mailbox (AEGIS_MAIL_INBOUND is off): check Sent Items in "
                                         "Outlook yourself before you send. Its fields are loaded below.",
                   "retired_not_covered": "The Outlook checklist was retired (recorded: not sent from Outlook), but "
                                          "Aegis read the mailbox's Sent Items only from a date after this checklist "
                                          "was prepared (AEGIS_MAIL_INBOUND_SINCE, or the mailbox's first sync), or "
                                          "this mailbox's Sent Items are not read at all: an Outlook send of it would "
                                          "not have been seen. Check Sent Items in Outlook yourself, back to the day "
                                          "the checklist was prepared, before you send. Its fields are loaded below.",
                   "mailbox_dropped": "The case mailbox was taken out of Cc / Bcc: Aegis sends from it, and its Sent "
                                      "Items keeps the copy."}


@router.get("/cases/{case_id}/authorities/correspondence/{corr_id}/email", response_class=HTMLResponse)
def compose_page(request: Request, corr_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                 db: Session = Depends(get_db)):
    access.require("prepare_email")
    corr, authority = _corr_for_mail(db, access, corr_id)
    if corr.status != CorrespondenceStatus.DRAFT:  # sent meanwhile (another tab, a double click): the e-mail that did
        sent = compose.letter_in_flight(db, corr)
        mid = sent.id if sent is not None else (corr.meta or {}).get("mail_message_id")
        return RedirectResponse(f"/cases/{access.case.id}/mail/messages/{int(mid)}" if isinstance(mid, int)
                                else f"/cases/{access.case.id}/authorities/correspondence/{corr.id}", status_code=303)
    try:
        compose._check_draft(access, corr)
        compose.refuse_pointless(db, corr)
    except compose.ComposeError as e:
        raise HTTPException(409, str(e)) from None
    q = request.query_params
    confirm = _pending_confirm(db, access, corr, q.get("confirm"))
    notice = COMPOSE_NOTICES.get(q.get("done") or "")
    gone = sorted({int(v) for v in q.getlist("cancelled") if v.isdigit()})
    if notice and gone:
        notice += " " + ", ".join(f"#{i}" for i in gone) + (" were" if len(gone) > 1 else " was") + \
            " cancelled (nothing was sent from " + ("them" if len(gone) > 1 else "it") + ")."
    if q.get("dropped") and notice:
        notice += " " + COMPOSE_NOTICES["mailbox_dropped"]
    if q.get("confirm") and confirm is None and (compose.is_manual() or compose.open_checklist(db, corr) is None):
        notice = "That prepared e-mail is no longer waiting (sent, cancelled, expired or edited): nothing was sent."
    return _render_compose(request, db, access, corr, authority, confirm=confirm, notice=notice,
                           failed=_failed_text(db, access, corr, q.get("send_failed")))


def _failed_text(db: Session, access: CaseAccess, corr, raw: str | None) -> str | None:
    """The editor's error after the "Sending…" screen saw e-mail `raw` of this letter fail (?send_failed=<id>)."""
    if not raw or not raw.isdigit() or len(raw) > 12:
        return None
    mm = db.get(MailMessage, int(raw))
    if mm is None or mm.case_id != access.case.id or mm.correspondence_id != corr.id or \
            mm.direction != MailDirection.OUT or mm.status != MailStatus.FAILED:
        return None
    why = f" ({mm.error_reason})" if mm.error_reason else ""
    detail = f": {mm.error_message}" if mm.error_message else ""
    return (f"E-mail #{mm.id} was not sent{why}{detail}. Nothing went out and the letter is still a draft: check the "
            "steps below and send it again.")


COMPOSE_ACTIONS = ("save", "upload", "prepare", "send_now", "use_signature")


async def _compose_form(request: Request) -> tuple[str, dict, list[tuple[str, bytes]]]:
    # every file part is read into memory below: at most UPLOAD_MAX_FILES (+1: an empty file input) per request, as
    # the route's CSRF dependency parsed it (require_csrf_form: the cap applies there, before any part is spooled)
    data = await request.form(max_files=compose.UPLOAD_MAX_FILES + 1)
    form = {"draft_hash": data.get("draft_hash") or "", "to": data.getlist("to"), "cc": data.getlist("cc"),
            "bcc": data.getlist("bcc"), "to_other": data.get("to_other") or "", "cc_other": data.get("cc_other") or "",
            "bcc_other": data.get("bcc_other") or "", "subject": data.get("subject") or "",
            "attach": data.getlist("attach"), "cc_add": data.getlist("cc_add"),
            "cc_offered": str(data.get("cc_offered") or "")}
    if "body_markdown" in data:
        form["body_markdown"] = str(data.get("body_markdown") or "")
    limit = compose.max_bytes_for(mail_send._settings())
    uploads = []
    for f in data.getlist("upload"):
        if hasattr(f, "read") and (getattr(f, "filename", "") or ""):
            uploads.append((str(f.filename), await f.read(limit + 1)))
    return str(data.get("action") or ""), form, uploads


def _audit_save(db: Session, access: CaseAccess, corr, saved: compose.SaveResult, form: dict) -> None:
    for item in saved.uploaded:
        audit(db, access, CREATE, access.case, item, folder=item.folder.value, size=item.size_bytes, sha256=item.sha256,
              via="mail_compose", correspondence_id=corr.id)
    fields = ["meta.mail_draft"] + (["body_markdown"] if saved.body_changed else [])
    audit(db, access, UPDATE, access.case, corr, fields=fields, via="mail_compose", stop_order_id=corr.stop_order_id,
          body_chars=len(corr.body_markdown or "") if saved.body_changed else None,
          n_versions=len((corr.meta or {}).get("versions") or []) if saved.body_changed else None,
          n_to=len(compose._split(form.get("to")) + compose._split(form.get("to_other"))),
          n_cc=len(compose._split(form.get("cc")) + compose._split(form.get("cc_other"))),
          n_bcc=len(compose._split(form.get("bcc")) + compose._split(form.get("bcc_other"))),
          n_attachments=len(form.get("attach") or []), n_uploaded=len(saved.uploaded),
          **({"cc_add": [k for k in compose._split(form.get("cc_add")) if k in compose.CC_OFFER_KEYS]}
             if form.get("cc_offered") else {}),
          **({"signature_from_profile": True} if form.get("_action") == "use_signature" else {}))
    for mid in saved.superseded:
        mm = db.get(MailMessage, mid)
        if mm is not None:
            audit(db, access, "MAIL_CANCELLED", access.case, mm, correspondence_id=corr.id, reason="edited")


def _audit_prepared(db: Session, access: CaseAccess, corr, mm: MailMessage, **extra) -> None:
    bcc = compose.bcc_of(mm)
    audit(db, access, CREATE, access.case, mm, correspondence_id=corr.id, n_to=len(mm.to_addrs or []),
          n_cc=len(mm.cc_addrs or []), n_bcc=len(bcc), n_attachments=len(mm.attachments or []),
          mime_size=mm.mime_size, transport=mm.transport, **extra)


@router.post("/cases/{case_id}/authorities/correspondence/{corr_id}/email",
             dependencies=[Depends(require_csrf_form(max_files=compose.UPLOAD_MAX_FILES + 1))],
             response_class=HTMLResponse)
async def compose_prepare(request: Request, corr_id: int,
                          access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db)):
    """The editor's buttons (`action`): save | upload (keep the edits, back to the editor) | prepare (the
    preview, for a case admin to send) | send_now (case admins: prepare, then the confirmation on this page,
    whose Send posts to the preview's Send route). Without `action` (older forms): prepare only."""
    access.require("prepare_email")
    corr, authority = _corr_for_mail(db, access, corr_id)
    action, form, uploads = await _compose_form(request)
    return_to = _return_to(access, (await request.form()).get("return_to"))  # the parsed form (cached)
    if action and action not in COMPOSE_ACTIONS:
        raise HTTPException(400, "unknown action")
    if action == "send_now" and not access.can("send_email"):
        raise HTTPException(403, "only case admins send e-mail")
    gone = compose.pointless_text(db, corr) if corr.status == CorrespondenceStatus.DRAFT else None
    if gone is not None:  # never prepared, saved or sent: discard it (freeze_board.letter_flag)
        raise HTTPException(409, gone)
    base = f"/cases/{access.case.id}/authorities/correspondence/{corr.id}/email"
    if action == "use_signature":  # one click: the sender profile's opening and signature, a normal saved edit
        fixed = compose.profile_signature_body(db, access.case, str(form.get("body_markdown", corr.body_markdown)
                                                                    or ""))
        if fixed is None:
            raise HTTPException(409, "this case has no sender profile: set it up first")
        form["body_markdown"], form["_action"] = fixed, "use_signature"
    if action:
        try:
            if action == "send_now" and compose.is_manual():
                raise compose.ComposeError("Aegis does not send in manual mode (Draft — you send): prepare the e-mail "
                                           "and send it from Outlook", "form")
            saved = compose.save_compose(db, access, corr, authority, form, uploads)
        except LookupError:
            db.rollback()
            raise HTTPException(404, "attachment not found") from None
        except compose.ComposeError as e:
            db.rollback()
            return _render_compose(request, db, access, corr, authority, form=form, error=e,
                                   status=409 if e.field == "checklist" else 400, return_to=return_to)
        _audit_save(db, access, corr, saved, form)
        if action in ("save", "upload", "use_signature"):
            done = "uploaded" if saved.uploaded else "saved"
            if action == "use_signature":
                done = "signature" if saved.body_changed else "signature_same"
            gone = "".join(f"&cancelled={i}" for i in saved.superseded)
            return RedirectResponse(f"{base}?done={done}{gone}{_rt(return_to)}"
                                    f"#{'attachments' if saved.uploaded else 'editor'}", status_code=303)
    try:
        mm = compose.prepare(db, access, corr, authority, form)
    except LookupError:
        db.rollback()
        raise HTTPException(404, "attachment not found") from None
    except compose.ComposeError as e:
        db.rollback()
        return _render_compose(request, db, access, corr, authority, form=form, error=e,
                               status=409 if e.field == "checklist" else 400, return_to=return_to)
    _audit_prepared(db, access, corr, mm, via=action or "prepare")
    if action == "send_now":
        return RedirectResponse(f"{base}?confirm={mm.id}{_rt(return_to)}#confirm", status_code=303)
    return RedirectResponse(mail_flow.with_query(f"/cases/{access.case.id}/mail/messages/{mm.id}",
                                                 return_to=return_to or None), status_code=303)


@router.post("/cases/{case_id}/authorities/correspondence/{corr_id}/email/preview",
             dependencies=[Depends(require_csrf_form(max_files=0, max_fields=5))])
async def compose_body_preview(request: Request, corr_id: int,
                               access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                               db: Session = Depends(get_db)):
    """The editor's live preview: the letter text as the e-mail's HTML part renders it (escaped, nothing saved)."""
    access.require("prepare_email")
    corr, _authority = _corr_for_mail(db, access, corr_id)
    if not desk.can_view_body(access, corr):
        raise HTTPException(403, "the letter text is restricted for your role")
    data = await request.form(max_files=0, max_fields=5)  # text only: the CSRF dependency refused any file part
    raw = data.get("body_markdown")
    body = (raw if isinstance(raw, str) else "")[:compose.BODY_MAX]
    return JSONResponse({"html": compose.body_html(body), "chars": len(body)}, headers={"Cache-Control": "no-store"})


@router.post("/cases/{case_id}/stop-orders/{order_id}/email", dependencies=_csrf)
def stop_order_email(order_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                     db: Session = Depends(get_db), return_to: str = Form("")):
    access.require("prepare_email")
    order = get_case_object(db, StopOrder, order_id, access)
    if not order.entity_id:
        raise HTTPException(409, "this stop order has no counterparty on file")
    authority = _authority_or_404(db, access, f"entity-{order.entity_id}")
    from app.blocks import freeze_board as fb

    gone = fb.pointless_text(fb.order_flag(db, access.case, authority, f"o{order.id}")) \
        if order.status.value == "draft" else None
    if gone is not None:  # never e-mailed: discard it (the board's pointless / duplicate flag)
        raise HTTPException(409, gone)
    try:
        corr, created = compose.ensure_correspondence(db, order, authority, access.user)
    except compose.ComposeError as e:
        raise HTTPException(409, str(e)) from None
    if created:
        audit(db, access, CREATE, access.case, corr, stop_order_id=order.id, kind=corr.kind.value, via="mail")
    back = _return_to(access, return_to)
    return RedirectResponse(mail_flow.with_query(f"/cases/{access.case.id}/authorities/correspondence/{corr.id}/email",
                                                 return_to=back or None), status_code=303)


# --------------------------------------------------------------------------- preview / send
def _message(db: Session, access: CaseAccess, mid: int) -> MailMessage:
    mm = get_case_object(db, MailMessage, mid, access)
    if mm.direction != MailDirection.OUT:
        raise HTTPException(404, "mail_messages not found")
    return mm


def _confirm_rows(mm: MailMessage, card: directory.ContactCard | None, org_name: str) -> list[dict]:
    rows = []
    bcc = {b.lower() for b in compose.bcc_of(mm)}
    for a in mail_send.expected_confirmations(mm)["unverified"]:
        e = card.entry_for(a) if card is not None else None
        source = (e.label or e.source.replace("_", " ")) if e is not None else "typed in"
        rows.append({"address": a, "org": org_name, "source": source, "bcc": a.lower() in bcc})
    return rows


def _render_preview(request: Request, db: Session, access: CaseAccess, mm: MailMessage, *, error: str | None = None,
                    status: int = 200, record_form: dict | None = None,
                    suspected: MailMessage | None = None, return_to: str | None = None) -> HTMLResponse:
    corr = db.get(Correspondence, mm.correspondence_id) if mm.correspondence_id else None
    authority = _authority_of(db, access, corr) if corr is not None else None
    card = directory.channels_for(db, access, authority) if authority is not None else None
    pv = compose.preview(db, mm, corr)
    st, problem = mail_send.transport_status()
    atts = _attachment_context(db, access, mm, pv)  # attached evidence this member may not see: counted, never named
    superseded_by = (mm.meta or {}).get("superseded_by")
    q = request.query_params
    meta = mm.meta or {}
    expired = mm.status == MailStatus.PREPARED and mm.expires_at is not None and \
        datetime.now(tz=UTC) >= (mm.expires_at if mm.expires_at.tzinfo else mm.expires_at.replace(tzinfo=UTC))
    busy = busy_text = None
    sender_check = None
    if corr is not None and mm.status in (MailStatus.PREPARED, MailStatus.EXPIRED) and (
            mm.status == MailStatus.PREPARED or mm.transport == "manual"):
        busy = compose.letter_in_flight(db, corr, exclude_id=mm.id)
        busy_text = compose.letter_busy_text(corr, busy) if busy is not None else None
        sender_check = compose.sender_check(db, access.case, corr)
    auth_warning = compose.authorisation_warning(db, access.case, corr, list(mm.attachments or [])) \
        if mm.status == MailStatus.PREPARED and not expired else None
    manual = mm.transport == "manual" or (pv.unsent and mm.status != MailStatus.SENT)
    checklist = None
    if manual and pv.ok and corr is not None:
        tag = compose.TAG_RE.search(mm.subject or "")
        checklist = {"to": ", ".join(mm.to_addrs or []), "cc": ", ".join(mm.cc_addrs or []),
                     "bcc": ", ".join(compose.bcc_of(mm)), "subject": mm.subject or "",
                     "tag": tag.group(0) if tag else "",
                     "text": pv.text, "html": pv.html,
                     "mailto": compose.mailto_url(list(mm.to_addrs or []), list(mm.cc_addrs or []), mm.subject or "",
                                                  pv.text, compose.bcc_of(mm))}
    guidance = None
    if manual and authority is not None and access.can("view_restricted") and mm.status == MailStatus.PREPARED:
        try:
            guidance = mail_guidance.for_authority(db, access, authority, corr, card=card)
        except Exception:  # noqa: BLE001 - advice only
            guidance = None
    now = datetime.now(tz=UTC)
    letter_draft = corr is not None and corr.status == CorrespondenceStatus.DRAFT
    other_busy = compose.letter_in_flight(db, corr, exclude_id=mm.id) if letter_draft else None
    # an old "Draft — you send" checklist of the letter while Aegis sends itself: nothing else goes ahead until a case
    # admin retires it or records it as sent (on the checklist itself: the only two actions offered)
    block = compose.open_checklist(db, corr) if letter_draft and not compose.is_manual() else None
    if block is not None and error == compose.checklist_text(block):
        error = None  # the page's checklist notice says exactly this, with the link
    can_edit = letter_draft and other_busy is None and block is None and access.can("prepare_email") \
        and mm.status in compose.EDITABLE and not isinstance(superseded_by, int) and desk.can_view_body(access, corr) \
        and (mm.status != MailStatus.PREPARED or access.can("send_email") or mm.created_by == access.user.id)
    return templates.TemplateResponse(request, "mail_preview.html", {
        "case": access.case, "access": access, "mm": mm, "corr": corr, "authority": authority, "pv": pv,
        **atts, "auth_warning": auth_warning, "bcc": compose.bcc_of(mm), "can_edit": can_edit,
        "checklist_block": block, "checklist_block_text": compose.checklist_text(block) if block is not None else "",
        # a pointless letter (its provider answered LE only / declined, or it predates their reply): Send refuses it
        "pointless": compose.pointless_text(db, corr) if letter_draft and mm.status == MailStatus.PREPARED else None,
        "is_block": block is not None and block.id == mm.id,
        "can_retire": block is not None and block.id == mm.id and access.can("send_email") and other_busy is None,
        "inbound_on": _inbound_on() if block is not None and block.id == mm.id else False,
        "suspected": suspected,
        "discarded": mm.status in (MailStatus.CANCELLED, MailStatus.EXPIRED) or expired,
        "superseded_by": superseded_by if isinstance(superseded_by, int) else None,
        "can_check_draft": compose.stale_draft_left(mm),
        "confirm_rows": _confirm_rows(mm, card, authority.name if authority else "the recipient"),
        "ev_text": ev.ref_mask(access), "transport": st, "transport_problem": problem,
        "can_send": access.can("send_email"), "error": error, "expired": expired,
        "can_renew": access.can("prepare_email") and letter_draft and block is None and (
            expired or mm.status in compose.RENEWABLE)
        and compose.draft_hash(corr) == meta.get("draft_hash") and compose.letter_in_flight(db, corr) is None,
        "draft_changed": corr is not None and mm.status == MailStatus.PREPARED
        and compose.draft_hash(corr) != meta.get("draft_hash"),
        "result": SEND_RESULT_TEXT.get(q.get("r") or ""), "result_key": q.get("r") or "",
        "busy": busy, "busy_text": busy_text, "sender_check": sender_check,
        "sender_help": sender_mod.SENDER_OF_RECORD_HELP,
        "history": list(meta.get("history") or []), "default_due_days": desk.DEFAULT_RESPONSE_DAYS,
        "can_cancel": mm.status == MailStatus.PREPARED and not (block is not None and block.id == mm.id) and (
            access.can("send_email") or mm.created_by == access.user.id),
        "user_names": {u.id: u.display_name for u in db.scalars(select(User).where(User.id.in_(
            {h.get("by") for h in meta.get("history") or [] if h.get("by")} | {0})))},
        "mask": desk.contact_mask(access, authority, corr),
        "manual": manual, "checklist": checklist, "guidance": guidance,
        "can_record": manual and access.can("send_email") and corr is not None
        and mm.status in mail_send.EXTERNAL_RECORDABLE and corr.status == CorrespondenceStatus.DRAFT
        and busy is None and compose.draft_hash(corr) == meta.get("draft_hash"),
        "record_defaults": {"sent_at": now.strftime("%Y-%m-%dT%H:%M"), "to": ", ".join(mm.to_addrs or []),
                            "cc": ", ".join(mm.cc_addrs or []), "max": now.strftime("%Y-%m-%dT%H:%M")},
        "record_form": record_form or {}, "upload_max_mb": mail_send.SENT_UPLOAD_MAX // (1 << 20),
        "return_to": return_to if return_to is not None else _return_to(access, q.get("return_to"))},
        status_code=status)


@router.get("/cases/{case_id}/mail/messages/{mid}", response_class=HTMLResponse)
def preview_page(request: Request, mid: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                 db: Session = Depends(get_db)):
    return _render_preview(request, db, access, _message(db, access, mid))


@router.get("/cases/{case_id}/mail/messages/{mid}/eml")
def preview_eml(mid: int, access: CaseAccess = Depends(require_case_role(ADMIN)), db: Session = Depends(get_db)):
    mm = _message(db, access, mid)
    try:
        raw = compose.read_raw(mm, db)
    except (OSError, ev.EvidenceError):
        raise HTTPException(410, "the message bytes are no longer available") from None
    audit(db, access, DOWNLOAD, access.case, mm, mode="eml", size=len(raw), status=mm.status.value)
    ref = re.sub(r"[^A-Za-z0-9._-]+", "-", access.case.reference)[:40]
    name = f"{ref}_email-{mm.correspondence_id or 0}-{mm.id}.eml"
    return Response(raw, media_type="message/rfc822", headers={
        "Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff"})


def _after(access: CaseAccess, mm: MailMessage, key: str) -> RedirectResponse:
    return RedirectResponse(f"/cases/{access.case.id}/mail/messages/{mm.id}?r={key}", status_code=303)


def _audit_outcome(db: Session, access: CaseAccess, out: mail_send.SendOutcome, *, via: str = "send") -> None:
    mm = out.mm
    if out.outcome == "sent":
        corr = db.get(Correspondence, mm.correspondence_id) if mm.correspondence_id else None
        audit(db, access, LETTER_SENT, access.case, corr if corr is not None else mm, via="email",
              transport=mm.transport, mail_message_id=mm.id, n_to=len(mm.to_addrs or []), n_cc=len(mm.cc_addrs or []),
              n_attachments=len(mm.attachments or []), mime_size=mm.mime_size, mime_sha256=mm.mime_sha256,
              eml_evidence_id=mm.eml_evidence_id,
              attachment_evidence_ids=[m["evidence_id"] for m in mm.attachments or [] if m.get("evidence_id")],
              n_unverified_confirmed=(mm.meta or {}).get("n_unverified_confirmed", 0),
              recipient_domains=_domains([*(mm.to_addrs or []), *(mm.cc_addrs or [])]),
              n_bcc=len(compose.bcc_of(mm)), bcc_domains=_domains(compose.bcc_of(mm)),
              filed=bool((mm.meta or {}).get("finalized")), stop_order_id=corr.stop_order_id if corr else None,
              sender_problem=(mm.meta or {}).get("sender_problem"),
              sender_mismatch_acknowledged=bool((mm.meta or {}).get("sender_ack")), step=via)
    elif out.outcome == "failed":
        audit(db, access, "MAIL_SEND_FAILED", access.case, mm, reason=mm.error_reason, transport=mm.transport,
              attempts=mm.attempts, step=via)
    elif out.outcome == "unknown":
        audit(db, access, "MAIL_SEND_UNKNOWN", access.case, mm, reason=mm.error_reason, transport=mm.transport,
              attempts=mm.attempts, step=via)


@router.post("/cases/{case_id}/mail/messages/{mid}/send", dependencies=_csrf, response_class=HTMLResponse)
async def preview_send(request: Request, mid: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                       db: Session = Depends(get_db)):
    mm = _message(db, access, mid)
    data = await request.form()
    form = {"prepare_token": data.get("prepare_token") or "", "confirm_send": data.get("confirm_send") or "",
            "confirm_unverified": data.getlist("confirm_unverified"),
            "confirm_attachment": data.getlist("confirm_attachment"), "due_days": data.get("due_days"),
            "ack_sender": data.get("ack_sender") or "", "ack_sender_reason": str(data.get("ack_sender_reason") or "")}
    guided = "return_to" in data  # the flow's Send forms (_mail_send_form.html) always carry it, maybe empty
    return_to = _return_to(access, data.get("return_to"))
    try:
        out = mail_send.send(db, access, mm, form)
    except LookupError:
        raise HTTPException(404, "mail_messages not found") from None
    except mail_send.SendError as e:
        db.rollback()
        if e.status == 403:
            raise HTTPException(403, str(e)) from None
        db.refresh(mm)
        return _render_preview(request, db, access, mm, error=str(e), status=e.status, return_to=return_to)
    _audit_outcome(db, access, out)
    _todo_changed(access.case.id)
    if guided and out.outcome != "already":
        return RedirectResponse(mail_flow.with_query(f"/cases/{access.case.id}/mail/messages/{mm.id}/sending",
                                                     return_to=return_to or None), status_code=303)
    return _after(access, mm, out.outcome)


def _todo_changed(case_id: int) -> None:
    """A send changes the To do list (its derived tasks re-derive on the next build): the tab bar's cached badge
    count of this case is dropped at once (app.web.routes_todo)."""
    try:
        from app.web import routes_todo

        routes_todo._forget(case_id)
    except Exception:  # noqa: BLE001 - a badge cache: never fails a send
        log.debug("to do badge cache not cleared")


SEND_STATES = {MailStatus.SENT: "sent", MailStatus.SENT_EXTERNAL: "sent", MailStatus.FAILED: "failed",
               MailStatus.UNKNOWN: "unknown", MailStatus.SENDING: "pending"}


def send_state(mm: MailMessage) -> str:
    """Where a send stands for the "Sending…" screen: pending (the transport has not answered), sent, failed,
    unknown (reconcile: Check the mailbox), or other (prepared, cancelled, expired: nothing is on its way)."""
    state = SEND_STATES.get(mm.status, "other")
    if state == "pending":
        at = mm.updated_at or mm.prepared_at
        at = at.replace(tzinfo=UTC) if at is not None and at.tzinfo is None else at
        if at is not None and datetime.now(tz=UTC) - at > mail_send.STUCK_SENDING:
            return "unknown"  # the process died mid-send: only a check of the mailbox tells
    return state


def _default_return(db: Session, access: CaseAccess, mm: MailMessage) -> str:
    """Where the flow ends without a `return_to`: the authority's page, else the letter, else the e-mail."""
    corr = db.get(Correspondence, mm.correspondence_id) if mm.correspondence_id else None
    authority = _authority_of(db, access, corr) if corr is not None else None
    if authority is not None:
        return f"/cases/{access.case.id}/authorities/{authority.key}"
    if corr is not None:
        return f"/cases/{access.case.id}/authorities/correspondence/{corr.id}"
    return f"/cases/{access.case.id}/mail/messages/{mm.id}"


@router.get("/cases/{case_id}/mail/messages/{mid}/status")
def message_send_status(mid: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                        db: Session = Depends(get_db)):
    """The "Sending…" screen's poll: the e-mail's state (read-only: no addresses, no body; nothing changes)."""
    mm = _message(db, access, mid)
    state = send_state(mm)
    return JSONResponse({"id": mm.id, "status": mm.status.value, "state": state, "done": state != "pending"},
                        headers={"Cache-Control": "no-store"})


@router.get("/cases/{case_id}/mail/messages/{mid}/sending", response_class=HTMLResponse)
def message_sending(request: Request, mid: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                    db: Session = Depends(get_db)):
    """The "Sending…" screen: an hourglass while js/mail.js polls …/status, then …/after-send."""
    mm = _message(db, access, mid)
    return_to = _return_to(access, request.query_params.get("return_to"))
    corr = db.get(Correspondence, mm.correspondence_id) if mm.correspondence_id else None
    authority = _authority_of(db, access, corr) if corr is not None else None
    base = f"/cases/{access.case.id}/mail/messages/{mm.id}"
    n_bcc, n_att = len(compose.bcc_of(mm)), len(mm.attachments or [])
    who = f"{len(mm.to_addrs or [])} To · {len(mm.cc_addrs or [])} Cc" + (f" · {n_bcc} Bcc" if n_bcc else "")
    state = send_state(mm)
    steps = [compose.ComposeStep(1, "recipients", "Recipients", "", "done", who),
             compose.ComposeStep(2, "letter", "Letter", "", "done", f"letter #{corr.id}" if corr else ""),
             compose.ComposeStep(3, "attachments", "Attachments", "", "done",
                                 f"{n_att} file{'s' if n_att != 1 else ''} attached"),
             compose.ComposeStep(4, "send", "Review & send", "", {"pending": "current", "sent": "done",
                                                                  "failed": "error", "unknown": "warn"}.get(state, "todo"),
                                 {"pending": "sending…", "sent": "sent", "failed": "not sent",
                                  "unknown": "not confirmed"}.get(state, "nothing on its way"))]
    return templates.TemplateResponse(request, "mail_sending.html", {
        "case": access.case, "access": access, "mm": mm, "corr": corr, "authority": authority, "steps": steps,
        "state": state, "status_url": f"{base}/status",
        "next_url": mail_flow.with_query(f"{base}/after-send", return_to=return_to or None),
        "return_to": return_to}, headers={"Cache-Control": "no-store"})


@router.get("/cases/{case_id}/mail/messages/{mid}/after-send")
def message_after_send(request: Request, mid: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                       db: Session = Depends(get_db)):
    """Where the "Sending…" screen goes once the mailbox answered (module doc). Never an open redirect: `return_to`
    is a path of this case's pages (mail_flow.safe_return), else the authority's page."""
    mm = _message(db, access, mid)
    return_to = _return_to(access, request.query_params.get("return_to"))
    state = send_state(mm)
    base = f"/cases/{access.case.id}/mail/messages/{mm.id}"
    if state == "sent":
        target = mail_flow.with_query(return_to or _default_return(db, access, mm), mail_sent=mm.id)
    elif state == "pending":
        target = mail_flow.with_query(f"{base}/sending", return_to=return_to or None)
    elif state == "failed" and mm.correspondence_id is not None and access.can("prepare_email") and (
            (corr := db.get(Correspondence, mm.correspondence_id)) is not None
            and corr.status == CorrespondenceStatus.DRAFT):
        target = mail_flow.with_query(f"/cases/{access.case.id}/authorities/correspondence/{corr.id}/email",
                                      send_failed=mm.id, return_to=return_to or None) + "#mail-error"
    else:  # unknown (check the mailbox there), or nothing on its way
        target = mail_flow.with_query(base, r=state if state in ("failed", "unknown") else None,
                                      return_to=return_to or None)
    return RedirectResponse(target, status_code=303)


@router.post("/cases/{case_id}/mail/messages/{mid}/reconcile", dependencies=_csrf, response_class=HTMLResponse)
def preview_reconcile(request: Request, mid: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                      db: Session = Depends(get_db)):
    mm = _message(db, access, mid)
    before = mm.status.value
    try:
        state = mail_send.reconcile(db, mm, access.user)
    except Exception as e:  # noqa: BLE001 - a transport problem is shown, never a 500
        db.rollback()
        db.refresh(mm)
        return _render_preview(request, db, access, mm, error=f"Could not check the mailbox: "
                               f"{mail_send._clean_error(str(e))}", status=502)
    audit(db, access, "MAIL_RECONCILED", access.case, mm, state=state or "none", before=before,
          after=mm.status.value, eml_evidence_id=mm.eml_evidence_id)
    return _after(access, mm, "reconciled")


@router.post("/cases/{case_id}/mail/messages/{mid}/finalize", dependencies=_csrf, response_class=HTMLResponse)
def preview_finalize(request: Request, mid: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                     db: Session = Depends(get_db)):
    mm = _message(db, access, mid)
    try:
        ok = mail_send.retry_filing(db, access, mm)
    except mail_send.SendError as e:
        return _render_preview(request, db, access, mm, error=str(e), status=e.status)
    audit(db, access, UPDATE, access.case, mm, fields=["eml_evidence_id", "meta.finalized"], filed=ok,
          eml_evidence_id=mm.eml_evidence_id)
    if not ok:
        return _render_preview(request, db, access, mm, error="Filing failed again: " +
                               str((mm.meta or {}).get("finalize_error") or "unknown error"), status=500)
    return _after(access, mm, "filed")


@router.post("/cases/{case_id}/mail/messages/{mid}/renew", dependencies=_csrf, response_class=HTMLResponse)
def preview_renew(request: Request, mid: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                  db: Session = Depends(get_db)):
    """Prepare an expired / failed / cancelled e-mail again (same recipients, subject, attachments)."""
    access.require("prepare_email")
    mm = _message(db, access, mid)
    if mm.correspondence_id is None:
        raise HTTPException(409, "this e-mail has no letter")
    corr, authority = _corr_for_mail(db, access, mm.correspondence_id)
    try:
        compose._check_draft(access, corr)
        new = compose.renew(db, access, mm, corr, authority)
    except LookupError:
        db.rollback()
        raise HTTPException(404, "attachment not found") from None
    except compose.ComposeError as e:
        db.rollback()
        if e.field in ("draft", "form", "checklist"):
            db.refresh(mm)
            return _render_preview(request, db, access, mm, error=str(e), status=409)
        return _render_compose(request, db, access, corr, authority, form=compose.renew_form(mm, access.case, corr),
                               error=e, status=400)
    _audit_prepared(db, access, corr, new, renewed_from=mm.id)
    return RedirectResponse(f"/cases/{access.case.id}/mail/messages/{new.id}", status_code=303)


@router.post("/cases/{case_id}/mail/messages/{mid}/edit", dependencies=_csrf, response_class=HTMLResponse)
def preview_edit(request: Request, mid: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                 db: Session = Depends(get_db), return_to: str = Form("")):
    """Back to the editor with every field as prepared; a prepared preview is cancelled (never sent)."""
    access.require("prepare_email")
    mm = _message(db, access, mid)
    if mm.correspondence_id is None:
        raise HTTPException(409, "this e-mail has no letter")
    corr, _authority = _corr_for_mail(db, access, mm.correspondence_id)
    try:
        cancelled = compose.reopen_for_edit(db, access, mm, corr)
    except LookupError:
        raise HTTPException(404, "mail_messages not found") from None
    except compose.ComposeError as e:
        db.rollback()
        if e.field == "forbidden":
            raise HTTPException(403, str(e)) from None
        db.refresh(mm)
        return _render_preview(request, db, access, mm, error=str(e), status=409)
    audit(db, access, UPDATE, access.case, corr, fields=["meta.mail_draft"], via="mail_edit", from_message=mm.id)
    if cancelled:
        audit(db, access, "MAIL_CANCELLED", access.case, mm, correspondence_id=corr.id, reason="edit")
    done = "edit" if cancelled else "edit_loaded"  # nothing was cancelled: expired, failed, cancelled, or a checklist
    dropped = mm.transport == "manual" and not compose.is_manual() and compose.mailbox_copied(mm)
    return RedirectResponse(f"/cases/{access.case.id}/authorities/correspondence/{corr.id}/email?done={done}"
                            f"{'&dropped=1' if dropped else ''}{_rt(_return_to(access, return_to))}#editor",
                            status_code=303)


SYNC_RETRY = {
    "too_soon": "Aegis read the mailbox a few seconds ago and reads its Sent Items again before an Outlook checklist is "
                "retired: press the button again in a few seconds.",
    "busy": "Aegis is reading the mailbox right now, and reads its Sent Items again before an Outlook checklist is "
            "retired: press the button again in a minute.",
}


def _inbound_on() -> bool:
    """Whether Aegis reads the case mailbox (AEGIS_MAIL_INBOUND): the retire panel says whether Sent Items is read."""
    try:
        from app.mail.config import mail_settings

        return bool(mail_settings().aegis_mail_inbound)
    except Exception:  # noqa: BLE001 - wording only
        return False


RETIRED_NOTICE = {"ok": "retired", "inbound_off": "retired_no_inbound", "no_sent_items": "retired_not_covered",
                  "before_cutover": "retired_not_covered"}  # else ("off", "error", "failed"): retired_unchecked


def _sync_sent_items_quietly(db: Session, access: CaseAccess, mm: MailMessage, *,
                             trigger: str = "retire_checklist") -> str:
    """Read the mailbox now (Inbox and Sent Items; its lease applies, and only the short "letter_check" floor of
    app.mail.ingest), so a letter sent from Outlook since the last scheduled sync is recorded, or listed for review,
    before its checklist `mm` is retired. Returns the result: "ok" (Sent Items was read, back to before `mm` was
    prepared: mail_compose.sent_items_coverage), "too_soon" / "busy" (the caller refuses: try again), or
    "inbound_off" / "off" / "error" / "failed" / "no_sent_items" / "before_cutover" (an Outlook send of `mm` may not
    have been seen: the caller warns the member)."""
    try:
        from app.mail import ingest
        from app.mail.config import mail_settings

        settings = mail_settings()
        if not settings.aegis_mail_inbound:
            return "inbound_off"
        report = ingest.sync_mailbox(db, trigger="letter_check", actor=access.user, settings=settings)
        flag = "too_soon" if report.too_soon else "busy" if report.busy else "off" if report.disabled else \
            "error" if report.error else compose.sent_items_coverage(db, report, mm)
        audit(db, access, "MAIL_SYNC", access.case, ("mail_sync_state", None), ok=flag == "ok",
              trigger=trigger, result=flag)
        return flag
    except Exception:  # noqa: BLE001 - the review check still applies; the member is warned
        db.rollback()
        log.warning("retire checklist: the mailbox sync before it failed")
        return "failed"


@router.post("/cases/{case_id}/mail/messages/{mid}/retire-checklist", dependencies=_csrf, response_class=HTMLResponse)
def preview_retire_checklist(request: Request, mid: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                             db: Session = Depends(get_db)):
    """"I did not send it from Outlook — retire it": an old manual-mode checklist once Aegis sends itself. Sent Items is
    read first; a message that may be it waiting for review refuses it (mail_compose.retire_checklist). Then back to
    the editor with the checklist's fields."""
    access.require("send_email")
    mm = _message(db, access, mid)
    if mm.correspondence_id is None:
        raise HTTPException(409, "this e-mail has no letter")
    corr, _authority = _corr_for_mail(db, access, mm.correspondence_id)
    if compose.is_manual() or not compose.is_open_checklist(mm):
        return _render_preview(request, db, access, mm, status=409, error=f"This e-mail is {mm.status.value}; only an "
                               "open Outlook checklist is retired, once Aegis sends e-mail itself.")
    if corr.status != CorrespondenceStatus.DRAFT or compose.letter_in_flight(db, corr) is not None:
        return _render_preview(request, db, access, mm, status=409, error="This letter was already sent or recorded "
                               "as sent; nothing was retired.")  # a stale tab: compose.retire_checklist refuses too
    flag = _sync_sent_items_quietly(db, access, mm)
    db.refresh(mm)
    db.refresh(corr)
    if flag in SYNC_RETRY:
        return _render_preview(request, db, access, mm, error=SYNC_RETRY[flag] + " Nothing was retired.", status=409)
    try:
        dropped = compose.retire_checklist(db, access, mm, corr)
    except LookupError:
        raise HTTPException(404, "mail_messages not found") from None
    except compose.OutlookSendWaiting as e:
        db.rollback()
        db.refresh(mm)
        return _render_preview(request, db, access, mm, error=str(e), status=409, suspected=e.seen)
    except compose.ComposeError as e:
        db.rollback()
        if e.field == "forbidden":
            raise HTTPException(403, str(e)) from None
        db.refresh(mm)
        return _render_preview(request, db, access, mm, error=str(e), status=409)
    audit(db, access, "MAIL_CANCELLED", access.case, mm, correspondence_id=corr.id, reason="retired_not_sent",
          sent_items=flag)
    done = RETIRED_NOTICE.get(flag, "retired_unchecked")
    return RedirectResponse(f"/cases/{access.case.id}/authorities/correspondence/{corr.id}/email?done={done}"
                            f"{'&dropped=1' if dropped else ''}#editor", status_code=303)


@router.post("/cases/{case_id}/mail/messages/{mid}/cancel", dependencies=_csrf, response_class=HTMLResponse)
def preview_cancel(request: Request, mid: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                   db: Session = Depends(get_db)):
    mm = _message(db, access, mid)
    try:
        mail_send.cancel(db, access, mm)
    except mail_send.SendError as e:
        if e.status == 403:
            raise HTTPException(403, str(e)) from None
        return _render_preview(request, db, access, mm, error=str(e), status=e.status)
    audit(db, access, "MAIL_CANCELLED", access.case, mm, correspondence_id=mm.correspondence_id)
    return _after(access, mm, "cancelled")


@router.post("/cases/{case_id}/evidence/{evidence_id}/mail-safe", dependencies=_csrf)
def evidence_mail_safe(evidence_id: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                       db: Session = Depends(get_db), safe: str = Form("1"), back: str = Form("")):
    """A case admin marks a file received by e-mail safe to attach to outgoing e-mail (or withdraws it)."""
    access.require("send_email")
    item = get_case_object(db, EvidenceItem, evidence_id, access)
    if not ev.can_see(access, item):
        raise HTTPException(404, "evidence item not found")
    try:
        compose.mark_mail_safe(db, access, item, safe=safe == "1")
    except compose.ComposeError as e:
        db.rollback()
        raise HTTPException(409, str(e)) from None
    audit(db, access, UPDATE, access.case, item, fields=["meta.mail_safe"], mail_safe=safe == "1")
    target = back if re.fullmatch(rf"/cases/{access.case.id}/authorities/correspondence/\d{{1,12}}/email", back) \
        else f"/cases/{access.case.id}/evidence/{item.id}"
    return RedirectResponse(target, status_code=303)


@router.get("/api/cases/{case_id}/mail/messages/{mid}")
def api_message_status(mid: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                       db: Session = Depends(get_db)):
    return mail_send.status_json(_message(db, access, mid))


# --------------------------------------------------------------------------- manual mode: send it yourself
def _ref(access: CaseAccess) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", access.case.reference)[:40]


def _download(data: bytes, name: str, media_type: str) -> Response:
    return Response(data, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff"})


def _manual_raw(db: Session, mm: MailMessage) -> bytes:
    try:
        return compose.verified_raw(mm, db)
    except (OSError, ev.EvidenceError):
        raise HTTPException(410, "the prepared message is no longer available") from None


@router.get("/cases/{case_id}/mail/messages/{mid}/draft.eml")
def manual_draft(mid: int, access: CaseAccess = Depends(require_case_role(ADMIN)), db: Session = Depends(get_db)):
    """The prepared e-mail as an editable Outlook / Apple Mail draft (X-Unsent: 1, no Date or Message-ID)."""
    access.require("send_email")
    mm = _message(db, access, mid)
    raw = _manual_raw(db, mm)
    if b"\nX-Unsent: 1" not in b"\n" + raw.split(b"\r\n\r\n", 1)[0].replace(b"\r\n", b"\n"):
        raise HTTPException(409, "this e-mail was not prepared as a draft to send yourself (manual mode)")
    audit(db, access, DOWNLOAD, access.case, mm, mode="draft_eml", size=len(raw), status=mm.status.value)
    return _download(raw, f"{_ref(access)}_draft-letter-{mm.correspondence_id or 0}-{mm.id}.eml", "message/rfc822")


@router.get("/cases/{case_id}/mail/messages/{mid}/attachments.zip")
def manual_attachments_zip(mid: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                           db: Session = Depends(get_db)):
    access.require("send_email")
    mm = _message(db, access, mid)
    parts = compose.attachment_parts(_manual_raw(db, mm))
    if not parts:
        raise HTTPException(404, "this e-mail has no attachments")
    data = compose.attachments_zip(parts)
    audit(db, access, DOWNLOAD, access.case, mm, mode="attachments_zip", n_attachments=len(parts), size=len(data),
          attachment_evidence_ids=[m["evidence_id"] for m in mm.attachments or [] if m.get("evidence_id")])
    return _download(data, f"{_ref(access)}_attachments-letter-{mm.correspondence_id or 0}-{mm.id}.zip", "application/zip")


@router.get("/cases/{case_id}/mail/messages/{mid}/attachments/{n}")
def manual_attachment(mid: int, n: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                      db: Session = Depends(get_db)):
    access.require("send_email")
    mm = _message(db, access, mid)
    parts = compose.attachment_parts(_manual_raw(db, mm))
    if not 1 <= n <= len(parts):
        raise HTTPException(404, "attachment not found")
    name, mime, data = parts[n - 1]
    manifest = (mm.attachments or [])[n - 1] if n - 1 < len(mm.attachments or []) else {}
    audit(db, access, DOWNLOAD, access.case, mm, mode="attachment", index=n, size=len(data),
          evidence_id=manifest.get("evidence_id"), kind=manifest.get("kind"))
    return _download(data, name, mime if re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", mime or "") else
                     "application/octet-stream")


@router.post("/cases/{case_id}/mail/messages/{mid}/record-sent", dependencies=_csrf, response_class=HTMLResponse)
async def manual_record_sent(request: Request, mid: int, access: CaseAccess = Depends(require_case_role(ADMIN)),
                             db: Session = Depends(get_db)):
    """A case admin records that the prepared e-mail went out from Outlook (manual mode)."""
    mm = _message(db, access, mid)
    data = await request.form()
    form = {"sent_at": str(data.get("sent_at") or ""), "to": str(data.get("to") or ""), "cc": str(data.get("cc") or ""),
            "due_days": data.get("due_days"), "confirm_external": str(data.get("confirm_external") or "")}
    upload = None
    f = data.get("sent_message")
    if f is not None and hasattr(f, "read") and (getattr(f, "filename", "") or ""):
        upload = (f.filename, await f.read(mail_send.SENT_UPLOAD_MAX + 1))
    try:
        out = mail_send.record_external(db, access, mm, form, upload)
    except LookupError:
        raise HTTPException(404, "mail_messages not found") from None
    except mail_send.SendError as e:
        db.rollback()
        if e.status == 403:
            raise HTTPException(403, str(e)) from None
        db.refresh(mm)
        return _render_preview(request, db, access, mm, error=str(e), status=e.status, record_form=form)
    except ev.EvidenceError as e:
        db.rollback()
        db.refresh(mm)
        return _render_preview(request, db, access, mm, error=f"The sent message could not be stored: {e}", status=400,
                               record_form=form)
    if out.outcome == "sent_external":
        corr = db.get(Correspondence, mm.correspondence_id) if mm.correspondence_id else None
        rec = (mm.meta or {}).get("sent_external") or {}
        audit(db, access, LETTER_SENT, access.case, corr if corr is not None else mm, via="email_external",
              transport=mm.transport, mail_message_id=mm.id, n_to=len(mm.to_addrs or []), n_cc=len(mm.cc_addrs or []),
              n_attachments=len(mm.attachments or []), recipient_domains=_domains([*(mm.to_addrs or []),
                                                                                  *(mm.cc_addrs or [])]),
              sent_evidence_id=rec.get("evidence_id"), upload=rec.get("upload"),
              recipients_changed=bool(rec.get("recipients_changed")), stop_order_id=corr.stop_order_id if corr else None,
              due_days=(mm.meta or {}).get("due_days"), step="record_sent")
        _todo_changed(access.case.id)
    return _after(access, mm, out.outcome)


# --------------------------------------------------------------------------- import a reply
@router.get("/cases/{case_id}/mail/import", response_class=HTMLResponse)
def import_page(request: Request, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                db: Session = Depends(get_db)):
    access.require("log_correspondence")
    return _render_import(request, db, access)


def _render_import(request: Request, db: Session, access: CaseAccess, *, error: str | None = None,
                   result: mail_import.ImportResult | None = None, status: int = 200) -> HTMLResponse:
    q = request.query_params
    shown = None
    if result is None and (q.get("imported") or "").isdigit():
        mm = db.get(MailMessage, int(q["imported"]))
        if mm is not None and mm.case_id == access.case.id and mm.direction == MailDirection.IN:
            shown = {"mm": mm, "duplicate": q.get("dup") == "1", "letter_id": (mm.match or {}).get("correspondence_id")}
    elif result is not None:
        shown = {"mm": result.mm, "duplicate": result.duplicate, "letter_id": result.letter_id}
    authorities = desk.case_authorities(db, access.case, include_prospects=False)
    return templates.TemplateResponse(request, "mail_import.html", {
        "case": access.case, "access": access, "error": error, "shown": shown,
        "authorities": [{"key": a.key, "name": a.name} for a in authorities],
        "selected": (q.get("authority") or "") if desk.KEY_RE.fullmatch(q.get("authority") or "") else "",
        "can_review": access.can("triage_mail"),
        "max_mb": int(getattr(mail_send._settings(), "max_inbound_bytes", 25 << 20)) // (1 << 20)},
        status_code=status)


@router.post("/cases/{case_id}/mail/import", dependencies=_csrf, response_class=HTMLResponse)
async def import_reply(request: Request, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                       db: Session = Depends(get_db)):
    """Upload a reply (.eml / .msg): parsed by the inbound pipeline, then it waits on Mail to review."""
    access.require("log_correspondence")
    data = await request.form()
    key = str(data.get("authority_key") or "").strip()
    authority = None
    if key:
        if not desk.KEY_RE.fullmatch(key):
            raise HTTPException(404, "authority not found")
        authority = _authority_or_404(db, access, key)
    f = data.get("reply")
    if f is None or not hasattr(f, "read") or not (getattr(f, "filename", "") or ""):
        return _render_import(request, db, access, error="Choose the reply file (.eml or .msg) to import.", status=400)
    limit = int(getattr(mail_send._settings(), "max_inbound_bytes", 25 << 20))
    blob = await f.read(limit + 1)
    try:
        res = mail_import.import_reply(db, access, f.filename, blob, authority=authority)
    except mail_import.MailImportError as e:
        db.rollback()
        return _render_import(request, db, access, error=str(e), status=400)
    except ev.EvidenceError as e:
        db.rollback()
        return _render_import(request, db, access, error=f"The reply could not be stored: {e}", status=400)
    if not res.duplicate:
        audit(db, access, "MAIL_IMPORTED", access.case, res.mm, mail_message_id=res.mm.id, method=res.method,
              status=res.mm.status.value, letter_id=res.letter_id, file_format=(res.mm.meta or {}).get("imported_from"),
              authority_key=authority.key if authority is not None else None,
              original_evidence_id=res.original_evidence_id, n_attachments=len(res.mm.attachments or []))
    from urllib.parse import urlencode

    query = urlencode({"imported": res.mm.id, "dup": "1" if res.duplicate else "0",
                       **({"authority": authority.key} if authority is not None else {})})
    return RedirectResponse(f"/cases/{access.case.id}/mail/import?{query}", status_code=303)
