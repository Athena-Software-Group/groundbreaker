"""Block status (app.blocks): what every authority answered to the blocks the case requested, and what
to do next.

    GET  /cases/{id}/blocks                       read_only+    the Block status page (filters in the query)
    GET  /cases/{id}/blocks/export.{md|csv|docx}  read_only+    the report (EXPORT audit)
    GET  /api/cases/{id}/blocks                   read_only+    the same rows as JSON
    POST /cases/{id}/blocks/refresh               investigator  classify the replies now (rules; AI when allowed); next= the Recovery plan
    POST /cases/{id}/blocks/{key}/confirm         investigator  confirm a status (a proposal); `apply` = case admin
    POST /cases/{id}/blocks/{key}/path            investigator  record a path step only a person knows (LE filed, …) / undo
    POST /cases/{id}/blocks/{c<id>}/outlook       investigator  an Outlook e-mail for review: action=tie (letter=c|o<id>) / dismiss
    POST /cases/{id}/blocks/ai-setting            admin         "AI reads mailbox replies" on (consent) / off

Every POST is a CSRF-protected web form and is audited with ids, enum values and counts only (never a
reply's text, a quote or an address). Nothing here sends mail.

Wiring: `app.main` includes `router`. Importing this module registers the Jinja globals
`block_status_card(case, access)` (the Overview card, blocks_card.html) and
`block_status_by_authority(case, access)` (the status column of the Authorities tab).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from decimal import Decimal

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.blocks import classify_ai, report
from app.blocks import status as bs
from app.core.audit import EXPORT, UPDATE, audit
from app.core.csrf import require_csrf
from app.core.permissions import ADMIN, INVESTIGATOR, READ_ONLY, CaseAccess, require_case_role
from app.core.security import require_user
from app.db.session import SessionLocal, get_db
from app.web.templating import templates

log = logging.getLogger(__name__)
router = APIRouter(tags=["blocks"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]
KEY_RE = re.compile(r"[oc]\d{1,12}")
FORMATS = ("md", "csv", "docx")
DONE_TEXT = {
    "refreshed": "Replies classified.", "enabled": "AI reading of mailbox replies is on for this case.",
    "disabled": "AI reading of mailbox replies is off for this case.",
}


def _filters(status: str | None, type_: str | None, overdue: str | None, review: str | None) -> dict:
    st = (status or "").strip()
    if st and st not in report.FILTERS and st not in bs.BLOCK_STATUSES:
        st = ""
    ty = (type_ or "").strip()
    return {"status": st or None, "authority_type": ty if re.fullmatch(r"[a-z_]{1,32}", ty) else None,
            "overdue": overdue in ("1", "on", "true"), "review": review in ("1", "on", "true")}


@router.get("/cases/{case_id}/blocks", response_class=HTMLResponse)
def blocks_page(request: Request, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                db: Session = Depends(get_db), status: str | None = None, type: str | None = None,
                overdue: str | None = None, review: str | None = None):
    f = _filters(status, type, overdue, review)
    view = report.page_view(db, access, **f)
    dest = classify_ai.destination()
    # what refresh() would do: no provider without a token, and the kill switch wins (display only)
    usable = dest["configured"] and not dest["kill_switch"]
    may, why = classify_ai.may_call(access.case, _provider_stub(dest) if usable else None)
    unavailable = None
    if dest["provider"] != "none" and not usable:
        unavailable = classify_ai.REASON_TEXT["disabled" if dest["kill_switch"] else "not_configured"]
    from app.web import tabs

    ctx = {"case": access.case, "access": access, "v": view, "dest": dest,
           # the case tab bar, as on the Recovery plan (Block status is its sub-tab)
           "tabs": [t for t in tabs.TABS if access.at_least(t.min_role)], "tab": "recovery",
           "ai_active": may, "ai_reason": classify_ai.REASON_TEXT.get(why) if why else None,
           "ai_unavailable": unavailable,
           "can_refresh": access.can("log_correspondence"), "can_manage": access.can("manage_case"),
           "show_quotes": access.can("view_restricted"),
           "done": DONE_TEXT.get(request.query_params.get("done") or ""), "msg": request.query_params.get("msg"),
           "query": {k: v for k, v in (("status", status), ("type", type), ("overdue", overdue), ("review", review)) if v}}
    return templates.TemplateResponse(request, "blocks.html", ctx)


class _provider_stub:
    """The configured provider's label and model, for the consent check only (never called)."""

    def __init__(self, dest: dict):
        self.label, self.model, self.name = dest["label"], dest["model"], dest["provider"]


@router.get("/cases/{case_id}/blocks/export.{fmt}")
def blocks_export(fmt: str, access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db),
                  status: str | None = None, type: str | None = None,
                  overdue: str | None = None, review: str | None = None):
    if fmt not in FORMATS:
        raise HTTPException(404, "unknown export format")
    access.require("export")
    f = _filters(status, type, overdue, review)
    body, media, filename = report.export(db, access, fmt, **f)
    audit(db, access, EXPORT, access.case, ("block_status", None), format=fmt, kind="block_status",
          status_filter=f["status"], quotes=access.can("view_restricted"))
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"',
                                                     "Cache-Control": "no-store"})


def _jsonable(v):
    if isinstance(v, datetime):
        return v.isoformat(timespec="seconds")
    if isinstance(v, Decimal):
        return str(v)
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


@router.get("/api/cases/{case_id}/blocks")
def api_blocks(access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db),
               status: str | None = None, type: str | None = None):
    view = report.page_view(db, access, **_filters(status, type, None, None))
    rows = []
    for r in view["rows"]:
        r = dict(r)
        r["replies"] = [{k: v for k, v in x.items() if k != "human"} for x in r["replies"]]
        r["last_reply"] = r["replies"][-1] if r["replies"] else None
        rows.append(r)
    return JSONResponse(_jsonable({"case": access.case.reference, "summary": view["summary"], "rows": rows,
                                   "ai_enabled": view["ai_enabled"], "disclaimer": view["disclaimer"]}))


# --------------------------------------------------------------------------- actions
@router.post("/cases/{case_id}/blocks/refresh", dependencies=_csrf)
def blocks_refresh(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
                   next_url: str = Form("", alias="next")):
    access.require("log_correspondence")
    rep = bs.refresh(db, access.case, actor=access)
    audit(db, access, UPDATE, access.case, ("block_status", None), op="classify_replies", **rep.counts())
    if next_url == f"/cases/{access.case.id}/recovery-plan":  # the Recovery plan's "Read new replies"
        return RedirectResponse(next_url, status_code=303)
    return RedirectResponse(f"/cases/{access.case.id}/blocks?done=refreshed", status_code=303)


@router.post("/cases/{case_id}/blocks/{key}/confirm", dependencies=_csrf)
def blocks_confirm(key: str, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                   db: Session = Depends(get_db), status: str = Form(...), reply_id: str = Form(""),
                   amount: str = Form(""), asset: str = Form(""), apply: str = Form(""), note: str = Form(""),
                   read_reply: str = Form(""), next_url: str = Form("", alias="next")):
    if not KEY_RE.fullmatch(key or ""):
        raise HTTPException(404, "request not found")
    want_apply = apply in ("1", "on", "yes", "true")
    rid = reply_id.strip()
    if rid and not rid.isdigit():
        raise HTTPException(400, "invalid reply id")
    if want_apply and not access.can("manage_case"):
        audit(db, access, UPDATE, access.case, ("block_status", key), outcome="denied", op="apply_status",
              reason="not_case_admin")
        raise HTTPException(403, "Only a case admin can apply a status to the stop order.")
    try:
        res = bs.confirm(db, access, key, status=status, reply_id=int(rid) if rid else None, amount=amount,
                         asset=asset, apply=want_apply, note=note, read_myself=read_reply in ("1", "on", "yes"))
    except bs.BlockError as exc:
        db.rollback()
        raise HTTPException(exc.status, exc.message) from None
    audit(db, access, UPDATE, access.case, ("block_status", key), op="confirm_status", status=res.status,
          applied=res.applied, proposal=res.proposal, stop_order_status=res.stop_order_status,
          reply_id=int(rid) if rid else None, has_amount=bool(amount.strip()), has_note=bool(note.strip()),
          read_myself=read_reply in ("1", "on", "yes") or None)
    back = f"/cases/{access.case.id}/blocks"
    if next_url == f"/cases/{access.case.id}":
        back = next_url
    return RedirectResponse(f"{back}?msg={'applied' if res.applied else 'proposed' if res.proposal else 'confirmed'}"
                            f"#{key}", status_code=303)


@router.post("/cases/{case_id}/blocks/{key}/path", dependencies=_csrf)
def blocks_path_step(key: str, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                     db: Session = Depends(get_db), step: str = Form(...), outcome: str = Form(""),
                     note: str = Form("")):
    if not KEY_RE.fullmatch(key or ""):
        raise HTTPException(404, "request not found")
    try:
        res = bs.confirm_step(db, access, key, step=step.strip(), outcome=outcome.strip() or None, note=note)
    except bs.BlockError as exc:
        db.rollback()
        raise HTTPException(exc.status, exc.message) from None
    audit(db, access, UPDATE, access.case, ("block_status", key), op="record_path_step", step=res["step"],
          outcome=res["outcome"], has_note=bool(note.strip()))
    return RedirectResponse(f"/cases/{access.case.id}/blocks?msg=step#{key}", status_code=303)


@router.post("/cases/{case_id}/blocks/{key}/outlook", dependencies=_csrf)
def blocks_outlook_review(key: str, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                          db: Session = Depends(get_db), action: str = Form(...), letter: str = Form("")):
    """A "Sent from Outlook — needs review" row (`c<entry id>`): tie it to the letter it carried (as Mark sent
    does: investigators+, `send_letter`) or dismiss it (app.mail.sync_outbound)."""
    from app.mail import sync_outbound

    access.require("send_letter")
    if not re.fullmatch(r"c\d{1,12}", key or "") or action not in ("tie", "dismiss"):
        raise HTTPException(404, "request not found")
    try:
        mm = sync_outbound.review_row_for_entry(db, access.case, int(key[1:]))
        if action == "dismiss":
            sync_outbound.dismiss(db, mm, actor=access)
            done = None
        else:
            done = sync_outbound.tie_to_letter(db, mm, letter, actor=access)
    except sync_outbound.ReviewError as exc:
        db.rollback()
        raise HTTPException(exc.status, exc.message) from None
    return RedirectResponse(f"/cases/{access.case.id}/blocks?msg={'tied' if done else 'dismissed'}"
                            f"{'#' + done if done else ''}", status_code=303)


@router.post("/cases/{case_id}/blocks/ai-setting", dependencies=_csrf)
def blocks_ai_setting(access: CaseAccess = Depends(require_case_role(ADMIN)), db: Session = Depends(get_db),
                      enabled: str = Form(""), consent: str = Form(""), destination: str = Form("")):
    access.require("manage_case")
    on = enabled in ("1", "on", "true", "yes")
    dest = classify_ai.destination()
    if on and destination.strip() and destination.strip() != dest["label"]:
        raise HTTPException(409, "The AI destination changed while the page was open: reload and confirm again.")
    try:
        st = classify_ai.set_enabled(db, access.case, access.user, on, consent=consent in ("1", "on", "yes"), dest=dest)
    except classify_ai.AISettingError as exc:
        db.rollback()
        audit(db, access, UPDATE, access.case, ("cases", access.case.id), outcome="denied", setting="mail_ai_replies",
              enabled=on, reason="no_consent" if dest["provider"] != "none" else "no_provider")
        raise HTTPException(400, str(exc)) from None
    audit(db, access, UPDATE, access.case, ("cases", access.case.id), setting="mail_ai_replies", enabled=on,
          consent=on or None, provider=st.get("provider") if on else None,
          confirmed_destination=st.get("destination") if on else None, model=st.get("model") if on else None)
    return RedirectResponse(f"/cases/{access.case.id}/blocks?done={'enabled' if on else 'disabled'}#ai-setting",
                            status_code=303)


# --------------------------------------------------------------------------- Jinja globals
def block_status_card(case, access) -> dict | None:
    """The Overview card (blocks_card.html): counts and the rows that need attention. None on failure. Shares one
    case_blocks pass with the Recovery plan card (routes_recovery.overview_cards, once per request)."""
    from app.web import routes_recovery

    return routes_recovery.overview_cards(case, access)["blocks"]


def card_from_rows(c, rows: list, access) -> dict:
    """The block status card's data from the case's rows (bs.case_blocks)."""
    s = bs.summary(rows)
    attention = [r for r in rows if r.kind != "onchain" and (
        r.needs_confirmation or r.needs_review or r.overdue or r.status in (
            "redirected", "delivery_failed", "le_process_required", "info_requested"))][:6]
    views = {r.key: report.row_view(r, access, c) for r in rows if r.kind not in ("onchain", "outlook")}
    mask_rows = []
    for r in attention:
        v = views.get(r.key) or report.row_view(r, access, c)
        mask_rows.append({k: v[k] for k in ("key", "authority", "request", "status_text", "tone",
                                            "needs_confirmation", "confirm_tag", "overdue", "days_waiting",
                                            "next_action", "source_text")})
    by: dict[tuple[str, bool], int] = {}
    for r in rows:
        if r.kind != "onchain" and not r.probable_copy:  # the chips count what the tiles count
            # a reply a person read and confirmed as unclear is no longer "Reply needs review"
            k = (r.status, r.status == "unclear" and r.source == "human")
            by[k] = by.get(k, 0) + 1
    chips = [(st, bs.UNCLEAR_CONFIRMED_LABEL if read else bs.LABELS[st],
              "neutral" if read else bs.TONES.get(st, "neutral"), n) for (st, read), n in
             sorted(by.items(), key=lambda kv: (bs.BLOCK_STATUSES.index(kv[0][0]), kv[0][1]))]
    # every request's status as Block status words it (bs.BlockRow.status_text), by request key ("o12"): the
    # Overview's Open stop orders table shows the same status, never the stop order's own record state
    status = {k: {"text": v["status_text"], "tone": v["tone"], "confirm_tag": v["confirm_tag"],
                  "overdue": v["overdue"]} for k, v in views.items()}
    return {"summary": s, "attention": mask_rows, "chips": chips, "status": status}


def block_status_by_authority(case, access) -> dict:
    """authority key -> [{key, kind, request, status_text, tone, needs_confirmation}] for the Authorities tab."""
    try:
        with SessionLocal() as db:
            from app.db.models import Case

            c = db.get(Case, case.id)
            out: dict[str, list[dict]] = {}
            for r in bs.case_blocks(db, c):
                if r.kind == "onchain":
                    continue
                v = report.row_view(r, access, c)
                out.setdefault(r.authority.key, []).append(
                    {"key": r.key, "kind": r.kind, "request": v["request"], "status_text": v["status_text"], "tone": v["tone"],
                     "needs_confirmation": v["needs_confirmation"], "confirm_tag": v["confirm_tag"],
                     "overdue": v["overdue"]})
            return out
    except Exception as err:  # noqa: BLE001
        log.warning("block status column failed for case %s (%s)", getattr(case, "id", None), type(err).__name__)
        return {}


templates.env.globals["block_status_card"] = block_status_card
templates.env.globals["block_status_by_authority"] = block_status_by_authority
