"""On-chain freeze detection (app.freeze): the case's freeze page, "Check freeze status now", the per-case
"On-chain freeze checks" setting and the watched wallets.

    GET  /cases/{id}/freeze                      read_only+   status, readings, watched wallets, setting
    POST /cases/{id}/freeze/check                investigator  run the checks now (FREEZE_CHECK audit)
    POST /cases/{id}/freeze/settings             admin         on (with the consent tick) / off (UPDATE audit)
    POST /cases/{id}/freeze/watch                investigator  add a wallet to watch (CREATE audit)
    POST /cases/{id}/freeze/watch/{wid}/remove   investigator  stop watching it (DELETE audit)
    GET  /api/cases/{id}/freeze                  read_only+   the same status as JSON

Nothing is sent to a public endpoint unless a case admin turned the setting on for the case; the
setting page lists what each endpoint receives before the admin consents, and the consent (with the
hosts) is in the audit row. Audit rows carry ids, counts, chains and hosts, never a wallet label, a
source note or a URL.

Wiring: `app.main` includes `router`. Importing this module also registers the Jinja global
`freeze_overview(case, access)` used by case/_freeze_overview.html on the Overview tab.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.attribution import service as attr
from app.core.audit import CREATE, DELETE, UPDATE, audit
from app.core.csrf import require_csrf
from app.core.permissions import (
    ADMIN,
    INVESTIGATOR,
    READ_ONLY,
    CaseAccess,
    get_case_object,
    require_case_role,
)
from app.core.security import require_user
from app.db.models import FreezeWatch
from app.db.session import SessionLocal, get_db
from app.freeze import native, service
from app.freeze.issuers import CHAIN_LABELS, CHAINS, CONTRACTS
from app.web.templating import templates

log = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]
FREEZE_CHECK = "FREEZE_CHECK"


def _back(case_id: int, next_url: str | None, anchor: str = "") -> str:
    """`next` when it is a page of this case (no dot segments: /cases/1/../../x resolves elsewhere), else
    the case's freeze page."""
    base = f"/cases/{case_id}"
    url = (next_url or "").split("#")[0]
    path = url.split("?")[0]
    if url and (url == base or url.startswith(base + "?") or url.startswith(base + "/")) \
            and "//" not in url and "\\" not in url and "%" not in path \
            and not any(seg in (".", "..") for seg in path.split("/")):
        return url + anchor
    return f"{base}/freeze{anchor}"


REFUSED = {
    "case_setting_off": "On-chain freeze checks are off for this case: a case admin can turn them on on the freeze "
                        "page (nothing was sent).",
    "deployment_disabled": "On-chain freeze checks are switched off for this deployment (nothing was sent).",
    "consent_outdated": "The endpoints the checks would use have changed since a case admin consented: a case admin "
                        "must confirm the new endpoints on the freeze page first (nothing was sent).",
    "run_in_progress": "A check of this case is already running (the scheduler or another member): wait for it to "
                       "finish, then reload (nothing more was sent).",
}


def _status_for(db: Session, access: CaseAccess) -> dict:
    st = service.case_status(db, access.case)
    if not access.can("view_restricted"):  # the source note (where a watched wallet came from) is R2
        for w in st["wallets"]:
            w["source_note"] = None
    attr.annotate_rows(db, access.case, st["wallets"], show_notes=access.can("view_restricted"))  # who owns each
    return st


# --------------------------------------------------------------------------- page
@router.get("/cases/{case_id}/freeze", response_class=HTMLResponse)
def freeze_page(request: Request, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                db: Session = Depends(get_db)):
    case = access.case
    ctx = {
        "case": case, "access": access, "st": _status_for(db, access), "plan": service.egress_plan(),
        "watched": service.watched(db, case), "native": native.view(db, case), "chains": [(c, CHAIN_LABELS.get(c, c)) for c in CHAINS],
        "tlps": service.TLP_CHOICES, "contracts": CONTRACTS, "can_check": access.can("poll_watch"),
        "can_watch": access.can("edit"), "can_manage": access.can("manage_case"),
        "show_notes": access.can("view_restricted"),
        "error": request.query_params.get("error"), "done": request.query_params.get("done"),
    }
    return templates.TemplateResponse(request, "case/_freeze_page.html", ctx)


@router.get("/api/cases/{case_id}/freeze")
def api_freeze(access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db)):
    st = _status_for(db, access)
    for k in ("enabled_at", "last_run_at"):
        st[k] = st[k].isoformat(timespec="seconds") if st[k] else None
    return JSONResponse(st)


# --------------------------------------------------------------------------- actions
@router.post("/cases/{case_id}/freeze/check", dependencies=_csrf)
def check_now(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
              next_url: str = Form("", alias="next")):
    access.require("poll_watch")
    case = access.case
    try:
        rep = service.run_checks(db, case, trigger="manual")
    except service.FreezeChecksDisabled as exc:
        hosts = service.new_hosts(service.setting_for(db, case)) if exc.reason == "consent_outdated" else None
        audit(db, access, FREEZE_CHECK, case, ("freeze_checks", None), outcome="denied", reason=exc.reason,
              **({"hosts": hosts} if hosts else {}))
        raise HTTPException(409, REFUSED.get(exc.reason, REFUSED["case_setting_off"])) from None
    audit(db, access, FREEZE_CHECK, case, ("freeze_checks", None), trigger="manual", **rep.counts())
    return RedirectResponse(_back(case.id, next_url, "#freeze"), status_code=303)


@router.post("/cases/{case_id}/freeze/settings", dependencies=_csrf)
def update_setting(access: CaseAccess = Depends(require_case_role(ADMIN)), db: Session = Depends(get_db),
                   enabled: str = Form(""), consent: str = Form("")):
    access.require("manage_case")
    case = access.case
    on = enabled in ("1", "on", "true", "yes")
    if on and consent not in ("1", "on", "yes"):
        raise HTTPException(400, "To turn on-chain freeze checks on, confirm that the case's wallet addresses "
                                 "may be sent to the public endpoints listed.")
    row = service.set_enabled(db, case, access.user, on)
    db.commit()
    audit(db, access, UPDATE, case, row, setting="onchain_freeze_checks", enabled=on, consent=on or None,
          hosts=list((row.consent or {}).get("hosts") or []) if on else None)
    return RedirectResponse(f"/cases/{case.id}/freeze?done={'enabled' if on else 'disabled'}#setting", status_code=303)


@router.post("/cases/{case_id}/freeze/watch", dependencies=_csrf)
def add_watch(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
              chain: str = Form(...), address: str = Form(...), label: str = Form(""), source_note: str = Form(""),
              tlp: str = Form(""), next_url: str = Form("", alias="next")):
    access.require("edit")
    try:
        row = service.add_watch(db, access.case, access.user, chain=chain, address=address, label=label,
                                source_note=source_note, tlp=tlp)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from None
    db.commit()
    audit(db, access, CREATE, access.case, row, chain=row.chain, tlp=row.tlp, has_label=bool(row.label),
          has_source_note=bool(row.source_note))
    if next_url:  # back to the page that proposed it (the Recovery plan, Block status), a page of this case only
        return RedirectResponse(_back(access.case.id, next_url), status_code=303)
    return RedirectResponse(f"/cases/{access.case.id}/freeze?done=watch#watched", status_code=303)


@router.post("/cases/{case_id}/freeze/watch/{watch_id}/remove", dependencies=_csrf)
def remove_watch(watch_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                 db: Session = Depends(get_db)):
    access.require("edit")
    row = get_case_object(db, FreezeWatch, watch_id, access)
    service.remove_watch(db, row, access.user)
    db.commit()
    audit(db, access, DELETE, access.case, row, chain=row.chain)
    return RedirectResponse(f"/cases/{access.case.id}/freeze?done=unwatch#watched", status_code=303)


# --------------------------------------------------------------------------- overview (Jinja global)
def freeze_overview(case, access) -> dict | None:
    """The Overview tab's on-chain freeze block (case/_freeze_overview.html). None on any failure, so
    the overview always renders."""
    try:
        from app.web.routes_recovery import overview_cards

        names = access.can("view_restricted")
        owners = overview_cards(case, access).get("owners")  # the Recovery plan card's attribution pass
        with SessionLocal() as db:
            st = service.case_status(db, case)
            if owners is not None:
                for w in st["wallets"]:
                    a = owners.get(attr.key_of(w["chain"], w["address"]))
                    w["owner"] = a.as_dict(False, names) if a is not None else None
            else:
                attr.annotate_rows(db, case, st["wallets"], show_names=names)
        return {**st, "can_check": access.can("poll_watch"), "can_manage": access.can("manage_case")}
    except Exception:
        log.exception("freeze overview failed for case %s", getattr(case, "id", None))
        return None


templates.env.globals["freeze_overview"] = freeze_overview
