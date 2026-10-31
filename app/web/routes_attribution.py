"""Wallet owners (app.attribution): who owns each wallet of the case, the explorer lookups and a person's attribution.

    GET  /api/cases/{id}/owners            read_only+    every wallet's owner, kind, confidence, evidence, who to ask
    POST /cases/{id}/owners/lookup         investigator  look up public explorer tags now (OWNER_LOOKUP audit)
    POST /cases/{id}/owners/settings       admin         "Owner lookups" on (with the consent tick) / off (UPDATE audit)
    POST /cases/{id}/owners/mark           investigator  a person's attribution, or withdraw it (CREATE audit)

The page is the Recovery plan's "Who owns these wallets" panel (recovery.html #owners). Nothing is sent to an explorer
unless a case admin turned the setting on for the case after seeing the hosts; the consent (with the hosts) is in the
audit row. Audit rows carry ids, counts, chains, kinds and hosts, never an owner's name, a note or an address.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.attribution import service as attr
from app.core.audit import CREATE, UPDATE, audit
from app.core.csrf import require_csrf
from app.core.permissions import ADMIN, INVESTIGATOR, READ_ONLY, CaseAccess, require_case_role
from app.core.security import require_user
from app.db.session import get_db
from app.web.routes_freeze import _back

router = APIRouter(tags=["owners"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]
OWNER_LOOKUP = "OWNER_LOOKUP"
REFUSED = {
    "case_setting_off": "Owner lookups are off for this case: a case admin can turn them on in the Recovery plan's "
                        "\"Who owns these wallets\" panel (nothing was sent).",
    "deployment_disabled": "Owner lookups are switched off for this deployment (nothing was sent).",
    "consent_outdated": "The explorer endpoints changed since a case admin consented: a case admin must confirm the "
                        "new endpoints first (nothing was sent).",
}


def _owners_url(case_id: int, next_url: str | None, done: str = "") -> str:
    back = _back(case_id, next_url or f"/cases/{case_id}/recovery-plan")
    if back.endswith("/freeze") and not next_url:
        back = f"/cases/{case_id}/recovery-plan"
    if done:
        back += ("&" if "?" in back else "?") + f"done={done}"
    return back + "#owners"


@router.get("/api/cases/{case_id}/owners")
def api_owners(access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db)):
    rows = [a.as_dict(access.can("view_restricted")) for a in attr.attribute(db, access.case).values()]
    return JSONResponse({"case": access.case.reference, "wallets": rows, "lookups": attr.status(access.case),
                         "advisory": "Aegis's attribution from the sources listed (a person's wins): advisory."})


@router.post("/cases/{case_id}/owners/lookup", dependencies=_csrf)
def lookup_now(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
               next_url: str = Form("", alias="next"), force: str = Form("")):
    access.require("poll_watch")
    case = access.case
    try:
        rep = attr.run_lookups(db, case, force=force in ("1", "on", "yes"))
    except attr.OwnerLookupsDisabled as exc:
        hosts = attr.new_hosts(case) if exc.reason == "consent_outdated" else None
        audit(db, access, OWNER_LOOKUP, case, ("wallet_attributions", None), outcome="denied", reason=exc.reason,
              **({"hosts": hosts} if hosts else {}))
        raise HTTPException(409, REFUSED.get(exc.reason, REFUSED["case_setting_off"])) from None
    audit(db, access, OWNER_LOOKUP, case, ("wallet_attributions", None), trigger="manual", **rep.counts())
    return RedirectResponse(_owners_url(case.id, next_url, "lookup"), status_code=303)


@router.post("/cases/{case_id}/owners/settings", dependencies=_csrf)
def update_setting(access: CaseAccess = Depends(require_case_role(ADMIN)), db: Session = Depends(get_db),
                   enabled: str = Form(""), consent: str = Form(""), hosts: str | None = Form(None)):
    access.require("manage_case")
    case = access.case
    on = enabled in ("1", "on", "true", "yes")
    if on and consent not in ("1", "on", "yes"):
        raise HTTPException(400, "To turn owner lookups on, confirm that the case's wallet addresses may be sent to "
                                 "the public explorers listed.")
    if on and hosts is None:  # consent is always to the endpoints the admin was shown
        raise HTTPException(400, "Turning owner lookups on needs the explorer endpoints the page showed: reload the "
                                 "page and confirm again.")
    shown = sorted({h.strip() for h in (hosts or "").split(",") if h.strip()})
    if on and shown != attr.consent_hosts(attr.egress_plan()):
        raise HTTPException(409, "The explorer endpoints changed while the page was open: reload and confirm again "
                                 "(nothing was consented).")
    st = attr.set_enabled(db, case, access.user, on)
    audit(db, access, UPDATE, case, ("cases", case.id), setting="owner_lookups", enabled=on, consent=on or None,
          hosts=list(st.get("hosts") or []) if on else None)
    return RedirectResponse(_owners_url(case.id, None, "enabled" if on else "disabled"), status_code=303)


@router.post("/cases/{case_id}/owners/mark", dependencies=_csrf)
def mark_owner(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
               chain: str = Form(...), address: str = Form(...), owner: str = Form(""), kind: str = Form("unknown"),
               note: str = Form(""), clear: str = Form(""), next_url: str = Form("", alias="next")):
    access.require("edit")
    try:
        row = attr.mark(db, access.case, access.user, chain=chain, address=address, owner=owner, kind=kind, note=note,
                        clear=clear in ("1", "on", "yes"))
    except ValueError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from None
    db.commit()
    audit(db, access, CREATE, access.case, row, chain=row.chain, kind=row.kind, cleared=bool((row.detail or {}).get(
        "cleared")) or None, has_owner=bool(row.owner), has_note=bool((row.detail or {}).get("note")))
    return RedirectResponse(_owners_url(access.case.id, next_url, "marked"), status_code=303)
