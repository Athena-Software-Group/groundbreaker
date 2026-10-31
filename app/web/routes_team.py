"""Team tab (case members and roles), user administration and the audit log.

Owner: the team feature. Partial: templates/case/_tab_team.html; pages: templates/audit_log.html
and the /admin/users page (templates/admin_users.html); static: css/team.css, js/team.js.
Membership helpers: app.core.permissions.add_member / membership / effective_role.

    GET  /cases/{case_id}/team                               → 303 to the tab
    POST /cases/{case_id}/team/members                       add an existing user, or invite a new one
    POST /cases/{case_id}/team/members/{member_id}           change role / expiry
    POST /cases/{case_id}/team/members/{member_id}/remove
    GET  /cases/{case_id}/audit                              case audit log (view_audit: case admins)
    GET  /admin/users · POST /admin/users · POST /admin/users/{user_id}   (system admins)
    GET  /admin/audit                                        global audit log (system admins)
    GET/POST /api/cases/{case_id}/team · PATCH/DELETE /api/cases/{case_id}/team/{member_id}
    GET  /api/cases/{case_id}/audit

Rules: only case admins manage members (`manage_members`); the last admin of a case can be neither
removed, demoted nor time-boxed; only external members carry an expiry (default 30 days, at most
90, docs/identity-spec.md §7; extensions are audited). Case admins add existing, active accounts
only, and the answer is the same whether or not the address has an account (no account probing);
only system administrators create accounts from the invite form. An invited user gets a random
one-time password that is shown once in the response and never stored or logged. System administrators cannot lock themselves out (no
self-deactivation or self-demotion; the last active system admin stays).
"""

from __future__ import annotations

import secrets
from datetime import UTC, date, datetime, time, timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import CREATE, ROLE_GRANT, ROLE_REVOKE, UPDATE, audit, verify_chain
from app.core.csrf import require_csrf
from app.core.permissions import (
    ACTIONS,
    ADMIN,
    EXTERNAL,
    READ_ONLY,
    ROLE_ORDER,
    CaseAccess,
    add_member,
    as_role,
    get_case_object,
    require_case_role,
)
from app.core.security import (
    hash_password,
    normalise_email,
    require_system_admin,
    require_user,
    revoke_all_sessions,
)
from app.db.models import AuditEvent, Case, CaseMember, CaseRole, User
from app.db.session import get_db
from app.web.tabs import tab_context
from app.web.templating import templates

router = APIRouter(tags=["team"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]
_manage = require_case_role(ACTIONS["manage_members"])
_view_audit = require_case_role(ACTIONS["view_audit"])

ROLES: tuple[str, ...] = tuple(r.value for r in sorted(CaseRole, key=lambda r: -ROLE_ORDER[r]))
EXTERNAL_DEFAULT_DAYS = 30
EXTERNAL_MAX_DAYS = 90  # an external membership is time-boxed; longer needs a fresh grant
ONE_TIME_PASSWORD_BYTES = 12  # token_urlsafe(12) → 16 characters

TEAM_ERRORS = {
    "last_admin": "A case needs at least one admin: promote someone else first.",
    "bad_email": "That is not an e-mail address.",
    "need_name": "No account has this e-mail address yet: give a display name to invite them.",
    "already_member": "That user is already on the team; change their role in the list instead.",
    "bad_role": "Unknown role.",
    "bad_expiry": "The expiry must be a date in the future.",
    "expiry_too_far": f"External access is time-boxed: the expiry can be at most {EXTERNAL_MAX_DAYS} days ahead.",
    "inactive": "That account is deactivated; a system administrator can re-activate it.",
}
# the one answer a case admin gets for "add this address" (whether or not an account exists)
SUBMITTED = ("If an active account exists for that e-mail address, it now has access to this case. "
             "New accounts are created by a system administrator.")


class TeamError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _now() -> datetime:
    return datetime.now(tz=UTC)


def one_time_password() -> str:
    return secrets.token_urlsafe(ONE_TIME_PASSWORD_BYTES)


# --------------------------------------------------------------------------- team logic
def admin_count(db: Session, case: Case) -> int:
    now = _now()
    return sum(1 for m in db.scalars(select(CaseMember).where(CaseMember.case_id == case.id,
                                                              CaseMember.role == CaseRole.ADMIN))
               if m.expires_at is None or m.expires_at > now)


def _parse_expiry(value: str | date | datetime | None) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, date):
            dt = datetime.combine(value, time(23, 59, 59))
        elif len(value.strip()) == 10:
            dt = datetime.combine(date.fromisoformat(value.strip()), time(23, 59, 59))  # end of that day
        else:
            dt = datetime.fromisoformat(value.strip())
    except ValueError:
        raise TeamError("bad_expiry") from None
    dt = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    if dt <= _now():
        raise TeamError("bad_expiry")
    return dt


def _role(value: str) -> CaseRole:
    try:
        return as_role(value)
    except ValueError:
        raise TeamError("bad_role") from None


def _expiry_for(role: CaseRole, expires: datetime | None) -> datetime | None:
    """Only external members are time-boxed (default EXTERNAL_DEFAULT_DAYS, at most EXTERNAL_MAX_DAYS)."""
    if role != EXTERNAL:
        return None
    if expires is not None and expires > _now() + timedelta(days=EXTERNAL_MAX_DAYS, hours=24):
        raise TeamError("expiry_too_far")
    return expires or _now() + timedelta(days=EXTERNAL_DEFAULT_DAYS)


def may_invite_accounts(access: CaseAccess) -> bool:
    """Creating an account is system-level: only system administrators invite new addresses."""
    return bool(access.user.is_system_admin)


def add_or_invite(db: Session, access: CaseAccess, email: str, display_name: str, role: str,
                  expires_at: str | date | None) -> tuple[CaseMember | None, str | None]:
    """Add an existing user, or (system admins only) create one with a one-time password.
    Returns (member, password|None); (None, None) when a case admin named an address without an
    active account (the caller answers exactly as for a successful add). Audits and commits."""
    email = normalise_email(email or "")
    if "@" not in email or "." not in email.split("@")[-1] or len(email) > 255:
        raise TeamError("bad_email")
    new_role = _role(role)
    expires = _expiry_for(new_role, _parse_expiry(expires_at))
    user = db.scalar(select(User).where(User.email == email))
    password = None
    if not may_invite_accounts(access) and (user is None or not user.is_active):
        audit(db, access, ROLE_GRANT, access.case, ("case_members", None), outcome="denied", reason="not_added",
              role=new_role.value)
        return None, None
    if user is None:
        name = (display_name or "").strip()[:255]
        if not name:
            raise TeamError("need_name")
        password = one_time_password()
        user = User(email=email, display_name=name, password_hash=hash_password(password))
        db.add(user)
        db.flush()
        audit(db, access, CREATE, access.case, user, via="team_invite")
    elif not user.is_active:
        raise TeamError("inactive")
    elif db.scalar(select(CaseMember).where(CaseMember.case_id == access.case.id, CaseMember.user_id == user.id)):
        raise TeamError("already_member")
    m = add_member(db, access.case, user, new_role, added_by=access.user, expires_at=expires)
    audit(db, access, ROLE_GRANT, access.case, m, user_id=user.id, role=new_role.value, invited=password is not None,
          expires_at=expires)
    return m, password


def update_member(db: Session, access: CaseAccess, m: CaseMember, role: str,
                  expires_at: str | date | None) -> CaseMember:
    new_role = _role(role)
    expires = _expiry_for(new_role, _parse_expiry(expires_at))
    if m.role == ADMIN and new_role != ADMIN and admin_count(db, access.case) <= 1:
        raise TeamError("last_admin")
    old, old_expiry = m.role, m.expires_at
    m.role, m.expires_at = new_role, expires
    db.flush()
    extended = bool(expires and old_expiry and expires > old_expiry)
    audit(db, access, ROLE_GRANT if new_role != old else UPDATE, access.case, m, user_id=m.user_id,
          role=new_role.value, previous_role=old.value, expires_at=expires,
          previous_expires_at=old_expiry, extended=extended)
    return m


def remove_member(db: Session, access: CaseAccess, m: CaseMember) -> None:
    if m.role == ADMIN and admin_count(db, access.case) <= 1:
        raise TeamError("last_admin")
    ref = ("case_members", m.id)
    user_id, role = m.user_id, m.role.value
    db.delete(m)
    db.flush()
    audit(db, access, ROLE_REVOKE, access.case, ref, user_id=user_id, role=role)


# --------------------------------------------------------------------------- tab
@tab_context("team")
def team_tab(request: Request, db: Session, access: CaseAccess) -> dict:
    members = sorted(access.case.members, key=lambda m: (-ROLE_ORDER[m.role], m.user.display_name.lower()))
    ids = {m.added_by for m in members if m.added_by}
    added_by = {u.id: u for u in db.scalars(select(User).where(User.id.in_(ids or [-1])))}
    flash = getattr(request.state, "team_flash", None) or {}
    now = _now()
    return {
        "members": members, "added_by": added_by, "ROLES": ROLES, "admin_total": admin_count(db, access.case),
        "team_error": TEAM_ERRORS.get(request.query_params.get("team_error") or ""),
        "team_saved": request.query_params.get("team_saved") in ("added", "updated", "removed"),
        "team_submitted": SUBMITTED if request.query_params.get("team_saved") == "submitted" else None,
        "may_invite": may_invite_accounts(access), "external_max_days": EXTERNAL_MAX_DAYS,
        "max_external_expiry": (now + timedelta(days=EXTERNAL_MAX_DAYS)).date().isoformat(),
        "invited": flash.get("invited"), "one_time_password": flash.get("one_time_password"),
        "expired": {m.id for m in members if m.expires_at is not None and m.expires_at <= now},
        "default_external_expiry": (now + timedelta(days=EXTERNAL_DEFAULT_DAYS)).date().isoformat(),
        "today": now.date().isoformat(),
    }


@router.get("/cases/{case_id}/team")
def team_tab_page(case_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY))):
    return RedirectResponse(f"/cases/{case_id}?tab=team", status_code=303)


def _team_redirect(case_id: int, **q: str) -> RedirectResponse:
    qs = "".join(f"&{k}={v}" for k, v in q.items())
    return RedirectResponse(f"/cases/{case_id}?tab=team{qs}#team", status_code=303)


@router.post("/cases/{case_id}/team/members", dependencies=_csrf)
def team_add(request: Request, case_id: int, access: CaseAccess = Depends(_manage), db: Session = Depends(get_db),
             email: str = Form(""), display_name: str = Form(""), role: str = Form("investigator"),
             expires_at: str = Form("")):
    try:
        m, password = add_or_invite(db, access, email, display_name, role, expires_at)
    except TeamError as exc:
        db.rollback()
        return _team_redirect(case_id, team_error=exc.code)
    if not may_invite_accounts(access):
        return _team_redirect(case_id, team_saved="submitted")  # same answer, account or not
    if password is None:
        return _team_redirect(case_id, team_saved="added")
    # Show the one-time password once: rendered into this response only (never stored, never logged).
    from app.web.routes import case_detail

    request.state.team_flash = {"invited": m.user, "one_time_password": password}
    response = case_detail(request, tab="team", access=access, db=db)
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/cases/{case_id}/team/members/{member_id}", dependencies=_csrf)
def team_update(case_id: int, member_id: int, access: CaseAccess = Depends(_manage), db: Session = Depends(get_db),
                role: str = Form(...), expires_at: str = Form("")):
    m = get_case_object(db, CaseMember, member_id, access, shared_only=False)
    try:
        update_member(db, access, m, role, expires_at)
    except TeamError as exc:
        db.rollback()
        return _team_redirect(case_id, team_error=exc.code)
    return _team_redirect(case_id, team_saved="updated")


@router.post("/cases/{case_id}/team/members/{member_id}/remove", dependencies=_csrf)
def team_remove(case_id: int, member_id: int, access: CaseAccess = Depends(_manage), db: Session = Depends(get_db)):
    m = get_case_object(db, CaseMember, member_id, access, shared_only=False)
    try:
        remove_member(db, access, m)
    except TeamError as exc:
        db.rollback()
        return _team_redirect(case_id, team_error=exc.code)
    return _team_redirect(case_id, team_saved="removed")


# --------------------------------------------------------------------------- team API
class MemberIn(BaseModel):
    email: str
    display_name: str = ""
    role: str = "investigator"
    expires_at: datetime | None = None


class MemberPatch(BaseModel):
    role: str
    expires_at: datetime | None = None


def _member_json(m: CaseMember) -> dict:
    return {"id": m.id, "user_id": m.user_id, "display_name": m.user.display_name, "email": m.user.email,
            "role": m.role.value, "added_by": m.added_by, "added_at": m.added_at.isoformat() if m.added_at else None,
            "expires_at": m.expires_at.isoformat() if m.expires_at else None}


def _api_error(exc: TeamError) -> HTTPException:
    return HTTPException(409 if exc.code in ("last_admin", "already_member") else 422,
                         {"code": exc.code, "message": TEAM_ERRORS[exc.code]})


@router.get("/api/cases/{case_id}/team")
def api_team(case_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY))):
    return [_member_json(m) for m in sorted(access.case.members, key=lambda m: (-ROLE_ORDER[m.role], m.id))]


@router.post("/api/cases/{case_id}/team", status_code=201)
def api_team_add(case_id: int, body: MemberIn, response: Response, access: CaseAccess = Depends(_manage),
                 db: Session = Depends(get_db)):
    try:
        m, password = add_or_invite(db, access, body.email, body.display_name, body.role, body.expires_at)
    except TeamError as exc:
        db.rollback()
        raise _api_error(exc) from None
    if not may_invite_accounts(access):  # same answer, account or not (GET …/team lists the members)
        response.status_code = 202
        return {"status": "submitted", "message": SUBMITTED}
    out = _member_json(m)
    if password is not None:
        out["one_time_password"] = password  # shown once; not retrievable later
    return out


@router.patch("/api/cases/{case_id}/team/{member_id}")
def api_team_patch(case_id: int, member_id: int, body: MemberPatch, access: CaseAccess = Depends(_manage),
                   db: Session = Depends(get_db)):
    m = get_case_object(db, CaseMember, member_id, access, shared_only=False)
    try:
        update_member(db, access, m, body.role, body.expires_at)
    except TeamError as exc:
        db.rollback()
        raise _api_error(exc) from None
    return _member_json(m)


@router.delete("/api/cases/{case_id}/team/{member_id}", status_code=204)
def api_team_delete(case_id: int, member_id: int, access: CaseAccess = Depends(_manage),
                    db: Session = Depends(get_db)):
    m = get_case_object(db, CaseMember, member_id, access, shared_only=False)
    try:
        remove_member(db, access, m)
    except TeamError as exc:
        db.rollback()
        raise _api_error(exc) from None


# --------------------------------------------------------------------------- audit log
AUDIT_PAGE = 100


def _audit_query(case_id: int | None, *, action: str = "", outcome: str = "", actor: int | None = None,
                 object_type: str = "", since: str = "", until: str = ""):
    q = select(AuditEvent)
    if case_id is not None:
        q = q.where(AuditEvent.case_id == case_id)
    if action:
        q = q.where(AuditEvent.action == action.strip().upper()[:64])
    if outcome in ("allowed", "denied"):
        q = q.where(AuditEvent.outcome == outcome)
    if actor:
        q = q.where(AuditEvent.actor_user_id == actor)
    if object_type:
        q = q.where(AuditEvent.object_type == object_type.strip()[:64])
    for value, op in ((since, "ge"), (until, "lt")):
        if value:
            try:
                d = datetime.combine(date.fromisoformat(value), time(0), tzinfo=UTC)
            except ValueError:
                raise HTTPException(400, "dates are YYYY-MM-DD") from None
            q = q.where(AuditEvent.ts >= d) if op == "ge" else q.where(AuditEvent.ts < d + timedelta(days=1))
    return q


def _audit_context(db: Session, case: Case | None, filters: dict, page: int) -> dict:
    q = _audit_query(case.id if case else filters.get("case_id"), action=filters["action"],
                     outcome=filters["outcome"], actor=filters["actor"], object_type=filters["object_type"],
                     since=filters["since"], until=filters["until"])
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    page = max(page, 1)
    events = db.scalars(q.order_by(AuditEvent.id.desc()).offset((page - 1) * AUDIT_PAGE).limit(AUDIT_PAGE)).all()
    scope = select(AuditEvent.action).distinct()
    if case is not None:
        scope = scope.where(AuditEvent.case_id == case.id)
    actions = sorted(a for a in db.scalars(scope) if a)
    user_ids = {e.actor_user_id for e in events if e.actor_user_id}
    if case is not None:
        user_ids |= {m.user_id for m in case.members}
    users = {u.id: u for u in db.scalars(select(User).where(User.id.in_(user_ids or [-1])))}
    case_ids = {e.case_id for e in events if e.case_id}
    cases = {c.id: c for c in db.scalars(select(Case).where(Case.id.in_(case_ids or [-1])))}
    return {"events": events, "total": total, "page": page, "pages": max(1, -(-total // AUDIT_PAGE)),
            "actions": actions, "users": users, "cases": cases, "filters": filters, "chain_broken": verify_chain(db),
            "scope_case": case}


def _filters(action: str, outcome: str, actor: str, object_type: str, since: str, until: str) -> dict:
    return {"action": action, "outcome": outcome if outcome in ("allowed", "denied") else "",
            "actor": int(actor) if actor.isdigit() else None, "object_type": object_type, "since": since,
            "until": until}


@router.get("/cases/{case_id}/audit", response_class=HTMLResponse)
def case_audit(request: Request, case_id: int, access: CaseAccess = Depends(_view_audit), db: Session = Depends(get_db),
               action: str = "", outcome: str = "", actor: str = "", object_type: str = "", since: str = "",
               until: str = "", page: int = 1):
    filters = _filters(action, outcome, actor, object_type, since, until)
    ctx = _audit_context(db, access.case, filters, page)
    audit(db, access, "VIEW_AUDIT", access.case, page=ctx["page"], filters=sorted(k for k, v in filters.items() if v))
    return templates.TemplateResponse(request, "audit_log.html", ctx)


@router.get("/admin/audit", response_class=HTMLResponse)
def global_audit(request: Request, user: User = Depends(require_system_admin), db: Session = Depends(get_db),
                 action: str = "", outcome: str = "", actor: str = "", object_type: str = "", since: str = "",
                 until: str = "", case: str = "", page: int = 1):
    filters = _filters(action, outcome, actor, object_type, since, until)
    filters["case_id"] = int(case) if case.isdigit() else None
    ctx = _audit_context(db, None, filters, page)
    ctx["all_cases"] = db.scalars(select(Case).order_by(Case.id.desc())).all()
    audit(db, user, "VIEW_AUDIT", None, scope="global", page=ctx["page"],
          filters=sorted(k for k, v in filters.items() if v))
    return templates.TemplateResponse(request, "audit_log.html", ctx)


def _event_json(e: AuditEvent) -> dict:
    return {"id": e.id, "ts": e.ts.isoformat() if e.ts else None, "actor_user_id": e.actor_user_id,
            "case_id": e.case_id, "action": e.action, "object_type": e.object_type, "object_id": e.object_id,
            "outcome": e.outcome, "detail": e.detail, "request_id": e.request_id}


@router.get("/api/cases/{case_id}/audit")
def api_case_audit(case_id: int, access: CaseAccess = Depends(_view_audit), db: Session = Depends(get_db),
                   action: str = "", outcome: str = "", actor: str = "", object_type: str = "", since: str = "",
                   until: str = "", limit: int = 200):
    filters = _filters(action, outcome, actor, object_type, since, until)
    q = _audit_query(case_id, action=filters["action"], outcome=filters["outcome"], actor=filters["actor"],
                     object_type=filters["object_type"], since=since, until=until)
    events = db.scalars(q.order_by(AuditEvent.id.desc()).limit(max(1, min(limit, 1000)))).all()
    audit(db, access, "VIEW_AUDIT", access.case, via="api", count=len(events))
    return {"events": [_event_json(e) for e in events], "chain_broken_at": verify_chain(db)}


# --------------------------------------------------------------------------- user administration
ADMIN_USERS_ERRORS = {
    "bad_email": "That is not an e-mail address.",
    "exists": "An account with this e-mail address already exists.",
    "need_name": "A display name is required.",
    "self": "You cannot deactivate yourself or remove your own system-admin rights.",
    "last_sysadmin": "At least one active system administrator must remain.",
}

def _render_admin_users(request: Request, db: Session, me: User, **extra) -> HTMLResponse:
    users = db.scalars(select(User).order_by(User.is_active.desc(), User.display_name)).all()
    ctx = {"request": request, "users": users, "me_id": me.id,
           "error": ADMIN_USERS_ERRORS.get(request.query_params.get("error") or ""),
           "saved": request.query_params.get("saved") == "1", **extra}
    html = templates.get_template("admin_users.html").render(ctx)
    response = HTMLResponse(html)
    if extra.get("one_time_password"):
        response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, me: User = Depends(require_system_admin), db: Session = Depends(get_db)):
    return _render_admin_users(request, db, me)


@router.post("/admin/users", dependencies=_csrf)
def admin_users_create(request: Request, me: User = Depends(require_system_admin), db: Session = Depends(get_db),
                       email: str = Form(""), display_name: str = Form(""), system_admin: str = Form(""),
                       can_create_cases: str = Form("")):
    email = normalise_email(email)
    if "@" not in email or "." not in email.split("@")[-1] or len(email) > 255:
        return RedirectResponse("/admin/users?error=bad_email", status_code=303)
    if not display_name.strip():
        return RedirectResponse("/admin/users?error=need_name", status_code=303)
    if db.scalar(select(User).where(User.email == email)):
        return RedirectResponse("/admin/users?error=exists", status_code=303)
    password = one_time_password()
    user = User(email=email, display_name=display_name.strip()[:255], password_hash=hash_password(password),
                is_system_admin=system_admin == "on", can_create_cases=can_create_cases == "on", is_active=True)
    db.add(user)
    db.flush()
    audit(db, me, CREATE, None, user, via="admin_users", system_admin=user.is_system_admin,
          can_create_cases=user.can_create_cases)
    return _render_admin_users(request, db, me, one_time_password=password, otp_user=user)


@router.post("/admin/users/{user_id}", dependencies=_csrf)
def admin_users_update(request: Request, user_id: int, me: User = Depends(require_system_admin),
                       db: Session = Depends(get_db), display_name: str = Form(""), system_admin: str = Form(""),
                       is_active: str = Form(""), reset_password: str = Form(""), can_create_cases: str = Form("")):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    want_admin, want_active = system_admin == "on", is_active == "on"
    if user.id == me.id and (not want_admin or not want_active):
        return RedirectResponse("/admin/users?error=self", status_code=303)
    if user.is_system_admin and user.is_active and not (want_admin and want_active):
        others = db.scalar(select(func.count()).select_from(User).where(
            User.is_system_admin.is_(True), User.is_active.is_(True), User.id != user.id)) or 0
        if others == 0:
            return RedirectResponse("/admin/users?error=last_sysadmin", status_code=303)
    changed = []
    if display_name.strip() and display_name.strip()[:255] != user.display_name:
        user.display_name = display_name.strip()[:255]
        changed.append("display_name")
    if want_admin != user.is_system_admin:
        user.is_system_admin = want_admin
        changed.append("is_system_admin")
    if want_active != user.is_active:
        user.is_active = want_active
        changed.append("is_active")
    if (can_create_cases == "on") != user.can_create_cases:
        user.can_create_cases = can_create_cases == "on"
        changed.append("can_create_cases")
    password = None
    if reset_password == "on":
        password = one_time_password()
        user.password_hash = hash_password(password)
        changed.append("password")
    # a new password or a deactivation ends the user's sessions (not the admin's own current one)
    revoked = revoke_all_sessions(db, user) if (password or not user.is_active) and user.id != me.id else 0
    db.flush()
    audit(db, me, UPDATE, None, user, fields=changed, sessions_revoked=revoked, system_admin=user.is_system_admin,
          active=user.is_active)
    if password:
        return _render_admin_users(request, db, me, one_time_password=password, otp_user=user)
    return RedirectResponse("/admin/users?saved=1", status_code=303)
