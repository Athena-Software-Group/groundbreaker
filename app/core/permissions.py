"""Case-level access control: one policy for every case-scoped route.

Default deny (docs/identity-spec.md §7). A user sees a case only through an unexpired
`case_members` row; system administrators see every case (as case admin). Roles, lowest first:

    external < read_only < investigator < admin

* `require_case_role(min_role)` is the route dependency. It reads `case_id` from the path, 404s
  for non-members (so case ids cannot be probed), 403s for members below `min_role`, and returns
  a `CaseAccess` (case, user, effective role, membership).
* `can(actor, case, action)` answers finer questions inside a route or template, from the
  `ACTIONS` table below. Unknown actions raise KeyError (fail closed, caught in tests).
* Objects addressed by their own id inside a case route (runs, stop orders, evidence, …) must be
  checked with `get_case_object(db, Model, obj_id, access)`, which 404s on another case's object.

External members (e.g. an LE liaison) see only items flagged `shared_with_external`; feature code
filters with `access.is_external`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, HTTPException, Request
from sqlalchemy import Select, or_, select
from sqlalchemy.orm import Session, object_session

from app.core.audit import audit
from app.core.security import require_user
from app.db.models import Case, CaseMember, CaseRole, User
from app.db.session import get_db

ROLE_ORDER: dict[CaseRole, int] = {
    CaseRole.EXTERNAL: 0,
    CaseRole.READ_ONLY: 1,
    CaseRole.INVESTIGATOR: 2,
    CaseRole.ADMIN: 3,
}

EXTERNAL, READ_ONLY, INVESTIGATOR, ADMIN = (CaseRole.EXTERNAL, CaseRole.READ_ONLY, CaseRole.INVESTIGATOR,
                                             CaseRole.ADMIN)

# action -> minimum role. Feature code may use any of these; add new actions here (one line each).
ACTIONS: dict[str, CaseRole] = {
    "view_shared": EXTERNAL,  # the case shell and items shared with externals
    "view": READ_ONLY,  # traces, graph, letters, correspondence, evidence metadata, team, notifications
    "export": READ_ONLY,  # .docx letters, reports (step-up later)
    "use_assistant": READ_ONLY,
    "edit": INVESTIGATOR,  # case facts, seeds
    "run_trace": INVESTIGATOR,
    "poll_watch": INVESTIGATOR,
    "draft_letter": INVESTIGATOR,
    "send_letter": INVESTIGATOR,  # four-eyes approval comes later
    "log_correspondence": INVESTIGATOR,
    "manage_le_contacts": INVESTIGATOR,
    "add_evidence": INVESTIGATOR,
    "verify_evidence": INVESTIGATOR,  # re-hash evidence bytes against the recorded sha256
    "annotate_run": INVESTIGATOR,  # label / notes on a trace run
    "ai_summarize": INVESTIGATOR,  # generate the assistant's case status summary
    "view_restricted": INVESTIGATOR,  # R3 content
    "share_external": ADMIN,
    "view_financial": ADMIN,  # the evidence Financial folder
    "view_source_path": ADMIN,  # where a referenced evidence original lives
    "delete_evidence": ADMIN,
    "declassify_evidence": ADMIN,  # lower an evidence item's classification (e.g. R3 -> R2)
    "manage_notifications": ADMIN,
    "manage_members": ADMIN,
    "manage_case": ADMIN,  # settings, ai_mode, close
    "view_audit": ADMIN,
    # e-mail desk (app.domain.mail_compose / mail_send, app.domain.directory, app.domain.sender)
    "prepare_email": INVESTIGATOR,  # build the e-mail preview of a draft letter
    "send_email": ADMIN,  # press Send (web form only; the assistant and the API never send)
    "manage_channels": ADMIN,  # add / verify / disable case-scoped contact channels
    "manage_sender_profile": ADMIN,  # the case's sender of record
    "triage_mail": ADMIN,  # accept / reject inbound mail suggested for the case
    "sync_mailbox": ADMIN,  # "Check mailbox now"
}


def as_role(role: CaseRole | str) -> CaseRole:
    return role if isinstance(role, CaseRole) else CaseRole(role)


def role_at_least(role: CaseRole | str | None, min_role: CaseRole | str) -> bool:
    return role is not None and ROLE_ORDER[as_role(role)] >= ROLE_ORDER[as_role(min_role)]


def _now() -> datetime:
    return datetime.now(tz=UTC)


def membership(db: Session, user: User, case: Case | int) -> CaseMember | None:
    """The user's unexpired membership of the case, if any."""
    case_id = case if isinstance(case, int) else case.id
    m = db.scalar(select(CaseMember).where(CaseMember.case_id == case_id, CaseMember.user_id == user.id))
    if m is None or (m.expires_at is not None and m.expires_at <= _now()):
        return None
    return m


def effective_role(db: Session, user: User | None, case: Case | int) -> CaseRole | None:
    if user is None or not user.is_active:
        return None
    if user.is_system_admin:
        return ADMIN
    m = membership(db, user, case)
    return m.role if m else None


def can(actor: User | CaseAccess | None, case: Case | None, action: str, db: Session | None = None) -> bool:
    """May `actor` do `action` on `case`? `actor` may be a CaseAccess (then `case` may be None)."""
    min_role = ACTIONS[action]
    if isinstance(actor, CaseAccess):
        return role_at_least(actor.role, min_role)
    if actor is None or case is None:
        return False
    db = db or object_session(case)
    return role_at_least(effective_role(db, actor, case), min_role)


def may_create_cases(user: User | None) -> bool:
    """A system-level permission, independent of any case role: system admins, and accounts a system
    admin granted `can_create_cases` (scripts/create_user.py --can-create-cases, /admin/users).
    The creator becomes the new case's admin, so this is never implied by a case membership."""
    return bool(user is not None and user.is_active and (user.is_system_admin or user.can_create_cases))


def visible_cases(user: User) -> Select:
    """SELECT of the cases the user may open (members only; system admins: all)."""
    q = select(Case)
    if not user.is_system_admin:
        now = _now()
        q = q.join(CaseMember, CaseMember.case_id == Case.id).where(
            CaseMember.user_id == user.id, or_(CaseMember.expires_at.is_(None), CaseMember.expires_at > now)
        )
    return q.order_by(Case.id.desc())


def add_member(db: Session, case: Case, user: User, role: CaseRole | str, *, added_by: User | None = None,
               expires_at: datetime | None = None) -> CaseMember:
    """Create or update a membership (caller audits and commits)."""
    role = as_role(role)
    m = db.scalar(select(CaseMember).where(CaseMember.case_id == case.id, CaseMember.user_id == user.id))
    if m is None:
        m = CaseMember(case=case, user=user, role=role, added_by=added_by.id if added_by else None,
                       expires_at=expires_at)
        db.add(m)
    else:
        m.role, m.expires_at = role, expires_at
    db.flush()
    return m


@dataclass
class CaseAccess:
    """What require_case_role hands the route: the case, who is asking and with which role."""

    case: Case
    user: User
    role: CaseRole
    member: CaseMember | None  # None for a system admin who is not a member

    @property
    def is_external(self) -> bool:
        return self.role == EXTERNAL

    def at_least(self, min_role: CaseRole | str) -> bool:
        return role_at_least(self.role, min_role)

    def can(self, action: str) -> bool:
        return role_at_least(self.role, ACTIONS[action])

    def require(self, action: str) -> None:
        """403 unless the role allows `action`."""
        if not self.can(action):
            raise HTTPException(403, f"your role on this case does not allow '{action}'")


def require_case_role(min_role: CaseRole | str = READ_ONLY):
    """Route dependency factory: `access: CaseAccess = Depends(require_case_role(INVESTIGATOR))`.

    The route must have a `case_id: int` path parameter."""
    min_role = as_role(min_role)

    def dependency(case_id: int, request: Request, user: User = Depends(require_user),
                   db: Session = Depends(get_db)) -> CaseAccess:
        case = db.get(Case, case_id)
        role = effective_role(db, user, case) if case else None
        if case is None or role is None:
            if case is not None:
                audit(db, user, "ACCESS_DENIED", case, outcome="denied", reason="not_a_member",
                      path=request.url.path)
            raise HTTPException(404, "case not found")
        if not role_at_least(role, min_role):
            audit(db, user, "ACCESS_DENIED", case, outcome="denied", reason="role", role=role.value,
                  required=min_role.value, method=request.method)
            raise HTTPException(403, f"this needs the {min_role.value} role on the case")
        access = CaseAccess(case=case, user=user, role=role, member=membership(db, user, case))
        request.state.case_access = access
        return access

    dependency.__name__ = f"require_case_role_{min_role.value}"
    return dependency


def get_case_object(db: Session, model: type, obj_id: Any, access: CaseAccess, *, shared_only: bool | None = None):
    """Load `model` by primary key and 404 unless it belongs to `access.case` (fixes raw-id IDOR).

    With shared_only (default: True for external members) an object that has a
    `shared_with_external` flag must have it set."""
    obj = db.get(model, obj_id)
    if obj is None or getattr(obj, "case_id", None) != access.case.id:
        raise HTTPException(404, f"{getattr(model, '__tablename__', 'object')} not found")
    if shared_only is None:
        shared_only = access.is_external
    if shared_only and not getattr(obj, "shared_with_external", False):
        raise HTTPException(404, f"{getattr(model, '__tablename__', 'object')} not found")
    return obj
