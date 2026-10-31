"""Notifications: the case rule editor and feed (tab), the personal inbox (/notifications) and the API.

Owner: the notifications feature (it also owns the body of app.core.events.emit, which hands over
to app.domain.notify). Partial: templates/case/_tab_notifications.html; inbox page:
templates/notifications_inbox.html; static: css/team.css, js/team.js (shared with the team feature).

    GET  /cases/{case_id}/notifications                      → 303 to the tab
    POST /cases/{case_id}/notifications/rules/{event_type}   rule editor (manage_notifications)
    POST /cases/{case_id}/notifications/rules/reset          back to the built-in defaults
    POST /cases/{case_id}/notifications/{nid}/read           mark one read (for the signed-in user)
    POST /cases/{case_id}/notifications/read-all
    GET  /notifications                                      inbox (?unread=1)
    POST /notifications/{nid}/read · POST /notifications/read-all
    GET  /notifications/unread-count                         {"unread": n} for the header badge
    GET  /api/cases/{case_id}/notifications                  latest 100 for the case
    GET  /api/cases/{case_id}/notifications/rules            effective rules
    PUT  /api/cases/{case_id}/notifications/rules/{event_type}

The header badge: the Jinja global `inbox_unread()` (registered below) returns the signed-in
user's unread count; js/team.js also fills / inserts the badge from /notifications/unread-count.
"""

from __future__ import annotations

from decimal import Decimal

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import pass_context
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import UPDATE, audit
from app.core.csrf import require_csrf
from app.core.events import EVENT_TYPES
from app.core.permissions import ACTIONS, READ_ONLY, CaseAccess, get_case_object, require_case_role
from app.core.security import require_user
from app.db.models import Case, Notification, NotificationRule, User
from app.db.session import SessionLocal, get_db
from app.domain import notify
from app.web.tabs import tab_context
from app.web.templating import templates

router = APIRouter(tags=["notifications"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]
_manage = require_case_role(ACTIONS["manage_notifications"])


# --------------------------------------------------------------------------- header badge
@pass_context
def inbox_unread(ctx) -> int:
    """Jinja global: the signed-in user's unread notification count (0 when signed out)."""
    request = ctx.get("request")
    user = getattr(request.state, "user", None) if request is not None else None
    if user is None:
        return 0
    try:
        with SessionLocal() as db:
            return notify.unread_count(db, user)
    except Exception:  # noqa: BLE001 - a badge must never break a page
        return 0


templates.env.globals["inbox_unread"] = inbox_unread


# --------------------------------------------------------------------------- tab
RULE_ERRORS = {"amount": "Min USD must be a non-negative amount.",
               "pct": "Min % of loss must be between 0 and 100.",
               "days": "Overdue days must be a whole number between 1 and 365."}


@tab_context("notifications")
def notifications_tab(request: Request, db: Session, access: CaseAccess) -> dict:
    cid = access.case.id
    notes = db.scalars(select(Notification).where(Notification.case_id == cid)
                       .order_by(Notification.id.desc()).limit(50)).all()
    saved = request.query_params.get("saved")
    return {
        "notifications": notes,
        "rules": notify.effective_rules(db, access.case),
        "read_ids": {n.id for n in notes if notify.is_read(n, access.user)},
        "channel_status": notify.channel_status(),
        "CHANNELS": notify.CHANNELS, "RECIPIENT_ROLES": notify.RECIPIENT_ROLES,
        "AMOUNT_EVENTS": notify.AMOUNT_EVENTS, "EVENT_LABELS": notify.EVENT_LABELS,
        "RESPONSE_OVERDUE": "response_overdue",
        "saved": saved if saved in EVENT_TYPES or saved == "defaults" else None,
        "rule_error": RULE_ERRORS.get(request.query_params.get("rule_error") or ""),
    }


@router.get("/cases/{case_id}/notifications")
def notifications_tab_page(case_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY))):
    return RedirectResponse(f"/cases/{case_id}?tab=notifications", status_code=303)


# --------------------------------------------------------------------------- rule editing
def _case_rule_row(db: Session, case: Case, event_type: str, user: User) -> NotificationRule:
    row = db.scalar(select(NotificationRule).where(NotificationRule.case_id == case.id,
                                                  NotificationRule.event_type == event_type)
                    .order_by(NotificationRule.id).limit(1))
    if row is None:
        row = NotificationRule(case_id=case.id, event_type=event_type, created_by=user.id)
        db.add(row)
    return row


def _spec(event_type: str, enabled: bool, min_usd, min_pct, days, channels, roles) -> notify.RuleSpec:
    """Validated RuleSpec from form / JSON values (ValueError names the bad field)."""
    try:
        usd = notify.parse_usd(min_usd)
    except ValueError:
        raise ValueError("amount") from None
    pct = None
    if min_pct not in (None, ""):
        try:
            pct = float(str(min_pct).replace("%", "").strip())
        except ValueError:
            raise ValueError("pct") from None
        if not 0 <= pct <= 100:
            raise ValueError("pct")
    n_days = None
    if days not in (None, ""):
        try:
            n_days = int(str(days).strip())
        except ValueError:
            raise ValueError("days") from None
        if not 1 <= n_days <= 365:
            raise ValueError("days")
    return notify.RuleSpec(event_type=event_type, enabled=enabled, min_usd=usd, min_pct_of_loss=pct,
                           channels=notify.normalise_channels(channels or []),
                           recipient_roles=notify.normalise_roles(roles or []), overdue_days=n_days)


def _save_rule(db: Session, access: CaseAccess, spec: notify.RuleSpec) -> NotificationRule:
    row = _case_rule_row(db, access.case, spec.event_type, access.user)
    notify.apply_rule_values(row, spec)
    db.flush()
    audit(db, access, UPDATE, access.case, row, event_type=spec.event_type, enabled=spec.enabled,
          min_usd=spec.min_usd, min_pct_of_loss=spec.min_pct_of_loss, overdue_days=spec.overdue_days,
          channels=row.channels, recipient_roles=row.recipient_roles)
    return row


@router.post("/cases/{case_id}/notifications/rules/reset", dependencies=_csrf)
def reset_rules(case_id: int, access: CaseAccess = Depends(_manage), db: Session = Depends(get_db)):
    n = notify.seed_default_rules(db, access.case, created_by=access.user, overwrite=True)
    audit(db, access, UPDATE, access.case, ("notification_rules", None), reset="defaults", rules=n)
    return RedirectResponse(f"/cases/{case_id}?tab=notifications&saved=defaults", status_code=303)


@router.post("/cases/{case_id}/notifications/rules/{event_type}", dependencies=_csrf)
def save_rule(case_id: int, event_type: str, access: CaseAccess = Depends(_manage), db: Session = Depends(get_db),
              enabled: str = Form(""), min_usd: str = Form(""), min_pct_of_loss: str = Form(""),
              overdue_days: str = Form(""), channels: list[str] = Form([]), recipient_roles: list[str] = Form([])):
    if event_type not in EVENT_TYPES:
        raise HTTPException(404, "unknown event type")
    try:
        spec = _spec(event_type, enabled in ("on", "true", "1"), min_usd, min_pct_of_loss, overdue_days, channels,
                     recipient_roles)
    except ValueError as exc:
        return RedirectResponse(f"/cases/{case_id}?tab=notifications&rule_error={exc}#rule-{event_type}",
                                status_code=303)
    _save_rule(db, access, spec)
    return RedirectResponse(f"/cases/{case_id}?tab=notifications&saved={event_type}#rule-{event_type}",
                            status_code=303)


# --------------------------------------------------------------------------- read state (case)
@router.post("/cases/{case_id}/notifications/read-all", dependencies=_csrf)
def case_read_all(case_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                  db: Session = Depends(get_db)):
    n = 0
    for note in db.scalars(select(Notification).where(Notification.case_id == case_id)):
        n += notify.mark_read(db, note, access.user)
    audit(db, access, UPDATE, access.case, ("notifications", None), read=n)
    return RedirectResponse(f"/cases/{case_id}?tab=notifications", status_code=303)


@router.post("/cases/{case_id}/notifications/{nid}/read", dependencies=_csrf)
def case_read_one(case_id: int, nid: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                  db: Session = Depends(get_db)):
    note = get_case_object(db, Notification, nid, access, shared_only=False)
    if notify.mark_read(db, note, access.user):
        audit(db, access, UPDATE, access.case, note, read=1)
    return RedirectResponse(f"/cases/{case_id}?tab=notifications", status_code=303)


# --------------------------------------------------------------------------- inbox
def _inbox_note(db: Session, user: User, nid: int) -> Notification:
    note = db.get(Notification, nid)
    if note is None or not notify.visible_to(note, user, notify._roles_by_case(db, user)):
        raise HTTPException(404, "notification not found")
    return note


@router.get("/notifications", response_class=HTMLResponse)
def inbox_page(request: Request, unread: int = 0, user: User = Depends(require_user), db: Session = Depends(get_db)):
    notes = notify.inbox(db, user, unread_only=bool(unread), limit=200)
    case_ids = {n.case_id for n in notes if n.case_id is not None}
    cases = {c.id: c for c in db.scalars(select(Case).where(Case.id.in_(case_ids or [-1])))}
    return templates.TemplateResponse(request, "notifications_inbox.html", {
        "notes": notes, "cases": cases, "unread_only": bool(unread),
        "read_ids": {n.id for n in notes if notify.is_read(n, user)}, "unread_total": notify.unread_count(db, user),
        "EVENT_LABELS": notify.EVENT_LABELS,
    })


@router.get("/notifications/unread-count")
def inbox_unread_count(user: User = Depends(require_user), db: Session = Depends(get_db)):
    return JSONResponse({"unread": notify.unread_count(db, user)}, headers={"Cache-Control": "no-store"})


@router.post("/notifications/read-all", dependencies=_csrf)
def inbox_read_all(user: User = Depends(require_user), db: Session = Depends(get_db)):
    n = 0
    for note in notify.inbox(db, user, unread_only=True, limit=500):
        n += notify.mark_read(db, note, user)
    audit(db, user, UPDATE, None, ("notifications", None), read=n)
    return RedirectResponse("/notifications", status_code=303)


@router.post("/notifications/{nid}/read", dependencies=_csrf)
def inbox_read_one(nid: int, next: str = Form(""), user: User = Depends(require_user), db: Session = Depends(get_db)):
    note = _inbox_note(db, user, nid)
    if notify.mark_read(db, note, user):
        audit(db, user, UPDATE, note.case_id, note, read=1)
    # "open": go to the event's link; only app-relative targets are followed
    target = note.link if next == "link" and note.link and note.link.startswith("/") and not note.link.startswith(
        "//") else "/notifications"
    return RedirectResponse(target, status_code=303)


# --------------------------------------------------------------------------- API
def _note_json(n: Notification, user: User) -> dict:
    return {"id": n.id, "case_id": n.case_id, "event_type": n.event_type, "severity": n.severity, "title": n.title,
            "body": n.body, "link": n.link, "usd": str(n.usd) if n.usd is not None else None,
            "created_at": n.created_at.isoformat() if n.created_at else None, "read": notify.is_read(n, user),
            "deliveries": [{k: d.get(k) for k in ("channel", "status", "at", "recipients", "error")}
                           for d in (n.deliveries or [])]}


def _rule_json(r: notify.RuleSpec) -> dict:
    return {"event_type": r.event_type, "label": r.label, "enabled": r.enabled,
            "min_usd": str(r.min_usd) if r.min_usd is not None else None, "min_pct_of_loss": r.min_pct_of_loss,
            "overdue_days": r.overdue_days, "channels": r.channels, "recipient_roles": r.recipient_roles,
            "source": r.source}


class RuleIn(BaseModel):
    enabled: bool = True
    min_usd: Decimal | None = Field(default=None, ge=0)
    min_pct_of_loss: float | None = Field(default=None, ge=0, le=100)
    overdue_days: int | None = Field(default=None, ge=1, le=365)
    channels: list[str] = Field(default_factory=lambda: ["in_app"])
    recipient_roles: list[str] = Field(default_factory=lambda: ["admin", "investigator"])


@router.get("/api/cases/{case_id}/notifications")
def api_notifications(case_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                      db: Session = Depends(get_db)):
    notes = db.scalars(select(Notification).where(Notification.case_id == case_id)
                       .order_by(Notification.id.desc()).limit(100))
    return [_note_json(n, access.user) for n in notes]


@router.get("/api/cases/{case_id}/notifications/rules")
def api_rules(case_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
              db: Session = Depends(get_db)):
    return {"rules": [_rule_json(r) for r in notify.effective_rules(db, access.case)],
            "channels_configured": notify.channel_status()}


@router.put("/api/cases/{case_id}/notifications/rules/{event_type}")
def api_put_rule(case_id: int, event_type: str, body: RuleIn, access: CaseAccess = Depends(_manage),
                 db: Session = Depends(get_db)):
    if event_type not in EVENT_TYPES:
        raise HTTPException(404, "unknown event type")
    bad = [c for c in body.channels if c not in notify.CHANNELS] + [
        r for r in body.recipient_roles if r not in notify.RECIPIENT_ROLES]
    if bad:
        raise HTTPException(422, f"unknown channel or recipient role: {', '.join(bad)[:100]}")
    spec = _spec(event_type, body.enabled, body.min_usd, body.min_pct_of_loss, body.overdue_days, body.channels,
                 body.recipient_roles)
    _save_rule(db, access, spec)
    return _rule_json(notify.effective_rule(db, access.case, event_type))
