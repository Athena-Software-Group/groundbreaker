"""Sign-in / sign-out pages (per-user accounts; see app.core.security)."""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import LOGIN, LOGIN_FAILED, LOGOUT, audit
from app.core.config import get_settings
from app.core.csrf import require_csrf
from app.core.security import (
    authenticate,
    client_ip,
    email_fingerprint,
    end_session,
    login_limiter,
    normalise_email,
    optional_user,
    start_session,
)
from app.db.models import User
from app.db.session import get_db
from app.web.templating import templates

router = APIRouter(tags=["auth"])


def safe_next(target: str | None) -> str:
    """Only same-site absolute paths: no scheme, host or protocol-relative '//'."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return "/"
    return target


def _login_page(request: Request, db: Session, *, next_url: str, error: str | None = None, email: str = "",
                status_code: int = 200):
    no_users = not db.scalar(select(func.count()).select_from(User))
    return templates.TemplateResponse(request, "login.html", {
        "next": next_url, "error": error, "email": email, "no_users": no_users,
    }, status_code=status_code)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/", user: User | None = Depends(optional_user),
               db: Session = Depends(get_db)):
    if user is not None:
        return RedirectResponse(safe_next(next), status_code=303)
    return _login_page(request, db, next_url=safe_next(next))


@router.post("/login", dependencies=[Depends(require_csrf)])
def login(request: Request, db: Session = Depends(get_db), email: str = Form(...), password: str = Form(...),
          next: str = Form("/")):
    ip = client_ip(request)
    target = safe_next(next)
    wait = login_limiter.retry_after(email, ip)
    if wait:
        audit(db, None, LOGIN_FAILED, outcome="denied", reason="rate_limited", email_fp=email_fingerprint(email))
        resp = _login_page(request, db, next_url=target, email=email, status_code=429,
                           error=f"Too many failed sign-in attempts. Try again in {wait // 60 + 1} minutes.")
        resp.headers["Retry-After"] = str(wait)
        return resp
    user = authenticate(db, email, password)
    if user is None:
        login_limiter.failed(email, ip)
        audit(db, None, LOGIN_FAILED, outcome="denied", reason="bad_credentials", email_fp=email_fingerprint(email))
        return _login_page(request, db, next_url=target, email=email, status_code=401,
                           error="E-mail or password is wrong, or the account is disabled.")
    login_limiter.succeeded(email, ip)
    start_session(db, request, user)
    audit(db, user, LOGIN, auth_method="password")  # commits the new session row too
    return RedirectResponse(target, status_code=303)


@router.post("/logout", dependencies=[Depends(require_csrf)])
def logout(request: Request, user: User | None = Depends(optional_user), db: Session = Depends(get_db)):
    end_session(db, request)
    if user is not None:
        audit(db, user, LOGOUT)
    else:
        db.commit()
    return RedirectResponse("/login", status_code=303)


# --------------------------------------------------------------------------- dev-only sign-in
DEV_TOKEN_MIN_LEN = 32
_dev_logins_used: set[str] = set()  # e-mails signed in with the dev token by this process


def dev_login_enabled() -> bool:
    """Only with APP_ENV=local AND AEGIS_DEV_LOGIN_TOKEN set to a long token (never by default)."""
    s = get_settings()
    return s.is_local and len(s.aegis_dev_login_token.strip()) >= DEV_TOKEN_MIN_LEN


@router.get("/dev/login", include_in_schema=False)
def dev_login(request: Request, token: str = "", email: str = "", next: str = "/", db: Session = Depends(get_db)):
    """One-time sign-in link for headless screenshots and local demos: each e-mail can use the token
    once per server process. 404 unless dev_login_enabled(); every use is audited."""
    if not dev_login_enabled():
        raise HTTPException(404)
    expected = get_settings().aegis_dev_login_token.strip()
    addr = normalise_email(email)
    user = db.scalar(select(User).where(User.email == addr)) if addr else None
    if (not hmac.compare_digest(token.encode(), expected.encode()) or user is None or not user.is_active
            or addr in _dev_logins_used):
        audit(db, None, LOGIN_FAILED, outcome="denied", reason="dev_token", email_fp=email_fingerprint(email))
        raise HTTPException(404)
    _dev_logins_used.add(addr)
    start_session(db, request, user, auth_method="dev_token")
    audit(db, user, LOGIN, auth_method="dev_token")
    return RedirectResponse(safe_next(next), status_code=303)
