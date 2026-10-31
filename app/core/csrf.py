"""Signed, session-bound double-submit CSRF protection for the server-rendered forms.

The middleware gives every browser a random token `nonce.HMAC(APP_SECRET_KEY, binding|nonce)` in
an HttpOnly, SameSite=Strict cookie (`__Host-aegis_csrf` outside APP_ENV=local, so a sibling
subdomain cannot plant it); each POST form repeats it in a hidden field (`{{ csrf_field() }}`),
and `require_csrf` accepts the request only when the field equals the cookie and the signature
verifies for *this* session. `binding` is a hash of the server-side session token (or "anon"
before sign-in), so a validly signed token obtained by someone else, e.g. from their own
GET /login, is worthless in the victim's session. A new session (sign-in) gets a new token on
the next page.

The middleware also rejects any unsafe-method request whose Origin header names another site.
For the JSON API under /api (no form token), an unsafe request authenticated by the session
cookie must also prove it is same-origin: an Origin or Referer naming this host, or an
`X-Requested-With` header (which a cross-site form cannot send). Requests with an Authorization
header (HTTP Basic for scripts) carry no ambient browser credential beyond cached Basic, which the
Origin rule covers.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

from fastapi import Form, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from jinja2 import pass_context
from markupsafe import Markup, escape

from app.core.config import get_settings

COOKIE = "aegis_csrf"  # APP_ENV=local (plain http): browsers refuse __Host- cookies without Secure
HOST_COOKIE = "__Host-aegis_csrf"
FIELD = "csrf_token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
_SESSION_KEY = "sid"  # app.core.security.SESSION_KEY


def cookie_name() -> str:
    return COOKIE if get_settings().is_local else HOST_COOKIE


def binding_for(request: Request) -> str:
    """What the token is bound to: a hash of the session token, or "anon" before sign-in."""
    sid = request.session.get(_SESSION_KEY) if "session" in request.scope else None
    return hashlib.sha256(sid.encode()).hexdigest()[:32] if sid else "anon"


def _sign(nonce: str, binding: str) -> str:
    return hmac.new(get_settings().signing_key, f"{binding}|{nonce}".encode(), hashlib.sha256).hexdigest()


def new_token(binding: str = "anon") -> str:
    nonce = secrets.token_urlsafe(32)
    return f"{nonce}.{_sign(nonce, binding)}"


def is_valid(token: str | None, binding: str = "anon") -> bool:
    if not token or token.count(".") != 1:
        return False
    nonce, sig = token.split(".")
    return hmac.compare_digest(sig, _sign(nonce, binding))


def _netloc(url: str | None) -> str | None:
    if not url or url == "null":
        return None
    return urlsplit(url).netloc


def _cross_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return False
    return origin == "null" or urlsplit(origin).netloc != request.headers.get("host", "")


def _proves_same_origin(request: Request) -> bool:
    host = request.headers.get("host", "")
    if _netloc(request.headers.get("origin")) == host:
        return True
    if not request.headers.get("origin") and _netloc(request.headers.get("referer")) == host:
        return True
    return bool(request.headers.get("x-requested-with"))


def _cookie_authenticated_api_write(request: Request) -> bool:
    path = request.url.path
    if request.method in SAFE_METHODS or not (path == "/api" or path.startswith("/api/")):
        return False
    # A session cookie is an ambient browser credential even when an Authorization header is also sent
    # (the session wins in optional_user), so only cookie-less requests are exempt.
    return bool("session" in request.scope and request.session.get(_SESSION_KEY))


async def csrf_middleware(request: Request, call_next):
    if request.method not in SAFE_METHODS and _cross_origin(request):
        return PlainTextResponse("Cross-origin request rejected", status_code=status.HTTP_403_FORBIDDEN)
    if _cookie_authenticated_api_write(request) and not _proves_same_origin(request):
        return PlainTextResponse("Cookie-authenticated API writes need a same-origin Origin or Referer header "
                                 "(or X-Requested-With)", status_code=status.HTTP_403_FORBIDDEN)
    name = cookie_name()
    cookie = request.cookies.get(name)
    issued = None if is_valid(cookie, binding_for(request)) else new_token(binding_for(request))
    request.state.csrf_token = issued or cookie
    response = await call_next(request)
    if issued and response.headers.get("content-type", "").startswith("text/html"):
        response.set_cookie(name, issued, httponly=True, samesite="strict", secure=not get_settings().is_local,
                            path="/")
    return response


def require_csrf(request: Request, csrf_token: str = Form("")) -> None:
    """Route dependency for every state-changing HTML form."""
    _check(request, csrf_token)


def _check(request: Request, csrf_token: str) -> None:
    cookie = request.cookies.get(cookie_name(), "")
    if not (csrf_token and hmac.compare_digest(csrf_token, cookie) and is_valid(csrf_token, binding_for(request))):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid — reload the page and retry")


def require_csrf_form(*, max_files: int, max_fields: int = 1000):
    """`require_csrf` for a form whose parts are capped. With `require_csrf` (a Form() parameter) FastAPI parses the
    whole body with Starlette's defaults (1,000 files, spooled to disk) before the route runs, and caches it, so a
    later `request.form(max_files=...)` in the route caps nothing. This dependency parses the form itself first with
    these caps (too many file parts or fields: HTTP 400, before they are read), then checks the token; the route's
    own `await request.form()` gets the same, capped, form (its uploaded files are closed after the response)."""

    async def require_csrf_capped(request: Request):
        data = await request.form(max_files=max_files, max_fields=max_fields)
        try:
            token = data.get(FIELD)
            _check(request, token if isinstance(token, str) else "")
            yield
        finally:
            await data.close()

    return require_csrf_capped


@pass_context
def csrf_field(ctx) -> Markup:
    """Jinja global: the hidden input for the current request's token."""
    token = getattr(ctx["request"].state, "csrf_token", None) or ""
    return Markup(f'<input type="hidden" name="{FIELD}" value="{escape(token)}">')
