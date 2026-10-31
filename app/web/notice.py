"""Refusals shown as a dialog, not as raw JSON.

A browser form that Aegis refuses (an HTTPException with a 4xx status: "Request #12 was sent: only a follow-up …")
comes back to the page it was sent from, with the message in a dialog (`<dialog open>` + `<form method="dialog">`:
no script, CSP-safe). Only requests that ask for HTML (`Accept: text/html`, what a browser sends) outside the JSON API
get this; API clients, scripts and tests keep the JSON response unchanged.

    app.add_exception_handler(StarletteHTTPException, notice.http_exception)   # app/main.py
    {% set n = pop_notice(request) %}                                         # base.html shows it
"""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.security import is_api_path

KEY = "_notice"
MAX = 1200
TITLES = {400: "Check the form", 403: "Not allowed for your role", 404: "Not found", 409: "Not done",
          413: "Too large", 422: "Check the form", 429: "Please wait"}


def _wants_html(request: Request) -> bool:
    return "text/html" in (request.headers.get("accept") or "") and not is_api_path(request.url.path)


def _back(request: Request) -> str | None:
    """The page the form was sent from: the same-origin Referer's path (never another site)."""
    ref = request.headers.get("referer") or ""
    if not ref:
        return None
    u = urlsplit(ref)
    if u.netloc and u.netloc != request.url.netloc:
        return None
    path = u.path or "/"
    if not path.startswith("/") or path.startswith("//") or "\\" in path:
        return None
    return path + (f"?{u.query}" if u.query else "")


def _text(detail) -> str:
    if isinstance(detail, str):
        return detail[:MAX]
    if isinstance(detail, list):  # validation errors
        return "; ".join(str(d.get("msg", d)) if isinstance(d, dict) else str(d) for d in detail)[:MAX]
    return str(detail or "")[:MAX]


async def http_exception(request: Request, exc: StarletteHTTPException):
    """A refused browser form goes back to its page with the message in a dialog; everything else as before."""
    if not (400 <= exc.status_code < 500) or exc.status_code == 401 or not _wants_html(request):
        return await http_exception_handler(request, exc)
    back = _back(request) if request.method != "GET" else None
    text = _text(exc.detail)
    if back is not None and "session" in request.scope:
        request.session[KEY] = {"text": text, "status": exc.status_code,
                                "title": TITLES.get(exc.status_code, "Not done")}
        return RedirectResponse(back, status_code=303)
    from app.web.templating import templates

    return templates.TemplateResponse(request, "notice.html", {
        "notice": {"text": text, "status": exc.status_code, "title": TITLES.get(exc.status_code, "Not done")},
        "back": _back(request) or "/"}, status_code=exc.status_code)


def pop_notice(request) -> dict | None:
    """Jinja global: the pending refusal for this page (shown once), or None."""
    try:
        return request.session.pop(KEY, None) if request is not None and "session" in request.scope else None
    except Exception:  # noqa: BLE001 - a page never fails on its notice
        return None
