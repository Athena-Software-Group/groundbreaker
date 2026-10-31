"""Baseline security headers for every response.

The UI loads only same-origin scripts (vendored Cytoscape/dagre, graph.js, ui.js); page data
travels in `<script type="application/json">` blocks, which CSP does not execute. Inline
`style=""` attributes are still used by the templates, hence 'unsafe-inline' for styles only.
FastAPI's Swagger page (/api/docs) needs its CDN bundle and one inline bootstrap script, so it
gets a separate, wider policy.
"""

from __future__ import annotations

from fastapi import Request

from app.core.config import get_settings

CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)
DOCS_PATHS = {"/api/docs", "/api/docs/oauth2-redirect"}


HSTS = "max-age=31536000; includeSubDomains"


async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    h = response.headers
    if not get_settings().is_local:  # served over HTTPS behind the ALB; local runs are plain http
        h.setdefault("Strict-Transport-Security", HSTS)
    h.setdefault("Content-Security-Policy", DOCS_CSP if request.url.path in DOCS_PATHS else CSP)
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    # same-origin, not no-referrer: under no-referrer browsers send `Origin: null` on our own form
    # POSTs, which the CSRF middleware must reject; same-origin still sends nothing to other sites.
    h.setdefault("Referrer-Policy", "same-origin")
    return response
