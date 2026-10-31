import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app import __version__
from app.api.routes import router as api_router
from app.core.audit import request_context_middleware
from app.core.config import get_settings, insecure_settings
from app.core.csrf import csrf_middleware
from app.core.headers import security_headers_middleware
from app.core.logging import configure_logging
from app.core.security import SESSION_COOKIE, NotAuthenticated, is_api_path, require_user
from app.web.routes import router as web_router
from app.web.routes_admin_ai import router as admin_ai_router
from app.web.routes_assistant import router as assistant_router
from app.web.routes_attribution import router as attribution_router
from app.web.routes_auth import dev_login_enabled
from app.web.routes_auth import router as auth_router
from app.web.routes_authorities import router as authorities_router
from app.web.routes_blocks import router as blocks_router
from app.web.routes_evidence import router as evidence_router
from app.web.routes_evidence_intel import router as evidence_intel_router
from app.web.routes_freeze import router as freeze_router
from app.web.routes_mail import router as mail_router
from app.web.routes_mail_admin import router as mail_admin_router
from app.web.routes_notifications import router as notifications_router
from app.web.routes_recovery import router as recovery_router
from app.web.routes_team import router as team_router
from app.web.routes_todo import router as todo_router
from app.web.routes_trace import router as trace_router

log = logging.getLogger("app")


def check_secrets() -> None:
    """Refuse to start outside APP_ENV=local while secrets are unset or placeholders."""
    settings = get_settings()
    problems = insecure_settings(settings)
    if problems and not settings.is_local:
        raise RuntimeError(f"Refusing to start with APP_ENV={settings.app_env}: " + "; ".join(problems))
    for p in problems:
        log.warning("insecure configuration (allowed only because APP_ENV=local): %s", p)
    if settings.aegis_dev_login_token:
        log.warning("AEGIS_DEV_LOGIN_TOKEN is set: the dev sign-in link /dev/login is %s",
                    "ENABLED (local only; unset it when done)" if dev_login_enabled() else "ignored")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(get_settings().log_level)
    check_secrets()
    yield


# The schema and Swagger UI sit behind the same sign-in as the rest of the app, so the built-in
# (unauthenticated) routes are disabled and re-mounted below with require_user.
app = FastAPI(title="Aegis", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
_settings = get_settings()
# Middleware: the last added is the outermost. Order (outer → inner): headers, request context,
# session, CSRF (the CSRF token is bound to the session, so the session is decoded first).
app.middleware("http")(csrf_middleware)
app.add_middleware(
    SessionMiddleware, secret_key=_settings.derived_key("session"), session_cookie=SESSION_COOKIE,
    max_age=_settings.session_max_hours * 3600, same_site="strict", https_only=not _settings.is_local,
)
app.middleware("http")(request_context_middleware)
app.middleware("http")(security_headers_middleware)  # outermost: also covers CSRF rejections
app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "web" / "static")), name="static")

# One router per feature; each feature edits only its own router module (see README §5 for the layout
# and docs/fixture-schema.md for the fixture loaders).
for r in (auth_router, api_router, web_router, trace_router, authorities_router, evidence_router, team_router,
          notifications_router, assistant_router, admin_ai_router, mail_router, mail_admin_router, freeze_router,
          blocks_router, recovery_router, attribution_router, evidence_intel_router, todo_router):
    app.include_router(r)


from starlette.exceptions import HTTPException as _StarletteHTTPException

from app.web import notice as _notice

# a refused browser form: back to its page with the message in a dialog (JSON for the API and scripts, as before)
app.add_exception_handler(_StarletteHTTPException, _notice.http_exception)


@app.exception_handler(NotAuthenticated)
async def _not_authenticated(request: Request, exc: NotAuthenticated):
    if is_api_path(request.url.path):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401,
                            headers={"WWW-Authenticate": 'Basic realm="aegis"'})
    target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    return RedirectResponse(f"/login?next={quote(target, safe='')}", status_code=303)


@app.get("/openapi.json", include_in_schema=False, dependencies=[Depends(require_user)])
def openapi_schema() -> JSONResponse:
    if app.openapi_schema is None:
        app.openapi_schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
    return JSONResponse(app.openapi_schema)


@app.get("/api/docs", include_in_schema=False, dependencies=[Depends(require_user)])
def swagger_ui() -> HTMLResponse:
    return get_swagger_ui_html(openapi_url="/openapi.json", title="Aegis — API docs")


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok", "version": __version__}
