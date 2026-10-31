"""AI settings (system administrators): the assistant's provider configuration, read-only.

Owner: the assistant feature. Page: templates/admin_ai.html. Settings are env-driven
(AEGIS_LLM_*, AEGIS_HF_BILL_TO, HF_INFERENCE_TOKEN, AEGIS_AI_DISABLED; app.ai.providers); the page
never shows or accepts a token, only whether one is configured.

    GET  /admin/ai          provider, base-URL host, model, bill-to org, token yes/no, kill switch
    POST /admin/ai/test     (CSRF) "Test connection": a fixed non-case prompt; served model, latency, cost
    POST /admin/ai/health   (CSRF) GET {base_url}/models (10 s): is the model listed, which providers serve it

Both POSTs send no case data and write an audit row (AI_TEST_CONNECTION / AI_HEALTH_CHECK, metadata only).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.ai import providers as ai_providers
from app.ai.assistant import reason_text, run_connection_test
from app.core.audit import audit
from app.core.csrf import require_csrf
from app.core.security import require_system_admin, require_user
from app.db.models import User
from app.db.session import get_db
from app.web.templating import templates

router = APIRouter(tags=["admin"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]

UNAVAILABLE_TEXT = {
    "disabled": "The kill switch AEGIS_AI_DISABLED is on: no model is called.",
    "provider_none": "AEGIS_LLM_PROVIDER=none: no model is configured.",
    "not_configured": "No inference token is configured (HF_INFERENCE_TOKEN, HF_TOKEN or LLM_API_KEY).",
    "host_not_allowed": "The base URL's host is not on the allow-list.",
}


def _provider() -> tuple[object | None, str | None]:
    provider = ai_providers.get_provider()
    if provider is not None:
        return provider, None
    return None, ai_providers.resolve_provider()[1] or "not_configured"


def _render(request: Request, **extra) -> HTMLResponse:
    provider, why = _provider()
    info = ai_providers.describe()
    ctx = {"info": info, "ready": provider is not None, "unavailable": UNAVAILABLE_TEXT.get(why or "", why),
           "test_prompt": ai_providers.TEST_PROMPT, "test": None, "health": None, **extra}
    response = templates.TemplateResponse(request, "admin_ai.html", ctx)
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/admin/ai", response_class=HTMLResponse)
def admin_ai(request: Request, me: User = Depends(require_system_admin)):
    return _render(request)


@router.post("/admin/ai/test", response_class=HTMLResponse, dependencies=_csrf)
def admin_ai_test(request: Request, me: User = Depends(require_system_admin), db: Session = Depends(get_db)):
    provider, why = _provider()
    if provider is None:
        result = {"ok": False, "reason": why, "error": UNAVAILABLE_TEXT.get(why or "", why)}
    else:
        result = run_connection_test(provider)
        if not result["ok"]:
            result["error"] = f"{reason_text(result['reason'])} {result.get('error') or ''}".strip()
    usage = result.get("usage") or {}
    audit(db, me, "AI_TEST_CONNECTION", None, ("ai_provider", None), ok=result["ok"], reason=result.get("reason"),
          provider=getattr(provider, "name", None), model=getattr(provider, "model", None),
          served_model=result.get("served_model"), latency_ms=result.get("latency_ms"),
          input_tokens=usage.get("input_tokens"), output_tokens=usage.get("output_tokens"),
          estimated_cost=usage.get("estimated_cost"), status=result.get("status"))
    return _render(request, test=result)


@router.post("/admin/ai/health", response_class=HTMLResponse, dependencies=_csrf)
def admin_ai_health(request: Request, me: User = Depends(require_system_admin), db: Session = Depends(get_db)):
    provider, why = _provider()
    if provider is None:
        health = {"ok": False, "error": UNAVAILABLE_TEXT.get(why or "", why)}
    elif not hasattr(provider, "list_models"):
        health = {"ok": False, "error": f"The {provider.name} provider has no /models health check."}
    else:
        try:
            health = {"ok": True, **provider.list_models()}
        except ai_providers.ProviderError as err:
            health = {"ok": False, "reason": err.reason, "error": err.message}
    audit(db, me, "AI_HEALTH_CHECK", None, ("ai_provider", None), ok=health["ok"], reason=health.get("reason"),
          provider=getattr(provider, "name", None), listed=health.get("listed"),
          pinned_provider_listed=health.get("pinned_provider_listed"), latency_ms=health.get("latency_ms"))
    return _render(request, health=health)
