"""AI Assistant (Pythia) tab (key "assistant"): case Q&A and status summaries, governed by Case.ai_mode (off | redacted | full).

Owner: the assistant feature. Partial: templates/case/_tab_assistant.html; static:
css/assistant.css, js/assistant.js. Logic lives in app/ai (context, rules, assistant). Tests must
mock the LLM SDK (no network).

The tab has three sub-tabs (?tab=assistant&sub=chat|summary|mode; all three are rendered, the
inactive ones `hidden`, and js/assistant.js switches between them without a reload): the chat with
the skills palette, the stored status summary, and the AI mode / data path settings.

Pages (forms, CSRF):
    POST /cases/{id}/assistant/chat          read_only+   one chat turn (JSON {"text"}; CSRF in the X-CSRF-Token
                                                          header): a /command runs its skill (app.ai.skills),
                                                          anything else is a question. Returns the rendered
                                                          messages and the suggested commands; 429 when the AI
                                                          service (or this member's previous request) is busy
    POST /cases/{id}/assistant/chat/form     read_only+   the same as a plain form (no JavaScript): redirects back
    POST /cases/{id}/assistant/chat/clear    read_only+   delete this member's conversation on the case
    POST /cases/{id}/assistant/summary   investigator+   generate and store a status summary
    POST /cases/{id}/assistant/ask       read_only+      one question; JSON for fetch(), else the tab
    POST /cases/{id}/assistant/mode      admin           switch ai_mode (full: DPA box; with the third-party
                                                         hf_router provider also "Full case content will be
                                                         sent to <destination>", recorded in the audit row)
API:
    GET  /api/cases/{id}/assistant/skills            read_only+  the skills registry (what this member may run)
    GET  /api/cases/{id}/assistant/chat              read_only+  this member's conversation (Markdown + metadata)
    POST /api/cases/{id}/assistant/chat              read_only+  {"text"}: one chat turn. A cookie session must
                                                                 also send the page's X-CSRF-Token (on top of
                                                                 app.core.csrf.csrf_middleware's same-origin
                                                                 check); an Authorization (HTTP Basic) request
                                                                 carries no ambient cookie and needs none
    GET  /api/cases/{id}/assistant/summary           read_only+  the stored summary
    POST /api/cases/{id}/assistant/summary           investigator+
    POST /api/cases/{id}/assistant/ask               read_only+  {"question", "history"}
    GET  /api/cases/{id}/assistant/context-preview   admin       exactly what would be sent (?mode=)

Read-only members may ask questions only while the case is in `redacted` (or `off`) mode: in
`full` mode the context carries restricted content (letter bodies, references, names).
"""

from __future__ import annotations

import hmac
import json
import threading
from contextlib import contextmanager

import markdown_it  # type: ignore
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from markupsafe import Markup
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ai import providers as ai_providers
from app.ai import skills as ai_skills
from app.ai.assistant import (
    MAX_QUESTION_CHARS,
    SYSTEM_PROMPT,
    answer_question,
    full_mode_confirmed,
    reason_text,
    stored_summary,
    summarize_case,
    summary_instructions,
)
from app.ai.context import MODE_HELP, build_context
from app.core import csrf as csrf_mod
from app.core.audit import DELETE, UPDATE, audit
from app.core.csrf import require_csrf
from app.core.permissions import ADMIN, INVESTIGATOR, READ_ONLY, CaseAccess, require_case_role
from app.core.security import require_user
from app.db.models import AIMode
from app.db.session import get_db
from app.web.tabs import tab_context
from app.web.templating import templates

router = APIRouter(tags=["assistant"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]
SUB_TABS = (("chat", "Chat"), ("summary", "Status summary"), ("mode", "AI mode & data path"))


# --------------------------------------------------------------------------- chat rendering
def _safe_link(url: str) -> bool:
    """Links in chat messages: app-relative paths only (no other site, no javascript:/data: URLs)."""
    return url.startswith("/") and not url.startswith("//") and "\\" not in url


# Model and skill output is Markdown: raw HTML is escaped (html disabled), images are off and links
# may only point inside Aegis, so nothing a model writes can run script or pull a remote resource.
_chat_md = markdown_it.MarkdownIt("commonmark", {"html": False, "breaks": True, "linkify": False}).enable("table")
_chat_md.disable("image")
_chat_md.validateLink = _safe_link


def chat_markdown(text: str | None) -> Markup:
    return Markup(_chat_md.render(text or ""))  # safe: html disabled, links validated above


def _msg_ctx(request: Request, access: CaseAccess) -> dict:
    return {"request": request, "case": access.case, "chat_md": chat_markdown, "disclaimer": ai_skills.DISCLAIMER}


def _render_messages(request: Request, access: CaseAccess, msgs: list) -> str:
    tpl = templates.get_template("case/assistant/_message.html")
    ctx = _msg_ctx(request, access)
    return "".join(tpl.render({**ctx, "m": m}) for m in msgs)


def _message_json(m) -> dict:
    meta = m.meta or {}
    return {"id": m.id, "role": m.role, "content": m.content, "skill": m.skill, "source": m.source,
            "served_model": m.served_model, "mode": m.mode, "created_at": m.created_at.isoformat() if m.created_at
            else None, "label": meta.get("label"), "generated_by": meta.get("generated_by"),
            "actions": meta.get("actions") or [], "suggested_commands": meta.get("suggested") or [],
            "drafts": meta.get("drafts") or []}


def _initial_suggestions(db: Session, access: CaseAccess, msgs: list) -> list[str]:
    """After the last assistant reply: its suggestions; on an empty conversation: what the case needs."""
    last = next((m for m in reversed(msgs) if m.role == "assistant"), None)
    if last is not None and (last.meta or {}).get("suggested"):
        return ai_skills.validate_suggestions(last.meta["suggested"], access)
    return ai_skills.context_suggestions(db, access)


# one chat request per member and case at a time (a model call can take over a minute)
_inflight: set[tuple[int, int]] = set()
_inflight_lock = threading.Lock()


@contextmanager
def _one_at_a_time(access: CaseAccess):
    key = (access.case.id, access.user.id)
    with _inflight_lock:
        if key in _inflight:
            raise ai_skills.SkillBusy("Your previous request is still running. Wait for it to finish, then retry.")
        _inflight.add(key)
    try:
        yield
    finally:
        with _inflight_lock:
            _inflight.discard(key)


def _require_csrf_header(request: Request) -> None:
    """fetch() POSTs carry the page's CSRF token in X-CSRF-Token (same check as require_csrf)."""
    token = request.headers.get("x-csrf-token", "")
    cookie = request.cookies.get(csrf_mod.cookie_name(), "")
    if not (token and cookie and hmac.compare_digest(token, cookie)
            and csrf_mod.is_valid(token, csrf_mod.binding_for(request))):
        raise HTTPException(403, "CSRF token missing or invalid — reload the page and retry")


def _require_csrf_header_for_cookie_session(request: Request) -> None:
    """POST /api/.../assistant/chat: a browser (cookie) session sends X-CSRF-Token as the page's fetch() does,
    in addition to the middleware's Origin check; a script authenticating with an Authorization header
    carries no ambient browser credential to ride on, so it needs no token — but only when no session
    cookie is present, since the session takes precedence over HTTP Basic in optional_user."""
    has_session = "session" in request.scope and request.session.get("sid")
    if request.headers.get("authorization") and not has_session:
        return
    _require_csrf_header(request)


def _turn(db: Session, access: CaseAccess, text: str) -> ai_skills.ChatTurn:
    _require_ask(access)
    with _one_at_a_time(access):
        return ai_skills.chat_turn(db, access, text)


def _skill_error_response(exc: Exception) -> JSONResponse:
    if isinstance(exc, ai_skills.SkillBusy):
        return JSONResponse({"detail": exc.message, "busy": True}, status_code=429, headers={"Retry-After": "10"})
    assert isinstance(exc, ai_skills.SkillError)
    return JSONResponse({"detail": exc.message}, status_code=exc.status)


# --------------------------------------------------------------------------- policy
def can_ask(access: CaseAccess) -> bool:
    """use_assistant, and below investigator only while nothing restricted can reach the model."""
    if not access.can("use_assistant"):
        return False
    return access.at_least(INVESTIGATOR) or AIMode(access.case.ai_mode) in (AIMode.REDACTED, AIMode.OFF)


def can_summarize(access: CaseAccess) -> bool:
    return access.can("ai_summarize")


def _require_ask(access: CaseAccess) -> None:
    if not can_ask(access):
        raise HTTPException(403, "read-only members can ask questions only while the case's AI mode is 'redacted'")


def _summary_visible(access: CaseAccess, stored: dict | None) -> bool:
    """A summary generated in full mode may quote restricted content: investigators and above only."""
    return stored is not None and (stored.get("mode") != AIMode.FULL.value or access.can("view_restricted"))


def shown_summary(access: CaseAccess, stored: dict | None) -> dict | None:
    """The stored summary as this member reads it: with the real names and references (`summary_full`, a rule-based
    summary's) for a member with view_restricted, else with the placeholders the model reads."""
    if stored is None:
        return None
    if access.can("view_restricted") and isinstance(stored.get("summary_full"), dict):
        return {**stored, "summary": stored["summary_full"]}
    return stored


def _answer_payload(result) -> dict:
    return {"answer": result.output, "source": result.source, "label": result.label, "mode": result.mode,
            "model": result.model, "served_model": result.served_model, "provider_label": result.provider_label,
            "generated_by": result.generated_by, "reason": reason_text(result.reason)}


# --------------------------------------------------------------------------- tab
@tab_context("assistant")
def assistant_tab(request: Request, db: Session, access: CaseAccess) -> dict:
    mode = AIMode(access.case.ai_mode or AIMode.REDACTED)
    stored = stored_summary(access.case)
    visible = _summary_visible(access, stored)
    provider = ai_providers.get_provider()
    info = ai_providers.describe()
    return {
        "ai_mode": mode,
        "ai_modes": [(m.value, MODE_HELP[m.value]) for m in AIMode],
        "ai_configured": mode != AIMode.OFF and provider is not None,
        "ai_provider_ready": provider is not None,
        "ai_model": getattr(provider, "model", None) or info["model"],
        "ai_destination": getattr(provider, "label", None) or info["label"],
        "ai_third_party": getattr(provider, "name", info["provider"]) == "hf_router",
        "ai_mode_sends": MODE_HELP[mode.value],
        "ai_full_unconfirmed": mode == AIMode.FULL and provider is not None
                               and not full_mode_confirmed(db, access.case, provider),
        "assistant_summary": shown_summary(access, stored) if visible else None,
        "assistant_summary_hidden": stored is not None and not visible,
        "assistant_summary_reason": reason_text(stored.get("reason")) if visible else None,
        "can_summarize": can_summarize(access),
        "can_ask": can_ask(access),
        "can_switch_mode": access.can("manage_case"),
        "assistant_answer": getattr(request.state, "assistant_answer", None),
        "max_question_chars": MAX_QUESTION_CHARS,
        **_chat_context(request, db, access),
    }


def _chat_context(request: Request, db: Session, access: CaseAccess) -> dict:
    sub = request.query_params.get("sub", "chat")
    msgs = ai_skills.visible_messages(db, access) if can_ask(access) else []
    skills = [s.as_dict(access) for s in ai_skills.SKILLS.values()]
    return {
        "assistant_sub": sub if sub in {k for k, _ in SUB_TABS} else "chat",
        "assistant_subtabs": SUB_TABS,
        "chat_messages": msgs,
        "chat_skills": skills,
        "chat_suggestions": _initial_suggestions(db, access, msgs) if can_ask(access) else [],
        "chat_md": chat_markdown,
        "disclaimer": ai_skills.DISCLAIMER,
        "rule_note": ai_skills.RULE_NOTE,
        "chat_data": {"case_id": access.case.id, "max_chars": MAX_QUESTION_CHARS,
                      "skills": [s for s in skills if s["allowed"]]},
    }


@router.get("/cases/{case_id}/assistant")
def assistant_tab_page(case_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY))):
    return RedirectResponse(f"/cases/{case_id}?tab=assistant", status_code=303)


# --------------------------------------------------------------------------- chat
class ChatIn(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_QUESTION_CHARS)


@router.post("/cases/{case_id}/assistant/chat", dependencies=[Depends(_require_csrf_header)])
def assistant_chat(payload: ChatIn, request: Request, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                   db: Session = Depends(get_db)):
    """One chat turn for the page's fetch(): the rendered messages and the suggested commands."""
    try:
        turn = _turn(db, access, payload.text)
    except (ai_skills.SkillBusy, ai_skills.SkillError) as exc:
        return _skill_error_response(exc)
    return JSONResponse({"html": _render_messages(request, access, [turn.user, turn.assistant]),
                         "suggestions": turn.suggestions, "message": _message_json(turn.assistant)})


@router.post("/cases/{case_id}/assistant/chat/form", dependencies=_csrf)
def assistant_chat_form(access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db),
                        text: str = Form(...)):
    """The chat without JavaScript: run the turn, then show the tab again (the history is stored)."""
    try:
        _turn(db, access, text[:MAX_QUESTION_CHARS])
    except ai_skills.SkillBusy as exc:
        raise HTTPException(429, exc.message) from None
    except ai_skills.SkillError as exc:
        raise HTTPException(exc.status, exc.message) from None
    return RedirectResponse(f"/cases/{access.case.id}?tab=assistant#assistant-chat-end", status_code=303)


@router.post("/cases/{case_id}/assistant/chat/clear", dependencies=_csrf)
def assistant_chat_clear(request: Request, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                         db: Session = Depends(get_db)):
    n = ai_skills.clear_history(db, access)
    audit(db, access, DELETE, access.case, ("ai_messages", None), scope="own_conversation", count=n)
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"deleted": n, "suggestions": ai_skills.context_suggestions(db, access)
                             if can_ask(access) else []})
    return RedirectResponse(f"/cases/{access.case.id}?tab=assistant", status_code=303)


@router.get("/api/cases/{case_id}/assistant/skills")
def api_skills(access: CaseAccess = Depends(require_case_role(READ_ONLY))):
    return {"skills": [s.as_dict(access) for s in ai_skills.SKILLS.values()], "disclaimer": ai_skills.DISCLAIMER}


@router.get("/api/cases/{case_id}/assistant/chat")
def api_chat_history(access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db)):
    _require_ask(access)
    msgs = ai_skills.visible_messages(db, access)
    return {"messages": [_message_json(m) for m in msgs], "suggestions": _initial_suggestions(db, access, msgs),
            "disclaimer": ai_skills.DISCLAIMER}


@router.post("/api/cases/{case_id}/assistant/chat", dependencies=[Depends(_require_csrf_header_for_cookie_session)])
def api_chat(payload: ChatIn, access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db)):
    try:
        turn = _turn(db, access, payload.text)
    except (ai_skills.SkillBusy, ai_skills.SkillError) as exc:
        return _skill_error_response(exc)
    return {"user": _message_json(turn.user), "assistant": _message_json(turn.assistant),
            "suggestions": turn.suggestions, "disclaimer": ai_skills.DISCLAIMER}


# --------------------------------------------------------------------------- pages
@router.post("/cases/{case_id}/assistant/summary", dependencies=_csrf)
def assistant_summary(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db)):
    summarize_case(db, access.case, actor=access)
    return RedirectResponse(f"/cases/{access.case.id}?tab=assistant#assistant-summary", status_code=303)


def _parse_history(raw: str) -> list:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    return data if isinstance(data, list) else []


@router.post("/cases/{case_id}/assistant/ask", dependencies=_csrf)
def assistant_ask(request: Request, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                  db: Session = Depends(get_db), question: str = Form(...), history: str = Form("")):
    _require_ask(access)
    result = answer_question(db, access.case, question, _parse_history(history), actor=access)
    payload = _answer_payload(result)
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(payload)
    # without JavaScript: render the case page with the answer in the Assistant tab
    from app.web.routes import case_detail  # local import: app.web.routes is the core shell

    request.state.assistant_answer = {**payload, "question": question.strip()[:MAX_QUESTION_CHARS]}
    return case_detail(request, tab="assistant", access=access, db=db)


@router.post("/cases/{case_id}/assistant/mode", dependencies=_csrf)
def assistant_mode(access: CaseAccess = Depends(require_case_role(ADMIN)), db: Session = Depends(get_db),
                   mode: str = Form(...), confirm_full: str = Form(""), confirm_provider: str = Form("")):
    """Switch the case's AI mode. `full` needs the DPA box and, while the provider is the third-party
    hf_router, the "Full case content will be sent to <destination>" box; the confirmed provider and
    destination go into the audit row (app.ai.assistant.full_mode_confirmed reads them back). An admin
    can re-confirm a case already in full mode (e.g. after the provider changed) by ticking the boxes."""
    access.require("manage_case")
    try:
        new = AIMode(mode)
    except ValueError:
        raise HTTPException(400, f"unknown AI mode {mode!r}") from None
    case = access.case
    old = AIMode(case.ai_mode or AIMode.REDACTED)
    if new == AIMode.FULL and (old != AIMode.FULL or confirm_provider == "yes"):
        info = ai_providers.describe()
        if confirm_full != "yes":
            raise HTTPException(400, "switching to full mode needs the data-processing confirmation box ticked")
        if info["third_party"] and confirm_provider != "yes":
            raise HTTPException(400, f"switching to full mode needs the confirmation that full case content will be "
                                     f"sent to {info['label']}")
        case.ai_mode = new
        db.commit()
        audit(db, access, UPDATE, case, case, field="ai_mode", old=old.value, new=new.value,
              confirmed_provider=info["provider"], confirmed_destination=info["label"],
              confirmed_model=info["model"], dpa_confirmed=True)
    elif new != old:
        case.ai_mode = new
        db.commit()
        audit(db, access, UPDATE, case, case, field="ai_mode", old=old.value, new=new.value)
    return RedirectResponse(f"/cases/{case.id}?tab=assistant#assistant-mode", status_code=303)


# --------------------------------------------------------------------------- API
class AskIn(BaseModel):
    question: str = Field(min_length=1, max_length=MAX_QUESTION_CHARS)
    history: list[dict] = Field(default_factory=list)


@router.get("/api/cases/{case_id}/assistant/summary")
def api_get_summary(access: CaseAccess = Depends(require_case_role(READ_ONLY))):
    stored = stored_summary(access.case)
    if stored is None:
        raise HTTPException(404, "no summary yet")
    if not _summary_visible(access, stored):
        raise HTTPException(403, "this summary was generated in full mode; investigators and above only")
    return {"status_summary": access.case.status_summary, **stored}


@router.post("/api/cases/{case_id}/assistant/summary")
def api_post_summary(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db)):
    return summarize_case(db, access.case, actor=access)


@router.post("/api/cases/{case_id}/assistant/ask")
def api_ask(payload: AskIn, access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db)):
    _require_ask(access)
    return _answer_payload(answer_question(db, access.case, payload.question, payload.history, actor=access))


@router.get("/api/cases/{case_id}/assistant/context-preview")
def api_context_preview(mode: str | None = None, access: CaseAccess = Depends(require_case_role(ADMIN)),
                        db: Session = Depends(get_db)):
    """Exactly what a summary or question would send for `mode` (default: the case's own mode)."""
    access.require("manage_case")
    try:
        m = AIMode(mode) if mode else AIMode(access.case.ai_mode or AIMode.REDACTED)
    except ValueError:
        raise HTTPException(400, f"unknown AI mode {mode!r}") from None
    audit(db, access, "AI_CONTEXT_PREVIEW", access.case, ("assistant_context", None), mode=m.value)
    info = ai_providers.describe()
    if m == AIMode.OFF:
        return {"mode": m.value, "sent": False, "explanation": MODE_HELP[m.value], "model": None,
                "destination": None, "system_prompt": None, "context": None}
    return {
        "mode": m.value, "sent": True, "explanation": MODE_HELP[m.value], "provider": info["provider"],
        "model": info["model"], "destination": info["label"], "system_prompt": SYSTEM_PROMPT,
        "summary_instructions": summary_instructions(), "context": build_context(db, access.case, m),
        "note": "The context is sent as compact JSON (sorted keys) inside <case_context> tags in the first user "
                "turn after the system prompt; questions and earlier turns follow it (redacted the same way in "
                "redacted mode). Summaries append summary_instructions (the JSON schema) to the system prompt.",
    }
