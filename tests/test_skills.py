"""Assistant skills and chat (app/ai/skills.py, the chat routes in app/web/routes_assistant.py, the
ai_messages table). The model provider is mocked everywhere: no test reaches the network."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic.config import Config
from conftest import csrf_token
from sqlalchemy import create_engine, inspect, select

from alembic import command
from app import services
from app.ai import assistant as ai
from app.ai import providers, skills
from app.ai.providers import ChatResult, ProviderError
from app.core.permissions import CaseAccess, effective_role
from app.db.models import (
    AiMessage,
    AIMode,
    AuditEvent,
    CaseRole,
    Correspondence,
    CorrespondenceStatus,
    Entity,
    StopOrder,
    StopOrderStatus,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVED = "deepseek-ai/DeepSeek-V4.1-Flash"
LABEL = "Hugging Face Inference Router → DeepInfra (third-party inference provider)"
REQUIRED = {"summary", "analyze-flow", "stop-orders", "follow-ups", "next-steps", "wallet", "timeline",
            "evidence-gaps", "le-update", "help"}
DORMANT = "0xc6a2b6d375e5c1fbaab2b4a8adbcef887225d5a1"


class FakeProvider:
    def __init__(self, *responses, name: str = "hf_router", model: str = SERVED + ":deepinfra", label: str = LABEL):
        self.responses, self.calls = list(responses), []
        self.name, self.model, self.label = name, model, label

    def chat(self, messages, *, json_mode=False, max_tokens=None, temperature=0.2, schema=None):
        self.calls.append({"messages": messages, "json_mode": json_mode})
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        return r


def reply(text: str) -> ChatResult:
    return ChatResult(text=text, served_model=SERVED, provider_label=LABEL, usage={"input_tokens": 10,
                      "output_tokens": 5, "total_tokens": 15, "estimated_cost": 0.00001}, latency_ms=10,
                      finish_reason="stop")


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


@pytest.fixture
def scase(db, case):
    """The traced demo case; stop orders, correspondence and chat rows the test adds are removed afterwards."""
    if not case.trace_runs:
        services.run_trace(db, case)
    orders = {o.id: (o.status, dict(o.identifiers or {})) for o in case.stop_orders}
    corr = {c.id: dict(c.meta or {}) for c in case.correspondence}
    yield case
    db.rollback()
    db.expire_all()
    for row in db.scalars(select(AiMessage).where(AiMessage.case_id == case.id)).all():
        db.delete(row)
    for c in list(case.correspondence):
        if c.id not in corr:
            db.delete(c)
        else:
            c.meta = corr[c.id]
    db.flush()
    for o in list(case.stop_orders):
        if o.id not in orders:
            db.delete(o)
        else:
            o.status = orders[o.id][0]
    db.flush()
    case.ai_mode = AIMode.REDACTED
    db.commit()


def _retire_open_drafts(db, case, names: set[str]) -> None:
    """Earlier tests of the run leave drafts to the shared demo case's providers, and a provider has one open request at
    a time (app.domain.request_gate): retire them as replaced drafts (scase restores them) so the test starts with no
    open request to `names` (a drafted follow-up tied to a sent stop order is one too)."""
    ids = {e.id for e in db.scalars(select(Entity).where(Entity.name.in_(names)))}
    for c in case.correspondence:
        if c.entity_id in ids and c.direction.value == "out" and c.status == CorrespondenceStatus.DRAFT:
            c.meta = {**(c.meta or {}), "superseded_by_letter": c.id}
    for o in case.stop_orders:
        if o.entity_id in ids and o.status == StopOrderStatus.DRAFT:
            o.status = StopOrderStatus.SUPERSEDED
    db.commit()


def _access(db, case, client) -> CaseAccess:
    return CaseAccess(case=case, user=client.user, role=effective_role(db, client.user, case), member=None)


def _chat(c, case, text, *, token=None):
    token = token or csrf_token(c, f"/cases/{case.id}?tab=assistant")
    return c.post(f"/cases/{case.id}/assistant/chat", json={"text": text},
                  headers={"X-CSRF-Token": token, "Accept": "application/json"})


def _new_corr(db, case, before: set[int]) -> list[Correspondence]:
    db.expire_all()
    return [c for c in case.correspondence if c.id not in before]


# --------------------------------------------------------------------------- registry and gating
def test_registry_has_every_skill_with_metadata():
    assert REQUIRED <= set(skills.SKILLS)
    for name, s in skills.SKILLS.items():
        assert s.slash == f"/{name}" and s.title and s.description and callable(s.handler)
        assert s.min_role in (CaseRole.READ_ONLY, CaseRole.INVESTIGATOR)
    assert skills.SKILLS["le-update"].min_role == CaseRole.INVESTIGATOR
    assert {n for n, s in skills.SKILLS.items() if s.drafts} == {"stop-orders", "follow-ups", "le-update"}
    assert {n for n, s in skills.SKILLS.items() if s.needs_ai} >= {"summary", "analyze-flow", "next-steps", "wallet"}
    assert skills.parse_command("/stop-orders  draft   all") == ("stop-orders", "draft all")
    assert skills.parse_command("where is the money?") is None


def test_read_only_runs_read_skills_and_is_refused_drafts(client_for, db, scase):
    ro = client_for("read_only", case=scase)
    acc = _access(db, scase, ro)
    for cmd in ("help", "summary", "analyze-flow", "stop-orders", "follow-ups", "next-steps", "wallet", "timeline",
                "evidence-gaps"):
        res = skills.run_skill(db, acc, cmd, "")
        assert res.markdown and res.suggested_commands, cmd
        assert all(skills.SKILLS[c.split()[0][1:]].allowed(acc) for c in res.suggested_commands)
    with pytest.raises(skills.SkillError) as exc:
        skills.run_skill(db, acc, "le-update", "")
    assert exc.value.status == 403
    before = {c.id for c in scase.correspondence}
    token = csrf_token(ro, f"/cases/{scase.id}?tab=assistant")
    for text in ("/stop-orders draft all", "/follow-ups draft", "/le-update"):
        r = _chat(ro, scase, text, token=token)
        assert r.status_code == 403, text
    assert _new_corr(db, scase, before) == []
    page = ro.get(f"/cases/{scase.id}?tab=assistant").text
    assert "Draft stop orders for all" not in page
    assert client_for("external", case=scase).post(f"/cases/{scase.id}/assistant/chat", json={"text": "/help"},
                                                    headers={"X-CSRF-Token": token}).status_code == 403
    assert client_for(None, case=scase).get(f"/api/cases/{scase.id}/assistant/skills").status_code == 404


def test_chat_needs_the_csrf_header(client_for, scase):
    inv = client_for("investigator", case=scase)
    csrf_token(inv, f"/cases/{scase.id}?tab=assistant")
    r = inv.post(f"/cases/{scase.id}/assistant/chat", json={"text": "/help"})
    assert r.status_code == 403
    r = inv.post(f"/cases/{scase.id}/assistant/chat", json={"text": "/help"}, headers={"X-CSRF-Token": "x.y"})
    assert r.status_code == 403


def test_api_chat_needs_the_csrf_header_from_a_cookie_session(client_for, basic_client, scase):
    """POST /api/.../assistant/chat: the same-origin Origin header alone is not enough for a cookie session."""
    inv = client_for("investigator", case=scase)
    token = csrf_token(inv, f"/cases/{scase.id}?tab=assistant")
    url = f"/api/cases/{scase.id}/assistant/chat"
    assert inv.post(url, json={"text": "/help"}).status_code == 403
    assert inv.post(url, json={"text": "/help"}, headers={"X-Requested-With": "fetch"}).status_code == 403
    assert inv.post(url, json={"text": "/help"}, headers={"X-CSRF-Token": "x.y"}).status_code == 403
    r = inv.post(url, json={"text": "/help"}, headers={"X-CSRF-Token": token})
    assert r.status_code == 200, r.text
    assert r.json()["assistant"]["content"]
    # a script with HTTP Basic carries no ambient cookie: no token needed
    r = basic_client.post(url, json={"text": "/help"})
    assert r.status_code == 200, r.text


# --------------------------------------------------------------------------- drafts only, never sent
def test_stop_orders_creates_drafts_only(client_for, db, scase):
    issuers = {"Circle (USDC issuer)", "Tether (USDT issuer)"}
    for o in scase.stop_orders:  # earlier tests may have drafted (or sent) these: start from "no stop order on file"
        if o.entity is not None and o.entity.name in issuers:
            # a sent order marked superseded still counts as contacted (app.blocks.freeze_board): undo the send too
            o.status, o.sent_at = StopOrderStatus.SUPERSEDED, None
    db.commit()
    _retire_open_drafts(db, scase, issuers)
    inv = client_for("investigator", case=scase)
    acc = _access(db, scase, inv)
    plan = skills.stop_order_plan(db, scase)
    recommended = [r for r in plan["rows"] if r["status"] == "recommended"]
    assert {r["entity"] for r in recommended} >= issuers
    assert any(r["status"] == "requested" for r in plan["rows"])  # the imported, sent preservation letters
    listing = skills.run_skill(db, acc, "stop-orders", "")
    # both issuers act on LE process only (the board's rows): the LE route is the move, the letter a notice
    assert "Acts on LE process only" in listing.markdown and "Mark sent" in listing.markdown
    assert "Send a stop order now to" not in listing.markdown
    assert {"label": f"Draft {len(recommended)} notices to LE-only issuers",
            "command": "/stop-orders draft all"} in listing.actions, listing.markdown
    sent_before = len(db.scalars(select(AuditEvent).where(AuditEvent.action == "LETTER_SENT")).all())
    before = {c.id for c in scase.correspondence}
    r = _chat(inv, scase, "/stop-orders draft all")
    assert r.status_code == 200, r.text
    body = r.json()
    new = _new_corr(db, scase, before)
    assert len(new) == len(recommended)
    for c in new:
        assert c.status == CorrespondenceStatus.DRAFT and c.occurred_at is None
        assert c.stop_order is not None and c.stop_order.status == StopOrderStatus.DRAFT
        assert c.stop_order.sent_at is None and c.meta["created_via"] == "assistant:/stop-orders"
        assert f"/authorities/correspondence/{c.id}" in body["html"]
    assert "Nothing has been sent" in body["message"]["content"] and "never" in body["message"]["content"]
    assert "Mark sent" in body["html"] and "Drafts only: nothing was sent" in body["html"]
    assert skills.DISCLAIMER not in body["html"]  # no AI wrote it
    assert len(db.scalars(select(AuditEvent).where(AuditEvent.action == "LETTER_SENT")).all()) == sent_before
    creates = db.scalars(select(AuditEvent).where(AuditEvent.case_id == scase.id, AuditEvent.action == "CREATE",
                                                  AuditEvent.object_type == "correspondence")
                         .order_by(AuditEvent.id.desc()).limit(len(new))).all()
    assert {int(e.object_id) for e in creates} == {c.id for c in new}
    assert all(e.detail["via"] == "assistant" for e in creates)
    # the plan now shows them as drafts waiting for review
    assert {r["entity"] for r in skills.stop_order_plan(db, scase)["rows"] if r["status"] == "draft"} >= issuers
    # the letter page says who drafted it and repeats the disclaimer
    page = inv.get(f"/cases/{scase.id}/authorities/correspondence/{new[0].id}").text
    assert "Created by the case assistant (/stop-orders)" in page and skills.DISCLAIMER in page
    assert "it has not been sent" in page


def test_stop_orders_draft_target_must_name_one_draftable_service(client_for, db, scase):
    """`draft <name>` never drafts a batch from a typo, nor a letter to a service that already has one."""
    inv = client_for("investigator", case=scase)
    acc = _access(db, scase, inv)
    rows = skills.stop_order_plan(db, scase)["rows"]
    before = {c.id for c in scase.correspondence}
    with pytest.raises(skills.SkillError) as short:
        skills.run_skill(db, acc, "stop-orders", "draft e")
    assert short.value.status == 400 and "too short" in short.value.message
    names = [r["entity"].lower() for r in rows]

    def ambiguous(t):
        return sum(n.startswith(t) for n in names) > 1 or (
            not any(n.startswith(t) for n in names) and sum(t in n for n in names) > 1)

    common = next(t for n in names for t in (n[i:i + 3] for i in range(len(n) - 2)) if t.strip() == t
                  and ambiguous(t))
    with pytest.raises(skills.SkillError) as many:
        skills.run_skill(db, acc, "stop-orders", f"draft {common}")
    assert many.value.status == 400 and "matches" in many.value.message
    requested = next(r for r in rows if r["status"] == "requested")
    res = skills.run_skill(db, acc, "stop-orders", f"draft {requested['key']}")
    assert "Nothing drafted" in res.markdown and not res.drafts
    assert _new_corr(db, scase, before) == []


def test_generated_stop_order_cites_its_wallets_in_the_plan(client_for, db, scase):
    """A generated stop order stores its addresses as dicts: once it is sent, the plan finds every
    wallet cited (no 'not cited' note) and /wallet names the order, as the graph does."""
    tether = "Tether (USDT issuer)"
    for o in scase.stop_orders:
        if o.entity is not None and o.entity.name == tether:
            o.status = StopOrderStatus.SUPERSEDED
    db.commit()
    inv = client_for("investigator", case=scase)
    acc = _access(db, scase, inv)
    row = next(r for r in skills.stop_order_plan(db, scase)["rows"] if r["entity"] == tether)
    res = skills.run_skill(db, acc, "stop-orders", f"draft {row['key']}")
    assert len(res.drafts) == 1
    db.expire_all()
    waiting = skills.run_skill(db, acc, "stop-orders", "")
    assert "Drafts are waiting to be reviewed and sent for" in waiting.markdown
    assert "already has a stop order on file" not in waiting.markdown
    order = next(o for o in scase.stop_orders if o.entity is not None and o.entity.name == tether
                 and o.status == StopOrderStatus.DRAFT)
    assert all(isinstance(a, dict) for a in order.identifiers["addresses"])
    order.status, order.sent_at = StopOrderStatus.SENT, datetime.now(tz=UTC)
    db.commit()
    row = next(r for r in skills.stop_order_plan(db, scase)["rows"] if r["entity"] == tether)
    assert row["status"] == "requested" and row["wallets"] and row["uncovered"] == []
    wallet = skills.run_skill(db, acc, "wallet", row["wallets"][0]["address"])
    assert f"Cited in stop order #{order.id}" in wallet.markdown


def test_follow_ups_and_le_update_draft_only(client_for, db, scase):
    kucoin = db.scalar(select(Entity).where(Entity.name == "KuCoin"))
    now = datetime.now(tz=UTC)
    order = StopOrder(case=scase, entity=kucoin, kind="freeze", status=StopOrderStatus.SENT, subject="Freeze request",
                      body_markdown="x", identifiers={"addresses": ["0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2"]},
                      sent_at=now - timedelta(days=10), response_due_at=now - timedelta(days=3))
    db.add(order)
    db.commit()
    _retire_open_drafts(db, scase, {"KuCoin"})
    inv = client_for("investigator", case=scase)
    acc = _access(db, scase, inv)
    assert "/follow-ups" in skills.context_suggestions(db, acc)
    listing = skills.run_skill(db, acc, "follow-ups", "")
    assert f"#{order.id}" in listing.markdown and {"label": "Draft 1 status request",
                                                   "command": "/follow-ups draft"} in listing.actions
    before = {c.id for c in scase.correspondence}
    res = skills.run_skill(db, acc, "follow-ups", "draft")
    new = _new_corr(db, scase, before)
    assert len(new) == 1 and new[0].kind.value == "status_request" and new[0].status == CorrespondenceStatus.DRAFT
    assert new[0].stop_order_id == order.id and res.drafts[0]["id"] == new[0].id
    assert "Mark sent" in res.markdown
    # a drafted status request is not drafted twice
    again = skills.run_skill(db, acc, "follow-ups", "draft")
    assert _new_corr(db, scase, before) == new and "Already drafted" in again.markdown
    # LE update: list, then a draft cover letter for one authority
    le = skills.run_skill(db, acc, "le-update", "")
    keys = re.findall(r"`((?:complaint|le|entity)-\d+)`", le.markdown)
    assert keys and "[VICTIM]" not in le.markdown
    before = {c.id for c in scase.correspondence}
    res = skills.run_skill(db, acc, "le-update", keys[0])
    new = _new_corr(db, scase, before)
    assert len(new) == 1 and new[0].kind.value == "le_cover" and new[0].status == CorrespondenceStatus.DRAFT
    assert "Nothing has been sent" in res.markdown
    with pytest.raises(skills.SkillError):
        skills.run_skill(db, acc, "le-update", "no-such-authority")


# --------------------------------------------------------------------------- suggestions
def test_suggestions_are_validated_against_the_registry(client_for, db, scase):
    ro = _access(db, scase, client_for("read_only", case=scase))
    inv = _access(db, scase, client_for("investigator", case=scase))
    raw = ["/stop-orders draft all", "/bogus", "rm -rf /", "summary", "/wallet 0xabc<script>", "/le-update",
           "/WALLET " + DORMANT, "/summary", None, 42]
    assert skills.validate_suggestions(raw, inv, from_model=True) == [
        "/stop-orders", "/summary", "/wallet", "/le-update", "/wallet " + DORMANT]
    assert skills.validate_suggestions(raw, ro, from_model=True) == ["/stop-orders", "/summary", "/wallet",
                                                                     "/wallet " + DORMANT]
    # deterministic actions may carry draft arguments for investigators, never for read-only members
    assert skills.validate_command("/stop-orders draft all", inv) == "/stop-orders draft all"
    assert skills.validate_command("/stop-orders draft all", ro) == "/stop-orders"
    initial = skills.context_suggestions(db, ro)
    assert {"/summary", "/analyze-flow", "/stop-orders"} <= set(initial)  # candidates without a stop order exist
    assert all(s.split()[0][1:] in skills.SKILLS for s in initial)


def test_free_text_uses_model_json_and_validates_its_suggestions(monkeypatch, client_for, db, scase):
    answer = json.dumps({"answer": "Two hub outflows are dormant [derived.dormant_large_balances].",
                         "suggested_commands": ["/wallet " + DORMANT, "/delete-case", "/stop-orders draft all"]})
    fake = FakeProvider(reply("Sure.\n" + answer))
    monkeypatch.setattr(providers, "get_provider", lambda: fake)
    inv = client_for("investigator", case=scase)
    r = _chat(inv, scase, f"Which wallets are dormant? Ask {scase.victim_name}.")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["suggestions"] == ["/wallet " + DORMANT, "/stop-orders"]
    assert body["message"]["source"] == "ai" and body["message"]["generated_by"] == f"{SERVED} via {LABEL}"
    assert f"Generated by {SERVED} via {LABEL}" in body["html"]
    call = fake.calls[0]
    assert call["json_mode"] is True and call["messages"][0]["content"] == ai.SYSTEM_PROMPT
    task = call["messages"][-1]["content"]
    assert task.startswith("TASK: chat\n") and "/stop-orders" in task and "[VICTIM]" in task
    assert scase.victim_name not in json.dumps(call, ensure_ascii=False)
    ev = db.scalars(select(AuditEvent).where(AuditEvent.case_id == scase.id, AuditEvent.action == "AI_QUERY")
                    .order_by(AuditEvent.id.desc())).first()
    assert ev.detail["kind"] == "chat" and ev.detail["served_model"] == SERVED
    assert "dormant" not in json.dumps(ev.detail).lower()
    # a second turn sends the stored history (redacted)
    _chat(inv, scase, "And the largest?")
    roles = [m["role"] for m in fake.calls[1]["messages"]]
    assert roles == ["system", "user", "user", "assistant", "user"]
    assert "[VICTIM]" in fake.calls[1]["messages"][2]["content"]


def test_ai_skill_keeps_findings_and_falls_back_when_busy(monkeypatch, client_for, db, scase):
    fake = FakeProvider(reply(json.dumps({"answer": "**Most funds** sit in two dormant wallets.",
                                          "suggested_commands": ["/stop-orders"]})))
    monkeypatch.setattr(providers, "get_provider", lambda: fake)
    inv = _access(db, scase, client_for("investigator", case=scase))
    res = skills.run_skill(db, inv, "analyze-flow", "")
    assert res.source == "ai" and res.findings and "Where the funds sit now" in res.findings
    assert "<aegis_findings>" in fake.calls[0]["messages"][-1]["content"]
    busy = FakeProvider(ProviderError("rate_limited", status=429))
    monkeypatch.setattr(providers, "get_provider", lambda: busy)
    res = skills.run_skill(db, inv, "analyze-flow", "")
    assert res.source == "rule_based" and res.reason == "rate_limited" and "busy" in res.markdown
    assert {"label": "Retry with AI", "command": "/analyze-flow"} in res.actions


def test_busy_free_text_returns_429_and_stores_nothing(monkeypatch, client_for, db, scase):
    monkeypatch.setattr(providers, "get_provider", lambda: FakeProvider(ProviderError("rate_limited", status=429)))
    inv = client_for("investigator", case=scase)
    r = _chat(inv, scase, "Where are the funds?")
    assert r.status_code == 429 and r.json()["busy"] is True and r.headers["retry-after"]
    db.expire_all()
    assert db.scalars(select(AiMessage).where(AiMessage.case_id == scase.id)).all() == []


# --------------------------------------------------------------------------- history
def test_history_is_per_user_persisted_and_clearable(client_for, db, scase):
    a = client_for("investigator", case=scase)
    b = client_for("read_only", case=scase)
    assert _chat(a, scase, "/timeline").status_code == 200
    assert _chat(a, scase, "Where are the funds?").status_code == 200
    assert _chat(b, scase, "/help").status_code == 200
    ha = a.get(f"/api/cases/{scase.id}/assistant/chat").json()
    assert [m["role"] for m in ha["messages"]] == ["user", "assistant", "user", "assistant"]
    assert ha["messages"][0]["skill"] == "timeline" and ha["messages"][1]["source"] == "rule_based"
    assert ha["messages"][3]["label"] == "rule-based (AI not configured)"
    assert ha["disclaimer"] == skills.DISCLAIMER
    hb = b.get(f"/api/cases/{scase.id}/assistant/chat").json()
    assert [m["content"] for m in hb["messages"] if m["role"] == "user"] == ["/help"]
    page = a.get(f"/cases/{scase.id}?tab=assistant").text
    assert "Case timeline" in page and "Where are the funds?" in page and "Skills" in page
    token = csrf_token(a, f"/cases/{scase.id}?tab=assistant")
    r = a.post(f"/cases/{scase.id}/assistant/chat/clear", data={"csrf_token": token},
               headers={"Accept": "application/json"})
    assert r.status_code == 200 and r.json()["deleted"] == 4
    assert a.get(f"/api/cases/{scase.id}/assistant/chat").json()["messages"] == []
    assert len(b.get(f"/api/cases/{scase.id}/assistant/chat").json()["messages"]) == 2
    db.expire_all()
    ev = db.scalars(select(AuditEvent).where(AuditEvent.case_id == scase.id, AuditEvent.action == "DELETE",
                                             AuditEvent.object_type == "ai_messages")).all()[-1]
    assert ev.detail["count"] == 4 and ev.actor_user_id == a.user.id


def test_full_mode_turns_are_not_sent_as_history_in_redacted_mode(monkeypatch, client_for, db, scase):
    marker = "the quoted letter body only full mode may send"
    fake = FakeProvider(reply(json.dumps({"answer": "Two dormant wallets.", "suggested_commands": []})),
                        reply(json.dumps({"answer": f"Per the letter body: {marker}", "suggested_commands": []})))
    monkeypatch.setattr(providers, "get_provider", lambda: fake)
    monkeypatch.setattr("app.ai.assistant.full_mode_confirmed", lambda *a, **k: True)
    inv = client_for("investigator", case=scase)
    assert _chat(inv, scase, "Where are the funds?").json()["message"]["mode"] == "redacted"
    scase.ai_mode = AIMode.FULL
    db.commit()
    r = _chat(inv, scase, "Quote the letter body")
    assert r.status_code == 200 and r.json()["message"]["mode"] == "full", r.text
    _chat(inv, scase, "And then?")  # still full: the full-mode turn goes back as history
    assert marker in json.dumps(fake.calls[-1]["messages"], ensure_ascii=False)
    scase.ai_mode = AIMode.REDACTED
    db.commit()
    assert _chat(inv, scase, "Next?").status_code == 200
    sent = json.dumps(fake.calls[-1]["messages"], ensure_ascii=False)
    assert marker not in sent and "Quote the letter body" not in sent
    assert "Where are the funds?" in sent  # the earlier redacted-mode turn still goes
    assert skills.history_allowed(None, AIMode.REDACTED) is False
    assert skills.history_allowed("full", "full") and skills.history_allowed("off", "redacted")


def test_skill_output_masks_service_names_the_redactor_knows(monkeypatch, client_for, db, scase):
    rows = skills.stop_order_plan(db, scase)["rows"]
    name = rows[0]["entity"]
    real = skills.redactor_for

    def masking(db_, case_, **kw):
        r = real(db_, case_, **kw)
        r.add(name, "[MASKED_SERVICE]")
        return r

    monkeypatch.setattr(skills, "redactor_for", masking)
    # a read-only member reads what the model reads: the placeholder
    ro = _access(db, scase, client_for("read_only", case=scase))
    res = skills.run_skill(db, ro, "stop-orders", "")
    assert "MASKED" in res.markdown and name not in res.markdown
    assert all(name not in (a.get("label") or "") for a in res.actions)
    # an investigator (view_restricted) reads the real name; the model's copy of the turn keeps the placeholder
    inv = _access(db, scase, client_for("investigator", case=scase))
    res = skills.run_skill(db, inv, "stop-orders", "")
    assert name in res.markdown and "MASKED" in res.model_markdown and name not in res.model_markdown
    assert "\ue000" not in res.markdown + res.model_markdown + json.dumps(res.actions)
    assert skills.stop_order_plan(db, scase)["rows"][0]["entity"] == name  # the plan keeps the real name


def test_form_fallback_without_javascript(client_for, db, scase):
    ro = client_for("read_only", case=scase)
    token = csrf_token(ro, f"/cases/{scase.id}?tab=assistant")
    r = ro.post(f"/cases/{scase.id}/assistant/chat/form", data={"csrf_token": token, "text": "/next-steps"},
                follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("?tab=assistant#assistant-chat-end")
    assert "Next steps" in ro.get(f"/cases/{scase.id}?tab=assistant").text
    assert ro.post(f"/cases/{scase.id}/assistant/chat/form", data={"text": "/help"}).status_code == 403  # no CSRF


def test_read_only_cannot_chat_in_full_mode(client_for, db, scase):
    ro = client_for("read_only", case=scase)
    token = csrf_token(ro, f"/cases/{scase.id}?tab=assistant")
    scase.ai_mode = AIMode.FULL
    db.commit()
    assert _chat(ro, scase, "/help", token=token).status_code == 403
    assert "assistant-chat-form" not in ro.get(f"/cases/{scase.id}?tab=assistant").text


def test_unknown_command_and_empty_input(client_for, db, scase):
    inv = client_for("investigator", case=scase)
    r = _chat(inv, scase, "/frobnicate now")
    assert r.status_code == 200 and "Unknown command" in r.json()["message"]["content"]
    assert _chat(inv, scase, "   ").status_code == 400
    assert _chat(inv, scase, "/wallet not-an-address!").status_code == 400
    r = _chat(inv, scase, "/wallet " + DORMANT)
    assert r.status_code == 200 and "Freeze status" in r.json()["message"]["content"]


# --------------------------------------------------------------------------- page, disclaimer, rendering
def test_disclaimer_and_subtabs_on_the_page(monkeypatch, client_for, scase):
    page = client_for("read_only", case=scase).get(f"/cases/{scase.id}?tab=assistant").text
    # no AI configured: no "AI can make mistakes" under the chat input (no AI writes the answers); the rule note instead
    under = re.search(r'id="assistant-disclaimer">([^<]*)<', page).group(1)
    assert skills.DISCLAIMER not in under and "No AI is used here" in under
    monkeypatch.setattr(providers, "get_provider", lambda: FakeProvider(reply("{}")))
    page = client_for("read_only", case=scase).get(f"/cases/{scase.id}?tab=assistant").text
    assert page.count(skills.DISCLAIMER) >= 2  # under the chat input and on the Status summary sub-tab
    assert 'id="assistant-disclaimer"' in page
    for key in ("chat", "summary", "mode"):
        assert f'id="assistant-sub-{key}"' in page
    assert 'id="assistant-sub-summary" data-sub="summary" hidden' in page
    summary = client_for("read_only", case=scase).get(f"/cases/{scase.id}?tab=assistant&sub=summary").text
    assert 'id="assistant-sub-chat" data-sub="chat" hidden' in summary
    assert "AI mode: redacted" in page and "Data path" in page
    data = json.loads(re.search(r'<script type="application/json" id="assistant-chat-data">(.*?)</script>', page,
                                re.DOTALL).group(1))
    assert {s["command"] for s in data["skills"]} >= {"/summary", "/stop-orders"} and "/le-update" not in {
        s["command"] for s in data["skills"]}
    assert 'class="assistant-chip"' in page  # initial suggestion chips


def test_model_output_is_rendered_without_html(monkeypatch, client_for, db, scase):
    evil = ("<script>alert(1)</script> <img src=x onerror=alert(2)> [click](javascript:alert(3)) "
            f"[ext](https://evil.example/x) ![p](/static/x.png) [ok](/cases/{scase.id}?tab=evidence)")
    monkeypatch.setattr(providers, "get_provider",
                        lambda: FakeProvider(reply(json.dumps({"answer": evil, "suggested_commands": []}))))
    inv = client_for("investigator", case=scase)
    r = _chat(inv, scase, "<b>bold?</b> <script>x()</script>")
    html = r.json()["html"]
    assert "<script" not in html and "<img" not in html and not re.search(r"<[^>]*onerror", html)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html and "&lt;b&gt;bold?&lt;/b&gt;" in html
    assert 'href="javascript' not in html and 'href="https://evil.example' not in html
    assert f'href="/cases/{scase.id}?tab=evidence"' in html
    page = inv.get(f"/cases/{scase.id}?tab=assistant").text
    assert "<script>alert(1)" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page


# --------------------------------------------------------------------------- migration
def test_migration_0007_up_and_down(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "0007_ai_messages")
    with engine.connect() as conn:
        insp = inspect(conn)
        assert "ai_messages" in insp.get_table_names()
        cols = {c["name"] for c in insp.get_columns("ai_messages")}
        assert cols == {"id", "case_id", "user_id", "role", "content", "skill", "source", "served_model", "mode",
                        "meta", "created_at"}
        assert {i["name"] for i in insp.get_indexes("ai_messages")} >= {"ix_ai_messages_case_user",
                                                                         "ix_ai_messages_case_id"}
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.downgrade(cfg, "0006_case_reference_ci")
    with engine.connect() as conn:
        assert "ai_messages" not in inspect(conn).get_table_names()
        assert "cases" in inspect(conn).get_table_names()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
    engine.dispose()


# --------------------------------------------------------------------------- review round: rule-based wording
def test_rows_without_a_known_mode_stay_hidden_from_a_member_without_view_restricted(client_for, db, scase):
    """visible_messages uses the same rule as history_allowed: no or an unknown stored mode counts as full."""
    ro = client_for("read_only", case=scase)
    acc = _access(db, scase, ro)
    for mode in (None, "bogus", "full", "redacted", "off"):
        db.add(AiMessage(case_id=scase.id, user_id=ro.user.id, role="assistant", content=f"mode={mode}", mode=mode))
    db.commit()
    shown = [m.content for m in skills.visible_messages(db, acc)]
    assert shown == ["mode=redacted", "mode=off"]
    api = ro.get(f"/api/cases/{scase.id}/assistant/chat").json()["messages"]
    assert [m["content"] for m in api] == ["mode=redacted", "mode=off"]


def test_follow_ups_names_the_next_stop_order_reply_not_an_internal_note(client_for, db, scase, monkeypatch):
    inv = client_for("investigator", case=scase)
    acc = _access(db, scase, inv)
    real = skills.local_context

    def ctx(db_, case_, **kw):
        c = real(db_, case_, **kw)
        c["derived"] = {**c["derived"], "status_request_due": [], "overdue": [], "upcoming_deadlines": [
            {"type": "correspondence", "id": 8, "entity": None, "kind": "follow_up", "due": "2026-10-20",
             "direction": "note"},
            {"type": "stop_order", "id": 3, "entity": "KuCoin", "kind": "freeze", "due": "2026-10-21T09:00:00+00:00"}]}
        return c

    monkeypatch.setattr(skills, "local_context", ctx)
    md = skills.run_skill(db, acc, "follow-ups", "").markdown
    assert "The next stop-order reply falls due on 21 Oct 2026" in md and "20 Oct 2026" not in md


def test_wallet_amounts_are_rounded_for_display(client_for, db, scase):
    inv = client_for("investigator", case=scase)
    acc = _access(db, scase, inv)
    run = services.latest_run(db, scase)
    victim = next(n for n in run.nodes if n.address.address_type.value == "victim")
    md = skills.run_skill(db, acc, "wallet", victim.address.address).markdown
    assert "**Outflows**" in md
    assert not re.search(r"\d\.\d{9,}", md), md
    assert "399247.92 USDC" in md
    assert skills._amount("399247.919999999983701855", "USDC") == "399247.92"
    assert skills._amount("1.1234567891", "USDT") == "1.123457"  # stablecoins: 6 dp
    assert skills._amount("0.123456789", "ETH") == "0.12345679" and skills._amount("0.123456789", "BTC") == "0.12345679"
    assert skills._amount("12.5000", "ETH") == "12.5" and skills._amount("100", "USDC") == "100"
    assert skills._amount("5.123456789", "USDC→ETH") == "5.12345679"  # a swap counts as its output asset


def test_analyze_flow_lists_splits_seen_in_the_transfers(client_for, db, scase):
    inv = client_for("investigator", case=scase)
    md = skills.run_skill(db, _access(db, scase, inv), "analyze-flow", "").markdown
    section = md.split("**Peel chains and splits**", 1)[1].split("**Gaps**", 1)[0]
    assert "sends tainted funds on to" in section, section
    # the demo's distribution hub (156.611 ETH split within 90 minutes) leads, as a rapid split
    hub = next(line for line in section.splitlines() if "Distribution hub" in line)
    assert "**distribution hub, rapid split**" in hub and "on to 12 wallets" in hub and "within 15 minutes" in hub
    assert section.index("Distribution hub") < section.index("Peel wallet")
    assert "No peel-chain or fan-out flag was raised, and no listed wallet" not in section


def test_chat_cookie_session_with_junk_authorization_still_needs_csrf(client_for, scase):
    """A session cookie plus an unrelated Authorization header must not skip the CSRF checks."""
    inv = client_for("investigator", case=scase)
    token = csrf_token(inv, f"/cases/{scase.id}?tab=assistant")
    url = f"/api/cases/{scase.id}/assistant/chat"
    assert inv.post(url, json={"text": "/help"}, headers={"Authorization": "Bearer x"}).status_code == 403
    r = inv.post(url, json={"text": "/help"}, headers={"Authorization": "Bearer x", "X-CSRF-Token": token})
    assert r.status_code == 200, r.text
