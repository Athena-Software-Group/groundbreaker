"""Model providers (app/ai/providers.py) and the admin AI settings page (app/web/routes_admin_ai.py).

No test reaches the network: the OpenAI-compatible provider runs over httpx.MockTransport, the
Anthropic SDK client is a fake. The token below is a fake that is not shaped like a real one."""

from __future__ import annotations

import json
import logging

import httpx
import pytest
from anthropic.types.beta import BetaMessage
from conftest import csrf_token
from sqlalchemy import select

from app.ai import assistant as ai
from app.ai import client as ai_client
from app.ai import providers
from app.ai.providers import (
    REASONING_HEADROOM,
    AnthropicProvider,
    LLMConfig,
    OpenAICompatProvider,
    ProviderConfigError,
    ProviderError,
)
from app.db.models import AuditEvent

TOKEN = "test-token-NOT-REAL-7d1c55"
SERVED = "deepseek-ai/DeepSeek-V4.1-Flash"
MODEL = "deepseek-ai/DeepSeek-V4.1-Flash:deepinfra"
LABEL = "Hugging Face Inference Router → DeepInfra (third-party inference provider)"


def cfg(**over) -> LLMConfig:
    base = {"provider": "hf_router", "base_url": "https://router.huggingface.co/v1", "model": MODEL,
            "bill_to": "example-org", "timeout": 5.0, "max_tokens": 6000, "allow_any_host": False,
            "token_source": "HF_INFERENCE_TOKEN", "_token": TOKEN}
    base.update(over)
    return LLMConfig(**base)


def completion(content: str, *, model: str = SERVED, usage: dict | None = None, finish: str = "stop",
               reasoning: str | None = None) -> dict:
    message = {"role": "assistant", "content": content}
    if reasoning is not None:
        message["reasoning_content"] = reasoning
    return {"id": "chatcmpl-test", "object": "chat.completion", "model": model,
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": usage if usage is not None else {"prompt_tokens": 900, "completion_tokens": 120,
                                                      "total_tokens": 1020, "cost": 0.00031}}


class Recorder:
    """A MockTransport handler serving queued responses and recording the requests."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        if isinstance(r, httpx.Response):
            return r
        return httpx.Response(200, json=r)

    def bodies(self) -> list[dict]:
        return [json.loads(r.content) for r in self.requests]


def provider(rec: Recorder, **over) -> OpenAICompatProvider:
    return OpenAICompatProvider(cfg(**over), transport=httpx.MockTransport(rec))


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(providers, "_sleep", sleeps.append)
    return sleeps


# --------------------------------------------------------------------------- OpenAI-compatible provider
def test_success_sends_openai_compat_request_and_reports_served_model():
    rec = Recorder(completion("Hello"))
    res = provider(rec).chat([{"role": "user", "content": "hi"}], json_mode=True, temperature=0.1)
    (req,) = rec.requests
    assert req.method == "POST" and str(req.url) == "https://router.huggingface.co/v1/chat/completions"
    assert req.headers["authorization"] == f"Bearer {TOKEN}"
    assert req.headers["x-hf-bill-to"] == "example-org"
    body = rec.bodies()[0]
    assert body["model"] == MODEL and body["messages"] == [{"role": "user", "content": "hi"}]
    assert body["response_format"] == {"type": "json_object"} and body["temperature"] == 0.1
    assert body["max_tokens"] == 6000 + REASONING_HEADROOM and body["stream"] is False
    assert res.text == "Hello" and res.served_model == SERVED and res.provider_label == LABEL
    assert res.usage == {"input_tokens": 900, "output_tokens": 120, "total_tokens": 1020, "estimated_cost": 0.00031}
    assert res.latency_ms >= 0 and res.attempts == 1 and res.finish_reason == "stop"


def test_plain_text_mode_and_no_bill_to_header_when_unset():
    rec = Recorder(completion("plain"))
    provider(rec, bill_to="").chat([{"role": "user", "content": "hi"}], json_mode=False, max_tokens=16)
    body = rec.bodies()[0]
    assert "response_format" not in body and body["max_tokens"] == 16 + REASONING_HEADROOM
    assert "x-hf-bill-to" not in rec.requests[0].headers


def test_think_blocks_are_stripped_and_reasoning_content_ignored():
    rec = Recorder(completion("<think>secret chain of thought</think>\n\nOK", reasoning="more reasoning"))
    res = provider(rec).chat([{"role": "user", "content": "x"}])
    assert res.text == "OK"
    assert providers.strip_reasoning("lead-in reasoning</think>answer") == "answer"
    assert providers.strip_reasoning("answer<think>cut off reasoning") == "answer"
    assert providers.strip_reasoning("<THINK>a</THINK>b<think>c</think>d") == "bd"


@pytest.mark.parametrize("first", [httpx.Response(503, text="busy"), httpx.Response(429, text="slow"),
                                   httpx.Response(502), httpx.Response(504), httpx.ReadTimeout("slow")])
def test_transient_error_is_retried_then_succeeds(first, _no_sleep):
    rec = Recorder(first, completion("OK"))
    res = provider(rec).chat([{"role": "user", "content": "x"}])
    assert res.text == "OK" and res.attempts == 2 and len(rec.requests) == 2
    assert _no_sleep == [providers.RETRY_DELAY_SECONDS if isinstance(first, Exception) else providers.RETRY_DELAYS[0]]


def test_rate_limit_backs_off_three_times_then_gives_up(_no_sleep):
    rec = Recorder(httpx.Response(429, json={"error": "rate limited"}))
    with pytest.raises(ProviderError) as exc:
        provider(rec).chat([{"role": "user", "content": "x"}])
    assert exc.value.reason == "rate_limited" and exc.value.status == 429 and len(rec.requests) == 4
    assert _no_sleep == list(providers.RETRY_DELAYS)


def test_rate_limit_waits_for_retry_after_capped(_no_sleep):
    rec = Recorder(httpx.Response(429, headers={"retry-after": "7"}), httpx.Response(503, headers={"retry-after": "600"}),
                   httpx.Response(429, headers={"retry-after": "soon"}), completion("OK"))
    res = provider(rec).chat([{"role": "user", "content": "x"}])
    assert res.text == "OK" and res.attempts == 4
    assert _no_sleep == [7.0, providers.RETRY_AFTER_CAP, providers.RETRY_DELAYS[2]]


def test_timeout_twice_gives_up_after_one_retry():
    rec = Recorder(httpx.ConnectTimeout("no route"))
    with pytest.raises(ProviderError) as exc:
        provider(rec).chat([{"role": "user", "content": "x"}])
    assert exc.value.reason == "timeout" and len(rec.requests) == 2


def test_http_error_surfaces_a_truncated_token_free_body(caplog):
    echo = {"error": f"Invalid credentials in header: Bearer {TOKEN}; also hf_FAKE0000000000000000 " + "x" * 800}
    rec = Recorder(httpx.Response(401, json=echo))
    caplog.set_level(logging.DEBUG)
    with pytest.raises(ProviderError) as exc:
        provider(rec).chat([{"role": "user", "content": "x"}])
    err = exc.value
    assert err.reason == "api_error_401" and err.status == 401 and len(rec.requests) == 1  # 401 is not retried
    assert err.message.startswith("HTTP 401 from router.huggingface.co: ") and "Invalid credentials" in err.message
    assert len(err.message) < providers.ERROR_BODY_CHARS + 60
    for text in (err.message, str(err), repr(err), caplog.text):
        assert TOKEN not in text and "hf_FAKE" not in text


def test_connection_error_is_reported_without_details():
    rec = Recorder(httpx.ConnectError("dns failure"))
    with pytest.raises(ProviderError) as exc:
        provider(rec).chat([{"role": "user", "content": "x"}])
    assert exc.value.reason == "connection_error" and len(rec.requests) == 1


def test_cut_off_empty_answer_is_max_tokens():
    rec = Recorder(completion("<think>long", finish="length"))
    with pytest.raises(ProviderError) as exc:
        provider(rec).chat([{"role": "user", "content": "x"}])
    assert exc.value.reason == "max_tokens" and exc.value.served_model == SERVED


def test_unexpected_shape_is_invalid_response():
    rec = Recorder({"unexpected": True})
    with pytest.raises(ProviderError) as exc:
        provider(rec).chat([{"role": "user", "content": "x"}])
    assert exc.value.reason == "invalid_response"


def test_host_allowlist(monkeypatch):
    monkeypatch.delenv("AEGIS_AI_DISABLED")
    for url in ("https://router.huggingface.co/v1", "https://abc123.us-east-1.aws.endpoints.huggingface.cloud/v1",
                "http://localhost:8000/v1", "http://127.0.0.1:8000/v1"):
        assert providers.check_base_url(url) == url
    for url in ("https://api.evil.example/v1", "https://router.huggingface.co.evil.example/v1",
                "https://endpoints.huggingface.cloud/v1", "http://router.huggingface.co/v1", "ftp://localhost/v1",
                "https://user:pw@router.huggingface.example/v1", "https://user:pw@localhost/v1", "not a url"):
        with pytest.raises(ProviderConfigError):
            providers.check_base_url(url)
    assert providers.check_base_url("https://llm.internal.example/v1", allow_any_host=True)
    with pytest.raises(ProviderConfigError):
        OpenAICompatProvider(cfg(base_url="https://api.evil.example/v1"))
    p, why = providers.resolve_provider(cfg(base_url="https://api.evil.example/v1"))
    assert p is None and why == "host_not_allowed"
    p, why = providers.resolve_provider(cfg(base_url="https://api.evil.example/v1", allow_any_host=True))
    assert p is not None and why is None


def test_resolution_kill_switch_provider_none_and_missing_token(monkeypatch):
    assert providers.resolve_provider(cfg()) == (None, "disabled")  # conftest sets AEGIS_AI_DISABLED=1
    monkeypatch.delenv("AEGIS_AI_DISABLED")
    assert providers.resolve_provider(cfg(provider="none")) == (None, "provider_none")
    assert providers.resolve_provider(cfg(_token="", token_source=None)) == (None, "not_configured")
    p, why = providers.resolve_provider(cfg())
    assert isinstance(p, OpenAICompatProvider) and why is None and p.label == LABEL
    monkeypatch.setattr(ai_client, "get_client", lambda: None)
    assert providers.resolve_provider(cfg(provider="anthropic")) == (None, "not_configured")


def test_token_resolution_order_never_reads_hf_api_key(monkeypatch):
    for var in ("HF_INFERENCE_TOKEN", "HF_TOKEN", "LLM_API_KEY", "HF_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HF_API_KEY", "admin-write-token-NOT-REAL")
    c = providers.load_config()
    assert not c.token_configured and c.token_source is None
    monkeypatch.setenv("LLM_API_KEY", "llm-NOT-REAL")
    assert providers.load_config().token_source == "LLM_API_KEY"
    monkeypatch.setenv("HF_TOKEN", "hftoken-NOT-REAL")
    assert providers.load_config().token_source == "HF_TOKEN"
    monkeypatch.setenv("HF_INFERENCE_TOKEN", TOKEN)
    c = providers.load_config()
    assert c.token_source == "HF_INFERENCE_TOKEN" and c.token_configured
    assert c.provider == "hf_router" and c.base_url == "https://router.huggingface.co/v1" and c.model == MODEL
    assert c.timeout == 120.0 and c.max_tokens == 6000 and c.bill_to == ""
    assert TOKEN not in repr(c) and TOKEN not in repr(OpenAICompatProvider(c))
    assert TOKEN not in json.dumps(providers.describe(c), default=str)
    monkeypatch.setenv("AEGIS_HF_BILL_TO", "example-org")
    monkeypatch.setenv("AEGIS_LLM_PROVIDER", "hf_endpoint")
    monkeypatch.setenv("AEGIS_LLM_BASE_URL", "https://abc.eu-west-1.aws.endpoints.huggingface.cloud/v1/")
    c = providers.load_config()
    assert c.bill_to == "example-org" and c.base_url.endswith("/v1") and providers.provider_label(c) == (
        "Hugging Face Inference Endpoint (dedicated, abc.eu-west-1.aws.endpoints.huggingface.cloud)")


def test_provider_labels():
    assert providers.provider_label(cfg()) == LABEL
    assert "Together AI" in providers.provider_label(cfg(model="org/m:together"))
    assert "auto-selected provider" in providers.provider_label(cfg(model="org/m"))
    assert providers.provider_label(cfg(provider="hf_endpoint", base_url="http://localhost:8000/v1")).startswith(
        "Self-hosted")


def test_list_models_health_check():
    rec = Recorder({"object": "list", "data": [
        {"id": "other/model", "providers": [{"provider": "together", "status": "live"}]},
        {"id": SERVED, "providers": [{"provider": "deepinfra", "status": "live", "pricing": {"input": 0.1}},
                                     {"provider": "novita", "status": "staging"}]}]})
    out = provider(rec).list_models()
    assert str(rec.requests[0].url) == "https://router.huggingface.co/v1/models" and rec.requests[0].method == "GET"
    assert out["listed"] and out["model_id"] == SERVED and out["pinned_provider"] == "deepinfra"
    assert out["pinned_provider_listed"] is True and [p["provider"] for p in out["providers"]] == ["deepinfra", "novita"]
    rec = Recorder({"object": "list", "data": []})
    assert provider(rec).list_models()["listed"] is False


# --------------------------------------------------------------------------- end to end through the assistant
def test_summary_over_mock_transport_records_served_model_and_bill_to(monkeypatch, db, case):
    from tests.test_assistant import summary_json

    fenced = "```json\n" + summary_json() + "\n```"
    rec = Recorder(completion("<think>reasoning</think>" + fenced, model="deepseek-ai/DeepSeek-V4.1-Flash-served"))
    p = provider(rec)
    monkeypatch.setattr(providers, "get_provider", lambda: p)
    try:
        out = ai.summarize_case(db, case)
        assert out["meta"]["source"] == "ai" and out["meta"]["served_model"] == "deepseek-ai/DeepSeek-V4.1-Flash-served"
        req = rec.requests[0]
        assert req.headers["x-hf-bill-to"] == "example-org" and rec.bodies()[0]["response_format"] == {"type": "json_object"}
        db.expire_all()
        ev = db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id, AuditEvent.action == "AI_QUERY")
                        .order_by(AuditEvent.id.desc())).first()
        d = ev.detail
        assert d["served_model"] == "deepseek-ai/DeepSeek-V4.1-Flash-served" and d["model"] == MODEL
        assert d["provider"] == "hf_router" and d["provider_label"] == LABEL and d["estimated_cost"] == 0.00031
        assert d["input_tokens"] == 900 and d["output_tokens"] == 120 and isinstance(d["latency_ms"], int)
        assert TOKEN not in json.dumps(d)
    finally:
        from app.ai.context import SUMMARY_FACTS_KEY

        case.status_summary = None
        case.facts = {k: v for k, v in (case.facts or {}).items() if k != SUMMARY_FACTS_KEY}
        db.commit()


def test_repair_over_mock_transport(monkeypatch, db, case):
    from tests.test_assistant import summary_json

    rec = Recorder(completion('{"status_summary": "incomplete"}'), completion(summary_json()))
    p = provider(rec)
    monkeypatch.setattr(providers, "get_provider", lambda: p)
    try:
        out = ai.summarize_case(db, case)
        assert out["meta"]["source"] == "ai" and len(rec.requests) == 2
        repair_msgs = rec.bodies()[1]["messages"]
        assert repair_msgs[-2] == {"role": "assistant", "content": '{"status_summary": "incomplete"}'}
        assert "schema validation failed" in repair_msgs[-1]["content"] and "key_facts" in repair_msgs[-1]["content"]
    finally:
        from app.ai.context import SUMMARY_FACTS_KEY

        case.status_summary = None
        case.facts = {k: v for k, v in (case.facts or {}).items() if k != SUMMARY_FACTS_KEY}
        db.commit()


# --------------------------------------------------------------------------- Anthropic provider (optional)
def message(text: str | None = "ok", *, stop_reason: str = "end_turn", stop_details: dict | None = None,
            content: list | None = None) -> BetaMessage:
    blocks = content if content is not None else ([{"type": "text", "text": text}] if text is not None else [])
    return BetaMessage.model_validate({
        "id": "msg_test", "type": "message", "role": "assistant", "model": ai_client.MODEL, "content": blocks,
        "stop_reason": stop_reason, "stop_details": stop_details,
        "usage": {"input_tokens": 1234, "output_tokens": 321, "cache_read_input_tokens": 900,
                  "cache_creation_input_tokens": 0},
    })


class FakeAnthropic:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[dict] = []
        outer = self

        class _Messages:
            def create(self, **kwargs):
                outer.calls.append(kwargs)
                r = outer.responses.pop(0) if len(outer.responses) > 1 else outer.responses[0]
                if isinstance(r, Exception):
                    raise r
                return r

        self.beta = type("Beta", (), {"messages": _Messages()})()


MSGS = [{"role": "system", "content": "SYSTEM"}, {"role": "user", "content": "<case_context>{}</case_context>"},
        {"role": "user", "content": "TASK: status_summary"}]


def test_anthropic_provider_request_shape():
    fake = FakeAnthropic(message('{"a": 1}'))
    res = AnthropicProvider(fake).chat(MSGS, json_mode=True, schema=ai.summary_schema())
    kw = fake.calls[0]
    assert kw["model"] == "claude-opus-5-5" and kw["betas"] == ["server-side-fallback-2026-07-01"]
    assert kw["fallbacks"] == "default" and kw["thinking"] == {"type": "adaptive"}
    assert kw["output_config"]["effort"] == "medium" and kw["output_config"]["format"]["type"] == "json_schema"
    assert set(kw["output_config"]["format"]["schema"]["required"]) >= {"status_summary", "funds_position"}
    assert kw["system"] == [{"type": "text", "text": "SYSTEM", "cache_control": {"type": "ephemeral"}}]
    assert kw["messages"][0]["content"][0]["cache_control"] == {"type": "ephemeral"}
    assert [m["role"] for m in kw["messages"]] == ["user", "user"]
    assert res.text == '{"a": 1}' and res.served_model == "claude-opus-5-5"
    assert res.usage["input_tokens"] == 1234 and res.usage["cache_read_tokens"] == 900
    plain = FakeAnthropic(message("answer"))
    AnthropicProvider(plain).chat(MSGS, json_mode=False)
    assert "format" not in plain.calls[0]["output_config"]


def test_anthropic_text_after_fallback_block_and_refusal():
    content = [{"type": "fallback", "from": {"model": "claude-opus-5-5"}, "to": {"model": "claude-opus-4-8"},
                "trigger": {"type": "refusal", "category": "cyber"}},
               {"type": "text", "text": "served by the fallback"}]
    assert AnthropicProvider(FakeAnthropic(message(content=content))).chat(MSGS).text == "served by the fallback"
    refused = message(content=[{"type": "text", "text": "PARTIAL"}], stop_reason="refusal",
                      stop_details={"type": "refusal", "category": "cyber", "explanation": "declined"})
    with pytest.raises(ProviderError) as exc:
        AnthropicProvider(FakeAnthropic(refused)).chat(MSGS)
    assert exc.value.reason == "refusal" and exc.value.category == "cyber" and exc.value.usage["input_tokens"] == 1234


def test_anthropic_sdk_errors_map_to_reasons():
    import anthropic
    import httpx2

    req = httpx2.Request("POST", "https://api.anthropic.example/v1/messages")
    cases = [(anthropic.RateLimitError("slow", response=httpx2.Response(429, request=req), body=None), "rate_limited"),
             (anthropic.APIConnectionError(request=req), "connection_error"),
             (anthropic.InternalServerError("boom", response=httpx2.Response(500, request=req), body=None),
              "api_error_500")]
    for exc_in, reason in cases:
        with pytest.raises(ProviderError) as exc:
            AnthropicProvider(FakeAnthropic(exc_in)).chat(MSGS)
        assert exc.value.reason == reason


# --------------------------------------------------------------------------- /admin/ai
class _FakeOK:
    name, model, label = "hf_router", MODEL, LABEL

    def __init__(self):
        self.calls = []

    def chat(self, messages, **kw):
        self.calls.append((messages, kw))
        return providers.ChatResult(text="OK", served_model=SERVED, provider_label=LABEL,
                                    usage={"input_tokens": 12, "output_tokens": 1, "estimated_cost": 0.000004},
                                    latency_ms=321)

    def list_models(self):
        return {"listed": True, "model_id": SERVED, "models_count": 3, "pinned_provider": "deepinfra",
                "pinned_provider_listed": True, "latency_ms": 45,
                "providers": [{"provider": "deepinfra", "status": "live", "pricing": None, "context_length": None}]}


def test_admin_ai_is_system_admin_only(client_for, case):
    for role in ("admin", "investigator", "read_only"):
        c = client_for(role, case=case)
        assert c.get("/admin/ai").status_code == 403, role
    sysadmin = client_for(None, system_admin=True)
    page = sysadmin.get("/admin/ai")
    assert page.status_code == 200 and "AI settings" in page.text and page.headers["cache-control"] == "no-store"
    assert "router.huggingface.co" in page.text and MODEL in page.text and LABEL in page.text
    assert "Kill switch <b>AEGIS_AI_DISABLED</b> is on" in page.text  # conftest forces it
    assert 'href="/admin/ai"' in page.text
    assert sysadmin.post("/admin/ai/test", data={}).status_code == 403  # CSRF


def test_admin_ai_shows_token_presence_never_its_value(monkeypatch, client_for):
    monkeypatch.setenv("HF_INFERENCE_TOKEN", TOKEN)
    monkeypatch.setenv("AEGIS_HF_BILL_TO", "example-org")
    page = client_for(None, system_admin=True).get("/admin/ai").text
    assert TOKEN not in page and TOKEN[:8] not in page and TOKEN[-6:] not in page
    assert "from HF_INFERENCE_TOKEN" in page and "example-org" in page


def test_admin_ai_test_connection_and_health_mocked(monkeypatch, client_for, db):
    fake = _FakeOK()
    monkeypatch.setattr(providers, "get_provider", lambda: fake)
    c = client_for(None, system_admin=True)
    token = csrf_token(c, "/admin/ai")
    r = c.post("/admin/ai/test", data={"csrf_token": token})
    assert r.status_code == 200 and 'id="ai-test-result"' in r.text
    assert SERVED in r.text and "321 ms" in r.text and "$0.000004" in r.text
    (messages, kw), = fake.calls
    assert messages == [{"role": "user", "content": "Reply with the single word OK."}] and kw["json_mode"] is False
    ev = db.scalars(select(AuditEvent).where(AuditEvent.action == "AI_TEST_CONNECTION")
                    .order_by(AuditEvent.id.desc())).first()
    assert ev.detail["ok"] is True and ev.detail["served_model"] == SERVED and ev.detail["latency_ms"] == 321
    assert ev.detail["estimated_cost"] == 0.000004 and ev.case_id is None
    r = c.post("/admin/ai/health", data={"csrf_token": token})
    assert r.status_code == 200 and 'id="ai-health-result"' in r.text and "serves it" in r.text
    assert db.scalars(select(AuditEvent).where(AuditEvent.action == "AI_HEALTH_CHECK")).first().detail["listed"]


def test_admin_ai_test_connection_error_is_token_free(monkeypatch, client_for):
    rec = Recorder(httpx.Response(401, json={"error": f"bad token {TOKEN}"}))
    p = provider(rec)
    monkeypatch.setattr(providers, "get_provider", lambda: p)
    c = client_for(None, system_admin=True)
    r = c.post("/admin/ai/test", data={"csrf_token": csrf_token(c, "/admin/ai")})
    assert r.status_code == 200 and "HTTP 401 from router.huggingface.co" in r.text and TOKEN not in r.text


def test_admin_ai_test_without_provider(client_for):
    c = client_for(None, system_admin=True)
    r = c.post("/admin/ai/test", data={"csrf_token": csrf_token(c, "/admin/ai")})
    assert r.status_code == 200 and "kill switch AEGIS_AI_DISABLED is on" in r.text


@pytest.mark.parametrize("url", [
    "https://evil.com\\.endpoints.huggingface.cloud/v1",
    "https://evil.com%2f.endpoints.huggingface.cloud/v1",
    "https://ev il.endpoints.huggingface.cloud/v1",
])
def test_base_url_rejects_odd_host_characters(url):
    with pytest.raises(providers.ProviderConfigError):
        providers.check_base_url(url)
