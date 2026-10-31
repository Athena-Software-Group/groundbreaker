"""Model providers for the case assistant: one small chat interface over several backends.

    provider = get_provider()            # None when AI is not configured (see resolve_provider)
    result = provider.chat(messages, json_mode=True, max_tokens=6000, temperature=0.2)
    result.text, result.served_model, result.provider_label, result.usage, result.latency_ms

`messages` are OpenAI-style ``[{"role": "system" | "user" | "assistant", "content": str}]``.

Providers (``AEGIS_LLM_PROVIDER``):

* ``hf_router`` (default): the Hugging Face Inference Router, an OpenAI-compatible API at
  ``https://router.huggingface.co/v1``. The client:
  ``POST {base_url}/chat/completions`` over httpx, ``Authorization: Bearer <token>``,
  ``X-HF-Bill-To: <org>`` when ``AEGIS_HF_BILL_TO`` is set, JSON mode through
  ``response_format={"type": "json_object"}``, up to three retries with backoff (``RETRY_DELAYS``, or the
  provider's ``Retry-After`` up to ``RETRY_AFTER_CAP``) on HTTP 429 / 502 / 503 / 504 and one on a timeout,
  and the (truncated, token-free) error body surfaced on HTTP errors. The model id pins the
  third-party inference provider (``deepseek-ai/DeepSeek-V4.1-Flash:deepinfra``), so the data path is
  fixed; the response's ``model`` field reports what actually served and is logged and audited.
* ``hf_endpoint``: a dedicated Hugging Face Inference Endpoint (TGI / vLLM) or a self-hosted
  OpenAI-compatible server; ``AEGIS_LLM_BASE_URL`` = the endpoint URL + ``/v1``. Same API.
* ``anthropic``: the Anthropic Messages API (optional, off by default; ``ANTHROPIC_API_KEY``).
* ``none``: no model; every summary and answer is rule-based.

Token: ``HF_INFERENCE_TOKEN``, else ``HF_TOKEN``, else ``LLM_API_KEY``. ``HF_API_KEY`` is never read
(it is the admin / write token for model provisioning). The token never appears in a log line, an
exception message, an audit row or a page: only "configured: yes / no" is ever reported.

Base-URL hosts are limited to ``router.huggingface.co``, ``*.endpoints.huggingface.cloud`` and
localhost (a self-hosted vLLM) unless ``AEGIS_LLM_ALLOW_ANY_HOST=1``; plain http only for localhost.

Reasoning models: ``<think>…</think>`` blocks are stripped from the answer and ``reasoning_content``
is ignored; ``REASONING_HEADROOM`` tokens are added to ``max_tokens`` so the reasoning does not eat
the answer budget.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from app.core.config import Settings

log = logging.getLogger(__name__)

PROVIDERS = ("hf_router", "hf_endpoint", "anthropic", "none")
REASONING_HEADROOM = 4096  # reasoning tokens count against max_tokens
RETRY_STATUSES = frozenset({429, 502, 503, 504})
RETRY_DELAY_SECONDS = 2.0  # before the retry after a timeout
RETRY_DELAYS = (2.0, 5.0, 10.0)  # before each retry after a 429 / 5xx
RETRY_AFTER_CAP = 20.0
ERROR_BODY_CHARS = 300
HEALTH_TIMEOUT_SECONDS = 10.0
ALLOWED_HOSTS = frozenset({"router.huggingface.co", "localhost", "127.0.0.1", "::1"})
ALLOWED_HOST_SUFFIXES = (".endpoints.huggingface.cloud",)
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
TOKEN_ENV = ("HF_INFERENCE_TOKEN", "HF_TOKEN", "LLM_API_KEY")  # never HF_API_KEY
TEST_PROMPT = "Reply with the single word OK."

# Display names of the Hugging Face inference providers (the ":suffix" of a router model id)
HF_PROVIDER_NAMES = {
    "deepinfra": "DeepInfra", "together": "Together AI", "fireworks-ai": "Fireworks AI", "novita": "Novita AI",
    "nebius": "Nebius AI", "sambanova": "SambaNova", "groq": "Groq", "cerebras": "Cerebras",
    "hyperbolic": "Hyperbolic", "featherless-ai": "Featherless AI", "nscale": "Nscale", "cohere": "Cohere",
    "hf-inference": "HF Inference", "scaleway": "Scaleway", "ovhcloud": "OVHcloud", "publicai": "Public AI",
    "zai-org": "Z.ai",
}

_sleep = time.sleep  # tests replace it


def _retry_after(resp: httpx.Response) -> float | None:
    """The provider's Retry-After in seconds (capped at RETRY_AFTER_CAP), when it sends a number."""
    try:
        v = float(resp.headers.get("retry-after", ""))
    except ValueError:
        return None
    return min(v, RETRY_AFTER_CAP) if v > 0 else None


# --------------------------------------------------------------------------- results and errors
@dataclass
class ChatResult:
    text: str
    served_model: str | None
    provider_label: str
    usage: dict = field(default_factory=dict)  # input_tokens, output_tokens, total_tokens, estimated_cost
    latency_ms: int = 0
    finish_reason: str | None = None
    attempts: int = 1


class ProviderError(Exception):
    """A failed model call. `reason` is a short code (rate_limited, timeout, connection_error,
    api_error_<status>, refusal, max_tokens, invalid_response); `message` is safe to show to an
    admin (no token, error body truncated)."""

    def __init__(self, reason: str, message: str = "", *, status: int | None = None, category: str | None = None,
                 explanation: str | None = None, usage: dict | None = None, served_model: str | None = None):
        super().__init__(message or reason)
        self.reason = reason
        self.message = message or reason
        self.status = status
        self.category = category  # refusals (anthropic)
        self.explanation = explanation  # refusals: shown to the asker only, never logged or audited
        self.usage = usage or {}
        self.served_model = served_model


class ProviderConfigError(ValueError):
    """The configuration cannot be used (host not allowed, bad URL)."""


class Provider(Protocol):
    name: str
    model: str
    label: str

    def chat(self, messages: list[dict], *, json_mode: bool = False, max_tokens: int | None = None,
             temperature: float = 0.2, schema: dict | None = None) -> ChatResult: ...


# --------------------------------------------------------------------------- configuration
def ai_disabled_by_env() -> bool:
    return os.environ.get("AEGIS_AI_DISABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    base_url: str
    model: str
    bill_to: str
    timeout: float
    max_tokens: int
    allow_any_host: bool
    token_source: str | None  # the env var the token came from (never the value)
    _token: str = field(default="", repr=False, compare=False)

    @property
    def token_configured(self) -> bool:
        return bool(self._token)

    @property
    def host(self) -> str:
        return (urlsplit(self.base_url).hostname or "").lower()


def load_config(settings: Settings | None = None) -> LLMConfig:
    """The assistant's model configuration, read fresh from the environment (and .env)."""
    s = settings or Settings()
    token, source = "", None
    for var in TOKEN_ENV:
        value = getattr(s, var.lower()).get_secret_value().strip()
        if value:
            token, source = value, var
            break
    return LLMConfig(
        provider=s.aegis_llm_provider, base_url=s.aegis_llm_base_url.strip().rstrip("/"),
        model=s.aegis_llm_model.strip(), bill_to=s.aegis_hf_bill_to.strip(), timeout=float(s.aegis_llm_timeout),
        max_tokens=int(s.aegis_llm_max_tokens), allow_any_host=_truthy(s.aegis_llm_allow_any_host),
        token_source=source, _token=token,
    )


def host_allowed(host: str) -> bool:
    host = (host or "").lower().strip("[]")
    return host in ALLOWED_HOSTS or any(host.endswith(sfx) and len(host) > len(sfx) for sfx in ALLOWED_HOST_SUFFIXES)


_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")


def check_base_url(base_url: str, *, allow_any_host: bool = False) -> str:
    """The base URL if it may be used, else ProviderConfigError (https only, except localhost)."""
    parts = urlsplit(base_url or "")
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("https", "http") or not host:
        raise ProviderConfigError("AEGIS_LLM_BASE_URL is not an http(s) URL")
    if parts.username or parts.password:
        raise ProviderConfigError("AEGIS_LLM_BASE_URL must not carry credentials")
    if not _HOST_RE.fullmatch(host) or "@" in parts.netloc:
        raise ProviderConfigError("AEGIS_LLM_BASE_URL host has invalid characters")
    if parts.scheme == "http" and host not in LOCAL_HOSTS and not allow_any_host:
        raise ProviderConfigError(f"AEGIS_LLM_BASE_URL host {host} needs https")
    if not allow_any_host and not host_allowed(host):
        raise ProviderConfigError(
            f"AEGIS_LLM_BASE_URL host {host} is not allowed (router.huggingface.co, *.endpoints.huggingface.cloud, "
            "localhost); set AEGIS_LLM_ALLOW_ANY_HOST=1 to override")
    return base_url.rstrip("/")


def hf_provider_suffix(model: str) -> str | None:
    """'org/model:deepinfra' -> 'deepinfra' (the pinned router provider), else None."""
    _, sep, suffix = (model or "").rpartition(":")
    return suffix.strip().lower() or None if sep else None


def hf_provider_name(suffix: str | None) -> str:
    if not suffix:
        return "auto-selected provider"
    return HF_PROVIDER_NAMES.get(suffix, suffix.replace("-", " ").title())


def provider_label(cfg: LLMConfig) -> str:
    """Where the data goes, for the UI and the audit log."""
    if cfg.provider == "hf_router":
        return (f"Hugging Face Inference Router → {hf_provider_name(hf_provider_suffix(cfg.model))} "
                "(third-party inference provider)")
    if cfg.provider == "hf_endpoint":
        if cfg.host in LOCAL_HOSTS:
            return f"Self-hosted OpenAI-compatible server ({cfg.host})"
        return f"Hugging Face Inference Endpoint (dedicated, {cfg.host})"
    if cfg.provider == "anthropic":
        from app.ai import client as anthropic_client

        return f"Anthropic API ({anthropic_client.MODEL})"
    return "none (rule-based only)"


def configured_model(cfg: LLMConfig) -> str | None:
    if cfg.provider in ("hf_router", "hf_endpoint"):
        return cfg.model
    if cfg.provider == "anthropic":
        from app.ai import client as anthropic_client

        return anthropic_client.MODEL
    return None


# --------------------------------------------------------------------------- helpers
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def strip_reasoning(text: str | None) -> str:
    """Drop <think>…</think> blocks, a dangling reasoning preamble ending in </think> and an
    unterminated trailing <think>."""
    t = _THINK_RE.sub("", text or "")
    low = t.lower()
    if "</think>" in low:
        t = t[low.rfind("</think>") + len("</think>"):]
        low = t.lower()
    if "<think>" in low:
        t = t[:low.find("<think>")]
    return t.strip()


_TOKEN_SHAPES = re.compile(r"(hf_[A-Za-z0-9]{8,}|sk-[A-Za-z0-9_-]{8,}|Bearer\s+\S+)")


def scrub_secret(text: str, token: str = "") -> str:
    """Remove the token (and anything token-shaped) from an error body or message."""
    out = text or ""
    if token:
        out = out.replace(token, "[REDACTED]")
    return _TOKEN_SHAPES.sub("[REDACTED]", out)


def _usage(data: dict, headers: httpx.Headers | None = None) -> dict:
    u = data.get("usage") or {}
    if not isinstance(u, dict):
        u = {}
    out: dict[str, Any] = {
        "input_tokens": u.get("prompt_tokens", u.get("input_tokens")),
        "output_tokens": u.get("completion_tokens", u.get("output_tokens")),
        "total_tokens": u.get("total_tokens"),
    }
    details = u.get("completion_tokens_details") or {}
    if isinstance(details, dict) and details.get("reasoning_tokens") is not None:
        out["reasoning_tokens"] = details.get("reasoning_tokens")
    cost = next((v for v in (u.get("estimated_cost"), u.get("cost"), u.get("total_cost"), data.get("estimated_cost"),
                             data.get("cost")) if isinstance(v, (int, float))), None)
    if cost is None and headers is not None:
        for h in ("x-inference-cost", "x-hf-cost", "x-cost"):
            try:
                cost = float(headers[h]) if h in headers else None
            except ValueError:
                cost = None
            if cost is not None:
                break
    if cost is not None:
        out["estimated_cost"] = cost
    return {k: v for k, v in out.items() if v is not None}


# --------------------------------------------------------------------------- OpenAI-compatible (HF)
class OpenAICompatProvider:
    """hf_router / hf_endpoint: OpenAI-compatible chat completions over httpx."""

    def __init__(self, cfg: LLMConfig, *, transport: httpx.BaseTransport | None = None):
        if not cfg.token_configured:
            raise ProviderConfigError("no inference token configured (HF_INFERENCE_TOKEN)")
        self.name = cfg.provider
        self.base_url = check_base_url(cfg.base_url, allow_any_host=cfg.allow_any_host)
        self.model = cfg.model
        self.label = provider_label(cfg)
        self.cfg = cfg
        self._token = cfg._token
        self._transport = transport

    def __repr__(self) -> str:  # never the token
        return f"OpenAICompatProvider(name={self.name!r}, host={self.cfg.host!r}, model={self.model!r})"

    def _headers(self) -> dict[str, str]:
        h = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json",
             "Accept": "application/json"}
        if self.cfg.bill_to:
            h["X-HF-Bill-To"] = self.cfg.bill_to
        return h

    def _client(self, timeout: float) -> httpx.Client:
        # trust_env=False: proxy env vars must not silently route model traffic around the host allowlist.
        return httpx.Client(timeout=timeout, transport=self._transport, follow_redirects=False, trust_env=False)

    def _http_error(self, resp: httpx.Response) -> ProviderError:
        try:
            body = resp.text
        except (UnicodeDecodeError, LookupError):  # pragma: no cover - undecodable body
            body = ""
        body = scrub_secret(" ".join(body.split()), self._token)[:ERROR_BODY_CHARS]
        reason = "rate_limited" if resp.status_code == 429 else f"api_error_{resp.status_code}"
        return ProviderError(reason, f"HTTP {resp.status_code} from {self.cfg.host}: {body}".rstrip(": "),
                             status=resp.status_code)

    def _post(self, payload: dict) -> tuple[httpx.Response, int]:
        """POST chat/completions; retries a 429 / 502 / 503 / 504 (RETRY_DELAYS, or Retry-After up to
        RETRY_AFTER_CAP) and a timeout once."""
        url = f"{self.base_url}/chat/completions"
        attempts = 0
        with self._client(self.cfg.timeout) as client:
            while True:
                attempts += 1
                try:
                    resp = client.post(url, json=payload, headers=self._headers())
                except httpx.TimeoutException as exc:
                    if attempts < 2:
                        log.warning("llm call to %s timed out; retrying once", self.cfg.host)
                        _sleep(RETRY_DELAY_SECONDS)
                        continue
                    raise ProviderError("timeout", f"timed out after {self.cfg.timeout:.0f}s ({self.cfg.host})") from exc
                except httpx.HTTPError as exc:
                    raise ProviderError("connection_error",
                                        f"{type(exc).__name__} reaching {self.cfg.host}") from exc
                if resp.status_code in RETRY_STATUSES and attempts <= len(RETRY_DELAYS):
                    delay = _retry_after(resp) or RETRY_DELAYS[attempts - 1]
                    log.warning("llm call to %s answered HTTP %s; retry %d in %.0fs", self.cfg.host,
                                resp.status_code, attempts, delay)
                    _sleep(delay)
                    continue
                return resp, attempts

    def chat(self, messages: list[dict], *, json_mode: bool = False, max_tokens: int | None = None,
             temperature: float = 0.2, schema: dict | None = None) -> ChatResult:
        payload: dict[str, Any] = {
            "model": self.model, "messages": messages, "temperature": temperature,
            "max_tokens": int(max_tokens or self.cfg.max_tokens) + REASONING_HEADROOM, "stream": False,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        started = time.monotonic()
        resp, attempts = self._post(payload)
        latency_ms = int((time.monotonic() - started) * 1000)
        if resp.status_code >= 400:
            err = self._http_error(resp)
            log.warning("llm call failed: provider=%s model=%s status=%s latency_ms=%d", self.name, self.model,
                        resp.status_code, latency_ms)
            raise err
        try:
            data = resp.json()
            choice = data["choices"][0]
            message = choice.get("message") or {}
            raw = message.get("content")  # reasoning_content is ignored on purpose
        except (ValueError, KeyError, IndexError, TypeError, AttributeError) as exc:
            raise ProviderError("invalid_response", f"unexpected response shape from {self.cfg.host}") from exc
        text = strip_reasoning(raw if isinstance(raw, str) else "")
        usage = _usage(data, resp.headers)
        served = data.get("model") if isinstance(data.get("model"), str) else None
        finish = choice.get("finish_reason")
        log.info("llm call: provider=%s model=%s served=%s latency_ms=%d attempts=%d input_tokens=%s "
                 "output_tokens=%s cost=%s finish=%s", self.name, self.model, served, latency_ms, attempts,
                 usage.get("input_tokens"), usage.get("output_tokens"), usage.get("estimated_cost"), finish)
        if not text and finish == "length":
            raise ProviderError("max_tokens", "the answer was cut off (max_tokens)", usage=usage, served_model=served)
        return ChatResult(text=text, served_model=served, provider_label=self.label, usage=usage,
                          latency_ms=latency_ms, finish_reason=finish, attempts=attempts)

    def list_models(self) -> dict:
        """Health check: GET {base_url}/models (10 s). Whether the configured model is listed and which
        router providers serve it."""
        base_id = self.model.split(":", 1)[0]
        wanted = hf_provider_suffix(self.model) if self.name == "hf_router" else None
        started = time.monotonic()
        try:
            with self._client(HEALTH_TIMEOUT_SECONDS) as client:
                resp = client.get(f"{self.base_url}/models", headers=self._headers())
        except httpx.TimeoutException as exc:
            raise ProviderError("timeout", f"timed out after {HEALTH_TIMEOUT_SECONDS:.0f}s ({self.cfg.host})") from exc
        except httpx.HTTPError as exc:
            raise ProviderError("connection_error", f"{type(exc).__name__} reaching {self.cfg.host}") from exc
        latency_ms = int((time.monotonic() - started) * 1000)
        if resp.status_code >= 400:
            raise self._http_error(resp)
        try:
            rows = resp.json().get("data") or []
        except (ValueError, AttributeError) as exc:
            raise ProviderError("invalid_response", f"unexpected /models response from {self.cfg.host}") from exc
        row = next((r for r in rows if isinstance(r, dict) and r.get("id") in (self.model, base_id)), None)
        providers = []
        for p in (row or {}).get("providers") or []:
            if isinstance(p, dict) and p.get("provider"):
                providers.append({"provider": str(p.get("provider")), "status": p.get("status"),
                                  "pricing": p.get("pricing") if isinstance(p.get("pricing"), dict) else None,
                                  "context_length": p.get("context_length")})
        return {"listed": row is not None, "model_id": base_id, "models_count": len(rows), "providers": providers,
                "pinned_provider": wanted,
                "pinned_provider_listed": (wanted in {p["provider"] for p in providers}) if wanted else None,
                "latency_ms": latency_ms}


# --------------------------------------------------------------------------- Anthropic (optional)
class AnthropicProvider:
    """The Anthropic Messages API (claude-opus-5-5, adaptive thinking, server-side refusal fallback).
    Optional and off by default (AEGIS_LLM_PROVIDER=anthropic)."""

    name = "anthropic"

    def __init__(self, client: Any):
        from app.ai import client as anthropic_client

        self._client = client
        self.model = anthropic_client.MODEL
        self.label = f"Anthropic API ({self.model})"

    def __repr__(self) -> str:
        return f"AnthropicProvider(model={self.model!r})"

    @staticmethod
    def _split(messages: list[dict]) -> tuple[list[dict], list[dict]]:
        system = [{"type": "text", "text": m["content"]} for m in messages if m["role"] == "system"]
        turns = [{"role": m["role"], "content": m["content"]} for m in messages if m["role"] != "system"]
        if system:
            system[-1]["cache_control"] = {"type": "ephemeral"}
        if turns and isinstance(turns[0]["content"], str):  # the case context: cached for follow-up questions
            turns[0] = {"role": turns[0]["role"], "content": [
                {"type": "text", "text": turns[0]["content"], "cache_control": {"type": "ephemeral"}}]}
        return system, turns

    def chat(self, messages: list[dict], *, json_mode: bool = False, max_tokens: int | None = None,
             temperature: float = 0.2, schema: dict | None = None) -> ChatResult:
        import anthropic

        from app.ai import client as anthropic_client

        output_config: dict[str, Any] = {"effort": anthropic_client.EFFORT}
        if json_mode and schema is not None:
            try:
                output_config["format"] = {"type": "json_schema", "schema": anthropic.transform_schema(schema)}
            except Exception as exc:  # noqa: BLE001 - a shape the SDK cannot transform ("string" | "null" unions):
                # JSON by instruction only, the caller validates the answer
                log.warning("anthropic: schema not transformable (%s); JSON by instruction", type(exc).__name__)
        system, turns = self._split(messages)
        started = time.monotonic()
        try:
            resp = self._client.beta.messages.create(
                model=self.model, max_tokens=anthropic_client.MAX_TOKENS, betas=[anthropic_client.FALLBACK_BETA],
                fallbacks="default", thinking={"type": "adaptive"}, output_config=output_config, system=system,
                messages=turns,
            )
        except anthropic.RateLimitError as exc:
            raise ProviderError("rate_limited", "HTTP 429 from the Anthropic API", status=429) from exc
        except anthropic.APIConnectionError as exc:  # includes APITimeoutError
            raise ProviderError("connection_error", "the Anthropic API could not be reached") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"api_error_{exc.status_code}", f"HTTP {exc.status_code} from the Anthropic API",
                                status=exc.status_code) from exc
        except anthropic.AnthropicError as exc:
            raise ProviderError(type(exc).__name__.lower(), type(exc).__name__) from exc
        latency_ms = int((time.monotonic() - started) * 1000)
        u = getattr(resp, "usage", None)
        usage = {} if u is None else {k: v for k, v in {
            "input_tokens": getattr(u, "input_tokens", None), "output_tokens": getattr(u, "output_tokens", None),
            "cache_read_tokens": getattr(u, "cache_read_input_tokens", None),
            "cache_write_tokens": getattr(u, "cache_creation_input_tokens", None)}.items() if v is not None}
        served = getattr(resp, "model", None)
        stop = getattr(resp, "stop_reason", None)
        if stop == "refusal":  # the whole fallback chain declined: content is not usable
            details = getattr(resp, "stop_details", None)
            explanation = getattr(details, "explanation", None)
            raise ProviderError("refusal", "the model declined", category=getattr(details, "category", None),
                                explanation=explanation if isinstance(explanation, str) else None, usage=usage,
                                served_model=served)
        if stop == "max_tokens":
            raise ProviderError("max_tokens", "the answer was cut off (max_tokens)", usage=usage, served_model=served)
        blocks = list(getattr(resp, "content", None) or [])
        last = max((i for i, b in enumerate(blocks) if getattr(b, "type", None) == "fallback"), default=-1)
        text = "".join(b.text for b in blocks[last + 1:] if getattr(b, "type", None) == "text")
        log.info("llm call: provider=anthropic model=%s served=%s latency_ms=%d input_tokens=%s output_tokens=%s",
                 self.model, served, latency_ms, usage.get("input_tokens"), usage.get("output_tokens"))
        return ChatResult(text=text, served_model=served, provider_label=self.label, usage=usage,
                          latency_ms=latency_ms, finish_reason=stop)


# --------------------------------------------------------------------------- resolution
def resolve_provider(cfg: LLMConfig | None = None, *,
                     transport: httpx.BaseTransport | None = None) -> tuple[Provider | None, str | None]:
    """(provider, None) or (None, reason): disabled | provider_none | not_configured | host_not_allowed."""
    if ai_disabled_by_env():
        return None, "disabled"
    cfg = cfg or load_config()
    if cfg.provider == "none":
        return None, "provider_none"
    if cfg.provider == "anthropic":
        from app.ai import client as anthropic_client

        client = anthropic_client.get_client()
        return (AnthropicProvider(client), None) if client is not None else (None, "not_configured")
    if not cfg.token_configured:
        return None, "not_configured"
    try:
        return OpenAICompatProvider(cfg, transport=transport), None
    except ProviderConfigError as exc:
        log.warning("llm provider refused: %s", exc)
        return None, "host_not_allowed"


def get_provider() -> Provider | None:
    """The configured provider, or None (the assistant then answers rule-based). Tests replace it."""
    return resolve_provider()[0]


def describe(cfg: LLMConfig | None = None) -> dict:
    """What the admin page and the Assistant tab may show: never the token, nor any part of it."""
    cfg = cfg or load_config()
    host_ok, host_error = True, None
    if cfg.provider in ("hf_router", "hf_endpoint"):
        try:
            check_base_url(cfg.base_url, allow_any_host=cfg.allow_any_host)
        except ProviderConfigError as exc:
            host_ok, host_error = False, str(exc)
    token_configured = cfg.token_configured
    if cfg.provider == "anthropic":
        token_configured = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    return {
        "provider": cfg.provider, "label": provider_label(cfg), "base_url_host": cfg.host or None,
        "model": configured_model(cfg), "bill_to": cfg.bill_to or None, "token_configured": token_configured,
        "token_source": cfg.token_source if cfg.provider in ("hf_router", "hf_endpoint") else None,
        "kill_switch": ai_disabled_by_env(), "host_allowed": host_ok, "host_error": host_error,
        "allow_any_host": cfg.allow_any_host, "timeout": cfg.timeout, "max_tokens": cfg.max_tokens,
        "third_party": cfg.provider == "hf_router",
    }
