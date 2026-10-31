"""Anthropic client resolution for the optional `anthropic` provider (app.ai.providers).

Used only when AEGIS_LLM_PROVIDER=anthropic (the default provider is the Hugging Face Inference
Router). `get_client()` returns a configured `anthropic.Anthropic` or None. None means "AI not
configured" and the assistant answers with the rule-based fallback instead. That happens when:

* `AEGIS_AI_DISABLED` is set to 1/true/yes (CI, demos, air-gapped installs);
* the `anthropic` package is not installed;
* the SDK resolves no credential (no `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`, no profile,
  no workload-identity federation), or resolution raises.

Tests replace `get_client` (monkeypatch `app.ai.client.get_client`) or the provider
(`app.ai.providers.get_provider`); they never reach the network.
"""

from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger(__name__)

MODEL = "claude-opus-5-5"
# server-side refusal fallback, scalar "default" form (the array form uses a different header)
FALLBACK_BETA = "server-side-fallback-2026-07-01"
EFFORT = "medium"
TIMEOUT_SECONDS = 300.0
MAX_RETRIES = 2  # the SDK retries 408/409/429/5xx and connection errors with backoff
MAX_TOKENS = 16000  # adaptive thinking counts against this


def ai_disabled_by_env() -> bool:
    return os.environ.get("AEGIS_AI_DISABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def get_client() -> Any | None:
    """A ready `anthropic.Anthropic`, or None when AI is not configured (see module docstring)."""
    if ai_disabled_by_env():
        return None
    try:
        import anthropic
    except ImportError:  # pragma: no cover - requirements.txt installs it
        return None
    try:
        client = anthropic.Anthropic(max_retries=MAX_RETRIES, timeout=TIMEOUT_SECONDS)
    except (anthropic.AnthropicError, TypeError, ValueError, OSError) as exc:
        log.warning("anthropic client not configured: %s", type(exc).__name__)
        return None
    if not (client.api_key or client.auth_token or getattr(client, "credentials", None) is not None):
        return None
    return client
