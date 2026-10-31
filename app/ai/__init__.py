"""Case assistant: AI status summaries and Q&A over a case, governed by `Case.ai_mode`.

* `app.ai.context` builds what may leave Aegis for a case (`off` | `redacted` | `full`).
* `app.ai.rules` is the deterministic, offline fallback over the same context.
* `app.ai.assistant` calls the model (`summarize_case`, `ask`), audits every call and stores
  the latest summary on the case.
* `app.ai.providers` is the model interface: the Hugging Face Inference Router (default,
  OpenAI-compatible), a dedicated HF Inference Endpoint, the optional Anthropic API, or
  none (`get_provider()` is None when AI is not configured).
* `app.ai.client` resolves the Anthropic SDK client for the optional `anthropic` provider.

docs/data-handling.md §6 applies: in the default `redacted` mode only chain data, trace
statistics and metadata reach the model (a third-party inference provider via the HF router by default); people, references, letter bodies and evidence
content never do.
"""
