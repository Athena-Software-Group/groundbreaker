"""What a member reads of the assistant's text, and what goes back to the model.

    shown(text, reveal=True)    # the screen: masks resolved (real values when allowed), source tags hidden
    sent(text)                  # the model: placeholders, source tags kept

The rule checks end each statement with a source tag naming the context section it comes from ("[trace.nodes]",
"[stop_orders#5]", "[derived.funds_position]"), and a model is asked to cite the same way. The tags ground the model's
reading of earlier turns; on the screen they are noise (and raw keys), so `shown` drops them. Markdown links
("[stop order #5](/cases/…)") and the redaction placeholders ("[LE_UNIT]", upper case) are not tags.
"""

from __future__ import annotations

import re
from typing import Any

from app.ai.context import MASKED_RE, unmask, unmask_obj

# the context sections (and Aegis's own pages) a source tag may name
CITATION_ROOTS = ("case", "trace", "freeze_candidates", "stop_orders", "correspondence", "derived", "evidence_index",
                  "evidence", "seeds", "watch", "authorities", "owners", "freeze_checks", "block_status", "board",
                  "recovery_plan", "mailbox", "setup", "aegis", "le_contacts", "team", "redaction", "funds_position",
                  "untrusted_external_email", "schema")
_ROOT = "(?:" + "|".join(sorted((r.replace("_", r"\\?_") for r in CITATION_ROOTS), key=len, reverse=True)) + ")"
_PART = _ROOT + r"(?:[.#][A-Za-z0-9\\_.#]*[A-Za-z0-9])?"
CITATION_RE = re.compile(r"[ \t]*\\?\[" + _PART + r"(?:\s*[,;]\s*" + _PART + r")*\\?\](?!\()")


_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")


def first_sentence(text: str | None) -> str:
    """The first sentence of a (marked) text, never cutting a mask (a mask is one word here)."""
    text = text or ""
    pos = 0
    for m in [*MASKED_RE.finditer(text), None]:
        end = m.start() if m is not None else len(text)
        hit = _SENTENCE_END.search(text, pos, end)
        if hit is not None:
            return text[:hit.start()]
        if m is None:
            break
        pos = m.end()
    return text


def strip_citations(text: Any) -> Any:
    """`text` without its source tags (module doc)."""
    if not isinstance(text, str) or "[" not in text:
        return text
    return CITATION_RE.sub("", text)


def shown(text: Any, *, reveal: bool) -> Any:
    """The text on a member's screen: masks resolved (`reveal`: the real values), source tags hidden."""
    return strip_citations(unmask(text, reveal=reveal))


def sent(text: Any) -> Any:
    """The text the model may read back (earlier turns, a skill's findings): placeholders, tags kept."""
    return unmask(text, reveal=False)


def shown_obj(obj: Any, *, reveal: bool) -> Any:
    """`shown` over every string of a JSON-able object (a summary)."""
    obj = unmask_obj(obj, reveal=reveal)
    if isinstance(obj, str):
        return strip_citations(obj)
    if isinstance(obj, dict):
        return {k: shown_obj(v, reveal=reveal) for k, v in obj.items()}
    if isinstance(obj, list):
        return [shown_obj(v, reveal=reveal) for v in obj]
    return obj


def summary_obj(summary: dict, *, reveal: bool, cite: bool = False) -> dict:
    """A (marked) summary resolved for the screen (`cite`: keep the source tags, for the model's copy): a next step
    whose action is left out of this copy (a move built from what a reply names, for the model) is dropped."""
    out = unmask_obj(summary, reveal=reveal) if cite else shown_obj(summary, reveal=reveal)
    if isinstance(out, dict) and isinstance(out.get("next_steps"), list):
        out["next_steps"] = [s for s in out["next_steps"] if not isinstance(s, dict) or str(s.get("action") or "").strip()]
    return out


__all__ = ["CITATION_RE", "first_sentence", "sent", "shown", "shown_obj", "strip_citations", "summary_obj"]
