"""The assistant's rule-based answers as the demo shows them (app/ai/skills.py, app/ai/casestate.py,
app/ai/display.py): real names on the screen of a member allowed to see them and placeholders only in the
model's copy; no source tags or raw enum keys on the screen; statuses, "overdue" and the order of the next
moves as Block status, the freeze & stop-order board and the Recovery plan give them. The model provider is
mocked: no test reaches the network."""

from __future__ import annotations

import contextlib
import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import services
from app.ai import display, providers, skills
from app.ai.context import local_context, mask_terms, masked, redactor_for, unmask
from app.ai.providers import ChatResult
from app.ai.rules import derive
from app.blocks import recovery as rp
from app.blocks import status as bs
from app.core.permissions import CaseAccess, effective_role
from app.db.models import AiMessage, AIMode

TICKET = "RB-DEMO-0001"  # Rainbet's acknowledgement (the demo fixture's reply)
MARKS = ("", "", "")
TAGS = ("[trace.", "[derived.", "[freeze_candidates]", "[stop_orders", "[case.", "[correspondence#", "[evidence_index]",
        "[block_status", "[board,", "\\[freeze\\_candidates", "\\[stop\\_orders", "\\[trace.", "\\[case.")


class FakeProvider:
    def __init__(self, text: str):
        self.text, self.calls = text, []
        self.name, self.model, self.label = "hf_router", "deepseek-ai/DeepSeek-V4.1-Flash:deepinfra", "test provider"

    def chat(self, messages, *, json_mode=False, max_tokens=None, temperature=0.2, schema=None):
        self.calls.append(messages)
        return ChatResult(text=self.text, served_model="deepseek-ai/DeepSeek-V4.1-Flash", provider_label=self.label,
                          usage={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2, "estimated_cost": 0.0},
                          latency_ms=1, finish_reason="stop")


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


@pytest.fixture
def dcase(db, case):
    """The traced demo case; chat rows the test adds are removed afterwards."""
    if not case.trace_runs:
        services.run_trace(db, case)
    yield case
    db.rollback()
    for row in db.scalars(select(AiMessage).where(AiMessage.case_id == case.id)).all():
        db.delete(row)
    case.ai_mode = AIMode.REDACTED
    db.commit()


@contextlib.contextmanager
def replies_overdue(db, case, days: int = 2):
    """The demo morning: every reply date passed (the workspace clock moved back `days`), restored afterwards."""
    d = timedelta(days=days)
    fields = {"stop_orders": ("sent_at", "response_due_at", "responded_at", "created_at"),
              "correspondence": ("occurred_at", "due_at")}

    def shift(sign: int) -> None:
        for o in case.stop_orders:
            for f in fields["stop_orders"]:
                if getattr(o, f):
                    setattr(o, f, getattr(o, f) + sign * d)
        for c in case.correspondence:
            for f in fields["correspondence"]:
                if getattr(c, f):
                    setattr(c, f, getattr(c, f) + sign * d)
        db.commit()

    shift(-1)
    try:
        yield
    finally:
        db.rollback()
        shift(+1)


def _access(db, case, client) -> CaseAccess:
    return CaseAccess(case=case, user=client.user, role=effective_role(db, client.user, case), member=None)


def _no_tags(text: str) -> None:
    for tag in TAGS:
        assert tag not in text, (tag, text[:400])


# --------------------------------------------------------------------------- masks and tags (units)
def test_masks_resolve_for_the_screen_and_for_the_model():
    t = masked("Carabinieri — Demo City station", "[LE_UNIT]")
    assert unmask(f"Brief {t}", reveal=True) == "Brief Carabinieri — Demo City station"
    assert unmask(f"Brief {t}", reveal=False) == "Brief [LE_UNIT]"
    nested = masked(f"row {t}", "")  # a line on the screen only
    assert unmask(nested, reveal=True) == "row Carabinieri — Demo City station" and unmask(nested, reveal=False) == ""
    assert unmask("cut secret value", reveal=False) == "cut "  # a cut mask never sends its real value
    # reply details inside text already masked are not masked twice
    text = mask_terms(f"ticket {TICKET} and {t}", {TICKET: "[THEIR_TICKET]"})
    assert unmask(text, reveal=False) == "ticket [THEIR_TICKET] and [LE_UNIT]"


def test_source_tags_are_hidden_on_the_screen_only():
    md = ("Loss \\[case.loss\\] and [stop_orders#5]; see [stop order #5](/cases/1/stop-orders/5), "
          "[LE_UNIT] [trace.tainted_transfers, trace.nodes] [aegis.findings]")
    assert display.shown(md, reveal=True) == ("Loss and; see [stop order #5](/cases/1/stop-orders/5), [LE_UNIT]")
    assert display.sent(md) == md


# --------------------------------------------------------------------------- no placeholders on an admin's screen
def test_rule_based_answers_show_admins_the_real_values_and_the_model_the_placeholders(client_for, db, dcase):
    admin = client_for("admin", case=dcase)
    acc = _access(db, dcase, admin)
    for cmd in ("recovery-plan", "block-status", "summary", "next-steps", "stop-orders", "todo"):
        turn = skills.chat_turn(db, acc, f"/{cmd}")
        content = turn.assistant.content
        assert not any(m in content for m in MARKS), cmd
        assert "[LE_UNIT]" not in content and "[THEIR_TICKET]" not in content and "[REFERENCE]" not in content, (
            cmd, content[:600])
        assert "(amount stated in the reply)" not in content
        _no_tags(content)
        assert turn.assistant.meta["label"] == "rule-based (AI not configured)"  # one label while no AI may answer
    rows = {m.skill: m for m in db.scalars(select(AiMessage).where(AiMessage.case_id == dcase.id,
                                                                   AiMessage.role == "assistant"))}
    block = rows["block-status"]
    assert TICKET in block.content  # Rainbet's acknowledgement, as Block status shows it
    model = block.meta["model_content"]
    assert TICKET not in model and "[THEIR_TICKET]" in model.replace("\\", "") and not any(m in model for m in MARKS)
    assert "[stop_orders, correspondence]" in model.replace("\\", "")  # the model's copy keeps its source tags
    plan = rows["recovery-plan"]
    assert "Carabinieri — Demo City station" in plan.content
    assert "Carabinieri — Demo City station" not in plan.meta["model_content"]
    # what goes back to the model as history is the model's copy
    hist = json.dumps(skills.model_history(db, acc), ensure_ascii=False)
    assert TICKET not in hist and "Demo City station" not in hist
    # a read-only member reads what the model reads
    ro = _access(db, dcase, client_for("read_only", case=dcase))
    res = skills.run_skill(db, ro, "block-status", "")
    assert TICKET not in res.markdown and "[THEIR_TICKET]" in res.markdown.replace("\\", "")


def test_findings_sent_to_the_model_carry_placeholders_only(monkeypatch, client_for, db, dcase):
    fake = FakeProvider(json.dumps({"answer": "Rainbet acknowledged [stop_orders#5].", "suggested_commands": []}))
    monkeypatch.setattr(providers, "get_provider", lambda: fake)
    acc = _access(db, dcase, client_for("admin", case=dcase))
    res = skills.run_skill(db, acc, "block-status", "")
    sent = json.dumps(fake.calls, ensure_ascii=False)
    assert not any(m in sent for m in MARKS) and TICKET not in sent and "[THEIR_TICKET]" in sent.replace("\\", "")
    assert res.source == "ai" and res.markdown == "Rainbet acknowledged."  # the model's tag hidden on the screen
    assert res.model_markdown == "Rainbet acknowledged [stop_orders#5]."
    assert TICKET in res.findings  # Aegis's own findings, shown to the admin with the real values


# --------------------------------------------------------------------------- one story with Block status and the plan
def test_summary_and_next_steps_follow_block_status_and_the_recovery_plan(client_for, db, dcase):
    acc = _access(db, dcase, client_for("admin", case=dcase))
    with replies_overdue(db, dcase):
        rows = bs.case_blocks(db, dcase)
        overdue = bs.summary(rows)["overdue"]
        assert overdue >= 1
        summary = skills.run_skill(db, acc, "summary", "").markdown
        # Rainbet acknowledged: its overdue line says so and names the status request quoting their ticket
        rainbet = next(line for line in summary.splitlines() if "Rainbet — Stop order" in line)
        assert "Acknowledged" in rainbet and "nothing recorded" not in rainbet and TICKET in rainbet
        assert f"{overdue} with the reply overdue" in summary  # counted as Block status counts it
        assert "internal follow-up task" in summary  # the team's own notes named apart
        nxt = skills.run_skill(db, acc, "next-steps", "").markdown
        plan = rp.view(rp.build(db, dcase), acc)
        first = plan["moves"][0]["title"]
        assert f"| 1 | {first} |" in nxt and "Recovery plan" in nxt
        assert "Draft and send a stop order" not in nxt and "Draft and send a stop order" not in summary
        _no_tags(nxt)
        _no_tags(summary)


def test_issuer_lever_leaves_out_wallets_the_funds_moved_on_from(db, dcase):
    ctx = local_context(db, dcase)
    fp = derive(ctx, __import__("datetime").datetime.now(tz=__import__("datetime").UTC))["funds_position"]
    held = fp["issuer_held_usd"]
    assert held["Circle (USDC issuer)"] == 0  # swapped to ETH within minutes: nothing left to blacklist
    assert held["Tether (USDT issuer)"] > 0
    assert fp["issuer_blacklist_lever_usd"] == pytest.approx(sum(held.values()))
    assert fp["issuer_moved_on"]


def test_stop_orders_follow_the_board(client_for, db, dcase):
    acc = _access(db, dcase, client_for("admin", case=dcase))
    res = skills.run_skill(db, acc, "stop-orders", "")
    md = res.markdown
    _no_tags(md)
    assert "(stablecoin_issuer" not in md and "issuer_blacklist" not in md
    assert "for all 1 recommended" not in json.dumps(res.actions)
    for a in res.actions:  # a command names a service by its name, never an internal key
        if a.get("command", "").startswith("/stop-orders draft ") and a["command"] != "/stop-orders draft all":
            assert "entity-" not in a["command"], a


def test_redactor_marking_matches_the_plain_redactor(db, dcase):
    plain, marking = redactor_for(db, dcase), redactor_for(db, dcase, marking=True)
    for text in ("Brief Carabinieri — Demo City station (demo) about Tether",
                 f"Write to {dcase.victim_name} at compliance@kucoin.example, {'+41 79 ' + '000 00 00'}",
                 str(dcase.facts.get("investigator") or "")):
        assert unmask(marking(text), reveal=False) == plain(text)
        assert unmask(marking(text), reveal=True) == text.replace("\n", "\n")
