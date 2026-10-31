"""Case assistant (app/ai, app/web/routes_assistant.py). The model provider is fully mocked: no test
reaches the network, and every test runs with `providers.get_provider` replaced (None = AI not
configured). Provider-level tests (httpx.MockTransport, the Anthropic SDK) are in test_llm_providers.py."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import csrf_token
from sqlalchemy import select

from app import services
from app.ai import assistant as ai
from app.ai import client as ai_client
from app.ai import providers
from app.ai.context import SUMMARY_FACTS_KEY, build_context, redactor_for, to_json
from app.ai.providers import ChatResult, ProviderError
from app.ai.rules import RULE_LABEL, RULE_LABEL_INVALID, derive, rule_summary
from app.db.models import (
    AIMode,
    AuditEvent,
    Correspondence,
    CorrespondenceDirection,
    CorrespondenceKind,
    Entity,
    EvidenceFolder,
    EvidenceItem,
    StopOrder,
    StopOrderStatus,
)

ORIGIN_TX = "0x70abbe14aa9080b572aa69881536e5c165097c0574c4791467e915b708bba814"
PERP_WALLET = "0x57de1021a507d46272d386995d5b58667ac1f8df"
LETTER_SENTINEL = "LETTER-BODY-SENTINEL-7781"
EVIDENCE_SENTINEL = "EVIDENCE-CONTENT-SENTINEL-4410"
NOTE_SENTINEL = "NOTE-SENTINEL-5523"
REAL_GET_CLIENT = ai_client.get_client  # before the autouse fixture replaces it


def demo_pii(case) -> list[str]:
    """The demo identities that must never reach the model in redacted mode."""
    f = case.facts
    inv = f["investigator"]
    return [
        case.victim_name, "Jordan", "Avery", case.victim_entity, "Northbridge", "victim@northbridge.example",
        "Mara Lindqvist", "Lindqvist", inv["email"], inv["firm"], "kestrel-ridge.example", inv["phone"],
        "Beispielweg", *(c["reference"] for c in f["complaints"]), "Exempla Holding", "Adrian Example",
        "exempla-holding.example", "CHE-000.000.000", "demo0000project", "gsk_DEMO", case.reference,
        LETTER_SENTINEL, EVIDENCE_SENTINEL, NOTE_SENTINEL,
    ]


# --------------------------------------------------------------------------- provider fakes
SERVED = "deepseek-ai/DeepSeek-V4.1-Flash"
CONFIGURED = "deepseek-ai/DeepSeek-V4.1-Flash:deepinfra"
LABEL = "Hugging Face Inference Router → DeepInfra (third-party inference provider)"
USAGE = {"input_tokens": 1234, "output_tokens": 321, "total_tokens": 1555, "estimated_cost": 0.00042}


def reply(text: str = "ok", *, usage: dict | None = None, served: str = SERVED, finish: str = "stop") -> ChatResult:
    return ChatResult(text=text, served_model=served, provider_label=LABEL, usage=dict(usage or USAGE), latency_ms=850,
                      finish_reason=finish)


class FakeProvider:
    """Stands in for app.ai.providers.OpenAICompatProvider: records every chat() call."""

    def __init__(self, *responses, name: str = "hf_router", model: str = CONFIGURED, label: str = LABEL):
        self.responses = list(responses)
        self.calls: list[dict] = []
        self.name, self.model, self.label = name, model, label

    def chat(self, messages, *, json_mode=False, max_tokens=None, temperature=0.2, schema=None):
        self.calls.append({"messages": messages, "json_mode": json_mode, "max_tokens": max_tokens,
                           "temperature": temperature, "schema": schema})
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        return r


def sent_context(call: dict) -> dict:
    return json.loads(call["messages"][1]["content"].split("\n", 1)[1].rsplit("\n", 1)[0])


def summary_json(**over) -> str:
    data = {
        "status_summary": "Funds traced to five services; six preservation letters sent, none answered yet.",
        "key_facts": ["399,247.92 USDC left the victim wallet [case.loss]"],
        "funds_position": {"traced_usd": 399247.92, "at_freezable_services_usd": 63906.63, "frozen_usd": None,
                           "unknown": "Dormant hub outflows [derived.dormant_large_balances]"},
        "open_items": ["KuCoin has not answered [stop_orders#4]"],
        "deadlines": [{"what": "KuCoin reply", "due": "2026-10-21", "why": "72-hour follow-up [stop_orders#4]"}],
        "next_steps": [{"action": "Chase KuCoin", "owner_role": "investigator", "priority": "high",
                        "rationale": "No reply [stop_orders#4]"}],
        "risks": ["Dormant funds can move [trace.nodes]"],
        "data_gaps": ["Asserted relay hops [trace.tainted_transfers]"],
    }
    data.update(over)
    return json.dumps(data)


# --------------------------------------------------------------------------- fixtures
@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    """Default: AI not configured. Tests that exercise the model install a FakeProvider."""
    monkeypatch.setattr(providers, "get_provider", lambda: None)


def use_provider(monkeypatch, fake: FakeProvider) -> FakeProvider:
    monkeypatch.setattr(providers, "get_provider", lambda: fake)
    return fake


@pytest.fixture
def acase(db, case):
    """The demo case, traced, with PII-bearing letters, messages and evidence added; restored afterwards."""
    if not case.trace_runs:
        services.run_trace(db, case)
    kucoin = db.scalar(select(Entity).where(Entity.name == "KuCoin"))
    now = datetime.now(tz=UTC)
    order = StopOrder(
        case=case, entity=kucoin, kind="freeze", status=StopOrderStatus.SENT,
        subject=f"Freeze request for {case.victim_name}",
        body_markdown=f"{LETTER_SENTINEL} on behalf of {case.victim_name} ({case.victim_entity}), "
                      f"complaint {case.facts['complaints'][0]['reference']}, contact {case.facts['investigator']['email']}",
        recipient_email="compliance@kucoin.example", recipient_cc=[case.facts["investigator"]["email"]],
        identifiers={"addresses": [PERP_WALLET], "order_ids": ["demo0swf_t000_0000_0000_000000000001"],
                     "project_ref": "demo0000project"},
        sent_at=now - timedelta(days=10), response_due_at=now - timedelta(days=3), notes=NOTE_SENTINEL,
        external_ref="KC-TICKET-DEMO-0001",
    )
    db.add(order)
    db.flush()
    corr = Correspondence(
        # a status request linked to the order: its own reply clock counts even though the order has one
        case=case, entity=kucoin, direction=CorrespondenceDirection.OUT, kind=CorrespondenceKind.STATUS_REQUEST,
        subject=f"Re: {case.victim_name}", body_markdown=f"{LETTER_SENTINEL} {case.facts['persona']}",
        sender="Mara Lindqvist <mara.lindqvist@kestrel-ridge.example>", recipients=["compliance@kucoin.example"],
        occurred_at=now - timedelta(days=10), due_at=now - timedelta(days=2), stop_order_id=order.id,
    )
    ev1 = EvidenceItem(
        case=case, folder=EvidenceFolder.LAW_ENFORCEMENT, title=f"Police complaint of {case.victim_name}",
        description=f"Statement by {case.victim_name}", inline_text=EVIDENCE_SENTINEL, source_type="police_report",
        source_path="/nonexistent/vault/original.pdf", received_from=f"{case.victim_name} (victim)",
    )
    ev2 = EvidenceItem(
        case=case, folder=EvidenceFolder.INVESTIGATOR_REPORTS, title="Third-party analysis", tlp="TLP:RED",
        inline_text="TLP-RED-SENTINEL", description="restricted",
    )
    db.add_all([corr, ev1, ev2])
    db.commit()
    case.test_order_id = order.id  # plain attribute: earlier tests may leave other KuCoin orders on the case
    yield case
    db.rollback()
    for row in (corr, ev1, ev2, order):
        db.delete(row)
        db.flush()
    case.ai_mode = AIMode.REDACTED
    case.status_summary = None
    case.facts = {k: v for k, v in (case.facts or {}).items() if k != SUMMARY_FACTS_KEY}
    db.commit()


def _client(client_for, role, case):
    return client_for(role, case=case)


def _form(c, case, path, **data):
    token = csrf_token(c, f"/cases/{case.id}?tab=assistant")
    return c.post(f"/cases/{case.id}/assistant/{path}", data={"csrf_token": token, **data}, follow_redirects=False)


def _audits(db, case, action="AI_QUERY"):
    db.expire_all()
    return db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id, AuditEvent.action == action)
                      .order_by(AuditEvent.id)).all()


# --------------------------------------------------------------------------- context
def test_redacted_context_has_no_demo_pii_but_keeps_chain_data(db, acase):
    ctx = build_context(db, acase)
    assert ctx["mode"] == "redacted"
    text = to_json(ctx).lower()
    for s in demo_pii(acase):
        assert s.lower() not in text, s
    assert "kc-ticket-demo-0001" not in text and "/nonexistent/vault" not in text and "tlp-red-sentinel" not in text
    assert ORIGIN_TX in text and PERP_WALLET in text
    assert "kucoin" in text and "rainbet" in text and "swft" in text
    assert "demo0swf_t000_0000_0000_000000000001" in text  # swap order references are chain data
    assert ctx["freeze_candidates"] and ctx["trace"]["graph"]["nodes"] > 0
    # complaint authority types, not references; people as roles
    assert {c["authority"] for c in ctx["case"]["complaints"]} == {"Carabinieri (Italy)", "FBI IC3 (USA)"}
    assert "demo city" not in text  # the station / town of a complaint authority is never sent
    assert all("reference" not in c for c in ctx["case"]["complaints"])
    assert ctx["case"]["victim"].startswith("[VICTIM]")
    order = next(o for o in ctx["stop_orders"] if o["id"] == acase.test_order_id)
    assert order["entity"] == "KuCoin" and order["kind"] == "freeze"
    assert order["unanswered_over_7_days"] and order["overdue"] and order["recipient_ticket_on_file"]
    assert "subject" not in order and "body_markdown" not in order and "notes" not in order
    assert "project_ref" not in order["identifiers"]
    assert all("inline_text" not in e and "description" not in e for e in ctx["evidence_index"])


def test_full_context_adds_bodies_but_never_paths_or_restricted_content(db, acase):
    ctx = build_context(db, acase, AIMode.FULL)
    text = to_json(ctx)
    assert LETTER_SENTINEL in text and EVIDENCE_SENTINEL in text and acase.victim_name in text
    assert "/nonexistent/vault" not in text and "source_path" not in text and "vault_path" not in text
    assert "TLP-RED-SENTINEL" not in text and "Third-party analysis" not in text
    assert SUMMARY_FACTS_KEY not in text


# --------------------------------------------------------------------------- redaction regressions (review round 1)
@pytest.fixture
def real_shaped(db, acase):
    """The demo case with realistically shaped facts: a station-level authority with a street address,
    a second PI firm, personas, an attorney-in-fact, a meeting venue, an LE unit with a street, an
    infrastructure note citing the perpetrator wallet, a TLP:AMBER+STRICT report tagged with the
    firm's name and a stop order whose identifiers carry local file paths. Restored afterwards."""
    from app.db.models import LEContact

    facts_before = dict(acase.facts)
    facts = dict(acase.facts)
    facts["complaints"] = [*facts["complaints"], {
        "authority": "Carabinieri — Stazione Demoborgo Centro (Demopoli)", "reference": "DEMO-IT-1111111111",
        "filed_at": "2026-10-14", "address": "Via Esempio 12, 00000 Demopoli"}]
    facts["other_investigators"] = [{"firm": "Acmeforensic Partners Ltd", "contact": "Quentin Fakeworth"}]
    facts["personas"] = ["Bertha Fictive, Head of Treasury"]
    facts["attorney_in_fact"] = {"role": "attorney-in-fact", "name": "Ottilie Sampleton"}
    facts["meeting_venue"] = "Hotel Imaginario, Piazza Finta 3, Demopoli"
    facts["infrastructure"] = [*facts.get("infrastructure", []), {
        "provider": "ENS", "detail": f"lure name registered by the perpetrators, resolving to {PERP_WALLET}"}]
    acase.facts = facts
    le = LEContact(case=acase, agency="Carabinieri — Nucleo Investigativo Demopoli Est", unit="Via Inventata 7, Demopoli",
                   role="investigating unit", jurisdiction="Italy", reference="DEMO-IT-2222222222")
    report = EvidenceItem(case=acase, folder=EvidenceFolder.INVESTIGATOR_REPORTS, title="Partner report",
                          tlp="TLP:AMBER+STRICT", tags=["acmeforensic", "has-duplicate"], inline_text="x")
    tagged = EvidenceItem(case=acase, folder=EvidenceFolder.OTHER, title="Note", tags=["acmeforensic", "tlp-clear"],
                          inline_text="y")
    order = db.get(StopOrder, acase.test_order_id)
    ids_before = dict(order.identifiers)
    order.identifiers = {**ids_before, "original": "/Users/someone/OneDrive - Example Org/Case/Stop Orders/x.rtfd",
                         "letter_text_file": "/Users/someone/private/letters/x.txt"}
    order.notes = "see /Users/someone/OneDrive - Example Org/Case/notes.txt for the draft"
    db.add_all([le, report, tagged])
    db.commit()
    yield acase
    db.rollback()
    for row in (le, report, tagged):
        db.delete(row)
    order.identifiers, order.notes = ids_before, NOTE_SENTINEL
    acase.facts = facts_before
    db.commit()


REAL_SHAPED_PII = ["demoborgo", "demopoli", "via esempio", "via inventata", "acmeforensic", "quentin", "fakeworth",
                   "bertha", "fictive", "ottilie", "sampleton", "imaginario", "piazza finta", "demo-it-1111111111",
                   "demo-it-2222222222"]


def test_redacted_context_sends_authority_types_not_stations_units_or_towns(db, real_shaped):
    ctx = build_context(db, real_shaped)
    text = to_json(ctx).lower()
    for s in REAL_SHAPED_PII:
        assert s not in text, s
    assert "carabinieri (italy)" in text
    assert "Carabinieri (Italy)" in {le["agency"] for le in ctx["le_contacts"]}
    assert all("—" not in le["agency"] for le in ctx["le_contacts"])
    report = next(e for e in ctx["evidence_index"] if e["title"] == "[title withheld: TLP-restricted item]")
    assert report["tags"] == []
    assert any(e["tags"] == ["tlp-clear"] for e in ctx["evidence_index"])  # system tags only


def test_infrastructure_notes_never_erase_the_perpetrator_wallet(db, real_shaped):
    ctx = build_context(db, real_shaped)
    assert PERP_WALLET in [s["value"].lower() for s in ctx["seeds"]]
    assert PERP_WALLET in [n["address"].lower() for n in ctx["trace"]["nodes"]]
    assert any(PERP_WALLET in (t.get("to") or "").lower() or PERP_WALLET in (t.get("from") or "").lower()
               for t in ctx["trace"]["tainted_transfers"])
    assert "[ATTACKER_INFRA]" not in json.dumps(ctx["seeds"]) + json.dumps(ctx["trace"]["nodes"])


def test_no_mode_ever_sends_local_paths(db, real_shaped):
    for mode in (AIMode.REDACTED, AIMode.FULL):
        text = to_json(build_context(db, real_shaped, mode))
        assert "/Users/" not in text and "OneDrive" not in text, mode
        assert "letter_text_file" not in text and '"original"' not in text, mode
    full = build_context(db, real_shaped, AIMode.FULL)
    order = next(o for o in full["stop_orders"] if o["id"] == real_shaped.test_order_id)
    assert order["notes"].startswith("see [PATH]") and "order_ids" in order["identifiers"]


def test_off_mode_builds_nothing(db, acase):
    acase.ai_mode = AIMode.OFF
    db.commit()
    with pytest.raises(ValueError):
        build_context(db, acase)


def test_redactor_replaces_free_text_and_contact_shapes(db, acase):
    r = redactor_for(db, acase)
    out = r(f"Ask {acase.victim_name} or call +39 00 000 00 00 / write to someone@company.example")
    assert out == "Ask [VICTIM] or call [PHONE] / write to [EMAIL]"


def test_rules_flag_unanswered_overdue_and_dormant(db, acase):
    ctx = build_context(db, acase)
    d = ctx["derived"]
    assert any(u["entity"] == "KuCoin" for u in d["unanswered_stop_orders_over_7_days"])
    assert any(o["type"] == "stop_order" for o in d["overdue"]) and any(o["type"] == "correspondence" for o in d["overdue"])
    assert d["dormant_large_balances"] and d["pending_inputs"]["asserted_transfers"] > 0
    s = rule_summary(ctx)
    assert any(step["action"].startswith("Chase KuCoin") and step["priority"] == "high" for step in s["next_steps"])
    assert any("OVERDUE" in x["why"] for x in s["deadlines"])
    assert s["funds_position"]["traced_usd"] == pytest.approx(399247.92)
    # derive is pure: same input, same output
    assert derive(ctx, datetime.now(tz=UTC)) == derive(ctx, datetime.now(tz=UTC))


# --------------------------------------------------------------------------- summary
def test_summary_fallback_without_credentials(monkeypatch, client_for, db, acase):
    events = []
    real_emit = ai.emit

    def spy(db_, case_, event_type, **kw):
        events.append((event_type, kw))
        return real_emit(db_, case_, event_type, **kw)

    monkeypatch.setattr(ai, "emit", spy)
    c = _client(client_for, "investigator", acase)
    r = _form(c, acase, "summary")
    assert r.status_code == 303 and r.headers["location"].endswith("?tab=assistant#assistant-summary")
    db.expire_all()
    assert RULE_LABEL in acase.status_summary
    stored = acase.facts[SUMMARY_FACTS_KEY]
    assert stored["source"] == "rule_based" and stored["label"] == RULE_LABEL and stored["reason"] == "not_configured"
    ev = _audits(db, acase)[-1]
    assert ev.detail["kind"] == "summary" and ev.detail["source"] == "rule_based" and ev.actor_user_id == c.user.id
    (event_type, kw), = events  # whether a notification row results is the notification rules' decision
    assert event_type == "ai_summary" and kw["link"] == f"/cases/{acase.id}?tab=assistant"
    assert kw["severity"] == "info" and set(kw["payload"]) == {"audit_event_id"}
    assert acase.victim_name not in kw["title"] + (kw["body"] or "")
    page = c.get(f"/cases/{acase.id}?tab=assistant")
    assert page.status_code == 200 and RULE_LABEL in page.text and "Next steps" in page.text
    assert "Generate status summary" in page.text
    overview = c.get(f"/cases/{acase.id}?tab=overview")
    assert RULE_LABEL in overview.text


def test_summary_mode_off_never_calls_the_model(monkeypatch, client_for, db, acase):
    fake = use_provider(monkeypatch, FakeProvider(reply(summary_json())))
    acase.ai_mode = AIMode.OFF
    db.commit()
    out = ai.summarize_case(db, acase, actor=None)
    assert fake.calls == []
    assert out["meta"]["source"] == "rule_based" and out["meta"]["reason"] == "ai_mode_off"


def test_summary_with_mocked_provider(monkeypatch, client_for, db, acase):
    pii_status = f"Funds traced; {acase.victim_name} informed."  # the overview line is scrubbed regardless
    fake = use_provider(monkeypatch, FakeProvider(reply(summary_json(status_summary=pii_status))))
    c = _client(client_for, "investigator", acase)
    assert _form(c, acase, "summary").status_code == 303
    assert len(fake.calls) == 1
    kw = fake.calls[0]
    assert kw["json_mode"] is True and kw["schema"] == ai.summary_schema()
    msgs = kw["messages"]
    assert msgs[0] == {"role": "system", "content": ai.summary_system_prompt()}
    # the JSON-only system prompt embeds the exact schema
    assert json.dumps(ai.summary_schema(), separators=(",", ":"), ensure_ascii=False) in msgs[0]["content"]
    assert "exactly ONE JSON object" in msgs[0]["content"]
    assert msgs[1]["role"] == "user" and msgs[1]["content"].startswith("<case_context>")
    assert msgs[-1]["role"] == "user" and msgs[-1]["content"].startswith("TASK: status_summary\nas_of: 20")
    # the context turn carries only the day, so it is byte-stable within a Q&A session
    assert len(sent_context(kw)["as_of"]) == 10
    sent = json.dumps(kw, default=str, ensure_ascii=False).lower()
    for s in demo_pii(acase):
        assert s.lower() not in sent, s
    db.expire_all()
    stored = acase.facts[SUMMARY_FACTS_KEY]
    assert stored["source"] == "ai" and stored["model"] == CONFIGURED and stored["mode"] == "redacted"
    assert stored["served_model"] == SERVED and stored["provider"] == "hf_router" and stored["provider_label"] == LABEL
    assert stored["summary"]["next_steps"][0]["action"] == "Chase KuCoin"
    assert acase.status_summary == "Funds traced; [VICTIM] informed."
    ev = _audits(db, acase)[-1]
    d = ev.detail
    assert d["source"] == "ai" and d["model"] == CONFIGURED and d["served_model"] == SERVED and d["mode"] == "redacted"
    assert d["provider"] == "hf_router" and d["provider_label"] == LABEL and d["calls"] == 1
    assert d["input_tokens"] == 1234 and d["output_tokens"] == 321 and d["estimated_cost"] == pytest.approx(0.00042)
    assert d["latency_ms"] == 850 and d["repair_attempted"] is False
    assert "Chase KuCoin" not in json.dumps(ev.detail) and "Funds traced" not in json.dumps(ev.detail)
    page = c.get(f"/cases/{acase.id}?tab=assistant")
    assert "Chase KuCoin" in page.text and f"AI ({SERVED}, redacted mode)" in page.text
    assert f'Generated by <span class="mono">{SERVED}</span> via {LABEL}' in page.text
    assert f'Generated by <span class="mono">{SERVED}</span> via {LABEL}' in c.get(f"/cases/{acase.id}?tab=overview").text


def test_summary_json_inside_fences_and_prose_is_parsed(monkeypatch, db, acase):
    status = 'Braces {inside} strings and "quotes" survive.'
    text = "Here is the summary:\n```json\n" + summary_json(status_summary=status) + "\n```\nTrailing {prose}."
    use_provider(monkeypatch, FakeProvider(reply(text)))
    out = ai.summarize_case(db, acase)
    assert out["meta"]["source"] == "ai" and out["status_summary"] == status
    assert ai.extract_json_object('x {"a": "}{", "b": {"c": 1}} y {"d": 2}') == '{"a": "}{", "b": {"c": 1}}'
    assert ai.extract_json_object('{"unbalanced": ') is None and ai.extract_json_object("no object") is None


def test_summary_repair_call_fixes_invalid_json(monkeypatch, db, acase):
    broken = json.loads(summary_json())
    del broken["funds_position"]
    broken["next_steps"][0]["priority"] = "urgent"
    fake = use_provider(monkeypatch, FakeProvider(reply(json.dumps(broken)), reply(summary_json())))
    out = ai.summarize_case(db, acase)
    assert out["meta"]["source"] == "ai" and len(fake.calls) == 2
    repair = fake.calls[1]["messages"]
    assert repair[:-2] == fake.calls[0]["messages"]  # same conversation, plus the bad reply and the error
    assert repair[-2]["role"] == "assistant" and repair[-1]["role"] == "user"
    assert "funds_position" in repair[-1]["content"] and "next_steps.0.priority" in repair[-1]["content"]
    assert fake.calls[1]["json_mode"] is True
    d = _audits(db, acase)[-1].detail
    assert d["calls"] == 2 and d["repair_attempted"] is True and d["input_tokens"] == 2468
    assert d["estimated_cost"] == pytest.approx(0.00084) and d["latency_ms"] == 1700


def test_invalid_output_after_repair_falls_back_with_label(monkeypatch, db, acase):
    fake = use_provider(monkeypatch, FakeProvider(reply("not json"), reply("{\"still\": \"wrong\"}")))
    out = ai.summarize_case(db, acase)
    assert len(fake.calls) == 2
    assert out["meta"]["source"] == "rule_based" and out["meta"]["reason"] == "invalid_output"
    assert out["meta"]["label"] == RULE_LABEL_INVALID == "rule-based (AI response invalid)"
    db.expire_all()
    assert acase.status_summary.endswith(RULE_LABEL_INVALID)
    d = _audits(db, acase)[-1].detail
    assert d["source"] == "rule_based" and d["served_model"] == SERVED and d["calls"] == 2 and d["repair_attempted"]


def test_summary_refusal_falls_back_to_rules(monkeypatch, db, acase):
    use_provider(monkeypatch, FakeProvider(ProviderError("refusal", category="cyber", explanation="declined",
                                                         usage={"input_tokens": 1234}, served_model="claude-x")))
    out = ai.summarize_case(db, acase)
    assert out["meta"]["source"] == "rule_based" and out["meta"]["reason"] == "refusal"
    ev = _audits(db, acase)[-1]
    assert ev.detail["stop_reason"] == "refusal" and ev.detail["refusal_category"] == "cyber"
    assert ev.detail["input_tokens"] == 1234  # the declined call's usage is still recorded
    assert "declined" not in json.dumps(ev.detail)


@pytest.mark.parametrize("reason", ["rate_limited", "timeout", "connection_error", "api_error_500", "api_error_401"])
def test_provider_errors_fall_back(monkeypatch, db, acase, reason):
    use_provider(monkeypatch, FakeProvider(ProviderError(reason, f"HTTP error ({reason})")))
    out = ai.summarize_case(db, acase)
    assert out["meta"]["source"] == "rule_based" and out["meta"]["reason"] == reason
    assert out["meta"]["label"] == "rule-based (AI unavailable)"
    result = ai.answer_question(db, acase, "Where are the funds?")
    assert result.source == "ai" and result.reason == reason and "No answer was generated" in result.output
    assert result.generated_by is None  # no model output to attribute


def test_full_mode_needs_confirmation_for_the_third_party_router(monkeypatch, client, db, acase):
    """A case put in full mode without confirming the hf_router destination (e.g. before the provider
    changed) never sends full content: rule-based until an admin confirms it."""
    real_describe = providers.describe
    monkeypatch.setattr(providers, "describe", lambda cfg=None: {**real_describe(cfg), "provider": "hf_router",
                                                                "label": LABEL, "model": CONFIGURED,
                                                                "third_party": True})
    fake = use_provider(monkeypatch, FakeProvider(reply(summary_json())))
    acase.ai_mode = AIMode.FULL
    db.commit()
    out = ai.summarize_case(db, acase)
    assert fake.calls == [] and out["meta"]["reason"] == "full_mode_unconfirmed"
    page = client.get(f"/cases/{acase.id}?tab=assistant").text
    assert "full mode was not confirmed for" in page and f"Full case content will be sent to <b>{LABEL}</b>" in page
    # the DPA box alone is not enough on hf_router
    assert _form(client, acase, "mode", mode="full", confirm_full="yes", confirm_provider="").status_code == 303  # no-op
    acase.ai_mode = AIMode.REDACTED
    db.commit()
    r = _form(client, acase, "mode", mode="full", confirm_full="yes")
    assert r.status_code == 400
    r = _form(client, acase, "mode", mode="full", confirm_full="yes", confirm_provider="yes")
    assert r.status_code == 303
    db.expire_all()
    ev = _audits(db, acase, "UPDATE")[-1]
    assert ev.detail["new"] == "full" and ev.detail["confirmed_provider"] == "hf_router"
    assert ev.detail["confirmed_destination"] == LABEL and ev.detail["dpa_confirmed"] is True
    out = ai.summarize_case(db, acase)
    assert len(fake.calls) == 1 and out["meta"]["source"] == "ai" and out["meta"]["mode"] == "full"
    # a different destination (another pinned provider) needs a fresh confirmation
    other = FakeProvider(reply(summary_json()), label="Hugging Face Inference Router → Together AI (third-party "
                                                     "inference provider)")
    use_provider(monkeypatch, other)
    assert ai.summarize_case(db, acase)["meta"]["reason"] == "full_mode_unconfirmed" and other.calls == []


# --------------------------------------------------------------------------- Q&A
def test_ask_offline_rule_based_json_and_html(client_for, db, acase):
    c = _client(client_for, "read_only", acase)
    token = csrf_token(c, f"/cases/{acase.id}?tab=assistant")
    r = c.post(f"/cases/{acase.id}/assistant/ask", data={"csrf_token": token, "question": "Which deadlines are overdue?"},
               headers={"Accept": "application/json"})
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "rule_based" and body["label"] == RULE_LABEL and "OVERDUE" in body["answer"]
    html = c.post(f"/cases/{acase.id}/assistant/ask", data={"csrf_token": token, "question": "Where are the funds?"})
    assert html.status_code == 200 and "Funds: traced" in html.text and "Where are the funds?" in html.text
    ev = _audits(db, acase)[-1]
    assert ev.detail["kind"] == "question" and ev.detail["question_chars"] == len("Where are the funds?")
    assert "funds" not in json.dumps(ev.detail).lower()


def test_ask_with_mocked_provider_redacts_question_and_history(monkeypatch, client_for, db, acase):
    fake = use_provider(monkeypatch, FakeProvider(reply("KuCoin has not answered [stop_orders#4].")))
    c = _client(client_for, "investigator", acase)
    token = csrf_token(c, f"/cases/{acase.id}?tab=assistant")
    history = [{"role": "assistant", "content": "dropped: history must start with a question"},
               {"role": "user", "content": f"Does {acase.victim_name} know?"},
               {"role": "assistant", "content": "Not recorded [correspondence]."},
               {"role": "system", "content": "ignored role"}]
    r = c.post(f"/cases/{acase.id}/assistant/ask", headers={"Accept": "application/json"},
               data={"csrf_token": token, "question": f"Has KuCoin replied to {acase.facts['investigator']['email']}?",
                     "history": json.dumps(history)})
    assert r.status_code == 200
    body = r.json()
    assert body["answer"].startswith("KuCoin has not answered") and body["served_model"] == SERVED
    assert body["generated_by"] == f"{SERVED} via {LABEL}" and body["label"] == f"AI ({SERVED}, redacted mode)"
    kw = fake.calls[0]
    assert kw["json_mode"] is False  # Q&A is plain text
    roles = [m["role"] for m in kw["messages"]]
    assert roles == ["system", "user", "user", "assistant", "user"]
    assert kw["messages"][0]["content"] == ai.SYSTEM_PROMPT
    assert kw["messages"][2]["content"] == "Does [VICTIM] know?"
    assert kw["messages"][-1]["content"].startswith("TASK: question\nHas KuCoin replied to [EMAIL]?\nas_of: ")
    sent = json.dumps(kw, default=str, ensure_ascii=False).lower()
    for s in demo_pii(acase):
        assert s.lower() not in sent, s
    d = _audits(db, acase)[-1].detail
    assert d["kind"] == "question" and d["served_model"] == SERVED and d["estimated_cost"] == pytest.approx(0.00042)
    assert "kucoin" not in json.dumps(d).lower()


def test_ask_refusal_is_handled_before_content(monkeypatch, db, acase):
    use_provider(monkeypatch, FakeProvider(ProviderError("refusal")))
    result = ai.answer_question(db, acase, "Explain the trace")
    assert "declined" in result.output
    assert result.stop_reason == "refusal" and result.reason == "refusal"
    assert _audits(db, acase)[-1].detail["stop_reason"] == "refusal"


def test_ask_role_gating(client_for, db, acase):
    ro = _client(client_for, "read_only", acase)
    assert ro.post(f"/api/cases/{acase.id}/assistant/ask", json={"question": "status?"}).status_code == 200
    acase.ai_mode = AIMode.FULL
    db.commit()
    assert ro.post(f"/api/cases/{acase.id}/assistant/ask", json={"question": "status?"}).status_code == 403
    page = ro.get(f"/cases/{acase.id}?tab=assistant")
    assert "assistant-ask-form" not in page.text and "only while the AI mode is" in page.text
    inv = _client(client_for, "investigator", acase)
    assert inv.post(f"/api/cases/{acase.id}/assistant/ask", json={"question": "status?"}).status_code == 200
    ext = _client(client_for, "external", acase)
    assert ext.post(f"/api/cases/{acase.id}/assistant/ask", json={"question": "status?"}).status_code == 403
    outsider = client_for(None, case=acase)
    assert outsider.post(f"/api/cases/{acase.id}/assistant/ask", json={"question": "status?"}).status_code == 404


def test_summary_role_gating_and_csrf(client_for, db, acase):
    ro = _client(client_for, "read_only", acase)
    assert _form(ro, acase, "summary").status_code == 403
    assert "Generate status summary" not in ro.get(f"/cases/{acase.id}?tab=assistant").text
    assert ro.post(f"/api/cases/{acase.id}/assistant/summary").status_code == 403
    inv = _client(client_for, "investigator", acase)
    assert inv.post(f"/cases/{acase.id}/assistant/summary", data={}, follow_redirects=False).status_code == 403  # no CSRF
    assert inv.post(f"/api/cases/{acase.id}/assistant/summary").json()["meta"]["source"] == "rule_based"
    assert ro.get(f"/api/cases/{acase.id}/assistant/summary").status_code == 200


def test_full_mode_summary_hidden_from_read_only(client_for, db, acase):
    acase.ai_mode = AIMode.FULL
    db.commit()
    ai.summarize_case(db, acase)
    ro = _client(client_for, "read_only", acase)
    assert ro.get(f"/api/cases/{acase.id}/assistant/summary").status_code == 403
    assert "generated in <b>full</b> mode" in ro.get(f"/cases/{acase.id}?tab=assistant").text
    inv = _client(client_for, "investigator", acase)
    assert inv.get(f"/api/cases/{acase.id}/assistant/summary").json()["mode"] == "full"


# --------------------------------------------------------------------------- mode switch and preview
def test_mode_switch_admin_only_and_audited(client, client_for, db, acase):
    inv = _client(client_for, "investigator", acase)
    assert _form(inv, acase, "mode", mode="off").status_code == 403
    assert _form(client, acase, "mode", mode="bogus").status_code == 400
    assert _form(client, acase, "mode", mode="full").status_code == 400  # needs the DPA confirmation
    r = _form(client, acase, "mode", mode="off")
    assert r.status_code == 303
    db.expire_all()
    assert acase.ai_mode == AIMode.OFF
    ev = _audits(db, acase, "UPDATE")[-1]
    assert ev.detail == {"field": "ai_mode", "old": "redacted", "new": "off"} and ev.object_type == "cases"
    # the default provider is the third-party hf_router: the DPA box alone is not enough
    assert _form(client, acase, "mode", mode="full", confirm_full="yes").status_code == 400
    assert _form(client, acase, "mode", mode="full", confirm_provider="yes").status_code == 400
    assert _form(client, acase, "mode", mode="full", confirm_full="yes", confirm_provider="yes").status_code == 303
    db.expire_all()
    assert acase.ai_mode == AIMode.FULL
    page = client.get(f"/cases/{acase.id}?tab=assistant")
    assert "Save AI mode" in page.text and "context-preview?mode=redacted" in page.text
    assert "Save AI mode" not in inv.get(f"/cases/{acase.id}?tab=assistant").text


def test_context_preview_is_exactly_what_is_sent(monkeypatch, client, client_for, db, acase):
    r = client.get(f"/api/cases/{acase.id}/assistant/context-preview")
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "redacted" and body["sent"] and body["system_prompt"] == ai.SYSTEM_PROMPT
    text = json.dumps(body).lower()
    for s in demo_pii(acase):
        assert s.lower() not in text, s
    assert body["destination"] == providers.describe()["label"] and body["model"] == providers.describe()["model"]
    assert body["summary_instructions"] == ai.summary_instructions()
    fake = use_provider(monkeypatch, FakeProvider(reply(summary_json())))
    ai.summarize_case(db, acase)
    sent_ctx = sent_context(fake.calls[0])
    preview = body["context"]
    sent_ctx.pop("as_of"), preview.pop("as_of")
    # only time-dependent counters may differ between the two calls
    assert sent_ctx.keys() == preview.keys() and sent_ctx["freeze_candidates"] == preview["freeze_candidates"]
    assert sent_ctx["evidence_index"] == preview["evidence_index"]
    full = client.get(f"/api/cases/{acase.id}/assistant/context-preview?mode=full").json()
    assert LETTER_SENTINEL in json.dumps(full["context"])
    off = client.get(f"/api/cases/{acase.id}/assistant/context-preview?mode=off").json()
    assert off == {**off, "sent": False, "context": None}
    for role in ("investigator", "read_only"):
        assert _client(client_for, role, acase).get(f"/api/cases/{acase.id}/assistant/context-preview").status_code == 403
    assert client_for(None, case=acase).get(f"/api/cases/{acase.id}/assistant/context-preview").status_code == 404
    assert _audits(db, acase, "AI_CONTEXT_PREVIEW")


def test_assistant_tab_redirect_and_read_only_view(client_for, acase):
    ro = _client(client_for, "read_only", acase)
    r = ro.get(f"/cases/{acase.id}/assistant", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/cases/{acase.id}?tab=assistant"
    page = ro.get(f"/cases/{acase.id}?tab=assistant")
    assert page.status_code == 200 and "Ask about this case" in page.text and "Only the case admin" in page.text
    assert "AI not configured" in page.text


# --------------------------------------------------------------------------- client resolution
def test_get_client_resolution(monkeypatch, tmp_path):
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE", "ANTHROPIC_IDENTITY_TOKEN",
                "ANTHROPIC_IDENTITY_TOKEN_FILE", "ANTHROPIC_FEDERATION_RULE_ID", "AEGIS_AI_DISABLED"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ANTHROPIC_CONFIG_DIR", str(tmp_path))  # no profile on disk
    monkeypatch.setenv("HOME", str(tmp_path))
    assert REAL_GET_CLIENT() is None
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")  # constructing a client makes no request
    c = REAL_GET_CLIENT()
    assert c is not None and c.api_key == "test-key-not-real"
    monkeypatch.setenv("AEGIS_AI_DISABLED", "1")
    assert REAL_GET_CLIENT() is None
