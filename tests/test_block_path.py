"""Request paths (app.blocks.path, wired through status / correspondence / report / the scheduler's overdue pass):
the path step derived from the replies, the playbook and the linked LE brief; the jurisdiction match and the
cross-border route; the LE / counsel brief; the provider clocks and their alerts. Synthetic replies on the demo
case (every address, ticket and number is made up). Offline: no model, no mail, no chain."""

from datetime import UTC, datetime, timedelta

import pytest
from conftest import csrf_token
from sqlalchemy import select

from app.ai import providers
from app.blocks import classify_rules as R
from app.blocks import path as P
from app.blocks import status as bs
from app.db.models import (
    Correspondence,
    Entity,
    EntityCategory,
    LEContact,
    Notification,
    StopOrder,
    StopOrderStatus,
)
from app.domain import correspondence as desk
from app.domain import directory
from app.domain import mail_guidance as mg
from app.domain import playbook as pbm

T0 = datetime(2026, 10, 19, 9, 0, tzinfo=UTC)
WALLET = "0x" + "4d" * 20
CIRCLE_COURT = ("Thank you for your message. Circle requires a valid court order from a US or French court before it "
                "can block an address holding USDC.")
TETHER_ACK = ("Thank you for contacting Tether Compliance.\n\nThis is an automated response. Your request has been "
              "received and ticket #482913 has been created. Tether will only act upon appropriate legal process "
              "submitted by a law enforcement agency.\n\nTether Compliance")
MEXC_TEMP = ("We have temporarily frozen the account linked to the deposit address you reported. Please provide proof "
             "of the police report within 48 hours, otherwise the temporary freeze will be lifted.")
KUCOIN_HOLD = ("We have placed a temporary hold on the account. The hold will be automatically lifted after 30 days "
               "unless a freezing order stating the freeze duration is received.")
GATE_LE = ("Thank you for your report. Gate's law enforcement channel is not intended for private parties, whether "
           "engaged in private investigations or civil litigations. Requests must come from an official government "
           "domain.")


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


@pytest.fixture
def case(db, tmp_path):
    from test_block_status import fresh_case

    yield fresh_case(db, tmp_path)


def _italian(db, case):
    """The demo case as an Italian one: no US agency on it (the Carabinieri / Procura are its LE authorities)."""
    for le in list(case.le_contacts):
        if "IC3" in le.agency:
            db.delete(le)
    facts = dict(case.facts or {})
    facts["complaints"] = [c for c in facts.get("complaints") or [] if "IC3" not in (c.get("authority") or "")]
    case.facts, case.victim_jurisdiction = facts, "Italy"
    db.commit()
    db.refresh(case)


def _entity(db, name: str, category=EntityCategory.EXCHANGE) -> Entity:
    ent = db.scalar(select(Entity).where(Entity.name == name))
    if ent is None:
        ent = Entity(name=name, category=category)
        db.add(ent)
        db.commit()
    return ent


def _sent_order(db, case, entity, *, at=T0, to="desk@provider-demo.example") -> StopOrder:
    order = StopOrder(case=case, entity=entity, kind="freeze", status=StopOrderStatus.SENT, subject="Freeze request",
                      body_markdown=f"Please block {WALLET}.", sent_at=at, sent_via="email", recipient_email=to,
                      identifiers={"chain": "ethereum", "addresses": [{"chain": "ethereum", "address": WALLET}],
                                   "amounts": {"deposit": "1,500 USDC"}})
    db.add(order)
    db.commit()
    return order


def _reply(db, case, order, text, at):
    from test_block_status import _reply as reply

    return reply(db, case, order, text, at=at, mailbox=True)


def _row(db, case, key, **kw):
    from test_block_status import _row as row

    return row(db, case, key, **kw)


def _le(db, case, word: str) -> desk.Authority:
    return next(a for a in desk.case_authorities(db, case, include_prospects=False) if word in a.name and a.is_le)


def _notes(db, case, event):
    return db.scalars(select(Notification).where(Notification.case_id == case.id, Notification.event_type == event)
                      .order_by(Notification.id)).all()


# --------------------------------------------------------------------------- Circle: court order, Italian case
def test_circle_court_order_reply_opens_the_cross_border_route_for_an_italian_case(db, case):
    _italian(db, case)
    circle = db.scalar(select(Entity).where(Entity.name == "Circle (USDC issuer)"))
    order = _sent_order(db, case, circle)
    _reply(db, case, order, CIRCLE_COURT, T0 + timedelta(hours=2))
    row = _row(db, case, f"o{order.id}")
    assert row.status == R.LE_PROCESS_REQUIRED and row.org_key == "circle"
    assert row.path_step == "le_only_redirect" and row.path.path.key == "private_notice"
    assert row.path.instrument["type"] == "us_or_fr_court_order" and row.path.target.key == "court_order_us_fr"
    route = row.path.route
    assert route["kind"] == "cross_border" and route["jur"] == "IT" and set(route["acts_on"]) == {"US", "FR"}
    kinds = [o["type"] for o in route["options"]]
    assert {"eu_freezing_order", "eio", "mlat", "counsel"} <= set(kinds)
    assert kinds[0] in ("eu_freezing_order", "mlat")  # what the Italian side's playbook says it issues to Circle
    na = row.next_action
    assert na["kind"] == "le" and "template=le_brief" in na["href"] and f"ref=o{order.id}" in na["href"]
    # the prosecutor (PM) issues the cross-border instruments, not the police station; the pack is what the route's
    # first instrument needs (the domestic order to recognise), not Circle's US / French court-order evidence
    assert "Procura" in na["text"] and "cannot ask directly" in na["text"] and row.path.le.role == "judicial"
    assert "EU freezing order" in na["text"] and "MLAT" in na["text"] and "counsel" in na["text"]
    assert na["evidence"] and any(e["key"] == "domestic_order" for e in na["evidence"])
    # the LE brief, prefilled and linked to the request
    cara = _le(db, case, "Carabinieri")
    opts = {o["key"]: o for o in desk.template_options(cara, None)}
    assert opts["le_brief"]["available"] and not opts["counsel_brief"]["available"]
    brief = desk.generate_letter(db, case, cara, "le_brief", actor=None, ref=f"o{order.id}")
    assert brief.meta["follow_up_of"] == f"o{order.id}" and brief.kind.value == "le_cover"
    body = brief.body_markdown
    assert "Circle" in body and "US or French court" in body and WALLET in body and "1,500 USDC" in body
    assert "goes cross-border" in body and "An EU freezing order" in body and "An MLAT request to US" in body
    assert "Circle requires a valid court order" in body  # their reply, quoted


def test_circle_with_a_us_agency_on_the_case_is_a_direct_route(db, case):
    circle = db.scalar(select(Entity).where(Entity.name == "Circle (USDC issuer)"))
    order = _sent_order(db, case, circle)
    _reply(db, case, order, CIRCLE_COURT, T0 + timedelta(hours=2))
    row = _row(db, case, f"o{order.id}")
    # IC3 is a complaint intake: it files nothing with Circle, so it is never the brief's recipient
    assert "IC3" not in row.path.le.name and [x["name"] for x in row.path.route["intake"]] == [
        "FBI Internet Crime Complaint Center (IC3)"]
    # but a US victim with an IC3 reference: a US case agent can ask Circle directly, ahead of the cross-border route
    na = row.next_action
    assert "Fastest: get a US case agent assigned" in na["text"] and "IC3-DEMO" in na["text"]
    assert "Slower fallback" in na["text"] and row.path.route["agent"]["jur"] == "US"
    # a US case agent on the case: the direct route, with counsel's US / French court order in parallel
    db.add(LEContact(case=case, agency="US Secret Service (demo field office)", role="case agent",
                     name="Agent Demo", email="agent@usss-demo.example", jurisdiction="USA"))
    db.commit()
    db.refresh(case)
    row = _row(db, case, f"o{order.id}")
    assert row.path.route["kind"] == "direct" and "Secret Service" in row.path.le.name
    assert "cannot ask directly" not in row.next_action["text"]
    assert "In parallel, instruct counsel for a US or French court order" in row.next_action["text"]
    # only IC3 on the case: get a case agent assigned (quoting the IC3 reference) or instruct counsel
    for le in list(case.le_contacts):
        if "IC3" not in le.agency:
            db.delete(le)
    facts = dict(case.facts or {})
    facts["complaints"] = [c for c in facts.get("complaints") or [] if "IC3" in (c.get("authority") or "")]
    case.facts = facts
    db.commit()
    db.refresh(case)
    na = _row(db, case, f"o{order.id}").next_action
    assert "Get a case agent assigned" in na["text"] and "IC3-DEMO" in na["text"] and "counsel" in na["text"]


# --------------------------------------------------------------------------- Tether: ack with a ticket
def test_tether_ack_is_provider_ack_and_hands_off_to_le_quoting_the_ticket(db, case):
    tether = db.scalar(select(Entity).where(Entity.name == "Tether (USDT issuer)"))
    order = _sent_order(db, case, tether)
    _reply(db, case, order, TETHER_ACK, T0 + timedelta(minutes=5))
    row = _row(db, case, f"o{order.id}")
    assert row.path_step == "provider_ack" and row.path.handoff and row.ticket == "482913"
    na = row.next_action
    assert na["kind"] == "le" and "hand off now" in na["text"] and "482913" in na["text"]
    assert "template=le_brief" in na["href"] and f"ref=o{order.id}" in na["href"]
    assert "Aegis never submits to an LE-only channel" in na["text"]  # Tether's LE channels are the officer's


# A Tether-style refusal (synthetic test text built around the playbook's reply-signal phrases)
TETHER_REFUSAL = ("Thank you for contacting Tether.\n\nThe referenced addresses do not belong to Tether and are not "
                  "controlled by Tether. We do not wish to be drawn into a possible dispute between two parties.\n\nWe "
                  "recommend that you contact local law enforcement authorities to help you with this case and ask that "
                  "you please direct law enforcement to inforequests@tether.to if they have any questions. Please be "
                  "advised that the law enforcement department managing the case must directly submit all law "
                  "enforcement requests to us.")


def test_tether_refusal_is_le_only_and_the_brief_names_the_le_inbox_their_reply_gives(db, case):
    tether = db.scalar(select(Entity).where(Entity.name == "Tether (USDT issuer)"))
    order = _sent_order(db, case, tether)
    _reply(db, case, order, TETHER_ACK, T0 + timedelta(minutes=5))
    _reply(db, case, order, TETHER_REFUSAL, T0 + timedelta(hours=10))
    row = _row(db, case, f"o{order.id}")
    assert row.status == "le_process_required" and row.ticket == "482913"
    na = row.next_action
    assert na["kind"] == "le" and "inforequests@tether.to (the LE inbox their reply names)" in na["text"]


# --------------------------------------------------------------------------- the linked LE brief
def test_a_sent_linked_le_brief_opens_the_le_route_and_answers_le_process_required(db, case):
    _italian(db, case)
    circle = db.scalar(select(Entity).where(Entity.name == "Circle (USDC issuer)"))
    order = _sent_order(db, case, circle)
    reply = _reply(db, case, order, CIRCLE_COURT, T0 + timedelta(hours=2))
    key = f"o{order.id}"
    # a follow-up to Circle itself does not answer "LE process required"
    a = desk.get_authority(db, case, f"entity-{circle.id}")
    desk.log_entry(db, case, a, actor=None, direction="out", channel="email", kind="status_request",
                   subject="Follow-up", body="Any news?", stop_order=order, occurred_at=reply.occurred_at
                   + timedelta(hours=1), recipients=["desk@provider-demo.example"], due_days=7)
    assert _row(db, case, key).status == R.LE_PROCESS_REQUIRED
    cara = _le(db, case, "Carabinieri")
    brief = desk.generate_letter(db, case, cara, "le_brief", actor=None, ref=key)
    row = _row(db, case, key)
    assert row.status == R.LE_PROCESS_REQUIRED and row.path_step == "le_only_redirect"
    assert f"#{brief.id} is still a draft" in row.next_action["text"]
    desk.mark_sent(db, case, db.get(Correspondence, brief.id), actor=None, sent_at=T0 + timedelta(hours=5),
                   due_days=3)
    db.commit()
    row = _row(db, case, key, now=T0 + timedelta(hours=6))
    assert row.status == bs.AWAITING and row.source == "le_route" and row.path_step == "le_route_open"
    assert row.status_text == "LE briefed, awaiting LE process" and not row.overdue
    na = row.next_action
    assert na["kind"] == "wait" and f"letter #{brief.id}" in na["text"] and "record it (LE filed)" in na["text"]
    late = _row(db, case, key, now=T0 + timedelta(days=4))
    assert late.next_action["kind"] == "chase" and "Chase the officer" in late.next_action["text"]
    # a person records that LE filed (and can undo it)
    from test_block_status import _Access

    acc = _Access()
    acc.case, acc.user = case, type("U", (), {"id": None})()
    res = bs.confirm_step(db, acc, key, step="le_filed", note="portal reference noted")
    assert res["timeline_id"] and _row(db, case, key).path_step == "le_filed"
    with pytest.raises(bs.BlockError):
        bs.confirm_step(db, acc, key, step="outcome", outcome="frozen")  # an amount: Confirm status
    bs.confirm_step(db, acc, key, step="undo")
    assert _row(db, case, key).path_step == "le_route_open"


# --------------------------------------------------------------------------- MEXC: 48 hours from the temporary freeze
def test_mexc_temporary_freeze_starts_the_48h_clock_and_alerts_ahead(db, case):
    mexc = _entity(db, "MEXC")
    order = _sent_order(db, case, mexc, at=T0)
    reply = _reply(db, case, order, MEXC_TEMP, T0 + timedelta(hours=1))
    at = reply.occurred_at.replace(tzinfo=UTC)
    row = _row(db, case, f"o{order.id}", now=at + timedelta(hours=1))
    assert row.org_key == "mexc" and row.path.path.key == "victim_report"
    assert row.path.freeze_at == at and row.path.suggests == "hold_discretionary"
    keys = {c["key"]: c for c in row.clocks if c.get("source") == "playbook"}
    assert keys["victim_report.le_request"]["due_at"] == at + timedelta(hours=48)  # from MEXC's freeze, not our letter
    # the police-report proof also runs from MEXC's freeze (not our letter), so it never reads "passed" too early
    assert keys["victim_report.police_acceptance"]["due_at"] == at + timedelta(hours=48)
    assert row.next_deadline["due_at"] <= at + timedelta(hours=48)
    na = row.next_action  # our deadline first: answer MEXC with the receipt; the LE brief follows
    assert na["kind"] == "answer" and "template=info_response" in na["href"] and "Clock:" in na["text"]
    assert "temporarily frozen" in na["text"] and "police report receipt" in na["text"]
    # the scheduler's overdue pass: high-severity alert ahead of the deadline, once
    desk.check_overdue(db, case, now=at + timedelta(hours=25))
    first = _notes(db, case, "provider_deadline")
    assert first and all(n.severity == "high" for n in first) and "MEXC" not in first[0].title
    assert any(n.payload.get("request") == f"o{order.id}" and n.payload.get("phase") == "ahead" for n in first)
    desk.check_overdue(db, case, now=at + timedelta(hours=26))
    assert len(_notes(db, case, "provider_deadline")) == len(first)
    desk.check_overdue(db, case, now=at + timedelta(hours=49))
    assert any(n.payload.get("phase") == "due" for n in _notes(db, case, "provider_deadline"))


# --------------------------------------------------------------------------- KuCoin: 30-day auto-lift
def test_kucoin_hold_expiry_counts_only_once_a_person_confirms_the_hold(db, case, client_for):
    from test_block_status import _order

    order = _order(case, "KuCoin")
    at = order.sent_at.replace(tzinfo=UTC) + timedelta(hours=6)
    reply = _reply(db, case, order, KUCOIN_HOLD, at)
    key = f"o{order.id}"
    row = _row(db, case, key, now=at + timedelta(hours=1))
    assert row.suggestion["status"] == R.HOLD_PLACED and row.hold_expires_at is None
    assert row.path.suggests == "hold_discretionary" and row.path_step != "hold_discretionary"
    desk.check_overdue(db, case, now=at + timedelta(days=28))
    assert not _notes(db, case, "hold_expiring")  # nobody confirmed the hold
    inv = client_for("investigator", case=case, email="inv-path-kucoin@tests.example")
    r = inv.post(f"/cases/{case.id}/blocks/{key}/confirm", data={
        "status": "hold_placed", "reply_id": str(reply.id), "amount": "0.0568", "asset": "ETH",
        "csrf_token": csrf_token(inv, f"/cases/{case.id}/blocks")})
    assert r.status_code == 200
    row = _row(db, case, key, now=at + timedelta(days=1))
    assert row.path_step == "hold_discretionary" and row.hold_expires_at is not None
    assert abs(row.hold_expires_at - (at + timedelta(days=30))) < timedelta(days=1)
    assert row.next_action["kind"] == "le" and "Hold in place until" in row.next_action["text"]
    assert "stating the freeze duration" in row.next_action["text"] and "digitally signed" in row.next_action["text"]
    desk.check_overdue(db, case, now=at + timedelta(days=28))
    notes = _notes(db, case, "hold_expiring")
    assert len(notes) == 1 and notes[0].severity == "high" and notes[0].payload["request"] == key


# --------------------------------------------------------------------------- Gate: private parties excluded
def test_gate_pi_letter_never_goes_to_its_le_channel_and_its_refusal_routes_to_le(db, case):
    gate = _entity(db, "Gate")
    pb = directory.load_catalogue().by_key["gate"].playbook
    assert pb.who("gate.le") == "le_only" and not pbm.may_use(pb.who("gate.le"), "pi")
    lert = "le-desk@gate-demo.example"
    g = mg.guide(mg.Inputs(authority_name="Gate", case_reference=case.reference, letter_kind="stop_order",
                           letter_id=1, mailbox="case-desk@aegis.example", manual=True,
                           channels=(mg.Channel(lert, verified=True, source="catalogue", purpose="le_request",
                                                who=pb.who("gate.le")),)))
    assert lert not in [s.address for s in g.to] and g.why_for(lert) == "Not suggested: " + pbm.LE_ONLY_REASON
    order = _sent_order(db, case, gate)
    _reply(db, case, order, GATE_LE, T0 + timedelta(hours=3))
    row = _row(db, case, f"o{order.id}")
    assert row.path_step == "le_only_redirect" and row.path.target.key == "le_freeze"
    na = row.next_action
    assert na["kind"] == "le" and "template=le_brief" in na["href"] and "victim report" in na["text"]


# --------------------------------------------------------------------------- exports, page, derivation rules
def test_exports_and_page_show_the_path_step_and_clocks(db, case, client_for):
    _italian(db, case)
    circle = db.scalar(select(Entity).where(Entity.name == "Circle (USDC issuer)"))
    order = _sent_order(db, case, circle)
    _reply(db, case, order, CIRCLE_COURT, T0 + timedelta(hours=2))
    adm = client_for("admin", case=case, email="admin-path@tests.example")
    csv = adm.get(f"/cases/{case.id}/blocks/export.csv").text
    head = csv.splitlines()[0].split(",")
    assert head[-5:] == ["path_step", "instrument", "next_deadline", "hold_expires_at", "tickets"]
    line = next(x for x in csv.splitlines() if "Circle" in x)
    assert "LE process required" in line and "a US or French court order" in line
    md = adm.get(f"/cases/{case.id}/blocks/export.md").text
    assert "- Path: LE process required" in md and "- Route:" in md
    page = adm.get(f"/cases/{case.id}/blocks").text
    assert "LE process required" in page and "cross-border" in page and "Record a step" in page
    assert "What the next step needs" in page
    api = adm.get(f"/api/cases/{case.id}/blocks").json()
    r = next(x for x in api["rows"] if x["key"] == f"o{order.id}")
    assert r["path"]["step"] == "le_only_redirect" and r["next_action"]["evidence"]
    # recording a step through the page (audited); read-only members cannot
    ro = client_for("read_only", case=case, email="ro-path@tests.example")
    assert "Record a step" not in ro.get(f"/cases/{case.id}/blocks").text
    resp = adm.post(f"/cases/{case.id}/blocks/o{order.id}/path", data={
        "step": "outcome", "outcome": "funds_moved", "csrf_token": csrf_token(adm, f"/cases/{case.id}/blocks")},
        follow_redirects=False)
    assert resp.status_code == 303
    row = _row(db, case, f"o{order.id}")
    assert row.path_step == "outcome" and row.path.outcome == "funds_moved" and row.next_action["kind"] == "trace"


def test_declines_and_steps_follow_the_playbook(db, case):
    from test_block_status import _order

    order = _order(case, "KuCoin")
    _reply(db, case, order, "We are unable to locate any account associated with the addresses provided.",
           order.sent_at.replace(tzinfo=UTC) + timedelta(hours=3))
    row = _row(db, case, f"o{order.id}")
    assert row.status == R.DECLINED_NO_ASSETS and row.path_step == "outcome"
    assert row.path.outcome == "declined_terminal"
    cat = directory.load_catalogue()
    assert P.our_path(cat.by_key["okx"].playbook, "pi").kind == "private_notice"  # a notice to its help desk
    assert P.our_path(cat.by_key["t3-fcu"].playbook, "pi") is None  # LE only for us
    assert P.STEPS[0] == "notice_sent" and P.RANK["outcome"] == len(P.STEPS) - 1


def test_the_counsel_brief_is_for_counsel_only(db, case):
    _italian(db, case)
    circle = db.scalar(select(Entity).where(Entity.name == "Circle (USDC issuer)"))
    order = _sent_order(db, case, circle)
    _reply(db, case, order, CIRCLE_COURT, T0 + timedelta(hours=2))
    counsel = Entity(name="Example Counsel LLP (demo)", category=EntityCategory.LEGAL_COUNSEL)
    db.add(counsel)
    db.flush()
    db.add(LEContact(case=case, entity_id=counsel.id, agency="Example Counsel LLP (demo)", role="US counsel"))
    db.commit()
    a = next(x for x in desk.case_authorities(db, case, include_prospects=False) if x.name.startswith("Example Counsel"))
    assert next(o for o in desk.template_options(a, None) if o["key"] == "counsel_brief")["available"]
    letter = desk.generate_letter(db, case, a, "counsel_brief", actor=None, ref=f"o{order.id}")
    assert letter.meta["follow_up_of"] == f"o{order.id}" and "tracing declaration" in letter.body_markdown
    row = _row(db, case, f"o{order.id}")
    assert row.links and row.links[0]["counsel"] and not row.links[0]["sent"]


def test_the_le_brief_from_the_authority_page(db, case, client_for):
    _italian(db, case)
    circle = db.scalar(select(Entity).where(Entity.name == "Circle (USDC issuer)"))
    order = _sent_order(db, case, circle)
    _reply(db, case, order, CIRCLE_COURT, T0 + timedelta(hours=2))
    cara = _le(db, case, "Carabinieri")
    inv = client_for("investigator", case=case, email="inv-path-brief@tests.example")
    url = f"/cases/{case.id}/authorities/{cara.key}"
    page = inv.get(f"{url}?template=le_brief&ref=o{order.id}").text
    assert f'<option value="o{order.id}" selected>' in page and 'data-for="le_brief"' in page
    r = inv.post(f"{url}/letters", data={"template": "le_brief", "brief_ref": f"o{order.id}", "ref": "c1",
                                         "csrf_token": csrf_token(inv, url)}, follow_redirects=False)
    assert r.status_code == 303
    letter = db.scalars(select(Correspondence).where(Correspondence.case_id == case.id)
                        .order_by(Correspondence.id.desc())).first()
    assert letter.meta["template_key"] == "le_brief" and letter.meta["follow_up_of"] == f"o{order.id}"
    ext = client_for("external", case=case, email="ext-path-brief@tests.example").get(url).text
    assert 'data-for="le_brief"' not in ext or f'value="o{order.id}"' not in ext
