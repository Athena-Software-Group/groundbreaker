"""Review fixes of the provider-playbook release: path steps that a later confirmed hold supersedes, clocks a reply
states (their alert lead), a conditional freeze that is none, MEXC's hold and police-proof deadline, a provider-named
destination after the funds left, the LE / counsel brief wording, IC3 never briefed. Synthetic replies on the masked
demo case (every address, ticket and number is made up). Offline: no model, no mail, no chain."""

import io
import json
import zipfile
from datetime import UTC, timedelta

import pytest
from sqlalchemy import select

from app.ai import providers
from app.blocks import classify_rules as R
from app.blocks import path as P
from app.blocks import recovery as rp
from app.blocks import status as bs
from app.db.models import Entity, Notification
from app.domain import correspondence as desk
from app.freeze import abi

TRON_DEST = abi.b58check_encode(bytes([0x41]) + bytes(range(41, 61)))  # synthetic, valid checksum


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


@pytest.fixture
def case(db, tmp_path):
    from test_block_status import fresh_case

    yield fresh_case(db, tmp_path)


def _h():
    import test_block_path as h

    return h


def _access(case):
    from test_block_status import _Access

    acc = _Access()
    acc.case, acc.user, acc.role = case, type("U", (), {"id": None})(), type("R", (), {"value": "investigator"})()
    return acc


def _notes(db, case, event):
    return db.scalars(select(Notification).where(Notification.case_id == case.id, Notification.event_type == event)
                      .order_by(Notification.id)).all()


# --------------------------------------------------------------------------- a later confirmed hold supersedes
def test_a_confirmed_hold_after_a_no_assets_reply_supersedes_it_and_its_clock_runs(db, case):
    from test_block_status import _order

    h = _h()
    order = _order(case, "KuCoin")
    t0 = order.sent_at.replace(tzinfo=UTC)
    h._reply(db, case, order, "We could not find any account associated with the address you provided. No assets are "
                              "held.", t0 + timedelta(hours=3))
    key = f"o{order.id}"
    assert h._row(db, case, key).path.outcome == "declined_terminal"
    second = h._reply(db, case, order, "Update: we have now located the account and placed a hold on it.",
                      t0 + timedelta(days=2))
    bs.confirm(db, _access(case), key, status=R.HOLD_PLACED, reply_id=second.id, amount="1000", asset="USDT")
    at = second.occurred_at.replace(tzinfo=UTC)
    row = h._row(db, case, key, now=at + timedelta(days=1))
    assert row.status == R.HOLD_PLACED and row.path_step == "hold_discretionary"
    lift = next(c for c in row.clocks if c.get("key") == "le_freeze.auto_unfreeze")
    assert not lift["met"] and lift["approx"]  # KuCoin's LE-freeze term, read against a voluntary hold
    # KuCoin's own 7-day temporary restraint (its X post) lapses first
    own = next(c for c in row.clocks if c.get("key") == "victim_report.restraint_lapses")
    assert not own["met"] and not own["approx"] and own["due_at"] < lift["due_at"]
    assert row.hold_expires_at == own["due_at"] and row.next_deadline is not None
    desk.check_overdue(db, case, now=at + timedelta(days=5))
    assert [n.payload["request"] for n in _notes(db, case, "hold_expiring")] == [key]


# --------------------------------------------------------------------------- clocks a reply states
def test_a_reply_stated_deadline_alerts_half_its_span_ahead(db, case):
    h = _h()
    ent = h._entity(db, "Demo Exchange Without Playbook")
    order = h._sent_order(db, case, ent)
    reply = h._reply(db, case, order, "Please provide the police report within 48 hours, otherwise we cannot proceed.",
                     h.T0 + timedelta(hours=1))
    at = reply.occurred_at.replace(tzinfo=UTC)
    row = h._row(db, case, f"o{order.id}", now=at + timedelta(hours=1))
    c = next(c for c in row.clocks if c.get("source") != "playbook")
    assert c["start_at"] == at and P.lead(c) == timedelta(hours=24)
    desk.check_overdue(db, case, now=at + timedelta(hours=12))
    assert not _notes(db, case, "provider_deadline")
    desk.check_overdue(db, case, now=at + timedelta(hours=25))
    notes = _notes(db, case, "provider_deadline")
    assert len(notes) == 1 and "in 23h" in notes[0].title


def test_distinct_clocks_due_close_together_are_both_announced(db, case):
    from test_block_status import _order

    h = _h()
    order = _order(case, "KuCoin")
    t0 = order.sent_at.replace(tzinfo=UTC)
    reply = h._reply(db, case, order, "We have placed a temporary hold on the account for 3 days. Please submit the "
                                      "police report within 71 hours.", t0 + timedelta(hours=1))
    bs.confirm(db, _access(case), f"o{order.id}", status=R.HOLD_PLACED, reply_id=reply.id, amount="10", asset="USDT")
    at = reply.occurred_at.replace(tzinfo=UTC)
    desk.check_overdue(db, case, now=at + timedelta(hours=60))
    assert _notes(db, case, "hold_expiring") and _notes(db, case, "provider_deadline")


# --------------------------------------------------------------------------- a freeze that is only conditional
def test_a_conditional_temporary_freeze_starts_no_clock(db, case):
    h = _h()
    mexc = h._entity(db, "MEXC")
    order = h._sent_order(db, case, mexc)
    h._reply(db, case, order, "MEXC can only place a temporary freeze on an account after we receive a valid police "
                              "report. Please submit it through our form.", h.T0 + timedelta(hours=2))
    row = h._row(db, case, f"o{order.id}")
    assert row.path.freeze_at is None and row.path.suggests is None
    assert not any(c.get("starts") == "provider_freeze_confirmed" for c in row.clocks)
    assert P.temp_freeze_stated("We have temporarily frozen the account.")
    assert not P.temp_freeze_stated("We have not temporarily frozen the account.")


def test_an_unconfirmed_hold_never_sets_the_next_deadline(db, case):
    from test_block_status import _order

    h = _h()
    order = _order(case, "KuCoin")
    h._reply(db, case, order, h.KUCOIN_HOLD, order.sent_at.replace(tzinfo=UTC) + timedelta(hours=2))
    row = h._row(db, case, f"o{order.id}")
    assert row.suggestion is not None and any(c["what"] in P.HOLD_WHAT for c in row.clocks)
    assert row.next_deadline is None or row.next_deadline["what"] not in P.HOLD_WHAT


# --------------------------------------------------------------------------- MEXC: the hold, the receipt, the LE request
MEXC_BOTH = ("We have temporarily frozen the account associated with the deposit address you reported. Please provide "
             "the police report receipt within 48 hours, otherwise the temporary freeze will be lifted. A law "
             "enforcement request must also be submitted via our Law Enforcement Online Request System.")


def test_mexc_freeze_with_an_le_request_is_a_hold_to_confirm_and_the_receipt_comes_first(db, case):
    h = _h()
    mexc = h._entity(db, "MEXC")
    order = h._sent_order(db, case, mexc, at=h.T0)
    order.identifiers = {**order.identifiers, "amounts": {"deposit": "25,000 USDT"}}
    db.commit()
    reply = h._reply(db, case, order, MEXC_BOTH, h.T0 + timedelta(hours=10))
    at = reply.occurred_at.replace(tzinfo=UTC)
    key = f"o{order.id}"
    row = h._row(db, case, key, now=at + timedelta(hours=1))
    assert row.path.freeze_at == at and row.path.suggests == "hold_discretionary"
    assert "victim report" not in row.next_action["text"]  # the provider already holds the funds
    na = row.next_action
    assert na["kind"] == "answer" and "police report receipt" in na["text"] and "info_response" in na["href"]
    plan = rp.build(db, case, now=at + timedelta(hours=1))
    m = plan.find(key)
    assert m.kind == "answer" and m.title.startswith("Answer MEXC by")
    assert "police_report" in [e["key"] for e in m.evidence]  # the reply's ask is on the checklist
    assert any("template=le_brief" in (a.get("href") or "") for a in m.actions)  # the LE brief as the second step
    assert m.value == pytest.approx(25000, rel=0.05) and "cited in our request" in m.basis
    # a person confirms the temporary freeze: no 30-day "hold until" (that is MEXC's limit for LE orders)
    bs.confirm(db, _access(case), key, status=R.HOLD_PLACED, reply_id=reply.id, amount="25000", asset="USDT")
    row = h._row(db, case, key, now=at + timedelta(hours=2))
    assert not any(c.get("key", "").startswith("le_freeze.le_freeze_hold") for c in row.clocks)
    assert row.hold_expires_at is None or row.hold_expires_at <= at + timedelta(days=3)
    # a later letter that does not carry the receipt does not meet the deadline
    a = desk.get_authority(db, case, f"entity-{mexc.id}")
    desk.log_entry(db, case, a, actor=None, direction="out", channel="email", kind="status_request",
                   subject="Follow-up", body="Any news on the account?", stop_order=order,
                   occurred_at=at + timedelta(hours=3), recipients=["desk@provider-demo.example"], due_days=7)
    row = h._row(db, case, key, now=at + timedelta(hours=4))
    pa = next(c for c in row.clocks if c.get("key") == "victim_report.police_acceptance")
    assert not pa["met"]


# --------------------------------------------------------------------------- the funds left: the destination is the lead
def test_funds_withdrawn_to_a_named_wallet_is_the_hottest_lead(db, case):
    from test_block_status import _order

    from app import services

    h = _h()
    services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")
    order = _order(case, "KuCoin")
    h._reply(db, case, order, f"The funds in the account were withdrawn on request to the external address {TRON_DEST} "
                              "(USDT TRC20). No assets remain in the account.",
             order.sent_at.replace(tzinfo=UTC) + timedelta(hours=3))
    row = h._row(db, case, f"o{order.id}")
    assert row.status == R.DECLINED_NO_ASSETS and row.path.suggests == "outcome:funds_moved"
    plan = rp.build(db, case)
    m = next(x for x in plan.moves if x.key.startswith("fwatch:") and TRON_DEST in x.key)
    assert "funds moved" in m.reason and m.urgency >= 3 and "The funds left KuCoin" in m.title
    # the issuer letter is its own move, the address prefilled; never valued at KuCoin's whole stake as if read
    issuer = next(x for x in plan.moves if x.key == f"issuer:tron:{TRON_DEST}")
    tether = next(a for a in issuer.actions if "Tether" in a["label"])
    assert "template=info_request" in tether["href"] and TRON_DEST in tether["href"]
    assert m.value is None and "balance not read" in issuer.basis and issuer.effort >= rp.EFFORT["request"]
    # KuCoin itself still holds the KYC, the withdrawal IP and the destination records: an LE disclosure request
    ku = plan.find(f"o{order.id}")
    assert ku is not None and ku.kind == "le" and "KYC" in ku.text and not any(d["key"] == ku.key for d in plan.done)


# --------------------------------------------------------------------------- Circle-style wording, the briefs
CIRCLE_STYLE = ("Thank you for reaching out. Circle is unable to block the addresses you listed at this time and will "
               "only take such action when legally compelled, pursuant to a valid order from a U.S. or French court or "
               "authority of competent jurisdiction.")


def test_circle_refusal_reads_le_process_and_the_italian_brief_asks_the_pm_for_the_certificate(db, case):
    h = _h()
    h._italian(db, case)
    circle = db.scalar(select(Entity).where(Entity.name == "Circle (USDC issuer)"))
    order = h._sent_order(db, case, circle)
    h._reply(db, case, order, CIRCLE_STYLE, h.T0 + timedelta(hours=2))
    row = h._row(db, case, f"o{order.id}")
    assert row.status == R.LE_PROCESS_REQUIRED and row.path_step == "le_only_redirect"
    proc = h._le(db, case, "Procura")
    body = desk.build_letter(db, case, proc, "le_brief", ref=f"o{order.id}")[1]
    assert "Reg. (EU) 2018/1805 freezing certificate" in body and "immediate freezing is necessary" in body
    assert "ask you to send Circle" not in body  # LE never "sends" a court order
    assert "Domestic order" in body or "domestic order" in body
    assert "native token" in body  # the statement the checklist counts as "in the letter"
    assert "Le identity" not in body


def test_tether_on_tron_points_the_officer_to_the_t3_fcu_form(db, case):
    h = _h()
    tether = db.scalar(select(Entity).where(Entity.name == "Tether (USDT issuer)"))
    order = h._sent_order(db, case, tether)
    order.identifiers = {"chain": "tron", "addresses": [{"chain": "tron", "address": TRON_DEST}]}
    db.commit()
    h._reply(db, case, order, h.TETHER_ACK, h.T0 + timedelta(minutes=5))
    row = h._row(db, case, f"o{order.id}")
    assert row.path.target.key == "t3fcu_tron"
    cara = h._le(db, case, "Carabinieri")
    body = desk.build_letter(db, case, cara, "le_brief", ref=f"o{order.id}")[1]
    assert "T3 FCU" in body and "not published" in body


def test_counsel_pack_without_counsel_on_the_case(db, case, client_for):
    h = _h()
    h._italian(db, case)
    circle = db.scalar(select(Entity).where(Entity.name == "Circle (USDC issuer)"))
    order = h._sent_order(db, case, circle)
    h._reply(db, case, order, h.CIRCLE_COURT, h.T0 + timedelta(hours=2))
    key = f"o{order.id}"
    m = rp.build(db, case).find(key)
    act = next(a for a in m.actions if "brief=counsel" in (a.get("href") or ""))
    assert "counsel for a US or French court order" in act["label"]
    inv = client_for("investigator", case=case, email="inv-review-counsel@tests.example")
    r = inv.get(act["href"])
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.content))
    man = json.loads(z.read("manifest.json"))
    assert "counsel brief" in man["brief"]["source"] and "Dear Counsel" in z.read("brief.md").decode()
