"""Recovery plan (app.blocks.recovery, app.domain.evidence_requirements, app/web/routes_recovery.py, /recovery-plan): the
ranked moves built from the block requests, the latest trace, the on-chain readings, the watch list and the evidence on
file; untouched targets; the cross-border move; the evidence checklist and its waivers; roles; the page, the Overview
card, the API, the LE brief pack and the skill. The demo case plus synthetic replies (every address, ticket and
number is made up). Offline: no model, no mail, no chain."""

import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from conftest import csrf_token
from sqlalchemy import select

from app import services
from app.ai import providers
from app.blocks import recovery as rp
from app.db.models import (
    Alert,
    AuditEvent,
    Entity,
    EvidenceFolder,
    EvidenceItem,
    FreezeCheck,
    StopOrder,
    StopOrderStatus,
    TraceNode,
    WatchItem,
)
from app.domain import evidence_requirements as er
from app.freeze import abi
from app.tracing.freeze import freeze_candidates

NOW = datetime.now(tz=UTC)
TETHER_ACK = ("Thank you for contacting Tether Compliance.\n\nThis is an automated response. Your request has been "
              "received and ticket #482913 has been created. Tether will only act upon appropriate legal process "
              "submitted by a law enforcement agency.\n\nTether Compliance")
CIRCLE_COURT = ("Thank you for your message. Circle requires a valid court order from a US or French court before it "
                "can block an address holding USDC.")
TRON_NEW = abi.b58check_encode(bytes([0x41]) + bytes(range(1, 21)))
NEW_DEPOSIT = (f"The funds were forwarded to a new deposit address {TRON_NEW} belonging to UID: 48213977. Please send "
               "us the transaction hash and proof of ownership.")


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(providers, "get_provider", lambda: None)


@pytest.fixture
def case(db, tmp_path):
    from test_block_status import fresh_case

    c = fresh_case(db, tmp_path)
    services.run_trace(db, c, provider_mode="fixture")
    db.refresh(c)
    return c


def _plan(db, case) -> rp.Plan:
    db.expire_all()
    return rp.build(db, case)


def _ent(db, name) -> Entity:
    return db.scalar(select(Entity).where(Entity.name == name))


def _cand(db, case, name):
    return next(c for c in freeze_candidates(db, services.latest_run(db, case)) if c.entity_name == name)


def _sent(db, case, entity, address, *, chain, at=None) -> StopOrder:
    order = StopOrder(case=case, entity=entity, kind="freeze", status=StopOrderStatus.SENT, subject="Freeze request",
                      body_markdown=f"Please block {address}.", sent_at=at or NOW - timedelta(days=1), sent_via="email",
                      recipient_email="desk@provider-demo.example",
                      identifiers={"chain": chain, "addresses": [{"chain": chain, "address": address}],
                                   "amounts": {"deposit": "250,000 USDT"}})
    db.add(order)
    db.commit()
    return order


def _reply(db, case, order, text, at):
    from test_block_status import _reply as reply

    return reply(db, case, order, text, at=at, mailbox=True)


def _reading(db, case, address, balance, *, chain="tron", blacklisted=False):
    db.add(FreezeCheck(case_id=case.id, chain=chain, address=address, issuer="Tether", token_symbol="USDT",
                       token_contract="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", status="ok", blacklisted=blacklisted,
                       balance=Decimal(balance), checked_at=NOW - timedelta(minutes=5), block_number=71_000_000,
                       raw_sha256="ab" * 32, meta={"balance_raw": str(int(Decimal(balance) * 10**6))}))
    db.commit()


def _traced_in(db, case, address, usd):
    """The latest trace put `usd` into `address` (its node's taint): a balance up to 5x that is the case's money."""
    run = services.latest_run(db, case)
    for n in db.scalars(select(TraceNode).where(TraceNode.run_id == run.id)).all():
        if n.address.address == address:
            n.taint_usd = Decimal(usd)
    db.commit()


def _italian(db, case):
    from test_block_path import _italian as italian

    italian(db, case)


def _circle_court(db, case):
    _italian(db, case)
    circle = _ent(db, "Circle (USDC issuer)")
    addr = _cand(db, case, "Circle (USDC issuer)").identifiers[0].address
    order = _sent(db, case, circle, addr, chain="ethereum")
    _reply(db, case, order, CIRCLE_COURT, NOW - timedelta(hours=20))
    return order


# --------------------------------------------------------------------------- moves and ranking
def test_untouched_freezable_targets_appear_with_the_prefilled_letter(db, case):
    plan = _plan(db, case)
    circle, tether = _ent(db, "Circle (USDC issuer)"), _ent(db, "Tether (USDT issuer)")
    c = plan.find(f"entity-{circle.id}")
    t = plan.find(f"entity-{tether.id}")
    # one source of truth (freeze_board.provider_target): Circle acts on LE process only, so its move leads with the
    # board row's LE step (a US case agent, through the IC3 complaint); the prefilled notice is the next action
    assert c is not None and c.untouched and c.kind == "le" and c.actionable and c.target is not None
    assert c.href == c.target.step.href and "/authorities/le-" in c.href, c.href
    notice = f"/cases/{case.id}/authorities/entity-{circle.id}?template=stop_order#generate"
    assert any(a.get("href") == notice and not a.get("primary") for a in c.actions), c.actions
    # both Circle wallets forwarded everything on (the USDC was swapped to ETH): nothing to blacklist there, so the
    # move stays (read them on-chain / re-trace) at $0 and ranks below the moves about where the money sits now
    assert c.value == 0 and "moved on" in c.basis and "0x57de" in c.basis
    # IC3 (a complaint intake) files nothing; but on this US victim's case a US case agent (through the IC3
    # reference) can ask Circle directly, ahead of the slower cross-border route through the prosecutor on the case
    assert "US case agent can ask directly" in c.likelihood_why
    assert "IC3" not in c.route["le"] and c.route["agent"]["jur"] == "US" and "Slower:" in c.text
    assert any("LE cover letter" in a["label"] for a in c.actions)  # Circle acts on LE process: brief in parallel
    assert t is not None and t.untouched and t.value == pytest.approx(1359.90) and "nobody has asked" in t.reason
    assert plan.moves.index(c) > plan.moves.index(plan.find("identify"))
    assert plan.moves.index(c) > plan.moves.index(t)  # the freezable balance nobody has asked about comes first
    assert plan.totals["untouched"] >= 2 and plan.totals["untouched_usd"] >= 1359.90
    # the requests already sent and waiting: their clocks, never a move
    waiting = {m.authority.name for m in plan.waiting}
    assert {"Rainbet", "KuCoin"} <= waiting and all(m.clock for m in plan.waiting if m.authority.name == "Rainbet")
    assert not {m.authority.name for m in plan.moves if m.authority is not None} & waiting
    assert any("on-chain freeze readings" in n for n in plan.notes)


def test_large_freezable_usdt_with_a_provider_ack_beats_a_small_unhosted_wallet(db, case):
    tether = _ent(db, "Tether (USDT issuer)")
    addr = _cand(db, case, "Tether (USDT issuer)").identifiers[0].address
    order = _sent(db, case, tether, addr, chain="tron")
    _reply(db, case, order, TETHER_ACK, NOW - timedelta(hours=20))
    _reading(db, case, addr, "250000")
    _traced_in(db, case, addr, 250000)
    # a small unhosted wallet moved funds after the trace (a watch-list alert)
    run = services.latest_run(db, case)
    small = min((n for n in db.scalars(select(TraceNode).where(TraceNode.run_id == run.id)).all()
                 if n.address.entity_id is None and 0 < float(n.taint_usd or 0) < 5000), key=lambda n: n.taint_usd)
    item = db.scalar(select(WatchItem).where(WatchItem.case_id == case.id, WatchItem.address_id == small.address_id)) \
        or services.add_watch(db, case, small.address)
    db.add(Alert(watch_item_id=item.id, severity="high", tx_hash="0x" + "3" * 64, message="moved",
                 created_at=run.finished_at.replace(tzinfo=UTC) + timedelta(minutes=1)))
    db.commit()
    plan = _plan(db, case)
    t = plan.find(f"o{order.id}")
    r = plan.find("retrace")
    assert t is not None and r is not None
    assert t.kind == "le" and t.step == "provider_ack" and t.value == pytest.approx(250000)
    assert t.basis.startswith("$250,000 on-chain, not frozen") and "LE process" in t.likelihood_why
    assert "funds moved" in r.reason
    assert plan.moves.index(t) < plan.moves.index(r) and t.score > r.score
    # the board row's step (freeze_board.provider_target): the station on the path has no officer on file, so the
    # step adds the officer's contact; the LE brief the reply asks for, to the reachable LE, is the next action
    assert t.target is not None and t.href == t.target.step.href and t.actions[0]["label"] == "Add the officer's contact"
    assert any("template=le_brief" in (x.get("href") or "") and f"ref=o{order.id}" in x["href"] for x in t.actions)
    assert "has no named officer or e-mail on file" in t.text
    ev = {e["key"]: e["state"] for e in t.evidence}
    assert ev["balance_reading"] == "have" and ev["prior_ticket_ref"] == "have"


def test_circle_cross_border_move_on_an_italian_case(db, case):
    order = _circle_court(db, case)
    plan = _plan(db, case)
    m = plan.find(f"o{order.id}")
    assert m is not None and m.kind == "cross_border" and m.route["kind"] == "cross_border"
    assert m.step == "le_only_redirect" and "Start the cross-border route for Circle" in m.title
    assert "Procura" in m.title and "cross-border" in m.likelihood_why  # the PM issues the cross-border instruments
    assert "template=le_brief" in m.href and m.effort >= rp.EFFORT["cross_border"]
    assert "cannot ask directly" in m.text and "MLAT" in m.text
    ev = {e["key"]: e["state"] for e in m.evidence}
    assert ev["domestic_order"] == "le" and ev["tx_list_copyable"] == "have" and ev["native_vs_bridged_stmt"] == "letter"
    assert ev["trace_report_run"] == "missing" and ev["balance_reading"] == "missing"


def test_evidence_have_and_missing_follow_what_is_on_file(db, case):
    order = _circle_court(db, case)
    db.add(EvidenceItem(case=case, folder=EvidenceFolder.CHAIN_REPORTS, title="Trace report (snapshot)",
                        source_type="trace_report", sha256="cd" * 32))
    db.commit()
    addr = _cand(db, case, "Circle (USDC issuer)").identifiers[0].address
    db.add(FreezeCheck(case_id=case.id, chain="ethereum", address=addr.lower(), issuer="Circle", token_symbol="USDC",
                       token_contract="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", status="ok", blacklisted=False,
                       balance=Decimal(50000), checked_at=NOW, block_number=23_000_000,
                       meta={"balance_raw": str(50000 * 10**6)}))
    db.commit()
    m = _plan(db, case).find(f"o{order.id}")
    ev = {e["key"]: e for e in m.evidence}
    assert ev["trace_report_run"]["state"] == "have" and ev["trace_report_run"]["ids"]
    assert ev["balance_reading"]["state"] == "have" and "block 23000000" in ev["balance_reading"]["source"]
    assert m.value >= 50000 and "$50,000 on-chain, not frozen" in m.basis
    # the generic checklist: the demo's complaint receipts and letter of authorisation, a missing ownership proof
    h = er.holdings(db, case, run=services.latest_run(db, case))
    items = {i["key"]: i for i in er.check(h, ["police_report", "ic3_ref", "loa", "ownership_proof", "court_order",
                                              "incident_narrative", "freeze_duration_stmt"])}
    assert items["police_report"]["state"] == "have" and items["police_report"]["ids"]
    assert items["ic3_ref"]["state"] == "have" and items["loa"]["state"] == "have"
    assert items["ownership_proof"]["state"] == "missing" and items["ownership_proof"]["how"]
    # a statement counts as "in the letter" only when the chosen letter writes it (the LE brief does; a stop order not)
    assert items["court_order"]["state"] == "le" and items["freeze_duration_stmt"]["state"] == "missing"
    assert er.check(h, ["freeze_duration_stmt"], emits=er.emits_for("?template=le_brief"))[0]["state"] == "letter"
    assert er.check(h, ["english_version"])[0]["state"] == "letter"


def test_waivers_are_for_case_admins_and_audited_without_the_reason(db, case, client_for):
    order = _circle_court(db, case)
    url = f"/cases/{case.id}/recovery-plan"
    inv = client_for("investigator", case=case, email="inv-rp1@tests.example")
    r = inv.post(f"{url}/waive", data={"csrf_token": csrf_token(inv, url), "key": "trace_report_run", "reason": "x"},
                 follow_redirects=False)
    assert r.status_code == 403
    adm = client_for("admin", case=case, email="adm-rp1@tests.example")
    page = adm.get(url).text
    assert f'action="/cases/{case.id}/recovery-plan/waive"' in page
    r = adm.post(f"{url}/waive", data={"csrf_token": csrf_token(adm, url), "key": "trace_report_run",
                                       "reason": "the officer has the trace report already", "move": f"o{order.id}"},
                 follow_redirects=False)
    assert r.status_code == 303 and "done=waived" in r.headers["location"]
    m = _plan(db, case).find(f"o{order.id}")
    tr = next(e for e in m.evidence if e["key"] == "trace_report_run")
    assert tr["state"] == "waived" and tr["waiver"]["reason"] == "the officer has the trace report already"
    ev = db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id).order_by(AuditEvent.id.desc())).first()
    assert ev.detail.get("op") == "waive_evidence" and ev.detail.get("requirement") == "trace_report_run"
    assert "officer" not in json.dumps(ev.detail)
    bad = adm.post(f"{url}/waive", data={"csrf_token": csrf_token(adm, url), "key": "not_a_key", "reason": "x"})
    assert bad.status_code == 400
    adm.post(f"{url}/waive", data={"csrf_token": csrf_token(adm, url), "key": "trace_report_run", "undo": "1"})
    m = _plan(db, case).find(f"o{order.id}")
    assert next(e for e in m.evidence if e["key"] == "trace_report_run")["state"] == "missing"


# --------------------------------------------------------------------------- page, roles, card, API
def test_page_card_api_and_roles(db, case, client_for):
    url = f"/cases/{case.id}/recovery-plan"
    adm = client_for("admin", case=case, email="adm-rp2@tests.example")
    page = adm.get(url)
    assert page.status_code == 200 and "<h1>Recovery plan</h1>" in page.text
    # Circle acts on LE process only: its move is the board row's LE step (freeze_board.provider_target)
    assert "Get a US case agent on Circle (USDC issuer)" in page.text and "not asked yet" in page.text
    assert f'href="/cases/{case.id}/blocks"' in page.text and "Waiting on others" in page.text
    assert "Open the stop order" in page.text and "Waive" in page.text and "LE brief pack" in page.text
    inv = client_for("investigator", case=case, email="inv-rp2@tests.example").get(url).text
    assert "Open the stop order" in inv and "LE brief pack" in inv and ">Waive<" not in inv
    ro = client_for("read_only", case=case, email="ro-rp2@tests.example").get(url)
    assert ro.status_code == 200 and "Get a US case agent on Circle (USDC issuer)" in ro.text
    assert "Open the stop order" not in ro.text and "LE brief pack" not in ro.text and ">Waive<" not in ro.text
    assert f'action="/cases/{case.id}/blocks/refresh"' not in ro.text
    assert client_for("external", case=case, email="ext-rp2@tests.example").get(url).status_code == 403
    ov = adm.get(f"/cases/{case.id}?tab=overview").text
    assert 'id="recovery-plan"' in ov and f"/cases/{case.id}/recovery-plan#m-entity-" in ov
    blocks = adm.get(f"/cases/{case.id}/blocks").text
    assert f'href="/cases/{case.id}/recovery-plan"' in blocks and "rp-subnav" in blocks
    api = adm.get(f"/api/cases/{case.id}/recovery-plan").json()
    assert any(m["untouched"] for m in api["moves"]) and api["moves"][0]["rank"] == 1
    assert api["totals"]["in_play_usd"] > 0
    assert "advisory" in api and all("score" in m and "evidence" in m for m in api["moves"])
    # "Read new replies" goes back to the plan
    r = adm.post(f"/cases/{case.id}/blocks/refresh", data={"csrf_token": csrf_token(adm, url), "next": url},
                 follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == url


def test_masked_contacts_for_read_only_members(db, case, client_for):
    _circle_court(db, case)
    from app.domain import evidence as ev

    refs = ev.known_references(case)
    assert refs
    ro = client_for("read_only", case=case, email="ro-rp3@tests.example").get(f"/cases/{case.id}/recovery-plan").text
    assert all(r not in ro for r in refs)


# --------------------------------------------------------------------------- actions: watch, freeze watch
def test_watch_move_adds_unhosted_wallets_to_the_watch_list(db, case, client_for):
    run = services.latest_run(db, case)
    nodes = [n for n in db.scalars(select(TraceNode).where(TraceNode.run_id == run.id)).all()
             if n.address.entity_id is None and {"dormant", "trace_next"} & set(n.flags or [])
             and float(n.taint_usd or 0) >= 1000 and n.address.address_type.value not in ("victim", "contract")
             and not n.address.address.endswith("_PENDING")]
    assert nodes
    for w in case.watch_items:
        if w.address_id in {n.address_id for n in nodes}:
            w.active = False
    db.commit()
    m = _plan(db, case).find("watch")
    assert m is not None and m.kind == "watch" and m.actions[0]["post"].endswith("/recovery-plan/watch")
    url = f"/cases/{case.id}/recovery-plan"
    ro = client_for("read_only", case=case, email="ro-rp4@tests.example")
    assert ro.post(f"{url}/watch", data={"csrf_token": csrf_token(ro, url), "address_id": [str(nodes[0].address_id)]}
                   ).status_code == 403
    inv = client_for("investigator", case=case, email="inv-rp4@tests.example")
    assert "Add to the watch list" in inv.get(url).text
    r = inv.post(f"{url}/watch", data={"csrf_token": csrf_token(inv, url),
                                       "address_id": [str(x) for x in m.actions[0]["fields"]["address_id"]]},
                 follow_redirects=False)
    assert r.status_code == 303 and "done=watch" in r.headers["location"]
    assert _plan(db, case).find("watch") is None or len(_plan(db, case).find("watch").related) < len(m.related)
    assert inv.post(f"{url}/watch", data={"csrf_token": csrf_token(inv, url), "address_id": ["999999"]}
                    ).status_code == 404


def test_reply_naming_a_new_wallet_proposes_a_freeze_watch_for_investigators_only(db, case, client_for):
    from test_block_status import _order

    order = _order(case, "KuCoin")
    _reply(db, case, order, NEW_DEPOSIT, NOW - timedelta(hours=3))
    plan = _plan(db, case)
    # a deposit address belonging to a KuCoin UID is at KuCoin itself: ask KuCoin to extend the hold, no issuer watch
    assert plan.find(f"fwatch:tron:{TRON_NEW}") is None
    ku = plan.find(f"o{order.id}")
    assert ku.kind == "answer" and {"ownership_proof", "tx_list_copyable"} <= {e["key"] for e in ku.evidence}
    assert f"Ask {ku.authority.name} to extend the hold" in ku.text and TRON_NEW not in ku.text
    from app.domain import correspondence as desk

    letter = desk.generate_letter(db, case, ku.authority, "info_response", actor=None, ref=ku.key)
    assert TRON_NEW in letter.body_markdown and "48213977" in letter.body_markdown
    assert "extend the hold" in letter.body_markdown
    # an external wallet a reply names: one click to watch it for an issuer freeze (investigators only)
    _reply(db, case, order, f"Please note the user also sent funds to the external address {TRON_NEW}.",
           NOW - timedelta(hours=2))
    plan = _plan(db, case)
    m = plan.find(f"fwatch:tron:{TRON_NEW}")
    assert m is not None and m.sensitive and m.actions[0]["post"].endswith("/freeze/watch")
    assert m.actions[0]["fields"]["next"] == f"/cases/{case.id}/recovery-plan"
    url = f"/cases/{case.id}/recovery-plan"
    inv = client_for("investigator", case=case, email="inv-rp5@tests.example")
    assert TRON_NEW in inv.get(url).text
    ro = client_for("read_only", case=case, email="ro-rp5@tests.example").get(url).text
    assert TRON_NEW not in ro
    r = inv.post(f"/cases/{case.id}/freeze/watch", data={"csrf_token": csrf_token(inv, url), "chain": "tron",
                                                         "address": TRON_NEW, "source_note": "named in a reply",
                                                         "next": url}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == url
    assert _plan(db, case).find(f"fwatch:tron:{TRON_NEW}") is None


# --------------------------------------------------------------------------- the LE brief pack
def test_le_brief_pack_has_the_brief_the_manifest_the_movements_and_the_readings(db, case, client_for):
    order = _circle_court(db, case)
    key = f"o{order.id}"
    url = f"/cases/{case.id}/recovery-plan/pack/{key}.zip"
    assert client_for("read_only", case=case, email="ro-rp6@tests.example").get(url).status_code == 403
    inv = client_for("investigator", case=case, email="inv-rp6@tests.example")
    r = inv.get(url)
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    assert {"manifest.json", "manifest.md", "brief.md", "movements.csv", "freeze_readings.csv"} <= names
    man = json.loads(z.read("manifest.json"))
    assert man["case"] == case.reference and man["move"]["key"] == key
    assert "preview" in man["brief"]["source"] and "Circle" in z.read("brief.md").decode()
    import hashlib

    for f in man["files"]:
        assert hashlib.sha256(z.read(f["name"])).hexdigest() == f["sha256"]
    ids = {e["id"] for e in man["evidence"]}
    police = [e for e in case.evidence_items if e.source_type in ("police_report", "complaint_receipt")]
    assert {e.id for e in police} <= ids and all("sha256" in e for e in man["evidence"])
    assert any(c["key"] == "domestic_order" and c["state"] == "le" for c in man["checklist"])
    assert "tx_hash" in z.read("movements.csv").decode().splitlines()[0]
    ev = db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id, AuditEvent.action == "EXPORT")
                    .order_by(AuditEvent.id.desc())).first()
    assert ev.detail.get("kind") == "le_brief_pack" and ev.detail.get("has_brief") is True
    # a sent brief linked to the request is the one in the pack
    from test_block_path import _le

    from app.domain import correspondence as desk

    brief = desk.generate_letter(db, case, _le(db, case, "Carabinieri"), "le_brief", actor=None, ref=key)
    z = zipfile.ZipFile(io.BytesIO(inv.get(url).content))
    assert json.loads(z.read("manifest.json"))["brief"]["correspondence_id"] == brief.id
    # an untouched target's pack: the LE cover letter preview
    circle = _ent(db, "Tether (USDT issuer)")
    r = inv.get(f"/cases/{case.id}/recovery-plan/pack/entity-{circle.id}.zip")
    assert r.status_code == 200 and "brief.md" in zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert inv.get(f"/cases/{case.id}/recovery-plan/pack/o999999.zip").status_code == 404


# --------------------------------------------------------------------------- the skill
def test_recovery_plan_skill_without_reply_details(db, case, client_for):
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership

    tether = _ent(db, "Tether (USDT issuer)")
    addr = _cand(db, case, "Tether (USDT issuer)").identifiers[0].address
    order = _sent(db, case, tether, addr, chain="tron")
    _reply(db, case, order, TETHER_ACK, NOW - timedelta(hours=20))
    assert "recovery-plan" in skills.SKILLS and skills.SKILLS["recovery-plan"].needs_ai
    user = client_for("read_only", case=case, email="ro-rp7@tests.example").user
    access = CaseAccess(case=case, user=user, role=effective_role(db, user, case), member=membership(db, user, case))
    res = skills.run_skill(db, access, "recovery-plan")
    assert "**Recovery plan**" in res.markdown and "Circle" in res.markdown and "Advisory" in res.markdown
    assert "482913" not in res.markdown  # their ticket: only when "AI reads mailbox replies" is on
    assert res.source == "rule_based" and any(a.get("href", "").endswith("/recovery-plan") for a in res.actions)


def test_a_traced_wallet_holding_far_more_than_was_traced_in_reads_as_a_possible_service_wallet(db, case):
    """A balance far above the traced inflow (an exchange / swap hot wallet, a pooled service) is not the case's
    money: the value at stake is what was traced in, the move says to identify the owner first, and its odds drop."""
    tether = _ent(db, "Tether (USDT issuer)")
    cand = _cand(db, case, "Tether (USDT issuer)")
    addr, traced = cand.identifiers[0].address, float(cand.identifiers[0].taint_usd)
    _reading(db, case, addr, "1030000")
    t = _plan(db, case).find(f"entity-{tether.id}")
    assert t.value == pytest.approx(traced) and t.value < 1030000
    assert "possibly an exchange / service hot wallet" in t.basis and "identify the owner" in t.basis
    assert "its owner is asked first" in t.likelihood_why
    _traced_in(db, case, addr, 1_000_000)  # the trace really put it there: the case's money
    t = _plan(db, case).find(f"entity-{tether.id}")
    assert t.value == pytest.approx(1030000) and "hot wallet" not in t.basis


def test_a_wallet_the_trace_attributes_to_a_service_counts_only_what_was_traced_in(db, case):
    """A traced wallet the trace labels as a service's (a swap payout wallet) holds that service's float: its
    balance never inflates the issuer move, which names the owner to ask instead."""
    from app.freeze import service as fz

    tether = _ent(db, "Tether (USDT issuer)")
    svc = next(w for w in fz.wallet_rows(db, case) if w["chain"] == "tron" and w.get("entity")
               and w["entity"] != tether.name)
    _reading(db, case, svc["address"], "1030000")
    t = _plan(db, case).find(f"entity-{tether.id}")
    assert t.value is None or t.value < 1030000
    assert f"ask {svc['entity']}" in t.basis and "not the case's balance" in t.basis
    assert "its owner is asked first" in t.likelihood_why
