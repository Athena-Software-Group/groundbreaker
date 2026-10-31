"""Freeze & stop-order board (app.blocks.freeze_board; the Authorities tab's "Freeze & stop-order actions" panel, the
"Draft requests for uncontacted targets" generator POST /cases/{id}/stop-orders and the discard route): one row per
target with its status, group and one next step; the generator never drafts a second request to a target already
contacted or answered LE only; duplicate drafts flagged and discarded by a case admin; roles; the page; one pass over
the sources. The demo case plus synthetic replies (every address, ticket and number is made up). Offline."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from urllib.parse import parse_qs, urlparse

import pytest
from conftest import csrf_token
from sqlalchemy import event, select

from app import services
from app.ai import providers
from app.blocks import classify_rules as R
from app.blocks import freeze_board as fb
from app.blocks import recovery as rp
from app.blocks import status as bs
from app.db.models import (
    AuditEvent,
    Entity,
    EntityCategory,
    FreezeCheck,
    StopOrder,
    StopOrderStatus,
)
from app.db.session import engine
from app.domain import request_gate as rg
from app.tracing.freeze import freeze_candidates

NOW = datetime.now(tz=UTC)
_SENT = fb._SENTENCE
CIRCLE_COURT = ("Thank you for your message. Circle requires a valid court order from a US or French court before it "
                "can block an address holding USDC.")
TETHER_LOCAL_LE = ("Thank you for contacting Tether.\n\nThe referenced addresses do not belong to Tether and are not "
                   "controlled by Tether. We do not wish to be drawn into a possible dispute between two parties.\n\nWe "
                   "recommend that you contact local law enforcement authorities to help you with this case and ask "
                   "that you please direct law enforcement to inforequests@tether-demo.example if they have any "
                   "questions. Please be advised that the law enforcement department managing the case must directly "
                   "submit all law enforcement requests to us.")
HOLD_REPLY = "Update: we have located the account and placed a temporary hold on it pending your LE request."


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


def _board(db, case, **kw) -> fb.Board:
    db.expire_all()
    return fb.build(db, case, **kw)


def _ent(db, name) -> Entity:
    return db.scalar(select(Entity).where(Entity.name == name))


def _cand(db, case, name):
    return next(c for c in freeze_candidates(db, services.latest_run(db, case)) if c.entity_name == name)


def _sent(db, case, name, *, chain, at=None) -> StopOrder:
    entity = _ent(db, name)
    address = _cand(db, case, name).identifiers[0].address
    order = StopOrder(case=case, entity=entity, kind="freeze", status=StopOrderStatus.SENT, subject="Freeze request",
                      body_markdown=f"Please block {address}.", sent_at=at or NOW - timedelta(days=1), sent_via="email",
                      recipient_email="desk@provider-demo.example",
                      identifiers={"chain": chain, "addresses": [{"chain": chain, "address": address}],
                                   "amounts": {"deposit": "250,000 USDT"}})
    db.add(order)
    db.commit()
    return order


def _gate(db, case, key, template="stop_order", **kw) -> rg.Decision:
    """The request gate's decision (app.domain.request_gate) for a new `template` letter to counterparty `key`."""
    from app.domain import correspondence as desk

    db.expire_all()
    return rg.gate(db, case, desk.get_authority(db, case, key, run=services.latest_run(db, case)), template, **kw)


def _legacy(db, case, name) -> StopOrder:
    """A generated stop-order draft made past the request gate (app.domain.request_gate): what a case can still hold
    from before the gate (the old "Generate all stop orders"), the board's duplicate flags are for."""
    return services.generate_stop_orders(db, case, services.latest_run(db, case), only=[name], gate=False)[0]


def _reply(db, case, order, text, at):
    from test_block_status import _reply as reply

    return reply(db, case, order, text, at=at, mailbox=True)


def _le_only(db, case):
    """Circle answered "court order" and Tether "contact local law enforcement": both LE process required."""
    circle = _sent(db, case, "Circle (USDC issuer)", chain="ethereum")
    _reply(db, case, circle, CIRCLE_COURT, NOW - timedelta(hours=20))
    tether = _sent(db, case, "Tether (USDT issuer)", chain="tron")
    _reply(db, case, tether, TETHER_LOCAL_LE, NOW - timedelta(hours=10))
    return circle, tether


def _t(board, name) -> fb.Target:
    t = next((x for x in board.targets if x.name == name), None)
    assert t is not None, name
    return t


def _order(case, name):
    from test_block_status import _order as order

    return order(case, name)


def _access(case, role="investigator"):
    from test_block_status import _Access

    acc = _Access()
    acc.case, acc.user, acc.role = case, type("U", (), {"id": None})(), type("R", (), {"value": role})()
    return acc


# --------------------------------------------------------------------------- statuses, groups, next steps
def test_uncontacted_le_only_issuer_leads_with_the_le_route_and_offers_the_notice(db, case):
    board = _board(db, case)
    circle = _t(board, "Circle (USDC issuer)")
    assert circle.status == fb.NOT_CONTACTED and circle.group == fb.ACT and circle.traced_usd == pytest.approx(399247.92)
    # Circle acts on LE process only: the LE route (a US case agent) is the primary step, the notice the second
    assert circle.notice_only and circle.step.kind == "le" and circle.step.label == "Get a US case agent"
    assert circle.step.href and not circle.step.post and "/authorities/le-" in circle.step.href
    assert circle.step.lead.startswith("Circle (USDC issuer) acts on LE process only: the LE route")
    assert "our letter is a notice" in circle.detail
    notice = next(s for s in circle.extra if s.post)
    assert notice.label == "Send notice (flags the wallets)" and notice.post == f"/cases/{case.id}/stop-orders"
    assert notice.fields == {"entity": "Circle (USDC issuer)"} and circle.draftable and circle.skip is None
    assert circle.onchain == {"usd": 0.0, "frozen_usd": 0.0, "checked_at": None, "wallets": 2, "read": 0, "unread": 2}
    assert any(s.label == "Check the balance on-chain" for s in circle.extra)
    # Act now first, ranked by the Recovery plan score; the rest of the groups in order. The trace saw Circle's
    # wallets forward everything on (app.attribution), so its move keeps a $0 value (read them on-chain / re-trace)
    # and Tether's (funds still traced at its wallets) ranks first
    plan = rp.build(db, case)
    act = [t for t in board.targets if t.group == fb.ACT]
    assert [t.score for t in act] == sorted((t.score for t in act), reverse=True)
    assert all(t.score == plan.find(t.key).score for t in act)
    assert act[0] is _t(board, "Tether (USDT issuer)") and circle in act and circle.value == 0
    assert "moved on" in circle.basis
    assert [g["key"] for g in board.groups] == [fb.ACT, fb.WAITING, fb.NOTHING]
    uniswap = _t(board, "Uniswap (Universal Router)")
    assert uniswap.group == fb.NOTHING and "Non-custodial" in uniswap.step.text and not uniswap.step.label


def test_sent_request_awaits_its_reply_and_a_follow_up_only_near_the_due_date(db, case):
    order = _order(case, "KuCoin")
    order.sent_at, order.response_due_at = NOW - timedelta(days=1), NOW + timedelta(days=9)
    db.commit()
    kucoin = _t(_board(db, case), "KuCoin")
    assert kucoin.status == fb.AWAITING and kucoin.group == fb.WAITING and kucoin.status_label == "Sent — awaiting reply"
    assert kucoin.deadline is not None and kucoin.deadline_label == "reply due" and not kucoin.step.label
    assert not any(s.kind == "follow_up" for s in kucoin.extra)  # the day after sending: nothing to chase yet
    assert kucoin.deciding["no"] == f"#{order.id}" and kucoin.skip == ("sent", f"o{order.id}")
    assert fb.skip_text("sent", f"o{order.id}", kucoin) == (
        f"already contacted (request #{order.id}): wait for the reply (reply due {kucoin.deadline:%d %b %Y})")
    order.response_due_at = NOW + timedelta(days=1)
    db.commit()
    kucoin = _t(_board(db, case), "KuCoin")
    follow = next(s for s in kucoin.extra if s.kind == "follow_up")
    assert follow.label == f"Draft a follow-up to request #{order.id}" and "template=status_request" in follow.href


def test_overdue_reply_is_act_now_with_chase(db, case):
    order = _order(case, "KuCoin")
    order.sent_at, order.response_due_at = NOW - timedelta(days=20), NOW - timedelta(days=13)
    db.commit()
    kucoin = _t(_board(db, case), "KuCoin")
    assert kucoin.status == fb.OVERDUE and kucoin.group == fb.ACT and kucoin.step.label == "Chase"
    assert "template=status_request" in kucoin.step.href and kucoin.deadline < NOW


def test_acknowledged_with_ticket_waits(db, case):
    rainbet = _t(_board(db, case), "Rainbet")
    assert rainbet.status == fb.ACKNOWLEDGED and rainbet.group == fb.WAITING
    assert rainbet.ticket == "RB-DEMO-0001" and "RB-DEMO-0001" in rainbet.detail


def test_le_only_replies_brief_le_never_a_new_draft(db, case):
    circle_o, tether_o = _le_only(db, case)
    board = _board(db, case)
    for name, order in (("Circle (USDC issuer)", circle_o), ("Tether (USDT issuer)", tether_o)):
        t = _t(board, name)
        assert t.primary.status == R.LE_PROCESS_REQUIRED, name
        assert t.status == fb.LE_ONLY and t.group == fb.ACT and t.status_label == "LE only / court order"
        assert t.step.kind == "le" and t.step.label in ("Add the officer's contact", "Get a US case agent or court order")
        assert t.step.label != "Draft request" and not t.step.post and not t.draftable
        assert t.skip == ("le_only", f"o{order.id}") and "LE hand-off due" in t.detail
    circle = _t(board, "Circle (USDC issuer)")
    # a US victim with an IC3 reference: the playbook route is a US case agent (Circle acts on a US / FR court order)
    assert circle.step.label == "Get a US case agent or court order"
    tether = _t(board, "Tether (USDT issuer)")
    # the Carabinieri station has no officer on file (the text says so first): the step adds the officer's contact;
    # the brief to the reachable LE the text names is the second button, never a brief to the unreachable station
    assert tether.step.lead.startswith("Carabinieri") and "has no named officer" in tether.step.lead
    assert tether.step.href == f"/cases/{case.id}?tab=evidence&folder=law_enforcement#" + tether.step.href.rsplit("#", 1)[1]
    assert tether.step.perm == "manage_le_contacts"
    alt = tether.extra[0]
    assert alt.label == "Brief Procura della Repubblica di Esempio (demo prosecutor's office)"
    assert "template=le_brief" in alt.href and f"ref=o{tether_o.id}" in alt.href
    procura = next(a for a in board.le_keys.items() if a[0].startswith("Procura"))[1]
    assert f"/authorities/{procura}?" in alt.href
    assert not any(s.kind == "follow_up" for s in circle.extra + tether.extra)  # no letter to the provider again


def test_held_and_frozen_on_chain_are_secured(db, case):
    order = _order(case, "KuCoin")
    reply = _reply(db, case, order, HOLD_REPLY, NOW - timedelta(hours=5))
    bs.confirm(db, _access(case), f"o{order.id}", status=R.HOLD_PLACED, reply_id=reply.id, amount="140",
               asset="USDT")
    tether_o = _sent(db, case, "Tether (USDT issuer)", chain="tron")
    addr = _cand(db, case, "Tether (USDT issuer)").identifiers[0].address
    db.add(FreezeCheck(case_id=case.id, chain="tron", address=addr, issuer="Tether", token_symbol="USDT",
                       token_contract="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", status="ok", blacklisted=True,
                       balance=Decimal(1300), checked_at=NOW - timedelta(minutes=5), block_number=71_000_000,
                       raw_sha256="ab" * 32, meta={"balance_raw": str(1300 * 10**6)}))
    db.commit()
    board = _board(db, case)
    kucoin = _t(board, "KuCoin")
    # a temporary hold LE must turn into an order: Act now from the day it is confirmed, not "Secured"
    assert kucoin.status == fb.HELD and kucoin.held == "140 USDT held (confirmed)" and kucoin.group == fb.ACT
    assert kucoin.deadline_label == "hold lapses" and kucoin.deadline - NOW > fb.HOLD_SOON  # KuCoin's 7-day hold
    assert kucoin.detail == f"LE must act by {kucoin.deadline:%d %b %Y}" and kucoin.step.href
    assert kucoin.basis == "140 USDT held (confirmed)"
    tether = _t(board, "Tether (USDT issuer)")
    # read on-chain, nobody confirmed it yet: "Frozen — confirm or claim it", never under Secured ("nothing to do")
    assert tether.status == fb.FROZEN and tether.group == fb.CLAIM
    assert tether.onchain["frozen_usd"] == pytest.approx(1300, rel=0.01) and tether.onchain["checked_at"] is not None
    assert tether.step.label == "Confirm the freeze" and tether.step.href == f"/cases/{case.id}/blocks#o{tether_o.id}"
    assert tether.skip == ("frozen", f"o{tether_o.id}")


def test_hold_lapsing_soon_is_act_now(db, case):
    order = _order(case, "KuCoin")
    reply = _reply(db, case, order, HOLD_REPLY, NOW - timedelta(days=1))
    bs.confirm(db, _access(case), f"o{order.id}", status=R.HOLD_PLACED, reply_id=reply.id, amount="140",
               asset="USDT")
    kucoin = _t(_board(db, case, now=NOW), "KuCoin")
    exp = kucoin.primary.hold_expires_at
    assert kucoin.status == fb.HELD and kucoin.group == fb.ACT and exp is not None
    # two days before the hold lapses (and once it lapsed) the same target is back in Act now: brief LE for the order
    for now in (exp - timedelta(days=2), exp + timedelta(hours=1)):
        late = _t(_board(db, case, now=now), "KuCoin")
        assert late.status == fb.HELD and late.group == fb.ACT, now
        assert late.step.href and late.deadline_label in ("hold lapses", "hold lapsed")
    assert _t(_board(db, case, now=exp - timedelta(days=2)), "KuCoin").step.label == "Brief LE before the hold lapses"
    lapsed = _t(_board(db, case, now=exp + timedelta(hours=1)), "KuCoin")
    assert lapsed.step.label == "Ask whether the hold still stands" and lapsed.deadline_label == "hold lapsed"


def _frozen_on_chain(db, case, name="Tether (USDT issuer)"):
    addr = _cand(db, case, name).identifiers[0].address
    db.add(FreezeCheck(case_id=case.id, chain="tron", address=addr, issuer="Tether", token_symbol="USDT",
                       token_contract="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", status="ok", blacklisted=True,
                       balance=Decimal(1300), checked_at=NOW, block_number=71_000_000, raw_sha256="cd" * 32,
                       meta={"balance_raw": str(1300 * 10**6)}))
    db.commit()


def test_uncontacted_issuer_frozen_on_chain_is_claimed_by_the_notice(db, case):
    _frozen_on_chain(db, case)
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    # an issuer blacklist traps the funds; it does not tie them to this victim: the case's notice and LE link it.
    # Tether acts on LE process only: the LE route is the primary step, the notice the second button
    assert tether.status == fb.FROZEN and tether.group == fb.CLAIM and "not yet claimed" in tether.detail
    # the route's LE (the Carabinieri station) has no officer on file: add the officer's contact, or write to the
    # reachable LE the route names (the cover letter to the Procura is the alternative)
    assert tether.step.kind == "le" and tether.step.label == "Add the officer's contact"
    assert tether.step.perm == "manage_le_contacts" and "?tab=evidence&folder=law_enforcement#ev-contact-" in tether.step.href
    assert "has no named officer or e-mail on file" in tether.step.lead
    assert "acts on LE process only: brief LE" in tether.step.text
    alt = tether.extra[0]
    assert alt.label.startswith("Cover letter to Procura") and "template=le_cover" in alt.href
    notice = next(s for s in tether.extra if s.post)
    assert notice.label == "Send notice (links the freeze to this case)"
    assert "Nothing to do" not in tether.step.text and tether.draftable and tether.skip is None
    assert tether.notice_only and tether.basis.endswith("frozen on-chain (issuer blacklist)")


def test_frozen_on_chain_le_only_issuer_keeps_the_le_route_once_its_notice_is_drafted(client_for, db, case):
    _frozen_on_chain(db, case)
    board = _board(db, case)
    # the claim's letter is a notice: never counted as a freeze request (the issuer froze the wallets already)
    assert board.generate_label == ("Draft notices to LE-only issuers (2)", False)
    inv = client_for("investigator", case=case, email="fb-r3-claim@tests.example")
    r = _generate(inv, case, entity="Tether (USDT issuer)")
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["so_n"] == ["1"] and q["so_notice"] == [f"entity-{_ent(db, 'Tether (USDT issuer)').id}"]
    page = inv.get(r.headers["location"]).text
    assert "Drafted 1 notice." in page and "freeze request" not in page.split("fb-flash", 1)[1].split("</div>", 1)[0]
    assert "drafted as a notice (it links the on-chain freeze to this case)" in page
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    draft = tether.primary
    assert draft is not None and draft.status == bs.NOT_SENT
    # still frozen, still unclaimed until the notice goes out; the LE route stays the primary step
    assert tether.status == fb.FROZEN and tether.group == fb.CLAIM and tether.notice_only
    assert tether.detail.endswith(f"frozen on-chain by the issuer — notice {fb.req_no(draft)} drafted, not yet sent")
    assert tether.step.kind == "le" and tether.step.label == "Add the officer's contact"
    assert "template=le_cover" in tether.extra[0].href  # the cover letter to the reachable LE
    assert f"send the case's notice {fb.req_no(draft)} in parallel" in tether.step.text
    send = tether.extra[1]
    assert send.label == "Open & send notice" and send.href == f"/cases/{case.id}/stop-orders/{draft.order.id}"
    assert tether.skip == ("draft", draft.key) and not tether.draftable
    names, skipped = fb.generator_plan(_board(db, case), only="Tether (USDT issuer)")
    assert not names and skipped[0][1] == "draft"


def test_info_request_and_draft_ready(db, case):
    order = _order(case, "KuCoin")
    _reply(db, case, order, "Please provide the transaction hash and a copy of the police report so we can review "
                            "your request.", NOW - timedelta(hours=3))
    services.generate_stop_orders(db, case, services.latest_run(db, case), only=["Circle (USDC issuer)"])
    board = _board(db, case)
    kucoin = _t(board, "KuCoin")
    assert kucoin.status == fb.INFO_REQUESTED and kucoin.group == fb.ACT and kucoin.step.label == "Answer their questions"
    circle = _t(board, "Circle (USDC issuer)")
    assert circle.status == fb.DRAFT_READY and circle.group == fb.ACT and circle.extra[0].label == "Open & send notice"
    draft = next(o for o in case.stop_orders if o.entity_id == circle.authority.entity.id and o.status.value == "draft")
    assert circle.extra[0].href == f"/cases/{case.id}/stop-orders/{draft.id}"
    assert circle.skip == ("draft", f"o{draft.id}") and not circle.duplicates  # no sent request: not a duplicate


# --------------------------------------------------------------------------- the generator
def _generate(client, case, **data):
    page = f"/cases/{case.id}?tab=authorities"
    return client.post(f"/cases/{case.id}/stop-orders", data={"csrf_token": csrf_token(client, page), **data},
                       follow_redirects=False)


def test_generator_drafts_only_uncontacted_targets_and_reports_the_skipped(client_for, db, case):
    circle_o, tether_o = _le_only(db, case)
    before = {o.id for o in case.stop_orders}
    inv = client_for("investigator", case=case, email="fb-gen@tests.example")
    r = _generate(inv, case)
    assert r.status_code == 303
    loc = urlparse(r.headers["location"])
    q = parse_qs(loc.query)
    assert loc.fragment == "freeze" and q["so"] == ["1"] and q["so_n"] == ["0"]
    db.expire_all()
    assert {o.id for o in db.scalars(select(StopOrder).where(StopOrder.case_id == case.id))} == before  # nothing new
    skips = q["so_skip"][0]
    circle, tether = _ent(db, "Circle (USDC issuer)"), _ent(db, "Tether (USDT issuer)")
    assert f"entity-{circle.id}:le_only:o{circle_o.id}" in skips and f"entity-{tether.id}:le_only:o{tether_o.id}" in skips
    assert f"entity-{_ent(db, 'KuCoin').id}:sent:" in skips
    page = inv.get(f"{loc.path}?{loc.query}").text
    assert "No new request drafted." in page
    assert (f"Circle (USDC issuer): answered LE only / court order (request #{circle_o.id}): brief LE instead of "
            "writing again") in page
    assert "KuCoin: already contacted" in page
    audit = db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id,
                                                AuditEvent.action == "STOP_ORDERS_SKIPPED")).all()
    assert audit and "le_only" in audit[-1].detail["reasons"]


def test_generator_on_the_demo_drafts_the_issuers_once(client_for, db, case):
    inv = client_for("investigator", case=case, email="fb-gen2@tests.example")
    page = inv.get(f"/cases/{case.id}?tab=authorities").text
    # both drafts are notices (Circle and Tether act on LE process only): counted as notices, not the primary button
    gen = page.split('class="inline fb-generate"', 1)[1].split("</form>", 1)[0]
    assert "Draft notices to LE-only issuers (2)</button>" in gen and "primary" not in gen
    assert "Generate all stop orders" not in page
    r = _generate(inv, case)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["so_n"] == ["2"]
    db.expire_all()
    drafts = db.scalars(select(StopOrder).where(StopOrder.case_id == case.id,
                                                StopOrder.status == StopOrderStatus.DRAFT)).all()
    assert sorted(o.entity.name for o in drafts) == ["Circle (USDC issuer)", "Tether (USDT issuer)"]
    # pressing it again drafts nothing: the drafts from this trace are ready to send
    r = _generate(inv, case)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["so_n"] == ["0"] and ":draft:o" in q["so_skip"][0]
    # one row's Draft on a contacted target drafts nothing either
    r = _generate(inv, case, entity="KuCoin")
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["so_n"] == ["0"] and q["so_skip"][0].split(":")[1] == "sent"
    db.expire_all()
    assert len(db.scalars(select(StopOrder).where(StopOrder.case_id == case.id,
                                                  StopOrder.status == StopOrderStatus.DRAFT)).all()) == 2


def test_skip_lines_never_echo_the_query():
    board = fb.Board(case_id=1)
    assert fb.skip_lines("<script>:sent:o1,entity-1:evil:o2,entity-9:sent:o3", board) == [
        "the selected target: already contacted (request #3)"]
    assert fb.notice_lines("<b>,entity-1", board) == []


# --------------------------------------------------------------------------- duplicates
def test_duplicate_draft_is_flagged_and_a_case_admin_discards_it(client_for, db, case):
    circle_o, _ = _le_only(db, case)
    # the old "Generate all stop orders": a fresh draft for a target answered LE only
    dup = _legacy(db, case, "Circle (USDC issuer)")
    board = _board(db, case)
    circle = _t(board, "Circle (USDC issuer)")
    assert circle.status == fb.LE_ONLY and circle.primary.key == f"o{circle_o.id}"  # the draft never decides
    assert [d["text"] for d in circle.duplicates] == [
        f"Draft #{dup.id} duplicates request #{circle_o.id} (already answered: LE only) — discard?"]
    inv = client_for("investigator", case=case, email="fb-dup-inv@tests.example")
    tab = inv.get(f"/cases/{case.id}?tab=authorities").text
    assert f"Draft #{dup.id} duplicates request #{circle_o.id}" in tab
    assert f"/stop-orders/{dup.id}/discard" not in tab and "a case admin can discard it" in tab
    tok = csrf_token(inv, f"/cases/{case.id}?tab=authorities")
    assert inv.post(f"/cases/{case.id}/stop-orders/{dup.id}/discard", data={"csrf_token": tok},
                    follow_redirects=False).status_code == 403
    adm = client_for("admin", case=case, email="fb-dup-adm@tests.example")
    tab = adm.get(f"/cases/{case.id}?tab=authorities").text
    assert f'action="/cases/{case.id}/stop-orders/{dup.id}/discard"' in tab
    tok = csrf_token(adm, f"/cases/{case.id}?tab=authorities")
    r = adm.post(f"/cases/{case.id}/stop-orders/{dup.id}/discard",
                 data={"csrf_token": tok, "duplicates": f"o{circle_o.id}"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("#freeze")
    db.expire_all()
    order = db.get(StopOrder, dup.id)
    assert order.status == StopOrderStatus.SUPERSEDED and order.identifiers["discarded"]["duplicates"] == f"o{circle_o.id}"
    ev = db.scalars(select(AuditEvent).where(AuditEvent.object_type == "stop_orders", AuditEvent.object_id == str(dup.id),
                                             AuditEvent.action == "UPDATE")).all()
    assert ev and ev[-1].detail["reason"] == "duplicate_draft"
    assert not _t(_board(db, case), "Circle (USDC issuer)").duplicates
    # the Stop orders table folds the discarded draft into the request it repeated
    tab = adm.get(f"/cases/{case.id}?tab=authorities").text
    table = tab.split('id="stop-orders"', 1)[1].split("</table>", 1)[0]
    assert "+1 superseded draft" in table and f"/stop-orders/{dup.id}\" class=\"mono\">#{dup.id}</a>" in table
    # a discarded (non-draft) order cannot be discarded again
    assert adm.post(f"/cases/{case.id}/stop-orders/{dup.id}/discard", data={"csrf_token": tok},
                    follow_redirects=False).status_code == 409


def test_order_groups_fold_superseded_drafts_into_their_successor(db, case):
    first = _legacy(db, case, "Circle (USDC issuer)")
    second = _legacy(db, case, "Circle (USDC issuer)")
    third = _legacy(db, case, "Circle (USDC issuer)")
    db.expire_all()
    groups = {o.id: [e.id for e in earlier] for o, earlier in fb.order_groups(case.stop_orders)}
    assert groups[third.id] == [second.id, first.id] and first.id not in groups and second.id not in groups
    sent = [o.id for o in case.stop_orders if o.status == StopOrderStatus.SENT]
    assert set(sent) <= set(groups)  # sent ones always visible


# --------------------------------------------------------------------------- roles and the page
def test_read_only_sees_the_board_without_buttons(client_for, db, case):
    _le_only(db, case)
    _legacy(db, case, "Circle (USDC issuer)")
    ro = client_for("read_only", case=case, email="fb-ro@tests.example")
    page = ro.get(f"/cases/{case.id}?tab=authorities")
    assert page.status_code == 200
    panel = page.text.split('id="freeze"', 1)[1].split('id="stop-orders"', 1)[0]
    assert "Freeze &amp; stop-order actions" in page.text and "Act now" in panel and "LE only / court order" in panel
    assert "fb-generate" not in panel and "<button" not in panel
    assert 'class="btn small' not in panel and "/discard" not in panel
    inv = client_for("investigator", case=case, email="fb-inv@tests.example")
    panel = inv.get(f"/cases/{case.id}?tab=authorities").text.split('id="freeze"', 1)[1].split('id="stop-orders"')[0]
    assert "fb-generate" in panel and "Get a US case agent or court order" in panel
    assert "Draft a follow-up to request #" in panel
    ext = client_for("external", case=case, email="fb-ext@tests.example")
    assert 'id="freeze"' not in ext.get(f"/cases/{case.id}?tab=authorities").text


def test_page_renders_every_group_and_the_details_toggle(client_for, db, case):
    _le_only(db, case)
    order = _order(case, "KuCoin")
    reply = _reply(db, case, order, HOLD_REPLY, NOW - timedelta(hours=5))
    bs.confirm(db, _access(case), f"o{order.id}", status=R.HOLD_PLACED, reply_id=reply.id, amount="140",
               asset="USDT")
    adm = client_for("admin", case=case, email="fb-page@tests.example")
    page = adm.get(f"/cases/{case.id}?tab=authorities")
    assert page.status_code == 200
    panel = page.text.split('id="freeze"', 1)[1].split('id="stop-orders"', 1)[0]
    for heading in ("Act now", "Waiting on them", "Nothing to do"):
        assert heading in panel
    assert "<details class=\"fb-details\"><summary>details</summary>" in panel and "<script" not in panel
    assert "Centrally-issued stablecoin" in panel  # the trace rationale, behind the toggle
    assert "Freeze / preservation candidates" not in page.text


# --------------------------------------------------------------------------- one pass
def test_board_reads_each_source_once_and_its_own_queries_do_not_grow_with_targets(db, case, monkeypatch):
    calls: dict[str, int] = {}
    paused = [0]

    def wrap(mod, name):
        fn = getattr(mod, name)

        def inner(*a, **k):
            calls[name] = calls.get(name, 0) + 1
            paused[0] += 1
            try:
                return fn(*a, **k)
            finally:
                paused[0] -= 1
        monkeypatch.setattr(mod, name, inner)

    from app import services as svc
    from app.domain import correspondence as desk
    from app.tracing import freeze as tf

    for mod, name in ((bs, "case_blocks"), (rp, "build"), (fb, "_readings"), (fb, "_awaiting"),
                      (svc, "latest_run"), (tf, "freeze_candidates"), (desk, "case_authorities")):
        wrap(mod, name)
    count, total = [0], [0]

    def on_query(*_a, **_k):
        total[0] += 1
        if not paused[0]:
            count[0] += 1

    def own_queries() -> int:
        db.expire_all()
        count[0] = total[0] = 0
        calls.clear()
        event.listen(engine, "before_cursor_execute", on_query)
        try:
            fb.build(db, case)
        finally:
            event.remove(engine, "before_cursor_execute", on_query)
        assert calls["case_blocks"] == 1 and calls["build"] == 1 and calls["_readings"] == 1, calls
        assert total[0] > 20  # the sources do query (the listener sees them)
        return count[0]

    base = own_queries()
    for i in range(4):  # four more contacted targets
        ent = Entity(name=f"Demo Exchange {i} ({case.reference})", category=EntityCategory.EXCHANGE)
        db.add(ent)
        db.flush()
        db.add(StopOrder(case=case, entity=ent, kind="freeze", status=StopOrderStatus.SENT, subject="Freeze request",
                         body_markdown="Please freeze.", sent_at=NOW - timedelta(days=1), sent_via="email",
                         recipient_email=f"desk{i}@exchange-demo.example", identifiers={}))
    db.commit()
    more = own_queries()
    assert len(_board(db, case).targets) >= 13
    assert more <= base + 2, (base, more)  # the board's own lookups are dictionary reads, not one query per target


# --------------------------------------------------------------------------- review round: freeze & stop-order steps
FROZEN_REPLY = ("We have frozen the account linked to the addresses in your request. The freeze is temporary: it will "
                "be lifted in 7 days unless law enforcement sends a freezing order.")


def _prepared(db, case, corr):
    from app.db.models import MailMessage

    mm = MailMessage(case_id=case.id, correspondence_id=corr.id, letter_key=f"c{corr.id}", direction="out",
                     status="prepared", transport="graph", mailbox="cases@aegis-demo.example",
                     message_id=f"<fb-{corr.id}@aegis-demo.example>", subject="Freeze request",
                     to_addrs=["desk@provider-demo.example"], expires_at=NOW + timedelta(hours=2))
    db.add(mm)
    db.commit()
    return mm


def test_discard_cancels_the_prepared_e_mail_and_the_letter_can_never_be_sent(client_for, db, case):
    from app.db.models import Correspondence, MailMessage, MailStatus
    from app.domain import correspondence as desk
    from app.domain import mail_compose as compose
    from app.domain import mail_send

    circle_o, _ = _le_only(db, case)
    dup = _legacy(db, case, "Circle (USDC issuer)")
    corr, _ = compose.ensure_correspondence(db, dup, desk.get_authority(db, case, f"entity-{dup.entity_id}"), None)
    mm = _prepared(db, case, corr)
    board = _board(db, case, awaiting=mail_send.awaiting_send(db, case.id))
    d = _t(board, "Circle (USDC issuer)").duplicates[0]
    assert d["prepared"] == mm.id and f"Prepared e-mail #{mm.id} for it awaits Send: discarding cancels it." in d["text"]
    adm = client_for("admin", case=case, email="fb-dis-mail@tests.example")
    tab = adm.get(f"/cases/{case.id}?tab=authorities").text
    assert f"and cancel prepared e-mail #{mm.id}" in tab
    tok = csrf_token(adm, f"/cases/{case.id}?tab=authorities")
    # the form's "duplicates" value is ignored: the request it repeats comes from the board
    r = adm.post(f"/cases/{case.id}/stop-orders/{dup.id}/discard", data={"csrf_token": tok, "duplicates": "o1"},
                 follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    order = db.get(StopOrder, dup.id)
    assert order.status == StopOrderStatus.SUPERSEDED and order.identifiers["discarded"]["duplicates"] == f"o{circle_o.id}"
    assert order.identifiers["discarded"]["cancelled_mail"] == [mm.id]
    hist = order.identifiers["status_history"][-1]
    assert hist["status"] == "superseded" and hist["previous"] == "draft" and hist["reason"] == "duplicate_draft"
    assert db.get(MailMessage, mm.id).status == MailStatus.CANCELLED
    assert mail_send.awaiting_send(db, case.id) == []
    assert db.scalars(select(AuditEvent).where(AuditEvent.case_id == case.id,
                                               AuditEvent.action == "MAIL_CANCELLED")).all()
    letter = db.get(Correspondence, corr.id)
    assert fb.discarded(letter)
    # and nothing sends it: the cancelled preview refuses, the letter page offers no e-mail, Mark sent refuses
    try:
        out = mail_send.send(db, _access(case, "admin"), db.get(MailMessage, mm.id), {"confirm_send": "1"})
        assert out.status != "sent"
    except mail_send.SendError:
        pass
    page = adm.get(f"/cases/{case.id}/authorities/correspondence/{corr.id}").text
    assert 'id="email"' not in page
    tok = csrf_token(adm, f"/cases/{case.id}/authorities/correspondence/{corr.id}")
    r = adm.post(f"/cases/{case.id}/authorities/correspondence/{corr.id}/sent", data={"csrf_token": tok},
                 follow_redirects=False)
    assert r.status_code == 409
    db.expire_all()
    assert db.get(Correspondence, corr.id).status.value == "draft" and db.get(MailMessage, mm.id).status.value == \
        "cancelled"


def test_discard_refuses_an_order_the_board_does_not_flag(client_for, db, case):
    from app.db.models import StopOrderOrigin

    lone = services.generate_stop_orders(db, case, services.latest_run(db, case), only=["Circle (USDC issuer)"])[0]
    imported = StopOrder(case=case, entity=_ent(db, "Tether (USDT issuer)"), kind="freeze",
                         status=StopOrderStatus.DRAFT, origin=StopOrderOrigin.IMPORTED, subject="Imported draft",
                         body_markdown="Imported.", identifiers={})
    db.add(imported)
    db.commit()
    adm = client_for("admin", case=case, email="fb-dis-no@tests.example")
    for oid in (lone.id, imported.id):
        tok = csrf_token(adm, f"/cases/{case.id}?tab=authorities")
        r = adm.post(f"/cases/{case.id}/stop-orders/{oid}/discard",
                     data={"csrf_token": tok, "duplicates": f"o{_order(case, 'KuCoin').id}"}, follow_redirects=False)
        assert r.status_code == 409, oid
    db.expire_all()
    assert db.get(StopOrder, lone.id).status == StopOrderStatus.DRAFT
    assert db.get(StopOrder, imported.id).status == StopOrderStatus.DRAFT


def test_api_generator_never_drafts_for_a_contacted_target(client_for, db, case):
    circle_o, _ = _le_only(db, case)
    adm = client_for("admin", case=case, email="fb-api@tests.example")
    tok = csrf_token(adm, f"/cases/{case.id}?tab=authorities")
    before = {o.id for o in case.stop_orders}
    r = adm.post(f"/api/cases/{case.id}/stop-orders", headers={"X-CSRF-Token": tok})
    assert r.status_code == 201 and r.json() == []
    circle = _ent(db, "Circle (USDC issuer)")
    assert f"entity-{circle.id}:le_only:o{circle_o.id}" in r.headers["x-aegis-skipped"]
    assert f"entity-{_ent(db, 'KuCoin').id}:sent:" in r.headers["x-aegis-skipped"]
    r = adm.post(f"/api/cases/{case.id}/stop-orders", json=["Circle (USDC issuer)", "No Such Entity"],
                 headers={"X-CSRF-Token": tok})
    assert r.status_code == 201 and r.json() == [] and "-:unknown:" in r.headers["x-aegis-skipped"]
    db.expire_all()
    assert {o.id for o in db.scalars(select(StopOrder).where(StopOrder.case_id == case.id))} == before


def test_api_generator_drafts_the_uncontacted_issuers(client_for, db, case):
    adm = client_for("admin", case=case, email="fb-api2@tests.example")
    tok = csrf_token(adm, f"/cases/{case.id}?tab=authorities")
    r = adm.post(f"/api/cases/{case.id}/stop-orders", headers={"X-CSRF-Token": tok})
    assert r.status_code == 201
    db.expire_all()
    assert sorted(db.get(StopOrder, o["id"]).entity.name for o in r.json()) == [
        "Circle (USDC issuer)", "Tether (USDT issuer)"]


def test_authority_page_closes_the_stop_order_template_for_a_contacted_target(client_for, db, case):
    circle_o, _ = _le_only(db, case)
    circle = _ent(db, "Circle (USDC issuer)")
    inv = client_for("investigator", case=case, email="fb-auth@tests.example")
    page = inv.get(f"/cases/{case.id}/authorities/entity-{circle.id}?template=stop_order").text
    opt = page.split('id="letter-template"', 1)[1].split('<option value="stop_order"', 1)[1].split("</option>", 1)[0]
    assert "disabled" in opt and "(one open request: see the message above)" in opt and 'id="request-gate"' in page
    assert f"Answered LE only / court order (request #{circle_o.id})" in page
    before = {o.id for o in case.stop_orders}
    tok = csrf_token(inv, f"/cases/{case.id}/authorities/entity-{circle.id}")
    r = inv.post(f"/cases/{case.id}/authorities/entity-{circle.id}/letters",
                 data={"csrf_token": tok, "template": "stop_order"}, follow_redirects=False)
    assert r.status_code == 409 and f"Answered LE only / court order (request #{circle_o.id}): brief LE" in r.text
    db.expire_all()
    assert {o.id for o in db.scalars(select(StopOrder).where(StopOrder.case_id == case.id))} == before
    tether = _ent(db, "Tether (USDT issuer)")
    assert _gate(db, case, f"entity-{tether.id}").kind == rg.LE_BRIEF_ONLY  # answered LE only too
    kucoin = _gate(db, case, f"entity-{_ent(db, 'KuCoin').id}")
    assert kucoin.kind == rg.FOLLOW_UP_ONLY and "only a follow-up tied to it" in kucoin.text


def test_authority_page_still_drafts_a_stop_order_for_an_uncontacted_issuer(client_for, db, case):
    circle = _ent(db, "Circle (USDC issuer)")
    inv = client_for("investigator", case=case, email="fb-auth2@tests.example")
    tok = csrf_token(inv, f"/cases/{case.id}/authorities/entity-{circle.id}")
    r = inv.post(f"/cases/{case.id}/authorities/entity-{circle.id}/letters",
                 data={"csrf_token": tok, "template": "stop_order"}, follow_redirects=False)
    assert r.status_code == 303


def test_skip_flash_names_the_rows_own_next_step(client_for, db, case):
    order = _order(case, "KuCoin")
    order.sent_at, order.response_due_at = NOW - timedelta(days=20), NOW - timedelta(days=13)
    db.commit()
    inv = client_for("investigator", case=case, email="fb-skipstep@tests.example")
    r = _generate(inv, case, entity="KuCoin")
    page = inv.get(r.headers["location"]).text
    assert f"KuCoin: already contacted (request #{order.id}): next step on its row: “Chase”" in page
    assert "Draft a follow-up” on its row" not in page


def test_generator_reports_a_target_it_drafted_nothing_for(client_for, db, case, monkeypatch):
    monkeypatch.setattr(services, "generate_stop_orders", lambda *a, **k: [])
    inv = client_for("investigator", case=case, email="fb-refused@tests.example")
    r = _generate(inv, case)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["so_n"] == ["0"] and q["so_skip"][0].count(":refused:") == 2
    page = inv.get(r.headers["location"]).text
    assert "Circle (USDC issuer): the letter generator drafted nothing for it" in page


def test_generator_flash_says_le_only_issuers_got_a_notice(client_for, db, case):
    inv = client_for("investigator", case=case, email="fb-notice@tests.example")
    r = _generate(inv, case)
    q = parse_qs(urlparse(r.headers["location"]).query)
    circle, tether = _ent(db, "Circle (USDC issuer)"), _ent(db, "Tether (USDT issuer)")
    assert set(q["so_notice"][0].split(",")) == {f"entity-{circle.id}", f"entity-{tether.id}"}
    page = inv.get(r.headers["location"]).text
    assert ("Circle (USDC issuer): drafted as a notice only (it flags the wallets): Circle (USDC issuer) acts on LE "
            "process only, so brief LE in parallel") in page


def test_confirmed_freeze_with_a_lapse_clock_keeps_the_le_step_in_act_now(db, case):
    order = _order(case, "KuCoin")
    reply = _reply(db, case, order, FROZEN_REPLY, NOW - timedelta(hours=5))
    bs.confirm(db, _access(case), f"o{order.id}", status=R.FROZEN, reply_id=reply.id, amount="140", asset="USDT")
    kucoin = _t(_board(db, case), "KuCoin")
    assert kucoin.status == fb.FROZEN and kucoin.primary.status == R.FROZEN
    assert kucoin.step.label and kucoin.step.href and "Nothing to do" not in kucoin.step.text
    # KuCoin's freeze is lifted in 7 days unless LE files: Act now, with the date, not "Secured — nothing to do"
    exp = kucoin.primary.hold_expires_at
    assert exp is not None and kucoin.group == fb.ACT and kucoin.detail == f"LE must act by {exp:%d %b %Y}"
    assert kucoin.deadline == exp and kucoin.deadline_label == "hold lapses"
    assert kucoin.basis == "140 USDT frozen (confirmed)"


def test_status_column_links_the_deciding_request_never_the_duplicate(client_for, db, case):
    circle_o, _ = _le_only(db, case)
    dup = _legacy(db, case, "Circle (USDC issuer)")
    circle = _t(_board(db, case), "Circle (USDC issuer)")
    assert circle.deciding["key"] == f"o{circle_o.id}" and all(r["key"] != f"o{dup.id}" for r in circle.earlier)
    inv = client_for("investigator", case=case, email="fb-deciding@tests.example")
    page = inv.get(f"/cases/{case.id}?tab=authorities").text
    row = page.split(f'id="fb-{circle.key}"', 1)[1].split("</tr>", 1)[0]
    status = row.split('class="fb-status"', 1)[1].split("</td>", 1)[0]
    assert f'href="/cases/{case.id}/stop-orders/{circle_o.id}" class="mono">#{circle_o.id}</a>' in status
    assert f"/stop-orders/{dup.id}\"" not in status and "LE process required" in status


def test_sent_issuer_with_no_reply_shows_the_le_hand_off(db, case):
    _sent(db, case, "Circle (USDC issuer)", chain="ethereum")
    circle = _t(_board(db, case), "Circle (USDC issuer)")
    assert circle.primary.next_action.get("kind") == "le"
    assert circle.status == fb.HANDOFF and circle.group == fb.ACT and circle.status_label == "Sent — LE hand-off due"
    assert circle.step.label == "Get a US case agent or court order" and "/authorities/le-" in circle.step.href
    assert circle.step.lead.startswith("Fastest: get a US case agent assigned")  # the instruction, not the policy


def test_drafted_le_brief_is_the_step_and_leads_the_text(db, case):
    from app.domain import correspondence as desk

    tether_o = _sent(db, case, "Tether (USDT issuer)", chain="tron")
    _reply(db, case, tether_o, TETHER_LOCAL_LE, NOW - timedelta(hours=10))
    t = _t(_board(db, case), "Tether (USDT issuer)")
    le_key = t.primary.next_action["href"].split("/authorities/", 1)[1].split("?", 1)[0]
    brief = desk.generate_letter(db, case, desk.get_authority(db, case, le_key), "le_brief", actor=None,
                                 run=services.latest_run(db, case), ref=f"o{tether_o.id}")
    t = _t(_board(db, case), "Tether (USDT issuer)")
    assert t.step.label == f"Send LE brief #{brief.id}" and t.detail == f"LE brief #{brief.id} drafted, not sent"
    assert t.step.lead == f"Your LE brief #{brief.id} is still a draft: send it."


def test_waiting_lists_money_targets_before_records_requests(db, case):
    waiting = [t for t in _board(db, case).targets if t.group == fb.WAITING]
    money = [bool(t.traced_usd or t.value) for t in waiting]
    assert money == sorted(money, reverse=True), [(t.name, t.traced_usd, t.value) for t in waiting]
    rainbet = next(t for t in waiting if t.name == "Rainbet")
    assert rainbet.detail == "ticket RB-DEMO-0001"


def test_tab_reads_block_rows_once(client_for, db, case, monkeypatch):
    from app.domain import correspondence as desk
    from app.tracing import freeze as tf
    from app.web import routes_authorities as ra

    calls: dict[str, int] = {}

    def wrap(mod, name):
        fn = getattr(mod, name)

        def inner(*a, **k):
            calls[name] = calls.get(name, 0) + 1
            return fn(*a, **k)
        monkeypatch.setattr(mod, name, inner)

    adm = client_for("admin", case=case, email="fb-cost@tests.example")
    for mod, name in ((bs, "case_blocks"), (tf, "freeze_candidates"), (ra, "freeze_candidates"),
                      (desk, "case_authorities")):
        wrap(mod, name)
    page = adm.get(f"/cases/{case.id}?tab=authorities")
    assert page.status_code == 200 and 'class="bk-col"' in page.text
    # one block-row pass for the board and the Block status column; the tab's candidates and counterparties once,
    # plus the Recovery plan's own read (it takes only rows=)
    assert calls["case_blocks"] == 1, calls
    assert calls["freeze_candidates"] == 2 and calls["case_authorities"] <= 2, calls


# --------------------------------------------------------------------------- review round 2
def _letter(db, case, name, kind, *, at=None, due_days=5):
    """A SENT outgoing letter of `kind` to `name`, not tied to a stop order."""
    from app.domain import correspondence as desk

    a = desk.get_authority(db, case, f"entity-{_ent(db, name).id}")
    corr = desk.log_entry(db, case, a, actor=None, direction="out", channel="email", kind=kind,
                          subject="Preservation and information request", body="Please preserve the records.",
                          occurred_at=at or NOW - timedelta(days=1), recipients=["desk@provider-demo.example"],
                          due_days=due_days)
    db.commit()
    return corr


def _letter_reply(db, case, name, letter, text, at):
    from app.db.models import MailDirection, MailMessage, MailStatus
    from app.domain import correspondence as desk

    a = desk.get_authority(db, case, f"entity-{_ent(db, name).id}")
    corr = desk.log_entry(db, case, a, actor=None, direction="in", channel="email", kind="reply",
                          subject="RE: Preservation and information request", body=text, body_format="text",
                          occurred_at=at, in_reply_to=letter, classification="R3")
    mm = MailMessage(case_id=case.id, correspondence_id=corr.id, direction=MailDirection.IN, status=MailStatus.RECEIVED,
                     transport="file", mailbox="investigations@athena-demo.example",
                     message_id=f"<reply-{corr.id}@issuer-demo.example>", subject=corr.subject,
                     from_addr="compliance@circle-demo.example", received_at=at)
    db.add(mm)
    db.flush()
    corr.meta = {**(corr.meta or {}), "source": "mailbox", "untrusted_external": True, "mail_message_id": mm.id,
                 "auto_reply": False, "sender_domain_ok": True}
    db.commit()
    return corr


def test_drafted_notice_keeps_the_le_route_as_the_primary_step(client_for, db, case):
    inv = client_for("investigator", case=case, email="fb-r2-notice@tests.example")
    r = _generate(inv, case)
    assert parse_qs(urlparse(r.headers["location"]).query)["so_n"] == ["2"]
    board = _board(db, case, access=_access(case, "admin"))
    circle, tether = _t(board, "Circle (USDC issuer)"), _t(board, "Tether (USDT issuer)")
    for t, label in ((circle, "Get a US case agent"), (tether, "Add the officer's contact")):
        draft = t.primary
        assert t.status == fb.DRAFT_READY and t.group == fb.ACT and t.notice_only, t.name
        # the LE route is still the row's primary step; the drafted notice is the next button (after the reachable
        # LE's cover letter when the route's LE has no officer on file), the pack stays
        assert t.step.kind == "le" and t.step.label == label and t.step.href, t.name
        assert t.detail == "acts on LE process only: our letter is a notice (draft ready)"
        send = next(s for s in t.extra if s.kind == "send")
        assert send is t.extra[0 if t is circle else 1], t.name
        assert send.label == "Open & send notice" and send.href == f"/cases/{case.id}/stop-orders/{draft.order.id}"
        assert any(s.kind == "pack" and s.href.endswith(f"/pack/{draft.key}.zip") for s in t.extra), t.name
        lead = t.step.lead if t is circle else _SENT.split(t.step.text, maxsplit=1)[1]  # Tether: the blocker first
        assert lead.startswith(f"{t.name} acts on LE process only: the LE route"), t.name
        assert f"your notice {fb.req_no(draft)} flags the wallets: send it in parallel" in lead
        assert t.skip == ("draft", draft.key) and not t.draftable
    # the pack the row links exists (the Recovery plan the pack route builds has the draft's own move)
    adm = client_for("admin", case=case, email="fb-r2-notice-adm@tests.example")
    assert adm.get(f"/cases/{case.id}/recovery-plan/pack/{circle.primary.key}.zip").status_code == 200
    # an ordinary draft (no request sent before) keeps its e-mail button ("Edit & send e-mail": its /email form) and
    # "sent" on its page
    page = adm.get(f"/cases/{case.id}/stop-orders/{circle.primary.order.id}").text
    assert f'stop-orders/{circle.primary.order.id}/email"' in page and '<option value="sent"' in page and "duplicates request" not in page
    # a prepared e-mail for the notice: still the LE route first, the e-mail second
    from app.domain import correspondence as desk
    from app.domain import mail_compose as compose
    from app.domain import mail_send

    order = circle.primary.order
    corr, _ = compose.ensure_correspondence(db, order, desk.get_authority(db, case, circle.key), None)
    mm = _prepared(db, case, corr)
    circle = _t(_board(db, case, access=_access(case, "admin"), awaiting=mail_send.awaiting_send(db, case.id)),
                "Circle (USDC issuer)")
    assert circle.status == fb.PREPARED and circle.step.kind == "le" and circle.step.label == "Get a US case agent"
    assert circle.extra[0].label == "Open & send e-mail (notice)"
    assert circle.extra[0].href == f"/cases/{case.id}/mail/messages/{mm.id}"
    assert circle.detail.endswith("(prepared e-mail awaiting Send)")


def test_info_request_only_target_with_funds_still_gets_the_freeze_request(client_for, db, case):
    letter = _letter(db, case, "Circle (USDC issuer)", "info_request")
    board = _board(db, case)
    t = _t(board, "Circle (USDC issuer)")
    assert t.primary.key == f"c{letter.id}" and t.freeze_open and t.group == fb.ACT
    # a records request asks for no freeze: the freeze request is still to send, drafted by the generator
    ask = t.step if t.step.post else t.extra[0]
    assert ask.post == f"/cases/{case.id}/stop-orders" and ask.fields == {"entity": "Circle (USDC issuer)"}
    assert t.draftable and t.skip is None and "no freeze asked yet" in t.detail
    assert _gate(db, case, t.key).allowed  # the freeze ask the records-only request lacked
    names, skipped = fb.generator_plan(board, only="Circle (USDC issuer)")
    assert names == ["Circle (USDC issuer)"] and not skipped
    # the authority page's stop-order template stays open; a generated draft is not a duplicate of the records request
    inv = client_for("investigator", case=case, email="fb-r2-info@tests.example")
    page = inv.get(f"/cases/{case.id}/authorities/{t.key}?template=stop_order").text
    opt = page.split('id="letter-template"', 1)[1].split('<option value="stop_order"', 1)[1].split("</option>", 1)[0]
    assert "disabled" not in opt
    services.generate_stop_orders(db, case, services.latest_run(db, case), only=["Circle (USDC issuer)"])
    t = _t(_board(db, case), "Circle (USDC issuer)")
    assert not t.duplicates and t.skip is not None and t.skip[0] == "draft"


def test_info_request_answered_le_only_blocks_every_generator(client_for, db, case):
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership

    letter = _letter(db, case, "Circle (USDC issuer)", "info_request", at=NOW - timedelta(days=2))
    _letter_reply(db, case, "Circle (USDC issuer)", letter, CIRCLE_COURT, NOW - timedelta(hours=20))
    circle = _ent(db, "Circle (USDC issuer)")
    t = _t(_board(db, case), "Circle (USDC issuer)")
    assert t.status == fb.LE_ONLY and t.skip == ("le_only", f"c{letter.id}") and not t.draftable
    before = {o.id for o in case.stop_orders}
    user = client_for("investigator", case=case, email="fb-r2-skill@tests.example").user
    access = CaseAccess(case=case, user=user, role=effective_role(db, user, case), member=membership(db, user, case))
    res = skills.run_skill(db, access, "stop-orders", "draft circle")
    db.expire_all()
    assert {o.id for o in db.scalars(select(StopOrder).where(StopOrder.case_id == case.id))} == before
    assert not res.drafts and "Not drafted" in res.markdown and "answered le only" in res.markdown.lower()
    from app.domain import correspondence as desk

    assert _gate(db, case, f"entity-{circle.id}").kind == rg.LE_BRIEF_ONLY
    assert desk.get_authority(db, case, f"entity-{circle.id}") is not None


def test_duplicate_is_flagged_in_the_stop_orders_table_and_on_its_page(client_for, db, case):
    circle_o, _ = _le_only(db, case)
    dup = _legacy(db, case, "Circle (USDC issuer)")
    inv = client_for("investigator", case=case, email="fb-r2-dup-inv@tests.example")
    tab = inv.get(f"/cases/{case.id}?tab=authorities").text
    table = tab.split('id="stop-orders"', 1)[1].split("</table>", 1)[0]
    row = table.split(f'<td class="mono">{dup.id}</td>', 1)[1].split("</tr>", 1)[0]
    assert f"duplicate of #{circle_o.id} (answered LE only)" in row and "a case admin can discard it" in row
    page = inv.get(f"/cases/{case.id}/stop-orders/{dup.id}").text
    assert f"Draft #{dup.id} duplicates request #{circle_o.id}" in page and f'{dup.id}/email"' not in page
    assert '<option value="sent"' not in page and "/discard" not in page
    tok = csrf_token(inv, f"/cases/{case.id}/stop-orders/{dup.id}")
    r = inv.post(f"/cases/{case.id}/stop-orders/{dup.id}/status", data={"csrf_token": tok, "status": "sent"},
                 follow_redirects=False)
    assert r.status_code in (403, 409)
    adm = client_for("admin", case=case, email="fb-r2-dup-adm@tests.example")
    page = adm.get(f"/cases/{case.id}/stop-orders/{dup.id}").text
    assert f'action="/cases/{case.id}/stop-orders/{dup.id}/discard"' in page and f'{dup.id}/email"' not in page
    tok = csrf_token(adm, f"/cases/{case.id}/stop-orders/{dup.id}")
    r = adm.post(f"/cases/{case.id}/stop-orders/{dup.id}/status", data={"csrf_token": tok, "status": "sent"},
                 follow_redirects=False)
    assert r.status_code == 409
    db.expire_all()
    assert db.get(StopOrder, dup.id).status == StopOrderStatus.DRAFT
    table = adm.get(f"/cases/{case.id}?tab=authorities").text.split('id="stop-orders"', 1)[1].split("</table>", 1)[0]
    assert f'action="/cases/{case.id}/stop-orders/{dup.id}/discard"' in table


def test_frozen_rows_with_a_step_are_never_under_secured(db, case):
    tether_o = _sent(db, case, "Tether (USDT issuer)", chain="tron")
    addr = _cand(db, case, "Tether (USDT issuer)").identifiers[0].address
    db.add(FreezeCheck(case_id=case.id, chain="tron", address=addr, issuer="Tether", token_symbol="USDT",
                       token_contract="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", status="ok", blacklisted=True,
                       balance=Decimal(1300), checked_at=NOW - timedelta(minutes=5), block_number=71_000_000,
                       raw_sha256="ef" * 32, meta={"balance_raw": str(1300 * 10**6)}))
    db.commit()
    board = _board(db, case)
    groups = {g["key"]: g for g in board.groups}
    assert all(t.name != "Tether (USDT issuer)" for t in groups.get(fb.SECURED, {}).get("targets", []))
    claim = groups[fb.CLAIM]
    assert claim["label"] == "Frozen — confirm or claim it" and [t.name for t in claim["targets"]] == ["Tether (USDT issuer)"]
    assert claim["targets"][0].step.href == f"/cases/{case.id}/blocks#o{tether_o.id}"
    assert claim["targets"][0].step.label == "Confirm the freeze"
    assert [g["key"] for g in board.groups].index(fb.CLAIM) == 1  # right after Act now, above Waiting on them
    assert "nothing to do" not in {k: h for k, _l, h in fb.GROUPS}[fb.SECURED]


def test_a_draft_from_an_earlier_trace_is_never_replaced_in_bulk(client_for, db, case):
    inv = client_for("investigator", case=case, email="fb-r2-old@tests.example")
    _generate(inv, case)
    db.expire_all()
    first = {o.entity.name: o.id for o in db.scalars(select(StopOrder).where(
        StopOrder.case_id == case.id, StopOrder.status == StopOrderStatus.DRAFT))}
    services.run_trace(db, case, provider_mode="fixture")
    board = _board(db, case)
    circle = _t(board, "Circle (USDC issuer)")
    run = services.latest_run(db, case)
    assert circle.skip == ("draft_old", f"o{first['Circle (USDC issuer)']}") and not circle.draftable
    redraft = next(s for s in circle.extra if s.kind == "redraft")
    assert redraft.label == f"Redraft from trace #{run.id}" and redraft.fields == {
        "entity": "Circle (USDC issuer)", "redraft": "1"}
    assert not board.draftable and board.generate_label == ("Draft freeze requests", False)
    r = _generate(inv, case)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["so_n"] == ["0"] and ":draft_old:o" in q["so_skip"][0]
    db.expire_all()
    assert {o.entity.name: o.id for o in db.scalars(select(StopOrder).where(
        StopOrder.case_id == case.id, StopOrder.status == StopOrderStatus.DRAFT))} == first
    # the row's own Redraft replaces that one draft only
    r = _generate(inv, case, entity="Circle (USDC issuer)", redraft="1")
    assert parse_qs(urlparse(r.headers["location"]).query)["so_n"] == ["1"]
    db.expire_all()
    now_drafts = {o.entity.name: o.id for o in db.scalars(select(StopOrder).where(
        StopOrder.case_id == case.id, StopOrder.status == StopOrderStatus.DRAFT))}
    assert now_drafts["Tether (USDT issuer)"] == first["Tether (USDT issuer)"]
    assert now_drafts["Circle (USDC issuer)"] != first["Circle (USDC issuer)"]


def test_released_and_closed_have_their_own_skip_text_and_a_superseded_sent_order_still_counts(db, case):
    assert fb.skip_text("released", "o12") == "funds returned (request #12)"
    assert fb.skip_text("closed", "o12") == "closed (request #12)"
    assert fb.SKIP_CODE[fb.RELEASED] == "released" and fb.SKIP_CODE[fb.CLOSED] == "closed"
    order = _sent(db, case, "Circle (USDC issuer)", chain="ethereum")
    order.status = StopOrderStatus.SUPERSEDED
    db.commit()
    board = _board(db, case)
    circle = _t(board, "Circle (USDC issuer)")
    assert circle.status != fb.NOT_CONTACTED and not circle.draftable
    assert circle.skip == ("sent", f"o{order.id}") and circle.step.href == f"/cases/{case.id}/stop-orders/{order.id}"
    assert "then marked superseded" in circle.detail
    d = _gate(db, case, circle.key)
    assert d.kind == rg.FOLLOW_UP_ONLY and d.key == f"o{order.id}" and "only a follow-up" in d.text
    names, _ = fb.generator_plan(board)
    assert "Circle (USDC issuer)" not in names


def test_generator_label_counts_requests_and_notices_apart():
    def t(key, notice):
        return fb.Target(key=key, name=key, category="exchange", draftable=True, notice_only=notice)

    assert fb.Board(case_id=1).generate_label == ("Draft freeze requests", False)
    assert fb.Board(case_id=1, targets=[t("a", True), t("b", True)]).generate_label == (
        "Draft notices to LE-only issuers (2)", False)
    assert fb.Board(case_id=1, targets=[t("a", False)]).generate_label == ("Draft freeze request (1)", True)
    assert fb.Board(case_id=1, targets=[t("a", False), t("b", True), t("c", True)]).generate_label == (
        "Draft 1 freeze request + 2 notices", True)


def test_uncontacted_le_only_text_says_what_to_do_and_le_only_offers_the_counsel_pack(db, case):
    circle = _t(_board(db, case), "Circle (USDC issuer)")
    assert "ask for a US case agent to be assigned, quoting reference IC3-DEMO-00000000" in circle.step.lead
    assert "notice flags the wallets; brief" not in circle.step.text  # the move's own parallel-brief sentence
    assert "Fastest LE route" not in circle.step.text
    _le_only(db, case)
    circle = _t(_board(db, case, access=_access(case, "admin")), "Circle (USDC issuer)")
    counsel = next(s for s in circle.extra if s.label == "Counsel brief pack (court order)")
    assert counsel.href.endswith("?brief=counsel") and counsel.perm == "pack"


def test_nothing_to_do_is_not_applicable_and_records_requests_fold_under_waiting(client_for, db, case):
    board = _board(db, case)
    uniswap = _t(board, "Uniswap (Universal Router)")
    assert uniswap.status == fb.NOT_APPLICABLE and uniswap.tone == "neutral" and uniswap.status_label == "Not applicable"
    waiting = next(g for g in board.groups if g["key"] == fb.WAITING)
    assert waiting["records"] and all(not (t.traced_usd or t.value) for t in waiting["records"])
    assert all(t.traced_usd or t.value for t in waiting["main"])
    adm = client_for("admin", case=case, email="fb-r2-records@tests.example")
    panel = adm.get(f"/cases/{case.id}?tab=authorities").text.split('id="freeze"', 1)[1].split('id="stop-orders"', 1)[0]
    rec = panel.split('<details class="fb-records"', 1)[1].split("</table>", 1)[0]
    assert f"Records / takedown requests ({len(waiting['records'])})" in rec
    for t in waiting["records"]:
        assert f'id="fb-{t.key}"' in rec


def test_authority_page_queries_do_not_grow_with_the_case_targets(client_for, db, case):
    circle = _ent(db, "Circle (USDC issuer)")
    adm = client_for("admin", case=case, email="fb-r2-cost@tests.example")
    url = f"/cases/{case.id}/authorities/entity-{circle.id}"
    count = [0]

    def on_query(*_a, **_k):
        count[0] += 1

    def queries() -> int:
        count[0] = 0
        event.listen(engine, "before_cursor_execute", on_query)
        try:
            assert adm.get(url).status_code == 200
        finally:
            event.remove(engine, "before_cursor_execute", on_query)
        return count[0]

    queries()  # warm
    base = queries()
    for i in range(8):
        ent = Entity(name=f"Demo Exchange {i} ({case.reference})", category=EntityCategory.EXCHANGE)
        db.add(ent)
        db.flush()
        db.add(StopOrder(case=case, entity=ent, kind="freeze", status=StopOrderStatus.SENT, subject="Freeze request",
                         body_markdown="Please freeze.", sent_at=NOW - timedelta(days=1), sent_via="email",
                         recipient_email=f"desk{i}@exchange-demo.example", identifiers={}))
    db.commit()
    more = queries()
    assert more <= base + 3, (base, more)


# --------------------------------------------------------------------------- review round 3
def test_duplicate_stays_flagged_once_the_sent_request_it_repeats_is_marked_superseded(client_for, db, case):
    circle_o, _ = _le_only(db, case)
    dup = _legacy(db, case, "Circle (USDC issuer)")
    circle_o.status = StopOrderStatus.SUPERSEDED  # sent_at stays: Circle was contacted
    db.commit()
    circle = _t(_board(db, case), "Circle (USDC issuer)")
    assert [d["order_id"] for d in circle.duplicates] == [dup.id]
    assert circle.duplicates[0]["of"] == f"#{circle_o.id}" and circle.duplicates[0]["of_key"] == f"o{circle_o.id}"
    assert circle.skip == ("sent", f"o{circle_o.id}") and circle.sent_ref == f"o{circle_o.id}"
    assert circle.status == fb.AWAITING and "then marked superseded" in circle.detail and not circle.draftable
    adm = client_for("admin", case=case, email="fb-r3-ghost@tests.example")
    page = adm.get(f"/cases/{case.id}/stop-orders/{dup.id}").text
    assert f"duplicates request #{circle_o.id}" in page
    assert f'{dup.id}/email"' not in page and '<option value="sent"' not in page


def test_le_only_issuer_letter_is_a_notice_before_and_after_it_is_drafted(client_for, db, case):
    letter = _letter(db, case, "Circle (USDC issuer)", "info_request")
    circle = _t(_board(db, case), "Circle (USDC issuer)")
    assert circle.status == fb.HANDOFF and circle.notice_only
    ask = next(s for s in [circle.step, *circle.extra] if s.post)
    assert ask.label == "Send notice (flags the wallets)"
    inv = client_for("investigator", case=case, email="fb-r3-info-notice@tests.example")
    _generate(inv, case, entity="Circle (USDC issuer)")
    circle = _t(_board(db, case), "Circle (USDC issuer)")
    assert circle.primary.key == f"c{letter.id}" and circle.notice_only
    draft = next(o for o in case.stop_orders if o.entity_id == circle.authority.entity.id and o.status.value == "draft")
    labels = [s.label for s in [circle.step, *circle.extra]]
    assert f"Open & send notice #{draft.id}" in labels and not any("freeze request" in x for x in labels)


def test_api_and_assistant_never_draft_over_a_superseded_sent_request(client_for, db, case):
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership

    order = _sent(db, case, "Circle (USDC issuer)", chain="ethereum")
    order.status = StopOrderStatus.SUPERSEDED
    db.commit()
    before = {o.id for o in case.stop_orders}
    adm = client_for("admin", case=case, email="fb-r3-api@tests.example")
    tok = csrf_token(adm, f"/cases/{case.id}?tab=authorities")
    r = adm.post(f"/api/cases/{case.id}/stop-orders", json=["Circle (USDC issuer)"], headers={"X-CSRF-Token": tok})
    circle = _ent(db, "Circle (USDC issuer)")
    assert r.status_code == 201 and r.json() == []
    assert f"entity-{circle.id}:sent:o{order.id}" in r.headers["x-aegis-skipped"]
    access = CaseAccess(case=case, user=adm.user, role=effective_role(db, adm.user, case),
                        member=membership(db, adm.user, case))
    res = skills.run_skill(db, access, "stop-orders", "draft circle")
    assert not res.drafts and f"request #{order.id} to circle (usdc issuer) was sent" in res.markdown.lower()
    assert "only a follow-up tied to it" in res.markdown
    db.expire_all()
    assert {o.id for o in db.scalars(select(StopOrder).where(StopOrder.case_id == case.id))} == before


# --------------------------------------------------------------------------- review round 4: the LE step always leads
def _le_key(board, prefix):
    return next(k for n, k in board.le_keys.items() if n.startswith(prefix))


def _cover(db, case, le_key, *, sent=False, days=6, channel="email"):
    """An LE cover letter to LE contact `le_key`, drafted; `sent`: sent `days` ago (the default 6: its 7-day reply
    clock is nearly due, so the follow-up is offered)."""
    from app.domain import correspondence as desk

    corr = desk.generate_letter(db, case, desk.get_authority(db, case, le_key), "le_cover", actor=None,
                                run=services.latest_run(db, case))
    if sent:
        desk.mark_sent(db, case, corr, actor=None, sent_at=NOW - timedelta(days=days), channel=channel)
    return corr


def _sent_now(db, corr, *, days, due_in):
    """Move LE letter `corr`'s send date and reply clock (sent `days` ago, its reply due in `due_in` days)."""
    db.refresh(corr)
    corr.occurred_at, corr.due_at = NOW - timedelta(days=days), NOW + timedelta(days=due_in)
    db.commit()


def test_overdue_notice_to_an_le_only_issuer_keeps_the_le_step_primary_and_chase_is_an_extra(db, case):
    circle_o = _sent(db, case, "Circle (USDC issuer)", chain="ethereum", at=NOW - timedelta(days=9))
    tether_o = _sent(db, case, "Tether (USDT issuer)", chain="tron", at=NOW - timedelta(days=9))
    board = _board(db, case, access=_access(case, "admin"))
    for name, order in (("Circle (USDC issuer)", circle_o), ("Tether (USDT issuer)", tether_o)):
        t = _t(board, name)
        assert t.primary.next_action.get("kind") == "chase", name  # the reply window passed
        # the notice's reply never freezes an LE-only issuer's wallets: the LE step stays primary, Chase is an extra
        assert t.status == fb.HANDOFF and t.group == fb.ACT and t.step.kind == "le" and t.step.label, name
        assert f"reply to notice #{order.id} overdue" in t.detail, name
        chase = next(s for s in t.extra if s.label == "Chase")
        assert "template=status_request" in chase.href and not chase.post, name
        assert any(s.kind == "pack" for s in t.extra), name  # the plan's move still lists the LE brief pack
        assert t.skip == ("sent", f"o{order.id}") and not t.draftable, name
    circle = _t(board, "Circle (USDC issuer)")
    assert circle.step.label.startswith("Get a US case agent") and "/authorities/" in circle.step.href
    assert "chase it in parallel" in circle.step.text
    tether = _t(board, "Tether (USDT issuer)")
    assert tether.step.label == "Add the officer's contact" and tether.step.perm == "manage_le_contacts"
    assert tether.extra[0].label.startswith("Cover letter to Procura")
    assert fb.skip_text("sent", f"o{tether_o.id}", tether).endswith("next step on its row: “Add the officer's contact”")


def test_le_cover_letter_drafted_then_sent_is_the_le_step_of_an_uncontacted_le_only_issuer(db, case):
    board = _board(db, case)
    tether = _t(board, "Tether (USDT issuer)")
    assert tether.status == fb.NOT_CONTACTED and tether.step.label == "Add the officer's contact"
    station, procura = tether.step.le, _le_key(board, "Procura")
    assert "/authorities/" + procura + "?template=le_cover" in tether.extra[0].href
    # drafted to the reachable LE: "Send LE cover letter #N" (its page), the notice still the extra
    corr = _cover(db, case, procura)
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    assert tether.step.kind == "le" and tether.step.label == f"Send LE cover letter #{corr.id}"
    assert tether.step.href == f"/cases/{case.id}/authorities/correspondence/{corr.id}"
    assert tether.step.lead.startswith(f"Your LE cover letter #{corr.id} to Procura") and "is still a draft" in \
        tether.step.lead
    assert f"LE cover letter #{corr.id} drafted, not sent" in tether.detail and "start it now" not in tether.step.text
    assert any(s.post and s.label == "Send notice (flags the wallets)" for s in tether.extra)
    assert tether.status == fb.NOT_CONTACTED and tether.group == fb.ACT and tether.draftable
    # sent 12 hours ago: the sent text, no follow-up button before the officer's reply is nearly due
    from app.domain import correspondence as desk

    desk.mark_sent(db, case, corr, actor=None, sent_at=NOW - timedelta(hours=12), channel="email")
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    assert tether.step.kind == "le" and tether.step.label == "" and tether.step.href is None
    assert tether.step.lead.startswith(f"LE cover letter #{corr.id} sent") and "reply is due" in tether.step.lead
    assert "status_request" not in "".join(s.href or "" for s in [tether.step, *tether.extra])
    assert "le_cover" not in "".join(s.href or "" for s in [tether.step, *tether.extra])
    assert tether.status == fb.NOT_CONTACTED and tether.group == fb.ACT  # the notice is still to send
    assert any(s.post and s.label == "Send notice (flags the wallets)" for s in tether.extra)
    # the reply nearly due: follow up with the officer, never a second cover letter; the notice stays the extra
    _sent_now(db, corr, days=2, due_in=1)
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    sent_at = (NOW - timedelta(days=2)).strftime("%d %b %Y")
    assert tether.step.label == "Follow up with the officer"
    assert tether.step.href == f"/cases/{case.id}/authorities/{procura}?template=status_request#generate"
    assert tether.step.lead.startswith(f"LE cover letter #{corr.id} sent {sent_at} to Procura")
    assert tether.step.lead.endswith(": follow up with the officer.") and "start it now" not in tether.step.text
    assert "le_cover" not in "".join(s.href or "" for s in [tether.step, *tether.extra])  # no second cover letter
    assert any(s.post and s.label == "Send notice (flags the wallets)" for s in tether.extra)
    assert tether.le_letter["id"] == corr.id and tether.le_letter["sent"] and station != procura
    # overdue: chase the officer
    _sent_now(db, corr, days=9, due_in=-2)
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    assert tether.step.label == "Chase the officer" and "template=status_request" in tether.step.href
    assert "chase the officer" in tether.step.lead


def test_le_cover_letter_to_the_station_with_no_officer_shows_its_own_state(db, case):
    board = _board(db, case)
    station = _t(board, "Tether (USDT issuer)").step.le
    corr = _cover(db, case, station)  # the finding's repro: the cover letter to the route's own LE (le-2)
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    assert tether.step.label == f"Send LE cover letter #{corr.id}"
    assert tether.extra[0].label == "Add the officer's contact" and tether.extra[0].perm == "manage_le_contacts"
    assert tether.extra[1].label.startswith("Cover letter to Procura")
    from app.domain import correspondence as desk

    desk.mark_sent(db, case, corr, actor=None, sent_at=NOW - timedelta(days=6), channel="letter")
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    # sent by post to a contact with no officer or e-mail on file: following it up starts with the officer's contact
    assert tether.step.label == "Add the officer's contact" and tether.step.perm == "manage_le_contacts"
    assert tether.step.href.startswith(f"/cases/{case.id}?tab=evidence&folder=law_enforcement#")
    assert tether.step.lead.startswith(f"LE cover letter #{corr.id} sent") and "to Carabinieri" in tether.step.lead
    follow = tether.extra[0]
    assert follow.label.startswith("Follow-up letter to Carabinieri") and f"/authorities/{station}?" in follow.href
    assert "template=status_request" in follow.href


def test_drafted_notice_and_sent_cover_letter_keep_the_le_step_first(client_for, db, case):
    inv = client_for("investigator", case=case, email="fb-r4-notice-cover@tests.example")
    _generate(inv, case)  # the bulk button drafts both notices
    board = _board(db, case)
    corr = _cover(db, case, _le_key(board, "Procura"), sent=True)
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    draft = tether.primary
    assert tether.status == fb.DRAFT_READY and tether.step.label == "Follow up with the officer"
    assert f"Send your notice #{draft.order.id} in parallel" in tether.step.text
    assert any(s.label == "Open & send notice" and s.href.endswith(f"/stop-orders/{draft.order.id}")
               for s in tether.extra)
    assert f"LE cover letter #{corr.id} sent" in tether.detail


def test_notice_sent_and_le_cover_letter_sent_is_the_le_route_in_progress(db, case):
    tether_o = _sent(db, case, "Tether (USDT issuer)", chain="tron", at=NOW - timedelta(days=9))
    board = _board(db, case)
    corr = _cover(db, case, _le_key(board, "Procura"), sent=True)
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    assert tether.status == fb.LE_ROUTE and tether.group == fb.LE_GROUP
    assert tether.step.label == "Follow up with the officer" and f"LE cover letter #{corr.id} sent" in tether.detail
    assert any(s.label == "Chase" for s in tether.extra)  # the notice's own follow-up stays on the row
    assert tether.deadline_label == "LE reply due" and tether.deadline == tether.le_letter["due_at"]
    assert tether.skip == ("le_route", f"o{tether_o.id}")


def test_target_for_names_the_rows_own_next_step(client_for, db, case):
    from app.domain import correspondence as desk

    tether_o = _sent(db, case, "Tether (USDT issuer)", chain="tron")
    circle_o = _sent(db, case, "Circle (USDC issuer)", chain="ethereum")
    board = _board(db, case)
    for name in ("Tether (USDT issuer)", "Circle (USDC issuer)"):
        row = _t(board, name)
        one = fb.target_for(db, case, None, desk.get_authority(db, case, row.key))
        assert one.step.label == row.step.label and one.status == row.status, name
        why = _gate(db, case, row.key).text
        assert f"next step on its row: “{row.step.label}”" in why, name
    assert _t(board, "Tether (USDT issuer)").step.label == "Add the officer's contact"
    circle = _t(board, "Circle (USDC issuer)")
    inv = client_for("investigator", case=case, email="fb-r4-target-for@tests.example")
    tok = csrf_token(inv, f"/cases/{case.id}/authorities/{circle.key}")
    r = inv.post(f"/cases/{case.id}/authorities/{circle.key}/letters",
                 data={"csrf_token": tok, "template": "stop_order"}, follow_redirects=False)
    assert r.status_code == 409 and f"next step on its row: “{circle.step.label}”" in r.text
    assert tether_o.id and circle_o.id


def test_authority_page_stop_order_never_silently_replaces_a_ready_draft(client_for, db, case):
    inv = client_for("investigator", case=case, email="fb-r4-replace@tests.example")
    _generate(inv, case)  # the bulk button drafts the notices
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    draft = tether.primary.order
    url = f"/cases/{case.id}/authorities/{tether.key}"
    page = inv.get(f"{url}?template=stop_order").text
    opt = page.split('id="letter-template"', 1)[1].split('<option value="stop_order"', 1)[1].split("</option>", 1)[0]
    assert "disabled" not in opt and f"replaces draft #{draft.id}" in opt
    assert f'name="replace_draft" value="o{draft.id}"' in page
    assert f"Draft #{draft.id} (a notice) is ready: open draft #{draft.id}" in page
    before = {o.id for o in case.stop_orders}
    tok = csrf_token(inv, url)
    r = inv.post(f"{url}/letters", data={"csrf_token": tok, "template": "stop_order"}, follow_redirects=False)
    assert r.status_code == 409 and f"open draft #{draft.id}" in r.text
    db.expire_all()
    assert {o.id for o in db.scalars(select(StopOrder).where(StopOrder.case_id == case.id))} == before
    assert db.get(StopOrder, draft.id).status == StopOrderStatus.DRAFT
    # confirmed on the form (the option said it replaces the draft): the new stop order supersedes it
    r = inv.post(f"{url}/letters", data={"csrf_token": tok, "template": "stop_order", "replace_draft": f"o{draft.id}"},
                 follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    assert db.get(StopOrder, draft.id).status == StopOrderStatus.SUPERSEDED


def test_generators_draft_nothing_when_the_board_cannot_be_built(client_for, db, case, monkeypatch):
    def broken(*_a, **_k):
        raise RuntimeError("source down")

    monkeypatch.setattr(rp, "build", broken)
    before = {o.id for o in case.stop_orders}
    inv = client_for("investigator", case=case, email="fb-r4-broken@tests.example")
    r = _generate(inv, case)
    assert r.status_code == 303 and "so_err=board" in r.headers["location"]
    page = inv.get(r.headers["location"]).text
    assert "could not be built, so nothing was drafted" in page and 'id="freeze-error"' in page
    tok = csrf_token(inv, f"/cases/{case.id}?tab=authorities")
    r = inv.post(f"/api/cases/{case.id}/stop-orders", json=None, headers={"X-CSRF-Token": tok})
    assert r.status_code == 503 and "nothing drafted" in r.text
    db.expire_all()
    assert {o.id for o in db.scalars(select(StopOrder).where(StopOrder.case_id == case.id))} == before


def test_assistant_says_why_an_le_only_target_gets_no_new_stop_order(client_for, db, case):
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership

    circle_o, _ = _le_only(db, case)
    adm = client_for("admin", case=case, email="fb-r4-skill@tests.example")
    access = CaseAccess(case=case, user=adm.user, role=effective_role(db, adm.user, case),
                        member=membership(db, adm.user, case))
    circle = _t(_board(db, case), "Circle (USDC issuer)")
    res = skills.run_skill(db, access, "stop-orders", "draft circle")
    assert not res.drafts
    assert f"Answered LE only / court order (request #{circle_o.id})" in res.markdown
    assert f"next step on its row: “{circle.step.label}”" in res.markdown
    assert "Nothing drafted." in res.markdown and "Authorities page" not in res.markdown


# --------------------------------------------------------------------------- r3: the LE letter's state, every notice state
def _hrefs(t) -> str:
    return " ".join(s.href or "" for s in [t.step, *t.step.alts, *t.extra])


def test_notice_sent_within_its_window_follows_the_le_cover_letter_drafted_then_sent(db, case):
    tether_o = _sent(db, case, "Tether (USDT issuer)", chain="tron", at=NOW - timedelta(days=1))
    board = _board(db, case)
    tether = _t(board, "Tether (USDT issuer)")
    assert tether.status == fb.HANDOFF and tether.step.label == "Add the officer's contact" and tether.step.le
    procura = _le_key(board, "Procura")
    corr = _cover(db, case, procura)
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    assert tether.step.label == f"Send LE cover letter #{corr.id}" and tether.group == fb.ACT
    assert tether.step.href == f"/cases/{case.id}/authorities/correspondence/{corr.id}"
    assert f"LE cover letter #{corr.id} drafted, not sent" in tether.detail
    assert "has no named officer" not in tether.step.text  # it went to the reachable LE
    assert "le_brief" not in _hrefs(tether) and "le_cover" not in _hrefs(tether)  # no second LE letter offered
    from app.domain import correspondence as desk

    desk.mark_sent(db, case, corr, actor=None, sent_at=NOW - timedelta(days=6), channel="email")
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    assert tether.step.label == "Follow up with the officer"
    assert tether.step.href == f"/cases/{case.id}/authorities/{procura}?template=status_request#generate"
    assert tether.status == fb.LE_ROUTE and tether.group == fb.LE_GROUP
    assert "le_brief" not in _hrefs(tether) and "le_cover" not in _hrefs(tether)
    assert f"LE cover letter #{corr.id} sent" in tether.detail and tether.skip[1] == f"o{tether_o.id}"


def test_le_only_reply_follows_the_le_cover_letter_drafted_then_sent(db, case):
    _le_only(db, case)
    board = _board(db, case)
    tether = _t(board, "Tether (USDT issuer)")
    assert tether.status == fb.LE_ONLY and tether.step.label == "Add the officer's contact" and tether.step.le
    assert "template=le_brief" in tether.extra[0].href  # the reachable LE's brief, before any LE letter
    procura = _le_key(board, "Procura")
    corr = _cover(db, case, procura)
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    assert tether.step.label == f"Send LE cover letter #{corr.id}"
    assert "le_brief" not in _hrefs(tether) and "le_cover" not in _hrefs(tether)
    from app.domain import correspondence as desk

    desk.mark_sent(db, case, corr, actor=None, sent_at=NOW - timedelta(days=6), channel="email")
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    assert tether.step.label == "Follow up with the officer" and f"/authorities/{procura}?" in tether.step.href
    assert tether.status == fb.LE_ROUTE and "le_brief" not in _hrefs(tether) and "le_cover" not in _hrefs(tether)


def test_le_only_reply_and_a_cover_letter_posted_to_the_station(db, case):
    _le_only(db, case)
    station = _t(_board(db, case), "Tether (USDT issuer)").step.le
    corr = _cover(db, case, station, sent=True, channel="letter")
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    assert tether.le_letter["id"] == corr.id and tether.le_letter["le_key"] == station
    assert tether.step.label == "Add the officer's contact" and "to Carabinieri" in tether.step.lead
    assert tether.extra[0].label.startswith("Follow-up letter to Carabinieri")
    assert tether.status == fb.LE_ROUTE and f"LE cover letter #{corr.id} sent" in tether.detail
    assert "le_brief" not in _hrefs(tether) and "le_cover" not in _hrefs(tether)


def test_le_cover_letter_sent_hours_ago_offers_no_follow_up_yet(db, case):
    procura = _le_key(_board(db, case), "Procura")
    corr = _cover(db, case, procura, sent=True, days=0.5)
    tether = _t(_board(db, case), "Tether (USDT issuer)")
    assert tether.status == fb.NOT_CONTACTED and tether.group == fb.ACT
    assert tether.step.kind == "le" and not tether.step.label and "status_request" not in _hrefs(tether)
    assert tether.step.lead.startswith(f"LE cover letter #{corr.id} sent") and "reply is due" in tether.step.lead
    assert any(s.post and s.label == "Send notice (flags the wallets)" for s in tether.extra)


def test_authority_page_and_assistant_draft_nothing_when_the_target_cannot_be_read(client_for, db, case,
                                                                                      monkeypatch):
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership

    inv = client_for("investigator", case=case, email="fb-r3-gate-error@tests.example")
    _generate(inv, case)  # the bulk button drafts the notices
    circle = _t(_board(db, case), "Circle (USDC issuer)")
    draft = circle.primary.order

    def broken(*_a, **_k):
        raise RuntimeError("source down")

    monkeypatch.setattr(fb, "target_for", broken)
    url = f"/cases/{case.id}/authorities/{circle.key}"
    page = inv.get(f"{url}?template=stop_order").text
    opt = page.split('id="letter-template"', 1)[1].split('<option value="stop_order"', 1)[1].split("</option>", 1)[0]
    assert "disabled" in opt and "freeze board could not be read" in opt
    tok = csrf_token(inv, url)
    r = inv.post(f"{url}/letters", data={"csrf_token": tok, "template": "stop_order"}, follow_redirects=False)
    assert r.status_code == 503 and "freeze board could not be read" in r.text
    db.expire_all()
    assert db.get(StopOrder, draft.id).status == StopOrderStatus.DRAFT
    before = {o.id for o in db.scalars(select(StopOrder).where(StopOrder.case_id == case.id))}
    # the assistant: nothing drafted, and it says why
    adm = client_for("admin", case=case, email="fb-r3-gate-skill@tests.example")
    access = CaseAccess(case=case, user=adm.user, role=effective_role(db, adm.user, case),
                        member=membership(db, adm.user, case))
    for what in ("draft all", "draft circle"):
        res = skills.run_skill(db, access, "stop-orders", what)
        assert not res.drafts, what
    db.expire_all()
    assert {o.id for o in db.scalars(select(StopOrder).where(StopOrder.case_id == case.id))} == before
    d = rg.gate(db, case, circle.authority, "stop_order")
    assert d.kind == rg.UNAVAILABLE and d.text == fb.GATE_ERROR


def test_assistant_draft_all_says_not_drafted_when_the_board_cannot_be_read(client_for, db, case, monkeypatch):
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership

    def broken(*_a, **_k):
        raise RuntimeError("source down")

    monkeypatch.setattr(fb, "target_for", broken)
    adm = client_for("admin", case=case, email="fb-r3-gate-all@tests.example")
    access = CaseAccess(case=case, user=adm.user, role=effective_role(db, adm.user, case),
                        member=membership(db, adm.user, case))
    before = {o.id for o in case.stop_orders}
    res = skills.run_skill(db, access, "stop-orders", "draft all")
    assert not res.drafts and "Not drafted" in res.markdown and "freeze board could not be read" in res.markdown
    circle_o, tether_o = _le_only(db, case)  # one target answered: the single-target reply says the same
    res = skills.run_skill(db, access, "stop-orders", "draft circle")
    assert not res.drafts and "Not drafted" in res.markdown and "freeze board could not be read" in res.markdown
    db.expire_all()
    assert {o.id for o in db.scalars(select(StopOrder).where(StopOrder.case_id == case.id))} == before | {
        circle_o.id, tether_o.id}


# --------------------------------------------------------------------------- r4: the LE letter of a secured LE-only issuer
@pytest.mark.parametrize("status,reply", [(R.FROZEN, "We have frozen the addresses in your request."),
                                          (R.HOLD_PLACED, HOLD_REPLY)])
def test_confirmed_freeze_at_an_le_only_issuer_follows_the_le_letter(db, case, status, reply):
    from app.domain import correspondence as desk

    order = _sent(db, case, "Tether (USDT issuer)", chain="tron")
    rep = _reply(db, case, order, reply, NOW - timedelta(hours=5))
    # the freeze applied to the stop order by a case admin; the hold confirmed by an investigator (a hold applied to
    # the stop order is recorded as frozen)
    bs.confirm(db, _access(case, "admin"), f"o{order.id}", status=status, reply_id=rep.id, amount="1300",
               asset="USDT", apply=status == R.FROZEN)
    board = _board(db, case, access=_access(case, "admin"))
    tether = _t(board, "Tether (USDT issuer)")
    want = fb.FROZEN if status == R.FROZEN else fb.HELD
    group = tether.group
    assert tether.status == want and tether.primary.source in bs.HUMAN_SOURCES and group in (fb.SECURED, fb.ACT)
    if status == R.FROZEN:
        assert group == fb.SECURED  # no lapse clock: secured while LE prepares the order
    station, procura = _le_key(board, "Carabinieri"), _le_key(board, "Procura")
    # no LE letter yet: the route's LE (the station) has no officer on file: add it, or the reachable LE's letter
    assert tether.step.kind == "le" and tether.step.label == "Add the officer's contact" and tether.step.le == station
    assert tether.step.perm == "manage_le_contacts"
    # (the freeze: the LE cover letter so the funds stay held for seizure; the hold: the LE brief for the order)
    letter, tpl = ("Cover letter to", "le_cover") if status == R.FROZEN else ("Brief", "le_brief")
    assert tether.extra[0].label.startswith(f"{letter} Procura")
    assert f"/authorities/{procura}?template={tpl}" in tether.extra[0].href
    # the cover letter drafted to the reachable LE: send it (its page); still frozen / held, same group
    corr = _cover(db, case, procura)
    tether = _t(_board(db, case, access=_access(case, "admin")), "Tether (USDT issuer)")
    assert tether.step.label == f"Send LE cover letter #{corr.id}"
    assert tether.step.href == f"/cases/{case.id}/authorities/correspondence/{corr.id}"
    assert f"LE cover letter #{corr.id} drafted, not sent" in tether.detail
    assert "le_cover" not in _hrefs(tether) and "le_brief" not in _hrefs(tether)
    assert tether.status == want and tether.group == group
    # sent (its reply nearly due): follow up with the officer, never a second cover letter on the row
    desk.mark_sent(db, case, corr, actor=None, sent_at=NOW - timedelta(days=6), channel="email")
    tether = _t(_board(db, case, access=_access(case, "admin")), "Tether (USDT issuer)")
    assert tether.step.lead.startswith(f"LE cover letter #{corr.id} sent") and "to Procura" in tether.step.lead
    assert tether.step.lead.endswith("follow up with the officer.")
    assert tether.step.label == "Follow up with the officer"
    assert tether.step.href == f"/cases/{case.id}/authorities/{procura}?template=status_request#generate"
    assert "le_cover" not in _hrefs(tether) and "le_brief" not in _hrefs(tether)
    assert tether.status == want and tether.group == group and tether.le_letter["id"] == corr.id


def _zip(client, href) -> dict[str, str]:
    import io
    import zipfile

    r = client.get(href)
    assert r.status_code == 200, href
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        return {n: z.read(n).decode("utf-8") for n in z.namelist()}


def test_le_only_row_keeps_its_packs_while_a_duplicate_draft_exists(client_for, db, case):
    order = _sent(db, case, "Circle (USDC issuer)", chain="ethereum", at=NOW - timedelta(days=20))
    _reply(db, case, order, "Thank you for contacting Circle. We have received your request and opened ticket "
                            "CIR-DEMO-1234. We will review it.", NOW - timedelta(days=19))
    order.response_due_at = NOW - timedelta(days=5)  # acknowledged, then the reply window passed: Chase
    db.commit()
    circle = _t(_board(db, case, access=_access(case, "admin")), "Circle (USDC issuer)")
    want = {"LE brief pack (.zip)": f"/cases/{case.id}/recovery-plan/pack/o{order.id}.zip",
            "Counsel brief pack (court order)": f"/cases/{case.id}/recovery-plan/pack/o{order.id}.zip?brief=counsel"}
    assert {s.label: s.href for s in circle.extra if s.kind == "pack"} == want
    score = circle.score
    adm = client_for("admin", case=case, email="fb-r4-dup-pack@tests.example")
    before = {href: _zip(adm, href) for href in want.values()}
    # a duplicate draft (the generator's, repeating the sent request): the board's plan leaves it out, so the row's
    # move, score and both packs stay the sent request's, never the draft the board says to discard
    dup = _legacy(db, case, "Circle (USDC issuer)")
    circle = _t(_board(db, case, access=_access(case, "admin")), "Circle (USDC issuer)")
    assert circle.move.row.key == f"o{order.id}" and circle.primary.key == f"o{order.id}" and circle.duplicates
    assert circle.status == fb.HANDOFF and circle.step.kind == "le" and circle.step.label
    assert circle.score == score
    assert {s.label: s.href for s in circle.extra if s.kind == "pack"} == want
    for href in want.values():
        files = _zip(adm, href)
        assert set(files) == set(before[href]) and "brief.md" in files, href
        assert "second freeze request" not in files["manifest.md"] and f"o{dup.id}" not in files["manifest.json"]
        assert "no LE authority on the case" not in files["manifest.md"]
        assert "No provider request to brief on" not in files["manifest.md"]
    # the duplicate's own move (the Recovery plan page still lists it) keeps its pack
    assert adm.get(f"/cases/{case.id}/recovery-plan/pack/o{dup.id}.zip").status_code == 200


def test_overdue_notice_keeps_its_pack_and_its_rank_when_a_duplicate_is_drafted(client_for, db, case):
    order = _sent(db, case, "Tether (USDT issuer)", chain="tron", at=NOW - timedelta(days=12))
    tether = _t(_board(db, case, access=_access(case, "admin")), "Tether (USDT issuer)")
    pack = f"/cases/{case.id}/recovery-plan/pack/o{order.id}.zip"
    assert tether.status == fb.HANDOFF and any(s.href == pack for s in tether.extra)
    score = tether.score
    dup = _legacy(db, case, "Tether (USDT issuer)")
    tether = _t(_board(db, case, access=_access(case, "admin")), "Tether (USDT issuer)")
    assert tether.duplicates and tether.duplicates[0]["order_id"] == dup.id
    assert tether.move.key == f"o{order.id}" and tether.score == score  # the duplicate never raises the rank
    packs = [s.href for s in tether.extra if s.kind == "pack"]
    assert packs == [pack]
    adm = client_for("admin", case=case, email="fb-r5-dup-tether@tests.example")
    files = _zip(adm, pack)
    assert "brief.md" in files and "send the drafted second freeze request" not in files["manifest.md"]
    # the pack's move is the sent request's, its step the board row's (freeze_board.provider_target: the LE hand-off)
    m = rp.build(db, case, keep=fb.without_duplicates).find(f"o{order.id}")
    assert m is not None and m.target is not None and m.target.step.href == tether.step.href
    assert f"Move: **{m.title}**" in files["manifest.md"]


# --------------------------------------------------------------------------- r4: wallet owners (app.attribution)
def _owned(db, case, owner, kind="exchange_deposit", i=0):
    """A person marks the i-th wallet of the plan's "Identify the owner" move as `owner`'s (a synthetic call)."""
    from app.attribution import service as attr

    chain, address = rp.build(db, case).find("identify").wallets[i]
    attr.mark(db, case, None, chain=chain, address=address, owner=owner, kind=kind)
    db.commit()
    return chain, address


def test_rows_show_who_owns_the_wallets(db, case):
    board = _board(db, case)
    plan = rp.build(db, case)
    kucoin = _t(board, "KuCoin")
    assert kucoin.owners == plan.find(kucoin.move.key).owners and kucoin.owners
    assert any(o["owner"] == "KuCoin" and o["kind"] == "exchange_deposit" for o in kucoin.owners)
    tether = _t(board, "Tether (USDT issuer)")
    assert tether.owners and all(o["kind"] == "unhosted" for o in tether.owners)


def test_owner_move_to_a_service_that_is_no_counterparty_yet_is_a_row(client_for, db, case):
    chain, address = _owned(db, case, "Exchange Demo-X")
    plan = rp.build(db, case)
    move = plan.find(f"owner:{chain}:{address}")
    assert move is not None and move.authority is None
    board = _board(db, case, access=_access(case, "admin"))
    t = _t(board, "Exchange Demo-X")
    # its own row in Act now, ranked by the owner move's score; never drafted by the generator
    assert t.key.startswith("owner-") and "demo" not in t.key.lower() and t.authority is None
    assert t.status == fb.NOT_CONTACTED and t.group == fb.ACT and t.move.key == move.key and t.score == move.score
    assert t.value == move.value and t.category == "exchange" and not t.draftable and t.skip is None
    assert t.owners and t.owners[0]["owner"] == "Exchange Demo-X" and t.owners[0]["kind"] == "exchange_deposit"
    assert t.detail.startswith("nobody has asked yet · identified as the owner of")
    # not a counterparty yet: the step says so (no button back to the tab itself), the evidence is the button
    assert not t.step.label and t.step.lead.startswith("Exchange Demo-X is not a counterparty of the case yet")
    assert "Ask Exchange Demo-X to freeze the account behind" in t.step.text
    assert t.extra[0].label == "Who owns it (evidence)" and t.extra[0].href.endswith("/recovery-plan#owners")
    names, _skipped = fb.generator_plan(board)
    assert "Exchange Demo-X" not in names
    inv = client_for("investigator", case=case, email="fb-r4-owner-inv@tests.example")
    panel = inv.get(f"/cases/{case.id}?tab=authorities").text.split('id="freeze"', 1)[1].split('id="stop-orders"')[0]
    assert f'id="fb-{t.key}"' in panel and "owner: " in panel and "Exchange Demo-X · exchange deposit address" in panel
    # a person's free-text owner name (no catalogue organisation) is restricted: masked below view_restricted
    ro = client_for("read_only", case=case, email="fb-r4-owner-ro@tests.example")
    panel = ro.get(f"/cases/{case.id}?tab=authorities").text.split('id="freeze"', 1)[1].split('id="stop-orders"')[0]
    assert "Demo-X" not in panel and "a person&#39;s attribution" in panel


def test_owner_move_to_an_uncontacted_counterparty_is_its_next_step(db, case):
    entity = Entity(name="Exchange Demo-Y", category=EntityCategory.EXCHANGE)
    db.add(entity)
    db.flush()
    # a counterparty of the case nobody wrote to: a draft discarded before it was sent
    db.add(StopOrder(case=case, entity=entity, kind="freeze", status=StopOrderStatus.SUPERSEDED, subject="Freeze",
                     body_markdown="(discarded)"))
    db.commit()
    assert _t(_board(db, case), "Exchange Demo-Y").status == fb.NOT_APPLICABLE  # no funds traced at it
    chain, address = _owned(db, case, "Exchange Demo-Y")
    move = rp.build(db, case).find(f"owner:{chain}:{address}")
    assert move is not None and move.authority is not None and move.authority.key == f"entity-{entity.id}"
    t = _t(_board(db, case, access=_access(case, "admin")), "Exchange Demo-Y")
    assert t.key == f"entity-{entity.id}" and t.status == fb.NOT_CONTACTED and t.group == fb.ACT
    assert t.score == move.score and t.value == move.value and t.move.key == move.key
    # the freeze request to the exchange, the deposit address prefilled
    assert t.step.kind == "draft" and t.step.label == "Open the letter to Exchange Demo-Y"
    assert t.step.href == (f"/cases/{case.id}/authorities/entity-{entity.id}?template=info_request&freeze="
                           f"{chain}:{address}#generate")
    assert t.step.lead.startswith("Ask Exchange Demo-Y to freeze the account behind")
    assert any(s.label == "Who owns it (evidence)" for s in t.extra) and not t.draftable


def test_owner_move_to_a_contacted_service_that_waits_leads_its_row(db, case):
    chain, address = _owned(db, case, "Rainbet", kind="casino")
    move = rp.build(db, case).find(f"owner:{chain}:{address}")
    assert move is not None and move.authority is not None
    rainbet = _t(_board(db, case), "Rainbet")
    # already contacted, its own step only the reply it waits for: the owner letter (it quotes the earlier request,
    # never a new stop order) is the row's step, in Act now, with the owner move's value and basis
    assert rainbet.status == fb.ACKNOWLEDGED and rainbet.group == fb.ACT and rainbet.owner_led
    assert rainbet.step.label == "Open the letter to Rainbet" and f"freeze={chain}:{address}" in rainbet.step.href
    assert "template=info_request" in rainbet.step.href and "&ref=" in rainbet.step.href
    assert rainbet.step.lead.startswith(f"{move.title}.")
    assert f"Request {fb.req_no(rainbet.primary)}: acknowledged" in rainbet.step.more  # the reply it waits for
    assert rainbet.value == move.value and rainbet.basis == move.basis and rainbet.score == move.score
    assert [m.key for m in rainbet.owner_moves] == [move.key]
    assert rainbet.owners[0]["short"] == rp._short(address)  # the identified wallet is named first on the row
    assert f"identified as the owner of {rp._short(address)}" in rainbet.detail


def test_owner_move_to_a_contacted_exchange_is_its_step_on_the_board_and_in_the_assistant(client_for, db, case):
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership

    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    plan = rp.build(db, case)
    move = plan.find(f"owner:{chain}:{address}")
    assert move is not None and move.authority is not None and plan.moves[0].key == move.key
    board = _board(db, case, access=_access(case, "admin"))
    kucoin = _t(board, "KuCoin")
    assert kucoin.status == fb.AWAITING and kucoin.group == fb.ACT and kucoin.owner_led
    assert board.targets[0] is kucoin  # the plan's best move tops Act now
    assert kucoin.step.kind == "draft" and kucoin.step.label == "Open the letter to KuCoin"
    assert f"freeze={chain}:{address}" in kucoin.step.href and kucoin.step.lead.startswith(f"{move.title}.")
    assert "Wait for the reply" not in [s.label for s in kucoin.extra]
    assert kucoin.value == move.value and kucoin.score == move.score
    assert kucoin.owners[0]["short"] == rp._short(address)
    adm = client_for("admin", case=case, email="fb-r5-owner-kucoin@tests.example")
    page = adm.get(f"/cases/{case.id}?tab=authorities").text
    row = page.split(f'id="fb-{kucoin.key}"', 1)[1].split("</tr>", 1)[0]
    assert f"owner: {rp._short(address)}" in row and f"<b>${move.value:,.2f}</b>" in row
    assert "Open the letter to KuCoin" in row and "Ask KuCoin to freeze the account behind" in row
    # the assistant names the same next step, never "wait for the reply"
    access = CaseAccess(case=case, user=adm.user, role=effective_role(db, adm.user, case),
                        member=membership(db, adm.user, case))
    res = skills.run_skill(db, access, "stop-orders", "draft kucoin")
    assert not res.drafts and "next step on its row: “Open the letter to KuCoin”" in res.markdown
    assert "wait for the reply" not in res.markdown


def test_owner_row_for_a_service_that_is_no_counterparty_ranks_below_rows_with_a_button(db, case):
    _owned(db, case, "Binance", "exchange_deposit")
    board = _board(db, case, access=_access(case, "admin"))
    t = next(x for x in board.targets if x.key.startswith("owner-"))
    act = [x for x in board.targets if x.group == fb.ACT]
    assert t.group == fb.ACT and not t.step.label and t.score >= max(x.score for x in act)
    assert all(act.index(x) < act.index(t) for x in act if x.step.label)  # every row with a button first
    # the step says what can actually be done (Aegis has no form that adds a counterparty by name)
    assert "Aegis cannot add one by name" in t.step.lead and "outside Aegis" in t.step.lead


def test_both_issuers_frozen_share_one_case_wide_cover_letter(db, case):
    from app.domain import correspondence as desk

    adm = _access(case, "admin")
    for name, chain in (("Tether (USDT issuer)", "tron"), ("Circle (USDC issuer)", "ethereum")):
        o = _sent(db, case, name, chain=chain)
        rep = _reply(db, case, o, "We have frozen the addresses in your request.", NOW - timedelta(hours=5))
        bs.confirm(db, adm, f"o{o.id}", status=R.FROZEN, reply_id=rep.id, amount="1300", asset="USDT", apply=True)
    board = _board(db, case, access=adm)
    station, procura = _le_key(board, "Carabinieri"), _le_key(board, "Procura")
    # the request's LE contact (the station) has no officer or e-mail on file, even where the route names no
    # reachable LE (Circle's is cross-border): add the officer, or the cover letter to the reachable Procura
    for name in ("Tether (USDT issuer)", "Circle (USDC issuer)"):
        t = _t(board, name)
        assert t.status == fb.FROZEN and t.step.label == "Add the officer's contact" and t.step.le == station, name
        assert t.extra[0].label.startswith("Cover letter to Procura"), name
        assert f"/authorities/{procura}?template=le_cover" in t.extra[0].href, name
    # one case-wide cover letter drafted to the Procura: both rows send it, neither offers a second one
    corr = _cover(db, case, procura)
    board = _board(db, case, access=adm)
    for name in ("Tether (USDT issuer)", "Circle (USDC issuer)"):
        t = _t(board, name)
        assert t.step.label == f"Send LE cover letter #{corr.id}", name
        assert t.step.href == f"/cases/{case.id}/authorities/correspondence/{corr.id}", name
        assert f"LE cover letter #{corr.id} drafted, not sent" in t.detail, name
        assert "le_cover" not in _hrefs(t) and t.status == fb.FROZEN, name
    desk.mark_sent(db, case, corr, actor=None, sent_at=NOW - timedelta(days=6), channel="email")
    board = _board(db, case, access=adm)
    for name in ("Tether (USDT issuer)", "Circle (USDC issuer)"):
        t = _t(board, name)
        assert t.step.lead.startswith(f"LE cover letter #{corr.id} sent") and "to Procura" in t.step.lead, name
        assert "le_cover" not in _hrefs(t) and t.le_letter["id"] == corr.id, name


# --------------------------------------------------------------------------- an owner letter, once drafted / sent
def _owner_letter(client_for, db, case, name, href, email):
    """Draft the owner move's freeze letter through the authority page (the link's own template / freeze / ref)."""
    from app.db.models import Correspondence

    q = parse_qs(urlparse(href).query)
    key = urlparse(href).path.rsplit("/", 1)[1]
    inv = client_for("investigator", case=case, email=email)
    r = inv.post(f"/cases/{case.id}/authorities/{key}/letters",
                 data={"csrf_token": csrf_token(inv, f"/cases/{case.id}/authorities/{key}"), "template": "info_request",
                       "freeze_address": q["freeze"][0], "ref": (q.get("ref") or [""])[0]}, follow_redirects=False)
    assert r.status_code == 303, r.text[:300]
    db.expire_all()
    return db.get(Correspondence, int(r.headers["location"].rsplit("/", 1)[1]))


@pytest.mark.parametrize("name,kind,i", [("KuCoin", "exchange_deposit", 1), ("Rainbet", "casino", 0)])
def test_owner_letter_drafted_then_sent_is_never_offered_again(client_for, db, case, name, kind, i):
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership
    from app.domain import correspondence as desk

    adm = _access(case, "admin")
    chain, address = _owned(db, case, name, kind=kind, i=i)
    t = _t(_board(db, case, access=adm), name)
    link = f"freeze={chain}:{address}"
    assert link in t.step.href  # before: the owner letter is the row's step
    corr = _owner_letter(client_for, db, case, name, t.step.href, f"fb-own-{name.lower()}@tests.example")
    assert corr.meta["freeze"] == f"{chain}:{address.lower()}"
    # drafted: the row's step sends that draft; no step or extra drafts a second letter for the same deposit
    board = _board(db, case, access=adm)
    t = _t(board, name)
    draft = f"/cases/{case.id}/authorities/correspondence/{corr.id}"
    assert t.step.kind == "send" and t.step.label == "Open & send draft" and t.step.href == draft
    assert link not in _hrefs(t) and _hrefs(t).count(draft) == 1 and t.group == fb.ACT
    assert f"identified as the owner of {rp._short(address)}" in t.detail
    plan = rp.build(db, case)
    m = plan.find(f"owner:{chain}:{address}")
    assert m.kind == "send" and m.href == draft and m.cites["key"] == f"c{corr.id}"
    assert m.title == f"Send the drafted freeze request for {rp._short(address)} to {name}"
    # one move for the one draft: the letter's own move carries the deposit (its value, owner line, evidence link)
    own = plan.find(f"c{corr.id}")
    assert own in plan.moves and own.merged == [m] and m not in plan.moves + plan.waiting
    assert own.value >= m.value and any(o.get("short") == rp._short(address) for o in own.owners)
    assert any(x["label"] == "Who owns it (evidence)" for x in own.actions)
    assert not any(link in (x.get("href") or "") for mv in plan.moves + plan.waiting for x in mv.actions)
    viewer = client_for("investigator", case=case, email=f"fb-own-view-{name.lower()}@tests.example")
    page = viewer.get(f"/cases/{case.id}/recovery-plan").text
    assert link not in page and f"Send draft letter #{corr.id}" in page
    assert link not in viewer.get(f"/cases/{case.id}?tab=authorities").text
    # sent: the move waits on that request (its clock), the row shows the request's own status and next step
    desk.mark_sent(db, case, corr, actor=None, sent_at=NOW - timedelta(hours=2), channel="email")
    board = _board(db, case, access=adm)
    t = _t(board, name)
    assert link not in _hrefs(t) and not t.owner_led and t.owners[0]["short"] == rp._short(address)
    assert t.deciding["key"] == f"c{corr.id}" and t.status == fb.AWAITING and t.step.kind != "draft"
    plan = rp.build(db, case)
    m = plan.find(f"owner:{chain}:{address}")
    assert m.kind == "wait" and not m.actionable and m not in plan.moves + plan.waiting
    assert m.clock is not None and m.clock["due_at"] == t.primary.due_at
    own = plan.find(f"c{corr.id}")  # one wait, the letter's own (merged)
    assert own in plan.waiting and own.merged == [m] and own.value >= m.value
    assert not any(link in (x.get("href") or "") for mv in plan.moves + plan.waiting for x in mv.actions)
    # the assistant (and the redraft gate) name the request's own step, never the owner letter again
    inv = client_for("admin", case=case, email=f"fb-own-adm-{name.lower()}@tests.example")
    access = CaseAccess(case=case, user=inv.user, role=effective_role(db, inv.user, case),
                        member=membership(db, inv.user, case))
    why = skills._gate_reason(db, access, t.authority)
    assert f"letter #{corr.id}" in why and f"Open the letter to {name}" not in why and "wait for the reply" in why
    res = skills.run_skill(db, access, "stop-orders", f"draft {t.authority.key}")
    assert not res.drafts and f"Open the letter to {name}" not in res.markdown
    assert f"letter #{corr.id}" in res.markdown and "wait for the reply" in res.markdown
    page = inv.get(f"/cases/{case.id}/recovery-plan")
    assert page.status_code == 200 and f"Request letter #{corr.id} asks {name} to freeze the account" in page.text
    assert link not in page.text and link not in inv.get(f"/cases/{case.id}?tab=authorities").text


def test_owner_letter_to_an_uncontacted_counterparty_drafted_then_sent(client_for, db, case):
    entity = Entity(name="Exchange Demo-Z", category=EntityCategory.EXCHANGE)
    db.add(entity)
    db.flush()
    db.add(StopOrder(case=case, entity=entity, kind="freeze", status=StopOrderStatus.SUPERSEDED, subject="Freeze",
                     body_markdown="(discarded)"))
    db.commit()
    chain, address = _owned(db, case, "Exchange Demo-Z")
    adm = _access(case, "admin")
    t = _t(_board(db, case, access=adm), "Exchange Demo-Z")
    corr = _owner_letter(client_for, db, case, t.name, t.step.href, "fb-own-demo-z@tests.example")
    t = _t(_board(db, case, access=adm), "Exchange Demo-Z")
    move = rp.build(db, case).find(f"owner:{chain}:{address}")
    assert t.step.label == "Open & send draft" and "freeze=" not in _hrefs(t)
    assert t.value == move.value and t.score >= move.score  # the deposit's money stays on the row
    from app.domain import correspondence as desk

    desk.mark_sent(db, case, corr, actor=None, sent_at=NOW - timedelta(hours=2), channel="email")
    t = _t(_board(db, case, access=adm), "Exchange Demo-Z")
    assert "freeze=" not in _hrefs(t) and t.status == fb.AWAITING and t.value == move.value
    assert rp.build(db, case).find(f"owner:{chain}:{address}").kind == "wait"


def test_uncontacted_exchange_leads_with_its_deposit_and_one_stop_order_cites_both(client_for, db, case):
    o = _order(case, "KuCoin")
    o.status, o.sent_at = StopOrderStatus.SUPERSEDED, None
    for c in list(o.correspondence):
        db.delete(c)
    db.commit()
    adm = _access(case, "admin")
    own_value = _t(_board(db, case, access=adm), "KuCoin").value
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    move = rp.build(db, case).find(f"owner:{chain}:{address}")
    t = _t(_board(db, case, access=adm), "KuCoin")
    # the identified deposit outweighs the trace's own value: the owner letter leads, with its value
    assert move.value > (own_value or 0) and t.status == fb.NOT_CONTACTED and t.group == fb.ACT and t.draftable
    assert t.step.label == "Open the letter to KuCoin" and f"freeze={chain}:{address}" in t.step.href
    assert t.value == move.value and t.basis == move.basis
    assert [s.label for s in t.extra[:2]] == ["Who owns it (evidence)", "Draft request"]
    # the bulk generator's stop order cites the deposit too: then the row and the plan send that one draft
    inv = client_for("investigator", case=case, email="fb-own-kucoin-bulk@tests.example")
    assert _generate(inv, case).status_code == 303
    db.expire_all()
    draft = next(x for x in case.stop_orders if x.entity_id == t.authority.entity.id
                 and x.status == StopOrderStatus.DRAFT)
    assert address.lower() in {a["address"].lower() for a in draft.identifiers["addresses"]}
    assert address in draft.body_markdown
    t = _t(_board(db, case, access=adm), "KuCoin")
    assert t.step.label == "Open & send draft" and t.step.href == f"/cases/{case.id}/stop-orders/{draft.id}"
    assert "freeze=" not in _hrefs(t)
    m = rp.build(db, case).find(f"owner:{chain}:{address}")
    assert m.kind == "send" and m.cites["key"] == f"o{draft.id}"


def test_owner_move_to_a_service_that_is_no_counterparty_never_promises_to_add_it(db, case):
    chain, address = _owned(db, case, "Binance", "exchange_deposit")
    m = rp.build(db, case).find(f"owner:{chain}:{address}")
    assert not any("as a counterparty" in x["label"] for x in m.actions) and m.href is None
    assert "Authorities tab first" not in m.text and "Aegis cannot add one by name" in m.text
    t = next(x for x in _board(db, case, access=_access(case, "admin")).targets if x.key.startswith("owner-"))
    assert t.step.text.count("Aegis cannot add one by name") == 1 and "Authorities tab first" not in t.step.text
    assert t.step.lead.startswith("Binance is not a counterparty of the case yet")


def test_claim_with_the_le_cover_letter_sent_says_the_notice_links_the_freeze(db, case):
    from app.domain import correspondence as desk

    adm = _access(case, "admin")
    _frozen_on_chain(db, case)
    corr = _cover(db, case, _le_key(_board(db, case, access=adm), "Procura"))
    desk.mark_sent(db, case, corr, actor=None, sent_at=NOW - timedelta(days=6), channel="email")
    t = _t(_board(db, case, access=adm), "Tether (USDT issuer)")
    assert t.group == fb.CLAIM and t.step.lead.startswith(f"LE cover letter #{corr.id} sent")
    assert "links the freeze to this case" in t.step.text and "flags the wallets" not in t.step.text
    assert "not claimed for this case" in t.step.text


# --------------------------------------------------------------------------- an owner letter is a freeze request
def _uncontacted_kucoin(db, case, *, draft=False):
    """KuCoin made uncontacted (its stop order superseded unsent, its letters gone) or, `draft`, left with a generated
    stop-order draft that was never sent (from no trace run: an earlier one)."""
    from app.db.models import StopOrderOrigin

    o = _order(case, "KuCoin")
    o.status, o.sent_at = (StopOrderStatus.DRAFT if draft else StopOrderStatus.SUPERSEDED), None
    if draft:
        o.origin = StopOrderOrigin.GENERATED
    for c in list(o.correspondence):
        db.delete(c)
    db.commit()
    return o


def _post_owner_letter(client, case, href):
    q = parse_qs(urlparse(href).query)
    key = urlparse(href).path.rsplit("/", 1)[1]
    return client.post(f"/cases/{case.id}/authorities/{key}/letters",
                       data={"csrf_token": csrf_token(client, f"/cases/{case.id}/authorities/{key}"),
                             "template": "info_request", "freeze_address": q["freeze"][0],
                             "ref": (q.get("ref") or [""])[0]}, follow_redirects=False)


def _kucoin_orders(db, case):
    db.expire_all()
    return [o for o in case.stop_orders if o.entity is not None and o.entity.name == "KuCoin"]


def test_sent_owner_letter_is_a_freeze_request_the_generators_never_repeat(client_for, db, case):
    from app.db.models import Correspondence
    from app.domain import correspondence as desk

    _uncontacted_kucoin(db, case)
    _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    adm = _access(case, "admin")
    t = _t(_board(db, case, access=adm), "KuCoin")
    assert t.step.label == "Open the letter to KuCoin" and t.draftable
    inv = client_for("investigator", case=case, email="fb-own-freeze-inv@tests.example")
    r = _post_owner_letter(inv, case, t.step.href)
    assert r.status_code == 303
    db.expire_all()
    corr = db.get(Correspondence, int(r.headers["location"].rsplit("/", 1)[1]))
    desk.mark_sent(db, case, corr, actor=None, sent_at=NOW - timedelta(hours=2), channel="email")
    # sent: the letter asked for the freeze (it is no records-only request): the row waits on it, nothing to draft
    t = _t(_board(db, case, access=adm), "KuCoin")
    assert t.status == fb.AWAITING and not t.freeze_open and not t.draftable and t.group == fb.WAITING
    assert t.skip == ("sent", f"c{corr.id}") and t.step.label != "Draft freeze request"
    assert "no freeze asked yet" not in t.detail and "Only a records" not in t.step.text
    names, skipped = fb.generator_plan(_board(db, case, access=adm))
    assert "KuCoin" not in names and ("sent", f"c{corr.id}") in [(c, k) for x, c, k in skipped if x and x.name == "KuCoin"]
    before = {o.id for o in _kucoin_orders(db, case)}
    assert _generate(inv, case).status_code == 303
    assert {o.id for o in _kucoin_orders(db, case)} == before  # the bulk generator drafts nothing for it
    d = _gate(db, case, t.key)
    assert d.kind == rg.FOLLOW_UP_ONLY and d.key == f"c{corr.id}" and f"letter #{corr.id}" in d.text
    # a stop order drafted before the gate (legacy data) repeats the sent letter: flagged, never the row's step
    dup = _legacy(db, case, "KuCoin")
    t = _t(_board(db, case, access=adm), "KuCoin")
    assert [d["text"] for d in t.duplicates] == [
        f"Draft #{dup.id} duplicates request letter #{corr.id} (already sent {corr.occurred_at:%d %b %Y}) — discard?"]
    assert t.primary.key == f"c{corr.id}" and t.status == fb.AWAITING and t.deciding["key"] == f"c{corr.id}"
    assert f"/stop-orders/{dup.id}" not in _hrefs(t) and t.step.kind != "send"
    board = _board(db, case, access=adm)
    assert t.move is None or t.move.row is None or t.move.row.key != f"o{dup.id}"
    # the board and its plan agree: no move sends the duplicate
    plan = rp.build(db, case, rows=fb.without_duplicates(board.rows))
    assert not any(m.key == f"o{dup.id}" for m in plan.moves + plan.waiting)


def test_stop_order_draft_lacking_the_deposit_gets_it_added_never_a_second_letter(client_for, db, case):
    old = _uncontacted_kucoin(db, case, draft=True)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    short = rp._short(address)
    adm = _access(case, "admin")
    t = _t(_board(db, case, access=adm), "KuCoin")
    # one open request per provider: the deposit goes into the open stop-order draft, never a separate owner letter
    assert t.status == fb.DRAFT_READY and t.owner_led
    assert t.step.kind == "add" and t.step.label == f"Add {short} to draft #{old.id}"
    assert t.step.post == f"/cases/{case.id}/authorities/{t.key}/letters"
    assert t.step.fields["about"] == f"{chain}:{address}" and t.step.fields["template"] == "info_request"
    assert "freeze=" not in _hrefs(t) and [s.label for s in t.extra].count("Open & send draft") == 1
    m = rp.build(db, case).find(f"owner:{chain}:{address}")
    assert m.cites["state"] == "add" and m.cites["key"] == f"o{old.id}"
    assert m.actions[0]["label"] == f"Add {short} to draft #{old.id}" and "freeze=" in m.actions[0]["href"]
    # the row's button: the address added to that draft (identifiers + a sentence), no new stop order
    inv = client_for("investigator", case=case, email="fb-own-add@tests.example")
    before = {o.id for o in _kucoin_orders(db, case)}
    r = inv.post(t.step.post, data={"csrf_token": csrf_token(inv, f"/cases/{case.id}/authorities/{t.key}"),
                                    **t.step.fields}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(f"/cases/{case.id}/stop-orders/{old.id}?added=")
    orders = _kucoin_orders(db, case)
    assert {o.id for o in orders} == before
    draft = db.get(StopOrder, old.id)
    assert draft.status == StopOrderStatus.DRAFT
    assert address.lower() in {str(a["address"] if isinstance(a, dict) else a).lower()
                               for a in draft.identifiers["addresses"]}
    assert address in draft.body_markdown and draft.identifiers["added"][-1]["about"] == [f"{chain}:{address}"]
    ev = db.scalars(select(AuditEvent).where(AuditEvent.object_type == "stop_orders",
                                             AuditEvent.object_id == str(old.id), AuditEvent.action == "UPDATE")).all()
    assert ev and ev[-1].detail["reason"] == "request_gate_add_to_draft"
    t = _t(_board(db, case, access=adm), "KuCoin")
    assert t.step.label == "Open & send draft" and t.step.href == f"/cases/{case.id}/stop-orders/{old.id}"
    assert "freeze=" not in _hrefs(t) and not any(s.kind == "add" for s in [t.step, *t.extra])
    m = rp.build(db, case).find(f"owner:{chain}:{address}")
    assert m.cites["state"] == "draft" and m.cites["key"] == f"o{old.id}"
    # the same link again: the draft already cites it (409, no second letter, no second add)
    r = inv.post(f"/cases/{case.id}/authorities/{t.key}/letters",
                 data={"csrf_token": csrf_token(inv, f"/cases/{case.id}/authorities/{t.key}"),
                       "template": "info_request", "freeze_address": f"{chain}:{address}"}, follow_redirects=False)
    assert r.status_code == 409 and f"Draft #{old.id} to KuCoin is not sent yet" in r.text
    db.expire_all()
    assert len(db.get(StopOrder, old.id).identifiers["added"]) == 1


def test_draft_from_this_trace_lacking_the_deposit_gets_it_added(client_for, db, case):
    _uncontacted_kucoin(db, case)
    draft = services.generate_stop_orders(db, case, services.latest_run(db, case), only=["KuCoin"])[0]
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    board = _board(db, case, access=_access(case, "admin"))
    t = _t(board, "KuCoin")
    assert t.skip == ("draft", f"o{draft.id}") and t.step.label == f"Add {rp._short(address)} to draft #{draft.id}"
    assert "KuCoin" not in fb.generator_plan(board)[0]  # never in bulk
    assert fb.generator_plan(board, only="KuCoin", redraft=True)[0] == []  # no redraft of a draft from this trace
    d = _gate(db, case, t.key, "info_request", about=[f"{chain}:{address}"])
    assert d.kind == rg.ADD_TO_DRAFT and d.key == f"o{draft.id}" and d.about == [f"{chain}:{address}"]


@pytest.mark.parametrize("via", ["page", "assistant"])
def test_stop_order_from_the_authority_page_or_the_assistant_cites_the_owner_deposit(client_for, db, case, via):
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership

    _uncontacted_kucoin(db, case)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    adm = _access(case, "admin")
    key = _t(_board(db, case, access=adm), "KuCoin").key
    inv = client_for("investigator", case=case, email=f"fb-own-so-{via}@tests.example")
    if via == "page":
        r = inv.post(f"/cases/{case.id}/authorities/{key}/letters",
                     data={"csrf_token": csrf_token(inv, f"/cases/{case.id}/authorities/{key}"),
                           "template": "stop_order"}, follow_redirects=False)
        assert r.status_code == 303, r.text[:300]
    else:
        access = CaseAccess(case=case, user=inv.user, role=effective_role(db, inv.user, case),
                            member=membership(db, inv.user, case))
        assert skills.run_skill(db, access, "stop-orders", "draft kucoin").drafts
    order = next(o for o in _kucoin_orders(db, case) if o.status == StopOrderStatus.DRAFT)
    assert address.lower() in {a["address"].lower() for a in order.identifiers["addresses"]}
    assert address in order.body_markdown
    # one letter: the row sends that draft (the deposit's value), no owner letter beside it
    t = _t(_board(db, case, access=adm), "KuCoin")
    assert t.step.label == "Open & send draft" and t.step.href == f"/cases/{case.id}/stop-orders/{order.id}"
    assert "freeze=" not in _hrefs(t) and t.owner_led
    plan = rp.build(db, case)
    assert plan.find(f"owner:{chain}:{address}").cites["key"] == f"o{order.id}"
    assert not any("freeze=" in (x.get("href") or "") for m in plan.moves + plan.waiting for x in m.actions)
    sends = [m for m in plan.moves if m.authority is not None and m.authority.key == key]
    assert [m.key for m in sends] == [f"o{order.id}"]  # one move for the one draft (the owner move merged into it)


def test_second_owner_letter_for_the_same_deposit_is_refused(client_for, db, case):
    from app.db.models import Correspondence
    from app.domain import correspondence as desk

    _uncontacted_kucoin(db, case)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    adm = _access(case, "admin")
    t = _t(_board(db, case, access=adm), "KuCoin")
    href = t.step.href
    inv = client_for("investigator", case=case, email="fb-own-twice-inv@tests.example")
    r = _post_owner_letter(inv, case, href)
    assert r.status_code == 303
    first = int(r.headers["location"].rsplit("/", 1)[1])
    # the same freeze link again (back button, a second tab, a bookmarked plan link): the gate's message, no form
    page = inv.get(href).text
    assert 'id="request-gate"' in page and f"Draft letter #{first} to KuCoin is not sent yet" in page
    assert f'href="/cases/{case.id}/authorities/correspondence/{first}"' in page
    r = _post_owner_letter(inv, case, href)
    assert r.status_code == 409 and f"letter #{first}" in r.text
    # no path makes a second one: the domain call refuses too (the gate is in generate_letter)
    db.expire_all()
    a = _t(_board(db, case, access=adm), "KuCoin").authority
    with pytest.raises(desk.GateRefused) as exc:
        desk.generate_letter(db, case, a, "info_request", actor=None, freeze=f"{chain}:{address}")
    assert exc.value.decision.kind == rg.OPEN_EXISTING and exc.value.decision.key == f"c{first}"
    with pytest.raises(desk.GateRefused):
        desk.generate_letter(db, case, a, "stop_order", actor=None, run=services.latest_run(db, case))
    db.expire_all()
    drafts = db.scalars(select(Correspondence).where(Correspondence.case_id == case.id,
                                                     Correspondence.entity_id == a.entity.id,
                                                     Correspondence.status == "draft")).all()
    assert [c.id for c in drafts] == [first]
    t = _t(_board(db, case, access=adm), "KuCoin")
    assert not t.duplicates and t.step.href == f"/cases/{case.id}/authorities/correspondence/{first}"
    # sent: only follow-ups tied to it; the same deposit never again
    desk.mark_sent(db, case, db.get(Correspondence, first), actor=None, sent_at=NOW - timedelta(hours=2),
                   channel="email")
    r = _post_owner_letter(inv, case, href)
    assert r.status_code == 409 and f"Request letter #{first} to KuCoin already asks about" in r.text


def test_plan_has_one_move_per_owner_letter_and_an_overdue_one_says_chase(client_for, db, case):
    from app.db.models import Correspondence
    from app.domain import correspondence as desk

    _uncontacted_kucoin(db, case)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    inv = client_for("investigator", case=case, email="fb-own-plan@tests.example")
    r = _post_owner_letter(inv, case, t.step.href)
    loc = r.headers["location"]
    cid = int(loc.rsplit("/", 1)[1])
    db.expire_all()
    plan = rp.build(db, case)
    kucoin = [m for m in plan.moves + plan.waiting if m.key == f"c{cid}" or m.key.startswith("owner:")
              and m.authority is not None and m.authority.name == "KuCoin"]
    assert [m.key for m in kucoin] == [f"c{cid}"] and kucoin[0].value == plan.find(f"owner:{chain}:{address}").value
    page = inv.get(f"/cases/{case.id}/recovery-plan").text
    # one open request: every KuCoin wallet's step is that draft (the move, the owners panel), never a new letter
    assert "Send the drafted freeze request for" not in page and f"/authorities/{t.key}?template=" not in page
    back = f"?return_to=%2Fcases%2F{case.id}%2Frecovery-plan%23owners"  # the e-mail flow comes back here
    assert f'href="{loc}{back}">Open the draft</a> <span class="bk-small">Send draft letter #{cid} (it asks KuCoin to ' \
        'freeze the account behind' in page
    # sent 12 days ago (overdue): one move, the letter's chase; the deposit's text says to chase it
    db.expire_all()
    desk.mark_sent(db, case, db.get(Correspondence, cid), actor=None, sent_at=NOW - timedelta(days=12),
                   channel="email")
    plan = rp.build(db, case)
    own = plan.find(f"c{cid}")
    m = plan.find(f"owner:{chain}:{address}")
    assert own in plan.moves + plan.waiting and own.merged == [m] and m not in plan.moves + plan.waiting
    assert m.title.startswith("Chase KuCoin: the freeze request for") and "chase it" in m.text
    assert "wait for its reply" not in m.text

