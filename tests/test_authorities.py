"""Authorities & stop-order desk: counterparties, the communications timeline, form letters, stop-order
status changes, response-overdue checks, role gating and export path containment."""

import re
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest
from conftest import csrf_token, ungated
from docx import Document
from sqlalchemy import select

from app import services
from app.core import events
from app.db.models import (
    AuditEvent,
    Chain,
    Correspondence,
    CorrespondenceDirection,
    CorrespondenceStatus,
    Entity,
    EntityCategory,
    StopOrder,
    StopOrderStatus,
)
from app.domain import correspondence as desk
from app.reports.stop_orders import md_escape, render_letter
from app.web.templating import _render_md

PAYLOAD = '<script>alert(1)</script> **bold** [x](javascript:alert(1)) <img src=x>'


@pytest.fixture
def emitted(monkeypatch):
    """Record every event the desk emits (independent of the notification rules)."""
    calls: list[dict] = []
    real = events.emit

    def spy(db, case, event_type, **kw):
        calls.append({"type": event_type, "case_id": case.id if case is not None else None, **kw})
        return real(db, case, event_type, **kw)

    monkeypatch.setattr(desk.events, "emit", spy)
    return calls


@pytest.fixture
def run(db, case):
    return services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")


@pytest.fixture
def iso(db):
    """An isolated case with one exchange counterparty and a stop order sent ten days ago."""
    tag = uuid.uuid4().hex[:8]
    case = services.create_case(
        db, reference=f"TEST-AUTH-{tag}", title="Authorities desk test", victim_name="Test Victim",
        victim_entity=None, loss_amount=Decimal(1000), loss_asset="USDC", loss_usd=Decimal(1000), fraud_date=None,
        chain=Chain.ETHEREUM, origin_tx=None, victim_wallet=None,
        perpetrator_wallet="0x57de1021A507d46272d386995d5B58667Ac1F8df",
    )
    entity = Entity(name=f"Test Exchange {tag}", category=EntityCategory.EXCHANGE, compliance_email="compliance@exchange.example")
    db.add(entity)
    sent = datetime.now(tz=UTC) - timedelta(days=10)
    order = StopOrder(case=case, entity=entity, kind="preservation", status=StopOrderStatus.SENT,
                      subject="Preservation request – test", body_markdown="Dear team, please preserve.",
                      identifiers={"chain": "ethereum", "addresses": ["0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2"],
                                   "tx_hashes": ["0x580d3a804899ca7e084af17c13ecd2cb7af781e15572a62eaf604ff056c30293"]},
                      sent_at=sent, sent_via="email")
    db.add(order)
    db.commit()
    return SimpleNamespace(case=case, entity=entity, order=order, key=f"entity-{entity.id}", sent=sent)


def _authority(db, case, key, **kw):
    db.expire_all()
    a = desk.get_authority(db, case, key, **kw)
    assert a is not None, key
    return a


def _by_name(db, case, name, run=None):
    db.expire_all()
    return next(a for a in desk.case_authorities(db, case, run=run) if a.name == name)


def _timeline_html(html: str) -> str:
    return html.split('<div class="timeline">', 1)[1].split('<aside class="auth-side">', 1)[0]


def _post(c, path, page, data):
    return c.post(path, data={"csrf_token": csrf_token(c, page), **data}, follow_redirects=False)


# --------------------------------------------------------------------------- authorities list
def test_tab_lists_every_counterparty_with_status_columns(client, db, case, run):
    names = {a.name: a for a in desk.case_authorities(db, case, run=run)}
    # VASPs and swap services (freeze candidates), issuers, infrastructure (case facts), LE contacts, the router
    assert {"KuCoin", "Rainbet", "SWFT / Bridgers", "Tether (USDT issuer)", "Hostinger", "Supabase",
            "Uniswap (Universal Router)", "FBI Internet Crime Complaint Center (IC3)"} <= set(names)
    assert names["KuCoin"].candidate is not None and names["Uniswap (Universal Router)"].non_custodial
    assert names["FBI Internet Crime Complaint Center (IC3)"].is_le
    page = client.get(f"/cases/{case.id}?tab=authorities")
    assert page.status_code == 200
    for col in ("Last contact", "Open stop orders", "Response due", "In · Out · Notes"):
        assert col in page.text
    assert f'/cases/{case.id}/authorities/{names["KuCoin"].key}' in page.text
    assert "freeze candidate" in page.text and "non-custodial" in page.text
    api = client.get(f"/api/cases/{case.id}/authorities").json()
    kucoin = next(a for a in api if a["name"] == "KuCoin")
    assert {"last_contact", "open_stop_orders", "response_due", "overdue", "counts"} <= set(kucoin)


def test_overview_columns_count_and_flag_overdue(db, iso):
    a = _authority(db, iso.case, iso.key)
    assert a.contacted and [o.id for o in a.open_orders] == [iso.order.id]
    assert a.next_due() == iso.sent + timedelta(days=desk.DEFAULT_RESPONSE_DAYS)  # default sent + 7 days
    assert a.overdue() and a.counts == {"in": 0, "out": 1, "note": 0, "draft": 0}
    assert a.last_contact == iso.sent


# --------------------------------------------------------------------------- timeline
def test_timeline_is_chronological_and_filterable(client_for, db, iso):
    c = client_for("investigator", case=iso.case)
    page = f"/cases/{iso.case.id}/authorities/{iso.key}"
    base = iso.sent
    for direction, kind, offset, subject in (("note", "other", 5, "Call with the desk"),
                                             ("in", "reply", 2, "Re: Preservation request"),
                                             ("out", "other", 3, "Follow-up e-mail")):
        r = _post(c, f"{page}/log", page, {
            "direction": direction, "kind": kind, "channel": "email", "subject": subject, "body": f"body of {subject}",
            "occurred_at": (base + timedelta(days=offset)).strftime("%Y-%m-%dT%H:%M"),
            "stop_order_id": str(iso.order.id) if direction == "in" else ""})
        assert r.status_code == 303, r.text
    items = desk.timeline(_authority(db, iso.case, iso.key))
    assert [i.subject for i in items] == ["Preservation request – test", "Re: Preservation request",
                                          "Follow-up e-mail", "Call with the desk"]
    assert [i.at for i in items] == sorted(i.at for i in items)
    newest = desk.timeline(_authority(db, iso.case, iso.key), newest_first=True)
    assert [i.subject for i in newest] == [i.subject for i in reversed(items)]
    assert [i.subject for i in desk.timeline(_authority(db, iso.case, iso.key), direction="in")] == [
        "Re: Preservation request"]
    # the inbound reply linked to the stop order answers it: no longer awaiting a response
    db.expire_all()
    order = db.get(StopOrder, iso.order.id)
    assert order.responded_at is not None and not desk.awaiting_response(order)
    html = _timeline_html(c.get(page).text)
    assert html.index("Re: Preservation request") < html.index("Follow-up e-mail") < html.index("Call with the desk")
    assert "body of Call with the desk" in html  # expandable body
    filtered = _timeline_html(c.get(page, params={"direction": "note"}).text)
    assert "Call with the desk" in filtered and "Follow-up e-mail" not in filtered
    api = c.get(f"/api/cases/{iso.case.id}/authorities/{iso.key}/timeline").json()
    assert [i["subject"] for i in api["items"]] == [i.subject for i in items]


def test_logged_bodies_are_escaped(client_for, db, iso):
    c = client_for("investigator", case=iso.case)
    page = f"/cases/{iso.case.id}/authorities/{iso.key}"
    for fmt in ("text", "markdown"):
        r = _post(c, f"{page}/log", page, {"direction": "in", "kind": "reply", "channel": "email",
                                           "subject": f"{fmt} {PAYLOAD}", "body": PAYLOAD, "body_format": fmt})
        assert r.status_code == 303
    html = c.get(page).text
    assert "<script>alert" not in html and "<img src=x" not in html and 'href="javascript:' not in html
    assert "&lt;script&gt;alert" in html


def test_linked_evidence_is_shown(client_for, db, case):
    if not case.evidence_items:
        pytest.skip("demo fixture has no evidence items")
    ev = case.evidence_items[0]
    kucoin = _by_name(db, case, "KuCoin")
    c = client_for("investigator", case=case)
    page = f"/cases/{case.id}/authorities/{kucoin.key}"
    r = _post(c, f"{page}/log", page, {"direction": "note", "kind": "other", "channel": "other",
                                       "subject": "Evidence-linked note", "evidence_ids": str(ev.id)})
    assert r.status_code == 303
    assert f"/cases/{case.id}/evidence/{ev.id}" in c.get(page).text


# --------------------------------------------------------------------------- role gating
def test_read_only_can_view_but_not_generate_or_log(client_for, db, case, iso):
    c = client_for("read_only", case=iso.case)
    page = f"/cases/{iso.case.id}/authorities/{iso.key}"
    r = c.get(page)
    assert r.status_code == 200 and "Preservation request – test" in r.text
    assert "Generate letter" not in r.text and "Log correspondence" not in r.text
    assert "Content restricted (R3)" in r.text  # letters are R3: bodies need view_restricted
    assert c.get(f"/cases/{iso.case.id}?tab=authorities").status_code == 200
    token = csrf_token(c, page)
    for path, data in ((f"{page}/log", {"direction": "in", "subject": "x"}),
                       (f"{page}/letters", {"template": "status_request"}),
                       (f"/cases/{iso.case.id}/stop-orders/{iso.order.id}/status", {"status": "frozen"})):
        assert c.post(path, data={"csrf_token": token, **data}).status_code == 403, path
    assert not [x for x in iso.case.correspondence]
    # an investigator may
    inv = client_for("investigator", case=iso.case)
    r = _post(inv, f"{page}/letters", page, {"template": "status_request", "ref": f"o{iso.order.id}"})
    assert r.status_code == 303


def test_non_members_and_unknown_keys_get_404(client_for, db, case, iso):
    outsider = client_for(None, case=iso.case)
    assert outsider.get(f"/cases/{iso.case.id}/authorities/{iso.key}").status_code == 404
    inv = client_for("investigator", case=iso.case)
    for key in ("entity-999999", "le-999999", "nonsense", "correspondence"):
        assert inv.get(f"/cases/{iso.case.id}/authorities/{key}").status_code == 404, key
    # an entity that has nothing to do with this case is not an authority of it
    kucoin = _by_name(db, case, "KuCoin")
    assert inv.get(f"/cases/{iso.case.id}/authorities/{kucoin.key}").status_code == 404
    # correspondence of another case
    other = Correspondence(case=case, direction=CorrespondenceDirection.NOTE, subject="other case note")
    db.add(other)
    db.commit()
    assert inv.get(f"/cases/{iso.case.id}/authorities/correspondence/{other.id}").status_code == 404
    assert inv.get(f"/api/cases/{iso.case.id}/authorities/correspondence/{other.id}/md").status_code == 404


def test_external_members_see_only_shared_items(client_for, db, iso):
    admin = client_for("admin", case=iso.case)
    page = f"/cases/{iso.case.id}/authorities/{iso.key}"
    for subject, share in (("Shared acknowledgement", "1"), ("Internal only", "")):
        _post(admin, f"{page}/log", page, {"direction": "in", "kind": "reply", "channel": "email",
                                           "subject": subject, "body": "x", "shared_with_external": share})
    ext = client_for("external", case=iso.case)
    full = ext.get(page).text
    html = _timeline_html(full)
    assert "Shared acknowledgement" in html and "Internal only" not in full
    assert "Preservation request – test" not in html  # stop orders are not shared
    assert "Log correspondence" not in full and "Generate letter" not in full
    assert ext.get(f"/cases/{iso.case.id}?tab=authorities").status_code == 200
    internal = next(x for x in iso.case.correspondence if x.subject == "Internal only")
    assert ext.get(f"/cases/{iso.case.id}/authorities/correspondence/{internal.id}").status_code == 404


# --------------------------------------------------------------------------- form letters
def test_every_template_renders_with_demo_data(db, case, run):
    kucoin = _by_name(db, case, "KuCoin", run)
    hostinger = _by_name(db, case, "Hostinger", run)
    ic3 = _by_name(db, case, "FBI Internet Crime Complaint Center (IC3)", run)
    with ungated():  # every template once (the demo already asked KuCoin and Hostinger: the rendering is under test)
        stop = desk.generate_letter(db, case, kucoin, "stop_order", actor=None, run=run)
    assert stop.status == CorrespondenceStatus.DRAFT and stop.stop_order is not None
    assert stop.stop_order.status == StopOrderStatus.DRAFT and stop.stop_order.template_key == "stop_order"
    desk.mark_sent(db, case, stop, actor=None, sent_at=datetime.now(tz=UTC) - timedelta(days=4))
    order = stop.stop_order
    assert order.status == StopOrderStatus.SENT and order.response_due_at == order.sent_at + timedelta(days=7)
    kucoin = _by_name(db, case, "KuCoin", run)
    status = desk.generate_letter(db, case, kucoin, "status_request", actor=None, run=run, ref=f"c{stop.id}")
    desk.record_stop_order_status(db, case, order, "frozen", actor=None, amount_held=Decimal("0.0568"), asset="eth")
    kucoin = _by_name(db, case, "KuCoin", run)
    with ungated():  # the status request above is still a draft (one open request per provider)
        release = desk.generate_letter(db, case, kucoin, "release_request", actor=None, run=run)
    with ungated():
        info = desk.generate_letter(db, case, hostinger, "info_request", actor=None, run=run)
    cover = desk.generate_letter(db, case, ic3, "le_cover", actor=None, run=run)
    letters = {"stop_order": stop, "status_request": status, "release_request": release, "info_request": info,
               "le_cover": cover}
    for key, corr in letters.items():
        body = corr.body_markdown
        assert corr.status == CorrespondenceStatus.DRAFT or key == "stop_order", key
        assert corr.kind.value == desk.LETTER_TEMPLATES[key].kind.value and corr.classification.value == "R3", key
        # the demo case's sender profile: Athena on behalf of the victim, under the Letter of Authorisation
        assert "Athena Software Group, Inc., on behalf of Northbridge Analytics, Inc. (Jordan Avery)" in body, key
        assert "Kestrel Ridge Investigations GmbH" not in body, key
        assert "Letter of Authorisation" in body and "power of attorney" not in body.lower(), key
        assert "ASSERTED:" not in body and "DEMO-IT-0000000000" in body, key
        html = _render_md(body)
        assert "<script" not in html, key
    # status request: earlier letter by date + subject, its identifiers, hold + account status, days elapsed
    sb = status.body_markdown
    assert order.sent_at.strftime("%d.%m.%Y") in sb and order.subject in sb
    assert "4 days have passed" in sb and "current status of the account(s)" in sb and "amount and asset held" in sb
    assert "0x0a17ed3ea9e61d9c16be85e22dea19b09aa758e2" in sb
    assert status.stop_order_id == order.id and status.meta["references"] == f"c{stop.id}"
    # release: cites the hold and asks for return to the victim
    assert "0.0568 ETH" in release.body_markdown and "release the held funds" in release.body_markdown
    # info request to an infrastructure provider cites the IOC from the case facts
    assert "exempla-holding.example" in info.body_markdown and "Subscriber" in info.body_markdown
    # LE cover: identifiers and where funds sit, with the stop-order status of each service
    cb = cover.body_markdown
    assert "Where the funds sit" in cb and "KuCoin" in cb and "hold confirmed" in cb
    assert "IC3-DEMO-00000000" in cb and "0x70abbe14aa9080b572aa69881536e5c165097c0574c4791467e915b708bba814" in cb
    assert "_PENDING" not in cb


def test_swap_letters_carry_the_swft_order_reference(db, case, run):
    swft = _by_name(db, case, "SWFT / Bridgers", run)
    _, body, _ = desk.build_letter(db, case, swft, "info_request", run=run)
    assert "`demo0swf_t000_0000_0000_000000000001`" in body


def test_non_custodial_router_gets_no_freeze_letter(client_for, db, case, run):
    uni = _by_name(db, case, "Uniswap (Universal Router)", run)
    options = {o["key"]: o for o in desk.template_options(uni, run)}
    assert not options["stop_order"]["available"] and "Non-custodial" in options["stop_order"]["reason"]
    assert options["info_request"]["available"]
    with pytest.raises(desk.DeskError):
        desk.generate_letter(db, case, uni, "stop_order", actor=None, run=run)
    c = client_for("investigator", case=case)
    page = f"/cases/{case.id}/authorities/{uni.key}"
    assert _post(c, f"{page}/letters", page, {"template": "stop_order"}).status_code == 400
    r = _post(c, f"{page}/letters", page, {"template": "info_request"})
    assert r.status_code == 303
    corr = db.get(Correspondence, int(r.headers["location"].rsplit("/", 1)[1]))
    assert "We are not asking for a freeze" in corr.body_markdown and corr.stop_order is None


def test_template_rules_by_counterparty(db, case, run):
    ic3 = _by_name(db, case, "FBI Internet Crime Complaint Center (IC3)", run)
    opts = {o["key"]: o["available"] for o in desk.template_options(ic3, run)}
    assert opts["le_cover"] and not opts["stop_order"]
    kucoin = _by_name(db, case, "KuCoin", run)
    assert not {o["key"]: o["available"] for o in desk.template_options(kucoin, run)}["le_cover"]


def test_letter_values_are_markdown_escaped(db, case, run):
    from app.domain.sender import get_profile

    original = case.victim_name
    profile = get_profile(db, case)  # the demo case's sender profile: its values are escaped too
    behalf = profile.on_behalf_of
    try:
        case.victim_name = PAYLOAD
        profile.on_behalf_of = PAYLOAD
        db.commit()
        hostinger = _by_name(db, case, "Hostinger", run)
        _, body, _ = desk.build_letter(db, case, hostinger, "info_request", run=run)
        assert PAYLOAD not in body and md_escape(PAYLOAD) in body
        html = _render_md(body)
        assert "<script" not in html and "<img" not in html and 'href="javascript:' not in html
        assert "<strong>bold</strong>" not in html  # the victim name cannot inject emphasis either
    finally:
        case.victim_name = original
        profile.on_behalf_of = behalf
        db.commit()


def test_wording_rules_are_enforced():
    from app.reports.stop_orders import LetterWordingError

    ctx = {"sender": {"firm": "F", "contact": "C", "instrument": "Letter of Authorisation", "cc": []}, "victim": {"name": "V"},
           "complaints": [], "case": SimpleNamespace(reference="DEMO"), "subject": "s", "salutation": "x",
           "entity_name": "E", "iocs": [], "identifiers": [], "unverified": set(), "records": [],
           "non_custodial": False, "generated_at": "now", "template_label": "t", "run_ref": None,
           "extra_note": "Attached: Power of Attorney"}
    with pytest.raises(LetterWordingError):
        render_letter("info_request", **ctx)
    ctx["extra_note"] = None
    ctx["identifiers"] = [{"chain": "ethereum", "address": "0xabc", "address_type": "unknown", "label": None,
                           "inbound": [{"tx_hash": "ASSERTED:relay-1", "asserted": True, "amount": "1", "asset": "ETH",
                                        "from": "0xdef", "timestamp": "2026-10-12T11:00:00+00:00"}],
                           "outbound": [], "flags": [], "swap_orders": []}]
    body = render_letter("info_request", **ctx)
    assert "ASSERTED:" not in body and "*Asserted* link, not yet observed on-chain (described, not cited)" in body
    with pytest.raises(ValueError):
        render_letter("../preservation_request", **ctx)


# --------------------------------------------------------------------------- drafts, sending, export
def test_draft_is_editable_until_sent(client_for, db, iso):
    c = client_for("investigator", case=iso.case)
    page = f"/cases/{iso.case.id}/authorities/{iso.key}"
    r = _post(c, f"{page}/letters", page, {"template": "status_request", "ref": f"o{iso.order.id}"})
    letter = r.headers["location"]
    cid = int(letter.rsplit("/", 1)[1])
    r = _post(c, letter, letter, {"subject": "Edited subject", "body_markdown": "Edited **body**",
                                  "recipients": "compliance@exchange.example", "cc": ""})
    assert r.status_code == 303
    db.expire_all()
    corr = db.get(Correspondence, cid)
    assert corr.subject == "Edited subject" and corr.body_markdown == "Edited **body**"
    r = _post(c, f"{letter}/sent", letter, {"sent_at": "", "channel": "email", "external_ref": "TCK-9", "due_days": ""})
    assert r.status_code == 303
    db.expire_all()
    corr = db.get(Correspondence, cid)
    assert corr.status == CorrespondenceStatus.SENT and corr.due_at == corr.occurred_at + timedelta(days=7)
    assert corr.external_ref == "TCK-9"
    assert _post(c, letter, letter, {"subject": "again", "body_markdown": "x"}).status_code == 409
    sent = list(db.scalars(select(AuditEvent).where(AuditEvent.action == "LETTER_SENT",
                                                    AuditEvent.object_id == str(cid))))
    assert len(sent) == 1 and "body" not in sent[0].detail


def test_stop_order_draft_sent_from_letter_page_updates_the_order(db, case, run, emitted):
    kucoin = _by_name(db, case, "KuCoin", run)
    with ungated():  # the demo already asked KuCoin: marking a stop-order draft sent is under test
        corr = desk.generate_letter(db, case, kucoin, "stop_order", actor=None, run=run)
    desk.update_draft(db, corr, subject=corr.subject, body=corr.body_markdown + "\nEdited.", recipients=[], cc=[])
    assert corr.stop_order.body_markdown.endswith("Edited.")
    desk.mark_sent(db, case, corr, actor=None)
    order = corr.stop_order
    assert order.status == StopOrderStatus.SENT and order.sent_at == corr.occurred_at
    assert {e["type"] for e in emitted} >= {events.CORRESPONDENCE_OUT, events.STOP_ORDER_STATUS}


def test_export_md_and_docx_inside_export_dir(client_for, db, iso, tmp_path, monkeypatch):
    monkeypatch.setattr(services, "EXPORT_DIR", tmp_path / "exports")
    corr = Correspondence(case=iso.case, entity=iso.entity, direction=CorrespondenceDirection.OUT,
                          status=CorrespondenceStatus.DRAFT, subject="../../etc/passwd \\ evil",
                          body_markdown="**Subject:** x\n\n- `0xabc` \\*not italic\\*\n\n### Heading\n", meta={})
    db.add(corr)
    db.commit()
    c = client_for("investigator", case=iso.case)
    for fmt in ("md", "docx"):
        r = c.get(f"/api/cases/{iso.case.id}/authorities/correspondence/{corr.id}/{fmt}")
        assert r.status_code == 200, r.text
        files = list((tmp_path / "exports").glob(f"*.{fmt}"))
        assert len(files) == 1 and files[0].parent == (tmp_path / "exports").resolve()
        assert re.fullmatch(rf"[A-Za-z0-9-]+_letter-{corr.id}_[A-Za-z0-9-]+\.{fmt}", files[0].name)
    doc = Document(next((tmp_path / "exports").glob("*.docx")))
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "*not italic*" in text and "\\" not in text
    with zipfile.ZipFile(next((tmp_path / "exports").glob("*.docx"))) as zf:
        assert not [n for n in zf.namelist() if not n.endswith((".xml", ".rels"))]
    assert db.scalar(select(AuditEvent).where(AuditEvent.action == "EXPORT", AuditEvent.object_type == "correspondence",
                                              AuditEvent.object_id == str(corr.id)))
    # read-only members cannot export R3 letters
    corr.classification = desk.Classification.R3
    db.commit()
    ro = client_for("read_only", case=iso.case)
    assert ro.get(f"/api/cases/{iso.case.id}/authorities/correspondence/{corr.id}/docx").status_code == 403


@pytest.mark.parametrize("reference,subject", [
    ("../../../etc/passwd", "../../x"),
    ("/abs/path", "a/b\\c..d"),
    ("..", ".."),
])
def test_export_path_is_contained(tmp_path, monkeypatch, reference, subject):
    monkeypatch.setattr(services, "EXPORT_DIR", tmp_path / "exports")
    corr = SimpleNamespace(id=7, subject=subject, body_markdown="hello", case=SimpleNamespace(reference=reference))
    for fmt in ("md", "docx"):
        path = desk.export_correspondence(corr, fmt)
        assert path.parent == (tmp_path / "exports").resolve() and path.exists()
        assert re.fullmatch(rf"[A-Za-z0-9-]+_letter-7_[A-Za-z0-9-]+\.{fmt}", path.name)
    with pytest.raises(desk.DeskError):
        desk.export_path(corr, "../html")


# --------------------------------------------------------------------------- stop-order status
def test_status_changes_log_correspondence_and_emit(client_for, db, iso, emitted):
    c = client_for("investigator", case=iso.case)
    page = f"/cases/{iso.case.id}/authorities/{iso.key}"
    path = f"/cases/{iso.case.id}/stop-orders/{iso.order.id}/status"
    assert _post(c, path, page, {"status": "released", "back": "authority"}).status_code == 400  # not frozen yet
    r = _post(c, path, page, {"status": "acknowledged", "external_ref": "TCK-77", "back": "authority"})
    assert r.status_code == 303 and r.headers["location"].endswith(f"{page}#o{iso.order.id}")
    r = _post(c, path, page, {"status": "frozen", "amount_held": "5.0416", "asset": "eth", "notes": "hold confirmed",
                              "back": "authority"})
    assert r.status_code == 303
    r = _post(c, path, page, {"status": "released", "amount_held": "5.0416", "asset": "ETH", "back": "authority"})
    assert r.status_code == 303
    db.expire_all()
    order = db.get(StopOrder, iso.order.id)
    assert desk.order_state(order) == "released" and not desk.order_open(order)
    hold = desk.hold_state(order)
    assert hold["state"] == "released" and hold["amount"] == "5.0416" and hold["asset"] == "ETH"
    assert order.external_ref == "TCK-77" and order.responded_at is not None
    assert [h["status"] for h in order.identifiers["status_history"]] == ["acknowledged", "frozen", "released"]
    logged = [x for x in order.correspondence if (x.meta or {}).get("source") == "stop_order_status"]
    assert [x.status for x in logged] == [CorrespondenceStatus.LOGGED] * 3
    assert "5.0416 ETH held" in logged[1].subject
    status_events = [e for e in emitted if e["type"] == events.STOP_ORDER_STATUS]
    assert [e["payload"]["status"] for e in status_events] == ["acknowledged", "frozen", "released"]
    frozen = status_events[1]
    assert frozen["severity"] == "high" and frozen["usd"] == Decimal("12856.08")
    for e in status_events:  # no counterparty names, ids and amounts only
        assert iso.entity.name not in e["title"] + e["body"] and e["link"].startswith(f"/cases/{iso.case.id}/")
    audits = list(db.scalars(select(AuditEvent).where(AuditEvent.object_type == "stop_orders",
                                                      AuditEvent.object_id == str(order.id))))
    assert {a.detail.get("status") for a in audits} >= {"acknowledged", "frozen", "released"}
    assert c.get(page).text.count("held") >= 1


# --------------------------------------------------------------------------- overdue
def test_check_overdue_emits_once_per_due_date(db, iso, emitted):
    first = desk.check_overdue(db, iso.case)
    overdue = [e for e in emitted if e["type"] == events.RESPONSE_OVERDUE]
    assert len(overdue) == 1 and overdue[0]["payload"]["stop_order_id"] == iso.order.id
    assert "3 days overdue" in overdue[0]["title"] and iso.entity.name not in overdue[0]["title"]
    assert overdue[0]["link"] == f"/cases/{iso.case.id}/authorities/{iso.key}#o{iso.order.id}"
    assert len(first) <= 1  # the notification rules may suppress delivery; the event was emitted
    desk.check_overdue(db, iso.case)
    assert len([e for e in emitted if e["type"] == events.RESPONSE_OVERDUE]) == 1
    # a new due date (the desk extended it) is notified again; an answered order is not
    db.expire_all()
    order = db.get(StopOrder, iso.order.id)
    order.response_due_at = datetime.now(tz=UTC) - timedelta(hours=1)
    db.commit()
    desk.check_overdue(db, iso.case)
    assert len([e for e in emitted if e["type"] == events.RESPONSE_OVERDUE]) == 2
    order.responded_at = datetime.now(tz=UTC)
    order.response_due_at = datetime.now(tz=UTC) - timedelta(minutes=5)
    db.commit()
    desk.check_overdue(db, iso.case)
    assert len([e for e in emitted if e["type"] == events.RESPONSE_OVERDUE]) == 2


def test_overdue_letters_without_a_reply(db, iso, emitted):
    authority = _authority(db, iso.case, iso.key)
    corr = desk.log_entry(db, iso.case, authority, actor=None, direction="out", channel="email", kind="info_request",
                          subject="Information request", body="x",
                          occurred_at=datetime.now(tz=UTC) - timedelta(days=9), due_days=7)
    iso.order.responded_at = datetime.now(tz=UTC)  # the stop order itself is answered
    db.commit()
    desk.check_overdue(db, iso.case)
    hits = [e for e in emitted if e["type"] == events.RESPONSE_OVERDUE]
    assert [e["payload"].get("correspondence_id") for e in hits] == [corr.id]
    # a later inbound message from the same authority answers it
    desk.log_entry(db, iso.case, _authority(db, iso.case, iso.key), actor=None, direction="in", channel="email",
                   kind="reply", subject="Re: Information request", body="y")
    assert not _authority(db, iso.case, iso.key).awaiting()


def test_check_overdue_api_requires_investigator(client_for, iso):
    ro = client_for("read_only", case=iso.case)
    assert ro.post(f"/api/cases/{iso.case.id}/authorities/check-overdue").status_code == 403
    inv = client_for("investigator", case=iso.case)
    r = inv.post(f"/api/cases/{iso.case.id}/authorities/check-overdue")
    assert r.status_code == 200 and "emitted" in r.json()


def test_authority_pages_render_for_every_demo_counterparty(client, db, case, run):
    for a in desk.case_authorities(db, case, run=run):
        r = client.get(f"/cases/{case.id}/authorities/{a.key}")
        assert r.status_code == 200, (a.key, r.text[:300])
        assert "Generate letter" in r.text and "Log correspondence" in r.text


def test_financial_evidence_never_leaks_through_the_desk(client_for, db, iso):
    from app.domain import evidence as evd

    fin = evd.add_note(db, iso.case, title="FINSECRET bank statement", text="statement", folder="financial",
                       classification="R3")
    db.commit()
    page = f"/cases/{iso.case.id}/authorities/{iso.key}"
    inv = client_for("investigator", case=iso.case)
    assert "FINSECRET" not in inv.get(page).text  # not offered in the evidence select
    r = _post(inv, f"{page}/log", page, {"direction": "note", "kind": "other", "channel": "other",
                                         "subject": "try to link", "evidence_ids": str(fin.id)})
    assert r.status_code == 400
    r = _post(inv, f"/cases/{iso.case.id}/stop-orders/{iso.order.id}/status", page,
              {"status": "acknowledged", "evidence_ids": str(fin.id)})
    assert r.status_code == 400
    admin = client_for("admin", case=iso.case)
    assert "FINSECRET" in admin.get(page).text
    r = _post(admin, f"{page}/log", page, {"direction": "note", "kind": "other", "channel": "other",
                                           "subject": "admin links the statement", "evidence_ids": str(fin.id)})
    assert r.status_code == 303
    for role in ("investigator", "read_only"):
        c = client_for(role, case=iso.case)
        assert "FINSECRET" not in c.get(page).text, role
        items = c.get(f"/api/cases/{iso.case.id}/authorities/{iso.key}/timeline").json()["items"]
        assert all(fin.id not in i["evidence_ids"] for i in items), role
    items = admin.get(f"/api/cases/{iso.case.id}/authorities/{iso.key}/timeline").json()["items"]
    assert any(fin.id in i["evidence_ids"] for i in items)


def test_stop_order_table_fits_at_1280(client_for, case):
    """The stop-order table's dates may wrap between date and time (never inside either) and the Open / .docx
    actions may stack, so the table fits a 1280 px window instead of cutting the .docx button off."""
    page = client_for("admin", case=case).get(f"/cases/{case.id}?tab=authorities").text
    table = page.split('id="stop-orders"', 1)[1].split("</table>", 1)[0]
    rows = re.findall(r"<tr>.*?</tr>", table.split("<tbody>", 1)[1], re.DOTALL)
    assert rows
    for row in rows:
        assert re.search(r'<span class="nowrap">\d\d \w{3} \d{4}</span> <span class="nowrap">\d\d:\d\d UTC</span>', row)
        actions = re.search(r'<td class="([^"]*)"><a class="btn small" href="[^"]+/stop-orders/\d+">Open</a>', row)
        assert actions and "so-actions" in actions.group(1) and "nowrap" not in actions.group(1)
        assert "/docx\">.docx</a>" in row
    assert not re.search(r'<td class="nowrap">\d\d \w{3} \d{4} \d\d:\d\d UTC</td>', table)
