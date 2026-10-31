"""Review round 15 of the request gate (app.domain.request_gate) as regressions: after a court-order answer every
surface sends the person to ONE LE step — the row's own LE route (a US case agent's complaint page), never the LE brief
to another LE: the board row, the Recovery plan's provider move, the owners panel, the authority page's gate button and
the gate's own link, with or without an identified deposit and with a stale draft; a pointless draft (stale, court,
LE only, declined, gated) is never recorded as sent by hand — no "Mark sent" panel, no export, no "sent" status, and
every manual route (the letter's Mark sent, the stop order's status form, the API PATCH) answers 409 — unless its
e-mail may already be out (recording it as sent settles it); a records-only draft whose owner deposit leads the plan's
move is titled by that step; the assistant's /stop-orders names the stop order replacing a records-only draft, never
"open it and send it". The demo case plus synthetic replies (every address, ticket and number is made up).
Offline."""

import html
import re
from datetime import timedelta

import pytest
from conftest import csrf_token
from test_freeze_board import (
    CIRCLE_COURT,
    NOW,
    _access,
    _board,
    _order,
    _owned,
    _reply,
    _t,
    _uncontacted_kucoin,
)
from test_request_gate import _kucoin, _panel_link, _skill
from test_request_gate_r13 import _gate_kucoin, _plan_move, _post, _prepared_mail, _primary
from test_request_gate_r14 import _pointless_draft, _run

from app import services
from app.ai import providers
from app.blocks import freeze_board as fb
from app.blocks import recovery as rp
from app.db.models import Correspondence, StopOrder
from app.domain import correspondence as desk
from app.domain import request_gate as rg

COURT = CIRCLE_COURT.replace("Circle", "KuCoin")


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


def _gate_button(client, case, key, query="") -> tuple[str, str]:
    """The authority page's request-gate button (href, label)."""
    page = html.unescape(client.get(f"/cases/{case.id}/authorities/{key}{query}").text)
    i = page.find('id="request-gate')
    assert i >= 0, page[:400]
    m = re.search(r'<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>', page[i:i + 2000])
    assert m is not None, page[i:i + 1200]
    return m.group(1), m.group(2).strip()


# --------------------------------------------------------------------------- one LE step after a court-order answer
@pytest.mark.parametrize("deposit", [False, True])
@pytest.mark.parametrize("stale", [False, True])
def test_a_court_order_answer_leads_every_surface_to_one_le_step(client_for, db, case, stale, deposit):
    o = _order(case, "KuCoin")
    key = _t(_board(db, case), "KuCoin").key
    inv = client_for("investigator", case=case, email=f"r15-court-{stale}-{deposit}@tests.example")
    if stale:  # a status request drafted before their answer: pointless now
        assert _post(inv, case, key, template="status_request", ref=f"o{o.id}").status_code == 303
    _reply(db, case, _order(case, "KuCoin"), COURT, NOW - timedelta(minutes=10))
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1) if deposit else (None, None)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    le = t.step.href
    assert t.step.kind in fb.LE_KINDS and re.fullmatch(rf"/cases/{case.id}/authorities/le-\d+", le or ""), t.step
    st = rg.state(db, case, _kucoin(db, case))
    assert st.le_only and st.le_href == le and st.le_label == t.step.label, (st.le_href, st.le_label)
    if stale:
        assert len(st.pointless) == 1, st.pointless
    # the plan's provider move
    m = _plan_move(rp.build(db, case))
    assert _primary(m)["href"] == le and m.href == le, (le, m.href, m.actions)
    # the gate's own link, for every template (an owner deposit's letter included)
    for tpl in ("stop_order", "info_request", "status_request"):
        d = rg.gate(db, case, _kucoin(db, case), tpl)
        assert d.kind == rg.LE_BRIEF_ONLY and d.href == le and d.label() == t.step.label, (tpl, d.href, d.label())
    about = [f"{chain}:{address}"] if deposit else None
    d = rg.gate(db, case, _kucoin(db, case), "info_request", about=about)
    assert d.href == le and "brief LE instead" in d.text and f"“{t.step.label}”" in d.text, (d.href, d.text)
    # the authority page's request-gate button (plain, and as an owner deposit's letter link opens it)
    assert _gate_button(inv, case, key) == (le, t.step.label)
    if deposit:
        assert _gate_button(inv, case, key, f"?template=info_request&freeze={chain}:{address}")[0] == le
        # the owners panel's line for the identified deposit
        href, text = _panel_link(inv, case, address)
        assert href == le and text.startswith(t.step.label), (href, text, le)
    # the assistant's refusal names the same step
    res = _skill(db, case, inv)
    assert not res.drafts and f"“{t.step.label}”" in res.markdown, res.markdown


def test_an_le_only_answers_le_step_stays_the_le_brief_naming_the_deposit(db, case):
    """Control: the local-LE answer's row step is the LE brief, and the gate's link names the address too."""
    from test_freeze_board import TETHER_LOCAL_LE

    _reply(db, case, _order(case, "KuCoin"), TETHER_LOCAL_LE.replace("Tether", "KuCoin"), NOW - timedelta(minutes=10))
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert "template=le_brief" in (t.step.href or ""), t.step
    d = rg.gate(db, case, _kucoin(db, case), "info_request", about=[f"{chain}:{address}"])
    assert d.href.startswith(t.step.href.split("#")[0]) and "about=" in d.href and d.label() == "Open the LE brief"


# --------------------------------------------------------------------------- a pointless draft is never marked sent
@pytest.mark.parametrize("why", ["stale", "court", "le_only", "declined", "gated"])
def test_a_pointless_draft_letter_is_never_recorded_as_sent(client_for, db, case, monkeypatch, why):
    adm = client_for("admin", case=case, email=f"r15-sent-{why}@tests.example")
    corr, key = _pointless_draft(db, case, adm, why, monkeypatch)
    assert key in [p.key for p in rg.state(db, case, _kucoin(db, case)).pointless]
    url = f"/cases/{case.id}/authorities/correspondence/{corr.id}"
    page = adm.get(url).text
    assert 'id="draft-pointless"' in page, page[:600]
    assert 'id="send"' not in page and "/sent" not in page and "send the letter outside Aegis" not in page.lower()
    assert f"/correspondence/{corr.id}/docx" not in page and f"/correspondence/{corr.id}/md" not in page
    r = adm.post(f"{url}/sent", data={"csrf_token": csrf_token(adm, url), "channel": "email"},
                 follow_redirects=False)
    assert r.status_code == 409 and "pointless" in r.json()["detail"], (r.status_code, r.text[:300])
    db.expire_all()
    assert db.get(Correspondence, corr.id).status.value == "draft"


def test_a_pointless_draft_stop_order_is_never_recorded_as_sent(client_for, db, case, monkeypatch):
    o = _uncontacted_kucoin(db, case, draft=True)
    _gate_kucoin(monkeypatch)
    assert f"o{o.id}" in [p.key for p in rg.state(db, case, _kucoin(db, case)).pointless]
    adm = client_for("admin", case=case, email="r15-so-gated@tests.example")
    url = f"/cases/{case.id}/stop-orders/{o.id}"
    page = adm.get(url).text
    assert 'id="draft-pointless"' in page and 'option value="sent"' not in page, page[:800]
    assert f"/stop-orders/{o.id}/docx" not in page
    tok = csrf_token(adm, url)
    r = adm.post(f"{url}/status", data={"csrf_token": tok, "status": "sent"}, follow_redirects=False)
    assert r.status_code == 409 and "pointless" in r.text, (r.status_code, r.text[:300])
    r = adm.patch(f"/api/cases/{case.id}/stop-orders/{o.id}", json={"status": "sent"}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 409 and "pointless" in r.json()["detail"], (r.status_code, r.text[:300])
    db.expire_all()
    assert db.get(StopOrder, o.id).status.value == "draft"
    # another status is still recorded (the form is no "sent" only)
    assert 'option value="acknowledged"' in page or "acknowledged" in desk.STATUS_CHOICES


def test_a_draft_that_is_not_pointless_is_still_recorded_as_sent(client_for, db, case):
    o = _uncontacted_kucoin(db, case, draft=True)
    adm = client_for("admin", case=case, email="r15-so-ok@tests.example")
    url = f"/cases/{case.id}/stop-orders/{o.id}"
    page = adm.get(url).text
    assert 'option value="sent"' in page and f"/stop-orders/{o.id}/docx" in page
    r = adm.post(f"{url}/status", data={"csrf_token": csrf_token(adm, url), "status": "sent"},
                 follow_redirects=False)
    assert r.status_code == 303, r.text[:300]


def test_a_pointless_draft_whose_e_mail_may_be_out_is_still_recorded_as_sent(client_for, db, case):
    o = _order(case, "KuCoin")
    key = _t(_board(db, case), "KuCoin").key
    adm = client_for("admin", case=case, email="r15-busy@tests.example")
    r = _post(adm, case, key, template="status_request", ref=f"o{o.id}")
    corr = db.get(Correspondence, int(r.headers["location"].split("?")[0].rsplit("/", 1)[1]))
    mm = _prepared_mail(db, case, corr, "unknown")  # its e-mail may already be out
    _reply(db, case, _order(case, "KuCoin"), COURT, NOW - timedelta(minutes=10))
    db.expire_all()
    flag = fb.letter_flag(db, case, corr)
    assert flag is not None and flag["busy"] == mm.id, flag
    url = f"/cases/{case.id}/authorities/correspondence/{corr.id}"
    page = adm.get(url).text
    assert 'id="draft-pointless"' in page and 'id="send"' in page  # recording it as sent settles it
    r = adm.post(f"{url}/sent", data={"csrf_token": csrf_token(adm, url), "channel": "email"},
                 follow_redirects=False)
    assert r.status_code == 303, (r.status_code, r.text[:300])
    db.expire_all()
    assert db.get(Correspondence, corr.id).status.value == "sent"


# --------------------------------------------------------------------------- a records-only draft at a funded provider
def _records_draft(db, case):
    _uncontacted_kucoin(db, case)
    return desk.generate_letter(db, case, _kucoin(db, case), "info_request", actor=None,
                                run=services.latest_run(db, case))


def test_a_records_drafts_move_is_titled_by_the_owner_step_it_leads_with(db, case):
    c = _records_draft(db, case)
    _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    assert t.step.kind == "add" and t.step.label.startswith("Add "), t.step
    m = _plan_move(rp.build(db, case))
    assert _primary(m)["label"] == t.step.label or m.actions[0]["label"] == t.step.label, m.actions
    assert m.title.startswith("Add ") and f"#{c.id}" in m.title and "Send a stop order" not in m.title, m.title


def test_the_assistant_names_the_stop_order_replacing_a_records_only_draft(client_for, db, case):
    c = _records_draft(db, case)
    t = _t(_board(db, case, access=_access(case, "admin")), "KuCoin")
    fo = rg.freeze_over_records(rg.state(db, case, _kucoin(db, case)))
    assert fo is not None and t.step.label == fo["label"], (t.step, fo)
    inv = client_for("investigator", case=case, email="r15-fo@tests.example")
    res = _run(db, case, inv, "stop-orders")
    row = next(ln for ln in res.markdown.splitlines() if ln.startswith("| KuCoin"))
    assert "Recommended now" not in row and f"“{fo['label']}”" in row and f"#{c.id}" in row, row
    assert "Draft for KuCoin" not in [a.get("label") for a in res.actions]
    res = _skill(db, case, inv)
    assert not res.drafts and "open it and send it" not in res.markdown, res.markdown
    assert f"“{fo['label']}”" in res.markdown and "records only" in res.markdown, res.markdown
