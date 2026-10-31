"""One open request per provider (app.domain.request_gate): every path that creates a letter or a stop order to a
provider — the Authorities tab's bulk and row generators, POST /api/cases/{id}/stop-orders, the authority page (any
template), the assistant's /stop-orders, the Recovery plan's owner moves and the owners panel's links — goes through the
one gate; the board, the plan, the owners panel and the assistant show the gate's step. State × path: no second request
to the provider; a newly identified address lands in the open draft; the LE brief is the only option once the provider
answered LE only / court order / declined. Plus the r9 review probes as regressions. The demo case plus
synthetic replies (every address, ticket and number is made up). Offline."""

import html
import re
from datetime import timedelta
from urllib.parse import parse_qs, unquote, urlparse

import pytest
from conftest import csrf_token
from test_freeze_board import (
    CIRCLE_COURT,
    NOW,
    TETHER_LOCAL_LE,
    _access,
    _board,
    _gate,
    _generate,
    _hrefs,
    _order,
    _owned,
    _post_owner_letter,
    _prepared,
    _reply,
    _t,
    _uncontacted_kucoin,
)

from app import services
from app.ai import providers
from app.blocks import freeze_board as fb
from app.blocks import recovery as rp
from app.db.models import Correspondence, StopOrder, StopOrderStatus
from app.domain import correspondence as desk
from app.domain import request_gate as rg

DECLINE = "Thank you for contacting KuCoin compliance. After review we must decline your request."
STATES = ("nothing", "draft", "prepared", "sent", "le_only", "court_order", "declined")
PATHS = ("bulk", "row", "api", "page", "page_info", "assistant", "owner_link", "owners_panel")


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


def _kucoin(db, case):
    db.expire_all()
    return desk.get_authority(db, case, _t(_board(db, case), "KuCoin").key, run=services.latest_run(db, case))


def _requests(db, case) -> tuple[set, set]:
    """(KuCoin's stop orders, its outgoing letters not tied to one) — every request ever made to it."""
    a = _kucoin(db, case)
    return ({o.id for o in a.stop_orders},
            {c.id for c in a.correspondence if c.direction.value == "out" and c.stop_order_id is None})


def _state(db, case, state):
    """KuCoin in `state`; returns the request key the gate should point at (None: nothing yet)."""
    if state == "nothing":
        _uncontacted_kucoin(db, case)
        return None
    if state in ("draft", "prepared"):
        o = _uncontacted_kucoin(db, case, draft=True)
        if state == "prepared":
            from app.domain import mail_compose as compose

            corr, _ = compose.ensure_correspondence(db, o, _kucoin(db, case), None)
            _prepared(db, case, corr)
        return f"o{o.id}"
    o = _order(case, "KuCoin")
    text = {"le_only": TETHER_LOCAL_LE.replace("Tether", "KuCoin"), "court_order": CIRCLE_COURT.replace("Circle", "KuCoin"),
            "declined": DECLINE}.get(state)
    if text:
        _reply(db, case, o, text, NOW - timedelta(hours=10))
    return f"o{o.id}"


def _skill(db, case, client):
    from app.ai import skills
    from app.core.permissions import CaseAccess, effective_role, membership

    access = CaseAccess(case=case, user=client.user, role=effective_role(db, client.user, case),
                        member=membership(db, client.user, case))
    return skills.run_skill(db, access, "stop-orders", "draft kucoin")


def _owner_link(case, key, chain, address, ref=None) -> str:
    """The owner move's own letter (app.attribution.ask_for: an exchange deposit), as a bookmarked link posts it."""
    return (f"/cases/{case.id}/authorities/{key}?template=info_request&freeze={chain}:{address}"
            + (f"&ref={ref}" if ref else "") + "#generate")


def _panel_link(client, case, address) -> tuple[str, str]:
    """The owners panel's (href, text) for `address` on the Recovery plan page: its Next step cell, the button's link
    and the cell's text (the button's label, then the line beside it)."""
    page = client.get(f"/cases/{case.id}/recovery-plan").text
    owners = page.split('id="owners"', 1)[1]
    short = rp._short(address)
    row = next(r for r in owners.split("<tr")[1:] if short in r)
    m = re.search(r'<td class="own-next"><a class="btn small" href="([^"]+)">([^<]+)</a> <span class="bk-small">'
                  r'([^<]*)</span>', row)
    assert m is not None, row[:600]
    # the e-mail flow's way back (app/web/mail_flow.py: ?return_to=…) is not part of the step's own link
    href = re.sub(r"[?&]return_to=[^&#]*", "", html.unescape(m.group(1)))
    return href, html.unescape(f"{m.group(2)} {m.group(3)}")


def _post_link(client, case, href):
    q = parse_qs(urlparse(href).query)
    key = urlparse(href).path.rsplit("/", 1)[1]
    data = {"csrf_token": csrf_token(client, f"/cases/{case.id}/authorities/{key}"),
            "template": q.get("template", ["info_request"])[0], "freeze_address": (q.get("freeze") or [""])[0],
            "about": (q.get("about") or [""])[0], "ref": (q.get("ref") or [""])[0],
            "extra_note": unquote((q.get("note") or [""])[0])}
    return client.post(f"/cases/{case.id}/authorities/{key}/letters", data=data, follow_redirects=False)


# --------------------------------------------------------------------------- state × path
@pytest.mark.parametrize("state", STATES)
@pytest.mark.parametrize("path", PATHS)
def test_no_second_request_to_the_provider_on_any_path(client_for, db, case, state, path):
    open_key = _state(db, case, state)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    key = _t(_board(db, case), "KuCoin").key
    before = _requests(db, case)
    inv = client_for("investigator", case=case, email=f"rg-{state}-{path}@tests.example")
    expect_new = state == "nothing" or (state == "sent" and path in ("owner_link", "owners_panel"))
    if path == "bulk":
        r = _generate(inv, case)
        assert r.status_code == 303
    elif path == "row":
        r = _generate(inv, case, entity="KuCoin")
        assert r.status_code == 303
        if not expect_new:
            assert "so_skip=" in r.headers["location"]
    elif path == "api":
        tok = csrf_token(inv, f"/cases/{case.id}?tab=authorities")
        r = inv.post(f"/api/cases/{case.id}/stop-orders", json=["KuCoin"], headers={"X-CSRF-Token": tok})
        assert r.status_code == 201
        if not expect_new:
            assert r.json() == [] and f"{key}:" in r.headers["x-aegis-skipped"]
    elif path in ("page", "page_info"):
        tok = csrf_token(inv, f"/cases/{case.id}/authorities/{key}")
        r = inv.post(f"/cases/{case.id}/authorities/{key}/letters", follow_redirects=False,
                     data={"csrf_token": tok, "template": "stop_order" if path == "page" else "info_request"})
        assert r.status_code == (303 if state == "nothing" else 409), r.text[:300]
        if state != "nothing":  # what to do instead: the open draft (or "replaces draft #N"), the request, LE
            d = _gate(db, case, key, "stop_order" if path == "page" else "info_request")
            assert not d.allowed and d.no in r.text, (d, r.text[:300])
    elif path == "assistant":
        res = _skill(db, case, inv)
        assert bool(res.drafts) == (state == "nothing"), res.markdown
    elif path == "owner_link":  # the owner move's letter, as a bookmarked / stale link posts it
        ref = "o" + open_key[1:] if state in ("sent",) else None
        r = _post_link(inv, case, _owner_link(case, key, chain, address, ref))
        if state in ("draft",):
            assert r.status_code == 303 and "?added=" in r.headers["location"]
        elif state in ("nothing", "sent"):
            assert r.status_code == 303 and "?added=" not in r.headers["location"]
        else:
            assert r.status_code == 409, r.text[:300]
    else:  # the owners panel's link for the wallet: what it points at, then posting it
        href, text = _panel_link(inv, case, address)
        if state == "prepared":
            assert "/mail/messages/" in href and "Open & send e-mail" in text
        elif state in ("le_only", "court_order", "declined"):
            assert "template=le_brief" in href or "template=le_cover" in href or "/authorities/le-" in href, href
            assert f"/authorities/{key}?" not in href
        elif state == "draft":
            assert f"/authorities/{key}?template=info_request" in href and "Add " in text
            page = inv.get(href).text  # the page says so and its button adds it (no second letter's form)
            assert 'id="request-gate-add"' in page and f"Add {rp._short(address)} to draft #{open_key[1:]}" in page
            r = _post_link(inv, case, href)
            assert r.status_code == 303 and "?added=" in r.headers["location"]
        elif state == "sent":  # the follow-up quoting the request already out
            ref = parse_qs(urlparse(href).query)["ref"][0]
            assert ref in rg.state(db, case, _kucoin(db, case)).sent_keys and f"freeze={chain}:{address}" in href
            r = _post_link(inv, case, href)
            assert r.status_code == 303
        else:
            r = _post_link(inv, case, href)
            assert r.status_code == 303
    after = _requests(db, case)
    new_orders, new_letters = after[0] - before[0], after[1] - before[1]
    if not expect_new:
        assert not new_orders and not new_letters, (state, path, new_orders, new_letters)
    else:
        assert len(new_orders) + len(new_letters) == 1, (state, path, new_orders, new_letters)
    a = _kucoin(db, case)
    if state == "draft" and path in ("owner_link", "owners_panel"):  # the new address landed in the open draft
        o = db.get(StopOrder, int(open_key[1:]))
        assert address in o.body_markdown and o.status == StopOrderStatus.DRAFT
        assert address.lower() in {str(x["address"] if isinstance(x, dict) else x).lower()
                                   for x in o.identifiers["addresses"]}
    if state == "sent" and path in ("owner_link", "owners_panel"):  # the follow-up quoting the request
        c = db.get(Correspondence, next(iter(new_letters)))
        assert c.meta["about"] == [f"{chain}:{address}"] and address in c.body_markdown
        assert "further to our letter of" in c.subject
        # and now that follow-up is the one open request: nothing else is drafted
        assert not _gate(db, case, key, "status_request").allowed
    if state == "nothing" and path in ("bulk", "row", "api", "page", "assistant"):  # one stop order citing both
        o = next(x for x in a.stop_orders if x.id in new_orders)
        assert address.lower() in {str(x["address"] if isinstance(x, dict) else x).lower()
                                   for x in o.identifiers["addresses"]}
    # whatever the path, a second attempt creates nothing more
    if expect_new:
        mid = _requests(db, case)
        _generate(inv, case, entity="KuCoin")
        assert _skill(db, case, inv).drafts == []
        assert _requests(db, case) == mid


@pytest.mark.parametrize("state", ("le_only", "court_order", "declined"))
def test_the_le_brief_is_the_only_option_once_the_provider_answered_le_only(client_for, db, case, state):
    open_key = _state(db, case, state)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    board = _board(db, case, access=_access(case, "admin"))
    t = _t(board, "KuCoin")
    # the row: its LE step (it names the identified address too), never a letter to KuCoin
    assert t.step.kind in fb.LE_KINDS and t.step.label, (t.step, t.status)
    assert not any(f"/authorities/{t.key}?template=" in (s.href or "") and "template=status_request" not in s.href
                   for s in [t.step, *t.extra]), _hrefs(t)
    assert not t.draftable and t.skip[0] in ("le_only", "declined")
    for tpl in ("stop_order", "info_request", "status_request"):
        d = _gate(db, case, t.key, tpl, about=[f"{chain}:{address}"])
        assert d.kind == rg.LE_BRIEF_ONLY and d.key == open_key, (tpl, d)
    d = _gate(db, case, t.key, "info_request", about=[f"{chain}:{address}"])
    assert "/authorities/le-" in d.href, d.href
    if "?template=" in d.href:  # the LE brief names the address; a court order's LE route is the row's own page
        assert "about=" in d.href and address.lower() in d.href.lower(), d.href
    else:
        assert d.href == t.step.href, (d.href, t.step)
    # the plan: the owner move is the LE brief (merged into the request's own LE move), no freeze letter
    plan = rp.build(db, case)
    m = plan.find(f"owner:{chain}:{address}")
    assert m.cites["state"] == "le" and m.kind == "le"
    assert not any(f"freeze={chain}:{address}" in (x.get("href") or "") for mv in plan.moves + plan.waiting
                   for x in mv.actions)
    inv = client_for("investigator", case=case, email=f"rg-le-{state}@tests.example")
    page = inv.get(f"/cases/{case.id}/recovery-plan").text
    assert f"freeze={chain}:{address}" not in page
    tab = inv.get(f"/cases/{case.id}?tab=authorities").text
    row = tab.split(f'id="fb-{t.key}"', 1)[1].split("</tr>", 1)[0]
    assert "Open the letter to KuCoin" not in row
    # the authority page shows the gate's message instead of the letter
    page = inv.get(f"/cases/{case.id}/authorities/{t.key}?template=info_request&freeze={chain}:{address}").text
    assert 'id="request-gate"' in page and "brief LE instead" in page


# --------------------------------------------------------------------------- the r9 review probes
def test_owner_letter_draft_blocks_every_generator_and_the_assistant(client_for, db, case):
    """r9: uncontacted KuCoin with the owner letter drafted: no generator drafts a second freeze letter."""
    _uncontacted_kucoin(db, case)
    _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    adm = _access(case, "admin")
    t = _t(_board(db, case, access=adm), "KuCoin")
    inv = client_for("investigator", case=case, email="r9-a@tests.example")
    r = _post_owner_letter(inv, case, t.step.href)
    cid = int(r.headers["location"].rsplit("/", 1)[1])
    board = _board(db, case, access=adm)
    t = _t(board, "KuCoin")
    assert t.step.label == "Open & send draft" and t.skip == ("draft", f"c{cid}") and not t.draftable
    before = _requests(db, case)
    _generate(inv, case)
    _generate(inv, case, entity="KuCoin")
    tok = csrf_token(inv, f"/cases/{case.id}?tab=authorities")
    r = inv.post(f"/api/cases/{case.id}/stop-orders", json=["KuCoin"], headers={"X-CSRF-Token": tok})
    assert r.json() == [] and f"{t.key}:draft:c{cid}" in r.headers["x-aegis-skipped"]
    tok = csrf_token(inv, f"/cases/{case.id}/authorities/{t.key}")
    r = inv.post(f"/cases/{case.id}/authorities/{t.key}/letters", data={"csrf_token": tok, "template": "stop_order"},
                 follow_redirects=False)
    assert r.status_code == 409 and f"draft letter #{cid}" in r.text
    res = _skill(db, case, inv)
    assert not res.drafts and f"letter #{cid}" in res.markdown and "Nothing drafted" not in res.markdown.split(":")[0]
    assert _requests(db, case) == before
    plan = rp.build(db, case)
    assert [m.key for m in plan.moves + plan.waiting if m.authority is not None and m.authority.name == "KuCoin"] == [
        f"c{cid}"]


def test_hot_wallet_letter_is_a_follow_up_once_and_never_twice(client_for, db, case):
    """r9: a hot wallet attributed to KuCoin (its request already sent): the letter is a follow-up quoting that
    request (ref), records what it concerns (meta.about), and is never drafted twice."""
    chain, address = _owned(db, case, "KuCoin", kind="exchange_hot_wallet", i=1)
    adm = _access(case, "admin")
    t = _t(_board(db, case, access=adm), "KuCoin")
    href = next(s.href for s in [t.step, *t.extra] if s.href and "template=info_request" in s.href)
    q = parse_qs(urlparse(href).query)
    sent = f"o{_order(case, 'KuCoin').id}"
    assert q["about"] == [f"{chain}:{address}"] and q["ref"][0] in (sent, *(f"c{c.id}" for c in
                                                                           _order(case, "KuCoin").correspondence))
    inv = client_for("investigator", case=case, email="r9-hw@tests.example")
    r = _post_link(inv, case, href)
    assert r.status_code == 303, r.text[:300]
    cid = int(r.headers["location"].rsplit("/", 1)[1])
    c = db.get(Correspondence, cid)
    assert c.meta["about"] == [f"{chain}:{address}"] and address in c.body_markdown
    # drafted: the row sends that draft; the plan and the owners panel offer no second hot-wallet letter
    t = _t(_board(db, case, access=adm), "KuCoin")
    assert t.step.href == f"/cases/{case.id}/authorities/correspondence/{cid}"
    page = inv.get(f"/cases/{case.id}/recovery-plan").text
    assert f"about={chain}:{address}" not in page.replace("%3A", ":")
    assert _post_link(inv, case, href).status_code == 409  # the same link again
    desk.mark_sent(db, case, db.get(Correspondence, cid), actor=None, sent_at=NOW - timedelta(hours=2),
                   channel="email")
    page = inv.get(f"/cases/{case.id}/recovery-plan").text
    assert "template=info_request&amp;about=" + f"{chain}:{address}" not in page
    r = _post_link(inv, case, href)
    assert r.status_code == 409 and "already asks about" in r.text  # sent: the same wallet never again
    assert not _t(_board(db, case, access=adm), "KuCoin").duplicates


def test_two_deposits_one_letter(client_for, db, case):
    """r9: two deposits identified at an uncontacted KuCoin: the second lands in the first one's draft."""
    _uncontacted_kucoin(db, case)
    c1, a1 = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    c0, a0 = _owned(db, case, "KuCoin", kind="exchange_deposit", i=0)
    adm = _access(case, "admin")
    t = _t(_board(db, case, access=adm), "KuCoin")
    inv = client_for("investigator", case=case, email="r9-2d@tests.example")
    r = _post_owner_letter(inv, case, t.step.href)
    cid = int(r.headers["location"].rsplit("/", 1)[1])
    first = db.get(Correspondence, cid)
    other = (c0, a0) if a1.lower() in first.meta["freeze"] else (c1, a1)
    t = _t(_board(db, case, access=adm), "KuCoin")
    add = next(s for s in [t.step, *t.extra] if s.kind == "add")
    assert add.label == f"Add {rp._short(other[1])} to draft letter #{cid}"
    assert not any("freeze=" in (s.href or "") for s in [t.step, *t.extra])
    r = inv.post(add.post, data={"csrf_token": csrf_token(inv, f"/cases/{case.id}/authorities/{t.key}"),
                                 **add.fields}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(
        f"/cases/{case.id}/authorities/correspondence/{cid}?added=")
    db.expire_all()
    first = db.get(Correspondence, cid)
    assert other[1] in first.body_markdown and f"{other[0]}:{other[1].lower()}" in first.meta["about"]
    assert _requests(db, case)[1] == {cid}
    page = inv.get(r.headers["location"]).text
    assert 'id="letter-added"' in page
    t = _t(_board(db, case, access=adm), "KuCoin")
    assert not any(s.kind == "add" for s in [t.step, *t.extra]) and t.step.label == "Open & send draft"


def test_swap_order_records_follow_up_quotes_the_request(db, case):
    """r9: a swap order attributed to SWFT (its request already sent): the records letter quotes that request."""
    chain, address = _owned(db, case, "SWFT / Bridgers", kind="swap_bridge", i=1)
    t = _t(_board(db, case, access=_access(case, "admin")), "SWFT / Bridgers")
    href = next(s.href for s in [t.step, *t.extra] if s.href and "template=info_request" in s.href)
    q = parse_qs(urlparse(href).query)
    assert q["about"] == [f"{chain}:{address}"] and q.get("ref")
    d = _gate(db, case, t.key, "info_request", about=q["about"], ref=q["ref"][0])
    assert d.allowed
    assert _gate(db, case, t.key, "info_request", about=q["about"]).kind == rg.FOLLOW_UP_ONLY  # never without ref


def test_court_order_reply_and_a_deposit_offer_only_the_le_route(client_for, db, case):
    """r9: KuCoin answered "court order": no freeze letter on the plan or the row."""
    _state(db, case, "court_order")
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    inv = client_for("investigator", case=case, email="r9-court@tests.example")
    page = inv.get(f"/cases/{case.id}/recovery-plan").text
    assert f"freeze={chain}:{address}" not in page
    tab = inv.get(f"/cases/{case.id}?tab=authorities").text
    t = _t(_board(db, case), "KuCoin")
    row = tab.split(f'id="fb-{t.key}"', 1)[1].split("</tr>", 1)[0]
    buttons = re.findall(r'>([^<>]{3,60})</(?:a|button)>', row)
    assert "Open the letter to KuCoin" not in buttons and any("LE" in b or "case agent" in b for b in buttons), buttons


def test_replacing_an_owner_letter_with_a_stop_order_carries_its_deposit(client_for, db, case):
    """r9: the authority page's "replaces draft letter #N": the letter is superseded and its deposit cited."""
    _uncontacted_kucoin(db, case)
    chain, address = _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    adm = _access(case, "admin")
    t = _t(_board(db, case, access=adm), "KuCoin")
    inv = client_for("investigator", case=case, email="r9-rep@tests.example")
    cid = int(_post_owner_letter(inv, case, t.step.href).headers["location"].rsplit("/", 1)[1])
    url = f"/cases/{case.id}/authorities/{t.key}"
    page = inv.get(f"{url}?template=stop_order").text
    assert f"replaces draft letter #{cid}" in page and f'name="replace_draft" value="c{cid}"' in page
    r = inv.post(f"{url}/letters", data={"csrf_token": csrf_token(inv, url), "template": "stop_order",
                                         "replace_draft": f"c{cid}"}, follow_redirects=False)
    assert r.status_code == 303, r.text[:300]
    db.expire_all()
    old = db.get(Correspondence, cid)
    new = db.get(Correspondence, int(r.headers["location"].rsplit("/", 1)[1]))
    order = new.stop_order
    assert old.meta["superseded_by"] == order.id and old.meta["superseded_by_letter"] == new.id
    assert address.lower() in {str(x["address"] if isinstance(x, dict) else x).lower()
                               for x in order.identifiers["addresses"]}
    assert f"{chain}:{address.lower()}" in new.meta["about"]
    t = _t(_board(db, case, access=adm), "KuCoin")
    assert [r_["key"] for r_ in t.requests] == [f"o{order.id}"] and t.step.label == "Open & send draft"
    plan = rp.build(db, case)
    assert plan.find(f"owner:{chain}:{address}").cites["key"] == f"o{order.id}"
    page = inv.get(f"/cases/{case.id}/authorities/correspondence/{cid}").text
    assert 'id="letter-replaced"' in page and 'id="send"' not in page
    r = inv.post(f"/cases/{case.id}/authorities/correspondence/{cid}/sent",
                 data={"csrf_token": csrf_token(inv, f"/cases/{case.id}/authorities/correspondence/{cid}"),
                       "channel": "email"}, follow_redirects=False)
    assert r.status_code == 409


def test_overdue_owner_letter_offers_the_chase_never_a_new_letter(client_for, db, case):
    """r9: the owner letter sent 12 days ago: the plan chases it, no new letter for that deposit."""
    _uncontacted_kucoin(db, case)
    _owned(db, case, "KuCoin", kind="exchange_deposit", i=1)
    adm = _access(case, "admin")
    t = _t(_board(db, case, access=adm), "KuCoin")
    inv = client_for("investigator", case=case, email="r9-od@tests.example")
    cid = int(_post_owner_letter(inv, case, t.step.href).headers["location"].rsplit("/", 1)[1])
    desk.mark_sent(db, case, db.get(Correspondence, cid), actor=None, sent_at=NOW - timedelta(days=12),
                   channel="email")
    page = inv.get(f"/cases/{case.id}/recovery-plan").text
    kucoin = [h for h in re.findall(r'href="([^"]*)"', page) if f"/authorities/{t.key}?" in h]
    assert kucoin and all("template=status_request" in h for h in kucoin), kucoin
    b = _board(db, case, access=adm)
    assert "KuCoin" not in fb.generator_plan(b)[0]
    assert _t(b, "KuCoin").step.label == "Chase"


def test_owners_panel_never_links_a_letter_for_a_wallet_a_request_cites(client_for, db, case):
    """r9: the demo's owners panel: a wallet a request of its provider already cites has no letter link."""
    inv = client_for("investigator", case=case, email="r9-op@tests.example")
    page = inv.get(f"/cases/{case.id}/recovery-plan").text
    owners = page.split('id="owners"', 1)[1]
    db.expire_all()
    cited = {}
    for o in case.stop_orders:
        if o.status == StopOrderStatus.SUPERSEDED:
            continue
        for x in (o.identifiers or {}).get("addresses") or []:
            a = str(x.get("address") if isinstance(x, dict) else x).lower()
            cited.setdefault(a, set()).add(f"entity-{o.entity_id}")
    for m in re.finditer(r'href="([^"]*template=info_request[^"]*)"', owners):
        href = m.group(1).replace("&amp;", "&")
        p = rg.parse_link(href)
        for k in p["about"]:
            assert p["key"] not in cited.get(rg.addr_of(k), set()), href


def test_untouched_issuers_plan_and_board_point_at_the_same_notice(client_for, db, case):
    """r9: the plan and the board agree on the LE-only issuers: once their notices are drafted neither offers a new
    stop order, both point at the drafts."""
    inv = client_for("investigator", case=case, email="r9-iss@tests.example")
    _generate(inv, case)
    board = _board(db, case, access=_access(case, "admin"))
    plan = rp.build(db, case)
    for name in ("Tether (USDT issuer)", "Circle (USDC issuer)"):
        t = _t(board, name)
        draft = next(o for o in t.authority.stop_orders if o.status == StopOrderStatus.DRAFT)
        assert any(s.href == f"/cases/{case.id}/stop-orders/{draft.id}" for s in [t.step, *t.extra]), name
        moves = [m for m in plan.moves + plan.waiting if m.authority is not None and m.authority.key == t.key]
        assert not any("template=stop_order" in (x.get("href") or "") for m in moves for x in m.actions), name
        assert _gate(db, case, t.key).kind == rg.OPEN_EXISTING


def test_every_letter_records_what_it_concerns(db, case):
    _uncontacted_kucoin(db, case)
    a = _kucoin(db, case)
    corr = desk.generate_letter(db, case, a, "stop_order", actor=None, run=services.latest_run(db, case))
    assert corr.meta["about"] and all(":" in k for k in corr.meta["about"])
    ids = {str(x["address"] if isinstance(x, dict) else x).lower() for x in corr.stop_order.identifiers["addresses"]}
    assert {rg.addr_of(k) for k in corr.meta["about"]} == ids
    hostinger = desk.get_authority(db, case, _t(_board(db, case), "Hostinger").key, run=services.latest_run(db, case))
    ref = rg.state(db, case, hostinger).sent.key  # Hostinger was asked already: a follow-up about the new address
    info = desk.generate_letter(db, case, hostinger, "info_request", actor=None, run=services.latest_run(db, case),
                                about=["ethereum:0x1111111111111111111111111111111111111111"], ref=ref)
    assert info.meta["about"] == ["ethereum:0x1111111111111111111111111111111111111111"]
    assert "0x1111111111111111111111111111111111111111" in info.body_markdown


def test_letters_to_le_and_counsel_are_never_gated(db, case):
    board = _board(db, case)
    le = next(iter(board.le_auths.values()))
    assert rg.gate(db, case, le, "le_cover").allowed and rg.state(db, case, le) is None
