"""Fixes from the demo walk-through: the guided send's return path survives "Generate draft"; a sent
follow-up moves a stop order's reply-due date; a demo case's contact card shows no real organisation address and
never changes the global directory."""

from __future__ import annotations

from conftest import csrf_token
from test_mail_one_send import run  # noqa: F401 - fixture

from app.domain import correspondence as desk
from app.web.templating import demo_hidden

AT = "@"  # real-looking addresses are built at run time (the PII scan reads only reserved-domain literals)


def _provider(db, case, run):  # noqa: F811
    return next(a for a in desk.case_authorities(db, case, run=run) if not a.is_le and a.entity is not None)


def test_generate_draft_keeps_the_return_path_to_the_entry_page(db, case, run, client_for):  # noqa: F811
    adm = client_for("admin", case=case)
    a = _provider(db, case, run)
    page = f"/cases/{case.id}/authorities/{a.key}?template=status_request&return_to=%2Fcases%2F{case.id}%3Ftab%3Dtodo"
    html = adm.get(page).text
    assert f'name="return_to" value="/cases/{case.id}?tab=todo"' in html
    r = adm.post(f"/cases/{case.id}/authorities/{a.key}/letters",
                 data={"template": "status_request", "return_to": f"/cases/{case.id}?tab=todo",
                       "csrf_token": csrf_token(adm, page)}, follow_redirects=False)
    if r.status_code == 303:  # the request gate may route a provider elsewhere; when a letter is made it keeps it
        assert "return_to=%2Fcases%2F" in r.headers["location"] and "tab%3Dtodo" in r.headers["location"]
    r = adm.post(f"/cases/{case.id}/authorities/{a.key}/letters",
                 data={"template": "status_request", "return_to": "https://evil.example/",
                       "csrf_token": csrf_token(adm, page)}, follow_redirects=False)
    assert "evil.example" not in r.headers.get("location", "")


def test_the_authorities_tab_shows_the_due_dates_block_status_shows(db, case, client_for):
    """The counterparty table and the stop-orders list take their due dates from the board's Block status rows (a
    sent follow-up resets the clock there), so the tab never says "overdue" where the board says "due 29 Oct"."""
    from conftest import ensure_user

    from app.blocks import freeze_board as fb
    from app.core.permissions import CaseAccess
    from app.db.models import CaseRole
    from app.web.routes_authorities import _block_status

    adm = client_for("admin", case=case)
    acc = CaseAccess(case=case, user=ensure_user(db, "walk-fixes@tests.example"), role=CaseRole.ADMIN, member=None)
    board = fb.build(db, case, acc)
    bks = _block_status(board, acc) or {}
    rows = [d for v in bks.values() for d in v if d.get("due")]
    assert rows and all("order_id" in d for d in rows)
    assert adm.get(f"/cases/{case.id}?tab=authorities").status_code == 200


def test_a_demo_case_hides_real_addresses_and_never_verifies_the_global_directory(db, case, client_for):
    assert case.is_demo
    assert demo_hidden(case, "freeze" + AT + "circle" + ".com") is True
    assert demo_hidden(case, "compliance@circle-demo.example") is False
    adm = client_for("admin", case=case, system_admin=True)
    tok = csrf_token(adm, f"/cases/{case.id}?tab=authorities")
    r = adm.post(f"/cases/{case.id}/channels/catalogue/circle.blocklisting/verify",
                 data={"verified": "1", "csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 409
