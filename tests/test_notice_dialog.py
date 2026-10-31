"""A refused browser form comes back to its page with the message in a dialog, never as raw JSON;
API clients, scripts and tests keep the JSON response."""

from __future__ import annotations

from conftest import csrf_token


def test_a_refused_browser_form_shows_a_dialog_on_its_page_and_json_stays_for_scripts(db, case, client_for):
    adm = client_for("admin", case=case, system_admin=True)
    page = f"/cases/{case.id}?tab=authorities"
    tok = csrf_token(adm, page)
    url = f"/cases/{case.id}/channels/catalogue/circle.blocklisting/verify"  # refused in a demo case (409)
    # a script / test (no Accept: text/html): JSON as before
    r = adm.post(url, data={"verified": "1", "csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 409 and r.headers["content-type"].startswith("application/json") and "detail" in r.json()
    # a browser form: back to the page it came from, the message in a dialog shown once
    browser = {"accept": "text/html,application/xhtml+xml", "referer": f"http://testserver{page}"}
    r = adm.post(url, data={"verified": "1", "csrf_token": tok}, headers=browser, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == page
    html = adm.get(page, headers={"accept": "text/html"}).text
    assert 'id="notice-dialog"' in html and "demo case" in html and 'method="dialog"' in html
    assert 'id="notice-dialog"' not in adm.get(page, headers={"accept": "text/html"}).text  # once
    # another site as Referer: never followed; the message is its own page (status kept)
    r = adm.post(url, data={"verified": "1", "csrf_token": tok},
                 headers={"accept": "text/html", "referer": "https://evil.example/x"}, follow_redirects=False)
    assert r.status_code == 409 and "notice-page" in r.text and "evil.example" not in r.text
    # the JSON API keeps JSON even for a browser
    assert adm.get(f"/api/cases/{case.id}/no-such-thing", headers={"accept": "text/html"}).headers[
        "content-type"].startswith("application/json")
