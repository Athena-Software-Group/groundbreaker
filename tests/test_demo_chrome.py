"""Demo chrome: no developer text on the sign-in page or in the header, a header that wraps at phone width, the
cases list as cards on a phone, thousands separators on native amounts."""

from __future__ import annotations

import re
from pathlib import Path

from conftest import anon_client

from app.web.templating import _amt, templates

CSS = (Path(__file__).resolve().parents[1] / "app" / "web" / "static" / "aegis.css").read_text(encoding="utf-8")


def test_login_page_carries_no_developer_text():
    page = anon_client().get("/login").text
    assert "Passkeys" not in page and "WebAuthn" not in page and "identity-spec" not in page
    assert "release v0.1" not in page and 'class="env"' not in page


def test_env_line_only_when_a_setting_asks_for_it(client, monkeypatch):
    page = client.get("/").text
    assert 'class="env"' not in page and "providers:" not in page
    info = dict(templates.env.globals["app_info"], show_env=True)  # AEGIS_SHOW_ENV_BADGE=1
    monkeypatch.setitem(templates.env.globals, "app_info", info)
    page = client.get("/").text
    assert 'class="env"' in page and f"env: <b>{info['env']}</b>" in page


def test_api_link_for_system_admins_only(client, client_for):
    assert 'href="/api/docs"' not in client.get("/").text
    assert 'href="/api/docs"' in client_for(None, system_admin=True).get("/").text


def test_cases_list_is_a_card_list_on_a_phone(client):
    page = client.get("/").text
    assert '<div class="table-scroll">' in page and 'class="cases-table"' in page
    assert 'data-label="Loss"' in page and 'data-label="Open orders"' in page
    assert "399,247.92 USDC" in page  # the native amount with separators, as the USD figure reads
    phone = CSS[CSS.index("@media (max-width: 760px)"):]
    for rule in ("header.top { flex-wrap: wrap;", "header.top nav { order: 3; flex-basis: 100%;",
                 ".cases-table thead, .cases-table .c-opt { display: none; }", ".panel { max-width: 100%; overflow-x: auto; }"):
        assert rule in phone, rule
    assert re.search(r"header\.top \.user-name \{[^}]*text-overflow: ellipsis", CSS)


def test_amounts_get_thousands_separators():
    assert _amt("399247.92") == "399,247.92" and _amt("1359.899028") == "1,359.9"
    assert _amt("0.05683880584988242") == "0.05683881" and _amt(None) == "—"
