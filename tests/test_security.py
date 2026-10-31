"""Security regressions: XSS escaping, CSRF, export containment, secret handling, headers, logs."""

import logging
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import ungated

from app import services
from app.core import csrf
from app.core.config import Settings, get_settings, insecure_settings
from app.core.logging import RedactingFilter, redact
from app.services import generate_stop_orders, latest_run, run_trace

PAYLOAD = '<script>alert("xss")</script><img src=x onerror=alert(1)>'
TEMPLATES = Path(__file__).resolve().parents[1] / "app" / "web" / "templates"


def _run(db, case):
    return latest_run(db, case) or run_trace(db, case, provider_mode="fixture")


def _token(client, path: str) -> str:
    page = client.get(path)
    assert page.status_code == 200
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert m, "form without CSRF field"
    return m.group(1)


# --------------------------------------------------------------------------- XSS
def test_markdown_filter_escapes_raw_html():
    from app.web.routes import _render_md

    html = _render_md(f"**bold** {PAYLOAD} [x](javascript:alert(1))")
    assert "<strong>bold</strong>" in html
    assert "<script" not in html and "<img" not in html and 'href="javascript:' not in html
    assert "&lt;script&gt;" in html


def test_untrusted_case_values_are_escaped_in_pages(client, db, case):
    from app.db.models import SenderProfile

    original = case.victim_name
    # the PI-firm letter quotes the victim's name verbatim (the demo's sender profile is restored by the
    # next seed: app.fixture_sections.load_sender_profile upserts it)
    db.query(SenderProfile).filter(SenderProfile.case_id == case.id).delete()
    try:
        case.victim_name = PAYLOAD
        db.commit()
        run = _run(db, case)
        with ungated():  # the demo already asked its providers: the escaping is under test
            order = generate_stop_orders(db, case, run)[0]
        assert PAYLOAD in order.body_markdown  # stored verbatim; escaping happens at render time
        for path in ("/", f"/cases/{case.id}", f"/cases/{case.id}?tab=authorities",
                     f"/cases/{case.id}/stop-orders/{order.id}"):
            text = client.get(path).text
            assert "<script>alert" not in text and "<img src=x" not in text, path
            assert "&lt;script&gt;alert" in text, path
    finally:
        case.victim_name = original
        db.commit()


def test_templates_have_no_inline_script_or_handlers():
    tpls = list(TEMPLATES.rglob("*.html"))
    assert any(t.parent.name == "case" for t in tpls)  # the tab partials are covered too
    for tpl in tpls:
        src = tpl.read_text()
        for tag in re.findall(r"<script\b[^>]*>", src):
            assert "src=" in tag or 'type="application/json"' in tag, (tpl.name, tag)
        assert not re.search(r"\son[a-z]+\s*=", src), tpl.name
        assert "|safe" not in src.replace(" ", ""), tpl.name


# --------------------------------------------------------------------------- CSRF
def test_html_post_without_csrf_token_is_rejected(client, case):
    r = client.post(f"/cases/{case.id}/watch/poll", follow_redirects=False)
    assert r.status_code == 403


def test_html_post_with_csrf_token_is_accepted(client, case):
    token = _token(client, f"/cases/{case.id}")
    r = client.post(f"/cases/{case.id}/watch/poll", data={"csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303


def test_csrf_token_must_match_the_cookie(client, case):
    _token(client, f"/cases/{case.id}")  # sets this client's cookie
    other = csrf.new_token()  # validly signed, but not this browser's
    r = client.post(f"/cases/{case.id}/watch/poll", data={"csrf_token": other}, follow_redirects=False)
    assert r.status_code == 403


def test_unsigned_double_submit_pair_is_rejected(client, case):
    forged = "attacker-nonce.deadbeef"
    client.cookies.set(csrf.COOKIE, forged)
    r = client.post(f"/cases/{case.id}/watch/poll", data={"csrf_token": forged}, follow_redirects=False)
    assert r.status_code == 403


def test_csrf_token_is_bound_to_the_session(client, case):
    """Review: any validly signed pair from someone else's GET /login was accepted."""
    from conftest import anon_client

    attacker = anon_client()
    attacker.get("/login")
    pair = attacker.cookies.get(csrf.COOKIE)
    assert pair and csrf.is_valid(pair)  # valid for an anonymous visitor ...
    client.cookies.set(csrf.COOKIE, pair, domain="testserver.local")  # replaces this browser's cookie
    r = client.post(f"/cases/{case.id}/watch/poll", data={"csrf_token": pair}, follow_redirects=False)
    assert r.status_code == 403  # ... but not in the victim's session
    token = _token(client, f"/cases/{case.id}")  # the page re-issues one bound to this session
    assert token != pair
    assert client.post(f"/cases/{case.id}/watch/poll", data={"csrf_token": token},
                       follow_redirects=False).status_code == 303


def test_cookie_authenticated_api_writes_need_a_same_origin_proof(client, basic_client, case):
    url = f"/api/cases/{case.id}/watch/poll"
    del client.headers["Origin"]
    assert client.post(url).status_code == 403
    assert client.post(url, headers={"X-Requested-With": "fetch"}).status_code == 200
    assert client.post(url, headers={"Referer": f"http://testserver/cases/{case.id}"}).status_code == 200
    assert client.post(url, headers={"Referer": "https://evil.example/"}).status_code == 403
    del basic_client.headers["Origin"]
    assert basic_client.post(url).status_code == 200  # scripts with HTTP Basic carry no ambient cookie


def test_csrf_cookie_uses_the_host_prefix_outside_local(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(type(get_settings()), "is_local", property(lambda self: False))
    assert csrf.cookie_name() == "__Host-aegis_csrf"


def test_csrf_cookie_flags():
    from conftest import anon_client

    r = anon_client().get("/login")
    cookie = r.headers["set-cookie"].lower()
    assert csrf.COOKIE in cookie and "httponly" in cookie and "samesite=strict" in cookie


def test_cross_origin_unsafe_request_is_rejected_on_api(client, case):
    r = client.post(f"/api/cases/{case.id}/watch/poll", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    same = client.post(f"/api/cases/{case.id}/watch/poll", headers={"Origin": "http://testserver"})
    assert same.status_code == 200


# --------------------------------------------------------------------------- exports
@pytest.mark.parametrize("reference,subject", [
    ("../../../etc/passwd", "../../x"),
    ("/abs/path", "a/b\\c..d"),
    ("..", ".."),
])
def test_docx_export_stays_inside_export_dir(tmp_path, monkeypatch, reference, subject):
    monkeypatch.setattr(services, "EXPORT_DIR", tmp_path / "exports")
    order = SimpleNamespace(id=7, subject=subject, body_markdown="hello", case=SimpleNamespace(reference=reference))
    path = services.export_stop_order_docx(order)
    assert path.parent == (tmp_path / "exports").resolve()
    assert path.exists() and path.suffix == ".docx"
    assert re.fullmatch(r"[A-Za-z0-9-]+_7_[A-Za-z0-9-]+\.docx", path.name)


def test_export_dir_is_configurable():
    assert services._export_root("exports") == services.REPO_ROOT / "exports"
    assert services._export_root("/srv/out") == Path("/srv/out").resolve()


# --------------------------------------------------------------------------- secrets
def test_settings_are_not_exposed_to_templates():
    from app.web.routes import templates

    env_globals = templates.env.globals
    assert "settings" not in env_globals
    assert not any(isinstance(v, Settings) for v in env_globals.values())
    s = get_settings()
    flat = repr(env_globals.get("app_info"))
    assert s.app_secret_key not in flat and "secret" not in flat.lower()


def test_insecure_settings_detected():
    bad = Settings(app_secret_key="CHANGE_ME", app_env="production")
    problems = insecure_settings(bad)
    assert any("APP_SECRET_KEY" in p for p in problems)
    assert any("shorter" in p for p in insecure_settings(Settings(app_secret_key="short", app_env="production")))
    good = Settings(app_secret_key="k" * 48, database_url="sqlite:///x.db", app_env="production")
    assert insecure_settings(good) == []


def test_refuses_to_start_outside_local_with_placeholder_secrets(monkeypatch):
    from app import main

    monkeypatch.setattr(main, "get_settings", lambda: Settings(app_env="production", app_secret_key=""))
    with pytest.raises(RuntimeError, match="Refusing to start"):
        main.check_secrets()


def test_local_with_placeholder_secrets_only_warns(monkeypatch, caplog):
    from app import main

    monkeypatch.setattr(main, "get_settings", lambda: Settings(app_env="local", app_secret_key="CHANGE_ME"))
    with caplog.at_level(logging.WARNING, logger="app"):
        main.check_secrets()
    assert "insecure configuration" in caplog.text


def test_basic_auth_for_unknown_user_is_rejected():
    import base64

    from conftest import anon_client

    anon = anon_client()
    anon.headers["Authorization"] = "Basic " + base64.b64encode(b"demo:demo").decode()  # HTTP Basic credentials
    assert anon.get("/api/cases").status_code == 401
    anon.headers["Authorization"] = "Basic " + base64.b64encode(b":").decode()
    assert anon.get("/api/cases").status_code == 401


def test_api_docs_and_schema_require_auth(client):
    from conftest import anon_client

    anon = anon_client()
    for path in ("/openapi.json", "/api/docs"):
        assert anon.get(path).status_code == 401, path
    schema = client.get("/openapi.json")
    assert schema.status_code == 200 and "/api/cases" in schema.json()["paths"]
    docs = client.get("/api/docs")
    assert docs.status_code == 200 and "/openapi.json" in docs.text
    assert "cdn.jsdelivr.net" in docs.headers["content-security-policy"]  # the wider docs-only policy


# --------------------------------------------------------------------------- headers
def test_security_headers(client):
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "script-src" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "same-origin"
    assert client.get("/static/graph.js").headers["content-security-policy"] == csp


# --------------------------------------------------------------------------- logs
def test_log_redaction():
    fake_key = "gsk_" + "abcdefghijkl"  # built at runtime so the repo's own secret scanner stays quiet
    line = ("GET https://api.etherscan.io/v2/api?module=account&apikey=ABCDEF123456&address="
            "0x57de1021A507d46272d386995d5B58667Ac1F8df by mara.lindqvist@kestrel-ridge.example "
            "tx 0x70abbe14aa9080b572aa69881536e5c165097c0574c4791467e915b708bba814 key " + fake_key)
    out = redact(line)
    assert "ABCDEF123456" not in out and "apikey=***" in out
    assert "0x57de…F8df" in out and "0x70ab…a814" in out
    assert "kestrel-ridge" not in out and fake_key not in out


def test_redacting_filter_formats_args_and_keeps_data():
    addr = "0x57de1021A507d46272d386995d5B58667Ac1F8df"
    rec = logging.LogRecord("app.x", logging.INFO, __file__, 1, "moved from %s", (addr,), None)
    RedactingFilter().filter(rec)
    assert rec.getMessage() == "moved from 0x57de…F8df"
    assert addr == "0x57de1021A507d46272d386995d5B58667Ac1F8df"
