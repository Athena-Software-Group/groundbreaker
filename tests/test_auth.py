"""Per-user sign-in, sessions, CSRF on login, rate limiting, case roles, IDOR and the audit log."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from conftest import TEST_PASSWORD, anon_client, csrf_token, ensure_user, login, set_role
from sqlalchemy import func, select

from app import services
from app.core import security
from app.core.audit import audit, verify_chain
from app.core.permissions import ACTIONS, can, require_case_role
from app.db.models import AuditEvent, Case, Chain, StopOrder, TraceRun, UserSession


def _events(db, action: str, **where) -> list[AuditEvent]:
    db.expire_all()
    q = select(AuditEvent).where(AuditEvent.action == action)
    for k, v in where.items():
        q = q.where(getattr(AuditEvent, k) == v)
    return list(db.scalars(q.order_by(AuditEvent.id)))


@pytest.fixture
def other_case(db):
    """A second case owned by someone else, with its own trace run and stop order."""
    owner = ensure_user(db, "other-owner@tests.example")
    case = db.scalar(select(Case).where(Case.reference == "TEST-OTHER-001"))
    if case is None:
        case = services.create_case(
            db, reference="TEST-OTHER-001", title="Other case", victim_name="Test Victim", victim_entity=None,
            loss_amount=Decimal(1), loss_asset="USDC", loss_usd=Decimal(1), fraud_date=None,
            chain=Chain.ETHEREUM, origin_tx=None, victim_wallet=None,
            perpetrator_wallet="0x57de1021A507d46272d386995d5B58667Ac1F8df", created_by=owner,
        )
    if not case.trace_runs:
        services.run_trace(db, case, provider_mode="fixture")
    if not case.stop_orders:
        db.add(StopOrder(case=case, subject="other case letter", body_markdown="secret body of the other case"))
        db.commit()
    db.refresh(case)
    return case


# --------------------------------------------------------------------------- passwords
def test_password_hash_is_salted_scrypt_and_verifies():
    a, b = security.hash_password("s3cret-pass-phrase"), security.hash_password("s3cret-pass-phrase")
    assert a != b and a.startswith("scrypt$")
    assert security.verify_password("s3cret-pass-phrase", a)
    assert not security.verify_password("wrong", a)
    assert not security.verify_password("x", None) and not security.verify_password("x", "garbage")


# --------------------------------------------------------------------------- login / logout
def test_pages_redirect_to_login_when_signed_out(case):
    anon = anon_client()
    r = anon.get(f"/cases/{case.id}?tab=fund_flow", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == f"/login?next=%2Fcases%2F{case.id}%3Ftab%3Dfund_flow"


def test_login_page_without_users_explains_create_user(monkeypatch):
    import sqlalchemy

    from app.web import routes_auth

    assert "scripts.create_user" not in anon_client().get("/login").text  # users exist in the test DB
    # pretend the users table is empty (count over an always-false filter) without deleting anyone
    monkeypatch.setattr(routes_auth, "select", lambda *cols: sqlalchemy.select(*cols).where(sqlalchemy.false()))
    page = anon_client().get("/login")
    assert page.status_code == 200 and "No user accounts exist yet" in page.text and "scripts.create_user" in page.text


def test_login_logout_roundtrip_and_session_is_server_side(db, case):
    user = ensure_user(db, "roundtrip@tests.example")
    set_role(db, case, user, "investigator")
    c = anon_client()
    r = login(c, "Roundtrip@Tests.example")  # e-mail is case-insensitive
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert security.SESSION_COOKIE in c.cookies
    assert c.get("/").status_code == 200
    assert _events(db, "LOGIN", actor_user_id=user.id)
    stolen = c.cookies.get(security.SESSION_COOKIE)

    r = c.post("/logout", data={"csrf_token": csrf_token(c, "/")}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert c.get("/", follow_redirects=False).status_code == 303
    assert _events(db, "LOGOUT", actor_user_id=user.id)
    # a copy of the old cookie is useless: logout revoked the server-side session
    replay = anon_client()
    replay.cookies.set(security.SESSION_COOKIE, stolen)
    assert replay.get("/", follow_redirects=False).status_code == 303


def test_login_requires_csrf_token(db):
    ensure_user(db, "csrf@tests.example")
    c = anon_client()
    c.get("/login")
    r = c.post("/login", data={"email": "csrf@tests.example", "password": TEST_PASSWORD}, follow_redirects=False)
    assert r.status_code == 403
    r = c.post("/login", data={"email": "csrf@tests.example", "password": TEST_PASSWORD,
                               "csrf_token": "forged.token"}, follow_redirects=False)
    assert r.status_code == 403
    assert security.SESSION_COOKIE not in c.cookies


def test_wrong_password_and_inactive_user_are_rejected(db):
    ensure_user(db, "inactive@tests.example", active=False)
    ensure_user(db, "wrongpw@tests.example")
    c = anon_client()
    assert login(c, "wrongpw@tests.example", "not the password").status_code == 401
    assert login(c, "inactive@tests.example").status_code == 401
    assert login(c, "nobody-at-all@tests.example").status_code == 401
    failed = _events(db, "LOGIN_FAILED")
    assert failed and failed[-1].actor_user_id is None and failed[-1].outcome == "denied"
    # the audit row holds a keyed fingerprint, never the address
    assert "email_fp" in failed[-1].detail and "nobody" not in str(failed[-1].detail)


def test_open_redirect_after_login_is_blocked(db):
    ensure_user(db, "redirect@tests.example")
    c = anon_client()
    token = csrf_token(c, "/login")
    r = c.post("/login", data={"email": "redirect@tests.example", "password": TEST_PASSWORD, "csrf_token": token,
                               "next": "//evil.example/x"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_failed_logins_are_rate_limited(db):
    ensure_user(db, "ratelimit@tests.example")
    c = anon_client()
    for _ in range(security.login_limiter.per_email):
        assert login(c, "ratelimit@tests.example", "bad guess").status_code == 401
    # even the right password is refused while the window is full
    r = login(c, "ratelimit@tests.example")
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0
    assert "Too many failed sign-in attempts" in r.text
    assert _events(db, "LOGIN_FAILED")[-1].detail["reason"] == "rate_limited"
    security.login_limiter.reset()
    assert login(c, "ratelimit@tests.example").status_code == 303


def test_rate_limit_also_counts_per_ip():
    limiter = security.LoginRateLimiter(per_email=100, per_ip=3)
    for i in range(3):
        limiter.failed(f"user{i}@tests.example", "203.0.113.9")
    assert limiter.retry_after("fresh@tests.example", "203.0.113.9") > 0
    assert limiter.retry_after("fresh@tests.example", "198.51.100.1") == 0


def test_a_stranger_cannot_lock_an_account_out_for_everyone():
    limiter = security.LoginRateLimiter(per_email=5, per_ip=100, per_email_global=50)
    for _ in range(5):
        limiter.failed("victim@tests.example", "203.0.113.9")
    assert limiter.retry_after("victim@tests.example", "203.0.113.9") > 0  # the attacker's client
    assert limiter.retry_after("victim@tests.example", "198.51.100.1") == 0  # the real user elsewhere
    for i in range(45):
        limiter.failed("victim@tests.example", f"192.0.2.{i}")
    assert limiter.retry_after("victim@tests.example", "198.51.100.1") > 0  # distributed guessing slows


def test_rate_limiter_memory_is_capped():
    limiter = security.LoginRateLimiter(max_keys=300)
    for i in range(2000):
        limiter.failed(f"random{i}@tests.example", f"198.51.100.{i % 250}")
    assert len(limiter) <= 300


def test_idle_session_expires(db, client_for, case):
    c = client_for("read_only", case=case, email="idle@tests.example")
    assert c.get("/").status_code == 200
    row = db.scalar(select(UserSession).where(UserSession.user_id == c.user.id, UserSession.revoked_at.is_(None))
                    .order_by(UserSession.created_at.desc()))
    row.last_seen_at = datetime.now(tz=UTC) - timedelta(hours=2)
    db.commit()
    assert c.get("/", follow_redirects=False).status_code == 303


def test_session_cookie_flags(db):
    ensure_user(db, "flags@tests.example")
    r = login(anon_client(), "flags@tests.example")
    cookie = next(h for h in r.headers.get_list("set-cookie") if h.startswith(security.SESSION_COOKIE)).lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


# --------------------------------------------------------------------------- roles
def test_read_only_member_can_view_but_not_post(client_for, case):
    c = client_for("read_only", case=case)
    assert c.get(f"/cases/{case.id}").status_code == 200
    assert c.get(f"/api/cases/{case.id}/stop-orders").status_code == 200
    token = csrf_token(c, f"/cases/{case.id}")
    for path in (f"/cases/{case.id}/trace", f"/cases/{case.id}/watch/poll", f"/cases/{case.id}/stop-orders"):
        assert c.post(path, data={"csrf_token": token}, follow_redirects=False).status_code == 403, path
    assert c.post(f"/api/cases/{case.id}/trace").status_code == 403
    # buttons that would 403 are not offered
    page = c.get(f"/cases/{case.id}?tab=fund_flow").text
    assert "Run trace" not in page


def test_investigator_can_run_a_trace_and_it_is_audited(db, client_for, case):
    c = client_for("investigator", case=case)
    token = csrf_token(c, f"/cases/{case.id}?tab=fund_flow")
    r = c.post(f"/cases/{case.id}/trace", data={"csrf_token": token, "mode": "fixture"}, follow_redirects=False)
    assert r.status_code == 303
    ev = _events(db, "RUN_TRACE", actor_user_id=c.user.id)[-1]
    assert ev.case_id == case.id and ev.object_type == "trace_runs" and ev.detail["status"] == "complete"
    run = db.get(TraceRun, int(ev.object_id))
    assert run.created_by == c.user.id


def test_non_member_gets_404_everywhere(db, client_for, case):
    c = client_for(None, case=case, email="outsider@tests.example")
    assert case.reference not in c.get("/").text
    assert c.get(f"/cases/{case.id}").status_code == 404
    assert c.get(f"/api/cases/{case.id}").status_code == 404
    assert c.get(f"/cases/{case.id}/team", follow_redirects=False).status_code == 404
    assert case.reference not in {x["reference"] for x in c.get("/api/cases").json()}
    token = csrf_token(c, "/")
    assert c.post(f"/cases/{case.id}/trace", data={"csrf_token": token}).status_code == 404
    denied = _events(db, "ACCESS_DENIED", actor_user_id=c.user.id)
    assert denied and denied[-1].outcome == "denied" and denied[-1].detail["reason"] == "not_a_member"


def test_expired_membership_is_no_membership(db, client_for, case):
    from app.core.permissions import add_member
    from app.db.models import User

    c = client_for("investigator", case=case, email="expired@tests.example")
    user = db.scalar(select(User).where(User.email == "expired@tests.example"))
    add_member(db, case, user, "investigator", expires_at=datetime.now(tz=UTC) - timedelta(minutes=1))
    db.commit()
    assert c.get(f"/cases/{case.id}").status_code == 404


def test_system_admin_sees_every_case(client_for, case, other_case):
    c = client_for(None, system_admin=True)
    refs = {x["reference"] for x in c.get("/api/cases").json()}
    assert {case.reference, other_case.reference} <= refs
    assert c.get(f"/cases/{other_case.id}").status_code == 200
    page = c.get("/").text
    assert case.reference in page and other_case.reference in page


def test_case_list_shows_only_member_cases(client_for, case, other_case):
    c = client_for("admin", case=case)
    page = c.get("/").text
    assert case.reference in page and other_case.reference not in page


def test_external_member_sees_only_shared_tabs(client_for, case):
    c = client_for("external", case=case)
    page = c.get(f"/cases/{case.id}")
    assert page.status_code == 200
    assert 'id="tab-authorities"' in page.text  # first tab an external may see
    assert "?tab=fund_flow" not in page.text and "Jordan Avery" not in page.text
    assert 'id="tab-authorities"' in c.get(f"/cases/{case.id}?tab=fund_flow").text  # falls back
    assert c.get(f"/api/cases/{case.id}/stop-orders").status_code == 403


def test_only_case_creators_may_open_cases(db, client_for, case):
    """Opening a case makes you its admin: never a right of an external, read-only or member-less
    account (review: an LE liaison could open a case and mint accounts / read other cases' files)."""
    payload = {"reference": "TEST-DENIED-1", "title": "t", "victim_name": "v", "loss_amount": "10",
               "perpetrator_wallet": "0x57de1021A507d46272d386995d5B58667Ac1F8df"}
    clients = [client_for("external", case=case, email="ext.creator@tests.example"),
               client_for("read_only", case=case, email="ro.creator@tests.example"),
               client_for("admin", case=case, email="caseadmin.creator@tests.example"),
               client_for(None, email="nomember.creator@tests.example")]
    for c in clients:
        assert c.get("/cases/new").status_code == 403
        assert "/cases/new" not in c.get("/").text
        r = c.post("/api/cases", json={**payload, "loss_usd": "10"})
        assert r.status_code == 403
    admin = clients[2]
    token = csrf_token(admin, f"/cases/{case.id}?tab=team")
    assert admin.post("/cases/new", data={"csrf_token": token, **payload}, follow_redirects=False).status_code == 403
    assert db.scalar(select(Case).where(Case.reference == "TEST-DENIED-1")) is None
    assert _events(db, "CREATE", object_type="cases", outcome="denied")
    # a system admin may (and so may an account granted can_create_cases, below)
    sysadmin = client_for(None, system_admin=True)
    assert sysadmin.get("/cases/new").status_code == 200


def test_creator_of_a_case_becomes_its_admin(db, client_for):
    c = client_for(None, email="creator@tests.example", can_create_cases=True)
    token = csrf_token(c, "/cases/new")
    ref = "TEST-NEW-" + datetime.now(tz=UTC).strftime("%H%M%S%f")
    r = c.post("/cases/new", data={
        "csrf_token": token, "reference": ref, "title": "t", "victim_name": "v", "loss_amount": "10",
        "perpetrator_wallet": "0x57de1021A507d46272d386995d5B58667Ac1F8df",
    }, follow_redirects=False)
    assert r.status_code == 303
    new = db.scalar(select(Case).where(Case.reference == ref))
    assert [(m.user_id, m.role.value) for m in new.members] == [(c.user.id, "admin")]
    assert _events(db, "CREATE", case_id=new.id, object_type="cases")



def test_case_references_are_unique_ignoring_case_and_unicode(db, client_for, case):
    """'demo-2026-001' next to 'DEMO-2026-001' is the same evidence directory on macOS: refused."""
    c = client_for(None, email="outsider@tests.example", can_create_cases=True)
    token = csrf_token(c, "/cases/new")
    form = {"csrf_token": token, "title": "t", "victim_name": "v", "loss_amount": "10",
            "perpetrator_wallet": "0x57de1021A507d46272d386995d5B58667Ac1F8df"}
    before = db.scalar(select(func.count()).select_from(Case))
    for ref, status in ((case.reference.lower(), 409), (f" {case.reference.swapcase()} ", 409),
                        ("DEMO-2026-00\u0031\u0301", 400), ("\uff24EMO-2026-001", 400), ("../x", 400)):
        r = c.post("/cases/new", data={**form, "reference": ref}, follow_redirects=False)
        assert r.status_code == status, (ref, r.status_code)
    api = c.post("/api/cases", json={"reference": case.reference.lower(), "title": "t", "victim_name": "v",
                                     "loss_amount": "1", "loss_usd": "1"})
    assert api.status_code == 409
    assert db.scalar(select(func.count()).select_from(Case)) == before
    with pytest.raises(services.CaseReferenceError):
        services.check_new_reference(db, case.reference.casefold())


# --------------------------------------------------------------------------- IDOR
def test_run_ids_of_another_case_are_not_reachable(db, client_for, case, other_case):
    c = client_for("admin", case=case)
    foreign_run = other_case.trace_runs[0].id
    assert c.get(f"/cases/{case.id}?tab=fund_flow&run_id={foreign_run}").status_code == 404
    assert c.get(f"/api/cases/{case.id}/trace/{foreign_run}/graph").status_code == 404
    assert c.get(f"/api/cases/{case.id}/trace/{foreign_run}/freeze-candidates").status_code == 404
    assert c.get(f"/api/cases/{other_case.id}/trace/{foreign_run}/graph").status_code == 404  # not a member
    own_run = (services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")).id
    assert c.get(f"/api/cases/{case.id}/trace/{own_run}/graph").status_code == 200
    assert c.get(f"/cases/{case.id}?tab=fund_flow&run_id={own_run}").status_code == 200


def test_stop_orders_of_another_case_are_not_reachable(client_for, case, other_case):
    c = client_for("admin", case=case)
    foreign = other_case.stop_orders[0].id
    for path in (f"/cases/{case.id}/stop-orders/{foreign}", f"/api/cases/{case.id}/stop-orders/{foreign}/docx"):
        r = c.get(path)
        assert r.status_code == 404 and "secret body" not in r.text, path
    token = csrf_token(c, f"/cases/{case.id}")
    r = c.post(f"/cases/{case.id}/stop-orders/{foreign}/status", data={"csrf_token": token, "status": "frozen"})
    assert r.status_code == 404
    r = c.patch(f"/api/cases/{case.id}/stop-orders/{foreign}", json={"status": "frozen"})
    assert r.status_code == 404
    assert other_case.stop_orders[0].status.value == "draft"


def test_old_unscoped_routes_are_gone(client):
    for path in ("/api/trace/1/graph", "/api/trace/1/freeze-candidates", "/stop-orders/1", "/api/stop-orders/1/docx"):
        assert client.get(path).status_code == 404, path


# --------------------------------------------------------------------------- policy helpers & audit
def test_can_and_role_order(db, case):
    ro = ensure_user(db, "policy-ro@tests.example")
    set_role(db, case, ro, "read_only")
    assert can(ro, case, "view") and not can(ro, case, "run_trace") and not can(ro, case, "manage_members")
    admin = ensure_user(db, "policy-sys@tests.example", system_admin=True)
    assert all(can(admin, case, a) for a in ACTIONS)
    assert not can(None, case, "view")
    with pytest.raises(KeyError):
        can(ro, case, "no-such-action")
    assert callable(require_case_role("investigator"))


def test_audit_is_append_only_and_hash_chained(db, case):
    ev = audit(db, None, "TEST_EVENT", case, ("thing", 42), outcome="allowed", count=3,
               email="someone@tests.example", body="free text")
    assert ev.object_type == "thing" and ev.object_id == "42" and ev.case_id == case.id
    assert ev.detail == {"count": 3}  # PII-shaped keys are dropped
    assert verify_chain(db) is None
    ev.action = "TAMPERED"
    with pytest.raises(ValueError, match="append-only"):
        db.commit()
    db.rollback()
    db.delete(db.get(AuditEvent, ev.id))
    with pytest.raises(ValueError, match="append-only"):
        db.commit()
    db.rollback()


def test_concurrent_audit_appends_never_fork_the_chain(db, case):
    """Review: parallel requests read the same previous hash and forked the chain (verify_chain then
    reported the log broken for good). Appends are now serialised."""
    import threading

    from app.db.session import SessionLocal

    assert verify_chain(db) is None
    barrier = threading.Barrier(8)
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        try:
            with SessionLocal() as s:
                barrier.wait()
                for i in range(12):
                    s.scalar(select(AuditEvent.id).limit(1))  # a read before the append, like a route
                    audit(s, None, "TEST_CONCURRENT", case.id, ("thing", n * 100 + i))
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    db.expire_all()
    assert verify_chain(db) is None
    rows = db.scalars(select(AuditEvent).where(AuditEvent.action == "TEST_CONCURRENT")).all()
    assert len(rows) == 96 and len({r.prev_hash for r in rows}) == 96


def test_events_emit_records_a_notification(db, case):
    from app.core import events
    from app.db.models import Notification

    n = events.emit(db, case, events.VASP_DEPOSIT, usd="1234.5", title="Deposit at KuCoin", body="0x0a17…58e2",
                    link=f"/cases/{case.id}?tab=fund_flow", severity="critical")
    assert db.get(Notification, n.id).usd == Decimal("1234.50")
    with pytest.raises(ValueError):
        events.emit(db, case, "nope", title="x", body=None, link=None)
