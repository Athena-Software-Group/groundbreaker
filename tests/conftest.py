"""Test harness: isolated SQLite DB, offline providers, demo fixture, exports outside the repo.

Safety rules (enforced before any app module is imported):
* a non-SQLite DATABASE_URL in the environment aborts the run — tests drop and recreate the
  schema, so they must never point at a real database;
* the SQLite file lives in a fresh temp directory (under $AEGIS_TEST_TMPDIR when set), never
  in the repository; pytest's tmp_path tree lives in that same per-session directory, so two
  concurrent runs never share (or wipe) each other's temp files;
* providers are forced to the offline fixture; .docx exports go to the temp directory.
"""

import atexit
import contextlib
import json
import os
import shutil
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:  # plain `pytest` (not `python -m pytest`) from any cwd
    sys.path.insert(0, str(REPO_ROOT))
DEMO_FIXTURE = REPO_ROOT / "data" / "fixtures" / "demo_case.json"

_existing = os.environ.get("DATABASE_URL", "")
if _existing and not _existing.startswith("sqlite"):
    raise RuntimeError(
        "Refusing to run tests: DATABASE_URL points at a non-SQLite database. "
        "Tests drop and recreate the schema; unset DATABASE_URL."
    )

_tmp_base = os.environ.get("AEGIS_TEST_TMPDIR") or None
if _tmp_base:
    Path(_tmp_base).mkdir(parents=True, exist_ok=True)
TEST_TMP = Path(tempfile.mkdtemp(prefix="aegis-tests-", dir=_tmp_base)).resolve()
atexit.register(shutil.rmtree, TEST_TMP, ignore_errors=True)
if TEST_TMP.is_relative_to(REPO_ROOT):
    raise RuntimeError(f"Refusing to run tests: temp dir {TEST_TMP} is inside the repository")

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_TMP / 'aegis_test.db'}"
os.environ["PROVIDER_MODE"] = "fixture"
# the sender of record the tests expect (the product defaults are placeholders: app.core.config)
os.environ["AEGIS_ORG_NAME"] = "Athena Software Group, Inc."
os.environ["AEGIS_SIGNATORY_NAME"] = "Athena Investigations"


# The demo fixture's workspace clock (its stop orders' sent_at / response_due_at, its correspondence's occurred_at /
# due_at) is fixed: the letters went out on 18 Oct 2026 with replies due on 21 Oct 2026 from 22:02 UTC. Tests read the
# board, the plan and the block rows against the real clock, so once that date passed every "wait" row turned "chase"
# (and with a whole-day shift, how far the replies were from due — 10 to 34 hours — still depended on the time of day).
# The tests seed a copy whose workspace clock is moved by FIXTURE_SHIFT (any sign, whole minutes) so that "now" is
# FIXTURE_ANCHOR in the fixture's own time, on any date and at any hour: after the notes' 20 Oct follow-up dates, about
# ten hours before the replies fall due (the suite's own run time is minutes). On-chain data (transfers, the fraud
# date, a stop order's identifiers) keeps its dates: it only gets older, and nothing the tests read changes past a
# week of age (the Recovery plan's "funds arrived" urgency). The fixture provider reads the same copy. `shifted()`
# gives a fixture timestamp as seeded.
FIXTURE_ANCHOR = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
_WORKSPACE_CLOCK = {"stop_orders_imported": ("sent_at", "response_due_at", "responded_at"),
                    "correspondence": ("occurred_at", "due_at")}


def _fixture_shift(now: datetime) -> timedelta:
    """Whole minutes (rounded down) from FIXTURE_ANCHOR to `now`: the seeded copy's "now" is the anchor, give or take a
    minute, whatever the date or the hour."""
    return timedelta(minutes=(now - FIXTURE_ANCHOR) // timedelta(minutes=1))


FIXTURE_SHIFT = _fixture_shift(datetime.now(tz=UTC))


def shifted(value: str | datetime) -> datetime:
    """A fixture workspace timestamp ("2026-10-18T22:27:06Z") as the tests' seeded copy holds it."""
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value + FIXTURE_SHIFT


def _shift_fixture(src: Path, dst: Path, shift: timedelta) -> Path:
    data = json.loads(src.read_text(encoding="utf-8"))
    for section, fields in _WORKSPACE_CLOCK.items():
        for item in data.get(section) or []:
            for f in fields:
                if item.get(f):
                    at = datetime.fromisoformat(item[f].replace("Z", "+00:00")) + shift
                    item[f] = at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    dst.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return dst


TEST_FIXTURE = _shift_fixture(DEMO_FIXTURE, TEST_TMP / "demo_case.json", FIXTURE_SHIFT)
os.environ["AEGIS_FIXTURE_PATH"] = str(TEST_FIXTURE)
# Trace with the shipped defaults (Settings.trace_max_hops): a shell override must not hide a
# default that is too small to reach the KuCoin leg (hop 9; see test_default_max_hops_*).
os.environ.pop("TRACE_MAX_HOPS", None)
os.environ["APP_ENV"] = "local"  # session cookie without Secure (TestClient talks plain http)
os.environ["APP_SECRET_KEY"] = "test-only-secret-key-" + "x" * 32
for _var in [v for v in os.environ if v.startswith("AEGIS_DEMO_") and v.endswith("_PASSWORD")]:
    os.environ.pop(_var)  # the demo fixture's team passwords: generated in tests, never from the shell
# The case assistant never reaches a model API in tests (tests that need a model patch
# app.ai.providers.get_provider, or build a provider over httpx.MockTransport); no token or LLM
# setting from the shell reaches a test. Dev-login and evidence settings come only from the tests.
os.environ["AEGIS_AI_DISABLED"] = "1"
for _var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE", "ANTHROPIC_BASE_URL",
             "HF_INFERENCE_TOKEN", "HF_TOKEN", "LLM_API_KEY", "HF_API_KEY", "AEGIS_HF_BILL_TO",
             "AEGIS_DEV_LOGIN_TOKEN", "AEGIS_VAULT_DIR", "AEGIS_EVIDENCE_ROOTS", "SMTP_HOST", "SLACK_WEBHOOK_URL"):
    os.environ.pop(_var, None)
for _var in [v for v in os.environ if v.startswith("AEGIS_LLM_")]:
    os.environ.pop(_var)
# Mail (transport, mailbox, Microsoft 365 credentials) comes only from the tests: nothing from the shell
# can make a test reach a real mailbox.
for _var in [v for v in os.environ if v.startswith(("AEGIS_MAIL_", "AEGIS_M365_"))]:
    os.environ.pop(_var)
# Owner lookups (public explorer tags) come only from the tests: no explorer key or URL from the shell.
for _var in [v for v in os.environ if v.startswith("AEGIS_OWNER_")] + ["TRONSCAN_API_KEY"]:
    os.environ.pop(_var, None)
os.environ["AEGIS_OWNER_LOOKUPS_AUTO"] = "0"  # no explorer call from every trace run in tests (tests opt in)

import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import services
from app.core import security
from app.core.permissions import add_member
from app.db.models import Base, Case, CaseRole, User
from app.db.session import SessionLocal, engine
from app.services import seed_from_fixture

security.SCRYPT_N = 2**10  # fast hashes for test users (verification honours the stored cost)
TEST_PASSWORD = "correct horse battery staple"

assert engine.url.get_backend_name() == "sqlite", engine.url
assert Path(engine.url.database).resolve().is_relative_to(TEST_TMP), engine.url

services.EXPORT_DIR = TEST_TMP / "exports"


def pytest_configure(config):
    # Keep pytest's own tmp_path tree inside this session's TEST_TMP (under AEGIS_TEST_TMPDIR when
    # given). It must be unique per session: pytest empties an explicit --basetemp when a session
    # starts, so a fixed "<AEGIS_TEST_TMPDIR>/pytest-basetemp" shared by two runs (two terminals, CI
    # jobs, agents) let the second run delete the first one's tmp_path directories mid-test, e.g.
    # the mail inbox / vault a sync was reading (FileNotFoundError during ingest).
    if _tmp_base and not config.option.basetemp:
        config.option.basetemp = str(TEST_TMP / "pytest-basetemp")


@pytest.fixture(scope="session", autouse=True)
def _schema():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)
    engine.dispose()
    shutil.rmtree(TEST_TMP, ignore_errors=True)


@pytest.fixture(autouse=True)
def _exports_outside_repo(monkeypatch):
    monkeypatch.setattr(services, "EXPORT_DIR", TEST_TMP / "exports")


@pytest.fixture
def db():
    with SessionLocal() as s:
        yield s


@pytest.fixture
def case(db):
    return seed_from_fixture(db)


@contextlib.contextmanager
def ungated():
    """Letters and stop orders made past the request gate (app.domain.request_gate: one open request per provider),
    as a case could hold them from before it: the mail and letter-rendering tests draft one letter after another to
    the shared demo case's KuCoin (already asked). The gate itself is tested in test_request_gate.py. Its belt in the
    generators (services.mail_pending: never supersede a draft whose e-mail waits for Send or is under way) is held to
    the rule from before the gate — an open "Draft — you send" checklist only — since one test leaves a prepared or
    sending e-mail of KuCoin's draft behind for the next (test_request_gate_r10.py tests the belt itself)."""
    from sqlalchemy import or_

    from app.db.models import MailDirection, MailMessage, MailStatus
    from app.domain import mail_compose
    from app.domain import request_gate as rg

    def checklists_only(db, orders, letters=None):
        keys = [f"o{o.id}" for o in orders] + [f"c{c.id}" for c in letters or []]
        cids = [c.id for o in orders for c in o.correspondence] + [c.id for c in letters or []]
        rows = db.scalars(select(MailMessage).where(
            or_(MailMessage.letter_key.in_(keys), MailMessage.correspondence_id.in_(cids)),
            MailMessage.direction == MailDirection.OUT, MailMessage.transport == "manual",
            MailMessage.status.in_((MailStatus.PREPARED, MailStatus.EXPIRED)))).all()
        return next((r for r in rows if mail_compose.is_open_checklist(r)), None)

    real, real_pending = rg.decide, services.mail_pending
    rg.decide = lambda *a, **k: rg.Decision(rg.ALLOW)
    services.mail_pending = checklists_only
    try:
        yield
    finally:
        rg.decide, services.mail_pending = real, real_pending


@pytest.fixture
def past_duplicates(monkeypatch):
    """E-mail a stop-order draft the board flags as a duplicate of a request already sent (freeze_board.draft_flags):
    the mail tests draft one stop order after another past the request gate (`ungated`) to the shared demo case's
    providers, already asked, so each one is such a duplicate. Compose, Send and the stop order's e-mail route refuse
    only a pointless draft here; the duplicate refusal itself is tested in test_request_gate_r14.py."""
    from app.blocks import freeze_board as fb

    monkeypatch.setattr(fb, "letter_flag", fb.letter_pointless)
    monkeypatch.setattr(fb, "order_flag", fb.pointless_flag)


@pytest.fixture(autouse=True)
def _reset_login_rate_limit():
    security.login_limiter.reset()
    yield
    security.login_limiter.reset()


# --------------------------------------------------------------------------- users & clients
def ensure_user(db, email: str, *, name: str | None = None, system_admin: bool = False,
                password: str = TEST_PASSWORD, active: bool = True, can_create_cases: bool = False) -> User:
    """Get or create a test user with a known password."""
    user = db.scalar(select(User).where(User.email == email.lower()))
    if user is None:
        user = User(email=email.lower(), display_name=name or email.split("@")[0],
                    password_hash=security.hash_password(password))
        db.add(user)
    user.is_system_admin, user.is_active, user.can_create_cases = system_admin, active, can_create_cases
    db.commit()
    return user


def set_role(db, case: Case, user: User, role: str | CaseRole | None) -> None:
    """Make `user` a member of `case` with `role` (None removes the membership)."""
    from app.db.models import CaseMember

    m = db.scalar(select(CaseMember).where(CaseMember.case_id == case.id, CaseMember.user_id == user.id))
    if role is None:
        if m is not None:
            db.delete(m)
    else:
        add_member(db, case, user, role)
    db.commit()


def csrf_token(client: TestClient, path: str = "/login") -> str:
    page = client.get(path)
    assert page.status_code == 200, (path, page.status_code)
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert m, f"no CSRF field on {path}"
    return m.group(1)


def login(client: TestClient, email: str, password: str = TEST_PASSWORD):
    """Sign in through the real form (CSRF included). Returns the POST response."""
    token = csrf_token(client, "/login")
    return client.post("/login", data={"email": email, "password": password, "csrf_token": token},
                       follow_redirects=False)


def anon_client() -> TestClient:
    """A fresh client. Like a browser it sends a same-origin Origin header on every request (the
    API refuses cookie-authenticated writes without one; see app.core.csrf)."""
    from app.main import app

    return TestClient(app, headers={"Origin": "http://testserver"})


@pytest.fixture
def client_for(db):
    """Factory: a TestClient signed in as a user with `role` on `case` (None = no membership).

        c = client_for("read_only", case=case)
        c = client_for(None, system_admin=True)
        c = client_for(None, can_create_cases=True)   # may open new cases
    """

    def make(role: str | None = "admin", *, case: Case | None = None, system_admin: bool = False,
             email: str | None = None, can_create_cases: bool = False) -> TestClient:
        email = email or f"{'sysadmin' if system_admin else (role or 'nobody')}@tests.example"
        user = ensure_user(db, email, system_admin=system_admin, can_create_cases=can_create_cases)
        if case is not None:
            set_role(db, case, user, role)
        c = anon_client()
        r = login(c, email)
        assert r.status_code == 303, r.text
        c.user = user  # type: ignore[attr-defined]
        return c

    return make


@pytest.fixture
def client(client_for, case):
    """Signed in (session cookie) as the demo case's admin member admin@tests.example."""
    return client_for("admin", case=case)


@pytest.fixture
def basic_client(db, case):
    """HTTP Basic against `users` (API only), as the demo case's admin member."""
    import base64

    ensure_user(db, "admin@tests.example")
    set_role(db, case, db.scalar(select(User).where(User.email == "admin@tests.example")), "admin")
    c = anon_client()
    c.headers["Authorization"] = "Basic " + base64.b64encode(f"admin@tests.example:{TEST_PASSWORD}".encode()).decode()
    return c
