"""Authentication: per-user accounts, password login, server-side sessions, HTTP Basic for /api.

* Passwords are hashed with stdlib `hashlib.scrypt` (random 16-byte salt, parameters stored in
  the hash) and verified in constant time. Accounts are created with `scripts/create_user.py`
  or the fixture "team" section; no account has a default password.
* The web UI signs in at /login. The session cookie (`aegis_session`, signed by Starlette's
  SessionMiddleware with a key derived from APP_SECRET_KEY) carries only a random token; the
  `user_sessions` row holds its SHA-256 plus idle / absolute expiry, so logout really ends it.
* Routes under /api (and /openapi.json) also accept HTTP Basic checked against `users`.
* Failed logins are rate-limited in memory per e-mail and per client IP.

Route code depends on `require_user` (any signed-in user) or, for anything case-scoped, on
`app.core.permissions.require_case_role`. An unauthenticated request raises `NotAuthenticated`;
app.main turns that into a redirect to /login for pages and a 401 for the API.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import User, UserSession
from app.db.session import get_db

SESSION_COOKIE = "aegis_session"
SESSION_KEY = "sid"  # key inside the signed cookie
API_PREFIXES = ("/api", "/openapi.json")

# scrypt cost: N=2**15, r=8, p=1 needs 32 MiB and ~50-100 ms; the parameters are stored in each
# hash, so raising them later keeps old hashes verifiable. Tests lower SCRYPT_N for speed.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
_DKLEN = 32


class NotAuthenticated(Exception):
    """No valid session (pages) or credentials (API). Handled in app.main."""


# --------------------------------------------------------------------------- passwords
def normalise_email(email: str) -> str:
    return email.strip().lower()


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=_DKLEN,
                          maxmem=256 * n * r + 1024 * 1024)


def hash_password(password: str) -> str:
    """'scrypt$N$r$p$<salt b64>$<hash b64>'."""
    if not password:
        raise ValueError("empty password")
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    b64 = lambda b: base64.b64encode(b).decode()
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(digest)}"


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time check. A missing or malformed hash still costs one scrypt run."""
    try:
        scheme, n, r, p, salt_b64, hash_b64 = (stored or "").split("$")
        if scheme != "scrypt":
            raise ValueError(scheme)
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(hash_b64)
        n_i, r_i, p_i = int(n), int(r), int(p)
    except (ValueError, binascii.Error):
        _scrypt(password or "x", b"\0" * 16, SCRYPT_N, SCRYPT_R, SCRYPT_P)
        return False
    return hmac.compare_digest(_scrypt(password or "", salt, n_i, r_i, p_i), expected)


_DUMMY_HASH: str | None = None


def _burn_time(password: str) -> None:
    """Equalise timing for unknown e-mails (no user-enumeration oracle)."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("dummy-password-for-timing")
    verify_password(password, _DUMMY_HASH)


# --------------------------------------------------------------------------- rate limiting
class LoginRateLimiter:
    """Sliding-window limit on *failed* attempts (in memory, per process). A success clears the
    e-mail's windows.

    * ``per_email`` failures for one account **from one client IP** lock that pair, so a stranger
      cannot lock a chosen account out for everyone;
    * ``per_email_global`` failures for one account from any IPs slow distributed guessing;
    * ``per_ip`` failures from one client IP (any accounts) stop spraying from one source.

    The client IP is the real one only when uvicorn trusts the load balancer's X-Forwarded-For
    (``--proxy-headers`` with FORWARDED_ALLOW_IPS set to the ALB subnet; docs/aws-deployment.md).
    At most ``max_keys`` windows are kept: expired ones are pruned first, then the oldest dropped."""

    def __init__(self, per_email: int = 5, per_ip: int = 20, window_s: int = 15 * 60, *,
                 per_email_global: int = 50, max_keys: int = 10_000):
        self.per_email, self.per_ip, self.window_s = per_email, per_ip, window_s
        self.per_email_global, self.max_keys = per_email_global, max_keys
        self._fails: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._fails[key]
        while q and now - q[0] > self.window_s:
            q.popleft()
        if not q:
            del self._fails[key]
            return deque()
        return q

    def _keys(self, email: str, ip: str | None) -> tuple[tuple[str, int], ...]:
        e = normalise_email(email)
        return ((f"p:{e}|{ip or '-'}", self.per_email), (f"e:{e}", self.per_email_global),
                (f"i:{ip or '-'}", self.per_ip))

    def retry_after(self, email: str, ip: str | None) -> int:
        """Seconds until another attempt is allowed (0 = allowed now)."""
        now = time.monotonic()
        waits = []
        with self._lock:
            for key, limit in self._keys(email, ip):
                if key not in self._fails:
                    continue
                q = self._prune(key, now)
                if len(q) >= limit:
                    waits.append(int(self.window_s - (now - q[0])) + 1)
        return max(waits, default=0)

    def failed(self, email: str, ip: str | None) -> None:
        now = time.monotonic()
        with self._lock:
            for key, _ in self._keys(email, ip):
                self._fails[key].append(now)
            if len(self._fails) > self.max_keys:
                self._shrink(now)

    def _shrink(self, now: float) -> None:
        for key in list(self._fails):
            self._prune(key, now)
        overflow = len(self._fails) - self.max_keys
        if overflow > 0:
            for key in sorted(self._fails, key=lambda k: self._fails[k][-1])[:overflow]:
                del self._fails[key]

    def succeeded(self, email: str, ip: str | None = None) -> None:
        e = normalise_email(email)
        with self._lock:
            self._fails.pop(f"e:{e}", None)
            for key in [k for k in self._fails if k.startswith(f"p:{e}|")]:
                if ip is None or key == f"p:{e}|{ip}":
                    del self._fails[key]

    def reset(self) -> None:
        with self._lock:
            self._fails.clear()

    def __len__(self) -> int:
        return len(self._fails)


login_limiter = LoginRateLimiter()


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def authenticate(db: Session, email: str, password: str) -> User | None:
    """The active user with this e-mail and password, else None. Does not touch the rate limiter."""
    user = db.scalar(select(User).where(User.email == normalise_email(email)))
    if user is None or not user.password_hash:
        _burn_time(password)
        return None
    if not verify_password(password, user.password_hash) or not user.is_active:
        return None
    return user


def email_fingerprint(email: str) -> str:
    """Short keyed hash of an e-mail for audit rows (failed logins) — never the address itself."""
    key = get_settings().derived_key("audit-email").encode()
    return hmac.new(key, normalise_email(email).encode(), hashlib.sha256).hexdigest()[:16]


# --------------------------------------------------------------------------- sessions
def _now() -> datetime:
    return datetime.now(tz=UTC)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(db: Session, request: Request, user: User, auth_method: str = "password") -> UserSession:
    """Create a fresh server-side session (the id rotates on every login) and set the cookie."""
    settings = get_settings()
    token = secrets.token_urlsafe(32)
    now = _now()
    row = UserSession(
        id=_token_hash(token), user=user, auth_method=auth_method, created_at=now, last_seen_at=now,
        expires_at=now + timedelta(hours=settings.session_max_hours), ip=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:255] or None,
    )
    db.add(row)
    user.last_login_at = now
    request.session.clear()
    request.session[SESSION_KEY] = token
    return row


def end_session(db: Session, request: Request) -> None:
    token = request.session.get(SESSION_KEY) if "session" in request.scope else None
    if token:
        row = db.get(UserSession, _token_hash(token))
        if row and row.revoked_at is None:
            row.revoked_at = _now()
    if "session" in request.scope:
        request.session.clear()


def revoke_all_sessions(db: Session, user: User) -> int:
    """Sign out everywhere. Returns the number of sessions revoked (caller commits)."""
    n = 0
    for row in user.sessions:
        if row.revoked_at is None:
            row.revoked_at = _now()
            n += 1
    return n


def session_user(request: Request, db: Session) -> User | None:
    if "session" not in request.scope:
        return None
    token = request.session.get(SESSION_KEY)
    if not token or not isinstance(token, str):
        return None
    row = db.get(UserSession, _token_hash(token))
    now = _now()
    idle = timedelta(minutes=get_settings().session_idle_minutes)
    if row is None or row.revoked_at or now >= row.expires_at or now - row.last_seen_at > idle:
        request.session.clear()
        return None
    user = row.user
    if not user.is_active:
        return None
    if now - row.last_seen_at > timedelta(seconds=60):  # one write per minute, not per request
        row.last_seen_at = now
        db.commit()
    request.state.user_session = row
    return user


def basic_user(request: Request, db: Session) -> User | None:
    """HTTP Basic against `users` (API only). Rate-limited like the login form."""
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic" or not value:
        return None
    try:
        email, _, password = base64.b64decode(value.strip()).decode("utf-8").partition(":")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    ip = client_ip(request)
    if login_limiter.retry_after(email, ip):
        return None
    user = authenticate(db, email, password)
    if user is None:
        login_limiter.failed(email, ip)
        return None
    login_limiter.succeeded(email, ip)
    return user


def is_api_path(path: str) -> bool:
    return path.startswith(API_PREFIXES)


def optional_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    """The signed-in user or None (session; HTTP Basic too on /api paths)."""
    cached = getattr(request.state, "user", None)
    if cached is not None:
        return cached
    user = session_user(request, db)
    if user is None and is_api_path(request.url.path):
        user = basic_user(request, db)
    request.state.user = user
    return user


def require_user(request: Request, user: User | None = Depends(optional_user)) -> User:
    """Route dependency: any signed-in, active user."""
    if user is None:
        raise NotAuthenticated()
    return user


def require_system_admin(user: User = Depends(require_user)) -> User:
    if not user.is_system_admin:
        raise HTTPException(403, "system administrators only")
    return user
