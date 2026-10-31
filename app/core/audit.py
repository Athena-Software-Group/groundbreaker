"""Append-only audit log (docs/identity-spec.md §8).

    audit(db, actor, action, case=None, obj=None, **detail)

Call it from every mutating route (and for denied access), after the change itself:

    order = services.mark_stop_order(db, order, status)
    audit(db, access, "UPDATE", access.case, order, status=status.value)

* `actor`: a User, a CaseAccess, a user id, or None (anonymous, e.g. a failed login).
* `case`: a Case, a CaseAccess, a case id, or None.
* `obj`: an ORM object (its table name and primary key are recorded), a `(type, id)` tuple, or None.
* `outcome`: "allowed" (default) or "denied".
* `**detail`: ids, field names, counts, enum values. **Never values that carry PII** (names,
  e-mails, letter bodies, free text). Keys that look like such values are dropped
  (`DROPPED_KEYS`), strings are cut to 200 characters.

`audit()` adds the row and **commits the session** (so the event survives even when the caller
forgets), and chains it to the previous row (`prev_hash` / `row_hash`). IP, user agent and the
request id come from the request context set by `request_context_middleware`.

Action names follow the spec: LOGIN, LOGIN_FAILED, LOGOUT, CREATE, UPDATE, DELETE, EXPORT, SHARE,
RUN_TRACE, LETTER_SENT, ROLE_GRANT, ROLE_REVOKE, ACCESS_DENIED, … (constants below; any upper-case
string is accepted).
"""

from __future__ import annotations

import enum
import hashlib
import json
import secrets
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from fastapi import Request
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.db.models import AuditEvent, Case, User

LOGIN = "LOGIN"
LOGIN_FAILED = "LOGIN_FAILED"
LOGOUT = "LOGOUT"
CREATE = "CREATE"
UPDATE = "UPDATE"
DELETE = "DELETE"
EXPORT = "EXPORT"
DOWNLOAD = "DOWNLOAD"
SHARE = "SHARE"
RUN_TRACE = "RUN_TRACE"
LETTER_SENT = "LETTER_SENT"
ROLE_GRANT = "ROLE_GRANT"
ROLE_REVOKE = "ROLE_REVOKE"
ACCESS_DENIED = "ACCESS_DENIED"
AI_QUERY = "AI_QUERY"
LIVE_PROVIDER_QUERY = "LIVE_PROVIDER_QUERY"

DROPPED_KEYS = {"password", "token", "secret", "email", "name", "body", "body_markdown", "text", "content",
                "phone", "address_line", "notes", "message"}
_MAX_STR = 200


@dataclass
class RequestContext:
    ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None


_request_ctx: ContextVar[RequestContext | None] = ContextVar("aegis_request_ctx", default=None)


async def request_context_middleware(request: Request, call_next):
    ctx = RequestContext(
        ip=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:255] or None,
        request_id=request.headers.get("x-request-id", "")[:64] or secrets.token_hex(8),
    )
    token = _request_ctx.set(ctx)
    try:
        return await call_next(request)
    finally:
        _request_ctx.reset(token)


def _clean(value: Any) -> Any:
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, str):
        return value[:_MAX_STR]
    if isinstance(value, dict):
        return {str(k): _clean(v) for k, v in value.items() if str(k).lower() not in DROPPED_KEYS}
    if isinstance(value, (list, tuple, set)):
        return [_clean(v) for v in value][:100]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:_MAX_STR]


def _actor_id(actor: Any) -> int | None:
    if actor is None or isinstance(actor, int):
        return actor
    if isinstance(actor, User):
        return actor.id
    user = getattr(actor, "user", None)  # CaseAccess
    return user.id if user is not None else None


def _case_id(case: Any) -> int | None:
    if case is None or isinstance(case, int):
        return case
    if isinstance(case, Case):
        return case.id
    inner = getattr(case, "case", None)  # CaseAccess
    return inner.id if inner is not None else None


def _obj_ref(obj: Any) -> tuple[str | None, str | None]:
    if obj is None:
        return None, None
    if isinstance(obj, tuple):
        kind, oid = obj
        return str(kind), None if oid is None else str(oid)
    kind = getattr(obj, "__tablename__", type(obj).__name__)
    oid = getattr(obj, "id", None)
    return kind, None if oid is None else str(oid)


def _row_hash(prev: str | None, ev: AuditEvent) -> str:
    material = json.dumps(
        [prev, ev.ts.isoformat(), ev.actor_user_id, ev.case_id, ev.action, ev.object_type, ev.object_id,
         ev.outcome, ev.detail], sort_keys=True, default=str,
    )
    return hashlib.sha256(material.encode()).hexdigest()


def audit(db: Session, actor: Any, action: str, case: Any = None, obj: Any = None, *, outcome: str = "allowed",
          **detail: Any) -> AuditEvent:
    """Append one audit event and commit. See the module docstring for the argument rules."""
    ctx = _request_ctx.get() or RequestContext()
    object_type, object_id = _obj_ref(obj)
    ev = AuditEvent(
        ts=datetime.now(tz=UTC), actor_user_id=_actor_id(actor), case_id=_case_id(case), action=action[:64],
        object_type=object_type, object_id=object_id, outcome=outcome, detail=_clean(detail),
        ip=ctx.ip, user_agent=ctx.user_agent, request_id=ctx.request_id,
    )
    _lock_chain_head(db)  # held until the commit below: one appender at a time, so the chain never forks
    prev = db.scalar(select(AuditEvent.row_hash).order_by(AuditEvent.id.desc()).limit(1))
    ev.prev_hash = prev
    ev.row_hash = _row_hash(prev, ev)
    db.add(ev)
    db.commit()
    return ev


_CHAIN_LOCK_KEY = 0x4145_4749_5341_5544  # pg advisory lock id ("AEGISAUD")


def _lock_chain_head(db: Session) -> None:
    """Serialise appends to the hash chain for the rest of this transaction.

    Reading the previous row's hash and inserting the new row must not interleave with another
    request doing the same, or two rows chain to the same predecessor and verify_chain reports the
    log broken from then on. Postgres: a transaction-scoped advisory lock (released by the commit).
    SQLite: take the database write lock (BEGIN IMMEDIATE) before reading, unless this transaction
    already holds it because the caller wrote something."""
    bind = db.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _CHAIN_LOCK_KEY})
    elif dialect == "sqlite":
        raw = db.connection().connection.driver_connection
        if raw is not None and not raw.in_transaction:
            raw.execute("BEGIN IMMEDIATE")


def verify_chain(db: Session) -> int | None:
    """Id of the first audit row whose hash chain is broken, or None when the chain is intact."""
    prev = None
    for ev in db.scalars(select(AuditEvent).order_by(AuditEvent.id)):
        if ev.prev_hash != prev or ev.row_hash != _row_hash(prev, ev):
            return ev.id
        prev = ev.row_hash
    return None
