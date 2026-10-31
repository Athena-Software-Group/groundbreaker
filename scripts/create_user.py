"""Create (or update) a user account, optionally adding it to a case.

    python -m scripts.create_user you@example.com "Your Name" --system-admin
    python -m scripts.create_user analyst@example.com "An Analyst" --case DEMO-2026-001 --role investigator
    python -m scripts.create_user lead@example.com "Case Lead" --can-create-cases
    python -m scripts.create_user liaison@le.example "LE Liaison" --case DEMO-2026-001 --role external --expires 2026-12-31
    AEGIS_NEW_PASSWORD=… python -m scripts.create_user a@example.com "A" --password-env AEGIS_NEW_PASSWORD

An external membership is time-boxed: it expires after 30 days unless --expires gives a date
(at most 90 days ahead, like the Team tab).

The password is read with getpass (asked twice) unless --password-env names an environment
variable holding it. It is never accepted as a command-line argument (shell history, ps).
An existing account is left alone unless --update is given.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import UTC, date, datetime, time, timedelta

MIN_PASSWORD = 12
EXTERNAL_DEFAULT_DAYS = 30  # app.web.routes_team.EXTERNAL_DEFAULT_DAYS
EXTERNAL_MAX_DAYS = 90  # app.web.routes_team.EXTERNAL_MAX_DAYS


def _expiry(role: str, value: str | None, now: datetime | None = None) -> datetime | None:
    """The membership expiry: external members only, default 30 days, end of the given day otherwise."""
    now = now or datetime.now(tz=UTC)
    if role != "external":
        if value:
            sys.exit("--expires applies to --role external only")
        return None
    if not value:
        return now + timedelta(days=EXTERNAL_DEFAULT_DAYS)
    try:
        when = datetime.combine(date.fromisoformat(value), time(23, 59, 59), tzinfo=UTC)
    except ValueError:
        sys.exit(f"--expires: not a date (YYYY-MM-DD): {value!r}")
    if when <= now:
        sys.exit("--expires must be in the future")
    if when > now + timedelta(days=EXTERNAL_MAX_DAYS, hours=24):
        sys.exit(f"--expires: external access is time-boxed to at most {EXTERNAL_MAX_DAYS} days")
    return when


def _read_password(env: str | None) -> str:
    if env:
        pw = os.environ.get(env, "")
        if not pw:
            sys.exit(f"--password-env {env}: the variable is unset or empty")
        return pw
    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Repeat password: "):
        sys.exit("passwords do not match")
    return pw


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("email")
    ap.add_argument("name", help="display name")
    ap.add_argument("--system-admin", action="store_true", help="sees and administers every case")
    ap.add_argument("--can-create-cases", action="store_true",
                    help="may open new cases (system admins always may; --update without it removes it)")
    ap.add_argument("--password-env", metavar="VAR", help="read the password from this environment variable")
    ap.add_argument("--update", action="store_true", help="update name / password / admin flag of an existing user")
    ap.add_argument("--case", metavar="REFERENCE", help="also add the user to this case")
    ap.add_argument("--role", default="investigator", choices=["admin", "investigator", "read_only", "external"])
    ap.add_argument("--expires", metavar="YYYY-MM-DD", help="external members: membership end (default 30 days)")
    args = ap.parse_args(argv)
    expires_at = _expiry(args.role, args.expires) if args.case else None

    from sqlalchemy import select

    from app.core.audit import CREATE, ROLE_GRANT, UPDATE, audit
    from app.core.permissions import add_member
    from app.core.security import hash_password, normalise_email
    from app.db.models import Case, User
    from app.db.session import SessionLocal

    email = normalise_email(args.email)
    if "@" not in email:
        sys.exit(f"not an e-mail address: {args.email!r}")
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        if user is not None and not args.update:
            print(f"User {email} already exists (id {user.id}); pass --update to change it.")
        else:
            password = _read_password(args.password_env)
            if len(password) < MIN_PASSWORD:
                sys.exit(f"password must be at least {MIN_PASSWORD} characters")
            created = user is None
            if created:
                user = User(email=email, display_name=args.name)
                db.add(user)
            user.display_name = args.name
            user.password_hash = hash_password(password)
            user.is_system_admin = args.system_admin  # --update without the flag removes system admin
            user.can_create_cases = args.can_create_cases
            user.is_active = True
            db.flush()
            audit(db, None, CREATE if created else UPDATE, None, user, via="create_user",
                  system_admin=user.is_system_admin, can_create_cases=user.can_create_cases)
            print(f"{'Created' if created else 'Updated'} user {email} (id {user.id})"
                  + (" — system admin" if user.is_system_admin else "")
                  + (" — may open cases" if user.can_create_cases and not user.is_system_admin else ""))
        if args.case:
            case = db.scalar(select(Case).where(Case.reference == args.case))
            if case is None:
                sys.exit(f"no case with reference {args.case!r}")
            m = add_member(db, case, user, args.role, expires_at=expires_at)
            audit(db, None, ROLE_GRANT, case, m, role=args.role, via="create_user", expires_at=expires_at)
            print(f"Added {email} to {case.reference} as {args.role}"
                  + (f" until {expires_at:%Y-%m-%d %H:%M} UTC" if expires_at else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
