"""Give every case without a sender profile the default one (app.domain.sender.defaults).

    python -m scripts.ensure_sender_profiles                    # every case that has none
    python -m scripts.ensure_sender_profiles --case DEMO-2026-001
    python -m scripts.ensure_sender_profiles --dry-run          # list what would be created, write nothing
    python -m scripts.ensure_sender_profiles --cc-client-on-file   # also Cc the client e-mail on file by default

The default profile: AEGIS_SIGNATORY_NAME writing as AEGIS_ORG_NAME on behalf of the case's client /
victim ("<entity> (<name>)" or the name), under the victim's Letter of Authorisation, the case mailbox
(AEGIS_MAIL_FROM) as contact, and no default Cc unless --cc-client-on-file is given (then the client's contact e-mail
on file, case.facts["victim_contact"]["email"]: a case admin's explicit choice, never silent). An existing profile is never touched; a case naming no client / victim is skipped. Each profile created
is audited (CREATE sender_profiles, source "ensure_script", field names only). Safe to run again: a second run
creates nothing.
"""

from __future__ import annotations

import argparse
import sys


def _client_email(case) -> str | None:
    """The client's contact e-mail on file, when it is a valid bare address (else None: no default Cc)."""
    from app.domain import sender

    raw = ((case.facts or {}).get("victim_contact") or {}).get("email")
    try:
        return sender.clean_client_email(str(raw)) if raw else None
    except sender.SenderError:
        return None


def _mail_settings():
    try:
        from app.mail.config import mail_settings

        return mail_settings()
    except Exception:  # noqa: BLE001 - without the mail package the contact falls back to AEGIS_MAIL_FROM
        return None


def ensure(db, *, reference: str | None = None, dry_run: bool = False, cc_client: bool = False,
           out=print) -> dict[str, int]:
    """Create the missing default profiles (all cases, or the one `reference` names). Returns the counts
    {"created", "existing", "skipped"}; raises LookupError for an unknown reference."""
    from sqlalchemy import func, select

    from app.db.models import Case
    from app.domain import sender

    query = select(Case).order_by(Case.id)
    if reference:
        query = query.where(func.lower(Case.reference) == reference.strip().lower())
    cases = db.scalars(query).all()
    if reference and not cases:
        raise LookupError(f"no case with reference {reference!r}")
    settings = _mail_settings()
    counts = {"created": 0, "existing": 0, "skipped": 0}
    for case in cases:
        if sender.get_profile(db, case) is not None:
            counts["existing"] += 1
            continue
        email = _client_email(case) if cc_client else None
        if not sender.client_label(case):
            counts["skipped"] += 1
            out(f"{case.reference}: skipped (the case names no client / victim)")
            continue
        if dry_run:
            counts["created"] += 1
            out(f"{case.reference}: would create the default sender profile"
                + (" (default Cc: the client's e-mail on file)" if email else ""))
            continue
        row = sender.create_default_profile(db, case, client_email=email, settings=settings)
        sender.audit_default_profile(db, None, case, row, source="ensure_script")  # commits
        counts["created"] += 1
        out(f"{case.reference}: created the default sender profile"
            + (" (default Cc: the client's e-mail on file)" if email else ""))
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--case", metavar="REFERENCE", help="only this case")
    ap.add_argument("--dry-run", action="store_true", help="list what would be created; write nothing")
    ap.add_argument("--cc-client-on-file", action="store_true",
                    help="default Cc = the client's e-mail on file (otherwise none: add it on the sender-profile page)")
    args = ap.parse_args(argv)

    from app.db.session import SessionLocal

    with SessionLocal() as db:
        try:
            counts = ensure(db, reference=args.case, dry_run=args.dry_run, cc_client=args.cc_client_on_file)
        except LookupError as e:
            sys.exit(str(e))
        if args.dry_run:
            db.rollback()
    verb = "would create" if args.dry_run else "created"
    print(f"{verb} {counts['created']}; already had one: {counts['existing']}; skipped: {counts['skipped']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
