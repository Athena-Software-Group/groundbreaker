"""Read the case mailbox once and print the counts (no addresses, subjects or bodies).

    python -m scripts.mail_sync            # needs AEGIS_MAIL_INBOUND=on and AEGIS_MAIL_TRANSPORT=file|graph

Replies to letters Aegis sent are filed on their authority's timeline; anything else waits in
/admin/mail/unassigned or the case's "Mail to review" page. `python -m scripts.run_scheduler`
runs the same sync on every pass.
"""

from __future__ import annotations

import argparse

from app.core.logging import configure_logging
from app.db.session import SessionLocal
from app.mail.config import mail_settings
from app.mail.ingest import sync_mailbox


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.parse_args(argv)
    configure_logging()
    settings = mail_settings()
    if not settings.aegis_mail_inbound:
        print("inbound mail is off: set AEGIS_MAIL_INBOUND=on")
        return 2
    with SessionLocal() as db:
        report = sync_mailbox(db, trigger="cli", settings=settings)
    if report.disabled:
        print(f"not run: {report.disabled}")
        return 2
    if report.busy:
        print("not run: another sync holds the lease")
        return 1
    if report.too_soon:
        print("not run: the mailbox was checked less than a minute ago; try again shortly")
        return 1
    print(" ".join(f"{k}={v}" for k, v in report.counts().items()))
    if report.error:
        print(f"error: {report.error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
