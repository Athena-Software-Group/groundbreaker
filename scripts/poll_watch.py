"""Poll every open case's watch list once and report movements as events. Intended for a scheduler
(EventBridge → ECS task / cron); `python -m scripts.run_scheduler` runs it in a loop.

    python -m scripts.poll_watch [--provider fixture|live]

Each new alert becomes a wallet_movement or vasp_deposit event through app.core.events.emit
(app.domain.notify.poll_and_notify), so the case's notification rules decide who hears.
Output carries case references, counts and short addresses only.
"""

from __future__ import annotations

import argparse

from sqlalchemy import select

from app.core.logging import configure_logging
from app.db.models import Case
from app.db.session import SessionLocal
from app.domain.notify import poll_and_notify


def poll_all(provider_mode: str | None = None, *, verbose: bool = True) -> tuple[int, int]:
    """One pass over the open cases. Returns (alerts, notifications)."""
    n_alerts = n_notes = 0
    with SessionLocal() as db:
        for case in db.scalars(select(Case).where(Case.status == "open")).all():
            alerts, notes = poll_and_notify(db, case, provider_mode)
            n_alerts += len(alerts)
            n_notes += len(notes)
            if verbose:
                print(f"{case.reference}: {len(alerts)} new alert(s), {len(notes)} notification(s)")
                for n in notes:
                    print(f"  [{n.severity}] {n.event_type}: {n.title}")
    return n_alerts, n_notes


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--provider", choices=["fixture", "live"], default=None, help="default: PROVIDER_MODE")
    args = ap.parse_args(argv)
    configure_logging()
    poll_all(args.provider)


if __name__ == "__main__":
    main()
