"""Seed the database from a fixture and run an initial trace.

    python -m scripts.seed_case                      # default: AEGIS_FIXTURE_PATH or data/fixtures/demo_case.json
    python -m scripts.seed_case --fixture PATH       # e.g. a real case fixture kept outside the repo

The same fixture backs the offline provider used for the initial trace, so
`--fixture` also sets AEGIS_FIXTURE_PATH for this process.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def main(fixture: str | None = None) -> None:
    if fixture:
        # make the offline provider read the same file as the seeder
        os.environ["AEGIS_FIXTURE_PATH"] = str(Path(fixture).expanduser().resolve())
        from app.core.config import get_settings
        from app.providers.registry import get_provider

        get_settings.cache_clear()
        get_provider.cache_clear()

    from app.core.logging import configure_logging
    from app.db.models import Base
    from app.db.session import SessionLocal, engine
    from app.fixture_sections import SeedReport
    from app.providers.fixture import resolve_fixture_path
    from app.services import latest_run, run_trace, seed_from_fixture

    configure_logging()
    Base.metadata.create_all(engine)  # no-op when Alembic already ran
    path = resolve_fixture_path(None)
    print(f"Fixture: {path}")
    with SessionLocal() as db:
        report = SeedReport()
        case = seed_from_fixture(db, path, report=report)
        print(f"Seeded case {case.reference}: {case.title}")
        for section, n in report.counts.items():
            print(f"  {section}: {n}")
        for note in report.notes:
            print(f"  note: {note}")
        if report.generated_passwords:
            print("Generated passwords for new team members (shown once; set password_env in the fixture to choose):")
            for email, password in report.generated_passwords:
                print(f"  {email}  {password}")
        else:
            from sqlalchemy import func, select

            from app.db.models import User

            if not db.scalar(select(func.count()).select_from(User)):
                print("No user accounts yet: python -m scripts.create_user you@example.com \"Your Name\" --system-admin")
        if latest_run(db, case) is None:
            from app.tracing.diff import emit_trace_completed

            run = run_trace(db, case, provider_mode="fixture", label="initial seed trace")
            emit_trace_completed(db, case, run)  # the case feed starts with the first trace
            print(f"Initial trace run #{run.id}: {run.status.value} — {run.stats}")
        from app.evidence_intel.service import seed_pass

        try:
            ev_counts = seed_pass(db, case)  # verified and read by the rules (no AI): nothing moved or confirmed
            db.commit()
            print(f"Evidence: {ev_counts['verified']} verified, {ev_counts['read']} read by the rules")
        except Exception as exc:  # noqa: BLE001 - advisory: the seed stands; "Verify all" / "Re-read all" do it later
            db.rollback()
            print(f"  note: evidence not verified / read at seed time ({type(exc).__name__})")


def _cli() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fixture", metavar="PATH", help="fixture JSON (default: AEGIS_FIXTURE_PATH or the demo case)")
    args = ap.parse_args()
    main(args.fixture)


if __name__ == "__main__":
    _cli()
