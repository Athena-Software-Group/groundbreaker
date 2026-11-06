"""Background loop: poll the watch lists, check for overdue responses and on-chain freezes every N minutes.

    python -m scripts.run_scheduler                 # every 5 minutes until Ctrl+C / SIGTERM
    python -m scripts.run_scheduler --interval 2 --provider live
    python -m scripts.run_scheduler --once          # one pass (cron / EventBridge)

Each pass runs
* the watch poller (scripts.poll_watch.poll_all → app.domain.notify.poll_and_notify), which emits
  wallet_movement / vasp_deposit events; and
* `check_overdue` from app.domain.correspondence when that module exists (the correspondence
  feature owns it), which emits response_overdue events. It is called as check_overdue(db, case)
  per open case when it takes a `case` argument (with default_days = the case's response_overdue
  rule, app.domain.notify.overdue_days, when it accepts that keyword), otherwise once as
  check_overdue(db). check_overdue also runs the block requests' clocks (app.blocks.status.check_clocks: a
  provider's submit-by, a playbook clock such as MEXC's 48 hours, a confirmed hold's expiry), rules only, which
  emit provider_deadline / hold_expiring.
* the mail pass (`mail_pass`): one mailbox sync (app.mail.ingest.sync_mailbox, trigger
  "scheduler"; graph: Inbox and Sent Items) when AEGIS_MAIL_INBOUND is on, AEGIS_MAIL_TRANSPORT is
  file or graph and the last sync started at least AEGIS_MAIL_SYNC_MINUTES (15) ago, then the
  e-mail desk's housekeeping when that module is installed: expire stale prepared e-mails and
  reconcile sends whose outcome is unknown (app.domain.mail_send.expire_prepared /
  reconcile_unknown_all). A failure in the mail pass sets `mail_error` (exit code 1 with --once).
* the on-chain freeze pass (`freeze_pass`, app.freeze.service.run_due): issuer blacklist checks for
  every open case whose "On-chain freeze checks" setting is on and whose last run is older than
  AEGIS_FREEZE_CHECK_MINUTES (360). Cases with the setting off send nothing. A failure of the pass, or
  of one case's run (`failed_cases`), sets `freeze_error` (exit code 1 with --once); readings that failed
  over HTTP (`errors`) are retried on the next run and do not.

* the native watch (`native_pass`, app.freeze.native.run_all): every pass, the ETH balance and transaction count of the
  Ethereum wallets on the freeze watch of a case with the checks on; wallet_movement when ETH leaves.

A failing step is logged and the loop carries on (each step in its own try). No APScheduler
needed: one process, one loop.
"""

from __future__ import annotations

import argparse
import inspect
import logging
import os
import signal
import threading
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core.logging import configure_logging
from app.db.models import Case
from app.db.session import SessionLocal
from app.domain.notify import overdue_days

log = logging.getLogger("app.scheduler")


def _load_check_overdue():
    try:
        from app.domain.correspondence import check_overdue  # type: ignore[import-not-found]
    except ImportError:
        return None
    return check_overdue


def check_overdue_all() -> int | None:
    """Run the correspondence feature's overdue check. None when the feature is not installed."""
    fn = _load_check_overdue()
    if fn is None:
        return None
    params = inspect.signature(fn).parameters
    per_case = "case" in params
    total = 0
    with SessionLocal() as db:
        if per_case:
            for case in db.scalars(select(Case).where(Case.status == "open")).all():
                try:
                    kw = {"default_days": overdue_days(db, case)} if "default_days" in params else {}
                    out = fn(db, case, **kw)
                except Exception:
                    db.rollback()
                    log.exception("check_overdue failed for case id %s", case.id)
                    continue
                total += len(out) if hasattr(out, "__len__") else int(out or 0)
        else:
            out = fn(db)
            total += len(out) if hasattr(out, "__len__") else int(out or 0)
    return total


def _load_mail_send():
    try:
        from app.domain import mail_send  # type: ignore[attr-defined]
    except ImportError:
        return None
    return mail_send


MAIL_SYNC_MINUTES = 15


def mail_sync_minutes() -> float:
    """AEGIS_MAIL_SYNC_MINUTES: how often the scheduler reads the mailbox (default 15; at least 1)."""
    try:
        return max(1.0, float(os.environ.get("AEGIS_MAIL_SYNC_MINUTES") or MAIL_SYNC_MINUTES))
    except ValueError:
        return float(MAIL_SYNC_MINUTES)


def mail_sync_due(db, settings, now: datetime | None = None) -> bool:
    """The mailbox's last sync (any trigger) started AEGIS_MAIL_SYNC_MINUTES ago or more (or never)."""
    from app.db.models import MailSyncState

    state = db.get(MailSyncState, settings.mail_from) if settings.mail_from else None
    last = state.last_started_at if state is not None else None
    if last is None:
        return True
    last = last if last.tzinfo else last.replace(tzinfo=UTC)
    return (now or datetime.now(tz=UTC)) - last >= timedelta(minutes=mail_sync_minutes())


def mail_pass() -> dict | None:
    """One mailbox sync (when inbound mail is on and a sync is due) plus the e-mail desk's housekeeping
    (when the desk is installed). None when there is nothing to do."""
    from app.mail.config import mail_settings

    settings = mail_settings()
    inbound = settings.aegis_mail_inbound and settings.aegis_mail_transport in ("file", "graph")
    send = _load_mail_send()
    if not inbound and send is None:
        return None
    out: dict = {}
    with SessionLocal() as db:
        if inbound and not mail_sync_due(db, settings):
            out["mail_sync"] = "not_due"
            inbound = False
        if inbound:
            from app.mail.ingest import sync_mailbox

            report = sync_mailbox(db, trigger="scheduler", settings=settings)
            out.update(report.counts())
            if report.busy:
                out["busy"] = True
            if report.disabled:
                out["disabled"] = report.disabled
            if report.error:
                out["sync_error"] = True
        for name in ("expire_prepared", "reconcile_unknown_all"):
            fn = getattr(send, name, None) if send is not None else None
            if fn is None:
                continue
            try:
                out[name] = fn(db)
            except Exception:
                db.rollback()
                log.exception("mail %s failed", name)
                out[f"{name}_error"] = True
    return out


def freeze_pass() -> dict:
    """On-chain freeze checks of the enabled cases that are due (app.freeze.service.run_due)."""
    from app.freeze.service import run_due

    with SessionLocal() as db:
        return run_due(db)


def native_pass() -> dict:
    """ETH balance reads of the freeze-watch wallets (app.freeze.native.run_all), every pass."""
    from app.freeze.native import run_all

    with SessionLocal() as db:
        return run_all(db)


def owner_pass() -> dict:
    """Automatic owner lookups of the open cases that are due (app.attribution.service.due_cases)."""
    from app.attribution.service import auto_lookups, due_cases

    out = {"cases": 0, "looked_up": 0}
    with SessionLocal() as db:
        for case in due_cases(db):
            rep = auto_lookups(db, case, trigger="scheduler")
            if rep is not None:
                out["cases"] += 1
                out["looked_up"] += rep.looked_up
    return out


def run_once(provider_mode: str | None = None) -> dict:
    from scripts.poll_watch import poll_all

    result: dict = {}
    t0 = time.monotonic()
    try:
        result["alerts"], result["notifications"] = poll_all(provider_mode, verbose=False)
    except Exception:
        log.exception("watch poll failed")
        result["poll_error"] = True
    try:
        result["overdue"] = check_overdue_all()
    except Exception:
        log.exception("overdue check failed")
        result["overdue_error"] = True
    try:
        result["mail"] = mail_pass()
    except Exception:
        log.exception("mail pass failed")
        result["mail"] = None
        result["mail_error"] = True
    try:
        result["freeze"] = freeze_pass()
        if (result["freeze"] or {}).get("failed_cases"):
            result["freeze_error"] = True  # a case's run raised; failed readings (HTTP errors) alone do not count
    except Exception:
        log.exception("freeze pass failed")
        result["freeze"] = None
        result["freeze_error"] = True
    try:
        result["native"] = native_pass()
    except Exception:
        log.exception("native watch failed")
        result["native"] = None
    try:
        result["owners"] = owner_pass()
    except Exception:
        log.exception("owner pass failed")
        result["owners"] = None
    result["seconds"] = round(time.monotonic() - t0, 2)
    log.info("scheduler pass: %s", result)
    return result


def run_forever(interval_minutes: float, provider_mode: str | None = None,
                stop: threading.Event | None = None, max_passes: int | None = None) -> int:
    """Run passes every `interval_minutes` until `stop` is set (SIGINT/SIGTERM). Returns the pass count."""
    stop = stop or threading.Event()
    passes = 0
    while not stop.is_set():
        run_once(provider_mode)
        passes += 1
        if max_passes is not None and passes >= max_passes:
            break
        stop.wait(max(interval_minutes, 0.0) * 60)
    return passes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--interval", type=float, default=5.0, metavar="MINUTES", help="minutes between passes (5)")
    ap.add_argument("--once", action="store_true", help="run one pass and exit")
    ap.add_argument("--provider", choices=["fixture", "live"], default=None, help="default: PROVIDER_MODE")
    args = ap.parse_args(argv)
    configure_logging()
    if args.once:
        r = run_once(args.provider)
        print(r)
        return 1 if r.get("poll_error") or r.get("overdue_error") or r.get("mail_error") or r.get("freeze_error") else 0
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    log.info("scheduler started: every %s minute(s)", args.interval)
    run_forever(args.interval, args.provider, stop)
    log.info("scheduler stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
