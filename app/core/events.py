"""Case event hook. Feature code reports what happened; the notifications layer decides who hears.

    emit(db, case, WALLET_MOVEMENT, usd=Decimal("1234.50"), title="0x2501…57e3 moved 1.2 ETH",
         body="…", link=f"/cases/{case.id}?tab=fund_flow", severity="high")

* `title` / `body` carry **no PII** (docs/data-handling.md §1: case ref, event type, amounts and
  short addresses only). They may be delivered to e-mail / Slack.
* `link` is app-relative (`/cases/{id}?tab=…`), never an absolute URL with secrets in it.
* `severity`: info | warning | high | critical.
* `usd`: the amount the event is about (rules filter on min_usd / min_pct_of_loss).
* `payload`: ids only (e.g. {"stop_order_id": 7}) for delivery workers.

`emit` validates its arguments and hands over to `app.domain.notify.dispatch`, which picks the
case's rule for the event (case row → global row → built-in default), applies its thresholds
(min_usd OR min_pct_of_loss), scrubs PII from title/body, stores one `notifications` row and
delivers it: in-app always, e-mail when SMTP_* is configured, Slack when SLACK_WEBHOOK_URL is set
(otherwise the delivery log says "not_configured"). It returns None when the rule suppresses the
event. With commit=False the row is only flushed (external channels are still attempted).
"""

from __future__ import annotations

from decimal import Decimal

from sqlalchemy.orm import Session

from app.db.models import Case, Notification

WALLET_MOVEMENT = "wallet_movement"  # a watched wallet moved funds
VASP_DEPOSIT = "vasp_deposit"  # tainted funds reached a VASP deposit address (freeze window open)
SWEEP_IMMINENT = "sweep_imminent"  # a deposit address is about to be swept to the omnibus
STOP_ORDER_STATUS = "stop_order_status"  # a stop order changed status (sent, acknowledged, frozen, …)
CORRESPONDENCE_IN = "correspondence_in"  # a reply / message was received
CORRESPONDENCE_OUT = "correspondence_out"  # a message / letter was sent
RESPONSE_OVERDUE = "response_overdue"  # a recipient has not answered by response_due_at
EVIDENCE_ADDED = "evidence_added"
TRACE_COMPLETED = "trace_completed"
AI_SUMMARY = "ai_summary"  # the assistant produced a case status summary
EVIDENCE_INTEGRITY = "evidence_integrity"  # an evidence item failed its re-hash (mismatch or original missing)
MAIL_PREPARED = "mail_prepared"  # an investigator prepared an e-mail: a case admin must press Send (30 min preview)
FREEZE_DETECTED = "freeze_detected"  # an issuer (Tether / Circle) blacklisted a case wallet on-chain (app.freeze)
FREEZE_LIFTED = "freeze_lifted"  # an issuer removed a case wallet from its blacklist: the funds can move again
BLOCK_STATUS_CHANGED = "block_status_changed"  # a block request's status changed (app.blocks: confirmed / suggested)
PROVIDER_DEADLINE = "provider_deadline"  # a provider's / the playbook's clock on a block request falls due (MEXC 48h)
HOLD_EXPIRING = "hold_expiring"  # a hold a person confirmed lapses soon (KuCoin's 30-day auto-lift)

EVENT_TYPES: tuple[str, ...] = (
    WALLET_MOVEMENT, VASP_DEPOSIT, SWEEP_IMMINENT, STOP_ORDER_STATUS, CORRESPONDENCE_IN, CORRESPONDENCE_OUT,
    RESPONSE_OVERDUE, EVIDENCE_ADDED, TRACE_COMPLETED, AI_SUMMARY, EVIDENCE_INTEGRITY, MAIL_PREPARED,
    FREEZE_DETECTED, FREEZE_LIFTED, BLOCK_STATUS_CHANGED, PROVIDER_DEADLINE, HOLD_EXPIRING,
)
SEVERITIES = ("info", "warning", "high", "critical")


def emit(db: Session, case: Case | None, event_type: str, *, usd: Decimal | float | str | None = None, title: str,
         body: str | None, link: str | None, severity: str = "info", payload: dict | None = None,
         commit: bool = True) -> Notification | None:
    """Record a case event. Returns the notification row (or None when rules suppress it)."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event type {event_type!r}")
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity {severity!r}")
    from app.domain import notify  # late import: notify imports the constants above

    return notify.dispatch(db, case, event_type, usd=usd, title=title, body=body, link=link, severity=severity,
                           payload=payload, commit=commit)
