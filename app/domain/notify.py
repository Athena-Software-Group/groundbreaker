"""Notifications: rules, PII scrubbing, delivery (in-app, e-mail, Slack) and the in-app inbox.

`app.core.events.emit` is the only entry point for feature code; it calls `dispatch` here:

    rule  = effective_rule(db, case, event_type)       # case row → global row (case_id NULL) → DEFAULT_RULES
    match = passes_thresholds(rule, usd, case.loss_usd)  # min_usd OR min_pct_of_loss (either one suffices)
    note  = Notification(title=scrub(title), body=scrub(body), …)
    deliveries: in_app (always) · email (SMTP_* set, else "not_configured") · slack (SLACK_WEBHOOK_URL set)

Rules
* Rows in `notification_rules` win: a case row first, then a global row (case_id NULL), then the
  built-in `DEFAULT_RULES`. `seed_default_rules(db, case)` writes the defaults as case rows (only
  event types the case has no row for), so the rule editor and emit() agree before any edit.
* Thresholds apply only when set. With both set, either one is enough. An event without a USD
  value never passes a threshold (unpriced tokens carry no taint: address-poisoning dust stays quiet).
* VASP deposits and imminent sweeps are always delivered as `critical` (the freeze window is open), and
  so are an on-chain issuer freeze (`freeze_detected`) and its removal (`freeze_lifted`).

Data handling (docs/data-handling.md §1): titles and bodies are scrubbed before they are stored
or sent. E-mail addresses and phone numbers become placeholders; the case's personal and
investigative identifiers (victim, persona, impersonated company, PI firm and staff, complaint
references, LE contacts, domains) are replaced with "[redacted]"; long chain addresses and
hashes are shortened (0x2501da…57e3). Outbound messages carry the case reference, the event, the
amount, short addresses and the app link only. Delivery logs hold channel, status, a recipient
count and an exception class name, never addresses, URLs or message text.

Channel settings come from the environment (or .env): SMTP_HOST, SMTP_PORT (587), SMTP_USERNAME,
SMTP_PASSWORD, SMTP_FROM, SMTP_STARTTLS (true), SMTP_SSL (false); SLACK_WEBHOOK_URL;
APP_BASE_URL (prefix for links in e-mail / Slack; links stay app-relative when unset).
"""

from __future__ import annotations

import logging
import re
import smtplib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from email.message import EmailMessage
from typing import Any

import httpx
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.events import (
    AI_SUMMARY,
    BLOCK_STATUS_CHANGED,
    CORRESPONDENCE_IN,
    CORRESPONDENCE_OUT,
    EVENT_TYPES,
    EVIDENCE_ADDED,
    EVIDENCE_INTEGRITY,
    FREEZE_DETECTED,
    FREEZE_LIFTED,
    HOLD_EXPIRING,
    MAIL_PREPARED,
    PROVIDER_DEADLINE,
    RESPONSE_OVERDUE,
    SEVERITIES,
    STOP_ORDER_STATUS,
    SWEEP_IMMINENT,
    TRACE_COMPLETED,
    VASP_DEPOSIT,
    WALLET_MOVEMENT,
    emit,
)
from app.db.models import (
    Alert,
    Case,
    CaseMember,
    CaseRole,
    EntityCategory,
    Notification,
    NotificationRule,
    Transfer,
    User,
)

log = logging.getLogger("app.notify")

IN_APP, EMAIL, SLACK = "in_app", "email", "slack"
CHANNELS: tuple[str, ...] = (IN_APP, EMAIL, SLACK)
# Externals never receive case notifications (they see only items shared with them).
RECIPIENT_ROLES: tuple[str, ...] = (CaseRole.ADMIN.value, CaseRole.INVESTIGATOR.value, CaseRole.READ_ONLY.value)

EVENT_LABELS: dict[str, str] = {
    WALLET_MOVEMENT: "Wallet movement",
    VASP_DEPOSIT: "VASP deposit",
    SWEEP_IMMINENT: "Sweep imminent",
    STOP_ORDER_STATUS: "Stop-order status",
    CORRESPONDENCE_IN: "Correspondence received",
    CORRESPONDENCE_OUT: "Correspondence sent",
    RESPONSE_OVERDUE: "Response overdue",
    EVIDENCE_ADDED: "Evidence added",
    TRACE_COMPLETED: "Trace completed",
    AI_SUMMARY: "AI status summary",
    EVIDENCE_INTEGRITY: "Evidence integrity failure",
    MAIL_PREPARED: "E-mail ready to send",  # Send in Aegis, or from Outlook in manual mode
    FREEZE_DETECTED: "On-chain freeze detected",
    FREEZE_LIFTED: "On-chain freeze lifted",
    BLOCK_STATUS_CHANGED: "Block status changed",  # app.blocks: a reply's status confirmed / suggested
    PROVIDER_DEADLINE: "Provider deadline",  # app.blocks: a clock on a request (submit by, file by) falls due
    HOLD_EXPIRING: "Hold expiring",  # app.blocks: a confirmed hold lapses soon
}
AMOUNT_EVENTS = (WALLET_MOVEMENT, VASP_DEPOSIT, SWEEP_IMMINENT)  # the rule editor shows thresholds for these
SEVERITY_FLOOR: dict[str, str] = {VASP_DEPOSIT: "critical", SWEEP_IMMINENT: "critical", FREEZE_DETECTED: "critical",
                                  FREEZE_LIFTED: "critical"}
DEFAULT_OVERDUE_DAYS = 7
_TEAM = ["admin", "investigator"]

# Built-in defaults (seeded as case rows by seed_default_rules).
DEFAULT_RULES: dict[str, dict[str, Any]] = {
    WALLET_MOVEMENT: {"enabled": True, "min_usd": Decimal(1000), "min_pct_of_loss": 1.0,
                      "channels": [IN_APP, EMAIL], "recipient_roles": _TEAM},
    VASP_DEPOSIT: {"enabled": True, "channels": [IN_APP, EMAIL, SLACK], "recipient_roles": _TEAM},
    SWEEP_IMMINENT: {"enabled": True, "channels": [IN_APP, EMAIL, SLACK], "recipient_roles": _TEAM},
    STOP_ORDER_STATUS: {"enabled": True, "channels": [IN_APP], "recipient_roles": _TEAM},
    CORRESPONDENCE_IN: {"enabled": True, "channels": [IN_APP, EMAIL], "recipient_roles": _TEAM},
    CORRESPONDENCE_OUT: {"enabled": False, "channels": [IN_APP], "recipient_roles": _TEAM},
    RESPONSE_OVERDUE: {"enabled": True, "overdue_days": DEFAULT_OVERDUE_DAYS, "channels": [IN_APP, EMAIL],
                       "recipient_roles": _TEAM},
    EVIDENCE_ADDED: {"enabled": True, "channels": [IN_APP], "recipient_roles": _TEAM},
    TRACE_COMPLETED: {"enabled": True, "channels": [IN_APP], "recipient_roles": _TEAM},
    AI_SUMMARY: {"enabled": False, "channels": [IN_APP], "recipient_roles": _TEAM},
    EVIDENCE_INTEGRITY: {"enabled": True, "channels": [IN_APP, EMAIL], "recipient_roles": ["admin"]},
    MAIL_PREPARED: {"enabled": True, "channels": [IN_APP, EMAIL], "recipient_roles": ["admin"]},
    # an issuer froze a case wallet (app.freeze): always critical, in-app only by default
    FREEZE_DETECTED: {"enabled": True, "channels": [IN_APP], "recipient_roles": _TEAM},
    # the issuer lifted that freeze: the funds can move again (the most urgent moment); always critical,
    # in-app by default like freeze_detected (a case admin can add e-mail in the rule editor)
    FREEZE_LIFTED: {"enabled": True, "channels": [IN_APP], "recipient_roles": _TEAM},
    # a block request's status changed (app.blocks: a reply classified, a status confirmed or applied): in-app
    BLOCK_STATUS_CHANGED: {"enabled": True, "channels": [IN_APP], "recipient_roles": _TEAM},
    # a clock on a block request (app.blocks.status.check_clocks, from the scheduler's overdue pass): ahead of it and
    # when it passes; missing one loses the remedy (MEXC lifts its temporary freeze after 48h), so e-mail too
    PROVIDER_DEADLINE: {"enabled": True, "channels": [IN_APP, EMAIL], "recipient_roles": _TEAM},
    HOLD_EXPIRING: {"enabled": True, "channels": [IN_APP, EMAIL], "recipient_roles": _TEAM},
}
assert set(DEFAULT_RULES) == set(EVENT_TYPES)

# Destinations where a freeze is possible: funds arriving there are a VASP deposit.
VASP_CATEGORIES = {EntityCategory.EXCHANGE, EntityCategory.CASINO, EntityCategory.SWAP_SERVICE,
                   EntityCategory.OTC, EntityCategory.BRIDGE}


# --------------------------------------------------------------------------- settings
class NotifySettings(BaseSettings):
    """Channel configuration. Read fresh on every delivery so a deployment can add it without a restart."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True
    smtp_ssl: bool = False
    slack_webhook_url: str = ""
    app_base_url: str = ""

    @property
    def email_configured(self) -> bool:
        return bool(self.smtp_host.strip() and self.smtp_from.strip())

    @property
    def slack_configured(self) -> bool:
        return self.slack_webhook_url.strip().startswith("https://")


def channel_settings() -> NotifySettings:
    return NotifySettings()


def channel_status() -> dict[str, bool]:
    """Which channels are configured (booleans only: templates never see the settings)."""
    s = channel_settings()
    return {IN_APP: True, EMAIL: s.email_configured, SLACK: s.slack_configured}


# --------------------------------------------------------------------------- rules
@dataclass
class RuleSpec:
    """The rule that applies to one event type on one case (wherever it came from)."""

    event_type: str
    enabled: bool = True
    min_usd: Decimal | None = None
    min_pct_of_loss: float | None = None
    channels: list[str] = field(default_factory=lambda: [IN_APP])
    recipient_roles: list[str] = field(default_factory=lambda: list(_TEAM))
    overdue_days: int | None = None
    source: str = "default"  # case | global | default
    rule_id: int | None = None

    @property
    def label(self) -> str:
        return EVENT_LABELS.get(self.event_type, self.event_type)

    @classmethod
    def from_row(cls, row: NotificationRule, source: str) -> RuleSpec:
        return cls(event_type=row.event_type, enabled=bool(row.enabled), min_usd=row.min_usd,
                   min_pct_of_loss=row.min_pct_of_loss, channels=list(row.channels or [IN_APP]),
                   recipient_roles=list(row.recipient_roles or _TEAM), overdue_days=row.overdue_days,
                   source=source, rule_id=row.id)

    @classmethod
    def default(cls, event_type: str) -> RuleSpec:
        d = DEFAULT_RULES[event_type]
        return cls(event_type=event_type, enabled=d["enabled"], min_usd=d.get("min_usd"),
                   min_pct_of_loss=d.get("min_pct_of_loss"), channels=list(d["channels"]),
                   recipient_roles=list(d["recipient_roles"]), overdue_days=d.get("overdue_days"))


def effective_rule(db: Session, case: Case | None, event_type: str) -> RuleSpec:
    if case is not None:
        row = db.scalar(select(NotificationRule).where(NotificationRule.case_id == case.id,
                                                      NotificationRule.event_type == event_type)
                        .order_by(NotificationRule.id).limit(1))
        if row is not None:
            return RuleSpec.from_row(row, "case")
    row = db.scalar(select(NotificationRule).where(NotificationRule.case_id.is_(None),
                                                  NotificationRule.event_type == event_type)
                    .order_by(NotificationRule.id).limit(1))
    if row is not None:
        return RuleSpec.from_row(row, "global")
    return RuleSpec.default(event_type)


def effective_rules(db: Session, case: Case | None) -> list[RuleSpec]:
    return [effective_rule(db, case, et) for et in EVENT_TYPES]


def overdue_days(db: Session, case: Case | None) -> int:
    """Days after which an unanswered letter/message is overdue (the response_overdue rule)."""
    days = effective_rule(db, case, RESPONSE_OVERDUE).overdue_days
    return days if days and days > 0 else DEFAULT_OVERDUE_DAYS


def seed_default_rules(db: Session, case: Case, *, created_by: User | None = None, overwrite: bool = False) -> int:
    """Write DEFAULT_RULES as the case's rules. Only missing event types unless `overwrite`.
    Flushes; the caller audits and commits. Returns the number of rows written."""
    existing = {r.event_type: r for r in db.scalars(select(NotificationRule)
                                                    .where(NotificationRule.case_id == case.id))}
    written = 0
    for et in EVENT_TYPES:
        row = existing.get(et)
        if row is not None and not overwrite:
            continue
        if row is None:
            row = NotificationRule(case_id=case.id, event_type=et, created_by=created_by.id if created_by else None)
            db.add(row)
        apply_rule_values(row, RuleSpec.default(et))
        written += 1
    db.flush()
    return written


def apply_rule_values(row: NotificationRule, spec: RuleSpec) -> NotificationRule:
    row.enabled = spec.enabled
    row.min_usd = spec.min_usd
    row.min_pct_of_loss = spec.min_pct_of_loss
    row.channels = normalise_channels(spec.channels)
    row.recipient_roles = normalise_roles(spec.recipient_roles)
    row.overdue_days = spec.overdue_days
    return row


def normalise_channels(channels: Iterable[str]) -> list[str]:
    """Known channels only, in_app always first (the in-app inbox always receives)."""
    chosen = {c for c in channels if c in CHANNELS}
    return [c for c in CHANNELS if c in chosen or c == IN_APP]


def normalise_roles(roles: Iterable[str]) -> list[str]:
    chosen = set(roles)
    return [r for r in RECIPIENT_ROLES if r in chosen]


def parse_usd(value: Any) -> Decimal | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    try:
        d = Decimal(str(value).replace(",", "").replace("$", "").strip())
    except InvalidOperation:
        raise ValueError(f"not an amount: {value!r}") from None
    if d < 0 or not d.is_finite():
        raise ValueError("amounts must be zero or more")
    return d.quantize(Decimal("0.01"))


def passes_thresholds(rule: RuleSpec, usd: Decimal | None, loss_usd: Decimal | None) -> bool:
    """True when no threshold is set, or when the amount meets min_usd OR min_pct_of_loss."""
    checks: list[bool] = []
    if rule.min_usd is not None:
        checks.append(usd is not None and usd >= Decimal(rule.min_usd))
    if rule.min_pct_of_loss is not None and loss_usd:
        checks.append(usd is not None and usd * 100 / Decimal(loss_usd) >= Decimal(str(rule.min_pct_of_loss)))
    return not checks or any(checks)


def _severity(event_type: str, severity: str) -> str:
    floor = SEVERITY_FLOOR.get(event_type)
    if floor and SEVERITIES.index(floor) > SEVERITIES.index(severity):
        return floor
    return severity


# --------------------------------------------------------------------------- PII scrubbing
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_PHONE_RE = re.compile(r"\+\d[\d ().-]{6,}\d")
_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]{40,}\b")
_TRON_RE = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
_BTC_RE = re.compile(r"\b(?:bc1[02-9ac-hj-np-z]{25,87}|[13][1-9A-HJ-NP-Za-km-z]{25,34})\b")
_PII_FACT_KEYS = {"impersonated_entity", "persona", "domains", "reference", "firm", "contact", "email", "cc",
                  "address", "phone", "name", "role", "victim_contact", "investigator", "complaints"}
_SPLITS = re.compile(r"\s+[—–-]\s+|\s*\(|,\s")


def short_address(value: str) -> str:
    return value if len(value) <= 14 else f"{value[:8]}…{value[-6:]}"


def _fact_terms(value: Any, key: str | None, out: set[str]) -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            if k in _PII_FACT_KEYS:
                _fact_terms(v, k, out)
    elif isinstance(value, list):
        for v in value:
            _fact_terms(v, key, out)
    elif isinstance(value, str) and key is not None:
        _add_term(value, out)


def _add_term(value: str | None, out: set[str]) -> None:
    value = (value or "").strip()
    if len(value) < 4:
        return
    out.add(value)
    head = _SPLITS.split(value, maxsplit=1)[0].strip()
    if len(head) >= 4 and head != value:
        out.add(head)  # "Exempla Holding AG (UID …)" → also "Exempla Holding AG"


def sensitive_terms(db: Session | None, case: Case | None) -> list[str]:
    """Case-specific strings that must never appear in a notification (longest first)."""
    if case is None:
        return []
    out: set[str] = set()
    for v in (case.victim_name, case.victim_entity):
        _add_term(v, out)
    _fact_terms(case.facts or {}, None, out)
    for c in getattr(case, "le_contacts", None) or []:
        for v in (c.name, c.email, c.phone, c.reference):
            _add_term(v, out)
    for m in getattr(case, "members", None) or []:
        if m.user is not None and " " in (m.user.display_name or "").strip():
            _add_term(m.user.display_name, out)
    return sorted(out, key=len, reverse=True)


def scrub(text: str | None, terms: Iterable[str] = ()) -> str | None:
    """Remove PII from a notification title/body (see the module docstring)."""
    if text is None:
        return None
    for term in terms:
        text = re.sub(re.escape(term), "[redacted]", text, flags=re.IGNORECASE)
    text = _EMAIL_RE.sub("[email]", text)
    text = _PHONE_RE.sub("[phone]", text)
    for rx in (_HEX_RE, _TRON_RE, _BTC_RE):
        text = rx.sub(lambda m: short_address(m.group(0)), text)
    return text


def pii_findings(text: str | None, case: Case | None) -> list[str]:
    """What in `text` would be scrubbed (for tests and checks). Empty = clean."""
    if not text:
        return []
    found = [t for t in sensitive_terms(None, case) if t.lower() in text.lower()]
    found += _EMAIL_RE.findall(text) + _PHONE_RE.findall(text)
    return found


def _ids_only(payload: dict | None) -> dict:
    """Payload values are ids, flags and short codes (no free text, nothing with an @)."""
    def ok(v: Any) -> bool:
        if v is None or isinstance(v, (bool, int, float)):
            return True
        if isinstance(v, str):
            return len(v) <= 64 and "@" not in v and " " not in v
        if isinstance(v, (list, tuple)):
            return all(ok(x) for x in v)
        return False

    return {str(k): (list(v) if isinstance(v, tuple) else v) for k, v in (payload or {}).items() if ok(v)}


# --------------------------------------------------------------------------- recipients & delivery
def recipients(db: Session, case: Case | None, roles: Iterable[str]) -> list[User]:
    """Active users who should hear: case members with one of `roles` (never externals); without a
    case, the active system administrators."""
    if case is None:
        return list(db.scalars(select(User).where(User.is_system_admin.is_(True), User.is_active.is_(True))
                               .order_by(User.id)))
    wanted = {CaseRole(r) for r in roles if r in RECIPIENT_ROLES}
    now = datetime.now(tz=UTC)
    rows = db.scalars(select(CaseMember).join(User, User.id == CaseMember.user_id).where(
        CaseMember.case_id == case.id, User.is_active.is_(True),
        or_(CaseMember.expires_at.is_(None), CaseMember.expires_at > now)).order_by(CaseMember.id))
    return [m.user for m in rows if m.role in wanted]


def outbound_text(case: Case | None, note: Notification, base_url: str = "") -> tuple[str, str]:
    """(subject, text) for e-mail / Slack: case reference, event, severity, amount, short addresses, link."""
    ref = case.reference if case is not None else "Aegis"
    label = EVENT_LABELS.get(note.event_type, note.event_type)
    subject = f"[Aegis] {ref} · {label} · {note.severity.upper()}"
    lines = [subject, note.title]
    if note.body:
        lines.append(note.body)
    if note.usd is not None:
        lines.append(f"Amount: ${Decimal(note.usd):,.2f}")
    if note.link:
        lines.append(f"Open: {base_url.rstrip('/')}{note.link}" if base_url else f"Open in Aegis: {note.link}")
    return subject, "\n".join(lines)


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="seconds")


def send_email(cfg: NotifySettings, to: list[str], subject: str, text: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.smtp_from
    msg["To"] = cfg.smtp_from  # recipients go in the envelope only (Bcc): members do not see each other
    msg.set_content(text)
    smtp_cls = smtplib.SMTP_SSL if cfg.smtp_ssl else smtplib.SMTP
    with smtp_cls(cfg.smtp_host, cfg.smtp_port, timeout=10) as smtp:
        if cfg.smtp_starttls and not cfg.smtp_ssl:
            smtp.starttls()
        if cfg.smtp_username:
            smtp.login(cfg.smtp_username, cfg.smtp_password)
        smtp.send_message(msg, to_addrs=to)


def send_slack(cfg: NotifySettings, text: str) -> None:
    r = httpx.post(cfg.slack_webhook_url.strip(), json={"text": text}, timeout=5.0)
    r.raise_for_status()


def deliver(db: Session, case: Case | None, note: Notification, rule: RuleSpec, users: list[User]) -> list[dict]:
    """Deliver through each channel of the rule. Never raises; returns the delivery log."""
    log_rows: list[dict] = [{"channel": IN_APP, "status": "delivered", "at": _now_iso(), "recipients": len(users)}]
    channels = [c for c in normalise_channels(rule.channels) if c != IN_APP]
    if not channels:
        return log_rows
    cfg = channel_settings()
    subject, text = outbound_text(case, note, cfg.app_base_url)
    for ch in channels:
        entry: dict[str, Any] = {"channel": ch, "at": _now_iso()}
        try:
            if ch == EMAIL:
                to = sorted({u.email for u in users if u.email})
                if not cfg.email_configured:
                    entry["status"] = "not_configured"
                elif not to:
                    entry["status"] = "no_recipients"
                else:
                    send_email(cfg, to, subject, text)
                    entry.update(status="sent", recipients=len(to))
            elif ch == SLACK:
                if not cfg.slack_configured:
                    entry["status"] = "not_configured"
                else:
                    send_slack(cfg, text)
                    entry["status"] = "sent"
        except Exception as exc:  # noqa: BLE001 - a failed channel must not lose the event
            entry.update(status="failed", error=type(exc).__name__)
            log.warning("notification %s: %s delivery failed (%s)", note.id, ch, type(exc).__name__)
        log_rows.append(entry)
    return log_rows


def dispatch(db: Session, case: Case | None, event_type: str, *, usd: Any, title: str, body: str | None,
             link: str | None, severity: str, payload: dict | None, commit: bool) -> Notification | None:
    """The body of app.core.events.emit (arguments already validated)."""
    usd_d = Decimal(str(usd)).quantize(Decimal("0.01")) if usd is not None else None
    rule = effective_rule(db, case, event_type)
    if not rule.enabled or not passes_thresholds(rule, usd_d, case.loss_usd if case is not None else None):
        return None
    terms = sensitive_terms(db, case)
    users = recipients(db, case, rule.recipient_roles)
    data = _ids_only(payload)
    data.update(recipient_user_ids=[u.id for u in users], rule=rule.source)
    if link and (not link.startswith("/") or link.startswith("//")):
        link = None  # app-relative links only
    note = Notification(
        case_id=case.id if case is not None else None, event_type=event_type,
        title=(scrub(title, terms) or "")[:255], body=scrub(body, terms), link=link,
        severity=_severity(event_type, severity), usd=usd_d, payload=data, deliveries=[], read_by=[],
    )
    db.add(note)
    db.flush()
    note.deliveries = deliver(db, case, note, rule, users)
    if commit:
        db.commit()
    else:
        db.flush()
    return note


# --------------------------------------------------------------------------- watch poller → events
def _fmt_amount(v: Decimal | None) -> str:
    if v is None:
        return "?"
    d = Decimal(v)
    q = Decimal("0.01") if abs(d) >= 1000 else Decimal("0.000001")
    s = f"{d.quantize(q):f}"
    return s.rstrip("0").rstrip(".") if "." in s else s


def emit_watch_alerts(db: Session, case: Case, alerts: Iterable[Alert]) -> list[Notification]:
    """Turn watch-poll alerts into wallet_movement / vasp_deposit events (idempotent per alert)."""
    from app.providers.prices import to_usd

    alerts = [a for a in alerts if a.id is not None]
    if not alerts:
        return []
    done = {n.payload.get("alert_id") for n in db.scalars(
        select(Notification).where(Notification.case_id == case.id,
                                   Notification.event_type.in_((WALLET_MOVEMENT, VASP_DEPOSIT))))}
    out: list[Notification] = []
    for a in alerts:
        if a.id in done:
            continue
        item = a.watch_item
        src = item.address
        t = None
        if a.tx_hash:
            t = db.scalar(select(Transfer).where(Transfer.tx_hash == a.tx_hash, Transfer.from_address_id == src.id)
                          .order_by(Transfer.sub_index).limit(1))
        dest = t.to_address if t is not None else None
        usd = None
        if t is not None and t.amount is not None:
            usd = t.amount_usd if t.amount_usd is not None else to_usd(t.asset, t.amount)
        is_vasp = bool(dest is not None and dest.entity is not None and dest.entity.category in VASP_CATEGORIES)
        amount = f"{_fmt_amount(t.amount if t else None)} {t.asset if t else ''}".strip()
        usd_txt = f" (≈ ${Decimal(usd):,.2f})" if usd is not None else ""
        if dest is not None:
            where = f"{dest.entity.name} {dest.short()}" if dest.entity else (
                f"{dest.label} {dest.short()}" if dest.label else dest.short())
        else:
            where = "an unknown address"
        when = f"{t.timestamp:%d %b %Y %H:%M} UTC" if t is not None else ""
        tx = f" · tx {short_address(a.tx_hash)}" if a.tx_hash else ""
        if is_vasp:
            event, sev = VASP_DEPOSIT, "critical"
            title = f"Funds reached {dest.entity.name}: {amount}"
            tail = " — freeze window open: send the stop order now."
        else:
            event, sev = WALLET_MOVEMENT, a.severity if a.severity in SEVERITIES else "high"
            title = f"Watched wallet {src.short()} moved {amount}"
            tail = ""
        body = f"{case.reference} · {amount}{usd_txt} from {src.short()} to {where}{tx} · {when}{tail}"
        note = emit(db, case, event, usd=usd, title=title, body=body, link=f"/cases/{case.id}?tab=fund_flow",
                    severity=sev, payload={"alert_id": a.id, "watch_item_id": item.id,
                                           "transfer_id": t.id if t else None, "address_id": src.id},
                    commit=False)
        if note is not None:
            out.append(note)
    db.commit()
    return out


def poll_and_notify(db: Session, case: Case, provider_mode: str | None = None) -> tuple[list[Alert], list[Notification]]:
    """services.poll_watch_items + emit_watch_alerts (the scheduler and the poll script use this)."""
    from app.services import poll_watch_items

    alerts = poll_watch_items(db, case, provider_mode)
    return alerts, emit_watch_alerts(db, case, alerts)


# --------------------------------------------------------------------------- inbox
_INBOX_SCAN = 500


def _roles_by_case(db: Session, user: User) -> dict[int, CaseRole]:
    now = datetime.now(tz=UTC)
    rows = db.scalars(select(CaseMember).where(CaseMember.user_id == user.id, or_(
        CaseMember.expires_at.is_(None), CaseMember.expires_at > now)))
    return {m.case_id: m.role for m in rows}


def visible_to(note: Notification, user: User, roles: dict[int, CaseRole]) -> bool:
    """Is `note` in the user's inbox? Addressed recipients only (rows without a recipient list: every
    non-external member; case-less rows: system admins)."""
    rec = (note.payload or {}).get("recipient_user_ids")
    if note.case_id is None:
        return user.is_system_admin if rec is None else user.id in rec
    if note.case_id not in roles and not user.is_system_admin:
        return False
    if rec is not None:
        return user.id in rec
    return user.is_system_admin or roles.get(note.case_id) not in (None, CaseRole.EXTERNAL)


def inbox(db: Session, user: User, *, unread_only: bool = False, limit: int = 100) -> list[Notification]:
    roles = _roles_by_case(db, user)
    q = select(Notification).order_by(Notification.id.desc()).limit(_INBOX_SCAN)
    if not user.is_system_admin:
        q = q.where(or_(Notification.case_id.in_(list(roles) or [-1]), Notification.case_id.is_(None)))
    out = []
    for n in db.scalars(q):
        if visible_to(n, user, roles) and not (unread_only and is_read(n, user)):
            out.append(n)
            if len(out) >= limit:
                break
    return out


def unread_count(db: Session, user: User) -> int:
    return len(inbox(db, user, unread_only=True, limit=_INBOX_SCAN))


def is_read(note: Notification, user: User) -> bool:
    return user.id in (note.read_by or [])


def mark_read(db: Session, note: Notification, user: User) -> bool:
    """Add the user to read_by (flushes). False when it was already read."""
    if is_read(note, user):
        return False
    note.read_by = [*(note.read_by or []), user.id]  # new list: JSON columns track reassignment only
    db.flush()
    return True
