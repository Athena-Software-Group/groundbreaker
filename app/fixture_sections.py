"""Optional case-workspace sections of a fixture file (docs/fixture-schema.md).

`services.seed_from_fixture` calls `load_sections(db, case, data, report)` after the case itself
is seeded. Every loader is idempotent (re-seeding updates in place, never duplicates) and every
section is optional; unknown top-level sections are ignored.

    team                  users + case roles (passwords from env vars, else generated and reported once)
    stop_orders_imported  letters sent outside Aegis (StopOrder origin=imported + an outbound correspondence row)
    correspondence        messages / calls / notes with entities
    le_contacts           law-enforcement contacts
    evidence              evidence metadata (storage inline | reference | vault)
    sender_profile        the case's sender of record ("<organisation>, on behalf of …")
    notification_rules    per-case notification rules

Each loader belongs to the feature that owns the section's tables; edit only your own loader.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.events import EVENT_TYPES
from app.core.permissions import add_member
from app.core.security import hash_password, normalise_email
from app.db.models import (
    Case,
    Classification,
    Correspondence,
    CorrespondenceChannel,
    CorrespondenceDirection,
    CorrespondenceKind,
    CorrespondenceStatus,
    Entity,
    EntityCategory,
    EvidenceFolder,
    EvidenceItem,
    EvidenceStorage,
    LEContact,
    NotificationRule,
    SenderProfile,
    StopOrder,
    StopOrderOrigin,
    StopOrderStatus,
    User,
)
from app.domain.sender import org_name as sender_org_name
from app.tracing.repository import get_or_create_entity

log = logging.getLogger(__name__)
# external memberships are time-boxed like grants on the Team tab (app.web.routes_team)
EXTERNAL_DEFAULT_DAYS = 30
EXTERNAL_MAX_DAYS = 90


@dataclass
class SeedReport:
    """What a seed run did that the operator must see (printed once by scripts/seed_case.py)."""

    generated_passwords: list[tuple[str, str]] = field(default_factory=list)  # (email, password)
    counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)  # adjustments the operator should know about (no PII)
    stop_orders: dict[str, StopOrder] = field(default_factory=dict)  # fixture key -> row
    correspondence: dict[str, Correspondence] = field(default_factory=dict)


def _ts(v: str | None) -> datetime | None:
    if not v:
        return None
    dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _entity(db: Session, name: str | None, category: str | None = None) -> Entity | None:
    if not name:
        return None
    row = db.scalar(select(Entity).where(Entity.name == name))
    if row is None:
        row = get_or_create_entity(db, name, category=EntityCategory(category or "unknown"))
    return row


# --------------------------------------------------------------------------- team
def _external_expiry(m: dict, n: int, report: SeedReport, now: datetime | None = None) -> datetime:
    """An external member's expiry: `expires_in_days` (relative to the seed) or `expires_at`, default
    EXTERNAL_DEFAULT_DAYS, clamped to EXTERNAL_MAX_DAYS from now (logged and reported, without the
    address: team row n)."""
    now = now or datetime.now(tz=UTC)
    if m.get("expires_in_days") is not None:
        wanted = now + timedelta(days=int(m["expires_in_days"]))
    else:
        wanted = _ts(m.get("expires_at")) or now + timedelta(days=EXTERNAL_DEFAULT_DAYS)
    limit = now + timedelta(days=EXTERNAL_MAX_DAYS)
    if wanted > limit:
        note = (f"team[{n}]: external membership expiry {wanted:%Y-%m-%d} is more than {EXTERNAL_MAX_DAYS} days "
                f"ahead; clamped to {limit:%Y-%m-%d}")
        log.warning("seed: %s", note)
        report.notes.append(note)
        return limit
    return wanted


def load_team(db: Session, case: Case, items: list[dict], report: SeedReport) -> None:
    for n, m in enumerate(items):
        email = normalise_email(m["email"])
        env_name = m.get("password_env")
        env_pw = os.environ.get(env_name) if env_name else None
        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            password = env_pw or secrets.token_urlsafe(12)
            user = User(email=email, display_name=m.get("display_name") or email,
                        password_hash=hash_password(password), is_system_admin=bool(m.get("system_admin", False)),
                        can_create_cases=bool(m.get("can_create_cases", False)))
            db.add(user)
            db.flush()
            if not env_pw:
                report.generated_passwords.append((email, password))
        elif env_pw:  # the operator set the variable: make it the current password
            user.password_hash = hash_password(env_pw)
        role = m.get("role", "read_only")
        expires = _external_expiry(m, n, report) if role == "external" else _ts(m.get("expires_at"))
        add_member(db, case, user, role, expires_at=expires)
    report.counts["team"] = len(items)


# --------------------------------------------------------------------------- letters / correspondence
def load_stop_orders_imported(db: Session, case: Case, items: list[dict], report: SeedReport) -> None:
    for o in items:
        key = o.get("key")
        entity = _entity(db, o.get("entity"), o.get("entity_category"))
        sent_at = _ts(o.get("sent_at"))
        subject = o["subject"]
        order = next((x for x in case.stop_orders if x.origin == StopOrderOrigin.IMPORTED and (
            (key and (x.identifiers or {}).get("fixture_key") == key)
            or (not key and x.subject == subject and x.sent_at == sent_at))), None)
        if order is None:
            order = StopOrder(case=case, origin=StopOrderOrigin.IMPORTED, subject=subject, body_markdown="")
            db.add(order)
        identifiers = dict(o.get("identifiers") or {})
        if key:
            identifiers["fixture_key"] = key
        identifiers.setdefault("entity", entity.name if entity else None)
        order.entity = entity
        order.kind = o.get("kind", "preservation")
        order.status = StopOrderStatus(o.get("status", "sent"))
        order.subject = subject
        order.body_markdown = o.get("body_markdown") or o.get("body") or ""
        order.recipient_email = o.get("recipient_email")
        order.recipient_cc = list(o.get("recipient_cc") or [])
        order.identifiers = identifiers
        order.external_ref = o.get("external_ref")
        order.template_key = o.get("template_key")
        order.sent_at = sent_at
        # an imported letter was written before it was sent, not when it was seeded: `created_at`, else its send time
        created_at = _ts(o.get("created_at")) or sent_at
        if created_at is not None:
            order.created_at = created_at
        order.sent_via = o.get("sent_via")
        order.response_due_at = _ts(o.get("response_due_at"))
        order.responded_at = _ts(o.get("responded_at"))
        order.notes = o.get("notes")
        db.flush()
        if key:
            report.stop_orders[key] = order
        own = next((c for c in order.correspondence if key and (c.meta or {}).get("fixture_key") == key
                    and c.kind == CorrespondenceKind.STOP_ORDER and c.direction == CorrespondenceDirection.OUT), None)
        if own is not None:  # re-seeding updates the letter's own logged row in place (the fixture's text, sender)
            own.subject, own.body_markdown, own.sender = subject, order.body_markdown, o.get("sender")
            own.recipients, own.cc = [r for r in [order.recipient_email] if r], list(order.recipient_cc or [])
            own.occurred_at, own.external_ref = sent_at, order.external_ref
        elif o.get("log_correspondence", True) and not order.correspondence:
            channel = o.get("sent_via") if o.get("sent_via") in CorrespondenceChannel._value2member_map_ else "email"
            db.add(Correspondence(
                case=case, entity=entity, direction=CorrespondenceDirection.OUT, channel=CorrespondenceChannel(channel),
                kind=CorrespondenceKind.STOP_ORDER, status=CorrespondenceStatus.SENT, subject=subject,
                body_markdown=order.body_markdown, sender=o.get("sender"),
                recipients=[r for r in [order.recipient_email] if r], cc=order.recipient_cc, occurred_at=sent_at,
                stop_order=order, external_ref=order.external_ref,
                classification=Classification(o.get("classification", "R3")), meta={"fixture_key": key} if key else {},
            ))
    db.flush()
    report.counts["stop_orders_imported"] = len(items)


def load_correspondence(db: Session, case: Case, items: list[dict], report: SeedReport) -> None:
    for c in items:
        key = c.get("key")
        direction = CorrespondenceDirection(c["direction"])
        occurred_at = _ts(c.get("occurred_at"))
        subject = c.get("subject")
        row = next((x for x in case.correspondence if (
            (key and (x.meta or {}).get("fixture_key") == key)
            or (not key and x.direction == direction and x.subject == subject and x.occurred_at == occurred_at))), None)
        if row is None:
            row = Correspondence(case=case, direction=direction)
            db.add(row)
        order = report.stop_orders.get(c.get("stop_order_key") or "") or next(
            (o for o in case.stop_orders if c.get("stop_order_key")
             and (o.identifiers or {}).get("fixture_key") == c["stop_order_key"]), None)
        row.entity = _entity(db, c.get("entity"), c.get("entity_category"))
        row.direction = direction
        row.channel = CorrespondenceChannel(c.get("channel", "email"))
        row.kind = CorrespondenceKind(c.get("kind", "other"))
        row.status = CorrespondenceStatus(c.get("status", "received" if direction == CorrespondenceDirection.IN
                                                 else "logged"))
        row.subject = subject
        row.body_markdown = c.get("body_markdown") or c.get("body")
        row.sender = c.get("sender")
        row.recipients = list(c.get("recipients") or [])
        row.cc = list(c.get("cc") or [])
        row.occurred_at = occurred_at
        row.due_at = _ts(c.get("due_at"))
        row.stop_order = order
        row.thread_key = c.get("thread_key")
        row.external_ref = c.get("external_ref")
        row.shared_with_external = bool(c.get("shared_with_external", False))
        row.classification = Classification(c.get("classification", "R2"))
        row.meta = {**(c.get("meta") or {}), **({"fixture_key": key} if key else {})}
        db.flush()
        if key:
            report.correspondence[key] = row
    for c in items:  # second pass: reply threading by key
        if c.get("key") and c.get("in_reply_to_key") in report.correspondence:
            report.correspondence[c["key"]].in_reply_to_id = report.correspondence[c["in_reply_to_key"]].id
    db.flush()
    report.counts["correspondence"] = len(items)


# --------------------------------------------------------------------------- LE contacts
def load_le_contacts(db: Session, case: Case, items: list[dict], report: SeedReport) -> None:
    fields = ("unit", "role", "name", "email", "phone", "reference", "jurisdiction", "notes")
    for c in items:
        row = next((x for x in case.le_contacts if x.agency == c["agency"] and x.reference == c.get("reference")
                    and x.name == c.get("name")), None)
        if row is None:
            row = LEContact(case=case, agency=c["agency"])
            db.add(row)
        for f in fields:
            setattr(row, f, c.get(f))
        row.classification = Classification(c.get("classification", "R3"))
        entity = _entity(db, c.get("entity"), c.get("entity_category", "law_enforcement"))
        row.entity_id = entity.id if entity else None
    db.flush()
    report.counts["le_contacts"] = len(items)


# --------------------------------------------------------------------------- evidence
def _sha256_file(path: Path) -> tuple[str, int]:
    h, size = hashlib.sha256(), 0
    with path.open("rb") as fh:  # read-only; the original is never copied or modified
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def load_evidence(db: Session, case: Case, items: list[dict], report: SeedReport) -> None:
    for e in items:
        folder = EvidenceFolder(e.get("folder", "other"))
        row = next((x for x in case.evidence_items if x.folder == folder and x.title == e["title"]), None)
        if row is None:
            row = EvidenceItem(case=case, folder=folder, title=e["title"])
            db.add(row)
        row.storage = EvidenceStorage(e.get("storage", "inline" if e.get("inline_text") else "reference"))
        for f in ("description", "source_type", "vault_path", "inline_text", "mime", "received_from", "tlp"):
            setattr(row, f, e.get(f))
        row.source_path = e.get("source_path")
        if row.storage == EvidenceStorage.REFERENCE and row.source_path and not Path(row.source_path).is_absolute():
            raise ValueError(f"evidence {e['title']!r}: source_path must be absolute in reference mode")
        row.doc_date = _ts(e.get("doc_date"))
        row.classification = Classification(e.get("classification", "R3"))
        row.tags = list(e.get("tags") or [])
        row.shared_with_external = bool(e.get("shared_with_external", False))
        row.meta = dict(e.get("meta") or {})
        row.sha256, row.size_bytes = e.get("sha256"), e.get("size_bytes")
        if row.storage == EvidenceStorage.INLINE and row.inline_text is not None and not row.sha256:
            raw = row.inline_text.encode("utf-8")
            row.sha256, row.size_bytes = hashlib.sha256(raw).hexdigest(), len(raw)
        elif row.storage == EvidenceStorage.REFERENCE and row.source_path and not row.sha256:
            path = Path(row.source_path)
            if path.is_file():
                row.sha256, row.size_bytes = _sha256_file(path)
                row.verified_at = datetime.now(tz=UTC)
    db.flush()
    report.counts["evidence"] = len(items)


# --------------------------------------------------------------------------- sender profile
SENDER_PROFILE_FIELDS = ("org_name", "on_behalf_of", "signatory_name", "signatory_title", "contact_email", "phone",
                         "postal_address", "instrument", "signature_block")


def load_sender_profile(db: Session, case: Case, item: dict, report: SeedReport) -> None:
    """The case's sender profile (app.domain.sender), upserted by case. `authority_evidence_titles`
    names evidence items of this case (loaded by the evidence section before this one)."""
    if not isinstance(item, dict):
        raise TypeError("sender_profile must be an object")
    if not str(item.get("on_behalf_of") or "").strip():
        raise ValueError("sender_profile: on_behalf_of is required")
    row = db.scalar(select(SenderProfile).where(SenderProfile.case_id == case.id))
    if row is None:
        row = SenderProfile(case_id=case.id, meta={})
        db.add(row)
    for f in SENDER_PROFILE_FIELDS:
        if f in item or f not in ("org_name", "instrument"):
            setattr(row, f, item.get(f))
    row.org_name = item.get("org_name") or sender_org_name()
    row.instrument = item.get("instrument") or "Letter of Authorisation"
    if "power of attorney" in row.instrument.lower():
        raise ValueError("sender_profile: an instrument called a Power of Attorney must be set through the page")
    by_title = {e.title: e.id for e in case.evidence_items}
    titles = list(item.get("authority_evidence_titles") or [])
    missing = [t for t in titles if t not in by_title]
    if missing:  # counted, never named (titles can carry case details)
        note = f"sender_profile: {len(missing)} authority document title(s) not found in the case's evidence; skipped"
        log.warning("seed: %s", note)
        report.notes.append(note)
    row.authority_evidence_ids = [by_title[t] for t in titles if t in by_title]
    row.cc_default = list(item.get("cc_default") or [])
    db.flush()


# --------------------------------------------------------------------------- notification rules
def load_notification_rules(db: Session, case: Case, items: list[dict], report: SeedReport) -> None:
    for r in items:
        if r["event_type"] not in EVENT_TYPES:
            raise ValueError(f"notification rule: unknown event_type {r['event_type']!r}")
        row = db.scalar(select(NotificationRule).where(NotificationRule.case_id == case.id,
                                                      NotificationRule.event_type == r["event_type"]))
        if row is None:
            row = NotificationRule(case_id=case.id, event_type=r["event_type"])
            db.add(row)
        row.enabled = bool(r.get("enabled", True))
        row.min_usd = Decimal(str(r["min_usd"])) if r.get("min_usd") is not None else None
        row.min_pct_of_loss = r.get("min_pct_of_loss")
        row.channels = list(r.get("channels") or ["in_app"])
        row.recipient_roles = list(r.get("recipient_roles") or ["admin", "investigator"])
        row.overdue_days = r.get("overdue_days")
    db.flush()
    report.counts["notification_rules"] = len(items)


# Order matters: team before anything with created_by; letters before correspondence that cites them.
LOADERS: dict[str, Callable[[Session, Case, list[dict], SeedReport], None]] = {
    "team": load_team,
    "le_contacts": load_le_contacts,
    "evidence": load_evidence,
    "sender_profile": load_sender_profile,
    "stop_orders_imported": load_stop_orders_imported,
    "correspondence": load_correspondence,
    "notification_rules": load_notification_rules,
}


def load_sections(db: Session, case: Case, data: dict, report: SeedReport | None = None) -> SeedReport:
    report = report or SeedReport()
    for name, loader in LOADERS.items():
        if data.get(name):
            loader(db, case, data[name], report)
    return report
