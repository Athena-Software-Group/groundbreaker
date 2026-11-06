"""SQLAlchemy ORM models.

Design notes
------------
* `Address` is unique per (chain, address). Case-insensitive chains (EVM) are
  stored lower-cased by the service layer; TRON/BTC are case-sensitive and kept
  verbatim.
* `Transfer` is the atomic edge of the graph: one native or token movement
  (one ERC-20 `Transfer` log, one UTXO output, one TRC-20 event). A single tx
  hash may therefore produce several `Transfer` rows (`sub_index`).
* `Entity` is the real-world service behind an address (exchange, casino, swap
  desk, hosting provider). Entities carry the compliance / LE contact data that
  the stop-order generator needs.
* Trace results are persisted per `TraceRun` so an investigator can diff runs
  over time ("did the funds move since yesterday?").
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime
from decimal import Decimal

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy import event as sa_event
from sqlalchemy import false as sa_false
from sqlalchemy import text as sa_text
from sqlalchemy import true as sa_true
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator):
    """Always hand back timezone-aware UTC datetimes.

    Postgres `timestamptz` does this natively; SQLite (used for quick local demos
    and tests) returns naive values, which would break every time comparison in
    the tracer.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:

            value = value.replace(tzinfo=UTC)
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:

            value = value.replace(tzinfo=UTC)
        return value


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- enums
class Chain(str, enum.Enum):
    ETHEREUM = "ethereum"
    ARBITRUM = "arbitrum"
    BASE = "base"
    BSC = "bsc"
    POLYGON = "polygon"
    TRON = "tron"
    BITCOIN = "bitcoin"
    SOLANA = "solana"


class EntityCategory(str, enum.Enum):
    EXCHANGE = "exchange"
    CASINO = "casino"
    SWAP_SERVICE = "swap_service"
    BRIDGE = "bridge"
    DEX = "dex"
    MIXER = "mixer"
    OTC = "otc"
    HOSTING = "hosting"
    INFRA = "infra"
    STABLECOIN_ISSUER = "stablecoin_issuer"
    LAW_ENFORCEMENT = "law_enforcement"
    PI_FIRM = "pi_firm"
    LEGAL_COUNSEL = "legal_counsel"
    REGULATOR = "regulator"
    UNKNOWN = "unknown"


class AddressType(str, enum.Enum):
    EOA = "eoa"
    CONTRACT = "contract"
    DEPOSIT = "deposit"  # per-customer deposit address at a VASP
    HOT_WALLET = "hot_wallet"  # VASP omnibus / hot wallet
    VICTIM = "victim"
    PERPETRATOR = "perpetrator"
    UNKNOWN = "unknown"


class SeedRole(str, enum.Enum):
    ORIGIN_TX = "origin_tx"
    VICTIM_WALLET = "victim_wallet"
    PERPETRATOR_WALLET = "perpetrator_wallet"
    KNOWN_DOWNSTREAM = "known_downstream"


class DataSource(str, enum.Enum):
    ETHERSCAN = "etherscan"
    BLOCKSCOUT = "blockscout"
    TRONGRID = "trongrid"
    MEMPOOL = "mempool"
    FIXTURE = "fixture"
    PI_REPORT = "pi_report"  # fact asserted in an investigator's report
    MANUAL = "manual"


class StopOrderStatus(str, enum.Enum):
    DRAFT = "draft"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    FROZEN = "frozen"
    DECLINED = "declined"
    SUPERSEDED = "superseded"
    RELEASED = "released"  # a frozen hold was lifted / funds returned (migration 0004)


class TraceStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


# Enums of the case workspace (users, teams, correspondence, evidence, notifications) are stored
# as plain VARCHAR holding the enum *value* (no native Postgres type, no CHECK constraint), so a
# feature can add a member without a migration. The older enums above keep their native types.
def value_enum(cls: type[enum.Enum], length: int = 32) -> Enum:
    return Enum(cls, native_enum=False, create_constraint=False, length=length,
                values_callable=lambda e: [m.value for m in e], validate_strings=True)


class CaseRole(str, enum.Enum):
    """Per-case role, lowest first. Ordering lives in app.core.permissions.ROLE_ORDER."""

    EXTERNAL = "external"  # e.g. LE liaison: only items marked shared_with_external
    READ_ONLY = "read_only"
    INVESTIGATOR = "investigator"
    ADMIN = "admin"  # case owner: members, settings, closing


class AIMode(str, enum.Enum):
    OFF = "off"
    REDACTED = "redacted"  # only masked / chain data reaches the model
    FULL = "full"


class Classification(str, enum.Enum):
    """docs/data-handling.md §1."""

    R3 = "R3"  # restricted LE / evidence
    R2 = "R2"  # restricted PII (default for unclassified case data)
    C1 = "C1"  # confidential investigative intel
    I0 = "I0"  # general, no case linkage


class CorrespondenceDirection(str, enum.Enum):
    IN = "in"
    OUT = "out"
    NOTE = "note"


class CorrespondenceChannel(str, enum.Enum):
    EMAIL = "email"
    PORTAL = "portal"
    LETTER = "letter"
    PHONE = "phone"
    MEETING = "meeting"
    OTHER = "other"


class CorrespondenceStatus(str, enum.Enum):
    DRAFT = "draft"
    SENT = "sent"
    RECEIVED = "received"
    LOGGED = "logged"


class CorrespondenceKind(str, enum.Enum):
    STOP_ORDER = "stop_order"
    STATUS_REQUEST = "status_request"
    INFO_REQUEST = "info_request"
    LE_COVER = "le_cover"
    RELEASE_REQUEST = "release_request"
    REPLY = "reply"
    OTHER = "other"


class StopOrderOrigin(str, enum.Enum):
    GENERATED = "generated"  # rendered by app.reports from a trace run
    IMPORTED = "imported"  # a letter sent outside Aegis, loaded from a fixture / import


class EvidenceFolder(str, enum.Enum):
    LAW_ENFORCEMENT = "law_enforcement"
    DIGITAL_ARTIFACTS = "digital_artifacts"
    INVESTIGATOR_REPORTS = "investigator_reports"
    STOP_ORDERS_CORRESPONDENCE = "stop_orders_correspondence"
    LEGAL = "legal"
    FINANCIAL = "financial"
    CHAIN_REPORTS = "chain_reports"
    OTHER = "other"


class EvidenceStorage(str, enum.Enum):
    REFERENCE = "reference"  # metadata + hash only; source_path points at the original, never copied
    VAULT = "vault"  # encrypted copy in the evidence vault (vault_path)
    INLINE = "inline"  # small text held in the DB (inline_text)


# --------------------------------------------------------------------------- core
class Case(Base):
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="open")

    victim_name: Mapped[str | None] = mapped_column(String(255))
    victim_entity: Mapped[str | None] = mapped_column(String(255))
    victim_jurisdiction: Mapped[str | None] = mapped_column(String(128))

    fraud_type: Mapped[str | None] = mapped_column(String(128))
    fraud_date: Mapped[datetime | None] = mapped_column(UTCDateTime())
    loss_amount: Mapped[Decimal | None] = mapped_column(Numeric(38, 18))
    loss_asset: Mapped[str | None] = mapped_column(String(32))
    loss_usd: Mapped[Decimal | None] = mapped_column(Numeric(20, 2))

    summary: Mapped[str | None] = mapped_column(Text)
    # Structured facts used by the stop-order templates:
    # {"impersonated_entity": ..., "persona": ..., "domains": [...],
    #  "complaints": [{"authority":..., "reference":..., "filed_at":...}],
    #  "investigator": {"firm":..., "contact":..., "email":...}}
    facts: Mapped[dict] = mapped_column(JSON, default=dict)
    # what the assistant may send to an LLM for this case (docs/data-handling.md §6)
    ai_mode: Mapped[AIMode] = mapped_column(value_enum(AIMode, 16), default=AIMode.REDACTED,
                                            server_default=AIMode.REDACTED.value)
    status_summary: Mapped[str | None] = mapped_column(Text)  # short human/AI status line, no PII
    # per-case "AI reads mailbox replies" (migration 0010; app.blocks): NULL = never set (off, the default).
    # A case admin's explicit consent naming the data path: {enabled, by, at, provider, destination, ...};
    # switching it off keeps the record with enabled false. AI output is advisory only.
    mail_ai_consent: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # per-case "Owner lookups" (migration 0011; app.attribution): public explorer tags of the case's wallets. NULL =
    # never set (off, the default). A case admin's consent naming the hosts: {enabled, by, at, hosts, plan, last_run}.
    owner_lookup_consent: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # per-case "AI reads evidence" (migration 0011; app.evidence_intel.ai): NULL = never set (off, the default). A case
    # admin's consent naming the data path: {enabled, by, at, provider, destination, model, host, what}.
    evidence_ai_consent: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=func.now(), onupdate=func.now()
    )

    members: Mapped[list[CaseMember]] = relationship(back_populates="case", cascade="all, delete-orphan")
    seeds: Mapped[list[CaseSeed]] = relationship(back_populates="case", cascade="all, delete-orphan")
    trace_runs: Mapped[list[TraceRun]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="TraceRun.id.desc()"
    )
    stop_orders: Mapped[list[StopOrder]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    watch_items: Mapped[list[WatchItem]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    correspondence: Mapped[list[Correspondence]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="Correspondence.occurred_at"
    )
    evidence_items: Mapped[list[EvidenceItem]] = relationship(back_populates="case", cascade="all, delete-orphan")
    le_contacts: Mapped[list[LEContact]] = relationship(back_populates="case", cascade="all, delete-orphan")

    DEMO_PREFIX = "DEMO-"

    @property
    def is_demo(self) -> bool:
        """A demo / training case (reference "DEMO-…", or `facts.demo` / `facts.is_demo` set): never part of the
        mailbox sync's matching (app.mail.matching), so a real reply can never be filed on it. Derived: no column."""
        facts = self.facts if isinstance(self.facts, dict) else {}
        return (self.reference or "").upper().startswith(self.DEMO_PREFIX) or bool(
            facts.get("demo") or facts.get("is_demo"))


# references are unique ignoring case (a reference also names the case's evidence directory, and
# macOS file systems ignore case); app.services.check_new_reference checks it first (migration 0006)
Index("uq_cases_reference_lower", func.lower(Case.reference), unique=True)


class Entity(Base):
    __tablename__ = "entities"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    category: Mapped[EntityCategory] = mapped_column(Enum(EntityCategory), default=EntityCategory.UNKNOWN)
    jurisdiction: Mapped[str | None] = mapped_column(String(128))
    website: Mapped[str | None] = mapped_column(String(255))

    # Where a preservation / freeze request goes
    compliance_email: Mapped[str | None] = mapped_column(String(255))
    le_portal_url: Mapped[str | None] = mapped_column(String(512))
    le_contact_notes: Mapped[str | None] = mapped_column(Text)
    freeze_capable: Mapped[bool] = mapped_column(Boolean, default=True)
    # typical hours before a VASP sweeps deposit addresses to omnibus; informs urgency
    sweep_window_hours: Mapped[int | None] = mapped_column(Integer)

    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())

    addresses: Mapped[list[Address]] = relationship(back_populates="entity")


class Address(Base):
    __tablename__ = "addresses"
    __table_args__ = (UniqueConstraint("chain", "address", name="uq_address_chain_addr"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    chain: Mapped[Chain] = mapped_column(Enum(Chain), index=True)
    address: Mapped[str] = mapped_column(String(128), index=True)
    address_type: Mapped[AddressType] = mapped_column(Enum(AddressType), default=AddressType.UNKNOWN)
    label: Mapped[str | None] = mapped_column(String(255))  # e.g. "KuCoin 17", "Rainbet.com"
    label_source: Mapped[str | None] = mapped_column(String(64))  # etherscan_tag, pi_report, manual

    entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id"), index=True)
    entity: Mapped[Entity | None] = relationship(back_populates="addresses")

    first_seen: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime())
    tx_count: Mapped[int | None] = mapped_column(Integer)
    is_contract: Mapped[bool | None] = mapped_column(Boolean)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())

    def short(self) -> str:
        a = self.address
        return a if len(a) <= 14 else f"{a[:8]}…{a[-6:]}"


class Transfer(Base):
    """One value movement. Several rows may share a tx_hash (token logs, UTXO outputs)."""

    __tablename__ = "transfers"
    __table_args__ = (
        UniqueConstraint("chain", "tx_hash", "sub_index", name="uq_transfer_chain_hash_sub"),
        Index("ix_transfers_from_ts", "from_address_id", "timestamp"),
        Index("ix_transfers_to_ts", "to_address_id", "timestamp"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    chain: Mapped[Chain] = mapped_column(Enum(Chain), index=True)
    tx_hash: Mapped[str] = mapped_column(String(128), index=True)
    sub_index: Mapped[int] = mapped_column(Integer, default=0)
    block_number: Mapped[int | None] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)

    from_address_id: Mapped[int] = mapped_column(ForeignKey("addresses.id"))
    to_address_id: Mapped[int] = mapped_column(ForeignKey("addresses.id"))
    from_address: Mapped[Address] = relationship(foreign_keys=[from_address_id])
    to_address: Mapped[Address] = relationship(foreign_keys=[to_address_id])

    asset: Mapped[str] = mapped_column(String(32))  # ETH, USDC, USDT, BTC ...
    token_contract: Mapped[str | None] = mapped_column(String(128))
    # NULL = movement asserted (e.g. by an investigator's report) but amount not yet observed
    amount: Mapped[Decimal | None] = mapped_column(Numeric(38, 18))
    amount_usd: Mapped[Decimal | None] = mapped_column(Numeric(20, 2))

    # cross-chain hop produced by a swap/bridge service: link to the counterpart
    bridged_to_transfer_id: Mapped[int | None] = mapped_column(ForeignKey("transfers.id"))

    source: Mapped[DataSource] = mapped_column(Enum(DataSource), default=DataSource.ETHERSCAN)
    confidence: Mapped[float] = mapped_column(default=1.0)  # 1.0 observed on-chain; <1 asserted/inferred; 0 refuted
    method: Mapped[str | None] = mapped_column(String(64))  # e.g. "transfer", "swap", "bridge", "sweep"
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())


class CaseSeed(Base):
    """Starting points for a trace: the origin tx, victim wallet, perpetrator wallet."""

    __tablename__ = "case_seeds"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    case: Mapped[Case] = relationship(back_populates="seeds")

    role: Mapped[SeedRole] = mapped_column(Enum(SeedRole))
    chain: Mapped[Chain] = mapped_column(Enum(Chain))
    value: Mapped[str] = mapped_column(String(128))  # tx hash or address
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())


# --------------------------------------------------------------------------- tracing
class TraceRun(Base):
    __tablename__ = "trace_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    case: Mapped[Case] = relationship(back_populates="trace_runs")

    status: Mapped[TraceStatus] = mapped_column(Enum(TraceStatus), default=TraceStatus.PENDING)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    label: Mapped[str | None] = mapped_column(String(128))  # e.g. "live re-run after relay check"
    notes: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

    nodes: Mapped[list[TraceNode]] = relationship(back_populates="run", cascade="all, delete-orphan")
    edges: Mapped[list[TraceEdge]] = relationship(back_populates="run", cascade="all, delete-orphan")


class TraceNode(Base):
    __tablename__ = "trace_nodes"
    __table_args__ = (UniqueConstraint("run_id", "address_id", name="uq_trace_node"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("trace_runs.id"), index=True)
    run: Mapped[TraceRun] = relationship(back_populates="nodes")
    address_id: Mapped[int] = mapped_column(ForeignKey("addresses.id"), index=True)
    address: Mapped[Address] = relationship()

    hop: Mapped[int] = mapped_column(Integer)
    taint_usd: Mapped[Decimal] = mapped_column(Numeric(20, 2), default=0)
    taint_fraction: Mapped[float] = mapped_column(default=0.0)  # share of the original loss
    is_terminal: Mapped[bool] = mapped_column(Boolean, default=False)
    terminal_reason: Mapped[str | None] = mapped_column(String(64))  # vasp, max_hops, below_threshold, dust
    risk_score: Mapped[int] = mapped_column(Integer, default=0)  # 0-100 freeze priority
    flags: Mapped[list] = mapped_column(JSON, default=list)


class TraceEdge(Base):
    __tablename__ = "trace_edges"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("trace_runs.id"), index=True)
    run: Mapped[TraceRun] = relationship(back_populates="edges")
    transfer_id: Mapped[int] = mapped_column(ForeignKey("transfers.id"))
    transfer: Mapped[Transfer] = relationship()
    hop: Mapped[int] = mapped_column(Integer)
    taint_usd: Mapped[Decimal] = mapped_column(Numeric(20, 2), default=0)


# --------------------------------------------------------------------------- response
class StopOrder(Base):
    """A preservation / risk-control / freeze request addressed to one entity."""

    __tablename__ = "stop_orders"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    case: Mapped[Case] = relationship(back_populates="stop_orders")
    entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id"))
    entity: Mapped[Entity | None] = relationship()

    # preservation | freeze | issuer_blacklist | le_referral | status_request | release_request …
    kind: Mapped[str] = mapped_column(String(32), default="preservation")
    status: Mapped[StopOrderStatus] = mapped_column(Enum(StopOrderStatus), default=StopOrderStatus.DRAFT)
    origin: Mapped[StopOrderOrigin] = mapped_column(value_enum(StopOrderOrigin, 16), default=StopOrderOrigin.GENERATED,
                                                    server_default=StopOrderOrigin.GENERATED.value)
    template_key: Mapped[str | None] = mapped_column(String(64))  # letter template used (None = default)
    trace_run_id: Mapped[int | None] = mapped_column(ForeignKey("trace_runs.id"))  # run it was generated from
    recipient_email: Mapped[str | None] = mapped_column(String(255))
    recipient_cc: Mapped[list] = mapped_column(JSON, default=list)
    subject: Mapped[str] = mapped_column(String(512))
    body_markdown: Mapped[str] = mapped_column(Text)
    identifiers: Mapped[dict] = mapped_column(JSON, default=dict)  # addresses, tx hashes, amounts cited
    external_ref: Mapped[str | None] = mapped_column(String(255))  # ticket / case no. from recipient

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))  # four-eyes (Phase 4)
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    sent_via: Mapped[str | None] = mapped_column(String(32))  # email | portal | letter | …
    response_due_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    responded_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    notes: Mapped[str | None] = mapped_column(Text)

    correspondence: Mapped[list[Correspondence]] = relationship(back_populates="stop_order")


class WatchItem(Base):
    """An address we poll for movement so a freeze can be requested the moment funds touch a VASP."""

    __tablename__ = "watch_items"
    __table_args__ = (UniqueConstraint("case_id", "address_id", name="uq_watch_case_addr"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    case: Mapped[Case] = relationship(back_populates="watch_items")
    address_id: Mapped[int] = mapped_column(ForeignKey("addresses.id"))
    address: Mapped[Address] = relationship()
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_seen_tx: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())

    alerts: Mapped[list[Alert]] = relationship(back_populates="watch_item", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    watch_item_id: Mapped[int] = mapped_column(ForeignKey("watch_items.id"), index=True)
    watch_item: Mapped[WatchItem] = relationship(back_populates="alerts")
    severity: Mapped[str] = mapped_column(String(16), default="high")
    tx_hash: Mapped[str | None] = mapped_column(String(128))
    message: Mapped[str] = mapped_column(Text)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())


# --------------------------------------------------------------------------- identity & audit
class User(Base):
    """A person who signs in. E-mail is stored lower-cased (app.core.security.normalise_email)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255))
    # "scrypt$n$r$p$salt$hash" (app.core.security.hash_password); NULL = passkey-only / no password login
    password_hash: Mapped[str | None] = mapped_column(String(255))
    is_system_admin: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    # may open new cases (and so become their admin); system admins always may
    can_create_cases: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=sa_true())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime())

    memberships: Mapped[list[CaseMember]] = relationship(
        back_populates="user", foreign_keys="CaseMember.user_id", cascade="all, delete-orphan"
    )
    webauthn_credentials: Mapped[list[WebAuthnCredential]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[list[UserSession]] = relationship(back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    """Server-side login session (docs/identity-spec.md §4). The signed cookie carries only a random
    token; this row holds its SHA-256, so a database leak yields no usable session. Logout revokes
    the row; "sign out everywhere" revokes every row of the user."""

    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256(token) hex
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    user: Mapped[User] = relationship(back_populates="sessions")
    auth_method: Mapped[str] = mapped_column(String(16), default="password")  # password | passkey | oidc
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())  # absolute lifetime
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    stepped_up_at: Mapped[datetime | None] = mapped_column(UTCDateTime())  # last fresh UV assertion (later)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(255))


class WebAuthnCredential(Base):
    """Passkey public-key credential (docs/identity-spec.md §3). Schema only: passkeys are spec-only
    for now. No biometric data is ever stored; the COSE public key is the only key material."""

    __tablename__ = "webauthn_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # UUID
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    user: Mapped[User] = relationship(back_populates="webauthn_credentials")
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)  # COSE key
    sign_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    aaguid: Mapped[str | None] = mapped_column(String(36))
    transports: Mapped[list] = mapped_column(JSON, default=list)  # internal | hybrid | usb | nfc
    backup_eligible: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    backup_state: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    attestation_fmt: Mapped[str | None] = mapped_column(String(32))  # none | packed | …
    user_verified_last: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    nickname: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class CaseMember(Base):
    """Default deny: a user sees a case only through a membership (system admins excepted)."""

    __tablename__ = "case_members"
    __table_args__ = (UniqueConstraint("case_id", "user_id", name="uq_case_member"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    case: Mapped[Case] = relationship(back_populates="members")
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    user: Mapped[User] = relationship(back_populates="memberships", foreign_keys=[user_id])
    role: Mapped[CaseRole] = mapped_column(value_enum(CaseRole, 16), default=CaseRole.READ_ONLY)
    added_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    added_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())  # external members: time-boxed


class AuditEvent(Base):
    """Append-only audit log (docs/identity-spec.md §8). Stores ids and field names, never values.

    Write with app.core.audit.audit(); the ORM refuses UPDATE and DELETE of these rows.
    `prev_hash` / `row_hash` chain each row to the one before it."""

    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_case_ts", "case_id", "ts"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"))
    action: Mapped[str] = mapped_column(String(64), index=True)  # LOGIN, CREATE, RUN_TRACE, …
    object_type: Mapped[str | None] = mapped_column(String(64))  # table name, e.g. "stop_orders"
    object_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(16), default="allowed", server_default="allowed")  # allowed|denied
    detail: Mapped[dict] = mapped_column(JSON, default=dict)  # ids / field names / counts only — no PII
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    request_id: Mapped[str | None] = mapped_column(String(64))
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    row_hash: Mapped[str | None] = mapped_column(String(64))


@sa_event.listens_for(AuditEvent, "before_update")
@sa_event.listens_for(AuditEvent, "before_delete")
def _audit_is_append_only(mapper, connection, target):
    raise ValueError("audit_events is append-only")


# --------------------------------------------------------------------------- case workspace
class Correspondence(Base):
    """One message, call, meeting or note with an entity (VASP, issuer, LE, PI firm, counsel)."""

    __tablename__ = "correspondence"
    __table_args__ = (Index("ix_correspondence_case_ts", "case_id", "occurred_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    case: Mapped[Case] = relationship(back_populates="correspondence")
    entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id"), index=True)
    entity: Mapped[Entity | None] = relationship()
    le_contact_id: Mapped[int | None] = mapped_column(ForeignKey("le_contacts.id"))
    direction: Mapped[CorrespondenceDirection] = mapped_column(value_enum(CorrespondenceDirection, 8))
    channel: Mapped[CorrespondenceChannel] = mapped_column(value_enum(CorrespondenceChannel, 16),
                                                           default=CorrespondenceChannel.EMAIL)
    kind: Mapped[CorrespondenceKind] = mapped_column(value_enum(CorrespondenceKind, 32), default=CorrespondenceKind.OTHER)
    status: Mapped[CorrespondenceStatus] = mapped_column(value_enum(CorrespondenceStatus, 16),
                                                         default=CorrespondenceStatus.LOGGED)
    subject: Mapped[str | None] = mapped_column(String(512))
    body_markdown: Mapped[str | None] = mapped_column(Text)
    sender: Mapped[str | None] = mapped_column(String(255))
    recipients: Mapped[list] = mapped_column(JSON, default=list)  # list of addresses / names
    cc: Mapped[list] = mapped_column(JSON, default=list)
    occurred_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    due_at: Mapped[datetime | None] = mapped_column(UTCDateTime())  # reply expected by
    stop_order_id: Mapped[int | None] = mapped_column(ForeignKey("stop_orders.id"), index=True)
    stop_order: Mapped[StopOrder | None] = relationship(back_populates="correspondence")
    in_reply_to_id: Mapped[int | None] = mapped_column(ForeignKey("correspondence.id"))
    thread_key: Mapped[str | None] = mapped_column(String(255), index=True)  # Message-ID / ticket thread
    evidence_item_id: Mapped[int | None] = mapped_column(ForeignKey("evidence_items.id"))  # e.g. the .eml
    external_ref: Mapped[str | None] = mapped_column(String(255))  # recipient's ticket / case number
    shared_with_external: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    classification: Mapped[Classification] = mapped_column(value_enum(Classification, 4), default=Classification.R2,
                                                           server_default=Classification.R2.value)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), onupdate=func.now())


class EvidenceItem(Base):
    """Evidence metadata. `reference` items point at the original (source_path, R3) and are never
    copied; `vault` items are encrypted copies; `inline` items are short texts held in the DB."""

    __tablename__ = "evidence_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    case: Mapped[Case] = relationship(back_populates="evidence_items")
    folder: Mapped[EvidenceFolder] = mapped_column(value_enum(EvidenceFolder, 32), default=EvidenceFolder.OTHER)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    source_type: Mapped[str | None] = mapped_column(String(64))  # police_report, screenshot, eml, pdf, chat, …
    storage: Mapped[EvidenceStorage] = mapped_column(value_enum(EvidenceStorage, 16), default=EvidenceStorage.REFERENCE)
    source_path: Mapped[str | None] = mapped_column(Text)  # R3: absolute path of the original (reference mode)
    vault_path: Mapped[str | None] = mapped_column(Text)
    inline_text: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    mime: Mapped[str | None] = mapped_column(String(128))
    doc_date: Mapped[datetime | None] = mapped_column(UTCDateTime())
    received_from: Mapped[str | None] = mapped_column(String(255))
    classification: Mapped[Classification] = mapped_column(value_enum(Classification, 4), default=Classification.R3,
                                                           server_default=Classification.R3.value)
    tlp: Mapped[str | None] = mapped_column(String(32))  # TLP:RED | TLP:AMBER+STRICT | … (data-handling §7)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    shared_with_external: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("evidence_items.id"))  # redacted derivative of
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime())  # last hash re-check


class LEContact(Base):
    """A law-enforcement / authority contact on the case (R2/R3 by default)."""

    __tablename__ = "le_contacts"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    case: Mapped[Case] = relationship(back_populates="le_contacts")
    entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id"))  # the agency as an Entity, if any
    agency: Mapped[str] = mapped_column(String(255))
    unit: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str | None] = mapped_column(String(128))  # complaint desk, investigating officer, prosecutor …
    name: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255))
    phone: Mapped[str | None] = mapped_column(String(64))
    reference: Mapped[str | None] = mapped_column(String(255))  # complaint / file number
    jurisdiction: Mapped[str | None] = mapped_column(String(128))
    notes: Mapped[str | None] = mapped_column(Text)
    classification: Mapped[Classification] = mapped_column(value_enum(Classification, 4), default=Classification.R3,
                                                           server_default=Classification.R3.value)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())


# --------------------------------------------------------------------------- notifications
class NotificationRule(Base):
    """When an event of `event_type` should notify whom, and through which channels.
    case_id NULL = a default rule for every case without its own rule for that event."""

    __tablename__ = "notification_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(64))  # app.core.events constants
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=sa_true())
    min_usd: Mapped[Decimal | None] = mapped_column(Numeric(20, 2))
    min_pct_of_loss: Mapped[float | None] = mapped_column(Float)
    channels: Mapped[list] = mapped_column(JSON, default=lambda: ["in_app"])  # in_app | email | slack
    recipient_roles: Mapped[list] = mapped_column(JSON, default=lambda: ["admin", "investigator"])
    overdue_days: Mapped[int | None] = mapped_column(Integer)  # response_overdue threshold
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), onupdate=func.now())


class Notification(Base):
    """One emitted event (app.core.events.emit). Title/body carry no PII: case ref, event type,
    amounts and short addresses only."""

    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notifications_case_ts", "case_id", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str | None] = mapped_column(Text)
    link: Mapped[str | None] = mapped_column(String(512))  # app-relative URL
    severity: Mapped[str] = mapped_column(String(16), default="info", server_default="info")  # info|warning|high|critical
    usd: Mapped[Decimal | None] = mapped_column(Numeric(20, 2))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)  # ids for the delivery workers, no PII
    deliveries: Mapped[list] = mapped_column(JSON, default=list)  # [{channel, status, at, error}]
    read_by: Mapped[list] = mapped_column(JSON, default=list)  # user ids
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())


# --------------------------------------------------------------------------- assistant
class AiMessage(Base):
    """One turn of a member's assistant chat on a case (app.ai.skills; migration 0007).

    Each conversation is private to its user on that case. `content` is the Markdown shown in the
    chat (R2 at most: what the member typed and what the assistant answered from the context its mode
    allows); the audit log keeps only the AI_QUERY metadata, never this text. `meta` holds the
    message's label, data path, mode, action buttons and suggested commands."""

    __tablename__ = "ai_messages"
    __table_args__ = (Index("ix_ai_messages_case_user", "case_id", "user_id", "id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(16))  # user | assistant | system
    content: Mapped[str] = mapped_column(Text, default="")
    skill: Mapped[str | None] = mapped_column(String(64))  # the slash command that produced it, e.g. "stop-orders"
    source: Mapped[str | None] = mapped_column(String(16))  # ai | rule_based (assistant messages)
    served_model: Mapped[str | None] = mapped_column(String(255))
    mode: Mapped[str | None] = mapped_column(String(16))  # the case's AI mode when it was generated
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=lambda: datetime.now(tz=UTC),
                                                 server_default=func.now())


# --------------------------------------------------------------------------- mail & contact directory
# The contact directory (app.domain.directory), the per-case sender of record (app.domain.sender) and
# the e-mail desk (app.domain.mail_compose / mail_send, app.mail): migration 0008. The shipped catalogue
# (data/catalogue/channels.json) is read at runtime and never copied into these tables.
class ChannelKind(str, enum.Enum):
    EMAIL = "email"
    PORTAL = "portal"
    WEBFORM = "webform"
    PHONE = "phone"
    POSTAL = "postal"
    WEBSITE = "website"


class ChannelPurpose(str, enum.Enum):
    LE_REQUEST = "le_request"
    FREEZE = "freeze"  # freeze / blocklisting requests (Circle's circleblocklisting@); VARCHAR(16): no migration
    COMPLIANCE = "compliance"
    ABUSE = "abuse"
    LEGAL = "legal"
    COMPLAINT = "complaint"
    GENERAL = "general"


class ChannelRole(str, enum.Enum):
    TO = "to"
    CC = "cc"


class ChannelSource(str, enum.Enum):
    CATALOGUE = "catalogue"  # a verification / override of a shipped catalogue channel (catalogue_key)
    MANUAL = "manual"  # added by an admin
    CASE_CORRESPONDENCE = "case_correspondence"  # learned from the case's own letters and replies
    ENTITY_RECORD = "entity_record"  # entities.compliance_email / le_portal_url
    LE_CONTACT = "le_contact"  # le_contacts.email


class MailDirection(str, enum.Enum):
    OUT = "out"
    IN = "in"


class MailStatus(str, enum.Enum):
    # outbound
    PREPARED = "prepared"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"
    UNKNOWN = "unknown"  # the transport could not confirm the send: reconcile before anything else
    SENT_EXTERNAL = "sent_external"  # the letter went out outside Aegis (recorded by hand, not sent by a transport)
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    # inbound
    RECEIVED = "received"
    NEEDS_REVIEW = "needs_review"
    UNASSIGNED = "unassigned"
    ASSIGNED = "assigned"
    IGNORED = "ignored"
    REJECTED = "rejected"


class EntityChannel(Base):
    """One way to reach a counterparty: an admin-added channel, a verification of a catalogue
    channel (`catalogue_key`), or a case-scoped channel (`case_id`, R2). At least one of entity_id,
    org_key or le_contact_id is set (enforced in app.domain.directory, not by the DB)."""

    __tablename__ = "entity_channels"
    __table_args__ = (Index("ix_entity_channels_case_entity", "case_id", "entity_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id"), index=True)
    org_key: Mapped[str | None] = mapped_column(String(64), index=True)  # catalogue org key, e.g. "kucoin"
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), index=True)  # NULL = global directory row
    le_contact_id: Mapped[int | None] = mapped_column(ForeignKey("le_contacts.id"))
    catalogue_key: Mapped[str | None] = mapped_column(String(128), index=True)  # the JSON channel it verifies
    kind: Mapped[ChannelKind] = mapped_column(value_enum(ChannelKind, 16))
    value: Mapped[str | None] = mapped_column(String(512))  # NULL = "to be confirmed"
    label: Mapped[str | None] = mapped_column(String(255))
    purpose: Mapped[ChannelPurpose] = mapped_column(value_enum(ChannelPurpose, 16), default=ChannelPurpose.GENERAL,
                                                    server_default=ChannelPurpose.GENERAL.value)
    role_default: Mapped[ChannelRole] = mapped_column(value_enum(ChannelRole, 4), default=ChannelRole.TO,
                                                      server_default=ChannelRole.TO.value)
    source: Mapped[ChannelSource] = mapped_column(value_enum(ChannelSource, 24), default=ChannelSource.MANUAL,
                                                  server_default=ChannelSource.MANUAL.value)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    verified_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    verification_note: Mapped[str | None] = mapped_column(String(512))
    notes: Mapped[str | None] = mapped_column(Text)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    classification: Mapped[Classification] = mapped_column(value_enum(Classification, 4), default=Classification.I0,
                                                           server_default=Classification.I0.value)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), onupdate=func.now())


def _default_org_name() -> str:
    """A new sender profile's organisation: the deployment's AEGIS_ORG_NAME."""
    from app.core.config import get_settings

    return get_settings().aegis_org_name.strip() or "Your Organisation"


class SenderProfile(Base):
    """Who a case's new letters come from: "<org_name>, on behalf of <on_behalf_of>"
    (app.domain.sender). One row per case."""

    __tablename__ = "sender_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), unique=True, index=True)
    org_name: Mapped[str] = mapped_column(String(255), default=lambda: _default_org_name())
    on_behalf_of: Mapped[str] = mapped_column(String(255))
    signatory_name: Mapped[str | None] = mapped_column(String(255))
    signatory_title: Mapped[str | None] = mapped_column(String(255))
    contact_email: Mapped[str | None] = mapped_column(String(255))
    phone: Mapped[str | None] = mapped_column(String(64))
    postal_address: Mapped[str | None] = mapped_column(String(512))
    instrument: Mapped[str] = mapped_column(String(128), default="Letter of Authorisation")
    signature_block: Mapped[str | None] = mapped_column(Text)  # free text replacing the composed signature lines
    authority_evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    cc_default: Mapped[list] = mapped_column(JSON, default=list)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), onupdate=func.now())


# 0009 added 'sent_external' (a letter recorded as sent outside Aegis, manual mode) to the 0008 predicate.
MAIL_LETTER_IN_FLIGHT = ("letter_key IS NOT NULL AND direction = 'out' "
                         "AND status IN ('sending', 'sent', 'unknown', 'sent_external')")
# 0010: a message read by the mailbox sync is stored at most once per mailbox folder (its internetMessageId),
# so a backfill or a replayed delta page never files it twice (app.mail.ingest / app.mail.sync_outbound).
MAIL_FOLDER_MESSAGE = "folder IS NOT NULL AND internet_message_id IS NOT NULL"


class MailFolder(str, enum.Enum):
    """The mailbox folders the sync reads (Microsoft Graph well-known folder names)."""

    INBOX = "inbox"
    SENTITEMS = "sentitems"


class MailMessage(Base):
    """One e-mail Aegis prepared / sent (direction out) or read from the case mailbox (direction in).
    The raw MIME lives in the vault (`mime_path`) until it is filed as an evidence item
    (`eml_evidence_id`); subjects, addresses and bodies never go to the audit log."""

    __tablename__ = "mail_messages"
    __table_args__ = (
        UniqueConstraint("mailbox", "provider_message_id", name="uq_mail_messages_mailbox_provider_id"),
        UniqueConstraint("prepare_token", name="uq_mail_messages_prepare_token"),
        Index("ix_mail_messages_case_dir_ts", "case_id", "direction", "created_at"),
        # One e-mail per letter (app.domain.mail_send): at most one outbound row per letter_key may be
        # sending, sent, of unknown outcome or recorded as sent outside Aegis, so two concurrent Sends (or
        # records) of one letter cannot both claim it.
        Index("uq_mail_messages_letter_in_flight", "letter_key", unique=True,
              sqlite_where=sa_text(MAIL_LETTER_IN_FLIGHT), postgresql_where=sa_text(MAIL_LETTER_IN_FLIGHT)),
        Index("uq_mail_messages_folder_imid", "mailbox", "folder", "internet_message_id", unique=True,
              sqlite_where=sa_text(MAIL_FOLDER_MESSAGE), postgresql_where=sa_text(MAIL_FOLDER_MESSAGE)),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), index=True)  # NULL = unassigned inbound
    correspondence_id: Mapped[int | None] = mapped_column(ForeignKey("correspondence.id"), index=True)
    # outbound: the letter this e-mail carries ("o<stop order id>" for a stop order's letter, else
    # "c<correspondence id>"); the partial unique index above allows one in-flight / sent row per key
    letter_key: Mapped[str | None] = mapped_column(String(32))
    direction: Mapped[MailDirection] = mapped_column(value_enum(MailDirection, 8))
    status: Mapped[MailStatus] = mapped_column(value_enum(MailStatus, 16))
    transport: Mapped[str] = mapped_column(String(16))
    mailbox: Mapped[str] = mapped_column(String(255))
    prepare_token: Mapped[str | None] = mapped_column(String(64))
    message_id: Mapped[str] = mapped_column(String(255), index=True)  # the Message-ID header, with <>
    internet_message_id: Mapped[str | None] = mapped_column(String(255), index=True)  # as Graph reports it
    provider_message_id: Mapped[str | None] = mapped_column(String(255))  # Graph immutable id | file:<name>
    conversation_id: Mapped[str | None] = mapped_column(String(255), index=True)
    in_reply_to: Mapped[str | None] = mapped_column(String(512))
    references: Mapped[str | None] = mapped_column(Text)
    subject: Mapped[str | None] = mapped_column(String(512))
    from_addr: Mapped[str | None] = mapped_column(String(255))
    to_addrs: Mapped[list] = mapped_column(JSON, default=list)
    cc_addrs: Mapped[list] = mapped_column(JSON, default=list)
    mime_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    mime_size: Mapped[int | None] = mapped_column(Integer)
    mime_path: Mapped[str | None] = mapped_column(Text)  # vault-relative, until filed as evidence
    eml_evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence_items.id"))
    attachments: Mapped[list] = mapped_column(JSON, default=list)
    confirmations: Mapped[dict] = mapped_column(JSON, default=dict)
    body_text: Mapped[str | None] = mapped_column(Text)  # sanitized inbound text (triage)
    match: Mapped[dict] = mapped_column(JSON, default=dict)
    error_reason: Mapped[str | None] = mapped_column(String(32))
    error_message: Mapped[str | None] = mapped_column(String(512))
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    prepared_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    received_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    sent_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    assigned_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), onupdate=func.now())
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    # mailbox sync (migration 0010; app.mail.ingest / app.mail.sync_outbound)
    folder: Mapped[str | None] = mapped_column(String(16))  # inbox | sentitems; NULL = not read from a folder
    graph_conversation_id: Mapped[str | None] = mapped_column(String(255), index=True)  # Graph conversationId
    authority_key: Mapped[str | None] = mapped_column(String(32))  # entity-<id> | le-<id> | … (correspondence keys)
    # how the sync tied it to the case: tag | thread | recipient | cited | letter | triage | … (ingest.METHODS)
    match_method: Mapped[str | None] = mapped_column(String(32))
    # a Sent Items message sent from the mailbox outside Aegis (Outlook), found by the sync
    outside_sent: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())


class MailSyncState(Base):
    """Inbound sync bookkeeping per mailbox (app.mail.ingest): the delta link (never shown), the
    cutover time and the lease that keeps two syncs from running at once."""

    __tablename__ = "mail_sync_state"

    mailbox: Mapped[str] = mapped_column(String(255), primary_key=True)
    transport: Mapped[str] = mapped_column(String(16))
    delta_link: Mapped[str | None] = mapped_column(Text)
    since: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_result: Mapped[dict] = mapped_column(JSON, default=dict)
    last_error: Mapped[str | None] = mapped_column(String(512))
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), onupdate=func.now())


class MailSyncFolder(Base):
    """Per-folder sync state of the case mailbox (migration 0010): the Graph delta link of Inbox and of
    Sent Items (never shown), the backfill start (`since`: AEGIS_MAIL_INBOUND_SINCE, or "Backfill since
    <date>"), and the last run's counts. The lease stays on the mailbox's MailSyncState row."""

    __tablename__ = "mail_sync_folders"

    mailbox: Mapped[str] = mapped_column(String(255), primary_key=True)
    folder: Mapped[str] = mapped_column(String(16), primary_key=True)  # MailFolder value
    delta_link: Mapped[str | None] = mapped_column(Text)
    since: Mapped[datetime | None] = mapped_column(UTCDateTime())
    backfill_requested_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    backfill_requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    last_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_result: Mapped[dict] = mapped_column(JSON, default=dict)  # counts only
    last_error: Mapped[str | None] = mapped_column(String(512))
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), onupdate=func.now())


class ReplyStatus(str, enum.Enum):
    """What an authority's reply says about a requested block (app.blocks)."""

    AUTO_REPLY = "auto_reply"
    ACKNOWLEDGED = "acknowledged"
    INFO_REQUESTED = "info_requested"
    LE_PROCESS_REQUIRED = "le_process_required"
    HOLD_PLACED = "hold_placed"
    FROZEN = "frozen"
    FUNDS_RETURNED = "funds_returned"
    DECLINED_NO_ASSETS = "declined_no_assets"
    DECLINED_OTHER = "declined_other"
    REDIRECTED = "redirected"
    UNCLEAR = "unclear"


class ReplySource(str, enum.Enum):
    RULES = "rules"
    AI = "ai"  # advisory only: never applied without a person's confirmation
    HUMAN = "human"


class ReplyClassification(Base):
    """The status an inbound reply reports for a request (migration 0010; written by app.blocks): from the
    rules, the optional AI reading (per-case consent, advisory) or a person. `quote` is the sentence that
    supports the status (≤ 500 characters); `applied` once it moved the stop order (a person confirmed)."""

    __tablename__ = "reply_classifications"
    __table_args__ = (UniqueConstraint("mail_message_id", name="uq_reply_classifications_mail_message_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    mail_message_id: Mapped[int] = mapped_column(ForeignKey("mail_messages.id"))
    correspondence_id: Mapped[int | None] = mapped_column(ForeignKey("correspondence.id"), index=True)
    stop_order_id: Mapped[int | None] = mapped_column(ForeignKey("stop_orders.id"), index=True)
    entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id"))
    status: Mapped[ReplyStatus] = mapped_column(value_enum(ReplyStatus, 24))
    amount: Mapped[Decimal | None] = mapped_column(Numeric(38, 18))
    asset: Mapped[str | None] = mapped_column(String(32))
    account_refs: Mapped[list] = mapped_column(JSON, default=list)
    quote: Mapped[str | None] = mapped_column(Text)
    rationale: Mapped[str | None] = mapped_column(Text)
    source: Mapped[ReplySource] = mapped_column(value_enum(ReplySource, 8))
    confidence: Mapped[float | None] = mapped_column(Float)
    model: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=lambda: datetime.now(tz=UTC),
                                                 server_default=func.now())
    confirmed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    confirmed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    applied: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())


# --------------------------------------------------------------------------- on-chain freeze detection
# app.freeze (migration 0009): issuer blacklist reads (Tether USDT, Circle USDC) of the case's wallets,
# the wallets an investigator added to watch, and the per-case consent setting. No request leaves
# Aegis for a case until a case admin enables the setting (docs/freeze-detection.md).
class FreezeSetting(Base):
    """Per-case "On-chain freeze checks" setting (off by default). `consent` keeps what was shown to the
    admin who enabled it: the public endpoints (hosts) and what each receives."""

    __tablename__ = "freeze_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    consent: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    enabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    disabled_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    disabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_result: Mapped[dict] = mapped_column(JSON, default=dict)  # counts and hosts only
    # set while a run of the case's checks is in progress (claimed with a conditional UPDATE): one run per case
    run_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), onupdate=func.now())


class FreezeWatch(Base):
    """A wallet an investigator asked Aegis to check for an issuer freeze although it is not (yet) in
    the trace, e.g. from a third-party trace report. Case-scoped: the label and the source note are case
    data (C1 / R2) and never leave the case; TLP:RED material is refused (docs/data-handling.md §7)."""

    __tablename__ = "freeze_watch"
    __table_args__ = (UniqueConstraint("case_id", "chain", "address", name="uq_freeze_watch_case_chain_addr"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    chain: Mapped[str] = mapped_column(String(16))  # ethereum | tron | base | arbitrum | polygon | optimism
    address: Mapped[str] = mapped_column(String(128))  # EVM lower-cased, TRON base58 verbatim
    label: Mapped[str | None] = mapped_column(String(255))
    source_note: Mapped[str | None] = mapped_column(String(512))  # e.g. "third-party trace report"
    tlp: Mapped[str | None] = mapped_column(String(32))  # TLP:CLEAR | TLP:GREEN | TLP:AMBER | TLP:AMBER+STRICT
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=sa_true())
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    removed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    removed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class FreezeCheck(Base):
    """One reading of one issuer contract for one wallet: blacklisted or not, the token balance, the block
    it was read at, how (`method` rpc | explorer) and the sha256 of the raw response. A status change
    (first blacklisted reading) emits `freeze_detected`. `frozen_at` is the block time of the issuer's
    blacklist event (`frozen_at_basis` event) when the explorer found it, else an upper bound
    (`at_or_before`: the first failed transfer, or the check time)."""

    __tablename__ = "freeze_checks"
    __table_args__ = (Index("ix_freeze_checks_case_wallet", "case_id", "chain", "address", "checked_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    chain: Mapped[str] = mapped_column(String(16))
    address: Mapped[str] = mapped_column(String(128))
    issuer: Mapped[str] = mapped_column(String(32))  # Tether | Circle
    token_symbol: Mapped[str] = mapped_column(String(16))  # USDT | USDC
    token_contract: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="ok", server_default="ok")  # ok | error
    error: Mapped[str | None] = mapped_column(String(64))  # error reason code (no URL, no key)
    blacklisted: Mapped[bool | None] = mapped_column(Boolean)  # NULL when the read failed
    balance: Mapped[Decimal | None] = mapped_column(Numeric(38, 18))  # token units (decimals applied)
    block_number: Mapped[int | None] = mapped_column(BigInteger)
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime())
    method: Mapped[str] = mapped_column(String(16), default="rpc", server_default="rpc")  # rpc | explorer
    raw_sha256: Mapped[str | None] = mapped_column(String(64))
    freeze_tx_hash: Mapped[str | None] = mapped_column(String(128))
    frozen_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    frozen_at_basis: Mapped[str | None] = mapped_column(String(16))  # event | at_or_before
    first_failed_tx: Mapped[str | None] = mapped_column(String(128))
    first_failed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    failed_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    source: Mapped[str] = mapped_column(String(16), default="trace", server_default="trace")  # trace | watched
    watch_id: Mapped[int | None] = mapped_column(ForeignKey("freeze_watch.id"))
    trigger: Mapped[str | None] = mapped_column(String(16))  # manual | scheduler
    meta: Mapped[dict] = mapped_column(JSON, default=dict)  # response hashes per call, failed tx list, hosts
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())


# --------------------------------------------------------------------------- wallet owners
class WalletAttribution(Base):
    """Who owns a wallet of a case (app.attribution, migration 0011): a person's attribution (`source` manual: it
    always wins; a row with detail.cleared withdraws it) or a public explorer lookup (`source` explorer: its tags,
    activity counters, hosts and response hashes in `detail`). Append-only: the latest row per wallet and source
    counts, earlier ones are the history. The trace's, the catalogue's and the behaviour attributions are derived
    on every read and never stored."""

    __tablename__ = "wallet_attributions"
    __table_args__ = (Index("ix_wallet_attributions_case_wallet", "case_id", "chain", "address"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    chain: Mapped[str] = mapped_column(String(16))
    address: Mapped[str] = mapped_column(String(128))  # EVM lower-cased, TRON / Bitcoin verbatim
    owner: Mapped[str | None] = mapped_column(String(255))  # entity name; NULL = not identified
    kind: Mapped[str] = mapped_column(String(32), default="unknown", server_default="unknown")
    confidence: Mapped[str] = mapped_column(String(1), default="M", server_default="M")  # H | M | L
    source: Mapped[str] = mapped_column(String(16))  # manual | explorer
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())


class CaseTask(Base):
    """The case's To do list (app.domain.todo, migration 0012): a manual task (`key` "manual:<id>") or a person's
    state of a task Aegis derives from the case (`key` its source key, e.g. "board:entity-5", "setup:authority_doc").
    A derived task needs no row until a person acts on it (assigns, re-prioritises, snoozes, dismisses, marks done);
    `fingerprint` is what its source said then, so a done / dismissed / snoozed derived task reopens when the source
    changes materially, and one whose source condition clears closes itself as "resolved". One row per case and key."""

    __tablename__ = "case_tasks"
    __table_args__ = (UniqueConstraint("case_id", "key", name="uq_case_tasks_case_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    key: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(16), default="manual", server_default="manual")
    title: Mapped[str] = mapped_column(String(300))  # a manual task's title; a derived task's title when last seen
    note: Mapped[str | None] = mapped_column(Text)
    priority_override: Mapped[str | None] = mapped_column(String(2))  # P1 | P2 | P3 (a manual task's priority)
    due_override: Mapped[datetime | None] = mapped_column(UTCDateTime())
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(16), default="open", server_default="open")  # app.domain.todo.STATUSES
    snoozed_until: Mapped[datetime | None] = mapped_column(UTCDateTime())
    dismissed_note: Mapped[str | None] = mapped_column(String(500))
    fingerprint: Mapped[str | None] = mapped_column(String(64))  # a derived task's source state (app.domain.todo)
    # built from reply content (a Recovery plan move naming a wallet): never shown below view_restricted
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), onupdate=func.now())
    done_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    done_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))  # NULL with status resolved: Aegis closed it
