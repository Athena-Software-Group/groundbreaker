"""case workspace: users, sessions, case teams, audit log, correspondence, evidence, LE contacts, notifications

Adds the identity / teams / audit tables (docs/identity-spec.md), the case-workspace tables the
feature routers build on, three entity categories, and new columns on cases, trace_runs and
stop_orders. Enums of the new tables are VARCHAR holding the enum value (app.db.models.value_enum),
so adding a member later needs no migration.

Revision ID: 0003_case_workspace
Revises: 0002_blockscout
Create Date: 2026-10-19
"""

import sqlalchemy as sa
from alembic import op

import app.db.models  # noqa: F401 - custom column types referenced below
from app.db.models import UTCDateTime

revision = "0003_case_workspace"
down_revision = "0002_blockscout"
branch_labels = None
depends_on = None

NEW_ENTITY_CATEGORIES = ("PI_FIRM", "LEGAL_COUNSEL", "REGULATOR")


def _ts(name: str, nullable: bool = True, now: bool = False) -> sa.Column:
    return sa.Column(name, UTCDateTime(timezone=True), nullable=nullable,
                     server_default=sa.func.now() if now else None)


def _fk_user(name: str, table: str) -> sa.Column:
    return sa.Column(name, sa.Integer(), sa.ForeignKey("users.id", name=f"fk_{table}_{name}_users"), nullable=True)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            for value in NEW_ENTITY_CATEGORIES:
                op.execute(f"ALTER TYPE entitycategory ADD VALUE IF NOT EXISTS '{value}'")

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("is_system_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        _ts("created_at", nullable=False, now=True),
        _ts("last_login_at"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", name="fk_user_sessions_user_id_users"),
                  nullable=False),
        sa.Column("auth_method", sa.String(16), nullable=False),
        _ts("created_at", nullable=False),
        _ts("last_seen_at", nullable=False),
        _ts("expires_at", nullable=False),
        _ts("revoked_at"),
        _ts("stepped_up_at"),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(255), nullable=True),
    )
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])

    op.create_table(
        "webauthn_credentials",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", name="fk_webauthn_credentials_user_id_users"),
                  nullable=False),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("aaguid", sa.String(36), nullable=True),
        sa.Column("transports", sa.JSON(), nullable=False),
        sa.Column("backup_eligible", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("backup_state", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("attestation_fmt", sa.String(32), nullable=True),
        sa.Column("user_verified_last", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("nickname", sa.String(128), nullable=True),
        _ts("created_at", nullable=False, now=True),
        _ts("last_used_at"),
        _ts("revoked_at"),
        sa.UniqueConstraint("credential_id", name="uq_webauthn_credential_id"),
    )
    op.create_index("ix_webauthn_credentials_user_id", "webauthn_credentials", ["user_id"])

    op.create_table(
        "case_members",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("cases.id", name="fk_case_members_case_id_cases"),
                  nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", name="fk_case_members_user_id_users"),
                  nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        _fk_user("added_by", "case_members"),
        _ts("added_at", nullable=False, now=True),
        _ts("expires_at"),
        sa.UniqueConstraint("case_id", "user_id", name="uq_case_member"),
    )
    op.create_index("ix_case_members_case_id", "case_members", ["case_id"])
    op.create_index("ix_case_members_user_id", "case_members", ["user_id"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        _ts("ts", nullable=False),
        _fk_user("actor_user_id", "audit_events"),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("cases.id", name="fk_audit_events_case_id_cases"),
                  nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("object_type", sa.String(64), nullable=True),
        sa.Column("object_id", sa.String(64), nullable=True),
        sa.Column("outcome", sa.String(16), nullable=False, server_default="allowed"),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("user_agent", sa.String(255), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("prev_hash", sa.String(64), nullable=True),
        sa.Column("row_hash", sa.String(64), nullable=True),
    )
    op.create_index("ix_audit_events_ts", "audit_events", ["ts"])
    op.create_index("ix_audit_events_actor_user_id", "audit_events", ["actor_user_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_case_ts", "audit_events", ["case_id", "ts"])

    op.create_table(
        "le_contacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("cases.id", name="fk_le_contacts_case_id_cases"),
                  nullable=False),
        sa.Column("entity_id", sa.Integer(), sa.ForeignKey("entities.id", name="fk_le_contacts_entity_id_entities"),
                  nullable=True),
        sa.Column("agency", sa.String(255), nullable=False),
        sa.Column("unit", sa.String(255), nullable=True),
        sa.Column("role", sa.String(128), nullable=True),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("phone", sa.String(64), nullable=True),
        sa.Column("reference", sa.String(255), nullable=True),
        sa.Column("jurisdiction", sa.String(128), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("classification", sa.String(4), nullable=False, server_default="R3"),
        _fk_user("created_by", "le_contacts"),
        _ts("created_at", nullable=False, now=True),
    )
    op.create_index("ix_le_contacts_case_id", "le_contacts", ["case_id"])

    op.create_table(
        "evidence_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("cases.id", name="fk_evidence_items_case_id_cases"),
                  nullable=False),
        sa.Column("folder", sa.String(32), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source_type", sa.String(64), nullable=True),
        sa.Column("storage", sa.String(16), nullable=False),
        sa.Column("source_path", sa.Text(), nullable=True),
        sa.Column("vault_path", sa.Text(), nullable=True),
        sa.Column("inline_text", sa.Text(), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("mime", sa.String(128), nullable=True),
        _ts("doc_date"),
        sa.Column("received_from", sa.String(255), nullable=True),
        sa.Column("classification", sa.String(4), nullable=False, server_default="R3"),
        sa.Column("tlp", sa.String(32), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("shared_with_external", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("parent_id", sa.Integer(),
                  sa.ForeignKey("evidence_items.id", name="fk_evidence_items_parent_id_evidence_items"),
                  nullable=True),
        sa.Column("meta", sa.JSON(), nullable=False),
        _fk_user("created_by", "evidence_items"),
        _ts("created_at", nullable=False, now=True),
        _ts("verified_at"),
    )
    op.create_index("ix_evidence_items_case_id", "evidence_items", ["case_id"])
    op.create_index("ix_evidence_items_sha256", "evidence_items", ["sha256"])

    op.create_table(
        "correspondence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("cases.id", name="fk_correspondence_case_id_cases"),
                  nullable=False),
        sa.Column("entity_id", sa.Integer(),
                  sa.ForeignKey("entities.id", name="fk_correspondence_entity_id_entities"), nullable=True),
        sa.Column("le_contact_id", sa.Integer(),
                  sa.ForeignKey("le_contacts.id", name="fk_correspondence_le_contact_id_le_contacts"), nullable=True),
        sa.Column("direction", sa.String(8), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("subject", sa.String(512), nullable=True),
        sa.Column("body_markdown", sa.Text(), nullable=True),
        sa.Column("sender", sa.String(255), nullable=True),
        sa.Column("recipients", sa.JSON(), nullable=False),
        sa.Column("cc", sa.JSON(), nullable=False),
        _ts("occurred_at"),
        _ts("due_at"),
        sa.Column("stop_order_id", sa.Integer(),
                  sa.ForeignKey("stop_orders.id", name="fk_correspondence_stop_order_id_stop_orders"), nullable=True),
        sa.Column("in_reply_to_id", sa.Integer(),
                  sa.ForeignKey("correspondence.id", name="fk_correspondence_in_reply_to_id_correspondence"),
                  nullable=True),
        sa.Column("thread_key", sa.String(255), nullable=True),
        sa.Column("evidence_item_id", sa.Integer(),
                  sa.ForeignKey("evidence_items.id", name="fk_correspondence_evidence_item_id_evidence_items"),
                  nullable=True),
        sa.Column("external_ref", sa.String(255), nullable=True),
        sa.Column("shared_with_external", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("classification", sa.String(4), nullable=False, server_default="R2"),
        sa.Column("meta", sa.JSON(), nullable=False),
        _fk_user("created_by", "correspondence"),
        _ts("created_at", nullable=False, now=True),
        _ts("updated_at"),
    )
    op.create_index("ix_correspondence_case_id", "correspondence", ["case_id"])
    op.create_index("ix_correspondence_entity_id", "correspondence", ["entity_id"])
    op.create_index("ix_correspondence_stop_order_id", "correspondence", ["stop_order_id"])
    op.create_index("ix_correspondence_thread_key", "correspondence", ["thread_key"])
    op.create_index("ix_correspondence_case_ts", "correspondence", ["case_id", "occurred_at"])

    op.create_table(
        "notification_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("cases.id", name="fk_notification_rules_case_id_cases"),
                  nullable=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("min_usd", sa.Numeric(20, 2), nullable=True),
        sa.Column("min_pct_of_loss", sa.Float(), nullable=True),
        sa.Column("channels", sa.JSON(), nullable=False),
        sa.Column("recipient_roles", sa.JSON(), nullable=False),
        sa.Column("overdue_days", sa.Integer(), nullable=True),
        _fk_user("created_by", "notification_rules"),
        _ts("created_at", nullable=False, now=True),
        _ts("updated_at"),
    )
    op.create_index("ix_notification_rules_case_id", "notification_rules", ["case_id"])

    op.create_table(
        "notifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("cases.id", name="fk_notifications_case_id_cases"),
                  nullable=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("link", sa.String(512), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="info"),
        sa.Column("usd", sa.Numeric(20, 2), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("deliveries", sa.JSON(), nullable=False),
        sa.Column("read_by", sa.JSON(), nullable=False),
        _ts("created_at", nullable=False, now=True),
    )
    op.create_index("ix_notifications_case_id", "notifications", ["case_id"])
    op.create_index("ix_notifications_event_type", "notifications", ["event_type"])
    op.create_index("ix_notifications_case_ts", "notifications", ["case_id", "created_at"])

    # ---- new columns on existing tables (batch mode: SQLite rebuilds the table, Postgres ALTERs)
    with op.batch_alter_table("cases") as b:
        b.add_column(sa.Column("ai_mode", sa.String(16), nullable=False, server_default="redacted"))
        b.add_column(sa.Column("status_summary", sa.Text(), nullable=True))
        b.add_column(sa.Column("created_by", sa.Integer(), nullable=True))
        b.create_foreign_key("fk_cases_created_by_users", "users", ["created_by"], ["id"])

    with op.batch_alter_table("trace_runs") as b:
        b.add_column(sa.Column("label", sa.String(128), nullable=True))
        b.add_column(sa.Column("notes", sa.Text(), nullable=True))
        b.add_column(sa.Column("created_by", sa.Integer(), nullable=True))
        b.create_foreign_key("fk_trace_runs_created_by_users", "users", ["created_by"], ["id"])

    with op.batch_alter_table("stop_orders") as b:
        b.add_column(sa.Column("origin", sa.String(16), nullable=False, server_default="generated"))
        b.add_column(sa.Column("template_key", sa.String(64), nullable=True))
        b.add_column(sa.Column("trace_run_id", sa.Integer(), nullable=True))
        b.add_column(sa.Column("recipient_cc", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
        b.add_column(sa.Column("created_by", sa.Integer(), nullable=True))
        b.add_column(sa.Column("approved_by", sa.Integer(), nullable=True))
        b.add_column(_ts("approved_at"))
        b.add_column(sa.Column("sent_via", sa.String(32), nullable=True))
        b.add_column(_ts("response_due_at"))
        b.create_foreign_key("fk_stop_orders_trace_run_id_trace_runs", "trace_runs", ["trace_run_id"], ["id"])
        b.create_foreign_key("fk_stop_orders_created_by_users", "users", ["created_by"], ["id"])
        b.create_foreign_key("fk_stop_orders_approved_by_users", "users", ["approved_by"], ["id"])


def downgrade() -> None:
    with op.batch_alter_table("stop_orders") as b:
        b.drop_constraint("fk_stop_orders_approved_by_users", type_="foreignkey")
        b.drop_constraint("fk_stop_orders_created_by_users", type_="foreignkey")
        b.drop_constraint("fk_stop_orders_trace_run_id_trace_runs", type_="foreignkey")
        for col in ("response_due_at", "sent_via", "approved_at", "approved_by", "created_by", "recipient_cc",
                    "trace_run_id", "template_key", "origin"):
            b.drop_column(col)

    with op.batch_alter_table("trace_runs") as b:
        b.drop_constraint("fk_trace_runs_created_by_users", type_="foreignkey")
        for col in ("created_by", "notes", "label"):
            b.drop_column(col)

    with op.batch_alter_table("cases") as b:
        b.drop_constraint("fk_cases_created_by_users", type_="foreignkey")
        for col in ("created_by", "status_summary", "ai_mode"):
            b.drop_column(col)

    for table in ("notifications", "notification_rules", "correspondence", "evidence_items", "le_contacts",
                  "audit_events", "case_members", "webauthn_credentials", "user_sessions", "users"):
        op.drop_table(table)

    # Postgres cannot drop single enum values: PI_FIRM / LEGAL_COUNSEL / REGULATOR stay in
    # entitycategory (unused after downgrade). Re-map any rows that use them first.
    op.execute("UPDATE entities SET category = 'UNKNOWN' WHERE category IN ('PI_FIRM', 'LEGAL_COUNSEL', 'REGULATOR')")
