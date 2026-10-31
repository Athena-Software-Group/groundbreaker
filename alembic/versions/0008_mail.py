"""mail: contact directory, sender profiles, mail messages, mailbox sync state

The e-mail desk (app.domain.directory / sender / mail_compose / mail_send, app.mail): admin-added and
verified contact channels (`entity_channels`; the shipped catalogue data/catalogue/channels.json is
read at runtime and never copied here), the per-case sender of record (`sender_profiles`), every
e-mail Aegis prepared, sent or read from the case mailbox (`mail_messages`), and the inbound sync
bookkeeping per mailbox (`mail_sync_state`). Plain VARCHAR / JSON / Boolean columns only, so the
same DDL runs on SQLite and PostgreSQL; the downgrade drops the four tables (prepared and received
mail metadata is lost; the .eml evidence items stay).

Revision ID: 0008_mail
Revises: 0007_ai_messages
Create Date: 2026-10-19
"""

import sqlalchemy as sa
from alembic import op

import app.db.models  # noqa: F401 - custom column types referenced below
from app.db.models import UTCDateTime

revision = "0008_mail"
down_revision = "0007_ai_messages"
branch_labels = None
depends_on = None


IN_FLIGHT = "letter_key IS NOT NULL AND direction = 'out' AND status IN ('sending', 'sent', 'unknown')"


def _fk(table: str, col: str, ref: str) -> sa.ForeignKey:
    return sa.ForeignKey(f"{ref}.id", name=f"fk_{table}_{col}_{ref}")


def _ts(name: str, *, nullable: bool = True, now: bool = False) -> sa.Column:
    return sa.Column(name, UTCDateTime(timezone=True), nullable=nullable,
                     server_default=sa.func.now() if now else None)


def upgrade() -> None:
    t = "entity_channels"
    op.create_table(
        t,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("entity_id", sa.Integer(), _fk(t, "entity_id", "entities"), nullable=True),
        sa.Column("org_key", sa.String(64), nullable=True),
        sa.Column("case_id", sa.Integer(), _fk(t, "case_id", "cases"), nullable=True),
        sa.Column("le_contact_id", sa.Integer(), _fk(t, "le_contact_id", "le_contacts"), nullable=True),
        sa.Column("catalogue_key", sa.String(128), nullable=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("value", sa.String(512), nullable=True),
        sa.Column("label", sa.String(255), nullable=True),
        sa.Column("purpose", sa.String(16), nullable=False, server_default="general"),
        sa.Column("role_default", sa.String(4), nullable=False, server_default="to"),
        sa.Column("source", sa.String(24), nullable=False, server_default="manual"),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("verified_by", sa.Integer(), _fk(t, "verified_by", "users"), nullable=True),
        _ts("verified_at"),
        sa.Column("verification_note", sa.String(512), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        _ts("last_used_at"),
        sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("classification", sa.String(4), nullable=False, server_default="I0"),
        sa.Column("meta", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.Integer(), _fk(t, "created_by", "users"), nullable=True),
        _ts("created_at", nullable=False, now=True),
        _ts("updated_at"),
    )
    op.create_index("ix_entity_channels_entity_id", t, ["entity_id"])
    op.create_index("ix_entity_channels_org_key", t, ["org_key"])
    op.create_index("ix_entity_channels_case_id", t, ["case_id"])
    op.create_index("ix_entity_channels_catalogue_key", t, ["catalogue_key"])
    op.create_index("ix_entity_channels_case_entity", t, ["case_id", "entity_id"])

    t = "sender_profiles"
    op.create_table(
        t,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), _fk(t, "case_id", "cases"), nullable=False),
        sa.Column("org_name", sa.String(255), nullable=False),
        sa.Column("on_behalf_of", sa.String(255), nullable=False),
        sa.Column("signatory_name", sa.String(255), nullable=True),
        sa.Column("signatory_title", sa.String(255), nullable=True),
        sa.Column("contact_email", sa.String(255), nullable=True),
        sa.Column("phone", sa.String(64), nullable=True),
        sa.Column("postal_address", sa.String(512), nullable=True),
        sa.Column("instrument", sa.String(128), nullable=False),
        sa.Column("signature_block", sa.Text(), nullable=True),
        sa.Column("authority_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("cc_default", sa.JSON(), nullable=False),
        sa.Column("meta", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.Integer(), _fk(t, "created_by", "users"), nullable=True),
        sa.Column("updated_by", sa.Integer(), _fk(t, "updated_by", "users"), nullable=True),
        _ts("created_at", nullable=False, now=True),
        _ts("updated_at"),
    )
    op.create_index("ix_sender_profiles_case_id", t, ["case_id"], unique=True)

    t = "mail_messages"
    op.create_table(
        t,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), _fk(t, "case_id", "cases"), nullable=True),
        sa.Column("correspondence_id", sa.Integer(), _fk(t, "correspondence_id", "correspondence"), nullable=True),
        sa.Column("letter_key", sa.String(32), nullable=True),
        sa.Column("direction", sa.String(8), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("transport", sa.String(16), nullable=False),
        sa.Column("mailbox", sa.String(255), nullable=False),
        sa.Column("prepare_token", sa.String(64), nullable=True),
        sa.Column("message_id", sa.String(255), nullable=False),
        sa.Column("internet_message_id", sa.String(255), nullable=True),
        sa.Column("provider_message_id", sa.String(255), nullable=True),
        sa.Column("conversation_id", sa.String(255), nullable=True),
        sa.Column("in_reply_to", sa.String(512), nullable=True),
        sa.Column("references", sa.Text(), nullable=True),
        sa.Column("subject", sa.String(512), nullable=True),
        sa.Column("from_addr", sa.String(255), nullable=True),
        sa.Column("to_addrs", sa.JSON(), nullable=False),
        sa.Column("cc_addrs", sa.JSON(), nullable=False),
        sa.Column("mime_sha256", sa.String(64), nullable=True),
        sa.Column("mime_size", sa.Integer(), nullable=True),
        sa.Column("mime_path", sa.Text(), nullable=True),
        sa.Column("eml_evidence_id", sa.Integer(), _fk(t, "eml_evidence_id", "evidence_items"), nullable=True),
        sa.Column("attachments", sa.JSON(), nullable=False),
        sa.Column("confirmations", sa.JSON(), nullable=False),
        sa.Column("body_text", sa.Text(), nullable=True),
        sa.Column("match", sa.JSON(), nullable=False),
        sa.Column("error_reason", sa.String(32), nullable=True),
        sa.Column("error_message", sa.String(512), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        _ts("prepared_at"), _ts("expires_at"), _ts("sent_at"), _ts("received_at"),
        sa.Column("created_by", sa.Integer(), _fk(t, "created_by", "users"), nullable=True),
        sa.Column("sent_by", sa.Integer(), _fk(t, "sent_by", "users"), nullable=True),
        sa.Column("assigned_by", sa.Integer(), _fk(t, "assigned_by", "users"), nullable=True),
        _ts("created_at", nullable=False, now=True),
        _ts("updated_at"),
        sa.Column("meta", sa.JSON(), nullable=False),
        sa.UniqueConstraint("mailbox", "provider_message_id", name="uq_mail_messages_mailbox_provider_id"),
        sa.UniqueConstraint("prepare_token", name="uq_mail_messages_prepare_token"),
    )
    op.create_index("ix_mail_messages_case_id", t, ["case_id"])
    op.create_index("ix_mail_messages_correspondence_id", t, ["correspondence_id"])
    op.create_index("ix_mail_messages_message_id", t, ["message_id"])
    op.create_index("ix_mail_messages_internet_message_id", t, ["internet_message_id"])
    op.create_index("ix_mail_messages_conversation_id", t, ["conversation_id"])
    op.create_index("ix_mail_messages_mime_sha256", t, ["mime_sha256"])
    op.create_index("ix_mail_messages_case_dir_ts", t, ["case_id", "direction", "created_at"])
    # one e-mail per letter: at most one outbound row per letter_key sending / sent / unknown (app.domain.mail_send)
    op.create_index("uq_mail_messages_letter_in_flight", t, ["letter_key"], unique=True,
                    sqlite_where=sa.text(IN_FLIGHT), postgresql_where=sa.text(IN_FLIGHT))

    op.create_table(
        "mail_sync_state",
        sa.Column("mailbox", sa.String(255), primary_key=True),
        sa.Column("transport", sa.String(16), nullable=False),
        sa.Column("delta_link", sa.Text(), nullable=True),
        _ts("since"), _ts("last_started_at"), _ts("last_finished_at"), _ts("last_success_at"), _ts("locked_until"),
        sa.Column("last_result", sa.JSON(), nullable=False),
        sa.Column("last_error", sa.String(512), nullable=True),
        _ts("updated_at"),
    )


def downgrade() -> None:
    op.drop_table("mail_sync_state")
    for name in ("uq_mail_messages_letter_in_flight", "ix_mail_messages_case_dir_ts", "ix_mail_messages_mime_sha256", "ix_mail_messages_conversation_id",
                 "ix_mail_messages_internet_message_id", "ix_mail_messages_message_id",
                 "ix_mail_messages_correspondence_id", "ix_mail_messages_case_id"):
        op.drop_index(name, table_name="mail_messages")
    op.drop_table("mail_messages")
    op.drop_index("ix_sender_profiles_case_id", table_name="sender_profiles")
    op.drop_table("sender_profiles")
    for name in ("ix_entity_channels_case_entity", "ix_entity_channels_catalogue_key", "ix_entity_channels_case_id",
                 "ix_entity_channels_org_key", "ix_entity_channels_entity_id"):
        op.drop_index(name, table_name="entity_channels")
    op.drop_table("entity_channels")
