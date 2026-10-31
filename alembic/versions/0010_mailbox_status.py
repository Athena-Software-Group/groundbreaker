"""mailbox status: per-folder mailbox sync, outside-sent letters, reply classifications, AI-reply consent

The case mailbox sync reads Inbox **and** Sent Items (app.mail.ingest, app.mail.sync_outbound;
docs/m365-setup.md, docs/data-handling.md §6.4):

* `mail_messages` gains `folder` (inbox | sentitems: the folder the sync read it from), `graph_conversation_id`
  (Graph's conversationId), `authority_key` (the authority it was tied to), `match_method` (how) and
  `outside_sent` (a Sent Items message sent from Outlook, outside Aegis), plus a partial unique index on
  (mailbox, folder, internet_message_id) so a message is stored once per folder (re-reads are no-ops).
* `mail_sync_folders`: the delta link, backfill start and last result per mailbox folder (the lease stays
  on `mail_sync_state`).
* `reply_classifications`: what a reply says about a requested block (app.blocks; rules, AI or a person).
* `cases.mail_ai_consent`: the per-case "AI reads mailbox replies" consent (NULL = off, the default).

Plain VARCHAR / JSON / Boolean / Numeric / Float columns, so the same DDL runs on SQLite and PostgreSQL. Existing
rows keep NULL / false in the new columns (they were not read from a folder). The downgrade drops the two
tables, the index and the columns (SQLite ≥ 3.35 drops plain columns natively; none of them is indexed once
the indexes are gone): the per-folder delta links and the classifications are lost, the mail rows stay.

Revision ID: 0010_mailbox_status
Revises: 0009_freeze_checks
Create Date: 2026-10-20
"""

import sqlalchemy as sa
from alembic import op

import app.db.models  # noqa: F401 - custom column types referenced below
from app.db.models import UTCDateTime

revision = "0010_mailbox_status"
down_revision = "0009_freeze_checks"
branch_labels = None
depends_on = None

FOLDER_MESSAGE = "folder IS NOT NULL AND internet_message_id IS NOT NULL"
MAIL_COLUMNS = ("folder", "graph_conversation_id", "authority_key", "match_method", "outside_sent")


def _fk(table: str, col: str, ref: str) -> sa.ForeignKey:
    return sa.ForeignKey(f"{ref}.id", name=f"fk_{table}_{col}_{ref}")


def _ts(name: str, *, nullable: bool = True, now: bool = False) -> sa.Column:
    return sa.Column(name, UTCDateTime(timezone=True), nullable=nullable,
                     server_default=sa.func.now() if now else None)


def upgrade() -> None:
    op.add_column("cases", sa.Column("mail_ai_consent", sa.JSON(), nullable=True))

    op.add_column("mail_messages", sa.Column("folder", sa.String(16), nullable=True))
    op.add_column("mail_messages", sa.Column("graph_conversation_id", sa.String(255), nullable=True))
    op.add_column("mail_messages", sa.Column("authority_key", sa.String(32), nullable=True))
    op.add_column("mail_messages", sa.Column("match_method", sa.String(32), nullable=True))
    op.add_column("mail_messages", sa.Column("outside_sent", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index("ix_mail_messages_graph_conversation_id", "mail_messages", ["graph_conversation_id"])
    op.create_index("uq_mail_messages_folder_imid", "mail_messages", ["mailbox", "folder", "internet_message_id"],
                    unique=True, sqlite_where=sa.text(FOLDER_MESSAGE), postgresql_where=sa.text(FOLDER_MESSAGE))

    t = "mail_sync_folders"
    op.create_table(
        t,
        sa.Column("mailbox", sa.String(255), primary_key=True),
        sa.Column("folder", sa.String(16), primary_key=True),
        sa.Column("delta_link", sa.Text(), nullable=True),
        _ts("since"),
        _ts("backfill_requested_at"),
        sa.Column("backfill_requested_by", sa.Integer(), _fk(t, "backfill_requested_by", "users"), nullable=True),
        _ts("last_started_at"),
        _ts("last_finished_at"),
        _ts("last_success_at"),
        sa.Column("last_result", sa.JSON(), nullable=False),
        sa.Column("last_error", sa.String(512), nullable=True),
        _ts("updated_at"),
    )

    t = "reply_classifications"
    op.create_table(
        t,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), _fk(t, "case_id", "cases"), nullable=False),
        sa.Column("mail_message_id", sa.Integer(), _fk(t, "mail_message_id", "mail_messages"), nullable=False),
        sa.Column("correspondence_id", sa.Integer(), _fk(t, "correspondence_id", "correspondence"), nullable=True),
        sa.Column("stop_order_id", sa.Integer(), _fk(t, "stop_order_id", "stop_orders"), nullable=True),
        sa.Column("entity_id", sa.Integer(), _fk(t, "entity_id", "entities"), nullable=True),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("amount", sa.Numeric(38, 18), nullable=True),
        sa.Column("asset", sa.String(32), nullable=True),
        sa.Column("account_refs", sa.JSON(), nullable=False),
        sa.Column("quote", sa.Text(), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("source", sa.String(8), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("model", sa.String(255), nullable=True),
        _ts("created_at", nullable=False, now=True),
        sa.Column("confirmed_by", sa.Integer(), _fk(t, "confirmed_by", "users"), nullable=True),
        _ts("confirmed_at"),
        sa.Column("applied", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("mail_message_id", name="uq_reply_classifications_mail_message_id"),
    )
    op.create_index("ix_reply_classifications_case_id", t, ["case_id"])
    op.create_index("ix_reply_classifications_correspondence_id", t, ["correspondence_id"])
    op.create_index("ix_reply_classifications_stop_order_id", t, ["stop_order_id"])


def downgrade() -> None:
    op.drop_index("ix_reply_classifications_stop_order_id", table_name="reply_classifications")
    op.drop_index("ix_reply_classifications_correspondence_id", table_name="reply_classifications")
    op.drop_index("ix_reply_classifications_case_id", table_name="reply_classifications")
    op.drop_table("reply_classifications")
    op.drop_table("mail_sync_folders")
    op.drop_index("uq_mail_messages_folder_imid", table_name="mail_messages")
    op.drop_index("ix_mail_messages_graph_conversation_id", table_name="mail_messages")
    for col in reversed(MAIL_COLUMNS):
        op.drop_column("mail_messages", col)
    op.drop_column("cases", "mail_ai_consent")
