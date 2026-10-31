"""ai_messages: the assistant chat history, per case and per user

The Assistant tab keeps each member's conversation (questions, skill results, suggested commands)
in this table instead of the browser (app.ai.skills, app/web/routes_assistant.py). Plain VARCHAR
and JSON columns only, so the same DDL runs on SQLite and PostgreSQL; the downgrade drops the table
(the chat history is lost, nothing else).

Revision ID: 0007_ai_messages
Revises: 0006_case_reference_ci
Create Date: 2026-10-19
"""

import sqlalchemy as sa
from alembic import op

import app.db.models  # noqa: F401 - custom column types referenced below
from app.db.models import UTCDateTime

revision = "0007_ai_messages"
down_revision = "0006_case_reference_ci"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_messages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("cases.id", name="fk_ai_messages_case_id_cases"),
                  nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", name="fk_ai_messages_user_id_users"),
                  nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("skill", sa.String(64), nullable=True),
        sa.Column("source", sa.String(16), nullable=True),
        sa.Column("served_model", sa.String(255), nullable=True),
        sa.Column("mode", sa.String(16), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=False),
        sa.Column("created_at", UTCDateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ai_messages_case_id", "ai_messages", ["case_id"])
    op.create_index("ix_ai_messages_user_id", "ai_messages", ["user_id"])
    op.create_index("ix_ai_messages_case_user", "ai_messages", ["case_id", "user_id", "id"])


def downgrade() -> None:
    op.drop_index("ix_ai_messages_case_user", table_name="ai_messages")
    op.drop_index("ix_ai_messages_user_id", table_name="ai_messages")
    op.drop_index("ix_ai_messages_case_id", table_name="ai_messages")
    op.drop_table("ai_messages")
