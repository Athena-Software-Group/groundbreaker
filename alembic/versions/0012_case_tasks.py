"""case tasks: the case's To do list (manual tasks and a person's state of the derived ones)

`case_tasks` (app.domain.todo; docs/todo.md): one row per case and key. A manual task has the key "manual:<id>" (its
own row id); a derived task (the freeze & stop-order board, the Recovery plan, Block status, deadlines, the mailbox,
evidence, case setup: its source key, e.g. "board:entity-5") gets a row only once a person acts on it — assigns it,
overrides its priority or due date, snoozes, dismisses or marks it done — with `fingerprint`, what its source said
then: a done / dismissed / snoozed derived task reopens when the source changes materially, and one whose source
condition clears closes itself (status "resolved", `done_by` NULL). `sensitive`: the task was built from reply content
(a Recovery plan move naming a wallet): members below view_restricted never see the row.

Plain VARCHAR / Text columns, so the same DDL runs on SQLite and PostgreSQL. The downgrade drops the table (manual
tasks and the recorded states are lost; nothing refers to them).

Revision ID: 0012_case_tasks
Revises: 0011_wallet_attributions
Create Date: 2026-10-22
"""

import sqlalchemy as sa
from alembic import op

import app.db.models  # noqa: F401 - custom column types referenced below
from app.db.models import UTCDateTime

revision = "0012_case_tasks"
down_revision = "0011_wallet_attributions"
branch_labels = None
depends_on = None


def _fk(table: str, col: str, ref: str) -> sa.ForeignKey:
    return sa.ForeignKey(f"{ref}.id", name=f"fk_{table}_{col}_{ref}")


def _ts(name: str, *, nullable: bool = True, now: bool = False) -> sa.Column:
    return sa.Column(name, UTCDateTime(timezone=True), nullable=nullable,
                     server_default=sa.func.now() if now else None)


def upgrade() -> None:
    t = "case_tasks"
    op.create_table(
        t,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), _fk(t, "case_id", "cases"), nullable=False),
        sa.Column("key", sa.String(255), nullable=False),
        sa.Column("source", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("priority_override", sa.String(2), nullable=True),
        _ts("due_override"),
        sa.Column("assignee_id", sa.Integer(), _fk(t, "assignee_id", "users"), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        _ts("snoozed_until"),
        sa.Column("dismissed_note", sa.String(500), nullable=True),
        sa.Column("fingerprint", sa.String(64), nullable=True),
        sa.Column("sensitive", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.Integer(), _fk(t, "created_by", "users"), nullable=True),
        _ts("created_at", nullable=False, now=True),
        _ts("updated_at"),
        _ts("done_at"),
        sa.Column("done_by", sa.Integer(), _fk(t, "done_by", "users"), nullable=True),
        sa.UniqueConstraint("case_id", "key", name="uq_case_tasks_case_key"),
    )
    op.create_index("ix_case_tasks_case_id", t, ["case_id"])


def downgrade() -> None:
    op.drop_index("ix_case_tasks_case_id", table_name="case_tasks")
    op.drop_table("case_tasks")
