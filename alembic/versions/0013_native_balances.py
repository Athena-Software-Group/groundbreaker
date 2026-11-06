"""native balances: the latest ETH reading of each freeze-watch wallet (app.freeze.native)

One row per watched wallet: the balance in wei (a string, so SQLite keeps it exact), the transaction count, the last
good reading, the last movement and the last failure. The downgrade drops the table; the readings are only the watch's
memory and the next pass starts it again.

Revision ID: 0013_native_balances
Revises: 0012_case_tasks
Create Date: 2026-11-06
"""

import sqlalchemy as sa
from alembic import op

import app.db.models  # noqa: F401 - custom column types referenced below
from app.db.models import UTCDateTime

revision = "0013_native_balances"
down_revision = "0012_case_tasks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_balances",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("cases.id", name="fk_native_balances_case_id_cases"), nullable=False),
        sa.Column("watch_id", sa.Integer(), sa.ForeignKey("freeze_watch.id", name="fk_native_balances_watch_id_freeze_watch"),
                  nullable=False),
        sa.Column("chain", sa.String(16), nullable=False),
        sa.Column("address", sa.String(128), nullable=False),
        sa.Column("wei", sa.String(80)),
        sa.Column("nonce", sa.Integer()),
        sa.Column("checked_at", UTCDateTime(timezone=True)),
        sa.Column("moved_at", UTCDateTime(timezone=True)),
        sa.Column("error", sa.String(64)),
        sa.Column("failed_at", UTCDateTime(timezone=True)),
        sa.UniqueConstraint("watch_id", name="uq_native_balances_watch_id"),
    )
    op.create_index("ix_native_balances_case_id", "native_balances", ["case_id"])


def downgrade() -> None:
    op.drop_index("ix_native_balances_case_id", table_name="native_balances")
    op.drop_table("native_balances")
