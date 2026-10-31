"""add RELEASED to the stoporderstatus enum

A frozen stop order can be released (funds returned or the hold lifted). Until this revision the
authorities desk recorded `released` only as `identifiers.hold.state`; app.domain.correspondence
switches to the real member automatically once it exists.

Revision ID: 0004_stop_order_released
Revises: 0003_case_workspace
Create Date: 2026-10-19
"""

from alembic import op

revision = "0004_stop_order_released"
down_revision = "0003_case_workspace"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # the native enum stores member names; ADD VALUE must run outside a transaction block
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE stoporderstatus ADD VALUE IF NOT EXISTS 'RELEASED'")
    # SQLite: SQLAlchemy's Enum is an unconstrained VARCHAR there, so nothing to do.


def downgrade() -> None:
    # Postgres cannot drop one enum value, so the value stays in the type; released orders fall
    # back to frozen (the desk also keeps `released` in identifiers.hold.state, so nothing is lost).
    op.execute("UPDATE stop_orders SET status = 'FROZEN' WHERE status = 'RELEASED'")
