"""users.can_create_cases: case creation becomes a system-level permission

Until this revision any signed-in account could open a case (and so become its admin). Now only
system administrators and accounts with `can_create_cases` may. Existing accounts start without it;
a system administrator grants it at /admin/users or with `scripts/create_user.py --can-create-cases`.

Revision ID: 0005_user_can_create_cases
Revises: 0004_stop_order_released
Create Date: 2026-10-19
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_user_can_create_cases"
down_revision = "0004_stop_order_released"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("can_create_cases", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("can_create_cases")
