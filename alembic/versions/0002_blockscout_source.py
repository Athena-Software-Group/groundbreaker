"""add BLOCKSCOUT to the datasource enum

Revision ID: 0002_blockscout
Revises: 0be4960645f2
Create Date: 2026-10-19
"""

from alembic import op

revision = "0002_blockscout"
down_revision = "0be4960645f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # ALTER TYPE ... ADD VALUE cannot run inside a transaction block on older PG; autocommit it
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE datasource ADD VALUE IF NOT EXISTS 'BLOCKSCOUT'")
    # SQLite stores enums as plain VARCHAR with a CHECK constraint only when native_enum=False;
    # SQLAlchemy's default Enum on SQLite is an unconstrained VARCHAR, so nothing to do.


def downgrade() -> None:
    # Postgres cannot drop a single enum value; leave it in place.
    pass
