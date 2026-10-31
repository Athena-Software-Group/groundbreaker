"""cases.reference: unique ignoring case

A case reference also names the case's evidence directory under a plain AEGIS_EVIDENCE_ROOTS root,
and macOS file systems ignore case, so 'demo-2026-001' must not exist next to 'DEMO-2026-001'.
app.services.check_new_reference refuses such a reference; this index backs it up in the database.
The upgrade fails if two existing references already differ only by case (rename one first).

Revision ID: 0006_case_reference_ci
Revises: 0005_user_can_create_cases
Create Date: 2026-10-19
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_case_reference_ci"
down_revision = "0005_user_can_create_cases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("uq_cases_reference_lower", "cases", [sa.text("lower(reference)")], unique=True)


def downgrade() -> None:
    op.drop_index("uq_cases_reference_lower", table_name="cases")
