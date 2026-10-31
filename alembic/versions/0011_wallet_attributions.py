"""wallet owners and evidence intel: wallet_attributions and the per-case owner-lookup / "AI reads evidence" consents

Wallet owner identification (app/attribution; docs/wallet-owners.md):

* `wallet_attributions`: who owns a wallet of a case, append-only (the latest row per wallet and source counts): a
  person's attribution (`source` manual, always wins) or a public explorer lookup (`source` explorer: tags, activity
  counters, hosts and response hashes in `detail`).
* `cases.owner_lookup_consent`: the per-case "Owner lookups" consent (NULL = off, the default): the hosts a case admin
  agreed may receive the case's wallet addresses.
* `cases.evidence_ai_consent` (app/evidence_intel; docs/evidence-intel.md): the per-case "AI reads evidence" consent
  (NULL = off, the default): the data path and model a case admin agreed may receive the text of the case's evidence
  documents. The reading itself lives in `evidence_items.meta["intel"]` and the extracted text in the evidence vault.

Plain VARCHAR / JSON columns, so the same DDL runs on SQLite and PostgreSQL. Existing cases keep NULL (off). The
downgrade drops the table (the attributions are lost; nothing refers to them) and the columns (SQLite ≥ 3.35 drops a
plain column natively).

Revision ID: 0011_wallet_attributions
Revises: 0010_mailbox_status
Create Date: 2026-10-21
"""

import sqlalchemy as sa
from alembic import op

import app.db.models  # noqa: F401 - custom column types referenced below
from app.db.models import UTCDateTime

revision = "0011_wallet_attributions"
down_revision = "0010_mailbox_status"
branch_labels = None
depends_on = None


def _fk(table: str, col: str, ref: str) -> sa.ForeignKey:
    return sa.ForeignKey(f"{ref}.id", name=f"fk_{table}_{col}_{ref}")


def upgrade() -> None:
    op.add_column("cases", sa.Column("owner_lookup_consent", sa.JSON(), nullable=True))
    op.add_column("cases", sa.Column("evidence_ai_consent", sa.JSON(), nullable=True))
    t = "wallet_attributions"
    op.create_table(
        t,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), _fk(t, "case_id", "cases"), nullable=False),
        sa.Column("chain", sa.String(16), nullable=False),
        sa.Column("address", sa.String(128), nullable=False),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("kind", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("confidence", sa.String(1), nullable=False, server_default="M"),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.Integer(), _fk(t, "created_by", "users"), nullable=True),
        sa.Column("created_at", UTCDateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_wallet_attributions_case_id", t, ["case_id"])
    op.create_index("ix_wallet_attributions_case_wallet", t, ["case_id", "chain", "address"])


def downgrade() -> None:
    op.drop_index("ix_wallet_attributions_case_wallet", table_name="wallet_attributions")
    op.drop_index("ix_wallet_attributions_case_id", table_name="wallet_attributions")
    op.drop_table("wallet_attributions")
    op.drop_column("cases", "evidence_ai_consent")
    op.drop_column("cases", "owner_lookup_consent")
