"""freeze checks: on-chain issuer blacklist readings, watched wallets, per-case consent setting

On-chain freeze detection (app/freeze; docs/freeze-detection.md): `freeze_settings` (one row per case:
"On-chain freeze checks", off by default, with what the enabling admin consented to), `freeze_watch`
(wallets an investigator added for checking, case-scoped) and `freeze_checks` (one row per issuer
contract reading: blacklisted, balance, block, method, response hash, freeze time, failed transfers).
Plain VARCHAR / JSON / Boolean / BigInteger columns, so the same DDL runs on SQLite and PostgreSQL. The
downgrade drops the three tables (the readings are lost; nothing else refers to them).

It also widens the e-mail desk's one-e-mail-per-letter index `uq_mail_messages_letter_in_flight` (0008) to
the status 'sent_external' ("Draft — you send": a letter recorded as sent from Outlook), so a letter recorded
as sent outside Aegis blocks a second send or record at the database too. Before 0009 no row can hold that
status, so the wider index always builds; the downgrade restores the 0008 predicate.

Revision ID: 0009_freeze_checks
Revises: 0008_mail
Create Date: 2026-10-20
"""

import sqlalchemy as sa
from alembic import op

import app.db.models  # noqa: F401 - custom column types referenced below
from app.db.models import UTCDateTime

revision = "0009_freeze_checks"
down_revision = "0008_mail"
branch_labels = None
depends_on = None


IN_FLIGHT_0008 = "letter_key IS NOT NULL AND direction = 'out' AND status IN ('sending', 'sent', 'unknown')"
IN_FLIGHT_0009 = ("letter_key IS NOT NULL AND direction = 'out' "
                  "AND status IN ('sending', 'sent', 'unknown', 'sent_external')")


def _letter_index(where: str) -> None:
    op.drop_index("uq_mail_messages_letter_in_flight", table_name="mail_messages")
    op.create_index("uq_mail_messages_letter_in_flight", "mail_messages", ["letter_key"], unique=True,
                    sqlite_where=sa.text(where), postgresql_where=sa.text(where))


def _fk(table: str, col: str, ref: str) -> sa.ForeignKey:
    return sa.ForeignKey(f"{ref}.id", name=f"fk_{table}_{col}_{ref}")


def _ts(name: str, *, nullable: bool = True, now: bool = False) -> sa.Column:
    return sa.Column(name, UTCDateTime(timezone=True), nullable=nullable,
                     server_default=sa.func.now() if now else None)


def upgrade() -> None:
    t = "freeze_settings"
    op.create_table(
        t,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), _fk(t, "case_id", "cases"), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("consent", sa.JSON(), nullable=False),
        sa.Column("enabled_by", sa.Integer(), _fk(t, "enabled_by", "users"), nullable=True),
        _ts("enabled_at"),
        sa.Column("disabled_by", sa.Integer(), _fk(t, "disabled_by", "users"), nullable=True),
        _ts("disabled_at"),
        _ts("last_run_at"),
        sa.Column("last_result", sa.JSON(), nullable=False),
        _ts("run_started_at"),
        _ts("created_at", nullable=False, now=True),
        _ts("updated_at"),
    )
    op.create_index("ix_freeze_settings_case_id", t, ["case_id"], unique=True)

    t = "freeze_watch"
    op.create_table(
        t,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), _fk(t, "case_id", "cases"), nullable=False),
        sa.Column("chain", sa.String(16), nullable=False),
        sa.Column("address", sa.String(128), nullable=False),
        sa.Column("label", sa.String(255), nullable=True),
        sa.Column("source_note", sa.String(512), nullable=True),
        sa.Column("tlp", sa.String(32), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.Integer(), _fk(t, "created_by", "users"), nullable=True),
        _ts("created_at", nullable=False, now=True),
        sa.Column("removed_by", sa.Integer(), _fk(t, "removed_by", "users"), nullable=True),
        _ts("removed_at"),
        sa.UniqueConstraint("case_id", "chain", "address", name="uq_freeze_watch_case_chain_addr"),
    )
    op.create_index("ix_freeze_watch_case_id", t, ["case_id"])

    t = "freeze_checks"
    op.create_table(
        t,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("case_id", sa.Integer(), _fk(t, "case_id", "cases"), nullable=False),
        sa.Column("chain", sa.String(16), nullable=False),
        sa.Column("address", sa.String(128), nullable=False),
        sa.Column("issuer", sa.String(32), nullable=False),
        sa.Column("token_symbol", sa.String(16), nullable=False),
        sa.Column("token_contract", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="ok"),
        sa.Column("error", sa.String(64), nullable=True),
        sa.Column("blacklisted", sa.Boolean(), nullable=True),
        sa.Column("balance", sa.Numeric(38, 18), nullable=True),
        sa.Column("block_number", sa.BigInteger(), nullable=True),
        _ts("checked_at", nullable=False),
        sa.Column("method", sa.String(16), nullable=False, server_default="rpc"),
        sa.Column("raw_sha256", sa.String(64), nullable=True),
        sa.Column("freeze_tx_hash", sa.String(128), nullable=True),
        _ts("frozen_at"),
        sa.Column("frozen_at_basis", sa.String(16), nullable=True),
        sa.Column("first_failed_tx", sa.String(128), nullable=True),
        _ts("first_failed_at"),
        sa.Column("failed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source", sa.String(16), nullable=False, server_default="trace"),
        sa.Column("watch_id", sa.Integer(), _fk(t, "watch_id", "freeze_watch"), nullable=True),
        sa.Column("trigger", sa.String(16), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=False),
        _ts("created_at", nullable=False, now=True),
    )
    op.create_index("ix_freeze_checks_case_id", t, ["case_id"])
    op.create_index("ix_freeze_checks_case_wallet", t, ["case_id", "chain", "address", "checked_at"])

    _letter_index(IN_FLIGHT_0009)


def downgrade() -> None:
    _letter_index(IN_FLIGHT_0008)
    op.drop_index("ix_freeze_checks_case_wallet", table_name="freeze_checks")
    op.drop_index("ix_freeze_checks_case_id", table_name="freeze_checks")
    op.drop_table("freeze_checks")
    op.drop_index("ix_freeze_watch_case_id", table_name="freeze_watch")
    op.drop_table("freeze_watch")
    op.drop_index("ix_freeze_settings_case_id", table_name="freeze_settings")
    op.drop_table("freeze_settings")
