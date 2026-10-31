"""Migration 0009_freeze_checks: up / down / up on SQLite, and an upgrade of a database created by main's
head (0008_mail) with data in it: the existing rows survive and the new tables take readings."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from alembic import command
from app.db.models import Base, FreezeCheck, FreezeSetting, FreezeWatch

REPO_ROOT = Path(__file__).resolve().parents[1]
USDT_ETH = "0xdac17f958d2ee523a2206206994597c13d831ec7"  # Tether USDT (Ethereum)
FREEZE_TABLES = {"freeze_settings", "freeze_watch", "freeze_checks"}


def _cfg(connection) -> Config:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.attributes["connection"] = connection
    return cfg


def _tables(engine) -> set[str]:
    with engine.connect() as conn:
        return set(inspect(conn).get_table_names())


def _head() -> str:
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(_cfg(None)).get_current_head()


def _revision(engine) -> str:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


@pytest.mark.filterwarnings("ignore:.*uq_cases_reference_lower")
def test_0009_up_down_up(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    # head is 0009 or a later revision (0010_mailbox_status): 0009's tables are there either way
    assert _revision(engine) == _head() and FREEZE_TABLES <= _tables(engine)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    drift = [d for d in diff if not (isinstance(d, list) and d[0][0] == "modify_type"
                                     and d[0][2] == "transfers" and d[0][3] == "source")]
    assert drift == [], drift
    with engine.begin() as conn:
        command.downgrade(_cfg(conn), "0008_mail")
    assert _revision(engine) == "0008_mail" and not (FREEZE_TABLES & _tables(engine))
    assert "mail_messages" in _tables(engine)
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    assert FREEZE_TABLES <= _tables(engine)
    engine.dispose()


@pytest.mark.filterwarnings("ignore:.*uq_cases_reference_lower")
def test_upgrade_from_a_main_created_database(tmp_path):
    """A database at main's head (0008) with a case, a user and a mail row upgrades in place."""
    engine = create_engine(f"sqlite:///{tmp_path / 'main.db'}")
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "0008_mail")
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO cases (id, reference, title, status, facts, ai_mode) "
                          "VALUES (1, 'MIG-0001', 't', 'open', '{}', 'redacted')"))
        conn.execute(text("INSERT INTO users (id, email, display_name, is_system_admin, can_create_cases, is_active) "
                          "VALUES (1, 'a@tests.example', 'A', 0, 0, 1)"))
        conn.execute(text("INSERT INTO mail_messages (case_id, direction, status, transport, mailbox, message_id, "
                          "to_addrs, cc_addrs, attachments, confirmations, match, attempts, meta) VALUES "
                          "(1, 'out', 'sent', 'file', 'cases@tests.example', '<m1@tests.example>', '[]', '[]', '[]', "
                          "'{}', '{}', 1, '{}')"))
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    assert FREEZE_TABLES <= _tables(engine)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT reference FROM cases")).scalar() == "MIG-0001"
        assert conn.execute(text("SELECT count(*) FROM mail_messages")).scalar() == 1
    now = datetime.now(tz=UTC)
    with Session(engine) as db:
        db.add(FreezeSetting(case_id=1, enabled=True, consent={"hosts": ["ethereum-rpc.publicnode.com"]},
                             last_result={}, enabled_by=1, enabled_at=now))
        w = FreezeWatch(case_id=1, chain="ethereum", address="0x" + "ab" * 20, tlp="TLP:GREEN", created_by=1)
        db.add(w)
        db.flush()
        db.add(FreezeCheck(case_id=1, chain="ethereum", address=w.address, issuer="Tether", token_symbol="USDT",
                           token_contract=USDT_ETH, blacklisted=True,
                           block_number=23_600_000_000, checked_at=now, raw_sha256="0" * 64, source="watched",
                           watch_id=w.id, meta={"balance_raw": "1"}))
        db.commit()
        row = db.query(FreezeCheck).one()
        assert row.status == "ok" and row.method == "rpc" and row.failed_count == 0  # server defaults
        assert row.block_number == 23_600_000_000 and row.checked_at.tzinfo is not None
        with pytest.raises(IntegrityError):  # one watched row per case, chain and address
            db.add(FreezeWatch(case_id=1, chain="ethereum", address="0x" + "ab" * 20))
            db.flush()
        db.rollback()
    with engine.begin() as conn:
        command.downgrade(_cfg(conn), "0008_mail")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT reference FROM cases")).scalar() == "MIG-0001"
    engine.dispose()


def _letter_index_sql(engine) -> str:
    with engine.connect() as conn:
        return conn.execute(text("SELECT sql FROM sqlite_master WHERE name = 'uq_mail_messages_letter_in_flight'")).scalar()


@pytest.mark.filterwarnings("ignore:.*uq_cases_reference_lower")
def test_0009_letter_index_covers_sent_external(tmp_path):
    """One e-mail per letter at the database: 0009 adds 'sent_external' (recorded as sent outside Aegis) to the
    0008 partial unique index; the downgrade restores the 0008 predicate."""
    engine = create_engine(f"sqlite:///{tmp_path / 'idx.db'}")
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "0008_mail")
    assert "sent_external" not in _letter_index_sql(engine)
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    assert "'sent_external'" in _letter_index_sql(engine)
    row = ("INSERT INTO mail_messages (case_id, direction, status, transport, mailbox, message_id, letter_key, "
           "to_addrs, cc_addrs, attachments, confirmations, match, attempts, meta) VALUES (1, 'out', :st, 'manual', "
           "'cases@tests.example', '', 'c7', '[]', '[]', '[]', '{}', '{}', 0, '{}')")
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO cases (id, reference, title, status, facts, ai_mode) "
                          "VALUES (1, 'MIG-0002', 't', 'open', '{}', 'redacted')"))
        conn.execute(text(row), {"st": "prepared"})
        conn.execute(text(row), {"st": "sent_external"})
    for st in ("sent_external", "sending"):
        with pytest.raises(IntegrityError, match="UNIQUE"), engine.begin() as conn:
            conn.execute(text(row), {"st": st})
    with engine.begin() as conn:
        command.downgrade(_cfg(conn), "0008_mail")
    assert "sent_external" not in _letter_index_sql(engine)
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    assert "'sent_external'" in _letter_index_sql(engine)
    engine.dispose()
