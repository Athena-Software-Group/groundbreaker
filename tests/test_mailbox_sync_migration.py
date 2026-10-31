"""Migration 0010_mailbox_status: up / down / up on SQLite, and an upgrade of a database created by main's head
(0009_freeze_checks) with mail data in it: existing rows keep their values (new columns NULL / false), the new
tables take rows, and the per-folder unique index refuses a message stored twice in one folder."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from alembic import command
from app.db.models import Base, MailMessage, MailSyncFolder, ReplyClassification

REPO_ROOT = Path(__file__).resolve().parents[1]
NEW_TABLES = {"mail_sync_folders", "reply_classifications"}
NEW_MAIL_COLUMNS = {"folder", "graph_conversation_id", "authority_key", "match_method", "outside_sent"}


def _cfg(connection) -> Config:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.attributes["connection"] = connection
    return cfg


def _tables(engine) -> set[str]:
    with engine.connect() as conn:
        return set(inspect(conn).get_table_names())


def _columns(engine, table: str) -> set[str]:
    with engine.connect() as conn:
        return {c["name"] for c in inspect(conn).get_columns(table)}


def _revision(engine) -> str:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def _no_drift(engine) -> None:
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    drift = [d for d in diff if not (isinstance(d, list) and d[0][0] == "modify_type"
                                     and d[0][2] == "transfers" and d[0][3] == "source")]
    assert drift == [], drift


@pytest.mark.filterwarnings("ignore:.*uq_cases_reference_lower")
def test_0010_up_down_up(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "0010_mailbox_status")
    assert _revision(engine) == "0010_mailbox_status" and NEW_TABLES <= _tables(engine)
    assert NEW_MAIL_COLUMNS <= _columns(engine, "mail_messages") and "mail_ai_consent" in _columns(engine, "cases")
    with engine.begin() as conn:
        command.downgrade(_cfg(conn), "0009_freeze_checks")
    assert _revision(engine) == "0009_freeze_checks" and not (NEW_TABLES & _tables(engine))
    assert not (NEW_MAIL_COLUMNS & _columns(engine, "mail_messages"))
    assert "mail_ai_consent" not in _columns(engine, "cases") and "freeze_checks" in _tables(engine)
    with engine.connect() as conn:  # 0009's own index survived the column drops
        assert conn.execute(text("SELECT count(*) FROM sqlite_master WHERE name = 'uq_mail_messages_letter_in_flight'")
                            ).scalar() == 1
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "0010_mailbox_status")
    assert NEW_TABLES <= _tables(engine)
    with engine.begin() as conn:  # the models describe head (0011 and later add to them): compared there
        command.upgrade(_cfg(conn), "head")
    _no_drift(engine)
    engine.dispose()


@pytest.mark.filterwarnings("ignore:.*uq_cases_reference_lower")
def test_upgrade_from_a_main_created_database(tmp_path):
    """A database at main's head (0009) with a case, a user, mail rows and the sync state upgrades in place."""
    engine = create_engine(f"sqlite:///{tmp_path / 'main.db'}")
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "0009_freeze_checks")
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO cases (id, reference, title, status, facts, ai_mode) "
                          "VALUES (1, 'MIG-0010', 't', 'open', '{}', 'redacted')"))
        conn.execute(text("INSERT INTO users (id, email, display_name, is_system_admin, can_create_cases, is_active) "
                          "VALUES (1, 'a@tests.example', 'A', 0, 0, 1)"))
        for n, (direction, status) in enumerate([("out", "sent_external"), ("in", "received")], start=1):
            conn.execute(text(
                "INSERT INTO mail_messages (id, case_id, direction, status, transport, mailbox, message_id, "
                "internet_message_id, to_addrs, cc_addrs, attachments, confirmations, match, attempts, meta) VALUES "
                f"({n}, 1, '{direction}', '{status}', 'graph', 'cases@mbx-demo.example', '<m{n}@mbx-demo.example>', "
                f"'<m{n}@mbx-demo.example>', '[]', '[]', '[]', '{{}}', '{{}}', 1, '{{}}')"))
        conn.execute(text("INSERT INTO mail_sync_state (mailbox, transport, delta_link, last_result) VALUES "
                          "('cases@mbx-demo.example', 'graph', 'https://graph.microsoft.com/v1.0/x?$deltatoken=1', '{}')"))
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    assert NEW_TABLES <= _tables(engine)
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT folder, outside_sent, match_method, authority_key FROM mail_messages "
                                 "ORDER BY id")).all()
        assert rows == [(None, 0, None, None), (None, 0, None, None)]
        assert conn.execute(text("SELECT mail_ai_consent FROM cases")).scalar() is None
        assert conn.execute(text("SELECT delta_link FROM mail_sync_state")).scalar().endswith("deltatoken=1")
    now = datetime.now(tz=UTC)
    with Session(engine) as db:
        db.add(MailSyncFolder(mailbox="cases@mbx-demo.example", folder="sentitems", since=now, last_result={}))
        db.add(ReplyClassification(case_id=1, mail_message_id=2, status="hold_placed", amount=Decimal("12633.77"),
                                   asset="USDT", account_refs=["T" + "1" * 33], quote="We have placed a hold.",
                                   rationale="hold phrase", source="rules", confidence=0.9))
        db.commit()
        rc = db.query(ReplyClassification).one()
        assert rc.applied is False and rc.created_at is not None
        assert rc.amount.quantize(Decimal("0.01")) == Decimal("12633.77")  # SQLite keeps Numeric as a float
        with pytest.raises(IntegrityError):  # one classification per mail message
            db.add(ReplyClassification(case_id=1, mail_message_id=2, status="unclear", account_refs=[], source="ai"))
            db.flush()
        db.rollback()
        mm = db.get(MailMessage, 1)
        mm.folder = "sentitems"
        db.commit()
        with pytest.raises(IntegrityError):  # a message is stored once per folder
            db.add(MailMessage(direction="out", status="sent_external", transport="graph",
                               mailbox="cases@mbx-demo.example", message_id="<m1@mbx-demo.example>",
                               internet_message_id="<m1@mbx-demo.example>", folder="sentitems", to_addrs=[],
                               cc_addrs=[], attachments=[], match={}, meta={}))
            db.flush()
        db.rollback()
        db.add(MailMessage(direction="in", status="unassigned", transport="graph", mailbox="cases@mbx-demo.example",
                           message_id="<m1@mbx-demo.example>", internet_message_id="<m1@mbx-demo.example>",
                           folder="inbox", to_addrs=[], cc_addrs=[], attachments=[], match={}, meta={}))
        db.commit()  # the same message in another folder (the mailbox Cc'd itself) is a row of its own
    with engine.begin() as conn:
        command.downgrade(_cfg(conn), "0009_freeze_checks")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM mail_messages")).scalar() == 3
        assert conn.execute(text("SELECT reference FROM cases")).scalar() == "MIG-0010"
    engine.dispose()
