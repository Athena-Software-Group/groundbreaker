"""Alembic migrations build the same schema as the models, and 0003 downgrades cleanly (SQLite)."""

from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from alembic import command
from app.db.models import Base

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_TABLES = {"users", "user_sessions", "webauthn_credentials", "case_members", "audit_events",
                    "correspondence", "evidence_items", "le_contacts", "notification_rules", "notifications"}
MAIL_TABLES = {"entity_channels", "sender_profiles", "mail_messages", "mail_sync_state"}  # 0008_mail


def _cfg(connection) -> Config:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.attributes["connection"] = connection
    return cfg


# SQLite cannot reflect the expression index uq_cases_reference_lower; test_case_reference_index checks it
@pytest.mark.filterwarnings("ignore:.*uq_cases_reference_lower")
def test_upgrade_downgrade_upgrade_matches_models(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    with engine.connect() as conn:
        tables = set(inspect(conn).get_table_names())
        assert WORKSPACE_TABLES <= tables
        assert MAIL_TABLES <= tables
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    # SQLite reflects the native enum of transfers.source as VARCHAR; nothing else may differ
    drift = [d for d in diff if not (isinstance(d, list) and d[0][0] == "modify_type"
                                     and d[0][2] == "transfers" and d[0][3] == "source")]
    assert drift == [], drift
    with engine.begin() as conn:  # 0008 down and up again
        command.downgrade(_cfg(conn), "0007_ai_messages")
    with engine.connect() as conn:
        tables = set(inspect(conn).get_table_names())
        assert not (MAIL_TABLES & tables) and "ai_messages" in tables
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    with engine.connect() as conn:
        assert MAIL_TABLES <= set(inspect(conn).get_table_names())
    with engine.begin() as conn:
        command.downgrade(_cfg(conn), "0002_blockscout")
    with engine.connect() as conn:
        tables = set(inspect(conn).get_table_names())
        assert not (WORKSPACE_TABLES & tables)
        assert "ai_mode" not in {c["name"] for c in inspect(conn).get_columns("cases")}
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    engine.dispose()


def test_case_reference_index_ignores_case(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'mig.db'}")
    with engine.begin() as conn:
        command.upgrade(_cfg(conn), "head")
    insert = text("INSERT INTO cases (reference, title, status, facts, ai_mode) VALUES (:r, 't', 'open', '{}', 'redacted')")
    with engine.begin() as conn:
        conn.execute(insert, {"r": "DEMO-2026-001"})
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(insert, {"r": "demo-2026-001"})
    engine.dispose()
