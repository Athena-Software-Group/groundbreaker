"""The sender of record is the deployment's own organisation: placeholders until AEGIS_ORG_NAME / AEGIS_SIGNATORY_NAME
are set (an open-source install never writes letters in someone else's name by default)."""

from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.domain import sender
from app.mail.config import MailSettings


@pytest.fixture
def fresh_settings(monkeypatch):
    def apply(**env):
        for k in ("AEGIS_ORG_NAME", "AEGIS_SIGNATORY_NAME", "AEGIS_MAIL_FROM_NAME"):
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        get_settings.cache_clear()
    yield apply
    get_settings.cache_clear()


def test_unconfigured_install_uses_placeholders(fresh_settings):
    fresh_settings()
    assert sender.org_name() == "Your Organisation" and sender.signatory_name() == "Investigations Desk"
    assert sender.ORG_NAME == "Your Organisation" and MailSettings(_env_file=None).from_name == "Your Organisation"


def test_configured_org_names_the_letters_and_the_from_header(fresh_settings):
    fresh_settings(AEGIS_ORG_NAME="Example Recovery Ltd", AEGIS_SIGNATORY_NAME="Example Desk")
    assert sender.org_name() == "Example Recovery Ltd" and sender.SIGNATORY_NAME == "Example Desk"
    assert MailSettings(_env_file=None).from_name == "Example Recovery Ltd"
    fresh_settings(AEGIS_ORG_NAME="Example Recovery Ltd", AEGIS_MAIL_FROM_NAME="Example Cases")
    assert MailSettings(_env_file=None).from_name == "Example Cases"
