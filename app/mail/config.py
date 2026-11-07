"""Mail settings (AEGIS_MAIL_*, AEGIS_M365_*), read fresh on every call like notify.NotifySettings.

Nothing here is ever rendered as-is: templates and audit rows get `describe()` (ids masked, the
secret as configured yes/no). The client secret is a SecretStr and never leaves this process except
in the token request body to the Microsoft identity platform (app/mail/graph.py).

Host allow-list: the Graph base must be https://graph.microsoft.com/… and the login host
https://login.microsoftonline.com; anything else makes the graph transport "not configured"
(`host_problem`).

Test-only override (a local mock of Graph, never a real tenant): `AEGIS_M365_TEST_GRAPH_BASE` and
`AEGIS_M365_TEST_LOGIN_HOST` replace both hosts, and are honoured only with `APP_ENV=local` and a URL on
`http(s)://127.0.0.1:<port>` (no credentials, query or fragment). Set anywhere else, or to any other host,
they make the transport "not configured" (fail closed: Aegis never falls back to the real hosts while an
override is set). Both must be set together.
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.config import get_settings

GRAPH_HOST = "graph.microsoft.com"
LOGIN_HOST = "login.microsoftonline.com"
TRUTHY = {"1", "true", "yes", "on"}
TEST_HOST = "127.0.0.1"  # the only host a test override may name (APP_ENV=local only)


class MailSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # manual (default): Aegis drafts the e-mail, a person sends it from the mailbox's own mail client
    # ("Draft — you send"); file: local demo .eml folders; graph: Microsoft 365 (on hold, optional);
    # none: no e-mail desk output at all
    aegis_mail_transport: Literal["manual", "none", "file", "graph"] = "manual"
    aegis_mail_from: str = ""
    aegis_mail_from_name: str = ""  # empty = the organisation name (AEGIS_ORG_NAME)
    aegis_mail_footer: str = ""  # one line every outgoing e-mail ends with, after the signature; empty = none
    aegis_mail_outbox_dir: str = ""
    aegis_mail_inbox_dir: str = ""
    aegis_mail_inbound: bool = False
    aegis_mail_inbound_since: str = ""  # ISO; empty = time of the first sync
    aegis_mail_max_message_bytes: int = 2_900_000
    aegis_mail_max_inbound_bytes: int = 25 * 1024 * 1024
    aegis_mail_send_per_hour: int = 20
    aegis_mail_send_per_hour_global: int = 60
    aegis_mail_test_sends_per_hour: int = 5
    aegis_mail_timeout: float = 30.0
    aegis_mail_dev_allowed_domains: str = "example.com,example.org,example.net,example"
    aegis_mail_live_sending: bool = False  # the owner's go-live: the case mailbox sends anywhere, as the mailbox does
    aegis_m365_tenant_id: str = ""
    aegis_m365_client_id: str = ""
    aegis_m365_client_secret: SecretStr = SecretStr("")
    aegis_m365_client_cert_path: str = ""  # reserved (D4): certificate auth needs `cryptography`
    aegis_m365_graph_base: str = "https://graph.microsoft.com/v1.0"
    aegis_m365_login_host: str = "https://login.microsoftonline.com"
    # test only (module doc): a local mock of Graph and the login host; APP_ENV=local and 127.0.0.1 only
    aegis_m365_test_graph_base: str = ""
    aegis_m365_test_login_host: str = ""
    app_env: str = "local"  # APP_ENV, as app.core.config reads it

    @field_validator("aegis_mail_transport", mode="before")
    @classmethod
    def _lower_transport(cls, v):
        if isinstance(v, str):
            return v.strip().lower() or "manual"  # AEGIS_MAIL_TRANSPORT= (empty) is the default too
        return v

    @field_validator("aegis_mail_inbound", mode="before")
    @classmethod
    def _bool_on(cls, v):
        if isinstance(v, str):
            return v.strip().lower() in TRUTHY
        return v

    # ---------------------------------------------------------------- derived values
    @property
    def mail_from(self) -> str:
        return self.aegis_mail_from.strip().lower()

    @property
    def mail_domain(self) -> str:
        return self.mail_from.rpartition("@")[2] if "@" in self.mail_from else ""

    @property
    def from_name(self) -> str:
        return (self.aegis_mail_from_name or "").strip() or get_settings().aegis_org_name.strip() or "Your Organisation"

    @property
    def footer(self) -> str:
        """AEGIS_MAIL_FOOTER on one line (whitespace collapsed), or empty."""
        return " ".join((self.aegis_mail_footer or "").split())

    @property
    def dev_allowed_domains(self) -> set[str]:
        return {d.strip().lower().lstrip("@") for d in self.aegis_mail_dev_allowed_domains.split(",") if d.strip()}

    @property
    def test_override(self) -> bool:
        """A test override of the Graph / login hosts is set (honoured only when `test_override_problem` is None)."""
        return bool(self.aegis_m365_test_graph_base.strip() or self.aegis_m365_test_login_host.strip())

    @property
    def test_override_problem(self) -> str | None:
        """Why a set test override is refused (None = honoured, or none set)."""
        if not self.test_override:
            return None
        # exactly APP_ENV=local, the predicate the rest of the app uses (app.core.config.Settings.is_local):
        # "Local" / " local " mean production guards elsewhere, so never the mock host here either
        from app.core.config import get_settings

        if self.app_env != "local" or not get_settings().is_local:
            return "AEGIS_M365_TEST_GRAPH_BASE / AEGIS_M365_TEST_LOGIN_HOST are honoured only with APP_ENV=local"
        for label, url in (("AEGIS_M365_TEST_GRAPH_BASE", self.aegis_m365_test_graph_base.strip()),
                           ("AEGIS_M365_TEST_LOGIN_HOST", self.aegis_m365_test_login_host.strip())):
            parts = urlsplit(url)
            try:
                port = parts.port
            except ValueError:
                port = None
            if parts.scheme not in ("http", "https") or parts.hostname != TEST_HOST or port is None \
                    or parts.username or parts.password or parts.query or parts.fragment:
                return f"host not allowed: {label} must be http(s)://{TEST_HOST}:<port> (local tests only)"
        return None

    @property
    def graph_base(self) -> str:
        if self.test_override and self.test_override_problem is None:
            return self.aegis_m365_test_graph_base.strip().rstrip("/")
        return self.aegis_m365_graph_base.strip().rstrip("/")

    @property
    def login_base(self) -> str:
        if self.test_override and self.test_override_problem is None:
            return self.aegis_m365_test_login_host.strip().rstrip("/")
        return self.aegis_m365_login_host.strip().rstrip("/")

    def graph_link_allowed(self, url: str) -> bool:
        """A nextLink / deltaLink may be followed: on the Graph host (or, under the test override, on exactly the
        override's scheme, host and port)."""
        parts = urlsplit(url or "")
        if self.test_override:
            if self.test_override_problem is not None:
                return False
            base = urlsplit(self.graph_base)
            try:
                return (parts.scheme, parts.hostname, parts.port) == (base.scheme, base.hostname, base.port) \
                    and not (parts.username or parts.password)
            except ValueError:
                return False
        return parts.scheme == "https" and (parts.hostname or "").lower() == GRAPH_HOST

    @property
    def max_message_bytes(self) -> int:
        return max(1, int(self.aegis_mail_max_message_bytes))

    @property
    def max_inbound_bytes(self) -> int:
        return max(1, int(self.aegis_mail_max_inbound_bytes))

    @property
    def secret_configured(self) -> bool:
        return bool(self.aegis_m365_client_secret.get_secret_value().strip())

    @property
    def host_problem(self) -> str | None:
        """Why the configured Graph / login hosts are refused (None = both allowed)."""
        if self.test_override:
            return self.test_override_problem
        for label, url, host in (("AEGIS_M365_GRAPH_BASE", self.graph_base, GRAPH_HOST),
                                 ("AEGIS_M365_LOGIN_HOST", self.login_base, LOGIN_HOST)):
            parts = urlsplit(url)
            if parts.scheme != "https" or (parts.hostname or "").lower() != host or parts.port not in (None, 443) \
                    or parts.username or parts.password or parts.query or parts.fragment:
                return f"host not allowed: {label} must be https://{host}"
        return None

    def graph_problem(self) -> str | None:
        """Why the graph transport is not usable (None = configured)."""
        if self.aegis_m365_client_cert_path.strip():
            return "certificate auth needs the `cryptography` package (owner decision); unset AEGIS_M365_CLIENT_CERT_PATH"
        missing = [name for name, value in (
            ("AEGIS_M365_TENANT_ID", self.aegis_m365_tenant_id.strip()),
            ("AEGIS_M365_CLIENT_ID", self.aegis_m365_client_id.strip()),
            ("AEGIS_M365_CLIENT_SECRET", self.secret_configured),
            ("AEGIS_MAIL_FROM", self.mail_from),
        ) if not value]
        if missing:
            return "not configured: set " + ", ".join(missing)
        return self.host_problem


def mail_settings() -> MailSettings:
    """Fresh settings (env / .env), so a deployment can change them without a restart."""
    return MailSettings()


def mask_id(value: str | None) -> str:
    """'00000000-1111-2222-3333-444455556666' -> '0000…6666' (first 4 and last 4 characters)."""
    v = (value or "").strip()
    if not v:
        return "—"
    return v if len(v) <= 8 else f"{v[:4]}…{v[-4:]}"


def describe(settings: MailSettings | None = None) -> dict:
    """What the admin page may show: no secret, no full ids, no paths."""
    s = settings or mail_settings()
    return {
        "transport": s.aegis_mail_transport,
        "mailbox": s.mail_from or None,
        "from_name": s.from_name,
        "tenant": mask_id(s.aegis_m365_tenant_id),
        "client": mask_id(s.aegis_m365_client_id),
        "secret_configured": s.secret_configured,
        "cert_path_set": bool(s.aegis_m365_client_cert_path.strip()),
        "graph_host": urlsplit(s.graph_base).hostname,
        "login_host": urlsplit(s.login_base).hostname,
        "host_problem": s.host_problem,
        "test_override": s.test_override,
        "max_message_bytes": s.max_message_bytes,
        "max_inbound_bytes": s.max_inbound_bytes,
        "send_per_hour": s.aegis_mail_send_per_hour,
        "send_per_hour_global": s.aegis_mail_send_per_hour_global,
        "test_sends_per_hour": s.aegis_mail_test_sends_per_hour,
        "dev_allowed_domains": sorted(s.dev_allowed_domains),
        "live_sending": bool(s.aegis_mail_live_sending),
        "outbox_set": bool(s.aegis_mail_outbox_dir.strip()),
        "inbox_set": bool(s.aegis_mail_inbox_dir.strip()),
        "inbound": s.aegis_mail_inbound,
        "inbound_since": s.aegis_mail_inbound_since.strip() or None,
        "timeout": s.aegis_mail_timeout,
    }
