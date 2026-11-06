import hashlib
import hmac
import secrets
from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Database
    database_url: str = "postgresql+psycopg://aegis:aegis@localhost:5432/aegis"

    # Providers
    provider_mode: Literal["fixture", "live"] = "fixture"
    # auto = Etherscan when a key is present, otherwise Blockscout (keyless, Etherscan-compatible)
    evm_provider: Literal["auto", "etherscan", "blockscout"] = "auto"
    etherscan_api_key: str = ""
    trongrid_api_key: str = ""
    mempool_base_url: str = "https://mempool.space/api"
    # Offline fixture (provider_mode=fixture and seeding). Env: AEGIS_FIXTURE_PATH. Relative paths
    # resolve against the current directory first, then the repo root.
    aegis_fixture_path: str = "data/fixtures/demo_case.json"

    # Tracing
    # 12: the demo case's KuCoin deposit sits at hop 9 (the true root is five relay hops before the hub)
    trace_max_hops: int = 12
    trace_max_fanout: int = 25
    trace_min_taint_usd: float = 50.0

    # App — no secret has a usable default. APP_ENV other than "local" refuses to start while
    # APP_SECRET_KEY is unset or a placeholder (see insecure_settings). Users sign in with their own
    # accounts (scripts/create_user.py); the old shared BASIC_AUTH_* variables are ignored.
    app_secret_key: str = ""
    app_env: str = "local"
    # AEGIS_SHOW_ENV_BADGE=1: the header shows the environment line (env · providers · db), e.g. on a dev or staging
    # instance; off by default, so a demo or production screen carries no developer text
    aegis_show_env_badge: bool = False
    log_level: str = "INFO"
    # Sessions (docs/identity-spec.md §4): idle timeout and absolute lifetime
    session_idle_minutes: int = 30
    session_max_hours: int = 12
    # .docx exports. Relative paths resolve against the repo root; the default is gitignored.
    export_dir: str = "exports"

    # Evidence (app/domain/evidence.py). The vault holds uploaded originals as <case_id>/<uuid>; it
    # must be an absolute path outside the repository, ideally on an encrypted volume. Uploads are
    # refused while it is unset. Reference-mode imports from the web UI are limited to the
    # AEGIS_EVIDENCE_ROOTS directories (os.pathsep-separated); originals are hashed, never copied.
    aegis_vault_dir: str = ""
    aegis_evidence_roots: str = ""
    aegis_max_upload_mb: int = 200

    # Dev-only one-time sign-in link (GET /dev/login?token=…&email=…) for headless screenshots.
    # Honoured only when APP_ENV=local AND this is set to a token of 32+ characters; never set it
    # anywhere else. Each token works once per process (the route then refuses it).
    aegis_dev_login_token: str = ""

    # Who new letters come from by default (the sender of record, app.domain.sender): the organisation that
    # writes on behalf of each case's client, and who signs. The defaults are placeholders, so an install
    # that has not set them is obvious in its first letter.
    aegis_org_name: str = "Your Organisation"
    aegis_signatory_name: str = "Investigations Desk"

    # Case assistant model access (app/ai/providers.py; docs/guide.md "Case assistant"). Default: the
    # Hugging Face Inference Router (OpenAI-compatible) with the inference provider pinned in the
    # model id (":deepinfra"), so the data path is fixed. The token comes from HF_INFERENCE_TOKEN,
    # then HF_TOKEN, then LLM_API_KEY; HF_API_KEY is never read (it is reserved for the admin /
    # write token). AEGIS_AI_DISABLED=1 is the kill switch (read by app.ai.providers).
    aegis_llm_provider: Literal["hf_router", "hf_endpoint", "anthropic", "none"] = "hf_router"
    aegis_llm_base_url: str = "https://router.huggingface.co/v1"
    aegis_llm_model: str = "deepseek-ai/DeepSeek-V4.1-Flash:deepinfra"
    aegis_hf_bill_to: str = ""
    aegis_llm_timeout: float = 120.0
    aegis_llm_max_tokens: int = 6000
    aegis_llm_allow_any_host: str = ""  # "1" / "true" allows any base-URL host (see providers.ALLOWED_HOSTS)
    hf_inference_token: SecretStr = SecretStr("")
    hf_token: SecretStr = SecretStr("")
    llm_api_key: SecretStr = SecretStr("")

    # On-chain freeze detection (app/freeze; docs/freeze-detection.md). Nothing is sent unless a case
    # admin turns "On-chain freeze checks" on for the case (per-case consent, audited). The issuer
    # contracts are read with eth_call over JSON-RPC (Ethereum: publicnode by default; the other USDC
    # chains only once their RPC URL is set) and over TronGrid's triggerconstantcontract. Freeze times
    # come from the explorer's logs API (Etherscan when ETHERSCAN_API_KEY is set, else Blockscout).
    # Hosts outside app.freeze.transport.ALLOWED_HOSTS are refused.
    aegis_eth_rpc_url: str = "https://ethereum-rpc.publicnode.com"
    aegis_base_rpc_url: str = ""  # unset: USDC on Base is not checked
    aegis_arbitrum_rpc_url: str = ""
    aegis_polygon_rpc_url: str = ""
    aegis_optimism_rpc_url: str = ""
    aegis_trongrid_url: str = "https://api.trongrid.io"  # TRONGRID_API_KEY (above) is sent when set
    aegis_freeze_explorer: Literal["auto", "etherscan", "blockscout", "none"] = "auto"
    aegis_freeze_check_minutes: int = 360  # scheduler: minutes between passes per enabled case
    aegis_freeze_cache_minutes: float = 10.0  # identical requests within this window reuse the answer
    aegis_freeze_timeout: float = 15.0  # seconds per request
    aegis_freeze_retries: int = 3  # retries after HTTP 429 / 5xx / a timeout (exponential backoff)
    aegis_freeze_min_interval: float = 0.25  # seconds between two requests to the same host
    aegis_freeze_log_lookback_blocks: int = 500_000  # freeze-event search window when no earlier block is known
    aegis_freeze_checks_disabled: str = ""  # "1" / "true": deployment kill switch, no freeze-check request at all

    # Wallet owner lookups (app/attribution; docs/wallet-owners.md): public explorer tags (Blockscout's metadata
    # service and instances for EVM chains, Tronscan's account API for TRON). Nothing is sent unless a case admin
    # turns "Owner lookups" on for the case (per-case consent, audited); hosts outside
    # app.attribution.explorer.ALLOWED_DOMAINS are refused. Tronscan needs TRONSCAN_API_KEY (a header).
    tronscan_api_key: str = ""
    aegis_owner_metadata_url: str = "https://metadata.services.blockscout.com"
    aegis_owner_tronscan_url: str = "https://apilist.tronscanapi.com"
    aegis_owner_cache_hours: float = 168.0  # a wallet looked up more recently is not asked again (unless forced)
    aegis_owner_max_wallets: int = 25  # wallets per lookup run (largest balances first)
    aegis_owner_lookups_disabled: str = ""  # "1" / "true": deployment kill switch, no owner lookup at all
    aegis_owner_lookups_auto: str = "1"  # each trace run (and the scheduler) looks up its wallets' owners; "0" = manual

    @property
    def freeze_checks_disabled(self) -> bool:
        return self.aegis_freeze_checks_disabled.strip().lower() in ("1", "true", "yes", "on")

    @property
    def owner_lookups_disabled(self) -> bool:
        return self.aegis_owner_lookups_disabled.strip().lower() in ("1", "true", "yes", "on")

    @property
    def owner_lookups_auto(self) -> bool:
        return self.aegis_owner_lookups_auto.strip().lower() not in ("0", "false", "no", "off", "")

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def is_local(self) -> bool:
        return self.app_env == "local"

    @property
    def signing_key(self) -> bytes:
        """HMAC key for CSRF tokens. Unset in local: a per-process random key (tokens reset on restart)."""
        return self.app_secret_key.encode() if self.app_secret_key else _EPHEMERAL_KEY

    def derived_key(self, purpose: str) -> str:
        """A per-purpose key derived from signing_key ("csrf", "session", …), hex-encoded."""
        return hmac.new(self.signing_key, f"aegis:{purpose}".encode(), hashlib.sha256).hexdigest()


_EPHEMERAL_KEY = secrets.token_bytes(32)
# placeholders shipped in .env.example / docker-compose / older docs — never valid outside local
PLACEHOLDER_SECRETS = {
    "", "change_me", "change-me", "changeme", "change-me-before-aws", "athena", "aegis", "admin", "password",
}


def insecure_settings(settings: Settings) -> list[str]:
    """Human-readable problems with the configured secrets (empty list = OK)."""
    problems = []
    key = settings.app_secret_key.strip()
    if key.lower() in PLACEHOLDER_SECRETS:
        problems.append("APP_SECRET_KEY is unset or a placeholder")
    elif len(key) < 32:
        problems.append("APP_SECRET_KEY is shorter than 32 characters")
    if ":aegis@" in settings.database_url or ":change_me@" in settings.database_url.lower():
        problems.append("DATABASE_URL uses the local-dev placeholder password")
    return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
