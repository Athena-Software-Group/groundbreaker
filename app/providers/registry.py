from __future__ import annotations

from functools import lru_cache

from app.core.config import get_settings
from app.db.models import Chain
from app.providers.base import ChainProvider, ProviderError


@lru_cache(maxsize=32)
def get_provider(chain: Chain, mode: str | None = None) -> ChainProvider:
    settings = get_settings()
    mode = mode or settings.provider_mode
    if mode == "fixture":
        from app.providers.fixture import FixtureProvider

        return FixtureProvider(chain)

    if chain in (Chain.ETHEREUM, Chain.ARBITRUM, Chain.BASE, Chain.BSC, Chain.POLYGON):
        from app.providers.etherscan import BlockscoutProvider, EtherscanProvider

        if settings.evm_provider == "blockscout" or (settings.evm_provider == "auto" and not settings.etherscan_api_key):
            return BlockscoutProvider(chain)
        return EtherscanProvider(settings.etherscan_api_key, chain)
    if chain == Chain.TRON:
        from app.providers.tron import TronProvider

        return TronProvider(settings.trongrid_api_key)
    if chain == Chain.BITCOIN:
        from app.providers.bitcoin import BitcoinProvider

        return BitcoinProvider(settings.mempool_base_url)
    raise ProviderError(f"No live provider for chain {chain}")
