"""Etherscan V2 provider — one API key, every supported EVM chain via `chainid`.

Docs: https://docs.etherscan.io/etherscan-v2
Rate limits on the free tier are 5 req/s; we keep calls sequential and small.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from decimal import Decimal

import httpx

from app.db.models import Chain
from app.providers.base import AddressInfo, ChainProvider, ProviderError, RawTransfer, TxDetail
from app.providers.prices import to_usd

log = logging.getLogger(__name__)

CHAIN_IDS: dict[Chain, int] = {
    Chain.ETHEREUM: 1,
    Chain.ARBITRUM: 42161,
    Chain.BASE: 8453,
    Chain.BSC: 56,
    Chain.POLYGON: 137,
}
NATIVE_SYMBOL: dict[Chain, str] = {
    Chain.ETHEREUM: "ETH",
    Chain.ARBITRUM: "ETH",
    Chain.BASE: "ETH",
    Chain.BSC: "BNB",
    Chain.POLYGON: "MATIC",
}

BASE_URL = "https://api.etherscan.io/v2/api"


class EtherscanProvider(ChainProvider):
    name = "etherscan"

    base_url = BASE_URL
    min_interval = 0.21  # Etherscan free tier: 5 req/s

    def __init__(self, api_key: str, chain: Chain = Chain.ETHEREUM, client: httpx.Client | None = None):
        if chain not in CHAIN_IDS:
            raise ProviderError(f"{chain} not supported by Etherscan V2 adapter")
        if not api_key and self.name == "etherscan":
            raise ProviderError("ETHERSCAN_API_KEY is required for the Etherscan provider (or use EVM_PROVIDER=blockscout)")
        self.chain = chain
        self.chain_id = CHAIN_IDS[chain]
        self.api_key = api_key
        self.client = client or httpx.Client(timeout=30)
        self._last_call = 0.0

    def _auth_params(self) -> dict:
        return {"chainid": self.chain_id, "apikey": self.api_key}

    # ------------------------------------------------------------------ helpers
    def normalise(self, address: str) -> str:
        return address.strip().lower()

    def _get(self, **params) -> list | dict:
        # crude 5 req/s throttle
        elapsed = time.monotonic() - self._last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        params.update(self._auth_params())
        r = self.client.get(self.base_url, params=params)
        self._last_call = time.monotonic()
        r.raise_for_status()
        data = r.json()
        if data.get("status") == "0" and data.get("message") not in ("No transactions found",):
            result = str(data.get("result", ""))
            if "rate limit" in result.lower():
                raise ProviderError(f"{self.name} rate limit: {result}")
            if "api key" in result.lower():
                raise ProviderError(f"{self.name}: {result}")
            return []
        return data.get("result", [])

    @staticmethod
    def _ts(v: str | int) -> datetime:
        return datetime.fromtimestamp(int(v), tz=UTC)

    def _native_rows(self, address: str, since: datetime | None, direction: str) -> list[RawTransfer]:
        rows = self._get(module="account", action="txlist", address=address, sort="asc", page=1, offset=1000)
        out: list[RawTransfer] = []
        sym = NATIVE_SYMBOL[self.chain]
        for row in rows:
            if row.get("isError") == "1" or int(row.get("value", "0")) == 0:
                continue
            ts = self._ts(row["timeStamp"])
            if since and ts < since:
                continue
            frm, to = row["from"].lower(), (row.get("to") or "").lower()
            if direction == "out" and frm != address:
                continue
            if direction == "in" and to != address:
                continue
            amt = Decimal(row["value"]) / Decimal(10**18)
            out.append(
                RawTransfer(
                    chain=self.chain, tx_hash=row["hash"], sub_index=0, timestamp=ts,
                    from_address=frm, to_address=to, asset=sym, amount=amt,
                    block_number=int(row["blockNumber"]), amount_usd=to_usd(sym, amt),
                    method=row.get("functionName", "").split("(")[0] or "transfer",
                )
            )
        return out

    def _token_rows(self, address: str, since: datetime | None, direction: str) -> list[RawTransfer]:
        rows = self._get(module="account", action="tokentx", address=address, sort="asc", page=1, offset=1000)
        out: list[RawTransfer] = []
        for row in rows:
            ts = self._ts(row["timeStamp"])
            if since and ts < since:
                continue
            frm, to = row["from"].lower(), row["to"].lower()
            if direction == "out" and frm != address:
                continue
            if direction == "in" and to != address:
                continue
            dec = int(row.get("tokenDecimal") or 18)
            amt = Decimal(row["value"]) / Decimal(10**dec)
            sym = row.get("tokenSymbol") or "TOKEN"
            out.append(
                RawTransfer(
                    chain=self.chain, tx_hash=row["hash"], sub_index=int(row.get("logIndex") or 0) + 1,
                    timestamp=ts, from_address=frm, to_address=to, asset=sym, amount=amt,
                    block_number=int(row["blockNumber"]), token_contract=row["contractAddress"].lower(),
                    amount_usd=to_usd(sym, amt), method="token_transfer",
                )
            )
        return out

    # ------------------------------------------------------------------ interface
    def get_tx(self, tx_hash: str) -> TxDetail | None:
        tx = self._get(module="proxy", action="eth_getTransactionByHash", txhash=tx_hash)
        if not tx:
            return None
        receipt = self._get(module="proxy", action="eth_getTransactionReceipt", txhash=tx_hash)
        block = self._get(module="proxy", action="eth_getBlockByNumber", tag=tx["blockNumber"], boolean="false")
        ts = self._ts(int(block["timestamp"], 16))
        transfers: list[RawTransfer] = []
        value = Decimal(int(tx["value"], 16)) / Decimal(10**18)
        sym = NATIVE_SYMBOL[self.chain]
        if value > 0:
            transfers.append(
                RawTransfer(
                    chain=self.chain, tx_hash=tx_hash, sub_index=0, timestamp=ts,
                    from_address=tx["from"].lower(), to_address=(tx.get("to") or "").lower(),
                    asset=sym, amount=value, block_number=int(tx["blockNumber"], 16),
                    amount_usd=to_usd(sym, value),
                )
            )
        # ERC-20 Transfer(address,address,uint256) logs
        topic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        for lg in (receipt or {}).get("logs", []):
            if lg.get("topics", [None])[0] != topic0 or len(lg["topics"]) < 3:
                continue
            frm = "0x" + lg["topics"][1][-40:]
            to = "0x" + lg["topics"][2][-40:]
            raw = int(lg["data"], 16)
            # decimals unknown from receipt alone; assume 6 for USDC/USDT contracts, else 18
            contract = lg["address"].lower()
            dec, sym = _known_token(contract)
            amt = Decimal(raw) / Decimal(10**dec)
            transfers.append(
                RawTransfer(
                    chain=self.chain, tx_hash=tx_hash, sub_index=int(lg["logIndex"], 16) + 1, timestamp=ts,
                    from_address=frm, to_address=to, asset=sym, amount=amt,
                    block_number=int(tx["blockNumber"], 16), token_contract=contract,
                    amount_usd=to_usd(sym, amt), method="token_transfer",
                )
            )
        status = "success" if (receipt or {}).get("status") == "0x1" else "failed"
        return TxDetail(chain=self.chain, tx_hash=tx_hash, timestamp=ts,
                        block_number=int(tx["blockNumber"], 16), transfers=transfers, status=status)

    def outgoing_transfers(self, address, since=None, limit=200):
        a = self.normalise(address)
        rows = self._native_rows(a, since, "out") + self._token_rows(a, since, "out")
        rows.sort(key=lambda r: (r.timestamp, r.sub_index))
        return rows[:limit]

    def incoming_transfers(self, address, since=None, limit=200):
        a = self.normalise(address)
        rows = self._native_rows(a, since, "in") + self._token_rows(a, since, "in")
        rows.sort(key=lambda r: (r.timestamp, r.sub_index))
        return rows[:limit]

    def address_info(self, address: str) -> AddressInfo:
        a = self.normalise(address)
        code = self._get(module="proxy", action="eth_getCode", address=a, tag="latest")
        is_contract = isinstance(code, str) and code not in ("0x", "")
        return AddressInfo(chain=self.chain, address=a, is_contract=is_contract)


_TOKENS_MAINNET = {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": (6, "USDC"),
    "0xdac17f958d2ee523a2206206994597c13d831ec7": (6, "USDT"),
    "0x6b175474e89094c44da98b954eedeac495271d0f": (18, "DAI"),
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": (18, "WETH"),
}


def _known_token(contract: str) -> tuple[int, str]:
    return _TOKENS_MAINNET.get(contract.lower(), (18, "TOKEN"))


# --------------------------------------------------------------------------- Blockscout
BLOCKSCOUT_URLS: dict[Chain, str] = {
    Chain.ETHEREUM: "https://eth.blockscout.com/api",
    Chain.ARBITRUM: "https://arbitrum.blockscout.com/api",
    Chain.BASE: "https://base.blockscout.com/api",
    Chain.POLYGON: "https://polygon.blockscout.com/api",
}


class BlockscoutProvider(EtherscanProvider):
    """Blockscout's Etherscan-compatible API: same `module`/`action` surface, **no API key**.

    Verified against eth.blockscout.com on 19 Oct 2026 for txlist / tokentx / balance.
    Use it as the default EVM source; keep Etherscan for labels/higher throughput once a key exists.
    Note: Blockscout's tokentx also returns ERC-20 *scam tokens* (homoglyph "ETH" etc.) used in
    address-poisoning — the tracer treats unknown symbols as non-valued (no USD) so they do not
    carry taint.
    """

    name = "blockscout"
    min_interval = 0.35

    def __init__(self, chain: Chain = Chain.ETHEREUM, client: httpx.Client | None = None, base_url: str | None = None):
        if chain not in BLOCKSCOUT_URLS and not base_url:
            raise ProviderError(f"{chain} not supported by the Blockscout adapter")
        super().__init__(api_key="", chain=chain, client=client)
        self.base_url = base_url or BLOCKSCOUT_URLS[chain]

    def _auth_params(self) -> dict:
        return {}
