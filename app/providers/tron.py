"""TronGrid provider (TRX + TRC-20, notably USDT-TRON which dominates laundering flows)."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import httpx

from app.db.models import Chain
from app.providers.base import ChainProvider, RawTransfer, TxDetail
from app.providers.prices import to_usd

BASE_URL = "https://api.trongrid.io"
USDT_TRC20 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


class TronProvider(ChainProvider):
    chain = Chain.TRON
    name = "trongrid"

    def __init__(self, api_key: str = "", client: httpx.Client | None = None):
        headers = {"TRON-PRO-API-KEY": api_key} if api_key else {}
        self.client = client or httpx.Client(timeout=20, headers=headers)

    @staticmethod
    def _ts(ms: int) -> datetime:
        return datetime.fromtimestamp(ms / 1000, tz=UTC)

    def _trc20(self, address: str, since: datetime | None, direction: str) -> list[RawTransfer]:
        params = {"limit": 200, "order_by": "block_timestamp,asc"}
        params["only_to" if direction == "in" else "only_from"] = "true"
        if since:
            params["min_timestamp"] = int(since.timestamp() * 1000)
        r = self.client.get(f"{BASE_URL}/v1/accounts/{address}/transactions/trc20", params=params)
        r.raise_for_status()
        out = []
        for row in r.json().get("data", []):
            info = row.get("token_info", {})
            dec = int(info.get("decimals", 6))
            sym = info.get("symbol", "TRC20")
            amt = Decimal(row["value"]) / Decimal(10**dec)
            out.append(
                RawTransfer(
                    chain=self.chain, tx_hash=row["transaction_id"], sub_index=1,
                    timestamp=self._ts(row["block_timestamp"]), from_address=row["from"],
                    to_address=row["to"], asset=sym, amount=amt, token_contract=info.get("address"),
                    amount_usd=to_usd(sym, amt), method="token_transfer",
                )
            )
        return out

    def _native(self, address: str, since: datetime | None, direction: str) -> list[RawTransfer]:
        params = {"limit": 200, "order_by": "block_timestamp,asc"}
        params["only_to" if direction == "in" else "only_from"] = "true"
        if since:
            params["min_timestamp"] = int(since.timestamp() * 1000)
        r = self.client.get(f"{BASE_URL}/v1/accounts/{address}/transactions", params=params)
        r.raise_for_status()
        out = []
        for row in r.json().get("data", []):
            for c in row.get("raw_data", {}).get("contract", []):
                if c.get("type") != "TransferContract":
                    continue
                v = c["parameter"]["value"]
                amt = Decimal(v.get("amount", 0)) / Decimal(10**6)
                out.append(
                    RawTransfer(
                        chain=self.chain, tx_hash=row["txID"], sub_index=0,
                        timestamp=self._ts(row["block_timestamp"]),
                        from_address=_hex_to_base58(v["owner_address"]),
                        to_address=_hex_to_base58(v["to_address"]), asset="TRX", amount=amt,
                        amount_usd=to_usd("TRX", amt),
                    )
                )
        return out

    def get_tx(self, tx_hash: str) -> TxDetail | None:
        r = self.client.post(f"{BASE_URL}/wallet/gettransactioninfobyid", json={"value": tx_hash})
        r.raise_for_status()
        info = r.json()
        if not info:
            return None
        ts = self._ts(info["blockTimeStamp"])
        transfers: list[RawTransfer] = []
        for i, lg in enumerate(info.get("log", [])):
            topics = lg.get("topics", [])
            if len(topics) == 3 and topics[0].endswith("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"):
                frm = _hex_to_base58("41" + topics[1][-40:])
                to = _hex_to_base58("41" + topics[2][-40:])
                amt = Decimal(int(lg["data"], 16)) / Decimal(10**6)
                contract = _hex_to_base58("41" + lg["address"][-40:])
                sym = "USDT" if contract == USDT_TRC20 else "TRC20"
                transfers.append(
                    RawTransfer(chain=self.chain, tx_hash=tx_hash, sub_index=i + 1, timestamp=ts,
                                from_address=frm, to_address=to, asset=sym, amount=amt,
                                token_contract=contract, amount_usd=to_usd(sym, amt),
                                block_number=info.get("blockNumber"), method="token_transfer")
                )
        return TxDetail(chain=self.chain, tx_hash=tx_hash, timestamp=ts,
                        block_number=info.get("blockNumber"), transfers=transfers)

    def outgoing_transfers(self, address, since=None, limit=200):
        rows = self._native(address, since, "out") + self._trc20(address, since, "out")
        rows.sort(key=lambda r: r.timestamp)
        return rows[:limit]

    def incoming_transfers(self, address, since=None, limit=200):
        rows = self._native(address, since, "in") + self._trc20(address, since, "in")
        rows.sort(key=lambda r: r.timestamp)
        return rows[:limit]


def _hex_to_base58(hex_addr: str) -> str:
    """TRON hex (41...) -> base58check. Small local implementation to avoid a dependency."""
    import hashlib

    raw = bytes.fromhex(hex_addr)
    chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    data = raw + chk
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = alphabet[rem] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + out
