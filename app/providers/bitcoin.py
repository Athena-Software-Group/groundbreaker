"""Bitcoin provider via the mempool.space REST API (Esplora-compatible).

UTXO model: each output is a `RawTransfer` from the (first) input address to the
output address. Multi-input coinjoin-style transactions are flagged so the
tracer applies a confidence haircut.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import httpx

from app.db.models import Chain
from app.providers.base import ChainProvider, RawTransfer, TxDetail
from app.providers.prices import to_usd

SATS = Decimal(10**8)


class BitcoinProvider(ChainProvider):
    chain = Chain.BITCOIN
    name = "mempool"

    def __init__(self, base_url: str = "https://mempool.space/api", client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx.Client(timeout=20)

    def _tx_to_transfers(self, tx: dict) -> list[RawTransfer]:
        ts = datetime.fromtimestamp(tx["status"].get("block_time", 0), tz=UTC)
        inputs = [vin.get("prevout", {}).get("scriptpubkey_address") for vin in tx.get("vin", [])]
        inputs = [i for i in inputs if i]
        primary_in = inputs[0] if inputs else "coinbase"
        multi = len(set(inputs)) > 1
        out: list[RawTransfer] = []
        for i, vout in enumerate(tx.get("vout", [])):
            addr = vout.get("scriptpubkey_address")
            if not addr:
                continue
            amt = Decimal(vout["value"]) / SATS
            out.append(
                RawTransfer(
                    chain=self.chain, tx_hash=tx["txid"], sub_index=i, timestamp=ts,
                    from_address=primary_in, to_address=addr, asset="BTC", amount=amt,
                    block_number=tx["status"].get("block_height"), amount_usd=to_usd("BTC", amt),
                    confidence=0.7 if multi else 1.0,
                    notes="multi-input tx; sender attribution is heuristic" if multi else None,
                    extra={"all_inputs": sorted(set(inputs))},
                )
            )
        return out

    def get_tx(self, tx_hash: str) -> TxDetail | None:
        r = self.client.get(f"{self.base_url}/tx/{tx_hash}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        tx = r.json()
        transfers = self._tx_to_transfers(tx)
        ts = transfers[0].timestamp if transfers else datetime.now(tz=UTC)
        return TxDetail(chain=self.chain, tx_hash=tx_hash, timestamp=ts,
                        block_number=tx["status"].get("block_height"), transfers=transfers)

    def _address_txs(self, address: str) -> list[dict]:
        r = self.client.get(f"{self.base_url}/address/{address}/txs")
        r.raise_for_status()
        return r.json()

    def outgoing_transfers(self, address, since=None, limit=200):
        out = []
        for tx in self._address_txs(address):
            spent = any(v.get("prevout", {}).get("scriptpubkey_address") == address for v in tx.get("vin", []))
            if not spent:
                continue
            for t in self._tx_to_transfers(tx):
                if t.to_address != address and (not since or t.timestamp >= since):
                    t.from_address = address
                    out.append(t)
        out.sort(key=lambda r: r.timestamp)
        return out[:limit]

    def incoming_transfers(self, address, since=None, limit=200):
        out = []
        for tx in self._address_txs(address):
            for t in self._tx_to_transfers(tx):
                if t.to_address == address and (not since or t.timestamp >= since):
                    out.append(t)
        out.sort(key=lambda r: r.timestamp)
        return out[:limit]
