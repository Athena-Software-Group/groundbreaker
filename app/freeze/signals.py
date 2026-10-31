"""Supporting signal: the wallet keeps trying to move the token and the token contract reverts.

A blacklisted wallet that still tries to send USDT / USDC produces transactions *from* the wallet *to the
token contract* calling transfer / transferFrom / approve that fail (Etherscan `isError` = 1 or
`txreceipt_status` = 0; TRON `contractRet` other than SUCCESS). That is not proof of a freeze (a transfer
also reverts for want of balance or gas), so Aegis reports it as "transfer attempts failing since <time>
(n attempts)" next to the blacklist reading, never instead of it.

    attempts = failed_from_txlist(rows, wallet, token_contract)       # Etherscan / Blockscout txlist rows
    attempts = failed_from_tron(rows, wallet, token_contract)         # TronGrid /v1/accounts/{a}/transactions

The rows come from the same explorer account `txlist` the EVM provider reads (app/providers/etherscan.py),
fetched here unfiltered, since the provider drops failed transactions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.freeze import abi
from app.freeze.issuers import Explorer, explorer_rows
from app.freeze.transport import FreezeHttp

SEL_TRANSFER = abi.selector("transfer(address,uint256)")  # 0xa9059cbb
SEL_TRANSFER_FROM = abi.selector("transferFrom(address,address,uint256)")  # 0x23b872dd
SEL_APPROVE = abi.selector("approve(address,uint256)")  # 0x095ea7b3
TOKEN_MOVES = {SEL_TRANSFER: "transfer", SEL_TRANSFER_FROM: "transferFrom", SEL_APPROVE: "approve"}
MAX_LISTED = 20


@dataclass
class FailedAttempts:
    count: int = 0
    first_tx: str | None = None
    first_at: datetime | None = None
    last_at: datetime | None = None
    txs: list[dict] = field(default_factory=list)  # [{hash, at, method}] oldest first, at most MAX_LISTED

    def add(self, tx_hash: str, at: datetime | None, method: str) -> None:
        self.count += 1
        if self.first_at is None or (at is not None and at < self.first_at):
            self.first_at, self.first_tx = at, tx_hash
        if at is not None and (self.last_at is None or at > self.last_at):
            self.last_at = at
        self.txs.append({"hash": tx_hash, "at": at.isoformat(timespec="seconds") if at else None, "method": method})

    def finish(self) -> FailedAttempts:
        self.txs.sort(key=lambda t: t["at"] or "")
        self.txs = self.txs[:MAX_LISTED]
        return self

    def text(self) -> str | None:
        if not self.count:
            return None
        since = f"{self.first_at:%d %b %Y %H:%M} UTC" if self.first_at else "an unknown time"
        return f"transfer attempts failing since {since} ({self.count} attempt{'s' if self.count != 1 else ''})"


def _ts(v) -> datetime | None:
    try:
        n = int(str(v))
    except (TypeError, ValueError):
        return None
    if n > 10**11:
        n //= 1000
    return datetime.fromtimestamp(n, tz=UTC)


def failed_from_txlist(rows: list[dict], wallet: str, token_contract: str) -> FailedAttempts:
    """Failed transfer / transferFrom / approve calls from `wallet` to `token_contract` (EVM)."""
    wallet, contract = wallet.lower(), token_contract.lower()
    out = FailedAttempts()
    for r in rows:
        if str(r.get("from") or "").lower() != wallet or str(r.get("to") or "").lower() != contract:
            continue
        failed = str(r.get("isError")) == "1" or str(r.get("txreceipt_status")) == "0"
        method = TOKEN_MOVES.get(str(r.get("input") or "")[:10].lower())
        if failed and method:
            out.add(str(r.get("hash") or ""), _ts(r.get("timeStamp")), method)
    return out.finish()


def _tron_hex(a: str) -> str:
    """TronGrid prints addresses as 41-hex (visible=false) or base58 (visible=true)."""
    return abi.tron_to_hex(a) if a.startswith("T") else a.lower()


def failed_from_tron(rows: list[dict], wallet: str, token_contract: str) -> FailedAttempts:
    """Failed TriggerSmartContract calls (transfer / transferFrom / approve) from `wallet` to the TRC-20."""
    owner_hex = abi.tron_to_hex(wallet)
    contract_hex = abi.tron_to_hex(token_contract)
    out = FailedAttempts()
    for r in rows:
        ret = (r.get("ret") or [{}])[0] or {}
        if str(ret.get("contractRet") or "SUCCESS").upper() == "SUCCESS":
            continue
        for c in (r.get("raw_data") or {}).get("contract") or []:
            if c.get("type") != "TriggerSmartContract":
                continue
            v = (c.get("parameter") or {}).get("value") or {}
            owner, target = str(v.get("owner_address") or ""), str(v.get("contract_address") or "")
            try:
                if _tron_hex(owner) != owner_hex or _tron_hex(target) != contract_hex:
                    continue
            except ValueError:
                continue
            method = TOKEN_MOVES.get("0x" + str(v.get("data") or "")[:8].lower())
            if method:
                out.add(str(r.get("txID") or ""), _ts(r.get("block_timestamp")), method)
    return out.finish()


# --------------------------------------------------------------------------- fetching
def fetch_failed_evm(http: FreezeHttp, explorer: Explorer, wallet: str, token_contract: str) -> tuple[FailedAttempts, str]:
    """(attempts, sha256 of the txlist answer) from the explorer's account txlist (newest 1,000)."""
    params = {"module": "account", "action": "txlist", "address": wallet.lower(), "sort": "desc", "page": 1,
              "offset": 1000, **explorer.auth}
    resp = http.get(explorer.url, params=params)
    return failed_from_txlist(explorer_rows(resp), wallet, token_contract), resp.sha256


def fetch_failed_tron(http: FreezeHttp, base_url: str, api_key: str, wallet: str,
                      token_contract: str) -> tuple[FailedAttempts, str]:
    headers = {"TRON-PRO-API-KEY": api_key} if api_key else None
    resp = http.get(f"{base_url.rstrip('/')}/v1/accounts/{wallet}/transactions",
                    params={"only_from": "true", "limit": 200, "order_by": "block_timestamp,desc"}, headers=headers)
    data = resp.data if isinstance(resp.data, dict) else {}
    rows = [r for r in data.get("data") or [] if isinstance(r, dict)]
    return failed_from_tron(rows, wallet, token_contract), resp.sha256
