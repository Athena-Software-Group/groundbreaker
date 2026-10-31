"""On-chain freeze detection: issuer blacklist reads (Tether USDT, Circle USDC) for a case's wallets.

* `abi` — Keccak-256, selectors, ABI encoding, TRON base58 <-> hex.
* `issuers` — the issuer contracts and their readers (JSON-RPC eth_call, TronGrid constant calls) and
  the freeze-event lookup (explorer logs API, TronGrid events).
* `signals` — failed transfer / transferFrom / approve attempts to the token contract.
* `transport` — allow-listed httpx client with retries, a per-host rate limiter and a short cache.
* `service` — the per-case consent setting, which wallets, running the checks, status for the UI.

Nothing here runs unless a case admin enables "On-chain freeze checks" for the case
(docs/freeze-detection.md).
"""
