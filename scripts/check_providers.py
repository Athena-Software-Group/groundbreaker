"""Connectivity + adapter diagnostic. Run this first on any new machine / network.

    python -m scripts.check_providers

It hits each live provider with a known transaction from the demo case (real on-chain
data; see data/fixtures/demo_case.json) and reports
reachability, auth, and whether the adapter parsed the response into RawTransfers.
Exit code 0 when every reachable provider parsed correctly.
"""

from __future__ import annotations

import sys
import traceback

import httpx

from app.core.config import get_settings
from app.db.models import Chain

CHECKS = [
    # (label, chain, kind, value)
    ("Ethereum · origin USDC transfer (victim → 0x57de)", Chain.ETHEREUM, "tx",
     "0x70abbe14aa9080b572aa69881536e5c165097c0574c4791467e915b708bba814"),
    ("Ethereum · known deposit to KuCoin addr", Chain.ETHEREUM, "tx",
     "0x580d3a804899ca7e084af17c13ecd2cb7af781e15572a62eaf604ff056c30293"),
    ("Ethereum · outgoing from the peel wallet 0x2501", Chain.ETHEREUM, "out",
     "0x25018daA80887E133ee16a0070986dD8D4De57E3"),
    ("TRON · SWFT payout (USDT)", Chain.TRON, "tx",
     "705f713545499afc5860f45d1be2c40413a8d813d28f268fb203b3ead818ea67"),
    ("Bitcoin · SWFT payout (BTC)", Chain.BITCOIN, "tx",
     "9e573f03585ce4647fbdeeb351bd6b95c154a49d42957ad68f19e34db5137897"),
]


def main() -> int:
    from app.providers.registry import get_provider

    s = get_settings()
    print(f"provider_mode={s.provider_mode} evm_provider={s.evm_provider} etherscan_key={'set' if s.etherscan_api_key else 'none'} "
          f"trongrid_key={'set' if s.trongrid_api_key else 'none'}\n")
    ok = True
    for label, chain, kind, value in CHECKS:
        try:
            p = get_provider(chain, "live")
            if kind == "tx":
                d = p.get_tx(value)
                n = len(d.transfers) if d else 0
                status = f"OK   {n} transfer(s)" if n else "WARN reachable but 0 transfers parsed"
                ok &= n > 0
                sample = d.transfers[0] if d and d.transfers else None
            else:
                rows = p.outgoing_transfers(value, limit=50)
                status = f"OK   {len(rows)} outgoing" if rows else "WARN reachable but 0 rows"
                ok &= bool(rows)
                sample = rows[0] if rows else None
            print(f"[{p.name:10s}] {label}: {status}")
            if sample:
                print(f"             e.g. {sample.timestamp:%Y-%m-%d %H:%M:%S} {sample.amount} {sample.asset} {sample.from_address[:10]}… → {sample.to_address[:10]}…")
        except httpx.ProxyError as exc:
            ok = False
            print(f"[{chain.value:10s}] {label}: BLOCKED by egress proxy ({exc}) — not a code problem; allow-list the host")
        except httpx.HTTPStatusError as exc:
            ok = False
            print(f"[{chain.value:10s}] {label}: HTTP {exc.response.status_code} — {exc.response.text[:120]}")
        except Exception as exc:  # noqa: BLE001
            ok = False
            print(f"[{chain.value:10s}] {label}: FAIL {type(exc).__name__}: {exc}")
            traceback.print_exc(limit=2)
    print("\nRESULT:", "all good" if ok else "see failures above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
