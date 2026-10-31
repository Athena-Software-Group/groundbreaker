"""One key per wallet address, so every page, plan and lookup matches the same wallet: EVM hex lower-case; TRON,
Solana and Bitcoin base58 (1… / 3…) as written (case-sensitive); Bitcoin bech32 (bc1… / tb1…) lower-case."""

from __future__ import annotations

from typing import Any

CASE_SENSITIVE = frozenset({"tron", "solana", "bitcoin"})
BECH32 = ("bc1", "tb1", "bcrt1")


def chain_of(chain: Any) -> str:
    return str(getattr(chain, "value", chain) or "").strip().lower()


def addr_key(chain: Any, address: str | None) -> str:
    c, a = chain_of(chain), (address or "").strip()
    if c not in CASE_SENSITIVE or (c == "bitcoin" and a.lower().startswith(BECH32)):
        return a.lower()
    return a


def wallet_key(chain: Any, address: str | None) -> tuple[str, str]:
    return chain_of(chain), addr_key(chain, address)
