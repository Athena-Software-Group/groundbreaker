"""USD valuation.

For the demo we use static reference prices so taint propagation has a USD
scale. In live mode swap this for a price provider (CoinGecko / Coinbase)
with timestamp-aware lookups; the interface is intentionally tiny.
"""

from decimal import Decimal

STATIC_PRICES_USD: dict[str, Decimal] = {
    "USDC": Decimal(1),
    "USDT": Decimal(1),
    "DAI": Decimal(1),
    "ETH": Decimal(2550),  # ≈ implied 12 Oct 2026 rate: 399,247.92 USDC / 156.611 ETH
    "WETH": Decimal(2550),
    "BTC": Decimal(106000),
    "TRX": Decimal("0.11"),
    "BNB": Decimal(600),
    "MATIC": Decimal("0.35"),
    "SOL": Decimal(140),
}


def to_usd(asset: str, amount: Decimal) -> Decimal | None:
    price = STATIC_PRICES_USD.get(asset.upper())
    if price is None:
        return None
    return (amount * price).quantize(Decimal("0.01"))
