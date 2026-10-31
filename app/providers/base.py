"""Provider abstraction.

Every chain backend (Etherscan V2, TronGrid, mempool.space, the offline fixture)
normalises its data into `RawTransfer`, so the tracing engine never sees a
provider-specific payload. Adding a chain = implementing three methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal

from app.db.models import Chain


@dataclass(slots=True)
class RawTransfer:
    chain: Chain
    tx_hash: str
    sub_index: int
    timestamp: datetime
    from_address: str
    to_address: str
    asset: str
    amount: Decimal | None  # None = asserted movement, amount unobserved
    block_number: int | None = None
    token_contract: str | None = None
    amount_usd: Decimal | None = None
    method: str | None = None
    notes: str | None = None
    confidence: float = 1.0
    # Hint for cross-chain continuation (swap services): the provider or fixture
    # may know the destination leg.
    bridged_to: tuple[Chain, str] | None = None  # (chain, tx_hash)
    extra: dict = field(default_factory=dict)


@dataclass(slots=True)
class TxDetail:
    chain: Chain
    tx_hash: str
    timestamp: datetime
    block_number: int | None
    transfers: list[RawTransfer]
    status: str = "success"


@dataclass(slots=True)
class AddressInfo:
    chain: Chain
    address: str
    is_contract: bool | None = None
    label: str | None = None
    label_source: str | None = None
    tx_count: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class ChainProvider(ABC):
    chain: Chain
    name: str = "base"

    @abstractmethod
    def get_tx(self, tx_hash: str) -> TxDetail | None:
        """All value movements in one transaction."""

    @abstractmethod
    def outgoing_transfers(
        self, address: str, since: datetime | None = None, limit: int = 200
    ) -> list[RawTransfer]:
        """Value leaving `address`, oldest first. Native + tokens."""

    @abstractmethod
    def incoming_transfers(
        self, address: str, since: datetime | None = None, limit: int = 200
    ) -> list[RawTransfer]:
        """Value arriving at `address`, oldest first."""

    def address_info(self, address: str) -> AddressInfo:
        return AddressInfo(chain=self.chain, address=address)

    # Convenience ---------------------------------------------------------------
    def normalise(self, address: str) -> str:
        return address.strip()


class ProviderError(RuntimeError):
    pass
