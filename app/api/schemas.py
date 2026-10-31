from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, Field

from app.db.models import Chain


class CaseCreate(BaseModel):
    reference: str = Field(min_length=3, max_length=64)
    title: str
    victim_name: str
    victim_entity: str | None = None
    loss_amount: Decimal
    loss_asset: str = "USDC"
    loss_usd: Decimal
    fraud_date: datetime | None = None
    chain: Chain = Chain.ETHEREUM
    origin_tx: str | None = None
    victim_wallet: str | None = None
    perpetrator_wallet: str | None = None
    summary: str | None = None
    facts: dict = Field(default_factory=dict)
    client_email: str | None = None  # the client's contact e-mail: the sender profile's default Cc
    authority_instrument: str | None = None  # default: Letter of Authorisation


class CaseOut(BaseModel):
    id: int
    reference: str
    title: str
    status: str
    victim_name: str | None
    loss_amount: Decimal | None
    loss_asset: str | None
    loss_usd: Decimal | None
    fraud_date: datetime | None

    model_config = {"from_attributes": True}


class CaseListOut(CaseOut):
    """A row of GET /api/cases. For an external membership only id, reference, title, status and
    role are filled (the victim and loss figures stay hidden, as on the case list page)."""

    role: str | None = None
    victim_name: str | None = None
    loss_amount: Decimal | None = None
    loss_asset: str | None = None
    loss_usd: Decimal | None = None
    fraud_date: datetime | None = None


class SeedUpdate(BaseModel):
    role: str
    chain: Chain = Chain.ETHEREUM
    value: str
    note: str | None = None


class TraceRunOut(BaseModel):
    id: int
    status: str
    params: dict
    stats: dict
    error: str | None
    started_at: datetime
    finished_at: datetime | None

    model_config = {"from_attributes": True}


class StopOrderOut(BaseModel):
    """A stop order. `body_markdown` (the R3 letter text) is null and `identifiers` holds only the
    on-chain keys (CHAIN_IDENTIFIER_KEYS) when the caller lacks view_restricted (`restricted`)."""

    id: int
    kind: str
    status: str
    recipient_email: str | None
    subject: str
    body_markdown: str | None
    identifiers: dict
    created_at: datetime
    sent_at: datetime | None
    restricted: bool = False

    model_config = {"from_attributes": True}


# identifier keys a member without view_restricted may see: chain data and swap-order references
CHAIN_IDENTIFIER_KEYS = ("entity", "chain", "addresses", "tx_hashes", "amounts", "order_ids",
                         "prior_deposit_dates", "theft_time", "hold")


def stop_order_out(order, *, restricted: bool) -> StopOrderOut:
    out = StopOrderOut.model_validate(order)
    if restricted:
        ids = order.identifiers or {}
        out.body_markdown = None
        out.identifiers = {k: ids[k] for k in CHAIN_IDENTIFIER_KEYS if k in ids}
        out.restricted = True
    return out


class StopOrderStatusUpdate(BaseModel):
    status: str
    external_ref: str | None = None
    notes: str | None = None
