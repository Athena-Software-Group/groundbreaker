"""Persistence helpers shared by the tracer, the seeder and the watcher."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Address, AddressType, Chain, DataSource, Entity, Transfer
from app.providers.base import AddressInfo, RawTransfer

# Confidence of a transfer the chain disproved: the row stays, since earlier trace versions show it, but no new trace
# walks it. The fixture retires an asserted link by setting this on its row.
REFUTED = 0.0


def normalise_address(chain: Chain, address: str) -> str:
    a = address.strip()
    if chain in (Chain.ETHEREUM, Chain.ARBITRUM, Chain.BASE, Chain.BSC, Chain.POLYGON) and a.startswith("0x"):
        return a.lower()
    return a


def get_or_create_address(
    db: Session, chain: Chain, address: str, *, info: AddressInfo | None = None,
    address_type: AddressType | None = None, label: str | None = None, label_source: str | None = None,
    entity: Entity | None = None, is_contract: bool | None = None,
) -> Address:
    norm = normalise_address(chain, address)
    row = db.scalar(select(Address).where(Address.chain == chain, Address.address == norm))
    if row is None:
        row = Address(chain=chain, address=norm, address_type=address_type or AddressType.UNKNOWN)
        db.add(row)
        db.flush()
    # enrich, never downgrade
    if info:
        if info.is_contract is not None and row.is_contract is None:
            row.is_contract = info.is_contract
        if info.label and not row.label:
            row.label, row.label_source = info.label, info.label_source
        if info.tx_count is not None:
            row.tx_count = info.tx_count
    if label and not row.label:
        row.label, row.label_source = label, label_source
    if address_type and row.address_type == AddressType.UNKNOWN:
        row.address_type = address_type
    if entity and row.entity_id is None:
        row.entity = entity
    if is_contract is not None and row.is_contract is None:
        row.is_contract = is_contract
    return row


def get_or_create_entity(db: Session, name: str, **fields) -> Entity:
    row = db.scalar(select(Entity).where(Entity.name == name))
    if row is None:
        row = Entity(name=name, **fields)
        db.add(row)
        db.flush()
    return row


def ingest_transfer(db: Session, raw: RawTransfer, default_source: DataSource) -> Transfer:
    """Idempotent upsert of one value movement. A row arriving as REFUTED retires the stored one, for good."""
    existing = db.scalar(
        select(Transfer).where(
            Transfer.chain == raw.chain, Transfer.tx_hash == raw.tx_hash, Transfer.sub_index == raw.sub_index
        )
    )
    if existing:
        if raw.confidence == REFUTED and existing.confidence != REFUTED:
            existing.confidence, existing.notes = REFUTED, raw.notes or existing.notes
            db.flush()
        return existing

    frm = get_or_create_address(db, raw.chain, raw.from_address)
    to = get_or_create_address(db, raw.chain, raw.to_address)
    source_str = raw.extra.get("source") if raw.extra else None
    source = DataSource(source_str) if source_str else default_source

    row = Transfer(
        chain=raw.chain, tx_hash=raw.tx_hash, sub_index=raw.sub_index, block_number=raw.block_number,
        timestamp=raw.timestamp, from_address=frm, to_address=to, asset=raw.asset,
        token_contract=raw.token_contract, amount=raw.amount, amount_usd=raw.amount_usd,
        source=source, confidence=raw.confidence, method=raw.method, notes=raw.notes,
    )
    db.add(row)
    db.flush()

    for addr, ts in ((frm, raw.timestamp), (to, raw.timestamp)):
        if addr.first_seen is None or ts < addr.first_seen:
            addr.first_seen = ts
        if addr.last_seen is None or ts > addr.last_seen:
            addr.last_seen = ts
    return row


def link_bridge(db: Session, src: Transfer, dst_chain: Chain, dst_hash: str) -> Transfer | None:
    dst = db.scalar(select(Transfer).where(Transfer.chain == dst_chain, Transfer.tx_hash == dst_hash))
    if dst and src.bridged_to_transfer_id is None:
        src.bridged_to_transfer_id = dst.id
    return dst


def outgoing_from_db(db: Session, address: Address, since: datetime | None) -> list[Transfer]:
    q = select(Transfer).where(Transfer.from_address_id == address.id, Transfer.confidence > REFUTED)
    if since:
        q = q.where(Transfer.timestamp >= since)
    return list(db.scalars(q.order_by(Transfer.timestamp, Transfer.sub_index)))
