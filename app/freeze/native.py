"""Native-coin watch: no issuer can freeze ETH, so the lever is knowing the moment it moves.

Every scheduler pass (scripts.run_scheduler `native_pass`) reads the balance and transaction count of each Ethereum
wallet on the freeze watch of a case whose on-chain checks are on, over the consented JSON-RPC node, and raises
wallet_movement when ETH leaves or the wallet signs a transaction. A wallet's first transaction ever always alerts,
however small: a test payment is the warning, so the value at stake is the balance it held. Incoming funds do not
alert (dust is constant). A reading that fails keeps the last good one and shows on the freeze page: a watch that
stopped reading must never look like a quiet wallet. See docs/freeze-detection.md.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.events import WALLET_MOVEMENT, emit
from app.db.models import Case, FreezeWatch, NativeBalance
from app.freeze import service
from app.freeze.transport import FreezeHttp, FreezeHttpError
from app.providers.prices import to_usd

log = logging.getLogger("app.freeze.native")

SYMBOLS = {"ethereum": "ETH"}  # chains whose node the checks already use
WEI = Decimal(10) ** 18
MIN_DROP_WEI = 5 * 10**14  # 0.0005 ETH: below this, with no transaction signed, nothing moved
LARGE_WEI = 10**18  # 1 ETH: a critical alert
STALE_AFTER = timedelta(minutes=30)  # the freeze page flags a wallet with no good reading for this long


def _uint(value) -> int:
    try:
        return int(str(value), 16)
    except ValueError:
        raise FreezeHttpError("bad_response", None, "not a hex quantity") from None


def _read(http: FreezeHttp, url: str, address: str) -> tuple[int, int]:
    wei, _ = http.rpc(url, "eth_getBalance", [address, "latest"])
    nonce, _ = http.rpc(url, "eth_getTransactionCount", [address, "latest"])
    return _uint(wei), _uint(nonce)


def amount(wei: int | str | None) -> Decimal | None:
    return None if wei is None else Decimal(int(wei)) / WEI


def _alert(db: Session, case: Case, row: NativeBalance, before: int, nonce_before: int, wei: int, nonce: int) -> None:
    symbol = SYMBOLS[row.chain]
    drop = max(0, before - wei)
    first = nonce_before == 0 and nonce > 0
    left = f"{(amount(drop) or 0):.4f} {symbol}"
    short = service.short_address(row.address)
    body = (f"{case.reference} · {short}: {symbol} balance went from {amount(before):.4f} to {amount(wei):.4f}, "
            f"{nonce - nonce_before} transaction(s) signed. No issuer can freeze {symbol}: re-trace now, and warn the "
            "next exchange and law enforcement.")
    emit(db, case, WALLET_MOVEMENT, usd=to_usd(symbol, amount(before if first else drop)),
         title=f"{short} sent its first transaction ever: {left} left" if first else f"{left} left {short}",
         body=body, link=f"/cases/{case.id}/freeze#native", severity="critical" if first or drop >= LARGE_WEI else "high",
         payload={"native_balance_id": row.id, "chain": row.chain}, commit=False)


def check_case(db: Session, case: Case, http: FreezeHttp, url: str, now: datetime) -> tuple[int, int, int]:
    """Read the case's watched wallets once. Returns (wallets read, failed readings, movements). Commits."""
    watches = [w for w in service.watched(db, case) if w.chain in SYMBOLS]
    rows = {r.watch_id: r for r in db.scalars(select(NativeBalance).where(NativeBalance.case_id == case.id))}
    read = failed = moved = 0
    for w in watches:
        row = rows.get(w.id)
        if row is None:
            row = NativeBalance(case_id=case.id, watch_id=w.id, chain=w.chain, address=w.address)
            db.add(row)
            db.flush()
        try:
            wei, nonce = _read(http, url, w.address)
        except FreezeHttpError as exc:
            row.error, row.failed_at = exc.reason[:64], now
            failed += 1
            db.commit()
            continue
        before, nonce_before = (int(row.wei), row.nonce) if row.wei is not None else (None, None)
        if before is not None and (nonce > nonce_before or before - wei >= MIN_DROP_WEI):
            _alert(db, case, row, before, nonce_before, wei, nonce)
            row.moved_at = now
            moved += 1
        row.wei, row.nonce, row.checked_at, row.error, row.failed_at = str(wei), nonce, now, None, None
        read += 1
        db.commit()
    return read, failed, moved


def run_all(db: Session, *, settings=None, transport=None, now: datetime | None = None) -> dict:
    """The scheduler's pass over every open case with the checks on and its endpoints consented."""
    settings = service._settings(settings)
    now = now or datetime.now(tz=UTC)
    out = {"cases": 0, "wallets": 0, "errors": 0, "moved": 0}
    if settings.freeze_checks_disabled:
        return out
    url = service.node_url("ethereum", settings)
    if not url:
        return out
    with service.FreezeHttp(settings, transport=transport, cache_minutes=0) as http:
        for case in db.scalars(select(Case).where(Case.status == "open")).all():
            setting = service.setting_for(db, case)
            if setting is None or not setting.enabled or service.new_hosts(setting, settings):
                continue
            read, failed, moved = check_case(db, case, http, url, now)
            if read or failed:
                out["cases"] += 1
            out["wallets"] += read
            out["errors"] += failed
            out["moved"] += moved
    if out["errors"]:
        log.warning("native watch: %s reading(s) failed", out["errors"])
    return out


def view(db: Session, case: Case, *, now: datetime | None = None) -> list[dict]:
    """The freeze page's table: one row per watched wallet the pass covers."""
    now = now or datetime.now(tz=UTC)
    rows = {r.watch_id: r for r in db.scalars(select(NativeBalance).where(NativeBalance.case_id == case.id))}
    out = []
    for w in db.scalars(select(FreezeWatch).where(FreezeWatch.case_id == case.id, FreezeWatch.active.is_(True))
                        .order_by(FreezeWatch.id)):
        if w.chain not in SYMBOLS:
            continue
        r = rows.get(w.id)
        at = r.checked_at if r is not None else None
        out.append({"address": w.address, "short": service.short_address(w.address), "label": w.label,
                    "symbol": SYMBOLS[w.chain], "balance": amount(r.wei) if r is not None else None,
                    "nonce": r.nonce if r is not None else None, "checked_at": at,
                    "moved_at": r.moved_at if r is not None else None, "error": r.error if r is not None else None,
                    "stale": at is None or now - at > STALE_AFTER})
    return out
