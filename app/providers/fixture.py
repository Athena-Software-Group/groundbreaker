"""Offline provider backed by a JSON fixture (one file = one case's known universe).

Used for demos, tests, and for environments without outbound API access. The
same file also seeds the database (see scripts/seed_case.py), so the fixture is
the single source of truth for what is known about the case.

The fixture path comes from settings (`AEGIS_FIXTURE_PATH`, default
`data/fixtures/demo_case.json` — the fictional demo case). Real case fixtures live
outside the repository and are selected with that variable or `--fixture`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from app.core.config import get_settings
from app.db.models import Chain
from app.providers.base import AddressInfo, ChainProvider, RawTransfer, TxDetail
from app.providers.prices import to_usd

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "data" / "fixtures"


def _parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(UTC)


def resolve_fixture_path(fixture: str | Path | None = None) -> Path:
    """Path of a fixture file.

    None -> settings.aegis_fixture_path. A bare name without a directory or suffix
    (e.g. "demo_case") -> data/fixtures/<name>.json. Relative paths resolve against
    the current directory if the file exists there, otherwise the repo root.
    """
    ref = Path(fixture) if fixture is not None else Path(get_settings().aegis_fixture_path)
    if not ref.is_absolute() and ref.parent == Path(".") and not ref.suffix:
        return FIXTURE_DIR / f"{ref.name}.json"
    if ref.is_absolute():
        return ref
    cwd_path = Path.cwd() / ref
    return cwd_path if cwd_path.exists() else REPO_ROOT / ref


def load_fixture(fixture: str | Path | None = None) -> dict:
    path = resolve_fixture_path(fixture)
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def fixture_transfers(data: dict) -> list[RawTransfer]:
    out: list[RawTransfer] = []
    for t in data["transfers"]:
        amt = Decimal(t["amount"]) if t.get("amount") is not None else None
        asset = t["asset"]
        bridged = None
        if t.get("bridged_to"):
            bridged = (Chain(t["bridged_to"]["chain"]), t["bridged_to"]["tx_hash"])
        out.append(
            RawTransfer(
                chain=Chain(t["chain"]), tx_hash=t["tx_hash"], sub_index=t.get("sub_index", 0),
                timestamp=_parse_ts(t["timestamp"]), from_address=t["from"], to_address=t["to"],
                asset=asset, amount=amt, block_number=t.get("block_number"),
                token_contract=t.get("token_contract"),
                amount_usd=to_usd(asset, amt) if amt is not None else None,
                method=t.get("method"), notes=t.get("notes"), confidence=t.get("confidence", 1.0),
                bridged_to=bridged, extra={"source": t.get("source", "fixture")},
            )
        )
    return out


class FixtureProvider(ChainProvider):
    name = "fixture"

    def __init__(self, chain: Chain, fixture: str | Path | None = None):
        self.chain = chain
        data = load_fixture(fixture)
        self._transfers = [t for t in fixture_transfers(data) if t.chain == chain]
        self._labels = {
            self.normalise(a["address"]): a for a in data["addresses"] if Chain(a["chain"]) == chain
        }

    def normalise(self, address: str) -> str:
        a = address.strip()
        return a.lower() if a.startswith("0x") else a

    def get_tx(self, tx_hash: str) -> TxDetail | None:
        rows = [t for t in self._transfers if t.tx_hash.lower() == tx_hash.lower()]
        if not rows:
            return None
        return TxDetail(chain=self.chain, tx_hash=tx_hash, timestamp=rows[0].timestamp,
                        block_number=rows[0].block_number, transfers=rows)

    def outgoing_transfers(self, address, since=None, limit=200):
        a = self.normalise(address)
        rows = [t for t in self._transfers if self.normalise(t.from_address) == a
                and (since is None or t.timestamp >= since)]
        rows.sort(key=lambda r: r.timestamp)
        return rows[:limit]

    def incoming_transfers(self, address, since=None, limit=200):
        a = self.normalise(address)
        rows = [t for t in self._transfers if self.normalise(t.to_address) == a
                and (since is None or t.timestamp >= since)]
        rows.sort(key=lambda r: r.timestamp)
        return rows[:limit]

    def address_info(self, address: str) -> AddressInfo:
        a = self.normalise(address)
        meta = self._labels.get(a, {})
        return AddressInfo(chain=self.chain, address=a, is_contract=meta.get("is_contract"),
                           label=meta.get("label"), label_source=meta.get("label_source"))
