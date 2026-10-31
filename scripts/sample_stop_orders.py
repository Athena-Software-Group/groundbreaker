"""Regenerate the sample stop orders in docs/samples/stop-orders from the demo case.

    DATABASE_URL=sqlite:////tmp/aegis-samples.db alembic upgrade head
    DATABASE_URL=sqlite:////tmp/aegis-samples.db python -m scripts.seed_case
    DATABASE_URL=sqlite:////tmp/aegis-samples.db python -m scripts.sample_stop_orders

Writes one Markdown and one .docx file per freeze candidate, numbered in priority order. Only a
DEMO-* case can be exported, so a real case seeded into the same database never lands in the repo.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "docs" / "samples" / "stop-orders"
SHORT_NAMES = {
    "Circle (USDC issuer)": "circle", "Tether (USDT issuer)": "tether", "SWFT / Bridgers": "swft-bridgers",
}


def _stem(n: int, order) -> str:
    entity = order.identifiers["entity"]
    name = SHORT_NAMES.get(entity) or re.sub(r"[^a-z0-9]+", "-", entity.lower()).strip("-")
    issuer = order.entity is not None and order.entity.category.value == "stablecoin_issuer"
    kind = "blacklist" if issuer else order.kind
    return f"{n:02d}-{name}-{kind}"


def main(reference: str = "DEMO-2026-001", out: Path = DEFAULT_OUT) -> list[Path]:
    from sqlalchemy import select

    from app.db.models import Case
    from app.db.session import SessionLocal
    from app.reports.stop_orders import export_markdown, to_docx
    from app.services import generate_stop_orders, latest_run

    if not reference.startswith("DEMO-"):
        raise SystemExit(f"refusing to export {reference!r}: only DEMO-* cases may be written as samples")
    out.mkdir(parents=True, exist_ok=True)
    for old in [*out.glob("*.md"), *out.glob("*.docx")]:
        old.unlink()
    written: list[Path] = []
    with SessionLocal() as db:
        case = db.scalar(select(Case).where(Case.reference == reference))
        if case is None or (run := latest_run(db, case)) is None:
            raise SystemExit(f"case {reference} not seeded / not traced — run `python -m scripts.seed_case` first")
        # one sample per candidate, in the scratch database the docstring sets up: past the request gate
        # (app.domain.request_gate), which would leave out every provider the demo case already asked
        for n, order in enumerate(generate_stop_orders(db, case, run, gate=False), 1):
            stem = _stem(n, order)
            md = out / f"{stem}.md"
            md.write_text(export_markdown(order), encoding="utf-8")
            written += [md, to_docx(order, out / f"{stem}.docx")]
            print(f"{stem}: {order.subject}")
    return written


def _cli() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--reference", default="DEMO-2026-001")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    main(args.reference, args.out)


if __name__ == "__main__":
    _cli()
