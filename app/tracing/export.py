"""Movement listings, trace reports and run listings for download.

Every function returns text or bytes; nothing is written to disk (the routes stream the result),
so an export can never land in the repository or in a shared export folder.

* `movements(db, run)`          every movement (TraceEdge + its Transfer) of one run, time-ordered
* `run_summary(db, run)` /
  `run_summaries(db, case)`     the per-run figures shown by the run selector and the runs listing
* `movements_csv / movements_txt`   the movement listing as CSV or as a fixed-width plain-text report
* `build_report` → `report_markdown / report_docx`   the "Trace report" (summary, freeze
  candidates, movement table, provenance notes)
* `runs_csv / runs_txt / runs_markdown`   the case-level listing of every run

Classification: exports are C1 (case-linked trace data, docs/data-handling.md §1). They carry the
case *reference* only: never the victim's name, the case title or other R2 fields.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal

from sqlalchemy import case as sql_case
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.db.models import Address, Case, TraceEdge, TraceNode, TraceRun, Transfer
from app.tracing.freeze import FreezeCandidate, freeze_candidates

CLASSIFICATION = "C1 Confidential-intel: case-linked trace data. Handle per docs/data-handling.md; do not forward."
MAKER = "Aegis (GroundBreaker), powered by Athena Software Group, Inc."
VASP_REASONS = ("vasp", "vasp_omnibus")

# data source -> what it means for the weight of a movement (shown in every export)
PROVENANCE: dict[str, str] = {
    "etherscan": "observed on-chain, read from the Etherscan V2 API",
    "blockscout": "observed on-chain, read from a Blockscout explorer",
    "trongrid": "observed on-chain, read from TronGrid",
    "mempool": "observed on-chain, read from mempool.space",
    "fixture": "case fixture: chain data recorded by the investigator (verify against the explorer)",
    "pi_report": "asserted in an investigator's report, not yet observed on-chain",
    "manual": "entered by hand (victim records or analyst input)",
}
PROVENANCE_NOTES = (
    "asserted = yes: the link is asserted (hash pending or amount unknown) and must be verified before filing.",
    "confidence: 1.0 = observed on-chain; below 1 = asserted or inferred; 0 = refuted by the chain.",
    "USD: value at the static rate of the run; taint USD: the share of the loss attributed to the movement.",
    "All times are UTC.",
)


# --------------------------------------------------------------------------- data
@dataclass
class Movement:
    edge_id: int
    transfer_id: int
    hop: int
    timestamp: datetime
    chain: str
    tx_hash: str
    sub_index: int
    from_address: str
    from_label: str | None
    to_address: str
    to_label: str | None
    asset: str
    amount: Decimal | None
    amount_usd: Decimal | None
    taint_usd: Decimal
    data_source: str
    confidence: float
    asserted: bool
    method: str | None
    notes: str | None
    bridged_to: str | None = None  # tx hash of the payout leg on the other chain

    @property
    def time_utc(self) -> str:
        return self.timestamp.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")

    def as_dict(self) -> dict:
        return {
            "edge_id": self.edge_id, "transfer_id": self.transfer_id, "hop": self.hop,
            "time_utc": self.timestamp.astimezone(UTC).isoformat(), "chain": self.chain, "tx_hash": self.tx_hash,
            "sub_index": self.sub_index, "from": self.from_address, "from_label": self.from_label,
            "to": self.to_address, "to_label": self.to_label, "asset": self.asset,
            "amount": _s(self.amount), "amount_usd": _s(self.amount_usd), "taint_usd": _s(self.taint_usd),
            "data_source": self.data_source, "confidence": self.confidence, "asserted": self.asserted,
            "method": self.method, "bridged_to": self.bridged_to,
        }


@dataclass
class RunSummary:
    id: int
    label: str | None
    notes: str | None
    status: str
    provider_mode: str | None
    started_at: datetime | None
    finished_at: datetime | None
    max_hops: int | None  # the run's hop limit (params)
    max_hop: int  # deepest hop reached
    nodes: int
    edges: int
    vasp_touchpoints: int
    total_taint_usd: Decimal  # taint that entered the trace (largest node taint)
    vasp_taint_usd: Decimal  # taint that reached VASP deposit addresses
    created_by: int | None
    error: str | None = None

    @property
    def at(self) -> datetime | None:
        return self.finished_at or self.started_at

    def as_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label, "notes": self.notes, "status": self.status,
            "provider_mode": self.provider_mode, "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at), "max_hops": self.max_hops, "max_hop": self.max_hop,
            "nodes": self.nodes, "edges": self.edges, "vasp_touchpoints": self.vasp_touchpoints,
            "total_taint_usd": _s(self.total_taint_usd), "vasp_taint_usd": _s(self.vasp_taint_usd),
            "created_by": self.created_by,
        }


def _s(v) -> str | None:
    return None if v is None else str(v)


def _iso(v: datetime | None) -> str | None:
    return v.astimezone(UTC).isoformat() if v else None


def _label(a: Address) -> str | None:
    return (a.entity.name if a.entity else None) or a.label or None


def is_asserted(t: Transfer) -> bool:
    """Same rule as the graph (app/tracing/graph.py): a placeholder hash or an unknown amount."""
    return t.tx_hash.startswith("ASSERTED:") or t.amount is None


def movements(db: Session, run: TraceRun) -> list[Movement]:
    """Every movement of the run (one row per TraceEdge), ordered by time, then hop."""
    edges = db.scalars(
        select(TraceEdge).where(TraceEdge.run_id == run.id).options(
            selectinload(TraceEdge.transfer).selectinload(Transfer.from_address).selectinload(Address.entity),
            selectinload(TraceEdge.transfer).selectinload(Transfer.to_address).selectinload(Address.entity),
        )
    ).all()
    bridged_ids = {e.transfer.bridged_to_transfer_id for e in edges if e.transfer.bridged_to_transfer_id}
    bridged = {t.id: t.tx_hash for t in db.scalars(select(Transfer).where(Transfer.id.in_(bridged_ids)))} if bridged_ids else {}
    out = []
    for e in edges:
        t = e.transfer
        out.append(Movement(
            edge_id=e.id, transfer_id=t.id, hop=e.hop, timestamp=t.timestamp, chain=t.chain.value,
            tx_hash=t.tx_hash, sub_index=t.sub_index or 0,
            from_address=t.from_address.address, from_label=_label(t.from_address),
            to_address=t.to_address.address, to_label=_label(t.to_address),
            asset=t.asset, amount=t.amount, amount_usd=t.amount_usd, taint_usd=e.taint_usd or Decimal(0),
            data_source=t.source.value, confidence=float(t.confidence if t.confidence is not None else 1.0),
            asserted=is_asserted(t), method=t.method, notes=t.notes,
            bridged_to=bridged.get(t.bridged_to_transfer_id) if t.bridged_to_transfer_id else None,
        ))
    out.sort(key=lambda m: (m.timestamp, m.hop, m.edge_id))
    return out


def _summaries(db: Session, runs: list[TraceRun]) -> list[RunSummary]:
    ids = [r.id for r in runs]
    if not ids:
        return []
    node_rows = {
        row[0]: row for row in db.execute(
            select(
                TraceNode.run_id, func.count(TraceNode.id), func.max(TraceNode.hop), func.max(TraceNode.taint_usd),
                func.sum(sql_case((TraceNode.terminal_reason == "vasp", TraceNode.taint_usd), else_=0)),
                func.sum(sql_case((TraceNode.terminal_reason.in_(VASP_REASONS), 1), else_=0)),
            ).where(TraceNode.run_id.in_(ids)).group_by(TraceNode.run_id)
        )
    }
    edge_counts = dict(db.execute(
        select(TraceEdge.run_id, func.count(TraceEdge.id)).where(TraceEdge.run_id.in_(ids)).group_by(TraceEdge.run_id)
    ).all())
    out = []
    for r in runs:
        _, n, max_hop, taint_max, vasp_taint, vasp_n = node_rows.get(r.id, (r.id, 0, 0, 0, 0, 0))
        params = r.params or {}
        out.append(RunSummary(
            id=r.id, label=r.label, notes=r.notes, status=r.status.value if r.status else "pending",
            provider_mode=params.get("provider_mode"), started_at=r.started_at, finished_at=r.finished_at,
            max_hops=params.get("max_hops"), max_hop=int(max_hop or 0), nodes=int(n or 0),
            edges=int(edge_counts.get(r.id, 0)), vasp_touchpoints=int(vasp_n or 0),
            total_taint_usd=Decimal(str(taint_max or 0)).quantize(Decimal("0.01")),
            vasp_taint_usd=Decimal(str(vasp_taint or 0)).quantize(Decimal("0.01")),
            created_by=r.created_by, error=r.error,
        ))
    return out


def run_summary(db: Session, run: TraceRun) -> RunSummary:
    return _summaries(db, [run])[0]


def run_summaries(db: Session, case: Case) -> list[RunSummary]:
    """Every run of the case, newest first (runs are never deleted: each is a version)."""
    runs = db.scalars(select(TraceRun).where(TraceRun.case_id == case.id).order_by(TraceRun.id.desc())).all()
    return _summaries(db, list(runs))


# --------------------------------------------------------------------------- formatting helpers
def _amount(v: Decimal | None) -> str:
    if v is None:
        return "?"
    q = Decimal("0.00000001") if abs(v) < 1000 else Decimal("0.01")
    s = f"{v.quantize(q).normalize():f}"
    return s


def _money(v: Decimal | None) -> str:
    return "" if v is None else f"{Decimal(v):,.2f}"


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _stamp(v: datetime | None) -> str:
    return v.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC") if v else "-"


def slug(text: str, max_len: int = 40) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text or "").strip("-")[:max_len].strip("-") or "case"


def filename(case: Case, kind: str, ext: str, run: TraceRun | None = None) -> str:
    """ASCII-only download name built from a slug of the reference and numeric ids."""
    run_part = f"_trace-{int(run.id)}" if run is not None else ""
    return f"{slug(case.reference)}{run_part}_{slug(kind, 20)}.{ext}"


def _run_title(run: TraceRun) -> str:
    return f"#{run.id}" + (f" ({run.label})" if run.label else "")


def _csv_cell(v) -> str:
    """Neutralise spreadsheet formulas in text cells (CSV injection): labels come from providers."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


# --------------------------------------------------------------------------- movements: CSV / TXT
MOVEMENT_CSV_COLUMNS = (
    "time_utc", "hop", "chain", "tx_hash", "sub_index", "from_address", "from_label", "to_address", "to_label",
    "asset", "amount", "amount_usd", "taint_usd", "data_source", "confidence", "asserted", "method", "bridged_to",
)


def movements_csv(rows: list[Movement]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(MOVEMENT_CSV_COLUMNS)
    for m in rows:
        w.writerow([
            m.time_utc, m.hop, m.chain, _csv_cell(m.tx_hash), m.sub_index, _csv_cell(m.from_address),
            _csv_cell(m.from_label), _csv_cell(m.to_address), _csv_cell(m.to_label), _csv_cell(m.asset),
            "" if m.amount is None else _amount(m.amount), "" if m.amount_usd is None else f"{m.amount_usd:.2f}",
            f"{m.taint_usd:.2f}", m.data_source, f"{m.confidence:g}", "yes" if m.asserted else "no",
            _csv_cell(m.method), _csv_cell(m.bridged_to),
        ])
    return buf.getvalue()


def _fixed_table(headers: list[str], rows: list[list[str]], right: set[int] = frozenset()) -> list[str]:
    widths = [max([len(h)] + [len(r[i]) for r in rows]) for i, h in enumerate(headers)]

    def fmt(cells: list[str]) -> str:
        return "  ".join(c.rjust(widths[i]) if i in right else c.ljust(widths[i]) for i, c in enumerate(cells)).rstrip()

    return [fmt(headers), "  ".join("-" * w for w in widths)] + [fmt(r) for r in rows]


def _legend_lines(rows: list[Movement]) -> list[str]:
    used = sorted({m.data_source for m in rows}) or sorted(PROVENANCE)
    lines = ["Provenance legend (data source):"]
    lines += [f"  {s:<11} {PROVENANCE.get(s, s)}" for s in used]
    lines += [f"  {n}" for n in PROVENANCE_NOTES]
    return lines


def movements_txt(case: Case, run: TraceRun, rows: list[Movement], summary: RunSummary | None = None,
                  generated_at: datetime | None = None) -> str:
    """Fixed-width plain-text movement report (header, legend, one line per movement)."""
    generated_at = generated_at or _now()
    rule = "=" * 100
    out = [
        rule,
        "AEGIS TRACE MOVEMENTS",
        rule,
        f"Case ref      : {case.reference}",
        f"Trace run     : {_run_title(run)}",
        f"Status        : {run.status.value if run.status else '-'}",
        f"Provider mode : {(run.params or {}).get('provider_mode', '-')}",
        f"Run finished  : {_stamp(run.finished_at)}",
        f"Generated at  : {_stamp(generated_at)}",
        f"Generated by  : {MAKER}",
        f"Classification: {CLASSIFICATION}",
    ]
    if summary is not None:
        out.append(
            f"Summary       : {summary.nodes} addresses, {summary.edges} movements, max hop {summary.max_hop}, "
            f"{summary.vasp_touchpoints} VASP touchpoints, taint traced USD {_money(summary.total_taint_usd)}, "
            f"at VASP deposits USD {_money(summary.vasp_taint_usd)}"
        )
    asserted = sum(1 for m in rows if m.asserted)
    out.append(f"Movements     : {len(rows)} ({len(rows) - asserted} observed, {asserted} asserted)")
    out.append(rule)
    out += _legend_lines(rows)
    out.append(rule)
    headers = ["Time (UTC)", "Hop", "Chain", "Tx hash", "From", "To", "Asset", "Amount", "USD", "Taint USD",
               "Source", "Conf", "Asserted"]
    table = [[m.time_utc, str(m.hop), m.chain, m.tx_hash + (f"#{m.sub_index}" if m.sub_index else ""),
              m.from_address, m.to_address, m.asset, _amount(m.amount), _money(m.amount_usd), _money(m.taint_usd),
              m.data_source, f"{m.confidence:.2f}", "yes" if m.asserted else "no"] for m in rows]
    out += _fixed_table(headers, table, right={1, 7, 8, 9, 11})
    out.append(rule)
    out.append("Every asserted link is labelled; verify before filing. End of report.")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- trace report
@dataclass
class TraceReport:
    case: Case
    run: TraceRun
    summary: RunSummary
    movements: list[Movement]
    candidates: list[FreezeCandidate]
    generated_at: datetime
    chains: list[str] = field(default_factory=list)
    sources: Counter = field(default_factory=Counter)


def build_report(db: Session, case: Case, run: TraceRun, generated_at: datetime | None = None) -> TraceReport:
    rows = movements(db, run)
    return TraceReport(
        case=case, run=run, summary=run_summary(db, run), movements=rows, candidates=freeze_candidates(db, run),
        generated_at=generated_at or _now(), chains=sorted({m.chain for m in rows}),
        sources=Counter(m.data_source for m in rows),
    )


def _md_cell(v) -> str:
    return str("" if v is None else v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _short(a: str) -> str:
    return a if len(a) <= 14 else f"{a[:6]}…{a[-4:]}"


def _summary_pairs(r: TraceReport) -> list[tuple[str, str]]:
    s, run = r.summary, r.run
    p = run.params or {}
    asserted = sum(1 for m in r.movements if m.asserted)
    return [
        ("Case ref", r.case.reference),
        ("Trace run", _run_title(run)),
        ("Status", s.status + (f" ({run.error})" if run.error else "")),
        ("Provider mode", s.provider_mode or "-"),
        ("Started / finished", f"{_stamp(s.started_at)} / {_stamp(s.finished_at)}"),
        ("Parameters", (f"max hops {p.get('max_hops', '-')}, max fan-out {p.get('max_fanout', '-')}, "
                        f"min taint USD {p.get('min_taint_usd', '-')}")),
        ("Addresses / movements", f"{s.nodes} / {s.edges} ({s.edges - asserted} observed, {asserted} asserted)"),
        ("Chains", ", ".join(r.chains) or "-"),
        ("Deepest hop", str(s.max_hop)),
        ("VASP touchpoints", str(s.vasp_touchpoints)),
        ("Taint traced (USD)", _money(s.total_taint_usd)),
        ("Taint at VASP deposits (USD)", _money(s.vasp_taint_usd)),
        ("Generated at", _stamp(r.generated_at)),
    ]


def _candidate_value(c: FreezeCandidate) -> str:
    """The candidate's tainted USD; for an issuer lever, only what the wallets still hold by the trace (a wallet the
    trace saw forward everything, Identifier.moved_on, has nothing left to blacklist: the Recovery plan's "moved on")."""
    gone = [i for i in c.identifiers if i.moved_on]
    if c.kind != "issuer_blacklist" or not gone:
        return _money(c.total_taint_usd)
    held = [i for i in c.identifiers if not i.moved_on]
    if not held:
        return f"none held (moved on; {_money(c.total_taint_usd)} received)"
    return f"{_money(min(sum((i.taint_usd for i in held), Decimal(0)), c.total_taint_usd))} (excl. wallets moved on)"


def _candidate_rows(r: TraceReport) -> list[list[str]]:
    return [[str(i), c.entity_name, c.category, c.kind, str(c.priority), _candidate_value(c),
             ", ".join(f"{x.chain}:{x.address}" + (" (moved on)" if x.moved_on and c.kind == "issuer_blacklist" else "")
                       for x in c.identifiers)] for i, c in enumerate(r.candidates, 1)]


MOVEMENT_HEADERS = ["Time (UTC)", "Hop", "Chain", "Tx hash", "From", "To", "Asset", "Amount", "USD", "Source",
                    "Conf.", "Asserted"]


def _movement_row(m: Movement, short: bool = False) -> list[str]:
    tx = m.tx_hash + (f"#{m.sub_index}" if m.sub_index else "")
    f, t = (_short(m.from_address), _short(m.to_address)) if short else (m.from_address, m.to_address)
    if m.from_label:
        f += f" ({m.from_label})"
    if m.to_label:
        t += f" ({m.to_label})"
    return [m.time_utc, str(m.hop), m.chain, tx, f, t, m.asset, _amount(m.amount), _money(m.amount_usd),
            m.data_source, f"{m.confidence:.2f}", "yes" if m.asserted else "no"]


def _provenance_note_lines(r: TraceReport) -> list[str]:
    lines = []
    for m in r.movements:
        bits = []
        if m.notes:
            bits.append(m.notes.strip())
        if m.bridged_to:
            bits.append(f"cross-chain payout leg {m.bridged_to}")
        if bits:
            lines.append(f"hop {m.hop}, {m.chain} {m.tx_hash}: " + " ".join(bits))
    return lines


def report_markdown(r: TraceReport) -> str:
    out = [
        f"# Trace report: {r.case.reference}, run {_run_title(r.run)}",
        "",
        (f"*{CLASSIFICATION} Generated {_stamp(r.generated_at)} by {MAKER} Every asserted link is labelled; "
         "verify before filing.*"),
        "",
        "## Summary",
        "",
        "| Field | Value |",
        "|---|---|",
    ]
    out += [f"| {_md_cell(k)} | {_md_cell(v)} |" for k, v in _summary_pairs(r)]
    if r.run.notes:
        out += ["", "**Run notes.** " + _md_cell(r.run.notes)]
    out += ["", "## Freeze candidates", ""]
    if r.candidates:
        out += ["| # | Entity | Category | Kind | Priority | Tainted USD | Identifiers |", "|---|---|---|---|---|---|---|"]
        out += ["| " + " | ".join(_md_cell(c) for c in row) + " |" for row in _candidate_rows(r)]
        for i, c in enumerate(r.candidates, 1):
            if c.rationale:
                out += ["", f"{i}. **{_md_cell(c.entity_name)}**: " + " ".join(_md_cell(x) for x in c.rationale)]
    else:
        out.append("No freeze or preservation candidates in this run.")
    out += ["", f"## Movements ({len(r.movements)})", "",
            "| " + " | ".join(MOVEMENT_HEADERS) + " |", "|" + "---|" * len(MOVEMENT_HEADERS)]
    for m in r.movements:
        cells = _movement_row(m)
        cells[3] = f"`{cells[3]}`"
        out.append("| " + " | ".join(_md_cell(c) for c in cells) + " |")
    out += ["", "## Provenance notes", "", "Data sources in this run:", ""]
    for s, n in sorted(r.sources.items()):
        out.append(f"- **{s}** ({n} movements): {PROVENANCE.get(s, s)}")
    out += [""] + [f"- {n}" for n in PROVENANCE_NOTES]
    notes = _provenance_note_lines(r)
    if notes:
        out += ["", "Per-movement notes:", ""] + [f"- {_md_cell(n)}" for n in notes]
    return "\n".join(out) + "\n"


def report_docx(r: TraceReport) -> bytes:
    """The trace report as .docx (landscape, built in memory; never written to disk)."""
    from docx import Document
    from docx.enum.section import WD_ORIENT
    from docx.opc.constants import RELATIONSHIP_TYPE as RT
    from docx.shared import Cm, Pt

    doc = Document()
    props = doc.core_properties
    now = r.generated_at.astimezone(UTC).replace(tzinfo=None)
    props.author = props.last_modified_by = "Aegis"
    props.title = f"Trace report {r.case.reference} run {r.run.id}"
    props.subject = f"Case {r.case.reference}"
    props.comments = f"Generated by {MAKER} {CLASSIFICATION}"
    props.keywords = props.category = ""
    props.content_status = "Generated"
    props.created = props.modified = now
    props.revision = 1
    # drop the stock template's thumbnail image, as the stop-order export does (text only)
    pkg_rels = doc.part.package.rels
    for r_id in [k for k, rel in pkg_rels.items() if rel.reltype == RT.THUMBNAIL]:
        pkg_rels.pop(r_id)
    sec = doc.sections[0]
    sec.orientation = WD_ORIENT.LANDSCAPE
    sec.page_width, sec.page_height = sec.page_height, sec.page_width
    sec.left_margin = sec.right_margin = Cm(1.5)
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10)

    def table(headers: list[str], rows: list[list[str]], size: float = 8):
        t = doc.add_table(rows=1, cols=len(headers))
        t.style = "Table Grid"
        for i, h in enumerate(headers):
            cell = t.rows[0].cells[i]
            cell.text = ""
            run = cell.paragraphs[0].add_run(h)
            run.bold = True
            run.font.size = Pt(size)
        for row in rows:
            cells = t.add_row().cells
            for i, v in enumerate(row):
                cells[i].text = ""
                run = cells[i].paragraphs[0].add_run(v)
                run.font.size = Pt(size)
        return t

    doc.add_heading(f"Trace report: {r.case.reference}, run {_run_title(r.run)}", level=1)
    p = doc.add_paragraph()
    it = p.add_run(f"{CLASSIFICATION} Generated {_stamp(r.generated_at)} by {MAKER} "
                   "Every asserted link is labelled; verify before filing.")
    it.italic = True
    it.font.size = Pt(9)
    doc.add_heading("Summary", level=2)
    table(["Field", "Value"], [[k, v] for k, v in _summary_pairs(r)], size=9)
    if r.run.notes:
        doc.add_paragraph().add_run("Run notes. ").bold = True
        doc.paragraphs[-1].add_run(r.run.notes)
    doc.add_heading("Freeze candidates", level=2)
    if r.candidates:
        table(["#", "Entity", "Category", "Kind", "Priority", "Tainted USD", "Identifiers"], _candidate_rows(r))
        for i, c in enumerate(r.candidates, 1):
            if c.rationale:
                par = doc.add_paragraph(style="List Number")
                par.add_run(f"{c.entity_name}: ").bold = True
                par.add_run(" ".join(c.rationale))
    else:
        doc.add_paragraph("No freeze or preservation candidates in this run.")
    doc.add_heading(f"Movements ({len(r.movements)})", level=2)
    table(MOVEMENT_HEADERS, [_movement_row(m, short=True) for m in r.movements], size=7)
    doc.add_paragraph().add_run("Addresses are shortened in this table; the CSV and text exports carry them in full.").italic = True
    doc.add_heading("Provenance notes", level=2)
    for s, n in sorted(r.sources.items()):
        par = doc.add_paragraph(style="List Bullet")
        par.add_run(f"{s} ({n} movements): ").bold = True
        par.add_run(PROVENANCE.get(s, s))
    for n in PROVENANCE_NOTES:
        doc.add_paragraph(n, style="List Bullet")
    notes = _provenance_note_lines(r)
    if notes:
        doc.add_paragraph().add_run("Per-movement notes").bold = True
        for n in notes:
            doc.add_paragraph(n, style="List Bullet")
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# --------------------------------------------------------------------------- all runs listing
RUN_COLUMNS = ("run_id", "label", "status", "provider_mode", "started_utc", "finished_utc", "max_hops", "max_hop",
               "nodes", "edges", "vasp_touchpoints", "total_taint_usd", "vasp_taint_usd")


def _run_cells(s: RunSummary) -> list[str]:
    return [str(s.id), s.label or "", s.status, s.provider_mode or "", _stamp(s.started_at), _stamp(s.finished_at),
            "" if s.max_hops is None else str(s.max_hops), str(s.max_hop), str(s.nodes), str(s.edges),
            str(s.vasp_touchpoints), f"{s.total_taint_usd:.2f}", f"{s.vasp_taint_usd:.2f}"]


def runs_csv(summaries: list[RunSummary]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(RUN_COLUMNS)
    for s in summaries:
        w.writerow([_csv_cell(c) for c in _run_cells(s)])
    return buf.getvalue()


def runs_txt(case: Case, summaries: list[RunSummary], generated_at: datetime | None = None) -> str:
    rule = "=" * 100
    out = [rule, "AEGIS TRACE RUNS", rule, f"Case ref      : {case.reference}",
           f"Runs          : {len(summaries)} (every run is kept as a version)",
           f"Generated at  : {_stamp(generated_at or _now())}", f"Generated by  : {MAKER}",
           f"Classification: {CLASSIFICATION}", rule]
    headers = ["Run", "Label", "Status", "Mode", "Finished (UTC)", "Hops", "Nodes", "Edges", "VASPs",
               "Taint USD", "At VASPs USD"]
    rows = [[f"#{s.id}", s.label or "", s.status, s.provider_mode or "", _stamp(s.at), str(s.max_hop),
             str(s.nodes), str(s.edges), str(s.vasp_touchpoints), _money(s.total_taint_usd),
             _money(s.vasp_taint_usd)] for s in summaries]
    out += _fixed_table(headers, rows, right={5, 6, 7, 8, 9, 10})
    return "\n".join(out + [rule]) + "\n"


def runs_markdown(case: Case, summaries: list[RunSummary], generated_at: datetime | None = None) -> str:
    out = [f"# Trace runs: {case.reference}", "",
           f"*{CLASSIFICATION} Generated {_stamp(generated_at or _now())} by {MAKER}*", "",
           "| Run | Label | Status | Mode | Finished (UTC) | Hops | Nodes | Edges | VASPs | Taint USD | At VASPs USD |",
           "|---|---|---|---|---|---|---|---|---|---|---|"]
    for s in summaries:
        out.append("| " + " | ".join(_md_cell(c) for c in [
            f"#{s.id}", s.label or "", s.status, s.provider_mode or "", _stamp(s.at), s.max_hop, s.nodes, s.edges,
            s.vasp_touchpoints, _money(s.total_taint_usd), _money(s.vasp_taint_usd)]) + " |")
    return "\n".join(out) + "\n"
