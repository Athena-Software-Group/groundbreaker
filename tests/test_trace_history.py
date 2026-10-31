"""Fund flow: trace versions, run labels / notes, movement listings, exports and run diffs."""

from __future__ import annotations

import csv
import io
import re
import zipfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from conftest import csrf_token
from sqlalchemy import func, select

from app import services
from app.db.models import (
    Address,
    AddressType,
    AuditEvent,
    Case,
    Chain,
    DataSource,
    Entity,
    EntityCategory,
    TraceEdge,
    TraceNode,
    TraceRun,
    TraceStatus,
    Transfer,
)
from app.tracing import diff as diff_mod
from app.tracing import export
from app.tracing.diff import EdgeSnap, NodeSnap, RunSnapshot, diff_runs

ORIGIN_TX = "0x70abbe14aa9080b572aa69881536e5c165097c0574c4791467e915b708bba814"
VICTIM_NAME = "Jordan Avery"  # demo victim (R2 in a live case): never in a trace export


@pytest.fixture
def run(db, case):
    return services.run_trace(db, case, "fixture")


def _edge_count(db, run) -> int:
    return db.scalar(select(func.count(TraceEdge.id)).where(TraceEdge.run_id == run.id))


def _exports(db, case_id: int) -> list[AuditEvent]:
    return list(db.scalars(select(AuditEvent).where(AuditEvent.action == "EXPORT", AuditEvent.case_id == case_id)
                           .order_by(AuditEvent.id)))


# --------------------------------------------------------------------------- exports: content & format
def test_movement_csv_lists_every_movement(db, client, case, run):
    r = client.get(f"/api/cases/{case.id}/trace/runs/{run.id}/movements.csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["content-disposition"] == f'attachment; filename="DEMO-2026-001_trace-{run.id}_movements.csv"'
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert tuple(rows[0].keys()) == export.MOVEMENT_CSV_COLUMNS
    assert len(rows) == _edge_count(db, run) == 40
    origin = next(x for x in rows if x["tx_hash"] == ORIGIN_TX)
    assert origin["hop"] == "0" and origin["asset"] == "USDC" and origin["amount"] == "399247.92"
    assert origin["time_utc"] == "2026-10-12 10:49:47" and origin["asserted"] == "no"
    relay = next(x for x in rows if x["tx_hash"].startswith("ASSERTED:relay1"))
    assert relay["asserted"] == "yes" and float(relay["confidence"]) < 1
    assert [x["time_utc"] for x in rows] == sorted(x["time_utc"] for x in rows)  # time-ordered
    assert VICTIM_NAME not in r.text


def test_movement_txt_is_a_fixed_width_report(db, client, case, run):
    r = client.get(f"/api/cases/{case.id}/trace/runs/{run.id}/movements.txt")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    text = r.text
    assert "Case ref      : DEMO-2026-001" in text
    assert f"Trace run     : #{run.id}" in text
    assert re.search(r"Generated at  : \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC", text)
    assert "Provenance legend" in text and "pi_report" in text and "asserted = yes" in text
    assert "C1 Confidential-intel" in text
    assert VICTIM_NAME not in text and case.title not in text
    lines = text.splitlines()
    head = next(i for i, ln in enumerate(lines) if ln.startswith("Time (UTC)"))
    rule = lines[head + 1]
    assert set(rule) <= {"-", " "}
    # fixed width: every column starts at the same offset in every row
    starts = [m.start() for m in re.finditer(r"-+", rule)]
    body = [ln for ln in lines[head + 2:] if re.match(r"\d{4}-\d\d-\d\d ", ln)]
    assert len(body) == 40
    tx_col = starts[3]
    for ln in body:
        assert ln[tx_col - 2:tx_col] == "  " and ln[tx_col] != " "
    assert any(ORIGIN_TX in ln for ln in body)


def test_trace_report_markdown_and_docx(db, client, case, run):
    md = client.get(f"/api/cases/{case.id}/trace/runs/{run.id}/report.md")
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    t = md.text
    for section in ("# Trace report: DEMO-2026-001", "## Summary", "## Freeze candidates", "## Movements (40)",
                    "## Provenance notes"):
        assert section in t, section
    assert "KuCoin" in t and "Circle (USDC issuer)" in t  # freeze candidates of the demo run
    assert f"`{ORIGIN_TX}`" in t
    assert "Origin transfer: from victim records" in t  # per-movement provenance note
    assert VICTIM_NAME not in t

    dx = client.get(f"/api/cases/{case.id}/trace/runs/{run.id}/report.docx")
    assert dx.status_code == 200
    assert dx.headers["content-disposition"].endswith(f'_trace-{run.id}_trace-report.docx"')
    from docx import Document

    doc = Document(io.BytesIO(dx.content))
    headings = [p.text for p in doc.paragraphs if p.style.name.startswith("Heading")]
    assert headings[0].startswith("Trace report: DEMO-2026-001")
    assert {"Summary", "Freeze candidates", "Movements (40)", "Provenance notes"} <= set(headings)
    movement_table = doc.tables[-1]
    assert movement_table.rows[0].cells[0].text == "Time (UTC)" and len(movement_table.rows) == 41
    assert doc.core_properties.author == "Aegis"
    names = zipfile.ZipFile(io.BytesIO(dx.content)).namelist()
    assert not any("thumbnail" in n for n in names)
    assert VICTIM_NAME not in "\n".join(p.text for p in doc.paragraphs)


def test_downloads_are_audited_and_never_written_to_disk(db, client, case, run, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = len(_exports(db, case.id))
    for path in ("movements.csv", "movements.txt", "report.md", "report.docx"):
        assert client.get(f"/api/cases/{case.id}/trace/runs/{run.id}/{path}").status_code == 200
    events = _exports(db, case.id)[before:]
    assert [(e.detail["kind"], e.detail["format"]) for e in events] == [
        ("movements", "csv"), ("movements", "txt"), ("report", "md"), ("report", "docx")]
    assert all(e.object_type == "trace_runs" and e.object_id == str(run.id) for e in events)
    assert list(tmp_path.iterdir()) == []
    assert not (services.EXPORT_DIR.exists() and any(services.EXPORT_DIR.glob(f"*trace-{run.id}*")))


def test_unknown_export_format_is_404(client, case, run):
    assert client.get(f"/api/cases/{case.id}/trace/runs/{run.id}/movements.xlsx").status_code == 404
    assert client.get(f"/api/cases/{case.id}/trace/runs/{run.id}/report.pdf").status_code == 404
    assert client.get(f"/api/cases/{case.id}/trace/runs/export.json").status_code == 404


def test_all_runs_listing(db, client, case, run):
    second = services.run_trace(db, case, "fixture", label="second pass")
    ids = [r.id for r in db.scalars(select(TraceRun).where(TraceRun.case_id == case.id))]
    rows = list(csv.DictReader(io.StringIO(client.get(f"/api/cases/{case.id}/trace/runs/export.csv").text)))
    assert tuple(rows[0].keys()) == export.RUN_COLUMNS
    assert sorted(int(x["run_id"]) for x in rows) == sorted(ids)
    assert [int(x["run_id"]) for x in rows] == sorted(ids, reverse=True)  # newest first
    row = next(x for x in rows if int(x["run_id"]) == second.id)
    assert row["label"] == "second pass" and row["nodes"] == "36" and row["edges"] == "40"
    assert row["provider_mode"] == "fixture" and row["total_taint_usd"] == "399247.92"
    txt = client.get(f"/api/cases/{case.id}/trace/runs/export.txt").text
    assert "AEGIS TRACE RUNS" in txt and f"#{second.id}" in txt and "second pass" in txt
    md = client.get(f"/api/cases/{case.id}/trace/runs/export.md").text
    assert md.startswith("# Trace runs: DEMO-2026-001") and f"| #{second.id} | second pass |" in md
    api = client.get(f"/api/cases/{case.id}/trace/runs").json()
    assert [x["id"] for x in api] == sorted(ids, reverse=True)
    assert api[0]["vasp_touchpoints"] == 3


def test_csv_cells_cannot_inject_spreadsheet_formulas():
    assert export._csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert export._csv_cell("@SUM") == "'@SUM" and export._csv_cell("0xabc") == "0xabc"
    assert export._csv_cell(None) == ""


# --------------------------------------------------------------------------- versions, labels, notes
def test_rerun_creates_a_new_version_and_reports_trace_completed(db, client_for, case, run, monkeypatch):
    calls = []
    real_emit = diff_mod.emit

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return real_emit(*args, **kwargs)

    monkeypatch.setattr(diff_mod, "emit", spy)
    c = client_for("investigator", case=case)
    token = csrf_token(c, f"/cases/{case.id}?tab=fund_flow")
    first_nodes = db.scalar(select(func.count(TraceNode.id)).where(TraceNode.run_id == run.id))
    r = c.post(f"/cases/{case.id}/trace", data={"csrf_token": token, "mode": "fixture", "label": "after relay check"},
               follow_redirects=False)
    assert r.status_code == 303
    new = db.scalar(select(TraceRun).where(TraceRun.case_id == case.id).order_by(TraceRun.id.desc()))
    assert new.id > run.id and new.label == "after relay check" and new.created_by == c.user.id
    assert r.headers["location"] == f"/cases/{case.id}?tab=fund_flow&run_id={new.id}"
    db.expire_all()
    assert db.scalar(select(func.count(TraceNode.id)).where(TraceNode.run_id == run.id)) == first_nodes  # kept as is
    (args, kw), = calls
    assert args[2] == "trace_completed" and kw["payload"]["trace_run_id"] == new.id
    assert kw["link"] == f"/cases/{case.id}?tab=fund_flow&run_id={new.id}"
    assert "DEMO-2026-001" in kw["title"] and "0x" not in kw["title"] + kw["body"]
    assert "after relay check" not in kw["title"] + kw["body"]  # free text stays out of notifications
    # an unknown provider mode never goes live
    r = c.post(f"/cases/{case.id}/trace", data={"csrf_token": token, "mode": "liev"}, follow_redirects=False)
    assert r.status_code == 400


def test_investigator_labels_and_annotates_a_run(db, client_for, case, run):
    c = client_for("investigator", case=case)
    token = csrf_token(c, f"/cases/{case.id}?tab=fund_flow&run_id={run.id}")
    r = c.post(f"/cases/{case.id}/trace/runs/{run.id}/annotate",
               data={"csrf_token": token, "label": "  baseline  ", "notes": "Relay hashes still pending.",
                     "view": "movements"}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == f"/cases/{case.id}?tab=fund_flow&run_id={run.id}&view=movements"
    db.refresh(run)
    assert run.label == "baseline" and run.notes == "Relay hashes still pending."
    ev = db.scalar(select(AuditEvent).where(AuditEvent.action == "UPDATE", AuditEvent.object_type == "trace_runs",
                                            AuditEvent.object_id == str(run.id)).order_by(AuditEvent.id.desc()))
    assert ev.detail["fields"] == ["label", "notes"] and "Relay hashes" not in str(ev.detail)
    page = c.get(f"/cases/{case.id}?tab=fund_flow&run_id={run.id}").text
    assert "baseline" in page and "Relay hashes still pending." in page
    # API: PATCH changes only the fields given
    r = c.patch(f"/api/cases/{case.id}/trace/runs/{run.id}", json={"label": "baseline v2"})
    assert r.status_code == 200 and r.json()["label"] == "baseline v2" and r.json()["notes"] == "Relay hashes still pending."
    assert c.patch(f"/api/cases/{case.id}/trace/runs/{run.id}", json={"label": "x" * 200}).status_code == 422


def test_run_selector_and_views_render(db, client, case, run):
    second = services.run_trace(db, case, "fixture", label="v2")
    page = client.get(f"/cases/{case.id}?tab=fund_flow").text
    assert 'id="graph-data"' in page and 'id="ff-graph"' in page and 'data-ff-cmd="fullscreen"' in page
    assert f'<option value="{run.id}"' in page and f'<option value="{second.id}" selected' in page
    old = client.get(f"/cases/{case.id}?tab=fund_flow&run_id={run.id}").text
    assert f'<option value="{run.id}" selected' in old
    mv = client.get(f"/cases/{case.id}?tab=fund_flow&run_id={run.id}&view=movements").text
    assert mv.count('<tr data-chain="') == 40 and 'data-ff-filter="chain"' in mv and 'data-ff-sort="num"' in mv
    assert ORIGIN_TX in mv
    cmp_ = client.get(f"/cases/{case.id}?tab=fund_flow&view=compare&base={run.id}&head={second.id}").text
    assert f"No difference between #{run.id} and #{second.id}" in cmp_  # same fixture, same result
    runs = client.get(f"/cases/{case.id}?tab=fund_flow&view=runs").text
    assert f"/api/cases/{case.id}/trace/runs/export.csv" in runs and f"diff vs #{run.id}" in runs
    assert client.get(f"/cases/{case.id}/trace/runs/{run.id}/movements", follow_redirects=False).headers["location"] \
        == f"/cases/{case.id}?tab=fund_flow&run_id={run.id}&view=movements"


# --------------------------------------------------------------------------- role gating
def test_read_only_may_view_and_download_but_not_change(db, client_for, case, run):
    c = client_for("read_only", case=case)
    for view in ("graph", "movements", "compare", "runs"):
        page = c.get(f"/cases/{case.id}?tab=fund_flow&run_id={run.id}&view={view}")
        assert page.status_code == 200, view
        assert "Run trace" not in page.text and "Save label" not in page.text and "Re-run" not in page.text
    for path in ("movements.csv", "movements.txt", "report.md", "report.docx", "movements"):
        assert c.get(f"/api/cases/{case.id}/trace/runs/{run.id}/{path}").status_code == 200, path
    assert c.get(f"/api/cases/{case.id}/trace/runs/export.csv").status_code == 200
    assert c.get(f"/api/cases/{case.id}/trace/diff", params={"base": run.id, "head": run.id}).status_code == 200
    token = csrf_token(c, f"/cases/{case.id}?tab=fund_flow")
    r = c.post(f"/cases/{case.id}/trace/runs/{run.id}/annotate", data={"csrf_token": token, "label": "x"},
               follow_redirects=False)
    assert r.status_code == 403
    assert c.patch(f"/api/cases/{case.id}/trace/runs/{run.id}", json={"label": "x"}).status_code == 403


def test_external_and_non_members_cannot_reach_trace_exports(db, client_for, case, run):
    ext = client_for("external", case=case, email="liaison@tests.example")
    assert ext.get(f"/api/cases/{case.id}/trace/runs/{run.id}/movements.csv").status_code == 403
    assert ext.get(f"/api/cases/{case.id}/trace/runs").status_code == 403
    outsider = client_for(None, case=case, email="outsider@tests.example")
    assert outsider.get(f"/api/cases/{case.id}/trace/runs/{run.id}/report.md").status_code == 404
    assert outsider.get(f"/api/cases/{case.id}/trace/runs/export.csv").status_code == 404


def test_runs_of_another_case_are_404(db, client, case, run):
    other = _synthetic_case(db)
    foreign = _synthetic_run(db, other, [], [])
    for path in (f"runs/{foreign.id}", f"runs/{foreign.id}/movements.csv", f"runs/{foreign.id}/report.docx"):
        assert client.get(f"/api/cases/{case.id}/trace/{path}").status_code == 404, path
    assert client.get(f"/api/cases/{case.id}/trace/diff", params={"base": run.id, "head": foreign.id}).status_code == 404
    assert client.get(f"/cases/{case.id}?tab=fund_flow&view=compare&base={foreign.id}").status_code == 404


# --------------------------------------------------------------------------- diff
def _addr(db, n: str, *, entity: Entity | None = None, kind: AddressType = AddressType.UNKNOWN) -> Address:
    value = "0x" + n * 40 if len(n) == 1 else n
    a = db.scalar(select(Address).where(Address.chain == Chain.ETHEREUM, Address.address == value))
    if a is None:
        a = Address(chain=Chain.ETHEREUM, address=value, address_type=kind, entity=entity)
        db.add(a)
        db.flush()
    return a


def _entity(db, name: str) -> Entity:
    e = db.scalar(select(Entity).where(Entity.name == name))
    if e is None:
        e = Entity(name=name, category=EntityCategory.EXCHANGE)
        db.add(e)
        db.flush()
    return e


def _transfer(db, tx: str, src: Address, dst: Address, amount: str) -> Transfer:
    t = db.scalar(select(Transfer).where(Transfer.chain == Chain.ETHEREUM, Transfer.tx_hash == tx))
    if t is None:
        t = Transfer(chain=Chain.ETHEREUM, tx_hash=tx, sub_index=0, timestamp=datetime(2026, 10, 12, 11, tzinfo=UTC)
                     + timedelta(minutes=len(tx)), from_address=src, to_address=dst, asset="ETH",
                     amount=Decimal(amount), amount_usd=Decimal(amount) * 1000, source=DataSource.FIXTURE)
        db.add(t)
        db.flush()
    return t


def _synthetic_case(db) -> Case:
    c = db.scalar(select(Case).where(Case.reference == "SYN-DIFF-001"))
    if c is None:
        c = Case(reference="SYN-DIFF-001", title="Synthetic diff case", loss_usd=Decimal(1000))
        db.add(c)
        db.commit()
    return c


def _synthetic_run(db, case: Case, nodes: list[tuple], edges: list[tuple]) -> TraceRun:
    """nodes: (address, hop, taint, terminal_reason|None); edges: (transfer, hop, taint)."""
    run = TraceRun(case=case, status=TraceStatus.COMPLETE, params={"provider_mode": "fixture", "max_hops": 12},
                   finished_at=datetime.now(tz=UTC))
    db.add(run)
    db.flush()
    for a, hop, taint, reason in nodes:
        db.add(TraceNode(run=run, address=a, hop=hop, taint_usd=Decimal(taint), taint_fraction=float(taint) / 1000,
                         is_terminal=reason is not None, terminal_reason=reason, flags=[]))
    for t, hop, taint in edges:
        db.add(TraceEdge(run=run, transfer=t, hop=hop, taint_usd=Decimal(taint)))
    db.commit()
    return run


@pytest.fixture
def two_runs(db):
    case = _synthetic_case(db)
    ex1, ex2 = _entity(db, "SynEx One"), _entity(db, "SynEx Two")
    R, X, Y, Z = (_addr(db, ch) for ch in "1234")
    K = _addr(db, "5", entity=ex1, kind=AddressType.DEPOSIT)
    M = _addr(db, "6", entity=ex2, kind=AddressType.DEPOSIT)
    t1 = _transfer(db, "0xsyn01", R, X, "0.6")
    t2 = _transfer(db, "0xsyn02", R, Y, "0.4")
    t3 = _transfer(db, "0xsyn003", X, K, "0.2")
    t4 = _transfer(db, "0xsyn0004", Y, Z, "0.15")
    t5 = _transfer(db, "0xsyn00005", X, M, "0.4")
    a = _synthetic_run(db, case, [(R, 1, "1000", None), (X, 2, "600", None), (Y, 2, "400", "max_hops"),
                                  (K, 3, "200", "vasp")],
                       [(t1, 1, "600"), (t2, 1, "400"), (t3, 2, "200")])
    b = _synthetic_run(db, case, [(R, 1, "1000", None), (X, 2, "600", None), (Y, 2, "250", None),
                                  (Z, 3, "150", "max_hops"), (M, 3, "400", "vasp")],
                       [(t1, 1, "600"), (t2, 1, "400"), (t4, 2, "150"), (t5, 2, "400")])
    return case, a, b, {"R": R, "X": X, "Y": Y, "Z": Z, "K": K, "M": M}


def test_diff_of_two_synthetic_runs(db, two_runs):
    _case, a, b, ad = two_runs
    d = diff_mod.diff(db, a, b)
    addr = {v.address: k for k, v in ad.items()}
    names = lambda items: sorted(addr[n.address] for n in items)
    assert names(d.nodes_added) == ["M", "Z"]
    assert names(d.nodes_removed) == ["K"]
    assert sorted(e.tx_hash for e in d.edges_added) == ["0xsyn00005", "0xsyn0004"]
    assert [e.tx_hash for e in d.edges_removed] == ["0xsyn003"]
    (ch,) = d.taint_changes
    assert addr[ch.node.address] == "Y" and ch.before == Decimal(400) and ch.after == Decimal(250)
    assert ch.delta == Decimal(-150)
    assert names(d.new_touchpoints) == ["M"] and d.new_touchpoints[0].entity == "SynEx Two"
    assert names(d.removed_touchpoints) == ["K"]
    assert names(d.new_terminals) == ["Z"]  # Y was already terminal in run a
    assert d.unchanged_nodes == 2 and d.unchanged_edges == 2
    # reversed direction mirrors the result
    r = diff_mod.diff(db, b, a)
    assert names(r.nodes_added) == ["K"] and names(r.new_touchpoints) == ["K"] and names(r.removed_touchpoints) == ["M"]
    assert diff_mod.diff(db, a, a).is_empty


def test_diff_api_and_compare_view(db, client_for, two_runs):
    case, a, b, ad = two_runs
    c = client_for("read_only", case=case, email="ro-syn@tests.example")
    j = c.get(f"/api/cases/{case.id}/trace/diff", params={"base": a.id, "head": b.id}).json()
    assert j["counts"]["nodes_added"] == 2 and j["counts"]["new_touchpoints"] == 1
    assert j["taint_changes"][0]["delta"] == "-150.00" and j["new_touchpoints"][0]["address"] == ad["M"].address
    page = c.get(f"/cases/{case.id}?tab=fund_flow&view=compare&base={a.id}&head={b.id}").text
    assert "New VASP / service touchpoints" in page and "SynEx Two" in page and "Taint changes per address" in page
    # without base, compare defaults to the run before head
    page = c.get(f"/cases/{case.id}?tab=fund_flow&view=compare&run_id={b.id}").text
    assert f'<option value="{a.id}" selected' in page and "SynEx Two" in page


def test_run_summary_figures(db, two_runs):
    case, a, b, _ = two_runs
    s = export.run_summary(db, b)
    assert (s.nodes, s.edges, s.max_hop, s.vasp_touchpoints) == (5, 4, 3, 1)
    assert s.total_taint_usd == Decimal("1000.00") and s.vasp_taint_usd == Decimal("400.00")
    assert [x.id for x in export.run_summaries(db, case)][:2] == [b.id, a.id]


def test_trace_completed_event_flags_new_touchpoints(db, two_runs, monkeypatch):
    case, a, b, ad = two_runs
    calls = []
    monkeypatch.setattr(diff_mod, "emit", lambda *args, **kw: calls.append((args, kw)))
    diff_mod.emit_trace_completed(db, case, b)
    (args, kw), = calls
    assert args[1] is case and args[2] == "trace_completed"
    assert kw["severity"] == "high" and kw["payload"] == {"trace_run_id": b.id, "previous_run_id": a.id,
                                                           "new_touchpoints": 1, "removed_touchpoints": 1}
    assert kw["usd"] == Decimal("400.00")
    assert "SYN-DIFF-001" in kw["title"] and "+2/-1 addresses" in kw["body"]
    assert "SynEx" not in kw["title"] + kw["body"] and "0x" not in kw["title"] + kw["body"]
    # the next run loses the touchpoint without reaching a new one: warning
    c = _synthetic_run(db, case, [(ad["R"], 1, "1000", None), (ad["X"], 2, "600", None)],
                       [(db.scalar(select(Transfer).where(Transfer.tx_hash == "0xsyn01")), 1, "600")])
    calls.clear()
    diff_mod.emit_trace_completed(db, case, c)
    (_, kw), = calls
    assert kw["severity"] == "warning" and kw["payload"]["removed_touchpoints"] == 1 and kw["usd"] == Decimal(0)


def test_pure_diff_handles_resolved_asserted_edges_and_small_deltas():
    n = lambda a, taint, **kw: NodeSnap("ethereum", a, 1, Decimal(taint), **kw)
    e = lambda tx, asserted=False: EdgeSnap("ethereum", tx, 0, "0xa", "0xb", "USDC", None, Decimal(5), 1, asserted)
    base = RunSnapshot.of(1, [n("0xa", "100"), n("0xb", "50.004")], [e("ASSERTED:relay", True)])
    head = RunSnapshot.of(2, [n("0xa", "100"), n("0xb", "50"), n("0xc", "9", terminal=True, terminal_reason="swap_service")],
                          [e("0xobserved")])
    d = diff_runs(base, head)
    assert [x.tx_hash for x in d.edges_removed] == ["ASSERTED:relay"] and [x.tx_hash for x in d.edges_added] == ["0xobserved"]
    assert d.taint_changes == []  # below min_delta
    assert [x.address for x in d.new_touchpoints] == ["0xc"] and d.new_terminals == []
    assert diff_runs(base, head, min_delta=Decimal("0.001")).taint_changes[0].delta == Decimal("-0.004")
