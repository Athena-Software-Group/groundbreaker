"""Fund-flow tab: trace runs (versions), the graph, movement listings, run diffs, exports, seeds and
the watch list.

Owner: the trace feature. Partial: templates/case/_tab_fund_flow.html (+ templates/trace_*.html for
its views); static: css/trace.css, js/trace.js (graph.js draws the Cytoscape graph).

Tab views: `/cases/{id}?tab=fund_flow&run_id=<run>&view=graph|movements|compare|runs`
(compare also takes `base` and `head` run ids).

Every run is kept: a re-run creates a new TraceRun (a version) and never edits an earlier one.
Investigators may label and annotate a run. Read-only members may view and download.

API (JSON unless noted), all under /api/cases/{case_id}/trace/:
    GET   runs                              every run with its summary figures
    GET   runs/export.{csv|txt|md}          the case-level listing of every run (download)
    GET   runs/{run_id}                     one run's summary
    PATCH runs/{run_id}                     {label?, notes?} (investigator)
    GET   runs/{run_id}/movements           every movement of the run
    GET   runs/{run_id}/movements.{csv|txt} movement listing (download)
    GET   runs/{run_id}/report.{md|docx}    the trace report (download)
    GET   diff?base=<run>&head=<run>        what changed between two runs
Downloads are built in memory and streamed; nothing is written to disk.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import services
from app.core.audit import EXPORT, LIVE_PROVIDER_QUERY, RUN_TRACE, UPDATE, audit
from app.core.csrf import require_csrf
from app.core.permissions import (
    INVESTIGATOR,
    READ_ONLY,
    CaseAccess,
    get_case_object,
    require_case_role,
)
from app.core.security import require_user
from app.db.models import Alert, Chain, SeedRole, TraceRun, WatchItem
from app.db.session import get_db
from app.domain import notify
from app.tracing import export
from app.tracing.annotate import FREEZE_STATUS_LABELS, annotate_elements
from app.tracing.diff import diff, emit_trace_completed, previous_run
from app.tracing.graph import build_graph, summary, to_cytoscape
from app.tracing.hover import display_labels, hover_data
from app.web.tabs import tab_context

router = APIRouter(tags=["trace"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]
ALERT_ACK = "ALERT_ACK"

VIEWS = ("graph", "movements", "compare", "runs")
TRACE_MODES = ("", "fixture", "live")  # "" = the configured default; anything else is refused (no typo goes live)
LABEL_MAX, NOTES_MAX = 128, 4000

MEDIA = {
    "csv": "text/csv; charset=utf-8",
    "txt": "text/plain; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


def _tab_url(case_id: int, run_id: int | None = None, view: str | None = None) -> str:
    url = f"/cases/{case_id}?tab=fund_flow"
    if run_id is not None:
        url += f"&run_id={int(run_id)}"
    if view and view != "graph":
        url += f"&view={view}"
    return url


def _int(v: str | None) -> int | None:
    return int(v) if v and v.isdigit() else None


def _clean(v: str | None, max_len: int) -> str | None:
    v = (v or "").strip()
    return v[:max_len] or None


# --------------------------------------------------------------------------- tab
@tab_context("fund_flow")
def fund_flow_tab(request: Request, db: Session, access: CaseAccess) -> dict:
    case = access.case
    q = request.query_params
    view = q.get("view") if q.get("view") in VIEWS else "graph"
    run_id = _int(q.get("run_id"))
    # 404 for another case's run (IDOR)
    run = get_case_object(db, TraceRun, run_id, access) if run_id else services.latest_run(db, case)
    runs = export.run_summaries(db, case)
    current = next((s for s in runs if run and s.id == run.id), None)
    ctx: dict = {"run": run, "runs": runs, "run_summary": current, "view": view, "graph": None, "stats": None,
                 "trace_modes": TRACE_MODES}
    if run is None:
        return ctx
    if view == "graph":
        g = build_graph(db, run)
        elements = to_cytoscape(g)
        # freeze status from the case's stop orders, recommended stop-order targets (deep links only
        # for members who may draft letters); no contact data enters the graph JSON
        recs = annotate_elements(db, case, run, elements, can_act=access.can("draft_letter"), owners=False)
        # data.hover: the hover cards (flows, status, owner, authority); the plan's moves only on the latest run, where
        # they also give the recommended actions their value, next step and order (the same as the Recovery plan)
        hover_data(db, case, run, elements, access, current=True if run_id is None else None, recs=recs)
        frozen: dict[str, int] = {}
        for n in elements["nodes"]:
            if n["data"].get("freeze_status"):
                frozen[n["data"]["freeze_status"]] = frozen.get(n["data"]["freeze_status"], 0) + 1
        ctx.update(graph=elements, stats=summary(g), recommendations=recs, freeze_counts=frozen,
                   freeze_labels=FREEZE_STATUS_LABELS, graph_labels=display_labels())
    elif view == "movements":
        rows = export.movements(db, run)
        ctx.update(movements=rows, chains=sorted({m.chain for m in rows}), assets=sorted({m.asset for m in rows}),
                   hops=sorted({m.hop for m in rows}), asserted_count=sum(1 for m in rows if m.asserted))
    elif view == "compare":
        head_id, base_id = _int(q.get("head")), _int(q.get("base"))
        head = get_case_object(db, TraceRun, head_id, access) if head_id else run
        base = get_case_object(db, TraceRun, base_id, access) if base_id else previous_run(db, head)
        ctx.update(head=head, base=base, diff=diff(db, base, head) if base is not None else None,
                   head_summary=next((s for s in runs if s.id == head.id), None),
                   base_summary=next((s for s in runs if base and s.id == base.id), None))
    return ctx


@router.get("/cases/{case_id}/trace")
def trace_tab(case_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY))):
    return RedirectResponse(f"/cases/{case_id}?tab=fund_flow", status_code=303)


@router.get("/cases/{case_id}/trace/runs/{run_id}/movements")
def movements_page(run_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                   db: Session = Depends(get_db)):
    run = get_case_object(db, TraceRun, run_id, access)
    return RedirectResponse(_tab_url(access.case.id, run.id, "movements"), status_code=303)


# --------------------------------------------------------------------------- page actions
@router.post("/cases/{case_id}/seeds", dependencies=_csrf)
def update_seed(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
                role: str = Form(...), chain: str = Form("ethereum"), value: str = Form(...), only_empty: str = Form("")):
    try:
        seed_role, seed_chain = SeedRole(role), Chain(chain)
    except ValueError:
        audit(db, access, UPDATE, access.case, ("case_seeds", None), outcome="denied", reason="invalid_input",
              role=role[:32], chain=chain[:32])
        raise HTTPException(400, "unknown seed role or chain") from None
    if not value.strip():
        raise HTTPException(400, "a seed value is required")
    if only_empty and any(s.role == seed_role for s in access.case.seeds):  # a proposal (evidence intel) never replaces
        raise HTTPException(409, "that seed is already set: change it on the case page")
    seed = services.update_seed(db, access.case, seed_role, seed_chain, value.strip())
    audit(db, access, UPDATE, access.case, seed, role=role, chain=chain)
    return RedirectResponse(f"/cases/{access.case.id}", status_code=303)


@router.post("/cases/{case_id}/trace", dependencies=_csrf)
def trace(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
          mode: str = Form(""), label: str = Form("")):
    """Run (or re-run) the trace. Each run is a new version; earlier runs stay as they were."""
    access.require("run_trace")
    if mode not in TRACE_MODES:
        raise HTTPException(400, f"unknown provider mode {mode!r}")
    run = services.run_trace(db, access.case, provider_mode=mode or None, actor=access.user,
                             label=_clean(label, LABEL_MAX))
    if run.params.get("provider_mode") == "live":
        audit(db, access, LIVE_PROVIDER_QUERY, access.case, run, purpose="trace")
    audit(db, access, RUN_TRACE, access.case, run, provider_mode=mode or "default", status=run.status,
          labelled=bool(run.label))
    emit_trace_completed(db, access.case, run)
    return RedirectResponse(_tab_url(access.case.id, run.id), status_code=303)


@router.post("/cases/{case_id}/trace/runs/{run_id}/annotate", dependencies=_csrf)
def annotate_run(run_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                 db: Session = Depends(get_db), label: str = Form(""), notes: str = Form(""),
                 view: str = Form("graph")):
    access.require("annotate_run")
    run = get_case_object(db, TraceRun, run_id, access)
    changed = _annotate(run, label=label, notes=notes)
    db.commit()
    audit(db, access, UPDATE, access.case, run, fields=changed)
    return RedirectResponse(_tab_url(access.case.id, run.id, view if view in VIEWS else None), status_code=303)


def _annotate(run: TraceRun, *, label: str | None = None, notes: str | None = None) -> list[str]:
    """Set label / notes (None = leave as is, "" = clear). Returns the names of changed fields."""
    changed = []
    if label is not None and _clean(label, LABEL_MAX) != run.label:
        run.label = _clean(label, LABEL_MAX)
        changed.append("label")
    if notes is not None and _clean(notes, NOTES_MAX) != run.notes:
        run.notes = _clean(notes, NOTES_MAX)
        changed.append("notes")
    return changed


@router.post("/cases/{case_id}/watch/poll", dependencies=_csrf)
def poll(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db)):
    alerts, notes = notify.poll_and_notify(db, access.case)
    audit(db, access, "POLL_WATCH", access.case, new_alerts=len(alerts), notifications=len(notes))
    return RedirectResponse(f"/cases/{access.case.id}?tab=overview#alerts", status_code=303)


def _case_alert(db: Session, access: CaseAccess, alert_id: int) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.watch_item is None or alert.watch_item.case_id != access.case.id:
        raise HTTPException(404, "alert not found")
    return alert


def _unacknowledged(db: Session, access: CaseAccess) -> list[Alert]:
    return list(db.scalars(select(Alert).join(WatchItem).where(WatchItem.case_id == access.case.id,
                                                               Alert.acknowledged.is_(False))))


def _acknowledge(db: Session, access: CaseAccess, alerts: list[Alert], *, scope: str) -> int:
    for a in alerts:
        a.acknowledged = True
    db.flush()
    audit(db, access, ALERT_ACK, access.case, alerts[0] if len(alerts) == 1 and scope == "one"
          else ("alerts", None), count=len(alerts), scope=scope, alert_ids=[a.id for a in alerts][:100])
    return len(alerts)


@router.post("/cases/{case_id}/watch/alerts/{alert_id:int}/ack", dependencies=_csrf)
def acknowledge_alert(alert_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                      db: Session = Depends(get_db)):
    """Mark one movement alert as reviewed (it no longer counts as an open item for the assistant)."""
    access.require("poll_watch")
    _acknowledge(db, access, [_case_alert(db, access, alert_id)], scope="one")
    return RedirectResponse(f"/cases/{access.case.id}?tab=overview#alerts", status_code=303)


@router.post("/cases/{case_id}/watch/alerts/ack-all", dependencies=_csrf)
def acknowledge_all_alerts(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                           db: Session = Depends(get_db)):
    access.require("poll_watch")
    alerts = _unacknowledged(db, access)
    if alerts:
        _acknowledge(db, access, alerts, scope="all")
    return RedirectResponse(f"/cases/{access.case.id}?tab=overview#alerts", status_code=303)


@router.post("/api/cases/{case_id}/watch/alerts/{alert_id:int}/ack")
def api_acknowledge_alert(alert_id: int, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                          db: Session = Depends(get_db)):
    access.require("poll_watch")
    alert = _case_alert(db, access, alert_id)
    _acknowledge(db, access, [alert], scope="one")
    return {"id": alert.id, "acknowledged": True}


@router.post("/api/cases/{case_id}/watch/alerts/ack-all")
def api_acknowledge_all_alerts(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                               db: Session = Depends(get_db)):
    access.require("poll_watch")
    alerts = _unacknowledged(db, access)
    return {"acknowledged": _acknowledge(db, access, alerts, scope="all") if alerts else 0}


# --------------------------------------------------------------------------- API: runs
class RunAnnotation(BaseModel):
    label: str | None = Field(None, max_length=LABEL_MAX)
    notes: str | None = Field(None, max_length=NOTES_MAX)


def _download(db: Session, access: CaseAccess, content: str | bytes, name: str, fmt: str, *, kind: str,
              run: TraceRun | None = None, rows: int | None = None) -> Response:
    audit(db, access, EXPORT, access.case, run, format=fmt, kind=kind,
          **({"rows": rows} if rows is not None else {}))
    body = content.encode("utf-8") if isinstance(content, str) else content
    return Response(body, media_type=MEDIA[fmt], headers={
        "Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store",
    })


@router.get("/api/cases/{case_id}/trace/runs")
def api_runs(access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db)):
    return [s.as_dict() for s in export.run_summaries(db, access.case)]


# declared before runs/{run_id}, which would otherwise capture "export.csv"
@router.get("/api/cases/{case_id}/trace/runs/export.{fmt}")
def api_runs_export(fmt: str, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                    db: Session = Depends(get_db)):
    access.require("export")
    summaries = export.run_summaries(db, access.case)
    if fmt == "csv":
        content = export.runs_csv(summaries)
    elif fmt == "txt":
        content = export.runs_txt(access.case, summaries)
    elif fmt == "md":
        content = export.runs_markdown(access.case, summaries)
    else:
        raise HTTPException(404, "format must be csv, txt or md")
    return _download(db, access, content, export.filename(access.case, "trace-runs", fmt), fmt, kind="runs",
                     rows=len(summaries))


@router.get("/api/cases/{case_id}/trace/runs/{run_id}")
def api_run(run_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db)):
    run = get_case_object(db, TraceRun, run_id, access)
    return export.run_summary(db, run).as_dict()


@router.patch("/api/cases/{case_id}/trace/runs/{run_id}")
def api_annotate_run(run_id: int, payload: RunAnnotation, access: CaseAccess = Depends(require_case_role(INVESTIGATOR)),
                     db: Session = Depends(get_db)):
    access.require("annotate_run")
    run = get_case_object(db, TraceRun, run_id, access)
    changed = _annotate(run, label=payload.label, notes=payload.notes)
    db.commit()
    audit(db, access, UPDATE, access.case, run, fields=changed)
    return export.run_summary(db, run).as_dict()


@router.get("/api/cases/{case_id}/trace/runs/{run_id}/movements")
def api_movements(run_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                  db: Session = Depends(get_db)):
    run = get_case_object(db, TraceRun, run_id, access)
    return {"run": export.run_summary(db, run).as_dict(), "movements": [m.as_dict() for m in export.movements(db, run)]}


@router.get("/api/cases/{case_id}/trace/runs/{run_id}/movements.{fmt}")
def api_movements_export(run_id: int, fmt: str, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
                         db: Session = Depends(get_db)):
    access.require("export")
    run = get_case_object(db, TraceRun, run_id, access)
    rows = export.movements(db, run)
    if fmt == "csv":
        content = export.movements_csv(rows)
    elif fmt == "txt":
        content = export.movements_txt(access.case, run, rows, export.run_summary(db, run))
    else:
        raise HTTPException(404, "format must be csv or txt")
    return _download(db, access, content, export.filename(access.case, "movements", fmt, run), fmt,
                     kind="movements", run=run, rows=len(rows))


@router.get("/api/cases/{case_id}/trace/runs/{run_id}/report.{fmt}")
def api_report(run_id: int, fmt: str, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
               db: Session = Depends(get_db)):
    access.require("export")
    run = get_case_object(db, TraceRun, run_id, access)
    if fmt not in ("md", "docx"):
        raise HTTPException(404, "format must be md or docx")
    report = export.build_report(db, access.case, run)
    content = export.report_markdown(report) if fmt == "md" else export.report_docx(report)
    return _download(db, access, content, export.filename(access.case, "trace-report", fmt, run), fmt,
                     kind="report", run=run, rows=len(report.movements))


@router.get("/api/cases/{case_id}/trace/diff")
def api_diff(base: int, head: int, access: CaseAccess = Depends(require_case_role(READ_ONLY)),
             db: Session = Depends(get_db)):
    base_run = get_case_object(db, TraceRun, base, access)
    head_run = get_case_object(db, TraceRun, head, access)
    return diff(db, base_run, head_run).as_dict()
