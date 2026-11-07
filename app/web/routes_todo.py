"""To do (app.domain.todo): the case's consolidated list of what should be done, with priority and due date.

    GET  /cases/{id}/todo                read_only+    → the To do tab (?tab=todo)
    GET  /api/cases/{id}/todo            read_only+    the open tasks as JSON (masked as on the tab)
    POST /cases/{id}/todo/add            investigator  a manual task: title, priority, due, assignee, note (CREATE audit)
    POST /cases/{id}/todo/task           investigator  key + op: done | reopen | snooze (days 1 / 3 / 7) | dismiss (note)
                                                       | edit (priority, due, assignee; a manual task's title and note)
                                                       (UPDATE audit)

The tab itself is the case page's "To do" tab (app/web/tabs.py, right after Overview; its context provider is
`todo_tab`), with the open P1 count on the tab bar (`todo_badge`) and the Overview's To do card (`todo_card`, a table of the top `CARD_ROWS`).
Every POST is a CSRF-protected web form, audited with ids, the op, the source and the changed field names only (never
a title, a note or a key that may carry an address). A derived task's own action is the source page's: nothing here
drafts, sends or confirms anything.

Wiring: `app.main` includes `router`. Importing this module registers the tab's context provider and the Jinja globals
`todo_badge(case, access)` and `todo_card(case, access)`.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session, object_session

from app.core.audit import CREATE, UPDATE, audit
from app.core.csrf import require_csrf
from app.core.permissions import INVESTIGATOR, READ_ONLY, CaseAccess, require_case_role
from app.core.security import require_user
from app.db.session import get_db
from app.domain import recovery_route, todo
from app.web import tabs
from app.web.templating import templates

log = logging.getLogger(__name__)
router = APIRouter(tags=["todo"], dependencies=[Depends(require_user)])
_csrf = [Depends(require_csrf)]
SHOW = ("all", "mine", "p1")
CARD_ROWS = 8  # the Overview card's table: the top open tasks, overdue first (todo.open_tasks)
DONE_TEXT = {"add": "Task added.", "done": "Marked done.", "reopen": "Reopened.", "snooze": "Snoozed.",
             "dismiss": "Dismissed: it stays hidden until its source changes.", "edit": "Saved."}


BADGE_TTL = 60.0  # seconds a badge count read on another tab may be old (this process; any change here clears it)
_BADGE: dict[tuple[int, int, str], tuple[float, int]] = {}  # (case, user, role) -> (monotonic time, open P1 count)


def _badge_key(case_id: int, access: CaseAccess) -> tuple[int, int, str]:
    return case_id, access.user.id, access.role.value


def _forget(case_id: int) -> None:
    for k in [k for k in _BADGE if k[0] == case_id]:
        _BADGE.pop(k, None)


def _memo(access: CaseAccess, case_id: int):
    m = getattr(access, "_todo", None)
    return m["tasks"] if isinstance(m, dict) and m.get("case") == case_id else None


def _remember(access: CaseAccess, case_id: int, tasks) -> None:
    access._todo = {"case": case_id, "tasks": tasks}  # this request's CaseAccess: the memo lives as long as it
    _BADGE[_badge_key(case_id, access)] = (time.monotonic(), todo.p1_open(tasks))


def _tasks(db: Session, access: CaseAccess, *, persist: bool = True):
    tasks = _memo(access, access.case.id)
    if tasks is None:
        tasks = todo.build(db, access.case, access, persist=persist)
        _remember(access, access.case.id, tasks)
    return tasks


def _filters(show: str | None, source: str | None) -> tuple[str, str | None]:
    return (show if show in SHOW else "all"), (source if source in todo.SOURCES else None)


def _back(case_id: int, show: str | None, source: str | None, *, done: str | None = None, anchor: str = "") -> str:
    show, source = _filters(show, source)
    q = {"tab": "todo"}
    if show != "all":
        q["show"] = show
    if source:
        q["source"] = source
    if done:
        q["done"] = done
    return f"/cases/{case_id}?{urlencode(q)}" + (f"#t-{anchor}" if anchor else "")


def _row_view(t: todo.Task, access: CaseAccess, now: datetime) -> dict:
    return {"key": t.key, "title": t.title, "why": t.why, "priority": t.priority, "source": t.source,
            "source_label": t.source_label, "status": t.status, "due_at": t.due.isoformat() if t.due else None,
            "due_label": t.due_label or None, "overdue": t.overdue(now), "value_usd": t.value, "manual": t.manual,
            "assignee": t.assignee, "mine": t.assignee_id == access.user.id,
            "action": ({"label": t.action.label, "href": t.action.href, "post": t.action.post}
                       if t.action is not None and todo.may(access, t.action) else None)}


@tabs.tab_context("todo")
def todo_tab(request: Request, db: Session, access: CaseAccess) -> dict:
    now = datetime.now(tz=UTC)
    tasks = _tasks(db, access)
    show, source = _filters(request.query_params.get("show"), request.query_params.get("source"))
    open_ = todo.open_tasks(tasks, now)
    rows = [t for t in open_ if (show != "mine" or t.assignee_id == access.user.id)
            and (show != "p1" or t.priority == todo.P1) and (source is None or t.source == source)]
    sources = sorted({t.source for t in open_}, key=lambda s: list(todo.SOURCES).index(s))
    return {
        "todo_rows": rows, "todo_open": len(open_), "todo_p1": todo.p1_open(tasks),
        "todo_overdue": sum(1 for t in open_ if t.overdue(now)),
        "todo_mine": sum(1 for t in open_ if t.assignee_id == access.user.id),
        "todo_done": todo.done_recently(tasks, now), "todo_snoozed": todo.snoozed(tasks),
        "todo_failed": [todo.SOURCES.get(s, s) for s in tasks.failed], "todo_show": show, "todo_source": source,
        "todo_sources": [(s, todo.SOURCES[s]) for s in sources], "todo_all_sources": todo.SOURCES,
        "todo_can_act": access.can(todo.ACT_PERM), "todo_may": lambda a: todo.may(access, a),
        "todo_assignees": todo.assignees(db, access.case) if access.can(todo.ACT_PERM) else [],
        "todo_priorities": todo.PRIORITY_LABELS, "todo_snooze_days": todo.SNOOZE_DAYS, "todo_relative": todo.relative,
        "todo_flash": DONE_TEXT.get(request.query_params.get("done") or ""), "now": now,
        "todo_route": None if access.is_external else recovery_route.view(db, access.case, tasks),
    }


@router.get("/cases/{case_id}/todo")
def todo_page(case_id: int, access: CaseAccess = Depends(require_case_role(READ_ONLY))):
    return RedirectResponse(f"/cases/{access.case.id}?tab=todo", status_code=303)


@router.get("/api/cases/{case_id}/todo")
def api_todo(access: CaseAccess = Depends(require_case_role(READ_ONLY)), db: Session = Depends(get_db)):
    now = datetime.now(tz=UTC)
    tasks = _tasks(db, access)
    return JSONResponse({"case": access.case.reference, "generated_at": now.isoformat(),
                         "open": [_row_view(t, access, now) for t in todo.open_tasks(tasks, now)],
                         "p1_open": todo.p1_open(tasks), "failed_sources": tasks.failed,
                         "advisory": "Aegis's list from the case's state (rules, no AI): a person does every step."})


@router.post("/cases/{case_id}/todo/add", dependencies=_csrf)
def todo_add(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
             title: str = Form(""), priority: str = Form("P2"), due: str = Form(""), assignee_id: str = Form(""),
             note: str = Form(""), show: str = Form(""), source: str = Form("")):
    try:
        row = todo.create(db, access, title=title, priority=priority, due=due, assignee_id=assignee_id, note=note)
    except todo.TodoError as e:
        db.rollback()
        raise HTTPException(e.status, str(e)) from None
    _forget(access.case.id)
    audit(db, access, CREATE, access.case, row, source=todo.MANUAL, priority=row.priority_override,
          fields=[f for f, v in (("title", row.title), ("note", row.note), ("due", row.due_override),
                                 ("assignee", row.assignee_id)) if v], assignee_id=row.assignee_id)
    return RedirectResponse(_back(access.case.id, show, source, done="add", anchor=todo.anchor(row.key)),
                            status_code=303)


@router.post("/cases/{case_id}/todo/task", dependencies=_csrf)
def todo_task(access: CaseAccess = Depends(require_case_role(INVESTIGATOR)), db: Session = Depends(get_db),
              key: str = Form(""), op: str = Form(""), days: str = Form(""), note: str | None = Form(None),
              priority: str = Form(""), due: str = Form(""), assignee_id: str = Form(""),
              title: str | None = Form(None), show: str = Form(""), source: str = Form("")):
    if not todo.KEY_RE.fullmatch(key or "") or op not in todo.OPS:
        raise HTTPException(400, "unknown task or change")
    task = todo.find(todo.build(db, access.case, access), key)
    if task is None:  # not derived now and no row: it cleared meanwhile (or never existed)
        raise HTTPException(404, "this task is no longer on the list (its source changed): reload the page")
    try:
        row, changed = todo.apply(db, access, task, op, days=days, note=note, priority=priority, due=due,
                                  assignee_id=assignee_id, title=title)
    except todo.TodoError as e:
        db.rollback()
        raise HTTPException(e.status, str(e)) from None
    _forget(access.case.id)
    detail = {"op": op, "source": row.source, "derived": task.derived, "fields": changed}
    if op == "snooze":
        detail["days"] = int(days)
    if op == "edit":
        detail.update(priority=row.priority_override, assignee_id=row.assignee_id, has_due=row.due_override is not None)
    audit(db, access, UPDATE, access.case, row, **detail)
    return RedirectResponse(_back(access.case.id, show, source, done=op, anchor=todo.anchor(row.key)),
                            status_code=303)


# --------------------------------------------------------------------------- Jinja globals
def _overview_tasks(case, access):
    """The Overview's tasks: built in the Overview cards' own pass (routes_recovery.overview_cards: one case_blocks
    read for the Block status, Recovery plan and To do cards and the badge)."""
    from app.web.routes_recovery import overview_cards

    tasks = overview_cards(case, access).get("todo")
    if tasks is not None:
        _remember(access, case.id, tasks)
    return tasks


def todo_badge(case, access, tab: str | None = None, board=None) -> int:
    """The tab bar's badge: the open P1 tasks this member sees (0 on any failure; never breaks a page). The To do tab
    and the Overview count from their own pass, the Authorities tab from its own board (`board`); another page reads
    the count of the last build (at most `BADGE_TTL` old: the To do tab, the Overview, a change on the list), else
    builds the list once with the page's session (nothing written)."""
    if access is None or getattr(access, "is_external", True) or not access.can("view"):
        return 0
    try:
        tasks = _memo(access, case.id)
        if tasks is None and tab == "overview":
            tasks = _overview_tasks(case, access)
        if tasks is None and board is None:
            hit = _BADGE.get(_badge_key(case.id, access))
            if hit is not None and time.monotonic() - hit[0] < BADGE_TTL:
                return hit[1]
        if tasks is None:
            db = object_session(case)
            if db is None:
                return 0
            tasks = todo.build(db, case, access, persist=False, board=board)
            _remember(access, case.id, tasks)
        return todo.p1_open(tasks)
    except Exception as err:  # noqa: BLE001 - a badge must never break a page
        log.warning("to do badge failed for case %s (%s)", getattr(case, "id", None), type(err).__name__)
        return 0


def todo_card(case, access) -> dict | None:
    """The Overview's To do card (todo_card.html): a table of the top `CARD_ROWS` open tasks (overdue first, as on the
    tab) with each task's own action (shown as on the tab: `todo.may`), and the counts; None on failure."""
    if access is None or access.is_external:
        return None
    now = datetime.now(tz=UTC)
    try:
        tasks = _memo(access, case.id)
        if tasks is None:
            tasks = _overview_tasks(case, access)
        if tasks is None:
            return None
        open_ = todo.open_tasks(tasks, now)
        rows = open_[:CARD_ROWS]
        return {"rows": rows, "n": len(open_), "more": len(open_) - len(rows), "p1": todo.p1_open(tasks),
                "overdue": sum(1 for t in open_ if t.overdue(now)), "now": now, "relative": todo.relative,
                "may": lambda a: todo.may(access, a)}
    except Exception as err:  # noqa: BLE001 - the Overview renders without the card
        log.warning("to do card failed for case %s (%s)", getattr(case, "id", None), type(err).__name__)
        return None


templates.env.globals["todo_badge"] = todo_badge
templates.env.globals["todo_card"] = todo_card
