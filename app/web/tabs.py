"""Case page tabs: the fixed tab list and a registry of per-tab context providers.

The case page (`GET /cases/{case_id}?tab=<key>`, app/web/routes.py) renders the shell
`case_detail.html` and includes only the active tab's partial `case/_tab_<key>.html`. A tab with an `href` is its
own page (the Recovery plan, app/web/routes_recovery.py): its link goes there, `?tab=<key>` redirects, and the page
shows the same tab bar (`case/_tabs_nav.html`). The
partial's template context comes from the provider its feature router registers:

    from app.web.tabs import tab_context

    @tab_context("evidence")
    def evidence_tab(request, db, access) -> dict:
        return {"items": ...}

Every partial also sees the shell context: `case`, `access` (CaseAccess), `tab`, `tabs`,
`can(action)` and `request`. A provider runs only when its tab is the active one.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Request
from sqlalchemy.orm import Session

from app.db.models import CaseRole


@dataclass(frozen=True)
class Tab:
    key: str
    label: str
    min_role: CaseRole  # tab hidden (and its URL falls back to the first visible tab) below this
    owner: str  # router module that owns the partial and its context provider
    href: str | None = None  # a tab that is its own page (/cases/{id}<href>): ?tab=<key> redirects there


TABS: tuple[Tab, ...] = (
    Tab("overview", "Overview", CaseRole.READ_ONLY, "app.web.routes"),
    Tab("todo", "To do", CaseRole.READ_ONLY, "app.web.routes_todo"),
    Tab("recovery", "Recovery plan", CaseRole.READ_ONLY, "app.web.routes_recovery", href="/recovery-plan"),
    Tab("fund_flow", "Fund flow", CaseRole.READ_ONLY, "app.web.routes_trace"),
    Tab("authorities", "Authorities", CaseRole.EXTERNAL, "app.web.routes_authorities"),
    Tab("evidence", "Evidence", CaseRole.EXTERNAL, "app.web.routes_evidence"),
    Tab("team", "Team", CaseRole.READ_ONLY, "app.web.routes_team"),
    Tab("notifications", "Notifications", CaseRole.READ_ONLY, "app.web.routes_notifications"),
    Tab("assistant", "AI Assistant (Pythia)", CaseRole.READ_ONLY, "app.web.routes_assistant"),
)
TAB_KEYS = tuple(t.key for t in TABS)

TabContext = Callable[[Request, Session, object], dict]
_providers: dict[str, TabContext] = {}


def tab_context(key: str) -> Callable[[TabContext], TabContext]:
    """Decorator registering the context provider of tab `key` (one per tab)."""
    if key not in TAB_KEYS:
        raise KeyError(f"unknown case tab {key!r}; tabs are {TAB_KEYS}")

    def register(fn: TabContext) -> TabContext:
        _providers[key] = fn
        return fn

    return register


def context_for(key: str, request: Request, db: Session, access) -> dict:
    fn = _providers.get(key)
    return fn(request, db, access) if fn else {}
