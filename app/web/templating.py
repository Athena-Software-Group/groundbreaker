"""The one Jinja2 environment for every web router (filters and globals live here).

Feature routers do `from app.web.templating import templates` and render with
`templates.TemplateResponse(request, "<file>.html", ctx)`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import markdown_it  # type: ignore
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context
from markupsafe import Markup

from app.core.config import get_settings
from app.core.csrf import csrf_field
from app.tracing.heuristics import FLAG_TEXT

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))
# Letter bodies interpolate case / fixture / form values: raw HTML in them must render as text.
_md = markdown_it.MarkdownIt("commonmark", {"html": False, "breaks": False})

# Feature stylesheets / scripts linked from base.html (one file each, owned by the feature).
FEATURES = ("trace", "authorities", "evidence", "team", "notifications", "assistant", "mail", "todo")


def _usd(v) -> str:
    if v is None:
        return "—"
    return f"${Decimal(v):,.2f}"


def _usd_short(v) -> str:
    """A compact dollar figure for narrow columns: $950, $63.8k, $1.2M (the exact one goes in a tooltip)."""
    if v is None:
        return "—"
    x = float(v)
    a = abs(x)
    if a >= 999_950:
        return f"${x / 1e6:,.1f}M".replace(".0M", "M")
    if a >= 999.5:
        return f"${x / 1e3:,.1f}k".replace(".0k", "k")
    return f"${x:,.0f}"


def _amt(v) -> str:
    if v is None:
        return "—"
    d = Decimal(v)
    q = Decimal("0.01") if abs(d) >= 1000 else Decimal("0.00000001")
    return f"{d.quantize(q).normalize():,f}"  # thousands separators: "399,247.92", as the USD figures read


def _dt(v: datetime | None) -> str:
    return v.astimezone(UTC).strftime("%d %b %Y %H:%M UTC") if v else "—"


def _render_md(s: str | None) -> Markup:
    return Markup(_md.render(s or ""))  # safe: html is disabled above, so any markup in s is escaped


def _app_info() -> dict:
    """The only configuration templates see — never the Settings object (it holds secrets)."""
    s = get_settings()
    return {"env": s.app_env, "provider_mode": s.provider_mode, "db": "sqlite" if s.is_sqlite else "postgres",
            "show_env": bool(s.aegis_show_env_badge)}  # AEGIS_SHOW_ENV_BADGE: the header's env line (base.html)


@pass_context
def current_user(ctx):
    """Jinja global: the signed-in User or None."""
    request = ctx.get("request")
    return getattr(request.state, "user", None) if request is not None else None


@pass_context
def mail_unassigned_count(ctx) -> int:
    """Jinja global: inbound e-mails waiting for a system admin to assign them (0 for everyone else)."""
    request = ctx.get("request")
    user = getattr(request.state, "user", None) if request is not None else None
    if user is None or not user.is_system_admin:
        return 0
    try:
        from sqlalchemy import func, select

        from app.db.models import MailDirection, MailMessage, MailStatus
        from app.db.session import SessionLocal

        with SessionLocal() as db:
            return db.scalar(select(func.count(MailMessage.id)).where(
                MailMessage.direction == MailDirection.IN, MailMessage.status == MailStatus.UNASSIGNED)) or 0
    except Exception:  # noqa: BLE001 - a badge must never break a page
        return 0


def may_create_cases(user) -> bool:
    """Jinja global: whether to offer "New case" (app.core.permissions.may_create_cases)."""
    from app.core.permissions import may_create_cases as _may

    return _may(user)


templates.env.filters.update(usd=_usd, usd_short=_usd_short, amt=_amt, dt=_dt, md=_render_md)
templates.env.globals.update(FLAG_TEXT=FLAG_TEXT, app_info=_app_info(), csrf_field=csrf_field,
                             current_user=current_user, FEATURES=FEATURES, may_create_cases=may_create_cases,
                             mail_unassigned_count=mail_unassigned_count,
                             inbox_unread=lambda: 0)  # replaced by app.web.routes_notifications

def demo_hidden(case, address) -> bool:
    """Jinja global: a demo / training case never shows a real organisation's e-mail address (the demo lock,
    app.domain.mail_compose.demo_lock_problem): the contact card and directory lists leave it out."""
    if case is None or not getattr(case, "is_demo", False) or not address or "@" not in str(address):
        return False
    from app.domain.mail_compose import demo_lock_problem

    return demo_lock_problem(case, [str(address)]) is not None


templates.env.globals.update(demo_hidden=demo_hidden)

from app.web.notice import pop_notice

templates.env.globals.update(pop_notice=pop_notice)

from app.web import mail_flow  # the send flow's return path: filter `mail_return`, its globals

mail_flow.register(templates)
