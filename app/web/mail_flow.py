"""The guided send flow's return path: where a member goes back to once an e-mail went out.

Owner: the mail feature (app/web/routes_mail.py). A page that opens the e-mail editor (the To do tab, the
Authorities tab's board, the Recovery plan, Block status, the authority page, a letter or a stop order) passes
`return_to` (the page itself, or the `return_to` it was opened with); the editor, its confirmation, the preview's
Send form and the "Sending…" screen carry it along, and once the mailbox confirmed the send the member lands back
there with `mail_sent=<id>` (the success banner, `_mail_sent_banner.html` in base.html).

    safe_return(raw, case_id)        a same-origin path of this case's pages, or None (never an open redirect)
    with_query(path, **params)       the path with these query parameters set (replacing any of the same name)
    {{ href | mail_return }}         Jinja filter: an editor-bound link gets `return_to` (other links unchanged)
    {{ mail_return_to() }}           Jinja global: the validated `return_to` of this request ('' when none)
    {{ mail_sent_banner() }}         Jinja global: the banner for `?mail_sent=<id>` (None unless it is this case's
                                     sent e-mail)

`return_to` is only ever a path of the same case (`/cases/<id>` and below): no scheme, no host, no `//`, no
backslash, no control character, no `.` / `..` segment, at most `RETURN_MAX` characters. Anything else is dropped,
and the flow falls back to the authority's page.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import unquote, unquote_plus, urlencode, urlsplit

from jinja2 import pass_context

log = logging.getLogger(__name__)

RETURN_MAX = 400
# the editor's way in: a stop order, a letter (and its editor), an authority's page, a prepared e-mail
_FLOW = re.compile(r"/cases/(\d{1,12})/(?:stop-orders/\d{1,12}|authorities/correspondence/\d{1,12}(?:/email)?|"
                   r"authorities/[a-z]{1,16}-\d{1,12}|mail/messages/\d{1,12})/?")
_PATH_OK = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=:@%/-]*")
# never part of the page a member returns to: the flow's own, a letter form's, one-off notices
TRANSIENT = ("return_to", "mail_sent", "send_failed", "confirm", "template", "about", "freeze_address", "ref",
             "added", "done", "r", "cancelled", "dropped")


def safe_return(raw, case_id) -> str | None:
    """`raw` when it is a path of case `case_id`'s pages (module doc), else None."""
    if not isinstance(raw, str) or case_id is None:
        return None
    s = raw.strip()
    if not s or len(s) > RETURN_MAX or not s.isprintable() or any(c in s for c in "\\ \t\r\n"):
        return None
    if not s.startswith("/") or s.startswith("//"):
        return None
    try:
        parts = urlsplit(s)
    except ValueError:
        return None
    if parts.scheme or parts.netloc or not _PATH_OK.fullmatch(parts.path):
        return None
    if any(unquote(seg) in (".", "..") for seg in parts.path.split("/")):  # %2e%2e too
        return None
    base = f"/cases/{int(case_id)}"
    if parts.path != base and not parts.path.startswith(base + "/"):
        return None
    return s


def with_query(path: str, **params) -> str:
    """`path` with `params` set in its query (replacing those names; None drops one), its fragment kept."""
    parts = urlsplit(path)
    # the other parameters stay exactly as written (a link's own encoding is never changed)
    keep = [p for p in parts.query.split("&") if p and unquote_plus(p.partition("=")[0]) not in params]
    new = urlencode([(k, str(v)) for k, v in params.items() if v is not None])
    query = "&".join([*keep, *([new] if new else [])])
    return parts.path + (f"?{query}" if query else "") + (f"#{parts.fragment}" if parts.fragment else "")


def _case_id(ctx):
    case = ctx.get("case") or getattr(ctx.get("access"), "case", None)
    return getattr(case, "id", None)


def current_return(request, case_id) -> str | None:
    """The page a link on this request's page returns to: the `return_to` it was opened with, else itself (without
    the flow's own parameters)."""
    if request is None or case_id is None:
        return None
    inbound = safe_return(request.query_params.get("return_to"), case_id)
    if inbound:
        return inbound
    here = request.url.path
    query = urlencode([(k, v) for k, v in request.query_params.multi_items() if k not in TRANSIENT])
    return safe_return(here + (f"?{query}" if query else ""), case_id)


@pass_context
def mail_return(ctx, href, anchor: str | None = None):
    """Jinja filter: `href` with `return_to` added when it leads to the e-mail editor (module doc); `anchor` is the
    fragment to come back to (e.g. the board row). Any other link, or no case on the page: unchanged."""
    if not href or not isinstance(href, str):
        return href
    case_id = _case_id(ctx)
    m = _FLOW.match(urlsplit(href).path or "")
    if case_id is None or m is None or int(m.group(1)) != int(case_id) or m.end() != len(urlsplit(href).path):
        return href
    back = current_return(ctx.get("request"), case_id)
    if not back:
        return href
    if anchor and "#" not in back and re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", str(anchor)):
        back = f"{back}#{anchor}"
    return with_query(href, return_to=back)


@pass_context
def mail_return_to(ctx) -> str:
    """Jinja global: this request's validated `return_to` ('' when none), for the flow's hidden fields."""
    request = ctx.get("request")
    if request is None:
        return ""
    return safe_return(request.query_params.get("return_to"), _case_id(ctx)) or ""


@pass_context
def mail_sent_banner(ctx) -> dict | None:
    """Jinja global: {id, letter, order, due, href} for `?mail_sent=<id>` when that is an e-mail of this page's case
    that went out, and the viewer is a member of the case; else None. Never breaks a page."""
    request = ctx.get("request")
    access = ctx.get("access")
    case = ctx.get("case") or getattr(access, "case", None)
    raw = request.query_params.get("mail_sent") if request is not None else None
    if not raw or not str(raw).isdigit() or len(str(raw)) > 12 or case is None or access is None \
            or getattr(access, "is_external", True):
        return None
    try:
        from sqlalchemy.orm import object_session

        from app.db.models import Correspondence, MailDirection, MailMessage, MailStatus

        db = object_session(case)
        if db is None:
            return None
        mm = db.get(MailMessage, int(raw))
        if mm is None or mm.case_id != case.id or mm.direction != MailDirection.OUT or \
                mm.status not in (MailStatus.SENT, MailStatus.SENT_EXTERNAL):
            return None
        corr = db.get(Correspondence, mm.correspondence_id) if mm.correspondence_id else None
        return {"id": mm.id, "letter": corr.id if corr is not None else None,
                "order": corr.stop_order_id if corr is not None else None,
                "due": corr.due_at if corr is not None else None,
                "external": mm.status == MailStatus.SENT_EXTERNAL,
                "href": f"/cases/{case.id}/mail/messages/{mm.id}"}
    except Exception as err:  # noqa: BLE001 - a banner must never break a page
        log.warning("mail sent banner failed (%s)", type(err).__name__)
        return None


def register(templates) -> None:
    templates.env.filters["mail_return"] = mail_return
    templates.env.globals.update(mail_return_to=mail_return_to, mail_sent_banner=mail_sent_banner)
