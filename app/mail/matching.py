"""Which case and letter does an inbound e-mail answer?

    result = match(db, parsed, mailbox="case-desk@…", conversation_id=None, transport="graph")

| Step | Rule | Result |
|---|---|---|
| 0 | From is the case mailbox itself | ignored (a loop) |
| 1 | an id in In-Reply-To / References (or a bounce's original Message-ID) is the Message-ID or internetMessageId of an outbound e-mail Aegis **sent** | method header: confident only from one of the authority's own domains **and** with an Authentication-Results pass for the From domain (graph transport), like a tag; a bounce (a delivery-status report by structure) only from the case mailbox's own MTA identity **and** authenticated (`trusted_bounce`); else needs review on that case |
| 2 | the subject carries `[Aegis <REF> #<corr id>]`, the case exists (reference, ignoring case) and the letter is an outbound sent letter of that case | method tag: as step 1 (own domain, authenticated, not the file transport) |
| 3 | Graph's conversationId equals a sent outbound e-mail's | as step 2 |
| 4 | nothing | unassigned |

**The authority's own domains** are those of the letter's To recipients, the entity's compliance
address, the authority's LE contacts and the e-mail channels in its contact directory; a subdomain of
one counts. Never part of it: the letter's Cc (the victim, our own team), free-mail and shared
providers (`SHARED_DOMAINS`: anyone can hold an address there), the case mailbox's domain and the
sender profile's own addresses.

**Authentication** (`ParsedEmail.from_authenticated`): the subject tag is printed in every sent
subject and letter ids are sequential, so a tag proves nothing on its own; a Message-ID reaches
everyone the letter was sent or forwarded to; and a From header can be forged. A header, tag or
conversation match is filed automatically only when the topmost
Authentication-Results header (Exchange Online stamps it on receipt) reports dmarc=pass or
compauth=pass for the From domain. The file transport (local demos) has no receiving MTA: there a
header, tag or conversation match always waits for review.

**Bounces** are filed automatically only when all of these hold (`trusted_bounce` /
`bounce_problem`): the message is a delivery-status report by its **structure**
(app.mail.inbound: multipart/report delivery-status, a message/delivery-status part, or an Exchange
NDR returning the original; a postmaster / mailer-daemon From alone never makes one); it comes from
the case mailbox's **own MTA identity** (postmaster / mailer-daemon / Exchange's
MicrosoftExchange<hex> system sender on the mailbox's domain or a subdomain); it is
**authenticated**: the topmost Authentication-Results passes DMARC / compauth for that domain, or,
on the graph transport, the message's internetMessageHeaders show Exchange generated it inside our
tenant (`exchange_generated`: CrossTenant-Id = AEGIS_M365_TENANT_ID, Organization-AuthAs Internal,
Is-Ndr); and it names the Message-ID of an e-mail Aegis sent. Never on the file transport. Any
other "bounce" waits for review; a postmaster message that is not a report is matched like any
other mail (and the mailbox's own domain is never the authority's).

A tag naming an unknown case or letter goes to unassigned with a generic reason, so a forged subject
never reveals whether a case exists.

The decision itself (`decide`) works on plain dicts through a `Lookup`, so it is testable without a DB.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Protocol

from app.mail.inbound import BOUNCE_SENDERS, ParsedEmail

_log = logging.getLogger("app.mail")
TAG_RE = re.compile(r"\[Aegis ([A-Za-z0-9._-]{3,64}) #(\d{1,12})\]")
_DOMAIN_RE = re.compile(r"@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")

HEADER, TAG, CONVERSATION, NONE, LOOP = "header", "tag", "conversation", "none", "loop"

# Free-mail and shared providers: an address there says nothing about who the sender works for.
SHARED_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "outlook.it", "outlook.de", "outlook.fr", "hotmail.com",
    "hotmail.it", "hotmail.co.uk", "hotmail.de", "hotmail.fr", "live.com", "live.it", "msn.com", "yahoo.com",
    "yahoo.it", "yahoo.co.uk", "yahoo.de", "yahoo.fr", "ymail.com", "rocketmail.com", "icloud.com", "me.com",
    "mac.com", "aol.com", "gmx.com", "gmx.de", "gmx.net", "gmx.ch", "gmx.at", "web.de", "t-online.de",
    "proton.me", "protonmail.com", "protonmail.ch", "pm.me", "tutanota.com", "tutanota.de", "tuta.io",
    "mail.com", "email.com", "zoho.com", "zohomail.com", "yandex.ru", "yandex.com", "mail.ru", "inbox.ru",
    "bk.ru", "list.ru", "qq.com", "163.com", "126.com", "sina.com", "naver.com", "fastmail.com", "hey.com",
    "libero.it", "virgilio.it", "tiscali.it", "alice.it", "tim.it", "email.it", "fastwebnet.it", "bluewin.ch",
    "orange.fr", "free.fr", "laposte.net", "wanadoo.fr", "sfr.fr", "btinternet.com", "comcast.net",
    "verizon.net", "att.net", "onmicrosoft.com", "googlegroups.com",
})


def tracking_tag(case, corr) -> str:
    return f"[Aegis {case.reference} #{corr.id}]"


def parse_tag(subject: str | None) -> tuple[str, int] | None:
    m = TAG_RE.search(subject or "")
    return (m.group(1), int(m.group(2))) if m else None


def domains_of(values) -> set[str]:
    out = set()
    for v in values or []:
        for d in _DOMAIN_RE.findall(str(v or "")):
            out.add(d.lower())
    return out


def own_domains(domains, exclude=()) -> set[str]:
    """`domains` without shared / free-mail providers and without `exclude` (and their subdomains)."""
    ex = {d.lower() for d in exclude if d}
    return {d.lower() for d in domains or () if d and d.lower() not in SHARED_DOMAINS
            and not any(d.lower() == e or d.lower().endswith("." + e) for e in ex)}


_EXCHANGE_SYSTEM = re.compile(r"microsoftexchange[0-9a-f]{32}")
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
MAX_PROVIDER_HEADERS = 500


def _mailbox_mta(parsed: ParsedEmail, mailbox_domain: str | None) -> bool:
    """From is the case mailbox's own MTA identity: postmaster / mailer-daemon / Exchange's
    MicrosoftExchange<32 hex> system sender, on the mailbox's domain or a subdomain of it."""
    if not mailbox_domain or not parsed.from_addr or "@" not in parsed.from_addr:
        return False
    local, _, dom = parsed.from_addr.lower().rpartition("@")
    mbx = mailbox_domain.lower()
    if not (dom == mbx or dom.endswith("." + mbx)):
        return False
    return local in BOUNCE_SENDERS or bool(_EXCHANGE_SYSTEM.fullmatch(local))


def _first_header(headers, name: str) -> str | None:
    """The topmost header `name` in a Graph internetMessageHeaders list ([{name, value}, …])."""
    want = name.lower()
    for h in list(headers or [])[:MAX_PROVIDER_HEADERS]:
        if isinstance(h, dict) and str(h.get("name") or "").strip().lower() == want:
            return str(h.get("value") or "").strip()
    return None


def exchange_generated(headers, tenant_id: str | None) -> bool:
    """Graph transport: do the message's internetMessageHeaders show a non-delivery report that
    Exchange Online generated inside our own tenant? All of: the topmost
    X-MS-Exchange-CrossTenant-Id is our tenant (a GUID: AEGIS_M365_TENANT_ID), the topmost
    X-MS-Exchange-Organization-AuthAs is Internal (Exchange strips X-MS-Exchange-Organization-*
    headers from mail arriving from outside the organisation, so a sender cannot write it), and
    X-MS-Exchange-Message-Is-Ndr is present. A tenant configured by domain name never matches."""
    tid = (tenant_id or "").strip().lower()
    if not _GUID.fullmatch(tid):
        return False
    cross = (_first_header(headers, "X-MS-Exchange-CrossTenant-Id") or "").lower()
    auth_as = (_first_header(headers, "X-MS-Exchange-Organization-AuthAs") or "").lower()
    return cross == tid and auth_as == "internal" and _first_header(headers, "X-MS-Exchange-Message-Is-Ndr") is not None


def bounce_problem(parsed: ParsedEmail, mailbox_domain: str | None, *, transport: str | None = None,
                   exchange_ndr: bool = False) -> str | None:
    """Why a delivery-status report is not trusted (None: it is). Trusted needs all three: it is a
    report by structure (`parsed.bounce`: app.mail.inbound._is_dsn, never the sender's local part);
    it comes from the case mailbox's own MTA identity (`_mailbox_mta`); and it is authenticated:
    the topmost Authentication-Results passes DMARC / compauth for that From domain, or, on the
    graph transport, `exchange_ndr` (`exchange_generated` over the message's
    internetMessageHeaders). The file transport has no receiving MTA: never trusted there."""
    if not parsed.bounce:
        return "not a delivery-status report"
    if not _mailbox_mta(parsed, mailbox_domain):
        return "not from the case mailbox's own mail server"
    if transport == "file":
        return "local file mailbox (no sender authentication)"
    if parsed.from_authenticated or (transport == "graph" and exchange_ndr):
        return None
    return "not authenticated as the case mailbox's own mail server"


def trusted_bounce(parsed: ParsedEmail, mailbox_domain: str | None, *, transport: str | None = None,
                   exchange_ndr: bool = False) -> bool:
    """A bounce filed without review (`bounce_problem` is None). Module doc."""
    return bounce_problem(parsed, mailbox_domain, transport=transport, exchange_ndr=exchange_ndr) is None


def domain_ok(sender_domain: str | None, allowed: set[str]) -> bool:
    if not sender_domain:
        return False
    s = sender_domain.lower()
    if s in SHARED_DOMAINS:
        return False
    return any(s == d or s.endswith("." + d) for d in allowed if d and d not in SHARED_DOMAINS)


@dataclass
class MatchResult:
    method: str  # header | tag | conversation | none | loop
    case_id: int | None = None
    correspondence_id: int | None = None
    confident: bool = False
    reason: str = ""
    sender_domain_ok: bool | None = None
    authenticated: bool | None = None  # Authentication-Results pass for the From domain
    original_mail_id: int | None = None  # the outbound mail_messages row answered
    extra: dict = field(default_factory=dict)

    @property
    def status(self) -> str:
        """The inbound mail row's status before it is filed: received | needs_review | unassigned | ignored."""
        if self.method == LOOP:
            return "ignored"
        if self.case_id is None:
            return "unassigned"
        return "received" if self.confident else "needs_review"

    def as_meta(self) -> dict:
        return {"method": self.method, "case_id": self.case_id, "correspondence_id": self.correspondence_id,
                "sender_domain_ok": self.sender_domain_ok, "authenticated": self.authenticated,
                "reason": self.reason[:200],
                "original_mail_id": self.original_mail_id, "confident": self.confident,
                **({"bounce_trusted": bool(self.extra["bounce_trusted"])} if "bounce_trusted" in self.extra else {})}


class Lookup(Protocol):
    """Rows are dicts: {mail_id, case_id, correspondence_id, allowed_domains: set[str]} where
    allowed_domains are the authority's own domains (module doc)."""

    def by_message_ids(self, ids: list[str]) -> dict | None: ...

    def by_tag(self, reference: str, corr_id: int) -> dict | None: ...

    def by_conversation(self, conversation_id: str) -> dict | None: ...


def _soft(method: str, row: dict, sender_domain: str | None, authenticated: bool, transport: str | None,
          what: str, allowed: set[str]) -> MatchResult:
    """A tag / conversation match: confident only from the authority's own domain, authenticated,
    over a transport with a receiving MTA."""
    ok = domain_ok(sender_domain, allowed)
    if not ok:
        why = ": sender domain is not the authority's, review"
    elif transport == "file":
        why = ": local file mailbox (no sender authentication), review"
    elif not authenticated:
        why = ": sender not authenticated (no DMARC / compauth pass for the From domain), review"
    else:
        why = ""
    return MatchResult(method, row["case_id"], row["correspondence_id"], not why, what + why, sender_domain_ok=ok,
                       authenticated=authenticated, original_mail_id=row.get("mail_id"))


def decide(parsed: ParsedEmail, lookup: Lookup, *, mailbox: str | None, conversation_id: str | None = None,
           transport: str | None = None, exchange_ndr: bool = False) -> MatchResult:
    sender_domain = parsed.sender_domain
    if mailbox and parsed.from_addr and parsed.from_addr.lower() == mailbox.lower():
        return MatchResult(LOOP, reason="sent from the case mailbox itself")
    mailbox_domain = mailbox.rpartition("@")[2].lower() if mailbox and "@" in mailbox else None
    authenticated = bool(parsed.from_authenticated)

    def allowed(row: dict) -> set[str]:
        return own_domains(row.get("allowed_domains") or set(), [mailbox_domain] if mailbox_domain else [])

    def bounce(method: str, row: dict) -> MatchResult:
        """A delivery-status report, however it matched. Filed without review only on the HEADER path
        (it names the Message-ID of an e-mail Aegis sent) and only from our own mailbox's MTA,
        authenticated (`bounce_problem`). A tag- or conversation-only bounce always waits for review:
        a genuine NDR from our own server can be provoked with a guessable tag (backscatter)."""
        problem = bounce_problem(parsed, mailbox_domain, transport=transport, exchange_ndr=exchange_ndr)
        if problem is None and method != HEADER:
            problem = f"names no Message-ID of an e-mail Aegis sent (matched by {method} only)"
        ok = problem is None
        return MatchResult(method, row["case_id"], row["correspondence_id"], ok,
                           "delivery failure for an e-mail Aegis sent" + ("" if ok else f": {problem}, review"),
                           sender_domain_ok=_mailbox_mta(parsed, mailbox_domain),
                           authenticated=authenticated or (ok and exchange_ndr),
                           original_mail_id=row.get("mail_id"), extra={"bounce_trusted": ok})

    ids = parsed.thread_ids()
    if parsed.bounce_original_message_id:
        ids = [parsed.bounce_original_message_id, *ids]
    if ids:
        row = lookup.by_message_ids(ids)
        if row is not None:
            if parsed.bounce:
                return bounce(HEADER, row)
            return _soft(HEADER, row, sender_domain, authenticated, transport, "replies to an e-mail Aegis sent",
                         allowed(row))

    tag = parse_tag(parsed.subject)
    if tag is not None:
        row = lookup.by_tag(*tag)
        if row is not None:
            if parsed.bounce:
                return bounce(TAG, row)
            return _soft(TAG, row, sender_domain, authenticated, transport, "tracking tag in the subject",
                         allowed(row))

    if conversation_id:
        row = lookup.by_conversation(conversation_id)
        if row is not None:
            if parsed.bounce:
                return bounce(CONVERSATION, row)
            return _soft(CONVERSATION, row, sender_domain, authenticated, transport, "same mailbox conversation",
                         allowed(row))

    return MatchResult(NONE, reason="no matching letter")


class StaticLookup:
    """A Lookup over plain dicts (tests, tools). `sent` rows: {mail_id, case_id, correspondence_id,
    message_id, internet_message_id, conversation_id, reference, allowed_domains}."""

    def __init__(self, sent: list[dict]):
        self.sent = sent

    def by_message_ids(self, ids):
        wanted = set(ids)
        return next((r for r in self.sent if r.get("message_id") in wanted or r.get("internet_message_id") in wanted),
                    None)

    def by_tag(self, reference, corr_id):
        return next((r for r in self.sent if str(r.get("reference", "")).lower() == reference.lower()
                     and r.get("correspondence_id") == corr_id), None)

    def by_conversation(self, conversation_id):
        return next((r for r in self.sent if r.get("conversation_id") == conversation_id), None)


# --------------------------------------------------------------------------- DB lookup
class DbLookup:
    """Lookup against mail_messages / correspondence (models referenced at call time)."""

    def __init__(self, db):
        self.db = db

    def _row(self, mm, corr) -> dict:
        return {"mail_id": mm.id if mm is not None else None, "case_id": corr.case_id, "correspondence_id": corr.id,
                "allowed_domains": allowed_domains(self.db, corr, mm)}

    def _sent_out(self):
        from sqlalchemy import select

        from app.db import models as M

        # sent by a transport, or sent from Outlook and recorded ("Draft — you send"; its Message-ID is the
        # one read from the uploaded sent copy, when there was one)
        return select(M.MailMessage).where(M.MailMessage.direction == M.MailDirection.OUT,
                                           M.MailMessage.status.in_((M.MailStatus.SENT, M.MailStatus.SENT_EXTERNAL)))

    def _first(self, q):
        """The newest row of `q` that answers for a letter: never a Sent Items message the sync logged for
        review (not tied to a letter by a person yet: a reply to it waits for review instead of being filed)."""
        from app.db import models as M

        for mm in self.db.scalars(q.order_by(M.MailMessage.id.desc()).limit(20)).all():
            if not under_review(mm):
                return mm
        return None

    def by_message_ids(self, ids):
        from sqlalchemy import or_

        from app.db import models as M

        ids = [i for i in ids if i][:50]
        if not ids:
            return None
        mm = self._first(self._sent_out().where(or_(M.MailMessage.message_id.in_(ids),
                                                    M.MailMessage.internet_message_id.in_(ids))))
        if mm is None or mm.correspondence_id is None or mm.case_id is None:
            return None
        corr = self.db.get(M.Correspondence, mm.correspondence_id)
        return self._row(mm, corr) if corr is not None and corr.case_id == mm.case_id else None

    def by_tag(self, reference, corr_id):
        from sqlalchemy import func, select

        from app.db import models as M

        case = self.db.scalars(select(M.Case).where(func.lower(M.Case.reference) == reference.lower())).first()
        if case is None:
            return None
        corr = self.db.get(M.Correspondence, corr_id)
        if corr is None or corr.case_id != case.id or corr.direction != M.CorrespondenceDirection.OUT \
                or corr.status != M.CorrespondenceStatus.SENT:
            return None
        mm = self._first(self._sent_out().where(M.MailMessage.correspondence_id == corr.id))
        if mm is None and under_review_entry(corr):
            return None
        return self._row(mm, corr)

    def by_conversation(self, conversation_id):
        from app.db import models as M

        mm = self._first(self._sent_out().where(M.MailMessage.conversation_id == conversation_id))
        if mm is None or mm.correspondence_id is None:
            return None
        corr = self.db.get(M.Correspondence, mm.correspondence_id)
        return self._row(mm, corr) if corr is not None and corr.case_id == mm.case_id else None


def under_review(mm) -> bool:
    """A Sent Items row the sync logged for review (app.mail.sync_outbound step 5: ambiguous, no letter, or
    metadata only): it answers for no letter until a person ties it to one."""
    return getattr(mm, "folder", None) == "sentitems" and bool((mm.meta or {}).get("needs_review"))


def under_review_entry(corr) -> bool:
    """A timeline entry logged from Sent Items for review (meta.source "mailbox_sent", meta.needs_review)."""
    meta = getattr(corr, "meta", None) or {}
    return meta.get("source") == "mailbox_sent" and bool(meta.get("needs_review"))


def recipients_untrusted(mm) -> bool:
    """A Sent Items row the sync logged because no To recipient is the letter's authority (app.mail.sync_outbound;
    still so once a person tied it to a letter): its To / Cc are never the authority's addresses or domains."""
    from app.domain.directory import OUTLOOK_NOT_TO_AUTHORITY

    meta = getattr(mm, "meta", None) or {}
    return bool(meta.get("recipients_untrusted")) or str(meta.get("review_reason") or "").startswith(
        OUTLOOK_NOT_TO_AUTHORITY)


# hosts of an organisation's links that are never its own domain (a profile page, a shared site host, an LE portal)
NOT_ORG_HOSTS = frozenset({
    "t.me", "telegram.me", "github.com", "github.io", "gitlab.com", "linktr.ee", "medium.com", "twitter.com", "x.com",
    "facebook.com", "linkedin.com", "instagram.com", "youtube.com", "google.com", "sites.google.com", "docs.google.com",
    "notion.site", "wixsite.com", "substack.com", "kodexglobal.com", "zendesk.com", "freshdesk.com", "typeform.com",
    "forms.gle", "bit.ly",
})
_HOST_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(?:[^@/]*@)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?(?:[/?#]|$)", re.IGNORECASE)


def url_domain(url: str | None) -> str | None:
    """The organisation domain of a website link ("https://www.circle.com/contact-us" → circle.com), or None for a
    host that is no organisation's own (`NOT_ORG_HOSTS`, a shared provider)."""
    m = _HOST_RE.match((url or "").strip())
    if not m:
        return None
    host = m.group(1).lower().rstrip(".")
    host = host.removeprefix("www.")
    if any(host == h or host.endswith("." + h) for h in NOT_ORG_HOSTS) or host in SHARED_DOMAINS:
        return None
    return host if "." in host else None


def org_domains(entity, catalogue=None, *, names=()) -> set[str]:
    """The authority's OWN organisation domains beyond its addresses: the entity's website, and the catalogue
    organisation's homepage, website and e-mail channels (data/catalogue/channels.json: values from the
    organisation's own site), matched by an exact name / alias of the entity (or `names`). Never a shared provider."""
    out: set[str] = set()
    if entity is not None:
        d = url_domain(getattr(entity, "website", None))
        if d:
            out.add(d)
    wanted = {n.strip().casefold() for n in [getattr(entity, "name", None), *names] if n and n.strip()}
    if not wanted:
        return out
    try:
        from app.domain import directory

        cat = catalogue or directory.load_catalogue()
    except Exception:  # noqa: BLE001 - an invalid catalogue: the entity's own website still counts
        return out
    for org in cat.orgs:
        if not any(a.casefold() in wanted for a in org.names):
            continue
        for v in [org.homepage, *(c.value for c in org.channels if c.kind in ("website", "email") and c.value)]:
            d = (v.rpartition("@")[2].lower() if "@" in (v or "") and "://" not in v else url_domain(v))
            if d and d not in SHARED_DOMAINS:
                out.add(d)
    return out


def allowed_domains(db, corr, mm=None) -> set[str]:
    """The authority's own domains for `corr` (module doc): its To recipients, the entity's
    compliance address, its LE contacts and directory e-mail channels; never the Cc, a shared
    provider, or a domain of the sender profile's own addresses."""
    from sqlalchemy import or_, select

    from app.db import models as M

    values: list = [*(corr.recipients or [])]
    if mm is not None and not recipients_untrusted(mm):
        values += [*(mm.to_addrs or [])]
    if corr.entity is not None and corr.entity.compliance_email:
        values.append(corr.entity.compliance_email)
    case = corr.case
    le_ids = {corr.le_contact_id} if corr.le_contact_id else set()
    for le in case.le_contacts if case is not None else []:
        if le.id in le_ids or (corr.entity_id and le.entity_id == corr.entity_id):
            le_ids.add(le.id)
            if le.email:
                values.append(le.email)
    conds = []
    if corr.entity_id:
        conds.append(M.EntityChannel.entity_id == corr.entity_id)
    if le_ids:
        conds.append(M.EntityChannel.le_contact_id.in_(le_ids))
    if conds:
        rows = db.scalars(select(M.EntityChannel.value).where(
            or_(*conds), M.EntityChannel.kind == M.ChannelKind.EMAIL, M.EntityChannel.value.is_not(None),
            M.EntityChannel.disabled.is_(False),
            or_(M.EntityChannel.case_id.is_(None), M.EntityChannel.case_id == corr.case_id))).all()
        values += list(rows)
    return own_domains(domains_of(values) | org_domains(corr.entity), _profile_domains(db, case))


def authority_domains(db, case, authority, orig=None, mailbox: str | None = None) -> set[str]:
    """The own domains of a chosen authority (manual filing: /admin/mail triage, case review): its
    entity compliance address, LE contacts, directory e-mail channels and the recipients of its
    sent outbound letters (never a draft's), plus `allowed_domains(orig)` for a chosen letter; never a shared provider,
    the case mailbox's domain or the sender profile's own domains."""
    from sqlalchemy import or_, select

    from app.db import models as M
    from app.domain.directory import recipients_untrusted as corr_untrusted

    values: list = []
    entity = getattr(authority, "entity", None)
    if entity is not None and entity.compliance_email:
        values.append(entity.compliance_email)
    les = list(getattr(authority, "le_contacts", None) or [])
    values += [le.email for le in les if le.email]
    for c in getattr(authority, "correspondence", None) or []:
        # sent letters only: a draft's (or a failed send's) recipients were never the authority's own addresses
        if c.direction == M.CorrespondenceDirection.OUT and c.status == M.CorrespondenceStatus.SENT \
                and not corr_untrusted(c):
            values += list(c.recipients or [])
    conds = []
    if entity is not None:
        conds.append(M.EntityChannel.entity_id == entity.id)
    if les:
        conds.append(M.EntityChannel.le_contact_id.in_([le.id for le in les]))
    if conds:
        values += list(db.scalars(select(M.EntityChannel.value).where(
            or_(*conds), M.EntityChannel.kind == M.ChannelKind.EMAIL, M.EntityChannel.value.is_not(None),
            M.EntityChannel.disabled.is_(False),
            or_(M.EntityChannel.case_id.is_(None), M.EntityChannel.case_id == case.id))).all())
    out = own_domains(domains_of(values) | org_domains(entity, names=[getattr(authority, "name", None)]),
                      _profile_domains(db, case))
    if orig is not None:
        out |= allowed_domains(db, orig)
    mbx = mailbox.rpartition("@")[2].lower() if mailbox and "@" in mailbox else None
    return own_domains(out, [mbx] if mbx else [])


def _profile_domains(db, case) -> set[str]:
    """Domains of the sender profile's own addresses (our side of the letter, never the authority)."""
    if case is None:
        return set()
    try:
        from app.domain import sender

        p = sender.get_profile(db, case)
    except Exception:  # noqa: BLE001 - matching works without a sender profile
        return set()
    if p is None:
        return set()
    return domains_of([*(p.cc_default or []), p.contact_email or ""])


def match(db, parsed: ParsedEmail, *, mailbox: str | None, conversation_id: str | None = None,
          transport: str | None = None, exchange_ndr: bool = False) -> MatchResult:
    return decide(parsed, DbLookup(db), mailbox=mailbox, conversation_id=conversation_id, transport=transport,
                  exchange_ndr=exchange_ndr)


# --------------------------------------------------------------------------- data minimisation (mailbox sync)
# The case mailbox is a real shared mailbox: the sync (app.mail.ingest) keeps a message only when it is
# related to a case (docs/data-handling.md §6.4). `CaseIndex` holds, per open case, what makes a message
# related: the authorities' addresses and domains, the case reference, the traced wallets / tx hashes and
# the subjects of its outbound letters. `assess` applies the rules:
#
#   (a) the subject carries an Aegis tracking tag                                  -> store (method tag)
#   (b) it threads (In-Reply-To / References / conversationId) to a stored message  -> store (thread)
#   (c) Sent Items: the subject / body cites the case reference or a traced wallet / tx hash
#                                                                                   -> store (cited | recipient)
#   (c') Sent Items: a To / Cc recipient is a known authority address or domain of an open case, but nothing
#       is cited                                                                    -> triage (recipient): stored in
#       full only when it matches one of the case's letters (app.mail.sync_outbound: a letter at THRESHOLD or
#       above), else metadata only (subject, recipient domains, date; no .eml, no timeline entry)
#   (d) Inbox: the sender is a known authority address or domain of an open case AND the message cites
#       case material (reference, wallet / tx hash, an earlier outbound subject)    -> store (sender_cited)
#       the sender is a known authority but nothing is cited                        -> triage, metadata only
#   (d') Inbox, an unknown sender: a reply ("Re:" / "AW:" / "RE:" …) to a subject we sent, or the case
#       reference in the subject or text (before the download only the subject, and for a reply subject the
#       text read in memory)                                                        -> triage, metadata only
#   (e) Inbox: a delivery-status report (multipart/report, or a DSN-like From / Subject) from any domain is
#       read in memory and kept only when the original Message-ID it carries is a stored message (rule (b))
#   everything else                                                                 -> counted, never stored
#
# Shared / free-mail domains (SHARED_DOMAINS) never match by domain alone (only an exact address does),
# and the case mailbox's own domain and the sender profile's addresses are never an authority's. An authority's own
# domains are its addresses' domains plus its entity's website and its catalogue organisation's domains
# (`org_domains`). Demo / training cases (`Case.is_demo`: reference "DEMO-…", facts.demo) take no part: they are
# left out of the index and a stored message of one never makes a thread. Sent Items: the To recipients name the
# authority (`Relevance.to_candidates`), a Cc never makes it ambiguous.

STORE_FULL, STORE_TRIAGE, STORE_NONE = "full", "triage", "none"
WALLET_RE = re.compile(r"(?<![0-9A-Za-z])(0x[0-9a-fA-F]{64}|0x[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|T[1-9A-HJ-NP-Za-km-z]{33}"
                       r"|bc1[02-9ac-hj-np-z]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})(?![0-9A-Za-z])")
# Re: / Fw: in a few languages. Not "Follow-up:": a follow-up letter (mail_guidance) is a letter of its own.
_REPLY_PREFIX = re.compile(r"(?i)^\s*((re|aw|sv|fw|fwd|wg|tr|r|rif)\s*(\[\d+\])?\s*:\s*)+")
_SUBJECT_TAG = re.compile(r"\s*\[Aegis [A-Za-z0-9._-]{3,64} #\d{1,12}\]\s*")
MIN_SUBJECT_MATCH = 15  # a normalised outbound subject shorter than this never counts as "cited"
MAX_SCAN = 200 * 1024  # characters of subject + body searched for case material


def norm_token(token: str) -> str:
    """A wallet / tx hash as compared: hex lower-cased (a 64-hex hash without its 0x), base58 verbatim."""
    t = (token or "").strip()
    low = t.lower()
    if low.startswith("0x") and len(low) == 66:
        return low[2:]
    if low.startswith("0x") or low.startswith("bc1") or re.fullmatch(r"[0-9a-f]{64}", low):
        return low
    return t


def chain_tokens(text: str | None) -> set[str]:
    return {norm_token(m.group(1)) for m in WALLET_RE.finditer((text or "")[:MAX_SCAN])}


def _walk_strings(node, out: list[str], depth: int = 0) -> None:
    if depth > 8:
        return
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _walk_strings(v, out, depth + 1)
    elif isinstance(node, list):
        for v in node[:5000]:
            _walk_strings(v, out, depth + 1)


def identifier_tokens(identifiers) -> set[str]:
    """The wallets and tx hashes cited in a stop order's identifiers JSON."""
    strings: list[str] = []
    _walk_strings(identifiers or {}, strings)
    out: set[str] = set()
    for s in strings:
        out |= chain_tokens(s)
    return out


def normalise_subject(subject: str | None) -> str:
    """A subject as compared: no tracking tag, no Re: / Fw: prefixes, ASCII dashes, lower case, whitespace
    collapsed."""
    s = _SUBJECT_TAG.sub(" ", subject or "")
    s = s.translate(str.maketrans({"–": "-", "—": "-", "‒": "-", "−": "-", "‘": "'", "’": "'", "“": '"', "”": '"',
                                   " ": " ", "…": "..."}))
    s = _REPLY_PREFIX.sub("", s)
    return " ".join(s.lower().split())


def is_reply_subject(subject: str | None) -> bool:
    return bool(_REPLY_PREFIX.match(_SUBJECT_TAG.sub(" ", subject or "")))


_FORWARD_PREFIX = re.compile(r"(?i)^\s*(?:(?:re|aw|sv|r|rif)\s*(?:\[\d+\])?\s*:\s*)*(?:fw|fwd|wg|tr|rv)\s*(?:\[\d+\])?\s*:")


def is_forward_subject(subject: str | None) -> bool:
    """A forward ("FW:", "Fwd:", "WG:", "TR:", "RV:"): of our own letter, it is that letter sent again elsewhere."""
    return bool(_FORWARD_PREFIX.match(_SUBJECT_TAG.sub(" ", subject or "")))


@dataclass
class AuthorityAddresses:
    key: str
    name: str
    addresses: set[str] = field(default_factory=set)  # exact addresses (lower case)
    domains: set[str] = field(default_factory=set)  # own domains (no shared provider, never ours)


@dataclass
class CaseMaterial:
    case_id: int
    reference: str
    authorities: dict[str, AuthorityAddresses] = field(default_factory=dict)
    tokens: set[str] = field(default_factory=set)  # traced wallets / tx hashes (norm_token)
    subjects: set[str] = field(default_factory=set)  # normalised outbound subjects (drafts included)
    sent_subjects: set[str] = field(default_factory=set)  # those of letters sent, or recorded as sent
    order_tokens: dict[int, set[str]] = field(default_factory=dict)  # stop order id -> its identifiers

    def cites_reference(self, text: str) -> bool:
        ref = re.escape(self.reference)
        return re.search(rf"(?i)(?<![A-Za-z0-9]){ref}(?![A-Za-z0-9])", text or "") is not None

    def authorities_for(self, address: str | None) -> list[str]:
        """Keys of the authorities `address` belongs to: an exact address, or its own (non-shared) domain."""
        a = (address or "").strip().lower()
        if "@" not in a:
            return []
        dom = a.rpartition("@")[2]
        out = []
        for key, auth in self.authorities.items():
            if a in auth.addresses or (dom not in SHARED_DOMAINS and domain_ok(dom, auth.domains)):
                out.append(key)
        return out


@dataclass
class Relevance:
    store: str  # full | triage | none
    method: str  # tag | thread | recipient | cited | sender_cited | triage | loop | none
    case_id: int | None = None
    authority_key: str | None = None
    candidates: list[tuple[int, str]] = field(default_factory=list)  # (case id, authority key) address matches
    to_candidates: list[tuple[int, str]] = field(default_factory=list)  # … of the To recipients only (Sent Items)
    cited_cases: list[int] = field(default_factory=list)
    thread_mail_id: int | None = None
    reason: str = ""


class _SystemAccess:
    """Enough of a CaseAccess for app.domain.directory.channels_for: every channel, unmasked (the sync
    reads addresses for matching only; nothing is shown)."""

    is_external = False
    user = None

    def __init__(self, case):
        self.case = case

    def can(self, _perm: str) -> bool:
        return True


def _authority_addresses(db, case, authority, exclude_addrs: set[str], exclude_domains: set[str],
                         catalogue=None) -> AuthorityAddresses:
    from app.db import models as M
    from app.domain import directory

    values: set[str] = set()
    try:
        card = directory.channels_for(db, _SystemAccess(case), authority, catalogue=catalogue)
        values |= {e.value.strip().lower() for e in card.entries if e.kind == "email" and e.value and not e.disabled}
    except Exception:  # noqa: BLE001 - a broken catalogue never stops the sync; the rows below still count
        _log.warning("mailbox sync: the contact card of an authority could not be read")
    if authority.entity is not None and authority.entity.compliance_email:
        values.add(authority.entity.compliance_email.strip().lower())
    values |= {le.email.strip().lower() for le in authority.le_contacts if le.email}
    if (authority.contact or {}).get("email"):
        values.add(str(authority.contact["email"]).strip().lower())
    for c in authority.correspondence:
        if c.direction == M.CorrespondenceDirection.OUT and (c.meta or {}).get("source") not in ("mailbox", "mailbox_sent"):
            values |= {str(r).strip().lower() for r in c.recipients or []}  # drafts and sent letters: To only
    for o in authority.stop_orders:
        if o.recipient_email:
            values.add(o.recipient_email.strip().lower())
    addrs = set()
    for v in values:
        for m in re.finditer(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", v):
            a = m.group(0).lower()
            if a not in exclude_addrs:
                addrs.add(a)
    # any address on the authority's own organisation domain(s) is the authority: its addresses' domains, the entity's
    # website and the catalogue organisation's (a new freeze inbox a redirect names, e.g. a blocklisting@ alias)
    names = [authority.name, *[le.agency for le in authority.le_contacts if le.agency]] if authority.entity is None \
        else [authority.name]
    return AuthorityAddresses(key=authority.key, name=authority.name, addresses=addrs,
                              domains=own_domains(domains_of(addrs) | org_domains(authority.entity, catalogue,
                                                                                  names=names), exclude_domains))


def case_material(db, case, *, mailbox: str | None = None, catalogue=None) -> CaseMaterial:
    """What makes a message related to `case` (module section above)."""
    from sqlalchemy import select

    from app.db import models as M
    from app.domain import correspondence as desk

    mbx = (mailbox or "").strip().lower()
    mbx_domain = mbx.rpartition("@")[2] if "@" in mbx else ""
    exclude_addrs = {mbx} if mbx else set()
    try:
        from app.domain import sender

        p = sender.get_profile(db, case)
    except Exception:  # noqa: BLE001
        p = None
    if p is not None:
        exclude_addrs |= {str(a).strip().lower() for a in [*(p.cc_default or []), p.contact_email or ""] if a}
    exclude_addrs |= {m.user.email.strip().lower() for m in case.members if m.user is not None and m.user.email}
    exclude_domains = ({mbx_domain} if mbx_domain else set()) | _profile_domains(db, case)
    mat = CaseMaterial(case_id=case.id, reference=case.reference)
    for a in desk.case_authorities(db, case, include_prospects=False):
        mat.authorities[a.key] = _authority_addresses(db, case, a, exclude_addrs, exclude_domains, catalogue)
    # traced wallets and tx hashes: seeds, the latest run's wallets (not service hot wallets or token
    # contracts, which other matters cite too) and movements, the stop orders' identifiers, watched wallets
    tokens = {norm_token(s.value) for s in case.seeds if s.value}
    run = db.scalar(select(M.TraceRun).where(M.TraceRun.case_id == case.id).order_by(M.TraceRun.id.desc()))
    if run is not None:
        skip = {M.AddressType.HOT_WALLET, M.AddressType.CONTRACT}
        tokens |= {norm_token(a) for a, t in db.execute(
            select(M.Address.address, M.Address.address_type).join(M.TraceNode, M.TraceNode.address_id == M.Address.id)
            .where(M.TraceNode.run_id == run.id)).all() if a and t not in skip}
        tokens |= {norm_token(h) for h in db.scalars(
            select(M.Transfer.tx_hash).join(M.TraceEdge, M.TraceEdge.transfer_id == M.Transfer.id)
            .where(M.TraceEdge.run_id == run.id)).all() if h}
    for o in case.stop_orders:
        mat.order_tokens[o.id] = identifier_tokens(o.identifiers)
        tokens |= mat.order_tokens[o.id]
        if o.subject:
            mat.subjects.add(normalise_subject(o.subject))
            if o.sent_at is not None:
                mat.sent_subjects.add(normalise_subject(o.subject))
    if hasattr(M, "FreezeWatch"):
        tokens |= {norm_token(a) for a in db.scalars(select(M.FreezeWatch.address).where(
            M.FreezeWatch.case_id == case.id, M.FreezeWatch.active.is_(True))).all() if a}
    mat.tokens = {t for t in tokens if len(t) >= 26}
    for c in case.correspondence:
        if c.direction == M.CorrespondenceDirection.OUT and c.subject:
            mat.subjects.add(normalise_subject(c.subject))
            if c.status == M.CorrespondenceStatus.SENT and not under_review_entry(c) \
                    and not (c.meta or {}).get("dismissed"):
                mat.sent_subjects.add(normalise_subject(c.subject))
    for mm in db.scalars(select(M.MailMessage).where(M.MailMessage.case_id == case.id,
                                                     M.MailMessage.direction == M.MailDirection.OUT,
                                                     M.MailMessage.subject.is_not(None))).all():
        mat.subjects.add(normalise_subject(mm.subject))
        if mm.status in (M.MailStatus.SENT, M.MailStatus.SENT_EXTERNAL) and not under_review(mm) \
                and not (mm.meta or {}).get("dismissed"):
            mat.sent_subjects.add(normalise_subject(mm.subject))
    mat.subjects = {s for s in mat.subjects if len(s) >= MIN_SUBJECT_MATCH}
    mat.sent_subjects = {s for s in mat.sent_subjects if len(s) >= MIN_SUBJECT_MATCH}
    return mat


class CaseIndex:
    """Every open case's material (built once per sync, `build_index`)."""

    def __init__(self, cases: list[CaseMaterial], *, mailbox: str | None = None):
        self.cases = {c.case_id: c for c in cases}
        self.by_reference = {c.reference.lower(): c for c in cases}
        self.mailbox = (mailbox or "").strip().lower()

    def address_matches(self, addresses) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        for addr in addresses or []:
            for mat in self.cases.values():
                for key in mat.authorities_for(addr):
                    if (mat.case_id, key) not in out:
                        out.append((mat.case_id, key))
        return out

    def citing(self, subject: str | None, text: str | None, *, subjects: bool = False) -> list[int]:
        """Open cases whose reference or traced wallets / tx hashes the message cites (and, with `subjects`,
        whose earlier outbound subject the subject repeats)."""
        blob = f"{subject or ''}\n{(text or '')[:MAX_SCAN]}"
        toks = chain_tokens(blob)
        norm = normalise_subject(subject) if subjects else ""
        out = []
        for mat in self.cases.values():
            if mat.cites_reference(blob) or (toks & mat.tokens) or (norm and any(
                    s == norm or (len(s) >= MIN_SUBJECT_MATCH and s in norm) for s in mat.subjects)):
                out.append(mat.case_id)
        return out


    def answering(self, subject: str | None, text: str | None) -> list[int]:
        """Open cases an Inbox message from an unknown sender may concern: a reply ("Re:" / "AW:" / "RE:" …) to
        the subject of a letter we sent (or recorded as sent: never a draft's, a prepared e-mail's or a Sent Items
        e-mail still under review), or the case reference cited in the subject or text."""
        norm = normalise_subject(subject) if is_reply_subject(subject) else ""
        blob = f"{subject or ''}\n{(text or '')[:MAX_SCAN]}"
        out = []
        for mat in self.cases.values():
            if (norm and any(s == norm or (len(s) >= MIN_SUBJECT_MATCH and s in norm) for s in mat.sent_subjects)) \
                    or mat.cites_reference(blob):
                out.append(mat.case_id)
        return out


def build_index(db, *, mailbox: str | None = None) -> CaseIndex:
    from sqlalchemy import select

    from app.db import models as M
    from app.domain import directory

    try:
        catalogue = directory.load_catalogue()
    except Exception:  # noqa: BLE001 - an invalid catalogue: the DB channels still count
        catalogue = None
    cases = db.scalars(select(M.Case).where(M.Case.status == "open").order_by(M.Case.id)).all()
    mats = []
    for case in cases:
        if case.is_demo:  # a demo / training case never takes part in the mailbox's matching (is_demo)
            continue
        mats.append(case_material(db, case, mailbox=mailbox, catalogue=catalogue))
    return CaseIndex(mats, mailbox=mailbox)


def thread_row(db, parsed: ParsedEmail, conversation_id: str | None, *, mailbox: str | None):
    """A stored (not metadata-only) mail row this message threads to: one of its In-Reply-To / References
    ids (or a bounce's original) is a stored Message-ID / internetMessageId, or its Graph conversationId is
    a stored row's (any mailbox: like DbLookup, a letter sent before the mailbox changed still counts)."""
    from sqlalchemy import or_, select

    from app.db import models as M

    ids = [i for i in [parsed.bounce_original_message_id, *parsed.thread_ids()] if i][:50]
    conds = []
    if ids:
        conds += [M.MailMessage.message_id.in_(ids), M.MailMessage.internet_message_id.in_(ids)]
    if conversation_id:
        conds += [M.MailMessage.conversation_id == conversation_id,
                  M.MailMessage.graph_conversation_id == conversation_id]
    if not conds:
        return None
    q = select(M.MailMessage).where(or_(*conds), M.MailMessage.status.not_in(
        (M.MailStatus.PREPARED, M.MailStatus.EXPIRED, M.MailStatus.CANCELLED, M.MailStatus.FAILED)))
    for row in db.scalars(q.order_by(M.MailMessage.id.desc()).limit(20)).all():
        if (row.meta or {}).get("metadata_only") or is_demo_case(db, row.case_id):
            continue  # (a demo case's message never ties a real one to it)
        return row
    return None


def is_demo_case(db, case_id: int | None) -> bool:
    """The case is a demo / training case (`Case.is_demo`): never part of the mailbox's matching."""
    if case_id is None:
        return False
    from app.db import models as M

    case = db.get(M.Case, case_id)
    return bool(case is not None and case.is_demo)


def _thread_case(db, row) -> tuple[int | None, str | None]:
    from app.db import models as M

    key = row.authority_key or (row.match or {}).get("authority_key")
    if key is None and row.correspondence_id:
        from app.mail.ingest import authority_key_for

        key = authority_key_for(db.get(M.Correspondence, row.correspondence_id))
    return row.case_id, key


def _one_key(cands: list[tuple[int, str]]) -> str | None:
    keys = {k for _, k in cands}
    return next(iter(keys)) if len(keys) == 1 else None


def assess(db, parsed: ParsedEmail, *, folder: str, index: CaseIndex, conversation_id: str | None = None,
           mailbox: str | None = None) -> Relevance:
    """Is this message related to a case, and how much of it may be stored (section above)?"""
    mbx = (mailbox or index.mailbox or "").lower()
    if folder == "inbox" and mbx and (parsed.from_addr or "").lower() == mbx:
        return Relevance(STORE_NONE, "loop", reason="a copy of a message from the case mailbox itself")
    tag = parse_tag(parsed.subject)
    if tag is not None:
        mat = index.by_reference.get(tag[0].lower())
        return Relevance(STORE_FULL, TAG, case_id=mat.case_id if mat else None, reason="tracking tag in the subject")
    row = thread_row(db, parsed, conversation_id, mailbox=mailbox)
    if row is not None:
        case_id, key = _thread_case(db, row)
        to_cands = cands = []
        if case_id is not None:
            # the thread's stored row names no authority (an e-mail logged for review): the addresses decide (Sent
            # Items: the To recipients first, a Cc'd colleague's firm never; the Inbox: the sender)
            if folder == "sentitems":
                to_cands = [x for x in index.address_matches(parsed.to) if x[0] == case_id]
                cands = [x for x in index.address_matches([*parsed.to, *parsed.cc]) if x[0] == case_id]
            else:
                cands = [x for x in index.address_matches([parsed.from_addr] if parsed.from_addr else [])
                         if x[0] == case_id]
            if key is None:
                key = _one_key(to_cands) or _one_key(cands)
        return Relevance(STORE_FULL, "thread", case_id=case_id, authority_key=key, thread_mail_id=row.id,
                         candidates=cands, to_candidates=to_cands, reason="same thread as a stored message")
    if folder == "sentitems":
        cands = index.address_matches([*parsed.to, *parsed.cc])
        to_cands = index.address_matches(parsed.to)
        cited = index.citing(parsed.subject, parsed.text)
        if cands or cited:
            cases = sorted({c for c, _ in cands} | set(cited))
            case_id = cases[0] if len(cases) == 1 else (cited[0] if len(cited) == 1 else None)
            # the To recipients name the authority; a Cc (our partner firm, a colleague at another authority of the
            # case) never makes it ambiguous
            key = _one_key([x for x in to_cands if x[0] == case_id]) or _one_key([x for x in cands if x[0] == case_id])
            if not cited:  # (c'): only a recipient ties it to a case; a letter match decides (sync_outbound)
                return Relevance(STORE_TRIAGE, "recipient", case_id=case_id, authority_key=key, candidates=cands,
                                 to_candidates=to_cands,
                                 reason="a recipient is an authority of an open case, nothing cited")
            return Relevance(STORE_FULL, "recipient" if cands else "cited", case_id=case_id,
                             authority_key=key, candidates=cands, to_candidates=to_cands,
                             cited_cases=cited,
                             reason=("a recipient is an authority of an open case, citing case material" if cands
                                     else "cites a case reference or traced wallet"))
        return Relevance(STORE_NONE, NONE, reason="not related to an open case")
    cands = index.address_matches([parsed.from_addr] if parsed.from_addr else [])
    if not cands:
        hits = index.answering(parsed.subject, parsed.text)
        if hits:  # an unknown domain answering a subject we sent, or citing a case reference: a person looks
            return Relevance(STORE_TRIAGE, "triage", cited_cases=hits,
                             reason="from an unknown domain, answering a subject we sent or citing a case reference: "
                                    "metadata only")
        return Relevance(STORE_NONE, NONE, reason="not related to an open case")
    cited = [c for c in index.citing(parsed.subject, parsed.text, subjects=True) if c in {x for x, _ in cands}]
    if cited:
        case_id = cited[0] if len(cited) == 1 else None
        keys = [k for c, k in cands if c == case_id]
        return Relevance(STORE_FULL, "sender_cited", case_id=case_id,
                         authority_key=keys[0] if len(set(keys)) == 1 else None, candidates=cands, cited_cases=cited,
                         reason="from an authority of the case, citing case material")
    return Relevance(STORE_TRIAGE, "triage", candidates=cands,
                     reason="from an authority's domain, but cites no case material: metadata only")
