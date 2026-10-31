"""Who to write to, who to copy and what the subject says, per authority and letter (the e-mail desk).

Owner: the mail feature (shown on the authority page's "How to email <authority>" panel and on the
compose page; web layer app/web/routes_mail.py, partial mail_guidance.html).

    g = guide(Inputs(...))                                   # pure: plain values in, Guidance out
    g = for_authority(db, access, authority, corr=None)      # the adapter: reads the case, then guide()

`guide` is pure (no database, no settings, no clock) so the ranking rules are tested on plain values
(tests/test_mail_manual.py). The adapter `for_authority` only gathers those values.

**To** (ranked, one line of *why* each):

| Score | Address | Why (example) |
|---|---|---|
| 100 | a verified law-enforcement / freeze request channel (first letters) | "verified LE-request channel" |
| 100 | the To of the last letter sent to this authority (follow-ups: status / release request) | "address used in the letter you sent on 18 Oct 2026" |
| 90 / 80 | that address for a first letter / a verified compliance, legal or abuse channel | |
| 85 | the address a reply from the authority's own domain named instead (a redirect; same domain only) | "named in their reply of 19 Oct 2026 as the address for this (unverified — …)" |
| 70 | an address that replied to this case | "replied to this case from this address on …" |
| 60 | a verified channel with another purpose, an LE officer on file (LE authorities) | |
| 40 | an unverified published or case-only address | "… (unverified — confirm before sending)" |
| 30 | the entity record's compliance address | "entity compliance address (unverified — confirm on their LE portal first)" |

**Redirects** (app.blocks: a reply read as "redirected", e.g. "this is a legacy inbox … contact the
following"): when the reply came from the authority's own domain, the address it came from is moved to
"not suggested" with the reason, and a warning names the address the reply gave. A redirect from another
domain only warns (it never steers the ranking).

**LE-only gate** (provider playbooks, app.domain.playbook): a channel the provider reserves for law enforcement
(`who: le_only`) is never a To for our letters (the sender is never LE: `Inputs.requester`): it is listed under
"not suggested" with "LE only: send the officer the pack". When the playbook has no path open to us at all, a
critical `le_only` warning says so and `next_kind` is "le_handoff" (no letter to this counterparty: brief the case
officer with the pack). A `counsel_with_order` channel is offered with "acts on LE process or a court order".

Never a To: the case mailbox, the victim's own addresses (and others on the victim's own domain),
the sender profile's addresses, a channel the directory lists as a copy address (that is a Cc), and,
for a counterparty that is not law enforcement, a law-enforcement officer's address.

**Cc:** the case mailbox (`AEGIS_MAIL_FROM`) when a person sends the e-mail (manual mode), so a
copy and Reply-All replies land where Aegis reads them; the sender profile's `cc_default` (the
investigator / PI contact when the profile says so); directory copy addresses; addresses copied on
earlier letters to this authority; the case's LE officers only on an **LE cover letter**. Never the
victim's personal address by default: when the draft or an earlier letter copies it, a warning says
so instead — unless the sender profile's default Cc names it (the client's contact e-mail given when
the case was opened: the client asked to be copied).

**Adviser** (the case's own PI firm or legal counsel, `authority.is_adviser`): the next letter is an
information request (the only template the letter form offers them), the subject a neutral
`Case Update – Ref <CASE>`, and an "adviser on this case" note replaces the LE-channel warnings.

**Demo lock** (a demo / training case, `Case.is_demo`: `Inputs.demo`): only reserved demo addresses are ever
suggested (`demo_safe`: the IETF reserved names `*.example`, `*.test`, `*.invalid`, `*.localhost`, and
example.com / .org / .net). A real organisation's published address (the catalogue's, a real directory entry) is
not listed at all, not even under "not suggested"; one info warning says how many were left out. The demo
fixture's reserved-domain addresses (e.g. `compliance@circle-demo.example`) are what the panel shows. Compose and Send
enforce the same rule (app.domain.mail_compose.demo_lock_problem, app.domain.mail_send).

**Portal-only** authorities (IC3) get no Cc list: a portal submission has no Cc. An LE cover letter
copies only the officers of the same agency (its LE contacts) or jurisdiction, never another agency's.

**Warnings:** portal-only authorities (e.g. IC3: "submit via portal, not e-mail"), non-custodial
counterparties (e.g. Uniswap: "cannot freeze — information request only"), no address on file, an
unverified best address, the victim or an LE officer copied where they should not be.

**Subject** (per letter kind; always ending with the tracking tag `[Aegis <REF> #<letter id>]` so a
reply that keeps the subject is matched to the letter):

* stop order: `URGENT – Preservation & Risk-Control Request – <service> – <asset> <amount> – Ref <CASE>`
* status request: `Follow-up: <original subject> – sent <date> – Ref <CASE>`
* information request: `Information & Preservation Request – <service> – Ref <CASE>`
* LE cover letter: `Fund-Flow Summary & Freeze Opportunities – Your ref <complaint ref> – Ref <CASE>`
* release request: `Request for Release of Held Funds – <service> – <asset> <amount held> – Ref <CASE>`
* anything else: `<letter subject> – Ref <CASE>`
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

from app.domain import playbook

TAG_RE = re.compile(r"\s*\[Aegis [A-Za-z0-9._-]{3,64} #(?:\d{1,12}|<[^>\]]{1,20}>)\]\s*")
SUBJECT_MAX = 220  # the part before the tag (app.domain.mail_compose.SUBJECT_MAX)
FOLLOW_UP_KINDS = frozenset({"status_request", "release_request"})
FREEZE_KINDS = frozenset({"stop_order", "release_request"})
KIND_LABELS = {"stop_order": "Stop order (preservation / risk-control request)", "status_request": "Status request / follow-up",
               "info_request": "Information request", "le_cover": "Law-enforcement cover letter",
               "release_request": "Release / return-of-funds request", "other": "Letter", "reply": "Letter",
               "le_handoff": "LE hand-off (no letter to this counterparty: brief the case officer with the pack)"}
# a demo / training case e-mails only these (the IETF reserved test names): never a real organisation
DEMO_SAFE_SUFFIXES = ("example", "test", "invalid", "localhost", "example.com", "example.org", "example.net")
DEMO_LOCK_TEXT = ("Demo case: e-mail goes only to reserved demo addresses (*.example), never to a real "
                  "organisation")
SHARED_DOMAINS = frozenset({  # free-mail: an address there says nothing about who holds it (cf. app.mail.matching)
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "icloud.com",
    "me.com", "aol.com", "gmx.com", "gmx.de", "gmx.net", "web.de", "proton.me", "protonmail.com", "pm.me",
    "mail.com", "zoho.com", "yandex.com", "mail.ru", "qq.com", "163.com", "libero.it", "bluewin.ch",
})


def demo_safe(address: str | None) -> bool:
    """The address is on a reserved demo / test domain (`DEMO_SAFE_SUFFIXES`): the only kind a demo case e-mails."""
    a = str(address or "").strip().lower()
    if "@" not in a:
        return False
    d = a.rpartition("@")[2].rstrip(".")
    return bool(d) and any(d == x or d.endswith("." + x) for x in DEMO_SAFE_SUFFIXES)


# --------------------------------------------------------------------------- inputs (plain values)
@dataclass(frozen=True)
class Channel:
    """An e-mail address the directory knows for the authority (app.domain.directory.ChannelEntry)."""

    address: str
    verified: bool = False
    source: str = "manual"  # catalogue | global | case | manual | entity_record | case_correspondence | le_contact
    purpose: str = "general"  # le_request | freeze | compliance | legal | abuse | complaint | general
    role_default: str = "to"  # to | cc
    label: str | None = None
    who: str | None = None  # provider playbook: any | victim_or_rep | le_only | counsel_with_order (None: not stated)


@dataclass(frozen=True)
class SentLetter:
    at: datetime | None
    to: tuple[str, ...] = ()
    cc: tuple[str, ...] = ()
    subject: str = ""


@dataclass(frozen=True)
class Reply:
    address: str
    at: datetime | None = None


@dataclass(frozen=True)
class Redirect:
    """An authority's reply said `away` is not the channel for this (a legacy / unmonitored inbox) and named `to`
    (app.blocks: a reply read as "redirected"). `trusted`: the reply came from the authority's own domain."""

    away: str | None
    to: str | None
    at: datetime | None = None
    trusted: bool = False
    reply_id: int | None = None  # the correspondence entry of their reply


@dataclass(frozen=True)
class SubjectFacts:
    service: str = ""
    asset: str | None = None
    amount: Decimal | str | None = None
    original_subject: str | None = None  # status request: the letter it follows up
    original_sent_at: datetime | None = None
    complaint_ref: str | None = None  # LE cover letter: the complaint's own reference
    letter_subject: str | None = None  # anything else: the letter's own subject


@dataclass(frozen=True)
class Inputs:
    authority_name: str
    case_reference: str
    letter_kind: str = "stop_order"
    letter_id: int | None = None
    is_le: bool = False
    is_adviser: bool = False  # the case's own PI firm / legal counsel: a case update, never a request to a counterparty
    info_only: bool = False  # non-custodial: cannot freeze (directory catalogue / entity category)
    portal_only: bool = False  # takes no e-mail (e.g. IC3)
    portal_url: str | None = None
    channels: tuple[Channel, ...] = ()
    sent: tuple[SentLetter, ...] = ()
    replies: tuple[Reply, ...] = ()
    mailbox: str | None = None
    manual: bool = True  # a person sends it (Cc the case mailbox); False: Aegis sends From the mailbox
    profile_cc: tuple[str, ...] = ()
    own_addresses: tuple[str, ...] = ()  # the sender profile's contact address, team members: never a To
    victim_addresses: tuple[str, ...] = ()
    le_addresses: tuple[str, ...] = ()  # the case's LE officers
    agency_le_addresses: tuple[str, ...] | None = None  # officers of this authority's agency / jurisdiction (None: all)
    draft_to: tuple[str, ...] = ()
    draft_cc: tuple[str, ...] = ()
    facts: SubjectFacts = field(default_factory=SubjectFacts)
    redirects: tuple[Redirect, ...] = ()  # replies that named another address (newest first)
    requester: str = "pi"  # who our letters come from (app.domain.sender.requester_kind; never LE)
    le_only_reason: str | None = None  # the provider playbook has no path open to `requester` (the LE-only gate)
    # the only domains this case may e-mail from here (local-mode Graph sending: AEGIS_MAIL_DEV_ALLOWED_DOMAINS),
    # None: any. An address elsewhere is never suggested first. (A demo case: `demo`, the stricter demo lock.)
    send_domains: tuple[str, ...] | None = None
    demo: bool = False  # a demo / training case (Case.is_demo): reserved demo addresses only (module doc)


# --------------------------------------------------------------------------- output
@dataclass
class Suggestion:
    address: str
    why: str
    verified: bool = False
    score: int = 0
    rank: int = 0

    @property
    def recommended(self) -> bool:
        return self.rank == 1


@dataclass
class Warning:
    level: str  # critical | warning | info
    code: str  # portal_only | info_only | no_address | unverified | victim_cc | le_cc | sender_cc
    text: str


@dataclass
class Guidance:
    authority_name: str
    letter_kind: str
    to: list[Suggestion]
    cc: list[Suggestion]
    warnings: list[Warning]
    subject: str  # the whole subject, tag included
    subject_body: str  # without the tag (what the compose field holds)
    tag: str
    instruction: str
    avoid: list[Suggestion] = field(default_factory=list)  # addresses deliberately not suggested

    @property
    def kind_label(self) -> str:
        return KIND_LABELS.get(self.letter_kind, "Letter")

    def why_for(self, address: str) -> str | None:
        a = (address or "").strip().lower()
        for s in [*self.to, *self.cc]:
            if s.address.lower() == a:
                return (f"To #{s.rank}: " if s in self.to else "Cc: ") + s.why
        for s in self.avoid:
            if s.address.lower() == a:
                return "Not suggested: " + s.why
        return None

    @property
    def blocking(self) -> bool:
        return any(w.level == "critical" for w in self.warnings)


# --------------------------------------------------------------------------- helpers
def _low(values) -> list[str]:
    return [str(v).strip().lower() for v in values or [] if v and "@" in str(v)]


def _domain(address: str) -> str:
    return address.rpartition("@")[2].lower()


def _domain_in(address: str, domains) -> bool:
    d = _domain(address)
    return any(d == x or d.endswith("." + x) for x in (str(x).strip().lower().lstrip("@") for x in domains) if x)


def fmt_day(v: datetime | None) -> str:
    if v is None:
        return "an earlier date"
    d = v.astimezone(UTC) if v.tzinfo else v
    return f"{d.day} {d:%b %Y}"


def fmt_amount(v) -> str | None:
    """'399,247.92' for large amounts, up to 8 significant decimals for small ones ('0.0581')."""
    if v is None or v == "":
        return None
    try:
        d = Decimal(str(v))
    except (InvalidOperation, ValueError):
        return None
    if d >= 1000:
        return f"{d.quantize(Decimal('0.01')):,}"
    s = f"{d.quantize(Decimal('0.00000001')).normalize():f}"
    return s


def _victim_like(inp: Inputs):
    victims = set(_low(inp.victim_addresses))
    domains = {_domain(a) for a in victims if _domain(a) not in SHARED_DOMAINS}

    def check(address: str) -> bool:
        a = address.lower()
        return a in victims or _domain(a) in domains

    return check


def _purpose_text(p: str) -> str:
    return {"le_request": "LE-request", "freeze": "freeze-request", "compliance": "compliance", "legal": "legal",
            "abuse": "abuse", "complaint": "complaint"}.get(p, "general")


# --------------------------------------------------------------------------- To
def rank_to(inp: Inputs) -> tuple[list[Suggestion], list[Suggestion]]:
    """(ranked To suggestions, addresses deliberately left out) — module doc."""
    is_victim = _victim_like(inp)
    mailbox = (inp.mailbox or "").lower()
    own = set(_low(inp.own_addresses)) | set(_low(inp.profile_cc))
    le = set(_low(inp.le_addresses))
    follow_up = inp.letter_kind in FOLLOW_UP_KINDS
    found: dict[str, Suggestion] = {}
    avoid: dict[str, Suggestion] = {}
    verified = {c.address.lower() for c in inp.channels if c.verified}
    le_only = set() if inp.requester in playbook.OFFICIAL else {c.address.lower() for c in inp.channels
                                                                 if not playbook.may_use(c.who, inp.requester)}

    def offer(address: str, score: int, why: str, is_verified: bool | None = None) -> None:
        a = address.strip().lower()
        if not a or "@" not in a:
            return
        if a == mailbox:
            return
        if inp.demo and not demo_safe(a):
            return  # a real organisation's address: never shown for a demo case (the demo lock)
        if is_victim(a):
            avoid.setdefault(a, Suggestion(a, "the victim's own address: letters go to the authority, not the client"))
            return
        if a in own:
            return
        if a in le_only:
            avoid.setdefault(a, Suggestion(a, playbook.LE_ONLY_REASON))
            return
        if a in le and not inp.is_le:
            avoid.setdefault(a, Suggestion(a, "a law-enforcement officer's address: not a recipient of letters to "
                                              f"{inp.authority_name}"))
            return
        v = a in verified if is_verified is None else is_verified
        cur = found.get(a)
        if cur is None or score > cur.score:
            found[a] = Suggestion(a, why, v, score)
        elif cur is not None and v and not cur.verified:
            cur.verified = True

    # earlier letters to this authority, newest first
    for letter in sorted(inp.sent, key=lambda s: s.at or datetime.min.replace(tzinfo=UTC), reverse=True):
        for a in _low(letter.to):
            tick = " · ✓ verified" if a in verified else " (not verified in the directory)"
            offer(a, 100 if follow_up else 90, f"address used in the letter you sent on {fmt_day(letter.at)}{tick}")
    for c in inp.channels:
        if c.role_default == "cc":
            continue
        label = f" ({c.label})" if c.label and c.source not in ("entity_record", "case_correspondence") else ""
        if c.who == "counsel_with_order" and inp.requester in playbook.PRIVATE:
            label += " — acts on LE process or a court order: expect a redirect"
        if c.verified:
            if c.purpose in ("le_request", "freeze"):
                offer(c.address, 95 if follow_up else 100, f"verified {_purpose_text(c.purpose)} channel{label}", True)
            elif c.purpose in ("compliance", "legal", "abuse"):
                offer(c.address, 80, f"verified {_purpose_text(c.purpose)} channel{label}", True)
            else:
                offer(c.address, 60, f"verified channel{label}", True)
        elif c.source == "entity_record":
            offer(c.address, 30, "entity compliance address (unverified — confirm on their LE portal first)", False)
        elif c.source == "le_contact":
            offer(c.address, 60 if inp.is_le else 20, "LE officer on file for this case", False)
        elif c.source == "case_correspondence":
            offer(c.address, 35, "seen in this case's correspondence (unverified — confirm before sending)", False)
        elif c.source in ("catalogue", "global"):
            offer(c.address, 40, f"published {_purpose_text(c.purpose)} address{label} (unverified — confirm on "
                                 "their LE portal or website first)", False)
        else:
            offer(c.address, 40, f"added for this case{label} (unverified — confirm before sending)", False)
    for r in sorted(inp.replies, key=lambda r: r.at or datetime.min.replace(tzinfo=UTC), reverse=True):
        offer(r.address, 70, f"replied to this case from this address on {fmt_day(r.at)}")
    # a reply that redirected us: the address it came from is not the channel; the address it named is offered
    # (only from the authority's own domain, on that same domain: verify it against their published channels)
    for rd in inp.redirects:
        away = (rd.away or "").strip().lower()
        if rd.trusted and rd.to and away and _domain(rd.to) == _domain(away):
            offer(rd.to, 85, f"named in their reply of {fmt_day(rd.at)} as the address for this (unverified — "
                             "check it against their published channels)")
    for rd in inp.redirects:
        away = (rd.away or "").strip().lower()
        if rd.trusted and away in found and found[away].address.lower() != (rd.to or "").lower():
            found.pop(away)
            avoid.setdefault(away, Suggestion(away, f"their reply of {fmt_day(rd.at)} says this is not the channel "
                                                    f"to use{(' and names ' + rd.to) if rd.to else ''}"))
    ranked = sorted(found.values(), key=lambda s: (-s.score, not s.verified, s.address))
    if inp.send_domains is not None:  # what cannot be sent from here goes last, saying why (the order is kept)
        ok = [s for s in ranked if _domain_in(s.address, inp.send_domains)]
        for s in ranked:
            if s not in ok:
                s.why += " — not first here: this case e-mails test addresses only"
        ranked = ok + [s for s in ranked if s not in ok]
    for i, s in enumerate(ranked, start=1):
        s.rank = i
    return ranked, list(avoid.values())


# --------------------------------------------------------------------------- Cc
def suggest_cc(inp: Inputs, to: list[Suggestion]) -> tuple[list[Suggestion], list[Suggestion]]:
    is_victim = _victim_like(inp)
    mailbox = (inp.mailbox or "").lower()
    taken = {s.address.lower() for s in to}
    le = set(_low(inp.le_addresses))
    out: dict[str, Suggestion] = {}
    avoid: dict[str, Suggestion] = {}
    chosen = set(_low(inp.profile_cc))  # the sender profile's default Cc: a case admin's deliberate choice

    def offer(address: str, score: int, why: str) -> None:
        a = address.strip().lower()
        if not a or "@" not in a or a in taken or a in out:
            return
        if inp.demo and not demo_safe(a) and a != mailbox:
            return  # the demo lock (the case mailbox is our own: a person sending it may copy it)
        if is_victim(a) and a not in chosen:
            avoid.setdefault(a, Suggestion(a, "the victim's personal address: never copied by default"))
            return
        if a in le and inp.letter_kind != "le_cover" and not inp.is_le:
            avoid.setdefault(a, Suggestion(a, "a law-enforcement officer: copied on LE cover letters only"))
            return
        out[a] = Suggestion(a, why, score=score)

    if inp.manual and mailbox:
        offer(mailbox, 100, "the case mailbox (AEGIS_MAIL_FROM): copy it when you send from another mailbox, so "
                            "replies land where Aegis reads them; not needed when you send from it")
    for a in _low(inp.profile_cc):
        offer(a, 90, "the sender profile copies this address on every letter")
    for c in inp.channels:
        if c.role_default == "cc" and c.address.lower() != mailbox:
            offer(c.address, 70, "the directory lists it as a copy address" + (f" ({c.label})" if c.label else ""))
    if inp.letter_kind == "le_cover":
        agency = inp.le_addresses if inp.agency_le_addresses is None else inp.agency_le_addresses
        for a in _low(agency):  # officers of this agency or jurisdiction only, never another agency's officer
            offer(a, 80, "law-enforcement contact of this agency on this case (LE cover letters only)")
    for letter in sorted(inp.sent, key=lambda s: s.at or datetime.min.replace(tzinfo=UTC), reverse=True):
        for a in _low(letter.cc):
            if a != mailbox:
                offer(a, 50, f"copied on the letter you sent on {fmt_day(letter.at)}")
    for a in _low(inp.draft_cc):  # the draft's own Cc: victim / LE copies end up in `avoid`
        if a != mailbox:
            offer(a, 40, "in the letter's Cc")
    ranked = sorted(out.values(), key=lambda s: (-s.score, s.address))
    for i, s in enumerate(ranked, start=1):
        s.rank = i
    return ranked, list(avoid.values())


# --------------------------------------------------------------------------- subject
def _clean_subject(s: str | None) -> str:
    text = TAG_RE.sub(" ", s or "")
    text = " ".join(text.split())
    while True:  # "Follow-up: Re: Follow-up: X" -> "X"
        m = re.match(r"(?i)^(follow-up|follow up|re|aw|fw|fwd|wg)\s*:\s*", text)
        if not m:
            break
        text = text[m.end():]
    text = re.sub(r"\s+–\s+Ref [A-Za-z0-9._-]+$", "", text)
    text = re.sub(r"\s+–\s+sent [^–]+$", "", text)  # an earlier follow-up's own "– sent <date>"
    return text.strip()


def _fit(parts: list[str], ref: str, flexible: int | None = None) -> str:
    """Join with " – ", end with "Ref <CASE>", shorten parts[flexible] (with "…") to fit SUBJECT_MAX."""
    tail = f"Ref {ref}"
    parts = [p for p in parts if p]
    text = " – ".join([*parts, tail])
    if len(text) <= SUBJECT_MAX or flexible is None or flexible >= len(parts):
        return text[:SUBJECT_MAX]
    over = len(text) - SUBJECT_MAX
    p = parts[flexible]
    parts[flexible] = (p[:max(8, len(p) - over - 1)].rstrip() + "…")
    return " – ".join([*parts, tail])[:SUBJECT_MAX]


def subject_body(kind: str, ref: str, facts: SubjectFacts, *, adviser: bool = False) -> str:
    service = " ".join((facts.service or "").split())
    if adviser and kind not in ("status_request", "other", "reply"):
        return _fit(["Case Update"], ref)  # to the case's own adviser: neither a request nor their name
    amount = fmt_amount(facts.amount)
    asset_amount = f"{facts.asset} {amount}" if facts.asset and amount else (facts.asset or "")
    if kind == "stop_order":
        return _fit(["URGENT", "Preservation & Risk-Control Request", service, asset_amount], ref)
    if kind == "status_request":
        orig = _clean_subject(facts.original_subject) or "our earlier letter"
        return _fit([f"Follow-up: {orig}", f"sent {fmt_day(facts.original_sent_at)}"], ref, flexible=0)
    if kind == "info_request":
        return _fit(["Information & Preservation Request", service], ref)
    if kind == "le_cover":
        own = " ".join((facts.complaint_ref or "").split())
        return _fit(["Fund-Flow Summary & Freeze Opportunities", f"Your ref {own}" if own else ""], ref)
    if kind == "release_request":
        return _fit(["Request for Release of Held Funds", service, asset_amount], ref)
    return _fit([_clean_subject(facts.letter_subject) or "Letter"], ref, flexible=0)


def tag_for(ref: str, letter_id: int | None) -> str:
    return f"[Aegis {ref} #{letter_id if letter_id is not None else '<letter no.>'}]"


# --------------------------------------------------------------------------- warnings
def warnings_for(inp: Inputs, to: list[Suggestion], avoid: list[Suggestion]) -> list[Warning]:
    out: list[Warning] = []
    name = inp.authority_name
    if inp.le_only_reason and not inp.is_le:
        out.append(Warning("critical", "le_only", inp.le_only_reason))
    le_only = [s.address for s in avoid if s.why == playbook.LE_ONLY_REASON]
    if le_only:
        out.append(Warning("warning", "le_only_channel", f"Not suggested: {', '.join(le_only)} — {name} reserves it "
                                                         f"for law enforcement. {playbook.LE_ONLY_REASON} (an LE "
                                                         "cover letter to the case's LE authority)."))
    if inp.portal_only:
        where = f" at {inp.portal_url}" if inp.portal_url else " at its portal"
        out.append(Warning("critical", "portal_only", f"Submit via portal, not e-mail: {name} takes reports only{where}. "
                                                      "Prepare the letter, submit it there, then Mark sent with "
                                                      "channel portal."))
    if inp.info_only:
        if inp.letter_kind in FREEZE_KINDS:
            out.append(Warning("critical", "info_only", f"Cannot freeze — information request only: {name} is "
                                                        "non-custodial (it holds no accounts or balances). Send an "
                                                        "information request instead of a freeze request."))
        else:
            out.append(Warning("info", "info_only", f"Non-custodial: {name} cannot freeze funds; ask for information "
                                                    "and preservation only."))
    if inp.is_adviser:
        out.append(Warning("info", "adviser", f"Adviser on this case: {name} works for the victim on this case. A letter "
                                              "to them is a case update or an information request, never a stop order."))
        if not to:
            out.append(Warning("warning", "no_address", f"No e-mail address on file for {name}: add their address "
                                                        "on the authority page first."))
        elif not to[0].verified:
            out.append(Warning("info", "unverified", f"{name}'s address ({to[0].address}) is not verified in the "
                                                     "directory: confirm it with them."))
    elif not to and not inp.portal_only:
        out.append(Warning("warning", "no_address", f"No e-mail address on file for {name}: find their "
                                                    "law-enforcement request channel (portal or published address) "
                                                    "and add it to the directory first."))
    elif to and not to[0].verified and not inp.portal_only and not inp.demo:
        out.append(Warning("warning", "unverified", f"The best address for {name} ({to[0].address}) is not verified: "
                                                    "confirm it on their LE portal or website before sending."))
    if inp.demo:
        hidden = len(demo_hidden(inp))
        out.append(Warning("info", "demo", DEMO_LOCK_TEXT + (
            f": {hidden} real published address{'es' if hidden != 1 else ''} not shown." if hidden else ".")))
    for rd in inp.redirects[:1]:  # the newest
        where = f" and names {rd.to}" if rd.to else ""
        check = "" if rd.trusted else " The reply did not come from their own domain: verify before using it."
        out.append(Warning("warning", "redirected", f"Their reply of {fmt_day(rd.at)} says "
                                                    f"{rd.away or 'the address used'} is not the channel to use{where}."
                                                    f"{check}"))
    victim_cc = [s.address for s in avoid if "victim" in s.why]
    if victim_cc:
        out.append(Warning("warning", "victim_cc", "Not copied: " + ", ".join(victim_cc) + " is the victim's personal "
                                                   "address. Copy the victim only if they asked for it."))
    le_cc = [s.address for s in avoid if "law-enforcement" in s.why]
    if le_cc:
        out.append(Warning("warning", "le_cc", "Not copied: " + ", ".join(le_cc) + " belongs to law enforcement; "
                                               "copy officers on LE cover letters only."))
    return out


def demo_hidden(inp: Inputs) -> list[str]:
    """The addresses the demo lock leaves out of a demo case's guidance (real organisations' addresses)."""
    if not inp.demo:
        return []
    mailbox = (inp.mailbox or "").lower()
    seen = [c.address.lower() for c in inp.channels] + [a for s in inp.sent for a in _low(s.to)] + [
        r.address.lower() for r in inp.replies]
    return sorted({a for a in seen if "@" in a and a != mailbox and not demo_safe(a)})


# --------------------------------------------------------------------------- all together
def instruction(mailbox: str | None, manual: bool, portal_only: bool = False) -> str:
    if portal_only:
        return ("Do not e-mail: submit the letter through the authority's portal, then record it with Mark sent "
                "(channel: portal) and keep the portal's confirmation as evidence.")
    if not manual:
        return "Aegis sends from the case mailbox; replies are matched by the tracking tag at the start of the subject."
    if not mailbox:
        return "Send it from Outlook; keep the subject unchanged so replies can be matched when you import them."
    return (f"Send it from the case mailbox ({mailbox}) in Outlook — or, from another mailbox, copy {mailbox} as "
            "suggested — and keep the subject unchanged so replies are matched.")


def guide(inp: Inputs) -> Guidance:
    to, avoid_to = rank_to(inp)
    cc, avoid_cc = suggest_cc(inp, to)
    if inp.portal_only:
        cc = []  # a portal submission has no Cc (and copying another agency on it is not ours to decide)
    avoid = {s.address: s for s in [*avoid_to, *avoid_cc]}
    tag = tag_for(inp.case_reference, inp.letter_id)
    body = subject_body(inp.letter_kind, inp.case_reference, inp.facts, adviser=inp.is_adviser)
    return Guidance(authority_name=inp.authority_name, letter_kind=inp.letter_kind, to=to, cc=cc,
                    warnings=warnings_for(inp, to, list(avoid.values())), subject=f"{body} {tag}",
                    subject_body=body, tag=tag, instruction=instruction(inp.mailbox, inp.manual, inp.portal_only),
                    avoid=list(avoid.values()))


# --------------------------------------------------------------------------- the adapter (reads the case)
def next_kind(authority, requester: str = "pi") -> str:
    """The letter an authority would get next: a follow-up once something went out, else a freeze
    request (an information request for a non-custodial service or the case's own adviser, an LE cover
    letter for LE). "le_handoff" when its provider playbook takes no letter from `requester` (the LE-only gate)."""
    from app.db.models import CorrespondenceDirection, CorrespondenceStatus
    from app.domain.correspondence import playbook_gate_reason

    if not authority.is_le and playbook_gate_reason(authority, requester):
        return "le_handoff"
    sent = any(c.direction == CorrespondenceDirection.OUT and c.status == CorrespondenceStatus.SENT
               for c in authority.correspondence) or any(o.sent_at for o in authority.stop_orders)
    if sent:
        return "status_request"
    if authority.is_le:
        return "le_cover"
    if getattr(authority, "is_adviser", False) or getattr(authority, "non_custodial", False):
        return "info_request"  # the only letter the form offers an adviser (correspondence.template_options)
    return "stop_order"


def _order_asset_amount(order) -> tuple[str | None, Decimal | None]:
    """The asset that reached the service's addresses in a stop order's identifiers (the largest USD value,
    else the most transfers) and its amount: the largest total received by **one** address. The addresses of
    an order often lie on one path (the same funds received by a wallet and then by the next one), so a sum
    over addresses would count the same money twice; the subject never states more than one address got."""
    if order is None:
        return None, None
    totals: dict[str, list] = {}  # asset -> [largest per-address amount, its USD, transfers in all]
    for a in (order.identifiers or {}).get("addresses") or []:
        if not isinstance(a, dict):
            continue  # an imported letter lists bare addresses
        per: dict[str, list] = {}
        for tx in a.get("inbound") or []:
            if not isinstance(tx, dict):
                continue
            asset = str(tx.get("asset") or "").strip()
            if not asset:
                continue
            row = per.setdefault(asset, [Decimal(0), Decimal(0), 0])
            try:
                row[0] += Decimal(str(tx.get("amount") or 0))
            except (InvalidOperation, ValueError):
                pass
            try:
                row[1] += Decimal(str(tx.get("amount_usd") or 0))
            except (InvalidOperation, ValueError):
                pass
            row[2] += 1
        for asset, (amount, usd, n) in per.items():
            best = totals.setdefault(asset, [Decimal(0), Decimal(0), 0])
            if (usd, amount) > (best[1], best[0]):
                best[0], best[1] = amount, usd
            best[2] += n
    if not totals:
        return None, None
    asset, (amount, _usd, _n) = max(totals.items(), key=lambda kv: (kv[1][1], kv[1][2]))
    return asset, amount if amount > 0 else None


def _emailed_subject(db, key: str) -> str | None:
    """The subject of the e-mail that actually carried letter `key` (o<ID> / c<ID>), sent by Aegis or
    recorded as sent outside it: the follow-up must quote what the authority received."""
    from app.db.models import (
        Correspondence,
        CorrespondenceKind,
        MailDirection,
        MailMessage,
        MailStatus,
    )

    keys = {key}
    if key.startswith("c"):  # a stop order's letter is filed under its stop order (mail_compose.letter_key)
        c = db.get(Correspondence, int(key[1:]))
        if c is not None and c.kind == CorrespondenceKind.STOP_ORDER and c.stop_order_id:
            keys.add(f"o{int(c.stop_order_id)}")
    mm = (db.query(MailMessage)
          .filter(MailMessage.letter_key.in_(sorted(keys)), MailMessage.direction == MailDirection.OUT,
                  MailMessage.status.in_([MailStatus.SENT, MailStatus.SENT_EXTERNAL]))
          .order_by(MailMessage.id.desc()).first())
    return mm.subject if mm is not None and mm.subject else None


def _reference_letter(db, authority, corr):
    """(subject, sent_at) of the letter a status request follows up: its `references` (c<ID> / o<ID>),
    else the authority's latest sent letter. The subject is the e-mail's own subject when the letter
    went out by e-mail (`_emailed_subject`), else the letter's heading."""
    subject, at = _reference_letter_heading(db, authority, corr)
    key = _reference_key(authority, corr)
    if key:
        emailed = _emailed_subject(db, key)
        if emailed:
            subject = emailed
    return subject, at


def _reference_key(authority, corr) -> str | None:
    from app.db.models import CorrespondenceDirection, CorrespondenceKind, CorrespondenceStatus

    ref = str(((corr.meta or {}) if corr is not None else {}).get("references") or "")
    if re.fullmatch(r"[co]\d{1,12}", ref):
        return ref
    sent = [(c.occurred_at, (f"o{c.stop_order_id}" if c.kind == CorrespondenceKind.STOP_ORDER and c.stop_order_id
                             else f"c{c.id}"))
            for c in authority.correspondence
            if c.direction == CorrespondenceDirection.OUT and c.status == CorrespondenceStatus.SENT and c.occurred_at]
    sent += [(o.sent_at, f"o{o.id}") for o in authority.stop_orders if o.sent_at]
    if not sent:
        return None
    return max(sent, key=lambda r: r[0] if r[0].tzinfo else r[0].replace(tzinfo=UTC))[1]


def _reference_letter_heading(db, authority, corr):
    from app.db.models import Correspondence, CorrespondenceDirection, CorrespondenceStatus

    ref = str(((corr.meta or {}) if corr is not None else {}).get("references") or "")
    if re.fullmatch(r"c\d{1,12}", ref):
        c = db.get(Correspondence, int(ref[1:]))
        if c is not None and corr is not None and c.case_id == corr.case_id:
            return c.subject, c.occurred_at
    if re.fullmatch(r"o\d{1,12}", ref):
        o = next((o for o in authority.stop_orders if o.id == int(ref[1:])), None)
        if o is not None:
            return o.subject, o.sent_at
    sent = [(c.occurred_at, c.subject) for c in authority.correspondence
            if c.direction == CorrespondenceDirection.OUT and c.status == CorrespondenceStatus.SENT and c.occurred_at]
    sent += [(o.sent_at, o.subject) for o in authority.stop_orders if o.sent_at]
    if not sent:
        return None, None
    at, subject = max(sent, key=lambda r: r[0] if r[0].tzinfo else r[0].replace(tzinfo=UTC))
    return subject, at


def _held(authority) -> tuple[str | None, Decimal | None]:
    for c in sorted(authority.correspondence, key=lambda c: c.id or 0, reverse=True):
        meta = c.meta or {}
        if meta.get("amount_held"):
            try:
                return meta.get("asset"), Decimal(str(meta["amount_held"]))
            except (InvalidOperation, ValueError):
                continue
    return None, None


def for_authority(db, access, authority, corr=None, *, card=None, settings=None) -> Guidance:
    """Guidance for writing to `authority` (the letter `corr` when given, else its next letter)."""
    from app.db.models import CorrespondenceDirection, CorrespondenceKind, CorrespondenceStatus
    from app.domain import directory
    from app.domain import sender as sender_mod

    if settings is None:
        from app.domain import mail_send

        settings = mail_send._settings()
    case = access.case
    card = card if card is not None else directory.channels_for(db, access, authority)
    requester = sender_mod.requester_kind(db, case)
    kind = corr.kind.value if corr is not None else next_kind(authority, requester)
    if kind == CorrespondenceKind.STOP_ORDER.value and corr is not None and corr.stop_order is None \
            and (corr.meta or {}).get("template_key") == "release_request":
        kind = "release_request"
    channels = tuple(Channel(address=e.value, verified=e.verified, source=e.source, purpose=e.purpose,
                             role_default=e.role_default, label=e.label, who=getattr(e, "who", None))
                     for e in card.emails())
    sent, replies = [], []
    for c in authority.correspondence:
        if corr is not None and c.id == corr.id:
            continue
        if c.direction == CorrespondenceDirection.OUT and c.status == CorrespondenceStatus.SENT:
            if directory.recipients_untrusted(c):
                continue  # an Outlook e-mail logged for review / dismissed / not addressed to the authority
            sent.append(SentLetter(at=c.occurred_at, to=tuple(c.recipients or []), cc=tuple(c.cc or []),
                                   subject=c.subject or ""))
        elif c.direction == CorrespondenceDirection.IN and (c.meta or {}).get("sender_domain_ok") is not False:
            for m in re.finditer(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", c.sender or ""):
                replies.append(Reply(m.group(0), c.occurred_at))
    logged = {c.stop_order_id for c in authority.correspondence if c.stop_order_id}
    for o in authority.stop_orders:
        if o.sent_at and o.id not in logged and o.recipient_email:
            sent.append(SentLetter(at=o.sent_at, to=(o.recipient_email,), cc=tuple(o.recipient_cc or []),
                                   subject=o.subject or ""))
    profile = sender_mod.get_profile(db, case)
    facts = dict(case.facts or {})
    victim = [str((facts.get("victim_contact") or {}).get("email") or "")]
    own = [profile.contact_email] if profile is not None and profile.contact_email else []
    own += [m.user.email for m in case.members if m.user is not None and m.user.email]
    order = corr.stop_order if corr is not None else next((o for o in authority.stop_orders), None)
    asset, amount = _order_asset_amount(order)
    if kind == "release_request":
        held_asset, held = _held(authority)
        asset, amount = held_asset or asset, held if held is not None else amount
    orig_subject, orig_at = _reference_letter(db, authority, corr) if kind == "status_request" else (None, None)
    complaint_ref = None
    if kind == "le_cover":
        complaint_ref = next((le.reference for le in authority.le_contacts if getattr(le, "reference", None)), None) \
            or (authority.contact or {}).get("reference")
    manual = getattr(settings, "aegis_mail_transport", "manual") in ("manual", "none")
    # LE officers copied on an LE cover letter: this authority's own, and the case's officers of the same jurisdiction
    own_le = [le for le in authority.le_contacts if le.email]
    places = {(le.jurisdiction or "").strip().lower() for le in own_le if (le.jurisdiction or "").strip()}
    agency_le = [le.email for le in own_le] + [le.email for le in case.le_contacts if le.email and places
                                               and (le.jurisdiction or "").strip().lower() in places]
    from app.domain.correspondence import playbook_gate_reason

    inp = Inputs(
        requester=requester, le_only_reason=playbook_gate_reason(authority, requester),
        send_domains=_send_domains(case, settings),
        redirects=_redirects(db, case, authority, kind),
        authority_name=authority.name, case_reference=case.reference, letter_kind=kind,
        letter_id=corr.id if corr is not None else None, is_le=bool(authority.is_le),
        is_adviser=bool(getattr(authority, "is_adviser", False)), agency_le_addresses=tuple(dict.fromkeys(agency_le)),
        info_only=bool(card.info_only or getattr(authority, "non_custodial", False)),
        portal_only=bool(card.portal_only), portal_url=card.portal_url, channels=channels, sent=tuple(sent),
        replies=tuple(replies), mailbox=getattr(settings, "mail_from", "") or None, manual=manual,
        profile_cc=tuple(profile.cc_default or []) if profile is not None else (), own_addresses=tuple(own),
        victim_addresses=tuple(v for v in victim if v), le_addresses=tuple(le.email for le in case.le_contacts if le.email),
        demo=bool(getattr(case, "is_demo", False)),
        draft_to=tuple(corr.recipients or []) if corr is not None else (),
        draft_cc=tuple(corr.cc or []) if corr is not None else (),
        facts=SubjectFacts(service=authority.name, asset=asset, amount=amount,
                           original_subject=orig_subject, original_sent_at=orig_at, complaint_ref=complaint_ref,
                           letter_subject=corr.subject if corr is not None else None))
    return guide(inp)


def _send_domains(case, settings) -> tuple[str, ...] | None:
    """The domains a letter of `case` can go to from here (`Inputs.send_domains`): the test domains
    (AEGIS_MAIL_DEV_ALLOWED_DOMAINS) for local-mode Graph sending (app.domain.mail_compose._dev_allowed); None: any.
    A demo case is limited by the demo lock instead (`Inputs.demo`, mail_compose.demo_lock_problem)."""
    try:
        from app.domain import mail_compose

        allowed = mail_compose._dev_allowed(settings)  # a demo case: the demo lock (`Inputs.demo`) already applies
        return tuple(sorted(allowed)) if allowed else None
    except Exception:  # noqa: BLE001 - advice only: no restriction stated
        return None


def _redirects(db, case, authority, kind: str | None = None) -> tuple[Redirect, ...]:
    """The authority's replies read as "redirected" (app.blocks.status, rules / AI / a person), newest first.
    The address offered keeps the purpose of the letter being written (`kind`: a freeze request or its status
    request → the freeze address; an information request / LE cover letter → the legal one), else the request's."""
    try:
        from app.blocks import status as block_status

        seen, out = set(), []
        for row in block_status.case_blocks(db, case, authorities=[authority]):
            for rv in row.replies:
                if rv.status != block_status.rules.REDIRECTED or rv.corr.id in seen:
                    continue
                seen.add(rv.corr.id)
                sender = (rv.corr.sender or "").strip().lower() or None
                out.append(Redirect(away=sender, to=block_status.pick_resend(rv.addresses, kind or row.kind), at=rv.at,
                                    trusted=rv.sender_domain_ok is True, reply_id=rv.corr.id))
        return tuple(sorted(out, key=lambda r: r.at or datetime.min.replace(tzinfo=UTC), reverse=True))
    except Exception:  # noqa: BLE001 - guidance is advice: it works without the block status
        return ()
