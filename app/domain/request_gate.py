"""One open request per provider: the ONE gate every letter and stop order addressed to a provider passes.

    st = state(db, case, authority)                        # the provider's requests (its block rows), None: not a provider
    d = decide(st, "info_request", about=["ethereum:0x…"], ref="o12")   # what may be created
    d = gate(db, case, authority, "stop_order")            # state + decide
    add_to_draft(db, case, authority, d, actor=user)       # an ADD_TO_DRAFT decision: the address into the open draft

**Who.** A *provider* authority: an exchange, an issuer, a swap service, a casino, a host — any entity counterparty that
is not law enforcement, not counsel / an adviser, not a complaint or PI-firm record (`is_provider`). Letters to LE
contacts and counsel are never gated here.

**Where.** Every creation of a letter or a stop order to a provider goes through `decide`: services
.generate_stop_orders (the Authorities tab's bulk button, a row's button, POST /api/cases/{id}/stop-orders),
correspondence.generate_letter (the authority page, any template; the assistant's /stop-orders; the Recovery plan's
actions, its owner moves and the owners panel's links all lead there). The Recovery plan (its actions:
`gate_actions`), the Freeze & stop-order board (its rows and owner steps), the owners panel and the assistant derive
the step they show from the same decision: when it is OPEN_EXISTING / ADD_TO_DRAFT / FOLLOW_UP_ONLY / LE_BRIEF_ONLY
they show that, never a new-letter link.

**Rules**, in order (the provider's requests are its block-status rows, app.blocks.status, without the duplicate drafts
the board flags):

(a) the provider answered LE only / court order, or declined (a refusal; "no account / no assets" is no refusal: its
    follow-ups stay open) → LE_BRIEF_ONLY for every template: the LE brief naming the provider (and the address:
    `about=` on its link). Its playbook acts on LE requests only for our requester (desk.playbook_gate_reason) →
    LE_BRIEF_ONLY for a first contact (GATED_TEMPLATES). Both come before any open draft: a draft to that provider
    (a follow-up drafted before the answer, an owner letter) is pointless (`State.pointless`: the board flags it, a
    case admin discards it), never "open it and send it" nor the place a new address is added to.
(b) an OPEN request — a draft letter or a draft stop order (not superseded, not discarded), a draft follow-up tied to
    a sent stop order (a status request / an answer quoting it), or one whose prepared e-mail waits for Send — gives
    OPEN_EXISTING (send that draft). A newly identified address of that provider (an
    owner deposit, a hot wallet, a swap order: `about=["<chain>:<address>"]`) that the draft does not cite yet gives
    ADD_TO_DRAFT: `add_to_draft` puts it into that draft (the stop order's identifiers, a sentence in the letter,
    `meta.about`), never a second letter. A BUSY draft is never changed underneath it: OPEN_EXISTING — its e-mail is
    prepared and waits for Send, or it may already be out (sending, sent, of unknown outcome, an open "Draft — you
    send" checklist, prepared or expired, a failed one that left an unsent draft in the mailbox: `busy_mail`, the rule
    services.mail_pending applies to a replacement). A draft follow-up (one tied to a sent stop order, or a letter
    quoting a sent request: a status request, an answer, a release request, a deposit follow-up) drafted before the
    latest reply to that request (or a state a person recorded on it) is STALE (`Request.stale`, `State.stale`) — unless
    it is HELD (its e-mail prepared and waiting for Send, or under way: it stays the open request, `Request.late`
    saying why it may no longer fit, so no second follow-up goes out beside it): it does not know that reply, so it
    is no open request — the board flags it like a pointless draft ("drafted before
    their reply of …", a case admin discards it), and the follow-up that reply calls for (the answer to their
    questions, a release request, a new deposit's follow-up quoting the request) is rule (c)'s, never "send the stale
    draft" nor the draft a new address is added to.
(c) a request SENT (awaiting reply, acknowledged, info requested, overdue, redirected, held / frozen …) → FOLLOW_UP_ONLY:
    only a follow-up tied to it — a status request, an answer to their questions, a release request, or an
    information request citing a NEW address with `ref=<that request>` (the "new deposit address" follow-up). An
    address a live request already cites never gets a second letter. One exception keeps the freeze ask: a provider
    with funds traced whose only sent requests asked for records (no freeze) may still get the stop order — unless it
    answered one of them that it holds no account / no assets (FOLLOW_UP_ONLY: follow that answer up).
    `freeze_over_records`: a records-only DRAFT to such a provider is no reason to hold the freeze ask back — the
    board and the plan lead with the stop order replacing it (freeze_board.replace_offer).
(d) else ALLOW.

A POINTLESS draft (`State.pointless`: rule (a)'s drafts, a stale follow-up) is never e-mailed: compose and Send refuse
it like a superseded one (mail_compose.pointless_text: "Draft #N is pointless: <why>; discard it"), the awaiting-Send
banner leaves its prepared e-mail out, and no page links it as "send" (the authority page's timeline included). So is
a DUPLICATE draft the board flags (a legacy stop-order draft repeating a freeze request already sent: it is no live
request here, and freeze_board.draft_flags / letter_flag carry its flag): "Draft #N duplicates request #M; discard it".

The LE brief / cover letter a provider's LE step opens names the LE the plan's LE route picks for that provider
(`le_key_for`: a reachable one first), the same on the board, the plan's moves, the owners panel and the gate's link.
After an LE-only / court-order / declined answer whose row has its own LE step — its LE brief / cover letter, or the LE
route's page (a US case agent's complaint, /authorities/le-N: `State.le_label` names it as the row does) — that step is
the gate's link on every surface (`_le_href`).

A pointless or duplicate draft is never recorded as sent by hand either (the letter's Mark sent, the stop order's
"sent" status, the API PATCH: routes_authorities.sent_refusal) — unless its e-mail may already be out (`busy`):
recording it as sent is how that is settled.

`replace={"o12"}`: the explicit "replaces draft #12" confirmation of the authority page (a stop order generated over
a draft; only the draft the page offers counts, freeze_board.replace_offer) or the row's "Redraft from trace #N": that
draft is not open for the decision (it is superseded by the creation; generate_letter marks a replaced letter
`meta.superseded_by` and carries its `about` into the stop order). Never a draft whose e-mail is prepared, nor a drafted
follow-up: those stay open (send them); the generators refuse to supersede a draft whose e-mail waits for Send or is
under way (services.mail_pending), and Send refuses a superseded letter (mail_compose.superseded_text).

Every generated letter records `meta.about` (the chain:address list it concerns); a stop order keeps its identifiers.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlparse

log = logging.getLogger(__name__)

ALLOW, OPEN_EXISTING, ADD_TO_DRAFT = "allow", "open_existing", "add_to_draft"
FOLLOW_UP_ONLY, LE_BRIEF_ONLY, UNAVAILABLE = "follow_up_only", "le_brief_only", "unavailable"
# follow-ups tied to a request already sent (any of them; their own template checks name which request)
FOLLOW_UPS = frozenset({"status_request", "info_response", "release_request"})
GATED_TEMPLATES = frozenset({"stop_order", "info_request"})  # desk.GATED_TEMPLATES: the playbook's LE-only gate
LE_TEMPLATES = frozenset({"le_cover", "le_brief", "counsel_brief"})  # to LE / counsel: never a provider's request
_ADDR = re.compile(r"^(?:([a-z0-9_-]{2,20}):)?([A-Za-z0-9]{20,100})$")


class Unavailable(Exception):
    """The provider's requests could not be read: nothing is drafted blind (the caller's 503 / "Not drafted")."""


def _now() -> datetime:
    return datetime.now(tz=UTC)


def addr_of(v: str | None) -> str:
    """The address part of "<chain>:<address>" (or a bare address), lower-cased: what "cites" compares."""
    return str(v or "").strip().rsplit(":", 1)[-1].strip().lower()


def norm_about(about) -> list[str]:
    """`about` as a list of "<chain>:<address>" (desk.freeze_key: an EVM address lower-cased), once each, from a list
    or a comma-separated string; anything that is no address is dropped."""
    from app.domain import correspondence as desk

    if not about:
        return []
    items = about.split(",") if isinstance(about, str) else list(about)
    out: list[str] = []
    for x in items:
        m = _ADDR.fullmatch(str(x or "").strip())
        if m is None:
            continue
        k = desk.freeze_key(m.group(1), m.group(2))
        if addr_of(k) not in {addr_of(y) for y in out}:
            out.append(k)
    return out[:20]


def short(v: str) -> str:
    a = str(v or "").rsplit(":", 1)[-1]
    return f"{a[:6]}…{a[-4:]}" if len(a) > 12 else a


def is_provider(authority) -> bool:
    """A counterparty that holds funds or records (an exchange, issuer, swap service, casino, host): not LE, not counsel
    or an adviser, not a complaint / PI-firm record."""
    return (authority is not None and getattr(authority, "entity", None) is not None and not authority.is_le
            and not authority.is_adviser and not authority.virtual)


# --------------------------------------------------------------------------- the provider's requests
@dataclass
class Request:
    """One live request of the provider (a block-status row): its key ("o12" / "c5"), how it is named, its page."""

    key: str
    no: str
    href: str
    sent: bool
    status: str
    row: Any = field(default=None, repr=False)
    order: Any = field(default=None, repr=False)
    letter: Any = field(default=None, repr=False)
    at: datetime | None = None
    about: list[str] = field(default_factory=list)  # the chain:address it concerns (identifiers, meta.about / freeze)
    body: str = field(default="", repr=False)
    prepared: int | None = None  # the prepared MailMessage waiting for Send
    mail_href: str | None = None  # its page
    keys: frozenset = frozenset()  # every key a follow-up may quote for it (its stop order's, its letters')
    asks_freeze: bool = False
    follow_up_of: str | None = None  # a draft follow-up tied to a sent stop order (its key): `_follow_up_drafts`
    busy: Any = field(default=None, repr=False)  # an e-mail of the draft that may be out (`busy_mail`), not prepared
    template: str | None = None  # stop_order, or the letter's template_key
    follows: str | None = None  # a draft follow-up letter: the key of the sent request it follows (`_follows`)
    stale: str | None = None  # a draft follow-up made before that request's latest reply: why ("drafted before …")
    late: str | None = None  # the same for a HELD draft (its e-mail prepared or under way): it stays the open request

    @property
    def held(self) -> bool:
        """Its e-mail is prepared or may be out: the draft is never changed or replaced underneath it."""
        return self.prepared is not None or self.busy is not None

    @property
    def held_href(self) -> str | None:
        mm = self.busy
        return self.mail_href or (f"/cases/{mm.case_id}/mail/messages/{mm.id}" if mm is not None else None)

    def cites(self, address: str) -> bool:
        """It concerns `address`: its identifiers / meta.about / freeze target, or its text names it."""
        a = addr_of(address)
        return bool(a) and (a in {addr_of(x) for x in self.about} or a in self.body)


@dataclass
class State:
    """Where one provider stands for the gate."""

    case_id: int
    authority: Any
    requests: list[Request] = field(default_factory=list)  # live (no flagged duplicate), newest first
    open: Request | None = None  # the open request (a draft, or a prepared e-mail)
    drafts: list[Request] = field(default_factory=list)  # every open draft (legacy cases may hold more than one)
    sent: Request | None = None  # the deciding sent request (the board's pick)
    sent_keys: frozenset = frozenset()
    answer: str | None = None  # the deciding sent request's block status (rules.*)
    freeze_asked: bool = False  # a sent request asked for a freeze (a stop order, an owner letter, a ghost order)
    money: bool = False  # funds traced at the provider (a freeze candidate)
    gated: str | None = None  # the playbook's LE-only gate for our requester (desk.playbook_gate_reason)
    le_href: str | None = None  # where the LE brief / cover letter about it starts (or the row's own LE route page)
    le_label: str = ""  # that step's button when it is the LE route's page ("Get a US case agent or court order")
    step: str = ""  # the board row's next step (its label), when the state came from target_for
    wait: str = ""  # its row has no button: "wait for the reply (reply due …)"
    candidate: bool = False
    target: Any = field(default=None, repr=False)  # the board's target (freeze_board.target_for), when read so

    stale: list[Request] = field(default_factory=list)  # draft follow-ups drafted before their latest reply (`_stale`)

    def citing(self, address: str) -> Request | None:
        """The live request citing `address` (a sent one first), or None. A stale draft follow-up is none."""
        hits = [r for r in self.requests if r.cites(address) and not r.stale]
        return next((r for r in hits if r.sent), hits[0] if hits else None)

    @property
    def le_only(self) -> str | None:
        """"LE only / court order" or "declined": the deciding sent request's answer, after which only LE acts."""
        if self.sent is not None and self.answer in LE_ANSWERS:
            return {"le_process_required": "LE only / court order", "declined_other": "declined"}[self.answer]
        return None

    @property
    def pointless(self) -> list[Request]:
        """The drafts no letter of ours can follow any more: every draft once the provider answered LE only / declined
        (rule (a)); a first-contact draft (a stop order, an information request) while its playbook gates our
        requester; a draft follow-up made before the latest reply to the request it follows (`stale`: a status
        request, an answer, a deposit follow-up that does not know that reply). The board flags them (a case admin
        discards them); never sent, never added to."""
        out = list(self.stale)
        if self.le_only:
            out += self.drafts
        elif self.gated:
            out += [d for d in self.drafts if d.template in GATED_TEMPLATES and not d.follow_up_of]
        return out


def _request(cid: int, r, prepared: dict, busy: dict) -> Request:
    from app.blocks import freeze_board as fb
    from app.blocks import status as bs
    from app.domain import correspondence as desk

    about: list[str] = []
    body: list[str] = []
    keys = {r.key}
    if r.order is not None:
        ids = r.order.identifiers or {}
        for x in ids.get("addresses") or []:
            a = x.get("address") if isinstance(x, dict) else x
            c = (x.get("chain") if isinstance(x, dict) else None) or ids.get("chain")
            if a:
                about.append(desk.freeze_key(c, str(a)))
        body.append(r.order.body_markdown or "")
    for c in [r.letter, *r.outbound]:
        if c is None:
            continue
        keys.add(f"c{c.id}")
        meta = c.meta or {}
        about += [str(x) for x in meta.get("about") or []]
        if meta.get("freeze"):
            about.append(str(meta["freeze"]))
        body.append(c.body_markdown or "")
    mm = (prepared.get(("o", r.order.id)) if r.order is not None else None) or (
        prepared.get(("c", r.letter.id)) if r.letter is not None else None)
    sent = r.status != bs.NOT_SENT
    held = None if sent or mm is not None else next(
        (busy[k] for k in ([("o", r.order.id)] if r.order is not None else [])
         + [("c", c.id) for c in [r.letter, *r.outbound] if c is not None] if k in busy), None)
    template = "stop_order" if r.order is not None else ((r.letter.meta or {}).get("template_key")
                                                         if r.letter is not None else None)
    return Request(key=r.key, no=fb.req_no(r), href=fb._item_url(cid, r), sent=sent,
                   status=r.status, row=r, order=r.order, letter=r.letter, at=r.requested_at,
                   about=list(dict.fromkeys(about)), body="\n".join(body).lower(),
                   prepared=mm.id if mm is not None else None, keys=frozenset(keys), asks_freeze=fb._asks_freeze(r),
                   mail_href=f"/cases/{cid}/mail/messages/{mm.id}" if mm is not None else None, busy=held,
                   template=template)


def state_from(cid: int, authority, rows: list, *, prepared: dict | None = None, gated: str | None = None,
               le_key: str | None = None, busy: dict | None = None) -> State | None:
    """The provider's state from the case's block rows (bs.case_blocks; those of other authorities are ignored), the
    prepared e-mails (freeze_board._prepared) and the e-mails that may be out (`busy_mail`). None for an authority that
    is no provider."""
    from app.blocks import freeze_board as fb
    from app.blocks import status as bs

    if not is_provider(authority):
        return None
    prepared, busy = prepared or {}, busy or {}
    reqs = [r for r in rows if r.authority.key == authority.key and r.kind not in ("onchain", "outlook")]
    ghost = fb._ghost_order(authority)
    dup = {id(r) for r in fb._duplicates(reqs, ghost)}
    live = [r for r in reqs if id(r) not in dup]
    requests = sorted((_request(cid, r, prepared, busy) for r in live),
                      key=lambda x: (x.at or datetime.min.replace(tzinfo=UTC), x.key), reverse=True)
    st = State(case_id=cid, authority=authority, requests=requests, gated=gated,
               candidate=authority.candidate is not None,
               money=authority.candidate is not None and float(authority.candidate.total_taint_usd or 0) > 0)
    # a draft follow-up tied to a sent stop order (a status request / an answer quoting it: build_letter attaches it to
    # that order, so it is no block row of its own) is an open request too
    drafts = [x for x in requests if not x.sent] + _follow_up_drafts(cid, live, prepared, busy)
    # a draft follow-up made before the latest reply to the request it follows is no open request: it is stale (the
    # board flags it, a case admin discards it), and the answer to that reply is drafted instead (rule (c))
    _stale(drafts, requests)
    st.stale = [x for x in drafts if x.stale]
    drafts = [x for x in drafts if not x.stale]
    # the open request: one whose e-mail is prepared (or may be out), else a stop-order draft (the freeze ask), else the
    # newest letter
    st.drafts = sorted(drafts, key=lambda x: (x.prepared is None, x.busy is None, x.order is None,
                                              -int(x.key[1:] or 0)))
    st.open = st.drafts[0] if st.drafts else None
    sent_rows = [r for r in live if r.status != bs.NOT_SENT]
    by_key = {x.key: x for x in requests}
    if sent_rows:
        st.sent = by_key.get(fb._pick(sent_rows).key)
        st.answer = st.sent.status if st.sent is not None else None
    keys: set[str] = set()
    for x in requests:
        if x.sent:
            keys |= x.keys
    if ghost is not None:
        keys.add(f"o{ghost.id}")
        if st.sent is None:
            st.sent = Request(key=f"o{ghost.id}", no=f"#{ghost.id}", href=f"/cases/{cid}/stop-orders/{ghost.id}",
                              sent=True, status=bs.AWAITING, order=ghost, asks_freeze=True,
                              at=fb._aware(ghost.sent_at), keys=frozenset({f"o{ghost.id}"}))
    st.sent_keys = frozenset(keys)
    st.freeze_asked = ghost is not None or any(x.sent and x.asks_freeze for x in requests)
    st.le_href, st.le_label = _le_href(cid, st, le_key)
    return st


def _follow_up_drafts(cid: int, rows: list, prepared: dict, busy: dict) -> list[Request]:
    """The draft letters tied to a sent stop order of these rows (not its own letter; not superseded, replaced or
    discarded): each one an open request, keyed c<id>."""
    from app.blocks import freeze_board as fb
    from app.blocks import status as bs
    from app.db.models import CorrespondenceDirection, CorrespondenceKind, CorrespondenceStatus

    out: list[Request] = []
    for r in rows:
        if r.order is None or r.status == bs.NOT_SENT:
            continue
        mine = [c for c in getattr(r.authority, "correspondence", None) or [] if c.stop_order_id == r.order.id]
        for c in sorted(mine, key=lambda x: x.id or 0):  # the counterparty's letters (loaded): no query per order
            meta = c.meta or {}
            if (c.direction != CorrespondenceDirection.OUT or c.status != CorrespondenceStatus.DRAFT
                    or c.kind == CorrespondenceKind.STOP_ORDER or c.id is None or meta.get("superseded_by")
                    or meta.get("superseded_by_letter") or fb.discarded(c)):
                continue
            mm = prepared.get(("c", c.id))
            about = [str(x) for x in meta.get("about") or []] + ([str(meta["freeze"])] if meta.get("freeze") else [])
            out.append(Request(key=f"c{c.id}", no=f"letter #{c.id}", href=f"/cases/{cid}/authorities/correspondence/"
                               f"{c.id}", sent=False, status=bs.NOT_SENT, letter=c, at=fb._aware(c.created_at),
                               about=list(dict.fromkeys(about)), body=(c.body_markdown or "").lower(),
                               prepared=mm.id if mm is not None else None, keys=frozenset({f"c{c.id}"}),
                               follow_up_of=r.key, busy=None if mm is not None else busy.get(("c", c.id)),
                               template=meta.get("template_key"),
                               mail_href=f"/cases/{cid}/mail/messages/{mm.id}" if mm is not None else None))
    return out


def _follows(letter, requests: list[Request]) -> Request | None:
    """The sent request a draft follow-up letter quotes (its `meta.references`: a status request, an answer to their
    questions, a release request, a deposit follow-up quoting a request), or None."""
    meta = getattr(letter, "meta", None) or {}
    ref = str(meta.get("references") or "")
    if not ref or not (meta.get("template_key") in FOLLOW_UPS or meta.get("template_key") == "info_request"):
        return None
    return next((x for x in requests if x.sent and ref in x.keys), None)


def _answers(row) -> list[tuple[Any, datetime | None]]:
    """(entry, at) of each answer a request got: its replies, and the states a person recorded on its stop order
    (acknowledged / frozen / declined / released: desk.record_stop_order_status)."""
    from app.blocks import freeze_board as fb
    from app.db.models import CorrespondenceDirection

    out = [(r.corr, r.at) for r in getattr(row, "replies", None) or []]
    order = getattr(row, "order", None)
    for c in (getattr(order, "correspondence", None) or []) if order is not None else []:
        meta = c.meta or {}
        if (c.direction == CorrespondenceDirection.NOTE and meta.get("source") == "stop_order_status"
                and meta.get("status") not in (None, "sent")):
            out.append((c, fb._aware(c.occurred_at or c.created_at)))
    return out


def _stale(drafts: list[Request], requests: list[Request]) -> None:
    """Mark each draft follow-up (one tied to a sent stop order, `follow_up_of`; a letter quoting a sent request,
    `_follows`) that was drafted before the latest answer to that request: `stale` = why. An answer logged after the
    draft counts (a higher entry id: what the person drafting it could not have seen, whatever date the reply bears —
    a mailbox sync may log a reply dated before the draft; entry times are too coarse to order the two). A HELD draft
    (its e-mail prepared and waiting for Send, or one that may be out: `Request.held`) is never stale: it stays the
    open request (settle or cancel that e-mail first), so no second follow-up goes out next to it; `late` says why it
    may no longer fit."""
    by_key = {x.key: x for x in requests}
    for d in drafts:
        if d.letter is None:
            continue
        of = by_key.get(d.follow_up_of) if d.follow_up_of else _follows(d.letter, requests)
        if of is None or of.row is None:
            continue
        d.follows = of.key
        later = [at for c, at in _answers(of.row)
                 if c is not d.letter and c.id is not None and d.letter.id is not None and c.id > d.letter.id]
        if later:
            last = max((a for a in later if a is not None), default=None)
            why = "drafted before their reply" + (f" of {last:%d %b %Y}" if last is not None else "")
            if d.held:
                d.late = why
            else:
                d.stale = why


def _le_href(cid: int, st: State, le_key: str | None) -> tuple[str | None, str]:
    """(where the provider's LE step starts, its button label: "" for the gate's own wording). After an LE-only /
    court-order / declined answer, the deciding request's row's own LE step when it has one — its LE brief / cover
    letter, or the LE route's own page (a case agent's complaint, the LE contact a court order goes through:
    /authorities/le-N) — so the board, the plan, the owners panel, the authority page and the gate's link lead to one
    LE; else the LE brief to the LE the plan's route picks (`le_key`)."""
    from app.blocks import freeze_board as fb

    s = st.sent
    if s is not None and s.row is not None and st.answer in LE_ANSWERS:
        na = s.row.next_action or {}
        href = na.get("href")  # the row's own LE step, else ours
        if href and not href.startswith(f"/cases/{cid}/authorities/{st.authority.key}?") and (
                re.search(r"/authorities/(?:le|entity)-\d+\?template=le_(?:brief|cover)\b", href)
                or re.fullmatch(rf"/cases/{cid}/authorities/le-\d{{1,12}}(?:[?#].*)?", href)):
            label = ""
            if "?template=" not in href:  # the route's page: named as the board names it (fb._le_label)
                try:
                    path = getattr(s.row, "path", None)
                    instrument = (getattr(path, "instrument", None) if path is not None else None) or (
                        (s.row.intel or {}).get("instrument") or None)
                    label = fb._le_label(getattr(path, "route", None) if path is not None else None, instrument,
                                         na.get("kind"), href)
                except Exception as err:  # noqa: BLE001 - the gate's own wording
                    log.warning("request gate: LE label failed (%s)", type(err).__name__)
            return href, label
        if le_key:
            return f"/cases/{cid}/authorities/{le_key}?template=le_brief&ref={s.key}#generate", ""
    if le_key:
        return f"/cases/{cid}/authorities/{le_key}?template=le_cover#generate", ""
    return None, ""


# the answers after which only LE acts (rules.LE_PROCESS_REQUIRED, rules.DECLINED). "No account / no assets"
# (rules.DECLINED_NO_ASSETS) is no refusal to act: its follow-ups (where the funds went, an internal transfer to
# another of its accounts) stay open, like any sent request's
LE_ANSWERS = frozenset({"le_process_required", "declined_other"})
NO_ASSETS = "declined_no_assets"  # rules.DECLINED_NO_ASSETS: no stop order after it (rule (c)'s records exception)


def busy_mail(db, case) -> dict[tuple[str, int], Any]:
    """("o", stop order id) / ("c", letter id) -> an outbound e-mail of that draft that may be (or have been)
    delivered: sending, sent, recorded as sent or of unknown outcome, an open "Draft — you send" checklist (manual
    transport, prepared or expired: it may have gone out from Outlook), or a failed one that left an unsent draft in the
    mailbox (the rule services.mail_pending applies before a draft is replaced). Such a draft is never changed
    underneath its e-mail (`Request.busy`). One query; a prepared e-mail waiting for Send is `prepared` (it counts
    the same)."""
    from sqlalchemy import select

    from app.db.models import MailDirection, MailMessage, MailStatus
    from app.domain import mail_compose

    rows = db.scalars(select(MailMessage).where(
        MailMessage.case_id == case.id, MailMessage.direction == MailDirection.OUT,
        MailMessage.status.in_((MailStatus.PREPARED, MailStatus.EXPIRED, MailStatus.FAILED,
                                *mail_compose.LETTER_BUSY))).order_by(MailMessage.id)).all()
    corr_order = {c.id: c.stop_order_id for c in case.correspondence}
    out: dict[tuple[str, int], Any] = {}
    for mm in rows:
        if not (mm.status in mail_compose.LETTER_BUSY or mail_compose.stale_draft_left(mm)
                or mail_compose.is_open_checklist(mm)):
            continue
        keys: list[tuple[str, int]] = []
        lk = str(mm.letter_key or "")
        if re.fullmatch(r"[oc]\d{1,12}", lk):
            keys.append((lk[0], int(lk[1:])))
        if mm.correspondence_id:
            keys.append(("c", mm.correspondence_id))
            if corr_order.get(mm.correspondence_id):
                keys.append(("o", corr_order[mm.correspondence_id]))
        for k in keys:
            out.setdefault(k, mm)
    return out


def _busy(db, case) -> dict:
    try:
        return busy_mail(db, case)
    except Exception as err:  # noqa: BLE001 - no mail tables: nothing is out
        log.warning("request gate: e-mails failed for case %s (%s)", case.id, type(err).__name__)
        return {}


def gated_reason(db, case, authority, requester: str | None = None) -> str | None:
    """The playbook's LE-only gate for this provider and our requester (desk.playbook_gate_reason with the orders on
    file that name it), or None."""
    from app.domain import correspondence as desk
    from app.domain import evidence_requirements as er
    from app.domain import sender as sender_mod

    try:
        req = requester or sender_mod.requester_kind(db, case)
        return desk.playbook_gate_reason(authority, req, er.held_instruments(case, er.provider_names(authority)))
    except Exception as err:  # noqa: BLE001 - an unreadable catalogue gates nothing (as the template options)
        log.warning("request gate: playbook gate failed for %s (%s)", getattr(authority, "key", "?"),
                    type(err).__name__)
        return None


def le_key_for(db, case, authority, les: list, *, requester: str | None = None, targets: list | None = None
               ) -> str | None:
    """The LE contact a provider's LE step names (its LE brief / cover letter: `State.le_href`): the one the plan's LE
    route picks for it (recovery._lead_le: the LE its playbook routes to, a reachable one first, else a reachable
    briefable LE, else the first briefable one), so the board, the plan's moves, the owners panel and the gate's own
    link name one LE; else the first LE contact of the case. `les`: the case's LE authorities; `targets`: their
    pathmod.le_targets when the caller has them."""
    from app.blocks import path as pathmod
    from app.blocks import recovery as rp
    from app.blocks import status as bs
    from app.domain import directory
    from app.domain import playbook as pbm
    from app.domain import sender as sender_mod

    if not les:
        return None
    try:
        targets = targets if targets is not None else pathmod.le_targets(les, directory.playbook_for)
        req = requester or sender_mod.requester_kind(db, case)
        pb, okey = bs._playbook(authority)
        href, _hint = rp._lead_le(case.id, pb, okey, targets, req, pbm.jurisdiction_code(case.victim_jurisdiction))
        m = re.search(r"/authorities/(le-\d{1,12})\?", href or "")
        if m is not None:
            return m.group(1)
    except Exception as err:  # noqa: BLE001 - no route: the case's first LE contact
        log.warning("request gate: LE route failed for %s (%s)", getattr(authority, "key", "?"), type(err).__name__)
    return les[0].key


def state(db, case, authority, *, now: datetime | None = None) -> State | None:
    """The provider's state from its own block rows and the case's LE contacts (freeze_board.target_for: the board's
    own sources, one counterparty's cost). None for an authority that is no provider. Raises Unavailable when the rows
    cannot be read (nothing is drafted blind)."""
    if not is_provider(authority):
        return None
    from app.blocks import freeze_board as fb

    try:
        t = fb.target_for(db, case, None, authority, now=now)
    except Exception as err:  # noqa: BLE001 - a broken source never drafts blind
        log.warning("request gate: %s unreadable on case %s (%s)", getattr(authority, "key", "?"), case.id,
                    type(err).__name__)
        raise Unavailable(fb.GATE_ERROR) from None
    if t is None:
        return None
    board = t.board
    le_key = le_key_for(db, case, authority, list(board.le_auths.values())) if board is not None else None
    st = state_from(case.id, authority, t.rows, prepared=t.prepared, gated=gated_reason(db, case, authority),
                    le_key=le_key, busy=_busy(db, case))
    if st is not None:
        st.target = t
        try:  # the row's buttons through the gate (freeze_board.provider_target's second half): the step it names
            fb._gate_target(case.id, t, st)
        except Exception as err:  # noqa: BLE001 - the row as read (every creation still passes `decide`)
            log.warning("request gate: row gate failed for %s (%s)", authority.key, type(err).__name__)
        st.step = t.step.label or ""
        if not t.step.label and st.sent is not None:
            st.wait = "wait for the reply" + (f" ({t.deadline_label or 'due'} {t.deadline:%d %b %Y})"
                                              if t.deadline is not None else "")
    return st


# --------------------------------------------------------------------------- the decision
@dataclass
class Decision:
    kind: str
    text: str = ""
    request: Request | None = None  # the open / sent request it points to
    href: str | None = None  # where to go instead (the draft, the prepared e-mail, the follow-up, the LE brief)
    about: list[str] = field(default_factory=list)  # ADD_TO_DRAFT: the addresses the draft lacks
    template: str | None = None
    who: str = ""  # the provider's name
    le_label: str = ""  # LE_BRIEF_ONLY to the LE route's own page (State.le_label): its button, as the board names it

    @property
    def allowed(self) -> bool:
        return self.kind == ALLOW

    @property
    def key(self) -> str | None:
        return self.request.key if self.request is not None else None

    @property
    def no(self) -> str | None:
        return self.request.no if self.request is not None else None

    def label(self, what: str = "") -> str:
        """The button a page shows for it."""
        r = self.request
        if self.kind == OPEN_EXISTING and r is not None:
            if r.late and r.held:  # drafted before their reply: its e-mail leads, saying it may no longer fit
                return f"Open e-mail #{r.prepared or r.busy.id} (draft {r.no}, drafted before their reply)"
            if r.prepared is not None:
                return "Open & send e-mail"
            if r.busy is not None:
                return f"Open e-mail #{r.busy.id} (draft {r.no})"
            return f"Open & send draft {r.no}" if r.follow_up_of else "Open & send draft"
        if self.kind == ADD_TO_DRAFT and r is not None:
            return f"Add {', '.join(short(a) for a in self.about[:2])} to draft {r.no}"
        if self.kind == LE_BRIEF_ONLY:
            if self.le_label:
                return self.le_label
            return "Open the LE brief" if "template=le_brief" in (self.href or "") else (
                "Open the LE cover letter" if "template=le_cover" in (self.href or "") else "Brief LE")
        if self.kind == FOLLOW_UP_ONLY and r is not None:
            if self.about and self.who:
                return f"Ask {self.who} about {', '.join(short(a) for a in self.about[:2])} on request {r.no}"
            return f"Draft a follow-up to request {r.no}" + (f" ({what})" if what else "")
        return what or "Open"


def _with_about(href: str | None, about: list[str]) -> str | None:
    """An LE brief / cover-letter link naming the address too (`about=`)."""
    if not href or not about or "?template=" not in href or "about=" in href:
        return href
    base, _, frag = href.partition("#")
    return f"{base}&about={quote(','.join(about), safe=':,')}" + (f"#{frag}" if frag else "")


def follow_up_href(st: State, about: list[str] | None = None) -> str | None:
    """The follow-up a FOLLOW_UP_ONLY decision offers: a new address → the information request citing it with
    ref=<the request>; else the status request on that request."""
    s = st.sent
    if s is None:
        return None
    base = f"/cases/{st.case_id}/authorities/{st.authority.key}"
    if about:
        q = urlencode({"template": "info_request", "freeze": about[0], "ref": s.key}, safe=":")
        return f"{base}?{q}#generate"
    return f"{base}?template=status_request&ref={s.key}#generate"


def decide(st: State | None, template: str, *, about=None, ref: str | None = None,
           replace: set[str] | frozenset | None = None) -> Decision:
    """What may be created for this provider (module doc). `about`: the chain:address list the new letter concerns;
    `ref`: the request a follow-up quotes; `replace`: draft keys the creation is confirmed to supersede."""
    if st is None or template in LE_TEMPLATES:
        return Decision(ALLOW, template=template)
    d = _decide(st, template, about=about, ref=ref, replace=replace)
    d.who = st.authority.name
    return d


def _pointless_text(st: State) -> str:
    drafts = st.pointless
    if not drafts:
        return ""
    many = len(drafts) > 1
    return (f" Draft{'s' if many else ''} {', '.join(d.no for d in drafts[:3])} to {st.authority.name} "
            f"{'are' if many else 'is'} pointless now: do not send {'them' if many else 'it'} (nothing is added to "
            f"{'them' if many else 'it'}); a case admin discards {'them' if many else 'it'} on the Authorities tab.")


def _decide(st: State, template: str, *, about, ref, replace) -> Decision:
    about = norm_about(about)
    name = st.authority.name
    s = st.sent
    # (a) LE only / court order / declined, the playbook's LE-only gate: before any open draft (it is pointless)
    if st.le_only or (st.gated and template in GATED_TEMPLATES):
        named = f"{name}" + (f" and {', '.join(short(a) for a in about)}" if about else "")
        # the row's LE route (a case agent, a court order: its own page) or the LE brief / cover letter
        what = "LE's request" if st.le_label else f"the LE {'brief' if st.le_only else 'letter'}"
        how = f"brief LE instead ({what} names {named})"
        lead = f"Answered {st.le_only} (request {s.no})" if st.le_only else st.gated
        return Decision(LE_BRIEF_ONLY, request=s, href=_with_about(st.le_href, about), template=template,
                        le_label=st.le_label,
                        text=(f"{lead}: {how}; no {'further letter' if st.le_only else 'letter from us'} to {name}."
                              + _pointless_text(st)))
    # (b) the open draft
    replace = set(replace or ())
    # a confirmed replacement never takes a draft whose e-mail is prepared or may be out: that e-mail could still be
    # sent (a stale "replaces draft #N" form, a forged field), so the draft stays the open request
    replace -= {d.key for d in st.drafts if d.held or d.follow_up_of}  # a follow-up: send it
    drafts = [d for d in st.drafts if d.key not in replace]
    if drafts:
        d = drafts[0]
        missing = [a for a in about if not any(x.cites(a) for x in st.requests if x.key not in replace and not x.stale)]
        later = (f" {', '.join(short(a) for a in missing)} goes in a follow-up once it is out." if missing else "")
        late = (f" It was {d.late}: if it no longer fits, cancel e-mail #{d.prepared or getattr(d.busy, 'id', '')} "
                "and discard the draft first." if d.late else "")
        if d.prepared is not None:
            return Decision(OPEN_EXISTING, request=d, href=d.mail_href or d.href, template=template,
                            text=(f"Prepared e-mail #{d.prepared} for draft {d.no} to {name} waits for Send: send it "
                                  f"(a case admin presses Send). One open request per provider: no second letter or "
                                  f"stop order to {name} while it is open.{later}{late}"))
        if d.busy is not None:
            mm = d.busy
            status = str(getattr(mm.status, "value", mm.status))
            what = (f"its “Draft — you send” checklist (e-mail #{mm.id}) may have gone out from Outlook"
                    if mm.transport == "manual" and status in ("prepared", "expired") else
                    f"its e-mail #{mm.id} is {status}: it may already be out")
            return Decision(OPEN_EXISTING, request=d, href=d.held_href or d.href, template=template,
                            text=(f"Draft {d.no} to {name}: {what}. It is never changed underneath its e-mail: open "
                                  "the e-mail and settle it (record it as sent, or cancel / retire it). One open "
                                  f"request per provider: no second letter or stop order to {name} while it is "
                                  f"open.{later}{late}"))
        if missing:
            return Decision(ADD_TO_DRAFT, request=d, href=d.href, about=missing, template=template,
                            text=(f"Draft {d.no} to {name} is not sent yet: "
                                  f"{', '.join(short(a) for a in missing)} is added to it (its identifiers and a "
                                  "sentence in the letter), then send it. One open request per provider: never a "
                                  "second letter."))
        what = f" (it already cites {', '.join(short(a) for a in about)})" if about else ""
        return Decision(OPEN_EXISTING, request=d, href=d.href, template=template,
                        text=(f"Draft {d.no} to {name} is not sent yet{what}: open it and send it. One open request "
                              f"per provider: no second letter or stop order to {name} while it is open."))
    # (c) a request sent
    if s is not None:
        if template in FOLLOW_UPS:
            return Decision(ALLOW, request=s, template=template)
        cited = [a for a in about if st.citing(a) is not None]
        new = [a for a in about if a not in cited]
        if template == "info_request" and new and ref and ref in st.sent_keys:
            return Decision(ALLOW, request=s, template=template, about=new)
        # the freeze ask a records-only request lacked — unless the provider answered it holds no account / assets
        nope = next((x for x in st.requests if x.sent and x.status == NO_ASSETS), None)
        if template == "stop_order" and st.money and not st.freeze_asked and not about and nope is None:
            return Decision(ALLOW, request=s, template=template)
        when = f" {s.at:%d %b %Y}" if s.at is not None else ""
        if template == "stop_order" and st.money and not st.freeze_asked and not about:
            return Decision(FOLLOW_UP_ONLY, request=nope, href=follow_up_href(st), template=template,
                            text=(f"{name} answered request {nope.no} that it holds no account / no assets for the "
                                  f"addresses it was asked about: a stop order to {name} is pointless now. Follow "
                                  "that answer up instead (a status request on it, or a follow-up citing a new "
                                  "address quoting it), never a second request."))
        if about and not new:
            c = st.citing(about[0]) or s
            return Decision(FOLLOW_UP_ONLY, request=c, href=f"/cases/{st.case_id}/authorities/{st.authority.key}"
                            f"?template=status_request&ref={c.key}#generate", template=template,
                            text=(f"Request {c.no} to {name} already asks about "
                                  f"{', '.join(short(a) for a in about)}: follow it up (a status request on it), "
                                  "never a second letter for the same address."))
        tail = (f"a follow-up citing {', '.join(short(a) for a in new)} quoting request {s.no}" if new else
                f"a status request on request {s.no}")
        return Decision(FOLLOW_UP_ONLY, request=s, href=follow_up_href(st, new), about=new, template=template,
                        text=(f"Request {s.no} to {name} was sent{when}: only a follow-up tied to it ({tail}, an answer "
                              "to their questions), never a second request."))
    return Decision(ALLOW, template=template, about=about)


def freeze_over_records(st: State | None) -> dict | None:
    """The freeze ask a records-only draft would otherwise stand in front of: the provider holds funds of the case, no
    request of ours asked it to freeze, and the open draft is a letter asking for records only (a swap order's records,
    a preservation request). The step is the stop order replacing that draft (freeze_board.replace_offer: its
    addresses carried into the stop order, their records asked for too): {key, no, label, href, text}; else None."""
    from app.blocks import freeze_board as fb

    d = st.open if st is not None else None
    if (d is None or d.held or d.order is not None or d.letter is None or d.asks_freeze or d.follow_up_of
            or d.follows or not st.money or st.freeze_asked or st.le_only or st.gated):
        return None
    offer = fb.replace_offer(st)
    if offer is None or offer["key"] != d.key:
        return None
    name = st.authority.name
    return {"key": d.key, "no": d.no, "label": f"Draft freeze request (replaces draft {d.no})",
            "href": f"/cases/{st.case_id}/authorities/{st.authority.key}?template=stop_order#generate",
            "text": (f"Draft {d.no} to {name} asks for records only, no freeze, and {name} holds funds of the case: a "
                     f"stop order replaces it (the addresses it cites are carried into the stop order, their records "
                     f"asked for too), so the freeze ask goes first. Or send draft {d.no} as it is.")}


def with_step(d: Decision, st: State | None) -> Decision:
    """The decision's text naming the board row's own next step (a person's message: the page's 409, the assistant)."""
    if st is None or d.allowed or "next step on its row" in d.text:
        return d
    if st.step:
        d.text = f"{d.text.rstrip('.')}; next step on its row: “{st.step}”."
    elif st.wait and d.kind == FOLLOW_UP_ONLY:
        d.text = f"{d.text.rstrip('.')}; {st.wait}."
    return d


def gate(db, case, authority, template: str, *, about=None, ref: str | None = None, replace=None,
         now: datetime | None = None) -> Decision:
    """`decide` over the provider's state read now (`state`). Unreadable: UNAVAILABLE (nothing is drafted blind)."""
    if not is_provider(authority) or template in LE_TEMPLATES:
        return Decision(ALLOW, template=template)
    try:
        st = state(db, case, authority, now=now)
    except Unavailable as err:
        return Decision(UNAVAILABLE, text=str(err), template=template)
    return with_step(decide(st, template, about=about, ref=ref, replace=replace), st)


# --------------------------------------------------------------------------- add to the open draft
def about_sentence(authority, about: list[str], *, added: bool = False) -> str:
    """The sentence a letter gets for the addresses it concerns beyond its own identifiers."""
    parts = []
    for k in about:
        chain, _, a = k.rpartition(":")
        parts.append(f"{a} ({chain})" if chain else a)
    what = ", ".join(parts)
    if getattr(authority, "is_le", False) or getattr(authority, "is_adviser", False):
        return f"This letter also concerns {what}, identified in this case as an address of the provider concerned."
    lead = "Further address identified since this request was drafted" if added else "This letter also concerns"
    return (f"{lead}: {what}, an address of {authority.name} that received funds of this case. Please include it in "
            "this request: identify the account it belongs to or credits, freeze it and preserve its records.")


def add_to_draft(db, case, authority, d: Decision, *, actor=None, now: datetime | None = None):
    """An ADD_TO_DRAFT decision applied: the open draft cites the new addresses — a stop order's identifiers, a sentence
    before the signature of the stop order and of its letter (or of the draft letter), `meta.about` and
    `meta.added` ({about, at, by}). Returns the draft letter (Correspondence) when there is one, else the StopOrder.
    The caller audits. Raises ValueError when the decision is no ADD_TO_DRAFT or the draft changed meanwhile."""
    from app import services
    from app.db.models import CorrespondenceStatus, StopOrderStatus
    from app.domain import correspondence as desk

    if d.kind != ADD_TO_DRAFT or d.request is None or not d.about:
        raise ValueError("nothing to add")
    now = now or _now()
    r = d.request
    # never under an e-mail that waits for Send or may be out (the decision was read before it was prepared)
    busy = services.mail_pending(db, [r.order] if r.order is not None else [],
                                 [c for c in [r.letter] if c is not None])
    if busy is not None:
        raise ValueError(services.mail_pending_text(busy).replace("it is not replaced", "nothing is added to it"))
    sentence = about_sentence(authority, d.about, added=True)
    stamp = {"about": list(d.about), "at": now.isoformat(timespec="seconds"), "by": getattr(actor, "id", None)}
    order = r.order
    letters = [c for c in ([r.letter] if r.letter is not None else []) if c.status == CorrespondenceStatus.DRAFT]
    if order is not None:
        if order.status != StopOrderStatus.DRAFT:
            raise ValueError(f"draft {r.no} is no longer a draft")
        letters = [c for c in order.correspondence if c.status == CorrespondenceStatus.DRAFT] or letters
        ids = dict(order.identifiers or {})
        addrs = list(ids.get("addresses") or [])
        for k in d.about:
            chain, _, a = k.rpartition(":")
            addrs.append({"chain": chain or ids.get("chain"), "address": a, "address_type": "deposit",
                          "label": "further address identified (wallet owner identification)"})
        ids["addresses"] = addrs
        ids["added"] = list(ids.get("added") or []) + [stamp]
        order.identifiers = ids
        order.body_markdown = desk.insert_before_signature(order.body_markdown or "", sentence)
    elif not letters:
        raise ValueError(f"draft {r.no} is no longer a draft")
    for c in letters:
        c.body_markdown = desk.insert_before_signature(c.body_markdown or "", sentence)
        meta = dict(c.meta or {})
        meta["about"] = list(dict.fromkeys([*(meta.get("about") or []), *d.about]))
        meta["added"] = list(meta.get("added") or []) + [stamp]
        if not getattr(authority, "is_le", False) and not getattr(authority, "is_adviser", False):
            meta["asks_freeze"] = True  # the sentence asks to freeze the account behind it (freeze_board._asks_freeze)
        c.meta = meta
    db.commit()
    return letters[0] if letters else order


# --------------------------------------------------------------------------- links (the Recovery plan, the panel)
_LINK = re.compile(r"^/cases/(\d{1,12})/authorities/((?:entity)-\d{1,12})\?")


def parse_link(href: str | None) -> dict | None:
    """A provider letter link (/cases/{id}/authorities/entity-N?template=…): {key, template, about, ref}; else None."""
    m = _LINK.match(href or "")
    if m is None:
        return None
    q = parse_qs(urlparse(href).query)
    template = (q.get("template") or [""])[0]
    if not template:
        return None
    about = norm_about([*(q.get("freeze") or []), *",".join(q.get("about") or []).split(",")])
    return {"key": m.group(2), "template": template, "about": about, "ref": (q.get("ref") or [None])[0]}


def gated_link(st: State | None, href: str | None) -> tuple[Decision | None, dict | None]:
    """The decision for a provider letter link, and the link it stands for instead (None: the link as it is):
    {label, href, kind, text}. OPEN_EXISTING → the draft (or its prepared e-mail); ADD_TO_DRAFT → the same page (its
    form adds the address to the draft); FOLLOW_UP_ONLY → the follow-up (or the wait on the request citing it);
    LE_BRIEF_ONLY → the LE brief."""
    p = parse_link(href)
    if p is None or st is None or p["key"] != st.authority.key:
        return None, None
    d = decide(st, p["template"], about=p["about"], ref=p["ref"])
    if d.allowed:
        return d, None
    if d.kind == ADD_TO_DRAFT:
        return d, {"label": d.label(), "href": href, "kind": "add", "text": d.text}
    if d.kind == OPEN_EXISTING:
        return d, {"label": d.label(), "href": d.href, "kind": "send", "text": d.text}
    if d.kind == LE_BRIEF_ONLY:
        return d, {"label": d.label(), "href": d.href, "kind": "le", "text": d.text}
    cited = bool(p["about"]) and not d.about
    if cited:  # a request already asks about it: wait on it (its own next step chases it), or follow it up
        return d, {"label": f"Open request {d.no}", "href": d.request.href, "kind": "wait", "text": d.text,
                   "follow": d.href}
    # the follow-up: an information request about the new address quoting the request (the link's own wording), else
    # the status request on it
    follow = _with_ref(href, d.request.key) if p["template"] == "info_request" and d.about else d.href
    return d, {"label": d.label(), "href": follow, "kind": "follow_up", "text": d.text}


def _with_ref(href: str, ref: str) -> str:
    base, _, frag = href.partition("#")
    path, _, query = base.partition("?")
    q = [(k, v) for k, v in parse_qs(query, keep_blank_values=True).items() if k != "ref"]
    pairs = [(k, x) for k, vs in q for x in vs] + [("ref", ref)]
    return f"{path}?{urlencode(pairs, safe=':,')}" + (f"#{frag}" if frag else "")


class States:
    """Per-provider states over one set of block rows (the Recovery plan, the board): read lazily, once each."""

    def __init__(self, cid: int, rows: list, prepared: dict, *, gated=None, le_key=None, busy: dict | None = None):
        # le_key: the LE key every provider's LE step names, or authority -> that key (`le_key_for`)
        self.cid, self.rows, self.prepared, self.le_key, self.busy = cid, rows, prepared, le_key, busy or {}
        self._gated = gated
        self._cache: dict[str, State | None] = {}

    def get(self, authority) -> State | None:
        if authority is None:
            return None
        if authority.key not in self._cache:
            gated = None
            if self._gated is not None and is_provider(authority):
                try:
                    gated = self._gated(authority)
                except Exception as err:  # noqa: BLE001
                    log.warning("request gate: gate failed for %s (%s)", authority.key, type(err).__name__)
            try:
                le_key = self.le_key(authority) if callable(self.le_key) else self.le_key
                self._cache[authority.key] = state_from(self.cid, authority, self.rows, prepared=self.prepared,
                                                        gated=gated, le_key=le_key, busy=self.busy)
            except Exception as err:  # noqa: BLE001 - no state: the link as it is (the POST still gates)
                log.warning("request gate: state failed for %s (%s)", authority.key, type(err).__name__)
                self._cache[authority.key] = None
        return self._cache[authority.key]


def states_for(db, case, rows: list, auths: list, *, requester: str | None = None) -> States:
    """`States` over the case's block rows, with the prepared e-mails (one query) and the playbook gate."""
    from app.blocks import freeze_board as fb

    try:
        from app.domain.mail_send import awaiting_send

        prepared = fb._prepared(case, awaiting_send(db, case.id))
    except Exception as err:  # noqa: BLE001 - no mail setup: no prepared state
        log.warning("request gate: prepared e-mails failed for case %s (%s)", case.id, type(err).__name__)
        prepared = {}
    les = [a for a in auths if a.is_le]
    targets: list = []
    try:
        from app.blocks import path as pathmod
        from app.domain import directory

        targets = pathmod.le_targets(les, directory.playbook_for) if les else []
    except Exception as err:  # noqa: BLE001 - le_key_for reads them itself
        log.warning("request gate: LE contacts failed for case %s (%s)", case.id, type(err).__name__)
        targets = None

    def le_key(a) -> str | None:  # the LE the plan's LE route picks for that provider (one LE on every surface)
        return le_key_for(db, case, a, les, requester=requester, targets=targets)
    return States(case.id, rows, prepared, gated=lambda a: gated_reason(db, case, a, requester), le_key=le_key,
                  busy=_busy(db, case))
