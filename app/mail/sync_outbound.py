"""Sent Items: letters sent from the case mailbox outside Aegis (Outlook), found by the mailbox sync.

    outcome = process_item(ctx, item, report)   # app.mail.ingest._sync_folder, folder "sentitems"

Every Sent Items message the sync reads goes through these steps (each message in its own try: a
failure counts in `report.sent["errors"]` and the folder's delta link is not advanced):

1. **Already known** (idempotent): its provider id, or its internetMessageId in this folder, is stored
   (`duplicates`); or it is an e-mail Aegis sent itself (an outbound row with that Message-ID: the
   graph transport's own send, or a "Record as sent" with the sent copy uploaded) → `known`, only the
   Graph conversationId is filled in.
2. **Related?** (data minimisation, app.mail.matching.assess; docs/data-handling.md §6.4): a tracking
   tag, a thread with a stored message, a recipient that is a known authority address or domain of an
   open case, or a cited case reference / traced wallet / tx hash. Anything else is counted
   (`not_related`) and never stored or downloaded beyond the in-memory check. A message tied to a case
   **only by a recipient** (no tag, no thread, nothing cited: `STORE_TRIAGE`) is stored in full only when
   step 3 finds a letter at `THRESHOLD` or above for it; otherwise only its metadata is kept (subject,
   recipient domains, date: `metadata_only`), so another client's matter or a personal e-mail to an
   authority's address never reaches the case.
3. **Which letter?** The candidates are the case's draft and sent outbound letters (and draft stop orders
   without a letter row) of the matched authorities (all of the case's when only a citation matched).
   The tracking tag names the letter outright; otherwise each candidate scores on the subject's
   similarity to the letter heading or the guidance subject (`SUBJECT_STRONG` 3 points, `SUBJECT_WEAK`
   1), the stop order's identifiers / wallets found in the body (2), and the recipients (the letter's
   To among the message's To: 2; only the domain: 1). One candidate at `THRESHOLD` or above is the
   letter; several, or none, is ambiguous, unless exactly one of several is left once letters already
   recorded as sent more than a day (`SENT_TIME_SLACK`) before the message went out are set aside.
   Never a candidate (`eligible_letters`): a letter another e-mail already carries (an outbound mail row
   with another internetMessageId: Aegis's own send, or another Sent Items message recorded or linked),
   or one recorded as sent more than `SENT_TIME_SLACK` after this message went out. The letter found must
   be addressed to its authority (`addressed_to_authority`): at least one To recipient is the letter's
   own To, or an address / own (non-shared) domain of that letter's authority (`CaseMaterial.authorities`);
   otherwise it is logged for review ("no recipient is the letter's authority"; metadata only when only a
   recipient tied it to the case), so a subject and a cited wallet alone never record a letter sent to
   someone else. A reply or forward (Re: / Fw: subject, or a thread with a message received before this
   one was sent) is never taken for the letter itself. The sync reads Sent Items before the Inbox, and Sent Items
   oldest first (app.mail.ingest), so a backfill records a letter at its first send before it reads the forwards of
   it and the replies to them. The authorities searched are those of the To recipients (`Relevance.to_candidates`;
   a Cc'd partner firm or another authority in Cc never widens the search or blurs the authority), else of any
   recipient, else the thread's; any address on an authority's own organisation domain counts as that authority
   (app.mail.matching.org_domains).
   **A forward of our letter** ("FW: <its subject>", `matching.is_forward_subject`) to the authority: in the thread
   of the recorded original it is a resend (step 5); without the original on record (`forwarded_letter`) it is that
   letter sent — a draft is recorded as sent (step 4), a letter already sent gets it as a resend (step 5).
4. **Unique letter, still a draft** → recorded as sent: the raw .eml filed as R3 evidence (sha256), an
   outbound mail row (`sent_external`, `folder` sentitems, `outside_sent`, `letter_key`: one e-mail per
   letter), the letter marked sent through the desk (`occurred_at` = sentDateTime, reply clock), the stop
   order `sent` with `sent_via` "email (investigations mailbox)" and `response_due_at`, the letter's
   other prepared previews cancelled, `correspondence_out` / `stop_order_status` emitted (`recorded`).
   **Unique letter, already sent** (marked sent by hand, or recorded without the sent copy) → the row is
   linked to it and the .eml filed; nothing about the letter changes (`linked`).
5. **A reply or forward in the thread of a request** (it threads onto a stored message tied to a stop order
   or to a sent letter) → an outbound follow-up of that request: logged on the authority with the stop
   order (`stop_order_id`) and the thread (`thread_key`) of the message it answers, `meta.follow_up_of`
   naming the request, no review flag (`logged`). Block status counts it as the request's outbound message,
   and the authority's answer to it lands on the same request.
6. **Ambiguous, no letter, or a reply outside a request** → an outbound correspondence entry logged from the
   mailbox on the authority (channel e-mail, no reply clock; `meta.source` "mailbox_sent") with
   `meta.needs_review`, why and the candidate letters, plus the row and the .eml (`logged`). It answers for no
   letter (app.mail.matching.DbLookup skips it, so a reply to it waits for review) and Block status lists it as
   "Sent from Outlook — needs review", never as a request. Without a single open case, or tied to the case
   only by a recipient with no letter matching, only metadata is kept: subject, recipient domains, date,
   `meta.needs_review` (`metadata_only`); without a single authority of the case the row and the .eml are kept
   on the case without a timeline entry. Both show on /admin/mail/mailbox.
7. **Review** (a person, `tie_to_letter` / `dismiss`: /admin/mail/mailbox for system admins, the Block status
   page's "Dismiss / tie to letter" for investigators+, as Mark sent): tied to a draft, the letter is recorded
   as sent at the e-mail's date with the .eml already filed as its evidence (as step 4); tied to a sent letter,
   it is linked; dismissed, it stays on the timeline and leaves the review lists. Either way `meta.needs_review`
   is cleared on the row and its timeline entry (`tied_to` / `dismissed`), and Block status no longer lists it.
   A metadata-only row can only be dismissed.

Never from the Inbox: only this module marks anything sent, and only for a Sent Items message.
Audit `MAIL_SENT_FOUND`: ids, the outcome (recorded / linked / logged / metadata_only / tied / tied_linked /
dismissed) and the method only.
"""

from __future__ import annotations

import hashlib
import io
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from difflib import SequenceMatcher

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError

from app.core.audit import audit
from app.mail import inbound, matching

log = logging.getLogger("app.mail")

MAILBOX_SENT_VIA = "email (investigations mailbox)"
MAILBOX_SOURCE = "mailbox_sent"  # correspondence.meta.source of an entry logged from Sent Items (step 5)
SUBJECT_STRONG = 0.85
SUBJECT_WEAK = 0.6
THRESHOLD = 3
TAGGED = 100
SENT_TIME_SLACK = timedelta(days=1)
OUTCOMES = ("duplicates", "known", "skipped_old", "not_related", "recorded", "linked", "logged", "metadata_only")


def _M():
    from app.db import models as M

    return M


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _aware(v: datetime | None) -> datetime | None:
    return v if v is None or v.tzinfo else v.replace(tzinfo=UTC)


# --------------------------------------------------------------------------- letters
@dataclass
class Letter:
    """A candidate letter: a draft or sent outbound correspondence row, or a draft stop order without one."""

    authority_key: str
    corr: object | None = None
    order: object | None = None
    subjects: list[str] = field(default_factory=list)
    to: set[str] = field(default_factory=set)
    tokens: set[str] = field(default_factory=set)
    score: int = 0

    @property
    def id(self) -> str:
        return f"c{self.corr.id}" if self.corr is not None else f"o{self.order.id}"

    @property
    def is_draft(self) -> bool:
        M = _M()
        if self.corr is not None:
            return self.corr.status == M.CorrespondenceStatus.DRAFT
        return self.order.status == M.StopOrderStatus.DRAFT


def _guidance_subject(case, authority, corr, order) -> str | None:
    """The subject the e-mail desk suggests for this letter (app.domain.mail_guidance), as sent (ASCII)."""
    from app.domain import mail_guidance as g

    kind = corr.kind.value if corr is not None else "stop_order"
    try:
        asset, amount = g._order_asset_amount(order)
        facts = g.SubjectFacts(service=authority.name, asset=asset, amount=amount,
                               letter_subject=corr.subject if corr is not None else (order.subject if order else None))
        return g.subject_body(kind, case.reference, facts, adviser=bool(getattr(authority, "is_adviser", False)))
    except Exception:  # noqa: BLE001 - the heading still counts
        log.debug("mailbox sync: no guidance subject for a letter")
        return None


def case_letters(db, case, keys: set[str] | None, mat: matching.CaseMaterial | None):
    """(letters, authorities by key) of `case`, limited to the authorities `keys` when given."""
    from app.domain import correspondence as desk

    M = _M()
    letters: list[Letter] = []
    authorities = {a.key: a for a in desk.case_authorities(db, case, include_prospects=False)}
    for key, a in authorities.items():
        if keys and key not in keys:
            continue
        with_row = set()
        for c in a.correspondence:
            if c.direction != M.CorrespondenceDirection.OUT or (c.meta or {}).get("source") in ("mailbox", MAILBOX_SOURCE):
                continue
            if c.status not in (M.CorrespondenceStatus.DRAFT, M.CorrespondenceStatus.SENT) \
                    or c.kind == M.CorrespondenceKind.REPLY:
                continue
            order = c.stop_order if c.kind == M.CorrespondenceKind.STOP_ORDER else None
            if order is not None:
                with_row.add(order.id)
            letters.append(_letter(case, a, c, order, mat))
        for o in a.stop_orders:
            if o.id in with_row or o.status not in (M.StopOrderStatus.DRAFT, M.StopOrderStatus.SENT):
                continue
            if any(c.stop_order_id == o.id and c.kind == M.CorrespondenceKind.STOP_ORDER for c in case.correspondence):
                continue
            letters.append(_letter(case, a, None, o, mat))
    return letters, authorities


def _letter(case, authority, corr, order, mat) -> Letter:
    subjects = [s for s in (corr.subject if corr is not None else None, order.subject if order is not None else None,
                            _guidance_subject(case, authority, corr, order)) if s]
    to = {str(r).strip().lower() for r in (corr.recipients if corr is not None else []) or [] if r}
    if order is not None and order.recipient_email:
        to.add(order.recipient_email.strip().lower())
    tokens = set()
    if order is not None:
        tokens |= (mat.order_tokens.get(order.id) if mat is not None else None) or matching.identifier_tokens(
            order.identifiers)
    if corr is not None:
        tokens |= matching.chain_tokens(corr.body_markdown)
    return Letter(authority_key=authority.key, corr=corr, order=order, subjects=subjects, to=to, tokens=tokens)


def score_letter(letter: Letter, parsed: inbound.ParsedEmail) -> int:
    norm = matching.normalise_subject(parsed.subject)
    ratio = max((SequenceMatcher(None, norm, matching.normalise_subject(s)).ratio() for s in letter.subjects),
                default=0.0) if norm else 0.0
    points = 3 if ratio >= SUBJECT_STRONG else (1 if ratio >= SUBJECT_WEAK else 0)
    if letter.tokens and matching.chain_tokens(f"{parsed.subject}\n{parsed.text}") & letter.tokens:
        points += 2
    to = {a.lower() for a in parsed.to}
    if to & letter.to:
        points += 2
    elif matching.own_domains(matching.domains_of(to)) & matching.own_domains(matching.domains_of(letter.to)):
        points += 1
    return points


def recorded_sent_at(letter: Letter) -> datetime | None:
    """When an already-sent candidate was recorded as sent (None for a draft)."""
    if letter.is_draft:
        return None
    if letter.corr is not None:
        return _aware(letter.corr.occurred_at)
    return _aware(getattr(letter.order, "sent_at", None))


def addressed_to_authority(letter: Letter, parsed: inbound.ParsedEmail, mat: matching.CaseMaterial | None) -> bool:
    """At least one To recipient of the message is the letter's own To, or an address / own (non-shared) domain
    of the letter's authority (`CaseMaterial.authorities[letter.authority_key]`). Only then can the message be
    the letter: a subject and a wallet alone never make a message sent to someone else the letter."""
    to = {str(a).strip().lower() for a in parsed.to or [] if a}
    if to & letter.to:
        return True
    if mat is None or letter.authority_key not in mat.authorities:
        return False
    return any(letter.authority_key in mat.authorities_for(a) for a in to)


def _tied_elsewhere(db, letter: Letter, imid: str | None) -> bool:
    """The letter already went out as another e-mail: an outbound mail row (Aegis's own send, a recorded or
    linked Sent Items copy) with another internetMessageId carries it."""
    from app.domain.mail_compose import letter_key as key_of

    if letter.corr is not None:
        busy = _letter_busy(db, key_of(letter.corr), letter.corr.id)
    else:
        busy = _letter_busy(db, f"o{letter.order.id}", None)
    if busy is None:
        return False
    other = busy.internet_message_id or (busy.message_id if busy.folder == "sentitems" else None)
    return bool(other) and other != imid


def eligible_letters(db, letters: list[Letter], *, imid: str | None, sent_at: datetime | None) -> list[Letter]:
    """The candidates this Sent Items message may be: never a letter already tied to another e-mail
    (`_tied_elsewhere`), nor one recorded as sent after the message went out (more than SENT_TIME_SLACK after
    it: a send recorded by hand is dated when the person clicked, so a little later is still the same send)."""
    out = []
    for x in letters:
        if _tied_elsewhere(db, x, imid):
            continue
        rec = recorded_sent_at(x)
        if rec is not None and sent_at is not None and rec > sent_at + SENT_TIME_SLACK:
            continue
        out.append(x)
    return out


def pick_letter(letters: list[Letter], parsed: inbound.ParsedEmail, case,
                sent_at: datetime | None = None) -> tuple[Letter | None, list[Letter]]:
    """(the letter, the candidates at or above THRESHOLD). The tracking tag decides outright. Several candidates
    are narrowed by time: a letter already recorded as sent more than SENT_TIME_SLACK before this message went
    out is not that send (e.g. a new stop order to an authority that already had a similar letter); when exactly
    one candidate is left, it is the letter. A single candidate is kept either way (`_link` flags the time).
    The caller passes `eligible_letters` and checks `addressed_to_authority` on the result."""
    tag = matching.parse_tag(parsed.subject)
    if tag is not None and tag[0].lower() == case.reference.lower():
        hit = next((x for x in letters if x.corr is not None and x.corr.id == tag[1]), None)
        if hit is not None:
            hit.score = TAGGED
            return hit, [hit]
    for x in letters:
        x.score = score_letter(x, parsed)
    strong = sorted([x for x in letters if x.score >= THRESHOLD], key=lambda x: -x.score)
    if len(strong) > 1 and sent_at is not None:
        timely = [x for x in strong if (rec := recorded_sent_at(x)) is None or sent_at <= rec + SENT_TIME_SLACK]
        if len(timely) == 1:
            return timely[0], strong
    return (strong[0] if len(strong) == 1 else None), strong


# --------------------------------------------------------------------------- rows & evidence
def _file_eml(db, case, raw: bytes, *, sent_at: datetime, title: str, actor=None):
    from app.domain import evidence as ev

    ref = re.sub(r"[^A-Za-z0-9._-]+", "-", case.reference)[:40]
    item = ev.store_upload(db, case, io.BytesIO(raw), filename=f"{ref}_email-sent-mailbox-{hashlib.sha256(raw).hexdigest()[:12]}.eml",
                           folder="stop_orders_correspondence", title=title, source_type="eml", classification="R3",
                           tags=["aegis-mail", "sent-email"], actor=actor, doc_date=sent_at)
    if item.sha256 != hashlib.sha256(raw).hexdigest():
        raise ValueError("the filed .eml does not match the message bytes")
    item.meta = {**(item.meta or {}), "sent_from_mailbox": True}
    db.flush()
    return item


def _drop_vault_copy(item) -> None:
    """Remove the vault file of an evidence row that was rolled back."""
    from app.domain import evidence as ev

    if item is None or not getattr(item, "vault_path", None):
        return
    try:
        root = ev.vault_dir(create=False)
        p = (root / item.vault_path).resolve()
        if p.is_relative_to(root):
            p.unlink(missing_ok=True)
    except (OSError, ev.EvidenceError):
        pass


def _row(ctx, item, parsed, *, imid, sent_at, raw=None, case_id=None, corr_id=None, letter_key=None,
         authority_key=None, method=None, eml_id=None, meta=None, metadata_only=False):
    M = _M()
    conv = (item.meta or {}).get("conversation_id")
    return M.MailMessage(
        case_id=case_id, correspondence_id=corr_id, letter_key=letter_key, direction=M.MailDirection.OUT,
        status=M.MailStatus.SENT_EXTERNAL, transport=ctx.transport.name, mailbox=ctx.mailbox,
        message_id=(parsed.message_id or imid or "")[:255], internet_message_id=(imid or parsed.message_id or None),
        provider_message_id=item.provider_id, conversation_id=conv, graph_conversation_id=conv,
        in_reply_to=" ".join(parsed.in_reply_to)[:512] or None, references=" ".join(parsed.references) or None,
        subject=parsed.subject or None, from_addr=parsed.from_addr or ctx.mailbox, to_addrs=list(parsed.to),
        cc_addrs=list(parsed.cc), mime_sha256=hashlib.sha256(raw).hexdigest() if raw is not None else None,
        mime_size=len(raw) if raw is not None else None, eml_evidence_id=eml_id, attachments=[], sent_at=sent_at,
        folder="sentitems", outside_sent=True, authority_key=authority_key, match_method=(method or "")[:32] or None,
        match={"method": method, "case_id": case_id, "correspondence_id": corr_id},
        meta={"trigger": ctx.trigger, "sent_from_mailbox": True, **({"metadata_only": True} if metadata_only else {}),
              **(meta or {})})


def _letter_busy(db, letter_key: str | None, corr_id: int | None):
    """An outbound row that already carries this letter (sending, sent, unknown, recorded)."""
    from app.domain.mail_compose import LETTER_BUSY

    M = _M()
    conds = []
    if letter_key:
        conds.append(M.MailMessage.letter_key == letter_key)
    if corr_id:
        conds.append(M.MailMessage.correspondence_id == corr_id)
    if not conds:
        return None
    return db.scalars(select(M.MailMessage).where(or_(*conds), M.MailMessage.direction == M.MailDirection.OUT,
                                                  M.MailMessage.status.in_(LETTER_BUSY))
                      .order_by(M.MailMessage.id.desc()).limit(1)).first()


# --------------------------------------------------------------------------- the steps
def _known(ctx, imids: list[str]):
    M = _M()
    imids = [i for i in dict.fromkeys(imids) if i]
    if not imids:
        return None
    return ctx.db.scalars(select(M.MailMessage).where(
        M.MailMessage.direction == M.MailDirection.OUT, M.MailMessage.folder.is_(None),
        M.MailMessage.status.in_((M.MailStatus.SENT, M.MailStatus.SENT_EXTERNAL, M.MailStatus.UNKNOWN)),
        or_(M.MailMessage.message_id.in_(imids), M.MailMessage.internet_message_id.in_(imids)))
        .order_by(M.MailMessage.id.desc()).limit(1)).first()


def _mark_known(ctx, mm, item, report) -> str:
    conv = (item.meta or {}).get("conversation_id")
    if conv and not mm.graph_conversation_id:
        mm.graph_conversation_id = conv
        mm.conversation_id = mm.conversation_id or conv
        ctx.db.commit()
    report.bump_sent("known")
    return "known"


def process_item(ctx, item, report) -> str:
    """One Sent Items message (module doc). Returns the outcome (OUTCOMES)."""
    db, M = ctx.db, _M()
    meta = item.meta or {}
    imid = meta.get("internet_message_id")
    exists = db.scalar(select(M.MailMessage.id).where(M.MailMessage.mailbox == ctx.mailbox,
                                                      M.MailMessage.provider_message_id == item.provider_id))
    if exists is None and imid:
        exists = db.scalar(select(M.MailMessage.id).where(
            M.MailMessage.mailbox == ctx.mailbox, M.MailMessage.folder == "sentitems",
            M.MailMessage.internet_message_id == imid))
    if exists is not None:
        report.bump_sent("duplicates")
        return "duplicates"
    known = _known(ctx, [imid])
    if known is not None:
        return _mark_known(ctx, known, item, report)
    sent_at = _aware(meta.get("sent_at")) or _aware(item.received_at) or _now()
    if ctx.since is not None and sent_at < ctx.since:
        report.bump_sent("skipped_old")
        return "skipped_old"
    from app.mail.ingest import prescreen

    if ctx.minimise and prescreen(ctx, item) is not None:
        report.bump_sent("not_related")
        return "not_related"
    raw = item.load()
    parsed = inbound.parse(raw)
    known = _known(ctx, [parsed.message_id])
    if known is not None:
        return _mark_known(ctx, known, item, report)
    imid = imid or parsed.message_id
    if imid and db.scalar(select(M.MailMessage.id).where(M.MailMessage.mailbox == ctx.mailbox,
                                                         M.MailMessage.folder == "sentitems",
                                                         M.MailMessage.internet_message_id == imid)) is not None:
        report.bump_sent("duplicates")
        return "duplicates"
    index = ctx.index()
    rel = matching.assess(db, parsed, folder="sentitems", index=index, conversation_id=meta.get("conversation_id"),
                          mailbox=ctx.mailbox)
    if rel.store == matching.STORE_NONE:
        report.bump_sent("not_related")
        return "not_related"
    case = db.get(M.Case, rel.case_id) if rel.case_id is not None else None
    if case is None or case.status != "open":
        return _metadata_only(ctx, item, parsed, rel, imid=imid, sent_at=sent_at, report=report,
                              why="the open case could not be determined")
    mat = index.cases.get(case.id)
    if mat is None:
        mat = matching.case_material(db, case, mailbox=ctx.mailbox)
    # the authorities the message went to: its To recipients first (a Cc'd partner firm or colleague at another
    # authority of the case never widens the search), else any recipient, else the thread's authority
    keys = {k for c, k in rel.to_candidates if c == case.id} or {k for c, k in rel.candidates if c == case.id} \
        or ({rel.authority_key} if rel.authority_key else set())
    letters, authorities = case_letters(db, case, keys or None, mat)
    letters = eligible_letters(db, letters, imid=imid, sent_at=sent_at)
    reply_row = db.get(M.MailMessage, rel.thread_mail_id) if rel.thread_mail_id else None
    # a reply or forward: Re: / Fw: subject, or the thread holds a message received *before* this one was sent
    # (a reply that arrived later cannot be what this message answers)
    received_before = reply_row is not None and reply_row.direction == M.MailDirection.IN and (
        _aware(reply_row.received_at) is None or _aware(reply_row.received_at) <= sent_at)
    is_reply = matching.is_reply_subject(parsed.subject) or received_before
    in_reply = db.get(M.Correspondence, reply_row.correspondence_id) \
        if reply_row is not None and reply_row.correspondence_id else None
    if in_reply is not None and in_reply.case_id != case.id:
        in_reply = None
    request = request_of(db, in_reply) if is_reply and in_reply is not None else None
    forwarded = None
    if is_reply and request is None and matching.is_forward_subject(parsed.subject):
        # a forward of our letter ("FW: <its subject>") to the authority (e.g. to the address their auto-reply named)
        # whose original is not on record: it is that letter sent — a draft is recorded as sent now; a letter
        # already sent gets the forward as a resend (a follow-up of its request)
        forwarded = forwarded_letter(db, case, keys, mat, parsed, imid=imid, sent_at=sent_at)
        if forwarded is not None and forwarded.is_draft:
            return _record(ctx, case, authorities[forwarded.authority_key], forwarded, item, raw, parsed, imid=imid,
                           sent_at=sent_at, method=rel.method, report=report)
        if forwarded is not None:
            in_reply = letter_entry(forwarded)
            request = request_of(db, in_reply) if in_reply is not None else None
    letter, strong = (None, []) if is_reply else pick_letter(letters, parsed, case, sent_at)
    not_addressed = None
    if letter is not None and not addressed_to_authority(letter, parsed, mat):
        # the subject and the case material match, but no To recipient is the letter's authority: never the
        # letter (e.g. a copy forwarded to a colleague, or a draft sent to the wrong person)
        not_addressed, letter = letter, None
    if rel.store == matching.STORE_TRIAGE and letter is None and request is None \
            and (not strong or not_addressed is not None):
        # tied to the case only by a recipient, and no letter of the case matches: metadata only (module doc)
        return _metadata_only(ctx, item, parsed, rel, imid=imid, sent_at=sent_at, report=report,
                              why="sent to an authority's address, but cites no case material and matches no letter")
    if not_addressed is not None:
        why = "no recipient is the letter's authority"
        strong = [not_addressed, *[x for x in strong if x is not not_addressed]]
    elif letter is not None:
        if letter.is_draft:
            return _record(ctx, case, authorities[letter.authority_key], letter, item, raw, parsed, imid=imid,
                           sent_at=sent_at, method=rel.method, report=report)
        linked = _link(ctx, case, letter, item, raw, parsed, imid=imid, sent_at=sent_at, method=rel.method,
                       report=report)
        if linked is not None:
            return linked
        why = "the letter was already recorded as sent from another message"
    elif is_reply:
        why = "a reply or forward in an existing thread"
    elif strong:
        why = f"{len(strong)} letters match (" + ", ".join(x.id for x in strong[:5]) + ")"
    else:
        why = "no letter of the case matches"
    key = rel.authority_key or (next(iter(keys)) if len(keys) == 1 else None)
    if forwarded is not None:
        key = forwarded.authority_key
    if key is None and letter is not None:
        key = letter.authority_key
    if key is None and len({x.authority_key for x in strong}) == 1:
        key = strong[0].authority_key
    if request is not None and key is None:
        from app.mail.ingest import authority_key_for

        key = authority_key_for(in_reply)
    authority = authorities.get(key) if key else None
    return _log(ctx, case, authority, item, raw, parsed, imid=imid, sent_at=sent_at, method=rel.method, why=why,
                candidates=[x.id for x in strong], in_reply_to=in_reply, request=request, report=report)


def forwarded_letter(db, case, keys: set[str], mat, parsed, *, imid: str | None,
                     sent_at: datetime | None) -> Letter | None:
    """The letter a forward ("FW: <subject>") sends again: one letter of the authorities `keys` (all of the case's
    when empty) at THRESHOLD or above (subject, wallets, recipients' domain: `score_letter`), addressed to that
    authority (`addressed_to_authority`: an address on its own domain counts, e.g. a new freeze inbox), and not
    recorded as sent after the forward went out. A letter another e-mail already carries is fine (the original send);
    a draft another e-mail carries is never one."""
    letters, _ = case_letters(db, case, keys or None, mat)
    out = []
    for x in letters:
        rec = recorded_sent_at(x)
        if rec is not None and sent_at is not None and rec > sent_at + SENT_TIME_SLACK:
            continue
        if x.is_draft and _tied_elsewhere(db, x, imid):
            continue
        x.score = score_letter(x, parsed)
        if x.score >= THRESHOLD:
            out.append(x)
    out.sort(key=lambda x: -x.score)
    if not out or (len(out) > 1 and out[0].score == out[1].score):
        return None
    return out[0] if addressed_to_authority(out[0], parsed, mat) else None


def letter_entry(letter: Letter):
    """The outbound correspondence entry of a letter (a stop order's own letter when the candidate is the order)."""
    M = _M()
    if letter.corr is not None:
        return letter.corr
    return next((c for c in letter.order.correspondence if c.kind == M.CorrespondenceKind.STOP_ORDER
                 and c.direction == M.CorrespondenceDirection.OUT), None)


def request_of(db, corr) -> tuple[str, object | None, object] | None:
    """The request a stored message belongs to: (key "o<id>" | "c<id>", the stop order or None, the letter or
    reply that carries the thread). A stop order (its letter, a follow-up or a reply linked to it), or a sent
    outbound letter (or a reply to one); None for anything else (an entry logged for review, a note)."""
    M = _M()
    seen = 0
    c = corr
    while c is not None and seen < 10:
        seen += 1
        if c.stop_order_id and c.stop_order is not None and c.stop_order.status != M.StopOrderStatus.SUPERSEDED:
            return f"o{c.stop_order_id}", c.stop_order, corr
        if c.direction == M.CorrespondenceDirection.OUT:
            if matching.under_review_entry(c) or c.status != M.CorrespondenceStatus.SENT:
                return None
            follow = (c.meta or {}).get("follow_up_of")
            if (c.meta or {}).get("source") == MAILBOX_SOURCE:
                if not follow:
                    return None
                if not c.in_reply_to_id:
                    return follow, None, corr
            else:
                return f"c{c.id}", None, corr
        c = db.get(M.Correspondence, c.in_reply_to_id) if c.in_reply_to_id else None
    return None


def _metadata_only(ctx, item, parsed, rel, *, imid, sent_at, report, why) -> str:
    """Subject, recipient domains and date only: no addresses, no body, no .eml, no hash, no timeline entry."""
    db = ctx.db
    domains = sorted(matching.domains_of([*parsed.to, *parsed.cc]))[:20]
    mm = _row(ctx, item, parsed, imid=imid, sent_at=sent_at, method=rel.method, metadata_only=True,
              meta={"needs_review": True, "review_reason": why[:200], "recipient_domains": domains,
                    "candidate_case_ids": sorted({c for c, _ in rel.candidates} | set(rel.cited_cases))[:20]})
    mm.in_reply_to = mm.references = None
    mm.to_addrs, mm.cc_addrs = [], []
    db.add(mm)
    db.commit()
    audit(db, ctx.actor, "MAIL_SENT_FOUND", None, mm, mail_message_id=mm.id, result="metadata_only", method=rel.method)
    report.bump_sent("metadata_only")
    return "metadata_only"


def _record(ctx, case, authority, letter: Letter, item, raw, parsed, *, imid, sent_at, method, report) -> str:
    """The letter went out from the mailbox: file it and mark it sent (module doc, step 4)."""
    from app.domain import correspondence as desk
    from app.domain import directory, mail_send
    from app.domain.mail_compose import letter_key as key_of

    db, M = ctx.db, _M()
    corr, order = letter.corr, letter.order
    eml = None
    committed = False  # the desk commits the evidence with the letter: from then on the .eml must stay
    try:
        eml = _file_eml(db, case, raw, sent_at=sent_at,
                        title=f"E-mail sent from the case mailbox: {'letter #' + str(corr.id) if corr is not None else 'stop order #' + str(order.id)} "
                              f"({sent_at.astimezone(UTC):%Y-%m-%d %H:%M} UTC)")
        to, cc = list(parsed.to), list(parsed.cc)
        if corr is not None:
            corr.recipients, corr.cc = to or list(corr.recipients or []), cc
            corr.sender = ctx.mailbox
            corr.channel = M.CorrespondenceChannel.EMAIL
            corr.evidence_item_id = eml.id
            corr.thread_key = (imid or corr.thread_key or "")[:255] or None
            ids = [int(i) for i in (corr.meta or {}).get("evidence_ids") or [] if str(i).isdigit()]
            corr.meta = {**(corr.meta or {}), "sent_via": "email_mailbox", "sent_via_text": MAILBOX_SENT_VIA,
                         "evidence_ids": [eml.id] + [i for i in ids if i != eml.id]}
            db.flush()
            desk.mark_sent(db, case, corr, actor=None, sent_at=sent_at, channel="email",
                           due_days=desk.DEFAULT_RESPONSE_DAYS, authority_key=authority.key)  # commits
            committed = True
        else:
            order.recipient_email = to[0] if to else order.recipient_email
            order.recipient_cc = cc
            db.flush()
            corr = desk.record_stop_order_status(db, case, order, "sent", actor=None, occurred_at=sent_at,
                                                 authority_key=authority.key, observed=True)  # commits
            committed = True
            corr.recipients, corr.cc, corr.sender = to or list(corr.recipients or []), cc, ctx.mailbox
            corr.channel = M.CorrespondenceChannel.EMAIL
            corr.evidence_item_id = eml.id
            corr.thread_key = (imid or "")[:255] or None
            corr.meta = {**(corr.meta or {}), "sent_via": "email_mailbox", "sent_via_text": MAILBOX_SENT_VIA,
                         "evidence_ids": [eml.id]}
        order = corr.stop_order or order
        if order is not None and order.sent_at is not None and order.sent_via in (None, "email"):
            order.sent_via = MAILBOX_SENT_VIA
        lk = key_of(corr)
        busy = _letter_busy(db, lk, corr.id)
        mm = _row(ctx, item, parsed, raw=raw, imid=imid, sent_at=sent_at, case_id=case.id, corr_id=corr.id,
                  letter_key=None if busy is not None else lk, authority_key=authority.key, method=method,
                  eml_id=eml.id, meta={"letter": letter.id, "score": letter.score, "due_days": desk.DEFAULT_RESPONSE_DAYS})
        db.add(mm)
        db.flush()
        eml.meta = {**(eml.meta or {}), "mail_message_id": mm.id}
        corr.meta = {**(corr.meta or {}), "mail_message_id": mm.id}
        directory.touch_used(db, case, [*to, *cc])
        db.commit()
    except Exception:
        db.rollback()
        if not committed:  # (once committed, the next sync finds the letter sent and links this message)
            _drop_vault_copy(eml)
        raise
    mail_send._retire_siblings(db, mm, None)
    audit(db, ctx.actor, "MAIL_SENT_FOUND", case, mm, mail_message_id=mm.id, result="recorded", method=method,
          correspondence_id=corr.id, stop_order_id=order.id if order is not None else None, eml_evidence_id=eml.id)
    report.bump_sent("recorded")
    return "recorded"


def _link(ctx, case, letter: Letter, item, raw, parsed, *, imid, sent_at, method, report) -> str | None:
    """The letter is already marked sent: tie this Sent Items copy to it (module doc, step 4). None when the
    letter already carries another message (then it is logged for review instead)."""
    from app.domain.mail_compose import letter_key as key_of

    db, M = ctx.db, _M()
    corr = letter.corr
    if corr is None:
        corr = next((c for c in letter.order.correspondence if c.kind == M.CorrespondenceKind.STOP_ORDER
                     and c.direction == M.CorrespondenceDirection.OUT), None)
    if corr is None:
        return None
    lk = key_of(corr)
    busy = _letter_busy(db, lk, corr.id)
    if busy is not None and busy.internet_message_id and busy.internet_message_id != imid:
        return None
    eml = None
    try:
        eml = _file_eml(db, case, raw, sent_at=sent_at,
                        title=f"E-mail sent from the case mailbox: letter #{corr.id} "
                              f"({sent_at.astimezone(UTC):%Y-%m-%d %H:%M} UTC)")
        differs = corr.occurred_at is not None and abs(_aware(corr.occurred_at) - sent_at) > SENT_TIME_SLACK
        if busy is not None:  # recorded as sent without the sent copy: this is it
            mm = busy
            mm.internet_message_id = imid
            mm.provider_message_id = mm.provider_message_id or item.provider_id
            conv = (item.meta or {}).get("conversation_id")
            mm.conversation_id = mm.conversation_id or conv
            mm.graph_conversation_id = conv
            mm.folder, mm.outside_sent = "sentitems", True
            mm.eml_evidence_id = mm.eml_evidence_id or eml.id
            mm.meta = {**(mm.meta or {}), "mailbox_copy_evidence_id": eml.id, "sent_time_differs": differs or None}
        else:
            mm = _row(ctx, item, parsed, raw=raw, imid=imid, sent_at=sent_at, case_id=case.id, corr_id=corr.id,
                      letter_key=lk, authority_key=letter.authority_key, method=method, eml_id=eml.id,
                      meta={"letter": letter.id, "linked": True, **({"sent_time_differs": True} if differs else {})})
            db.add(mm)
        db.flush()
        eml.meta = {**(eml.meta or {}), "mail_message_id": mm.id}
        if corr.evidence_item_id is None:
            corr.evidence_item_id = eml.id
        ids = [int(i) for i in (corr.meta or {}).get("evidence_ids") or [] if str(i).isdigit()]
        corr.meta = {**(corr.meta or {}), "evidence_ids": ids + [eml.id], "mailbox_copy": mm.id}
        if not corr.thread_key:
            corr.thread_key = (imid or "")[:255] or None
        db.commit()
    except IntegrityError:
        db.rollback()
        _drop_vault_copy(eml)
        return None
    except Exception:
        db.rollback()
        _drop_vault_copy(eml)
        raise
    audit(db, ctx.actor, "MAIL_SENT_FOUND", case, mm, mail_message_id=mm.id, result="linked", method=method,
          correspondence_id=corr.id, eml_evidence_id=eml.id)
    report.bump_sent("linked")
    return "linked"


def _log(ctx, case, authority, item, raw, parsed, *, imid, sent_at, method, why, candidates, in_reply_to,
         report, request=None) -> str:
    """A follow-up in a request's thread (module doc, step 5), or ambiguous / no letter / a reply outside a
    request: log it on the authority for review (step 6)."""
    from app.domain import correspondence as desk

    db = ctx.db
    eml = None
    committed = False
    try:
        eml = _file_eml(db, case, raw, sent_at=sent_at,
                        title=f"E-mail sent from the case mailbox ({sent_at.astimezone(UTC):%Y-%m-%d %H:%M} UTC)")
        corr = None
        if authority is not None:
            if in_reply_to is not None and in_reply_to not in authority.correspondence:
                in_reply_to, request = None, None
            order = request[1] if request is not None else None
            if order is not None and order not in authority.stop_orders:
                order, request = None, None
            thread = (in_reply_to.thread_key if request is not None and in_reply_to is not None else None) \
                or (imid or "")[:255] or None
            db.flush()
            corr = desk.log_entry(db, case, authority, actor=None, direction="out", channel="email", kind="other",
                                  subject=parsed.subject or "(no subject)", body=parsed.text or "(no text)",
                                  body_format="text", occurred_at=sent_at, sender=ctx.mailbox,
                                  recipients=list(parsed.to), cc=list(parsed.cc), in_reply_to=in_reply_to,
                                  stop_order=order, evidence_ids=[eml.id], classification="R3",
                                  thread_key=thread)  # commits
            committed = True
        else:
            request = None
        if request is not None:
            review = {"needs_review": False, "follow_up_of": request[0]}
        else:
            review = {"needs_review": True, "review_reason": why[:200], "candidates": candidates[:10]}
        mm = _row(ctx, item, parsed, raw=raw, imid=imid, sent_at=sent_at, case_id=case.id,
                  corr_id=corr.id if corr is not None else None,
                  authority_key=authority.key if authority is not None else None, method=method, eml_id=eml.id,
                  meta=review)
        db.add(mm)
        db.flush()
        eml.meta = {**(eml.meta or {}), "mail_message_id": mm.id}
        if corr is not None:
            # "mailbox_sent": our own message read back from Sent Items (not "mailbox": that marks inbound
            # external mail, shown with the untrusted-e-mail banner)
            corr.meta = {**(corr.meta or {}), "source": MAILBOX_SOURCE, "mail_message_id": mm.id,
                         "sent_from_mailbox": True, **review}
        db.commit()
    except Exception:
        db.rollback()
        if not committed:
            _drop_vault_copy(eml)
        raise
    audit(db, ctx.actor, "MAIL_SENT_FOUND", case, mm, mail_message_id=mm.id, result="logged", method=method,
          correspondence_id=mm.correspondence_id, eml_evidence_id=eml.id, n_candidates=len(candidates),
          follow_up_of=request[0] if request is not None else None)
    report.bump_sent("logged")
    return "logged"


# --------------------------------------------------------------------------- review: dismiss / tie to a letter
class ReviewError(ValueError):
    """A dismiss / tie request that cannot be done: `status` 400 / 404 / 409."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def review_row(db, mm_id: int):
    """The Sent Items row logged for review (needs_review), or ReviewError(404)."""
    M = _M()
    mm = db.get(M.MailMessage, mm_id)
    if mm is None or mm.direction != M.MailDirection.OUT or mm.folder != "sentitems" \
            or not (mm.meta or {}).get("needs_review"):
        raise ReviewError(404, "no Sent Items e-mail waiting for review")
    return mm


def review_row_for_entry(db, case, entry_id: int):
    """The review row behind a timeline entry logged from Sent Items on `case` (Block status, kind "outlook")."""
    M = _M()
    mm = db.scalar(select(M.MailMessage).where(M.MailMessage.case_id == case.id,
                                               M.MailMessage.correspondence_id == entry_id,
                                               M.MailMessage.folder == "sentitems")
                   .order_by(M.MailMessage.id.desc()).limit(1))
    if mm is None or not (mm.meta or {}).get("needs_review"):
        raise ReviewError(404, "no Sent Items e-mail waiting for review")
    return mm


def tie_candidates(db, mm) -> list[Letter]:
    """The letters a person may tie this review row to: the case's draft and sent letters (and draft stop orders
    without a letter row) of the row's authority (all of the case's when the row names none), not already
    carried by another e-mail nor recorded as sent more than SENT_TIME_SLACK after this e-mail went out (the
    rule of `eligible_letters`); the sync's own candidates first."""
    M = _M()
    case = db.get(M.Case, mm.case_id) if mm.case_id else None
    if case is None or (mm.meta or {}).get("metadata_only"):
        return []
    keys = {mm.authority_key} if mm.authority_key else None
    letters, _ = case_letters(db, case, keys, None)
    imid = mm.internet_message_id or mm.message_id
    letters = eligible_letters(db, letters, imid=imid, sent_at=_aware(mm.sent_at))
    first = [str(c) for c in (mm.meta or {}).get("candidates") or []]
    return sorted(letters, key=lambda x: (x.id not in first, first.index(x.id) if x.id in first else 0, x.id))


def _find_letter(letters: list[Letter], key: str) -> Letter | None:
    key = (key or "").strip().lower()
    for x in letters:
        if x.id == key or (x.order is not None and key == f"o{x.order.id}") or (
                x.corr is not None and key == f"c{x.corr.id}"):
            return x
    return None


def _actor_user(actor):
    return getattr(actor, "user", actor) if actor is not None and not hasattr(actor, "email") else actor


def _close_review(db, mm, entry_id: int | None, extra: dict) -> None:
    M = _M()
    mm.meta = {**(mm.meta or {}), "needs_review": False, **extra}
    entry = db.get(M.Correspondence, entry_id) if entry_id else None
    if entry is not None and (entry.meta or {}).get("source") == MAILBOX_SOURCE:
        entry.meta = {**(entry.meta or {}), "needs_review": False, **extra}


def dismiss(db, mm, *, actor=None) -> None:
    """A person read the e-mail: it carried no letter (or nothing the case needs). It leaves the review lists;
    the .eml and the timeline entry stay as filed. Audited (ids only)."""
    user = _actor_user(actor)
    _close_review(db, mm, mm.correspondence_id, {"dismissed": True, "reviewed_by": getattr(user, "id", None),
                                                 "reviewed_at": _now().isoformat(timespec="seconds")})
    db.commit()
    audit(db, actor, "MAIL_SENT_FOUND", mm.case_id, mm, mail_message_id=mm.id, result="dismissed",
          correspondence_id=mm.correspondence_id)


def tie_to_letter(db, mm, letter_key: str, *, actor=None) -> str:
    """A person says which letter this e-mail carried (`letter_key` "c<id>" / "o<id>"): a draft is recorded as
    sent at the e-mail's date (as the sync records one, with the .eml already filed as its evidence); an already
    sent letter is linked. The review entry is closed. Returns the letter key. Audited (ids only).
    An e-mail logged because no recipient is the letter's authority keeps the letter's own recipients (a draft's
    To / Cc, a stop order's recipient): its To never becomes an authority address (the mail row's meta says
    `recipients_untrusted`, the letter's `mail_to_untrusted`; the directory is not touched, and
    app.mail.matching.allowed_domains leaves that e-mail's To out for the replies to it)."""
    from app.domain import correspondence as desk
    from app.domain import mail_send
    from app.domain.mail_compose import letter_key as key_of

    M = _M()
    if (mm.meta or {}).get("metadata_only") or mm.case_id is None or not mm.eml_evidence_id:
        raise ReviewError(409, "Only metadata was kept for this e-mail (it is on no case): dismiss it, or record "
                               "the letter as sent by hand on the case.")
    case = db.get(M.Case, mm.case_id)
    letters = tie_candidates(db, mm)
    letter = _find_letter(letters, letter_key)
    if letter is None:
        raise ReviewError(400, "That letter is not one this e-mail can be tied to (another authority, already "
                               "carried by another e-mail, sent after this e-mail, or not a letter of this case).")
    user = _actor_user(actor)
    authorities = {a.key: a for a in desk.case_authorities(db, case, include_prospects=False)}
    authority = authorities.get(letter.authority_key)
    entry_id = mm.correspondence_id
    sent_at = _aware(mm.sent_at) or _now()
    imid = mm.internet_message_id or mm.message_id
    to, cc = list(mm.to_addrs or []), list(mm.cc_addrs or [])
    corr, order = letter.corr, letter.order
    was_draft = letter.is_draft
    # logged because no recipient is the letter's authority: a person says it carried the letter, but its To says
    # nothing about the authority's addresses. The letter keeps its own recipients (what the directory, the
    # guidance and the matching read) and the e-mail's To / Cc stay on the mail row and its .eml only.
    untrusted = matching.recipients_untrusted(mm)
    mail_meta = {"mail_to_untrusted": True} if untrusted else {}
    try:
        if was_draft:
            if corr is not None:
                if not untrusted:
                    corr.recipients, corr.cc = to or list(corr.recipients or []), cc
                corr.sender, corr.channel = mm.from_addr or corr.sender, M.CorrespondenceChannel.EMAIL
                corr.evidence_item_id = mm.eml_evidence_id
                corr.thread_key = (imid or corr.thread_key or "")[:255] or None
                ids = [int(i) for i in (corr.meta or {}).get("evidence_ids") or [] if str(i).isdigit()]
                corr.meta = {**(corr.meta or {}), "sent_via": "email_mailbox", "sent_via_text": MAILBOX_SENT_VIA,
                             "evidence_ids": [mm.eml_evidence_id] + [i for i in ids if i != mm.eml_evidence_id],
                             **mail_meta}
                db.flush()
                desk.mark_sent(db, case, corr, actor=user, sent_at=sent_at, channel="email",
                               due_days=desk.DEFAULT_RESPONSE_DAYS, authority_key=letter.authority_key)  # commits
            else:
                if not untrusted:
                    order.recipient_email = to[0] if to else order.recipient_email
                    order.recipient_cc = cc
                db.flush()
                corr = desk.record_stop_order_status(db, case, order, "sent", actor=user, occurred_at=sent_at,
                                                     authority_key=letter.authority_key, observed=True)  # commits
                if untrusted:
                    corr.recipients = [order.recipient_email] if order.recipient_email else list(corr.recipients or [])
                    corr.cc = list(order.recipient_cc or [])
                else:
                    corr.recipients, corr.cc = to or list(corr.recipients or []), cc
                corr.sender, corr.channel = mm.from_addr or corr.sender, M.CorrespondenceChannel.EMAIL
                corr.evidence_item_id = mm.eml_evidence_id
                corr.thread_key = (imid or "")[:255] or None
                corr.meta = {**(corr.meta or {}), "sent_via": "email_mailbox", "sent_via_text": MAILBOX_SENT_VIA,
                             "evidence_ids": [mm.eml_evidence_id], **mail_meta}
            order = corr.stop_order or order
            if order is not None and order.sent_at is not None and order.sent_via in (None, "email"):
                order.sent_via = MAILBOX_SENT_VIA
        else:
            if corr is None:
                corr = next((c for c in order.correspondence if c.kind == M.CorrespondenceKind.STOP_ORDER
                             and c.direction == M.CorrespondenceDirection.OUT), None)
            if corr is None:
                raise ReviewError(409, "The stop order has no sent letter to tie this e-mail to.")
            ids = [int(i) for i in (corr.meta or {}).get("evidence_ids") or [] if str(i).isdigit()]
            corr.meta = {**(corr.meta or {}), "evidence_ids": ids + [mm.eml_evidence_id], "mailbox_copy": mm.id,
                         **mail_meta}
            if corr.evidence_item_id is None:
                corr.evidence_item_id = mm.eml_evidence_id
            if not corr.thread_key:
                corr.thread_key = (imid or "")[:255] or None
        result = "tied" if was_draft else "tied_linked"
        lk = key_of(corr)
        busy = _letter_busy(db, lk, corr.id)
        mm.correspondence_id, mm.authority_key = corr.id, letter.authority_key
        mm.letter_key = None if busy is not None and busy.id != mm.id else lk
        mm.match = {**(mm.match or {}), "method": "review", "correspondence_id": corr.id}
        _close_review(db, mm, entry_id, {"tied_to": lk, "reviewed_by": getattr(user, "id", None),
                                         "reviewed_at": _now().isoformat(timespec="seconds"),
                                         "logged_entry_id": entry_id,
                                         **({"recipients_untrusted": True} if untrusted else {})})
        corr.meta = {**(corr.meta or {}), "mail_message_id": mm.id}
        if authority is not None and not untrusted:
            from app.domain import directory

            directory.touch_used(db, case, [*to, *cc])
        db.commit()
    except ReviewError:
        db.rollback()
        raise
    except IntegrityError:
        db.rollback()
        raise ReviewError(409, "That letter was recorded as sent from another e-mail meanwhile.") from None
    if was_draft:
        mail_send._retire_siblings(db, mm, getattr(user, "id", None))
    audit(db, actor, "MAIL_SENT_FOUND", case, mm, mail_message_id=mm.id, result=result, letter=lk,
          correspondence_id=corr.id, stop_order_id=order.id if order is not None else None)
    return lk


def needs_review(db, *, limit: int = 100) -> list:
    """Sent Items rows waiting for a person (logged for review, or metadata only), newest first."""
    M = _M()
    rows = db.scalars(select(M.MailMessage).where(M.MailMessage.direction == M.MailDirection.OUT,
                                                  M.MailMessage.folder == "sentitems")
                      .order_by(M.MailMessage.id.desc()).limit(500)).all()
    return [r for r in rows if (r.meta or {}).get("needs_review")][:limit]
