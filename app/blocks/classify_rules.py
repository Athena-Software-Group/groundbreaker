"""Rule-based classifier for an authority's reply to a block request (pure: no database, no I/O).

    r = classify(text, subject="RE: …", auto_reply=False, bounce=False,
                 exclude_addresses={"investigations@…"}, exclude_refs={"DEMO-2026-001"})
    r.status, r.confidence, r.quote, r.amount, r.asset, r.ticket, r.addresses, r.urls, r.also

Statuses (`REPLY_STATUSES`):

    frozen               "we have frozen …", "the funds have been frozen / blacklisted"
    hold_placed          "we placed a temporary hold", "the account has been restricted"
    funds_returned       "the funds have been returned / reversed / refunded"
    declined_no_assets   "no account found", "not our customer", "we are non-custodial"
    le_process_required  "submit via our law-enforcement portal", "we require a valid court order / subpoena"
    info_requested       "please provide the transaction hash …"
    declined_other       "we must decline your request" (no reason recognised)
    redirected           "this is a legacy inbox … please contact the following: x@…" (new addresses extracted)
    acknowledged         "we have received your request … ticket #12345", "our team is reviewing"
    auto_reply           out-of-office / "this is an automated response" with nothing else
    delivery_failed      a bounce (the e-mail desk filed a delivery-status report)
    unclear              nothing recognisable, or an empty reply

How it reads a reply:

* Only the sender's own text counts: quoted lines (``>``) and everything from a reply header
  ("On … wrote:", "-----Original Message-----", an Outlook "From: … Sent: …" block, and the German /
  Italian / French / Spanish equivalents) are cut, so the words of our own letter ("please freeze …")
  never classify the reply.
* Sentence by sentence (never split after an abbreviation such as "approx." or "No."; the patterns read
  `match_text`, where a decimal point and an abbreviation's dot no longer end a clause). A positive outcome (frozen / hold / returned) is ignored when the sentence
  negates it ("we have *not* frozen", "we are *unable* to confirm the funds have been frozen"), makes
  it conditional or future ("*if* … we *will* freeze", "*once* we receive a court order …") or asks
  it ("Have the funds been frozen?", also without its "?": a sentence or line that opens like a question,
  "Did / Have / Has / Is / Are / Can / Could you …"), says it came too late ("too late to freeze"), negates
  its object ("we have frozen *nothing*", "frozen *none* of the assets", "*none* of the funds were frozen"),
  says it was only considered or requested ("a hold was *considered* but *not placed*"), or lifts it again
  later in the sentence, also across "; " before a capital, or in the next two sentences ("frozen by mistake and
  have since been *released*", "the freeze was *lifted* / *removed* / *withdrawn* / *cancelled* / *rescinded*",
  "blacklisted by mistake; Tether has since *unblacklisted* the address", "The funds were frozen. They were
  *released* on 3 October", "a temporary hold, which *expired*", "…, which is *no longer in effect*", "Full access
  has been *reinstated*", "until the court *lifted* the order"; a lift that is itself negated or conditional,
  "frozen, not released", "frozen until released by a court order", leaves it standing; any lift word counts, also
  one about something else, so "frozen … and cancelled the pending withdrawals" goes to review). A lift that names
  the freeze / hold anywhere in the reply ("It has since been removed from the blacklist", "We removed the block")
  cancels every freeze / hold in it. Negations count in English, German, Italian, French and Spanish ("nicht",
  "kein", "non", "n'… pas", "nunca"), also inside the match ("The wallet *no longer* remains frozen", "Das Konto
  wurde *nicht* gesperrt"), and so do "zero" / a 0 amount ("We have frozen 0 USDT"). Also ignored: an intention,
  a need or a policy ("we *plan to* / *are going to* / *need a court order to* put a hold", "*Normally*, accounts …
  are frozen", "frozen *only upon receipt of* a court order", "frozen *as of tomorrow*"), someone else's claim, a
  quotation, a hedge or a request back to us ("*In your letter you state* that …", "*Reports that* … are
  *inaccurate*", "*We believe* …", "*Please confirm* the funds have been frozen", "…, *according to the user*"),
  another party or account ("frozen by the sending exchange, *not by us*", "*a different account* …, not the one
  you reported", "*at the request of another agency*"), a platform-wide suspension ("suspended *for maintenance*"),
  and a returned letter, request, document or e-mail ("We returned your request as incomplete": a return needs a
  funds object; a refund "to the suspect's card" is none). Partial outcomes ("We have frozen part of the funds; the
  remaining … had already been withdrawn") go to review. Imperatives addressed to us ("mark this case as frozen")
  match no pattern: every outcome pattern needs the sender to state it. Also to review (round 3): what is no funds
  (an e-mail / IP / sender address, a mail server, a portal or log-in account, "a hold on processing your request",
  "a freeze on new sign-ups"), another party as the subject ("The bank has frozen …"; only "we / our team has …")
  or another matter ("unrelated", "in 2023", "belongs to someone else"), a statement reported by anyone ("We were
  told …", "The customer says …", "the officer wrote: …", "We mistakenly reported …"), a policy or condition ("In the
  event of …", "Where …", "Assuming …", "on receipt of a court order", "Accounts are frozen …"), a lapse in other words
  ("reversed", "taken off", "now open", "had frozen … until …", "for 48 hours", "at the time"), a correction,
  disclaimer or partial outcome after "; " or in the next two sentences ("NOT by us", "Correction: we have not.",
  "This is incorrect.", "withdrawals remain open", "contains no funds"), a returned fee / payment details / records,
  and a return that bounced or is back with us. `positive_spans` lists the outcome
  statements that pass this guard: an AI quote of an outcome must overlap one (classify_ai.outcome_stated).
* When several outcomes appear, the strongest wins (`PRIORITY`); the others are kept in `also`
  (e.g. a hold that needs a court order within 10 days: hold_placed, also le_process_required).
  Conflicting outcomes (e.g. frozen and declined_no_assets) lower the confidence.
* `quote` is the sentence that supports the status, verbatim from the reply. `amount` / `asset` come
  from that sentence first (an amount needs an asset or currency next to it: "12,633.77 USDT",
  "USDT 12,633.77", "$1,200"). `ticket` is the recipient's own ticket / case number (never our case
  reference or tracking tag). `addresses` / `urls` are the channels a redirect names, minus the
  addresses we wrote to, the case mailbox and the ones the reply calls legacy / no longer monitored.

* Also cut as quoted: what a ticket system echoes of our letter — a "-- reply above this line --" marker (when it
  opens the message, the ticket system's own text after it is read), a rule line of underscores / dashes / equals
  signs, and a "Ticket details:" block with the fields of the request (Submitted / Subject / …): a ticket
  acknowledgement reads "acknowledged" with its number, never a status from our own echoed letter.

English first; the commonest German / Italian / French / Spanish phrasings are covered too.
Everything here is advisory: a frozen / hold / returned reading is only ever a suggestion a person confirms
(app.blocks.status), shown with `outcome_warnings`; a person confirms a status before it changes a stop order.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from decimal import Decimal, InvalidOperation

RULES_VERSION = 11  # 8: app.blocks.extract (tickets, instrument, channels, asks, deadlines, contacts, identifiers);
# 9: a provider playbook's LE-process wording raises an untracked acknowledgement; "withdrawn … no assets remain"
# 10: "contact local law enforcement" / "law enforcement … must directly submit" (an issuer's refusal): LE process
# 11: "for law enforcement only" / "report to your local police, who can contact us": LE process; "we have
# temporarily frozen the account": a hold
MAX_TEXT_CHARS = 60_000
MAX_QUOTE_CHARS = 400
MAX_ADDRESSES = 8

FROZEN = "frozen"
HOLD_PLACED = "hold_placed"
FUNDS_RETURNED = "funds_returned"
DECLINED_NO_ASSETS = "declined_no_assets"
LE_PROCESS_REQUIRED = "le_process_required"
INFO_REQUESTED = "info_requested"
DECLINED = "declined_other"  # models.ReplyStatus.DECLINED_OTHER
REDIRECTED = "redirected"
ACKNOWLEDGED = "acknowledged"
AUTO_REPLY = "auto_reply"
DELIVERY_FAILED = "delivery_failed"
UNCLEAR = "unclear"

REPLY_STATUSES: tuple[str, ...] = (
    FROZEN, HOLD_PLACED, FUNDS_RETURNED, DECLINED_NO_ASSETS, LE_PROCESS_REQUIRED, INFO_REQUESTED, DECLINED,
    REDIRECTED, ACKNOWLEDGED, AUTO_REPLY, DELIVERY_FAILED, UNCLEAR,
)
# strongest first: the status of a reply that says several things
PRIORITY: tuple[str, ...] = (
    DELIVERY_FAILED, FUNDS_RETURNED, FROZEN, HOLD_PLACED, DECLINED_NO_ASSETS, LE_PROCESS_REQUIRED, INFO_REQUESTED,
    DECLINED, REDIRECTED, ACKNOWLEDGED, AUTO_REPLY, UNCLEAR,
)
SUBSTANTIVE = frozenset({FROZEN, HOLD_PLACED, FUNDS_RETURNED, DECLINED_NO_ASSETS, LE_PROCESS_REQUIRED, INFO_REQUESTED,
                         DECLINED, REDIRECTED, DELIVERY_FAILED})
POSITIVE = frozenset({FROZEN, HOLD_PLACED, FUNDS_RETURNED})
# outcome families that contradict each other when one reply states both
_FAMILY = {FROZEN: "held", HOLD_PLACED: "held", FUNDS_RETURNED: "returned", DECLINED_NO_ASSETS: "declined",
           DECLINED: "declined"}

LABELS = {
    FROZEN: "Frozen", HOLD_PLACED: "Hold placed", FUNDS_RETURNED: "Funds returned",
    DECLINED_NO_ASSETS: "Declined — no account / no assets", LE_PROCESS_REQUIRED: "LE process required",
    INFO_REQUESTED: "Information requested", DECLINED: "Declined", REDIRECTED: "Redirected",
    ACKNOWLEDGED: "Acknowledged", AUTO_REPLY: "Auto-reply", DELIVERY_FAILED: "Not delivered (bounce)",
    UNCLEAR: "Unclear — needs review",
}

_I = re.IGNORECASE

# --------------------------------------------------------------------------- quoted text
_REPLY_HEADER = [
    re.compile(r"^\s*on\s.{0,300}\bwrote:\s*$", _I),
    re.compile(r"^\s*-{2,}\s*(?:original message|ursprüngliche nachricht|messaggio originale|message d'origine|"
               r"mensaje original|forwarded message|weitergeleitete nachricht)\s*-{2,}", _I),
    re.compile(r"^\s*am\s.{0,200}\bschrieb\b.{0,200}:\s*$", _I),
    re.compile(r"^\s*il giorno\s.{0,200}\bha scritto:\s*$", _I),
    re.compile(r"^\s*le\s.{0,200}\ba écrit\s*:\s*$", _I),
    re.compile(r"^\s*el\s.{0,200}\bescribió:\s*$", _I),
]
_FROM_LINE = re.compile(r"^\s*\**(?:from|von|da|de|van)\s*\**\s*:\s*\S", _I)
_SENT_LINE = re.compile(r"^\s*\**(?:sent|date|gesendet|datum|inviato|data|envoyé|enviado|fecha|verzonden)\s*\**\s*:", _I)
_WROTE_SPLIT = re.compile(r"^\s*on\s.{0,200}$", _I)
# a ticket system's marker ("-- reply above this line --", "##- Please type your reply above this line -##"): above
# it is the sender's own text; when it opens the message, the ticket system's own notification follows it
_REPLY_ABOVE = re.compile(r"^\s*(?:-{2,}|#{1,3}-?|={2,})?\s*(?:please\s+)?(?:(?:type|write|enter|add)\s+)?(?:your\s+)?"
                          r"(?:reply|response)\s+above\s+this\s+line\s*(?:-{2,}|-?#{1,3}|={2,})?\s*$", _I)
# a rule line (a row of underscores / dashes / equals signs, how Outlook renders an <hr>): an echo separator only when
# an echo follows it (`_echo_follows`); else it is the sender's own divider and the text after it is read
_RULE_LINE = re.compile(r"\s*(?:_{8,}|-{5,}|={8,})\s*")
# "Ticket details:" followed by the fields of the request a ticket system echoes (our subject, the submission date)
_DETAILS_HEAD = re.compile(r"^\s*\**\s*(?:ticket|request|case|inquiry|enquiry|submission|support\s+request)\s+"
                           r"(?:details|summary|information|info)\s*\**\s*:?\s*$", _I)
_DETAIL_FIELD = re.compile(r"^\s*\**(?:subject|submitted|description|message|requester|requested\s+by|from|created|"
                           r"date|your\s+(?:request|message|inquiry|enquiry))\s*\**\s*:", _I)
# the header fields of an echoed e-mail ("From: …", "Sent: …", "To: …", "Subject: …")
_HEADER_FIELD = re.compile(r"^\s*\**(?:from|sent|to|cc|subject|von|gesendet|an|betreff|da|inviato|oggetto|de|envoyé|"
                           r"objet|enviado|para|asunto)\s*\**\s*:\s*\S", _I)
# the opening of a letter: below a rule line, the start of the echoed message (our letter), not the sender's text
_SALUTATION = re.compile(r"^\s*(?:dear\b|to\s+whom\s+it\s+may\s+concern|(?:hello|hi|good\s+(?:morning|afternoon|"
                         r"evening))\b.{0,60},\s*$|sehr\s+geehrte|gentile\b|egregi|madame|monsieur|estimad)", _I)
_ECHO_LOOKAHEAD = 8  # non-blank lines read after a rule line for an echo
_MIN_ECHO_WORDS = 4


def _words(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", (text or "").lower()))


def _echo_follows(lines: list[str], i: int, echo: str) -> bool:
    """Does an echo follow the rule line at `lines[i]`? A header block ("From: … Sent: …", "Subject: …"), a ticket
    system's request fields, a reply header or ``>`` lines within a few lines, or a line of our own letter or its
    subject (`echo`: the words of the letters we sent, when known). When we do not know what we sent, a letter's
    salutation right after the rule line ("Dear Compliance Team,") counts too (cutting fails safe: the reply reads
    unclear and goes to review); when we do, it does not (an agent's comment may open with "Dear …"). Anything else
    is the sender's own divider ("We have received your request.\n-----\nPlease submit via our portal", Outlook's
    <hr> under "Dear team,", the agent's comment below a ticket system's "Your request (#…) has been updated.")."""
    ahead = [x for x in lines[i + 1:] if x.strip()][:_ECHO_LOOKAHEAD]
    for n in ahead:
        if (n.lstrip().startswith(">") or _HEADER_FIELD.match(n) or _DETAILS_HEAD.match(n) or _DETAIL_FIELD.match(n)
                or any(p.match(n) for p in _REPLY_HEADER)):
            return True
        w = _words(n)
        if echo and len(w.split()) >= _MIN_ECHO_WORDS and w in echo:
            return True
    return bool(ahead) and not echo and bool(_SALUTATION.match(ahead[0]))


def split_quoted(text: str, echo: Iterable[str | None] = ()) -> tuple[str, str]:
    """(the sender's own text, the quoted part: its ``>`` lines and everything from a reply header on).

    `echo`: the subjects / texts of the letters we sent (optional): a rule line is an echo separator when one of
    them follows it."""
    lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    known = "\n".join(_words(e) for e in echo if e)
    out: list[str] = []
    quoted: list[str] = []
    for i, line in enumerate(lines):
        if line.lstrip().startswith(">"):
            quoted.append(line)
            continue
        if _REPLY_ABOVE.match(line):
            if not any(x.strip() for x in out):
                continue  # it opens the message: the ticket system's own text follows (its echo comes later)
            quoted += lines[i:]
            break
        if _RULE_LINE.fullmatch(line):
            if _echo_follows(lines, i, known):
                quoted += lines[i:]
                break
            continue  # the sender's own divider: read on
        if _DETAILS_HEAD.match(line) and any(_DETAIL_FIELD.match(n) for n in lines[i + 1:i + 7]):
            quoted += lines[i:]  # "Ticket details: Submitted: … Subject: <our subject> …" and our letter after it
            break
        if any(p.match(line) for p in _REPLY_HEADER) or (
                # "On Mon, 20 Oct 2026 at 10:00, Someone <x@y>\nwrote:" (wrapped over two lines)
                _WROTE_SPLIT.match(line) and i + 1 < len(lines) and lines[i + 1].strip().lower().endswith("wrote:")) \
                or (_FROM_LINE.match(line) and any(_SENT_LINE.match(n) for n in lines[i + 1:i + 5])):
            quoted += lines[i:]
            break
        out.append(line)
    return "\n".join(out).strip(), "\n".join(quoted).strip()


def strip_quoted(text: str, echo: Iterable[str | None] = ()) -> tuple[str, bool]:
    """(the sender's own text, whether a quoted part was cut)."""
    own, quoted = split_quoted(text, echo)
    return own, bool(quoted)


# --------------------------------------------------------------------------- sentences
# never after an abbreviation ("approx. 2.1 ETH", "Ticket No. 48213", "e.g. the deposit")
_ABBREVIATIONS = ("approx", "appr", "ca", "circa", "est", "incl", "no", "nr", "ref", "vs", "e.g", "i.e", "resp")
_NO_SPLIT_AFTER = "".join(f"(?<!\\b{re.escape(a)}\\.)(?<!\\b{re.escape(a.capitalize())}\\.)" for a in _ABBREVIATIONS)
_SENT_SPLIT = re.compile(r"(?<=[.!?;])" + _NO_SPLIT_AFTER + r"\s+(?=[\"'(\[]?[A-Z0-9À-Ý])|\n\s*\n|"
                         r"\n(?=\s*(?:[-*•]|\d+[.)])\s)")
# the same split without "; ": the whole sentence, read for a later lift ("…frozen by mistake; Tether has since
# unblacklisted the address.")
_FULL_SPLIT = re.compile(r"(?<=[.!?])" + _NO_SPLIT_AFTER + r"\s+(?=[\"'(\[]?[A-Z0-9À-Ý])|\n\s*\n|"
                         r"\n(?=\s*(?:[-*•]|\d+[.)])\s)")
_DECIMAL_DOT = re.compile(r"(?<=\d)\.(?=\d)")
_NUMBER_NO = re.compile(r"\b[Nn][Oo]\.?(?=\s*#?\s*\d)")
_ABBREV_DOT = re.compile(r"\b(" + "|".join(re.escape(a) for a in _ABBREVIATIONS) + r")\.", re.IGNORECASE)


def match_text(sentence: str) -> str:
    """The sentence the patterns read: a decimal point ("12,633.77") and an abbreviation's dot ("approx.")
    become a comma / a space, so a clause pattern that stops at a sentence end reads across them. Same length
    as the sentence (the offsets stay valid); the quote and the amount are taken from the sentence itself."""
    s = _DECIMAL_DOT.sub(",", sentence)
    s = _NUMBER_NO.sub(lambda m: "Nr" + m.group(0)[2:].replace(".", " "), s)  # "No. 48213" is no negation
    return _ABBREV_DOT.sub(lambda m: m.group(1).replace(".", " ") + " ", s)


def sentences(text: str) -> list[tuple[int, str]]:
    """(start offset, sentence) of `text`, split on sentence ends, blank lines and list items.
    Single line breaks inside a paragraph are kept (wrapped e-mail text)."""
    out: list[tuple[int, str]] = []
    pos = 0
    for m in _SENT_SPLIT.finditer(text):
        chunk = text[pos:m.start()]
        if chunk.strip():
            lead = len(chunk) - len(chunk.lstrip())
            out.append((pos + lead, chunk.strip()))
        pos = m.end()
    tail = text[pos:]
    if tail.strip():
        out.append((pos + len(tail) - len(tail.lstrip()), tail.strip()))
    return out


def sentence_rest(text: str, end: int) -> str:
    """What follows offset `end` of `text` up to the end of its whole sentence: `sentences` also splits at "; "
    before a capital, this reads on to the next ".", "!", "?", blank line or list item."""
    m = _FULL_SPLIT.search(text, end)
    return text[end:m.start() if m else len(text)]


# --------------------------------------------------------------------------- patterns
@dataclass(frozen=True)
class Pattern:
    status: str
    regex: re.Pattern
    confidence: float
    exclude: re.Pattern | None = None  # the sentence must not match this
    subject_ok: bool = False  # may also match the subject line


def _p(status: str, rx: str, conf: float, exclude: str | None = None, subject_ok: bool = False) -> Pattern:
    return Pattern(status, re.compile(rx, _I), conf, re.compile(exclude, _I) if exclude else None, subject_ok)


_FUNDS = r"(?:funds?|assets?|balances?|tokens?|usdt|usdc|amounts?|accounts?|wallets?|address(?:es)?|deposits?|proceeds)"
_EMAILISH = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
_ASSETS = r"USDT|USDC|USD|EUR|GBP|CHF|ETH|BTC|TRX|DAI|BNB|SOL|XRP|EURC|PYUSD|FDUSD|BUSD|TUSD"
# the sender speaking ("we", "I", "we've", "we’ve")
_WE = r"\b(?:we|i)(?:['\u2019]ve\s+|\s+)"
# what can be returned: money, never a wallet / an account / a letter, the payment details or records asked for, or a
# fee ("We have refunded the transfer fee")
_PAPER = r"(?:requests?|forms?|letters?|e-?mails?|messages?|documents?|questionnaires?|applications?|paperwork|" \
         r"correspondence|notices?|envelopes?|parcels?|packages?|reports?|declarations?|claims?|details|records?|" \
         r"history|instructions?|information|data|statements?|confirmations?|receipts?|slips?|cop(?:y|ies)|" \
         r"fees?|charges?|commissions?)"
_NOT_PAPER = r"(?!\s+" + _PAPER + r"\b)"
_MONEY = r"(?:funds?|assets?|balances?|tokens?|usdt|usdc|amounts?|deposits?|proceeds|money|monies|payments?|transfers?|" \
         r"transactions?|sums?)"
_MONEY_OBJECT = (r"(?:(?:the|these|those|this|that|all|your|its|their|such)\s+)?(?:(?:full|entire|remaining|reported|"
                 r"stolen|relevant|frozen|whole|said)\s+)?(?:" + _MONEY + r"\b" + _NOT_PAPER + r"|\d[\d,.' ]*\s?(?:" + _ASSETS + r")\b|"
                 r"(?:" + _ASSETS + r"|US\$|\$|€|£)\s?\d)")
# a return to the suspect / their own card, or a returned e-mail / letter, is no return of the victim's funds
_RETURN_EXCLUDE = (r"\b(?:suspect|perpetrator|scammer|fraudster|offender|account\s+holder)['\u2019]?s?\b|\bto\s+(?:the\s+)?"
                   r"(?:user|customer|client|card)['\u2019]?s?\b|\bto\s+(?:his|her|their)\s+(?:own\s+)?(?:card|account|"
                   r"wallet)\b|\b(?:mailbox|undeliverable|postmaster|mail\s+delivery|delivery\s+(?:failure|status))\b|"
                   # "the funds request form was returned", "Your letter about the transfer was sent back"
                   r"\b" + _PAPER + r"\b(?:(?!\b(?:funds?|assets?|usdt|usdc|amounts?|money|payments?|transfers?|"
                   r"deposits?|tokens?)\b)[^.;]){0,40}?\b(?:was|were|is|are|has\s+been|have\s+been)\s+(?:\w+\s+)?"
                   r"(?:returned|sent\s+back|refunded)\b")
# a platform-wide / maintenance suspension is no hold on the reported account
_PLATFORM_WIDE = (r"\bmaintenance\b|\b(?:network|platform|system|exchange)[- ]wide\b|\bfor\s+all\s+(?:users|customers|"
                  r"clients|accounts)\b|\bsystem\s+upgrade\b|\bfor\s+this\s+(?:token|coin|asset|network)\b|"
                  r"\bscheduled\s+(?:upgrade|downtime)\b")

# what a hold / freeze is placed on: funds or an account ("a hold on the account", "… on all outgoing transfers")
_HOLD_OBJECT = (r"(?:(?:the|this|these|those|that|all|its|their|his|her|said|reported|relevant|affected|associated|"
                r"related|identified|listed|mentioned|above|subject|target|any|further|both|outgoing|incoming|"
                r"(?:suspect|user|customer|client|account\s+holder)['’]?s?)\s+)*(?:accounts?|wallets?|funds?|"
                r"withdrawals?|assets?|balances?|address(?:es)?|deposits?|transfers?|usdt|usdc|tokens?|proceeds|"
                r"amounts?|\d|(?:" + _ASSETS + r")\b)")

PATTERNS: tuple[Pattern, ...] = (
    # ---- funds returned
    # "we have returned": only with a funds / asset object right after the verb, never "we returned your letter /
    # request / the documents"
    _p(FUNDS_RETURNED, _WE + r"(?:have\s+|had\s+)?(?:now\s+|successfully\s+|already\s+)?(?:returned|refunded|"
                       r"reversed|sent\s+back|transferred\s+back|remitted\s+back|credited\s+back)\s+" + _MONEY_OBJECT,
       0.85, exclude=_RETURN_EXCLUDE),
    _p(FUNDS_RETURNED, rf"\b{_MONEY}\b[^.;]{{0,80}}?\b(?:(?:has|have)\s+"
                       r"(?:now\s+|since\s+|already\s+)?been|was|were)\s+(?:now\s+|already\s+|successfully\s+|fully\s+)?"
                       r"(?:returned|refunded|reversed|sent\s+back|credited\s+back|released\s+to\s+the\s+"
                       r"(?:victim|sender|originating|original|owner|claimant))\b", 0.85, exclude=_RETURN_EXCLUDE),
    # "… returned to the victim": a funds word earlier in the sentence ("Your message was returned to the sender"
    # is a bounce, never a return)
    _p(FUNDS_RETURNED, rf"\b{_MONEY}\b[^.;]{{0,80}}?\b(?:returned|refunded|released)\s+to\s+the\s+(?:victim|"
                       r"originating\s+(?:wallet|address|account)|original\s+(?:wallet|address|owner)|rightful\s+owner|"
                       r"claimant)\b", 0.8, exclude=_RETURN_EXCLUDE),
    # ---- frozen
    _p(FROZEN, _WE + r"(?:have\s+|had\s+|has\s+)?(?:now\s+|successfully\s+|already\s+|immediately\s+)?(?:frozen|"
               r"froze|blacklisted|blocklisted|seized|immobili[sz]ed)\b", 0.9),
    _p(FROZEN, r"\b(?:we|i)\s+did\s+(?:freeze|block|blacklist|blocklist|seize)\s+(?:the\s+|these\s+|those\s+|this\s+|"
               r"that\s+|all\s+)?" + _FUNDS + r"\b", 0.85),
    _p(FROZEN, r"\bour\s+(?:[a-z]+\s+){0,2}team\s+(?:has\s+)?(?:now\s+|already\s+)?(?:froze|frozen|blacklisted|"
               r"blocklisted|blocked|locked)\s+(?:the\s+|these\s+|those\s+|this\s+|that\s+|all\s+)?" + _FUNDS + r"\b",
       0.85),
    _p(FROZEN, _WE + r"(?:have\s+|had\s+)?(?:now\s+|successfully\s+|already\s+)?(?:blocked|locked)\s+(?:the\s+|"
               r"these\s+|those\s+|this\s+|that\s+|all\s+)?" + _FUNDS + r"\b", 0.85),
    # "we have / we've / our compliance department has blocked \u2026": the sender as the subject, never "The bank has
    # frozen \u2026", "Tether has frozen the address", "Nobody has frozen \u2026"
    _p(FROZEN, r"(?:\b(?:we|i)\s+(?:have|has)\s+|\b(?:we|i)['\u2019]ve\s+|\bour\s+(?:[a-z-]+\s+){0,2}(?:team|department|"
               r"unit|desk|staff)\s+(?:has|have)\s+)(?:now\s+|already\s+|successfully\s+)?(?:frozen|blacklisted|blocklisted|"
               r"blocked|locked)"
               r"\s+(?:the\s+|this\s+|these\s+|those\s+|that\s+|all\s+|your\s+)?(?:reported\s+|relevant\s+)?"
               + _FUNDS + r"\b", 0.85),
    _p(FROZEN, rf"\b{_FUNDS}\b[^.;]{{0,80}}?\b(?:has|have)\s+(?:now\s+|already\s+|successfully\s+)?been\s+(?:frozen|"
               r"blocked|locked|blacklisted|blocklisted|seized|immobili[sz]ed)\b", 0.9),
    _p(FROZEN, rf"\b{_FUNDS}\b[^.;]{{0,60}}?\b(?:is|are|remain|remains)\s+(?:now\s+|currently\s+|still\s+)?(?:frozen|"
               r"locked|blocked|blacklisted|blocklisted)\b", 0.85),
    _p(FROZEN, rf"\b{_FUNDS}\b[^.;]{{0,60}}?\b(?:was|were)\s+(?:now\s+|already\s+|successfully\s+|immediately\s+)?"
               r"(?:frozen|blocked|locked|blacklisted|blocklisted|seized)\b", 0.85),
    _p(FROZEN, r"\b(?:a\s+)?(?:total\s+|balance\s+|amount\s+)?of\s+[^.;]{0,40}\b(?:has|have)\s+been\s+frozen\b", 0.85),
    # "2.1 ETH have been frozen on the account" (an amount and its asset as the subject)
    _p(FROZEN, r"(?<![\w,.])\d[\d,.' ]*\s?(?:" + _ASSETS + r")\b[^.;]{0,30}?\b(?:has|have)\s+(?:now\s+|already\s+)?been\s+"
               r"(?:frozen|blacklisted|blocklisted|seized)\b", 0.85),
    _p(FROZEN, r"\b(?:added|included|listed|placed)\s+(?:to|on|in)\s+(?:our|the)\s+(?:internal\s+)?(?:block\s*list|"
               r"black\s*list|blocklist|blacklist|freeze\s+list|deny\s*list|sanctions?\s+list)\b", 0.85),
    _p(FROZEN, r"\b(?:confirm|implemented|applied|executed|enforced)\s+(?:a|the)\s+freeze\s+(?:of|on)\b", 0.85),
    _p(FROZEN, r"\b(?:a|the)\s+freeze\b[^.;]{0,60}?\b(?:is|remains)\s+(?:now\s+|currently\s+|still\s+)?in\s+place\b",
       0.85),
    _p(FROZEN, rf"\b{_FUNDS}\b[^.;]{{0,80}}?\b(?:is|are|was|were|has\s+been|have\s+been)\s+(?:now\s+|currently\s+|"
               r"successfully\s+|already\s+)?(?:subject\s+to\s+a\s+freeze|under\s+(?:a\s+)?freeze)\b", 0.85),
    _p(FROZEN, r"\b(?:abbiamo|sono\s+stat[ie]|è\s+stat[oa])\s+(?:congelat[oiae]|bloccat[oiae])\b", 0.85),
    _p(FROZEN, r"\b(?:wurden|wurde|haben\s+wir|ist|sind)\b[^.;]{0,60}?\b(?:eingefroren|gesperrt)\b", 0.85),
    _p(FROZEN, r"\bwir\s+haben\b[^.;]{0,60}?\b(?:eingefroren|gesperrt)\b", 0.85),
    _p(FROZEN, r"\b(?:nous\s+avons|ont\s+été|a\s+été)\s+(?:gel[ée]s?|bloqu[ée]s?)\b", 0.85),
    _p(FROZEN, r"\b(?:hemos|han\s+sido|ha\s+sido)\s+(?:congelad[oa]s?|bloquead[oa]s?)\b", 0.85),
    # ---- hold placed
    # "we have temporarily frozen the account associated with the deposit address" (a provisional freeze: a hold)
    _p(HOLD_PLACED, _WE + r"(?:have\s+|had\s+|has\s+)?(?:now\s+|already\s+|immediately\s+)?(?:temporarily|"
                    r"provisionally|precautionarily|preventively)\s+(?:frozen|froze|blocked|locked|restricted|suspended)"
                    r"\s+" + _HOLD_OBJECT, 0.85, exclude=_PLATFORM_WIDE),
    # "placed a hold (on the account / the funds / withdrawals)": what follows "on" must be funds or an account, never
    # "a hold on processing your request", "a block on further e-mails", "a freeze on new sign-ups"; a flag is no hold
    _p(HOLD_PLACED, r"\b(?:placed|put|applied|imposed|implemented|set)\s+(?:an?\s+|the\s+)?(?:temporary\s+|"
                    r"precautionary\s+|preventive\s+|preventative\s+|internal\s+|risk\s+)?(?:hold|freeze|restriction|"
                    r"block|lock)s?\b(?!\s+request)(?!\s+(?:on|upon|against|over|to)\s+(?!" + _HOLD_OBJECT + r"))",
       0.85, exclude=_PLATFORM_WIDE),
    _p(HOLD_PLACED, r"\b(?:restricted|suspended|limited|disabled)\s+(?:the\s+|this\s+|these\s+|that\s+|all\s+)?"
                    r"(?:user'?s?\s+|customer'?s?\s+|client'?s?\s+|relevant\s+|associated\s+|related\s+)?"
                    r"(?:account|accounts|withdrawals?|wallet|outgoing\s+transfers?)\b", 0.85, exclude=_PLATFORM_WIDE),
    _p(HOLD_PLACED, r"\b(?:hold|restriction|freeze)\b[^.;]{0,60}?\b(?:has|have)\s+been\s+(?:placed|put|applied|"
                    r"imposed|implemented|set)\b", 0.85, exclude=_PLATFORM_WIDE),
    _p(HOLD_PLACED, r"\b(?:account|accounts|withdrawals?|wallets?|funds?|amounts?|balances?|assets?|deposits?)\b"
                    r"[^.;]{0,60}?\b(?:has|have)\s+been\s+"
                    r"(?:restricted|suspended|limited|disabled|put\s+on\s+hold|placed\s+on\s+hold|placed\s+under\s+review)\b",
                    0.85, exclude=_PLATFORM_WIDE),
    _p(HOLD_PLACED, rf"\b{_FUNDS}\b[^.;]{{0,50}}?\b(?:is|are|remain|remains)\s+(?:now\s+|currently\s+)?(?:on|under)\s+"
                    r"(?:an?\s+)?(?:temporary\s+|precautionary\s+)?hold\b", 0.85, exclude=_PLATFORM_WIDE),
    _p(HOLD_PLACED, r"\b(?:a|the)\s+(?:temporary\s+|precautionary\s+)?(?:hold|restriction)\b[^.;]{0,60}?\b(?:is|remains)\s+"
                    r"(?:now\s+|currently\s+|still\s+)?in\s+place\b", 0.8, exclude=_PLATFORM_WIDE),
    _p(HOLD_PLACED, rf"\b{_FUNDS}\b[^.;]{{0,60}}?\b(?:is|are|remain|remains)\s+(?:now\s+|currently\s+|still\s+)?"
                    r"(?:being\s+)?held\b(?!\s+by\b)", 0.7, exclude=_PLATFORM_WIDE),
    # ---- declined: no account / no assets / non-custodial
    _p(DECLINED_NO_ASSETS, r"\b(?:could|can|were|are|was|did)\s*(?:not|n't)\s+(?:able\s+to\s+)?(?:find|locate|identify|"
                           r"match)\b[^.;]{0,80}?\b(?:account|user|customer|client|assets?|funds?|records?|deposits?)", 0.8),
    _p(DECLINED_NO_ASSETS, r"\b(?:unable|not\s+able)\s+to\s+(?:find|locate|identify|match)\b[^.;]{0,80}?\b(?:account|user|"
                           r"customer|client|assets?|funds?|records?|deposits?)", 0.8),
    _p(DECLINED_NO_ASSETS, r"\bno\s+(?:matching\s+|associated\s+|such\s+|related\s+|corresponding\s+|active\s+)?"
                           r"(?:accounts?|users?|customers?|clients?|records?|assets?|funds?|balances?)\b[^.;]{0,60}?\b"
                           r"(?:found|associated|identified|held|linked|exists?|with\s+us|on\s+our\s+(?:platform|"
                           r"exchange)|at\s+(?:this|that|the)\s+address|could\s+be)", 0.8),
    _p(DECLINED_NO_ASSETS, r"\b(?:is|are|was|were)\s+not\s+(?:a\s+|our\s+|one\s+of\s+our\s+)?(?:customer|client|user|"
                           r"account\s+holder)s?\b|\bnot\s+(?:one\s+of\s+)?our\s+(?:customer|client|user)s?\b", 0.8),
    _p(DECLINED_NO_ASSETS, r"\bnon[- ]custodial\b|\b(?:do|does)\s+not\s+(?:hold|custody|control|take\s+custody\s+of|"
                           r"have\s+(?:custody|control)\s+(?:of|over))\s+(?:user\s+|customer\s+|client\s+|any\s+|the\s+)?"
                           r"(?:funds|assets|keys|private\s+keys|tokens)\b", 0.8),
    _p(DECLINED_NO_ASSETS, r"\b(?:does|do)\s+not\s+belong\s+to\s+(?:us|our|any\s+of\s+our)\b|\bnot\s+(?:an?\s+)?"
                           r"(?:address|wallet)\s+(?:that\s+)?(?:belongs\s+to|controlled\s+by|operated\s+by)\s+(?:us|our)\b",
                           0.8),
    _p(DECLINED_NO_ASSETS, r"\bno\s+(?:assets?|funds?|balance)\s+(?:remains?|is\s+left|are\s+left|left)\b|"
                           r"\b(?:funds?|assets?|balance)\b[^.;]{0,60}?\b(?:were|was|have\s+been|has\s+been)\s+(?:fully\s+|"
                           r"subsequently\s+|since\s+)?withdrawn\b", 0.75),
    _p(DECLINED_NO_ASSETS, r"\b(?:funds?|assets?|balance)\b[^.;]{0,40}?\b(?:had\s+|have\s+|has\s+)?already\s+(?:been\s+)?"
                           r"(?:withdrawn|moved\s+out|transferred\s+out|swept|spent)\b|\b(?:zero|nil)\s+balance\b|"
                           r"\bbalance\s+(?:is|was)\s+(?:now\s+)?(?:zero|0(?:\.0+)?)\b|"
                           r"\b(?:withdrew|has\s+withdrawn|have\s+withdrawn)\s+(?:all\s+(?:of\s+)?)?(?:the\s+|their\s+|"
                           r"his\s+|her\s+)?(?:remaining\s+)?(?:funds|assets|balance)\b", 0.75),
    # ---- law-enforcement process required
    _p(LE_PROCESS_REQUIRED, r"\b(?:submit|submitted|file|filed|send|sent|lodge|lodged|made|make|route|routed)\b[^.;]{0,60}?"
                            r"\b(?:through|via|using|on|at|in)\b[^.;]{0,40}?\b(?:portal|kodex|lers|le\s+response|"
                            r"request\s+system|online\s+form)\b", 0.85),
    _p(LE_PROCESS_REQUIRED, r"\bkodex\b", 0.75),
    _p(LE_PROCESS_REQUIRED, r"\b(?:law[- ]enforcement|government|police|legal)\s+(?:request\s+|response\s+)?portal\b", 0.8),
    _p(LE_PROCESS_REQUIRED, r"\b(?:valid|formal|proper|official|appropriate|binding|duly\s+issued)\s+(?:legal\s+(?:process|"
                            r"request|order|demand)|court\s+order|subpoena|warrant|law[- ]enforcement\s+request|request\s+"
                            r"from\s+(?:law[- ]enforcement|a\s+law[- ]enforcement\s+agency|the\s+authorities|police|a\s+"
                            r"competent\s+authority))", 0.85),
    _p(LE_PROCESS_REQUIRED, r"\b(?:require|requires|required|need|needs|must\s+(?:receive|have|obtain|be\s+accompanied\s+by)|"
                            r"can\s+only|will\s+only|may\s+only|only\s+(?:act|respond|accept|comply|freeze|disclose))\b"
                            r"[^.;]{0,60}?\b(?:subpoena|court\s+order|warrant|legal\s+process|mlat|freezing\s+order|"
                            r"seizure\s+order|judicial\s+order|law[- ]enforcement\s+(?:request|agency|authority|officer)|"
                            r"request\s+(?:from|by)\s+(?:law[- ]enforcement|the\s+police|police|a\s+competent\s+authority))",
                            0.85),
    _p(LE_PROCESS_REQUIRED, r"\b(?:unable|not\s+able|cannot|can't|can\s*not)\s+(?:to\s+)?(?:act|freeze|disclose|share|"
                            r"provide|release|comply|assist|take\s+action)\b[^.;]{0,80}?\b(?:without|absent|unless|until)\b"
                            r"[^.;]{0,60}?\b(?:subpoena|court|warrant|legal|law[- ]enforcement|police|judicial|order|"
                            r"authorit)", 0.85),
    _p(LE_PROCESS_REQUIRED, r"\b(?:provide|submit|send|obtain|present|serve)\b[^.;]{0,40}?\b(?:court\s+order|subpoena|"
                            r"warrant|freezing\s+order|seizure\s+order|judicial\s+order|legal\s+process|mlat)\b", 0.8),
    _p(LE_PROCESS_REQUIRED, r"\b(?:once|when|upon|after|until)\s+(?:we\s+)?(?:receive|receipt\s+of|receiving|obtain|"
                            r"have\s+received)\b[^.;]{0,40}?\b(?:court\s+order|subpoena|warrant|legal\s+process|"
                            r"freezing\s+order|law[- ]enforcement\s+request|judicial|formal\s+request\s+from)", 0.8),
    # "contact local law enforcement", "the law enforcement department managing the case must directly submit all
    # requests", "direct law enforcement to <address>" (an issuer's standard refusal of a private request)
    _p(LE_PROCESS_REQUIRED, r"\b(?:recommend|suggest|advise|ask)\b[^.;]{0,30}?\b(?:contact|reach\s+out\s+to|report\s+"
                            r"(?:this|it)\s+to)\s+(?:your\s+|the\s+)?(?:local\s+|relevant\s+|competent\s+)?"
                            r"(?:law[- ]enforcement|police|authorities)\b", 0.85),
    _p(LE_PROCESS_REQUIRED, r"\b(?:law[- ]enforcement|police|authorit(?:y|ies))\b[^.;]{0,60}?\bmust\s+(?:directly\s+)?"
                            r"(?:submit|send|file|make)\b|\bdirect\s+(?:the\s+)?(?:law[- ]enforcement|police)\b[^.;]{0,20}?"
                            r"\bto\b", 0.85),
    _p(LE_PROCESS_REQUIRED, r"\b(?:only|exclusively)\s+(?:from|to|with|respond\s+to|accept\s+requests?\s+from)\s+"
                            r"(?:law[- ]enforcement|government|competent\s+authorit|the\s+police|police)", 0.8),
    # a generic LE-only refusal (Gate-style): "this channel is for law enforcement only and is not intended for private
    # parties ... report to your local police, who can contact us"
    _p(LE_PROCESS_REQUIRED, r"\bfor\s+(?:use\s+by\s+)?(?:law[- ]enforcement|government\s+agencies|the\s+authorities)\s+"
                            r"(?:agencies\s+|officials\s+)?only\b|\bnot\s+intended\s+for\s+private\s+(?:parties|"
                            r"individuals|persons)\b|\breport\s+(?:it\s+|this\s+|the\s+(?:matter|incident)\s+)?to\s+"
                            r"(?:your\s+)?(?:local\s+)?(?:police|law[- ]enforcement)\b[^.;]{0,40}?\b(?:who|which)\s+"
                            r"(?:can|may|will)\s+(?:then\s+)?(?:contact|reach\s+out\s+to|request|submit)", 0.8),
    _p(LE_PROCESS_REQUIRED, r"\b(?:richiesta|ordine|provvedimento)\s+(?:formale\s+)?(?:dell'?\s*|da\s+parte\s+dell'?\s*)?"
                            r"autorit[aà]\s+giudiziaria\b|\bgerichtliche[nrs]?\s+(?:beschluss|anordnung)\b|"
                            r"\brichterliche[nrs]?\s+beschluss\b|\bréquisition\s+judiciaire\b|\bordonnance\s+(?:du\s+"
                            r"tribunal|judiciaire)\b|\borden\s+judicial\b|\brequerimiento\s+judicial\b", 0.8),
    # ---- information requested
    _p(INFO_REQUESTED, r"\b(?:please|kindly|could\s+you|can\s+you|would\s+you|we\s+(?:would\s+)?(?:need|require|request|"
                       r"ask)(?:\s+you)?\s+to)\s+(?:also\s+)?(?:provide|send|share|supply|confirm|clarify|forward|"
                       r"attach|furnish)\b", 0.75, exclude=rf"{_EMAILISH}|https?://|\bportal\b|\bvia\b|\bthrough\b|"
                       r"\bcourt\s+order\b|\bsubpoena\b|\bwarrant\b|\blegal\s+process\b|\bjudicial\b|\bmlat\b"),
    _p(INFO_REQUESTED, r"\b(?:we|i)\s+(?:will\s+|would\s+|also\s+|first\s+)*(?:need|require|request)\s+(?:a\s+|the\s+|an?\s+"
                       r"(?:official|certified|signed)\s+)?(?:copy|copies|scan|certified\s+copy)\s+of\b", 0.75),
    _p(INFO_REQUESTED, r"\b(?:additional|further|more|missing)\s+(?:information|details|documentation|documents|evidence)"
                       r"\b[^.;]{0,60}?\b(?:required|needed|necessary|is\s+needed|are\s+needed)\b|\bwe\s+(?:need|require|"
                       r"would\s+need)\s+(?:additional|further|more|the\s+following)\s+(?:information|details|documents|"
                       r"documentation)", 0.75),
    # ---- declined (no reason recognised)
    _p(DECLINED, r"\b(?:must|have\s+to|will|are\s+(?:unable|not\s+able)\s+to|cannot|can\s*not|can't|won't|will\s+not)\s+"
                 r"(?:respectfully\s+)?(?:decline|refuse|reject)\b", 0.75),
    _p(DECLINED, r"\b(?:we\s+)?(?:respectfully\s+)?(?:declin(?:e|ed|ing)|reject(?:ed|ing)?|refus(?:e|ed|ing))\s+(?:your|"
                 r"the|this)\s+(?:request|demand|application)\b", 0.75),
    _p(DECLINED, r"\b(?:unable|not\s+able|not\s+in\s+a\s+position)\s+to\s+(?:assist|help|act\s+on|comply\s+with|action|"
                 r"accommodate|fulfil|fulfill)\b", 0.65),
    # ---- redirected
    _p(REDIRECTED, r"\b(?:legacy|deprecated|retired|decommissioned|unmonitored|no\s+longer\s+(?:monitored|in\s+use|"
                   r"active|used|checked|valid|available))\b[^.;]{0,40}?\b(?:inbox|mailbox|address|e-?mail|channel|"
                   r"alias|account)\b", 0.9),
    _p(REDIRECTED, r"\b(?:inbox|mailbox|address|e-?mail(?:\s+address)?|alias)\b[^.;]{0,40}?\b(?:is|has\s+been)\s+"
                   r"(?:no\s+longer\s+(?:monitored|in\s+use|active|used)|not\s+(?:actively\s+)?monitored|deprecated|"
                   r"retired|discontinued|a\s+legacy)\b", 0.9),
    _p(REDIRECTED, r"\b(?:please|kindly)\s+(?:re-?send|re-?submit|re-?direct|contact|reach\s+out\s+to|write\s+to|e-?mail|"
                   r"send\s+(?:your|the|this|all)?\s*(?:request|inquiry|enquiry|correspondence|e-?mail|message)s?\s+to|"
                   r"direct\s+(?:your|the|this|all)?\s*(?:request|inquiry|enquiry)s?)\b[^.;]{0,120}?"
                   rf"(?:{_EMAILISH}|\bthe\s+following\b|\bbelow\b)", 0.8),
    _p(REDIRECTED, r"\b(?:contact|reach|write\s+to)\s+the\s+following\b", 0.8),
    _p(REDIRECTED, r"\b(?:wrong|incorrect)\s+(?:address|department|team|recipient|contact|mailbox)\b|\bnot\s+the\s+"
                   r"(?:correct|right|appropriate|proper)\s+(?:address|department|team|channel|contact|mailbox)\b", 0.8),
    # ---- acknowledged
    _p(ACKNOWLEDGED, r"\b(?:we\s+)?(?:have\s+)?(?:received|receive|acknowledge(?:\s+receipt\s+of)?)\s+(?:your|the|this)"
                     r"\s+(?:[a-z-]+\s+){0,2}?(?:request|e-?mail|message|letter|inquiry|enquiry|correspondence|submission|report)\b", 0.7,
       subject_ok=False),
    _p(ACKNOWLEDGED, r"\b(?:your|the|this)\s+(?:request|e-?mail|message|letter|inquiry|enquiry|submission|case|ticket|"
                     r"report)\s+(?:has\s+been|was|is\s+being|is)\s+(?:received|logged|registered|recorded|created|"
                     r"opened|escalated|forwarded|assigned|reviewed|under\s+review)\b", 0.75),
    _p(ACKNOWLEDGED, r"\b(?:ticket|case|request|reference|incident|inquiry|enquiry)\s*(?:number|no|nr|id)?\s*[:#]?\s*#?\s*"
                     r"(?=[A-Z0-9_/,-]*\d)[A-Z0-9][A-Z0-9_/,-]{2,40}\s+(?:has\s+been|was|is)\s+(?:created|opened|logged|registered|raised|"
                     r"assigned|recorded)\b", 0.75),
    # a ticket system: "Your support request has been opened and assigned case number: #500123"
    _p(ACKNOWLEDGED, r"\b(?:has\s+been|was)\s+(?:created|opened|logged|raised|registered)\s+and\s+assigned\s+(?:the\s+)?"
                     r"(?:ticket|case|reference|request)\s*(?:number|no|nr|id)?\b", 0.7),
    _p(ACKNOWLEDGED, r"\byour\s+(?:ticket|case|request|incident|support\s+request)\s*(?:number|no|nr|id|reference)?\s*"
                     r"(?:is|has\s+been\s+assigned)\s+(?:the\s+)?(?:number\s+)?#?\s*(?=[A-Z0-9_/,-]*\d)"
                     r"[A-Z0-9][A-Z0-9_/,-]{2,40}", 0.7),  # a number, never "Your case is closed"
    _p(ACKNOWLEDGED, r"\b(?:we\s+are|we're|we\s+will(?:\s+be)?|our\s+(?:[a-z]+\s+){0,2}team\s+(?:is|"
                     r"will(?:\s+be)?))\s+(?:now\s+|currently\s+)?(?:review|reviewing|looking\s+into|investigating|"
                     r"examining|assessing|processing|handling)\b", 0.75),
    _p(ACKNOWLEDGED, r"\b(?:forwarded|escalated|routed|passed|referred)\s+(?:your\s+(?:request|e-?mail|message)\s+|this\s+|"
                     r"it\s+)?to\s+(?:the\s+|our\s+)?(?:relevant|appropriate|correct|responsible|compliance|legal|"
                     r"investigations?)\s+(?:team|department|unit)\b", 0.7),
    _p(ACKNOWLEDGED, r"\bthank\s+you\s+for\s+(?:your|contacting|reaching|the)\b", 0.45),
    _p(ACKNOWLEDGED, r"\babbiamo\s+ricevuto\b|\bwir\s+haben\s+ihre\b[^.;]{0,40}\berhalten\b|\bnous\s+avons\s+bien\s+reçu\b|"
                     r"\bhemos\s+recibido\b", 0.7),
    # ---- automatic reply / out of office
    _p(AUTO_REPLY, r"\b(?:out\s+of\s+(?:the\s+)?office|on\s+(?:annual\s+|parental\s+|sick\s+)?leave|on\s+vacation|"
                   r"on\s+holiday|currently\s+away|away\s+from\s+(?:the\s+|my\s+)?(?:office|desk)|limited\s+access\s+to\s+"
                   r"(?:my\s+)?e-?mail|return\s+to\s+the\s+office\s+on)\b", 0.85, subject_ok=True),
    _p(AUTO_REPLY, r"\b(?:this\s+is\s+an?\s+)?(?:automated|automatic|auto[- ]?generated|auto[- ]?reply|auto[- ]?response|"
                   r"automatic\s+reply|automatic\s+acknowledg(?:e)?ment)\b", 0.6, subject_ok=True),
    _p(AUTO_REPLY, r"\bdo\s+not\s+reply\s+to\s+this\b|\bplease\s+do\s+not\s+respond\s+to\s+this\b", 0.5),
    _p(AUTO_REPLY, r"\brisposta\s+automatica\b|\bfuori\s+(?:ufficio|sede)\b|\bautomatische\s+antwort\b|\babwesen(?:d|heit)\b|"
                   r"\bréponse\s+automatique\b|\babsent(?:e)?\s+du\s+bureau\b|\brespuesta\s+automática\b|"
                   r"\bfuera\s+de\s+la\s+oficina\b", 0.8, subject_ok=True),
)

# ---------------------------------------------------------------------------- the guard of a positive outcome
# Negations: English ("n't" with the ASCII or the typographic apostrophe Outlook writes, "haven’t"), German, Italian,
# French ("ne … pas", "n'ont pas") and Spanish; a refusal and "zero / nil" are negations too.
_NEG_WORDS = (r"not|no|never|cannot|unable|without|neither|nor|nothing|none|nobody|no-one|zero|nil|refus(?:e|es|ed|ing)|"
              r"declin(?:e|es|ed|ing)|fail(?:s|ed)?\s+to|"
              r"nicht|nichts|kein\w*|nie|niemals|non|mai|nessun\w*|niente|nulla|ne|pas|jamais|aucun\w*|"
              r"nunca|ningun\w*|ningún|nada|tampoco")
_NEGATION = re.compile(rf"\b(?:{_NEG_WORDS})\b|n['’]t\b|\bn['’](?=[a-zà-ÿ])", _I)
# what follows the outcome word in its clause: "A hold has not been placed", "Frozen: no.", "frozen? no"
_CLAUSE_END = re.compile(r"[;,]|\b(?:and|but|however|while|whereas|although|though|so|which|therefore|thus)\b", _I)
# … also a negated object ("We have frozen nothing", "… none of the assets") or a disputed claim ("… are inaccurate")
_AFTER_NEGATION = re.compile(r"\b(?:not|no|never|nothing|none|nobody|zero|nil|refus\w*|declin\w*|unable|cannot|false|incorrect|"
                             r"inaccurate|untrue|wrong|nicht|nichts|kein\w*|nie|niemals|non|mai|nessun\w*|pas|jamais|"
                             r"aucun\w*|nunca|ningun\w*|ningún|nada)\b|n['’]t\b", _I)
# right after the outcome word: it was only considered / asked for ("A hold was considered but not placed")
_NOT_DONE = re.compile(r"^\W*(?:was|were|is|are|has\s+been|have\s+been|had\s+been|being)\s+(?:only\s+|briefly\s+)?"
                       r"(?:considered|requested|proposed|discussed|recommended|suggested|contemplated|planned|"
                       r"evaluated|asked\s+for|sought)\b", _I)
# "… but not placed", "… but it was never applied": the next clause negates the outcome's own verb
_BUT_NOT = re.compile(r"\bbut\s+(?:(?:it|this|that|they|was|were|is|are|has|have|had|been|yet|ultimately|eventually|"
                      r"then|in\s+the\s+end)\s+){0,3}(?:not|never|\w+n['’]t)\s+(?:(?:been|yet|actually|ultimately|"
                      r"be)\s+)*(?:placed|put|applied|implemented|imposed|set|executed|enforced|effected|actioned|"
                      r"carried\s+out|frozen|froze|blocked|locked|blacklisted|blocklisted|seized|restricted|suspended|"
                      r"limited|disabled|held|done|in\s+place)\b", _I)
_AFTER_WINDOW = 60
# conditional, future, intention or need before the outcome ("if we freeze", "we plan to put a hold", "we are going
# to", "we need a court order to put a hold", "… to freeze")
_CONDITIONAL = re.compile(r"\b(?:if|once|when|whether|should|would|could|may|might|can|will|shall|upon|before|until|"
                          r"unless|in\s+order\s+to|able\s+to|requests?\s+(?:that|to)|requested\s+(?:that|to)|"
                          r"ask(?:s|ed|ing)?\s+(?:us\s+)?(?:that|to)|asked\s+us|wish(?:es)?\s+to|want(?:s)?\s+to|"
                          r"seek(?:s|ing)?\s+to|demand(?:s|ed)?\s+(?:that|to)|plan(?:s|ned|ning)?\s+to|"
                          r"intend(?:s|ed|ing)?\s+to|intention|going\s+to|about\s+to|need(?:s|ed)?|require(?:s|d)?|"
                          r"expect(?:s|ed)?\s+to|aim(?:s|ed)?\s+to|prepared\s+to|ready\s+to|propose(?:s|d)?\s+to|"
                          r"decided\s+to|tomorrow|next\s+(?:week|month|business\s+day)|"
                          # "In the event of a court order, …", "Assuming your information is correct, …", "In case the
                          # court approves, …", "Where a court order is received, …", "on receipt of a court order"
                          r"in\s+the\s+event|in\s+case|assum(?:e|es|ed|ing)|provided|providing|"
                          r"where\s+(?:a|an|such|there|we|you|it|any|the\s+court)|on\s+(?:the\s+)?receipt\s+of|"
                          r"following\s+(?:the\s+)?receipt|"
                          r"to\s+(?:put|place|set|apply|impose|implement|freeze|block|lock|blacklist|blocklist|restrict|"
                          r"suspend|limit|disable|return|refund|reverse|seize|hold))\b", _I)
# the same after the outcome, in its clause: "frozen only upon receipt of a court order", "frozen only if a court so
# orders", "frozen as of tomorrow"
_COND_AFTER = re.compile(r"\b(?:only|if|unless|once|provided|providing|assuming|subject\s+to|would|will|shall|"
                         r"tomorrow|whenever)\b|\bin\s+(?:the\s+event|case)\b|"
                         # "Accounts are frozen on receipt of a court order", "Funds are frozen after we receive a court
                         # order" (never "after we received your letter")
                         r"\bon\s+(?:the\s+)?receipt\s+of\b|\bfollowing\s+(?:the\s+)?receipt\b|"
                         r"\bafter\s+(?:we\s+|they\s+)?(?:receive|receiving|receipt)\b|"
                         r"\bupon\s+(?:receipt\s+of\s+)?(?:a|an|the)\s+(?:valid\s+|formal\s+|binding\s+|corresponding\s+)?"
                         r"(?:court|order|subpoena|warrant|legal|judicial|request|freezing)|\bas\s+of\s+(?:tomorrow|next|\d)|"
                         r"\b(?:from|starting|effective|beginning)\s+(?:tomorrow|next|on\s+\d)|"
                         r"\bnext\s+(?:week|month|business\s+day|monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b|"
                         r"\bin\s+(?:such|these|most|all|similar)\s+cases\b|\bas\s+a\s+rule\b|"
                         # "restricted until 18 October", "frozen until yesterday": it may have ended
                         r"\buntil\s+(?:\d|yesterday|today|last|recently|the\s+\d|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|"
                         r"oct|nov|dec)[a-z]*\b)", _I)
# harmless phrasings that contain a modal ("we can confirm that …", "we would like to inform you …")
_HARMLESS = re.compile(r"\b(?:can|could|would\s+like\s+to|wish\s+to|want\s+to|are\s+pleased\s+to|are\s+writing\s+to|"
                       r"(?:are|is|am)\s+(?:now\s+)?able\s+to|hereby|herewith)\s+(?:confirm|inform|advise|"
                       r"let\s+you\s+know|notify|update|report|state)\b|"
                       r"\bplease\s+be\s+advised\b|\bwe\s+write\s+to\s+(?:confirm|inform)\b", _I)
# someone else's claim, a hedge, a request back to us, a quotation or a policy rather than the sender stating the
# outcome: "In your letter you state that the funds have been frozen", "Reports that the account was frozen are
# inaccurate", "We believe the funds have been frozen by the receiving exchange", "Please confirm the funds have been
# frozen on your side", "As you wrote, "the funds have been frozen", …", "Normally, accounts … are frozen within 24 hours"
_HEARSAY = re.compile(
    r"\byou\s+(?:state|stated|states|wrote|write|say|said|claim(?:ed)?|mention(?:ed)?|allege(?:d)?|believe|assume|think|"
    r"suggest(?:ed)?|indicate(?:d)?|report(?:ed)?|informed\s+us)\b|"
    r"\byour\s+(?:letter|request|e-?mail|message|notice|report|correspondence)\s+(?:states?|stated|says?|said|claims?|"
    r"claimed|mentions?|mentioned|suggests?|indicates?|alleges?)\b|\bin\s+your\s+(?:letter|request|e-?mail|message|"
    r"notice|report)\b|\bas\s+you\s+(?:wrote|write|say|said|state|stated|mention(?:ed)?|claim(?:ed)?|suggest(?:ed)?)\b|"
    r"\b(?:claims?|reports?|allegations?|assertions?|suggestions?|statements?|rumou?rs?)\s+that\b|"
    r"\b(?:believe[sd]?|understand|understands|understood|assume[sd]?|appears?|appeared|seems?|seemed|suspects?|"
    r"suspected|thinks?|alleged(?:ly)?|reportedly|apparently|supposedly|presumably|possibly|probably|likely|perhaps|"
    r"maybe)\b|\bit\s+is\s+(?:incorrect|untrue|false|not\s+true|not\s+correct|wrong|inaccurate)\s+that\b|"
    r"\baccording\s+to\s+(?!our\b|my\b|us\b)|\b(?:please|kindly)\s+(?:confirm|verify|check|advise|let\s+us\s+know|tell\s+us|ensure)\b|"
    r"[\"“”„«»]|(?:^|\s)['‘]|"
    r"\b(?:normally|usually|typically|generally|ordinarily|customarily|routinely|always|whenever)\b|"
    # a statement reported by anyone ("We were told …", "The user informs us that …", "The customer says …", "The
    # investigator's letter states that …", "Earlier, the officer wrote: …", "Our earlier e-mail said …"), never "the
    # said account", "the United States"
    r"\b(?:told|tells?|inform(?:s|ed)|says|(?<!\bthe\s)said|(?<!\bunited\s)states|stated|wrote|writes|written|"
    r"report(?:s|ed)|mention(?:s|ed)|claim(?:s|ed)|alleg(?:es|ed)|assert(?:s|ed)|indicat(?:es|ed)|notified|"
    r"advised\s+(?:us|me)|heard|learned|learnt)\b"
    # … as a verb: "the reported account", "the above-mentioned wallet", "the stated amount" are no report
    r"(?!\s+(?:accounts?|address(?:es)?|wallets?|funds?|assets?|transactions?|transfers?|deposits?|amounts?|balances?|"
    r"tokens?|usdt|usdc|case|incident|fraud|scam|theft|request|confirmation|notice|order|sum|value)\b)|"
    r"\b(?:earlier|previous|prior|last|original)\s+(?:e-?mail|message|letter|reply|response|correspondence|notice)\b|"
    # a mistake: "We mistakenly reported …", "erroneously", "in error"
    r"\b(?:mistaken(?:ly)?|erroneous(?:ly)?|wrongly|incorrectly|inadvertently|accidentally)\b|\bin\s+error\b|"
    r"\bas\s+a\s+(?:rule|matter\s+of\s+(?:policy|course))\b|\bin\s+(?:such|these|most|all|similar)\s+cases\b|"
    r"\bour\s+(?:policy|practice|procedure|process)\b|\bstandard\s+(?:practice|procedure)\b|\bper\s+(?:our\s+)?policy\b",
    _I)
# a zero amount: "Zero funds have been frozen" (_NEGATION), "0 USDT has been frozen", "We have frozen 0 USDT"
_ZERO = r"0+(?:[.,]0+)?(?![.,]?\d)(?![a-z])"
_ZERO_BEFORE = re.compile(rf"(?<![\d,.'])(?<!\d\s)\b{_ZERO}\s?(?:{_ASSETS})\b|(?:US\$|\$|€|£)\s?{_ZERO}", _I)
_ZERO_AFTER = re.compile(rf"^\W*(?:(?:a\s+total|an?\s+(?:amount|sum|balance))\s+of\s+)?(?:(?:{_ASSETS}|US\$|\$|€|£)\s?)?"
                         rf"{_ZERO}", _I)
# the rest of the sentence after the outcome disowns it: another party, another account, a disputed claim
# ("frozen by the sending exchange, not by us", "…, according to the user", "We froze a different account …, not the
# one you reported", "restricted at the request of another agency, not in response to your letter")
_DISCLAIM_AFTER = re.compile(
    r"\bnot\s+(?:by\s+|from\s+)?(?:us|ourselves|our\s+(?:team|exchange|platform|company|side))\b|"
    r"\bnot\s+the\s+(?:one|ones|account|accounts|wallet|wallets|address|addresses|funds)\s+(?:you|that\s+you|which\s+you|"
    r"in\s+your|mentioned|reported|referred|named|listed)\b|\bnot\s+in\s+(?:response|relation|connection|reply)\s+to\b|"
    r"\baccording\s+to\s+(?!our\b|my\b|us\b)|\b(?:at\s+the\s+request\s+of|by|on\s+behalf\s+of|for)\s+(?:another|a\s+different|a\s+third|"
    r"an\s+other|the\s+(?:sending|receiving|originating|other|previous))\b|"
    r"\ba\s+different\s+(?:account|wallet|address|user|customer|client|person)\b|"
    r"\banother\s+(?:account|wallet|address|agency|authority|exchange|party|user|customer|platform)\b|"
    r"\bon\s+your\s+(?:side|end|platform)\b|\b(?:is|are|was|were)\s+(?:incorrect|inaccurate|untrue|wrong|false|"
    r"not\s+(?:correct|true|accurate))\b|\bthat\s+is\s+(?:not\s+(?:correct|true|accurate|the\s+case)|incorrect|untrue|"
    r"wrong|inaccurate)\b|\byou\s+(?:believe|claim|claimed|allege|alleged|think|assume)\b|"
    r"\bthe\s+(?:user|customer|client|victim|complainant)\s+(?:believes?|claims?|says?|said|states?|stated|alleges?|"
    r"alleged|wrote|thinks?|reported|told)\b|"
    # another party did it: "… by his bank", "NOT by us but by the issuer", "This was done by your bank"
    r"\bby\s+(?:his|her|their|your|its|the\s+(?:user|customer|client|account\s+holder)['\u2019]?s?)\s+(?:own\s+)?\w+|"
    r"\bby\s+(?:the|an?)\s+(?:\w+\s+)?(?:bank|issuer|exchange|provider|custodian|court|police|authorit\w*|agency|"
    r"regulator|prosecutor|user|customer|client|account\s+holder)\b(?!['\u2019]s\b|\s+(?:orders?|decisions?|rulings?|"
    r"warrants?|requests?|instructions?)\b)|\bor\s+so\b|"
    # another account or matter: "belongs to someone else", "unrelated to your request", "under a separate
    # investigation", "in 2023", "last year"
    r"\bbelong(?:s|ed)?\s+to\s+(?:someone|somebody|another|a\s+different|a\s+third|an\s+unrelated)\b|"
    r"\bsomeone\s+else\b|\bunrelated\b|\b(?:separate|different|other|another|previous|earlier|prior|older)\s+"
    r"(?:matter|case|investigation|request|proceeding|procedure|incident|inquiry|enquiry)s?\b|"
    r"\bin\s+(?:[a-z]+\s+)?(?:19|20)\d\d\b|\blast\s+(?:year|month|week)\b|\b\d+\s+(?:years?|months?)\s+ago\b", _I)
# a correction or retraction after the outcome, also in the next sentences ("Correction: we have not.", "Sorry, that
# was a template error; no action was taken.", "this was sent in error", "This is incorrect.")
_RETRACT_AFTER = re.compile(
    r"\bcorrection\b|\berror\b|\bby\s+mistake\b|\bmistake(?:n|nly)?\b|\berroneous(?:ly)?\b|\btemplate\b|"
    r"\b(?:disregard|ignore)\b|\bincorrect(?:ly)?\b|\bnot\s+(?:correct|true|accurate|the\s+case)\b|\buntrue\b|"
    r"\bno\s+(?:action|freeze|hold|block|restriction)\s+(?:was|has\s+been|had\s+been|is)\s+(?:\w+\s+)?"
    r"(?:taken|placed|applied|made|put|imposed|in\s+place)\b|"
    r"\b(?:we|i)\s+(?:have|had|did|has)\s*(?:not|n['\u2019]t)\b\s*(?:[.;!,:)]|$|(?:\w+\s+){0,2}(?:frozen|froze|freeze|"
    r"blocked|block|blacklisted|placed|put|restricted|suspended|seized|held|returned|refunded|done|taken|acted|"
    r"locked|applied|imposed))", _I)
# a following sentence that is only a negation ("Not by us, though.", "No.", "Not anymore."; never "No further action
# is required.")
_BARE_NEGATION = re.compile(r"^\W*(?:correction\W+)?(?:no|not|never|none|nothing|nobody)\b(?!\s+further\b)"
                            r"[^.!?;]{0,20}[.!?;]?\s*$", _I)
# a footer or a condition in the next sentences is no correction ("If you received this e-mail in error, …")
_FOOTER = re.compile(r"\b(?:if|unless|should\s+you)\b[^.!?]*|\b(?:received|receive)\s+(?:this|the)\s+(?:\w+\s+){0,2}in\s+"
                     r"error\b|\bintended\s+recipient\b[^.!?]*|\bno\s+further\s+action\b[^.!?]*", _I)
# a partial or limited outcome, or an empty wallet ("… ability to trade, but withdrawals remain open", "…; however, it
# contains no funds", "the funds had already left")
_PARTIAL_AFTER = re.compile(
    r"(?<!\bno\s)\bwithdrawals?\s+(?:\w+\s+)?(?:remain|remains|are|is|stay|stays)\s+(?:still\s+)?(?:open|possible|enabled|"
    r"available|allowed|permitted|unrestricted|active)\b|\bability\s+to\s+(?:trade|deposit|log|buy|sell|stake)\b|"
    r"\bcontain(?:s|ed)?\s+no\b|\bheld\s+no\b|\b(?:was|is|were|are)\s+(?:already\s+)?empty\b|\bno\s+(?:balance|funds|"
    r"assets|tokens)\b|\bnothing\s+(?:to\s+(?:freeze|block|hold)|left)\b|\bzero\s+balance\b|"
    r"\b(?:already\s+)?(?:been\s+)?(?:left|moved|withdrawn|transferred|drained|swept|spent)\s+(?:out\s+|from\s+|before\b)|"
    r"\balready\s+(?:left|moved|gone|withdrawn|transferred|drained)\b|\bpart(?:ial(?:ly)?)?\s+of\b|\bpartial(?:ly)?\b|"
    r"\bonly\s+(?:a\s+)?(?:part|portion|fraction|some)\b", _I)
# a lapsed frame in the outcome's own sentence: "We had frozen the account until the KYC review concluded", "for the
# duration of the review", "at the time", "briefly", "for 48 hours"
_LAPSED_FRAME = re.compile(
    r"\bhad\s+(?:\w+\s+){0,2}(?:frozen|blocked|locked|blacklisted|blocklisted|placed|put|restricted|suspended|limited|"
    r"disabled|held|seized)\b[^.!?]*\buntil\b|\bfor\s+the\s+(?:duration|length|period|course)\s+of\b|\bat\s+the\s+time\b|"
    r"\bbriefly\b|\bfor\s+(?:\d+|a\s+few|a\s+couple\s+of|several|one|two|three|four|five|six|seven|ten|24|48|72)\s*"
    r"(?:-\s*)?(?:hours?|days?|weeks?|months?)\b|\bat\s+that\s+(?:time|point)\b|\bback\s+then\b", _I)
# a policy sentence: a generic plural subject without a determiner, present tense ("Accounts are frozen on receipt of a
# court order", "Funds are frozen after we receive …", "Accounts flagged by law enforcement are frozen within 24 hours")
_GENERIC_POLICY = re.compile(
    r"(?:^|[,;:]\s*)\W*(?:\w+\s+)?(?:accounts|funds|wallets|addresses|assets|deposits|balances|withdrawals|tokens|"
    r"transactions|transfers|users|customers|clients)\b[^.;\d]{0,80}?\b(?:are|get|gets|is)\s+"
    r"(?!(?:now|currently|already|still|successfully|hereby)\b)(?:\w+\s+)?(?:frozen|"
    r"blocked|locked|blacklisted|blocklisted|restricted|suspended|held|seized|placed|put|returned|refunded)\b|"
    r"\b(?:is|are)\s+(?:\w+\s+)?(?:frozen|blocked|locked|blacklisted|blocklisted|restricted|suspended|held)\b[^.;]{0,60}?"
    r"\bwithin\s+\d+\s*(?:-\s*)?(?:hours?|days?|business\s+days?|minutes?)\b", _I)
# what is no freeze / hold of funds: an e-mail / IP / sender address, a mail server, a portal or log-in account
# ("Your e-mail address has been blocked by our spam filter", "Your portal account has been locked after three failed
# log-in attempts", "The sender address is blacklisted on our mail server")
_NOT_FUNDS_CONTEXT = re.compile(
    r"\b(?:e-?mail|ip|sender|mail|login|log-?in|sign-?in|portal|postal|billing|home|contact|return|web|website|"
    r"reply-?to|from)\s+(?:address(?:es)?|accounts?)\b|\bspam\b|\bmail\s*-?\s*servers?\b|\bfirewall\b|\bcaptcha\b|"
    r"\b(?:log-?in|login|sign-?in)\s+attempts?\b|\bfailed\s+(?:log-?in|login|sign-?in|attempts?)\b|\bpasswords?\b|"
    r"\bcredentials\b|\bsign-?ups?\b|\bregistrations?\b|\bportal\b|\be-?mails?\s+from\b|\bfurther\s+e-?mails\b|"
    r"\brepeated\s+requests\b|\brate[- ]limit|\bdomain\b|\bnewsletter\b|"
    r"\byour\s+(?:[\w-]+\s+){0,2}?(?:account|address|e-?mail|ip)\b", _I)
# a return undone again ("…; However, the transfer bounced and the money is back with us")
_RETURN_UNDONE = re.compile(
    r"\bbounced\b|\brejected\b|\bfail(?:ed|s)?\b|\breturned\s+to\s+us\b|\bback\s+with\s+us\b|\bback\s+to\s+us\b|"
    r"\breversed\b|\brecalled\b|\bcould\s+not\s+be\s+(?:completed|processed|credited|delivered)\b|\bunsuccessful\b|"
    r"\bnot\s+(?:been\s+)?(?:credited|received|completed|arrived)\b|\bpending\b|\bon\s+hold\b", _I)


# a question without its "?" ("Have the funds been frozen", "Could you confirm the account is frozen"): the
# sentence (or a line of it) opens with an auxiliary followed by its subject (never "Have been frozen …")
_QUESTION_START = re.compile(r"(?:^|\n)[\s\"'(\[]*(?:did|do|does|have|has|had|is|are|was|were|can|could|would|will|"
                             r"shall|should|may|might)\s+(?!(?:been|now|already|successfully|also|just|indeed|not|never|"
                             r"confirm|inform|advise|report|state|verify|update|note|let|be|keep|feel)\b|"
                             r"\w+(?:ed|en)\b)[a-z]", _I)
# "too late to freeze", "it was not possible to freeze": no freeze took place
_MISSED = re.compile(r"\btoo\s+late\b|\bnot\s+possible\b|\bimpossible\b", _I)
# a later lift / release / unfreeze / return / expiry of what was frozen or held cancels it ("frozen by mistake and
# have since been released", "a temporary hold, which expired after 72 hours", "…, which is no longer in effect",
# "The account was frozen; This is no longer the case.", "… Full access has been reinstated.")
_LIFTED = re.compile(r"\b(?:released|lifted|unfrozen|unfroze|unblocked|unlocked|un-?blacklisted|un-?blocklisted|"
                     r"delisted|removed|withdrawn|cancel(?:l)?ed|rescinded|discharged|returned|refunded|revoked|"
                     r"reinstated|restored|expired|lapsed|ended|terminated|reactivated|re-?enabled|re-?opened|"
                     r"unrestricted|unsuspended|paid\s+out|disbursed|transferred\s+back|sent\s+back|"
                     # "the freeze has now been reversed", "which we have since taken off", "overturned on appeal",
                     # "then let the funds go", "ordered us to unfreeze it", "subsequently forwarded to the
                     # beneficiary", "then transferred to …", "the review … has now concluded"
                     r"reversed|undone|overturned|vacated|quashed|dropped|taken\s+off|unfreeze|unblock|unlock|"
                     r"unblacklist|release|forwarded|transferred|moved|concluded|completed|finished|closed|"
                     r"(?:given|handed)\s+back|let\s+(?:\w+\s+){0,3}go|left|"
                     r"freigegeben|entsperrt|aufgehoben|sbloccat[oiae]|dissequestrat[oiae]|d[ée]bloqu[ée]e?s?|"
                     r"lev[ée]e?s?|desbloquead[oa]s?|liberad[oa]s?)\b|\bactive\s+again\b|"
                     r"\bagain\s+(?:active|accessible|available|usable)\b|\bback\s+to\s+normal\b|"
                     r"\bno\s+longer\s+(?:in\s+(?:effect|place|force)|frozen|blocked|locked|blacklisted|restricted|"
                     r"suspended|on\s+hold|held|active|applies|applicable|valid|the\s+case)\b|\bnot\s+any\s?more\b|"
                     r"\bfull\s+access\b|\bnow\s+(?:open|active|accessible|available|usable|unrestricted|operational)\b|"
                     r"\baccess\b[^.;]{0,40}?\b(?:given|granted|returned|handed)\b", _I)
# the same words before the outcome ("We lifted the freeze", "the released funds were frozen again"): no outcome
_LIFTED_BEFORE = re.compile(r"\b(?:released|lifted|unfrozen|unfroze|unblocked|unlocked|un-?blacklisted|un-?blocklisted|"
                            r"delisted|removed|cancel(?:l)?ed|rescinded|revoked|expired|lapsed)\b", _I)
# a lapse worded with a negation ("frozen no longer", "it is not frozen anymore", "nicht mehr gesperrt"): after the
# outcome it always cancels it (a "no longer" lift is never "negated" by its own "no")
_LAPSED = re.compile(r"\bno\s+longer\b|\bnot\b[^.;]{0,30}?\bany\s?more\b|\bnicht\s+mehr\b|\bnon\s+più\b|"
                     r"\bne\b[^.;]{0,20}?\bplus\b|\bn['\u2019][^.;]{0,20}?\bplus\b|\bya\s+no\b", _I)
_LIFT_WINDOW = 40  # what precedes the lift word: "not released", "will be released once …"
# "until <someone> lifted …" is a lift that happened ("We had frozen the funds until the court lifted the order"),
# "until released by a court order" / "until the order is lifted" is a condition
_UNTIL_DONE = re.compile(r"\buntil\s+(?:the|a|an|it|they|we|he|she|our|their|this|that|[A-Z][\w-]+)\b"
                         r"(?:(?!\b(?:is|are|be|been|being|will|would|shall|can|could|may|might|has|have)\b)[^,;]){0,40}$")
# a lift that names the freeze / hold anywhere in the sender's own text ("It has since been removed from the
# blacklist.", "The freeze has since been lifted.", "We removed the block on the wallet."): no freeze / hold of the
# reply stands
_NAMED_LIFT = re.compile(
    r"\b(?:freeze|freezing|hold|block|blocking|restriction|blacklisting|blocklisting|suspension|lock|limitation)s?\b"
    r"(?!\s+(?:request|order|letter|notice))[^.;]{0,40}?\b(?:has|have|had|was|were|is|are)\s+"
    r"(?:(?:since|now|already|subsequently|then|later|been)\s+){0,3}(?:lifted|removed|released|cancel(?:l)?ed|revoked|"
    r"rescinded|withdrawn|expired|lapsed|ended|discharged|terminated|reversed|undone|overturned|vacated|quashed|"
    r"dropped|taken\s+off)\b|"
    r"\b(?:lifted|removed|released|cancel(?:l)?ed|revoked|rescinded|withdrew|ended|terminated|reversed|overturned|"
    r"vacated|quashed|dropped|undid)\s+(?:the|this|that|our|its|"
    r"any)\s+(?:temporary\s+|precautionary\s+)?(?:freeze|hold|block|restriction|blacklisting|blocklisting|suspension|"
    r"lock)\b|\b(?:removed|delisted|deleted|taken\s+off)\s+(?:it\s+|them\s+)?from\s+(?:the|our)\s+(?:internal\s+)?"
    r"(?:block\s*list|black\s*list|deny\s*list|freeze\s+list|sanctions?\s+list)\b|"
    r"\b(?:unfroze|unfrozen|unblocked|unlocked|un-?blacklisted|un-?blocklisted)\b|\b(?:took|taken)\s+off\s+(?:the|this|"
    r"that|our)\s+(?:freeze|hold|block|restriction)\b|"
    r"\b(?:full\s+)?access\b[^.;]{0,30}?\b(?:has|have|was|were)\s+(?:(?:since|now|been)\s+){0,2}(?:reinstated|restored)\b",
    _I)
_LIFT_SENTENCES = 2  # the sentences after an outcome read for a lift of it


def _lift_stands(text: str, m: re.Match) -> bool:
    """The lift word at `m` is not itself negated or conditional ("frozen, not released", "frozen until released by
    a court order", "they will be released once …"); "until the court lifted the order" is a lift."""
    lead = text[max(0, m.start() - _LIFT_WINDOW):m.start()]
    if _NEGATION.search(lead):
        return False
    return not _CONDITIONAL.search(_UNTIL_DONE.sub(" ", lead))


def _cancelled(after: str) -> bool:
    """What follows the outcome (the rest of its sentence and the next `_LIFT_SENTENCES`) lifts it again: a lift /
    release / unfreeze / return / expiry word that is not itself negated or conditional."""
    return bool(_LAPSED.search(after)) or any(_lift_stands(after, m) for m in _LIFTED.finditer(after))


def named_lift(own: str) -> bool:
    """The sender's own text lifts a freeze / hold by name somewhere (`_NAMED_LIFT`), not negated or conditional."""
    for m in _NAMED_LIFT.finditer(own or ""):
        lead = own[max(0, m.start() - _LIFT_WINDOW):m.start()]
        if _NEGATION.search(lead) or _NEGATION.search(m.group(0)) or _CONDITIONAL.search(_UNTIL_DONE.sub(" ", lead)) \
                or _CONDITIONAL.search(m.group(0)):
            continue
        return True
    return False


def lift_context(text: str, end: int, more: int = _LIFT_SENTENCES) -> str:
    """What follows offset `end` of `text`: the rest of its whole sentence (`sentence_rest`: across "; " before a
    capital) and the `more` sentences after it, read for a lift only."""
    m = _FULL_SPLIT.search(text, end)
    stop = m.start() if m else len(text)
    for _ in range(more):
        if m is None:
            break
        m = _FULL_SPLIT.search(text, m.end())
        stop = m.start() if m else len(text)
    return text[end:stop][:800]


def _blocked(sentence: str, start: int, status: str, end: int | None = None, rest: str = "") -> bool:
    """A positive outcome that the sentence negates, makes conditional / future / intended, attributes to someone else
    or disputes, asks about (a "?", or a question's opening without one), or lifts again. `start` is where the outcome's
    match starts and `end` where it ends: everything before `end` (120 characters before the match and the match itself,
    so a "no longer", a "nicht" or a "you believe" inside "The funds you believe have been frozen" counts) is read for a
    negation, a condition, someone else's claim (`_HEARSAY`), a zero amount or an earlier lift; with `end` the rest of
    its clause is read too (a negation, a negated object, a condition such as "only upon receipt of a court order",
    "was only considered", "but not placed"), the rest of its sentence for a disclaimer ("not by us", "according to the
    user") or a zero amount, and that and `rest` (`lift_context`: the next sentences) for a lift."""
    if status not in POSITIVE:
        return False
    if sentence.rstrip().endswith("?"):
        return True
    q = _QUESTION_START.search(sentence)
    if q is not None and q.start() <= start:
        return True
    upto = end if end is not None else start
    prefix = _HARMLESS.sub(" ", sentence[max(0, start - 120):upto])
    if _NEGATION.search(prefix) or _CONDITIONAL.search(prefix) or _MISSED.search(prefix) or _HEARSAY.search(prefix) \
            or _ZERO_BEFORE.search(prefix):
        return True
    if status != FUNDS_RETURNED and _LIFTED_BEFORE.search(prefix):
        return True
    if status != FUNDS_RETURNED and (_NOT_FUNDS_CONTEXT.search(sentence) or _LAPSED_FRAME.search(sentence)):
        return True
    if _GENERIC_POLICY.search(sentence) or _DISCLAIM_AFTER.search(prefix):
        return True
    if end is None:
        return False
    tail = sentence[end:]
    if status != FUNDS_RETURNED and _cancelled(tail + " " + rest):
        return True
    # the rest of the clause, of the sentence across "; " and the next sentences (footers and conditions cut): a
    # disclaimer, a correction, a partial / empty outcome, an undone return, a sentence that is only a negation
    following = _FOOTER.sub(" ", tail + " " + rest)
    if status == FUNDS_RETURNED and _RETURN_UNDONE.search(following):
        return True
    if _ZERO_AFTER.search(tail) or _DISCLAIM_AFTER.search(following) or _RETRACT_AFTER.search(following) \
            or _PARTIAL_AFTER.search(following):
        return True
    if any(_BARE_NEGATION.match(s) for _, s in sentences(rest)):
        return True
    after = tail[:_AFTER_WINDOW]
    if _NOT_DONE.search(after) or _BUT_NOT.search(after):
        return True
    cut = _CLAUSE_END.search(after)
    clause = after[:cut.start()] if cut else after
    return bool(_AFTER_NEGATION.search(clause) or _COND_AFTER.search(clause))


def outcome_matches(own: str):
    """(pattern, sentence offset, sentence, match) for every pattern match in the sender's own text `own` that the
    guard lets through (`_blocked`; a freeze / hold also only when no lift of it is named anywhere: `named_lift`).
    The matches are of `match_text(sentence)`, at the sentence's offsets."""
    lifted = named_lift(match_text(own or ""))
    for start, sent in sentences(own or ""):
        if _TAG_RE.search(sent) and len(sent) < 160:
            continue  # a line that only repeats our tracking tag / subject
        probe = match_text(sent)
        rest = match_text(lift_context(own, start + len(sent)))
        for p in PATTERNS:
            if lifted and p.status in (FROZEN, HOLD_PLACED):
                continue
            for m in p.regex.finditer(probe):
                if p.exclude is not None and p.exclude.search(sent):  # read only once a pattern matched
                    break
                if not _blocked(probe, m.start(), p.status, m.end(), rest):
                    yield p, start, sent, m


def positive_spans(own: str) -> list[tuple[str, int, int]]:
    """(status, start, end) in `own` of every frozen / hold / returned statement the rules accept: the AI's quote of
    an outcome must overlap one of them (classify_ai.outcome_stated), so the AI guard is never laxer than the rules."""
    return [(p.status, start + m.start(), start + m.end()) for p, start, _, m in outcome_matches(own)
            if p.status in POSITIVE]


# --------------------------------------------------------------------------- warnings on a suggested outcome
# A frozen / hold / returned reading is only ever a suggestion a person confirms (app.blocks.status). These signals
# (the guard's vocabulary, read more widely: the whole reply, not only the outcome's own clause) are shown with it.
_W_LIFT = re.compile(
    r"\b(?:released?|lifted|unfrozen|unfroze|unfreeze|unblocked|unlocked|un-?blacklisted|un-?blocklisted|delisted|"
    r"expired|lapsed|reinstated|restored|revoked|rescinded|reversed|freed|reactivated|re-?enabled|re-?opened|"
    r"paid\s+(?:out|to)|cashed\s+out|emptied|swept|drained|withdrawn|back\s+in\s+use|regained\s+access|"
    r"(?:trade|withdraw|transact|use\s+it)\s+again|no\s+longer|not\s+any\s?more|nothing\s+(?:remains|is\s+still)|"
    r"(?:is|was|were|are)\s+gone|sent\s+to\s+(?:the\s+)?(?:customer|user|client)|"
    r"(?:customer|user|client)['\u2019]?s?\s+(?:own\s+)?(?:external\s+)?wallet)\b", _I)
_W_HYPOTHETICAL = re.compile(
    r"\b(?:suppose|supposing|imagine|as\s+soon\s+as|after\s+we|once\s+we|or\s+(?:are\s+)?about\s+to|tried\s+to|"
    r"attempted\s+to|or\s+rather|will|would|could|might|plan|intend|going\s+to)\b", _I)
_W_PARTIAL = re.compile(
    rf"\b\d[\d,.' ]*\s*(?:(?:{_ASSETS})\s+)?of\s+the\s+\d|\b(?:a\s+)?(?:tenth|fraction|portion|part|share|half)\s+of\b|"
    r"\bonly\b|\bunaffected\b|\b(?:nothing|not)\s+in\s+it\b|\bthere\s+was\s+nothing\b|\b(?:empty|zero)\b|"
    r"\bbalance\b[^.;]{0,25}\b0+(?:[.,]0+)?\b|\bdeposits?\s+only\b|\bwithdrawals?\b[^.;]{0,30}\bbut\b", _I)
_W_OTHER_PARTY = re.compile(
    r"\bby\s+[A-Z][\w-]+\b|\b(?:our|a|the)\s+(?:\w+\s+)?(?:bank(?:ing)?|partner|custodian|issuer|provider|processor)\b|"
    r"\b(?:update|statement|message|notice|news)\s+from\b|\b(?:our|their|the)\s+(?:customer|owner|user|client)\b", _I)
_W_GENERIC = re.compile(
    r"\b(?:before|in\s+the\s+past|previously|similar|this\s+year|last\s+year|other\s+(?:agencies|cases|accounts|"
    r"requests|authorities)|such\s+accounts|(?:have|has)\s+(?:\w+\s+)?(?:frozen|blocked|held)\s+(?:accounts|wallets|funds)\b)",
    _I)
_W_NOT_FUNDS = re.compile(
    r"\b(?:api\s+keys?|privileges?|trading|cooperation|onboarding|cards?|log-?ins?|sign-?ups?|registrations?|"
    r"customers\s+from)\b", _I)
_W_TEST = re.compile(r"\bjust\s+kidding\b|\btest\s+(?:message|e-?mail)\b|\bthis\s+is\s+(?:only\s+)?a\s+test\b|\bjoke\b",
                     _I)
# a lift the provider only announces for later, on a real condition ("The hold will be automatically lifted after 30
# days unless a freezing order …", "otherwise the temporary freeze will be lifted"): the hold stands now. An
# unconditional lift date ("will be unfrozen within 24 hours") still warns: the hold is about to go
_W_FUTURE_LIFT = re.compile(
    r"\b(?:will|would|shall|may|might|is\s+to)\s+(?:only\s+)?be\s+(?:automatically\s+|auto-?\s*)?(?:lifted|released|"
    r"removed|unfrozen|unblocked|expired)\b[^.;]{0,80}?\b(?:unless|if\s+(?:no|we\s+do\s+not|not)|"
    r"until\s+(?:we|you)\s+(?:receive|provide|submit))\b|\botherwise\b[^.;]{0,60}?\b(?:will|would|shall)\s+be\s+(?:automatically\s+)?"
    r"(?:lifted|released|removed|unfrozen|unblocked)\b", _I)
WARNING_TEXT = {
    "lifted": "the reply also says it was released / lifted, or that the funds left",
    "negated": "the outcome's sentence contains a negation",
    "conditional": "it may be conditional, future, hypothetical or only attempted",
    "question": "it may be a question",
    "partial": "it may be partial, limited, or the account empty",
    "other_party": "it may report another party's action or someone else's statement",
    "generic": "it may describe past practice or a policy, not this request",
    "not_funds": "what was frozen / held may not be the reported funds",
    "test": "the reply calls itself a test or a joke",
}


def outcome_warnings(own: str | None, quote: str | None, status: str) -> list[str]:
    """Why a suggested frozen / hold / returned reading may be wrong (`WARNING_TEXT` keys, in that order): the guard's
    signals read over the whole reply (`own`, the sender's own text) and the outcome's sentence (`quote`). Advisory:
    a person confirms every outcome; an empty list is no proof."""
    text = match_text(own or "")
    q = match_text(quote or "") or text
    out: list[str] = []
    now_text = _W_FUTURE_LIFT.sub(" ", text)  # a conditional, future lift is the hold's term, not a lift
    lifted = (_RETURN_UNDONE.search(text) if status == FUNDS_RETURNED
              else _W_LIFT.search(now_text) or named_lift(now_text) or _LAPSED.search(now_text))
    if lifted:
        out.append("lifted")
    if _NEGATION.search(_HARMLESS.sub(" ", q)):
        out.append("negated")
    if _W_HYPOTHETICAL.search(q) or _CONDITIONAL.search(_HARMLESS.sub(" ", q)) or _COND_AFTER.search(q):
        out.append("conditional")
    if "?" in (quote or "") or _QUESTION_START.search(q):
        out.append("question")
    if _W_PARTIAL.search(text) or _PARTIAL_AFTER.search(text) or _ZERO_BEFORE.search(text):
        out.append("partial")
    if _W_OTHER_PARTY.search(q) or _HEARSAY.search(q) or _DISCLAIM_AFTER.search(text) or _RETRACT_AFTER.search(text):
        out.append("other_party")
    if _W_GENERIC.search(q) or _GENERIC_POLICY.search(q):
        out.append("generic")
    if status != FUNDS_RETURNED and (_W_NOT_FUNDS.search(q) or _NOT_FUNDS_CONTEXT.search(q)):
        out.append("not_funds")
    if _W_TEST.search(text):
        out.append("test")
    return out


# --------------------------------------------------------------------------- amounts, tickets, channels
_AMOUNT_RE = re.compile(
    rf"(?:(?P<pre>{_ASSETS}|US\$|\$|€|£)\s?(?P<n1>\d{{1,3}}(?:\.\d{{3}})+,\d{{1,2}}(?!\d)|\d{{1,3}}(?:[,  ' ]\d{{3}})+(?:[.,]\d+)?|\d+(?:[.,]\d+)?)"
    rf"|(?P<n2>\d{{1,3}}(?:\.\d{{3}})+,\d{{1,2}}(?!\d)|\d{{1,3}}(?:[,  ' ]\d{{3}})+(?:[.,]\d+)?|\d+(?:[.,]\d+)?)\s?(?P<post>{_ASSETS})\b)"
    r"(?:\s?(?:TRC-?20|ERC-?20|BEP-?20|on\s+(?:tron|ethereum)))?", re.IGNORECASE)
_SYMBOL = {"US$": "USD", "$": "USD", "€": "EUR", "£": "GBP"}


def parse_number(raw: str) -> Decimal | None:
    """'12,633.77' / '12.633,77' / '12 633.77' / "12'633.77" / '0.000599' -> Decimal."""
    s = raw.replace(" ", "").replace(" ", "").replace("'", "").replace(" ", "").strip()
    if "," in s and "." in s:
        if s.rfind(",") > s.rfind("."):
            s = s.replace(".", "").replace(",", ".")
        else:
            s = s.replace(",", "")
    elif "," in s:
        parts = s.split(",")
        if len(parts) > 2 or (len(parts) == 2 and len(parts[1]) == 3 and len(parts[0]) <= 3):
            s = s.replace(",", "")  # thousands separators
        else:
            s = s.replace(",", ".")  # decimal comma
    elif s.count(".") > 1:
        s = s.replace(".", "")  # 1.234.567 (thousands)
    try:
        d = Decimal(s)
    except InvalidOperation:
        return None
    return d if d.is_finite() and d >= 0 else None


def find_amount(text: str) -> tuple[Decimal | None, str | None]:
    """The first amount with an asset / currency next to it, else (None, None)."""
    for m in _AMOUNT_RE.finditer(text or ""):
        raw = m.group("n1") or m.group("n2")
        sym = (m.group("pre") or m.group("post") or "").upper()
        sym = _SYMBOL.get(m.group("pre") or "", sym)
        d = parse_number(raw)
        if d is not None and d > 0:
            return d, sym or None
    return None, None


_TICKET_RE = re.compile(
    r"(?<![A-Za-z])(?P<your>your\s+)?(?P<kw>ticket|case|request|reference|ref|incident|inquiry|enquiry|query|"
    r"support\s+request)\s*(?:number|no\.?|num|id|nr\.?|#)?\s*(?P<is>is\s+|has\s+been\s+assigned\s+(?:the\s+)?"
    r"(?:number\s+)?)?[:#]?\s*#?\s*(?P<t>[A-Z0-9][A-Z0-9_./-]{2,40}[A-Z0-9])", re.IGNORECASE)
# "your case number is 99812" / "your ticket ID: 48213" assign their number; "your reference DEMO-…" quotes ours
_YOUR_OWN_KW = frozenset({"ticket", "case", "request", "incident", "support request"})
_BRACKET_TICKET = re.compile(r"\[\s*#\s*(?P<t>\d{4,12})\s*\]|(?<![\w#])#(?P<t2>\d{5,12})\b")
_TAG_RE = re.compile(r"\[Aegis\s[^\]]{1,80}\]", re.IGNORECASE)


def find_ticket(text: str, exclude_refs: set[str] | frozenset[str] = frozenset()) -> str | None:
    """The recipient's own ticket / case number: never our case reference, our tracking tag or a
    reference the sender quotes back as 'your reference'."""
    clean = _TAG_RE.sub(" ", text or "")
    excluded = {r.strip().lower() for r in exclude_refs if r and r.strip()}

    def ok(t: str) -> bool:
        low = t.lower().strip("./-")
        if not any(ch.isdigit() for ch in low) or low in excluded:
            return False
        return not any(low.startswith(e) or e.startswith(low) for e in excluded if len(e) >= 6)

    for m in _TICKET_RE.finditer(clean):
        if m.group("your") and not (" ".join(m.group("kw").lower().split()) in _YOUR_OWN_KW
                                    and (m.group("is") or ":" in m.group(0) or "#" in m.group(0))):
            continue
        t = m.group("t").rstrip(".")
        if ok(t):
            return t[:64]
    for m in _BRACKET_TICKET.finditer(clean):
        t = m.group("t") or m.group("t2")
        if t and ok(t):
            return t
    return None


EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+")
URL_RE = re.compile(r"\bhttps?://[^\s<>()\"'\]]+|\bwww\.[^\s<>()\"'\]]+|"
                    r"\b[a-z0-9-]{2,63}\.(?:com|io|org|net|co|ai|app|xyz|exchange|finance)/[^\s<>()\"'\]]+", re.IGNORECASE)
_LEGACY_NEAR = re.compile(r"\b(?:legacy|deprecated|retired|no\s+longer|not\s+(?:actively\s+)?monitored|discontinued|"
                          r"do\s+not\s+use|unmonitored)\b", re.IGNORECASE)
_NOREPLY = re.compile(r"^(?:no-?reply|do-?not-?reply|donotreply|mailer-daemon|postmaster|bounce[s]?)(?:[+._-].*)?@",
                      re.IGNORECASE)
_PURPOSES = (
    ("freeze", re.compile(r"\b(?:freez|frozen|block(?:ing|list)?|blacklist|blocklist|hold|asset\s+protection|"
                          r"access\s+denial|risk)", re.IGNORECASE)),
    ("le_request", re.compile(r"\b(?:law[- ]enforcement|police|government\s+request|le\s+request|kodex|portal)",
                              re.IGNORECASE)),
    ("legal", re.compile(r"\b(?:subpoena|legal\s+process|court|warrant|records|summons)", re.IGNORECASE)),
    ("compliance", re.compile(r"\b(?:compliance|aml|fraud|security)", re.IGNORECASE)),
)


def _purpose(context: str) -> str:
    for name, rx in _PURPOSES:
        if rx.search(context):
            return name
    return "general"


def _line_around(text: str, start: int, end: int) -> str:
    a = text.rfind("\n", 0, start) + 1
    b = text.find("\n", end)
    line = text[a:b if b != -1 else len(text)]
    if len(line.strip()) < 25:  # "Freezes:" on its own line, the address on the next
        prev_a = text.rfind("\n", 0, max(0, a - 1)) + 1
        line = text[prev_a:b if b != -1 else len(text)]
    return line


def find_channels(text: str, exclude_addresses: set[str] | frozenset[str] = frozenset()) -> tuple[list[dict], list[dict]]:
    """(addresses, urls) the reply names, each {value, purpose, legacy}; the excluded addresses (the
    ones we wrote to, the case mailbox), no-reply addresses and the ones the reply calls legacy are
    dropped from the result."""
    excluded = {a.strip().lower() for a in exclude_addresses if a}
    addrs: list[dict] = []
    seen: set[str] = set()
    for m in EMAIL_RE.finditer(text or ""):
        value = m.group(0).strip(".").lower()
        if value in seen:
            continue
        seen.add(value)
        after = text[m.end():m.end() + 60]
        before = text[max(0, m.start() - 40):m.start()]
        legacy = bool(_LEGACY_NEAR.search(after.split("\n")[0]) or re.search(
            r"(?:legacy|deprecated|retired|old)\s+(?:inbox|mailbox|address)?\s*\(?\s*$", before, re.IGNORECASE))
        if value in excluded or _NOREPLY.match(value) or legacy:
            continue
        addrs.append({"value": value, "purpose": _purpose(_line_around(text, m.start(), m.end())), "legacy": False})
        if len(addrs) >= MAX_ADDRESSES:
            break
    urls: list[dict] = []
    seen_u: set[str] = set()
    for m in URL_RE.finditer(text or ""):
        value = m.group(0).rstrip(".,;:")
        low = value.lower()
        if "@" in value or low in seen_u or any(w in low for w in ("unsubscribe", "privacy", "cookie", "linkedin",
                                                                    "twitter.com", "facebook.com", "x.com/")):
            continue
        seen_u.add(low)
        urls.append({"value": value[:300], "purpose": _purpose(_line_around(text, m.start(), m.end()))})
        if len(urls) >= MAX_ADDRESSES:
            break
    return addrs, urls


# --------------------------------------------------------------------------- the classifier
@dataclass
class Signal:
    status: str
    confidence: float
    quote: str
    offset: int


@dataclass
class RuleResult:
    status: str
    confidence: float
    quote: str | None = None
    amount: str | None = None  # Decimal as a string (exact)
    asset: str | None = None
    ticket: str | None = None
    addresses: list[dict] = field(default_factory=list)  # redirect targets {value, purpose, legacy}
    urls: list[dict] = field(default_factory=list)
    also: list[str] = field(default_factory=list)  # other statuses the reply states
    auto: bool = False  # sent automatically (header flag or "automated response" wording)
    quoted_cut: bool = False  # a quoted earlier message was removed before classifying
    conflict: bool = False
    suspicious: bool = False  # text addressed to an AI / assistant ("ignore previous instructions", "SYSTEM:")
    source: str = "rules"
    version: int = RULES_VERSION
    # app.blocks.extract: what the reply says beyond its status (stored apart: correspondence.meta block_status extract)
    extract: dict | None = None

    @property
    def label(self) -> str:
        return LABELS.get(self.status, self.status)

    def as_dict(self) -> dict:
        d = asdict(self)
        d.pop("extract", None)
        return d


_AMOUNT_CONTEXT = re.compile(r"\b(?:held|frozen|hold|locked|blocked|restricted|returned|refunded|reversed|balance|"
                             r"total|amount|eingefroren|congelat|gel[ée]|congelad)", re.IGNORECASE)


_INJECTION_BASE = (r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|your)\s+"
                   r"(?:instructions?|prompts?|rules?)|"
                   # a role marker opens a line or a sentence ("SYSTEM: …", ". System: …"), never a portal's name
                   # inside a sentence ("our Law Enforcement Request System: https://…")
                   r"(?:^|[\n.!?])\s*(?:system|assistant|developer)\s*(?:prompt)?\s*:|"
                   r"\byou\s+are\s+now\b|\b(?:mark|classify|set|record|label)\s+(?:this|the|it|that)\s+"
                   r"(?:case|request|reply|e-?mail|message|status|order)?\s*(?:as|to)\s+(?:frozen|hold|returned|"
                   r"declined|acknowledged)\b"
                   # "[system] … [/system]", "<system>", "### Instruction", a line addressed "AI:" / "Classifier:"
                   r"|[\[<]\s*/?\s*(?:system|assistant|developer|instructions?|inst)\s*[\]>]|#{2,}\s*instructions?\b"
                   r"|(?:^|\n)\s*(?:ai|llm|bot|model|classifier|assistant)\s*:"
                   r"|\bnote\s+(?:to|for)\s+(?:the\s+)?(?:ai|llm|bot|model|classifier|assistant|system)\b"
                   # "Classify as frozen", "set status le_process_required", JSON '"status": "frozen"'
                   r"|\b(?:classify|categori[sz]e|mark|record|label)\s+(?:it\s+|this\s+)?as\s+(?:frozen|hold\w*|"
                   r"returned|declined\w*|acknowledged|redirected|le_process\w*|unclear)\b"
                   r"|\bset\s+(?:the\s+)?status\s+(?:to\s+)?\w+"
                   r"|[\"']status[\"']\s*:")
_INJECTION = re.compile(_INJECTION_BASE + r"|\bstatus\s*[=:]\s*\w+", re.IGNORECASE)
# the quoted part of a reply (our own letter, an earlier message) may hold ordinary "Case status: open" lines:
# there a "status:" counts only with an outcome value ("status: frozen")
_INJECTION_QUOTED = re.compile(_INJECTION_BASE + r"|\bstatus\s*[=:]\s*[\"']?(?:frozen|hold|hold_placed|on\s+hold|"
                               r"returned|funds_returned|declined\w*|acknowledged)\b", re.IGNORECASE)


def looks_like_injection(text: str | None, *, quoted: bool = False) -> bool:
    """The reply carries text addressed to an AI / assistant rather than to the investigator. `quoted`: the text is
    the reply's quoted part, where a "status:" line counts only with an outcome value (`_INJECTION_QUOTED`)."""
    return bool((_INJECTION_QUOTED if quoted else _INJECTION).search(text or ""))


def _cut_quote(s: str) -> str:
    s = " ".join(s.split())
    return s if len(s) <= MAX_QUOTE_CHARS else s[:MAX_QUOTE_CHARS - 1].rstrip() + "…"


def classify(text: str | None, *, subject: str | None = None, auto_reply: bool = False, bounce: bool = False,
             exclude_addresses: set[str] | frozenset[str] = frozenset(),
             exclude_refs: set[str] | frozenset[str] = frozenset(), echo: Iterable[str | None] = (),
             playbook=None, received_at=None, known: Iterable[str] = (), org_key: str | None = None,
             others: dict[str, str] | None = None) -> RuleResult:
    """Classify one reply (see the module doc). Never raises on odd input. `echo`: the subjects / texts of the
    letters we sent, so a ticket system's echo of one below a rule line is cut (`split_quoted`). `playbook` (the
    authority's app.domain.playbook.Playbook), `received_at`, `known` (the identifiers of our own letters),
    `org_key` / `others` (catalogue domains → organisation): for `extract` (app.blocks.extract)."""
    from app.blocks import extract as ex

    raw = str(text or "")[:MAX_TEXT_CHARS]
    own, cut = strip_quoted(raw, echo)
    subject = str(subject or "")[:512]
    suspicious = looks_like_injection(own) or looks_like_injection(subject)
    ticket = find_ticket(f"{subject}\n{own}", exclude_refs)
    if bounce:
        return RuleResult(status=DELIVERY_FAILED, confidence=0.95, quote=None, ticket=None, auto=True, quoted_cut=cut,
                          suspicious=suspicious)
    try:
        extracted = ex.extract(own, playbook=playbook, subject=subject, received_at=received_at,
                               exclude_addresses=exclude_addresses, exclude_refs=exclude_refs, known=known,
                               org_key=org_key, others=others).as_dict()
    except Exception:  # noqa: BLE001 - the extraction is advisory: it never breaks a reading
        extracted = None
    ticket = ticket or next((t["value"] for t in (extracted or {}).get("tickets") or []), None)
    signals: list[Signal] = []
    seen: set[tuple[int, int]] = set()
    for p, start, sent, _m in outcome_matches(own):
        if (id(p), start) not in seen:  # one signal per pattern and sentence
            seen.add((id(p), start))
            signals.append(Signal(p.status, p.confidence, sent, start))
    if subject:
        for p in PATTERNS:
            if p.subject_ok and p.regex.search(subject):
                signals.append(Signal(p.status, p.confidence, subject.strip(), -1))
    auto = bool(auto_reply) or any(s.status == AUTO_REPLY for s in signals)
    addresses, urls = find_channels(own, exclude_addresses)

    # the provider playbook's own LE-process wording (Circle: "legally compelled", "U.S. or French court") in a reply the
    # rules read only as an acknowledgement / unclear, with no ticket: their final answer, LE process required
    le_said = not ticket and any(x.get("means") == LE_PROCESS_REQUIRED for x in (extracted or {}).get("signals") or [])
    if not signals:
        status = AUTO_REPLY if auto_reply else UNCLEAR
        if le_said and own.strip():
            return RuleResult(status=LE_PROCESS_REQUIRED, confidence=0.6, quote=None, ticket=ticket, auto=auto,
                              quoted_cut=cut, addresses=addresses, urls=urls, also=[status], suspicious=suspicious,
                              extract=extracted)
        return RuleResult(status=status, confidence=0.6 if auto_reply else (0.0 if not own.strip() else 0.2),
                          ticket=ticket, auto=auto, quoted_cut=cut, addresses=[], urls=[], suspicious=suspicious,
                          extract=extracted)

    by_status: dict[str, list[Signal]] = {}
    for s in signals:
        by_status.setdefault(s.status, []).append(s)
    # an "automated response" that receipts the request is an acknowledgement; one that only says it is
    # automatic stays an auto-reply
    order = [s for s in PRIORITY if s in by_status]
    if le_said and order[0] in (ACKNOWLEDGED, UNCLEAR) and LE_PROCESS_REQUIRED not in by_status:
        by_status[LE_PROCESS_REQUIRED] = [Signal(LE_PROCESS_REQUIRED, 0.7, by_status[order[0]][0].quote,
                                                 by_status[order[0]][0].offset)]
        order.insert(0, LE_PROCESS_REQUIRED)
    status = order[0]
    best = max(by_status[status], key=lambda s: (s.confidence, -s.offset))
    conf = best.confidence + 0.05 * (len(by_status[status]) - 1)
    families = {_FAMILY[s] for s in by_status if s in _FAMILY}
    conflict = len(families) > 1
    if conflict:
        conf -= 0.25
    if status == ACKNOWLEDGED and ticket:
        conf += 0.1
    if status == REDIRECTED and not (addresses or urls):
        conf -= 0.2
    if suspicious:
        conf -= 0.3
    conf = round(max(0.05, min(0.95, conf)), 2)
    amount = asset = None
    if status in (FROZEN, HOLD_PLACED, FUNDS_RETURNED):
        # the supporting sentence first, then the other outcome sentences, then a sentence that talks
        # about the amount held ("A total of 12,633.77 USDT is held on the account.")
        candidates = [best.quote] + [x.quote for x in by_status[status] if x is not best]
        candidates += [x.quote for st in (FROZEN, HOLD_PLACED, FUNDS_RETURNED) for x in by_status.get(st, [])]
        candidates += [t for _, t in sentences(own) if _AMOUNT_CONTEXT.search(t)]
        for q in candidates:
            a, sym = find_amount(q)
            if a is not None:
                amount, asset = str(a), sym
                break
    quote = _cut_quote(best.quote) if best.offset >= 0 or status in (AUTO_REPLY, ACKNOWLEDGED) else None
    return RuleResult(
        status=status, confidence=conf, quote=quote, amount=amount, asset=asset, ticket=ticket,
        addresses=addresses,
        urls=urls if status in (REDIRECTED, LE_PROCESS_REQUIRED) else [],
        also=[s for s in order[1:] if s != UNCLEAR], auto=auto, quoted_cut=cut, conflict=conflict,
        suspicious=suspicious, extract=extracted)
