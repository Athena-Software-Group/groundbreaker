"""Request paths: where a block request stands in the provider's process, the clocks it runs on and the next step the
provider's playbook (app.domain.playbook) points to. Pure: no database, no network.

    st = advance(row, playbook, requester="pi", links=[...], confirmed=[...], le=le_targets(...), now=now)
    st.step, st.outcome, st.suggests, st.instrument, st.route, st.clocks, st.hold_expires_at
    act = action(case_id, row, st, name="Circle")      # {kind, text, href, evidence, clock} or None (generic text)

**Steps** (`STEPS`, in order): notice_sent (our letter is out) → provider_ack (ticket / acknowledgement) →
provider_ask (they want documents) → hold_discretionary (a temporary hold: never "frozen") → le_only_redirect (they act
only on LE process / a court order, or point to an LE-only portal) → le_route_open (our LE brief, linked to the request
by `meta.follow_up_of`, went to an LE authority or counsel) → le_filed → binding_instrument → cross_border → outcome
(frozen, funds_returned, released, declined_terminal, funds_moved). The step is derived on every read from the replies
(status, extraction, playbook signals), the stop order's recorded state, the linked letters and the steps a person
confirmed; it is never stored. Only a person's steps are (status.confirm_step: le_filed, binding_instrument,
cross_border, outcome funds_moved / declined_terminal; case.facts[PATH_KEY]). Positive steps (a hold, an outcome frozen /
returned) come only from a person (a confirmed reply, the desk's recorded status); a reply that reads as one leaves
`suggests` set.

**Jurisdiction.** The instrument's issuer jurisdictions (the reply's, else the playbook path's, else the playbook's)
against each LE authority's: a mismatch is a cross-border route (an EU freezing order / EIO to the provider's EU state,
an MLAT, counsel where the provider acts), explained in the next action and the LE brief — unless a case agent of a
jurisdiction the provider acts on can be got (a complaint intake there, IC3; or the victim's country): that comes
first (`route["agent"]`). The instrument LE sends is the LE path's when the reply names only a police receipt (the
victim's answer: `asked`).

**Clocks.** The playbook's deadlines of the request's path, the paths it leads to and the one the reply names, from the
event that starts each (our letter, their acknowledgement, a temporary freeze they report, a hold a person confirmed, an
order a person recorded); a hold expiry only once a person confirmed the hold. Rules only, no AI.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from app.blocks import classify_rules as rules
from app.blocks import extract as ex
from app.db.models import CorrespondenceStatus
from app.domain import playbook as pbm

PATH_KEY = "_block_path"  # cases.facts: {request key: [{step, outcome, at, by, note}]}: the steps a person confirmed
STEPS = ("notice_sent", "provider_ack", "provider_ask", "hold_discretionary", "le_only_redirect", "le_route_open",
         "le_filed", "binding_instrument", "cross_border", "outcome")
RANK = {s: i for i, s in enumerate(STEPS)}
STEP_LABELS = {
    "notice_sent": "Notice sent", "provider_ack": "Provider acknowledged", "provider_ask": "Provider asks for more",
    "hold_discretionary": "Temporary hold", "le_only_redirect": "LE process required", "le_route_open": "LE briefed",
    "le_filed": "LE request filed", "binding_instrument": "Order obtained", "cross_border": "Cross-border request",
    "outcome": "Outcome",
}
OUTCOMES = {"frozen": "frozen", "funds_returned": "funds returned", "released": "released",
            "declined_terminal": "declined (final)", "funds_moved": "funds moved on"}
CONFIRM_STEPS = ("le_filed", "binding_instrument", "cross_border", "outcome")  # a person records these
CONFIRM_OUTCOMES = ("funds_moved", "declined_terminal")  # frozen / returned: Confirm status, with the amount
EVIDENCE_LABELS = {
    **ex.ASK_LABELS, "trace_report_run": "trace report", "balance_reading": "balance reading at a pinned block",
    "freeze_check": "on-chain freeze check", "special_proxy": "special power of attorney (procura speciale)",
    "mlat_bundle": "MLAT bundle", "native_vs_bridged_stmt": "native vs bridged token statement",
    "prior_ticket_ref": "their ticket number", "urgency_stmt": "urgency statement (funds about to move)",
    "domestic_order": "the domestic order (to be recognised abroad)", "court_order": "court order",
    "freeze_check_run": "freeze check",
}
CLOCK_LABELS = {**ex.DEADLINE_LABELS, "file_by": "file by", "recognise_by": "recognition by",
                "execute_by": "execution by", "validate_by": "validation by", "decide_by": "decision by"}
HOLD_WHAT = frozenset({"hold_until", "auto_lift"})
ACTION_WHAT = frozenset({"submit_by", "file_by"})  # our side acts (a later letter of ours meets it)
PRIVATE_BY = frozenset({"victim", "pi", "counsel"})
POSITIVE_STEP = {rules.HOLD_PLACED: ("hold_discretionary", None), rules.FROZEN: ("outcome", "frozen"),
                 rules.FUNDS_RETURNED: ("outcome", "funds_returned")}
_TEMP_FREEZE = re.compile(r"\btemporar(?:y|ily)\s+(?:freez\w*|frozen|hold|held|block\w*|restrict\w*|suspen\w*)|"
                          r"\bprecautionary\s+(?:hold|freeze|block|measure)|"
                          r"\bwe\s+have\s+(?:(?:temporarily\s+)?(?:frozen|blocked|restricted)|placed\s+a\s+(?:temporary\s+)?"
                          r"(?:hold|freeze|restriction))", re.IGNORECASE)
LEAD_MAX = timedelta(hours=72)


def _aware(v: datetime | None) -> datetime | None:
    return v if v is None or v.tzinfo else v.replace(tzinfo=UTC)


def _iso(v: Any) -> datetime | None:
    try:
        return _aware(datetime.fromisoformat(v)) if isinstance(v, str) and v else None
    except ValueError:
        return None


@dataclass
class LETarget:
    """An LE authority of the case as a recipient of our brief: its jurisdiction (ISO code) and what its playbook says
    it can issue to whom (`issues`: {instrument type: {org keys}})."""

    authority: Any
    jur: str | None
    playbook: Any = None

    @property
    def name(self) -> str:
        return self.authority.name

    def issues_to(self, org_key: str | None) -> set[str]:
        pb = self.playbook
        return {i.instrument for i in (pb.issues if pb is not None else ()) if org_key and org_key in i.to}

    @property
    def role(self) -> str | None:  # police | judicial | intake | coordination (the LE playbook's le_role)
        return getattr(self.playbook, "le_role", None)

    @property
    def briefable(self) -> bool:
        """It files with a provider itself: never a complaint intake portal (IC3), which only refers."""
        return self.role != "intake"

    @property
    def reachable(self) -> bool:
        """A named officer or an e-mail address on file."""
        return any(getattr(c, "email", None) or getattr(c, "name", None)
                   for c in getattr(self.authority, "le_contacts", ()) or ())

    @property
    def reference(self) -> str | None:
        return next((c.reference for c in getattr(self.authority, "le_contacts", ()) or () if c.reference), None)


def le_targets(authorities: list, playbook_for=None) -> list[LETarget]:
    out = []
    for a in authorities:
        try:
            pb = playbook_for(a) if playbook_for is not None else None
        except Exception:  # noqa: BLE001 - an invalid catalogue: no LE playbook
            pb = None
        jur = pbm.jurisdiction_code(a.jurisdiction) or (pb.jurisdiction if pb is not None and pb.jurisdiction != "EU"
                                                        else None)
        out.append(LETarget(authority=a, jur=jur, playbook=pb))
    return out


@dataclass
class PathState:
    step: str | None = None
    outcome: str | None = None
    suggests: str | None = None  # a positive step only a person confirms (hold_discretionary / outcome:frozen)
    path: Any = None  # the playbook Path our request follows
    target: Any = None  # the LE / court path the provider points to
    instrument: dict | None = None  # {type, label, issuer_jurisdictions, source: reply | playbook}: what LE sends
    asked: dict | None = None  # the instrument the reply names (a police receipt the victim answers with, an order)
    route: dict | None = None  # {kind direct | cross_border, le, jur, acts_on, options, text}
    le: LETarget | None = None  # the LE authority to brief
    links: list[dict] = field(default_factory=list)  # our letters to LE / counsel linked to this request
    confirmed: dict | None = None  # the person's latest step
    history: list[dict] = field(default_factory=list)  # [{step, outcome, at, why}] oldest first
    handoff: bool = False  # the provider never holds on a private letter: brief LE now
    clocks: list[dict] = field(default_factory=list)  # playbook clocks with a known start
    hold_at: datetime | None = None  # a person confirmed the hold (the provider's statement of it)
    freeze_at: datetime | None = None  # the provider reported a (temporary) freeze, confirmed or not
    hold_expires_at: datetime | None = None
    lapsed: dict | None = None  # {at, kind hold_expired | condition_missed, clock}: the hold may be gone (lapsed())
    evidence: list[dict] = field(default_factory=list)  # [{key, label}] the next step needs
    le_evidence: list[dict] = field(default_factory=list)  # [{key, label}] LE's request needs (the LE brief)
    requester: str = "pi"  # who our letters come from (app.domain.sender.requester_kind)
    victim_jur: str | None = None  # the victim's country (ISO code)
    fact_known: datetime | None = None  # when the victim learned of the offence (the case's fraud date)

    @property
    def label(self) -> str:
        if self.step is None:
            return ""
        if self.step == "outcome" and self.outcome:
            return f"Outcome: {OUTCOMES.get(self.outcome, self.outcome)}"
        return STEP_LABELS[self.step]

    @property
    def suggests_label(self) -> str | None:
        if not self.suggests:
            return None
        step, _, out = self.suggests.partition(":")
        return f"Outcome: {OUTCOMES.get(out, out)}" if out else STEP_LABELS.get(step, step)

    def view(self) -> dict:
        return {"step": self.step, "label": self.label, "outcome": self.outcome, "suggests": self.suggests,
                "suggests_label": self.suggests_label, "path": getattr(self.path, "key", None),
                "target": getattr(self.target, "key", None), "instrument": self.instrument,
                "route": {k: v for k, v in (self.route or {}).items() if k != "le"} or None,
                "le": self.le.name if self.le is not None else None, "confirmed": self.confirmed,
                "links": [{k: v for k, v in x.items()} for x in self.links], "handoff": self.handoff,
                "evidence": list(self.evidence), "history": list(self.history),
                "hold_expires_at": self.hold_expires_at}


# --------------------------------------------------------------------------- path choice
KIND_PREF = ("victim_report", "private_notice", "takedown", "complaint", "data_disclosure", "release")


_MEMBERS_ONLY = re.compile(r"\b(?:VIP|members?|clients?|customers?|account[- ]holders?)\s+only\b|\bonly\s+(?:for\s+)?"
                           r"(?:verified\s+)?(?:VIP|members|existing\s+(?:users|clients|customers))\b", re.IGNORECASE)


def members_only(p) -> bool:
    """The path's own notes limit it to the provider's members (Bybit's VIP portal): never a stranger's route."""
    return bool(_MEMBERS_ONLY.search(f"{getattr(p, 'notes', '') or ''} "
                                     f"{getattr(getattr(p, 'instrument', None), 'notes', '') or ''}"))


def our_path(pb, requester: str):
    """The playbook path a letter from `requester` takes: an open one, the provider's own victim intake first (a
    members-only intake, such as a VIP portal, after the general one)."""
    if pb is None:
        return None
    open_ = pb.open_paths(requester)
    return min(open_, key=lambda p: (KIND_PREF.index(p.kind) if p.kind in KIND_PREF else 99, members_only(p)),
               default=None)


def _target(pb, path, named: str | None, chains=()):
    """The LE / court path the provider points to: the one its reply names, else our path's on_refusal, else its first
    LE path; an LE request on one chain only (Tether's T3 FCU form for USDT on TRON) when every address is there."""
    if pb is None:
        return None
    out = None
    for key in (named, getattr(path, "on_refusal", None)):
        p = pb.path(key) if key else None
        if p is not None and not (set(p.requester) & pbm.PRIVATE and p.kind in ("victim_report", "private_notice")):
            out = p
            break
    out = out or next((p for p in pb.paths if "le" in p.requester and p.kind in ("le_request", "court_order")), None)
    chains = {c for c in chains if c}
    if chains and (out is None or out.kind == "le_request"):
        only = [p for p in pb.paths if p.kind == "le_request" and "le" in p.requester and len(chains) == 1
                and p.key.endswith("_" + next(iter(chains)))]
        out = only[0] if only else out
    return out


def _chains(row) -> set[str]:
    ids = (row.order.identifiers or {}) if getattr(row, "order", None) is not None else {}
    out = {(a.get("chain") or ids.get("chain")) for a in ids.get("addresses") or [] if isinstance(a, dict)}
    return {c for c in out if c}


def _chain(pb, path, limit: int = 3) -> list:
    out, p = [], path
    while p is not None and len(out) < limit and p not in out:
        out.append(p)
        p = pb.path(p.on_refusal) if p.on_refusal else None
    return out


def _label(itype: str | None) -> str:
    return ex.INSTRUMENT_LABELS.get(itype or "", pbm.INSTRUMENTS.get(itype or "", itype or "LE process"))


def channel_labels(org, keys, *, le_only: bool | None = None) -> list[str]:
    """The labels of an organisation's channels `keys` (only the LE-only ones / the others with `le_only`)."""
    out = []
    for c in getattr(org, "channels", ()) or ():
        if c.key in keys and (le_only is None or (c.who == "le_only") == le_only):
            out.append((c.label or c.key) + (" (LE only)" if c.who == "le_only" else ""))
    return out


# --------------------------------------------------------------------------- derivation
def _reply_step(r, path) -> tuple[str, str | None, str] | None:
    """(step, outcome, why) a reply moves the request to, or None. Positive readings never: `_suggests`."""
    x = r.extract or {}
    st = r.human.get("status") if r.human is not None else r.status
    le_signal = any(s.get("means") == rules.LE_PROCESS_REQUIRED for s in x.get("signals") or [])
    ins = x.get("instrument") or {}
    ticket = r.ticket or (x.get("tickets") or [{}])[0].get("value")
    if r.human is not None and st in POSITIVE_STEP:
        step, out = POSITIVE_STEP[st]
        return step, out, "confirmed by a person"
    if st == rules.LE_PROCESS_REQUIRED:
        if ticket and set(r.rules.also or ()) & {rules.ACKNOWLEDGED, rules.AUTO_REPLY}:
            return "provider_ack", None, f"acknowledged (ticket {ticket}); acts on LE process only"
        return "le_only_redirect", None, f"requires {_label(ins.get('type'))}" if ins else "requires LE process"
    if st in (rules.DECLINED, rules.DECLINED_NO_ASSETS):
        if st == rules.DECLINED and (ins.get("type") in pbm.BINDING or le_signal):
            return "le_only_redirect", None, f"declined without {_label(ins.get('type'))}"
        # final only where nothing is there or the playbook offers no other route (no playbook: escalate through LE)
        final = st == rules.DECLINED_NO_ASSETS or (path is not None and not path.on_refusal)
        return ("outcome", "declined_terminal", "declined (final)") if final else (
            "le_only_redirect", None, "declined: escalate through law enforcement")
    if st == rules.REDIRECTED and any(c.get("class") == "vendor_portal" and c.get("le_only")
                                      for c in x.get("channels") or []):
        return "le_only_redirect", None, "pointed to an LE-only portal"
    if st in (rules.ACKNOWLEDGED, rules.AUTO_REPLY, rules.UNCLEAR) and le_signal and not ticket:
        return "le_only_redirect", None, "LE process only (their playbook's wording)"
    if st == rules.ACKNOWLEDGED or (st == rules.AUTO_REPLY and ticket):
        return "provider_ack", None, f"acknowledged{f' (ticket {ticket})' if ticket else ''}"
    if st == rules.INFO_REQUESTED:
        return "provider_ask", None, "they asked for more"
    return None


def _froze(r) -> bool:
    """The reply reports a (temporary) freeze / hold: a person's reading, a suggestion, or the rules' wording."""
    if r.human is not None:
        return r.human.get("status") in POSITIVE_STEP and r.human.get("status") != rules.FUNDS_RETURNED
    if r.extract is None:
        return False  # nothing of the reply is used
    sug = (r.outcome_suggestion or {}).get("status")
    return sug in (rules.HOLD_PLACED, rules.FROZEN) or r.rules.status in (rules.HOLD_PLACED, rules.FROZEN) or \
        temp_freeze_stated(r.own or "") or any(s.get("means") == rules.HOLD_PLACED
                                                for s in (r.extract or {}).get("signals") or [])


def temp_freeze_stated(own: str) -> bool:
    """The sender's own text reports a temporary freeze / hold it placed, not negated, conditional, future or asked
    about ("can only place a temporary freeze after we receive a police report" is none): the rules' outcome guard."""
    for start, sent in rules.sentences(own):
        probe = rules.match_text(sent)
        rest = rules.match_text(rules.lift_context(own, start + len(sent)))
        if any(not rules._blocked(probe, m.start(), rules.HOLD_PLACED, m.end(), rest)
               for m in _TEMP_FREEZE.finditer(probe)):
            return True
    return False


def _moved_to(row) -> list[dict]:
    """New wallets a reply names as where the funds went (withdrawn / transferred / sent out to …)."""
    out = []
    for r in row.replies:
        x = r.extract or {}
        if r.human is None and r.rules.status != rules.DECLINED_NO_ASSETS:
            continue
        if _MOVED_OUT.search(r.own or ""):
            out += [i for i in x.get("identifiers") or [] if i.get("watch")]
    return out


_EXTERNAL = re.compile(r"\b(?:external|another\s+(?:exchange|platform|service|provider|vasp)|third[- ]party|"
                       r"outside\s+(?:our|the)\s+platform|off[- ]platform|not\s+(?:on|at)\s+our)\b", re.IGNORECASE)
# the wallet itself is at the replying provider: an internal transfer, a sub-account, "on our platform", or a deposit
# address credited to a UID / account there (never a UID that only names who withdrew the funds out)
_INTERNAL = re.compile(r"\b(?:internal\s+transfer|sub-?accounts?|on\s+our\s+(?:platform|exchange)|within\s+(?:our|the)\s+"
                       r"platform|deposit\s+address(?:es)?\b[^.;]{0,60}?\b(?:belonging\s+to|of|for|credited\s+to|"
                       r"linked\s+to|owned\s+by|registered\s+to|assigned\s+to)\s+(?:the\s+|an?\s+|another\s+)?"
                       r"(?:UID|user(?:'s)?(?:\s*ID|\s+account)?|account(?:\s+(?:ID|number|holder))?)\b|(?:UID|user\s*ID)"
                       r"[:\s]*\d+(?:'s|\u2019s)\s+deposit\s+address)", re.IGNORECASE)
_INTERNAL_WEAK = re.compile(r"\b(?:another\s+(?:account|user)\b|to\s+(?:the\s+)?(?:UID|user\s*ID|account\s+(?:ID|number))\b)",
                            re.IGNORECASE)
_MOVED_VERB = re.compile(r"\b(?:withdrawn|withdrew|withdrawal|transferred\s+out|sent\s+out|moved\s+out|swept|paid\s+out)"
                         r"\b[^.;]{0,120}?\b(?:to|into)\b", re.IGNORECASE)
# chains and self-custody wallet products that carry an exchange's name: never a deposit address at that exchange
_PRODUCTS = re.compile(r"\b(?:binance\s+smart\s+chain|bnb\s+(?:smart\s+|beacon\s+)?chain|op\s?bnb|bsc|bep-?20|bep-?2|"
                       r"kucoin\s+community\s+chain|kcc|okx?\s*chain|okt\s*chain|x\s*layer|"
                       r"(?:binance|coinbase|okx|bybit|gate(?:\.io)?|kucoin|bitget|mexc|kraken)\s+(?:web3\s+)?wallet|"
                       r"okx\s+web3|coinbase\s+(?:smart\s+)?wallet|base\s+(?:chain|network))\b", re.IGNORECASE)
_CUSTODY_BEFORE = re.compile(r"(?:\b(?:at|on|with|of|held\s+(?:at|by)|operated\s+by|hosted\s+(?:at|by)|belonging\s+to|"
                             r"belongs?\s+to|owned\s+by|controlled\s+by|registered\s+(?:to|with)|is(?:\s+an?)?)"
                             r"\s+(?:the\s+)?(?:(?:crypto\s+)?exchange\s+|platform\s+)?|\b(?:exchange|platform|service|"
                             r"vasp|provider|custodian)\s*\(\s*)$", re.IGNORECASE)
# "withdrew the funds to 0x… (Binance)": the address (blanked) right before a parenthesis that holds only the name
_CUSTODY_PAREN = re.compile(r"(?:^|\s)\(\s*$")
_CUSTODY_AFTER = re.compile(r"^(?:'s|\u2019s)?\s*(?:deposit|accounts?|users?|UID|hot\s+wallet|exchange|platform|customer|"
                            r"client|sub-?account)\b", re.IGNORECASE)
_BACKREF = re.compile(r"\b(?:this|that|it|which|the\s+(?:address|wallet|destination))\b", re.IGNORECASE)
_DEPOSIT_AT = re.compile(r"\bdeposit\s+address\b", re.IGNORECASE)


def _custodian_in(text: str, orgs: dict | None, own_key: str | None) -> tuple[str, str] | None:
    """The custodial service `text` names as holding the wallet: its name / alias with custody context next to it
    ("a deposit address at Binance", "another exchange (Binance)", "the Binance account UID …"), never a chain or a
    self-custody wallet product named after it (BEP20 / Binance Smart Chain, Coinbase Wallet)."""
    low = _PRODUCTS.sub(" ", text)
    for alias, (k, n) in (orgs or {}).items():
        if k == own_key:
            continue
        for m in re.finditer(rf"(?<![A-Za-z0-9]){re.escape(alias)}(?![A-Za-z0-9])", low, re.IGNORECASE):
            before = low[max(0, m.start() - 60):m.start()]
            if _CUSTODY_BEFORE.search(before) or _CUSTODY_AFTER.search(low[m.end():]) or (
                    _CUSTODY_PAREN.search(before) and re.match(r"\s*\)", low[m.end():])):
                return k, n
    return None


def destinations(row, orgs: dict[str, tuple[str, str]] | None = None) -> list[dict]:
    """Where the provider's replies say the funds went: each new wallet they name (a watch identifier), classified by
    the sentence that names it (and the next one or two when they refer back to it: "… withdrawn to 0x… . Our records
    show this is a deposit address at Binance."). `orgs`: {lower-case name / alias: (catalogue key, display name)} of
    the services that hold custody (exchanges, casinos, swap services: recovery._custodians). Each {value, chain,
    reply_id, where, org, accounts}: where "other" (a deposit address at another service: `org` = (key, name), or an
    unnamed external exchange), "own" (the wallet is at the replying provider itself: an internal transfer, a
    sub-account, a deposit address credited to a UID there: ask it to extend the hold) or "unknown" (an external
    wallet, including one the account holder withdrew to: an issuer can blacklist it if it holds USDT / USDC)."""
    out, seen = [], set()
    own_key = getattr(row, "org_key", None)
    for r in reversed(row.replies):  # the latest reply's word on a wallet wins
        x = r.extract or {}
        own = r.own or ""
        sents = [t for _, t in rules.sentences(own)]
        ids = x.get("identifiers") or []
        accounts = [i["value"] for i in ids if i.get("kind") == "account" and not i.get("known")]
        wallets = {i.get("value") for i in ids if i.get("watch") and i.get("value")}
        for i in ids:
            v = i.get("value") or ""
            if not i.get("watch") or not v or v in seen:
                continue
            seen.add(v)
            at = next((n for n, t in enumerate(sents) if v in t), None)
            sent = sents[at] if at is not None else own
            low = sent.replace(v, " ")
            org = _custodian_in(low, orgs, own_key)
            other = org is not None or bool(_DEPOSIT_AT.search(low) and _EXTERNAL.search(low))
            if not other and at is not None and not _DEPOSIT_AT.search(low):
                for nxt in sents[at + 1:at + 3]:  # "Our records show this is a deposit address at Binance."
                    if any(w in nxt for w in wallets) or not _BACKREF.search(nxt):
                        break
                    org = _custodian_in(nxt, orgs, own_key)
                    if org is not None or (_DEPOSIT_AT.search(nxt) and _EXTERNAL.search(nxt)):
                        other = True
                        break
            if other:
                where = "other"
            elif not _EXTERNAL.search(low) and (_INTERNAL.search(low) or _INTERNAL_WEAK.search(low)
                                                 and not _MOVED_VERB.search(sent[:max(0, sent.find(v))])):
                where = "own"
            else:
                where = "unknown"  # an external wallet, or one withdrawn out to (a UID there only names who withdrew)
            out.append({"value": v, "chain": i.get("chain"), "reply_id": i.get("reply_id") or r.corr.id,
                        "where": where, "org": org,
                        "accounts": [a for a in accounts if a in sent] if where == "own" else []})
    return out


_MOVED_OUT = re.compile(r"\b(?:withdrawn|withdrew|transferred\s+out|sent\s+out|moved\s+out|swept|paid\s+out)\b"
                        r"[^.;]{0,120}?\b(?:to|into)\b", re.IGNORECASE)


def advance(row, pb, *, requester: str = "pi", links: list[dict] | None = None, confirmed: list[dict] | None = None,
            le: list[LETarget] | None = None, now: datetime | None = None, org=None,
            victim_jur: str | None = None, fact_known: datetime | None = None) -> PathState:
    """Where `row` (a status.BlockRow, after _derive) stands: see the module doc. `victim_jur`: the victim's country
    (ISO code): a provider that acts on its authorities can be asked by a case agent there."""
    now = now or datetime.now(tz=UTC)
    st = PathState(links=list(links or []), requester=requester, victim_jur=victim_jur, fact_known=_aware(fact_known))
    if row.status in ("not_sent", "sent_review", "onchain_only") or row.requested_at is None:
        return st
    path = our_path(pb, requester)
    st.path = path
    # (step, outcome, at, why, firm): firm = a person's reading (a confirmed reply, a recorded status or step, our
    # sent letter); a later firm step supersedes an earlier soft end (declined / funds moved), and any later step one
    # only the rules read
    hist: list[tuple[str, str | None, datetime, str, bool]] = [("notice_sent", None, row.requested_at, "our letter",
                                                                 True)]
    named = None
    for r in row.replies:
        x = r.extract or {}
        if x.get("instrument") and x["instrument"].get("path"):
            named = x["instrument"]["path"]
        for s in x.get("signals") or []:
            if s.get("means") == rules.LE_PROCESS_REQUIRED and s.get("path"):
                named = named or s["path"]
        hit = _reply_step(r, path)
        if hit is not None:
            hist.append((hit[0], hit[1], r.at, hit[2], r.human is not None))
        if _froze(r):
            st.freeze_at = st.freeze_at or r.at
            if r.human is not None and r.human.get("status") in (rules.HOLD_PLACED, rules.FROZEN):
                st.hold_at = st.hold_at or r.at
    rec, rec_at = getattr(row, "recorded", None), getattr(row, "recorded_at", None) or row.requested_at
    if rec == rules.FROZEN:
        held = any(r.human is not None and r.human.get("status") == rules.HOLD_PLACED for r in row.replies)
        hist.append(("hold_discretionary", None, rec_at, "hold recorded", True) if held else
                    ("outcome", "frozen", rec_at, "recorded on the stop order", True))
        st.hold_at = st.hold_at or rec_at
        st.freeze_at = st.freeze_at or rec_at
    elif rec == rules.FUNDS_RETURNED:
        hist.append(("outcome", "funds_returned", rec_at, "recorded on the stop order", True))
    elif rec == rules.DECLINED:
        final = path is not None and not path.on_refusal
        hist.append(("outcome", "declined_terminal", rec_at, "recorded declined", True) if final else
                    ("le_only_redirect", None, rec_at, "recorded declined: escalate through law enforcement", True))
    elif rec == rules.ACKNOWLEDGED:
        hist.append(("provider_ack", None, rec_at, "recorded acknowledged", True))
    for ln in st.links:
        if ln.get("sent") and ln.get("at"):
            who = "counsel" if ln.get("counsel") else "LE"
            hist.append(("le_route_open", None, ln["at"], f"{who} briefed (letter #{ln['id']})", True))
    for c in confirmed or []:
        at = _iso(c.get("at")) or now
        if c.get("step") in RANK:
            hist.append((c["step"], c.get("outcome"), at, "recorded by a person", True))
            st.confirmed = c
    hist.sort(key=lambda h: h[2])
    best = hist[0]
    for h in hist[1:]:  # the furthest step; a later outcome replaces an earlier one; a soft end gives way (above)
        soft_end = best[0] == "outcome" and best[1] in ("declined_terminal", "funds_moved") and (h[4] or not best[4])
        if h[0] == "outcome" or soft_end or best[0] != "outcome" and RANK[h[0]] >= RANK[best[0]]:
            best = h
    st.step, st.outcome = best[0], best[1]
    st.history = [{"step": h[0], "outcome": h[1], "at": h[2], "why": h[3]} for h in hist]
    if st.hold_at is not None and any(h[0] == "outcome" and h[1] != "frozen" and h[2] > st.hold_at for h in hist):
        st.hold_at = None  # the hold ended (returned, declined, the funds moved on): its expiry no longer runs
    # a positive reading nobody confirmed: shown, never the step. A temporary freeze the provider reports is a hold
    # to confirm whatever else the reply says ("frozen for 48 hours; an LE request must follow")
    sug = getattr(row, "suggestion", None)
    if sug is not None and sug.get("status") in POSITIVE_STEP:
        step, out = POSITIVE_STEP[sug["status"]]
        if st.step != "outcome" and (RANK[step] >= RANK[st.step] or step == "hold_discretionary"):
            st.suggests = f"{step}:{out}" if out else step
    elif st.freeze_at and st.hold_at is None and st.step != "outcome":
        st.suggests = "hold_discretionary"
    elif st.step == "outcome" and st.outcome == "declined_terminal" and _moved_to(row):
        st.suggests = "outcome:funds_moved"  # "withdrawn to T…": a person records it, then the destination is the lead
    # the instrument and the path the provider points to
    ins = row.intel["instrument"]
    st.target = _target(pb, path, named, _chains(row))
    if ins:
        st.asked = {"type": ins["type"], "label": ins.get("label") or _label(ins["type"]),
                    "issuer_jurisdictions": list(ins.get("issuer_jurisdictions") or []), "source": "reply"}
    if ins and (ins["type"] in pbm.BINDING or st.target is None):
        st.instrument = st.asked
    elif st.target is not None:
        # what LE sends: the LE path's instrument, never the police receipt the reply asks of the victim (MEXC: the
        # victim answers with the receipt, LE sends a freezing order through LEORS)
        t = st.target.instrument
        st.instrument = {"type": t.type, "label": _label(t.type), "issuer_jurisdictions": list(t.issuer_jurisdictions),
                         "source": "playbook"}
    exp = set(getattr(path, "expected_replies", ()) or ())
    st.handoff = bool(path is not None and rules.LE_PROCESS_REQUIRED in exp
                      and not exp & {rules.HOLD_PLACED, rules.FROZEN} and st.target is not None)
    st.route, st.le = _route(pb, st, le or [], getattr(org, "key", None))
    st.clocks = clocks(row, st, pb, now=now)
    holds = [c["due_at"] for c in st.clocks if c["what"] in HOLD_WHAT and c["starts"] == "hold_confirmed"]
    st.hold_expires_at = min(holds) if holds else None
    tgt = st.target if st.step in ("le_only_redirect", "le_route_open", "hold_discretionary") or st.handoff else path
    opt = ((st.route or {}).get("options") or [{}])[0] if (st.route or {}).get("kind") == "cross_border" else {}
    urgent = (st.route or {}).get("urgent") or {}
    if tgt is st.target and (st.route or {}).get("agent") is not None and (st.route or {}).get("case_agent", True):
        # the leading route is a domestic case agent asking directly: what its request needs (Circle: the urgent LE
        # request, else the LE path), never the cross-border fallback's domestic order to recognise abroad
        tgt = pb.path(urgent["path"]) if urgent.get("path") and pb.path(urgent["path"]) is not None else tgt
    elif tgt is st.target and opt.get("path") and pb.path(opt["path"]) is not None:
        tgt = pb.path(opt["path"])  # what the route's first instrument needs (a domestic order to recognise, …)
    st.evidence = _evidence(tgt)
    # what LE's own request needs (the LE brief): the LE path's evidence even while our step is still the victim's
    # (MEXC after a temporary freeze: the Order states the duration, not the victim's ID)
    le_tgt = st.target
    if le_tgt is not None and opt.get("path") and pb.path(opt["path"]) is not None:
        le_tgt = pb.path(opt["path"])
    st.le_evidence = _evidence(le_tgt) if le_tgt is not None else list(st.evidence)
    return st


def _evidence(p) -> list[dict]:
    return [{"key": k, "label": EVIDENCE_LABELS.get(k, k.replace("_", " "))} for k in (getattr(p, "evidence", ()) or ())]


def _route(pb, st: PathState, le: list[LETarget], org_key: str | None) -> tuple[dict | None, LETarget | None]:
    """The LE authority to brief and whether it can ask the provider directly (see the module doc)."""
    if not le:
        return None, None
    ins = st.instrument or {}
    acts = list(ins.get("issuer_jurisdictions") or []) or list(
        getattr(getattr(st.target, "instrument", None), "issuer_jurisdictions", ()) or ()) or list(
        getattr(pb, "issuer_jurisdictions", ()) or ())

    def kind(t: LETarget) -> str | None:
        if not acts or t.jur is None:
            return None
        return "direct" if t.jur in acts or ("EU" in acts and t.jur in pbm.EU) else "cross_border"

    # a court / judicial instrument (never a freezing order LE issues itself: Binance, MEXC, KuCoin)
    strong = ins.get("type") not in (None, "none", "police_report", "le_request") and not le_issued(st)

    def judicial_first(t: LETarget) -> bool:  # binding or cross-border: the prosecutor (PM), not the police station
        return t.role == "judicial" and (strong or kind(t) == "cross_border")

    def domestic(t: LETarget) -> bool:  # LE process LE sends itself: the victim's own country's agent asks fastest
        return not strong and bool(st.victim_jur) and t.jur == st.victim_jur

    ranked = sorted(le, key=lambda t: (not t.briefable, kind(t) != "direct", kind(t) is None and bool(acts),
                                       not domestic(t), not t.issues_to(org_key), not judicial_first(t),
                                       not t.reachable, le.index(t)))
    chosen = ranked[0]
    k = kind(chosen)
    route = {"kind": k, "le": chosen.name, "jur": chosen.jur, "acts_on": acts, "options": [], "text": None,
             "direct": [t.name for t in le if kind(t) == "direct" and t is not chosen and t.briefable],
             "intake": [{"name": t.name, "reference": t.reference} for t in le if not t.briefable],
             "case_agent": chosen.briefable, "counsel": _counsel(pb, acts), "agent": None,
             # no named officer / e-mail on file for the chosen one: a reachable authority of the same route
             "reachable": None if chosen.reachable else next(
                 (t.name for t in ranked[1:] if t.briefable and t.reachable and kind(t) == kind(chosen)), None)}
    private = st.requester in PRIVATE_BY
    if k == "cross_border" or not chosen.briefable:
        route["agent"] = _agent(le, acts, st.victim_jur)
    jur = chosen.jur if k == "direct" and chosen.briefable else (route["agent"] or {}).get("jur")
    route["urgent"] = _urgent(pb, ins.get("type"), jur) if jur and strong else None
    if not chosen.briefable:
        route["kind"] = k = None  # a complaint intake (IC3) files nothing: get a case agent assigned, or counsel
        return route, chosen
    if k != "cross_border":
        return route, chosen
    issued = chosen.issues_to(org_key)
    opts = []
    for p in getattr(pb, "paths", ()) or ():
        t = p.instrument.type
        if p.kind != "cross_border":
            continue
        to = list(p.instrument.issuer_jurisdictions)
        if t in ("eu_freezing_order", "eio") and not (chosen.jur in pbm.EU and any(j in pbm.EU for j in to)):
            continue
        opts.append({"path": p.key, "type": t, "to": to, "issued": t in issued,
                     "text": _label(t) + (f" to {'/'.join(to)}" if to else "")})
    if route["counsel"]:
        opts.append({**route["counsel"], "issued": False})
    if not opts:
        opts = [{"path": None, "type": "mlat", "to": acts, "issued": "mlat" in issued,
                 "text": f"{_label('mlat')} to {'/'.join(acts)}"}]
    opts.sort(key=lambda o: not o["issued"])
    route["options"] = opts
    # counsel for a private client goes in the "in parallel" line (path.action), never last in the LE list
    texts = [o["text"] for o in opts if not (private and o["type"] == "counsel")] or [o["text"] for o in opts]
    route["text"] = (f"{chosen.name} ({chosen.jur}) cannot ask directly: the provider acts only on "
                     f"{' or '.join(acts)} authorities and courts. The cross-border route is " + (", ".join(texts[:-1]) + " or " + texts[-1]
                                                                   if len(texts) > 1 else texts[0]) + ".")
    return route, chosen


def le_issued(st: PathState) -> bool:
    """The freezing order is one law enforcement sends itself (Binance: "an appropriate official freezing order from
    law enforcement or a court"; MEXC: "an Order from an authorised LE agency or judicial body"; KuCoin: "a freezing
    order ... from law enforcement"): the LE path the provider points to takes it from LE, so no court application
    comes first."""
    t = st.target
    return (st.instrument or {}).get("type") == "freezing_order" and t is not None and t.kind == "le_request" \
        and "le" in t.requester


def le_only(st: PathState | None, pb=None) -> bool:
    """The provider acts on law-enforcement process only for letters from us: its reply says so (an LE-only redirect,
    an instrument the reply names), or its playbook does (our path expects "LE process required" and never a hold —
    the Recovery plan's "acts on LE process only" —, or no path is open to our requester: the LE-only gate). The one
    test behind "requires <instrument>" (Block status and its exports, the LE brief): a provider that may hold on our
    notice ("voluntary hold possible") or only flags and preserves never "requires an LE request"."""
    if st is None:
        return False
    if st.step == "le_only_redirect" or st.handoff or (st.asked or {}).get("source") == "reply":
        return True
    path = st.path
    exp = set(getattr(path, "expected_replies", ()) or ()) | set(getattr(path, "outcomes", ()) or ())
    if path is not None and rules.LE_PROCESS_REQUIRED in exp and not exp & {rules.HOLD_PLACED, rules.FROZEN}:
        return True
    return bool(pb is not None and getattr(pb, "paths", None) and pb.gate(st.requester).reason)


def ask_label(st: PathState, *, jur: bool = False) -> str:
    """The instrument LE is asked for, one wording everywhere (the next action, the hold preview, the brief): a freezing
    order LE issues itself reads "on LE letterhead (no court application first)"; `jur` adds the issuer jurisdictions
    inside that parenthesis."""
    ins = st.instrument or {}
    j = "/".join(ins.get("issuer_jurisdictions") or []) if jur else ""
    if le_issued(st):
        return f"a freezing order on LE letterhead ({f'{j}; ' if j else ''}no court application first)"
    return (ins.get("label") or "LE process") + (f" ({j})" if j and ins.get("type") != "us_or_fr_court_order" else "")


def _urgent(pb, itype: str | None, jur: str) -> dict | None:
    """An LE request the provider acts on pending a court order (Circle: an urgent LE request blocks until the order
    follows), for an authority of `jur` facing a court instrument: the same-day ask before the order exists."""
    if itype in (None, "none", "police_report", "le_request"):
        return None
    p = next((p for p in getattr(pb, "paths", ()) or () if p.kind == "le_request" and "le" in p.requester
              and p.instrument.type == "le_request"
              and (not p.instrument.issuer_jurisdictions or jur in p.instrument.issuer_jurisdictions)), None)
    if p is None:
        return None
    return {"path": p.key, "label": _label(p.instrument.type), "confidence": p.prov.confidence}


def _agent(le: list[LETarget], acts: list[str], victim_jur: str | None) -> dict | None:
    """A case agent in a country the provider acts on, when none is on the case yet: through the complaint intake's
    reference there (IC3: the FBI assigns a field-office agent) or in the victim's own country. Never when a briefable
    authority there is already on the case (that one is chosen and asks directly)."""
    if not acts:
        return None

    def ok(j: str | None) -> bool:
        return bool(j) and (j in acts or ("EU" in acts and j in pbm.EU))

    if any(t.briefable and ok(t.jur) for t in le):
        return None
    intake = next((t for t in le if not t.briefable and ok(t.jur)), None)
    jur = intake.jur if intake is not None else (victim_jur if ok(victim_jur) else None)
    if jur is None:
        return None
    return {"jur": jur, "via": intake.name if intake is not None else None,
            "via_key": intake.authority.key if intake is not None else None,
            "reference": intake.reference if intake is not None else None,
            "who": "an FBI field office or the USSS" if jur == "US" else "the national police / prosecutor"}


def _counsel(pb, acts: list[str]) -> dict | None:
    """The court-order path counsel can take for a private client (Circle: a US or French court order), or None."""
    for p in getattr(pb, "paths", ()) or ():
        if "counsel" in p.requester and p.kind == "court_order" and p.instrument.binding:
            jur = list(p.instrument.issuer_jurisdictions) or acts
            return {"path": p.key, "type": "counsel", "instrument": p.instrument.type, "to": jur,
                    "text": f"counsel for {_label(p.instrument.type)}"}
    return None


# --------------------------------------------------------------------------- clocks
def _le_hold(st: PathState) -> bool:
    """The confirmed hold followed LE filing / an order: an LE path's hold term applies as stated."""
    le_at = next((h["at"] for h in st.history if h["step"] in ("le_filed", "binding_instrument", "cross_border")), None)
    return st.hold_at is not None and le_at is not None and st.hold_at >= le_at


def _starts(row, st: PathState, starts: str) -> datetime | None:
    if starts == "sent":
        return row.requested_at
    if starts == "provider_ack":
        return next((r.at for r in row.replies if r.status != rules.DELIVERY_FAILED), None)
    if starts == "provider_freeze_confirmed":
        return st.freeze_at
    if starts == "hold_confirmed":
        return st.hold_at
    if starts == "order_served":
        return next((h["at"] for h in reversed(st.history) if h["step"] == "binding_instrument"), None)
    if starts == "fact_known":
        return st.fact_known
    return None


# the clock starts the engine resolves (_starts); the others (an LE seizure, a certificate received, a recognition)
# are the LE / court side's own steps, which Aegis does not see happen: their clocks are shown in the briefs only
RESOLVED_STARTS = frozenset({"sent", "provider_ack", "provider_freeze_confirmed", "hold_confirmed", "order_served",
                             "fact_known"})


def standing_clocks(pb, fact_known: datetime | None) -> list[dict]:
    """The deadlines on the victim's side of a (LE) playbook that run from the offence itself, not from a request
    (the querela term: 3 months from learning of the fact, art. 124 c.p.): [{key, path, label, action, span, due_at
    (None: the start is unknown), start_at, by, basis, confidence}]."""
    out = []
    for p in getattr(pb, "paths", ()) or ():
        for d in p.timing.deadlines:
            if d.starts != "fact_known" or (d.by is not None and d.by not in PRIVATE_BY):
                continue
            start = _aware(fact_known)
            out.append({"key": f"{p.key}.{d.key}", "path": p.key, "what": d.what,
                        "label": CLOCK_LABELS.get(d.what, d.what), "action": d.action, "span": d.span,
                        "start_at": start, "by": d.by, "basis": d.prov.basis, "confidence": d.prov.confidence,
                        "due_at": _aware(ex.span_due(start, float(d.amount), d.unit)) if start else None})
    return out


_CARRIES = re.compile(r"\b(?:police\s+report|complaint|denuncia|querela|ic3|case\s+(?:number|reference)|"
                      r"receipt|attached|enclosed|in\s+allegato|allegat[oa])\b", re.IGNORECASE)


def _met(row, st: PathState, d, start: datetime) -> bool:
    if d.what in HOLD_WHAT:
        return st.hold_at is None and st.step == "outcome" and st.outcome != "frozen"  # a hold ended (advance)
    if st.step == "outcome" and st.outcome != "frozen":
        return True
    if d.what in ACTION_WHAT and (d.by is None or d.by in PRIVATE_BY):
        # a later letter of ours that carries what was asked (the receipt, the reference, an attachment)
        return any(_aware(c.occurred_at) and _aware(c.occurred_at) > start and c.status == CorrespondenceStatus.SENT
                   and _CARRIES.search(c.body_markdown or "") for c in row.outbound if c is not row.letter)
    if d.what in ACTION_WHAT and d.by == "le":
        return RANK.get(st.step or "", 0) >= RANK["le_filed"]
    return False


def clocks(row, st: PathState, pb, *, now: datetime) -> list[dict]:
    """The playbook's clocks of this request whose start is known: [{key, what, label, due_at, start_at, starts, by,
    action, path, span, basis, confidence, met, source "playbook"}], earliest first."""
    if pb is None or st.path is None:
        return []
    paths = _chain(pb, st.path) + ([st.target] if st.target is not None else [])
    seen, out = set(), []
    for p in paths:
        items = list(p.timing.deadlines)
        whats = {d.what for d in items}
        own = p is st.path
        for days, what in ((p.timing.auto_lift_days, "auto_lift"), (p.timing.hold_days, "hold_until")):
            if days and what not in whats:  # our path's voluntary hold; an LE path's term from the order
                items.append(pbm.Deadline(key=f"{p.key}_{what}", what=what, unit="days", amount=days,
                                          starts="hold_confirmed" if own else "order_served", by=None, action=None,
                                          prov=p.prov))
        for d in items:
            if (p.key, d.key) in seen or (p is not st.path and d.by in PRIVATE_BY and d.what in ACTION_WHAT):
                continue
            seen.add((p.key, d.key))
            start = _starts(row, st, d.starts)
            if start is None:
                continue
            # an LE path's hold term read against a voluntary hold: shown and alerted, but only "if it applies"
            approx = d.what in HOLD_WHAT and d.starts == "hold_confirmed" and not own and not _le_hold(st)
            due = _aware(ex.span_due(start, float(d.amount), d.unit))
            out.append({"key": f"{p.key}.{d.key}", "what": d.what, "label": CLOCK_LABELS.get(d.what, d.what),
                        "due_at": due, "start_at": start, "starts": d.starts,
                        "starts_label": pbm.CLOCK_STARTS.get(d.starts, d.starts), "by": d.by, "action": d.action,
                        "path": p.key, "span": d.span, "basis": d.prov.basis, "confidence": d.prov.confidence,
                        "met": _met(row, st, d, start), "source": "playbook", "approx": approx})
    return sorted(out, key=lambda c: c["due_at"])


def reply_clock(row, st: PathState) -> datetime | None:
    """The playbook's own reply time for our path (response_days, a reply_by deadline): shortens the reply clock."""
    p = st.path
    if p is None or row.requested_at is None:
        return None
    cands = [c["due_at"] for c in st.clocks if c["what"] == "reply_by" and c["path"] == p.key]
    if p.timing.response_days:
        cands.append(row.requested_at + timedelta(days=float(p.timing.response_days)))
    return min(cands) if cands else None


def lead(c: dict) -> timedelta:
    """How long before a clock falls due its alert fires: half its span, at most three days."""
    start = c.get("start_at")
    if start is None:  # no known start: a day ahead
        return timedelta(hours=24)
    return min(max((c["due_at"] - start) / 2, timedelta(hours=1)), LEAD_MAX)


def clock_text(c: dict | None) -> str:
    if not c:
        return ""
    due = c.get("due_at")
    when = f"{due:%d %b %Y %H:%M} UTC" if isinstance(due, datetime) else "—"
    src = " (stated in their reply)" if c.get("source") != "playbook" else (
        f" ({c['span']} after {c['starts_label']})" if c.get("span") else "")
    act = f": {c['action'].rstrip('.')}" if c.get("action") else ""
    return f" Clock: {c['label']} {when}{src}{act}."


# --------------------------------------------------------------------------- next action
def _ticket(row) -> str:
    return f", quoting their ticket {row.ticket}" if row.ticket else ""


def _brief_href(cid: int, row, st: PathState, counsel: bool = False) -> str | None:
    if st.le is None:
        return None
    return f"/cases/{cid}/authorities/{st.le.authority.key}?template=le_brief&ref={row.key}#generate"


def _ev(st: PathState, n: int = 6) -> str:
    return (" The pack: " + ", ".join(e["label"] for e in st.evidence[:n]) + ".") if st.evidence else ""


def _via(org, st: PathState, row=None) -> str:
    """Where the officer files: the LE inbox or portal their reply names (Tether: "direct law enforcement to
    inforequests@…"), else the playbook's LE-only channel."""
    d = row.deciding if row is not None else None
    le_mail = {str(c.value).lower() for c in getattr(org, "channels", ()) or ()
               if c.kind == "email" and c.value and getattr(c, "who", None) == "le_only"}
    mail = next((a["value"] for a in (d.addresses if d is not None else []) if str(a.get("value", "")).lower() in le_mail),
                None)
    named = mail or next((u["value"] for u in (d.urls if d is not None else [])), None)
    labels = channel_labels(org, getattr(st.target, "channel_keys", ()) or (), le_only=True)
    if mail:
        return f" through {mail} (the LE inbox their reply names)"
    return f" through {named}" if named else f" through {labels[0]}" if labels else ""


_REGIONS = {"mainland china": {"CN"}, "china": {"CN"}, "russia": {"RU", "BY"}, "belarus": {"RU", "BY"},
            "hong kong": {"HK"}}


def _foreign_region(label: str, jur: str | None) -> bool:
    """The channel's label names a region the case LE is not in ("…, mainland China (Kodex)" for an Italian case)."""
    low = label.lower()
    return jur is not None and any(r in low and jur not in js for r, js in _REGIONS.items())


def _with_note(base: str, note: str) -> str:
    """`base` (an authority page with ?template=…) with its letter's extra paragraph prefilled (routes_authorities)."""
    from urllib.parse import quote

    path, _, frag = base.partition("#")
    return f"{path}{'&' if '?' in path else '?'}note={quote(note, safe='')}" + (f"#{frag}" if frag else "")


def _victim_intake(pb, org, st: PathState, requester: str) -> str:
    p = next((p for p in getattr(pb, "paths", ()) or () if p.kind == "victim_report" and p.open_to("victim")), None)
    if p is None or p is st.path and requester == "victim" or st.freeze_at is not None:
        return ""  # nothing to add, or the provider already holds the funds
    labels = channel_labels(org, p.channel_keys, le_only=False)
    return (f" Also file their own victim report{f' ({labels[0]})' if labels else ''} with the victim if not done: it "
            "may get a temporary hold.")


def _ours(c: dict) -> bool:
    return c.get("what") in ACTION_WHAT and not c.get("met") and (c.get("by") is None or c.get("by") in PRIVATE_BY)


def our_ask(row, now: datetime) -> dict | None:
    """The earliest open deadline on our side (the victim's / ours): a submit-by / file-by the provider set (MEXC's
    police-report proof within 48 hours of its freeze), unmet and still ahead."""
    return min((c for c in getattr(row, "clocks", ()) or () if _ours(c) and c["due_at"] > now),
               key=lambda c: c["due_at"], default=None)


def missed_ask(row, now: datetime) -> dict | None:
    """The latest deadline on our side that passed unmet (MEXC's 48 hours for the police proof): never dropped
    silently, the provider may have lifted its freeze."""
    return max((c for c in getattr(row, "clocks", ()) or () if _ours(c) and c["due_at"] <= now),
               key=lambda c: c["due_at"], default=None)


def lapsed(row, st: PathState, now: datetime) -> dict | None:
    """The hold may be gone: a confirmed hold's lapse date passed with nothing turning it into an LE freeze or an
    order (an LE filing, an order, a frozen outcome recorded after it, a later expiry stated), or a freeze the provider
    reported whose condition on our side (MEXC: the police proof within 48 hours) passed unmet with no later deadline
    on our side still open. {at, kind hold_expired | condition_missed, clock}, or None."""
    if st.step == "outcome" and st.outcome != "frozen" or st.freeze_at is None and st.hold_at is None:
        return None
    took = any(h["step"] in ("le_filed", "binding_instrument", "cross_border") or h["step"] == "outcome"
               and h["outcome"] == "frozen" for h in st.history
               if h["at"] >= (st.hold_at or st.freeze_at) and h["why"] != "hold recorded")
    if st.hold_at is not None and st.hold_expires_at is not None and st.hold_expires_at <= now and not took:
        return {"at": st.hold_expires_at, "kind": "hold_expired", "clock": None}
    miss = missed_ask(row, now)
    if st.freeze_at is not None and miss is not None and our_ask(row, now) is None and not took:
        return {"at": miss["due_at"], "kind": "condition_missed", "clock": miss, "side": "ours"}
    # the LE side's clock that keeps the hold (MEXC: an LE request through LEORS within 48 hours of the temporary
    # freeze) passed with no LE filing recorded: the hold may already be lifted
    le_side = [c for c in getattr(row, "clocks", ()) or () if c.get("what") in ACTION_WHAT and c.get("by") == "le"
               and not c.get("met")]
    passed = max((c for c in le_side if c["due_at"] <= now), key=lambda c: c["due_at"], default=None)
    if passed is not None and not any(c["due_at"] > now for c in le_side) and not took:
        return {"at": passed["due_at"], "kind": "condition_missed", "clock": passed, "side": "le"}
    return None


def _asks(row) -> str:
    asks = [a.get("label") or a.get("req_key", "").replace("_", " ") for a in (row.intel.get("asks") or [])
            if a.get("label") or a.get("req_key")]
    return ", ".join(dict.fromkeys(asks)) or "what they asked for"


def action(cid: int, row, st: PathState, *, name: str, pb=None, org=None, requester: str = "pi",
           next_clock: dict | None = None, now: datetime | None = None) -> dict | None:
    """The playbook's next action for `row` at `st`, or None (the generic status text applies). {kind, text, href}
    plus `evidence` (what the next step needs) and `clock` (the next deadline)."""
    now = now or datetime.now(tz=UTC)
    if st.step is None or row.authority.is_le or row.authority.is_adviser:
        return None
    what, need = ask_label(st), ask_label(st, jur=True)
    clock = clock_text(next_clock)
    route = st.route or {}
    le_name = st.le.name if st.le is not None else None
    sent = [x for x in st.links if x.get("sent")]
    drafts = [x for x in st.links if not x.get("sent")]

    def brief(lead_in: str, tail: str = "") -> dict:
        pack = _ev(st)
        counsel = route.get("counsel")
        cto = "/".join(counsel["to"]) if counsel else ""
        par = (f" In parallel, instruct {counsel['text']}{f' ({cto})' if cto else ''}: it does not wait for LE."
               if counsel and requester in PRIVATE_BY else "")
        agent = route.get("agent")
        urgent = route.get("urgent")
        if agent is not None and route.get("case_agent", True):
            # a domestic agent asks directly; the cross-border route through the LE on the case is the slow fallback
            ref = f", quoting {agent['via']} reference {agent['reference']}" if agent.get("reference") else (
                f" through the {agent['via']} complaint" if agent.get("via") else "")
            acts = "/".join(route.get("acts_on") or [])
            first = (f" (first {urgent['label']} pending the order: {name} may block on an urgent LE request, "
                     f"confidence {urgent['confidence']})" if urgent is not None else "")
            text = (f"{lead_in} Fastest: get a {agent['jur']} case agent assigned ({agent['who']}){ref}: {name} acts "
                    f"on {acts} authorities, so the agent can ask directly{first}; then brief them with the pack"
                    f"{_ticket(row)}.{par} Slower fallback: {route.get('text') or ''} {le_name} can start it with the "
                    f"LE brief.{pack}{tail}{clock}").replace("  ", " ")
            href = (f"/cases/{cid}/authorities/{agent['via_key']}" if agent.get("via_key")
                    else f"/cases/{cid}?tab=authorities")
            return {"kind": "le", "text": text, "href": href}
        if le_name is not None and not route.get("case_agent", True):  # only a complaint intake (IC3) on the case
            ref = next((x["reference"] for x in route.get("intake") or [] if x.get("reference")), None)
            direct = (f": {name} acts on {'/'.join(route.get('acts_on') or [])} authorities, so the agent can ask "
                      "directly" if agent is not None else "")
            text = (f"{lead_in} {le_name} is a complaint intake: it does not file with {name}. Get a case agent "
                    f"assigned (an FBI field office, the USSS or local police){f', quoting {ref}' if ref else ''}"
                    f"{direct}, then brief them with the pack{_ticket(row)}"
                    + (f"; or instruct {counsel['text']} now." if counsel else ".") + f"{pack}{tail}{clock}")
            return {"kind": "le", "text": text, "href": f"/cases/{cid}?tab=authorities"}
        if le_name is None:
            text = (f"{lead_in} Add the case's LE contact (the case officer), then brief them with the pack"
                    f"{_ticket(row)}.{pack}{tail}{clock}")
            return {"kind": "le", "text": text, "href": f"/cases/{cid}/authorities/{row.authority.key}"}
        if route.get("kind") == "cross_border":
            how = f" {route['text']} Brief {le_name} with the pack{_ticket(row)}: the LE brief explains the route."
        else:
            how = f" Brief {le_name} with the pack{_ticket(row)} so the officer files it{_via(org, st, row)}."
            if urgent is not None:
                how += (f" Ask first for {urgent['label']} pending the order: {name} may block on an urgent LE "
                        f"request (confidence {urgent['confidence']}); the court order follows.")
        other = f" {', '.join(route.get('direct') or [])} can ask directly too." if route.get("direct") else ""
        intake = "".join(f" {x['name']} is a complaint intake and files nothing itself." for x in
                         route.get("intake") or [])
        draft = (f" Your LE brief #{drafts[-1]['id']} is still a draft: send it." if drafts else "")
        if route.get("reachable") and not drafts:
            other += (f" {le_name} has no named officer or e-mail on file: add one to the LE contact, or brief "
                      f"{route['reachable']} (reachable) instead.")
        return {"kind": "le", "text": f"{lead_in}{how}{pack}{other}{intake}{par}{tail}{draft}{clock}",
                "href": (f"/cases/{cid}/authorities/correspondence/{drafts[-1]['id']}" if drafts
                         else _brief_href(cid, row, st))}

    if st.step == "outcome":
        if st.outcome == "funds_moved":
            return {"kind": "trace", "text": f"The funds moved on from {name}: re-trace from their payout and send "
                                             "the next request.", "href": f"/cases/{cid}?tab=fund_flow"}
        own = [d for d in destinations(row) if d["where"] == "own"] if st.outcome == "declined_terminal" else []
        if own:  # "the reported account is empty", but the funds went to another account on its own platform
            uids = list(dict.fromkeys(u for d in own for u in d["accounts"]))
            return {"kind": "answer", "title": f"Ask {name} to freeze the account its reply names now",
                    "text": f"{name} says the reported account holds nothing now, but its reply says the funds went to "
                            f"another account / deposit address on its own platform"
                            + (f" (UID {', '.join(uids)})" if uids else "") + f": they are still at {name}. Answer at "
                            f"once{_ticket(row)}: ask {name} to freeze it and preserve the records; brief LE in "
                            "parallel.",
                    "href": f"/cases/{cid}/authorities/{row.authority.key}?template=info_response&ref={row.key}#generate"}
        dd = next((p for p in getattr(pb, "paths", ()) or () if p.kind == "data_disclosure"), None)
        if st.outcome == "declined_terminal" and row.status == rules.DECLINED_NO_ASSETS and _moved_to(row) \
                and dd is not None:
            # the funds left, but the provider keeps the account holder's KYC, the withdrawal IP and the destination
            # records: an LE disclosure request is the next lead (the wallet itself: the Recovery plan's own move)
            who = (f"Brief {le_name} with the pack" if le_name and route.get("case_agent", True) else
                   "Brief the case officer (add the case's LE contact)")
            return {"kind": "le",
                    "text": f"{name} says the funds were withdrawn to the wallet its reply names and it holds nothing "
                            f"now, but it keeps the account holder's KYC, the withdrawal IP logs and the destination "
                            f"records. {who} so the officer asks {name} for them ({_label(dd.instrument.type)})"
                            f"{_ticket(row)}; re-trace from the destination.",
                    "href": (f"/cases/{cid}/authorities/{st.le.authority.key}?template=le_cover#generate"
                             if le_name and route.get("case_agent", True) else f"/cases/{cid}?tab=authorities")}
        if st.outcome == "declined_terminal" and row.status in (rules.DECLINED_NO_ASSETS, rules.DECLINED):
            why = "holds nothing we named" if row.status == rules.DECLINED_NO_ASSETS else \
                "declined and its playbook offers no other route"
            return {"kind": "close", "text": f"{name} {why}: close the request; re-trace in case the funds moved on.",
                    "href": f"/cases/{cid}?tab=fund_flow"}
        return None
    ask = our_ask(row, now)
    replied = row.deciding is not None and (bool(row.intel.get("asks")) or st.freeze_at is not None)
    first = ask or missed_ask(row, now)  # nothing from them yet: a passed clock of ours still goes out now
    if first is not None and row.status != rules.DELIVERY_FAILED and not replied and row.status in (
            "awaiting", rules.AUTO_REPLY, rules.ACKNOWLEDGED):
        # a clock on our side that runs from our own letter (MEXC: proof of police acceptance within 48 hours of the
        # submission) with nothing from them to answer yet: send it now, as a follow-up on the request
        police = bool(re.search(r"\bpolice\b|\bcomplaint\b|denuncia|querela|\bic3\b|receipt", first.get("action") or "",
                                re.IGNORECASE))
        give, short = (("the police report receipt", "the police receipt") if police else
                       ("what their process asks for", "what their process asks for"))
        note = (f"Further to our request of {row.requested_at:%d %b %Y}"
                + (f" (your ticket {row.ticket})" if row.ticket else "")
                + f": please find enclosed {give}, which your process asks for within its deadline.")
        passed = ask is None
        return {"kind": "chase",
                "title": (f"{name}'s deadline passed {first['due_at']:%d %b %H:%M} UTC: send {short} now"
                          if passed else f"Send {name} {short} by {first['due_at']:%d %b %H:%M} UTC"),
                "text": f"{name}'s clock on our side runs from our request, not from a reply: send {give} now"
                        + (" (file the complaint first if no receipt is on file)" if police else
                           f" ({(first.get('action') or '').rstrip('.')})" if first.get("action") else "")
                        + f", as a follow-up on the request{_ticket(row)}."
                        + (f" It passed {first['due_at']:%d %b %Y %H:%M} UTC unmet: send it at once." if passed else
                           clock_text(first)),
                "href": _with_note(f"/cases/{cid}/authorities/{row.authority.key}?template=status_request&ref="
                                   f"{row.key}#generate", note)}
    if ask is not None and row.status != rules.DELIVERY_FAILED and replied:
        # their deadline on our side comes first: answer with what they asked (the police receipt on file), then LE
        held = " has temporarily frozen the account and" if st.freeze_at is not None else ""
        conf = (" Confirm the hold on Block status (with the amount) so its clocks run." if st.suggests else "")
        le = (f" Then brief {le_name} with the pack so the officer files {what} (the LE request)." if le_name
              else "")
        lec = next((c for c in getattr(row, "clocks", ()) or () if c.get("by") == "le" and c.get("what") in
                    ACTION_WHAT and not c.get("met") and c["due_at"] > now and c.get("action")), None)
        if lec is not None:  # the LE side's own clock and its fallback (MEXC: not yet onboarded on LEORS)
            le += f" LE's clock: {lec['due_at']:%d %b %Y %H:%M} UTC: {lec['action'].rstrip('.')}."
        if row.intel.get("asks"):
            lead = f"{name}{held} asks for {_asks(row)} by {ask['due_at']:%d %b %Y %H:%M} UTC"
        else:  # never splice the playbook's sentence after "asks for"
            lead = (f"{name}{held.removesuffix(' and')}. Their deadline on our side: "
                    f"{(ask.get('action') or 'the documents their process asks for').rstrip('.')} "
                    f"(by {ask['due_at']:%d %b %Y %H:%M} UTC)")
        miss = missed_ask(row, now)
        late = (f" The earlier deadline ({miss.get('span') or 'ours'} from {miss.get('starts_label') or 'our request'})"
                f" passed {miss['due_at']:%d %b %Y %H:%M} UTC: answer at once and ask {name} to confirm the freeze "
                "still stands." if miss is not None else "")
        return {"kind": "answer",
                "text": f"{lead}: answer now{_ticket(row)}, attaching the police report receipt on file.{late}{conf}{le}"
                        f"{clock_text(ask)}",
                "href": f"/cases/{cid}/authorities/{row.authority.key}?template=info_response&ref={row.key}#generate"}
    gone = st.lapsed
    if gone is not None and row.status != rules.DELIVERY_FAILED:
        when = f"{gone['at']:%d %b %Y %H:%M} UTC"
        follow = f"/cases/{cid}/authorities/{row.authority.key}?template=status_request&ref={row.key}#generate"
        le_txt = (f" and chase {le_name} for {what}" if le_name else " and brief LE for " + what)
        if gone["kind"] == "hold_expired":
            return {"kind": "chase", "title": f"{name}'s hold lapsed {gone['at']:%d %b}: ask whether the funds are "
                                              "still held",
                    "text": f"{name}'s hold lapsed {when} with no LE freeze or order recorded: ask {name} at once "
                            f"whether the funds are still held (status request{_ticket(row)}), re-trace in case they "
                            f"moved{le_txt}. It no longer counts as secured until {name} confirms it still stands.",
                    "href": follow, "lapsed": gone}
        c = gone["clock"] or {}
        if gone.get("side") == "le":
            act = f" ({c['action'].rstrip('.')})" if c.get("action") else ""
            return {"kind": "chase", "title": f"{name}'s LE deadline passed {gone['at']:%d %b}: confirm the freeze still "
                                              f"stands and ask {name} to extend it",
                    "text": f"The LE request's deadline passed {when} with no LE filing recorded{act}: {name} may "
                            f"already have lifted its temporary freeze. Ask {name} at once whether the freeze still "
                            f"stands and to extend it (status request{_ticket(row)}), re-trace in case the funds moved"
                            f"{le_txt} now. The hold no longer counts as secured until {name} confirms it.",
                    "href": follow, "lapsed": gone}
        give = f"the {_asks(row)}" if row.intel.get("asks") else (
            "the police report receipt" if _CARRIES.search(c.get("action") or "") else "what their process asks for")
        note = (f"Further to our request of {row.requested_at:%d %b %Y}" + (f" (your ticket {row.ticket})"
                                                                           if row.ticket else "")
                + f": please find enclosed {give}. Please confirm that the freeze is still in place.")
        return {"kind": "answer", "title": f"{name}'s deadline passed {gone['at']:%d %b}: send {give} now and ask "
                                           f"{name} to confirm the freeze still stands",
                "text": f"{name}'s deadline on our side passed {when} unmet"
                        + (f" ({c['action'].rstrip('.')})" if c.get("action") else "")
                        + f": {name} may already have lifted its temporary freeze. Send {give} now{_ticket(row)} and "
                        f"ask {name} to confirm the freeze still stands{le_txt}. The hold no longer counts as "
                        "secured until they confirm it.",
                "href": (f"/cases/{cid}/authorities/{row.authority.key}?template=info_response&ref={row.key}#generate"
                         if row.deciding is not None else _with_note(follow, note)),
                "lapsed": gone}
    if row.suggestion is not None:
        return None  # a person confirms the outcome first (the generic "confirm" text, with the clock)
    if st.suggests == "hold_discretionary":
        until = (f" (it lapses {st.hold_expires_at:%d %b %Y})" if st.hold_expires_at else "")
        return {"kind": "confirm", "text": f"{name} reports a temporary freeze{until}: confirm the hold on Block status "
                                           f"(with the amount) so its clocks run, then lock it in through LE.{clock}",
                "href": f"/cases/{cid}/blocks#{row.key}"}
    if st.step in ("le_filed", "binding_instrument", "cross_border"):
        txt = {"le_filed": f"LE filed with {name} (recorded): wait for their freeze and confirm it when it comes.",
               "binding_instrument": f"Order obtained (recorded): serve it on {name}{_via(org, st, row)} and confirm the "
                                     "freeze when it comes.",
               "cross_border": f"Cross-border request under way (recorded): keep the LE officer's reference and "
                               f"chase {name} once the executing authority serves it."}[st.step]
        return {"kind": "wait", "text": txt + clock, "href": f"/cases/{cid}/blocks#{row.key}"}
    dated = [x for x in sent if x.get("at")]  # a sent letter with no date (a legacy row) never decides the step
    if st.step == "le_route_open" and dated:
        ln = max(dated, key=lambda x: (x["at"], x["id"]))
        due = ln.get("due_at")
        late = due is not None and due < now
        when = f"{ln['at']:%d %b %Y}"
        txt = (f"{ln['authority']} briefed on {when} (letter #{ln['id']}): the officer files {need} with {name}"
               f"{_via(org, st, row)}{_ticket(row)}. "
               + (f"Chase the officer: their reply was due {due:%d %b %Y}." if late else
                  f"Wait for LE to file{f' (chase by {due:%d %b %Y})' if due else ''}.")
               + f" When {name} confirms the LE request, record it (LE filed).{clock}")
        href = (f"/cases/{cid}/authorities/{ln['authority_key']}?template=status_request#generate" if late
                else f"/cases/{cid}/authorities/correspondence/{ln['id']}")
        return {"kind": "chase" if late else "wait", "text": txt, "href": href}
    if st.step == "le_only_redirect":
        portal = row.deciding is not None and any(c.get("le_only") for c in (row.deciding.extract or {}).get("channels")
                                                  or [])
        if row.status in (rules.INFO_REQUESTED, rules.DELIVERY_FAILED, rules.UNCLEAR) or (
                row.status == rules.REDIRECTED and not portal):
            return None  # answer / fix / read that first (the generic text)
        return brief(f"{name} acts only on {need}.", _victim_intake(pb, org, st, requester))
    if st.step == "hold_discretionary":
        t = st.target
        lapse = min((c for c in getattr(row, "clocks", ()) or () if c.get("what") in HOLD_WHAT and not c.get("met")
                     and c["due_at"] > now), key=lambda c: c["due_at"], default=None)
        until = (f" until {st.hold_expires_at:%d %b %Y}" + (" if its LE term applies" if lapse and lapse.get("approx")
                                                            and lapse["due_at"] == st.hold_expires_at else "")
                 if st.hold_expires_at else "")
        dur = " stating the freeze duration" if t is not None and "freeze_duration_stmt" in t.evidence else ""
        sign = (f" ({name} refuses digitally signed documents: send a signed scan)" if t is not None
                and t.instrument.signing == "not_digital" else "")
        # one instrument in the next action and the LE brief: the one their reply names, else the LE path's
        return brief(f"Hold in place{until}: ask for {what}{dur} before it lapses{sign}.")
    if st.handoff and not sent and st.step in ("notice_sent", "provider_ack") and not row.overdue and \
            row.status in ("awaiting", rules.AUTO_REPLY, rules.ACKNOWLEDGED, rules.LE_PROCESS_REQUIRED):
        due = f" (reply due {row.due_at:%d %b %Y})" if row.due_at else ""
        tk = f" (ticket {row.ticket})" if row.ticket else ""
        via = _via(org, st, row)

        def sure(k: str) -> bool:  # an unconfirmed regional channel (Binance's Russia / Belarus inbox) is not offered
            rule = pb.rule(k) if pb is not None else None
            return rule is None or rule.prov is None or rule.prov.confidence == "H"

        jur = st.le.jur if st.le is not None and st.le.jur else st.victim_jur

        def ours(p) -> bool:  # an LE channel for the case LE's country (never Binance.US LERT for an Italian case)
            to = set(p.instrument.issuer_jurisdictions)
            return not to or jur is None or jur in to or ("EU" in to and jur in pbm.EU)

        named = {(u.get("value") or "").lower() for u in (row.deciding.urls if row.deciding is not None else [])}
        same = {c.key for c in getattr(org, "channels", ()) or () if c.value and c.value.lower() in named}
        others = [x for x in channel_labels(org, {k for p in getattr(pb, "paths", ()) or () if "le" in p.requester
                                                  and p.kind == "le_request" and ours(p) for k in p.channel_keys
                                                  if sure(k) and k not in same}, le_only=True)
                  if x not in via and not _foreign_region(x, jur)]
        # their reply already says what they act on: nothing more to wait for from them
        wait = "" if row.status == rules.LE_PROCESS_REQUIRED else f" Meanwhile wait for their answer{due}."
        portal = ((f" Other LE channels: {', '.join(others[:3])}." if others else "")
                  + (" Aegis never submits to an LE-only channel: the officer does." if others or "(LE only)" in via
                     or any(c.key in same and c.who == "le_only" for c in getattr(org, "channels", ()) or ())
                     else ""))
        return brief(f"{name} acts on {need} from law enforcement, not on our letter{tk}: hand off now.",
                     portal + wait)
    return None
