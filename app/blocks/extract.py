"""What a reply says beyond its status: tickets, the instrument the provider wants, the channels it names, what it
asks for, its deadlines, LE contacts and references, and the wallets / transactions / accounts it names (pure: no
database, no I/O).

    x = extract(own, playbook=pb, received_at=at, exclude_addresses={…}, exclude_refs={"DEMO-…"}, known={…})
    x.tickets, x.instrument, x.channels, x.asks, x.deadlines, x.contacts, x.identifiers, x.signals; x.as_dict()
    ai = verify_ai(model_object, own, received_at=at)        # the AI's fields, each checked against the reply
    merged = merge(x.as_dict(), ai)                           # rules first; AI additions tagged, disagreements kept

Rules first, on the sender's own text only (`own`: classify_rules.split_quoted with our letters' echo cut, as
app.blocks.status.read_reply computes it), so nothing of our own letter is ever read back as theirs.

* **tickets** `{value, system, quote}`: classify_rules.find_ticket (never our reference) plus the playbook's ticket
  formats (`tickets[].regex`); `system` is the playbook's ticket system.
* **instrument** `{type, label, issuer_jurisdictions, jurisdictions_from, quote, via, path}`: the playbook's
  `reply_signals` that name an instrument, then a generic lexicon (court order, subpoena, warrant, freezing order,
  MLAT, EIO, formal legal directive, appropriate legal process, "exclusively for verified Law Enforcement Agencies",
  police report) in a sentence that makes it a condition ("requires", "only", "without", "valid", …). The strongest
  wins (`RANK`); `instruments` lists every type named. Issuer jurisdictions come from the sentence ("a US or French
  court": US, FR, read as us_or_fr_court_order) else from the playbook path the signal names.
* **channels** `{value, kind, purpose, class, tenant, le_only, org, pick}`: classify_rules.find_channels classified
  against the playbook's domains: own, sibling, vendor_portal (`le_only`, `tenant`), third_party (another catalogue
  organisation's domain) or unknown. A third_party / unknown target needs a person to pick it (`pick`): a
  legitimate reply can name the police, another exchange or quote the victim's own address.
* **asks** `{kind: document | field | question, req_key, label, quote}`: phrase lists mapped to the playbook's
  evidence keys (police report, proof of ownership, UID, TxID, freeze duration, English, …), only in a sentence that
  asks ("please provide", "we require", "?"), never one that says it is not needed.
* **deadlines** `{what: reply_by | hold_until | submit_by | auto_lift, amount, unit | date, starts, due, ambiguous,
  candidates, auto, quote}`: a duration ("within 48 hours", "30-day", "entro 5 giorni lavorativi", "innerhalb von
  7 Tagen", "sous 10 jours") or a date (ISO, "3 November 2026", "November 3, 2026", "3 novembre 2026", "3. November
  2026", "15.11.2026", "03/04/2026") after a deadline word ("within", "by", "until", "entro", "bis", "jusqu'au", …).
  A numeric date whose day and month could swap (03/04/2026, 03.04.2026) is `ambiguous`: both readings are
  `candidates` and it never shortens a clock by itself (`auto` False: a suggestion a person confirms). `auto` is True
  only for an unambiguous reply_by / submit_by in the future (a clock it may shorten); a hold expiry or auto-lift
  is applied only when a person confirms the hold. `due` counts from the reply's date (`starts` says when the
  provider's own clock starts: "from the date of the freeze" → hold_confirmed, `approx`).
* **contacts** `{agency, name, role, email, phone, reference, system, quote}`: LE reference formats ("Prot. n.",
  "R.G.N.R.", "Verfahrensnummer" / "Aktenzeichen", "numéro de procédure" / "PV n°", an IC3 complaint ID), the agency
  named, an officer's rank and name, and (from an LE sender, `le`) its signature's e-mail and phone. Proposals for
  an LE contact a person adds.
* **identifiers** `{kind: address | tx | account | order_id, chain, value, known, watch}`: EVM / TRON / Bitcoin
  addresses (checksums validated), transaction hashes, UIDs / account and order ids. `known`: already in our letters
  (`known`); `watch`: a TRON / EVM address an investigator may add to the freeze watch (app.freeze) in one click.

Everything here is advisory: it changes no status, no stop order and sends nothing. A person confirms every
proposal (watch a wallet, add a contact, pick a third-party channel).
"""

from __future__ import annotations

import calendar
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from app.blocks import classify_rules as rules

VERSION = 1
MAX_ITEMS = 12
_I = re.IGNORECASE

INSTRUMENT_LABELS = {
    "police_report": "a police report / complaint receipt", "le_request": "an LE request (official channel)",
    "subpoena": "a subpoena", "court_order": "a court order", "us_or_fr_court_order": "a US or French court order",
    "freezing_order": "a freezing / seizure order", "seizure_warrant": "a seizure warrant",
    "formal_directive": "a formal legal directive", "mlat": "an MLAT request",
    "eu_freezing_order": "an EU freezing order (Reg. (EU) 2018/1805)", "eio": "a European Investigation Order",
    "judicial_decision": "a judicial decision",
}
# strongest first: the instrument of a reply that names several ("a police report and a court order": court order)
RANK = ("us_or_fr_court_order", "eu_freezing_order", "freezing_order", "seizure_warrant", "court_order", "eio",
        "mlat", "judicial_decision", "formal_directive", "subpoena", "le_request", "police_report")
DEADLINE_LABELS = {"reply_by": "they reply by", "hold_until": "hold lasts until", "submit_by": "submit by",
                   "auto_lift": "lifted automatically"}
CLASS_LABELS = {"own": "their own domain", "sibling": "a sibling entity's domain", "vendor_portal": "their portal",
                "third_party": "another organisation", "unknown": "unknown domain"}
ASK_LABELS = {
    "police_report": "police report", "complaint_ref": "complaint / case number", "ic3_ref": "IC3 complaint ID",
    "ownership_proof": "proof of ownership", "victim_id": "victim's ID", "tx_list_copyable": "transaction hashes",
    "provider_ids": "account / UID / deposit address", "receiving_account": "receiving address",
    "loa": "letter of authority", "poa": "power of attorney", "court_order": "court order",
    "english_version": "English version", "freeze_duration_stmt": "freeze duration",
    "non_disclosure_stmt": "may the user be told", "incident_narrative": "incident description",
    "comms_export": "screenshots / chat logs", "wire_details": "bank / wire details",
    "le_agency_identity": "LE identity / official domain", "le_letterhead_request": "request on agency letterhead",
    "seizure_warrant": "seizure warrant",
}
ASK_KIND = {"provider_ids": "field", "tx_list_copyable": "field", "receiving_account": "field", "wire_details": "field",
            "freeze_duration_stmt": "question", "non_disclosure_stmt": "question", "incident_narrative": "question"}


# --------------------------------------------------------------------------- result
@dataclass
class Extracted:
    tickets: list[dict] = field(default_factory=list)
    instrument: dict | None = None
    instruments: list[str] = field(default_factory=list)
    channels: list[dict] = field(default_factory=list)
    asks: list[dict] = field(default_factory=list)
    deadlines: list[dict] = field(default_factory=list)
    contacts: list[dict] = field(default_factory=list)
    identifiers: list[dict] = field(default_factory=list)
    signals: list[dict] = field(default_factory=list)  # playbook reply_signals found {phrase, means, instrument, path}
    version: int = VERSION

    def as_dict(self) -> dict:
        return asdict(self)

    @property
    def empty(self) -> bool:
        return not (self.tickets or self.instrument or self.channels or self.asks or self.deadlines or self.contacts
                    or self.identifiers)


def _quote(s: str) -> str:
    s = " ".join((s or "").split())
    return s if len(s) <= rules.MAX_QUOTE_CHARS else s[:rules.MAX_QUOTE_CHARS - 1].rstrip() + "…"


# a clause: split on a sentence end (never after a digit, "3. November", nor "Prot." / "n." / "No."), a blank line or
# a list item
_CLAUSE_END = re.compile(r"(?<!\bProt)(?<!\bprot)(?<!\b[nN])(?<!\b[nN][rRoO])(?<!\bAz)(?<!\bca)(?<!\bapprox)"
                         r"[.!?]\s+(?=[\"'(\[]?[A-ZÀ-Ý])|\n\s*\n|\n(?=\s*(?:[-*•]|\d+[.)])\s)")


def clauses(text: str) -> list[tuple[int, int]]:
    out, pos = [], 0
    for m in _CLAUSE_END.finditer(text):
        if text[pos:m.start() + 1].strip():
            out.append((pos, m.start() + 1))
        pos = m.end()
    if text[pos:].strip():
        out.append((pos, len(text)))
    merged: list[tuple[int, int]] = []
    for a, b in out:  # "bis zum 3. November 2026": a German ordinal day is no sentence end
        if merged and _ORDINAL_END.search(text[merged[-1][0]:merged[-1][1]]) and _MONTH_START.match(text[a:b]):
            merged[-1] = (merged[-1][0], b)
        else:
            merged.append((a, b))
    return merged


def _clause_span(text: str, spans: list[tuple[int, int]], i: int) -> tuple[str, int]:
    """(the clause holding offset `i`, its start offset)."""
    a, b = next(((a, b) for a, b in spans if a <= i < b), (max(0, i - 200), i + 200))
    return text[a:b], a


def _clause_at(text: str, spans: list[tuple[int, int]], i: int) -> str:
    return _clause_span(text, spans, i)[0]


# --------------------------------------------------------------------------- jurisdictions, instruments
_JUR_WORDS = [
    (re.compile(r"\bU\.\s?S\.(?:\s?A\.)?|\bUSA?\b|\bUnited States\b|\bAmerican\b|\bfederal\b"), "US"),
    (re.compile(r"\bFrench\b|\bFrance\b|\bfran[çc]ais(?:e)?\b", _I), "FR"),
    (re.compile(r"\bItal(?:y|ian|ia|iano|iana)\b", _I), "IT"),
    (re.compile(r"\bGerman(?:y)?\b|\bDeutschland\b|\bdeutsche[nmrs]?\b", _I), "DE"),
    (re.compile(r"\bU\.?K\.?\b|\bUnited Kingdom\b|\bBritish\b(?!\s+Virgin)"), "GB"),
    (re.compile(r"\bBVI\b|\bBritish Virgin Islands\b"), "VG"),
    (re.compile(r"\bSingapore(?:an)?\b", _I), "SG"), (re.compile(r"\bHong Kong\b", _I), "HK"),
    (re.compile(r"\bSwiss\b|\bSwitzerland\b", _I), "CH"), (re.compile(r"\bAustria(?:n)?\b", _I), "AT"),
    (re.compile(r"\bLithuania(?:n)?\b", _I), "LT"), (re.compile(r"\bSeychelles\b", _I), "SC"),
    (re.compile(r"\bFinland\b|\bFinnish\b", _I), "FI"), (re.compile(r"\bSpain\b|\bSpanish\b", _I), "ES"),
    (re.compile(r"\bEU\b|\bEuropean Union\b|\bMember States?\b"), "EU"),
]


def jurisdictions(text: str) -> list[str]:
    return [code for rx, code in _JUR_WORDS if rx.search(text or "")]


_LEXICON: list[tuple[str, re.Pattern]] = [(t, re.compile(rx, _I)) for t, rx in (
    ("eu_freezing_order", r"\bEU\s+freezing\s+orders?\b|\bRegulation\s+\(EU\)\s+2018/1805\b|\b2018/1805\b"),
    ("eio", r"\bEuropean\s+Investigation\s+Orders?\b|\bEIO\b|\bOrdine\s+europeo\s+di\s+indagine\b"),
    ("freezing_order", (r"\b(?:freezing|freeze|seizure|restraint|restraining|blocking)\s+orders?\b|\bsequestro\b|"
                       r"\bBeschlagnahme\w*|\bArrestbeschluss\b|\bVermögensarrest\b|\bordonnance\s+de\s+(?:gel|saisie)\b|"
                       r"\bsaisie\s+p[ée]nale\b")),
    ("seizure_warrant", r"\bseizure\s+warrants?\b"),
    ("court_order", (r"\bcourt[- ]orders?\b|\bcourt\s+of\s+competent\s+jurisdiction\b|\b(?:judicial|court)\s+"
                    r"(?:decision|ruling)s?\b|\b(?:search\s+)?warrants?\b|\b(?:order|decision)s?\s+(?:of|from|by)\s+"
                    r"(?:a|the|an?\s+\w+)\s+court\b|\bprovvedimento\s+(?:del(?:l')?\s*)?(?:giudice|autorit[àa]\s+"
                    r"giudiziaria)\b|\bgerichtliche[nr]?\s+(?:Anordnung|Beschluss|Verfügung)\b|\bGerichtsbeschluss\b|"
                    r"\bd[ée]cision\s+de\s+justice\b|\bordonnance\s+(?:du\s+juge|judiciaire)\b")),
    ("mlat", r"\bMLATs?\b|\bmutual\s+legal\s+assistance\b|\brogatori[ae]\b|\bRechtshilfe\w*|\bentraide\s+judiciaire\b"),
    ("formal_directive", r"\bformal\s+(?:legal\s+)?directives?\b"),
    ("subpoena", r"\bsubpoenas?\b|\bsummons\b|\bcivil\s+investigative\s+demand\b"),
    ("le_request", (r"\b(?:appropriate|valid|proper|formal|official)\s+legal\s+process\b|\blegal\s+process\b|"
                   r"\b(?:exclusively|only)\s+(?:for|from)\s+(?:verified\s+)?(?:law[- ]enforcement|government)\b|"
                   r"\blaw[- ]enforcement\s+(?:request|agenc(?:y|ies)|authorit(?:y|ies)|portal|process|channel|officers?)s?\b|"
                   r"\bofficial\s+(?:LE\s+)?request\b|\brichiesta\s+(?:dell'autorit[àa]|ufficiale)\b|"
                   r"\bbeh[öo]rdliche\s+Anfrage\b|\br[ée]quisition\b")),
    ("police_report", (r"\bpolice\s+(?:report|case\s+number|complaint|reference)s?\b|\bcrime\s+report\b|"
                      r"\b(?:law[- ]enforcement|LE)\s+case\s+number\b|\bdenuncia(?:-querela)?\b|\bquerela\b|"
                      r"\bStrafanzeige\b|\bAnzeige\b|\b(?:d[ée]p[ôo]t\s+de\s+)?plainte\b")),
)]
_CONDITION = re.compile(
    r"\b(?:requires?|required|requiring|need(?:s|ed)?|only|exclusively|unless|without|upon|pursuant|valid|"
    r"appropriate|official|unable|cannot|can\s*not|can't|must|via|through|submit|provide|obtain|accompanied|"
    r"absent|subject\s+to|in\s+accordance|necessary|mandatory|serve[ds]?|issued|erforderlich|benötig\w*|nur|"
    r"ohne|necessari[oa]|occorre|solo|soltanto|senza|nécessaire|requis|uniquement|seulement|sans)\b", _I)
_NOT_NEEDED = re.compile(r"\bno\s+(?:\w+\s+){0,4}(?:is|are)\s+(?:required|needed|necessary)\b|"
                         r"\bnot\s+(?:required|needed|necessary)\b|\bno\s+need\b|\bnicht\s+erforderlich\b|"
                         r"\bnon\s+(?:è|e)\s+necessari[oa]\b", _I)


def _rank(t: str) -> int:
    return RANK.index(t) if t in RANK else len(RANK)


def _instrument(own: str, spans, playbook) -> tuple[dict | None, list[str], list[dict]]:
    found: list[dict] = []
    signals: list[dict] = []
    low = " ".join(own.lower().split())
    for s in getattr(playbook, "signals", ()) or ():
        phrase = " ".join(s.phrase.lower().split())
        if not phrase or phrase not in low:
            continue
        i = own.lower().find(s.phrase.lower())
        clause = _clause_at(own, spans, i) if i >= 0 else s.phrase
        signals.append({"phrase": s.phrase, "means": s.means, "instrument": s.instrument, "path": s.path})
        if s.instrument and s.instrument != "none":
            found.append({"type": s.instrument, "quote": clause, "via": "playbook", "path": s.path})
    for a, b in spans:
        clause = own[a:b]
        hits = [t for t, rx in _LEXICON if rx.search(clause)]
        if not hits or not _CONDITION.search(clause) or _NOT_NEEDED.search(clause):
            continue
        for t in hits:
            if t == "court_order" and {"US", "FR"} <= set(jurisdictions(clause)):
                t = "us_or_fr_court_order"
            found.append({"type": t, "quote": clause, "via": "rules", "path": None})
    if not found:
        return None, [], signals
    types = sorted(dict.fromkeys(f["type"] for f in found), key=_rank)
    best = min(found, key=lambda f: (_rank(f["type"]), f["via"] != "playbook"))
    jur = [j for j in jurisdictions(best["quote"]) if j in ("US", "FR") or best["type"] != "us_or_fr_court_order"]
    src = "reply" if jur else None
    if not jur and best["type"] == "us_or_fr_court_order":
        jur, src = ["US", "FR"], "instrument"
    if not jur and best["path"] and playbook is not None:
        p = playbook.path(best["path"])
        if p is not None and p.instrument.issuer_jurisdictions:
            jur, src = list(p.instrument.issuer_jurisdictions), "playbook"
    return ({"type": best["type"], "label": INSTRUMENT_LABELS.get(best["type"], best["type"]),
             "issuer_jurisdictions": jur, "jurisdictions_from": src, "quote": _quote(best["quote"]),
             "via": best["via"], "path": best["path"]}, types, signals)


# --------------------------------------------------------------------------- asks
_ASK_CUE = re.compile(
    r"\b(?:please|kindly|could\s+you|can\s+you|would\s+you|we\s+(?:will\s+)?(?:need|require)|(?:is|are)\s+required|"
    r"required|must|provide|submit|send|attach|share|upload|include|furnish|fill\s+(?:in|out)|complete|missing|"
    r"bitte|benötigen|erforderlich|übermitteln|si\s+prega|vi\s+preghiamo|necessari[oa]|occorre|fornire|inviare|"
    r"allegare|veuillez|merci\s+de|nécessaire|requis|fournir|transmettre|por\s+favor)\b|\?\s*$", _I)
_ASKS: list[tuple[str, re.Pattern]] = [(k, re.compile(rx, _I)) for k, rx in (
    ("ic3_ref", r"\bIC3\s+(?:complaint\s+)?(?:ID|number|reference|receipt)\b"),
    ("police_report", (r"\bpolice\s+report\b|\bcopy\s+of\s+the\s+(?:police\s+)?(?:report|complaint)\b|\bcrime\s+report\b|"
                      r"\bproof\s+of\s+(?:the\s+)?police\b|\bdenuncia\b|\bquerela\b|\bStrafanzeige\b|\bAnzeige\b|"
                      r"\bplainte\b|\breport\s+(?:filed\s+)?(?:with|to)\s+(?:the\s+)?(?:police|law\s+enforcement)\b")),
    ("complaint_ref", (r"\b(?:police|law[- ]enforcement|LE)\s+(?:case|file|reference|report)\s+(?:number|no\.?|ID)\b|"
                      r"\bcase\s+number\s+(?:from|issued\s+by)\b|\bcomplaint\s+(?:number|reference)\b|"
                      r"\bAktenzeichen\b|\bnumero\s+di\s+protocollo\b")),
    ("ownership_proof", (r"\bproof\s+of\s+(?:wallet\s+|account\s+|fund\s+)?ownership\b|\bproof\s+that\s+(?:you|the\s+"
                        r"victim)\s+own|\bownership\s+of\s+the\s+(?:wallet|account|funds|address)\b|\bEigentumsnachweis\b|"
                        r"\bprova\s+(?:della\s+)?propriet[àa]\b|\bpreuve\s+de\s+propri[ée]t[ée]\b")),
    ("victim_id", (r"\b(?:government[- ]issued\s+)?(?:photo\s+)?ID\s+(?:document|card)\b|\bidentity\s+document\b|"
                  r"\bproof\s+of\s+identity\b|\bpassport\b|\b(?:victim|your)['’]?s?\s+ID\b|\bAusweis\w*|"
                  r"\bdocumento\s+d'identit[àa]\b|\bpi[èe]ce\s+d'identit[ée]\b")),
    ("tx_list_copyable", (r"\btransaction\s+(?:hash(?:es)?|IDs?)\b|\bTX\s?IDs?\b|\btx\s+hash(?:es)?\b|\bhash(?:es)?\s+of\s+"
                         r"the\s+transactions?\b|\bTransaktions(?:-?ID|hash)\w*")),
    ("provider_ids", (r"\bUIDs?\b|\buser\s+IDs?\b|\baccount\s+(?:IDs?|numbers?)\b|\bdeposit\s+address(?:es)?\b|"
                     r"\border\s+(?:IDs?|numbers?)\b|\bmemo\b|\bdestination\s+tag\b")),
    ("receiving_account", r"\breceiving\s+(?:address|wallet|account)\b|\b(?:address|wallet)\s+that\s+received\b"),
    ("loa", (r"\bletter\s+of\s+(?:authori[sz]ation|authority|engagement)\b|\bauthori[sz]ation\s+(?:letter|from\s+the\s+"
            r"victim)\b|\bproof\s+of\s+(?:your\s+)?authority\b|\bmandate\b|\bVollmacht\b|\bdelega\b|\bmandat\b")),
    ("poa", r"\bpower\s+of\s+attorney\b|\bPOA\b|\bprocura\s+speciale\b|\bprocuration\b"),
    ("court_order", r"\bcopy\s+of\s+the\s+court\s+order\b|\bprovide\s+(?:a|the)\s+(?:valid\s+)?court\s+order\b"),
    ("seizure_warrant", r"\bprovide\s+(?:a|the)\s+(?:valid\s+)?seizure\s+warrant\b"),
    ("english_version", (r"\bin\s+English\b|\bEnglish\s+(?:translation|version)\b|\btranslated\s+into\s+English\b|"
                        r"\bauf\s+Englisch\b|\bin\s+inglese\b|\ben\s+anglais\b")),
    ("freeze_duration_stmt", (r"\b(?:freeze|freezing|hold)\s+(?:duration|period)\b|\bduration\s+of\s+the\s+"
                             r"(?:freeze|hold|restriction)\b|\bhow\s+long\s+(?:the\s+)?(?:freeze|hold|account)\b|"
                             r"\bperiod\s+(?:of|for)\s+which\b")),
    ("non_disclosure_stmt", (r"\b(?:whether|if)\s+(?:we\s+(?:may|can)|it\s+is\s+permitted\s+to)\s+(?:notify|inform|"
                            r"tell)\s+the\s+(?:user|customer|account\s+holder)\b|\bnon[- ]disclosure\b|\bgag\s+order\b|"
                            r"\bdisclose\s+(?:the\s+request\s+)?to\s+the\s+(?:user|customer)\b")),
    ("incident_narrative", (r"\b(?:description|summary|details|explanation)\s+of\s+(?:the\s+)?(?:incident|fraud|scam|"
                           r"case|events)\b|\bwhat\s+happened\b|\bSachverhalt\b")),
    ("comms_export", (r"\bscreenshots?\b|\bchat\s+(?:logs?|history)\b|\bcommunications?\s+with\s+the\s+(?:scammer|"
                     r"suspect|fraudster)\b")),
    ("wire_details", r"\bbank\s+(?:details|account\s+details|statement)\b|\bIBAN\b|\bwire\s+(?:details|confirmation)\b"),
    ("le_agency_identity", (r"\bofficial\s+(?:government\s+)?(?:e-?mail\s+)?domain\b|\b(?:badge|warrant\s+card)\s+"
                           r"(?:number|copy)\b|\bproof\s+(?:that\s+you\s+are|of\s+being)\s+(?:a\s+)?law\s+enforcement\b")),
    ("le_letterhead_request", r"\b(?:on|with)\s+(?:the\s+)?(?:agency['’]?s?\s+|official\s+)?letterhead\b"),
)]


def _asks(own: str, spans) -> list[dict]:
    out: dict[str, dict] = {}
    for a, b in spans:
        clause = own[a:b]
        if not _ASK_CUE.search(clause) or _NOT_NEEDED.search(clause):
            continue
        for key, rx in _ASKS:
            if key not in out and rx.search(clause):
                out[key] = {"kind": ASK_KIND.get(key, "document"), "req_key": key, "label": ASK_LABELS[key],
                            "quote": _quote(clause)}
    return list(out.values())[:MAX_ITEMS]


# --------------------------------------------------------------------------- deadlines
_NUM_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
              "ten": 10, "twelve": 12, "fourteen": 14, "fifteen": 15, "twenty": 20, "twenty-four": 24, "thirty": 30,
              "forty-eight": 48, "sixty": 60, "seventy-two": 72, "ninety": 90}
_UNITS = [
    ("working_days", (r"business\s+days?|working\s+days?|banking\s+days?|giorni\s+lavorativi|jours\s+ouvr(?:é|e|ables?)s?|"
                     r"werktage[n]?|arbeitstage[n]?|Werktag|Arbeitstag")),
    ("hours", r"hours?|hrs?|h|ore|stunden|heures?"),
    ("days", r"calendar\s+days?|days?|giorni|giorno|tage[n]?|tag|jours?"),
    ("weeks", r"weeks?|settimane|settimana|wochen|woche|semaines?"),
    ("months", r"months?|mesi|mese|monate[n]?|monat|mois"),
]
_UNIT_RX = "|".join(f"(?P<{k}>{rx})" for k, rx in _UNITS)
_DURATION = re.compile(r"(?<![\w/.,:])(?P<n>\d{1,3}|" + "|".join(sorted(_NUM_WORDS, key=len, reverse=True)) +
                       r")(?:\s*\(\d{1,3}\))?(?P<sep>\s*|-)(?:" + _UNIT_RX + r")(?![\w/])", _I)
_DUR_TRIGGER = re.compile(
    r"\b(?:within|in|for|up\s+to|after|no\s+later\s+than|at\s+most|maximum|max|entro|termine|per|dopo|innerhalb|"
    r"binnen|für|nach|dans|délai|sous|pendant|d'ici|durant|après|of|expire[sd]?|expiring|lasts?|remains?|valid|"
    r"scade|dura|gilt|läuft|expire)\b(?:\W+\w+){0,3}\W*$", _I)
_LIFT = re.compile(r"\bauto(?:matic(?:ally)?)?[- ]?(?:unfreez|lift|releas|expir|unblock|unlock)\w*|\bunfreez\w*|"
                   r"\bunfrozen\b|\bwill\s+be\s+(?:automatically\s+)?(?:lifted|released|removed|unblocked|unlocked)\b|"
                   r"\b(?:lifted|released|removed)\s+automatically\b|\bautomatisch\s+(?:aufgehoben|freigegeben|"
                   r"entsperrt)\b|\bsbloccat\w*|\bsvincolat\w*|\blev[ée]e?s?\s+automatiquement\b|\bd[ée]gel\w*", _I)
_SUBMIT = re.compile(r"\b(?:submit|provide|send|upload|file|furnish|present|deliver|receive[ds]?|obtain|presentare|"
                     r"inviare|fornire|trasmettere|depositare|einreichen|vorlegen|übermitteln|zusenden|nachreichen|"
                     r"fournir|transmettre|envoyer|soumettre|d[ée]poser|reichen|senden|schicken|documents?|documentation|"
                     r"documenti|documentazione|Unterlagen|Dokumente|pi[èe]ces)\w*|\bpolice\s+report\b|\bproof\b|"
                     r"\b(?:court|freezing)\s+order\b|\bdenuncia\b|\bStrafanzeige\b|\bplainte\b", _I)
_HOLD = re.compile(r"\b(?:hold|held|freez\w*|frozen|restrict\w*|block\w*|suspen\w*|bloccat\w*|congelat\w*|"
                   r"gesperrt|eingefroren|Sperr\w*|gel[ée]e?s?|bloqu[ée]e?s?|remain\s+in\s+place|expire\w*|"
                   r"valid)\b", _I)
_REPLY_W = re.compile(r"\b(?:reply|replies|respond|response|answer|get\s+back|revert|update\s+you|contact\s+you|"
                      r"review\w*|process\w*|rispost\w*|rispondere|antwort\w*|bearbeit\w*|r[ée]ponse|r[ée]pondr\w*|"
                      r"trait\w*)\b", _I)
_FROM_FREEZE = re.compile(r"\bfrom\s+(?:the\s+)?(?:date|time|moment)\s+of\s+(?:the\s+)?(?:temporary\s+)?(?:freez|hold|"
                          r"restrict|block)\w*|\b(?:after|of)\s+the\s+(?:temporary\s+)?(?:freeze|hold)\b|"
                          r"\bdalla\s+data\s+del\s+(?:blocco|congelamento|sequestro)\b|\bab\s+(?:dem\s+)?"
                          r"(?:Datum\s+der\s+)?(?:Sperrung|Einfrierung)\b|\b[àa]\s+compter\s+du\s+gel\b", _I)
_MONTHS = {
    **{m: i for i, m in enumerate(("january", "february", "march", "april", "may", "june", "july", "august",
                                   "september", "october", "november", "december"), 1)},
    **{m: i for i, m in enumerate(("gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio", "agosto",
                                   "settembre", "ottobre", "novembre", "dicembre"), 1)},
    **{m: i for i, m in enumerate(("januar", "februar", "märz", "april", "mai", "juni", "juli", "august", "september",
                                   "oktober", "november", "dezember"), 1)},
    **{m: i for i, m in enumerate(("janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août",
                                   "septembre", "octobre", "novembre", "décembre"), 1)},
    "jänner": 1, "fevrier": 2, "aout": 8, "decembre": 12, "marz": 3,
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "sept": 9, "oct": 10, "nov": 11,
    "dec": 12, "gen": 1, "mag": 5, "giu": 6, "lug": 7, "ago": 8, "set": 9, "ott": 10, "dic": 12, "mär": 3, "mrz": 3,
    "okt": 10, "dez": 12, "janv": 1, "févr": 2, "fevr": 2, "avr": 4, "juil": 7, "déc": 12,
}
_MONTH_RX = "|".join(sorted((re.escape(m) for m in _MONTHS), key=len, reverse=True))
_DATE = re.compile(
    r"(?<![\w/.-])(?:(?P<iy>\d{4})-(?P<im>\d{2})-(?P<id>\d{2})"
    rf"|(?P<d1>\d{{1,2}})(?:st|nd|rd|th|er|°|º)?\.?\s+(?:de\s+)?(?P<m1>{_MONTH_RX})\.?(?:,?\s+(?P<y1>\d{{4}}))?"
    rf"|(?P<m2>{_MONTH_RX})\.?\s+(?P<d2>\d{{1,2}})(?:st|nd|rd|th)?(?:,?\s+(?P<y2>\d{{4}}))?"
    r"|(?P<na>\d{1,2})(?P<sep>[./-])(?P<nb>\d{1,2})(?P=sep)(?P<ny>\d{4}|\d{2}))(?![\w/-])", _I)
_DATE_TRIGGER = re.compile(
    r"\b(?:by|before|until|till|through|no\s+later\s+than|deadline|due|expir\w*|valid|lifted|unfrozen|released|"
    r"on\s+or\s+before|on|entro|fino|oltre|scadenza|scade|il|al|bis|spätestens|vor|zum|Frist|am|avant|jusqu'au|"
    r"jusqu'à|au\s+plus\s+tard|d'ici|le|échéance)\b(?:\W+\w+){0,4}\W*$", _I)
_ORDINAL_END = re.compile(r"(?<![\d.])\d{1,2}\.$")
_MONTH_START = re.compile(rf"(?:{_MONTH_RX})\b", _I)
_EU_TEXT = re.compile(r"\b(?:il|del|della|entro|und|der|die|das|bis|le|la|les|du|des|jusqu)\b", _I)


def _add_working_days(start: datetime, n: int) -> datetime:
    d = start
    while n > 0:
        d += timedelta(days=1)
        if d.weekday() < 5:
            n -= 1
    return d


def _add_months(start: datetime, n: int) -> datetime:
    m = start.month - 1 + n
    y, m = start.year + m // 12, m % 12 + 1
    return start.replace(year=y, month=m, day=min(start.day, calendar.monthrange(y, m)[1]))


def span_due(start: datetime, amount: float, unit: str) -> datetime:
    n = int(amount)
    if unit == "hours":
        return start + timedelta(hours=amount)
    if unit == "working_days":
        return _add_working_days(start, n)
    if unit == "weeks":
        return start + timedelta(days=7 * amount)
    if unit == "months":
        return _add_months(start, n)
    return start + timedelta(days=amount)


def _what(clause: str, a: int = 0, b: int = 0) -> str | None:
    """What a deadline at clause[a:b] is about: the nearest cue wins ("provide the police report within 48 hours,
    otherwise the freeze is lifted": submit_by; "lifted automatically after 30 days unless an order is received":
    auto_lift), ties in the order submit_by, auto_lift, hold_until, reply_by."""
    best: tuple[int, int, str] | None = None
    for prio, (what, rx) in enumerate((("submit_by", _SUBMIT), ("auto_lift", _LIFT), ("hold_until", _HOLD),
                                       ("reply_by", _REPLY_W))):
        for m in rx.finditer(clause):
            gap = max(0, a - m.end(), m.start() - b)
            if best is None or (gap, prio) < best[:2]:
                best = (gap, prio, what)
    return best[2] if best else None


def _year(y: str | None, mo: int, d: int, ref: date) -> tuple[int, bool]:
    if y:
        n = int(y)
        return (n + 2000 if n < 100 else n), False
    yr = ref.year
    try:
        if date(yr, mo, d) < ref - timedelta(days=31):
            yr += 1
    except ValueError:
        pass
    return yr, True


def parse_date(m: re.Match, ref: date, eu_hint: bool = False) -> dict | None:
    """{date, candidates, ambiguous, likely, year_inferred} for a _DATE match; None for an impossible date."""
    g = m.groupdict()
    try:
        if g["iy"]:
            return {"date": date(int(g["iy"]), int(g["im"]), int(g["id"])).isoformat(), "candidates": [],
                    "ambiguous": False, "likely": None, "year_inferred": False}
        if g["m1"] or g["m2"]:
            mo = _MONTHS[(g["m1"] or g["m2"]).lower()]
            d = int(g["d1"] or g["d2"])
            yr, inferred = _year(g["y1"] or g["y2"], mo, d, ref)
            return {"date": date(yr, mo, d).isoformat(), "candidates": [], "ambiguous": False, "likely": None,
                    "year_inferred": inferred}
        a, b = int(g["na"]), int(g["nb"])
        yr, _ = _year(g["ny"], 1, 1, ref)
        dmy = date(yr, b, a) if 1 <= b <= 12 and 1 <= a <= 31 else None
        mdy = date(yr, a, b) if 1 <= a <= 12 and 1 <= b <= 31 else None
    except ValueError:
        return None
    if dmy and mdy and dmy != mdy:
        likely = "dmy" if g["sep"] == "." or eu_hint else None
        return {"date": None, "candidates": [dmy.isoformat(), mdy.isoformat()], "ambiguous": True, "likely": likely,
                "year_inferred": False}
    one = dmy or mdy
    return None if one is None else {"date": one.isoformat(), "candidates": [], "ambiguous": False, "likely": None,
                                     "year_inferred": False}


def _deadline_from(what: str, clause: str, *, received: datetime, amount=None, unit=None, parsed=None) -> dict:
    starts = "hold_confirmed" if _FROM_FREEZE.search(clause) else "reply"
    out = {"what": what, "label": DEADLINE_LABELS[what], "amount": amount, "unit": unit, "date": None,
           "candidates": [], "ambiguous": False, "likely": None, "starts": starts, "approx": starts != "reply",
           "due": None, "auto": False, "quote": _quote(clause)}
    if parsed is not None:
        out.update(date=parsed["date"], candidates=parsed["candidates"], ambiguous=parsed["ambiguous"],
                   likely=parsed["likely"], approx=parsed["year_inferred"])
        if parsed["date"]:
            out["due"] = datetime.fromisoformat(parsed["date"]).replace(hour=23, minute=59, tzinfo=UTC).isoformat()
    elif amount is not None:
        out["due"] = span_due(received, amount, unit).isoformat(timespec="minutes")
    due = datetime.fromisoformat(out["due"]) if out["due"] else None
    # only an unambiguous reply / submit clock in the future may shorten a clock by itself; a hold expiry or an
    # auto-lift is applied once a person confirms the hold, an ambiguous date is a suggestion
    out["auto"] = bool(due and due > received and what in ("reply_by", "submit_by") and not out["ambiguous"]
                       and not (parsed or {}).get("year_inferred"))
    return out


def _deadlines(own: str, spans, received: datetime) -> list[dict]:
    out: list[dict] = []
    eu_hint = bool(_EU_TEXT.search(own))
    for m in _DURATION.finditer(own):
        unit = next(k for k, _ in _UNITS if m.group(k))
        before = own[max(0, m.start() - 60):m.start()]
        if not (m.group("sep") == "-" or _DUR_TRIGGER.search(before)):
            continue
        clause, at = _clause_span(own, spans, m.start())
        what = _what(clause, m.start() - at, m.end() - at)
        if what is None:
            continue
        raw = m.group("n").lower()
        n = float(_NUM_WORDS[raw] if raw in _NUM_WORDS else int(raw))
        if n <= 0:
            continue
        if unit == "weeks":
            unit, n = "days", n * 7
        out.append(_deadline_from(what, clause, received=received, amount=n, unit=unit))
    for m in _DATE.finditer(own):
        before = own[max(0, m.start() - 50):m.start()]
        if not _DATE_TRIGGER.search(before):
            continue
        parsed = parse_date(m, received.date(), eu_hint)
        past = (received - timedelta(days=1)).date().isoformat()
        if parsed is None or all(x < past for x in ([parsed["date"]] if parsed["date"] else parsed["candidates"])):
            continue  # a date in the past is no deadline ("On 3 October we froze …")
        clause, at = _clause_span(own, spans, m.start())
        what = _what(clause, m.start() - at, m.end() - at) or (
            "reply_by" if re.search(r"\b(?:by|entro|bis|avant|before)\b", before, _I) else None)
        if what is None:
            continue
        out.append(_deadline_from(what, clause, received=received, parsed=parsed))
    seen, uniq = set(), []
    for d in out:
        k = (d["what"], d["due"], tuple(d["candidates"]))
        if k not in seen:
            seen.add(k)
            uniq.append(d)
    return uniq[:MAX_ITEMS]


# --------------------------------------------------------------------------- contacts, LE references
# "1234/2026 Mod 21" is one reference; "4417/2026 del 3 ottobre" is a reference and a date
_REF_TAIL = (r"(?P<v>[A-Z0-9][\w/.-]*\d[\w/.-]*(?:\s+(?!(?:del|dal|al|of|on|vom|am|du|le|il|dated?)\s)[A-Za-z]{1,4}\s+"
             r"\d[\w/.-]*)?)")
_REFS: list[tuple[str, re.Pattern]] = [
    ("protocollo", re.compile(r"\bProt(?:\.|ocollo)\s*(?:n(?:r|o|um)?\.?|numero|N\.)?\s*[:°º]?\s*" + _REF_TAIL, _I)),
    ("rgnr", re.compile(r"\bR\.?\s?G\.?\s?N\.?\s?R\.?\s*(?:n(?:r|o)?\.?\s*)?[:°º]?\s*" + _REF_TAIL)),
    ("rgnr", re.compile(r"\b(?:n\.?\s*)?(?P<v>\d{1,7}/\d{2,4})\s*R\.?\s?G\.?\s?N\.?\s?R\b", _I)),
    ("verfahrensnummer", re.compile(r"\b(?:Verfahrensnummer|Verfahrens-?Nr\.?|Aktenzeichen|Az\.|Vorgangsnummer|"
                                    r"Tagebuchnummer|Tgb\.?-?Nr\.?)\s*[:.]?\s*" + _REF_TAIL)),
    ("procedure_fr", re.compile(r"\b(?:num[ée]ro\s+de\s+(?:la\s+)?proc[ée]dure|n[°º]\s*de\s+proc[ée]dure|"
                                r"proc[ée]dure\s+n[°º]|PV\s+n[°º]|num[ée]ro\s+de\s+PV|r[ée]f[ée]rence\s+de\s+la\s+"
                                r"proc[ée]dure)\s*:?\s*" + _REF_TAIL, _I)),
    ("ic3", re.compile(r"\bIC3\b[^\n]{0,80}?\b(?:complaint\s+)?(?:ID|number|no\.?|reference|#)\s*(?:is)?\s*[:#]?\s*"
                       r"(?P<v>[A-Z0-9][A-Z0-9-]{6,40})\b", _I)),
    ("ic3", re.compile(r"\bcomplaint\s+(?:ID|reference\s+number)\s*(?:is)?\s*[:#]?\s*(?P<v>[A-Z0-9][A-Z0-9-]{6,40})\b", _I)),
    # a US police report: "Report Number: 26-004417", "Incident # 26-004417", "DR# 26-004417" (only in a text that names
    # the police); "Case No. 26-004417" only when it names a police agency (a provider's "case number" is a ticket)
    ("police_us", re.compile(r"\b(?:Police\s+)?(?:Report|Incident|DR)\s*(?:Number|No\.?|Nr\.?|#)\s*[:#]?\s*" + _REF_TAIL,
                             _I)),
    ("police_us_case", re.compile(r"\b(?:Police\s+)?Case\s*(?:Number|No\.?|#)\s*[:#]?\s*" + _REF_TAIL, _I)),
]
_POLICE_WORD = re.compile(r"\b(?:police|sheriff|incident\s+report|crime\s+report|offen[cs]e\s+report)\b", _I)
_AGENCIES = re.compile(
    r"\b(?:Comando\s+(?:Stazione\s+)?Carabinieri|Carabinieri|Polizia\s+(?:di\s+Stato|Postale)|Guardia\s+di\s+Finanza|"
    r"Procura\s+della\s+Repubblica|Landeskriminalamt|Bundeskriminalamt|Kriminalpolizei|Staatsanwaltschaft|Polizei\w*|"
    r"LKA|BKA|Gendarmerie(?:\s+nationale)?|Police\s+nationale|Parquet|Federal\s+Bureau\s+of\s+Investigation|FBI|IC3|"
    r"(?:U\.S\.\s+)?Secret\s+Service|USSS|Homeland\s+Security\s+Investigations|HSI|Europol|EC3|"
    r"[A-Z][a-z]+\s+Police(?:\s+Department)?|Police\s+Department|[A-Z]{3,}(?:\s+[A-Z]{3,})?\s+POLICE\s+DEPARTMENT|"
    r"[A-Z][A-Za-z]+(?:\s+County)?\s+Sheriff['’]s\s+(?:Office|Department)|[A-Z]{3,}\s+(?:COUNTY\s+)?SHERIFF['’]S\s+OFFICE)"
    r"\b")
_RANKS = (r"Special\s+Agent|Agent|Officer|Ofc\.|Off\.|Patrol\s+Officer|Deputy|Dep\.|Trooper|Corporal|Cpl\.|"
          r"Detective|Det\.|Inspector|Sergeant|Sgt\.|Lieutenant|Lt\.|Constable|"
          r"Maresciallo|Mar\.|Brigadiere|Appuntato|Capitano|Tenente|Ispettore|Sovrintendente|Commissario|"
          r"Kriminalhauptkommissar(?:in)?|Kriminalkommissar(?:in)?|Kommissar(?:in)?|KHK|KOK|POK|Polizeiobermeister|"
          r"Capitaine|Commandant|Brigadier|Adjudant|Gendarme|Lieutenant")
_PERSON = re.compile(rf"\b(?P<role>{_RANKS})\s+(?P<name>(?:[A-ZÀ-Ý]\.\s*)?[A-ZÀ-Ý][a-zà-ÿ'-]+"
                     rf"(?:\s+[A-ZÀ-Ý][a-zà-ÿ'-]+){{0,2}})")
_PHONE = re.compile(r"\b(?:Tel(?:efono|efon|\.)?|Phone|Ph\.|Tél\.?|Mobile|Mob\.|Cell|Cellulare|Handy)\s*[:.]?\s*"
                    r"(?P<v>\+?\d[\d ()./-]{6,20}\d)", _I)
_LE_DOMAIN = re.compile(r"(?:\.gov(?:\.[a-z]{2})?|\.police\.[a-z.]+|\.?polizia\w*\.it|carabinieri\.it|gdf\.it|"
                        r"polizei\.[a-z.]+|\.bund\.de|gendarmerie\.[a-z.]+|interieur\.gouv\.fr|justice\.fr|"
                        r"europol\.europa\.eu|giustizia\.it|\.mil)$", _I)


def _contacts(own: str, spans, *, le: bool, exclude_refs: set[str], le_domains: frozenset[str]) -> list[dict]:
    refs: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    police, agency_named = bool(_POLICE_WORD.search(own)), bool(_AGENCIES.search(own))
    for system, rx in _REFS:
        if (system == "police_us" and not police) or (system == "police_us_case" and not agency_named):
            continue
        for m in rx.finditer(own):
            v = m.group("v").rstrip(".-/")
            if v.lower() in seen or v.lower() in exclude_refs or not any(ch.isdigit() for ch in v):
                continue
            seen.add(v.lower())
            refs.append((system.removesuffix("_case"), v, m.start()))
    am = _AGENCIES.search(own)
    agency = " ".join(am.group(0).split()) if am else None
    person = _PERSON.search(own)
    emails = [e["value"] for e in rules.find_channels(own)[0]]
    le_mail = next((e for e in emails if _LE_DOMAIN.search(e.rpartition("@")[2])
                    or e.rpartition("@")[2] in le_domains), None) or (emails[0] if le and emails else None)
    pm = _PHONE.search(own) if (le or agency or le_mail) else None
    phone = pm.group("v").strip() if pm else None
    who = {"agency": agency, "name": person.group("name") if person else None,
           "role": " ".join(person.group("role").split()) if person else None, "email": le_mail, "phone": phone}
    out: list[dict] = []
    for i, (system, v, at) in enumerate(refs[:MAX_ITEMS]):
        base = who if i == 0 else {"agency": agency, "name": None, "role": None, "email": None, "phone": None}
        out.append({**base, "reference": v, "system": system, "quote": _quote(_clause_at(own, spans, at))})
    if not out and (person or le_mail) and (agency or le or le_mail):
        at = (person.start() if person else own.lower().find(le_mail or ""))
        out.append({**who, "reference": None, "system": None, "quote": _quote(_clause_at(own, spans, max(0, at)))})
    return out


# --------------------------------------------------------------------------- identifiers
_EVM_TX = re.compile(r"(?<![0-9A-Za-z])0x[0-9a-fA-F]{64}(?![0-9A-Za-z])")
_EVM_ADDR = re.compile(r"(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9A-Za-z])")
_HEX_TX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{64}(?![0-9A-Za-z])")
_TRON = re.compile(r"(?<![0-9A-Za-z])T[1-9A-HJ-NP-Za-km-z]{33}(?![0-9A-Za-z])")
_BTC = re.compile(r"(?<![0-9A-Za-z])(?:bc1[02-9ac-hj-np-z]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})(?![0-9A-Za-z])")
_ACCOUNT = re.compile(r"\b(?P<kw>UID|user\s*ID|account\s*(?:ID|number|no\.?)|customer\s*ID|member\s*ID|"
                      r"sub-?account(?:\s*ID)?|Kontonummer|Konto-?ID|ID\s+utente|ID\s+(?:del\s+)?conto|"
                      r"identifiant\s+(?:du\s+)?compte|order\s*(?:ID|number|no\.?)|orderId|withdrawal\s+ID|"
                      r"deposit\s+ID|Auftragsnummer|numero\s+(?:d'|dell')?ordine)\s*(?:is|:|#|=|-)?\s*[:#]?\s*"
                      r"(?P<v>[A-Za-z0-9][A-Za-z0-9_-]{3,40})", _I)


def _btc_ok(v: str) -> bool:
    if v.lower().startswith("bc1"):
        return v == v.lower()
    from app.freeze import abi

    try:
        body = abi.b58check_decode(v)
    except ValueError:
        return False
    return len(body) == 21 and body[0] in (0x00, 0x05)


def norm_id(v: str) -> str:
    t = (v or "").strip()
    low = t.lower()
    if low.startswith("0x") and len(low) == 66:
        return low[2:]
    return low if low.startswith(("0x", "bc1")) or re.fullmatch(r"[0-9a-f]{64}", low) else t


def _identifiers(own: str, *, known: set[str], skip: set[str]) -> list[dict]:
    from app.freeze import abi

    out: list[dict] = []
    seen: set[str] = set()

    def add(kind: str, chain: str | None, value: str) -> None:
        k = norm_id(value)
        if k in seen or k.lower() in skip:
            return
        seen.add(k)
        new = k not in known and k.lower() not in known
        out.append({"kind": kind, "chain": chain, "value": value, "known": not new,
                    "watch": new and kind == "address" and chain in ("tron", "evm")})

    for m in _EVM_TX.finditer(own):
        add("tx", "evm", m.group(0))
    for m in _EVM_ADDR.finditer(own):
        add("address", "evm", m.group(0))
    for m in _HEX_TX.finditer(own):
        add("tx", None, m.group(0))
    for m in _TRON.finditer(own):
        if abi.is_tron_address(m.group(0)):
            add("address", "tron", m.group(0))
    for m in _BTC.finditer(own):
        v = m.group(0)
        if any(c.isalpha() for c in v) and _btc_ok(v):
            add("address", "bitcoin", v)
    for m in _ACCOUNT.finditer(own):
        v = m.group("v")
        if not any(ch.isdigit() for ch in v) or norm_id(v) in seen:
            continue
        kw = m.group("kw").lower()
        add("order_id" if any(w in kw for w in ("order", "ordine", "auftrag", "withdrawal", "deposit")) else "account",
            None, v)
    return out[:MAX_ITEMS * 2]


# --------------------------------------------------------------------------- channels, tickets
def _host(value: str) -> str:
    v = value.lower()
    h = v.rpartition("@")[2] if "@" in v and "://" not in v else re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
    return h.split("/")[0].split(":")[0].removeprefix("www.")


def _channels(own: str, *, playbook, exclude: set[str], org_key: str | None, others: dict[str, str]) -> list[dict]:
    addrs, urls = rules.find_channels(own, exclude)
    out = []
    for kind, items in (("email", addrs), ("url", urls)):
        for c in items:
            v = c["value"]
            cls = playbook.domain_class(v) if playbook is not None else None
            vp = playbook.portal_for(v) if playbook is not None and cls and cls.startswith("vendor") else None
            host = _host(v)
            org = next((k for d, k in others.items() if host == d or host.endswith("." + d)), None)
            if cls is None:
                cls = "own" if org is not None and org == org_key else "third_party" if org else "unknown"
            entry = {"value": v, "kind": kind, "purpose": c.get("purpose"), "class": cls.replace("_le_only", ""),
                     "le_only": cls == "vendor_portal_le_only", "tenant": vp.tenant if vp else None,
                     "org": org if org != org_key else None, "pick": cls in ("third_party", "unknown")}
            out.append(entry)
    return out


def _tickets(own: str, subject: str, playbook, exclude_refs: set[str]) -> list[dict]:
    out: list[dict] = []
    fmts = list(getattr(playbook, "tickets", ()) or ())
    for t in fmts:
        if not t.regex:
            continue
        try:
            rx = re.compile(t.regex, _I)
        except re.error:
            continue
        for m in rx.finditer(f"{subject}\n{own}"):
            v = m.group(0)
            if v.lower() not in exclude_refs and v not in {x["value"] for x in out}:
                i = own.find(v)
                out.append({"value": v[:64], "system": t.system,
                            "quote": _quote(_clause_at(own, clauses(own), i)) if i >= 0 else None})
    generic = rules.find_ticket(f"{subject}\n{own}", exclude_refs)
    if generic and generic not in {x["value"] for x in out}:
        i = own.find(generic)
        sys_ = next((t.system for t in fmts if not t.regex), None) if len(fmts) == 1 or not out else None
        out.insert(0, {"value": generic, "system": sys_,
                       "quote": _quote(_clause_at(own, clauses(own), i)) if i >= 0 else None})
    return out[:MAX_ITEMS]


# --------------------------------------------------------------------------- entry point
def extract(own: str | None, *, playbook: Any = None, subject: str | None = None, received_at: datetime | None = None,
            exclude_addresses: Iterable[str] = (), exclude_refs: Iterable[str] = (), known: Iterable[str] = (),
            org_key: str | None = None, others: dict[str, str] | None = None, le: bool | None = None,
            le_domains: Iterable[str] = ()) -> Extracted:
    """Read `own` (the sender's own text) for the fields in the module doc. Never raises on odd input."""
    own = str(own or "")[:rules.MAX_TEXT_CHARS]
    received = received_at if received_at is not None and received_at.tzinfo else (
        received_at.replace(tzinfo=UTC) if received_at else datetime.now(tz=UTC))
    refs = {r.strip().lower() for r in exclude_refs if r and r.strip()}
    excl = {a.strip().lower() for a in exclude_addresses if a}
    spans = clauses(own)
    is_le = bool(le) if le is not None else getattr(playbook, "side", None) == "le"
    instrument, types, signals = _instrument(own, spans, playbook)
    tickets = _tickets(own, str(subject or "")[:512], playbook, refs)
    contacts = _contacts(own, spans, le=is_le, exclude_refs=refs, le_domains=frozenset(le_domains))
    skip = refs | {t["value"].lower() for t in tickets} | {str(c["reference"]).lower() for c in contacts
                                                           if c.get("reference")}
    known_n = {norm_id(k) for k in known if k} | {k.lower() for k in known if k}
    return Extracted(
        tickets=tickets, instrument=instrument, instruments=types,
        channels=_channels(own, playbook=playbook, exclude=excl, org_key=org_key, others=others or {}),
        asks=_asks(own, spans), deadlines=_deadlines(own, spans, received), contacts=contacts,
        identifiers=_identifiers(own, known=known_n, skip=skip), signals=signals)


def tokens(texts: Iterable[str | None]) -> set[str]:
    """The wallets / tx hashes / ids in our own letters (normalised): a reply naming them names nothing new."""
    out: set[str] = set()
    for t in texts:
        for rx in (_EVM_TX, _EVM_ADDR, _HEX_TX, _TRON, _BTC):
            out |= {norm_id(m.group(0)) for m in rx.finditer(t or "")}
        out |= {m.group("v").lower() for m in _ACCOUNT.finditer(t or "")}
    return out


# --------------------------------------------------------------------------- the AI's reading of the same fields
AI_IDENTIFIER_KINDS = ("address", "tx", "account", "order_id")
AI_DEADLINE_WHAT = tuple(DEADLINE_LABELS)


def _verbatim(needle: Any, own: str, *, min_chars: int = 1) -> str | None:
    if not isinstance(needle, str):
        return None
    n = " ".join(needle.split())
    return n if len(n) >= min_chars and n in " ".join(own.split()) else None


def verify_ai(data: Any, own: str, *, received_at: datetime | None = None) -> dict:
    """The AI's extraction fields, each kept only when it is grounded in the sender's own text: a quote verbatim in
    it, a ticket / reference / identifier / e-mail / phone that occurs in it, a deadline whose stated date or
    duration is in its quote and parses, an instrument / evidence key / identifier kind from the vocabulary, issuer
    jurisdictions the quote states. Everything it keeps is advisory (`source` "ai"); no AI deadline is `auto`."""
    from app.domain import playbook as pbm

    d = data if isinstance(data, dict) else {}
    received = received_at or datetime.now(tz=UTC)
    out: dict[str, Any] = {"tickets": [], "instrument": None, "asks": [], "deadlines": [], "contacts": [],
                           "identifiers": []}

    def items(k: str) -> list[dict]:
        v = d.get(k)
        return [x for x in v[:MAX_ITEMS] if isinstance(x, dict)] if isinstance(v, list) else []

    for t in items("tickets"):
        v = _verbatim(t.get("value"), own, min_chars=3)
        if v and any(ch.isdigit() for ch in v):
            out["tickets"].append({"value": v[:64], "system": None, "quote": _verbatim(t.get("quote"), own,
                                                                                      min_chars=10), "source": "ai"})
    ins = d.get("instrument") if isinstance(d.get("instrument"), dict) else None
    if ins and ins.get("type") in INSTRUMENT_LABELS:
        q = _verbatim(ins.get("quote"), own, min_chars=12)
        if q:
            stated = set(jurisdictions(q))
            jur = [j for j in (ins.get("issuer_jurisdictions") or []) if isinstance(j, str) and j in stated]
            out["instrument"] = {"type": ins["type"], "label": INSTRUMENT_LABELS[ins["type"]],
                                 "issuer_jurisdictions": jur, "jurisdictions_from": "reply" if jur else None,
                                 "quote": _quote(q), "via": "ai", "path": None, "source": "ai"}
    for a in items("asks"):
        q = _verbatim(a.get("quote"), own, min_chars=8)
        if q and a.get("req_key") in pbm.EVIDENCE and a["req_key"] not in {x["req_key"] for x in out["asks"]}:
            out["asks"].append({"kind": ASK_KIND.get(a["req_key"], "document"), "req_key": a["req_key"],
                                "label": ASK_LABELS.get(a["req_key"], a["req_key"].replace("_", " ")),
                                "quote": _quote(q), "source": "ai"})
    for x in items("deadlines"):
        q = _verbatim(x.get("quote"), own, min_chars=8)
        stated = _verbatim(x.get("stated"), q or "", min_chars=2) if q else None
        if not (q and stated and x.get("what") in AI_DEADLINE_WHAT):
            continue
        dl = None
        m = _DURATION.search(stated)
        if m:
            unit = next(k for k, _ in _UNITS if m.group(k))
            raw = m.group("n").lower()
            n = float(_NUM_WORDS[raw] if raw in _NUM_WORDS else int(raw))
            if unit == "weeks":
                unit, n = "days", n * 7
            dl = _deadline_from(x["what"], q, received=received, amount=n, unit=unit) if n > 0 else None
        else:
            m = _DATE.search(stated)
            parsed = parse_date(m, received.date(), bool(_EU_TEXT.search(own))) if m else None
            dl = _deadline_from(x["what"], q, received=received, parsed=parsed) if parsed else None
        if dl is not None:
            out["deadlines"].append({**dl, "auto": False, "source": "ai"})
    for c in items("contacts"):
        q = _verbatim(c.get("quote"), own, min_chars=8)
        if not q:
            continue
        vals = {k: _verbatim(c.get(k), own, min_chars=2) for k in ("agency", "name", "email", "phone", "reference")}
        if any(vals.values()):
            out["contacts"].append({**vals, "role": None, "system": None, "quote": _quote(q), "source": "ai"})
    shapes = {"address": (_EVM_ADDR, _TRON, _BTC), "tx": (_EVM_TX, _HEX_TX)}
    for i in items("identifiers"):
        v = _verbatim(i.get("value"), own, min_chars=4)
        kind = i.get("kind")
        if not v or kind not in AI_IDENTIFIER_KINDS or " " in v:
            continue
        if kind in shapes and not any(rx.fullmatch(v) for rx in shapes[kind]):
            continue
        chain = "evm" if v.lower().startswith("0x") else "tron" if _TRON.fullmatch(v) else (
            "bitcoin" if kind == "address" else None)
        if chain == "tron":
            from app.freeze import abi

            if not abi.is_tron_address(v):
                continue
        out["identifiers"].append({"kind": kind, "chain": chain, "value": v, "known": False,
                                   "watch": kind == "address" and chain in ("tron", "evm"), "source": "ai"})
    return out


def merge(ext: dict | None, ai: dict | None, *, exclude_refs=(), known=()) -> dict | None:
    """The rules' extraction with the AI's additions (tagged `source` "ai"). Never a silent overwrite: where the two
    read the instrument or a deadline differently, the rules' reading stays and the AI's is kept as `ai_instrument`
    / a deadline marked `suggestion`, and `disagree` names the field. The rules' exclusions hold for the AI too: our
    own case references are never their ticket (`exclude_refs`), and an identifier our letters cite (`known`) is
    known, not a new wallet to watch."""
    if not ext:
        return ext
    if not ai:
        return ext
    refs = {str(x).strip().lower() for x in exclude_refs if x and len(str(x).strip()) >= 3}
    known = {str(x) for x in known} | {str(x).lower() for x in known}
    ai = {**ai, "tickets": [t for t in ai.get("tickets") or [] if not any(
        r in str(t.get("value") or "").lower() or str(t.get("value") or "").lower() in r for r in refs)],
          "identifiers": [{**i, "known": norm_id(i.get("value") or "") in known
                           or norm_id(i.get("value") or "").lower() in known}
                          for i in ai.get("identifiers") or []]}
    for i in ai["identifiers"]:
        i["watch"] = bool(i.get("watch")) and not i["known"]
    out = {k: (list(v) if isinstance(v, list) else v) for k, v in ext.items()}
    disagree: list[str] = list(out.get("disagree") or [])
    ins, ai_ins = out.get("instrument"), ai.get("instrument")
    if ai_ins:
        if ins is None:
            out["instrument"] = ai_ins
        elif ai_ins["type"] != ins["type"]:
            out["ai_instrument"] = ai_ins
            disagree.append("instrument")
    have = {(x["what"], x["due"]) for x in out.get("deadlines") or []}
    whats = {x["what"]: x["due"] for x in out.get("deadlines") or []}
    for x in ai.get("deadlines") or []:
        if (x["what"], x["due"]) in have:
            continue
        if x["what"] in whats:
            disagree.append("deadline")
        out.setdefault("deadlines", []).append({**x, "auto": False, "suggestion": True})
    for key, ident in (("tickets", "value"), ("asks", "req_key"), ("identifiers", "value"), ("contacts", "quote")):
        seen = {str(x.get(ident)).lower() for x in out.get(key) or []}
        for x in ai.get(key) or []:
            if str(x.get(ident)).lower() not in seen:
                out.setdefault(key, []).append(x)
                seen.add(str(x.get(ident)).lower())
    if disagree:
        out["disagree"] = list(dict.fromkeys(disagree))
    return out
