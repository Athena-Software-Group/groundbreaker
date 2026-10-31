"""What a document names: wallets (EVM, TRON, Bitcoin, Solana), transaction hashes, exchange UIDs / order ids, LE
and complaint references (IC3 included), law-enforcement contacts, dates, amounts and catalogue providers (pure: the
patterns of app.blocks.extract and app.blocks.classify_rules; no database).

    f = find(text, known={…}, exclude_refs={…}, providers=catalogue_orgs)
    f["identifiers"], f["refs"], f["contacts"], f["dates"], f["amounts"], f["providers"], f["doc_date"], f["tickets"]

`tickets`: a provider's own ticket / case number (classify_rules.find_ticket: never our case reference, a complaint
or LE reference the text names, or a reference the case holds), for a person to record with the reply.

Every item is a proposal a person confirms (watch a wallet, seed the trace, add the LE contact or the complaint
reference, file the document as a reply to a request): nothing is added by itself.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, date, datetime

from app.blocks import classify_rules as rules
from app.blocks import extract as ex

MAX_ITEMS = 12
MAX_IDS = 24
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_SOL = re.compile(r"(?<![0-9A-Za-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![0-9A-Za-z])")
_SOL_CUE = re.compile(r"\b(?:solana|SOL|SPL|phantom|solscan)\b", re.IGNORECASE)


def b58decode(v: str) -> bytes | None:
    n = 0
    for ch in v:
        i = _B58.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(v) - len(v.lstrip("1"))) + body


def _solana(text: str, seen: set[str]) -> list[dict]:
    """Solana addresses (base58, 32 bytes) in a text that mentions Solana (a bare base58 run is too common)."""
    if not _SOL_CUE.search(text):
        return []
    out = []
    for m in _SOL.finditer(text):
        v = m.group(0)
        raw = b58decode(v)
        if raw is None or len(raw) != 32 or v in seen:
            continue
        if not (any(c.isdigit() for c in v) and any(c.islower() for c in v) and any(c.isupper() for c in v)):
            continue
        seen.add(v)
        out.append({"kind": "address", "chain": "solana", "value": v, "known": False, "watch": False})
    return out


# who a wallet belongs to is never read from the text: a person picks the role (victim / perpetrator / exchange or
# service / unknown) on the item page. Five rounds of wording rules each read some receipts, chats and complaints
# backwards ("From:" is the scammer's on an incoming transfer, "the address indicated by the victim" is the scammer's
# destination). The text only gives a HINT: the cue words next to the address on its own line, shown as they are
# ('near "From:"', 'near "scammer"'), for the person to read before choosing.
_HINT_WORDS = (r"victims?|vittim[ae]|persona\s+offesa|opfers?|gesch[äa]digte[nr]?|victimes?|complainants?|"
               r"claimants?|querelante|denunciante|parte\s+lesa|suspects?|scammers?|fraudsters?|perpetrators?|"
               r"offenders?|criminals?|attackers?|hackers?|exploiters?|thief|thieves|drainer|phishing|poison\w*|"
               r"indagat[oaie]|truffator[eia]|t[äa]ter[ns]?|betr[üu]ger[ns]?|escrocs?|arnaqueur\w*|exchange|deposit|"
               r"hot\s+wallet|my\s+(?:own\s+)?(?:wallet|address|account|metamask|ledger)|refund\w*|profit\w*|"
               r"received|incoming|withdrawal")
_HINT_LABELS = (r"from|to|sender|sent\s+from|sent\s+to|source|origin|recipient|beneficiary|receiver|payee|"
                r"destinatario|beneficiario|empf[äa]nger|destinataire|b[ée]n[ée]ficiaire|mittente|absender|"
                r"exp[ée]diteur")
_HINT = re.compile(rf"(?<!\w)(?:(?P<w>{_HINT_WORDS})(?![\w])|(?P<l>{_HINT_LABELS})\s*[:：])", re.IGNORECASE)
HINT_BEFORE, HINT_AFTER, HINT_MAX = 60, 40, 3


def address_hint(text: str | None, value: str) -> str | None:
    """'near "From:"', 'near "scammer", "To:"': the cue words (a fixed lexicon, never the document's other words)
    next to the address on its own line, for the person who picks its role; None when there are none. Never a role:
    nothing is assigned from it."""
    text = str(text or "")
    i = text.find(value)
    if i < 0:
        i = text.lower().find(value.lower())
    if i < 0:
        return None
    j = i + len(value)
    line_start = text.rfind("\n", 0, i) + 1
    end = text.find("\n", j)
    end = len(text) if end < 0 else end
    near = text[max(line_start, i - HINT_BEFORE):i] + " " + text[j:min(end, j + HINT_AFTER)]
    cues = []
    for m in _HINT.finditer(near):
        cue = " ".join((m.group("w") or f"{m.group('l')}:").split())
        if cue.lower() not in (c.lower() for c in cues):
            cues.append(cue)
    return "near " + ", ".join(f"“{c}”" for c in cues[:HINT_MAX]) if cues else None


# a US document writes NN/NN/YYYY month first; the document's own date follows a label ("Date Reported: …"); a date
# in the narrative ("between 08/14/2026 and 09/20/2026") is never the document's date
_US_TEXT = re.compile(r"\b(?:police\s+department|sheriff|FBI|IC3|U\.S\.|United\s+States|USA|Fedwire|ABA\s+routing|"
                      r"zip\s+code)", re.IGNORECASE)
_DOC_DATE_LABEL = re.compile(r"(?:date\s+(?:reported|filed|of\s+(?:report|filing|complaint|issue)|issued|submitted)|"
                             r"report(?:ed)?\s+date|(?:submitted|filed|issued|reported)\s+on|data\s+(?:della\s+)?"
                             r"(?:denuncia|querela)|datum\s+der\s+anzeige|date\s+de\s+(?:la\s+)?plainte|^\s*date)"
                             r"\s*[:.\-]?\s*$", re.IGNORECASE | re.MULTILINE)
_NARRATIVE = re.compile(r"\b(?:between|and|from|since|until|till|to|on\s+or\s+about|tra|dal|al|zwischen|bis|entre)\s*$",
                        re.IGNORECASE)


def _dates(text: str) -> list[dict]:
    out, seen = [], set()
    today = date.today()
    eu = bool(ex._EU_TEXT.search(text[:4000]))
    us = not eu and bool(_US_TEXT.search(text[:4000]))
    for m in ex._DATE.finditer(text[:rules.MAX_TEXT_CHARS]):
        d = ex.parse_date(m, today, eu)
        if d is None or (d["date"] is None and not d["candidates"]):
            continue
        if us and d["ambiguous"] and m.groupdict().get("sep") == "/" and len(d["candidates"]) == 2:
            d = {**d, "date": d["candidates"][1], "likely": "mdy"}  # month first in a US document
        key = d["date"] or "|".join(d["candidates"])
        before = text[max(0, m.start() - 40):m.start()]
        if key in seen:
            continue
        seen.add(key)
        out.append({"date": d["date"], "candidates": d["candidates"], "ambiguous": d["ambiguous"],
                    "likely": d["likely"], "year_inferred": d["year_inferred"], "raw": " ".join(m.group(0).split()),
                    "labelled": bool(_DOC_DATE_LABEL.search(before)), "narrative": bool(_NARRATIVE.search(before))})
        if len(out) >= MAX_ITEMS:
            break
    return out


def _amounts(text: str) -> list[dict]:
    out, seen = [], set()
    for m in rules._AMOUNT_RE.finditer(text[:rules.MAX_TEXT_CHARS]):
        d = rules.parse_number(m.group("n1") or m.group("n2") or "")
        asset = (m.group("pre") or m.group("post") or "").upper().replace("US$", "USD").replace("$", "USD")
        asset = {"€": "EUR", "£": "GBP"}.get(asset, asset)
        if d is None or d <= 0 or (str(d), asset) in seen:
            continue
        seen.add((str(d), asset))
        out.append({"amount": str(d), "asset": asset or None, "raw": " ".join(m.group(0).split())})
        if len(out) >= MAX_ITEMS:
            break
    return out


def _word(name: str, text: str) -> bool:
    # a whole word, written as a company writes its name (or in capitals): "Gate" and "Circle" are not "gate", "circle"
    return any(re.search(rf"(?<![A-Za-z0-9]){re.escape(n)}(?![A-Za-z0-9])", text) for n in {name, name.upper()})


def _providers(text: str, orgs: Iterable) -> list[dict]:
    out = []
    head = text[:rules.MAX_TEXT_CHARS]
    for o in orgs or ():
        if getattr(o, "category", "") in ("law_enforcement", "regulator"):
            continue
        names = [n for n in getattr(o, "names", ()) or () if len(n) >= 3]
        if any(_word(n, head) for n in names):
            out.append({"key": o.key, "name": o.name, "category": o.category})
        if len(out) >= MAX_ITEMS:
            break
    return out


def find(text: str | None, *, known: Iterable[str] = (), exclude_refs: Iterable[str] = (), orgs: Iterable = (),
         le: bool = False) -> dict:
    """The findings of `text` (see the module doc). Never raises on odd input."""
    text = str(text or "")[:rules.MAX_TEXT_CHARS]
    refs = {r.strip().lower() for r in exclude_refs if r and r.strip()}
    spans = ex.clauses(text)
    contacts = ex._contacts(text, spans, le=le, exclude_refs=refs, le_domains=frozenset())
    skip = refs | {str(c["reference"]).lower() for c in contacts if c.get("reference")}
    known_n = {ex.norm_id(k) for k in known if k} | {str(k).lower() for k in known if k}
    ids = ex._identifiers(text, known=known_n, skip=skip)
    seen = {i["value"] for i in ids}
    ids += [i for i in _solana(text, seen) if i["value"].lower() not in known_n and i["value"] not in known_n]
    dates = _dates(text)
    first = next((d["date"] for d in dates if d["date"] and d["labelled"] and not d["year_inferred"]), None) or next(
        (d["date"] for d in dates if d["date"] and not d["year_inferred"] and not d["narrative"]), None)
    ticket = rules.find_ticket(text, skip)
    return {
        "identifiers": ids[:MAX_IDS],
        "refs": [{"system": c["system"], "reference": c["reference"], "agency": c.get("agency")} for c in contacts
                 if c.get("reference")][:MAX_ITEMS],
        "contacts": contacts[:MAX_ITEMS], "dates": dates, "amounts": _amounts(text), "providers": _providers(text, orgs),
        "doc_date": first, "tickets": [ticket] if ticket else [],
    }


def stored(f: dict) -> dict:
    """The part of the findings kept in the database: chain identifiers, references, dates, amounts, providers and
    the agency named, never an officer's name, e-mail or phone (those are read again from the vault text)."""
    return {"identifiers": [{k: i.get(k) for k in ("kind", "chain", "value")} for i in f.get("identifiers") or []],
            "refs": f.get("refs") or [], "dates": [{k: d.get(k) for k in ("date", "candidates", "ambiguous")}
                                                   for d in f.get("dates") or []],
            "amounts": [{k: a.get(k) for k in ("amount", "asset")} for a in f.get("amounts") or []],
            "providers": f.get("providers") or [], "doc_date": f.get("doc_date"), "tickets": f.get("tickets") or [],
            "agencies": sorted({c["agency"] for c in f.get("contacts") or [] if c.get("agency")})[:MAX_ITEMS],
            "at": datetime.now(tz=UTC).isoformat(timespec="seconds")}
