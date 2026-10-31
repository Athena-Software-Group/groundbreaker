"""Evidence checklists (lightweight; design §4.1): which requirements of a request (the provider playbook's EVIDENCE
keys for the path, the asks read from a reply) the case already holds, and in which existing object. No new table.

    h = holdings(db, case, run=run, wallets=freeze_wallets)          # what the case holds, read once
    items = check(h, ["police_report", "tx_list_copyable", ...], access=access, addresses={...}, tickets=[...])
    counts(items) -> {"have": 3, "missing": 1, ...}
    waive(db, case, "ownership_proof", user=user, reason="…") / unwaive(db, case, key)   # case admins; the route audits

**Satisfied by** (never by content: by object type, folder, ids and the stored hash):
* police_report / complaint_ref / ic3_ref: an evidence item of type police_report / complaint_receipt, a complaint
  reference in case.facts["complaints"] or an LE contact's reference (app.domain.evidence.known_references);
* loa / poa / special_proxy: the sender profile's authority documents, a legal-folder item of that type;
* ownership_proof, victim_id, comms_export, wire_details: an item of a matching type;
* tx_list_copyable: the latest trace run (its movements CSV export); trace_report_run: a chain_reports item;
* balance_reading / freeze_check: an on-chain freeze reading (app.freeze) of the request's wallets (any wallet of the
  case when the request names none);
* receiving_account / provider_ids / prior_ticket_ref: the addresses the request cites, their ticket;
* incident_narrative: the case summary;
* the statements a letter makes (freeze duration, non-disclosure, native vs bridged, urgency, English): "letter" only
  when the chosen template states it (`emits`: the LE / counsel brief states each one; every letter is in English),
  else missing ("add it to the letter");
* LE / court instruments (agency identity, letterhead request, court order, seizure warrant, MLAT bundle, the domestic
  order): only an item of that type supplied by LE or counsel ("le" until then: Aegis never drafts one).
* else an item imported from a folder (its `source_type` is only the file extension) whose import metadata names the
  kind (`DERIVED`: the folder, `meta.mapping_rule`, `meta.reference_kind` and the title; never the
  file's content; any item of the Digital artifacts folder counts as a chat / e-mail export): "have", matched by its
  folder / title, for a person to check. An explicit type / tag wins; a case
  admin turns a match into one ("use evidence #N": the requirement key as the item's tag, `use_item`, audited).
* a type a person confirmed on the item (app.evidence_intel) counts as an explicit match (its keys), and an order's
  type becomes its tag (the instrument gate). A type the rules / the AI only suggest from the item's content
  satisfies nothing: the requirement stays missing (or "le"), shown as "suggested: police report — confirm" with the
  item, until a person confirms the type on the item page.

**States:** have, missing, letter, le, unusable (the item failed its integrity check), waived (a case admin recorded a
reason: `cases.facts[WAIVER_KEY]`, audited with the requirement key only). Members who may not see an item (the
Financial folder below admin) see "on file (restricted)" without its id.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Case, EvidenceFolder, EvidenceItem, TraceRun
from app.domain import evidence as ev

WAIVER_KEY = "_evidence_waivers"  # cases.facts: {requirement key: {at, by, reason}}
LETTER = frozenset({"freeze_duration_stmt", "non_disclosure_stmt", "native_vs_bridged_stmt", "urgency_stmt",
                    "english_version"})
LE_SUPPLIED = frozenset({"le_agency_identity", "le_letterhead_request", "court_order", "seizure_warrant", "mlat_bundle",
                         "domestic_order"})
TYPES = {
    "police_report": {"police_report", "complaint_receipt", "complaint"},
    "complaint_ref": {"police_report", "complaint_receipt", "complaint"},
    "ic3_ref": {"complaint_receipt"},
    "loa": {"authority_instrument", "loa", "letter_of_authority", "mandate", "authorisation"},
    "poa": {"poa", "power_of_attorney", "special_proxy", "mandate"},
    "special_proxy": {"special_proxy"},
    "ownership_proof": {"wallet_ownership", "signed_message", "exchange_statement", "bank_statement"},
    "victim_id": {"id_document", "passport", "victim_id"},
    "comms_export": {"chat_export", "transcript", "eml", "email", "chat", "screenshot"},
    "wire_details": {"wire", "wire_details", "bank_statement"},
    **{k: {k} for k in LE_SUPPLIED},
}
# requirement keys an imported item's metadata names: (keys, folders it must be in, pattern over its folder-free metadata)
_F = EvidenceFolder
DERIVED: tuple[tuple[tuple[str, ...], frozenset, re.Pattern], ...] = tuple(
    (k, frozenset(f), re.compile(p, re.IGNORECASE)) for k, f, p in (
        (("trace_report_run",), {_F.INVESTIGATOR_REPORTS, _F.CHAIN_REPORTS},
         (r"intelligence|\btrac(?:e|es|ed|ing)\b|fund[- ]?flow|\b(?:investigat\w*|forensic|blockchain|on[- ]?chain|"
         r"analysis|analytics)\s+report")),
        (("police_report", "complaint_ref"), {_F.LAW_ENFORCEMENT},
         (r"police|polizia|polizei|carabinieri|denunci|querela|esposto|complaint|\bic3\b|\bfbi\b|"
         r"\b(?:incident|crime|criminal|offen[cs]e)\s+report")),
        (("ic3_ref",), {_F.LAW_ENFORCEMENT}, r"\bic3\b"),
        (("poa", "loa"), {_F.LEGAL, _F.INVESTIGATOR_REPORTS},
         r"power\s+of\s+(?:agent|attorney)|\bprocura\b(?!\s+(?:della|di)\b)|\bpoa\b"),
        (("loa",), {_F.LEGAL, _F.INVESTIGATOR_REPORTS},
         r"\bloa\b|letter\s+of\s+authori|\bauthori[sz]ation\b|\bmandat[eo]\b|\bdelega\b"),
        (("special_proxy",), {_F.LEGAL}, r"procura\s+speciale|special\s+(?:power\s+of\s+attorney|proxy)"),
        (("ownership_proof",), {_F.FINANCIAL},
         r"bank\s+statement|account\s+statement|exchange\s+statement|estratto\s+conto|due[\s_-]+diligence"),
        (("wire_details",), {_F.FINANCIAL},
         r"bank\s+statement|\bwire\b|\btransfer\s+(?:confirmation|receipt|details)|bonifico|\bswift\b|\biban\b|remittance"),
        (("comms_export",), {_F.DIGITAL_ARTIFACTS},
         r"\bchats?\b|e-?mail|screenshot|transcript|meeting|whatsapp|telegram|\bmessages?\b|\beml\b"),
    ))
MATCHED_LABEL = "on file (matched by its folder / title: check)"
MATCHED_LABELS = {"folder / title": MATCHED_LABEL}
STATE_LABELS = {"have": "on file", "missing": "missing", "letter": "state it in the letter",
                "le": "from LE / counsel", "unusable": "on file, failed its integrity check", "waived": "waived"}
HOW = {
    "police_report": "file the complaint (police / IC3) and add the receipt on the Evidence tab",
    "complaint_ref": "add the complaint reference on the case (or the LE contact's reference)",
    "ic3_ref": "file at ic3.gov and record the complaint ID",
    "loa": "add the signed letter of authority (Sender profile → authority documents)",
    "poa": "add the power of attorney to the Legal folder", "special_proxy": "add the procura speciale (Legal folder)",
    "ownership_proof": "add a signed message / exchange statement proving the victim's wallet",
    "victim_id": "add the victim's ID document (Financial / Legal folder)",
    "tx_list_copyable": "run a trace (its movements CSV is the copyable list)",
    "trace_report_run": "Evidence tab → Snapshot trace report", "balance_reading": "run the on-chain freeze check",
    "freeze_check": "run the on-chain freeze check", "receiving_account": "cite the deposit address in the request",
    "provider_ids": "cite the account / deposit address", "prior_ticket_ref": "quote their ticket (none received yet)",
    "incident_narrative": "write the case summary", "comms_export": "add the chat / e-mail export",
    "wire_details": "add the bank / wire details",
    **{k: "the chosen letter does not state it: add the sentence before sending (the LE brief states it)"
       for k in LETTER},
    **{k: "the officer / counsel supplies it: Aegis never drafts one (add it to the Legal folder when received)"
       for k in LE_SUPPLIED},
}


def _labels() -> dict:
    from app.blocks.path import EVIDENCE_LABELS

    return EVIDENCE_LABELS


def label(key: str) -> str:
    return _labels().get(key, key.replace("_", " "))


@dataclass
class Holdings:
    case: Case
    items: list[EvidenceItem] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)  # complaint / LE references on file
    ic3: bool = False
    authority_ids: set[int] = field(default_factory=set)
    run: TraceRun | None = None
    readings: dict[tuple[str, str], dict] = field(default_factory=dict)  # (chain, address key) -> app.freeze wallet row
    summary: bool = False
    waivers: dict[str, dict] = field(default_factory=dict)
    held: frozenset = frozenset()  # instrument types of the orders on file (held_instruments)

    def held_for(self, authority) -> frozenset:
        """The instrument types of the orders on file that name this provider (its binding paths open)."""
        return held_instruments(self.case, provider_names(authority)) if self.held else frozenset()


def _key(chain: str | None, address: str | None) -> tuple[str, str]:
    from app.domain.addresses import addr_key

    a = (address or "").strip()
    return (chain or ""), (a if a.startswith("T") else addr_key(chain, a))


def waivers(case: Case) -> dict[str, dict]:
    raw = (case.facts or {}).get(WAIVER_KEY)
    return {k: v for k, v in raw.items() if isinstance(v, dict)} if isinstance(raw, dict) else {}


def holdings(db: Session, case: Case, *, run: TraceRun | None = None, wallets: list[dict] | None = None) -> Holdings:
    from app.domain import sender

    facts = case.facts or {}
    profile = sender.get_profile(db, case)
    ic3 = any("ic3" in str(c.get("authority") or "").lower() and c.get("reference")
              for c in facts.get("complaints") or [] if isinstance(c, dict))
    ic3 = ic3 or any("ic3" in (le.agency or "").lower() and le.reference for le in case.le_contacts)
    if wallets is None:
        try:
            from app.freeze.service import wallet_rows

            wallets = wallet_rows(db, case)
        except Exception:  # noqa: BLE001 - no readings: the balance requirement reads missing
            wallets = []
    readings = {_key(w["chain"], w["address"]): w for w in wallets
                if any(c.get("status") == "ok" for c in w.get("checks") or [])}
    return Holdings(case=case, items=list(case.evidence_items), refs=ev.known_references(case), ic3=ic3,
                    authority_ids={int(i) for i in (profile.authority_evidence_ids or []) if str(i).isdigit()}
                    if profile is not None else set(), run=run, readings=readings,
                    summary=bool((case.summary or "").strip()), waivers=waivers(case), held=held_instruments(case))


def _type(e: EvidenceItem) -> str:
    return (e.source_type or "").strip().lower()


def _tags(e: EvidenceItem) -> set[str]:
    return {str(t).lower() for t in e.tags or []}


def _items(h: Holdings, key: str) -> list[EvidenceItem]:
    from app.evidence_intel.service import confirmed_keys

    want = TYPES.get(key, set())
    out = [e for e in h.items if _type(e) in want or key in _tags(e)]
    if key == "ic3_ref":
        out = [e for e in out if "ic3" in (e.title or "").lower() or key in _tags(e)]
    if key in ("loa", "poa"):
        out += [e for e in h.items if e.id in h.authority_ids and e not in out]
    if key == "trace_report_run":
        out = [e for e in h.items if e.folder == EvidenceFolder.CHAIN_REPORTS or key in _tags(e)]
    # a type a person confirmed on the item (app.evidence_intel): an explicit match
    return out + [e for e in h.items if e not in out and key in confirmed_keys(e)]


def _meta_text(e: EvidenceItem) -> str:
    m = e.meta or {}
    return " ".join(str(v) for v in (m.get("mapping_rule"), m.get("reference_kind"), e.title) if v)


def derived_keys(e: EvidenceItem) -> set[str]:
    """The requirement keys an item's import metadata names (DERIVED), never from its content."""
    text = _meta_text(e)
    out = {k for keys, folders, pat in DERIVED if e.folder in folders and pat.search(text) for k in keys}
    if e.folder == EvidenceFolder.DIGITAL_ARTIFACTS:  # a chat / e-mail export by its folder alone (IMG_2034.png): check
        out.add("comms_export")
    return out


def _derived(h: Holdings, key: str) -> list[EvidenceItem]:
    return [e for e in h.items if key in derived_keys(e)]


def _suggested(h: Holdings, key: str) -> list[tuple[EvidenceItem, str]]:
    """(item, suggested type) of the items whose unconfirmed reading suggests a type satisfying `key`
    (app.evidence_intel.service.suggestions): never applied, a person confirms the type first."""
    from app.evidence_intel.service import suggestions

    return [(e, t) for e in h.items if (t := suggestions(e).get(key))]


def _from_items(found: list[EvidenceItem], access) -> tuple[str, str, list[int]]:
    ok = [e for e in found if ev.integrity_status(e) not in ("mismatch", "missing")]
    if not ok:
        return "unusable", f"evidence #{found[0].id} failed its integrity check", [e.id for e in found]
    seen = [e for e in ok if access is None or ev.can_see(access, e)]
    if not seen:
        return "have", "on file (restricted)", []
    e = seen[0]
    return "have", f"evidence #{e.id} ({(e.source_type or e.folder.value).replace('_', ' ')})", [x.id for x in seen]


EMITS = {"le_brief": LETTER, "counsel_brief": LETTER}  # the statements a template writes (correspondence.BRIEF_STATEMENTS)
ENGLISH = frozenset({"english_version"})  # every letter Aegis drafts is in English


def emits_for(href: str | None) -> frozenset:
    """The LETTER statements the letter behind an action's link states."""
    tpl = next((k for k in EMITS if f"template={k}" in (href or "")), None)
    return EMITS[tpl] if tpl else ENGLISH


# an order on file that a provider's binding path takes (Playbook.gate(held=…)): the evidence type → instrument types
HELD_TYPES = {"court_order": {"court_order"}, "freezing_order": {"freezing_order"}, "seizure_warrant": {"seizure_warrant"},
              "us_or_fr_court_order": {"us_or_fr_court_order", "court_order"}}


INSTRUMENT_KEYS = LE_SUPPLIED | frozenset(HELD_TYPES) | frozenset(t for v in HELD_TYPES.values() for t in v)


def held_orders(case: Case) -> list[EvidenceItem]:
    """The orders LE or counsel supplied that the checklist shows as on file (type or tag court_order / freezing_order
    / seizure_warrant, integrity intact)."""
    out = []
    for e in case.evidence_items:
        kinds = {_type(e), *(str(t).lower() for t in e.tags or [])} & set(HELD_TYPES)
        if kinds and ev.integrity_status(e) not in ("mismatch", "missing"):
            out.append(e)
    return out


def provider_names(authority) -> list[str]:
    """The names an order on file may give a provider: its own, its entity's and its catalogue aliases."""
    names = [getattr(authority, "name", None), getattr(getattr(authority, "entity", None), "name", None)]
    try:
        from app.domain import directory

        org = directory.org_for(authority)
    except Exception:  # noqa: BLE001 - an invalid catalogue: the names on the case only
        org = None
    if org is not None:
        names += [org.name, *org.names]
    return [n for n in dict.fromkeys(names) if n]


def _name_words(names) -> list[str]:
    """Whole-word keys of provider names: "Circle (USDC issuer)" → circle; "SWFT / Bridgers" → swft, bridgers."""
    out = []
    for n in names or ():
        for part in re.split(r"[/]", re.split(r"\s*\(", n or "")[0]):
            p = part.strip().casefold()
            if len(p) >= 3:
                out.append(p)
    return list(dict.fromkeys(out))


def names_provider(e: EvidenceItem, names) -> bool:
    """The order names one of `names` as a whole word (its title, description or `meta.to`): "Gate" never matches
    "investigate"."""
    text = f"{e.title or ''} {e.description or ''} {(e.meta or {}).get('to') or ''} {(e.meta or {}).get('entity') or ''}"
    return any(re.search(rf"(?<![A-Za-z0-9]){re.escape(w)}(?![A-Za-z0-9])", text, re.IGNORECASE)
               for w in _name_words(names))


def held_instruments(case: Case, names=None) -> frozenset[str]:
    """The instrument types those orders satisfy (a court order of a US or French court, `meta.jurisdiction`, also
    satisfies Circle's US-or-French court order). `names` (provider_names): only the orders that name that provider
    (an order to Circle never opens Gate's binding path); None: every order on file."""
    from app.domain import playbook as pbm

    out: set[str] = set()
    for e in held_orders(case):
        if names is not None and not names_provider(e, names):
            continue
        for k in {_type(e), *(str(t).lower() for t in e.tags or [])} & set(HELD_TYPES):
            out |= HELD_TYPES[k]
            if k == "court_order" and pbm.jurisdiction_code(str((e.meta or {}).get("jurisdiction") or "")) in ("US", "FR"):
                out.add("us_or_fr_court_order")
    return frozenset(out)


def check(h: Holdings, keys, *, access=None, addresses=(), tickets=(), cited: bool = False,
          emits: frozenset = ENGLISH) -> list[dict]:
    """One {key, label, state, state_label, source, ids, how, waiver} per requirement (first occurrence order).
    `addresses`: the (chain, address) pairs the request is about; `tickets`: their ticket numbers; `cited`: the request
    cites its deposit / receiving addresses; `emits`: the statements the letter states (EMITS)."""
    out = []
    want = {_key(c, a) for c, a in addresses}
    for key in dict.fromkeys(k for k in keys if k):
        state, source, ids, matched = "missing", None, [], None
        found = _items(h, key)
        if key in LETTER and key in emits:
            state, source = "letter", "the letter states it (check the draft)"
        elif key in LETTER:
            state = "missing"
        elif found:
            state, source, ids = _from_items(found, access)
        elif key in ("police_report", "complaint_ref") and h.refs:
            state, source = "have", f"complaint reference on file ({len(h.refs)})"
        elif key == "ic3_ref" and h.ic3:
            state, source = "have", "IC3 complaint reference on file"
        elif key == "tx_list_copyable" and h.run is not None:
            state, source = "have", f"movements CSV of trace run #{h.run.id}"
        elif key in ("balance_reading", "freeze_check"):
            hits = [w for k, w in h.readings.items() if not want or k in want]
            if hits:
                last = max((c.get("checked_at") or "" for w in hits for c in w["checks"] if c.get("status") == "ok"),
                           default="")
                blocks = [c.get("block_number") for w in hits for c in w["checks"] if c.get("block_number")]
                stale = any(c.get("stale_note") for w in hits for c in w["checks"])
                state, source = "have", (f"on-chain reading of {len(hits)} wallet{'s' if len(hits) != 1 else ''}"
                                         + (f", {last[:10]}" if last else "") + (f", block {max(blocks)}" if blocks else "")
                                         + ("; the last attempt failed: re-run the check" if stale else ""))
        elif key in ("receiving_account", "provider_ids") and (cited or want):
            state, source = "have", f"{max(len(want), 1)} address{'es' if len(want) > 1 else ''} from the trace / the request"
        elif key == "prior_ticket_ref" and tickets:
            state, source = "have", f"their ticket {tickets[0]}"
        elif key == "incident_narrative" and h.summary:
            state, source = "have", "the case summary"
        if state == "missing" and key not in LETTER and (guess := _derived(h, key)):
            state, source, ids = _from_items(guess, access)
            matched = "folder / title" if state == "have" else None
            source = f"{source}, matched by its folder / title: check" if matched else source
        suggested = None
        if state == "missing" and key in LE_SUPPLIED:
            state = "le"
        if state in ("missing", "le") and key not in LETTER and (sug := _suggested(h, key)):
            seen = [(e, t) for e, t in sug if access is None or ev.can_see(access, e)]
            e, t = (seen or sug)[0]
            suggested = {"type": t, "label": t.replace("_", " "), "ids": [x.id for x, _ in seen]}
            source = (f"evidence #{e.id} reads as a {suggested['label']}: confirm its type on the item page" if seen
                      else "an item reads as one (restricted): a case admin confirms its type")
        w = h.waivers.get(key)
        if w is not None and state in ("missing", "le", "unusable"):
            state = "waived"
        out.append({"key": key, "label": label(key), "state": state,
                    "state_label": (f"suggested: {suggested['label']} — confirm" if suggested and state != "waived"
                                    else MATCHED_LABELS.get(matched, STATE_LABELS[state])), "matched": matched,
                    "suggested": suggested if state != "waived" else None,
                    "source": source, "ids": ids, "how": HOW.get(key) if state in ("missing", "le") else None,
                    "instrument": key in INSTRUMENT_KEYS,  # never "use evidence #N": confirm the order's type instead
                    "waiver": ({"at": w.get("at"), "reason": w.get("reason")} if w is not None else None)})
    return out


def counts(items: list[dict]) -> dict:
    out = dict.fromkeys(STATE_LABELS, 0)
    for i in items:
        out[i["state"]] += 1
    out["open"] = out["missing"] + out["le"] + out["unusable"]
    return out


class WaiverError(ValueError):
    pass


def waive(db: Session, case: Case, key: str, *, user: Any, reason: str) -> dict:
    """Record that `key` is not needed for this case (a case admin's reason). The caller audits."""
    from app.domain.playbook import EVIDENCE

    reason = " ".join((reason or "").split())[:300]
    if key not in EVIDENCE:
        raise WaiverError("unknown requirement")
    if not reason:
        raise WaiverError("a waiver needs a reason")
    facts = dict(case.facts or {})
    w = dict(waivers(case))
    w[key] = {"at": datetime.now(tz=UTC).isoformat(timespec="seconds"), "by": getattr(user, "id", None),
              "reason": reason}
    facts[WAIVER_KEY] = w
    case.facts = facts
    db.commit()
    return w[key]


def use_item(db: Session, access, key: str, item_id: int) -> EvidenceItem:
    """A case admin marks evidence #item_id as satisfying requirement `key`: the key becomes one of the item's tags (an
    explicit match from then on). WaiverError on an unknown requirement or an item this member may not see. The caller
    audits (the item id and the key only)."""
    from app.domain.playbook import EVIDENCE

    case = access.case
    if key not in EVIDENCE or key in LETTER:
        raise WaiverError("unknown requirement")
    if key in INSTRUMENT_KEYS:  # an order LE / counsel supplies opens a provider's binding path: never by one field
        raise WaiverError("an order or LE instrument is never matched by an item number: open the item and confirm "
                          "its type (with the court / agency and the provider it names) on the Evidence tab")
    item = next((e for e in case.evidence_items if e.id == item_id), None)
    if item is None or not ev.can_see(access, item):
        raise WaiverError("no such evidence item on this case")
    item.tags = ev.parse_tags([*(item.tags or []), key])
    db.commit()
    return item


def unwaive(db: Session, case: Case, key: str) -> bool:
    w = dict(waivers(case))
    if w.pop(key, None) is None:
        return False
    facts = dict(case.facts or {})
    facts[WAIVER_KEY] = w
    case.facts = facts
    db.commit()
    return True
