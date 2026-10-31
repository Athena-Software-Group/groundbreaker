"""Evidence intel: read an item's text, understand what it is, propose its folder and the requirements it satisfies.

    iv = read_item(db, item, actor=access)          # text -> vault, rules (+ AI when the case consents) -> meta.intel
    confirm(db, access, item, "police_report")      # a person confirms (or picks another type): tag, folder, keys
    pick_role(db, access, item, "0x…", "perpetrator")  # a person picks a wallet's role: only then watch / seed it
    view(db, access, item)                          # the item page's panel: reading, findings, one-click proposals
    queue(access) / reread_all(db, access)          # the Evidence tab's "Unclassified / suggested" list, the backfill

**Where things live.** An upload's extracted text goes to the evidence vault next to the uploads, as
`<vault>/text/<case id>/<item sha256>.txt` (sha256-linked: the file is named by the item's bytes and its own hash is
recorded), never into the database. A referenced original is never copied, its text neither: it is read again from
the original when the item page shows it; an inline note is its own text. `evidence_items.meta["intel"]` keeps the reading: the text's kind / status /
note / size, a short excerpt (`EXCERPT_CHARS`), the rules' reading (app.evidence_intel.rules), the AI reading's type /
verified / confidence / model (app.evidence_intel.ai, advisory; its quote, summary, parties, dates, amounts and
identifiers go to a vault sidecar, `store_ai_detail`; for a referenced original they are not kept), the chain identifiers, references, dates, amounts and providers found
(never an officer's name, e-mail or phone: those are read again from the vault text when the page shows them) and,
once a person confirmed it, `confirmed` {type, keys, by, at, source}, and the wallet roles a person picked,
`wallet_roles` {address (lower case): {role, by, at}}.

**Nothing a heuristic says is applied by itself.** Reading changes no folder, tag or requirement: the rules' (and a
verified AI reading's) type is a suggestion, shown with its reasons; the evidence checklist shows it as "suggested:
police report — confirm", never "on file" (evidence_requirements.check). Confirming it adds the type as a tag (an
order's tag opens the instrument gate: evidence_requirements.held_instruments), records the requirement keys as
explicit matches and, when asked, files the item in the type's folder (the Financial folder needs a case admin).
A wallet the document names has no role until a person picks one (victim / perpetrator / exchange or service /
unknown; `WALLET_ROLES`): the text only gives a hint, the cue words next to it (findings.address_hint), and "Watch"
and "Seed the trace" stay disabled until the pick (audited by the route). A re-read keeps the confirmation and the
picks.

**A provider's reply.** The reply classifier (app.blocks.classify_rules) reads what a document naming a provider or a
ticket states (`reply_outcome`: status, amount / asset, their ticket; kept as meta.intel.reply). The item page
suggests the request it answers (`reply_orders`: the provider named, the wallets both cite, a sent letter) and
proposes the ticket and the reply's date; a person picks the request and files it (`link_reply`), which records the
type as a provider's reply and takes it off the "Unclassified / suggested" list. The outcome it states stays a
suggestion on Block status until a person confirms it there.
"""

from __future__ import annotations

import hashlib
import os
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import (
    Case,
    Correspondence,
    EvidenceFolder,
    EvidenceItem,
    EvidenceStorage,
    FreezeWatch,
    SeedRole,
)
from app.domain import evidence as ev
from app.evidence_intel import ai, findings
from app.evidence_intel import rules as R
from app.evidence_intel.text import MAX_READ_BYTES, Text, extract_text

VERSION = 1
EXCERPT_CHARS = 280
MAX_REREAD = 500
MAX_AI_PER_RUN = 25
LINK_BODY_CHARS = 20_000
SKIP_QUEUE_TAGS = frozenset({"received-email", "sent-email"})  # the mailbox's own messages: read by Block status
MAILBOX_TAGS = SKIP_QUEUE_TAGS | {"email-attachment"}  # never sent to the AI here ("AI reads mailbox replies" decides)
TEXT_LITE = frozenset({"kind", "status", "note", "pages", "chars", "truncated", "stored"})  # no excerpt, path or hash
STATUS_LABELS = {"unread": "not read yet", "suggested": "suggested", "unclassified": "unclassified",
                 "confirmed": "confirmed"}


def intel(item: EvidenceItem) -> dict:
    v = (item.meta or {}).get("intel")
    return dict(v) if isinstance(v, dict) else {}


def status(item: EvidenceItem) -> str:
    iv = intel(item)
    if not iv:
        return "unread"
    if iv.get("confirmed"):
        return "confirmed"
    return "suggested" if (iv.get("rules") or {}).get("type", "other") != "other" or (iv.get("ai") or {}).get(
        "verified") else "unclassified"


def confirmed_keys(item: EvidenceItem) -> set[str]:
    return set((intel(item).get("confirmed") or {}).get("keys") or [])


def suggestions(item: EvidenceItem) -> dict[str, str]:
    """{requirement key: the suggested type} of an unconfirmed reading: the keys the rules' type (and a verified AI
    reading's type) would count for once a person confirms it. A suggestion satisfies nothing by itself: the
    checklist shows it as "suggested: … — confirm"."""
    iv = intel(item)
    if not iv or iv.get("confirmed"):
        return {}
    out: dict[str, str] = {}
    a = iv.get("ai") or {}
    for t in ((iv.get("rules") or {}).get("type"), a.get("type") if a.get("verified") else None):
        dt = R.type_of(t)
        for k in dt.keys if dt is not None and t != "other" else ():
            out.setdefault(k, t)
    return out


def suggested_keys(item: EvidenceItem) -> set[str]:
    """The requirement keys an unconfirmed reading suggests (suggestions): never applied until confirmed."""
    return set(suggestions(item))


def _name(item: EvidenceItem) -> str:
    m = item.meta or {}
    return " · ".join(str(v) for v in (item.title, m.get("original_filename"), m.get("mapping_rule"), item.source_type)
                      if v)


def _file_name(item: EvidenceItem) -> str:
    m = item.meta or {}
    if m.get("original_filename"):
        return str(m["original_filename"])
    if item.source_path:
        return ev.parse_reference(item.source_path).display_name
    return str(m.get("demo_file") or item.title or "")


# --------------------------------------------------------------------------- the vault copy of the text
def _vault() -> Path | None:
    try:
        return ev.vault_dir()
    except ev.EvidenceError:
        return None


def store_text(item: EvidenceItem, text: str) -> dict | None:
    """Write the text to <vault>/text/<case>/<item sha256>.txt (0600, atomically). None when no vault is set."""
    root = _vault()
    if root is None or not text:
        return None
    raw = text.encode("utf-8")
    sha = hashlib.sha256(raw).hexdigest()
    d = root / "text" / str(item.case_id)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = f"{item.sha256 or sha}.txt"
    final, tmp = d / name, d / f"{name}.{os.getpid()}.part"
    try:
        with open(tmp, "wb") as out:
            os.chmod(tmp, 0o600)
            out.write(raw)
        os.replace(tmp, final)
    finally:
        if tmp.exists():
            tmp.unlink()
    return {"path": f"text/{item.case_id}/{name}", "sha256": sha}


AI_DETAIL = ("quote", "summary", "parties", "dates", "amounts", "identifiers")  # vault sidecar only, never the DB


def _vault_file(rel: str | None) -> Path | None:
    root = _vault()
    if root is None or not rel:
        return None
    p = (root / rel).resolve()
    return p if p.is_relative_to(root) and p.is_file() else None


def store_ai_detail(item: EvidenceItem, text_sha: str, detail: dict) -> dict | None:
    """The AI reading's quote, summary, parties, dates, amounts and identifiers (document content) as a vault sidecar
    <vault>/text/<case>/<text sha256>.ai.json (0600), sha256-linked from meta.intel.ai. None when no vault is set."""
    import json

    root = _vault()
    if root is None or not detail:
        return None
    raw = json.dumps(detail, ensure_ascii=False, sort_keys=True).encode("utf-8")
    d = root / "text" / str(item.case_id)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = f"{text_sha}.ai.json"
    final, tmp = d / name, d / f"{name}.{os.getpid()}.part"
    try:
        with open(tmp, "wb") as out:
            os.chmod(tmp, 0o600)
            out.write(raw)
        os.replace(tmp, final)
    finally:
        if tmp.exists():
            tmp.unlink()
    return {"path": f"text/{item.case_id}/{name}", "sha256": hashlib.sha256(raw).hexdigest()}


def ai_reading(item: EvidenceItem, deep: bool = True) -> dict | None:
    """The stored AI reading (type, label, verified, confidence, model) and, for `deep` viewers, its detail read back
    from the vault sidecar when its hash still matches."""
    import json

    a = dict(intel(item).get("ai") or {})
    if not a:
        return None
    side = a.pop("detail", None) or {}
    p = _vault_file(side.get("path")) if deep else None
    if p is not None:
        raw = p.read_bytes()
        if hashlib.sha256(raw).hexdigest() == side.get("sha256"):
            try:
                a.update({k: v for k, v in json.loads(raw).items() if k in AI_DETAIL})
            except ValueError:
                pass
    return a


def load_text(item: EvidenceItem) -> str | None:
    """The item's extracted text: its inline text, a reference's original read again (never copied), or an upload's
    vault copy when its recorded hash still matches."""
    if item.storage == EvidenceStorage.INLINE:
        return item.inline_text
    if item.storage == EvidenceStorage.REFERENCE:
        t = _read(item)
        return t.text or None
    t = intel(item).get("text") or {}
    root = _vault()
    if root is None or not t.get("path") or not t.get("sha256"):
        return None
    p = (root / t["path"]).resolve()
    if not p.is_relative_to(root) or not p.is_file():
        return None
    raw = p.read_bytes()
    return raw.decode("utf-8", errors="replace") if hashlib.sha256(raw).hexdigest() == t["sha256"] else None


# --------------------------------------------------------------------------- reading
def _read(item: EvidenceItem) -> Text:
    if item.storage == EvidenceStorage.INLINE:
        return extract_text((item.inline_text or "").encode("utf-8"), name=_file_name(item) or "note.txt",
                            mime="text/plain")
    if (item.size_bytes or 0) > MAX_READ_BYTES:
        return Text("unsupported", "too_large", note=f"larger than the read limit ({MAX_READ_BYTES >> 20} MB)")
    try:
        data = ev.read_verified(item, limit=MAX_READ_BYTES + 1)  # hashes it all, keeps a bounded prefix
    except ev.IntegrityError:
        return Text("unsupported", "error", note="integrity mismatch: the bytes no longer match the recorded sha256")
    except (OSError, ev.EvidenceError, zipfile.BadZipFile, KeyError):
        return Text("unsupported", "error", note="the original could not be read")
    if len(data) > MAX_READ_BYTES:
        return Text("unsupported", "too_large", note=f"larger than the read limit ({MAX_READ_BYTES >> 20} MB)")
    return extract_text(data, name=_file_name(item), mime=item.mime)


def _catalogue_orgs() -> tuple:
    from app.domain import directory

    try:
        return directory.load_catalogue().orgs
    except Exception:  # noqa: BLE001 - an invalid catalogue: no providers named
        return ()


def known_values(db: Session, case: Case) -> set[str]:
    """The case's own chain identifiers (seeds, the latest trace, stop orders) and its watched wallets."""
    from app.ai.context import _chain_values

    out = _chain_values(db, case)
    out |= {a.lower() for a in db.scalars(select(FreezeWatch.address).where(FreezeWatch.case_id == case.id,
                                                                           FreezeWatch.active.is_(True)))}
    return out


def _find(db: Session, case: Case, text: str) -> dict:
    return findings.find(text, known=known_values(db, case), orgs=_catalogue_orgs(),
                         exclude_refs=[case.reference, *ev.known_references(case)])


# the reply classifier's statuses that mark a document as a provider's answer (an "information requested" reads in an
# LE letter's requests too: not counted)
REPLY_SIGNALS = frozenset({"frozen", "hold_placed", "funds_returned", "declined_no_assets", "le_process_required",
                           "declined_other", "redirected", "acknowledged"})


def reply_outcome(case: Case, text: str | None, f: dict) -> dict | None:
    """What the document says as a provider's reply, read by the reply classifier (app.blocks.classify_rules): its
    status, the amount / asset of that statement and the provider's ticket; None when it states nothing a reply
    would. Only a proposal: filed as the reply to a request, Block status shows it as a suggestion a person confirms
    (a positive outcome is never applied by itself). Read only for a text that names a provider or a ticket."""
    if not text or not (f.get("providers") or f.get("tickets")):
        return None
    from app.blocks import classify_rules as cr

    try:
        r = cr.classify(text, exclude_refs={x.lower() for x in (case.reference, *ev.known_references(case)) if x})
    except Exception:  # noqa: BLE001 - advisory: an odd document never breaks the reading
        return None
    ticket = next(iter(f.get("tickets") or []), None) or r.ticket
    if r.status not in REPLY_SIGNALS and not ticket:
        return None
    out = {"ticket": ticket}
    if r.status in REPLY_SIGNALS:
        out.update(status=r.status, label=cr.LABELS.get(r.status, r.status), amount=r.amount, asset=r.asset,
                   positive=r.status in cr.POSITIVE)
    return out


def _case_link(case: Case, text: str, f: dict) -> bool:
    """The document cites the case: a wallet / transaction the case holds, or the case's reference."""
    if any(i.get("known") for i in f.get("identifiers") or []):
        return True
    return bool(case.reference) and case.reference.lower() in text.lower()


def read_item(db: Session, item: EvidenceItem, *, actor: Any = None, use_ai: bool = True, provider: Any = None,
              text: Text | None = None) -> dict:
    """Read the item (module doc) and store the reading in meta.intel. Never raises on unreadable content; commits
    nothing itself (an AI call's audit row commits). The AI is asked only when the case consents and it has not read
    this very text already."""
    return _read_item(db, item, actor=actor, use_ai=use_ai, provider=provider, text=text)[0]


def _read_item(db: Session, item: EvidenceItem, *, actor: Any, use_ai: bool, provider: Any,
               text: Text | None) -> tuple[dict, bool]:
    case = item.case
    t = text if text is not None else _read(item)
    f = _find(db, case, t.text) if t.text else findings.find("")
    n_ids = sum(1 for i in f["identifiers"] if i["kind"] in ("address", "tx"))
    reply = reply_outcome(case, t.text, f)
    reading = R.classify(t.text, name=_name(item), kind=t.kind, folder=item.folder, identifiers=n_ids,
                         provider_named=bool(f["providers"]), ticket=bool((reply or {}).get("ticket")),
                         case_link=bool(t.text) and _case_link(case, t.text, f),
                         reply_status=(reply or {}).get("label", "").lower() or None)
    vault = store_text(item, t.text) if t.text and item.storage == EvidenceStorage.VAULT else None
    prev = intel(item)
    excerpt = " ".join(t.text.split())[:EXCERPT_CHARS]
    tinfo = {"kind": t.kind, "status": t.status, "note": t.note, "pages": t.pages, "chars": len(t.text),
             "truncated": t.truncated, "excerpt": excerpt or None, "stored": {EvidenceStorage.INLINE: "inline",
             EvidenceStorage.REFERENCE: "original"}.get(item.storage, "vault" if vault else None), **(vault or {}),
             "attachments": len(t.meta.get("attachments") or [])}
    iv = {"version": VERSION, "at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
          "by": getattr(getattr(actor, "user", actor), "id", None), "source_sha256": item.sha256, "text": tinfo,
          "rules": reading, "findings": findings.stored(f), "reply": reply, "confirmed": prev.get("confirmed"),
          "wallet_roles": prev.get("wallet_roles") or {}}
    text_sha = tinfo.get("sha256") or hashlib.sha256(t.text.encode()).hexdigest()
    old_ai = prev.get("ai") or {}
    if old_ai and old_ai.get("text_sha256") == text_sha:
        iv["ai"] = old_ai
    item.meta = {**(item.meta or {}), "intel": iv}
    db.flush()
    called = False
    mailbox = bool({str(x).lower() for x in item.tags or []} & MAILBOX_TAGS)
    if use_ai and ai.is_enabled(case) and t.text.strip() and not iv.get("ai") and not mailbox:
        called = True
        res, why = ai.classify_document(db, case, item, t.text, actor=actor, provider=provider)
        iv = dict(intel(item))
        called = why not in ai.SKIPPED
        if res is not None:
            detail = {k: res.pop(k) for k in AI_DETAIL if k in res}
            # a referenced original is never copied: its AI quote / parties / identifiers are not kept either
            iv["ai"] = {**res, "text_sha256": text_sha, "detail": None if item.storage == EvidenceStorage.REFERENCE
                        else store_ai_detail(item, text_sha, detail)}
            iv.pop("ai_skipped", None)
        else:
            iv["ai_skipped"] = why
        item.meta = {**(item.meta or {}), "intel": iv}
        db.flush()
    return intel(item), called


def summary_line(item: EvidenceItem) -> str | None:
    """"Aegis read this as: Police report → Law enforcement (text: “denuncia”, …)" (PII-free: lexicon cues only)."""
    iv = intel(item)
    r = iv.get("rules") or {}
    t = iv.get("text") or {}
    if not iv:
        return None
    head = ""
    if t.get("status") == "image":
        head = "No text (image): describe it or attach a text version. "
    elif t.get("status") not in ("ok", None):
        head = f"{(t.get('note') or 'no text read').rstrip('.')}. "
    if r.get("type", "other") == "other":
        return head + "Aegis could not tell what this document is: pick its type on the item page."
    folder = ev.folder_label(r["folder"])
    rp = iv.get("reply") or {}
    if r["type"] == "provider_reply" and (rp.get("label") or rp.get("ticket")):
        states = (rp["label"] + (" " + " ".join(x for x in (rp.get("amount"), rp.get("asset")) if x)
                                 if rp.get("amount") else "")) if rp.get("label") else ""
        tk = f"ticket {rp['ticket']}" if rp.get("ticket") else ""
        return (head + f"Aegis read this as a provider's reply ({'; '.join(x for x in (states, tk) if x)}): "
                "“Review the reply” to file it with your request.")
    return (head + f"Aegis read this as: {r['label']} → {folder} ({', '.join(r.get('reasons')[:3])}): confirm or "
            "change it on the item page.")


# --------------------------------------------------------------------------- confirming
class IntelError(ValueError):
    pass


def confirm(db: Session, access, item: EvidenceItem, doc_type: str, *, move: bool = True,
            jurisdiction: str | None = None, to: str | None = None, doc_date: str | None = None) -> list[str]:
    """A person confirms the item's type (module doc). Returns the changed fields (for the audit). IntelError on an
    unknown type."""
    dt = R.type_of(doc_type)
    if dt is None:
        raise IntelError("unknown document type")
    iv = intel(item)
    prev = iv.get("confirmed") or {}
    changed: list[str] = []
    tags = [t for t in item.tags or [] if not (prev.get("tag") and t == prev["tag"] and t != doc_type)]
    if doc_type != "other" and doc_type not in tags:
        tags.append(doc_type)
    if tags != list(item.tags or []):
        item.tags = ev.parse_tags(tags)
        changed.append("tags")
    note = None
    rules_r = iv.get("rules") or {}
    target = dt.folder if doc_type != "other" else (EvidenceFolder(rules_r["folder"]) if rules_r.get("type") == "other"
                                                    and rules_r.get("folder") else None)
    if move and target is not None and target != EvidenceFolder.OTHER and target != item.folder:
        if target == EvidenceFolder.FINANCIAL and not ev.allowed(access, "view_financial"):
            note = "financial_admin"
        else:
            item.folder = target
            changed.append("folder")
            meta = dict(item.meta or {})
            section = dt.section if doc_type != "other" else rules_r.get("section")
            if section:
                meta["section"] = section
            else:
                meta.pop("section", None)
            item.meta = meta
    meta = dict(item.meta or {})
    if dt.order:
        from app.domain.playbook import jurisdiction_code

        j = jurisdiction_code((jurisdiction or "").strip())
        if j and meta.get("jurisdiction") != j:
            meta["jurisdiction"] = j
            changed.append("jurisdiction")
        to = " ".join((to or "").split())[:255]
        if to and meta.get("to") != to:
            meta["to"] = to
            changed.append("addressed_to")
    if doc_date and not item.doc_date:
        try:
            item.doc_date = ev._parse_date(doc_date)
            changed.append("doc_date")
        except ev.EvidenceError:
            pass
    src = "rules" if doc_type == rules_r.get("type") else "ai" if doc_type == (iv.get("ai") or {}).get("type") else "person"
    iv["confirmed"] = {"type": doc_type, "label": dt.label, "keys": list(dt.keys), "tag": doc_type if doc_type != "other"
                       else None, "by": getattr(getattr(access, "user", None), "id", None),
                       "at": datetime.now(tz=UTC).isoformat(timespec="seconds"), "source": src}
    meta["intel"] = iv
    item.meta = meta
    changed.append("type")
    db.flush()
    return changed + ([note] if note else [])


WALLET_ROLES = {"victim": "the victim's wallet", "perpetrator": "the perpetrator's wallet",
                "service": "an exchange / service", "unknown": "unknown (someone else's)"}


def wallet_roles(item: EvidenceItem) -> dict[str, dict]:
    raw = intel(item).get("wallet_roles")
    return {k: v for k, v in raw.items() if isinstance(v, dict) and v.get("role") in WALLET_ROLES} if isinstance(
        raw, dict) else {}


def pick_role(db: Session, access, item: EvidenceItem, value: str, role: str) -> dict:
    """A person picks the role of a wallet the item names (WALLET_ROLES; "" clears the pick). Only then are "Watch"
    and "Seed the trace" offered for it. IntelError on an unknown role or a wallet the item's reading does not name.
    The caller audits (commits)."""
    value = (value or "").strip()
    if role and role not in WALLET_ROLES:
        raise IntelError("unknown wallet role")
    named = {str(i.get("value") or "").lower() for i in (intel(item).get("findings") or {}).get("identifiers") or []
             if i.get("kind") == "address"}
    if not value or value.lower() not in named:
        raise IntelError("this item does not name that wallet")
    iv = intel(item)
    picks = dict(wallet_roles(item))
    if role:
        picks[value.lower()] = {"role": role, "by": getattr(getattr(access, "user", None), "id", None),
                                "at": datetime.now(tz=UTC).isoformat(timespec="seconds")}
    else:
        picks.pop(value.lower(), None)
    iv["wallet_roles"] = picks
    item.meta = {**(item.meta or {}), "intel": iv}
    db.flush()
    return picks.get(value.lower()) or {}


# --------------------------------------------------------------------------- the tab and the item page
def _queued(item: EvidenceItem, filed: set[int] = frozenset()) -> bool:
    if {str(t).lower() for t in item.tags or []} & SKIP_QUEUE_TAGS or (item.meta or {}).get("trace_run_id"):
        return False
    return status(item) != "confirmed" and item.id not in filed


def _filed(case: Case) -> set[int]:
    """The items filed as an inbound reply (a person linked them): their type is settled by that filing. A letter
    we sent citing an item (an authority document attached) settles nothing."""
    out: set[int] = set()
    for c in case.correspondence:
        if c.evidence_item_id and getattr(c.direction, "value", c.direction) == "in":
            out.add(c.evidence_item_id)
    return out


def queue(access) -> list[dict]:
    """The visible items still to classify: never read, suggested or unclassified (newest first); never one a person
    filed as a reply."""
    out = []
    filed = _filed(access.case)
    for e in ev.visible_items(access):
        if not _queued(e, filed):
            continue
        iv = intel(e)
        r = iv.get("rules") or {}
        a = iv.get("ai") or {}
        out.append({"item": e, "status": status(e), "status_label": STATUS_LABELS[status(e)], "rules": r or None,
                    "reply": iv.get("reply") if r.get("type") == "provider_reply" else None,
                    "ai": a if a.get("verified") else None, "text": iv.get("text") or {},
                    "folder_label": ev.folder_label(r["folder"]) if r.get("folder") else None,
                    "moves": bool(r.get("folder")) and r.get("folder") != e.folder.value and r.get("type") != "other",
                    "disagree": bool(a.get("verified") and r and a.get("type") != r.get("type"))})
    return out


def type_choices() -> list[tuple[str, str]]:
    return [(k, t.label) for k, t in R.DOC_TYPES.items()]


def tab_view(db: Session, access) -> dict:
    q = queue(access)
    st = ai.setting(access.case)
    from app.blocks.classify_ai import destination

    try:
        dest = destination()
    except Exception:  # noqa: BLE001 - no provider configuration: shown as none
        dest = {"provider": "none", "label": "none", "model": None, "host": None}
    read = [x for x in q if x["status"] != "unread"]
    unread = [x for x in q if x["status"] == "unread"]
    return {"queue": read[:40], "queue_count": len(q), "read_count": len(read), "unread": len(unread),
            "unread_items": [x["item"] for x in unread[:40]],
            "types": type_choices(), "ai": st, "ai_enabled": bool(st.get("enabled")), "dest": dest,
            "can_reread": ev.allowed(access, "delete_evidence"), "can_confirm": ev.allowed(access, "add_evidence"),
            "can_manage_ai": access.can("manage_case")}


def _seed_roles(case: Case) -> set[str]:
    return {s.role.value for s in case.seeds}


def _names_entity(ent: str | None, names: list[str]) -> bool:
    return bool(ent) and any(re.search(rf"(?<![A-Za-z0-9]){re.escape(n)}(?![A-Za-z0-9])", ent, re.IGNORECASE)
                             or re.search(rf"(?<![A-Za-z0-9]){re.escape(ent)}(?![A-Za-z0-9])", n, re.IGNORECASE)
                             for n in names)


def _short(v: str) -> str:
    return v if len(v) <= 14 else f"{v[:6]}…{v[-4:]}"


def reply_orders(case: Case, f: dict) -> list[dict]:
    """The case's stop orders the document may answer, best first: one to a provider it names, or one citing a
    wallet / transaction it names. Ranked by the provider named, the wallets both cite, the provider's ticket
    already on the order, a letter that was sent, then the newest. The first is only the suggestion: a person picks
    the request and files the reply (nothing is linked by itself)."""
    import json

    names = [p["name"] for p in f.get("providers") or []]
    ids = {str(i.get("value") or "").lower() for i in f.get("identifiers") or [] if i.get("value")}
    tickets = {str(t).lower() for t in f.get("tickets") or []}
    rows = []
    for o in case.stop_orders:
        if getattr(o.status, "value", o.status) == "superseded":  # replaced by a later letter: never the one answered
            continue
        ent = o.entity.name if o.entity is not None else None
        named = _names_entity(ent, names)
        hay = f"{o.body_markdown or ''}\n{json.dumps(o.identifiers or {})}".lower()
        cited = sorted(v for v in ids if v in hay)
        ticket = bool(o.external_ref) and o.external_ref.lower() in tickets
        if not (named or cited):
            continue
        why = ([f"to {ent}, which it names"] if named else []) + (
            [f"cites {', '.join(_short(v) for v in cited[:2])}" + (" …" if len(cited) > 2 else "")] if cited else []) + (
            ["their ticket is on it"] if ticket else []) + ([f"sent {o.sent_at:%d %b %Y}"] if o.sent_at else ["not sent"])
        score = 4 * named + 3 * bool(cited) + 2 * ticket + bool(o.sent_at)
        rows.append((score, o.id, {"id": o.id, "entity": ent, "kind": o.kind, "sent": bool(o.sent_at), "why": why}))
    rows.sort(key=lambda r: (-r[0], -r[1]))
    out = [r[2] for r in rows[:5]]
    if out:
        out[0]["suggested"] = True
    return out


def view(db: Session, access, item: EvidenceItem) -> dict:
    """The item page's panel. Findings, the excerpt and the proposals need the item's content (can_open) and
    view_restricted; other members see the reading only."""
    iv = intel(item)
    deep = ev.can_open(access, item) and ev.allowed(access, "view_restricted") and not access.is_external
    out: dict[str, Any] = {"status": status(item), "status_label": STATUS_LABELS[status(item)], "rules": iv.get("rules"),
                           "ai": ai_reading(item, deep), "ai_skipped": iv.get("ai_skipped"),
                           "confirmed": iv.get("confirmed"),
                           "text": {k: v for k, v in (iv.get("text") or {}).items() if deep or k in TEXT_LITE},
                           "at": iv.get("at"), "types": type_choices(), "deep": deep, "proposals": [],
                           "can_confirm": ev.allowed(access, "add_evidence"), "read": bool(iv),
                           "ai_reason": ai.REASON_TEXT.get(iv.get("ai_skipped") or "", None),
                           "order_types": sorted(R.ORDER_TYPES), "wallet_roles": list(WALLET_ROLES.items())}
    if out["rules"]:
        out["rules_folder_label"] = ev.folder_label(out["rules"]["folder"])
    if not deep or not iv:
        return out
    text = load_text(item)
    f = _find(db, access.case, text) if text else {**(iv.get("findings") or {}), "contacts": []}
    out["findings"] = f
    case = access.case
    watched = {(w.chain, w.address.lower()) for w in db.scalars(select(FreezeWatch).where(
        FreezeWatch.case_id == case.id, FreezeWatch.active.is_(True)))}
    roles = _seed_roles(case)  # each empty role is offered once, never a role that has a seed (the route refuses too)
    known = known_values(db, case)
    picks = wallet_roles(item)
    props = []
    for i in f.get("identifiers") or []:
        v, chain = i["value"], i.get("chain")
        if i.get("known") or v.lower() in known:
            continue
        p = {"kind": i["kind"], "chain": chain, "value": v,
             "watched": any(w[1] == v.lower() for w in watched)}
        if i["kind"] == "tx" and SeedRole.ORIGIN_TX.value not in roles:
            p["seed_role"] = SeedRole.ORIGIN_TX.value
        elif i["kind"] == "address" and chain:
            # no role until a person picks one: the text only hints (the cue words next to it); nothing is watched
            # or seeded before the pick
            role = (picks.get(v.lower()) or {}).get("role")
            p.update(role=role, role_label=WALLET_ROLES.get(role or ""), hint=findings.address_hint(text, v),
                     can_pick=access.can("edit"), seedable=True)
            p["watchable"] = chain in ("evm", "tron") and access.can("edit") and not p["watched"]
            p["watch"] = p["watchable"] and role in ("perpetrator", "service", "unknown")  # never the victim's own
            want = ((SeedRole.VICTIM_WALLET,) if role == "victim" else
                    (SeedRole.PERPETRATOR_WALLET, SeedRole.KNOWN_DOWNSTREAM) if role == "perpetrator" else
                    (SeedRole.KNOWN_DOWNSTREAM,) if role in ("service", "unknown") else ())
            p["seed_role"] = next((r.value for r in want if r.value not in roles), None)
        if p.get("seed_role"):
            roles = roles | {p["seed_role"]}
        props.append(p)
    out["ids"] = props[:24]
    have_refs = {r.lower() for r in ev.known_references(case)}
    contacts = []
    for c in f.get("contacts") or f.get("refs") or []:
        ref = c.get("reference")
        if ref and ref.lower() in have_refs:
            continue
        authority = c.get("agency") or ("FBI IC3" if c.get("system") == "ic3" else None)
        contacts.append({**c, "authority": authority, "note": f"read from evidence #{item.id}"})
    out["contacts"] = contacts[:8]
    out["can_contact"] = ev.allowed(access, "manage_le_contacts")
    out["can_trace"] = access.can("run_trace") if hasattr(access, "can") else False
    linked = db.scalar(select(Correspondence.id).where(Correspondence.case_id == case.id,
                                                       Correspondence.evidence_item_id == item.id))
    out["linked_corr"] = linked
    out["known_ids"] = [{"kind": i["kind"], "chain": i.get("chain"), "value": i["value"]}
                        for i in f.get("identifiers") or [] if i.get("known") or str(i["value"]).lower() in known][:8]
    out["orders"] = [] if linked else reply_orders(case, f)
    out["can_link"] = access.can("log_correspondence")
    out["providers"] = f.get("providers") or []
    shown = (out.get("confirmed") or {}).get("type") or (out.get("rules") or {}).get("type")
    is_reply = shown == "provider_reply" or ((out.get("ai") or {}).get("verified")
                                             and (out["ai"] or {}).get("type") == "provider_reply")
    # what the reply states (the reply classifier): a proposal shown with the link, applied by nobody but a person
    out["reply"] = (reply_outcome(case, text, f) if text else iv.get("reply")) if is_reply or out["orders"] else None
    jur = None
    if text and (out.get("confirmed") or out.get("rules") or {}).get("type") in R.ORDER_TYPES:
        from app.blocks.extract import jurisdictions

        js = [j for j in jurisdictions(text[:20_000]) if j != "EU"]
        jur = js[0] if len(js) == 1 else None
    out["jurisdiction_guess"] = (item.meta or {}).get("jurisdiction") or jur
    out["to_guess"] = (item.meta or {}).get("to") or ", ".join(p["name"] for p in out["providers"][:3])
    out["doc_date_guess"] = None if item.doc_date else f.get("doc_date")
    return out


# --------------------------------------------------------------------------- one-click actions
def add_complaint(db: Session, case: Case, item: EvidenceItem, *, authority: str, reference: str) -> dict:
    """Record a complaint reference read from the item in case.facts["complaints"] (the caller audits, commits)."""
    authority = " ".join((authority or "").split())[:255]
    reference = " ".join((reference or "").split())[:120]
    if not authority or not reference:
        raise IntelError("an authority and a reference are required")
    if reference.lower() in {r.lower() for r in ev.known_references(case)}:
        raise IntelError("that reference is already on the case")
    facts = dict(case.facts or {})
    rows = [c for c in facts.get("complaints") or [] if isinstance(c, dict)]
    row = {"authority": authority, "reference": reference, "evidence_item_id": item.id}
    if item.doc_date:
        row["filed_at"] = item.doc_date.date().isoformat()
    rows.append(row)
    facts["complaints"] = rows
    case.facts = facts
    db.flush()
    return row


def link_reply(db: Session, access, item: EvidenceItem, order_id: int, *, ticket: str | None = None,
               reply_date: str | None = None):
    """File the item as the provider's reply to stop order `order_id`: an inbound correspondence citing the item, its
    body the extracted text (so Block status reads it and suggests the outcome it states, for a person to confirm
    there: nothing is recorded as frozen here). A TLP:RED / AMBER+STRICT item's text is never copied (no
    correspondence body reaches the AI context or a classifier then): the reply is filed without it, for a person to
    review. `ticket`: the provider's ticket the person kept (the reply's external reference); `reply_date`
    (YYYY-MM-DD): the date the reply is dated, else the item's document date. A person filing it as the reply also
    tells its type: an item with no confirmed type is recorded as a provider's reply (source "link"), so it leaves
    the "Unclassified / suggested" list. The caller audits (commits)."""
    from app.ai.context import RESTRICTED_TLP
    from app.domain import correspondence as desk

    case = access.case
    order = next((o for o in case.stop_orders if o.id == order_id), None)
    if order is None:
        raise IntelError("no such stop order on this case")
    if db.scalar(select(Correspondence.id).where(Correspondence.evidence_item_id == item.id)):
        raise IntelError("this item is already filed as correspondence")
    authority = next((a for a in desk.case_authorities(db, case, include_prospects=False) if order in a.stop_orders),
                     None)
    if authority is None:
        raise IntelError("the stop order's counterparty was not found")
    restricted = (item.tlp or "").strip().upper() in RESTRICTED_TLP
    text = "" if restricted else (load_text(item) or "")[:LINK_BODY_CHARS]
    subject = f"Reply filed from evidence #{item.id}" + (" (TLP-restricted: text not copied)" if restricted else "")
    at = item.doc_date
    if reply_date and reply_date.strip():
        try:
            at = ev._parse_date(reply_date.strip())
        except ev.EvidenceError:
            raise IntelError("the reply date is not a date (YYYY-MM-DD)") from None
    ticket = " ".join((ticket or "").split())[:64] or None
    corr = desk.log_entry(db, case, authority, actor=access.user, direction="in", channel="other", kind="reply",
                          subject=subject, body=text or None, body_format="text",
                          occurred_at=at, stop_order=order, evidence_ids=[item.id], external_ref=ticket,
                          classification=item.classification.value if item.classification.value in ("R2", "R3", "C1",
                                                                                                     "I0") else "R2")
    if at is not None and item.doc_date is None:
        item.doc_date = at
    if not intel(item).get("confirmed") and ev.allowed(access, "add_evidence"):
        confirm(db, access, item, "provider_reply", move=True)
        iv = intel(item)
        iv["confirmed"] = {**iv["confirmed"], "source": "link"}
        item.meta = {**(item.meta or {}), "intel": iv}
        db.flush()
    return corr


def seed_pass(db: Session, case: Case) -> dict:
    """After a fixture is seeded (scripts/seed_case.py): verify each item whose bytes are readable and match the
    recorded sha256, and read each with the rules only (never the AI; nothing is moved, tagged or confirmed), so a
    fresh case does not open with every item "unverified" and "not read yet". An unreadable or mismatching original
    is left alone (a person's "Verify" reports it). Commits nothing."""
    counts = {"verified": 0, "read": 0}
    for e in list(case.evidence_items):
        if (e.meta or {}).get("trace_run_id"):
            continue
        try:
            actual, _size = ev.current_hash(e)
        except (OSError, ev.EvidenceError, zipfile.BadZipFile, KeyError):
            actual = None
        if actual and e.sha256 and actual == e.sha256:
            ev.verify_integrity(db, e)
            counts["verified"] += 1
        if not intel(e):
            _read_item(db, e, actor=None, use_ai=False, provider=None, text=None)
            counts["read"] += 1
    db.flush()
    return counts


def reread_all(db: Session, access, *, provider: Any = None) -> dict:
    """Read every visible item again (rules; the AI too when the case consents, at most MAX_AI_PER_RUN calls). Moves
    nothing. Returns the counts (for the audit and the message)."""
    counts = {"read": 0, "suggested": 0, "unclassified": 0, "no_text": 0, "errors": 0, "ai": 0}
    ai_left = MAX_AI_PER_RUN
    for e in ev.visible_items(access)[:MAX_REREAD]:
        if (e.meta or {}).get("trace_run_id"):
            continue
        iv, called = _read_item(db, e, actor=access, use_ai=ai_left > 0, provider=provider, text=None)
        if called:
            ai_left -= 1
            counts["ai"] += 1
        counts["read"] += 1
        st = (iv.get("text") or {}).get("status")
        if st == "error":
            counts["errors"] += 1
        elif st != "ok":
            counts["no_text"] += 1
        counts["suggested" if status(e) in ("suggested", "confirmed") else "unclassified"] += 1
    db.flush()
    return counts
