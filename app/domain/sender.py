"""Sender of record: who a case's new letters and e-mails come from (D9).

Owner: the mail feature (page: GET|POST /cases/{id}/sender-profile in app/web/routes_mail.py,
template sender_profile.html).

With a `sender_profiles` row, new letters are written as "<org_name>, on behalf of <on_behalf_of>" under
the victim's authority instrument (a Letter of Authorisation by default), and the profile's authority
documents are offered as e-mail attachments. Without one, letters keep the PI-firm block from
`case.facts["investigator"]` exactly as before (app.domain.correspondence.sender_profile). Imported
letters and existing drafts are never re-rendered.

The victim's name is never put in a mail header: the From header is the configured mailbox and its
display name (AEGIS_MAIL_FROM_NAME, default: the organisation name).

Default model (every case, `defaults` / `create_default_profile`): the deployment's organisation
(AEGIS_ORG_NAME, signed AEGIS_SIGNATORY_NAME, contact = the case mailbox) writes on behalf of the case's
client / victim, under the victim's Letter of Authorisation; the client's own contact e-mail, when known,
is the default Cc. A new case gets that profile when it is created (app.services.create_case);
`python -m scripts.ensure_sender_profiles` gives it to older cases that have none.

Nothing here audits except `audit_default_profile`, which the callers invoke (field names only).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, object_session

from app.core.config import get_settings
from app.db.models import Case, EvidenceItem, SenderProfile, User


def org_name() -> str:
    """The organisation new letters come from (AEGIS_ORG_NAME)."""
    return get_settings().aegis_org_name.strip() or "Your Organisation"


def signatory_name() -> str:
    """Who signs every case's letters by default (AEGIS_SIGNATORY_NAME)."""
    return get_settings().aegis_signatory_name.strip() or "Investigations Desk"


def __getattr__(name: str) -> str:  # sender.ORG_NAME / sender.SIGNATORY_NAME, read from the settings on each use
    if name == "ORG_NAME":
        return org_name()
    if name == "SIGNATORY_NAME":
        return signatory_name()
    raise AttributeError(name)


DEFAULT_INSTRUMENT = "Letter of Authorisation"
FIELDS = {  # form field -> max length (the column sizes)
    "org_name": 255, "on_behalf_of": 255, "signatory_name": 255, "signatory_title": 255, "contact_email": 255,
    "phone": 64, "postal_address": 512, "instrument": 128, "signature_block": 4000,
}
# what "sender of record" means (the sender profile page, the tooltip next to a mismatch warning)
SENDER_OF_RECORD_HELP = ("The sender of record is who a letter says it comes from: “<organisation>, on behalf of "
                         "<victim>”, acting under the victim's authority instrument. The e-mail goes out from the "
                         "case mailbox under the organisation's name, so the letter's opening and signature should "
                         "say the same. The case's sender profile sets it.")
MAX_AUTHORITY_DOCS = 10
MAX_CC = 5


class SenderError(ValueError):
    """A sender-profile value that is refused (HTTP 400)."""


class SenderForbidden(SenderError):
    """The member's role does not allow saving the profile (HTTP 403)."""


def get_profile(db: Session, case: Case) -> SenderProfile | None:
    return db.scalar(select(SenderProfile).where(SenderProfile.case_id == case.id))


def client_label(case: Case) -> str:
    """Who the letters are written for, as the opening reads best: "<entity> (<name>)" when the victim acts for an
    entity ("Northbridge Analytics, Inc. (Jordan Avery)"), else the victim's name."""
    name = " ".join((case.victim_name or "").split())
    entity = " ".join((case.victim_entity or "").split())
    if entity and name and entity.lower() != name.lower() and len(entity) + len(name) + 3 <= FIELDS["on_behalf_of"]:
        return f"{entity} ({name})"
    return (entity or name)[:FIELDS["on_behalf_of"]]


def defaults(case: Case, settings: Any = None, *, client_email: str | None = None,
             instrument: str | None = None) -> dict:
    """Starting values for a case's profile (the owner model, module doc): Athena Investigations writing as
    Athena Software Group, Inc. on behalf of the client, the case mailbox as contact (`settings.aegis_mail_from`,
    else AEGIS_MAIL_FROM), the client's contact e-mail as the default Cc."""
    mail_from = (getattr(settings, "aegis_mail_from", "") or "").strip().lower() if settings is not None else ""
    return {"org_name": org_name(), "on_behalf_of": client_label(case),
            "contact_email": mail_from or case_mailbox(), "instrument": instrument or DEFAULT_INSTRUMENT,
            "signatory_name": signatory_name(), "signatory_title": None, "phone": None, "postal_address": None,
            "signature_block": None, "authority_evidence_ids": [], "cc_default": [client_email] if client_email else []}


def clean_client_email(raw: str | None) -> str | None:
    """The client's contact e-mail as given when a case is opened (None when blank). Raises SenderError."""
    from app.domain.directory import DirectoryError, validate_address

    value = (raw or "").strip()
    if not value:
        return None
    try:
        return validate_address(value)
    except DirectoryError as e:
        raise SenderError(f"client contact e-mail: {e}") from None


def clean_instrument(raw: str | None) -> str:
    """The authority instrument given when a case is opened (default: a Letter of Authorisation). A Power of Attorney
    is set on the sender-profile page instead, where it must be confirmed as literally the instrument on file."""
    value = _text({"instrument": raw}, "instrument") or DEFAULT_INSTRUMENT
    if "power of attorney" in value.lower():
        raise SenderError("authority instrument: a Power of Attorney is set on the case's sender-profile page, where "
                          "it must be confirmed as literally the instrument on file")
    return value


def create_default_profile(db: Session, case: Case, *, client_email: str | None = None,
                           instrument: str | None = None, created_by: User | None = None,
                           settings: Any = None) -> SenderProfile | None:
    """Give `case` the owner model's profile (`defaults`) when it has none; never touches an existing one (returns
    None then, and when the case names no client / victim to write for). `client_email` / `instrument` are cleaned
    here (SenderError). Flushes; the caller commits and audits."""
    client_email = clean_client_email(client_email)
    instrument = clean_instrument(instrument)
    if get_profile(db, case) is not None:
        return None
    values = defaults(case, settings, client_email=client_email, instrument=instrument)
    if not values["on_behalf_of"]:
        return None
    row = SenderProfile(case_id=case.id, created_by=created_by.id if created_by else None,
                        updated_by=created_by.id if created_by else None, meta={"origin": "default"})
    for k in FIELDS:
        setattr(row, k, values[k])
    row.cc_default, row.authority_evidence_ids = list(values["cc_default"]), []
    db.add(row)
    db.flush()
    return row


def profile_fields(row: SenderProfile) -> list[str]:
    """The names of the fields a profile sets (an audit's `fields`: names only, never values)."""
    return sorted([k for k in FIELDS if getattr(row, k)] + [k for k in ("cc_default", "authority_evidence_ids")
                                                           if getattr(row, k)])


def audit_default_profile(db: Session, actor, case: Case, row: SenderProfile | None, *, source: str) -> None:
    """Audit (CREATE sender_profiles) the default profile `create_default_profile` gave `case` — field names and
    counts only; nothing when `row` is None. `source`: case_created | ensure_script. Commits (app.core.audit)."""
    from app.core.audit import CREATE, audit

    if row is not None:
        audit(db, actor, CREATE, case, row, fields=profile_fields(row), n_cc=len(row.cc_default or []),
              n_authority_docs=0, source=source)


def _text(values: dict, key: str) -> str | None:
    raw = values.get(key)
    if raw is None:
        return None
    s = str(raw).replace("\r\n", "\n").strip()
    if not s:
        return None
    if any(c in s for c in "\x00\r") or (key != "signature_block" and key != "postal_address" and "\n" in s):
        raise SenderError(f"{key.replace('_', ' ')}: line breaks are not allowed here")
    if len(s) > FIELDS[key]:
        raise SenderError(f"{key.replace('_', ' ')} is longer than {FIELDS[key]} characters")
    return s


def _ids(raw) -> list[int]:
    if raw is None:
        return []
    items = raw if isinstance(raw, (list, tuple)) else str(raw).replace(";", ",").split(",")
    out: list[int] = []
    for v in items:
        s = str(v).strip()
        if not s:
            continue
        if not s.isdigit():
            raise SenderError("authority documents: unknown evidence item")
        if int(s) not in out:
            out.append(int(s))
    return out


def authority_doc_problem(access, item: EvidenceItem | None) -> str | None:
    """Why an evidence item cannot be the profile's authority document (None = fine): same case,
    visible to this member, not TLP-blocked and with intact integrity (app.domain.mail_compose), and
    not correspondence ("correspondence": an e-mail Aegis sent or received, a file from one, or
    anything in Stop orders & correspondence — it would otherwise go to every authority)."""
    from app.domain import evidence as ev
    from app.domain import mail_compose

    if item is None or item.case_id != access.case.id or not ev.can_see(access, item):
        return "not_found"
    return mail_compose.static_block_reason(access, item) \
        or ("correspondence" if mail_compose.is_correspondence_item(item) else None)


def save_profile(db: Session, access, values: dict) -> tuple[SenderProfile, list[str]]:
    """Create or update the case's profile (case admins: manage_sender_profile). Returns the row and
    the names of the fields that changed. Raises SenderForbidden / SenderError; LookupError for an
    evidence id that is not this case's (the route answers 404, like get_case_object)."""
    from app.domain.directory import DirectoryError, validate_address

    if not access.can("manage_sender_profile"):
        raise SenderForbidden("only case admins may change the sender profile")
    clean: dict[str, Any] = {k: _text(values, k) for k in FIELDS}
    if not clean["on_behalf_of"]:
        raise SenderError("'on behalf of' is required (the victim the letters are written for)")
    clean["org_name"] = clean["org_name"] or org_name()
    clean["instrument"] = clean["instrument"] or DEFAULT_INSTRUMENT
    if "power of attorney" in clean["instrument"].lower() and str(values.get("instrument_is_poa") or "") != "1":
        raise SenderError("the instrument says 'Power of Attorney': tick the confirmation that this is literally the "
                          "instrument on file (letters must not call another instrument a Power of Attorney)")
    if clean["contact_email"]:
        try:
            clean["contact_email"] = validate_address(clean["contact_email"])
        except DirectoryError as e:
            raise SenderError(f"contact e-mail: {e}") from None
    cc: list[str] = []
    for raw in str(values.get("cc_default") or "").replace(";", ",").replace("\n", ",").split(","):
        if raw.strip():
            try:
                a = validate_address(raw)
            except DirectoryError as e:
                raise SenderError(f"default Cc: {e}") from None
            if a not in cc:
                cc.append(a)
    if len(cc) > MAX_CC:
        raise SenderError(f"at most {MAX_CC} default Cc addresses")
    ids = _ids(values.get("authority_evidence_ids"))
    if len(ids) > MAX_AUTHORITY_DOCS:
        raise SenderError(f"at most {MAX_AUTHORITY_DOCS} authority documents")
    for eid in ids:
        problem = authority_doc_problem(access, db.get(EvidenceItem, eid))
        if problem == "not_found":
            raise LookupError("evidence item not found")
        if problem:
            raise SenderError(f"evidence item #{eid} cannot be attached ({problem.replace('_', ' ')})")
    row = get_profile(db, access.case)
    if row is None:
        row = SenderProfile(case_id=access.case.id, created_by=access.user.id, meta={})
        db.add(row)
        changed = [k for k, v in clean.items() if v] + (["cc_default"] if cc else []) + (
            ["authority_evidence_ids"] if ids else [])
    else:
        changed = [k for k, v in clean.items() if getattr(row, k) != v]
        changed += [k for k, v in (("cc_default", cc), ("authority_evidence_ids", ids)) if list(getattr(row, k) or []) != v]
    for k, v in clean.items():
        setattr(row, k, v)
    row.cc_default, row.authority_evidence_ids = cc, ids
    row.updated_by = access.user.id
    meta = dict(row.meta or {})
    if "power of attorney" in clean["instrument"].lower():
        meta["instrument_is_poa_confirmed_by"] = access.user.id
    else:
        meta.pop("instrument_is_poa_confirmed_by", None)
    row.meta = meta
    db.flush()
    return row, changed


def requester_kind(db: Session | None, case: Case) -> str:
    """Who the case's letters come from, in the playbook's requester terms (app.domain.playbook.REQUESTERS):
    "pi" (a sender profile, or a PI firm in case.facts), "counsel" when the profile's meta says so, else "victim".
    Never "le": Aegis letters are never worded or sent as if from an agency (the LE-only gate)."""
    from app.domain.playbook import PRIVATE

    profile = get_profile(db, case) if db is not None and case.id is not None else None
    if profile is not None:
        kind = str((profile.meta or {}).get("requester") or "pi")
        return kind if kind in PRIVATE else "pi"
    return "pi" if ((case.facts or {}).get("investigator") or {}).get("firm") else "victim"


def case_mailbox() -> str | None:
    """The configured case mailbox (AEGIS_MAIL_FROM, read fresh), or None when mail is not set up."""
    import os

    value = (os.environ.get("AEGIS_MAIL_FROM") or "").strip().lower()
    return value if value and "@" in value else None


def profile_sender(profile: SenderProfile) -> dict:
    """The letter templates' `sender` dict for a profile (kind 'athena'). An empty contact e-mail means
    the case mailbox (AEGIS_MAIL_FROM), so the letter names the address the e-mail is sent from and
    replies come back to."""
    title = (profile.signatory_title or "").strip()
    name = (profile.signatory_name or "").strip()
    contact = (name + (f" — {title}" if title else "")) if name else (profile.org_name or org_name())
    return {"kind": "athena", "firm": profile.org_name or org_name(), "on_behalf_of": profile.on_behalf_of,
            "contact": contact, "signatory_name": name or None, "signatory_title": title or None,
            "email": profile.contact_email or case_mailbox(), "address": profile.postal_address, "phone": profile.phone,
            "cc": list(profile.cc_default or []), "instrument": profile.instrument or DEFAULT_INSTRUMENT,
            "based_in": None, "signature_block": profile.signature_block}


def letter_parts(case: Case, profile: SenderProfile) -> tuple[str, str]:
    """The opening paragraph ("We write as <org>, on behalf of …") and the signature (from "Yours faithfully,") that
    new letters get from `profile`, as Markdown (the letter templates' own _intro / _signature)."""
    import re

    from app.domain import correspondence as desk
    from app.reports import stop_orders as so

    ctx = {"sender": profile_sender(profile), "victim": desk._victim(case),
           "loss_fmt": f"{so._fmt_amt(case.loss_amount)} {case.loss_asset}" if case.loss_amount else None,
           "loss_usd_fmt": f"USD {so._fmt_usd(case.loss_usd)}" if case.loss_usd else None,
           "fraud_date_fmt": case.fraud_date.strftime("%d %B %Y") if case.fraud_date else None}
    env = so._letter_env()
    intro = env.get_template("letters/_intro.md.j2").render(**ctx)
    sig = env.get_template("letters/_signature.md.j2").render(**ctx)
    return re.sub(r"\n{3,}", "\n\n", intro).strip(), re.sub(r"\n{3,}", "\n\n", sig).strip()


def letter_sender(case: Case, actor: User | None = None, *, db: Session | None = None) -> dict | None:
    """The `sender` dict of new letters when the case has a profile, else None (the caller then uses
    the PI-firm / signed-in-user block)."""
    db = db or object_session(case)
    if db is None or case.id is None:
        return None
    profile = get_profile(db, case)
    return profile_sender(profile) if profile is not None else None


def delete_profile(db: Session, access) -> bool:
    """Remove the case's profile (letters fall back to the PI-firm block). Admins only; caller audits."""
    if not access.can("manage_sender_profile"):
        raise SenderForbidden("only case admins may change the sender profile")
    row = get_profile(db, access.case)
    if row is None:
        return False
    db.delete(row)
    db.flush()
    return True
