"""Render preservation / freeze requests from freeze candidates.

The template mirrors the structure of the preservation requests issued by the
PI firm on this case (identifiers → records → requested action), so recipients
see a familiar, complete letter. Output is Markdown (stored in the DB and shown
in the UI) with an optional .docx export.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from app.db.models import Case, EntityCategory, SeedRole, StopOrder, TraceRun
from app.tracing.freeze import FreezeCandidate

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

RECORDS_BY_CATEGORY: dict[str, list[str]] = {
    EntityCategory.EXCHANGE.value: [
        "KYC data: identity documents, selfie/liveness checks, nationality, address, phone, email.",
        "Account registration data, including sign-up date and IP.",
        "Login logs with IPs, device fingerprints and user-agents.",
        "Full deposit, trade, P2P and withdrawal history, including destination addresses and fiat off-ramp bank details.",
        "Any internal compliance alerts, STR/SAR flags or prior reports on these accounts.",
    ],
    EntityCategory.CASINO.value: [
        "Account registration data and any KYC, including sign-up IP.",
        "Login logs with IPs, devices and user-agents.",
        "Deposit, wager and withdrawal history, including withdrawal destination addresses. Deposits with minimal play followed by withdrawal are a laundering indicator.",
        "Affiliate or referral links associated with the account.",
    ],
    EntityCategory.SWAP_SERVICE.value: [
        "Complete order records: tokens, amounts, rates, timestamps, source, destination and refund addresses.",
        "IP address, device and user-agent at order creation, plus any account or email used.",
        "Partner, referrer or API integrator through which the orders were placed.",
        "Linked orders that share the same IP, device, source or destination address.",
    ],
    EntityCategory.STABLECOIN_ISSUER.value: [
        "Current balance of the token at the identified address(es).",
        "Blacklist / freeze of the identified address(es) pending law-enforcement process.",
        "Any prior compliance actions or reports concerning the identified address(es).",
    ],
}
DEFAULT_RECORDS = [
    "Account registration data, including sign-up date and IP.",
    "Login and authentication logs.",
    "Billing and payment records.",
]



# a swap service's own order reference in a transfer note: "SWFT order demo0swf_t000_… — ETH → USDT"
SWAP_ORDER_REF = re.compile(r"\border\s+([A-Za-z0-9][A-Za-z0-9_\-]{11,})")

def _fmt_ts(v: str) -> str:
    dt = datetime.fromisoformat(v)
    return dt.astimezone(UTC).strftime("%d.%m.%Y %H:%M:%S UTC")


def _fmt_amt(v) -> str:
    """Up to 8 decimals, never fewer than the value has (compliance teams match exact amounts),
    with thousands separators: 1359.899028 -> 1,359.899028."""
    if v is None:
        return "?"
    d = Decimal(str(v)).quantize(Decimal("0.00000001")).normalize()
    return f"{d:,f}"


def _fmt_usd(v) -> str:
    return f"{Decimal(str(v)):,.2f}"


def _fmt_date(v: str) -> str:
    return datetime.fromisoformat(v).astimezone(UTC).strftime("%d.%m.%Y")


ADDRESS_KIND = {
    "eoa": "Wallet", "deposit": "Deposit", "hot_wallet": "Hot wallet", "contract": "Contract",
    "perpetrator": "Perpetrator-controlled", "victim": "Victim", "unknown": "Unclassified",
}


def _addr_kind(v: str) -> str:
    return ADDRESS_KIND.get(v, v.replace("_", " ").capitalize())


def _is_weak(t) -> bool:
    """An asserted link with no known amount: the investigator says funds went this way, but
    neither the transaction nor the amount has been observed."""
    return t.tx_hash.startswith("ASSERTED:") and t.amount is None


def verified_addresses(run: TraceRun) -> set[str]:
    """Addresses reachable from the trace root through tainted edges none of which is a weak
    (asserted, amount-unknown) link. Cross-chain payout legs inherit the status of the deposit
    leg that funded them. Anything outside this set is only *suspected* to hold the victim's funds."""
    edges = [e.transfer for e in run.edges if (e.taint_usd or 0) > 0]
    funded_by = {t.bridged_to_transfer_id: t.id for t in edges if t.bridged_to_transfer_id}
    roots = [n.address_id for n in run.nodes if n.hop == 0]
    ok_addr: set[int] = set(roots)
    ok_edge: set[int] = set()
    changed = True
    while changed:
        changed = False
        for t in edges:
            if t.id in ok_edge or _is_weak(t):
                continue
            if t.from_address_id in ok_addr or funded_by.get(t.id) in ok_edge:
                ok_edge.add(t.id)
                ok_addr.add(t.to_address_id)
                changed = True
    return {n.address.address for n in run.nodes if n.address_id in ok_addr}


def _origin(case: Case, facts: dict) -> dict:
    """The victim's outgoing transfer: facts.origin when recorded, else the case seeds."""
    if facts.get("origin"):
        return dict(facts["origin"])
    seeds = {s.role: s.value for s in case.seeds}
    if SeedRole.PERPETRATOR_WALLET not in seeds:
        return {}
    return {"tx_hash": seeds.get(SeedRole.ORIGIN_TX), "victim_wallet": seeds.get(SeedRole.VICTIM_WALLET),
            "perpetrator_wallet": seeds[SeedRole.PERPETRATOR_WALLET]}


def _env() -> Environment:
    # The output is Markdown, not HTML, and also feeds .docx export and "Copy Markdown", so HTML
    # autoescaping here would corrupt it (& -> &amp;). The HTML boundary is the UI's Markdown
    # renderer, which runs with raw HTML disabled (app.web.routes._md).
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=False, trim_blocks=True, lstrip_blocks=True)
    env.filters.update(fmt_ts=_fmt_ts, fmt_amt=_fmt_amt, fmt_usd=_fmt_usd, fmt_date=_fmt_date, addr_kind=_addr_kind,
                       mdx=md_escape)  # mdx: Markdown-escape a value typed by a user (the sender profile)
    return env


def sender_profile_for_stop_order(case: Case) -> dict | None:
    """The case's sender profile as the letters' `sender` dict ("Athena Software Group, Inc., on
    behalf of …"), or None: the stop order then keeps the investigator (PI-firm) block."""
    from app.domain import sender as sender_mod  # local import: app.domain imports this module

    return sender_mod.letter_sender(case, None)


def render_stop_order(case: Case, run: TraceRun, cand: FreezeCandidate) -> StopOrder:
    facts = case.facts or {}
    sender = sender_profile_for_stop_order(case)
    investigator = facts.get("investigator") or {
        "firm": case.victim_entity or "Investigator", "contact": case.victim_name or "", "email": "", "address": "", "phone": "",
    }
    kind = "freeze" if cand.kind in ("freeze", "issuer_blacklist") else "preservation"
    prefix = {"freeze": "Urgent Preservation & Risk-Control Request", "preservation": "Urgent Preservation Request"}[kind]
    # Never state an unverified link as fact: if no identifier that received funds is reachable
    # from the root without a weak asserted hop, the subject says "suspected".
    verified = verified_addresses(run)
    receiving = [i for i in cand.identifiers if i.inbound]
    unverified = {i.address for i in receiving if i.address not in verified}
    suspected = bool(receiving) and len(unverified) == len(receiving)
    proceeds = "suspected fraud proceeds" if suspected else "fraud proceeds"
    if cand.kind == "issuer_blacklist":
        asset = cand.identifiers[0].inbound[0]["asset"] if cand.identifiers and cand.identifiers[0].inbound else "stablecoin"
        subject = f"{prefix} – Blacklist request: address(es) that received {proceeds} in {asset}"
    elif cand.category in (EntityCategory.SWAP_SERVICE.value, EntityCategory.BRIDGE.value, EntityCategory.DEX.value):
        subject = f"{prefix} – Swap orders {'suspected of processing' if suspected else 'processing'} fraud proceeds ({cand.entity_name})"
    else:
        subject = f"{prefix} – {proceeds.capitalize()} deposited to {cand.entity_name} accounts"

    loss_fmt = f"{_fmt_amt(case.loss_amount)} {case.loss_asset}" if case.loss_amount else "n/a"
    loss_usd_fmt = f"USD {_fmt_usd(case.loss_usd)}" if case.loss_usd else "n/a"
    fraud_date_fmt = case.fraud_date.strftime("%d %B %Y") if case.fraud_date else "the date stated in the complaint"
    fraud_ts_fmt = _fmt_ts(case.fraud_date.isoformat()) if case.fraud_date else None
    has_asserted = bool(unverified) or any(tx.get("asserted") for i in cand.identifiers for tx in i.inbound + i.context_inbound)

    records = RECORDS_BY_CATEGORY.get(cand.category, DEFAULT_RECORDS)
    # swap-service order references recorded on the transfers (e.g. "SWFT order <id> — ETH → USDT")
    order_ids = list(dict.fromkeys(
        m.group(1) for i in cand.identifiers for tx in i.inbound + i.outbound + i.context_inbound
        for m in SWAP_ORDER_REF.finditer(tx.get("notes") or "")))
    from types import SimpleNamespace

    from app.domain import evidence_requirements as er

    # an order LE / counsel obtained against this provider (it names it as a whole word): the letter serves it
    names = er.provider_names(SimpleNamespace(entity=cand.entity, name=cand.entity_name, le_contacts=[]))
    orders = [{"title": e.title, "type": (e.source_type or "court_order").replace("_", " ")}
              for e in er.held_orders(case) if er.names_provider(e, names)]
    body = _env().get_template("preservation_request.md.j2").render(
        orders=orders,
        subject=subject, recipient_salutation="Compliance / Legal Team", investigator=investigator, case=case,
        facts=facts, loss_fmt=loss_fmt, loss_usd_fmt=loss_usd_fmt, fraud_date_fmt=fraud_date_fmt, kind=kind,
        identifiers=cand.identifiers, records=records, run_ref=run.id, origin=_origin(case, facts),
        unverified=unverified, has_asserted=has_asserted, fraud_ts_fmt=fraud_ts_fmt, order_ids=order_ids,
        generated_at=datetime.now(tz=UTC).strftime("%d.%m.%Y %H:%M UTC"),
        sender_kind=sender["kind"] if sender else "investigator", sender=sender or {},
    )
    return StopOrder(
        case=case, entity=cand.entity, kind=kind, recipient_email=cand.entity.compliance_email if cand.entity else None,
        subject=subject, body_markdown=body,
        identifiers={
            "entity": cand.entity_name, "priority": cand.priority, "total_taint_usd": str(cand.total_taint_usd),
            "rationale": cand.rationale, "trace_run_id": run.id, "order_ids": order_ids,
            "addresses": [
                {"chain": i.chain, "address": i.address, "type": i.address_type, "label": i.label,
                 "inbound": i.inbound, "outbound": i.outbound, "context_inbound": i.context_inbound,
                 "flags": i.flags, "risk": i.risk}
                for i in cand.identifiers
            ],
        },
    )


# --------------------------------------------------------------------------- form letters
# Templates under templates/letters/*.md.j2 (status request, information request, LE cover letter,
# release request). The output is Markdown, so HTML autoescaping does not apply; instead every
# `{{ value }}` is Markdown-escaped by `finalize` (a victim name such as "**x** [y](javascript:…)"
# or "<script>" stays literal text). Filters that build Markdown on purpose (`code`, `bold`,
# `italic`) return MdSafe, which finalize passes through. Fragments shared between letters are
# `{% include %}`d, never macros: include output is not re-escaped.
LETTER_DIR = "letters"
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>])")
_ESCAPED = re.compile(r"\\([\\`*_\[\]<>{}()#+\-.!|~])")
_SHIELD = {c: chr(0xE000 + i) for i, c in enumerate("\\`*_[]<>{}()#+-.!|~")}
_UNSHIELD = {v: k for k, v in _SHIELD.items()}


class MdSafe(str):
    """A string that is already Markdown; letter templates output it as is."""


def md_escape(value) -> MdSafe:
    if isinstance(value, MdSafe):
        return value
    return MdSafe(_MD_SPECIAL.sub(r"\\\1", str(value)))


def unescape_md(text: str) -> str:
    return _ESCAPED.sub(r"\1", text)


def _unshield(text: str) -> str:
    return "".join(_UNSHIELD.get(ch, ch) for ch in text)


def _finalize(value):
    if value is None:
        return ""
    if isinstance(value, MdSafe | bool | int | float | Decimal):
        return value
    return md_escape(value)


def _code(value) -> MdSafe:
    """An inline code span (identifiers, hashes, references): verbatim, backticks removed."""
    text = str(value if value is not None else "").replace("`", "").replace("\n", " ").strip()
    return MdSafe(f"`{text}`") if text else MdSafe("")


def _bold(value) -> MdSafe:
    return MdSafe(f"**{md_escape(value)}**")


def _italic(value) -> MdSafe:
    return MdSafe(f"*{md_escape(value)}*")


def _one_line(value) -> str:
    return " ".join(str(value or "").split())


def _letter_env() -> Environment:
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=False, trim_blocks=True,
                      lstrip_blocks=True, finalize=_finalize, keep_trailing_newline=True)
    env.filters.update(fmt_ts=_fmt_ts, fmt_amt=_fmt_amt, fmt_usd=_fmt_usd, fmt_date=_fmt_date, addr_kind=_addr_kind,
                       code=_code, bold=_bold, italic=_italic, one_line=_one_line)
    return env


class LetterWordingError(ValueError):
    """A rendered letter breaks a wording rule (e.g. calls a Letter of Authorisation a Power of Attorney)."""


def render_letter(template_key: str, **context) -> str:
    """Render templates/letters/<template_key>.md.j2 to Markdown.

    Wording rules enforced on the output: an asserted link is never cited by its placeholder hash
    (`ASSERTED:…`), and the authority instrument is never called a Power of Attorney unless that
    is literally the instrument on file."""
    if not re.fullmatch(r"[a-z][a-z0-9_]*", template_key):
        raise ValueError(f"invalid letter template {template_key!r}")
    body = _letter_env().get_template(f"{LETTER_DIR}/{template_key}.md.j2").render(**context)
    body = re.sub(r"\n{3,}", "\n\n", body).strip() + "\n"
    instrument = str((context.get("sender") or {}).get("instrument") or "")
    if "power of attorney" in body.lower() and "power of attorney" not in instrument.lower():
        raise LetterWordingError("letters must not call the authority instrument a Power of Attorney")
    if "ASSERTED:" in body:
        raise LetterWordingError("an asserted link must be described, not cited by its placeholder hash")
    return body


def _utc(v: datetime | None) -> str | None:
    if v is None:
        return None
    v = v if v.tzinfo else v.replace(tzinfo=UTC)
    return v.astimezone(UTC).strftime("%d.%m.%Y %H:%M UTC")


def export_header_markdown(order: StopOrder) -> str:
    """The filing block above an exported stop order: what it is, to whom and when it was sent.
    Every value is Markdown-escaped (subjects and addresses are user-controlled)."""
    get = lambda name: getattr(order, name, None)
    status, origin = get("status"), get("origin")
    lines = [f"**Stop order #{int(order.id)}** · case {md_escape(order.case.reference)}"
             + (f" · status {md_escape(getattr(status, 'value', status))}" if status else "")
             + (f" · {md_escape(getattr(origin, 'value', origin))}" if origin else "")]
    lines.append(f"**To:** {md_escape(get('recipient_email'))}" if get("recipient_email") else
                 "**To:** the recipient's law-enforcement request portal (no e-mail on file)")
    if get("recipient_cc"):
        lines.append("**Cc:** " + ", ".join(md_escape(c) for c in get("recipient_cc")))
    if get("sent_at"):
        lines.append(f"**Sent:** {_utc(get('sent_at'))}" + (f" via {md_escape(get('sent_via'))}" if get("sent_via") else ""))
    else:
        lines.append("**Sent:** not sent (draft)")
    if get("response_due_at"):
        lines.append(f"**Reply due:** {_utc(get('response_due_at'))}")
    if get("external_ref"):
        lines.append(f"**Their reference:** {md_escape(get('external_ref'))}")
    head = (get("body_markdown") or "").lstrip()[:400]
    if not head.startswith("**Subject:**"):
        lines.append(f"**Subject:** {md_escape(' '.join((get('subject') or '').split()))}")
    return "\n".join(lines) + "\n\n---\n\n"


def export_markdown(order: StopOrder) -> str:
    """Header block + letter body: what the .md / .docx export of a stop order contains."""
    return export_header_markdown(order) + (order.body_markdown or "")


def to_docx(order: StopOrder, path: Path) -> Path:
    """Very small Markdown → .docx conversion (headings, bullets, bold, italics, code), with the
    filing header (subject, recipients, sent at, case reference, stop order number) on top."""
    return markdown_to_docx(order.subject, export_markdown(order), order.case.reference, path)


def markdown_to_docx(title: str, body_markdown: str, case_reference: str, path: Path) -> Path:
    """The .docx exporter shared by stop orders and every other letter (correspondence drafts).

    Handles the Markdown the letter templates emit: `### ` headings, `- ` / `  - ` bullets,
    **bold**, *italics*, `code`, and backslash escapes (rendered as the plain character)."""
    doc = _docx_document(title, body_markdown, case_reference)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(path)
    return path


def markdown_to_docx_bytes(title: str, body_markdown: str, case_reference: str, *, final: bool = False) -> bytes:
    """The same document in memory. `final=True` (the copy attached to an e-mail Aegis sends): the
    metadata says "Final" and "Sent by Athena Software Group, Inc. via Aegis" instead of "Draft …
    Review before sending"."""
    import io

    buf = io.BytesIO()
    _docx_document(title, body_markdown, case_reference, final=final).save(buf)
    return buf.getvalue()


def _docx_document(title: str, body_markdown: str, case_reference: str, *, final: bool = False):
    from docx import Document
    from docx.shared import Pt

    doc = Document()
    # python-docx's template ships author "python-docx" and a 2013 timestamp; set neutral metadata
    props = doc.core_properties
    now = datetime.now(tz=UTC).replace(tzinfo=None)
    props.author = props.last_modified_by = "Aegis"
    props.title = title
    props.subject = f"Case {case_reference}"
    props.comments = ("Sent by Athena Software Group, Inc. via Aegis" if final else
                      "Draft generated by Aegis (powered by Athena Software Group, Inc.). Review before sending.")
    props.keywords = props.category = ""
    props.content_status = "Final" if final else "Draft"
    props.created = props.modified = now
    props.revision = 1
    # the stock template also carries a thumbnail image (docProps/thumbnail.jpeg): drop it, so the
    # export holds text only and the repository's scanner never has to trust an image
    from docx.opc.constants import RELATIONSHIP_TYPE as RT

    pkg_rels = doc.part.package.rels
    for r_id in [k for k, rel in pkg_rels.items() if rel.reltype == RT.THUMBNAIL]:
        pkg_rels.pop(r_id)
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)

    def add_runs(par, text: str):
        # escaped punctuation (\\*, \\_, \\[ …) is shielded from the emphasis split, then unescaped
        text = _ESCAPED.sub(lambda m: _SHIELD[m.group(1)], text)
        for part in re.split(r"(\*\*[^*]+\*\*|`[^`]+`|\*[^*\s][^*]*\*)", text):
            if not part:
                continue
            if part.startswith("**"):
                r = par.add_run(_unshield(part.strip("*")))
                r.bold = True
            elif part.startswith("*") and len(part) > 2:
                r = par.add_run(_unshield(part[1:-1]))
                r.italic = True
            elif part.startswith("`"):
                r = par.add_run(_unshield(part.strip("`")))
                r.font.name = "Consolas"
                r.font.size = Pt(9.5)
            else:
                par.add_run(_unshield(part))

    for line in (body_markdown or "").splitlines():
        s = line.rstrip()
        if not s:
            continue
        if s.startswith("### "):
            doc.add_heading(s[4:], level=2)
        elif s.startswith("---") or s.startswith("* * *"):
            doc.add_paragraph("")
        elif s.startswith("  - "):
            add_runs(doc.add_paragraph(style="List Bullet 2"), s[4:])
        elif s.startswith("- "):
            add_runs(doc.add_paragraph(style="List Bullet"), s[2:])
        elif s.startswith("*") and s.endswith("*") and not s.startswith("**"):
            p = doc.add_paragraph()
            r = p.add_run(unescape_md(s.strip("*")))
            r.italic = True
            r.font.size = Pt(9)
        else:
            add_runs(doc.add_paragraph(), s)
    return doc
