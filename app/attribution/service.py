"""Who owns each wallet of a case: the sources, how they combine, who to ask, the per-case lookup consent and the runs.

    atts = attribute(db, case)                         # {(chain, address key): Attribution}, most money first; no network
    report = run_lookups(db, case, trigger="manual")   # OwnerLookupsDisabled unless a case admin consented
    row = mark(db, case, user, chain=…, address=…, owner="…", kind="exchange_deposit", note="…")  # a person's call

**Sources** (each claim keeps its source, confidence H / M / L and when it was retrieved):
* `manual` — a person's attribution ("owned by <entity>", with a note): always wins, H. A later "clear" withdraws it.
* `trace` — the trace's own entity map (an address the trace attributes to an exchange / swap service / casino, its
  deposit / hot-wallet type; a perpetrator wallet): H for a typed service address, else M.
* `catalogue` — the provider playbooks' published wallets (`addresses`, app.domain.playbook) and the issuers' token
  contracts (app.freeze.issuers): H. The catalogue's names, aliases and own domains also put an owner another source
  names on its catalogue organisation (`org_key`: who to ask, its playbook, its LE-only gate).
* `explorer` — public explorer tags (app.attribution.explorer: Blockscout, Tronscan), read only after a case admin
  consented for the case (`cases.owner_lookup_consent`, migration 0011), stored as `wallet_attributions` rows (the
  latest good lookup per wallet; a failed lookup is never stored, so it never hides an earlier one): M, a scam mark L.
* `behaviour` — a profile from data Aegis has: the balance read on-chain vs what the trace put in, the explorer's
  transaction count, the forwarding pattern (swept within SWEEP_MINUTES of arrival, ≥ 90 % to one wallet of a known
  service ⇒ "deposit address of <that service>"), a dormant self-custody wallet: L (M when it leans on an H claim).

**Combining.** The manual claim wins. Else the highest confidence, then a claim naming an owner, then the source
(catalogue > trace > explorer > behaviour). Two sources naming the same owner raise the confidence one step
("corroborated"); a source naming another owner is listed as a conflict. Nothing here overwrites another source:
each stays an evidence line.

**Who to ask** (`Attribution.ask`): an exchange deposit / casino → that service, a freeze request naming the address
(info_request with the address prefilled); an exchange / service hot wallet → the service (which customer account it
credited), never the issuer; a swap / bridge → the service's order records; a mixer / non-custodial protocol or DEX
router → nobody (follow the output); an unhosted wallet holding USDT / USDC → the issuer of the token it holds (largest
balance first); an unknown owner → identify it. Without the caller's authorities `attribute` reads them as the
Recovery plan does (recovery.ask_context), so every page gives the same ask. An owner whose playbook takes LE requests only from us is
briefed through LE (the LE-only gate). Advisory: nothing here sends, drafts or confirms anything.

Domain code: it never audits (the routes do). Egress only through app.freeze.transport with
app.attribution.explorer.ALLOWED_DOMAINS, and only for a case whose admin consented to the hosts in `egress_plan()`.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.ai.context import RESTRICTED_TLP
from app.attribution import explorer
from app.db.models import (
    Address,
    AddressType,
    Case,
    EntityCategory,
    TraceEdge,
    TraceNode,
    Transfer,
    User,
)
from app.db.models import WalletAttribution as Row
from app.domain.addresses import wallet_key
from app.freeze.transport import FreezeHttp

log = logging.getLogger("app.attribution")

KINDS = {"exchange_deposit": "exchange deposit address", "exchange_hot_wallet": "exchange / service hot wallet",
         "swap_bridge": "swap / bridge", "issuer": "token issuer contract", "casino": "casino",
         "non_custodial": "mixer / non-custodial protocol (no account to freeze)",
         "unhosted": "unhosted (self-custody; likely the scammer's)", "unknown": "unknown"}
SERVICE_KINDS = frozenset({"exchange_deposit", "exchange_hot_wallet", "swap_bridge", "casino"})
FLOAT_KINDS = frozenset({"exchange_hot_wallet", "swap_bridge"})  # a service's pooled float: the case's share only
DEPOSIT_KINDS = frozenset({"exchange_deposit", "casino"})  # one customer's deposit address: swept to its service
SOURCES = {"manual": "a person", "catalogue": "the catalogue", "trace": "the trace's entity map",
           "explorer": "public explorer tag", "behaviour": "behaviour profile"}
SOURCE_RANK = {"manual": 9, "catalogue": 5, "trace": 4, "explorer": 3, "behaviour": 1}
CONF_RANK = {"H": 3, "M": 2, "L": 1}
CONF_LABELS = {"H": "high", "M": "medium", "L": "low"}
SWEEP_MINUTES = 60
SWEEP_SHARE = 0.9
POOLED_FACTOR = 5.0  # balance / traced inflow above which a wallet behaves like a service's pooled float
POOLED_MIN_USD = 10_000.0
BUSY_TX = 10_000  # transactions: a service, not a person
QUIET_TX = 500
MONEY_MIN_USD = 1.0
CATEGORY_KIND = {"exchange": "exchange_hot_wallet", "otc": "exchange_hot_wallet", "casino": "casino",
                 "swap_service": "swap_bridge", "bridge": "swap_bridge", "dex": "swap_bridge",
                 "stablecoin_issuer": "issuer"}
STABLES = frozenset({"USDT", "USDC"})
STABLE_ISSUER = {"USDT": "Tether", "USDC": "Circle"}
WALLET_RE = {"tron": re.compile(r"T[1-9A-HJ-NP-Za-km-z]{33}"), "bitcoin": re.compile(r"(bc1|[13])[0-9A-Za-z]{25,62}"),
             "solana": re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}")}
EVM_RE = re.compile(r"0x[0-9a-fA-F]{40}")


class OwnerLookupsDisabled(Exception):
    """No request may be sent: `reason` case_setting_off | deployment_disabled | consent_outdated."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _settings(settings=None):
    if settings is None:
        from app.core.config import get_settings

        settings = get_settings()
    return settings


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _aware(v: datetime | None) -> datetime | None:
    return v if v is None or v.tzinfo else v.replace(tzinfo=UTC)


def key_of(chain: str | None, address: str | None) -> tuple[str, str]:
    return wallet_key(chain, address)


def short(a: str) -> str:
    return a if len(a) <= 14 else f"{a[:6]}…{a[-4:]}"


def normalise(chain: str, address: str) -> tuple[str, str]:
    """(chain, address key) of a wallet a person typed. ValueError on an unknown chain or a malformed address."""
    from app.db.models import Chain

    c = (chain or "").strip().lower()
    if c not in {x.value for x in Chain} | {"optimism"}:
        raise ValueError("unknown chain")
    a = (address or "").strip()
    rx = WALLET_RE.get(c, EVM_RE)
    if not rx.fullmatch(a):
        raise ValueError(f"not a {c} address")
    if c == "tron":
        from app.freeze import abi

        if not abi.is_tron_address(a):
            raise ValueError("not a TRON address (T… base58check)")
    return key_of(c, a)


# --------------------------------------------------------------------------- the catalogue
@dataclass(frozen=True)
class OrgRef:
    key: str
    name: str
    category: str
    playbook: Any = None


def _catalogue():
    from app.domain import directory

    try:
        return directory.load_catalogue()
    except Exception:  # noqa: BLE001 - an invalid catalogue: no catalogue source
        return None


def catalogue_addresses(cat=None) -> dict[tuple[str, str], tuple[OrgRef, Any]]:
    """{(chain, address key): (organisation, the playbook's KnownAddress)} plus the issuers' token contracts."""
    from app.freeze.issuers import CONTRACTS

    cat = cat if cat is not None else _catalogue()
    out: dict[tuple[str, str], tuple[OrgRef, Any]] = {}
    for o in getattr(cat, "orgs", ()) or ():
        for k in getattr(o.playbook, "addresses", ()) or ():
            out[key_of(k.chain, k.address)] = (OrgRef(o.key, o.name, o.category, o.playbook), k)
    for c in CONTRACTS:
        org = next((o for o in getattr(cat, "orgs", ()) or () if o.category == "stablecoin_issuer"
                    and c.issuer.casefold() in {n.casefold() for n in o.names}), None)
        ref = OrgRef(org.key, org.name, org.category, org.playbook) if org is not None else OrgRef(
            c.issuer.lower(), c.issuer, "stablecoin_issuer")
        out.setdefault(key_of(c.chain, c.contract), (ref, None))
    return out


def _word_in(name: str, text: str) -> bool:
    return bool(re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", text, re.IGNORECASE))


def match_org(text: str | None, url: str | None = None, cat=None) -> OrgRef | None:
    """The catalogue organisation a name (an exact name / alias, else one found as a whole word, the longest) or a
    URL on one of its own domains points to."""
    cat = cat if cat is not None else _catalogue()
    orgs = [o for o in getattr(cat, "orgs", ()) or () if o.category not in ("law_enforcement", "regulator")]
    t = (text or "").strip()
    host = (urlsplit(url if "//" in (url or "") else f"https://{url}").hostname or "").lower() if url else ""
    if host:
        for o in orgs:
            own = getattr(getattr(o.playbook, "domains", None), "own", ()) or ()
            if any(host == d or host.endswith("." + d) for d in own):
                return OrgRef(o.key, o.name, o.category, o.playbook)
    if not t:
        return None
    for o in orgs:
        if any(t.casefold() == n.casefold() for n in o.names):
            return OrgRef(o.key, o.name, o.category, o.playbook)
    best = None
    for o in orgs:
        for n in o.names:
            if len(n) >= 3 and _word_in(n, t) and (best is None or len(n) > best[0]):
                best = (len(n), OrgRef(o.key, o.name, o.category, o.playbook))
    return best[1] if best else None


# --------------------------------------------------------------------------- wallets
@dataclass
class Wallet:
    chain: str
    address: str  # the key form (EVM lower-case)
    label: str | None = None
    entity: Any = None  # the trace's Entity
    address_type: str | None = None
    label_source: str | None = None
    in_trace: bool = False
    watched: bool = False
    flags: set = field(default_factory=set)
    taint_usd: float = 0.0
    held_usd: float | None = None  # USDT / USDC balance read on-chain (app.freeze)
    holds_stable: bool = False  # received / holds an issuer-freezable stablecoin
    held_by: dict = field(default_factory=dict)  # symbol -> USD read on-chain (good readings with a balance)
    frozen: bool = False  # an issuer blacklisted it (a good reading): its balance is held, not a service's float
    received: set = field(default_factory=set)  # stablecoin symbols the trace saw arrive
    swept_float: bool = False  # its traced inflow is only sweeps from deposit addresses the case already lists
    holding: bool = False  # the trace saw no onward movement
    first_in: datetime | None = None
    first_out: datetime | None = None
    out_to: dict = field(default_factory=dict)  # address key -> USD sent there (the trace: each transfer's amount)
    out_taint: dict = field(default_factory=dict)  # address key -> case funds (taint) sent there (the trace)
    swept_usd: float | None = None  # the good reading before a sweep into its service (app.freeze `swept`)
    tlp: str | None = None  # the freeze watch's TLP (a restricted wallet is never sent to the public explorers)
    sources: set = field(default_factory=set)  # address keys the trace saw send it case funds
    # an ASSERTED link (an investigator's report, no hop observed on-chain) carries the hub's unquantified residual in
    # full to each of the hub's asserted destinations: an upper bound they share, never each one's own money
    observed_in: float = 0.0  # case funds the trace saw arrive over observed transfers
    asserted_in: float = 0.0  # case funds over asserted links
    asserted_out: dict = field(default_factory=dict)  # address key -> case funds it sent over an asserted link
    asserted_peers: int = 0  # the other asserted destinations of the hub(s) it was asserted from
    asserted_hub: tuple | None = None  # that hub's wallet key
    counterparties: int = 0
    tx_count: int | None = None
    at: datetime | None = None  # when the trace ran

    @property
    def key(self) -> tuple[str, str]:
        return self.chain, self.address

    @property
    def short(self) -> str:
        return short(self.address)

    @property
    def asserted(self) -> bool:
        """Its traced funds reached it (partly) over an asserted link: their amount is an upper bound."""
        return self.in_trace and self.asserted_in > 0

    @property
    def observed_usd(self) -> float:
        """What the trace saw reach it over observed transfers (all its taint unless an asserted link fed it)."""
        return round(min(self.taint_usd, self.observed_in), 2) if self.asserted else self.taint_usd

    @property
    def money_usd(self) -> float:
        if self.held_usd is not None:
            return round(self.held_usd, 2)
        if self.in_trace and (self.holding or self.address_type == "deposit") and not self.swept_float:
            return round(self.taint_usd, 2)
        return 0.0

    @property
    def stables(self) -> list[str]:
        """The stablecoins the wallet holds (by the balance read on-chain, largest first), else the ones it received."""
        held = [s for s, v in sorted(self.held_by.items(), key=lambda kv: -kv[1]) if v >= MONEY_MIN_USD]
        return held or sorted(self.received)

    @property
    def money_basis(self) -> str:
        if self.held_usd is not None:
            syms = [s for s, v in sorted(self.held_by.items(), key=lambda kv: -kv[1]) if v >= MONEY_MIN_USD]
            return f"{' / '.join(syms or sorted(self.held_by) or ['USDT / USDC'])} balance read on-chain"
        if self.swept_float:
            return "swept in from a deposit address of the case: the service's float (counted at that deposit address)"
        if self.in_trace and self.address_type == "deposit" and not self.holding:
            return "traced in: credited to the account behind it (upper bound)"
        if self.in_trace and self.holding:
            return "traced in, no onward movement seen (upper bound)"
        return "passed through" if self.in_trace else "not read"


def wallets(db: Session, case: Case, *, run=None, freeze_rows: list[dict] | None = None) -> dict[tuple[str, str], Wallet]:
    """Every wallet of the case that needs an owner: the latest trace's (not the victim's, placeholders or context-only
    rows), the on-chain readings' and the freeze watch list's."""
    from app import services

    run = run if run is not None else services.latest_run(db, case)
    out: dict[tuple[str, str], Wallet] = {}
    if run is not None:
        at = _aware(run.finished_at or run.started_at)
        nodes = db.scalars(select(TraceNode).where(TraceNode.run_id == run.id)
                           .options(selectinload(TraceNode.address).selectinload(Address.entity))).all()
        edges = db.scalars(select(TraceEdge).where(TraceEdge.run_id == run.id)
                           .options(selectinload(TraceEdge.transfer).selectinload(Transfer.from_address),
                                    selectinload(TraceEdge.transfer).selectinload(Transfer.to_address))).all()
        by_id: dict[int, Wallet] = {}
        for n in nodes:
            a = n.address
            flags = set(n.flags or [])
            if a.address_type == AddressType.VICTIM or flags & {"context_only", "pending_input"} or \
                    a.address.endswith("_PENDING") or "_" in a.address:
                continue
            w = Wallet(chain=a.chain.value, address=key_of(a.chain.value, a.address)[1], label=a.label, entity=a.entity,
                       address_type=a.address_type.value, label_source=a.label_source, in_trace=True, flags=flags,
                       taint_usd=float(n.taint_usd or 0), tx_count=a.tx_count, at=at,
                       holds_stable="stablecoin_freezable" in flags)
            by_id[a.id] = w
            out[w.key] = w
        outs: dict[int, list[tuple[Transfer, float]]] = {}
        peers: dict[int, set[int]] = {}
        srcs: dict[int, set[int]] = {}
        for e in edges:
            t = e.transfer
            asserted = t.tx_hash.startswith("ASSERTED:")
            if (e.taint_usd or 0) > 0:
                srcs.setdefault(t.to_address_id, set()).add(t.from_address_id)
            for me, other in ((t.to_address_id, t.from_address_id), (t.from_address_id, t.to_address_id)):
                peers.setdefault(me, set()).add(other)
            w = by_id.get(t.to_address_id)
            if w is not None and not asserted and (w.first_in is None or t.timestamp < w.first_in):
                w.first_in = _aware(t.timestamp)
            sym = (t.asset or "").split("→")[-1].strip().upper()
            if w is not None and sym in STABLES:
                w.holds_stable = True
                w.received.add(sym)
            if (e.taint_usd or 0) > 0:
                outs.setdefault(t.from_address_id, []).append((t, float(e.taint_usd or 0)))
                if w is not None and asserted:
                    w.asserted_in += float(e.taint_usd or 0)
                    w.asserted_hub = w.asserted_hub or key_of(t.from_address.chain.value, t.from_address.address)
                elif w is not None:
                    w.observed_in += float(e.taint_usd or 0)
        for aid, w in by_id.items():
            sent = outs.get(aid, [])
            observed = [t for t, _ in sent if not t.tx_hash.startswith("ASSERTED:")]
            w.holding = not sent or "dormant" in w.flags
            w.first_out = _aware(min((t.timestamp for t in observed), default=None))
            for t, taint in sent:
                k = key_of(t.to_address.chain.value, t.to_address.address)
                w.out_to[k] = w.out_to.get(k, 0.0) + (float(t.amount_usd) if t.amount_usd is not None else taint)
                w.out_taint[k] = w.out_taint.get(k, 0.0) + taint
                if t.tx_hash.startswith("ASSERTED:"):
                    w.asserted_out[k] = w.asserted_out.get(k, 0.0) + taint
            w.counterparties = len(peers.get(aid, ()))
            src = srcs.get(aid) or set()
            w.sources = {by_id[s].key for s in src if s in by_id}
            w.swept_float = bool(src) and w.address_type != "deposit" and all(
                s in by_id and by_id[s].address_type == "deposit" for s in src)
            if w.entity is not None and w.entity.category == EntityCategory.DEX and w.address_type == "contract":
                w.holding = False  # a non-custodial router keeps nothing
        for w in by_id.values():  # the other destinations one hub's unquantified residual was asserted to
            hub = out.get(w.asserted_hub) if w.asserted else None
            w.asserted_peers = max(0, len(hub.asserted_out) - 1) if hub is not None else 0
    for r in freeze_rows or []:
        k = key_of(r["chain"], r["address"])
        w = out.get(k) or out.setdefault(k, Wallet(chain=k[0], address=k[1], label=r.get("label")))
        w.watched = w.watched or bool(r.get("watch_id"))
        w.tlp = r.get("tlp") or w.tlp
        ok = [c for c in r.get("checks") or [] if c.get("status") == "ok"]
        # every fall read as the service's sweep (app.freeze `swept.total_usd`: the whole history, never only the
        # latest drop) plus what is there now: what was credited to the account behind it
        swept = [float(c.get("usd") or 0) + float(_swept_total(c["swept"]) or 0) for c in ok if c.get("swept")]
        if swept:
            w.swept_usd = sum(swept)
        if ok:
            w.held_usd = sum(float(c.get("usd") or 0) for c in ok)
            w.frozen = w.frozen or any(c.get("blacklisted") for c in ok)
            w.holds_stable = w.holds_stable or w.held_usd >= MONEY_MIN_USD
            for c in ok:
                sym = str(c.get("symbol") or "").upper() or next(
                    (s for s, i in STABLE_ISSUER.items() if i == c.get("issuer")), "")
                if sym:
                    w.held_by[sym] = w.held_by.get(sym, 0.0) + float(c.get("usd") or 0)
    return out


def _swept_total(sw: dict) -> float | None:
    v = sw.get("total_usd")
    return v if v is not None else sw.get("usd")


# --------------------------------------------------------------------------- claims
@dataclass
class Claim:
    source: str
    owner: str | None
    kind: str
    confidence: str
    text: str
    at: datetime | None = None
    org_key: str | None = None
    row_id: int | None = None
    by: int | None = None
    note: str | None = None  # a person's note (case data: view_restricted only)

    def line_for(self, show_notes: bool = True) -> str:
        when = f", {self.at.astimezone(UTC):%d %b %Y}" if self.at else ""
        note = f": {self.note}" if self.note and show_notes else ""
        return f"{SOURCES.get(self.source, self.source)} ({self.confidence}{when}): {self.text}{note}"

    @property
    def line(self) -> str:
        return self.line_for(True)

    def as_dict(self, show_notes: bool = True) -> dict:
        return {"source": self.source, "source_label": SOURCES.get(self.source, self.source), "owner": self.owner,
                "kind": self.kind, "kind_label": KINDS.get(self.kind, self.kind), "confidence": self.confidence,
                "at": self.at.isoformat(timespec="seconds") if self.at else None, "text": self.text,
                "note": self.note if show_notes else None, "line": self.line_for(show_notes), "org_key": self.org_key}


def trace_kind(category: str | None, address_type: str | None) -> str:
    """The kind the trace's entity map gives a wallet (the plan, the owners panel and the Fund flow hover card all read
    it so): by the entity's category, an exchange / OTC desk's typed deposit address is one account's, a casino's hot
    / payout wallet its float."""
    kind = CATEGORY_KIND.get(category or "", "unknown")
    if category in ("exchange", "otc") and address_type == "deposit":
        kind = "exchange_deposit"
    elif category == "casino" and address_type == "hot_wallet":
        kind = "exchange_hot_wallet"  # a casino's own hot / payout wallet: its float, not one depositor's address
    return kind


def _trace_claim(w: Wallet, cat) -> Claim | None:
    e = w.entity
    from app.tracing.hover import SOURCE_LABELS

    src = f" (label: {SOURCE_LABELS.get(w.label_source, w.label_source)})" if w.label_source else ""
    if e is not None:
        kind = trace_kind(e.category.value, w.address_type)
        org = match_org(e.name, cat=cat)
        conf = "H" if w.address_type in ("deposit", "hot_wallet", "contract") else "M"
        what = {"deposit": "a deposit address", "hot_wallet": "a hot / payout wallet", "contract": "a contract"}.get(
            w.address_type or "", "an address")
        return Claim("trace", e.name, kind, conf, f"the trace puts {w.short} at {e.name} as {what}"
                     + (f" ({w.label})" if w.label and w.label != e.name else "") + src, at=w.at,
                     org_key=org.key if org else None)
    if w.address_type == "perpetrator":
        return Claim("trace", None, "unhosted", "M", "the trace marks it a perpetrator wallet (self-custody)" + src,
                     at=w.at)
    return None


def _catalogue_claim(w: Wallet, addrs: dict) -> Claim | None:
    hit = addrs.get(w.key)
    if hit is None:
        return None
    org, known = hit
    if known is None:
        return Claim("catalogue", org.name, "issuer", "H", f"{org.name}'s own token contract (app.freeze.issuers): "
                     "the issuer's contract, not a wallet holding the case's funds", org_key=org.key)
    p = known.prov
    when = datetime.fromisoformat(p.retrieved_at + ("-01" if len(p.retrieved_at) == 7 else "")).replace(tzinfo=UTC)
    return Claim("catalogue", org.name, known.kind, p.confidence,
                 f"{org.name} publishes it as its {KINDS.get(known.kind, known.kind)}"
                 + (f" ({known.label})" if known.label else "") + f" (sources {', '.join(p.source_ids)})",
                 at=when, org_key=org.key)


def _org_category(cat, key: str | None) -> str | None:
    o = getattr(cat, "by_key", {}).get(key) if cat is not None and key else None
    return getattr(o, "category", None)


def _row_claim(r: Row, cat) -> Claim | None:
    d = dict(r.detail or {})
    if r.source == "manual":
        if d.get("cleared"):
            return None
        note = d.get("note")
        what = (f"owned by {r.owner}" + (f" ({KINDS.get(r.kind, r.kind)})" if r.kind and r.kind != "unknown" else "")
                if r.owner else KINDS.get(r.kind or "", r.kind))
        return Claim("manual", r.owner, r.kind or "unknown", "H", f"marked {what} by a person", at=_aware(r.created_at),
                     org_key=d.get("org_key"), row_id=r.id, by=r.created_by, note=note)
    tags = d.get("tags") or []
    prof = d.get("profile") or {}
    if not tags and not prof.get("is_scam"):
        return None
    names = "; ".join(dict.fromkeys(f"{t.get('name')} ({t.get('source')})" for t in tags[:4]))
    kind = r.kind or "unknown"
    owner, org_key, conf = r.owner, d.get("org_key"), r.confidence or "M"
    if kind == "unhosted" and tags:  # a row stored when a scam mark / user feedback hid the service a tag names
        o2, k2, c2 = explorer.classify(tags)
        if k2 in explorer.SERVICE_TAG_KINDS and o2:
            org = match_org(o2, cat=cat)
            owner, kind, conf = (org.name if org is not None else o2), k2, c2
            org_key = org.key if org is not None else org_key
    risk = " (users flagged it as risky: likely the scammer's account there)" if (
        prof.get("feedback_risk") or prof.get("is_scam")) and kind in SERVICE_KINDS else ""
    if explorer.MIXER.search(" | ".join(str(t.get("name") or "") for t in tags)):
        kind = "non_custodial"  # a row stored before the mixer lexicon: read again
    elif kind == "exchange_hot_wallet" and (explorer.INSTANT_SWAP.search(" | ".join(str(t.get("name") or "") for t in tags))
                                            or _org_category(cat, org_key) in ("swap_service", "bridge")):
        kind = "swap_bridge"  # an instant-swap service's payout wallet: its order records, not a customer account
    return Claim("explorer", owner, kind, conf,
                 (f"public tags: {names}" if names else "flagged by users as a scam") + risk
                 + (f" via {', '.join(d.get('hosts') or [])}" if d.get("hosts") else ""),
                 at=_aware(r.created_at), org_key=org_key, row_id=r.id)


def _profile_line(w: Wallet, prof: dict) -> str:
    parts = []
    if w.held_usd is not None:
        parts.append(f"holds ${w.held_usd:,.0f} on-chain")
    if w.in_trace:
        parts.append(f"${w.taint_usd:,.0f} traced in")
    n = prof.get("tx_count") if prof.get("tx_count") is not None else w.tx_count
    if n is not None:
        parts.append(f"{n:,} transactions")
    if w.counterparties:
        parts.append(f"{w.counterparties} counterpart{'ies' if w.counterparties != 1 else 'y'} in the trace")
    if prof.get("first_at") or prof.get("last_at"):
        parts.append(f"active {(prof.get('first_at') or '?')[:10]} → {(prof.get('last_at') or '?')[:10]}")
    if w.first_in and w.first_out:
        parts.append(f"first funds out {max(0, round((w.first_out - w.first_in).total_seconds() / 60))} min after the "
                     "first in")
    return ", ".join(parts)


def _sweep(w: Wallet) -> tuple[tuple[str, str], int, float] | None:
    """(the wallet the funds were swept to, minutes, share) when ≥ SWEEP_SHARE of the outflow went to one wallet within
    SWEEP_MINUTES of the first arrival."""
    if not w.first_in or not w.first_out or not w.out_to:
        return None
    mins = (w.first_out - w.first_in).total_seconds() / 60
    total = sum(w.out_to.values())
    top = max(w.out_to, key=w.out_to.get)
    share = (w.out_to[top] / total) if total else (1.0 if len(w.out_to) == 1 else 0.0)
    if 0 <= mins <= SWEEP_MINUTES and share >= SWEEP_SHARE:
        return top, round(mins), share
    return None


def _behaviour(w: Wallet, best: dict, prof: dict, tagged: bool = False) -> list[Claim]:
    out: list[Claim] = []
    n = prof.get("tx_count") if prof.get("tx_count") is not None else w.tx_count
    line = _profile_line(w, prof)
    sw = _sweep(w)
    if sw is not None:
        tk, mins, share = sw
        t = best.get(tk)
        pct = f"{round(share * 100)}%"
        pooled = t is not None and (t.kind == "exchange_hot_wallet" or (
            t.kind == "casino" and t.wallet.address_type not in ("deposit", None)))
        if pooled and t.owner:
            # a deposit address sweeps to its service's hot wallet; a wallet paying into a deposit address (or a swap
            # contract) is the customer's own, not the service's
            out.append(Claim("behaviour", t.owner, "casino" if t.kind == "casino" else "exchange_deposit",
                             "M" if t.confidence == "H" else "L",
                             f"swept {pct} of its funds within {mins} min of arrival to {short(tk[1])} ({t.owner}, "
                             f"{KINDS[t.kind]}): a deposit address of {t.owner}", org_key=t.org_key))
        elif t is not None and t.owner is None and t.kind == "exchange_hot_wallet":
            out.append(Claim("behaviour", None, "exchange_deposit", "L",
                             f"swept {pct} within {mins} min to {short(tk[1])}, which behaves like a service's pooled "
                             "wallet: likely a deposit address of the service behind it (identify that wallet's owner)"))
    if w.held_usd is not None and w.held_usd >= POOLED_MIN_USD and w.held_usd > POOLED_FACTOR * max(w.taint_usd, 1.0) \
            and (w.in_trace or w.watched) and not w.frozen:  # an issuer-frozen balance is held, never a float
        out.append(Claim("behaviour", None, "exchange_hot_wallet", "M" if (n or 0) >= BUSY_TX else "L",
                         f"a large balance far above what the trace put in ({line}): a service's pooled / hot wallet, "
                         "not the case's own balance"))
    elif n is not None and n >= 5 * BUSY_TX:
        out.append(Claim("behaviour", None, "exchange_hot_wallet", "L", f"very busy ({line}): a service wallet, not a "
                                                                          "person's"))
    elif w.in_trace and w.entity is None and w.holding and w.address_type in ("eoa", "unknown", "perpetrator") and \
            (n is None or n < QUIET_TX) and not prof.get("is_contract") and not tagged:
        looked = bool(prof)
        out.append(Claim("behaviour", None, "unhosted", "M" if looked and n is not None else "L",
                         (f"no public tag, few transactions ({line})" if looked else
                          f"no service behaviour in the trace ({line}); run the owner lookups to check")
                         + ": likely self-custody"))
    return out


# --------------------------------------------------------------------------- the attribution
@dataclass
class Attribution:
    wallet: Wallet
    owner: str | None = None
    kind: str = "unknown"
    confidence: str = "L"
    source: str | None = None
    org_key: str | None = None
    claims: list[Claim] = field(default_factory=list)
    chosen: Claim | None = None
    notes: list[str] = field(default_factory=list)  # corroborated by / conflicts
    profile: dict = field(default_factory=dict)
    ask: dict = field(default_factory=dict)  # {who, template, href, text, gated, authority}
    looked_up_at: datetime | None = None
    lookup_errors: list[str] = field(default_factory=list)
    # a service wallet's traced funds the trace saw leave it for wallets that are not its service's:
    # address key -> USD; `conflict`: the trace saw them go to a wallet no service owns (the deposit tag disagrees)
    onward: dict = field(default_factory=dict)
    conflict: str | None = None
    router: bool = False  # a non-custodial DEX router / contract: no customer account, its balance is nobody's here

    @property
    def key(self) -> tuple[str, str]:
        return self.wallet.key

    @property
    def kind_label(self) -> str:
        return KINDS.get(self.kind, self.kind)

    @property
    def owner_label(self) -> str:
        return self.owner or "unknown"

    @property
    def service(self) -> bool:
        return self.kind in SERVICE_KINDS

    @property
    def badge(self) -> str:
        """"Binance · exchange hot wallet · M (public explorer tag)"."""
        return (f"{self.owner_label} · {self.kind_label} · {self.confidence}"
                + (f" ({SOURCES.get(self.source, self.source)})" if self.source else ""))

    @property
    def credited_usd(self) -> float:
        """A deposit address's traced funds credited to the account behind it: what the trace saw reach it (over
        observed transfers: an asserted link's amount is no one wallet's), less what it followed on to wallets that
        are not its service's float (one owner per traced dollar), or the balance read there before the service swept
        it, if larger. Survives the sweep (a 0 reading after it)."""
        w = self.wallet
        if self.kind not in DEPOSIT_KINDS:
            return 0.0
        swept = w.swept_usd or 0.0
        if w.in_trace:
            return 0.0 if w.swept_float else round(max(0.0, w.observed_usd - sum(self.onward.values()), swept), 2)
        return round(swept, 2)

    @property
    def upper_usd(self) -> float:
        """What the trace put in, less what it followed on: an upper bound."""
        return round(max(0.0, self.wallet.taint_usd - sum(self.onward.values())), 2)

    @property
    def shared(self) -> str | None:
        """A deposit address the trace reaches only over an asserted link, nothing observed or read there: its traced
        amount is the hub's unquantified residual, given in full to each of the hub's asserted destinations (an
        upper bound, its amount here not observed)."""
        w = self.wallet
        if self.kind not in DEPOSIT_KINDS or not w.asserted or w.swept_float or self.upper_usd < MONEY_MIN_USD:
            return None
        if max(w.held_usd or 0.0, self.credited_usd) >= MONEY_MIN_USD:
            return None
        hub = f" of {short(w.asserted_hub[1])}" if w.asserted_hub else ""
        n = w.asserted_peers
        return (f"shared with {n} other asserted destination{'s' if n != 1 else ''}{hub}" if n else
                f"asserted from {short(w.asserted_hub[1]) if w.asserted_hub else 'an earlier wallet'}, its amount not "
                "observed")

    @property
    def share_usd(self) -> float:
        """The case's money at the wallet: a service float's balance is never the case's, only what was traced in and
        not followed on; a deposit address's is what was credited to the account behind it (its balance, or what
        reached it before the sweep); a non-custodial router's: nothing."""
        w = self.wallet
        if self.router:
            return 0.0
        if self.kind in FLOAT_KINDS and w.held_usd is not None:
            if not (w.in_trace and w.taint_usd):
                return 0.0
            return round(min(w.held_usd, max(0.0, w.observed_usd - sum(self.onward.values()))), 2)
        if self.kind in DEPOSIT_KINDS and not w.swept_float:
            if self.shared:
                return self.upper_usd
            return round(max(w.held_usd or 0.0, self.credited_usd), 2)
        return w.money_usd

    @property
    def share_basis(self) -> str:
        w = self.wallet
        on = (f" (the trace saw ${sum(self.onward.values()):,.0f} leave it, to "
              f"{', '.join(short(k[1]) for k in list(self.onward)[:3])})") if self.onward else ""
        if self.router:
            return ("a non-custodial router: it holds no customer's funds (its balance is not the case's); its records "
                    "only")
        if self.kind in FLOAT_KINDS and w.held_usd is not None:
            of = f"{self.owner}'s" if self.owner else "the service's"
            return (f"traced in (the case's share of {of} float, ${w.held_usd:,.0f} read on-chain){on}"
                    if w.in_trace and w.taint_usd else
                    f"{of} float (${w.held_usd:,.0f} read on-chain): the case's share unknown")
        if self.kind in DEPOSIT_KINDS and self.shared:
            return (f"up to: traced in over an asserted link, {self.shared} (the hub's residual, given in full to "
                    f"each: an upper bound, its amount here not observed){on}")
        cr = self.credited_usd
        if self.kind in DEPOSIT_KINDS and not w.swept_float and cr and cr > (w.held_usd or 0.0):
            if w.swept_usd is not None:  # a sweep was read: the account was credited
                was = ("traced in" if w.in_trace and cr > (w.swept_usd or 0.0) else "read on-chain before the sweep")
                return f"swept: the account was credited ({was}; ${w.held_usd or 0:,.0f} there now){on}"
            if w.held_usd is not None:
                return f"traced in: credited to the account behind it (${w.held_usd:,.0f} read there now){on}"
            return f"traced in: credited to the account behind it (upper bound){on}"
        if self.kind in DEPOSIT_KINDS and self.conflict:
            return self.conflict
        return w.money_basis

    @property
    def share_tag(self) -> str:
        """One word for what `share_usd` rests on (the owners table's Money column; `share_basis` says it in full)."""
        w = self.wallet
        if self.router:
            return "router"
        if w.frozen and w.held_usd is not None:
            return "frozen"
        if self.kind in FLOAT_KINDS and w.held_usd is not None:
            return "traced" if w.in_trace and w.taint_usd else "float"
        if self.kind in DEPOSIT_KINDS and self.shared:
            return "up to"
        cr = self.credited_usd
        if self.kind in DEPOSIT_KINDS and not w.swept_float and cr and cr > (w.held_usd or 0.0):
            return "swept" if w.swept_usd is not None else "traced"
        if self.kind in DEPOSIT_KINDS and self.conflict:
            return "conflict"
        if w.held_usd is not None:
            return "on-chain"
        if w.swept_float:
            return "float"
        if w.in_trace and (w.holding or w.address_type == "deposit"):
            return "traced"
        return "passed" if w.in_trace else "not read"

    @property
    def lines(self) -> list[str]:
        return [c.line for c in self.claims] + self.notes

    @property
    def private_names(self) -> set[str]:
        """Owner names a person typed that name no catalogue organisation (possibly a private individual)."""
        return {c.owner for c in self.claims if c.source == "manual" and c.owner and not c.org_key}

    def as_dict(self, show_notes: bool = True, show_names: bool | None = None) -> dict:
        """`show_notes`: a person's note (view_restricted); `show_names` (default: show_notes): a person's free-text
        owner name, else "a person's attribution"."""
        d = self._as_dict(show_notes)
        names = self.private_names if not (show_notes if show_names is None else show_names) else set()
        return mask_names(d, names) if names else d

    def _as_dict(self, show_notes: bool) -> dict:
        w = self.wallet
        return {"chain": w.chain, "address": w.address, "short": w.short, "label": w.label,
                "owner": self.owner, "owner_label": self.owner_label, "kind": self.kind, "kind_label": self.kind_label,
                "confidence": self.confidence, "confidence_label": CONF_LABELS.get(self.confidence, ""),
                "source": self.source, "source_label": SOURCES.get(self.source or "", "—"), "org_key": self.org_key,
                "badge": self.badge, "lines": [c.line_for(show_notes) for c in self.claims] + self.notes,
                "claims": [c.as_dict(show_notes) for c in self.claims],
                "notes": list(self.notes), "manual": self.source == "manual",
                "money_usd": w.money_usd, "money_basis": w.money_basis, "in_trace": w.in_trace,
                "share_usd": self.share_usd, "share_basis": self.share_basis, "share_tag": self.share_tag,
                "conflict": self.conflict,
"shared": self.shared, "router": self.router,
                "profile": dict(self.profile), "ask": dict(self.ask),
                "looked_up_at": self.looked_up_at.isoformat(timespec="seconds") if self.looked_up_at else None,
                "lookup_errors": list(self.lookup_errors)}


PRIVATE_LABEL = "a person's attribution"


def mask_names(v, names: set[str]):
    """`v` (str / dict / list) with each of `names` replaced by PRIVATE_LABEL."""
    if isinstance(v, str):
        for n in sorted(names, key=len, reverse=True):
            v = re.sub(re.escape(n), PRIVATE_LABEL, v, flags=re.IGNORECASE)
        return v
    if isinstance(v, dict):
        return {k: mask_names(x, names) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [mask_names(x, names) for x in v]
    return v


def _same(a: Claim, b: Claim) -> bool:
    if a.org_key and b.org_key:
        return a.org_key == b.org_key
    return bool(a.owner and b.owner and a.owner.casefold() == b.owner.casefold())


def resolve(w: Wallet, claims: list[Claim]) -> Attribution:
    att = Attribution(wallet=w, claims=list(claims))
    manual = next((c for c in claims if c.source == "manual"), None)
    pick = manual or max(claims, key=lambda c: (CONF_RANK.get(c.confidence, 0), c.owner is not None,
                                                c.kind != "unknown", SOURCE_RANK.get(c.source, 0)), default=None)
    if pick is None:
        return att
    att.chosen, att.owner, att.kind, att.confidence, att.source, att.org_key = (
        pick, pick.owner, pick.kind, pick.confidence, pick.source, pick.org_key)
    if pick.owner:
        agree = sorted({c.source for c in claims if c is not pick and c.source != pick.source and _same(c, pick)})
        if agree and pick.source != "manual" and pick.confidence != "H":
            att.confidence = "H" if pick.confidence == "M" else "M"
        if agree:
            att.notes.append(f"corroborated by {', '.join(SOURCES[s] for s in agree)}")
        if att.kind == "unknown":
            att.kind = next((c.kind for c in claims if c.kind != "unknown" and _same(c, pick)), "unknown")
        if att.org_key is None:
            att.org_key = next((c.org_key for c in claims if c.org_key and _same(c, pick)), None)
    for c in claims:
        if c.owner and pick.owner and not _same(c, pick):
            att.notes.append(f"conflicting: {SOURCES.get(c.source, c.source)} says {c.owner}"
                             + (" (a person's attribution wins)" if pick.source == "manual" else ""))
    return att


def stored(db: Session, case: Case) -> dict[tuple[str, str], dict[str, Row]]:
    """{wallet key: {source: its latest row}} (manual, explorer)."""
    out: dict[tuple[str, str], dict[str, Row]] = {}
    for r in db.scalars(select(Row).where(Row.case_id == case.id).order_by(Row.id)):
        out.setdefault(key_of(r.chain, r.address), {})[r.source] = r
    return out


def attribute(db: Session, case: Case, *, run=None, freeze_rows: list[dict] | None = None, auths: list | None = None,
              requester: str | None = None, le_pick=None, asks: bool = True) -> dict[tuple[str, str], Attribution]:
    """Every wallet's owner (module doc), most money first. Reads the database only (never the network). Without
    `auths` the case's authorities, requester and LE pick are read as the Recovery plan reads them
    (recovery.ask_context), so every page shows the same ask, link and LE-only gate."""
    from app import services

    run = run if run is not None else services.latest_run(db, case)
    if asks and auths is None:
        try:
            from app.blocks import recovery

            ctx = recovery.ask_context(db, case, run=run)
            auths, requester, le_pick = ctx["auths"], requester or ctx["requester"], le_pick or ctx["le_pick"]
        except Exception as err:  # noqa: BLE001 - no authorities: the asks name no letter
            log.warning("wallet owners: case authorities failed for case %s (%s)", case.id, type(err).__name__)
    if freeze_rows is None:
        try:
            from app.freeze import service as fz

            freeze_rows = fz.wallet_rows(db, case)
        except Exception:  # noqa: BLE001 - no readings: the trace's values
            freeze_rows = []
    ws = wallets(db, case, run=run, freeze_rows=freeze_rows)
    rows = stored(db, case)
    for k in rows:  # a wallet a person marked (or looked up) that is no longer in the trace stays listed
        if k not in ws:
            ws[k] = Wallet(chain=k[0], address=k[1])
    cat = _catalogue()
    addrs = catalogue_addresses(cat)
    claims: dict[tuple[str, str], list[Claim]] = {}
    profiles: dict[tuple[str, str], dict] = {}
    for k, w in ws.items():
        cs = [c for c in (_catalogue_claim(w, addrs), _trace_claim(w, cat)) if c is not None]
        for src in ("explorer", "manual"):
            r = rows.get(k, {}).get(src)
            c = _row_claim(r, cat) if r is not None else None
            if c is not None:
                cs.append(c)
        ex = rows.get(k, {}).get("explorer")
        profiles[k] = dict((ex.detail or {}).get("profile") or {}) if ex is not None else {}
        claims[k] = cs
    best = {k: resolve(w, claims[k]) for k, w in ws.items()}
    out: dict[tuple[str, str], Attribution] = {}
    for k, w in ws.items():
        ex = rows.get(k, {}).get("explorer")
        tagged = ex is not None and bool((ex.detail or {}).get("tags") or ex.owner or (ex.kind or "unknown") != "unknown")
        cs = claims[k] + _behaviour(w, best, profiles[k], tagged)
        att = resolve(w, cs)
        att.profile = profiles[k]
        if ex is not None:
            att.looked_up_at = _aware(ex.created_at)
        e = w.entity
        att.router = att.kind == "swap_bridge" and (
            (e is not None and e.category == EntityCategory.DEX and not e.freeze_capable)
            or _org_category(cat, att.org_key) == "dex")
        out[k] = att
    _onward(out)
    if asks:
        _asks(case, out, auths, requester, le_pick, cat)
    return dict(sorted(out.items(), key=lambda kv: (-kv[1].wallet.money_usd, kv[0])))


def _same_service(a: Attribution, b: Attribution) -> bool:
    """`b` is one of `a`'s own service's wallets (its float, a sweep into it, the same entity / owner)."""
    if b.wallet.swept_float:
        return True
    if a.wallet.entity is not None and b.wallet.entity is not None and a.wallet.entity.id == b.wallet.entity.id:
        return True
    return bool(b.service and a.owner and b.owner and (a.owner.casefold() == b.owner.casefold()
                                                       or (a.org_key and a.org_key == b.org_key)))


def _sent_on(atts: dict, att: Attribution) -> tuple[dict, dict]:
    """(onward, plain) of a service wallet the trace followed on: `onward` {address key: USD} the case funds the
    trace saw leave it for wallets not of its service, following its service's own float wallets the trace followed on
    (each hop scaled by the share of that wallet's taint the funds were); a wallet of its service is the sweep (what
    stayed with the service). `plain`: the part of it that reached wallets no service owns (directly or past its
    service's wallets). The wallet's own valuation only: what other moves count is the Recovery plan's (one group of
    moves on the same funds counts once there)."""
    on: dict = {}
    plain: dict = {}
    todo = [(att.wallet, 1.0, True)]  # (wallet, share of its taint that is att's, still att's money)
    seen = {att.key}
    while todo:
        w, frac, mine = todo.pop()
        for d, v in w.out_taint.items():
            b = atts.get(d)
            if v <= 0 or b is None or not b.wallet.in_trace or d in seen:
                continue
            usd = v * frac
            if not _same_service(att, b):
                if mine:
                    on[d] = on.get(d, 0.0) + usd
                if not b.service:
                    plain[d] = plain.get(d, 0.0) + usd
                continue
            deposit = b.kind in DEPOSIT_KINDS and not b.wallet.swept_float  # past another deposit: not att's
            bw = b.wallet
            if any(x != att.key and x in atts and atts[x].wallet.in_trace for x in bw.out_taint):
                seen.add(d)  # the trace followed it on: follow it
                todo.append((bw, frac * min(1.0, v / bw.taint_usd) if bw.taint_usd > 0 else frac, mine and not deposit))
    return {k: round(v, 2) for k, v in on.items()}, plain


def _onward(atts: dict) -> None:
    """A service wallet the trace followed on (a deposit address, a hot wallet, a swap service): its share is what
    stayed, never the funds the trace saw leave it for wallets not of its service (also past another wallet of its
    service). A deposit address whose funds reached a wallet no
    service owns: its tag conflicts with what the trace saw (a person checks it); a float read on-chain paying them
    out so: the case's share there is only what stayed."""
    for att in atts.values():
        w = att.wallet
        if att.kind not in SERVICE_KINDS or not w.in_trace or w.swept_float:
            continue
        att.onward, plain = _sent_on(atts, att)
        usd = sum(plain.values())
        if usd < MONEY_MIN_USD or (att.kind in FLOAT_KINDS and w.held_usd is None):
            continue  # a float with no reading has no value of its own here (nothing to rank on money moved on)
        where = ", ".join(short(d[1]) for d in list(plain)[:3])
        att.conflict = (f"the trace saw ${usd:,.0f} go on to {where} (a wallet no service owns): the "
                        f"{att.kind_label} tag conflicts with the trace, check it" if att.kind in DEPOSIT_KINDS else
                        f"the trace saw ${usd:,.0f} of the case's funds go on from it to {where} (a wallet no service "
                        "owns): only what stayed is the case's share here")
        if att.conflict not in att.notes:
            att.notes.append(att.conflict)


# --------------------------------------------------------------------------- who to ask
def _note_href(base: str, note: str) -> str:
    path, _, frag = base.partition("#")
    return f"{path}{'&' if '?' in path else '?'}note={quote(note, safe='')}" + (f"#{frag}" if frag else "")


def _authority_maps(auths: list | None, cat) -> tuple[dict, dict, dict, dict]:
    from app.blocks import status as bs
    from app.domain import directory

    by_entity, by_org, by_name, issuers = {}, {}, {}, {}
    for a in auths or []:
        if a.is_le or a.is_adviser or a.virtual:
            continue
        if a.entity is not None:
            by_entity.setdefault(a.entity.id, a)
        by_name.setdefault(a.name.casefold(), a)
        try:
            o = directory.org_for(a, cat) if cat is not None else None
        except Exception:  # noqa: BLE001
            o = None
        if o is not None:
            by_org.setdefault(o.key, a)
        iss = bs._issuer_of(a)
        if iss:
            issuers.setdefault(iss, a)
    return by_entity, by_org, by_name, issuers


def _asks(case: Case, atts: dict, auths: list | None, requester: str | None, le_pick, cat) -> None:
    from app.domain import evidence_requirements as er

    by_entity, by_org, by_name, issuers = _authority_maps(auths, cat)
    orgs = getattr(cat, "by_key", {}) if cat is not None else {}
    cache: dict = {}

    def held(a, owner) -> frozenset:  # the orders on file naming the provider (its binding paths open: no LE gate)
        k = a.key if a is not None else (owner or "").casefold()
        if k not in cache:
            try:
                cache[k] = er.held_instruments(case, er.provider_names(a) if a is not None else [owner])
            except Exception:  # noqa: BLE001 - no orders read: the gate as the playbook says
                cache[k] = frozenset()
        return cache[k]
    for att in atts.values():
        att.ask = ask_for(case.id, att, by_entity=by_entity, by_org=by_org, by_name=by_name, issuers=issuers,
                          requester=requester or "pi", le_pick=le_pick, orgs=orgs, held=held)


def ask_for(cid: int, att: Attribution, *, by_entity: dict, by_org: dict, by_name: dict, issuers: dict,
            requester: str, le_pick=None, orgs: dict | None = None, held=None) -> dict:
    """Who to ask about the wallet, with which template (module doc). `held(authority, owner)`: the instrument types
    of the orders on file naming that provider (they open its binding paths)."""
    w = att.wallet
    owner = att.owner
    a = None
    if w.entity is not None and att.source in ("trace", "behaviour", "catalogue") and owner == w.entity.name:
        a = by_entity.get(w.entity.id)
    a = a or (by_org.get(att.org_key) if att.org_key else None) or (by_name.get(owner.casefold()) if owner else None)
    org = (orgs or {}).get(att.org_key) if att.org_key else None
    pb = getattr(org, "playbook", None)
    if pb is None and a is not None:
        from app.blocks import status as bs

        pb = bs._playbook(a)[0]
    chain_q = w.chain  # the letter's freeze=<chain>:<address> (correspondence._FREEZE_ADDR)
    base = f"/cases/{cid}/authorities/{a.key}" if a is not None else None
    # what the letter concerns (meta.about: the request gate, app.domain.request_gate, compares it with the open draft
    # and the requests already out), and the request already out it follows up (ref=)
    about_q = f"about={chain_q}:{w.address}"
    if att.kind == "issuer":
        return {"who": None, "template": None, "href": None, "gated": False,
                "text": f"{owner or 'The issuer'}'s own token contract: nothing to freeze at this address"}
    if att.kind == "non_custodial":
        return {"who": None, "template": None, "href": None, "gated": False,
                "text": f"{owner + ': a' if owner else 'A'} mixer / non-custodial protocol: no account to freeze and "
                        "nobody to ask; follow the output (re-trace from it to the next service or issuer)"}
    if att.kind == "swap_bridge" and w.entity is not None and w.entity.category == EntityCategory.DEX \
            and not w.entity.freeze_capable:
        return {"who": None, "template": None, "href": None, "gated": False,
                "text": f"{owner + ': a' if owner else 'A'} non-custodial router: no account to freeze; the swap "
                        "output is followed by the trace (its issuer or the next service is the lever)"}
    if att.kind in SERVICE_KINDS and owner:
        gate = pb.gate(requester, held(a, owner) if held else frozenset(), name=owner).reason if pb is not None else None
        from app.domain import correspondence as desk

        sent = desk.sent_references(a) if a is not None else []  # a request already open: follow it up
        ref_q = f"&ref={sent[0]['value']}" if sent else ""
        if att.kind in ("exchange_deposit", "casino"):
            what = f"freeze the account credited by deposit address {w.short}" + (
                f" (an urgent freeze request quoting our letter of {sent[0].get('label') or 'an earlier date'})" if sent
                else "")
            href = (f"{base}?template=info_request&freeze={chain_q}:{w.address}"
                    + (f"&ref={sent[0]['value']}" if sent else "") + "#generate") if base else None
        elif att.kind == "exchange_hot_wallet":
            what = (f"identify the customer account the funds sent to {w.short} were credited to (the tx hashes) and "
                    "freeze it; not the issuer: the wallet is its float")
            note = (f"Our trace shows the funds reached your wallet {w.address} ({w.chain}). Please identify the "
                    "customer account they were credited to, freeze it and preserve its records.")
            href = _note_href(f"{base}?template=info_request&{about_q}{ref_q}#generate", note) if base else None
        else:
            what = f"preserve the order records behind {w.short} and say where the payout went"
            note = (f"Funds of the case passed through {w.address} ({w.chain}), your service. Please preserve the "
                    "order records (IP, device, payout destination) and tell us where the payout went.")
            href = _note_href(f"{base}?template=info_request&{about_q}{ref_q}#generate", note) if base else None
        if gate:
            le_href, hint = le_pick(pb, att.org_key) if le_pick else (None, "")
            return {"who": f"LE (for {owner})", "template": "le_cover", "href": le_href, "gated": True,
                    "authority": a.key if a is not None else None,
                    "text": f"{gate}: brief LE to have {owner} {what}.{hint}"}
        return {"who": owner, "template": "info_request", "href": href, "gated": False,
                "authority": a.key if a is not None else None,
                "text": f"Ask {owner} to {what}"}  # no counterparty yet: the Recovery plan says to write outside Aegis
    if att.kind == "unhosted":
        iss = [issuers[k] for k in ("Tether", "Circle") if k in issuers]
        if w.money_usd < MONEY_MIN_USD and w.in_trace:
            return {"who": None, "template": None, "href": None, "gated": False,
                    "text": "Self-custody, and the funds moved on: nothing is held here (follow where they went)"}
        syms = w.stables
        if syms:  # only the issuers of the tokens it holds (largest balance first), else of the tokens it received
            iss = [issuers[STABLE_ISSUER[s]] for s in syms if STABLE_ISSUER.get(s) in issuers]
        if w.holds_stable and iss:
            first = iss[0]
            what = " / ".join(syms) if syms else "your token"
            note = (f"The wallet {w.address} ({w.chain}) holds funds of the case in {what}. Please blacklist it "
                    "and preserve its records.")
            return {"who": first.name, "template": "info_request", "gated": False, "authority": first.key,
                    "href": _note_href(f"/cases/{cid}/authorities/{first.key}?template=info_request&about={chain_q}:"
                                       f"{w.address}#generate", note),
                    "text": f"Self-custody: ask {' / '.join(i.name for i in iss)} to blacklist it (issuer blacklist)"}
        return {"who": None, "template": None, "href": f"/cases/{cid}/recovery-plan#owners", "gated": False,
                "text": "Self-custody: nobody can freeze it there; watch it so the next deposit at a service names "
                        "who to ask"}
    if att.service and not owner:
        return {"who": None, "template": None, "href": f"/cases/{cid}/recovery-plan#owners", "gated": False,
                "text": "A service's wallet, owner not identified: run the owner lookups or mark the owner, then ask "
                        "that service (not the issuer)"}
    if owner:
        return {"who": owner, "template": "info_request", "gated": False,
                "authority": a.key if a is not None else None,
                "href": f"{base}?template=info_request&{about_q}#generate" if base else None,
                "text": f"Ask {owner} what this wallet is and to preserve its records"}
    return {"who": None, "template": None, "href": f"/cases/{cid}/recovery-plan#owners", "gated": False,
            "text": "Identify the owner: run the owner lookups (public explorer tags), or mark it yourself"}


# --------------------------------------------------------------------------- consent
def setting(case: Case) -> dict:
    """The case's owner-lookup setting. ON BY DEFAULT: a case nobody switched off looks
    up its wallets' public tags on the current explorer endpoints ("default": the deployment's allow-list, new hosts
    included); a case admin's explicit off stays off, an explicit on records the consented hosts as before."""
    v = getattr(case, "owner_lookup_consent", None)
    if isinstance(v, dict) and ("enabled" in v):
        return dict(v)
    return {**(dict(v) if isinstance(v, dict) else {}), "enabled": True, "default": True}


def egress_plan(settings=None) -> list[dict]:
    """What each public endpoint receives when the lookups run (shown before consent, kept with it). Hosts only."""
    settings = _settings(settings)
    meta = urlsplit(settings.aegis_owner_metadata_url or "").hostname or ""
    rows = [{"host": meta, "configured": bool(meta), "chains": "Ethereum, Base, Arbitrum One, Polygon PoS, OP Mainnet",
             "sends": "each looked-up EVM wallet address and its chain id (public tags)", "auth": None}]
    for chain, host in explorer.BLOCKSCOUT_HOSTS.items():
        rows.append({"host": host, "configured": True, "chains": chain,
                     "sends": "each looked-up wallet address (address details, transaction counters)", "auth": None})
    tron = urlsplit(settings.aegis_owner_tronscan_url or "").hostname or ""
    key = bool((settings.tronscan_api_key or "").strip())
    rows.append({"host": tron, "configured": bool(tron) and key, "chains": "TRON",
                 "sends": "each looked-up TRON wallet address (account tags, transaction counts)",
                 "auth": "TRON-PRO-API-KEY header" if key else None,
                 "note": None if key else "TRONSCAN_API_KEY not set: TRON wallets are not looked up"})
    return rows


def consent_hosts(plan: list[dict]) -> list[str]:
    return sorted({r["host"] for r in plan if r.get("configured") and r.get("host")})


def is_enabled(case: Case, settings=None) -> bool:
    return bool(setting(case).get("enabled")) and not _settings(settings).owner_lookups_disabled


def new_hosts(case: Case, settings=None) -> list[str]:
    st = setting(case)
    if not st.get("enabled") or st.get("default"):  # the default follows the deployment's allow-list
        return []
    return sorted(set(consent_hosts(egress_plan(settings))) - set(st.get("hosts") or []))


def set_enabled(db: Session, case: Case, user: User | None, enabled: bool, *, settings=None) -> dict:
    """On (recording the plan the admin consented to; also how an admin confirms changed endpoints) or off. Commits;
    the route audits."""
    st = setting(case)
    now = _now().isoformat(timespec="seconds")
    uid = user.id if user is not None else None
    if enabled:
        plan = egress_plan(settings)
        st = {"enabled": True, "by": uid, "at": now, "hosts": consent_hosts(plan), "plan": plan}
    else:
        st.update(enabled=False, disabled_by=uid, disabled_at=now)
    case.owner_lookup_consent = st
    db.commit()
    return st


def status(case: Case, settings=None) -> dict:
    settings = _settings(settings)
    st = setting(case)
    return {"enabled": bool(st.get("enabled")), "default": bool(st.get("default")),
            "auto": settings.owner_lookups_auto, "deployment_disabled": settings.owner_lookups_disabled,
            "consent_outdated": new_hosts(case, settings), "consent_hosts": list(st.get("hosts") or []),
            "enabled_at": st.get("at"), "last_run": st.get("last_run"), "plan": egress_plan(settings)}


# --------------------------------------------------------------------------- running the lookups
@dataclass
class LookupReport:
    looked_up: int = 0  # lookups stored
    tagged: int = 0  # of them, with a public tag
    errors: int = 0  # wallets whose every call failed (nothing stored; an earlier lookup stays)
    cached: int = 0  # skipped: looked up within AEGIS_OWNER_CACHE_HOURS
    skipped: int = 0  # a chain without an explorer (Bitcoin, Solana; TRON without TRONSCAN_API_KEY)
    requests: int = 0
    hosts: list[str] = field(default_factory=list)

    def counts(self) -> dict:
        return {"looked_up": self.looked_up, "tagged": self.tagged, "errors": self.errors, "cached": self.cached,
                "skipped": self.skipped, "requests": self.requests, "hosts": self.hosts}


def _store(db: Session, case: Case, got: explorer.Lookup, cat) -> Row:
    org = None
    if got.owner or got.tags:
        url = next((t.get("url") for t in got.tags if t.get("url")), None)
        org = match_org(got.owner, cat=cat) or (match_org(None, url, cat=cat) if url else None)
    owner = org.name if org is not None else got.owner
    kind = got.kind or (CATEGORY_KIND.get(org.category) if org is not None else None) or "unknown"
    if org is not None and org.category == "dex" and kind in ("swap_bridge", "exchange_hot_wallet", "exchange_deposit"):
        kind = "non_custodial"  # the catalogue says the protocol is a DEX: no account behind its router
    detail = {"tags": got.tags, "profile": got.profile, "hosts": sorted(set(got.hosts)), "sha256": got.sha256,
              "retrieved_at": got.retrieved_at.isoformat(timespec="seconds"), "errors": got.errors,
              "org_key": org.key if org is not None else None, "raw_owner": got.owner}
    row = Row(case_id=case.id, chain=got.chain, address=got.address, owner=owner, kind=kind,
              confidence=got.confidence, source="explorer", detail=detail, created_at=got.retrieved_at)
    db.add(row)
    return row


def run_lookups(db: Session, case: Case, *, http=None, settings=None, transport=None, force: bool = False,
                trigger: str = "manual", only: set[tuple[str, str]] | None = None) -> LookupReport:
    """Look up the public tags of the case's wallets (most money first, at most AEGIS_OWNER_MAX_WALLETS; a wallet a
    person marked is never sent, nor one whose freeze watch is TLP:RED / TLP:AMBER+STRICT; one looked up within AEGIS_OWNER_CACHE_HOURS is skipped unless `force`). Raises
    OwnerLookupsDisabled (nothing sent) unless a case admin consented to the current endpoints. Commits."""
    settings = _settings(settings)
    if settings.owner_lookups_disabled:
        raise OwnerLookupsDisabled("deployment_disabled")
    if not setting(case).get("enabled"):
        raise OwnerLookupsDisabled("case_setting_off")
    if new_hosts(case, settings):
        raise OwnerLookupsDisabled("consent_outdated")
    rep = LookupReport()
    atts = attribute(db, case, asks=False)
    rows = stored(db, case)
    now = _now()
    fresh = timedelta(hours=max(0.0, settings.aegis_owner_cache_hours))
    todo: list[Attribution] = []
    for k, att in atts.items():
        w = att.wallet
        if (only is not None and k not in only) or (only is None and w.money_usd < MONEY_MIN_USD and not w.in_trace):
            continue
        if "manual" in rows.get(k, {}) and not (rows[k]["manual"].detail or {}).get("cleared"):
            continue  # a person decided: nothing to send
        if (w.tlp or "").strip().upper() in RESTRICTED_TLP:
            rep.skipped += 1  # a watch marked TLP:RED / AMBER+STRICT: its address never leaves the organisation
            continue
        if not explorer.supported(w.chain, settings):
            rep.skipped += 1
            continue
        ex = rows.get(k, {}).get("explorer")
        if ex is not None and not force and now - (_aware(ex.created_at) or now) < fresh:
            rep.cached += 1
            continue
        todo.append(att)
    todo = todo[:max(1, settings.aegis_owner_max_wallets)]
    own = http is None
    http = http or FreezeHttp(settings, transport=transport, allowed_domains=explorer.ALLOWED_DOMAINS,
                              user_agent=explorer.USER_AGENT)
    cat = _catalogue()
    try:
        for att in todo:
            got = explorer.lookup(http, settings, att.wallet.chain, att.wallet.address)
            if not got.ok:
                rep.errors += 1
                continue
            _store(db, case, got, cat)
            rep.looked_up += 1
            rep.tagged += bool(got.tags)
    finally:
        rep.requests, rep.hosts = http.requests, sorted(http.hosts)
        if own:
            http.close()
    st = setting(case)
    st["last_run"] = {"at": now.isoformat(timespec="seconds"), "trigger": trigger, **rep.counts()}
    case.owner_lookup_consent = st
    db.commit()
    return rep


def auto_lookups(db: Session, case: Case, *, trigger: str = "trace", settings=None,
                 transport=None) -> LookupReport | None:
    """The automatic owner lookups (AEGIS_OWNER_LOOKUPS_AUTO, on by default): after a trace run and from the
    scheduler, for a case whose setting is on. Never raises: a failure is logged and the next run tries again."""
    settings = _settings(settings)
    if not settings.owner_lookups_auto or not is_enabled(case, settings) or new_hosts(case, settings):
        return None
    try:
        return run_lookups(db, case, settings=settings, transport=transport, trigger=trigger)
    except Exception as err:  # noqa: BLE001 - the trace / scheduler never fails on a lookup
        db.rollback()
        import logging

        logging.getLogger(__name__).warning("owner lookups failed for case %s (%s)", case.id, type(err).__name__)
        return None


def due_cases(db: Session, *, now: datetime | None = None, settings=None) -> list[Case]:
    """Open cases whose automatic lookups are due: setting on and the last run older than AEGIS_OWNER_CACHE_HOURS."""
    from sqlalchemy import select as _select

    settings = _settings(settings)
    if not settings.owner_lookups_auto or settings.owner_lookups_disabled:
        return []
    now = now or _now()
    out = []
    for case in db.scalars(_select(Case)).all():
        if getattr(case, "status", None) is not None and str(getattr(case.status, "value", case.status)) == "closed":
            continue
        if not is_enabled(case, settings):
            continue
        last = (setting(case).get("last_run") or {}).get("at")
        try:
            at = datetime.fromisoformat(last) if last else None
        except ValueError:
            at = None
        if at is None or now - (_aware(at) or now) >= timedelta(hours=max(1.0, settings.aegis_owner_cache_hours)):
            out.append(case)
    return out


# --------------------------------------------------------------------------- a person's attribution
def mark(db: Session, case: Case, user: User | None, *, chain: str, address: str, owner: str | None, kind: str,
         note: str | None = None, clear: bool = False) -> Row:
    """Record a person's attribution (it wins over every other source) or withdraw it (`clear`). ValueError on a bad
    chain / address / kind or an attribution naming neither an owner nor a kind. Flushes; the route audits and
    commits."""
    c, a = normalise(chain, address)
    owner = re.sub(r"\s+", " ", (owner or "").strip())[:255] or None
    note = (note or "").strip()[:1000] or None
    if clear:
        row = Row(case_id=case.id, chain=c, address=a, owner=None, kind="unknown", confidence="H", source="manual",
                  detail={"cleared": True}, created_by=user.id if user is not None else None, created_at=_now())
        db.add(row)
        db.flush()
        return row
    kind = (kind or "").strip()
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    if owner is None and kind == "unknown":
        raise ValueError("name the owner or say what the wallet is")
    org = match_org(owner) if owner else None
    if org is not None and owner.casefold() == org.name.casefold():
        owner = org.name
    row = Row(case_id=case.id, chain=c, address=a, owner=owner, kind=kind, confidence="H", source="manual",
              detail={"note": note, "org_key": org.key if org is not None else None},
              created_by=user.id if user is not None else None, created_at=_now())
    db.add(row)
    db.flush()
    return row


# --------------------------------------------------------------------------- readers for the other pages
def by_key(db: Session, case: Case, *, show_notes: bool = False, show_names: bool | None = None,
           **kw) -> dict[tuple[str, str], dict]:
    """{wallet key: Attribution.as_dict()}; {} on any failure (a page always renders)."""
    try:
        return {k: a.as_dict(show_notes, show_names) for k, a in attribute(db, case, **kw).items()}
    except Exception:
        log.exception("wallet owners failed for case %s", getattr(case, "id", None))
        return {}


def annotate_rows(db: Session, case: Case, rows: list[dict], *, show_notes: bool = False,
                  show_names: bool | None = None) -> list[dict]:
    """The freeze status rows with their wallet's `owner` (Attribution.as_dict(), or None)."""
    owners = by_key(db, case, freeze_rows=rows, show_notes=show_notes, show_names=show_names)
    for r in rows:
        r["owner"] = owners.get(key_of(r["chain"], r["address"]))
    return rows
