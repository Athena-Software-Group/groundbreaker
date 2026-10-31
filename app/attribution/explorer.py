"""Public explorer tags and activity counters for one wallet: Blockscout (EVM chains) and Tronscan (TRON).

    http = FreezeHttp(settings, transport=…, allowed_domains=ALLOWED_DOMAINS, user_agent=USER_AGENT)
    got = lookup(http, settings, "ethereum", "0x…")   # Lookup: tags, owner, kind, confidence, profile, hashes

* **EVM** (ethereum, base, arbitrum, polygon, optimism): the public tags come from Blockscout's metadata service
  (`GET {AEGIS_OWNER_METADATA_URL}/api/v1/metadata?addresses=<a>&chainId=<id>`: `addresses.<a>.tags[]` with `name`,
  `slug`, `tagType` name | generic | protocol | classifier | information | note, and `meta`, a JSON string whose
  `main_entity` names the owner), the contract / scam flags and the token from the chain's Blockscout instance
  (`GET https://<chain>.blockscout.com/api/v2/addresses/<a>`: `is_contract`, `is_scam`, `name`, `token`,
  `public_tags`, `metadata`) and the activity from `/api/v2/addresses/<a>/counters` (`transactions_count`,
  `token_transfers_count`). An address Blockscout has never seen answers 404: no tag, no activity.
* **TRON**: Tronscan's account API (`GET {AEGIS_OWNER_TRONSCAN_URL}/api/accountv2?address=<a>`, header
  `TRON-PRO-API-KEY`; it answers 401 without one, so nothing is sent while TRONSCAN_API_KEY is unset): `publicTag`,
  `addressTag`, `redTag` (a scam / phishing mark), `blueTag`, `greyTag`, `feedbackRisk` (user feedback: kept as a
  note, `feedback_risk`, never a scam mark), `totalTransactionCount`,
  `transactions_in` / `transactions_out`, `date_created` / `latest_operation_time` (ms since the epoch). Fields are
  read defensively: one missing is no tag, never an error.
* Every call goes through app.freeze.transport (https to ALLOWED_DOMAINS only, no redirects, retries with backoff on
  429 / 5xx, a per-host rate limiter, a breaker for a host that is down, a short cache). The sha256 of each raw
  answer is kept. A public tag is a third party's label: confidence M (a scam mark L), never H.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.freeze.issuers import EVM_CHAIN_IDS
from app.freeze.transport import FreezeHttp, FreezeHttpError

ALLOWED_DOMAINS = ("blockscout.com", "tronscanapi.com")
USER_AGENT = "Aegis owner-lookup (Athena Software Group, Inc.)"
BLOCKSCOUT_HOSTS = {"ethereum": "eth.blockscout.com", "base": "base.blockscout.com",
                    "arbitrum": "arbitrum.blockscout.com", "polygon": "polygon.blockscout.com",
                    "optimism": "optimism.blockscout.com"}
CHAINS = (*BLOCKSCOUT_HOSTS, "tron")
SCAM = re.compile(r"(?<![a-z])(scam|phish|fraud|hacker|hacked|hack\b|exploit|drainer|fake|heist|ponzi|stolen|"
                  r"sanction|ofac\b)", re.IGNORECASE)
# a mixer / privacy protocol or a non-custodial DEX router / aggregator: no account behind it, nobody to ask
MIXER = re.compile(r"\b(tornado(?:[\s.]?cash)?|mixer|mixing|tumbler|railgun|coin\s?join|wasabi|samourai|whirlpool|"
                   r"privacy\s+pools?|sinbad|blender|chipmixer|aztec|uniswap|sushiswap|pancakeswap|1inch|paraswap|"
                   r"0x\s+(?:protocol|exchange\s+proxy)|cow\s?swap|cow\s+protocol|kyberswap|odos|openocean|curve(?:\.fi)?|"
                   r"balancer|sunswap|jupiter|metamask\s+swaps?)\b", re.IGNORECASE)
# an instant-swap service: its "Payout" / "Hot" wallet pays out orders (the order records, not a customer account)
INSTANT_SWAP = re.compile(r"\b(fixed\s?float|change\s?now|side\s?shift|simple\s?swap|exch|swft|letsexchange|stealthex|"
                          r"changelly|godex|quickex|exolix|swapzone|flyp\.?me|instant\s+swap)\b", re.IGNORECASE)
CASINO = re.compile(r"\b(casino|gambl\w*|betting|sportsbook|bet)\b", re.IGNORECASE)
SWAP = re.compile(r"\b(bridge|swap|swaps|dex|router|aggregator|amm|instant exchange|cross-chain)\b", re.IGNORECASE)
DEPOSIT = re.compile(r"\bdeposit\b", re.IGNORECASE)
SERVICE = re.compile(r"\b(hot[\s_-]?wallet|cold[\s_-]?wallet|exchange|cex|custody|custodian|omnibus|"
                     r"withdrawal|payout)\b", re.IGNORECASE)
ISSUER = re.compile(r"\b(issuer|treasury)\b", re.IGNORECASE)
STABLES = {"USDT", "USDC"}
OWNER_TAIL = re.compile(r"(\s*[:|(\-–—]\s*.*$)|(\s+\d+$)|(\s+(hot|cold|deposit|wallet|exchange)\b.*$)", re.IGNORECASE)


@dataclass
class Lookup:
    chain: str
    address: str
    tags: list[dict] = field(default_factory=list)  # {name, type, source}
    owner: str | None = None
    kind: str | None = None  # app.attribution.service.KINDS key, None: the tags say nothing
    confidence: str = "M"
    profile: dict = field(default_factory=dict)  # tx_count, token_transfers, is_contract, is_scam, first_at, last_at …
    hosts: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    retrieved_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    errors: list[str] = field(default_factory=list)  # reason codes of calls that failed (no URL, no key)
    requests: int = 0

    @property
    def ok(self) -> bool:
        """At least one call answered (a lookup whose every call failed is not stored: it never hides a good one)."""
        return bool(self.sha256) or bool(self.profile.get("unseen"))


def supported(chain: str, settings) -> bool:
    if chain == "tron":
        return bool((settings.tronscan_api_key or "").strip())
    return chain in BLOCKSCOUT_HOSTS


def owner_from(name: str | None) -> str | None:
    """"Binance: Hot Wallet" / "Binance 14" / "Binance-Hot 3" -> "Binance"."""
    n = (name or "").strip()
    if not n:
        return None
    out = OWNER_TAIL.sub("", n).strip(" -_:")
    return out[:120] or None


HOT_WORDS = re.compile(r"\b(hot|payout|withdraw\w*|cold|treasury|operator)\b", re.IGNORECASE)
SERVICE_TAG_KINDS = frozenset({"exchange_deposit", "exchange_hot_wallet", "casino", "swap_bridge"})


def _kind_of(text: str) -> str | None:
    if MIXER.search(text):
        return "non_custodial"
    if INSTANT_SWAP.search(text):
        return "swap_bridge"
    if CASINO.search(text):  # a casino's own hot / payout wallet is its float, not one depositor's address
        return "exchange_hot_wallet" if HOT_WORDS.search(text) and not DEPOSIT.search(text) else "casino"
    if SWAP.search(text):
        return "swap_bridge"
    if DEPOSIT.search(text):
        return "exchange_deposit"
    if SERVICE.search(text):
        return "exchange_hot_wallet"
    if ISSUER.search(text):
        return "issuer"
    return None  # a name only: the catalogue (or a person) says what it is


def classify(tags: list[dict], *, is_scam: bool = False, token_symbol: str | None = None,
             is_contract: bool | None = None) -> tuple[str | None, str | None, str]:
    """(owner, kind, confidence) from public tags: a casino / swap / deposit / exchange word -> that kind; the owner
    from a name tag's `main_entity`, else a protocol tag, else the name tag's leading words. The issuer's own token
    contract (USDT / USDC) -> issuer. A mixer / privacy protocol or a DEX router / aggregator -> non_custodial (no
    account to freeze), before any swap / deposit word. A scam mark (`is_scam`: the explorer's own flag, never a
    user-feedback count; a red tag; a scam word) -> unhosted (likely the scammer's, L), unless another tag names a
    service: an exchange deposit address scammers use is the scammer's account at that exchange (ask the exchange),
    so the service tag's owner and kind stay."""
    clean = [t for t in tags if t.get("name") and t.get("type") != "red" and not SCAM.search(str(t["name"]))]
    names = [str(t.get("name") or "") for t in tags if t.get("name")]
    text = " | ".join(names)
    clean_text = " | ".join(str(t["name"]) for t in clean)
    owner = next((owner_from(t.get("main_entity")) for t in clean if t.get("main_entity")), None) or next(
        (owner_from(t["name"]) for t in clean if t.get("type") == "protocol"), None) or next(
        (owner_from(t["name"]) for t in clean if t.get("type") in ("name", "public", "address")), None)
    scam = is_scam or any(t.get("type") == "red" for t in tags) or bool(SCAM.search(text))
    if scam:
        kind = _kind_of(clean_text) if clean else None
        if kind in SERVICE_TAG_KINDS and owner:
            return owner, kind, "M"  # the scammer's account at that service: the service is asked
        return None, "unhosted", "L"
    if token_symbol and token_symbol.upper() in STABLES and is_contract:
        return owner or token_symbol.upper(), "issuer", "M"
    if not names:
        return None, None, "M"
    return owner, _kind_of(text), "M"


def _meta(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        v = json.loads(raw) if isinstance(raw, str) and raw.strip() else {}
    except json.JSONDecodeError:
        return {}
    return v if isinstance(v, dict) else {}


def _int(v) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _ms(v) -> str | None:
    n = _int(v)
    if not n or n <= 0:
        return None
    try:
        return datetime.fromtimestamp(n / 1000, tz=UTC).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return None


def _call(http: FreezeHttp, out: Lookup, url: str, *, params=None, headers=None):
    before = http.requests
    try:
        resp = http.get(url, params=params, headers=headers)
    except FreezeHttpError as exc:
        out.requests += http.requests - before
        if exc.reason == "http_404":
            return None, 404
        out.errors.append(f"{exc.reason} ({exc.host})")
        return None, None
    out.requests += http.requests - before
    out.hosts.append(resp.host)
    out.sha256.append(resp.sha256)
    return resp.data, 200


def blockscout(http: FreezeHttp, settings, chain: str, address: str) -> Lookup:
    out = Lookup(chain=chain, address=address)
    base = (settings.aegis_owner_metadata_url or "").rstrip("/")
    data, _ = _call(http, out, f"{base}/api/v1/metadata",
                    params={"addresses": address, "chainId": str(EVM_CHAIN_IDS[chain])})
    rows = ((data or {}).get("addresses") or {}) if isinstance(data, dict) else {}
    entry = next((v for k, v in rows.items() if str(k).lower() == address.lower()), None) or {}
    for t in entry.get("tags") or []:
        if isinstance(t, dict) and t.get("name"):
            m = _meta(t.get("meta"))
            out.tags.append({"name": str(t["name"])[:200], "type": str(t.get("tagType") or "")[:24],
                             "slug": str(t.get("slug") or "")[:80], "source": "blockscout metadata",
                             **({"main_entity": str(m["main_entity"])[:120]} if m.get("main_entity") else {}),
                             **({"url": str(m.get("tooltipUrl")).strip()[:200]} if m.get("tooltipUrl") else {})})
    host = BLOCKSCOUT_HOSTS[chain]
    info, status = _call(http, out, f"https://{host}/api/v2/addresses/{address}")
    token = None
    if status == 404:
        out.profile["unseen"] = True  # Blockscout has never seen the address: no activity
    elif isinstance(info, dict):
        out.profile.update(is_contract=bool(info.get("is_contract")), is_scam=bool(info.get("is_scam")))
        if info.get("name"):
            out.profile["contract_name"] = str(info["name"])[:120]
        tok = info.get("token") if isinstance(info.get("token"), dict) else None
        if tok:
            token = str(tok.get("symbol") or "")[:16] or None
            out.profile["token"] = {"symbol": token, "name": str(tok.get("name") or "")[:80] or None}
        for t in info.get("public_tags") or []:
            label = t.get("display_name") or t.get("label") if isinstance(t, dict) else None
            if label:
                out.tags.append({"name": str(label)[:200], "type": "public", "source": "blockscout public tag"})
        meta = info.get("metadata") if isinstance(info.get("metadata"), dict) else {}
        for t in meta.get("tags") or []:
            if isinstance(t, dict) and t.get("name") and not any(x["name"] == t["name"] for x in out.tags):
                m = _meta(t.get("meta"))
                out.tags.append({"name": str(t["name"])[:200], "type": str(t.get("tagType") or "")[:24],
                                 "source": "blockscout metadata",
                                 **({"main_entity": str(m["main_entity"])[:120]} if m.get("main_entity") else {})})
        counters, _ = _call(http, out, f"https://{host}/api/v2/addresses/{address}/counters")
        if isinstance(counters, dict):
            out.profile.update(tx_count=_int(counters.get("transactions_count")),
                               token_transfers=_int(counters.get("token_transfers_count")))
    out.owner, out.kind, out.confidence = classify(out.tags, is_scam=bool(out.profile.get("is_scam")),
                                                   token_symbol=token, is_contract=out.profile.get("is_contract"))
    return out


def tronscan(http: FreezeHttp, settings, address: str) -> Lookup:
    out = Lookup(chain="tron", address=address)
    key = (settings.tronscan_api_key or "").strip()
    if not key:
        out.errors.append("no_api_key")
        return out
    base = (settings.aegis_owner_tronscan_url or "").rstrip("/")
    data, status = _call(http, out, f"{base}/api/accountv2", params={"address": address},
                         headers={"TRON-PRO-API-KEY": key})
    if status == 404:
        out.profile["unseen"] = True
    if isinstance(data, dict):
        for k, typ in (("publicTag", "public"), ("addressTag", "address"), ("redTag", "red"), ("blueTag", "blue"),
                       ("greyTag", "grey")):
            v = data.get(k)
            if isinstance(v, str) and v.strip():
                out.tags.append({"name": v.strip()[:200], "type": typ, "source": f"tronscan {k}"})
        out.profile.update(tx_count=_int(data.get("totalTransactionCount")),
                           tx_in=_int(data.get("transactions_in")), tx_out=_int(data.get("transactions_out")),
                           first_at=_ms(data.get("date_created")), last_at=_ms(data.get("latest_operation_time")),
                           # Tronscan users' risk feedback: exchange deposit addresses scammers use collect it too, so
                           # it is a note, never a scam mark that would hide the service a tag names
                           feedback_risk=bool(data.get("feedbackRisk")) or None,
                           is_contract=data.get("accountType") == 2 or None)
        out.profile = {k: v for k, v in out.profile.items() if v is not None}
    out.owner, out.kind, out.confidence = classify(out.tags)
    return out


def lookup(http: FreezeHttp, settings, chain: str, address: str) -> Lookup:
    return tronscan(http, settings, address) if chain == "tron" else blockscout(http, settings, chain, address)
