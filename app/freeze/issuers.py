"""Issuer adapters: read a stablecoin issuer's blacklist for one wallet, and find when it froze it.

Contracts (all 6 decimals):

| Issuer | Token | Chain | Contract | Blacklist getter | Freeze event |
|---|---|---|---|---|---|
| Tether | USDT | ethereum | 0xdAC17F958D2ee523a2206206994597C13D831ec7 | isBlackListed(address) 0xe47d6060 (also getBlackListStatus 0x59bf1abe) | AddedBlackList(address), address in data |
| Tether | USDT | tron | TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t | isBlackListed(address) via TronGrid triggerconstantcontract | AddedBlackList(address) (TronGrid events API) |
| Circle | USDC | ethereum | 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 | isBlacklisted(address) 0xfe575a87 | Blacklisted(address indexed) |
| Circle | USDC | base / arbitrum / polygon / optimism | native USDC (below) | isBlacklisted(address) | Blacklisted(address indexed) |

The native-USDC addresses on Base, Arbitrum One, Polygon PoS and OP Mainnet are Circle's published
FiatToken proxies. They are only queried once the chain's RPC URL is configured (AEGIS_<CHAIN>_RPC_URL);
bridged variants (USDC.e) are not issuer-controlled in the same way and are not listed.
TODO: USDT on other chains (Arbitrum / Polygon / BSC / Solana) and USDC on Solana / TRON are not
covered; add them only from the issuer's own published contract list.

Every reading returns an `IssuerReading`: blacklisted, balance (Decimal, token decimals applied),
block number (EVM: the reads are pinned to one block), checked_at, and the sha256 of each raw response.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal

from app.freeze import abi
from app.freeze.transport import FreezeHttp, FreezeHttpError

TETHER, CIRCLE = "Tether", "Circle"
# the entity names app/tracing/freeze.py gives the issuer levers (STABLECOIN_ISSUER)
ISSUER_ENTITY = {TETHER: "Tether (USDT issuer)", CIRCLE: "Circle (USDC issuer)"}

SEL_TETHER_IS_BLACKLISTED = abi.selector("isBlackListed(address)")  # 0xe47d6060
SEL_TETHER_STATUS = abi.selector("getBlackListStatus(address)")  # 0x59bf1abe
SEL_CIRCLE_IS_BLACKLISTED = abi.selector("isBlacklisted(address)")  # 0xfe575a87
SEL_BALANCE_OF = abi.selector("balanceOf(address)")  # 0x70a08231
TOPIC_ADDED_BLACKLIST = abi.topic("AddedBlackList(address)")
TOPIC_REMOVED_BLACKLIST = abi.topic("RemovedBlackList(address)")
TOPIC_DESTROYED_BLACK_FUNDS = abi.topic("DestroyedBlackFunds(address,uint256)")
TOPIC_BLACKLISTED = abi.topic("Blacklisted(address)")
TOPIC_UNBLACKLISTED = abi.topic("UnBlacklisted(address)")

EVM_CHAIN_IDS = {"ethereum": 1, "optimism": 10, "polygon": 137, "base": 8453, "arbitrum": 42161}
RPC_SETTING = {"ethereum": "aegis_eth_rpc_url", "base": "aegis_base_rpc_url", "arbitrum": "aegis_arbitrum_rpc_url",
               "polygon": "aegis_polygon_rpc_url", "optimism": "aegis_optimism_rpc_url"}
CHAIN_LABELS = {"ethereum": "Ethereum", "tron": "TRON", "base": "Base", "arbitrum": "Arbitrum One",
                "polygon": "Polygon PoS", "optimism": "OP Mainnet"}
# public explorer pages for the links in the UI (clicking one reveals the address / tx to that explorer)
EXPLORER_TX = {"ethereum": "https://etherscan.io/tx/", "tron": "https://tronscan.org/#/transaction/",
               "base": "https://basescan.org/tx/", "arbitrum": "https://arbiscan.io/tx/",
               "polygon": "https://polygonscan.com/tx/", "optimism": "https://optimistic.etherscan.io/tx/"}
EXPLORER_ADDRESS = {"ethereum": "https://etherscan.io/address/", "tron": "https://tronscan.org/#/address/",
                    "base": "https://basescan.org/address/", "arbitrum": "https://arbiscan.io/address/",
                    "polygon": "https://polygonscan.com/address/", "optimism": "https://optimistic.etherscan.io/address/"}
LOG_PAGE_LIMIT = 1000  # Etherscan / Blockscout getLogs return at most this many rows per call
MAX_LOG_REQUESTS = 16
TRON_EVENT_PAGES = 5


@dataclass(frozen=True)
class TokenContract:
    issuer: str
    symbol: str
    chain: str
    contract: str  # EVM: checksummed 0x…; TRON: base58
    decimals: int
    blacklist_selector: str
    blacklist_signature: str
    added_topic: str  # event signalling the freeze
    address_indexed: bool  # the frozen address is topic1 (Circle) or in the data (Tether)
    status_selector: str | None = None  # alternative getter tried when the main one returns nothing
    removed_topic: str | None = None
    destroyed_topic: str | None = None

    @property
    def key(self) -> str:
        return f"{self.issuer.lower()}-{self.symbol.lower()}-{self.chain}"

    @property
    def is_tron(self) -> bool:
        return self.chain == "tron"

    @property
    def contract_id(self) -> str:
        """The contract as stored and compared: EVM lower-case, TRON base58."""
        return self.contract if self.is_tron else self.contract.lower()

    @property
    def entity(self) -> str:
        return ISSUER_ENTITY[self.issuer]


REMOVED_EVENT_NAME = {TETHER: "RemovedBlackList", CIRCLE: "UnBlacklisted"}
DESTROYED_EVENT_NAME = {TETHER: "DestroyedBlackFunds"}


def _tether(chain: str, contract: str) -> TokenContract:
    return TokenContract(TETHER, "USDT", chain, contract, 6, SEL_TETHER_IS_BLACKLISTED, "isBlackListed(address)",
                         TOPIC_ADDED_BLACKLIST, False, SEL_TETHER_STATUS, TOPIC_REMOVED_BLACKLIST,
                         TOPIC_DESTROYED_BLACK_FUNDS)


def _circle(chain: str, contract: str) -> TokenContract:
    return TokenContract(CIRCLE, "USDC", chain, contract, 6, SEL_CIRCLE_IS_BLACKLISTED, "isBlacklisted(address)",
                         TOPIC_BLACKLISTED, True, None, TOPIC_UNBLACKLISTED)


CONTRACTS: tuple[TokenContract, ...] = (
    _tether("ethereum", "0xdAC17F958D2ee523a2206206994597C13D831ec7"),
    _tether("tron", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
    _circle("ethereum", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
    _circle("base", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
    _circle("arbitrum", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
    _circle("polygon", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"),
    _circle("optimism", "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
)
CHAINS: tuple[str, ...] = tuple(dict.fromkeys(c.chain for c in CONTRACTS))


def contracts_for(chain: str, symbols: set[str] | frozenset[str] | None = None) -> list[TokenContract]:
    """The issuer contracts on `chain` (optionally only those of `symbols`, e.g. {"USDT"})."""
    return [c for c in CONTRACTS if c.chain == chain and (symbols is None or c.symbol in symbols)]


def contract_by_id(chain: str, contract: str) -> TokenContract | None:
    cid = contract if chain == "tron" else (contract or "").lower()
    return next((c for c in CONTRACTS if c.chain == chain and c.contract_id == cid), None)


def normalise_wallet(chain: str, address: str, *, checksum: bool = True) -> str:
    """EVM: lower-case 0x + 40 hex (a mixed-case input must pass its EIP-55 checksum); TRON: base58check
    (validated). ValueError otherwise. `checksum=False` for addresses Aegis already holds (the trace's own
    rows), where a casing slip must not drop the wallet from the checks."""
    a = (address or "").strip()
    if chain == "tron":
        if not abi.is_tron_address(a):
            raise ValueError("not a TRON address (T… base58check)")
        return a
    if chain not in EVM_CHAIN_IDS:
        raise ValueError(f"no issuer contract is checked on {chain!r}")
    if not abi.is_evm_address(a):
        raise ValueError("not an EVM address (0x + 40 hex)")
    if checksum and not abi.checksum_ok(a):
        raise ValueError("the address's EIP-55 checksum (its mix of upper- and lower-case letters) does not match: "
                         "check it for a typo, or paste it from the explorer again")
    return a.lower()


def units(raw: int, decimals: int) -> Decimal:
    return Decimal(raw) / (Decimal(10) ** decimals)


# --------------------------------------------------------------------------- readings
@dataclass
class IssuerReading:
    token: TokenContract
    wallet: str
    blacklisted: bool
    balance: Decimal | None
    block_number: int | None
    checked_at: datetime
    raw_sha256: str  # of the blacklist getter's raw response
    responses: list[dict] = field(default_factory=list)  # [{call, host, sha256, cached}]
    method: str = "rpc"
    balance_raw: int | None = None  # the uint256 as read (exact; `balance` = balance_raw / 10**decimals)


def _resp_row(call: str, resp) -> dict:
    return {"call": call, "host": resp.host, "sha256": resp.sha256, "cached": resp.cached,
            "at": resp.fetched_at.isoformat(timespec="seconds")}


def read_evm(http: FreezeHttp, rpc_url: str, token: TokenContract, wallet: str, *,
             block: int | None = None) -> IssuerReading:
    """isBlacklisted / isBlackListed and balanceOf at one block over JSON-RPC (eth_call)."""
    who = abi.evm_bytes(wallet)
    responses: list[dict] = []
    if block is None:
        result, resp = http.rpc(rpc_url, "eth_blockNumber", [])
        responses.append(_resp_row("eth_blockNumber", resp))
        block = abi.decode_uint(result)
    tag = hex(block)
    to = token.contract.lower()
    result, resp = http.rpc(rpc_url, "eth_call", [{"to": to, "data": abi.encode_call(token.blacklist_selector, who)}, tag])
    responses.append(_resp_row(token.blacklist_signature.split("(")[0], resp))
    primary_sha = resp.sha256
    try:
        blacklisted = abi.decode_bool(result)
    except ValueError:
        if token.status_selector is None:
            raise FreezeHttpError("bad_response", resp.host, "blacklist getter returned no bool") from None
        result, resp = http.rpc(rpc_url, "eth_call", [{"to": to, "data": abi.encode_call(token.status_selector, who)}, tag])
        responses.append(_resp_row("getBlackListStatus", resp))
        primary_sha = resp.sha256
        try:
            blacklisted = abi.decode_bool(result)
        except ValueError:
            raise FreezeHttpError("bad_response", resp.host, "blacklist getter returned no bool") from None
    result, resp = http.rpc(rpc_url, "eth_call", [{"to": to, "data": abi.encode_call(SEL_BALANCE_OF, who)}, tag])
    responses.append(_resp_row("balanceOf", resp))
    try:
        raw = abi.decode_uint(result)
    except ValueError:
        raw = None
    return IssuerReading(token, wallet, blacklisted, units(raw, token.decimals) if raw is not None else None, block,
                         datetime.now(tz=UTC), primary_sha, responses, balance_raw=raw)


def _tron_headers(api_key: str) -> dict | None:
    return {"TRON-PRO-API-KEY": api_key} if api_key else None


def _tron_constant(http: FreezeHttp, base: str, api_key: str, token: TokenContract, wallet: str, fn: str):
    body = {"owner_address": abi.tron_to_hex(wallet), "contract_address": abi.tron_to_hex(token.contract),
            "function_selector": fn, "parameter": abi.address_word(abi.tron_bytes(wallet)), "visible": False}
    resp = http.post(base.rstrip("/") + "/wallet/triggerconstantcontract", body, headers=_tron_headers(api_key))
    data = resp.data if isinstance(resp.data, dict) else {}
    ok = (data.get("result") or {}).get("result") is True
    out = data.get("constant_result") or []
    if not ok or not out or not isinstance(out[0], str):
        raise FreezeHttpError("bad_response", resp.host, "triggerconstantcontract returned no result")
    return out[0], resp


def read_tron(http: FreezeHttp, base_url: str, api_key: str, token: TokenContract, wallet: str) -> IssuerReading:
    """isBlackListed and balanceOf through TronGrid's /wallet/triggerconstantcontract (base58 → hex).
    TronGrid's constant call reports no block number."""
    responses: list[dict] = []
    word, resp = _tron_constant(http, base_url, api_key, token, wallet, token.blacklist_signature)
    responses.append(_resp_row("isBlackListed", resp))
    try:
        blacklisted = abi.decode_bool(word)
    except ValueError:
        raise FreezeHttpError("bad_response", resp.host, "blacklist getter returned no bool") from None
    primary_sha = resp.sha256
    try:
        word, resp = _tron_constant(http, base_url, api_key, token, wallet, "balanceOf(address)")
        responses.append(_resp_row("balanceOf", resp))
        raw = abi.decode_uint(word)
    except (FreezeHttpError, ValueError):
        raw = None
    return IssuerReading(token, wallet, blacklisted, units(raw, token.decimals) if raw is not None else None, None,
                         datetime.now(tz=UTC), primary_sha, responses, balance_raw=raw)


# --------------------------------------------------------------------------- freeze time (events)
@dataclass
class FreezeEvent:
    tx_hash: str
    block_number: int | None
    at: datetime | None
    host: str
    sha256: str
    requests: int = 1


def _int(v) -> int | None:
    if v is None or v == "":
        return None
    s = str(v)
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def _ts(v) -> datetime | None:
    n = _int(v)
    if n is None:
        return None
    if n > 10**11:  # milliseconds (TronGrid)
        n //= 1000
    return datetime.fromtimestamp(n, tz=UTC)


@dataclass(frozen=True)
class Explorer:
    kind: str  # etherscan | blockscout
    url: str
    auth: dict  # extra query parameters (Etherscan: chainid + apikey); never logged

    @property
    def host(self) -> str:
        from app.freeze.transport import host_of

        return host_of(self.url)


BLOCKSCOUT_API = {"ethereum": "https://eth.blockscout.com/api", "base": "https://base.blockscout.com/api",
                  "arbitrum": "https://arbitrum.blockscout.com/api", "polygon": "https://polygon.blockscout.com/api"}
ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"


def explorer_for(chain: str, settings) -> Explorer | None:
    """The logs / txlist explorer of an EVM chain: Etherscan V2 when a key is set (or forced), else
    Blockscout (keyless). None when switched off or no explorer is known for the chain.
    TODO: OP Mainnet has no Blockscout URL here yet; it uses Etherscan V2 only (with a key)."""
    mode = settings.aegis_freeze_explorer
    if mode == "none" or chain not in EVM_CHAIN_IDS:
        return None
    key = settings.etherscan_api_key
    if mode == "etherscan" or (mode == "auto" and key):
        if not key:
            return None
        return Explorer("etherscan", ETHERSCAN_V2, {"chainid": EVM_CHAIN_IDS[chain], "apikey": key})
    url = BLOCKSCOUT_API.get(chain)
    return Explorer("blockscout", url, {}) if url else None


def explorer_rows(resp) -> list[dict]:
    """The `result` list of an Etherscan-compatible answer ("No records found" / "No transactions found"
    = empty). Anything else that is not a list (an error string, a rate-limit notice) raises."""
    data = resp.data if isinstance(resp.data, dict) else {}
    result = data.get("result")
    if isinstance(result, list):
        return [r for r in result if isinstance(r, dict)]
    msg = str(data.get("message") or "") + " " + str(result or "")
    if "no records" in msg.lower() or "no transactions" in msg.lower() or "no logs" in msg.lower():
        return []
    if "rate limit" in msg.lower():
        raise FreezeHttpError("rate_limited", resp.host)
    raise FreezeHttpError("bad_response", resp.host, "explorer returned no result list")


def _log_matches(token: TokenContract, row: dict, wallet: str, topic: str | None = None,
                 indexed: bool | None = None) -> bool:
    topics = [t for t in (row.get("topics") or []) if t]
    if not topics or str(topics[0]).lower() != (topic or token.added_topic):
        return False
    if token.address_indexed if indexed is None else indexed:
        return len(topics) > 1 and abi.word_address(topics[1]) == wallet
    data = str(row.get("data") or "")
    h = data[2:] if data.lower().startswith("0x") else data
    return len(h) >= 64 and abi.word_address(h[:64]) == wallet


def find_freeze_event_evm(http: FreezeHttp, explorer: Explorer, token: TokenContract, wallet: str, *,
                          from_block: int, to_block: int, topic: str | None = None,
                          indexed: bool | None = None) -> FreezeEvent | None:
    """The latest blacklist event for `wallet` between two blocks, from the explorer's logs API.
    Tether's AddedBlackList carries the address in the data (not indexed), so every event of the range
    is read and matched; a range with LOG_PAGE_LIMIT rows or more is split in two (at most
    MAX_LOG_REQUESTS calls). Circle's Blacklisted is filtered by topic1. `topic` looks for another event of
    the contract instead (the removal: RemovedBlackList / UnBlacklisted; Tether's DestroyedBlackFunds, whose
    address is the first data word: `indexed=False`)."""
    wallet = wallet.lower()
    topic = topic or token.added_topic
    indexed = token.address_indexed if indexed is None else indexed
    best: FreezeEvent | None = None
    calls = 0
    stack = [(max(0, from_block), max(0, to_block))]
    while stack:
        lo, hi = stack.pop()
        if calls >= MAX_LOG_REQUESTS:
            raise FreezeHttpError("too_many_logs", explorer.host)
        params = {"module": "logs", "action": "getLogs", "fromBlock": lo, "toBlock": hi,
                  "address": token.contract.lower(), "topic0": topic, **explorer.auth}
        if indexed:
            params.update(topic1="0x" + abi.address_word(abi.evm_bytes(wallet)), topic0_1_opr="and")
        resp = http.get(explorer.url, params=params)
        calls += 1
        rows = explorer_rows(resp)
        if len(rows) >= LOG_PAGE_LIMIT and hi > lo and not indexed:
            mid = (lo + hi) // 2
            stack += [(lo, mid), (mid + 1, hi)]
            continue
        for r in rows:
            if not _log_matches(token, r, wallet, topic, indexed):
                continue
            ev = FreezeEvent(tx_hash=str(r.get("transactionHash") or ""), block_number=_int(r.get("blockNumber")),
                             at=_ts(r.get("timeStamp")), host=resp.host, sha256=resp.sha256)
            if best is None or (ev.block_number or 0) > (best.block_number or 0):
                best = ev
    if best is not None:
        best.requests = calls
    return best


def find_freeze_event_tron(http: FreezeHttp, base_url: str, api_key: str, token: TokenContract, wallet: str, *,
                           min_timestamp: datetime | None = None, event_name: str = "AddedBlackList") -> FreezeEvent | None:
    """The latest `event_name` event (AddedBlackList; RemovedBlackList / DestroyedBlackFunds for a removal or
    a burn) naming `wallet`, from TronGrid's /v1/contracts/{contract}/events (newest first, at most
    TRON_EVENT_PAGES pages of 200)."""
    url = f"{base_url.rstrip('/')}/v1/contracts/{token.contract}/events"
    params: dict = {"event_name": event_name, "only_confirmed": "true", "limit": 200,
                    "order_by": "block_timestamp,desc"}
    if min_timestamp is not None:
        params["min_block_timestamp"] = int(min_timestamp.timestamp() * 1000)
    for _ in range(TRON_EVENT_PAGES):
        resp = http.get(url, params=params, headers=_tron_headers(api_key))
        data = resp.data if isinstance(resp.data, dict) else {}
        for row in data.get("data") or []:
            values = (row.get("result") or {}).values() if isinstance(row.get("result"), dict) else []
            if any(isinstance(v, str) and abi.same_tron(v, wallet) for v in values):
                return FreezeEvent(tx_hash=str(row.get("transaction_id") or ""), block_number=_int(row.get("block_number")),
                                   at=_ts(row.get("block_timestamp")), host=resp.host, sha256=resp.sha256)
        fingerprint = ((data.get("meta") or {}).get("fingerprint"))
        if not fingerprint:
            return None
        params = {**params, "fingerprint": fingerprint}
    return None
