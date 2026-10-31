"""On-chain freeze detection end to end, offline: a mocked JSON-RPC node, explorer and TronGrid
(httpx.MockTransport) behind app.freeze.service; consent gating, readings, freeze time, failed transfers,
notifications once per flip, the scheduler job, the graph annotation, the overview, the routes and the
/freeze-status skill.

Blacklisted wallets in these tests are synthetic (0x…ab / T… from 41 + 0x22…) or the demo case's own
perpetrator hub, flipped only inside this mock; nothing here claims a real issuer action."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from conftest import csrf_token
from sqlalchemy import delete, select

from app import services
from app.blocks import status as bs
from app.core.config import get_settings
from app.core.permissions import CaseAccess
from app.db.models import (
    AuditEvent,
    CaseRole,
    FreezeCheck,
    FreezeSetting,
    FreezeWatch,
    Notification,
)
from app.domain import notify
from app.freeze import abi, issuers, service, signals
from app.freeze import transport as tp
from app.freeze.transport import FreezeHttp

USDT_ETH = "0xdac17f958d2ee523a2206206994597c13d831ec7"
USDC_ETH = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
USDT_TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
HUB = "0x54453e25e38b11009963361a123bde2b4457becb"  # the demo case's perpetrator distribution hub (USDT)
VICTIM = "0x7ac32c88e5489b4c406ffc1d6b835f4eba7b455b"
SYN_EVM = "0x" + "ab" * 20  # synthetic watched wallet
SYN_TRON = abi.hex_to_tron("41" + "22" * 20)
BLOCK = 23_600_000
T_FROZEN = datetime(2026, 10, 15, 8, 30, tzinfo=UTC)


def _word(n: int) -> str:
    return "0x" + format(n, "064x")


class ChainMock:
    """A tiny Ethereum node + Blockscout + TronGrid. `blacklisted` / `balances` are keyed by
    (token contract id, wallet) with EVM values lower-case and TRON base58."""

    def __init__(self):
        self.blacklisted: set[tuple[str, str]] = set()
        self.balances: dict[tuple[str, str], int] = {}
        self.logs: list[dict] = []
        self.txlist: dict[str, list[dict]] = {}
        self.tron_txs: dict[str, list[dict]] = {}
        self.tron_events: list[dict] = []
        self.rpc_429 = 0  # answer the next n JSON-RPC requests with 429
        self.rpc_error_wallets: set[str] = set()
        self.block = BLOCK  # what eth_blockNumber answers
        self.rpc_down = False  # every JSON-RPC request answers 503
        self.logs_down = False  # the explorer's logs API answers 503
        self.calls: list[tuple[str, str]] = []
        self.slept: list[float] = []

    def sleep(self, s: float) -> None:
        self.slept.append(s)

    # ------------------------------------------------------------------ handler
    def handler(self, request: httpx.Request) -> httpx.Response:
        url = urlsplit(str(request.url))
        host, path = url.hostname, url.path
        self.calls.append((host, path))
        if request.method == "POST" and path == "/wallet/triggerconstantcontract":
            return self._tron_call(json.loads(request.content))
        if request.method == "POST":
            if self.rpc_down:
                return httpx.Response(503)
            if self.rpc_429:
                self.rpc_429 -= 1
                return httpx.Response(429, headers={"Retry-After": "1"})
            return self._rpc(json.loads(request.content))
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if path.startswith("/v1/contracts/") and path.endswith("/events"):
            return httpx.Response(200, json={"data": self.tron_events, "success": True, "meta": {}})
        if path.startswith("/v1/accounts/") and path.endswith("/transactions"):
            wallet = path.split("/")[3]
            return httpx.Response(200, json={"data": self.tron_txs.get(wallet, []), "success": True, "meta": {}})
        if q.get("module") == "logs":
            if self.logs_down:
                return httpx.Response(503)
            rows = [r for r in self.logs if r["address"] == q["address"] and r["topics"][0] == q["topic0"]
                    and int(q["fromBlock"]) <= int(r["blockNumber"], 16) <= int(q["toBlock"])
                    and ("topic1" not in q or (len(r["topics"]) > 1 and r["topics"][1] == q["topic1"]))]
            if not rows:
                return httpx.Response(200, json={"status": "0", "message": "No records found", "result": []})
            return httpx.Response(200, json={"status": "1", "message": "OK", "result": rows})
        if q.get("module") == "account" and q.get("action") == "txlist":
            rows = self.txlist.get(q["address"], [])
            if not rows:
                return httpx.Response(200, json={"status": "0", "message": "No transactions found", "result": []})
            return httpx.Response(200, json={"status": "1", "message": "OK", "result": rows})
        return httpx.Response(404, json={})

    def _rpc(self, body: dict) -> httpx.Response:
        method, params = body["method"], body["params"]
        if method == "eth_blockNumber":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": hex(self.block)})
        if method == "eth_call":
            to, data = params[0]["to"].lower(), params[0]["data"]
            wallet = "0x" + data[-40:].lower()
            if wallet in self.rpc_error_wallets:
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "boom"}})
            sel = data[:10]
            if sel in (issuers.SEL_TETHER_IS_BLACKLISTED, issuers.SEL_CIRCLE_IS_BLACKLISTED, issuers.SEL_TETHER_STATUS):
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,
                                                 "result": _word(int((to, wallet) in self.blacklisted))})
            if sel == issuers.SEL_BALANCE_OF:
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,
                                                 "result": _word(self.balances.get((to, wallet), 0))})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no"}})

    def _tron_call(self, body: dict) -> httpx.Response:
        wallet = abi.hex_to_tron("41" + body["parameter"][-40:])
        contract = abi.hex_to_tron(body["contract_address"])
        if body["function_selector"] == "isBlackListed(address)":
            out = format(int((contract, wallet) in self.blacklisted), "064x")
        else:
            out = format(self.balances.get((contract, wallet), 0), "064x")
        return httpx.Response(200, json={"result": {"result": True}, "constant_result": [out], "energy_used": 900})

    # ------------------------------------------------------------------ fixtures
    def added_blacklist_log(self, wallet: str, at: datetime, block: int, tx: str = "0x" + "f1" * 32) -> None:
        """Tether's AddedBlackList(address): the address is in the data, not indexed."""
        self.logs.append({"address": USDT_ETH, "topics": [issuers.TOPIC_ADDED_BLACKLIST],
                          "data": "0x" + abi.address_word(abi.evm_bytes(wallet)), "blockNumber": hex(block),
                          "timeStamp": hex(int(at.timestamp())), "transactionHash": tx, "logIndex": "0x1"})

    def removed_blacklist_log(self, wallet: str, at: datetime, block: int, tx: str = "0x" + "e2" * 32) -> None:
        """Tether's RemovedBlackList(address): the address is in the data, not indexed."""
        self.logs.append({"address": USDT_ETH, "topics": [issuers.TOPIC_REMOVED_BLACKLIST],
                          "data": "0x" + abi.address_word(abi.evm_bytes(wallet)), "blockNumber": hex(block),
                          "timeStamp": hex(int(at.timestamp())), "transactionHash": tx, "logIndex": "0x1"})

    def failed_transfer(self, wallet: str, contract: str, at: datetime, tx: str, selector: str = "0xa9059cbb") -> None:
        self.txlist.setdefault(wallet, []).append({
            "hash": tx, "from": wallet, "to": contract, "isError": "1", "txreceipt_status": "0",
            "input": selector + "0" * 128, "timeStamp": str(int(at.timestamp())), "blockNumber": str(BLOCK - 10)})


TEST_SETTINGS = get_settings().model_copy(update={
    "aegis_freeze_explorer": "blockscout", "etherscan_api_key": "", "trongrid_api_key": "",
    "aegis_eth_rpc_url": "https://ethereum-rpc.publicnode.com", "aegis_trongrid_url": "https://api.trongrid.io",
    "aegis_base_rpc_url": "", "aegis_arbitrum_rpc_url": "", "aegis_polygon_rpc_url": "", "aegis_optimism_rpc_url": "",
    "aegis_freeze_checks_disabled": "", "aegis_freeze_min_interval": 0.0, "aegis_freeze_cache_minutes": 0.0,
    "aegis_freeze_retries": 2,
})


@pytest.fixture
def chain():
    return ChainMock()


@pytest.fixture(autouse=True)
def _offline(monkeypatch, chain, db):
    """Every FreezeHttp built by the service talks to the mock; the service's settings are TEST_SETTINGS."""
    real = FreezeHttp

    def factory(settings=None, *, transport=None, **kw):
        return real(settings or TEST_SETTINGS, transport=httpx.MockTransport(chain.handler), sleep=chain.sleep, **kw)

    monkeypatch.setattr(service, "FreezeHttp", factory)
    monkeypatch.setattr(service, "_settings", lambda settings=None: settings or TEST_SETTINGS)
    tp.clear_cache()
    for model in (FreezeCheck, FreezeWatch, FreezeSetting):
        db.execute(delete(model))
    db.execute(delete(Notification).where(Notification.event_type == "freeze_detected"))
    db.commit()
    yield
    tp.clear_cache()


@pytest.fixture
def run(db, case):
    return services.latest_run(db, case) or services.run_trace(db, case, provider_mode="fixture")


@pytest.fixture
def app_with_router():
    """The app with the freeze router (app.main includes it)."""
    from app.main import app

    assert app.url_path_for("freeze_page", case_id=1) == "/cases/1/freeze"
    return app


def enable(db, case):
    service.set_enabled(db, case, None, True)
    db.commit()


def freeze_notes(db, case):
    return list(db.scalars(select(Notification).where(Notification.case_id == case.id,
                                                      Notification.event_type == "freeze_detected")))


def access_for(db, case, role=CaseRole.ADMIN):
    from conftest import ensure_user

    user = ensure_user(db, f"{role.value}-freeze@tests.example")
    return CaseAccess(case=case, user=user, role=role, member=None)


# --------------------------------------------------------------------------- which wallets
def test_targets_are_the_trace_stablecoin_wallets(db, case, run):
    tg = {t.address: t for t in service.targets(db, case)}
    assert HUB in tg and tg[HUB].symbols == frozenset({"USDT"}) and tg[HUB].in_trace
    tron = [t for t in tg.values() if t.chain == "tron"]
    assert tron and all(t.symbols == frozenset({"USDT"}) for t in tron)
    assert any(t.symbols == frozenset({"USDC"}) for t in tg.values())
    assert VICTIM not in tg  # the victim's own wallet is not checked
    assert all(t.chain in issuers.CHAINS for t in tg.values())
    assert not any(t.address.endswith("_PENDING") for t in tg.values())
    # a watched wallet joins with every issuer contract on its chain
    service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM.upper().replace("0X", "0x"), label="w")
    w = next(t for t in service.targets(db, case) if t.address == SYN_EVM)
    assert w.source == "watched" and {c.symbol for c in w.contracts()} == {"USDT", "USDC"}


def test_watch_validation(db, case):
    with pytest.raises(ValueError, match="TLP:RED"):
        service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM, tlp="TLP:RED")
    with pytest.raises(ValueError):
        service.add_watch(db, case, None, chain="ethereum", address="0x1234")
    with pytest.raises(ValueError):
        service.add_watch(db, case, None, chain="bitcoin", address="bc1q" + "x" * 30)
    with pytest.raises(ValueError):
        service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM, tlp="secret")
    a = service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM, tlp="tlp:amber", label="x")
    service.remove_watch(db, a, None)
    b = service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM, label="again")
    assert a.id == b.id and b.active and b.tlp is None and b.label == "again"


# --------------------------------------------------------------------------- consent gating
def test_no_request_while_the_setting_is_off(db, case, run, chain):
    with pytest.raises(service.FreezeChecksDisabled) as e:
        service.run_checks(db, case)
    assert e.value.reason == "case_setting_off"
    assert service.run_due(db)["cases"] == 0
    enable(db, case)
    service.set_enabled(db, case, None, False)
    db.commit()
    with pytest.raises(service.FreezeChecksDisabled):
        service.run_checks(db, case)
    assert chain.calls == [] and db.scalar(select(FreezeCheck.id).limit(1)) is None


def test_deployment_kill_switch(db, case, run, chain):
    enable(db, case)
    off = TEST_SETTINGS.model_copy(update={"aegis_freeze_checks_disabled": "1"})
    with pytest.raises(service.FreezeChecksDisabled) as e:
        service.run_checks(db, case, settings=off)
    assert e.value.reason == "deployment_disabled"
    assert service.run_due(db, settings=off)["cases"] == 0 and chain.calls == []


def test_consent_records_the_endpoints(db, case):
    row = service.set_enabled(db, case, None, True)
    assert row.enabled and set(row.consent["hosts"]) == {"ethereum-rpc.publicnode.com", "eth.blockscout.com",
                                                          "api.trongrid.io"}
    plan = {(r["chain"], r["host"]) for r in row.consent["plan"]}
    assert ("base", None) in plan  # no RPC configured for Base: listed as not checked
    assert not any("apikey" in json.dumps(r) for r in row.consent["plan"])


# --------------------------------------------------------------------------- readings
def test_clean_run_reads_every_target(db, case, run, chain):
    enable(db, case)
    rep = service.run_checks(db, case)
    rows = db.scalars(select(FreezeCheck).where(FreezeCheck.case_id == case.id)).all()
    assert rep.checked == len(rows) == len(service.targets(db, case)) and rep.errors == 0 and rep.blacklisted == 0
    assert {r.blacklisted for r in rows} == {False} and all(r.status == "ok" and len(r.raw_sha256) == 64 for r in rows)
    evm = [r for r in rows if r.chain == "ethereum"]
    assert evm and all(r.block_number == BLOCK and r.method == "rpc" for r in evm)
    assert all(r.block_number is None for r in rows if r.chain == "tron")  # TronGrid's constant call has no block
    assert set(rep.hosts) <= {"ethereum-rpc.publicnode.com", "eth.blockscout.com", "api.trongrid.io"}
    assert freeze_notes(db, case) == []
    st = service.case_status(db, case)
    assert st["n_checked"] == st["n_wallets"] and not st["frozen"] and st["frozen_usd"] == 0


def test_blacklisted_tron_wallet_with_event_time(db, case, run, chain):
    service.add_watch(db, case, None, chain="tron", address=SYN_TRON, label="consolidation", source_note="report X",
                      tlp="TLP:AMBER")
    enable(db, case)
    chain.blacklisted.add((USDT_TRON, SYN_TRON))
    chain.balances[(USDT_TRON, SYN_TRON)] = 1_234_560_000
    chain.tron_events = [
        {"transaction_id": "e0" * 32, "block_number": 76_000_000, "block_timestamp": int(T_FROZEN.timestamp() * 1000),
         "event_name": "AddedBlackList", "result": {"_user": "0x" + "22" * 20}},
    ]
    rep = service.run_checks(db, case)
    row = db.scalar(select(FreezeCheck).where(FreezeCheck.address == SYN_TRON))
    assert row.blacklisted and row.issuer == "Tether" and row.source == "watched"
    assert service.exact_balance(row) == Decimal("1234.56") and row.meta["balance_raw"] == "1234560000"
    assert row.frozen_at == T_FROZEN and row.frozen_at_basis == "event" and row.freeze_tx_hash == "e0" * 32
    assert rep.newly_frozen == [row.id]
    (note,) = freeze_notes(db, case)
    assert note.severity == "critical" and note.usd == Decimal("1234.56") and note.link == f"/cases/{case.id}/freeze"
    assert "Tether" in note.title and "1,234.56 USDT" in note.title and case.reference in note.body
    assert SYN_TRON not in (note.title + note.body)  # short address only
    assert "consolidation" not in note.body and "report X" not in note.body  # label / source note never leave
    assert notify.pii_findings(note.title + " " + note.body, case) == []
    assert service.onchain_label("Tether", "USDT", service.exact_balance(row)) == "frozen (on-chain: Tether blacklist, 1,234.56 USDT)"


def test_usdt_event_matched_in_data_and_usdc_by_topic(db, case, chain):
    """Tether's AddedBlackList is not indexed: every event of the range is read and matched on the data."""
    http = service.FreezeHttp(TEST_SETTINGS)
    ex = issuers.explorer_for("ethereum", TEST_SETTINGS)
    usdt = issuers.contract_by_id("ethereum", USDT_ETH)
    usdc = issuers.contract_by_id("ethereum", USDC_ETH)
    chain.added_blacklist_log("0x" + "cd" * 20, T_FROZEN, BLOCK - 50, tx="0x" + "aa" * 32)  # someone else
    chain.added_blacklist_log(SYN_EVM, T_FROZEN, BLOCK - 40, tx="0x" + "bb" * 32)
    ev = issuers.find_freeze_event_evm(http, ex, usdt, SYN_EVM, from_block=BLOCK - 1000, to_block=BLOCK)
    assert ev.tx_hash == "0x" + "bb" * 32 and ev.block_number == BLOCK - 40 and ev.at == T_FROZEN
    assert issuers.find_freeze_event_evm(http, ex, usdt, SYN_EVM, from_block=BLOCK - 10, to_block=BLOCK) is None
    chain.logs.append({"address": USDC_ETH, "topics": [issuers.TOPIC_BLACKLISTED, "0x" + abi.address_word(abi.evm_bytes(SYN_EVM))],
                       "data": "0x", "blockNumber": hex(BLOCK - 5), "timeStamp": hex(int(T_FROZEN.timestamp())),
                       "transactionHash": "0x" + "cc" * 32})
    ev = issuers.find_freeze_event_evm(http, ex, usdc, SYN_EVM, from_block=0, to_block=BLOCK)
    assert ev.tx_hash == "0x" + "cc" * 32


def test_large_log_ranges_are_split(chain):
    http = service.FreezeHttp(TEST_SETTINGS)
    ex = issuers.explorer_for("ethereum", TEST_SETTINGS)
    usdt = issuers.contract_by_id("ethereum", USDT_ETH)
    for i in range(1000):  # a full page in the first half of the range: it must be split
        chain.added_blacklist_log("0x" + format(i + 1, "040x"), T_FROZEN, BLOCK - 900 + (i % 400))
    chain.added_blacklist_log(SYN_EVM, T_FROZEN, BLOCK - 10, tx="0x" + "dd" * 32)
    ev = issuers.find_freeze_event_evm(http, ex, usdt, SYN_EVM, from_block=BLOCK - 1000, to_block=BLOCK)
    assert ev is not None and ev.tx_hash == "0x" + "dd" * 32 and ev.requests > 1


def test_freeze_time_falls_back_to_the_first_failed_transfer(db, case, run, chain):
    service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM)
    enable(db, case)
    chain.blacklisted.add((USDT_ETH, SYN_EVM))
    chain.balances[(USDT_ETH, SYN_EVM)] = 5_000_000_000
    t1, t2 = T_FROZEN + timedelta(hours=2), T_FROZEN + timedelta(hours=5)
    chain.failed_transfer(SYN_EVM, USDT_ETH, t2, "0x" + "02" * 32)
    chain.failed_transfer(SYN_EVM, USDT_ETH, t1, "0x" + "01" * 32, selector="0x095ea7b3")
    chain.txlist[SYN_EVM].append({"hash": "0x" + "03" * 32, "from": SYN_EVM, "to": USDT_ETH, "isError": "0",
                                  "txreceipt_status": "1", "input": "0xa9059cbb", "timeStamp": "1"})  # succeeded
    service.run_checks(db, case)
    row = db.scalar(select(FreezeCheck).where(FreezeCheck.address == SYN_EVM, FreezeCheck.token_symbol == "USDT"))
    assert row.blacklisted and service.exact_balance(row) == Decimal(5000) and row.frozen_at_basis == "at_or_before"
    assert row.frozen_at == t1 and row.meta["frozen_at_source"] == "first_failed_transfer"
    assert row.failed_count == 2 and row.first_failed_tx == "0x" + "01" * 32 and row.first_failed_at == t1
    assert [t["method"] for t in row.meta["failed_txs"]] == ["approve", "transfer"]
    usdc = db.scalar(select(FreezeCheck).where(FreezeCheck.address == SYN_EVM, FreezeCheck.token_symbol == "USDC"))
    assert usdc.blacklisted is False and usdc.failed_count == 0  # failures to USDT are not USDC's


def test_freeze_time_is_the_check_time_without_any_signal(db, case, run, chain):
    service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM)
    enable(db, case)
    chain.blacklisted.add((USDC_ETH, SYN_EVM))
    service.run_checks(db, case)
    row = db.scalar(select(FreezeCheck).where(FreezeCheck.address == SYN_EVM, FreezeCheck.token_symbol == "USDC"))
    assert row.frozen_at_basis == "at_or_before" and row.frozen_at == row.checked_at
    assert row.meta["frozen_at_source"] == "check_time"


def test_failed_transfer_detection_tron():
    wallet, contract = SYN_TRON, USDT_TRON
    rows = [
        {"txID": "aa" * 32, "block_timestamp": int(T_FROZEN.timestamp() * 1000), "ret": [{"contractRet": "REVERT"}],
         "raw_data": {"contract": [{"type": "TriggerSmartContract", "parameter": {"value": {
             "owner_address": abi.tron_to_hex(wallet), "contract_address": abi.tron_to_hex(contract),
             "data": "a9059cbb" + "0" * 128}}}]}},
        {"txID": "bb" * 32, "block_timestamp": int(T_FROZEN.timestamp() * 1000) + 1000, "ret": [{"contractRet": "SUCCESS"}],
         "raw_data": {"contract": [{"type": "TriggerSmartContract", "parameter": {"value": {
             "owner_address": abi.tron_to_hex(wallet), "contract_address": abi.tron_to_hex(contract),
             "data": "a9059cbb"}}}]}},
        {"txID": "cc" * 32, "block_timestamp": 1, "ret": [{"contractRet": "REVERT"}],  # another contract
         "raw_data": {"contract": [{"type": "TriggerSmartContract", "parameter": {"value": {
             "owner_address": abi.tron_to_hex(wallet), "contract_address": "41" + "33" * 20, "data": "a9059cbb"}}}]}},
    ]
    got = signals.failed_from_tron(rows, wallet, contract)
    assert got.count == 1 and got.first_tx == "aa" * 32 and got.first_at == T_FROZEN
    assert got.text() == "transfer attempts failing since 15 Oct 2026 08:30 UTC (1 attempt)"
    assert signals.failed_from_tron([], wallet, contract).text() is None


def test_rpc_error_and_429_retry(db, case, run, chain):
    enable(db, case)
    chain.rpc_429 = 2  # the first two JSON-RPC requests are rate-limited, then the node answers
    chain.rpc_error_wallets.add(HUB)
    rep = service.run_checks(db, case)
    assert chain.slept[:2] == [1.0, 1.0]  # Retry-After honoured
    hub = db.scalar(select(FreezeCheck).where(FreezeCheck.address == HUB))
    assert hub.status == "error" and hub.error == "rpc_error" and hub.blacklisted is None
    assert rep.errors == 1 and rep.checked == len(service.targets(db, case)) - 1
    st = service.case_status(db, case)
    assert any(w["address"] == HUB and w["state"] == "error" for w in st["wallets"])


# --------------------------------------------------------------------------- notifications once per flip
def test_freeze_detected_once_per_flip(db, case, run, chain):
    service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM)
    enable(db, case)
    key = (USDT_ETH, SYN_EVM)
    chain.blacklisted.add(key)
    chain.added_blacklist_log(SYN_EVM, T_FROZEN, BLOCK - 40)
    service.run_checks(db, case)
    assert len(freeze_notes(db, case)) == 1
    tp.clear_cache()
    rep = service.run_checks(db, case)  # still blacklisted: no second event, freeze tx reused (no logs query)
    assert rep.newly_frozen == [] and len(freeze_notes(db, case)) == 1
    rows = db.scalars(select(FreezeCheck).where(FreezeCheck.address == SYN_EVM, FreezeCheck.token_symbol == "USDT")
                      .order_by(FreezeCheck.id)).all()
    assert rows[-1].freeze_tx_hash == rows[0].freeze_tx_hash and rows[-1].meta["freeze_event"]["reused"] == rows[0].id
    chain.blacklisted.discard(key)
    tp.clear_cache()
    service.run_checks(db, case)  # removed from the blacklist: no event
    assert len(freeze_notes(db, case)) == 1
    chain.blacklisted.add(key)
    tp.clear_cache()
    service.run_checks(db, case)  # blacklisted again: a new flip
    assert len(freeze_notes(db, case)) == 2


# --------------------------------------------------------------------------- scheduler
def test_scheduler_runs_enabled_cases_when_due(db, case, run, chain):
    assert service.run_due(db)["cases"] == 0 and chain.calls == []
    enable(db, case)
    out = service.run_due(db)
    assert out["cases"] == 1 and out["checked"] > 0
    ev = db.scalar(select(AuditEvent).where(AuditEvent.action == "FREEZE_CHECK").order_by(AuditEvent.id.desc()).limit(1))
    assert ev.case_id == case.id and ev.actor_user_id is None and ev.detail["trigger"] == "scheduler"
    n = len(chain.calls)
    assert service.run_due(db)["cases"] == 0 and len(chain.calls) == n  # not due yet
    later = datetime.now(tz=UTC) + timedelta(minutes=TEST_SETTINGS.aegis_freeze_check_minutes + 1)
    assert service.run_due(db, now=later)["cases"] == 1


def test_scheduler_script_has_the_freeze_pass(monkeypatch):
    from scripts import poll_watch, run_scheduler

    monkeypatch.setattr(poll_watch, "poll_all", lambda *a, **k: (0, 0))
    monkeypatch.setattr(run_scheduler, "check_overdue_all", lambda: 0)
    monkeypatch.setattr(run_scheduler, "mail_pass", lambda: None)
    result = run_scheduler.run_once()
    assert result["freeze"] == {"cases": 0, "checked": 0, "newly_frozen": 0, "newly_lifted": 0, "errors": 0,
                                "failed_cases": 0}
    assert "freeze_error" not in result

    def boom():
        raise RuntimeError("x")

    monkeypatch.setattr(run_scheduler, "freeze_pass", boom)
    assert run_scheduler.run_once()["freeze_error"] is True
    # a case whose run raised makes --once fail; readings that failed over HTTP (retried next run) do not
    monkeypatch.setattr(run_scheduler, "freeze_pass", lambda: {"cases": 1, "errors": 3, "failed_cases": 0})
    assert "freeze_error" not in run_scheduler.run_once()
    monkeypatch.setattr(run_scheduler, "freeze_pass", lambda: {"cases": 0, "errors": 0, "failed_cases": 1})
    assert run_scheduler.run_once()["freeze_error"] is True
    monkeypatch.setattr(run_scheduler, "run_once", lambda provider=None: {"freeze": {"failed_cases": 1},
                                                                         "freeze_error": True})
    assert run_scheduler.main(["--once"]) == 1


def test_run_due_counts_a_failing_case(db, case, run, chain, monkeypatch):
    enable(db, case)

    def explode(*a, **kw):
        raise RuntimeError("db gone")

    monkeypatch.setattr(service, "targets", explode)
    out = service.run_due(db)
    assert out["failed_cases"] == 1 and out["cases"] == 0 and out["errors"] == 0
    db.expire_all()
    assert service.setting_for(db, case).run_started_at is None  # the run claim is released after a crash


# --------------------------------------------------------------------------- graph
def _hub_frozen(db, case, chain):
    enable(db, case)
    chain.blacklisted.add((USDT_ETH, HUB))
    chain.balances[(USDT_ETH, HUB)] = 70_000_123_456
    chain.added_blacklist_log(HUB, T_FROZEN, BLOCK - 40)
    service.run_checks(db, case)


def test_graph_annotation(db, case, run, chain):
    from app.tracing import annotate as an
    from app.tracing.graph import build_graph, to_cytoscape

    _hub_frozen(db, case, chain)
    elements = to_cytoscape(build_graph(db, run))
    an.annotate_elements(db, case, run, elements, can_act=True)
    by = {n["data"]["address"].lower(): n["data"] for n in elements["nodes"]}
    hub = by[HUB]
    assert hub["onchain_frozen"] is True and hub["onchain_freeze"]["state"] == "frozen"
    assert hub["onchain_freeze"]["label"] == "frozen (on-chain: Tether blacklist, 70,000.12 USDT)"
    (c,) = hub["onchain_freeze"]["checks"]
    assert c["block_number"] == BLOCK and c["method"] == "rpc" and c["freeze_tx_hash"] == "0x" + "f1" * 32
    assert c["frozen_at_basis"] == "event"
    assert hub.get("freeze_status") != "frozen"  # the stop-order status stays the stop orders'
    checked = [d for d in by.values() if d.get("onchain_freeze")]
    assert all(d["onchain_freeze"]["state"] == "clear" for d in checked if d is not hub)
    assert all("onchain_frozen" not in d for d in checked if d is not hub)
    assert "onchain_freeze" not in by[VICTIM]
    assert an.onchain_counts(elements)["frozen"] == 1
    # the pure function: no readings, no keys
    plain = to_cytoscape(build_graph(db, run))
    an.apply_onchain(plain, {})
    assert not any("onchain_freeze" in n["data"] for n in plain["nodes"])


def test_graph_api_and_legend(db, case, run, chain, client, app_with_router):
    _hub_frozen(db, case, chain)
    r = client.get(f"/api/cases/{case.id}/trace/{run.id}/graph")
    if r.status_code == 404:
        r = client.get(f"/api/cases/{case.id}/trace/runs/{run.id}/graph")
    assert r.status_code == 200
    body = r.text
    assert "onchain_frozen" in body and "Tether blacklist" in body
    page = client.get(f"/cases/{case.id}?tab=fund_flow&run_id={run.id}").text
    assert 'id="ff-lg-onchain"' in page and "frozen on-chain (issuer blacklist)" in page and "/static/css/freeze.css" in page


# --------------------------------------------------------------------------- overview & routes
def test_overview_shows_onchain_frozen_separately(db, case, run, chain, client, app_with_router):
    page = client.get(f"/cases/{case.id}").text
    assert "Frozen (confirmed holds)" in page and "Frozen on-chain (issuer blacklist)" in page
    assert "checks off: nothing is sent" in page and "Check freeze status now" not in page
    _hub_frozen(db, case, chain)
    page = client.get(f"/cases/{case.id}").text
    assert "$70,000.12" in page and "Tether blacklist" in page and "Check freeze status now" in page
    assert "confirmed by the exchange" in page and "cannot be seen on-chain" in page
    st = service.case_status(db, case)
    assert st["frozen_usd"] == 70000.12 and {"KuCoin", "Rainbet"} <= set(st["not_visible"])


def test_routes_roles_consent_and_audit(db, case, run, chain, client_for, app_with_router):
    ro = client_for("read_only", case=case)
    inv = client_for("investigator", case=case)
    adm = client_for("admin", case=case)
    ext = client_for("external", case=case)
    assert ro.get(f"/cases/{case.id}/freeze").status_code == 200
    assert ext.get(f"/cases/{case.id}/freeze").status_code == 403
    assert client_for(None).get(f"/cases/{case.id}/freeze").status_code == 404

    tok = csrf_token(ro, f"/cases/{case.id}/freeze")
    assert ro.post(f"/cases/{case.id}/freeze/check", data={"csrf_token": tok}).status_code == 403
    tok = csrf_token(inv, f"/cases/{case.id}/freeze")
    r = inv.post(f"/cases/{case.id}/freeze/check", data={"csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 409 and chain.calls == []  # off: nothing sent
    assert inv.post(f"/cases/{case.id}/freeze/settings", data={"csrf_token": tok, "enabled": "1", "consent": "1"}
                    ).status_code == 403
    assert inv.post(f"/cases/{case.id}/freeze/check", data={}, follow_redirects=False).status_code in (400, 403)  # CSRF

    tok = csrf_token(adm, f"/cases/{case.id}/freeze")
    r = adm.post(f"/cases/{case.id}/freeze/settings", data={"csrf_token": tok, "enabled": "1"}, follow_redirects=False)
    assert r.status_code == 400 and not service.is_enabled(db, case)  # no consent tick
    r = adm.post(f"/cases/{case.id}/freeze/settings", data={"csrf_token": tok, "enabled": "1", "consent": "1"},
                 follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    assert service.is_enabled(db, case)
    ev = db.scalar(select(AuditEvent).where(AuditEvent.action == "UPDATE", AuditEvent.object_type == "freeze_settings")
                   .order_by(AuditEvent.id.desc()).limit(1))
    assert ev.detail["consent"] is True and "ethereum-rpc.publicnode.com" in ev.detail["hosts"]

    tok = csrf_token(inv, f"/cases/{case.id}/freeze")
    r = inv.post(f"/cases/{case.id}/freeze/watch", data={"csrf_token": tok, "chain": "ethereum", "address": SYN_EVM,
                                                         "label": "consolidation", "source_note": "third-party trace report",
                                                         "tlp": "TLP:AMBER"}, follow_redirects=False)
    assert r.status_code == 303
    r = inv.post(f"/cases/{case.id}/freeze/watch", data={"csrf_token": tok, "chain": "ethereum", "address": SYN_EVM,
                                                         "tlp": "TLP:RED"}, follow_redirects=False)
    assert r.status_code == 400
    ev = db.scalar(select(AuditEvent).where(AuditEvent.action == "CREATE", AuditEvent.object_type == "freeze_watch")
                   .order_by(AuditEvent.id.desc()).limit(1))
    assert ev.detail == {"chain": "ethereum", "tlp": "TLP:AMBER", "has_label": True, "has_source_note": True}
    assert "third-party" not in json.dumps(ev.detail) and SYN_EVM not in json.dumps(ev.detail)

    r = inv.post(f"/cases/{case.id}/freeze/check", data={"csrf_token": tok, "next": f"/cases/{case.id}"},
                 follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/cases/{case.id}#freeze" and chain.calls
    ev = db.scalar(select(AuditEvent).where(AuditEvent.action == "FREEZE_CHECK").order_by(AuditEvent.id.desc()).limit(1))
    assert ev.actor_user_id == inv.user.id and ev.detail["trigger"] == "manual" and ev.detail["checked"] > 0
    r = inv.post(f"/cases/{case.id}/freeze/check", data={"csrf_token": tok, "next": "https://evil.example/"},
                 follow_redirects=False)
    assert r.headers["location"] == f"/cases/{case.id}/freeze#freeze"

    # the source note is investigator-only; read-only members see the reading and the TLP tag
    assert "third-party trace report" in inv.get(f"/cases/{case.id}/freeze").text
    ro_page = ro.get(f"/cases/{case.id}/freeze").text
    assert "third-party trace report" not in ro_page and SYN_EVM in ro_page and "TLP:AMBER" in ro_page
    api = ro.get(f"/api/cases/{case.id}/freeze").json()
    assert api["enabled"] and all(w["source_note"] is None for w in api["wallets"])

    wid = db.scalar(select(FreezeWatch.id).where(FreezeWatch.address == SYN_EVM))
    assert ro.post(f"/cases/{case.id}/freeze/watch/{wid}/remove", data={"csrf_token": csrf_token(ro, f"/cases/{case.id}/freeze")}
                   ).status_code == 403
    assert inv.post(f"/cases/{case.id}/freeze/watch/{wid}/remove", data={"csrf_token": tok},
                    follow_redirects=False).status_code == 303
    assert inv.post(f"/cases/{case.id}/freeze/watch/999999/remove", data={"csrf_token": tok}).status_code == 404

    r = adm.post(f"/cases/{case.id}/freeze/settings", data={"csrf_token": csrf_token(adm, f"/cases/{case.id}/freeze"),
                                                           "enabled": ""}, follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    assert not service.is_enabled(db, case)


# --------------------------------------------------------------------------- assistant
def test_freeze_status_skill(db, case, run, chain):
    from app.ai import skills

    assert skills.SKILLS["freeze-status"].min_role == CaseRole.READ_ONLY and not skills.SKILLS["freeze-status"].drafts
    ro = access_for(db, case, CaseRole.READ_ONLY)
    off = skills.run_skill(db, ro, "freeze-status", "")
    assert "**off**" in off.markdown and "Ask a case admin" in off.markdown and chain.calls == []
    service.add_watch(db, case, None, chain="tron", address=SYN_TRON, label="secret label", source_note="report Y",
                      tlp="TLP:AMBER+STRICT")
    # watched wallets with a CLEAR / no TLP: their free-text labels never reach the assistant either
    service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM, label="clear label from report Z",
                      source_note="report Z", tlp="TLP:CLEAR")
    other = "0x" + "cd" * 20
    service.add_watch(db, case, None, chain="ethereum", address=other, label="untagged label")
    chain.blacklisted.update({(USDT_TRON, SYN_TRON), (USDT_ETH, SYN_EVM)})
    chain.failed_transfer(other, USDC_ETH, T_FROZEN, "0x" + "0c" * 32)
    _hub_frozen(db, case, chain)
    n = len(chain.calls)
    res = skills.run_skill(db, ro, "freeze-status", "")
    assert len(chain.calls) == n  # read-only: the skill never queries the chain
    md = res.markdown
    assert "Blacklisted by the issuer" in md and "70,000.12 USDT" in md and "LE-cover letter" in md
    assert "Tether froze" in md and "law enforcement / seizure" in md
    assert "secret label" not in md and "report Y" not in md  # TLP:AMBER+STRICT label withheld, notes never shown
    assert "clear label" not in md and "report Z" not in md and "untagged label" not in md
    assert "watched wallet (TLP:CLEAR)" in md and "watched wallet (TLP:AMBER+STRICT)" in md
    assert "Transfers failing" in md and "| watched wallet |" in md
    assert "cannot be seen on-chain" in md and "KuCoin" in md
    assert any(a.get("href") == f"/cases/{case.id}/freeze" for a in res.actions)


# --------------------------------------------------------------------------- a lifted freeze
def _usdt_rows(db, wallet):
    return db.scalars(select(FreezeCheck).where(FreezeCheck.address == wallet, FreezeCheck.token_symbol == "USDT")
                      .order_by(FreezeCheck.id)).all()


def lifted_notes(db, case):
    return list(db.scalars(select(Notification).where(Notification.case_id == case.id,
                                                      Notification.event_type == "freeze_lifted")))


def test_blacklisted_removed_and_re_added(db, case, run, chain, client, app_with_router):
    """Tether blacklists the hub, then lifts it (RemovedBlackList), then blacklists it again: one freeze_detected
    per flip to blacklisted, one critical freeze_lifted for the lift, and the wallet reads 'unfrozen' (not a silent
    'not blacklisted') on every surface until the issuer blacklists it again."""
    from app.tracing import annotate as an
    from app.tracing.graph import build_graph, to_cytoscape

    db.execute(delete(Notification).where(Notification.event_type == "freeze_lifted"))
    db.commit()
    _hub_frozen(db, case, chain)
    assert len(freeze_notes(db, case)) == 1
    t_removed = datetime.now(tz=UTC).replace(microsecond=0) + timedelta(seconds=30)  # after the blacklisted reading
    chain.blacklisted.discard((USDT_ETH, HUB))
    chain.block = BLOCK + 100
    chain.removed_blacklist_log(HUB, t_removed, BLOCK + 60)
    chain.removed_blacklist_log(HUB, T_FROZEN - timedelta(days=30), BLOCK - 900, tx="0x" + "99" * 32)  # an older lift
    tp.clear_cache()
    rep = service.run_checks(db, case)
    row = _usdt_rows(db, HUB)[-1]
    assert row.blacklisted is False and rep.newly_lifted == [row.id] and rep.newly_frozen == []
    info = row.meta["unfrozen"]
    assert info["was_frozen_at_basis"] == "event" and info["was_frozen_at"] == T_FROZEN.isoformat(timespec="seconds")
    assert info["removed_at_basis"] == "event" and info["removed_tx"] == "0x" + "e2" * 32
    assert info["removed_at"] == t_removed.isoformat(timespec="seconds") and info["last_blacklisted_balance"]
    (note,) = lifted_notes(db, case)
    assert note.severity == "critical" and "funds can move" in note.title and case.reference in note.body
    assert "Tether" in note.title and HUB not in note.title + note.body
    assert notify.pii_findings(note.title + " " + note.body, case) == []
    st = service.case_status(db, case)
    (w,) = [w for w in st["wallets"] if w["address"] == HUB]
    assert w["state"] == "unfrozen" and st["unfrozen"] == [w] and not st["frozen"] and st["frozen_usd"] == 0
    assert w["checks"][0]["unfrozen"]["removed_at_basis"] == "event"
    page = client.get(f"/cases/{case.id}/freeze").text
    assert "freeze lifted: funds can move" in page and "Freeze lifted." in page and "removed from an issuer blacklist" in page
    overview = client.get(f"/cases/{case.id}").text
    assert "freeze lifted: funds can move" in overview and "1</b> freeze lifted" in overview
    elements = to_cytoscape(build_graph(db, run))
    an.annotate_elements(db, case, run, elements, can_act=True)
    hub = next(n["data"] for n in elements["nodes"] if n["data"]["address"].lower() == HUB)
    assert hub["onchain_unfrozen"] is True and "onchain_frozen" not in hub and hub["onchain_freeze"]["state"] == "unfrozen"
    # still not blacklisted: the lift stays on record (carried forward), no second notification
    tp.clear_cache()
    service.run_checks(db, case)
    again = _usdt_rows(db, HUB)[-1]
    assert again.meta["unfrozen"]["carried_from"] == row.id and len(lifted_notes(db, case)) == 1
    assert service.case_status(db, case)["unfrozen"]
    # blacklisted again: a new flip, a new freeze_detected; the state is frozen again
    chain.blacklisted.add((USDT_ETH, HUB))
    tp.clear_cache()
    rep = service.run_checks(db, case)
    assert len(rep.newly_frozen) == 1 and len(freeze_notes(db, case)) == 2 and len(lifted_notes(db, case)) == 1
    st = service.case_status(db, case)
    assert [w["address"] for w in st["frozen"]] == [HUB] and not st["unfrozen"]


def test_lift_without_an_explorer_is_bounded_by_the_checks(db, case, run, chain):
    noex = TEST_SETTINGS.model_copy(update={"aegis_freeze_explorer": "none"})
    service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM)
    service.set_enabled(db, case, None, True, settings=noex)
    db.commit()
    chain.blacklisted.add((USDT_ETH, SYN_EVM))
    chain.balances[(USDT_ETH, SYN_EVM)] = 2_000_000
    service.run_checks(db, case, settings=noex)
    first = _usdt_rows(db, SYN_EVM)[-1]
    assert first.meta["freeze_event_lookup"] == "no_explorer"
    assert "no explorer is configured" in service.frozen_at_note(first)
    chain.blacklisted.clear()
    tp.clear_cache()
    service.run_checks(db, case, settings=noex)
    row = _usdt_rows(db, SYN_EVM)[-1]
    info = row.meta["unfrozen"]
    assert info["removed_at_basis"] == "at_or_before" and info["removed_event_lookup"] == "no_explorer"
    d = service._check_dict(row)["unfrozen"]
    assert "removal event was not looked up" in d["removed_note"] and d["last_blacklisted_balance_label"] == "2.00"


def test_balance_destroyed_while_blacklisted_is_recorded(db, case, run, chain):
    service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM)
    enable(db, case)
    chain.blacklisted.add((USDT_ETH, SYN_EVM))
    chain.balances[(USDT_ETH, SYN_EVM)] = 9_000_000
    chain.added_blacklist_log(SYN_EVM, T_FROZEN, BLOCK - 40)
    service.run_checks(db, case)
    chain.balances[(USDT_ETH, SYN_EVM)] = 0
    chain.block = BLOCK + 10
    chain.logs.append({"address": USDT_ETH, "topics": [issuers.TOPIC_DESTROYED_BLACK_FUNDS],
                       "data": "0x" + abi.address_word(abi.evm_bytes(SYN_EVM)) + format(9_000_000, "064x"),
                       "blockNumber": hex(BLOCK + 5), "timeStamp": hex(int((T_FROZEN + timedelta(days=1)).timestamp())),
                       "transactionHash": "0x" + "d0" * 32})
    tp.clear_cache()
    service.run_checks(db, case)
    row = _usdt_rows(db, SYN_EVM)[-1]
    burnt = row.meta["balance_destroyed"]
    assert row.blacklisted and burnt["balance_before"] == "9" and burnt["tx"] == "0x" + "d0" * 32 and burnt["basis"] == "event"
    assert service._check_dict(row)["balance_destroyed"]["balance_before_label"] == "9.00"


# --------------------------------------------------------------------------- freeze time bound
def test_at_or_before_bound_is_carried_forward(db, case, run, chain):
    """Without an event the 'frozen at or before' time is the first check that saw the wallet blacklisted; a
    later check never moves it later. An event found later still upgrades the basis."""
    service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM)
    enable(db, case)
    chain.blacklisted.add((USDT_ETH, SYN_EVM))
    service.run_checks(db, case)
    first = _usdt_rows(db, SYN_EVM)[-1]
    assert first.frozen_at_basis == "at_or_before" and first.frozen_at == first.checked_at
    assert first.meta["freeze_event_lookup"] == "not_found"
    tp.clear_cache()
    service.run_checks(db, case)
    second = _usdt_rows(db, SYN_EVM)[-1]
    assert second.id != first.id and second.checked_at >= first.checked_at
    assert second.frozen_at == first.frozen_at and second.frozen_at_basis == "at_or_before"
    assert second.meta["frozen_at_check"] == first.id and second.meta["frozen_at_source"] == "check_time"
    assert service.frozen_at_note(second).startswith("the first check that read it blacklisted; ")
    tp.clear_cache()
    service.run_checks(db, case)
    assert _usdt_rows(db, SYN_EVM)[-1].frozen_at == first.frozen_at and _usdt_rows(db, SYN_EVM)[-1].meta["frozen_at_check"] == first.id
    # an earlier failed transfer wins over the carried bound
    t_fail = T_FROZEN - timedelta(days=1)
    chain.failed_transfer(SYN_EVM, USDT_ETH, t_fail, "0x" + "0f" * 32)
    tp.clear_cache()
    service.run_checks(db, case)
    row = _usdt_rows(db, SYN_EVM)[-1]
    assert row.frozen_at == t_fail and row.meta["frozen_at_source"] == "first_failed_transfer"
    # the explorer finds the event later: basis event
    chain.added_blacklist_log(SYN_EVM, T_FROZEN, BLOCK - 40)
    tp.clear_cache()
    service.run_checks(db, case)
    row = _usdt_rows(db, SYN_EVM)[-1]
    assert row.frozen_at_basis == "event" and row.frozen_at == T_FROZEN and len(freeze_notes(db, case)) == 1


def test_event_lookup_failure_is_named(db, case, run, chain, client, app_with_router):
    service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM)
    enable(db, case)
    chain.blacklisted.add((USDT_ETH, SYN_EVM))
    chain.logs_down = True
    service.run_checks(db, case)
    row = _usdt_rows(db, SYN_EVM)[-1]
    assert row.meta["freeze_event_error"] == "server"
    page = client.get(f"/cases/{case.id}/freeze").text
    assert "the blacklist event lookup failed (server)" in page and "not found in the explorer" not in page


def test_explorer_hashes_are_validated_before_storing(db, case, run, chain):
    assert service.clean_tx_hash("ethereum", "0x" + "AB" * 32) == "0x" + "ab" * 32
    assert service.clean_tx_hash("ethereum", "0x" + "ab" * 200) is None and service.clean_tx_hash("ethereum", "x") is None
    assert service.clean_tx_hash("tron", "0x" + "cd" * 32) == "cd" * 32 and service.clean_tx_hash("tron", "zz") is None
    service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM)
    enable(db, case)
    chain.blacklisted.add((USDT_ETH, SYN_EVM))
    chain.added_blacklist_log(SYN_EVM, T_FROZEN, BLOCK - 40, tx="0x" + "ab" * 300)  # oversized
    chain.failed_transfer(SYN_EVM, USDT_ETH, T_FROZEN, "0x" + "cd" * 300)
    rep = service.run_checks(db, case)
    row = _usdt_rows(db, SYN_EVM)[-1]
    assert rep.errors == 0 and row.status == "ok" and row.freeze_tx_hash is None and row.first_failed_tx is None
    assert row.frozen_at_basis == "at_or_before" and row.meta["freeze_event_error"] == "bad_tx_hash"
    assert row.meta["failed_txs"][0]["hash"] is None and row.failed_count == 1


# --------------------------------------------------------------------------- robustness
def test_a_host_that_is_down_is_not_called_for_every_wallet(db, case, run, chain):
    enable(db, case)
    chain.rpc_down = True
    rep = service.run_checks(db, case)
    rpc_calls = [c for c in chain.calls if c[0] == "ethereum-rpc.publicnode.com"]
    evm_rows = db.scalars(select(FreezeCheck).where(FreezeCheck.chain == "ethereum")).all()
    assert len(evm_rows) > 2 and {r.status for r in evm_rows} == {"error"}
    assert {r.error for r in evm_rows} == {"server", "host_unavailable"}
    assert len(rpc_calls) == 2 * (TEST_SETTINGS.aegis_freeze_retries + 1)  # two failed calls, then the breaker
    assert rep.errors == len(evm_rows)


def test_one_run_per_case_at_a_time(db, case, run, chain):
    enable(db, case)
    row = service.setting_for(db, case)
    row.run_started_at = datetime.now(tz=UTC) - timedelta(seconds=30)  # another run holds the claim
    db.commit()
    with pytest.raises(service.FreezeChecksDisabled) as e:
        service.run_checks(db, case)
    assert e.value.reason == "run_in_progress" and chain.calls == []
    assert service.case_status(db, case)["running"] is True
    assert service.run_due(db)["cases"] == 0 and chain.calls == []
    row.run_started_at = datetime.now(tz=UTC) - service.RUN_LEASE - timedelta(minutes=1)  # a crashed run
    db.commit()
    rep = service.run_checks(db, case)
    db.expire_all()
    assert rep.checked > 0 and service.setting_for(db, case).run_started_at is None
    assert service.case_status(db, case)["running"] is False


def test_endpoints_changed_since_the_consent(db, case, run, chain, client, client_for, app_with_router, monkeypatch):
    """ETHERSCAN_API_KEY set after the consent moves the explorer from Blockscout to etherscan.io: nothing is sent
    until a case admin confirms the new endpoints."""
    enable(db, case)
    keyed = TEST_SETTINGS.model_copy(update={"etherscan_api_key": "K" * 34, "aegis_freeze_explorer": "auto"})
    assert service.new_hosts(service.setting_for(db, case), keyed) == ["api.etherscan.io"]
    with pytest.raises(service.FreezeChecksDisabled) as e:
        service.run_checks(db, case, settings=keyed)
    assert e.value.reason == "consent_outdated" and chain.calls == []
    assert service.run_due(db, settings=keyed)["cases"] == 0 and chain.calls == []
    assert service.run_due(db, settings=keyed)["cases"] == 0
    denied = [a for a in db.scalars(select(AuditEvent).where(AuditEvent.action == "FREEZE_CHECK",
                                                             AuditEvent.outcome == "denied", AuditEvent.case_id == case.id))
              if a.detail.get("reason") == "consent_outdated"]
    assert len(denied) == 1  # audited once, not on every scheduler pass
    assert denied[0].detail["hosts"] == ["api.etherscan.io"]
    monkeypatch.setattr(service, "_settings", lambda settings=None: settings or keyed)
    inv = client_for("investigator", case=case)
    tok = csrf_token(inv, f"/cases/{case.id}/freeze")
    r = inv.post(f"/cases/{case.id}/freeze/check", data={"csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 409 and "endpoints" in r.text and chain.calls == []
    page = client.get(f"/cases/{case.id}/freeze").text
    assert "Endpoints changed, re-confirm" in page and "Confirm the new endpoints" in page and "api.etherscan.io" in page
    assert "Check freeze status now" not in page
    tok = csrf_token(client, f"/cases/{case.id}/freeze")
    assert client.post(f"/cases/{case.id}/freeze/settings", data={"csrf_token": tok, "enabled": "1", "consent": "1"},
                       follow_redirects=False).status_code == 303
    db.expire_all()
    assert service.new_hosts(service.setting_for(db, case), keyed) == []
    assert "refused" not in service.setting_for(db, case).last_result


def test_next_with_dot_segments_stays_on_the_freeze_page(db, case, run, chain, client_for, app_with_router):
    from app.web.routes_freeze import _back

    assert _back(1, "/cases/1") == "/cases/1" and _back(1, "/cases/1/freeze?x=1#a", "#freeze") == "/cases/1/freeze?x=1#freeze"
    for bad in ("/cases/1/../../evil", "/cases/1/./x", "/cases/1/..", "/cases/1/%2e%2e/evil", "/cases/12", "//evil"):
        assert _back(1, bad) == "/cases/1/freeze", bad
    enable(db, case)
    inv = client_for("investigator", case=case)
    tok = csrf_token(inv, f"/cases/{case.id}/freeze")
    r = inv.post(f"/cases/{case.id}/freeze/check", data={"csrf_token": tok, "next": f"/cases/{case.id}/../../evil"},
                 follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/cases/{case.id}/freeze#freeze"


# --------------------------------------------------------------------------- an outage never hides the last good reading
def test_a_failed_check_never_shadows_the_last_good_reading_and_a_drop_notifies(db, case, run, chain, client,
                                                                                 app_with_router):
    service.add_watch(db, case, None, chain="ethereum", address=SYN_EVM)
    enable(db, case)
    chain.balances[(USDT_ETH, SYN_EVM)] = 12_600 * 10**6
    chain.blacklisted.add((USDC_ETH, SYN_EVM))
    service.run_checks(db, case)
    tp.clear_cache()
    chain.rpc_error_wallets.add(SYN_EVM)  # an outage: every reading of the wallet fails
    rep = service.run_checks(db, case)
    assert rep.errors >= 2
    st = service.case_status(db, case)
    w = next(w for w in st["wallets"] if w["address"] == SYN_EVM)
    usdt = next(c for c in w["checks"] if c["symbol"] == "USDT")
    usdc = next(c for c in w["checks"] if c["symbol"] == "USDC")
    assert usdt["status"] == "ok" and usdt["balance_label"] == "12,600.00"
    assert "last checked OK" in usdt["stale_note"] and "the last attempt failed (rpc_error" in usdt["stale_note"]
    assert usdc["blacklisted"] and w["state"] == "frozen" and w in st["frozen"] and w in st["stale"]
    assert w not in st["errors"]
    page = client.get(f"/cases/{case.id}/freeze").text
    assert "last checked OK" in page and "the next run retries" in page
    from app.ai import skills

    md = skills.run_skill(db, access_for(db, case, CaseRole.READ_ONLY), "freeze-status", "").markdown
    assert "**Last attempt failed**" in md and "the last good reading is shown" in md
    oc = bs.onchain_by_issuer(db, case)  # the Block status overlay reads the same good reading
    assert any(e["address"] == SYN_EVM for e in oc["Circle"]["frozen"])
    # the wallet is drained between two good readings: the funds are moving (one high notification, never twice)
    tp.clear_cache()
    chain.rpc_error_wallets.discard(SYN_EVM)
    chain.balances[(USDT_ETH, SYN_EVM)] = 250_000
    rep = service.run_checks(db, case)
    assert len(rep.funds_left) == 1
    w = next(w for w in service.case_status(db, case)["wallets"] if w["address"] == SYN_EVM)
    f = next(c for c in w["checks"] if c["symbol"] == "USDT")["funds_left"]
    assert f["from_label"] == "12,600.00" and f["to_label"] == "0.25" and f["usd"] > 12_000
    notes = [n for n in db.scalars(select(Notification).where(Notification.case_id == case.id,
                                                              Notification.event_type == "wallet_movement"))
             if (n.payload or {}).get("freeze_check_id") in rep.funds_left]
    assert len(notes) == 1 and notes[0].severity == "high" and "Funds left" in notes[0].title
    assert "Funds left this wallet" in client.get(f"/cases/{case.id}/freeze").text
    md = skills.run_skill(db, access_for(db, case, CaseRole.READ_ONLY), "freeze-status", "").markdown
    assert "**Funds left these wallets**" in md and "12,600.00" in md and "re-trace now" in md
    assert "funds left" in client.get(f"/cases/{case.id}").text
    tp.clear_cache()
    assert service.run_checks(db, case).funds_left == []  # the same balance again: no second alert
