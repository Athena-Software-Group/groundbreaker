"""app.freeze.transport: host allow-list, no ambient proxy, retries with backoff on 429 / 5xx, no retry on
other 4xx, JSON-RPC errors, the result cache and the per-host rate limiter. httpx.MockTransport only."""

from __future__ import annotations

import json

import httpx
import pytest

from app.core.config import get_settings
from app.freeze import transport as tp
from app.freeze.transport import FreezeHttp, FreezeHttpError

RPC = "https://ethereum-rpc.publicnode.com"


@pytest.fixture(autouse=True)
def _fresh():
    tp.clear_cache()
    yield
    tp.clear_cache()


class Clock:
    def __init__(self):
        self.t = 1000.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.slept.append(round(s, 3))
        self.t += s


def make(handler, **kw) -> tuple[FreezeHttp, Clock]:
    clock = Clock()
    http = FreezeHttp(get_settings(), transport=httpx.MockTransport(handler), sleep=clock.sleep, clock=clock, **kw)
    return http, clock


def rpc_ok(result):
    return lambda request: httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})


@pytest.mark.parametrize("url,ok", [
    ("https://ethereum-rpc.publicnode.com", True), ("https://eth.blockscout.com/api", True),
    ("https://api.etherscan.io/v2/api", True), ("https://api.trongrid.io/wallet/x", True),
    ("http://localhost:8545", True), ("http://127.0.0.1:8545", True),
    ("http://ethereum-rpc.publicnode.com", False),  # plain http to a public host
    ("https://evil.example/publicnode.com", False), ("https://publicnode.com.evil.example", False),
    ("https://mainnet.infura.io/v3/x", False), ("ftp://localhost/x", False),
])
def test_host_allow_list(url, ok):
    assert tp.host_allowed(url) is ok


def test_refused_host_sends_nothing():
    seen = []
    http, _ = make(lambda r: seen.append(r) or httpx.Response(200, json={}))
    with pytest.raises(FreezeHttpError) as e:
        http.get("https://rpc.evil.example/")
    assert e.value.reason == "host_not_allowed" and seen == [] and http.requests == 0


def test_client_ignores_ambient_proxy_settings(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    http, _ = make(rpc_ok("0x1"))
    assert http.client._trust_env is False
    result, resp = http.rpc(RPC, "eth_blockNumber", [])
    assert result == "0x1" and resp.host == "ethereum-rpc.publicnode.com" and len(resp.sha256) == 64


def test_retries_429_with_retry_after_then_succeeds():
    answers = [httpx.Response(429, headers={"Retry-After": "3"}), httpx.Response(503),
               httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x10"})]
    calls = []

    def handler(request):
        calls.append(json.loads(request.content))
        return answers[len(calls) - 1]

    http, clock = make(handler, retries=3, min_interval=0)
    result, _ = http.rpc(RPC, "eth_blockNumber", [])
    assert result == "0x10" and len(calls) == 3 and http.requests == 3
    assert clock.slept == [3.0, 2.0]  # Retry-After wins, then exponential backoff (2^1)


def test_gives_up_after_retries():
    http, clock = make(lambda r: httpx.Response(429), retries=2, min_interval=0)
    with pytest.raises(FreezeHttpError) as e:
        http.rpc(RPC, "eth_blockNumber", [])
    assert e.value.reason == "rate_limited" and http.requests == 3 and clock.slept == [1.0, 2.0]


def test_timeouts_are_retried_and_reported():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    http, _ = make(handler, retries=1, min_interval=0)
    with pytest.raises(FreezeHttpError) as e:
        http.get(RPC)
    assert e.value.reason == "timeout" and http.requests == 2


def test_other_4xx_is_not_retried_and_never_echoes_the_query():
    http, _ = make(lambda r: httpx.Response(403), retries=3, min_interval=0)
    with pytest.raises(FreezeHttpError) as e:
        http.get("https://api.etherscan.io/v2/api", params={"apikey": "SECRET-KEY-123"})
    assert e.value.reason == "http_403" and http.requests == 1
    assert "SECRET-KEY-123" not in str(e.value) and "apikey" not in str(e.value)


def test_json_rpc_error_object():
    http, _ = make(lambda r: httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,
                                                       "error": {"code": -32000, "message": "execution reverted"}}))
    with pytest.raises(FreezeHttpError) as e:
        http.rpc(RPC, "eth_call", [{}, "latest"])
    assert e.value.reason == "rpc_error" and "execution reverted" in (e.value.detail or "")


def test_bad_json():
    http, _ = make(lambda r: httpx.Response(200, content=b"<html>busy</html>"))
    with pytest.raises(FreezeHttpError) as e:
        http.get(RPC)
    assert e.value.reason == "bad_json"


def test_cache_reuses_an_identical_request():
    n = []
    http, clock = make(lambda r: n.append(1) or httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x2"}),
                       cache_minutes=10, min_interval=0)
    _, first = http.rpc(RPC, "eth_blockNumber", [])
    _, second = http.rpc(RPC, "eth_blockNumber", [])
    assert len(n) == 1 and second.cached and not first.cached and second.sha256 == first.sha256
    assert second.fetched_at == first.fetched_at  # the reading keeps its original time
    clock.t += 601
    _, third = http.rpc(RPC, "eth_blockNumber", [])
    assert len(n) == 2 and not third.cached


def test_rate_limiter_spaces_requests_per_host():
    http, clock = make(lambda r: httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x1"}),
                       min_interval=0.5, cache_minutes=0)
    http.rpc(RPC, "eth_blockNumber", [])
    http.rpc(RPC, "eth_chainId", [])
    http.get("https://eth.blockscout.com/api")  # another host: no wait
    assert clock.slept == [0.5]


def test_circuit_breaker_stops_calling_a_host_that_is_down():
    """A host that keeps failing (5xx / timeouts after the retries) is not called again by this client:
    one run against a dead node costs two failed calls, not (retries + 1) x timeout per wallet and contract."""
    seen = []

    def handler(request):
        seen.append(request.url.host)
        if request.url.host == "eth.blockscout.com":
            return httpx.Response(200, json={"status": "1", "result": []})
        return httpx.Response(503)

    http, clock = make(handler, retries=1, min_interval=0, cache_minutes=0)
    for _ in range(2):
        with pytest.raises(FreezeHttpError) as e:
            http.rpc(RPC, "eth_blockNumber", [])
        assert e.value.reason == "server"
    assert len(seen) == 4 and "ethereum-rpc.publicnode.com" in http.tripped
    for _ in range(5):  # tripped: refused at once, nothing sent, no backoff
        with pytest.raises(FreezeHttpError) as e:
            http.rpc(RPC, "eth_call", [{}, "latest"])
        assert e.value.reason == "host_unavailable"
    assert len(seen) == 4 and http.requests == 4 and clock.slept == [1.0, 1.0]
    http.get("https://eth.blockscout.com/api")  # another host is still called
    assert seen[-1] == "eth.blockscout.com"
    fresh, _ = make(handler, retries=0, min_interval=0, cache_minutes=0)  # the next run tries again
    with pytest.raises(FreezeHttpError) as e:
        fresh.rpc(RPC, "eth_blockNumber", [])
    assert e.value.reason == "server"


def test_circuit_breaker_resets_on_an_answer():
    answers = iter([httpx.Response(503), httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x1"}),
                    httpx.Response(503), httpx.Response(503)])
    http, _ = make(lambda r: next(answers), retries=0, min_interval=0, cache_minutes=0)
    with pytest.raises(FreezeHttpError):
        http.rpc(RPC, "eth_blockNumber", [])
    assert http.rpc(RPC, "eth_chainId", [])[0] == "0x1"  # an answer in between: the count starts again
    with pytest.raises(FreezeHttpError) as e:
        http.rpc(RPC, "eth_gasPrice", [])
    assert e.value.reason == "server" and not http.tripped
