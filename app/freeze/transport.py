"""HTTP for the freeze checks: JSON-RPC and explorer / TronGrid calls with an allow-list, retries,
a per-host rate limiter and a short result cache.

    http = FreezeHttp(settings)                       # tests: FreezeHttp(settings, transport=httpx.MockTransport(...))
    result, resp = http.rpc(url, "eth_call", [{"to": …, "data": …}, "0x…"])
    resp = http.get(url, params={…})                  # resp.data (parsed JSON), resp.sha256, resp.fetched_at

* **Hosts.** Only `ALLOWED_DOMAINS` (or the client's `allowed_domains`: app.attribution passes its own) and
  their sub-domains over https, plus localhost (http or https)
  for a self-hosted node. Anything else raises `FreezeHttpError("host_not_allowed")` before a socket
  is opened. Redirects are not followed.
* **No ambient proxy / credentials.** `trust_env=False`: no HTTP(S)_PROXY, no .netrc.
* **Retries.** HTTP 429, 5xx, timeouts and connection errors are retried up to `retries` times with
  exponential backoff (1 s, 2 s, 4 s …, capped at 30 s; a `Retry-After` in seconds wins, also capped).
  Public endpoints do rate-limit (Blockscout answered 429 on 19 Oct 2026). Other 4xx are not retried.
* **Circuit breaker.** After `breaker_after` (2) calls in a row to one host that failed for good (retries used
  up on 429, 5xx, a timeout or a connection error), this client sends that host nothing more: every further
  call raises `FreezeHttpError("host_unavailable")` at once, so one run against a host that is down costs a
  couple of failed calls, not (retries + 1) x timeout for every wallet and contract. A new client (the next
  run) tries the host again.
* **Rate limiter.** At most one request per `min_interval` seconds per host, process-wide.
* **Cache.** An identical request (method, URL, parameters, body) within `cache_minutes` returns the
  stored answer (`resp.cached` = True, `fetched_at` = the original time), so pressing "Check now" twice
  does not query twice.
* **Errors** carry a reason code and the host only, never the URL query (an Etherscan key travels in
  it) or a header.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Self
from urllib.parse import urlsplit

import httpx

ALLOWED_DOMAINS = ("publicnode.com", "blockscout.com", "etherscan.io", "trongrid.io")
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
MAX_BACKOFF_S = 30.0
BREAKER_AFTER = 2  # calls in a row that failed for good before a client stops calling the host
BREAKER_REASONS = ("rate_limited", "server", "network", "timeout")
USER_AGENT = "Aegis freeze-check (Athena Software Group, Inc.)"


class FreezeHttpError(RuntimeError):
    """A failed call. `reason`: host_not_allowed | host_unavailable | rate_limited | server | network | timeout
    | http_<code> | bad_json | rpc_error | bad_response."""

    def __init__(self, reason: str, host: str | None = None, detail: str | None = None):
        super().__init__(f"{reason} ({host or 'no host'})" + (f": {detail}" if detail else ""))
        self.reason, self.host, self.detail = reason, host, (detail or "")[:200] or None


@dataclass
class Response:
    data: Any
    sha256: str  # of the raw response body
    host: str
    fetched_at: datetime
    cached: bool = False
    status: int = 200


def host_allowed(url: str, domains: tuple[str, ...] = ALLOWED_DOMAINS) -> bool:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host in LOCAL_HOSTS:
        return parts.scheme in ("http", "https")
    if parts.scheme != "https" or not host:
        return False
    return any(host == d or host.endswith("." + d) for d in domains)


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


# process-wide limiter and cache (a scheduler pass and a web request share them)
_lock = threading.Lock()
_last_call: dict[str, float] = {}
_cache: dict[str, tuple[float, Response]] = {}


def clear_cache() -> None:
    with _lock:
        _cache.clear()
        _last_call.clear()


class FreezeHttp:
    def __init__(self, settings=None, *, transport: httpx.BaseTransport | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                 retries: int | None = None, min_interval: float | None = None, cache_minutes: float | None = None,
                 timeout: float | None = None, breaker_after: int = BREAKER_AFTER,
                 allowed_domains: tuple[str, ...] = ALLOWED_DOMAINS, user_agent: str = USER_AGENT):
        if settings is None:
            from app.core.config import get_settings

            settings = get_settings()
        self.retries = settings.aegis_freeze_retries if retries is None else retries
        self.min_interval = settings.aegis_freeze_min_interval if min_interval is None else min_interval
        self.cache_s = 60.0 * (settings.aegis_freeze_cache_minutes if cache_minutes is None else cache_minutes)
        self.sleep, self.clock = sleep, clock
        self.allowed = tuple(allowed_domains)  # app.attribution passes its own list (explorer tag lookups)
        self.client = httpx.Client(
            transport=transport, trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(settings.aegis_freeze_timeout if timeout is None else timeout),
            headers={"User-Agent": user_agent, "Accept": "application/json"},
        )
        self.requests = 0  # network requests actually sent (cache hits not counted)
        self.hosts: set[str] = set()
        self.breaker_after = max(1, breaker_after)
        self.failures: dict[str, int] = {}  # host -> calls in a row that failed for good
        self.tripped: set[str] = set()  # hosts this client no longer calls

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ plumbing
    def _throttle(self, host: str) -> None:
        with _lock:
            last = _last_call.get(host)
            now = self.clock()
            wait = 0.0 if last is None else self.min_interval - (now - last)
            _last_call[host] = now + max(wait, 0.0)
        if wait > 0:
            self.sleep(wait)

    @staticmethod
    def _delay(attempt: int, resp: httpx.Response | None) -> float:
        if resp is not None:
            ra = resp.headers.get("retry-after", "").strip()
            if ra.isdigit():
                return min(float(ra), MAX_BACKOFF_S)
        return min(2.0 ** attempt, MAX_BACKOFF_S)

    def request(self, method: str, url: str, *, params: dict | None = None, json_body: Any = None,
                headers: dict | None = None) -> Response:
        if not host_allowed(url, self.allowed):
            raise FreezeHttpError("host_not_allowed", host_of(url))
        host = host_of(url)
        key = json.dumps([method, url, sorted((params or {}).items()), json_body], sort_keys=True, default=str)
        now = self.clock()
        with _lock:
            hit = _cache.get(key)
        if hit is not None and now - hit[0] < self.cache_s:
            r = hit[1]
            return Response(data=r.data, sha256=r.sha256, host=r.host, fetched_at=r.fetched_at, cached=True,
                            status=r.status)
        if host in self.tripped:
            raise FreezeHttpError("host_unavailable", host, "earlier calls in this run failed")
        last_reason = "network"
        for attempt in range(self.retries + 1):
            self._throttle(host)
            resp = None
            try:
                self.requests += 1
                self.hosts.add(host)
                resp = self.client.request(method, url, params=params, json=json_body, headers=headers)
            except httpx.TimeoutException:
                last_reason = "timeout"
            except httpx.HTTPError:
                last_reason = "network"
            else:
                if resp.status_code == 429:
                    last_reason = "rate_limited"
                elif resp.status_code >= 500:
                    last_reason = "server"
                elif resp.status_code >= 400:
                    self.failures[host] = 0  # the host answers: a 4xx is about this request
                    raise FreezeHttpError(f"http_{resp.status_code}", host)
                else:
                    self.failures[host] = 0
                    raw = resp.content
                    try:
                        data = json.loads(raw.decode("utf-8") or "null")
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        raise FreezeHttpError("bad_json", host) from None
                    out = Response(data=data, sha256=hashlib.sha256(raw).hexdigest(), host=host,
                                   fetched_at=datetime.now(tz=UTC), status=resp.status_code)
                    with _lock:
                        _cache[key] = (self.clock(), out)
                    return out
            if attempt < self.retries:
                self.sleep(self._delay(attempt, resp))
        self.failures[host] = self.failures.get(host, 0) + 1
        if last_reason in BREAKER_REASONS and self.failures[host] >= self.breaker_after:
            self.tripped.add(host)
        raise FreezeHttpError(last_reason, host)

    # ------------------------------------------------------------------ helpers
    def get(self, url: str, *, params: dict | None = None, headers: dict | None = None) -> Response:
        return self.request("GET", url, params=params, headers=headers)

    def post(self, url: str, body: Any, *, headers: dict | None = None) -> Response:
        return self.request("POST", url, json_body=body, headers=headers)

    def rpc(self, url: str, method: str, params: list) -> tuple[Any, Response]:
        """One JSON-RPC 2.0 call. A JSON-RPC error object raises FreezeHttpError("rpc_error")."""
        resp = self.post(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        data = resp.data if isinstance(resp.data, dict) else {}
        if data.get("error") is not None:
            err = data["error"]
            msg = err.get("message") if isinstance(err, dict) else str(err)
            raise FreezeHttpError("rpc_error", resp.host, str(msg)[:200])
        if "result" not in data:
            raise FreezeHttpError("bad_response", resp.host)
        return data["result"], resp
