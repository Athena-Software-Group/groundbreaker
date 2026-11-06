# On-chain freeze detection

_Code: `app/freeze/`, `app/web/routes_freeze.py`, migration `0009_freeze_checks`._

Stablecoin issuers can freeze a self-custodied wallet: Tether blacklists it in the USDT contract and
Circle in the USDC contract. A frozen wallet's tokens cannot move. This is visible to anyone, because the
contracts expose the blacklist. Before this feature, Aegis learned about a freeze only from a stop-order
reply ("frozen, amount held"). It now reads the issuers' contracts directly, much as commercial tracing
vendors do: they call the contract's blacklist getter (Etherscan's "Read contract" `isBlackListed` /
`getBlackListStatus`) and look for transfers that fail.

**What it cannot see:** a freeze *inside* a custodial service. Exchange and casino accounts (in the demo
case, KuCoin and Rainbet) are ledger entries in the service's own database, not wallets. Their freeze stays
**confirmed by the recipient's reply** (Authorities tab → status "frozen" with the amount held). The UI says
this wherever the on-chain status is shown.

## 1. Consent first: nothing is sent while the setting is off

A check sends the case's wallet addresses to public endpoints, and that can link them to the investigation
(docs/data-handling.md §6). Because of that:

* **Per-case setting "On-chain freeze checks"** (`freeze_settings.enabled`) is **off by default**. Only a case
  admin can switch it, on the case's freeze page (`/cases/{id}/freeze`, *Set up on-chain checks* on the
  Overview). Before switching it on, the page lists every endpoint and what it receives, and the admin
  ticks a confirmation. The admin, the time and the hosts go into `freeze_settings.consent` and an `UPDATE`
  audit row (`setting=onchain_freeze_checks`, `consent=true`, `hosts=[…]`).
* `app.freeze.service.run_checks` raises `FreezeChecksDisabled` before it builds an HTTP client, unless the
  setting is on. The scheduler only runs enabled, open cases.
* **Changed endpoints need a fresh consent.** Before every run the hosts the checks would use now
  (`consent_hosts(egress_plan())`) are compared with the consented ones. A host the admin did not see (an
  `ETHERSCAN_API_KEY` set later moves the explorer from Blockscout to etherscan.io in `auto` mode; a new
  `AEGIS_ETH_RPC_URL`) stops the checks (`consent_outdated`, audited as a denied `FREEZE_CHECK` with the new
  hosts; the scheduler audits it once, not on every pass). The freeze page says *Endpoints changed,
  re-confirm*, and the case admin confirms the new list there.
* **One run per case at a time.** A run claims the case with a conditional `UPDATE` of
  `freeze_settings.run_started_at` (taken over after 15 minutes, a crashed run). A second *Check now* or a
  scheduler pass meanwhile gets `run_in_progress` (409, nothing sent), so two runs never read the same
  earlier reading and flip it twice.
* **Deployment kill switch:** `AEGIS_FREEZE_CHECKS_DISABLED=1` stops every check on every case.
* The *Check freeze status now* button (investigator+, CSRF) and every scheduler run are audited as
  `FREEZE_CHECK`, with counts and hosts only. Wallet labels, source notes and URLs are never written there.

## 2. What is read, and from where

| Issuer | Token | Chain | Contract | Status call | Freeze event |
|---|---|---|---|---|---|
| Tether | USDT | Ethereum | `0xdAC17F958D2ee523a2206206994597C13D831ec7` | `isBlackListed(address)` `0xe47d6060` (fallback `getBlackListStatus` `0x59bf1abe`) | `AddedBlackList(address)` `0x42e16015…819dc` (address in the **data**, not indexed) |
| Tether | USDT | TRON | `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` | `isBlackListed(address)` via TronGrid `/wallet/triggerconstantcontract` | `AddedBlackList` via TronGrid `/v1/contracts/{c}/events` |
| Circle | USDC | Ethereum | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` | `isBlacklisted(address)` `0xfe575a87` | `Blacklisted(address indexed)` |
| Circle | USDC | Base, Arbitrum One, Polygon PoS, OP Mainnet | native USDC (`app/freeze/issuers.py`) | `isBlacklisted(address)` | `Blacklisted(address indexed)` |

`balanceOf(address)` (`0x70a08231`) gives the amount held; all six contracts use 6 decimals. On EVM chains
the blacklist call and `balanceOf` both run at the block returned by `eth_blockNumber`, so the reading names
the block it is true for. TronGrid's constant call reports no block. Selectors and topics are computed with
Keccak-256 in `app/freeze/abi.py` and checked against the published values in `tests/test_freeze_abi.py`.
Every EVM contract address there must pass its EIP-55 checksum.
TODO: USDT on other chains and USDC on Solana / TRON. Add a contract only from the issuer's own published
list.

| Endpoint | Setting (default) | Receives |
|---|---|---|
| Ethereum JSON-RPC | `AEGIS_ETH_RPC_URL` (`https://ethereum-rpc.publicnode.com`) | each wallet inside `eth_call` (blacklist getter, `balanceOf`), `eth_blockNumber`; freeze-watch wallets also `eth_getBalance`, `eth_getTransactionCount` |
| Base / Arbitrum / Polygon / OP JSON-RPC | `AEGIS_BASE_RPC_URL`, `AEGIS_ARBITRUM_RPC_URL`, `AEGIS_POLYGON_RPC_URL`, `AEGIS_OPTIMISM_RPC_URL` (empty: not checked) | as above |
| Explorer logs / txlist | Etherscan V2 when `ETHERSCAN_API_KEY` is set, else Blockscout (`AEGIS_FREEZE_EXPLORER=auto\|etherscan\|blockscout\|none`) | each wallet (account `txlist`); the issuer contract plus a block range (Circle: plus the wallet) in a logs query |
| TronGrid | `AEGIS_TRONGRID_URL` (`https://api.trongrid.io`), optional `TRONGRID_API_KEY` header | each TRON wallet (constant calls, outgoing transactions), the USDT contract's `AddedBlackList` events |

**Transport** (`app/freeze/transport.py`):

* A host allow-list: `publicnode.com`, `blockscout.com`, `etherscan.io`, `trongrid.io` (and sub-domains) over
  https, plus `localhost` for a self-hosted node.
* `trust_env=False` and no redirects.
* Timeouts: `AEGIS_FREEZE_TIMEOUT`, 15 s.
* Retries on 429, 5xx, timeouts and connection errors: `AEGIS_FREEZE_RETRIES`, 3, with exponential backoff
  of 1, 2, 4 s, capped at 30 s. A `Retry-After` header wins. Public endpoints do rate-limit: Blockscout
  answered 429 on 19 Oct 2026.
* A per-host rate limiter: `AEGIS_FREEZE_MIN_INTERVAL`, 0.25 s.
* A per-run circuit breaker: after two calls in a row to a host failed for good (retries used up on 429, 5xx, a
  timeout or a connection error), the run sends that host nothing more; the remaining readings are stored as
  errors with `host_unavailable` and the next run tries again. A dead host costs a run two failed calls, not
  (retries + 1) × timeout per wallet and contract.
* A result cache: `AEGIS_FREEZE_CACHE_MINUTES`, 10.

Errors carry a reason code and the host, never the query string, because an Etherscan key travels in it.

## 3. Which wallets

* **From the trace:** every address of the latest run, on a chain listed above, that sent or received
  USDT / USDC in the run. Only that token's contract is checked for it. Excluded: the victim, `*_PENDING`
  placeholders, context-only nodes, contracts, and DEX / bridge / mixer addresses.
* **Watched wallets** (*Add wallet to watch* on the freeze page, investigator+): chain, address, label, source
  note (e.g. "third-party trace report") and the source's TLP marking. A mixed-case EVM address must pass its
  EIP-55 checksum (a typo is refused instead of checking another wallet); all-lower / all-upper case is
  accepted. Every issuer contract on the chain is
  checked. They are stored case-scoped in `freeze_watch`.
  * TLP:RED is refused. It is for named recipients only (docs/data-handling.md §7).
  * The label and source note stay on the case's freeze page. They never appear in notifications, the audit
    log or the assistant, whatever the TLP (`/freeze-status` names a watched wallet "watched wallet (TLP:…)";
    a trace wallet keeps the trace's own entity or address label). The source note is shown to investigators
    and admins only.
* Do not add a wallet taken from a third-party report to the repository or to the demo fixture. Real cases
  add them through the UI.

## 4. What a check records (`freeze_checks`)

One row per wallet and issuer contract per run:

* `blacklisted`, `balance` (token units; `meta.balance_raw` keeps the exact uint256), `block_number`,
  `checked_at` and `method` (`rpc`).
* `raw_sha256`: the sha256 of the blacklist call's raw response. `meta.responses` holds the hash of every
  other response, which makes the reading reproducible evidence: provider, endpoint, time and response hash.
* `status` / `error` when the read failed (`rpc_error`, `rate_limited`, `timeout`, …). The next run retries.
* `source` (`trace` | `watched`) and `trigger` (`manual` | `scheduler`).

**Freeze time.** The node only answers "blacklisted now", and `eth_getLogs` over a long range needs an
archive node on public RPCs. So Aegis asks the explorer's logs API for the issuer's blacklist event:

* **Tether** does not index the address, so every `AddedBlackList` of the block range is read and matched on
  the data. A range returning 1,000 rows (the API's limit) is split in two, up to 16 calls.
* **Circle** is filtered on `topic1`.
* The range starts at the block where the wallet first received the token in the trace (else
  `AEGIS_FREEZE_LOG_LOOKBACK_BLOCKS`, 500,000 back) and ends at the checked block.

When the event is found, Aegis records `frozen_at` (the block time), `freeze_tx_hash` and
`frozen_at_basis = event`. The event is not queried again on later runs. When it is not found, Aegis records
an upper bound, `frozen_at_basis = at_or_before`: the earliest of the first failed transfer, this check, and,
while the wallet stays blacklisted, the bound of the earlier reading (`meta.frozen_at_check`), so re-checks
never move the bound later; an event found later still upgrades it to `event`. The UI says "frozen at or
before …" with the reason: no explorer configured for the chain (`AEGIS_FREEZE_EXPLORER=none`, OP Mainnet
without a key), the event lookup failed (with its reason, e.g. `rate_limited`), or not found in the logs.
Transaction hashes from the explorer / TronGrid are checked before they are stored (EVM `0x` + 64 hex, TRON
64 hex); anything else is dropped (`freeze_event_error = bad_tx_hash`).

**Lifted freezes.** When the earlier reading of a wallet / contract was blacklisted and the new one is not, the
issuer has lifted the freeze and the funds can move again. The reading keeps `meta.unfrozen`: when it was
frozen (time, basis, tx), the last blacklisted balance and when it was removed: the issuer's removal event
(Tether `RemovedBlackList`, Circle `UnBlacklisted`; explorer logs from the earlier reading's block, TronGrid
`event_name=RemovedBlackList`), else "at or before" this check. The wallet's state is `unfrozen` (*freeze
lifted: funds can move*) on the freeze page, the Overview and the graph, and later readings carry the record
until the issuer blacklists the wallet again. A blacklisted balance that drops to zero is recorded as
`meta.balance_destroyed` (Tether `DestroyedBlackFunds`, with the event when the explorer has it).

**Supporting signal (failed transfers)** (`app/freeze/signals.py`):

* EVM: the wallet's transactions *to the token contract* calling `transfer` (`0xa9059cbb`), `transferFrom`
  (`0x23b872dd`) or `approve` (`0x095ea7b3`) that reverted, read from the explorer account `txlist`
  (`isError` = 1 / `txreceipt_status` = 0). The tracer's provider drops failed transactions, so the list is
  fetched unfiltered.
* TRON: `TriggerSmartContract` calls with `contractRet` other than `SUCCESS`.
* Shown as "transfer attempts failing since <time> (n attempts)" with the tx links. Without a blacklist
  reading this is only a hint: low balance or gas also make transfers fail.

## 5. Notifications, display, assistant, scheduler

* **`freeze_detected`** (critical, in-app by default; a rule per case like every event type) is emitted the
  first time a wallet / contract reads blacklisted: no earlier reading, or the earlier one was not
  blacklisted. It fires once per flip, never on every re-check. If the issuer removes the wallet and later
  re-adds it, that is a new flip. The body carries the case reference, issuer, short address, amount and
  block, and nothing else (no label, no source note).
* **`freeze_lifted`** (critical, in-app by default) is emitted once when a blacklisted wallet reads not
  blacklisted: "Freeze lifted: Tether un-blacklisted 0x…  — funds can move", with when it was frozen and
  removed. The same data rules apply.
* **Graph** (`app/tracing/annotate.py` `apply_onchain`): a blacklisted node gets `onchain_frozen` and a thick
  magenta double border with a lock-and-chain badge (magenta is used by no other border; green is the victim
  and the stop-order *frozen*). A lifted freeze gets `onchain_unfrozen`: a dashed magenta border, no badge. This style is distinct from the stop-order "frozen" status,
  which an exchange's reply confirms. The label reads "frozen (on-chain: Tether blacklist, 1,234.56 USDT)".
  The details panel lists each reading: check time, block, method, response hash, freeze tx and failed
  attempts with links. The legend has an **On-chain** row with the count. On-chain readings never change
  the stop-order status or the recommendations.
* **Overview:**
  * In the funds position, a **Frozen on-chain (issuer blacklist)** tile sits next to **Frozen (confirmed
    holds)**. The new tile is the whole balance of the blacklisted wallets, which need not all be the
    victim's money.
  * An **On-chain freeze status** block lists the blacklisted wallets, failing transfers, counts and *Check
    freeze status now*.
* **Freeze page** `/cases/{id}/freeze` (read-only+): every wallet with its latest readings, the watched
  wallets, and the setting with its endpoint table. JSON: `GET /api/cases/{id}/freeze`.
* **Assistant `/freeze-status`** (read-only, never queries the chain): wallets checked, blacklisted ones with
  amounts, times, block and freeze tx, failing transfers, wallets not checked yet, and next steps. For
  example: "Tether froze `0x…`: send Tether an LE-cover letter asking it to keep the funds held for law
  enforcement / seizure."
* **Scheduler** (`scripts/run_scheduler.py` → `freeze_pass` → `service.run_due`): every enabled open case
  whose last run is older than `AEGIS_FREEZE_CHECK_MINUTES` (360). Each run is audited as `FREEZE_CHECK`
  with `trigger=scheduler`. `run_due` counts readings that failed over HTTP (`errors`, retried next run)
  apart from cases whose run raised (`failed_cases`); a failed case makes `--once` exit 1.

### The native-coin watch

No issuer can freeze ETH, so what helps is knowing the moment it moves: the next stop may be an exchange that can act.
On every scheduler pass, `app.freeze.native` reads the ETH balance and transaction count of each Ethereum wallet on the
freeze watch of a case with the checks on, over the same consented node. It keeps one row per wallet (`native_balances`).

* **ETH left, or the wallet signed a transaction:** `wallet_movement`. A movement of 1 ETH or more is `critical`.
* **A wallet's first transaction ever** is always `critical` and always passes the notification thresholds, because the
  value at stake is the balance it held: a small test payment is the warning.
* **Incoming funds** do not alert: dust arrives constantly.
* **Smaller movements** follow the case's `wallet_movement` rule (by default $1,000 or 1% of the loss); the freeze page
  shows every balance change either way.
* **A failed reading** keeps the last good one. After 30 minutes without a good reading, the freeze page flags the wallet,
  so a watch that stopped reading does not look like a quiet wallet.

The watch runs only while the scheduler runs. Add a wallet to the freeze watch to include it.

## 6. Tests

All offline: `httpx.MockTransport` stands in for the node, the explorer and TronGrid.

* `tests/test_freeze_abi.py`: Keccak, selectors and topics, ABI encoding, decimals, TRON base58 ↔ hex,
  EIP-55 checksums of the registry.
* `tests/test_freeze_transport.py`: allow-list, proxy, retries / backoff, 4xx, JSON-RPC error, cache, rate
  limiter.
* `tests/test_freeze_checks.py`: targets, consent gating (no request while off, changed endpoints), readings
  (blacklisted / not / error / 429), event-based and fallback freeze times (the bound carried forward, the
  reason shown), hash validation, failed transfers, one notification per flip, blacklisted → removed →
  re-added (`freeze_lifted`), a burnt balance, the circuit breaker, the per-case run claim, the scheduler,
  the graph, the overview, the routes and roles (`next` with dot segments), `/freeze-status` (no watched
  label at any TLP).
* `tests/test_freeze_migration.py`: 0009 up / down / up, and an upgrade of a database at 0008 with data.

The wallets blacklisted in the tests are synthetic, or the demo hub flipped inside the mock only.
* `tests/test_freeze_migration.py` also checks that 0009 widens the e-mail desk's one-e-mail-per-letter index
  to `sent_external` (and that the downgrade restores the 0008 predicate).

## 7. Local demo without network

The transport accepts `localhost` / `127.0.0.1` over http, so a demo can point every endpoint at a small local
mock instead of the public hosts (nothing in the repository; the integration run of 20 Oct used a throwaway
script in a scratch folder):

```bash
export AEGIS_ETH_RPC_URL=http://127.0.0.1:9060/eth      # JSON-RPC: eth_blockNumber, eth_call
export AEGIS_TRONGRID_URL=http://127.0.0.1:9060/tron    # /wallet/triggerconstantcontract, /v1/contracts/…/events,
                                                        # /v1/accounts/…/transactions
export AEGIS_FREEZE_EXPLORER=none                       # no EVM explorer: no freeze event, no failed-transfer list
```

The mock answers `isBlackListed = true` with a balance for one demo wallet (the USDT-TRON destination
`TWdZZhGv…L77`, 1,359.899028 USDT) and `false` / 0 for the others, plus a synthetic `AddedBlackList` event and
one reverted transfer for that wallet. The demo fixture itself marks nothing as blacklisted: a reading exists
only after a check. Never put a real third-party-report wallet into the fixture or a mock committed here.

**Integration run (20 Oct 2026, fresh SQLite, port 9050, mock on 9060).** With the setting off, the mock saw
**zero** requests and *Check freeze status now* answered 409 (audited `FREEZE_CHECK` `case_setting_off`); an
investigator could not switch it on (403), an admin without the confirmation got 400. Switched on with
consent (`UPDATE` audit: `hosts: ["127.0.0.1"]`), one *Check freeze status now* made 20 requests for the 8
trace wallets: 7 not blacklisted (block 23,610,000 on Ethereum, no block on TRON), 1 blacklisted with
`frozen_at_basis = event` and one failed transfer. One critical `freeze_detected` notification ("On-chain freeze:
Tether blacklisted TWdZZhGv…RteL77 (1,359.90 USDT)"), the Overview tile **Frozen on-chain $1,359.90**, the
graph's frozen node with its readings in the details panel and the legend's **On-chain** row, and
`/freeze-status` (no request sent) were checked on screenshots at 1280 × 800 and 1600 × 1000. Fixed in that
run: the router was not yet included in `app/main.py`; freeze times printed as ISO (`2026-10-19 09:50`) next to
the app's `19 Oct 2026 09:50 UTC`; the status line's "with failing transfers" counted only wallets that are not
blacklisted (now says so).

## 8. Not confirmed yet

* The live response shapes of publicnode, Blockscout's `getLogs` and TronGrid have not been seen from this code
  (the tests and the demo use mocks). In particular, how TronGrid prints the address in `AddedBlackList`
  results is handled in several forms but unconfirmed. Run one check against a known-blacklisted public wallet
  on a non-case DEMO deployment before relying on it.
* TronGrid's constant call reports no block number, so TRON readings name only the time.
* OP Mainnet has no Blockscout URL in `issuers.py`; freeze times there need `ETHERSCAN_API_KEY`.
* The removal event lookup (`RemovedBlackList` / `UnBlacklisted`) and `DestroyedBlackFunds` have only run
  against the mock; confirm the live shapes together with `AddedBlackList`.
