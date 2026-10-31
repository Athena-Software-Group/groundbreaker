# Wallet owners: who controls each wallet, and who to ask

_Code: `app/attribution/`, `app/web/routes_attribution.py`, migration `0011_wallet_attributions`._

Knowing who controls a wallet decides who can freeze the money there. An exchange deposit address means the
exchange can freeze the account it credits. An exchange or service hot wallet holds that service's float, so the
service is asked which customer account received the funds, not the issuer. A self-custody wallet can only be
blacklisted by the issuer of the stablecoin it holds, or watched until it reaches a service. Aegis shows the owner
wherever a wallet appears:

* **Recovery plan:** an *Owner* badge on every move, and the **Who owns these wallets** panel (`#owners`). The panel
  lists every wallet with money (an on-chain balance, or traced funds with no onward movement) with its owner, kind,
  confidence, evidence lines and next step. Investigators can mark an owner there.
* **Fund-flow graph:** the node's details panel opens with its owner and the evidence for it.
* **Freeze page and Overview card:** an owner badge on every wallet.
* **Assistant:** `/wallet <address>` includes an *Owner* line.
* **API:** `GET /api/cases/{id}/owners` returns the same data as JSON.

Every one of these reads the same attribution with the same case authorities, requester and LE pick as the Recovery
plan (`recovery.ask_context`), so the next step, its link and the LE-only gate are the same on every page. The graph's
hover card and its click panel read one attribution pass. Every page keys a wallet the same way
(`app/domain/addresses.py`): EVM hex lower-case; TRON, Solana and Bitcoin base58 (1… / 3…) as written; bech32
lower-case.

## 1. Sources

Every claim records its source, a confidence (H / M / L) and when it was retrieved. No source overwrites
another. Each stays an evidence line.

| Source | What it uses | Confidence |
|---|---|---|
| a person (`manual`) | "owned by <entity>" or a kind, with a note; always wins; *Withdraw* takes it back | H |
| the trace's entity map | addresses the trace puts at an exchange, casino or swap service (deposit, hot / payout wallet, contract); perpetrator wallets | H for a typed service address, else M |
| the catalogue | wallets an organisation publishes (`addresses` in its playbook, `docs/playbook.md`; never an observed fact); the issuers' token contracts; names, aliases and own domains that tie an owner to a catalogue organisation | the playbook's own |
| public explorer tags | Blockscout (EVM: the metadata service's tags plus the instance's address details and counters) and Tronscan (TRON: `publicTag` / `addressTag` / `redTag`, counters); requires the case's consent (§2) | M; a scam mark L |
| behaviour profile | balance vs what the trace put in, transaction count, first / last activity, the forwarding pattern | L, or M when it rests on an H claim |

The behaviour rules:

* **Swept within 60 minutes of arrival, at least 90 % of it to one known service's hot wallet:** a deposit address of
  that service.
* **A wallet paying into a deposit address or a swap contract:** the customer's own wallet, never the service's.
* **A balance of at least $10,000 that is more than 5× what was traced in:** a service's pooled or hot wallet. Its
  owner is identified before the issuer is asked.
* **A very busy wallet (over 50,000 transactions):** a service wallet.
* **A dormant wallet in the trace with no service behaviour:** probably self-custody. L until a lookup finds no tag
  and few transactions, then M.

**How the sources combine.** A person's attribution wins. Otherwise Aegis takes the highest confidence, then a
claim that names an owner, then the source in this order: catalogue, trace, explorer, behaviour. When two
sources name the same owner, the confidence goes up one step ("corroborated"). When another source names a
different owner, it is listed as a conflict.

## 2. Explorer lookups: consent, hosts, rate limits

The lookups send the case's wallet addresses to public explorers, as the freeze checks do
(`docs/freeze-detection.md`, `docs/data-handling.md` §6):

* **Per-case setting "Owner lookups"** (`cases.owner_lookup_consent`) is **on by default**: a case nobody switched off looks up its wallets on the deployment's allow-listed explorer hosts,
  **automatically after every trace run** and from the scheduler when the last run is older than
  `AEGIS_OWNER_CACHE_HOURS` (`AEGIS_OWNER_LOOKUPS_AUTO=0` makes them manual). A case admin can switch it off (an
  explicit off stays off) or on again in the Recovery plan's panel, which lists each host and what it receives; an
  explicit choice, its time and hosts are stored and audited (`UPDATE`, `setting=owner_lookups`, `hosts=[…]`).
* **Re-confirming** (an explicit consent only; the default follows the allow-list). If a host appears that the admin did not consent to (for example, `TRONSCAN_API_KEY` set
  later adds `apilist.tronscanapi.com`), the lookups stop with `consent_outdated` until the admin confirms again.
  `AEGIS_OWNER_LOOKUPS_DISABLED=1` switches lookups off everywhere.
* **Allowed hosts.** Every call goes through `app.freeze.transport` with `explorer.ALLOWED_DOMAINS`
  (`blockscout.com`, `tronscanapi.com`): https only, no redirects, no ambient proxy, retries with backoff on 429 /
  5xx (`Retry-After` honoured), a per-host rate limiter, a breaker for a host that is down, and a short cache.
  Tronscan's key travels in the `TRON-PRO-API-KEY` header. Without a key, nothing is sent for TRON.
* **What is never sent.** The victim's wallet is never looked up, and neither is a wallet a person has already
  marked. A wallet looked up within `AEGIS_OWNER_CACHE_HOURS` (default 168) is skipped unless forced. One run
  handles at most `AEGIS_OWNER_MAX_WALLETS` wallets (default 25), largest balances first.
* **Failed lookups.** A lookup whose every call failed is not stored, so it never hides an earlier good one.
* **Audit.** Each run is audited as `OWNER_LOOKUP` with counts and hosts. A person's attribution is audited as
  `CREATE` with the chain, the kind and whether there is an owner or a note: never the owner's name, the note or
  the address. The note is case data and is shown only to `view_restricted` members, never in the graph or to
  the assistant. A person's free-text owner name that names no catalogue organisation (possibly a private
  individual) is shown to other members as "a person's attribution".

## 3. What the Recovery plan does with it

* **Known exchange or casino deposit:** "Ask <exchange> to freeze the account behind <address>", a freeze request
  with the address prefilled (`info_request&freeze=<chain>:<address>`, plus `&ref=` quoting the request already open
  to that exchange). When the exchange's playbook takes LE requests only from us, the LE brief comes first (the
  LE-only gate), unless an order on file naming the exchange opens its binding path. A deposit address swept into
  its exchange (its balance falling between two good readings) is expected: no "funds left" alert or move; the
  exchange is asked to freeze the credited account.
* **Service hot wallet:** the service is asked which account received the funds. Its value is the case's share
  (what was traced in), never the service's float; with no traced share the move has no value. An instant-swap
  service's payout wallet (FixedFloat, ChangeNOW, SideShift…) is a swap service, asked for its order records. The
  issuer move counts only what was traced in, names the owner and halves its odds, whether or not the wallet's balance was read on-chain.
  The wallet's value is counted once. A hot wallet whose traced inflow is only a sweep from a deposit address of the
  case is that service's float: it is listed without money (the deposit address counts it).
* **Swap or bridge:** the service is asked for its order records. A non-custodial router is not asked at all.
* **Mixer or non-custodial protocol** (an explorer tag naming Tornado Cash, Railgun, a CoinJoin, a privacy pool or a
  DEX router / aggregator, or a catalogue DEX): kind `non_custodial`, nobody to ask, no account to freeze; the trace
  follows the output (the watch and trace-further moves keep it).
* **Self-custody wallet holding a stablecoin:** only the issuer of the token it holds is asked (largest balance
  first; else the tokens the trace saw arrive), and the money basis names that token.
* **Large balance with no known owner:** "Identify the owner". The move offers to run the lookups (once
  consented), to mark the owner, or to re-trace.
* **Unhosted-wallet watch and trace-further moves** leave out wallets an attribution puts at a service.
* **Counted once:** an owner move's value that the trace saw come from an issuer's traced wallet (swapped or sent
  on) leaves that issuer's upper bound. The money in play never exceeds the case's loss (the plan says when it is
  capped).

Advisory throughout: a person decides, drafts and sends. Nothing here sends a letter or confirms a hold.
