# GroundBreaker guide

The full reference for running and operating GroundBreaker (codename Aegis). New here? Start with the
[README](../README.md).

> Contributors should read **docs/data-handling.md** (what may and may not enter this repository)
> before the first commit, and **docs/fixture-schema.md** for the case fixture format.

Aegis starts from the original fraudulent transaction (hash plus from/to wallets). It follows the
money forward across chains and finds where the funds touch a service that can **freeze** or
**preserve** them: exchanges, casinos, swap desks and stablecoin issuers. It then generates the
preservation and risk-control requests those services need, in the structure that investigators
already use, so a hold can be requested within minutes of the fraud being identified.

Python end to end.

**What is in it today** (October 2026):

| Area | What it does |
|---|---|
| **Fund flow** | Forward trace from the origin transaction across EVM chains, TRON and Bitcoin; value-sized, coin-coloured graph; trace versions with diff; movement exports (.txt / .csv / report) |
| **Freeze & stop orders** | Freeze candidates and recommended stop-order targets on the graph; per-authority desk with correspondence timeline and form letters (stop order, status request, information request, LE cover, release) |
| **On-chain freeze detection** | Reads Tether (USDT, Ethereum + TRON) and Circle (USDC) blacklist status, frozen balances, the issuer's freeze event and failed transfer attempts; per-case opt-in, scheduled re-checks, critical notification on a freeze |
| **E-mail desk** | "Draft — you send": per-authority To / Cc / Subject guidance, Outlook-draft `.eml`, attachments, *Record as sent*, reply import. With Microsoft 365 (Graph): the investigations mailbox is read (Inbox and Sent Items, case-related mail only) and letters are sent from it |
| **Block status** | Per case × authority × request: what was asked, what came back (replies classified by rules, optionally by AI with consent), the status, days waiting and the next action; a hold, freeze or return is only ever a **suggestion** until a person confirms it (Confirm & apply to the stop order); Overview card, report exports, `/block-status` |
| **Provider playbooks** | Per organisation (`data/catalogue/providers/*.json`, every claim sourced with basis and confidence): who may use which channel (LE-only channels are never offered to us: the next step is a brief to the case officer), request paths with the instrument, evidence and clocks each needs, reply phrases and ticket formats; replies are read against them (ticket, instrument, asks, deadlines), each request's path step, cross-border route and provider clocks are derived, and the LE / counsel brief is prefilled (docs/playbook.md) |
| **Recovery plan** | Per case, next to Block status: the ranked moves that trap the most money fastest (value at stake × urgency × likelihood ÷ effort, one-line reasoning each), the targets nobody has asked yet, the evidence checklist per move (have / missing, waivers), one-click actions and the LE brief pack (.zip: brief, manifest with hashes, movements, freeze readings); Overview card, `/recovery-plan` (docs/recovery-plan.md) |
| **Case workspace** | Users and case roles (admin / investigator / read-only / external), evidence folders with sha256 chain of custody, law-enforcement contacts, notification rules, audit log |
| **Case assistant** | `/summary`, `/analyze-flow`, `/stop-orders`, `/freeze-status`, … with redacted / full / off data modes; open-weight model (DeepSeek-V4.1-Flash via the Hugging Face router) or a rule-based fallback |

```
origin tx ─▶ perpetrator wallet ─▶ laundering hops ─▶ VASP deposit addr ─▶ omnibus (stop)
                                   └─▶ swap contract ─▶ (cross-chain) ─▶ USDT-TRON / BTC
                                                                           ▲ issuer blacklist lever
```

---

## 1. Quick start (local)

```bash
git clone <repo> aegis && cd aegis
cp .env.example .env        # then set APP_SECRET_KEY (and POSTGRES_PASSWORD for Docker)

# Option A — everything in Docker (Postgres + app)
docker compose up --build                  # http://localhost:8000

# Option B — Postgres in Docker, app on your machine
docker compose up -d db
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
alembic upgrade head                       # create schema
python -m scripts.seed_case                # load the demo case DEMO-2026-001 + first trace + demo team
python -m scripts.create_user you@example.com "Your Name" --system-admin   # your own account
uvicorn app.main:app --reload              # http://localhost:8000
python -m scripts.run_scheduler            # optional, second terminal: watch polling + overdue checks

# Option C — zero dependencies (SQLite) for a quick look
DATABASE_URL=sqlite:///./aegis.db alembic upgrade head
DATABASE_URL=sqlite:///./aegis.db python -m scripts.seed_case
DATABASE_URL=sqlite:///./aegis.db python -m scripts.create_user you@example.com "Your Name" --system-admin
DATABASE_URL=sqlite:///./aegis.db uvicorn app.main:app --reload
```

Sign in at `/login` with a per-user account. `scripts/create_user.py` asks for the password
(or reads it from `--password-env VAR`); `--case DEMO-2026-001 --role investigator` also adds the
user to a case. Seeding the demo case creates its fictional team (`team` section of the fixture):
each member's password comes from the variable named in the fixture (e.g.
`AEGIS_DEMO_ADMIN_PASSWORD`) or is generated and printed once. With no account at all, the login
page says how to create one. Users see only the cases they are members of (system admins see all);
the JSON API accepts the browser session or HTTP Basic with a user's e-mail and password.

The demo case's true root sits five relay hops before the distribution hub, so the KuCoin deposit
is at hop 9. The default `TRACE_MAX_HOPS=12` reaches it; a value below 9 silently drops the KuCoin
request (a test pins this).

Tests: `pytest` (SQLite in a temp dir, offline fixture, no services needed). Lint: `ruff check app tests scripts`.
API docs: `/api/docs`.

### Loading a real case

Real cases are **never** committed. The offline fixture provider and the seeder read the fixture
named by `AEGIS_FIXTURE_PATH`. The default is `data/fixtures/demo_case.json`, the fictional demo case.
Point it at a file in the private case vault outside the repository:

```bash
export AEGIS_FIXTURE_PATH=/path/outside/repo/<CASE-REF>/case.json
python -m scripts.seed_case                       # or: python -m scripts.seed_case --fixture "$AEGIS_FIXTURE_PATH"
```

Relative paths resolve against the current directory first, then the repo root. Keep real fixtures
out of the working tree. `.gitignore` excludes `data/cases/`, `data/private/`, `vault/`, `evidence/`,
`deliverables/` and `exports/`, and in `data/fixtures/` tracks only `demo_case.json` and the synthetic
`demo_evidence/*.txt` files, as a second line
of defence. It is not the first.

### Going live against real chain data

```ini
PROVIDER_MODE=live
EVM_PROVIDER=auto            # auto = Etherscan if a key is set, else Blockscout (keyless, Etherscan-compatible)
ETHERSCAN_API_KEY=...        # optional; one V2 key covers Ethereum, Arbitrum, Base, BSC, Polygon
TRONGRID_API_KEY=...         # optional; raises rate limits
```

Live lookups send the case's wallet addresses to third-party explorers. For a real case, that is a
deliberate per-case decision (see docs/data-handling.md §6).

Check connectivity and adapter parsing first with `python -m scripts.check_providers`. It tells an
egress-proxy block apart from an auth error and from a parsing bug.

Then open the case and choose **Run trace** with provider `live` on the Fund flow tab. As the walk
resolves fixture-asserted edges (dashed in the graph), observed transfers replace them. Every run is
kept as a version: pick one in the version selector, and use **Compare runs** to see which
addresses, movements, taint figures and VASP touchpoints changed between two versions.

---

## 2. The case workspace

Each case is one page with seven tabs (`/cases/{id}?tab=…`). Only the active tab is rendered.

| Tab | What it does |
|---|---|
| **Overview** | Case status at a glance: the latest assistant summary (AI or rule-based, with its date and mode), the funds position (traced, at freezable services, issuer blacklist lever, frozen (confirmed holds), **frozen on-chain (issuer blacklist)**, dormant self-custody), the **On-chain freeze status** block (see "On-chain freeze detection" below), open stop orders with reply deadlines, overdue and upcoming replies, holds reported by recipients, the latest notifications and movement alerts. |
| **Fund flow** | The Cytoscape graph (zoom, fit, labels, fullscreen, search, details panel) with coin colours, value-sized nodes, freeze-requested badges and the recommended stop-order targets called out (see "Fund flow graph" below), every trace run as a version (label and notes), the movements table (sort / filter), **Compare runs**, and downloads: movements `.txt` / `.csv`, trace report `.md` / `.docx`, the run listing. Exports are C1 and built in memory. |
| **Authorities** | Every counterparty (VASPs, swap services, issuers, infrastructure providers, LE) with last contact, open stop orders and reply deadlines. Each authority page has a **How to contact** card (the directory: e-mail, portals, phone / post, this case's own contacts, what is still to be confirmed, each verified or not), the full timeline (letters, replies, notes, status changes), logging of inbound / outbound / notes, status recording (acknowledged, frozen with the amount held, declined, released) and **form letters**: stop order, status request / follow-up, information request, LE cover letter, release request; drafts are editable until marked sent, and export to `.md` / `.docx`. A draft becomes an **e-mail** (see "E-mail from Aegis" below): by default *Draft — you send* (Prepare e-mail → the **Send it yourself** checklist → a person sends it from Outlook → a case admin **records it as sent**; **Import reply** brings the answer back), or, with a sending transport, a case admin presses **Send** and gets **Check mailbox now** for replies. Each authority page also has **How to email <authority>** (who to write to and copy, why, and the subject). The tab names the case's sender profile. Overdue replies raise `response_overdue`. |
| **Evidence** | Folder tree (law enforcement, digital artifacts, investigator reports, stop orders & correspondence, legal, financial (admins only), chain reports, other). Add by upload (to the vault), by reference (hashed read-only, never copied) or as an inline note; verify integrity; per-item preview and download (audited). LE contacts live under Law enforcement › Contacts and are masked for read-only members. |
| **Team** | Members, roles and expiry; add an existing account or invite a new address (one-time password shown once); last-admin protection; link to the case audit log. |
| **Notifications** | The case's event feed with delivery status, and the rule editor per event type (on/off, min USD, min % of loss, overdue days, channels, recipient roles). |
| **AI Assistant (Pythia)** | Three sub-tabs. **Chat**: a chat with skills (`/summary`, `/analyze-flow`, `/stop-orders`, …; see "Assistant chat, skills and commands" below), suggested commands and the AI disclaimer. **Status summary**: the case status summary and its Generate button. **AI mode & data path**: what the current mode sends and where; case admins choose the mode (`off` / `redacted` / `full`; docs/data-handling.md §6.1). Models are reached through the Hugging Face Inference Router (DeepSeek-V4.1-Flash on DeepInfra by default; see "Case assistant (AI)" below). With no token, answers are rule-based and labelled so. |

The header shows the signed-in user, an **Inbox** link with the unread-notification badge
(`/notifications`), **Directory** (`/directory`: the organisations Aegis knows and how to reach
them), and for system administrators **Mail** (`/admin/mail`, with the count of unassigned replies),
**Users** (`/admin/users`), **Audit** (`/admin/audit`), **AI** and the **API** docs. The environment line
(env · providers · db) is developer text: it shows only with `AEGIS_SHOW_ENV_BADGE=1` (a dev or staging
instance), so a demo or production screen carries none. Below about 760 px the header wraps (brand and the
user menu, then the nav) and wide tables scroll inside their panel; the cases list becomes one card per case.

### Fund flow graph

The graph of the selected run, with a legend (collapsible, bottom left; it starts collapsed on short
screens) and a **Recommended actions** column (collapsible, top left).

| Encoding | Meaning |
|---|---|
| **Fill colour** = coin | The asset of the node's largest tainted inflow (the victim's wallet: its largest outflow): USDC `#2775CA`, USDT `#26A17B`, ETH `#A78BFA`, BTC `#F7931A`, TRX `#EB0029`, other `#8A94A6`. Edges take their own asset's colour (a swap leg the asset paid out); grey edges carry no taint (pre-fraud context). |
| **Shape** = chain | Ellipse Ethereum / EVM, diamond TRON, hexagon Bitcoin. |
| **Size** = value received | Diameter grows with the square root of the tainted USD the node **received** (not the balance it still holds: a relay that passed the funds on is drawn as large as the hub), from 18 px to 80 px for the run's largest node; the value is in the label (`$399k`). Zoomed out, a node with a stop-order status keeps at least 18 CSS px on screen, so its colour and shape stay visible next to its lock badge. |
| **Border** | Green = victim, white = terminal (the walk stopped there), red = freeze priority ≥ 50. A stop-order status replaces these. |
| **Stop-order status** (border + lock badge) | From the case's stop orders, generated and imported: *requested* amber double border, *acknowledged* amber solid, *frozen* thick green, *declined* grey dashed, *released* teal (open lock), *draft* grey dotted. A node is covered when the order is addressed to its own entity, or cites its full address (case-insensitive; a shortened `0x1234…abcd` never matches). An imported letter quotes every address in its body, so a wallet it is not addressed to (a peel wallet, a prior depositor, a swap-order sender) is only *cited*: thin blue dotted border, no lock badge, not counted as a request and left out of the "only freeze-requested" filter; an imported issuer (blacklist) request keeps *requested*. Superseded orders are ignored; the strongest status wins (*cited* is the weakest). The legend counts the nodes per status. |
| **Recommended target** (red dashed, pulsing ring + `⚑ Stop order → <service>` callout) | A freeze candidate holding at least $50 with no stop order standing for that service (a draft or a request that was only declined still counts as open, the same rule as the assistant's `/stop-orders`). On the demo: Circle (two USDC wallets, $399,247.92) and Tether (the USDT-TRON wallet, $1,359.90). The column lists each one; investigators and admins get **Generate letter →** (the authority page's form with *Stop order* selected) or **Review draft**. |
| **On-chain frozen** (thick magenta double border + lock-and-chain badge) | The issuer's own contract reads the wallet as blacklisted (Tether USDT, Circle USDC; "On-chain freeze detection" below). Separate from the stop-order *frozen* (green), which only an exchange's reply confirms; magenta is used by no other border, so the hub never reads like the green-ringed victim. The label reads "frozen (on-chain: Tether blacklist, 1,359.90 USDT)" and the details panel lists each reading. A freeze the issuer **lifted** again (dashed magenta border, no badge) means the funds can move: the details panel says when it was frozen and removed. Never changes the stop-order status or the recommendations. |
| **Edges** | Solid = observed, dashed = asserted, dotted = cross-chain swap leg; width = tainted USD. |

Filters in the legend: only recommended, only freeze-requested, hide dust (< $50). The node's details
panel lists its stop orders (number, recipient organisation, status, date sent, amount held, link)
and its recommendation. The graph JSON (also `GET /api/cases/{id}/trace/{run}/graph`, which returns
the same annotations plus `recommendations`) never carries contact details. Logic:
`app/tracing/annotate.py`.

### On-chain freeze detection

Stablecoin issuers freeze a self-custodied wallet in the token contract itself (Tether's USDT blacklist,
Circle's USDC blacklist), so the freeze is visible on-chain, as commercial tracing vendors read it. Aegis
reads it too (`app/freeze/`, `app/web/routes_freeze.py`; full detail in **docs/freeze-detection.md**):

* **Off by default, per case.** A case admin turns **On-chain freeze checks** on at `/cases/{id}/freeze`
  (*Set up on-chain checks* on the Overview) after seeing which public endpoint receives what and ticking a
  confirmation; the consent and the hosts are audited. While it is off no request leaves Aegis.
  `AEGIS_FREEZE_CHECKS_DISABLED=1` switches it off for the whole deployment.
* **What is read:** `isBlackListed` / `isBlacklisted` and `balanceOf` at a named block (USDT on Ethereum and
  TRON, USDC on Ethereum; Base / Arbitrum / Polygon / OP once their RPC URL is set), the issuer's blacklist
  event for the freeze time (else "frozen at or before", a bound that never moves later on re-checks, with
  the reason: no explorer configured, the lookup failed, or not found), and failed token transfers as a
  supporting hint. Each reading keeps the block, time, method and the sha256 of every raw response.
* **Lifted freezes:** when a blacklisted wallet reads *not blacklisted* again (Tether `RemovedBlackList`,
  Circle `UnBlacklisted`), Aegis records when it was frozen and when it was removed, emits a critical
  `freeze_lifted` ("funds can move") and shows the wallet as *freeze lifted* on the freeze page, the
  Overview and the graph until the issuer blacklists it again (a new `freeze_detected`).
* **Which wallets:** every wallet of the latest trace that sent or received USDT / USDC (not the victim,
  placeholders, contracts or DEX / bridge / mixer addresses), plus **watched wallets** an investigator adds
  (TLP:RED refused; a mixed-case EVM address must pass its EIP-55 checksum; label and source note stay on
  the case's freeze page: never in notifications, the assistant or the audit log, whatever the TLP).
* **Shown as:** the graph's *on-chain frozen* style, the Overview's **Frozen on-chain (issuer blacklist)**
  figure and **On-chain freeze status** block with **Check freeze status now** (investigators, audited), the
  freeze page (`GET /api/cases/{id}/freeze` for JSON), a critical `freeze_detected` notification once per
  flip, and the assistant's read-only `/freeze-status` (it never queries the chain). Exchange and casino
  accounts (KuCoin, Rainbet in the demo) cannot be seen on-chain: their freeze stays confirmed by the
  recipient's reply.
* The scheduler re-checks enabled cases every `AEGIS_FREEZE_CHECK_MINUTES` (360). One run per case at a time
  (a run claim on `freeze_settings`); a host that keeps failing is not called again in the same run (circuit
  breaker); when the endpoints change after the consent (e.g. `ETHERSCAN_API_KEY` set later), nothing is
  sent until a case admin confirms the new hosts on the freeze page.

### Roles

| Role | Can |
|---|---|
| `external` | See the Authorities and Evidence tabs, limited to items flagged *shared with externals* (e.g. an LE liaison); stop-order ids and states only for stop orders whose own letter was shared. Contact details and complaint references are masked as for `read_only`. Membership is time-boxed (`expires_at`: 30 days by default, 90 at most, also when seeded). Never receives notifications. |
| `read_only` | See every tab and download exports; R3 content (letter bodies, restricted evidence) is hidden. LE and PI contact names (also without a rank or first name), e-mails, phones and any address on the PI firm's own domain, and the case's complaint references, are masked wherever they appear: LE contacts, authority pages, timelines, letter subjects, bodies, senders / recipients / cc (`Name <addr>` included), page titles, the Stop orders & correspondence folder, evidence metadata, exports and API JSON. The Team tab is the exception by design: every member sees the other members' account names and e-mails (the people they work the case with), so a PI who is also a team member is identifiable there. May ask the assistant while the case is in `redacted` / `off` mode. |
| `investigator` | Everything above plus R3 content, running traces, annotating runs, drafting letters and marking them sent, **preparing** e-mails (the preview / checklist), **importing replies** (.eml / .msg, for review), **Check freeze status now** and watched wallets, logging correspondence, adding and verifying evidence, generating summaries. |
| `admin` | Everything above plus **sending e-mail from Aegis** (manual mode: downloading the Outlook draft and the attachments, **Record as sent**), turning **on-chain freeze checks** on or off (with the consent), the case's contact channels and sender profile, reviewing inbound mail suggested for the case, "Check mailbox now", team management, notification rules, sharing with externals, the AI mode, the case audit log, the Financial evidence folder and evidence source paths. |

System administrators (`users.is_system_admin`) see every case as a case admin and manage user
accounts. Non-members get 404 for a case, members below the required role 403. Opening a case
(which makes you its admin) is a system-level permission: system admins and accounts granted
`can_create_cases` (`--can-create-cases`, or the checkbox at `/admin/users`) only, never a case role.
Case references are 3 to 64 ASCII letters, digits, `.`, `_` or `-`, unique ignoring case
(`demo-2026-001` is refused next to `DEMO-2026-001`).

### User accounts

```bash
python -m scripts.create_user you@example.com "Your Name" --system-admin   # prompts for the password
python -m scripts.create_user ana@example.com "Ana" --case DEMO-2026-001 --role investigator --password-env ANA_PW
python -m scripts.create_user lead@example.com "Lead" --can-create-cases     # may open new cases
python -m scripts.create_user le@le.example "LE" --case DEMO-2026-001 --role external --expires 2026-12-31  # default 30 days, max 90
make user EMAIL=you@example.com NAME="Your Name" ARGS=--system-admin
```

Case admins add existing accounts from the Team tab (the answer is the same whether or not an
address has an account); only system admins create accounts, there or at `/admin/users`, where
they also deactivate them. Seeding the demo case creates its fictional team; each member's
password comes from the `AEGIS_DEMO_*_PASSWORD` variable named in the fixture or is generated and
printed once (`.env.example` lists them).

### Configuration (environment or `.env`)

| Variable | Purpose |
|---|---|
| `DATABASE_URL`, `APP_SECRET_KEY`, `APP_ENV` | Database; signing key for sessions and CSRF (required outside `APP_ENV=local`) |
| `SESSION_IDLE_MINUTES`, `SESSION_MAX_HOURS` | Session lifetime (30 min idle, 12 h absolute) |
| `PROVIDER_MODE`, `EVM_PROVIDER`, `ETHERSCAN_API_KEY`, `TRONGRID_API_KEY`, `MEMPOOL_BASE_URL` | Chain data (default offline `fixture`) |
| `TRACE_MAX_HOPS`, `TRACE_MAX_FANOUT`, `TRACE_MIN_TAINT_USD` | Tracer guards (12 / 25 / 50) |
| `AEGIS_FIXTURE_PATH`, `EXPORT_DIR` | Fixture to seed / trace offline; `.docx` export folder |
| `AEGIS_VAULT_DIR` | Evidence vault for uploads: absolute, outside the repo, ideally an encrypted volume (uploads are refused while unset). Run the server with `TMPDIR` on the same volume. |
| `AEGIS_EVIDENCE_ROOTS`, `AEGIS_MAX_UPLOAD_MB` | Where the web UI may reference originals from, per case (`:`-separated; `<dir>` means `<dir>/<case reference>/` for cases seeded or opened by a system admin, matched by identity; `REFERENCE=<dir>` names one case's folder and is the only way for a case opened by a `can_create_cases` account); upload size limit (200 MB) |
| `AEGIS_LLM_PROVIDER`, `AEGIS_LLM_BASE_URL`, `AEGIS_LLM_MODEL`, `AEGIS_HF_BILL_TO`, `HF_INFERENCE_TOKEN`, `AEGIS_LLM_TIMEOUT`, `AEGIS_LLM_MAX_TOKENS`, `AEGIS_LLM_ALLOW_ANY_HOST`, `AEGIS_AI_DISABLED` | Case assistant model access (below). No token (or `AEGIS_AI_DISABLED=1`) = rule-based only |
| `AEGIS_ORG_NAME`, `AEGIS_SIGNATORY_NAME` | Who letters come from: the organisation that writes on behalf of each case's client (default `Your Organisation`) and who signs by default (default `Investigations Desk`); every new case's sender profile starts from them, and `AEGIS_MAIL_FROM_NAME` defaults to the organisation name |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_STARTTLS`, `SMTP_SSL` | E-mail notifications (off unless `SMTP_HOST` and `SMTP_FROM` are set; recipients are blind-copied) |
| `SLACK_WEBHOOK_URL`, `APP_BASE_URL` | Slack notifications (https webhook); absolute link prefix in e-mail / Slack |
| `AEGIS_DEV_LOGIN_TOKEN` | Dev-only one-time sign-in link `/dev/login?token=…&email=…` (only with `APP_ENV=local`; never set it elsewhere) |
| `AEGIS_MAIL_*`, `AEGIS_M365_*` | E-mail from Aegis (below, "E-mail from Aegis"): transport (default `manual`, "Draft — you send"), mailbox, limits, Microsoft 365 credentials (the investigations mailbox, docs/m365-setup.md) |
| `AEGIS_ETH_RPC_URL`, `AEGIS_BASE_RPC_URL`, `AEGIS_ARBITRUM_RPC_URL`, `AEGIS_POLYGON_RPC_URL`, `AEGIS_OPTIMISM_RPC_URL`, `AEGIS_TRONGRID_URL`, `AEGIS_FREEZE_EXPLORER`, `AEGIS_FREEZE_CHECK_MINUTES`, `AEGIS_FREEZE_CACHE_MINUTES`, `AEGIS_FREEZE_TIMEOUT`, `AEGIS_FREEZE_RETRIES`, `AEGIS_FREEZE_MIN_INTERVAL`, `AEGIS_FREEZE_LOG_LOOKBACK_BLOCKS`, `AEGIS_FREEZE_CHECKS_DISABLED` | On-chain freeze detection (below; docs/freeze-detection.md): JSON-RPC / TronGrid endpoints (publicnode and api.trongrid.io by default; the other USDC chains only once set), the explorer for freeze times, scheduler interval (360 min), cache, timeouts, retries, rate limit, and the deployment kill switch. Nothing is sent for a case until a case admin turns its checks on. |

### Case assistant (AI)

The assistant calls models with an OpenAI-compatible client:
`POST {base_url}/chat/completions` over httpx with `Authorization: Bearer <token>`,
`X-HF-Bill-To: <org>`, JSON mode (`response_format: {"type": "json_object"}`) for summaries, one retry
after ~2 s on a timeout or HTTP 429 / 502 / 503 / 504, and the error body (truncated, token-free)
surfaced on HTTP errors (`app/ai/providers.py`).

* **Default:** the Hugging Face Inference Router, `https://router.huggingface.co/v1`, model
  `deepseek-ai/DeepSeek-V4.1-Flash:deepinfra`. The `:deepinfra` suffix pins the inference provider, so
  the data path is fixed: Aegis → Hugging Face router → DeepInfra (a third-party inference provider).
  The response's `model` field (the model that actually served) is logged, audited and shown as
  "Generated by <served model> via <data path> · <time>" under each summary.
* **Billing:** `AEGIS_HF_BILL_TO=your-hf-org` bills the calls to that Hugging Face organisation
  (header `X-HF-Bill-To`); unset, the token owner's account pays.
* **Data path and modes:** cases start in `redacted` (chain data and metadata, people as roles).
  Switching a case to `full` needs a case admin, the DPA box and, on the router, the explicit
  confirmation "Full case content will be sent to <data path>", recorded in the audit log. If the
  destination changes later (another pinned provider), full-mode calls stay rule-based until an admin
  confirms again. For strict privacy use a dedicated Inference Endpoint (`hf_endpoint`).
* **Summaries:** a JSON-only system prompt embeds the exact schema; the first balanced `{…}` of the
  reply is parsed (code fences and prose are tolerated) and validated; one repair call sends the
  validation error back; otherwise the rule-based summary answers, labelled
  "rule-based (AI response invalid)". `<think>` blocks are stripped, `reasoning_content` is ignored and
  4,096 tokens of reasoning headroom are added to `AEGIS_LLM_MAX_TOKENS`.
* **Admin page:** `/admin/ai` (system admins) shows the provider, base-URL host, model, bill-to org,
  whether a token is configured (never the value) and the kill switch; **Test connection** sends the
  fixed prompt "Reply with the single word OK." and shows served model, latency and cost; **Health
  check** reads `{base_url}/models` and shows whether the model is listed and which providers serve it.

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_LLM_PROVIDER` | `hf_router` | `hf_router` · `hf_endpoint` (dedicated HF Inference Endpoint / TGI / self-hosted vLLM; base URL = endpoint URL + `/v1`) · `anthropic` (optional, `ANTHROPIC_API_KEY`) · `none` |
| `AEGIS_LLM_BASE_URL` | `https://router.huggingface.co/v1` | Allowed hosts: `router.huggingface.co`, `*.endpoints.huggingface.cloud`, `localhost` / `127.0.0.1`; anything else is refused unless `AEGIS_LLM_ALLOW_ANY_HOST=1` |
| `AEGIS_LLM_MODEL` | `deepseek-ai/DeepSeek-V4.1-Flash:deepinfra` | Model id (`:provider` pins the router's inference provider) |
| `AEGIS_HF_BILL_TO` | empty | HF organisation billed (e.g. `your-hf-org`) |
| `HF_INFERENCE_TOKEN` | empty | Fine-grained, inference-only token (then `HF_TOKEN`, then `LLM_API_KEY`). `HF_API_KEY` is never read: it is the admin / write token for model provisioning |
| `AEGIS_LLM_TIMEOUT`, `AEGIS_LLM_MAX_TOKENS` | `120`, `6000` | Request timeout (s); answer budget (+4,096 reasoning headroom) |
| `AEGIS_AI_DISABLED` | unset | Kill switch: `1` = rule-based only |

**Token setup (local):** keep the token in a file outside the repository, e.g.
`~/.config/aegis/aegis.env` (mode 600), as `HF_INFERENCE_TOKEN=…`, and never type its value on a
command line that ends up in the shell history. Load it only into the server's environment:

```bash
set -a; . ~/.config/aegis/aegis.env; set +a
AEGIS_HF_BILL_TO=your-hf-org uvicorn app.main:app --port 8000
```

Never put a token value in `.env.example`, a test, a fixture, a log or a commit.

### Assistant chat, skills and commands

The **Chat** sub-tab of the **AI Assistant (Pythia)** tab is a chat kept per case and per user (table `ai_messages`; **Clear
conversation** deletes only your own, audited). Type `/` for the command list (arrow keys, Enter /
Tab, Escape), click a skill in the palette on the left, or ask a question in plain text. Suggested
commands appear as chips at the start and after every reply: they follow the case (e.g. `/follow-ups`
when a reply is overdue, `/stop-orders` when there are recommended targets), and after a free-text
answer the model proposes up to three. Every suggestion is checked against the registry and your
role, and a model suggestion never carries arguments that create drafts. A free-text question sends
your earlier turns as history, but only those the case's current mode allows: after a switch from
`full` to `redacted` (or `off`), turns generated in `full` mode stay out of the model call.

| Command | Role | AI | What it does |
|---|---|---|---|
| `/help` | read_only | — | Lists the skills you can use. |
| `/summary` | read_only (generate: investigator) | yes | Case status summary: funds position, deadlines, next steps, risks; stored on the Status summary sub-tab. |
| `/analyze-flow` | read_only | yes | Where the funds sit now, largest balances, VASP touchpoints, peel chains, dormant vs moving wallets, gaps in the latest trace. |
| `/stop-orders [draft all \| draft <name>]` | read_only (drafting: investigator) | — | Which services and wallets should get a stop order now and which were already asked; `draft …` creates **draft** letters. |
| `/follow-ups [draft]` | read_only (drafting: investigator) | — | Unanswered stop orders past their reply date; `draft` creates the status-request drafts. |
| `/next-steps` | read_only | yes | Prioritised next actions and who usually owns them. |
| `/wallet <address>` | read_only | yes | One wallet of the latest trace: role, inflows / outflows, freeze status, what to do. |
| `/timeline` | read_only | — | The case in chronological order. |
| `/evidence-gaps` | read_only | yes | Evidence still missing for LE and exchange requests. |
| `/le-update [authority]` | investigator | — | Drafts a law-enforcement update (cover letter with identifiers, where the funds sit, every stop order's status). |
| `/block-status` | read_only | yes | What every authority answered to the blocks requested: status, days waiting, next action per request. |
| `/recovery-plan` | read_only | yes | The ranked moves that trap the most money fastest: value at stake, clock, the provider's process for a letter from us, what each move needs; the targets nobody has asked yet. Advisory. |

* **Drafts only.** `/stop-orders`, `/follow-ups` and `/le-update` create drafts through the
  authorities desk (`correspondence.generate_letter`), audited as `CREATE` with `via=assistant` and
  tagged `meta.created_via`; the letter page says the assistant created it. Nothing is ever sent: a
  person reviews each draft, sends it and clicks **Mark sent**. Roles are enforced on the server
  (403 for a read-only member asking for drafts).
* **AI skills** send Aegis's own rule-based findings with the instruction; the findings stay
  visible in a collapsible block under the answer. With no token, mode `off`, or a busy / failing
  model they answer rule-based, labelled so; a busy model also gets **Retry with AI**. A busy
  free-text question answers HTTP 429 with a Retry button and stores nothing.
* Every message is labelled "Generated by <served model> via <data path>" or "rule-based", rendered
  from Markdown on the server (no raw HTML, no images, links only inside Aegis). The line
  **"AI can make mistakes. Please double-check important information before acting on it."** sits
  under the chat input, on the Status summary sub-tab and on drafts the assistant created.
* Routes: `POST /cases/{id}/assistant/chat` (JSON, `X-CSRF-Token` header), `…/chat/form` (no-JS
  fallback), `…/chat/clear`; API `GET /api/cases/{id}/assistant/skills`, `GET|POST
  /api/cases/{id}/assistant/chat`. Registry: `app/ai/skills.py`.

### E-mail from Aegis

**Connecting the investigations mailbox.** Aegis can
read the shared investigations mailbox and send from it: `AEGIS_MAIL_TRANSPORT=graph`, Microsoft 365
app-only access (client credentials) limited to that one mailbox by an Application Access Policy,
Mail.ReadWrite + Mail.Send, history read from `AEGIS_MAIL_INBOUND_SINCE` (e.g. `2026-01-01T00:00:00Z`). What it does
with the mailbox is under **Mailbox sync and Block status** below; how to give Aegis access is
docs/m365-setup.md (an Entra app registration, not the mailbox's password). "Draft — you send" stays
available and is still the default when nothing is configured.

**"Draft — you send" (`AEGIS_MAIL_TRANSPORT=manual`, the default).** Aegis drafts every e-mail and
guides who it goes to, but a person sends it from the investigations mailbox in Outlook. Aegis opens no mail connection in this
mode. Code: `app/domain/mail_guidance.py` (who / subject), `mail_compose.py` (the draft),
`mail_send.record_external` (record the send), `mail_import.py` (replies), routes in
`app/web/routes_mail.py`.

1. **How to email <authority>** (the authority page, under *How to contact*, and the compose page):
   ranked **To** suggestions, each with one line of *why* ("verified LE-request channel", "address
   used in the letter you sent on 18 Oct 2026", "entity compliance address (unverified — confirm on
   their LE portal first)"); **Cc** suggestions with *why* (the case mailbox `AEGIS_MAIL_FROM`, so a
   copy and Reply-All answers land where replies are read; the sender profile's `cc_default`, e.g.
   the client's contact e-mail given when the case was opened; LE officers only on LE cover letters;
   **never the victim's personal address** by default, a warning instead — unless the profile's
   default Cc names it); warnings for portal-only authorities (IC3: "submit via portal, not
   e-mail"), non-custodial ones (Uniswap: "cannot freeze — information request only") and unverified
   addresses; and the **subject** for the letter kind, always ending with the tracking tag:
   `URGENT – Preservation & Risk-Control Request – <service> – <asset> <amount> – Ref <CASE> [Aegis <CASE> #<id>]`,
   `Follow-up: <original subject> – sent <date> – Ref <CASE> [Aegis …]`,
   `Information & Preservation Request – <service> – Ref <CASE> [Aegis …]`,
   `Fund-Flow Summary & Freeze Opportunities – Your ref <complaint ref> – Ref <CASE> [Aegis …]`,
   `Request for Release of Held Funds – <service> – <asset> <amount> – Ref <CASE> [Aegis …]`.
   The e-mail itself carries these subjects with plain ASCII punctuation (" - " for "–", straight
   quotes): typographic characters force RFC 2047 encoded words, which Python ≤ 3.13 (CI and the
   Docker image run 3.12) folds with a stray space. `mail_compose.ascii_header` and the non-folding
   `SEND_POLICY` keep the received subject identical to the preview.
2. **Prepare** (investigators) works as below; the subject field is prefilled with the standard
   subject and the tag is appended at its end. The case mailbox may be a Cc (never a To). The
   checklist stays valid for 14 days; up to 20 MB.
3. **Send it yourself** (the preview): To / Cc / Subject / Body each with a **Copy** button (the body
   as formatted HTML with a plain-text fallback), **Download all attachments (.zip)** and each one
   on its own, **Download as Outlook draft (.eml)** and, for a short letter only, a `mailto:` link
   (text only, no attachments; mail apps cut links of about 2,000 characters). Downloads are for
   case admins and audited. The draft carries `X-Unsent: 1`, so Outlook and Apple Mail open it as an
   editable new message; it has **no Date and no Message-ID** (the sending server sets both: Aegis
   claims no id for a message it did not send) and From / Reply-To the configured mailbox when one
   is set. *Send from the investigations mailbox in Outlook; keep the subject unchanged so replies
   are matched.*
4. **Record as sent** (case admins, CSRF, a confirmation box): the actual date and time (UTC), the To /
   Cc actually used (prefilled), the reply clock, and optionally the sent message saved from Outlook
   (.eml or .msg, ≤ 25 MB), kept in the vault as R3 evidence with its sha256. The e-mail becomes
   `sent_external`; the letter and its stop order are marked sent (`sent_via` "email (sent outside
   Aegis)", `response_due_at`), `correspondence_out` / `stop_order_status` fire, the audit row has
   ids, counts and domains only. One e-mail per letter still applies: a recorded letter is never
   prepared again (write a follow-up letter); since migration 0009 the database's one-e-mail-per-letter
   index covers `sent_external` too, so two concurrent records of one letter cannot both succeed.
5. **Import a reply** (investigators and up): upload the reply (.eml or Outlook .msg) on the
   authority page, with **Import reply** on the Authorities tab, or at `/cases/{id}/mail/import`. It runs
   through the inbound pipeline with file-transport rules (never trusted automatically: it waits on
   **Mail to review**, with the letter it answers pre-selected by the tracking tag, by its In-Reply-To /
   References naming the Message-ID of the sent copy uploaded at step 4, else the authority's latest
   letter); a case
   admin accepts it onto the timeline. A `.msg` is converted for reading (MS-CFB / MS-OXMSG reader,
   no extra dependency) and the original file is kept as evidence. A tag naming another case's
   letter is ignored.

The rest of this section describes the other transports: `file` (local demos) and `graph`
(Microsoft 365, the investigations mailbox; docs/m365-setup.md). With them letters go out from
**one shared case mailbox** configured into the platform, not from anyone's own mail client, and the
replies come back into the case. Code: `app/domain/directory.py`, `sender.py`, `mail_compose.py`,
`mail_send.py` (routes `app/web/routes_mail.py`) and `app/mail/` (transports, inbound, `/admin/mail`).

1. **Who to write to.** Each authority page has a **How to contact** card: the shipped catalogue of
   generic organisational channels (`data/catalogue/channels.json`: homepages and portals; every
   law-enforcement or compliance channel an organisation has not published is listed as *to be
   confirmed*, never invented), channels system admins added for every case (`/directory`), the
   entity record, this case's own contacts (added or verified by case admins), and the addresses the
   case's own correspondence used. Each is marked ✓ verified or ⚠ unverified, with its source and
   when it was last used. A non-custodial router says "information requests only"; a portal-only
   authority (e.g. IC3) says to submit the letter at its portal and **Mark sent** with channel portal.
2. **Who it comes from.** The case's **sender profile** (`/cases/{id}/sender-profile`, case admins):
   new letters read "We write as <organisation>, on behalf of <victim>" under the victim's
   authority instrument (a Letter of Authorisation by default; "Power of Attorney" only when confirmed
   as literally the instrument on file), with its signature block. The From header is the configured
   mailbox and its display name (`AEGIS_MAIL_FROM_NAME`); the victim's name is never in a header.
   Leave the profile's contact e-mail empty and the letter names the case mailbox
   (`AEGIS_MAIL_FROM`) as the single point of contact, so the body, From and Reply-To agree and
   replies come back into Aegis (the demo profile does this).
   **Every new case gets its profile when it is opened**: the deployment's organisation
   (`AEGIS_ORG_NAME`, signed `AEGIS_SIGNATORY_NAME`, the case mailbox as
   contact) on behalf of the client ("<victim entity> (<victim name>)", or the name), under the
   instrument given on the New case form (default: Letter of Authorisation); the client's contact
   e-mail from that form is the default Cc. The Overview then says "Sender of record set: … — attach
   the signed Letter of Authorisation" until the signed document is attached on the profile page.
   Older cases without a profile: `python -m scripts.ensure_sender_profiles [--case REF] [--dry-run]`
   creates the same default (never touching an existing profile; audited).
   Cases without a profile keep the PI-firm block; imported and already drafted letters are unchanged.
3. **Prepare** (investigators): on a draft letter (its page or its timeline entry) or a draft stop
   order, **Prepare e-mail** →
   choose To / Cc from the card or type addresses (bare addresses only; 1–10 To, 0–10 Cc, 15 in all,
   never the mailbox itself), keep or edit the subject after the tracking tag
   `[Aegis <REF> #<letter id>]`, choose attachments: the letter as `.docx` (final copy, no filing
   header), the profile's authority documents and any evidence item of the case. TLP:RED /
   TLP:AMBER (also +STRICT, on the item, a tag or a parent) and items whose integrity check failed
   cannot be attached; attached files get neutral names (`<REF>_evidence-<id>.<ext>`). Aegis builds
   the exact MIME message (text and safe HTML from the same letter), stores it in the vault and shows
   it: headers, text, HTML, attachments with their sha256. A message over 2.9 MB is refused (use the
   recipient's portal). The preview is valid for 30 minutes. When an investigator prepares it, the
   case admins get a `mail_prepared` notification, and the Authorities tab (**E-mail awaiting Send**)
   and the letter's timeline entry link to the preview; an expired preview offers **Prepare again**
   (same recipients, subject and attachments; every check runs again).
4. **Send** (case admins only, web form only): tick one box per unverified or typed-in address
   ("I confirmed … is an intended recipient"), one per evidence attachment, and the summary box, then
   **Send**. Aegis sends exactly the previewed bytes once, and **one e-mail per letter**: a second
   click or tab does nothing, another preview of the same letter (or of the same stop order's letter)
   is refused while one is sending, sent or of unknown outcome (also at the database: a partial
   unique index on `mail_messages.letter_key`), and the letter's other prepared previews are cancelled once it went out. If
   the letter is not signed by the sender of record (no sender profile, a body generated before the
   profile, or a From name that differs from the profile's organisation), the compose page and the
   preview say so and Send is refused until the letter is generated again with the profile or the
   case admin ticks an acknowledgement and gives a reason (recorded on the e-mail). Aegis files
   the sent bytes as an R3 `.eml` evidence item under Stop orders & correspondence, marks the letter
   (and its stop order) sent with the reply clock, and notifies `correspondence_out` /
   `stop_order_status`. If the mailbox cannot confirm the send, the e-mail is **unknown**: the only
   way on is **Check the mailbox now** (also run by the scheduler), which marks it sent (and files it)
   or, once it has been missing or an unsent draft for 15 minutes, failed (an unsent Graph draft is
   deleted first; while it cannot be, the letter stays blocked); never resend by hand.
   Files received by e-mail (and anything tagged `dangerous`) are never attached: a case admin can
   mark a received, non-dangerous file **safe to attach** on the compose page (never a received
   e-mail itself). E-mails filed as evidence and anything in Stop orders & correspondence go only
   to the authority they came from; the preview warns when the letter says its Letter of
   Authorisation is attached but no authority document is. Limits:
   20 sends per case and 60 overall per hour. With `AEGIS_MAIL_TRANSPORT=none` Send is disabled and
   a case admin can download the exact `.eml` instead.
5. **Replies.** The mailbox is read on the scheduler (or **Check mailbox now**): a reply that
   answers a sent Message-ID, or carries the tracking tag, or shares the conversation, from one of
   the authority's own domains (the letter's To, the entity's compliance address, LE contacts,
   directory channels; never the Cc, free-mail providers or the case mailbox's domain) **and** with a
   DMARC / compauth pass in Exchange's `Authentication-Results`, is filed on the authority's
   timeline as R3 (plain text only; inbound HTML is never rendered), with its `.eml` and attachments
   as evidence (at most 25 attachments / 20 MiB extracted; beyond that they stay only in the `.eml`,
   flagged *attachments truncated*), and stops the reply clock. With the file transport every match
   waits for review (no receiving MTA authenticates the sender); a reply filed on review (or by a system admin) whose sender is not on the
   chosen authority's own domains carries a red *sender domain not expected* tag. Auto-replies and
   bounces are notes; a bounce (a delivery-status report by structure) is filed automatically only
   from the case mailbox's own mail server, authenticated, and naming one of our Message-IDs. Anything uncertain goes to the
   case admins' **Mail to review** or, unmatched, to the system admins' unassigned queue at
   `/admin/mail`. Nothing in an inbound e-mail ever changes a status, drafts or sends anything.

#### Filing and translating mail

**Mail → unassigned mail** lists e-mail no letter claimed. Choose the case, set where each e-mail goes and file the ticked ones
in one step. An authority is suggested only when the sender is on its own domain. An authority's timeline counts what is
filed there as its reply, so file a forward of one of your own letters under your PI firm, not under the provider it went to.

An inbound e-mail's page has **Translate to English**, which needs the case's "AI reads mailbox replies" consent. The
translation sits above the original, which stays the record.

#### Mailbox sync and Block status (graph transport)

Aegis reads the mailbox's **Inbox and Sent Items** and reports, per case, the status of every block it
requested across all the authorities. Code: `app/mail/ingest.py` (sync), `app/mail/sync_outbound.py` (Sent
Items), `app/mail/matching.py` (`assess`: what is case-related), `app/blocks/` (classification and status),
routes `app/web/routes_mail_admin.py` and `app/web/routes_blocks.py`; details in docs/block-status.md and
docs/data-handling.md §6.4.

1. **Sync** (scheduler every `AEGIS_MAIL_SYNC_MINUTES`, default 15; **Sync now** / **Backfill since <date>**
   on `/admin/mail/mailbox`, system admins). One Graph delta link per folder (`mail_sync_folders`); the first
   run starts at `AEGIS_MAIL_INBOUND_SINCE`. Sent Items are read before the Inbox (and oldest first), so in one
   backfill a letter is recorded at its first send before its forwards and the replies to it are read and those
   thread onto it. Demo cases (reference `DEMO-…`, or `facts.demo`) never take part in this matching.
2. **Only case-related mail is kept** (data-handling §6.4): a tracking tag, a thread with a stored
   message, a cited case reference / traced wallet / tx hash, or an authority's address or domain (from
   the Inbox together with cited case material; in Sent Items together with a matching letter). Anything
   else (newsletters, personal mail) is counted as `not_related` and never stored; its body is never
   downloaded (at most its thread headers, and for Sent Items the text, are read in memory). Mail tied to a
   case only by an authority's address keeps metadata only (sender or recipient domains, subject, date).
3. **Letters sent from Outlook** are found in Sent Items and recorded on their letter or draft stop order:
   marked sent at the message's sentDateTime, `sent_via` "email (investigations mailbox)", reply clock
   started, the sent message filed as R3 evidence. An Outlook answer in a request's thread (e.g. to their
   question) is recorded as a follow-up of that request, so their next reply lands on it. A forward of our
   letter ("FW: <subject>", e.g. to the freeze inbox an auto-reply named) is that letter sent again: a resend of
   the request (or, without the original on record, the letter's send). The To recipients name the authority
   (a Cc'd partner firm never makes it ambiguous), and any address on the authority's own organisation domain
   (its addresses, its website, the catalogue's organisation domains) is that authority. A message Aegis
   cannot tie to exactly one letter is logged on the authority with **needs review** and shows on Block
   status as "Sent from Outlook — needs review" (never as a request; the drafts it may have carried say
   "possibly already sent"); nothing is marked sent from the Inbox.
4. **Replies** are matched and filed as before (sender domain + DMARC / compauth); a message from an
   authority's domain that cites case material but answers no known letter waits on **Mail to review**, with
   that authority (and the letter whose subject it repeats) preselected.
5. **Reading each reply** (when it is filed): rules (`classify_rules`: frozen / hold placed / funds returned /
   declined / no account / LE process required / information requested / redirected / acknowledged /
   auto-reply / unclear, with the verbatim quote, amount, asset and their ticket) and, only when a case admin
   turned on **AI reads mailbox replies** for the case, a second reading of the reply's full text by the
   configured model (consent names the data path, by default Hugging Face Inference Router → DeepInfra; off by
   default; blocked when the case's AI mode is off). The AI is advisory: its quote must be a verbatim
   sentence of the sender's own text that says the outcome, its amount one the reply states next to an
   asset, and a disagreement with the rules (or a different amount) is shown as "needs review". Only the
   sender's own text counts: quoted earlier messages and what a ticket system echoes of our letter ("-- reply
   above this line --", "Ticket details:", a rule line) are cut first.
6. **Block status** (`/cases/{id}/blocks`, the Overview card, a column on the Authorities tab, `.md` / `.csv` /
   `.docx` exports, `/api/cases/{id}/blocks`, `/block-status` in the assistant): per case × authority ×
   request, what was asked, when and to whom, what came back, the status, days waiting and the next action
   (resend to the address a redirect named, an LE cover letter, answer their questions, wait, close).
   **A person confirms every positive outcome**: a hold, freeze or return read by the rules, the AI or on-chain
   is shown as a suggestion (*Reply suggests: Frozen (2.1 ETH) — confirm*, with the quote and warnings), the
   request keeps its earlier status (*Reply received — suggests …, needs confirmation*), the held / frozen totals
   count confirmed outcomes only, the Confirm form preselects nothing for one (the person chooses the status and
   types the amount held), and notifications say "reply needs review". Investigators **Confirm**, case admins
   **Confirm & apply** (e.g. *Frozen* with the amount held → the stop order is FROZEN). Non-positive readings
   (acknowledged, redirected, LE process required, …) apply automatically. `block_status_changed` notifications.
   The **Recovery plan** sub-tab next to it (`/cases/{id}/recovery-plan`, docs/recovery-plan.md) ranks the moves
   across every request, the trace's untouched targets and the moving wallets, with each move's evidence checklist
   and its LE brief pack.
7. **Sending directly** from the app (case admins, one e-mail per letter, as in step 4 above). When a reply
   redirected the request (e.g. an issuer's legacy-inbox auto-reply), the authority page's guidance and the compose
   page name the address the reply gave (typed in only when the reply came from the authority's own domain)
   and do not suggest the address that redirected; the follow-up letter (or a forward of the letter there)
   turns the request back to *awaiting*, and a copy of the redirect logged by hand afterwards, or their answer
   from the address it named, no longer reads *Redirected*.

**Local walk with a mock Graph** (no Microsoft account, no network): with `APP_ENV=local` only,
`AEGIS_M365_TEST_GRAPH_BASE=http://127.0.0.1:<port>/v1.0` and `AEGIS_M365_TEST_LOGIN_HOST=http://127.0.0.1:<port>`
point the graph transport at a mock of Graph and the token endpoint on 127.0.0.1. Any other host, or any
other `APP_ENV`, makes the transport "not configured" (it never falls back to the real hosts while one is set);
`/admin/mail` shows *local test mock*. The graph mailbox sync never matches a demo case (`DEMO-…`): walk it with a
case of its own reference (the file transport below still works with the demo case).

**Local demo with the file transport** (no Microsoft account, no network): outbound mail is written
as `.eml` files to a folder, inbound mail is read from another.

```bash
export APP_ENV=local DATABASE_URL=sqlite:////abs/demo/demo.db AEGIS_VAULT_DIR=/abs/demo/vault
export AEGIS_MAIL_TRANSPORT=file AEGIS_MAIL_FROM=cases@athena.example AEGIS_MAIL_INBOUND=on
export AEGIS_MAIL_OUTBOX_DIR=/abs/demo/outbox AEGIS_MAIL_INBOX_DIR=/abs/demo/inbox
alembic upgrade head && python -m scripts.seed_case && uvicorn app.main:app --port 8000
# prepare and send a letter in the browser, then simulate the recipient's reply and read it:
python -m scripts.mail_demo_reply --outbox /abs/demo/outbox --inbox /abs/demo/inbox
python -m scripts.mail_sync                 # or "Check mailbox now" on the Authorities tab (case admins)
```

A walk-through: sign in as the demo case admin, open **Circle (USDC issuer)** from the Authorities
tab and look at its **How to contact** card. The catalogue lists no address for Circle's LE desk
(*to be confirmed*), so add a case-only channel with a synthetic address on a reserved domain (e.g.
`le-requests@circle-demo.example`). Then **Draft** Circle's stop order from the freeze candidates →
**Edit & send e-mail** → choose recipients and attachments → **Send now** → check the frozen message
on the same page → tick the confirmations → **Send**. One `.eml` lands in the outbox. It is filed as evidence (same sha256) and
the letter and stop order are marked sent. Investigators can prepare but not send; `read_only`
members cannot open the preview at all. **The e-mail editor:** the compose page edits everything in
Aegis — the letter text (with a live preview; the previous text is kept as a version), To / Cc and
**Bcc** (hidden recipients: never a header of the message; with Graph they are set on the draft as
`bccRecipients` before it is sent), the subject and the attachments, including files **uploaded from
the computer** (filed as R3 evidence in Stop orders & correspondence, then attached; only PDF, images, text /
CSV / JSON and macro-free .docx / .xlsx / .pptx / OpenDocument files whose content matches their type are
taken — archives, installers, programs, scripts, web pages, legacy Office, RTF, macro and e-mail files are
refused; each goes out as `<REF>_evidence-<id>.<ext>`). A case admin presses
**Send now** and confirms on the same page, where the editor is locked and the text as it will be sent is
shown (**Edit** cancels that prepared e-mail and reopens the editor); others **Prepare for review**. A
prepared e-mail has **Edit** (back to the editor with every field; the preview is cancelled, so it can
never be sent). **An old checklist once Aegis sends itself:** while a letter has a "Draft — you send"
checklist still open (prepared or expired: it may have gone out from Outlook unrecorded), nothing prepares,
edits or sends a live e-mail of that letter — every Send included — and the pages say so with a link to the
checklist. There a case admin chooses **I did not send it from Outlook — retire it** (Aegis reads Sent Items
first, and refuses while a message sent from Outlook that may be the letter waits for review; the retire is
audited and the editor opens with the checklist's fields) or **Record as sent**. The editor says to check Sent
Items in Outlook yourself whenever that read could not have seen the checklist go out: `AEGIS_MAIL_INBOUND` off,
the read failed, no Sent Items read (file inbound), or Sent Items is read only from a date after the checklist
was prepared (`AEGIS_MAIL_INBOUND_SINCE`, or the mailbox's first sync: older sends are skipped). A letter already
recorded as sent is never retired. While an e-mail of the letter is sending, sent or of unknown
outcome, the letter and its e-mail fields cannot be changed. **Inbound with the file transport:** every `.eml` file
dropped into `AEGIS_MAIL_INBOX_DIR` is read on the next sync and moved to `processed/`. A reply that
answers the sent Message-ID (what `mail_demo_reply` writes) is threaded onto the authority's
timeline. One with neither thread headers nor a tracking tag lands in `/admin/mail/unassigned`. The
tab shows the result ("Mailbox checked: 1 reply filed on this case, 0 waiting for review.").

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_MAIL_TRANSPORT` | `manual` | `manual` ("Draft — you send": Aegis drafts, you send from Outlook; no connection) · `none` (no sending) · `file` (local demo: `.eml` files) · `graph` (Microsoft 365: the investigations mailbox, read and send) |
| `AEGIS_MAIL_FROM`, `AEGIS_MAIL_FROM_NAME` | empty, the organisation name (`AEGIS_ORG_NAME`) | The shared case mailbox and the From display name (manual mode: the draft's From and the suggested Cc; optional) |
| `AEGIS_MAIL_OUTBOX_DIR`, `AEGIS_MAIL_INBOX_DIR` | empty | File transport folders (absolute, outside the repository and the vault) |
| `AEGIS_MAIL_INBOUND`, `AEGIS_MAIL_INBOUND_SINCE` | off, empty | Read the mailbox (graph: Inbox and Sent Items); the backfill start, ISO time (e.g. `2026-01-01T00:00:00Z`; default: the first sync) |
| `AEGIS_MAIL_SYNC_MINUTES` | 15 | How often the scheduler reads both folders |
| `AEGIS_MAIL_MAX_MESSAGE_BYTES`, `AEGIS_MAIL_MAX_INBOUND_BYTES` | 2,900,000, 25 MiB | Largest outbound MIME (Graph's 4 MB request limit after base64) and inbound message |
| `AEGIS_MAIL_SEND_PER_HOUR`, `AEGIS_MAIL_SEND_PER_HOUR_GLOBAL`, `AEGIS_MAIL_TEST_SENDS_PER_HOUR` | 20, 60, 5 | Send limits per case, overall, and for the admin test message |
| `AEGIS_MAIL_TIMEOUT` | 30 | Graph request timeout (s) |
| `AEGIS_MAIL_DEV_ALLOWED_DOMAINS` | `example.com,example.org,example.net,example` | With `APP_ENV=local` and the graph transport, recipients must be on these domains |
| `AEGIS_MAIL_LIVE_SENDING` | off | `1` = go-live: the case mailbox sends to any recipient, as the mailbox itself does (lifts the local domain limit above; one send per letter, admin sending, LE-only blocks, rate limits and the demo lock stay) |
| (demo lock, no setting) | always on | A demo / training case (`Case.is_demo`: reference `DEMO-…` or `facts.demo`) never prepares, sends or records an e-mail to a real organisation, whatever the transport or `AEGIS_MAIL_LIVE_SENDING` say: every recipient must be on a reserved demo domain (`*.example`, `*.test`, `*.invalid`, `*.localhost`, example.com / .org / .net; the case mailbox itself may be a manual-mode Cc). Its "How to email" panel and compose page show only the demo fixture's reserved-domain addresses (e.g. `compliance@circle-demo.example`), never a catalogue address |
| `AEGIS_M365_TENANT_ID`, `AEGIS_M365_CLIENT_ID`, `AEGIS_M365_CLIENT_SECRET` | empty | Entra app registration (client credentials; the secret only in a file outside the repo, e.g. `~/.config/aegis/aegis.env` (mode 600), or Secrets Manager) |
| `AEGIS_M365_CLIENT_CERT_PATH` | empty | Reserved: certificate auth needs the `cryptography` package, not yet a dependency; while set, the transport is not configured |
| `AEGIS_M365_GRAPH_BASE`, `AEGIS_M365_LOGIN_HOST` | `https://graph.microsoft.com/v1.0`, `https://login.microsoftonline.com` | Only these hosts are allowed |
| `AEGIS_M365_TEST_GRAPH_BASE`, `AEGIS_M365_TEST_LOGIN_HOST` | empty | Tests / local walks only: a mock on `http(s)://127.0.0.1:<port>`, honoured only with `APP_ENV=local` (both or neither; anything else: transport not configured) |

### Scheduler

```bash
python -m scripts.run_scheduler              # loop: watch-list poll + overdue-reply check every 5 min (+ freeze checks of enabled cases, + the mailbox sync every AEGIS_MAIL_SYNC_MINUTES)
python -m scripts.run_scheduler --once       # one pass (EventBridge / cron); --interval N, --provider live
python -m scripts.poll_watch                 # watch poll only
python -m scripts.import_evidence --case DEMO-2026-001 --source /abs/folder --dry-run   # index evidence by reference
```

A watch alert whose destination is an exchange, casino, swap service, OTC desk or bridge becomes a
critical `vasp_deposit` notification; other movements become `wallet_movement` (thresholds per
rule). The **Poll watch list** button on the Overview tab does the same on demand. Each pass also runs the
on-chain freeze checks of every open case whose checks are on and whose last run is older than
`AEGIS_FREEZE_CHECK_MINUTES` (audited as `FREEZE_CHECK`, `trigger=scheduler`).

---

## 3. Keeping real data out of git

Before the first commit, and on every commit after it, run the PII and secret scanner:

```bash
export AEGIS_DENYLIST=/path/outside/repo/denylist.txt   # identifiers from your real cases; never inside the repo
python scripts/pii_scan.py                              # scans every file that would be committed
make scan                                               # same thing
```

* `scripts/pii_scan.py` applies generic rules: e-mail addresses outside reserved example domains and
  generic role aliases, international phone numbers, API keys, JWTs and private keys. It also matches
  the literals and regexes in the `AEGIS_DENYLIST` file. That file lists real identifiers, so it lives
  **outside** the repository, and the scanner refuses a denylist inside the repo. Findings are printed
  masked.
* It fails closed. It opens zip containers recursively (`.docx`/`.xlsx`/`.pptx` parts and metadata
  included), decompresses PDF streams, reads PNG text chunks, and also scans decoded variants of
  text: HTML/SVG entities, JS/JSON escapes and base64 `data:` URIs. Multi-word denylist terms match
  across line breaks. PDFs, archives, mail files, photos, videos, key stores and databases are a
  finding even when clean, and so is any other unrecognised binary. Vendored JS is scanned too.
* Pre-commit hook: `pip install pre-commit && pre-commit install --hook-type pre-commit --hook-type pre-push`.
  The hooks run `scripts/pii_scan.py` and gitleaks (`.gitleaks.toml`). If you hold case data, export
  `AEGIS_DENYLIST` (a private denylist kept outside the repo) so the scan also checks those identifiers.
* CI (`.github/workflows/ci.yml`) runs ruff, pytest, the scanner with generic rules only, and gitleaks.
  The denylist never goes to CI.

The full rules are in **docs/data-handling.md**: classification tiers, masking rules for fixtures,
where real case data lives, egress and TLP handling, and what to do if real data is ever committed.

---

## 4. What it does, in order

| Step | Module | Notes |
|---|---|---|
| **Intake** | `app/services.create_case` | Minimum input: origin tx hash *or* perpetrator wallet. Loss amount/asset, fraud time, complaint references and the investigator block (`Case.facts`) feed the letters. |
| **Fetch** | `app/providers/*` | Uniform `ChainProvider` interface: `get_tx`, `outgoing_transfers`, `incoming_transfers`, `address_info`. Adapters: Etherscan V2 (all EVM chains), **Blockscout** (keyless, same API), TronGrid, mempool.space (BTC), and an **offline fixture** (`AEGIS_FIXTURE_PATH`). Every fetched record is persisted (`transfers`, `addresses`), so re-runs are cheap and can be diffed. |
| **Trace** | `app/tracing/engine.py` | Walks forward in time from the origin (BFS). USD **taint** is allocated chronologically across outflows. Asserted edges with an unknown amount pass the remaining taint on as an *upper bound* and flag the node. The walk stops at a VASP deposit address after one sweep hop to the omnibus wallet. At swap contracts it follows only the known cross-chain leg. Guards: `TRACE_MAX_HOPS`, `TRACE_MAX_FANOUT`, `TRACE_MIN_TAINT_USD`. |
| **Attribute** | `app/tracing/heuristics.py` | Flags with plain-English explanations: `vasp_deposit`, `rapid_forward`, `peel_chain`, `high_fanout`, `pre_fraud_activity`, `stablecoin_freezable`, `dormant`, `sweep_imminent`, `asserted_link`, `unquantified_taint`. A 0–100 **freeze priority** combines share of loss, service type, dormancy and confidence. |
| **Candidates** | `app/tracing/freeze.py` | Groups tainted identifiers by **entity** (KuCoin, Rainbet, SWFT…) and adds **issuer levers**: Tether and Circle can blacklist addresses holding USDT/USDC on any exchange or wallet. Each candidate carries every hash, amount, timestamp, dwell time and rationale the compliance team will ask for. |
| **Stop orders** | `app/reports/` | A Jinja template following the structure of investigators' preservation letters: identifiers, then records, then the requested action. Rendered as Markdown, stored, viewable and exportable to `.docx`. Status workflow: draft → sent → acknowledged → frozen / declined. Asserted links are *described*, never cited as fact. |
| **Watch** | `app/services.poll_watch_items`, `app/domain/notify.py` | Every non-terminal tainted address goes on a watch list. Polling raises an alert when funds move, and a **critical** alert when the destination is a known VASP (the freeze window has just opened); alerts become notifications. `scripts/run_scheduler.py` runs it on a loop or once per EventBridge tick. |
| **Desk** | `app/domain/correspondence.py` | Authorities, timelines, status recording with amounts held, form letters, overdue checks. |
| **Evidence** | `app/domain/evidence.py` | Hash-on-ingest register (reference / vault / inline), integrity checks, masked LE contacts, bulk import. |
| **Assistant** | `app/ai/` | Chat with skills (`app/ai/skills.py`), case summary and Q&A from a mode-dependent context (off / redacted / full), with a deterministic rule-based fallback. |
| **Notify** | `app/core/events.py`, `app/domain/notify.py` | `emit()` → per-case rules → scrubbed in-app / e-mail / Slack notifications and the inbox. |
| **UI** | `app/web/` | Server-rendered (Jinja2) plus a Cytoscape.js graph (vendored, no CDN). Click a node for details and explorer links. Colour = coin, shape = chain, size = tainted USD, borders and lock badges = stop-order status, red ring = recommended stop-order target (§2 "Fund flow graph"). |

### Provenance rules (important for anything that goes to a regulator)

* Every `Transfer` has a `source` (`etherscan`, `blockscout`, `trongrid`, `mempool`, `fixture`, `pi_report`, `manual`) and a `confidence`.
* `amount = NULL` means the movement is asserted but its amount was not observed. The tracer never invents a number; the UI shows `? ETH` and the letters omit it.
* Placeholder identifiers (`*_PENDING`) are flagged `pending_input` and scored 0 until replaced.

---

## 5. Project layout

```
aegis/
├── app/
│   ├── main.py                 FastAPI app factory, /healthz
│   ├── core/                   settings, logging, CSRF, auth (sessions), permissions, audit, events
│   ├── domain/                 authorities desk (correspondence.py), evidence.py, notify.py, contact directory
│   │                           (directory.py), sender profile (sender.py), e-mail guidance / compose / send / import (mail_*.py)
│   ├── mail/                   e-mail transports (manual default / none / file / Microsoft Graph), inbound parsing, matching, mailbox sync
│   ├── freeze/                 on-chain freeze detection: issuer registry, ABI, guarded HTTP, failed-transfer signals, check service
│   ├── ai/                     case assistant: chat skills registry, context builder + redactor, rules fallback, model providers (HF router / endpoint, Anthropic)
│   ├── db/                     SQLAlchemy 2 models, session
│   ├── providers/              chain adapters + fixture + registry + reference prices
│   ├── tracing/                engine, heuristics, freeze candidates, graph serialiser + annotations (annotate.py), repository
│   ├── reports/                stop-order renderer, form-letter templates (letters/*.md.j2), .docx export
│   ├── api/                    JSON API (everything the UI does)
│   └── web/                    one router per tab (routes_*.py), Jinja templates, CSS/JS per feature, vendored Cytoscape
├── alembic/                    migrations
├── data/fixtures/demo_case.json  fictional demo case DEMO-2026-001 (default AEGIS_FIXTURE_PATH)
├── data/catalogue/channels.json  contact catalogue: generic organisational channels only (I0, unverified)
├── brand/, img/                GroundBreaker logo assets (Thread & Labyrinth) + palette notes
├── scripts/seed_case.py        seed + first trace
├── scripts/check_providers.py  live-provider connectivity/parsing diagnostic
├── scripts/poll_watch.py       watch-list poller with notifications (one pass)
├── scripts/run_scheduler.py    background loop: watch poll + overdue-reply checks + on-chain freeze checks
├── scripts/create_user.py      user accounts (optionally adds them to a case)
├── scripts/import_evidence.py  bulk evidence indexing by reference (read-only hashing)
├── scripts/pii_scan.py         PII / secret scanner (pre-commit, CI)
├── tests/                      pytest (SQLite, offline)
├── docs/                       data-handling.md, fixture-schema.md, identity-spec.md, aws-deployment.md, m365-setup.md, freeze-detection.md, block-status.md, playbook.md, recovery-plan.md, samples/
├── LICENSE, NOTICE, SECURITY.md
└── docker-compose.yml, Dockerfile, .env.example, requirements*.txt, pyproject.toml, Makefile
```

### Data model (Postgres)

`cases` → `case_seeds` (origin tx / victim / perpetrator) → `trace_runs` → `trace_nodes` / `trace_edges`
`addresses` (unique per chain, linked to `entities`) ↔ `transfers` (one row per value movement; `bridged_to_transfer_id` links swap legs)
`stop_orders` (per entity, status workflow incl. released) · `watch_items` → `alerts`
`users` · `user_sessions` · `case_members` · `audit_events` (append-only, hash-chained)
`correspondence` · `evidence_items` · `le_contacts` · `notification_rules` · `notifications` · `ai_messages` (assistant chat, per case and user)
`entity_channels` (contact directory rows) · `sender_profiles` · `mail_messages` (outbound and inbound e-mail; `sent_external` = sent from Outlook and recorded) · `mail_sync_state`
`freeze_settings` (per-case consent setting) · `freeze_watch` (watched wallets) · `freeze_checks` (issuer blacklist readings) — migration 0009

---

## 6. The demo case (DEMO-2026-001)

`data/fixtures/demo_case.json` is a **fictional** demo case. Its people, companies, e-mail addresses
and references are invented, and every domain is a reserved one (`*.example`, RFC 6761):

* the victim Jordan Avery of Northbridge Analytics, Inc.; the impersonated company Exempla Holding AG
  (`exempla-holding.example`, persona "Adrian Example, CFO"); the investigating firm Kestrel Ridge
  Investigations GmbH; places such as "Demo City" and "Musterstadt";
* complaint references (`DEMO-IT-0000000000`, `IC3-DEMO-00000000`) and attacker-infrastructure
  placeholders (`demo0000project`, `gsk_DEMO…XXXX`, `index-DEMO0000.js`);
* the services the funds touch (KuCoin, Rainbet, SWFT/Bridgers, Tether, Circle, Uniswap, Hostinger,
  Supabase, Groq) appear as organisations only, with no named contacts. The loss is 399,247.92 USDC.

The trace roots at the victim's origin transfer (`0x70ab…a814`, 12 Oct 2026 10:49:47 UTC, from
`0x7AC3…455b`) to the perpetrator wallet `0x57de…F8df`. From there it follows three USDC relays to the
perpetrator's swap wallet `0xe944…4b1b`, then the distribution hub `0x5445…becb` (156.611 ETH), then
the downstream exchange, casino, swap and issuer touchpoints. The relay-hop transaction hashes are
not yet verified on-chain, so those edges are **asserted** (amount known, hash pending; docs/fixture-schema.md).

Sample stop orders generated from this case are in `docs/samples/`.

---

## 7. Roadmap

**Shipped:** safe-to-push repo (fictional demo case, PII scanning, CI); case workspace (accounts, roles,
audit, evidence folders, LE contacts, notifications); authorities desk and form letters; trace
versions and exports; value-sized graph with freeze status and recommended stop orders; case
assistant with skills; e-mail desk ("draft — you send", and the investigations mailbox over Graph: sync, outside-sent letters,
direct send); block status across the authorities; on-chain issuer freeze detection; provider playbooks (LE-only and
instrument gates, request paths, reply extraction, provider clocks, the LE / counsel brief); the per-case recovery plan
with evidence checklists and the LE brief pack.

**Next:**

1. **Trustworthy trace:** live adapter runs (pagination, internal transactions), verify the asserted relay hops on-chain, pull watched wallets (e.g. a wallet found frozen downstream) into the trace by linking their funding back to traced funds, a token registry, historical prices, a "root confirmed" gate before any letter.
2. **E-mail via Microsoft 365:** checks against a live tenant (docs/m365-setup.md): the Graph create-cleanup edge case, the Sent Items delta filter, `permanentDelete` under the access policy.
3. **Assistant:** move summaries off the request path; decide whether real cases use a dedicated HF Inference Endpoint instead of the router.
4. **Evidence vault:** per-case encryption at rest and redacted derivatives.
5. **Reporting:** the graph in the LE brief pack, file the movements CSV and freeze readings as evidence items, pack versions with a stored manifest hash (deferred: `evidence_packs`), per-case playbook overrides and provider response statistics (deferred); e-mail/Slack/SMS delivery.
6. **Hardening:** passkeys (docs/identity-spec.md), bridge resolvers, Solana/TON, AWS (EU region), pen test.

---

## 8. Security notes

* Per-user accounts (scrypt passwords, server-side sessions, rate-limited login), case roles and an append-only, hash-chained audit log (`/cases/{id}/audit`, `/admin/audit`); passkeys are specified in docs/identity-spec.md. On AWS, the ALB (Cognito/OIDC) authenticates in front of the app.
* Notifications, audit details and AI prompts carry no personal data by construction (scrubbing, ids-only detail, redacted mode); see docs/data-handling.md.
* No private keys, no signing, no custody: chain access is read-only.
* Case data is sensitive (victim PII, LE references). It stays out of git, CI, logs and notifications; docs/data-handling.md sets the rules.
* Outbound egress should be limited to the chain-data providers; the freeze-check endpoints
  (`ethereum-rpc.publicnode.com`, `api.trongrid.io`, `eth.blockscout.com`) only for cases where an
  admin turned on-chain checks on (consent recorded in the audit log); `router.huggingface.co` when
  the case assistant is enabled; and `login.microsoftonline.com` / `graph.microsoft.com` only once
  Microsoft 365 e-mail is configured. The UI has no CDN dependencies.
* E-mail: only case admins send, through the web form only (no API route sends; the assistant cannot
  import the mail code); recipients are validated strictly, attachments re-checked by sha256 and TLP
  marking at prepare and at send, and every sent message is filed as R3 evidence (docs/data-handling.md §6.3).
* To report a vulnerability, see SECURITY.md.

---

© 2026 Athena Software Group, Inc. Licensed under the GNU Affero General Public License v3.0
(AGPL-3.0); see LICENSE and NOTICE. The licence covers the code only: it grants no right to use the
GroundBreaker or Athena names, logos or other marks.
