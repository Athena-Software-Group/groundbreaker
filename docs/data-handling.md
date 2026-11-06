# Data handling — what may enter this repository

_Applies to everyone who commits to this repository or runs Aegis on real cases, and to CI._

The rule in one line: **git holds code and synthetic or masked data only.** Real case material
never enters the working tree, git history, CI, issue trackers, logs, notifications or LLM prompts.

## 1. Classification tiers

Every field, file and export carries one tier. Unclassified case data defaults to **R2**. Combining
items raises the tier: a public tx hash plus the case label is C1, and with the victim's name added
it is R2.

| Tier | What | Examples | Git | Logs / notifications | Leaves the case team |
|---|---|---|---|---|---|
| **R3** Restricted-LE / evidence | Law-enforcement and evidentiary material | Police and IC3 complaint references and documents, PI reports, original screenshots, chats and e-mails, exchange statements, victim KYC/ID, powers of attorney or agent, letters as signed or sent, LE-portal responses | **Never** | Never | Only as a reviewed, redacted derivative, through an audited export |
| **R2** Restricted-PII | Personal data | Victim name, e-mail, phone, address, company and role; identity-linked loss amount; names and e-mails of PI staff, named exchange compliance officers and impersonated people; original evidence filenames | **Never** (masked equivalents only) | Never; IDs only | Minimised per recipient; consent or another lawful basis is needed for third-party contacts |
| **C1** Confidential-intel | Case-linked investigative judgments | Address labels and roles (victim/perpetrator), trace graphs, freeze candidates and scores, watch lists, alerts, attacker IOCs (infra project ids, key fragments, bundle hashes, scam domains, personas), swap order ids, exchange ticket numbers | **Never** for a real case; fictional or masked values only | Case ref and event type only | Deliberate, audited export (e.g. IOCs to LE or an issuer) |
| **I0** General | No case linkage | Source code, the fictional demo fixture, generic VASP role aliases (`compliance@`, `legal@`, `abuse@`) and LE-portal URLs, the contact catalogue `data/catalogue/channels.json` (generic organisational channels only: homepages, portals, generic aliases with their published source; never a named person, every entry unverified, unknown channels "to be confirmed"), architecture docs, brand assets, public chain data with no case label | **Allowed** | Allowed | Anyone (this repository is public) |

Only I0 material enters this repository. Public material (the demo case, sample letters, screenshots,
marketing) uses fictional identities only.

## 2. What may and may not enter git

**May:** application code, migrations, tests, the fictional demo fixture `data/fixtures/demo_case.json` and other
synthetic or masked fixtures, `docs/samples/` (stop orders generated from the demo case), brand assets, these docs.

**May not:**

* real fixtures (`case.json` for a real case), `deliverables/`, letters, evidence, exports;
* screenshots, PDFs, `.docx`, `.eml`/`.msg`, photos and video of anything case-related;
* the denylist and the masking map: they list real identifiers, so they are R2/R3 themselves;
* `.env` files, API keys, tokens, private keys;
* explorer API responses saved during a real investigation (C1 once linked to the case).

`.gitignore` excludes `deliverables/`, `data/cases/`, `data/private/`, `vault/`, `evidence/`,
`case-data/`, `*-private/`, `exports/` and evidence-shaped file types (`*.docx`, `*.pdf`, `*.eml`, `*.msg`, images,
video, `*.zip`). Only the demo fixture `data/fixtures/demo_case.json`, its synthetic evidence texts
`data/fixtures/demo_evidence/*.txt` (+ `fixture-section.json`) and the generated sample
letters `docs/samples/stop-orders/NN-*.docx` are re-included; the hard rules (secrets, keys,
databases, case-data folders, denylist and masking map, evidence formats) are repeated after those
exceptions so nothing re-opens them. `.dockerignore` is an allowlist (app code, migrations, scripts,
the demo fixture). Treat both as a safety net, not a storage policy. **Never copy real material into the working tree in the first place.**

## 3. Where real case data lives

| Stage | Location |
|---|---|
| Now | A local private folder **outside** the repository and outside any cloud-synced folder, one sub-folder per case (e.g. `../case-data/<CASE-REF>/`). It holds the real fixture, original documents, the analysis, the denylist and the masking map. |
| Next (local) | An encrypted volume (e.g. an encrypted APFS disk image on macOS, its passphrase held by the case team only) at a path given by configuration, using the same layout. |
| Hosted | S3 with SSE-KMS (one data key per case, wrapped by a per-organisation KMS key), Block Public Access, versioning and Object Lock for originals, an EU-region bucket for EU-origin material. The database holds metadata and ciphertext only (docs/aws-deployment.md). |

To work on a real case, load it by path. Do not copy it:

```bash
export AEGIS_FIXTURE_PATH=/path/outside/repo/<CASE-REF>/case.json
python -m scripts.seed_case
```

## 4. Masking rules for fixtures

A fixture that enters git is either fully synthetic or, when you build a demo or a test case from a
real case, masked under these rules:

1. **May stay as observed:** chains, wallet addresses, tx hashes, amounts, timestamps, movements,
   public explorer labels (e.g. "KuCoin 17") and the names of services as organisations (exchanges,
   casinos, swap services, issuers, infrastructure providers). This is public chain data, but next to
   a case it shows which wallets and services an investigation is watching: keep it only when the case
   lead agrees that no longer matters, and use synthetic chain data otherwise.
2. **Replace with obviously fictional values:** every person (victim, investigators, personas),
   the victim's company, impersonated companies (names, registry IDs, street addresses, domains),
   complaint and case references, service order and ticket references (swap orders, exchange tickets),
   phone numbers, attacker infrastructure identifiers (project ids, key fragments, bundle names and
   hashes).
   Also make **places and infrastructure times** generic: the town of a police station or of the
   PI firm, the meeting place, and the registration / issue / last-modified times of attacker
   infrastructure (domains, keys, files) are replaced or shifted to round fictional values, since
   registrar or WHOIS history can link them back. Chain timestamps fall under rule 1.
3. **Remove:** named individual contacts at services. Keep only generic role aliases at the
   service's own domain (`compliance@`, `legal@`, `abuse@`), or set the field to null with the note
   "use the entity's law-enforcement request portal; named contact on file in the case vault".
4. **Domains and e-mails** use reserved names only: `*.example`, `example.com/.org/.net`
   (RFC 6761). Phone numbers use all-zero placeholders (`+41 00 000 00 00`). References use a `DEMO-`
   prefix.
5. **Use one fictional value per real value, everywhere.** The same person keeps the same fake name
   in the fixture, tests, docs and sample letters. The mapping lives in the case's `masking-map.json`,
   outside the repo.
6. **Do not import third-party-report findings** into a masked fixture until your own on-chain
   verification has reproduced them (see §7). Model unverified movements as asserted edges
   (amount known, hash pending), not as observed transfers.
7. Add every real string you masked to the case's denylist so the scanner catches regressions.

The demo case `DEMO-2026-001` (docs/guide.md §6) is fictional. Its invented values use the same conventions:
reserved domains, all-zero phone numbers and `DEMO-` references.

## 5. Pre-commit scan

```bash
pip install pre-commit
pre-commit install --hook-type pre-commit --hook-type pre-push
export AEGIS_DENYLIST=/path/outside/repo/denylist.txt   # in your shell profile
python scripts/pii_scan.py                              # or: make scan
```

* `scripts/pii_scan.py` scans every file that would be committed (`git ls-files`, or a `.gitignore`-aware
  walk before `git init`), vendored JS included. It fails closed: zip containers (Office files too) are
  opened recursively, PDF streams decompressed, entity/escape/base64 `data:` encodings decoded, and
  multi-word denylist terms matched across line breaks. PDFs, archives, mail, photos, videos, key
  stores and databases are findings even when clean, and so is any other unrecognised binary.
* The pre-commit/pre-push hook adds the private denylist when `AEGIS_DENYLIST` is set; maintainers who
  hold case data set it (or run the scanner with `--require-denylist`) so a missing denylist fails loudly.
* **Generic rules** (always on, also in CI): e-mail addresses outside reserved domains and generic
  service aliases, international phone numbers, API keys (Groq, OpenAI/Anthropic, AWS, GitHub, Slack),
  JWTs and private-key headers.
* **Denylist** (local only): case-insensitive literals and `re:` regexes of real identifiers. The file
  lives outside the repo; the scanner refuses a denylist inside the repo and masks what it prints.
  The denylist is **never** uploaded to CI or shared outside the case team.
* gitleaks runs as a second hook with `.gitleaks.toml` (default rules plus Groq/Supabase keys).
* Run a full scan with the denylist **before the first commit** and before every push. A finding
  blocks the commit. Fix the content; never add an allowlist entry for a real value.

## 6. Egress policy for live lookups

A live trace sends the case's wallet addresses and transaction hashes to third-party explorers
(Etherscan, Blockscout, TronGrid, mempool.space). That discloses the investigation and can tip off
the perpetrators.

* The default is `PROVIDER_MODE=fixture`. CI never runs live and never holds provider keys.
* For a real case, going live is a per-case decision by the case lead, and it is recorded: who decided, when, which providers.
* Allowed hosts are only the chain-data providers in `docs/aws-deployment.md` (egress allow-list),
  plus the SMTP relay / Slack webhook when notifications are configured, the LLM host when the
  case assistant is enabled (`router.huggingface.co`, or the dedicated endpoint; below), and
  `login.microsoftonline.com` and `graph.microsoft.com` when the Graph e-mail transport is configured (§6.3;
  the default `manual` mode connects to nothing), and the freeze-check endpoints below. No case data
  goes to OCR services or analytics.
* **On-chain freeze checks** (docs/freeze-detection.md) send the case's wallet addresses to a JSON-RPC node
  (`ethereum-rpc.publicnode.com` by default), TronGrid (`api.trongrid.io`) and an explorer's logs API
  (Blockscout, or Etherscan with a key). They are **off per case by default**: a case admin switches them on
  after the page lists each host and what it receives, and ticks a confirmation. That consent (who, when,
  which hosts) is the per-case record this section asks for, kept in `freeze_settings.consent` and an `UPDATE`
  audit row. The transport refuses every host outside `app.freeze.transport.ALLOWED_DOMAINS` (plus
  `localhost` for a self-hosted node); `AEGIS_FREEZE_CHECKS_DISABLED=1` stops all of it. When the hosts the
  checks would use change after the consent (another RPC URL, an Etherscan key moving the explorer to
  etherscan.io), the checks stop until a case admin confirms the new hosts (audited). Watched-wallet labels and
  source notes stay on the case's freeze page: never in notifications, the assistant (whatever the TLP) or
  the audit log; audit rows carry counts and hosts only.
* Explorer links in the UI reveal an address to the explorer when clicked. Treat that like a live lookup.
* Provider API keys never appear in URLs that get logged. Redact them in error messages.

### 6.1 The case assistant (LLM) and what each AI mode sends

The assistant (`app/ai/`) calls a model API only when the deployment has an inference token
(`HF_INFERENCE_TOKEN`) and `AEGIS_AI_DISABLED` is unset. Without a token every summary and answer is
rule-based, computed locally and labelled "rule-based (AI not configured)".

**Where the data goes.** By default (`AEGIS_LLM_PROVIDER=hf_router`) requests go to the Hugging Face
Inference Router (`router.huggingface.co`), which forwards them to a **third-party inference
provider**. The model id pins that provider (`deepseek-ai/DeepSeek-V4.1-Flash:deepinfra` → DeepInfra),
so the data path is fixed and shown on the AI Assistant (Pythia) tab and at `/admin/ai`: "Hugging Face Inference
Router → DeepInfra (third-party inference provider)". With `AEGIS_HF_BILL_TO` set, calls are billed to that Hugging Face organisation
(`X-HF-Bill-To: <org>`). The response names the model that actually served; it is audited with
every call. **Using the router on a deployment that holds real cases requires data-processing terms
covering Hugging Face and the pinned inference provider**, and `router.huggingface.co` on the egress
allow-list. Where that is not acceptable, use a dedicated Hugging Face Inference Endpoint
(`AEGIS_LLM_PROVIDER=hf_endpoint`, `*.endpoints.huggingface.cloud`, region and instance chosen by us)
or a self-hosted vLLM on `localhost`; base URLs on any other host are refused unless
`AEGIS_LLM_ALLOW_ANY_HOST=1`. The token is a fine-grained, inference-only token kept outside the
repository (e.g. `~/.config/aegis/aegis.env`, mode 600); it is never logged, audited, shown or committed, and
`HF_API_KEY` (the admin / write token) is never read by the app.

Each case has its own AI mode (`cases.ai_mode`, set by a case admin on the AI Assistant (Pythia) tab).
**`redacted` stays the default**:

| Mode | What leaves Aegis | Tier sent |
|---|---|---|
| `off` | Nothing. No model is called; rule-based summaries and answers only. | — |
| `redacted` (default) | Chain data (addresses, tx hashes, amounts, timestamps, service names, swap order ids), trace statistics, freeze candidates, stop-order and correspondence **metadata** (recipient organisation, kind, status, dates, answered/overdue), the evidence index (folder, type, date, classification, Aegis's own system tags; titles that come from original file names are withheld, free-form tags are not sent), the complaint authorities and LE agencies as *type and country* only (e.g. "Carabinieri (Italy)", never the station, unit or town), LE role/jurisdiction, team role counts. Chain-shaped values (addresses, hashes, swap order ids) are never replaced, even when an infrastructure note cites them. A final scrub replaces the case's own personal values (victim and victim contact, company, personas, impersonated company, domains, the case's PI firms and staff, the attorney-in-fact, LE contacts, units and station / town names, complaint addresses, the meeting venue, senders, CC lists, complaint and ticket references, attacker-infra tokens) with role placeholders such as `[VICTIM]`, and e-mail addresses / phone numbers with `[EMAIL]` / `[PHONE]`. | C1 (case-linked chain intel) |
| `full` | Adds names, references, subjects, letter and message bodies (truncated), notes, evidence descriptions and inline text. Switching to full needs a case admin and an explicit DPA confirmation; on the third-party router also the confirmation "Full case content will be sent to <data path>", recorded in the audit row (`confirmed_provider`, `confirmed_destination`). If the destination changes afterwards (another pinned provider), the case's calls stay rule-based until an admin confirms again. A summary made in full mode is hidden from read-only members. | R2 / R3 |

Never sent, in any mode: evidence file bytes and file paths (the extracted text of evidence documents goes only
under the separate per-case "AI reads evidence" consent below; stop-order identifiers such as
`original` / `letter_text_file` / `*_path` are dropped, and any path-shaped text, e.g. inside a
letter body, becomes `[PATH]`), the content, title and tags of TLP:RED and TLP:AMBER+STRICT items,
internal fact keys, passwords or tokens. The context block carries only the day it was built; the
exact time travels in the task turn, so follow-up questions reuse the prompt cache. Every call (AI or rule-based)
writes one `AI_QUERY` audit row with the mode, provider and data path, the configured and the
**served** model, token counts, estimated cost, latency, stop reason and whether a repair call was
made; prompt and answer text are never stored. The admin page's connection test sends only the fixed
prompt "Reply with the single word OK." (no case data). `GET /api/cases/{id}/assistant/context-preview?mode=` (case admins)
shows exactly what a mode would send. Whether real cases should start in `off` rather than
`redacted` is a decision for each deployment.

**Mailbox replies ("AI reads mailbox replies", app/blocks/classify_ai.py).** A
separate per-case setting, **off by default**, independent of the mode above except that mode `off` blocks it
too. When a case admin turns it on (an explicit consent naming the data path, e.g. "Hugging Face Inference
Router → DeepInfra (third-party inference provider)", and the model; recorded in `cases.mail_ai_consent` and
in the audit row as `confirmed_destination`), the **full text** of each reply filed from the case mailbox
(subject and body as filed, quoted earlier messages included; at most 24,000 characters) and the kind of
request it answers are sent for a second reading of its status: R3, not redacted. Nothing else from the case
is sent, and only mail that §6.4 stored (never notes an investigator typed). The text travels between
per-call nonce markers as untrusted data; the answer is advisory only (its quote must be verbatim in the
sender's own text and, for frozen / hold / returned, overlap a statement of that same outcome the rules' guard
accepts; it never
upgrades an unclear rules reading and adds no confidence to a rules outcome; a disagreement with the rules shows
as "needs review"; nothing changes a stop order until a person confirms). When the provider or model changes, no call is made until an admin consents again. Every
call writes one `AI_QUERY` audit row (`kind=reply_classification`; no reply text, quote or rationale).

**Evidence documents ("AI reads evidence", app/evidence_intel/ai.py).** A third per-case setting, **off by
default**, recorded in `cases.evidence_ai_consent` (migration 0011) and the audit row (`setting=evidence_ai_reading`,
`confirmed_destination`). When a case admin turns it on, the extracted text of each evidence document Aegis reads
(at most 16,000 characters) is sent for a second reading of its type: **redacted** through the case's redactor in
mode `redacted` (the names, contacts and references the case already holds, and any e-mail or phone, as
placeholders; chain identifiers kept; other personal data in a document, such as a name the case does not know yet,
is **sent**; an ID document or financial record, by the rules' reading, the type a person confirmed, its tags or the Financial
folder, is not sent at all),
with only file paths removed in mode `full`; mode `off`, the kill switch and items marked TLP:RED / TLP:AMBER+STRICT mean no
call. The answer is advisory: kept only where its quotes and values occur in the text that was sent, shown next to
the rules' reading, and a person confirms every type. One `AI_QUERY` row per call (`kind=evidence_classification`;
no text, quote or summary). Without the setting, evidence is read by the rules only, on the machine
(docs/evidence-intel.md): an upload's extracted text is kept in the vault (`<vault>/text/<case>/<sha256>.txt`), a
referenced original's text is never copied, and the database holds a 280-character excerpt and the reading (the
type, whether its quote was found, the confidence and the model). The AI reading's quote, summary, parties, dates,
amounts and identifiers are document content: they live in a vault sidecar (`<vault>/text/<case>/<text
sha256>.ai.json`, sha256-linked), never in the database; for a referenced original they are not kept at all (only
the type and whether it was verified).

### 6.2 Evidence storage modes

| Mode | What happens | Where the bytes are |
|---|---|---|
| `reference` | The original is hashed (sha256, size) **read-only** and never copied. From the web UI the path must lie under the case's own evidence root (`AEGIS_EVIDENCE_ROOTS`: `<dir>/<case reference>/`, or `REFERENCE=<dir>`; a plain `<dir>` serves only cases seeded or opened by a system admin, and the folder must be spelled exactly like the reference and must not be, contain or lie in another case's folder, compared by file identity so case-insensitive file systems and symlinks cannot alias it; references are unique ignoring case), never inside the repository or the vault, and never be a symlinked file (re-checked on every read; a path that is not allowed and one that does not exist get the same answer); `python -m scripts.import_evidence` indexes a whole folder this way (zip members as `archive.zip!member`, `.rtfd` bundles as one item, dedup by hash). Downloads, the in-page text preview and inline text in the API re-hash the bytes first (409 / an integrity notice on a mismatch, 410 when it is gone) and each writes a `DOWNLOAD` audit row (`mode` = attachment, inline, preview or api). Lowering an item's classification needs a case admin and is audited as `DECLASSIFY`. Only case admins see the source path. | Where they already are (e.g. the encrypted case volume) |
| `vault` (upload) | Streamed into `AEGIS_VAULT_DIR/<case_id>/<uuid>` and hashed on the way. Refused while the variable is unset, relative or inside the repo. Uploads over 1 MB are first spooled by the web server to a temp file, so run the server with `TMPDIR` on the same encrypted volume. | The vault (outside the repo) |
| `inline` | Short text notes and generated chain reports stored in the database (hashed). | The database |

"Verify integrity" re-hashes and records the result in `meta.integrity`; a mismatch or missing
original is flagged on the Evidence tab and raises an `evidence_integrity` notification. The
recorded hash is never rewritten.

### 6.3 What leaves the platform when you send an e-mail

E-mail from Aegis (docs/guide.md "E-mail from Aegis"; docs/m365-setup.md) sends case material outside the
platform on purpose, so it is gated: only case admins press Send, after confirming every unverified
recipient and every evidence attachment, and only through the web form.

**Default mode: "Draft — you send" (`AEGIS_MAIL_TRANSPORT=manual`).** Aegis transmits nothing and opens no
mail connection; a person sends the e-mail from the investigations mailbox in Outlook. The material
therefore leaves Aegis **to a workstation first**:

* **Downloads (case admins only, each audited as `DOWNLOAD` with ids and counts):** the Outlook draft
  (`.eml`, `X-Unsent: 1`: the letter text and HTML plus every attachment) and the attachments (one by one
  or as a `.zip`). These files are **R3**. Save them only to the encrypted case volume (§3), never to a
  synced or shared folder (Desktop / Downloads synced to iCloud or OneDrive included), and delete them once
  the e-mail is sent and recorded. The Copy buttons put the same R3 text on the clipboard: clear it after use.
* **The investigations mailbox** (Sent Items, and the Inbox for replies) becomes an R3 store, as below for
  the Graph transport: delegates limited to the case team, MFA, a retention policy.
* **Record as sent** may upload the sent message (`.eml` / `.msg` from Sent Items); it is stored in the vault
  as R3 evidence with its sha256, like a reply imported with **Import reply**. Delete the local copies
  after the upload.
* The attachment rules below (TLP:RED / AMBER never attached, integrity re-checked, neutral file names)
  apply to the checklist, the draft and the `.zip` alike.

The rest of this section describes the sending transports (`graph`, and `file` for local demos).

* **What goes out:** the letter text (as plain text and HTML), the letter as `.docx`, the evidence
  items selected as attachments, the sender profile's authority documents, and the case reference
  inside the tracking tag of the subject (`[Aegis <REF> #<letter id>]`). Attachment file names are
  neutral (`<REF>_evidence-<id>.<ext>`): evidence titles and original file names (R2) stay inside.
  No Bcc header (Bcc recipients a member adds are handed to the transport beside the message: Graph sets
  them on the draft as `bccRecipients`; they are kept on the e-mail record, the audit holds their count
  and domains only), no X-headers with case data; the victim's name is never in a mail header. Files
  uploaded on the compose page are stored first as R3 evidence (vault, sha256) and go only to the
  authority of that letter; only PDF, images, text / CSV / JSON and macro-free Office Open XML /
  OpenDocument files whose content matches their extension are accepted (no archives, installers,
  legacy Office, RTF, web pages, scripts or e-mail files).
* **Where a copy stays:** in the Microsoft 365 shared case mailbox (Sent Items, and the Inbox for
  replies; what Aegis reads back from it is limited by §6.4), which therefore becomes an **R3 store**: restrict delegates to the case team, enforce
  MFA for them, set a retention policy, and choose an EU datacentre where the tenant allows it. The
  Entra app may reach only that mailbox (Exchange application access policy).
* **Law-enforcement material** goes only to the law-enforcement recipient it concerns.
* **TLP:RED and TLP:AMBER (including AMBER+STRICT) items, and their derivatives** (an item whose
  parent carries the marking, or a tag with it), can never be attached; neither can an item whose
  integrity check failed. The server re-checks the marking and the sha256 at prepare and at send.
* **Inside Aegis:** every sent message is filed as an R3 `.eml` evidence item (the exact bytes
  sent); inbound mail is R3 and stored only in the database and the vault, shown as escaped plain
  text (inbound HTML is never rendered, remote content never fetched). Audit rows hold ids, counts and
  domains only, never addresses, subjects or bodies.
* **The file transport (local demos only)** writes the exact outbound bytes to `AEGIS_MAIL_OUTBOX_DIR`
  (owner-only `.eml` files) and reads every `.eml` in `AEGIS_MAIL_INBOX_DIR`, moving each to
  `processed/`. Both folders must be absolute and outside the repository (the outbox also outside
  the vault). Treat them as R3 stores and delete them after the demo; never point them at real case
  mail.

### 6.4 Reading the case mailbox (Inbox and Sent Items): data minimisation

With the Graph transport and `AEGIS_MAIL_INBOUND=on`, Aegis reads the shared investigations mailbox
(app/mail/ingest.py, app/mail/sync_outbound.py, app/mail/matching.py `assess`). That mailbox also holds
mail that has nothing to do with any case (newsletters, other business, colleagues' messages), so Aegis
**stores a message only when it is related to a case**:

| Rule | Message | Stored |
|---|---|---|
| (a) | the subject carries an Aegis tracking tag `[Aegis <REF> #<id>]` | in full (Inbox: matched as before; Sent Items: tied to its letter) |
| (b) | it is in a thread with a stored message (In-Reply-To / References / Graph conversationId) | in full |
| (c) | **Sent Items:** the subject / body cites the case reference or a traced wallet / tx hash of an open case, or a To / Cc recipient is a known authority address or domain of the case (the contact directory incl. catalogue and case-learned recipients, entity compliance addresses, LE contacts, the case's letters) **and** the message matches one of the case's letters (app/mail/sync_outbound.py: subject, identifiers and recipients at `THRESHOLD`) | in full; the raw `.eml` is filed as R3 evidence |
| (c′) | **Sent Items:** only a recipient ties it to a case (an authority's address or domain, or an officer's exact free-mail address), nothing is cited and no letter matches (e.g. another client's matter sent to someone at that exchange, a personal e-mail to an officer) | **metadata only** on /admin/mail/mailbox: subject, recipient **domains**, date. No addresses, no body, no `.eml`, no hash, no timeline entry; a reply to it is not filed on the case |
| (d) | **Inbox:** the sender is a known authority address or domain of an open case **and** it cites case material (the case reference, a traced wallet / tx hash, or repeats the subject of an earlier outbound letter) | in full; it waits on the case's **Mail to review** unless it answers a letter (then the usual matching rules) |
| (d′) | **Inbox:** the sender is a known authority address or domain, but nothing is cited | the system admins' unassigned queue with **metadata only**: sender, subject, date. No body, no recipients, no attachments, no hash. The message is read from the mailbox only when a system admin opens or assigns it (one `MAIL_TRIAGE_OPENED` audit row, written by `ingest.load_metadata_only` for either) |
| (d″) | **Inbox:** an unknown sender replies ("Re:" / "AW:" / "RE:" …) to the subject of a letter we sent or recorded as sent (never a draft's, a prepared e-mail's or an Outlook e-mail still under review), or cites a case reference (in the subject; for a reply subject, or any subject of a message whose listing lacks the sender, also in the text, read in memory) | the unassigned queue with **metadata only**, as (d′) |
| (e) | **Inbox:** a delivery-status report from any domain (multipart/report by its headers, or a DSN-like sender / subject such as mailer-daemon@ or "Undeliverable:") | read in memory and kept only when the original Message-ID it carries is a stored message (rule (b)); otherwise discarded |
| — | everything else (incl. copies of the mailbox's own messages in its Inbox) | **never stored**: only counted (`not_related` in the sync result) |

* **A case reference in the body of mail from an unknown domain (data minimisation).** When the folder listing
  carries the sender (the usual case), the body of an Inbox message from a sender that is no known authority
  address or domain is read (in memory) only when its subject is a reply ("Re:" / "AW:" / "RE:" …), and a
  message with a fresh subject is decided from the listing alone, so its case reference counts only when it is
  in the subject: a new message from an unknown domain that cites the case reference only in its body is never
  stored (counted `not_related`) and no header or body of it is read for a reference. When the listing lacks
  the sender, the message is downloaded and read in memory to find it; a case reference in its body then puts
  it in the unassigned queue with metadata only, as (d″), and nothing else of it is stored. A person who
  expects such mail imports it by hand (the `.eml` / `.msg`
  upload on the case, `/cases/{id}/mail/import`: it waits on **Mail to review**).
* **Demo / training cases** (reference "DEMO-…", or `facts.demo` / `facts.is_demo`: `Case.is_demo`) are not open
  cases for these rules: they are left out of the index, a stored message of one never ties a new message to it,
  and a reply matched to one is treated as matching nothing. A real message never lands on a demo copy of a real
  authority or wallet.
* **An authority's own domains** are its addresses' domains plus its entity's website and the catalogue
  organisation's homepage / website / e-mail domains (never a shared host such as t.me or a portal provider), so a
  new inbox on that domain (e.g. a freeze address a redirect names) is that authority's. For Sent Items the **To**
  recipients decide the authority; a Cc (a partner firm, our own team) never widens or blurs it.
* **Free-mail and shared domains** (`app.mail.matching.SHARED_DOMAINS`, e.g. gmail.com) never match by domain
  alone; only an exact known address does (e.g. an LE officer's recorded address). The case mailbox's own
  domain, the sender profile's addresses and the case members' addresses are never an authority's.
* **Before downloading anything** the sync decides from the folder listing's metadata (sender, recipients,
  subject, conversationId). When that ties nothing to a case it reads only the message's thread headers
  (In-Reply-To / References) and, for Sent Items, its text body without attachments (rule (c) needs it), in
  memory, and discards them. The raw message (`$value`) is downloaded only for a message that may be related,
  and a message that turns out unrelated is discarded without a trace (no row, no vault file, no log line with
  its content). The traced wallets compared are the case's seeds, its latest run's wallets (not service hot
  wallets or token contracts, which other matters cite too) and movements, its stop orders' identifiers and its
  watched wallets.
* **Only from the backfill start**: `AEGIS_MAIL_INBOUND_SINCE` (an ISO time, e.g. `2026-01-01T00:00:00Z`; unset: the first sync), or the
  date a system admin gives on **Backfill since <date>** (`/admin/mail/mailbox`, audited `MAIL_BACKFILL`).
* **Sent Items never come from the Inbox**: only a Sent Items message can mark a letter sent, and only one
  addressed to that letter's authority (a To recipient that is the letter's To, or an address / own domain of
  the authority); an Inbox copy of one of our letters (the mailbox Cc'd) is never stored.
* What is stored is R3 (§1) and handled as in §6.3: the mailbox rows, the vault copies and the evidence items.
  Audit rows carry ids, counts, the matching method and the outcome only, never addresses, subjects or bodies.
  A database error in the sync or the block-status hooks is recorded (`last_error` on /admin/mail/mailbox, the
  logs) by its type only: its text carries the SQL's bound parameters, which can hold a subject or body.
* The per-case **"AI reads mailbox replies"** setting (off by default; app/blocks) is the only way a stored
  reply's text reaches a model: a case admin's explicit consent naming the data path (Hugging Face Inference
  Router → DeepInfra, §6.1) is recorded in `cases.mail_ai_consent` and the audit log; the model's reading is
  advisory and never changes a stop order. Mail that is not stored (above) never reaches it. While it is off,
  the assistant's `/block-status` leaves the details read from replies out of what it sends to a model (their
  ticket numbers and portal URLs as placeholders, e-mail addresses as `[EMAIL]`, amounts a reply states left
  out; amounts a person recorded stay).

## 7. TLP and third-party markings

Third-party reports (exchange aftercare partners, analytics vendors, other investigators) often
carry a Traffic Light Protocol (TLP 2.0) marking or a contractual use restriction. The marking travels
with the data and with anything derived from it.

| Marking | Meaning for us |
|---|---|
| TLP:RED | Named recipients only. Do not store it in Aegis beyond the evidence vault. Do not derive fixture data from it. |
| TLP:AMBER+STRICT | The recipient organisation only. Keep it inside the case team. Derived facts may not go to partners, demos or this repository. |
| TLP:AMBER | The recipient organisation and its clients, on a need-to-know basis. Same exclusions from the repo and demos. |
| TLP:GREEN / CLEAR | Community or public. It can be cited, but it is still case-linked (C1) when tied to the case. |

* Record the marking on the evidence item. A derivative inherits its parent's marking.
* TLP:RED and TLP:AMBER (incl. +STRICT) items, on the item, in its tags or on a parent, are never
  attached to an e-mail sent from Aegis (§6.3); the compose page shows them disabled.
* A fact becomes ours, and so free of the marking, only once we have reproduced it independently from
  public chain data. Record the observation (provider, endpoint, retrieved-at, response hash).
* Do not name the report's author or quote its findings in the repo, the issue tracker or external materials.

## 8. Incident procedure: real data committed

1. **Stop.** Do not push, or stop pushing. Tell the maintainers and the case lead straight away.
2. **Not yet pushed:** remove the content and rewrite the local commits (`git reset` or
   `git commit --amend`, or an interactive rebase run by a maintainer). Re-run `scripts/pii_scan.py`
   with the denylist.
3. **Pushed:**
   * **Rotate first.** Revoke and reissue any credential that was exposed (API keys, tokens,
     passwords). Assume it is compromised whatever the purge achieves.
   * **Purge the history** with `git filter-repo`: use `--invert-paths --path <file>` for whole files,
     or `--replace-text <expressions-file>` for strings, with the expressions file kept outside the repo.
     Then force-push every branch and tag. Ask GitHub Support to remove cached views and pull-request
     refs, check for forks, and have every collaborator re-clone.
   * **Verify** with `gitleaks detect --log-opts=--all` and `scripts/pii_scan.py` on a fresh clone.
4. **Notify.** The data controller (the organisation running the case) assesses whether the exposure is a personal-data breach (GDPR Art. 33: 72 hours
   to the supervisory authority where it applies; Swiss FADP: notify the FDPIC as soon as possible
   when there is a high risk). Inform affected parties and the source of any marked report as required.
5. **Record** the incident (what, when, who had access, actions taken) in the case vault, not in the
   repo. Add the leaked strings to the denylist.
