# Provider playbooks — who acts on what, through which channel, on whose request

A **playbook** says, for one catalogue organisation (an exchange, an issuer, a swap service, a host, an LE agency),
what a request has to look like for that organisation to act on it: who may use which channel, which paths a request
can take (a victim report, an LE request, a court order, a cross-border request …), the instrument and evidence each
path needs, its clocks, the reply phrases that mean something and the sources of every claim. Aegis uses it to

* keep **LE-only channels** away from our letters (the LE-only gate: the next action becomes a brief to the case
  officer with the pack);
* gate **binding instruments** (a path that needs a court order is closed to us until LE / counsel supplies one);
* read replies (`reply_signals`, ticket formats, the vendor portals they name: app.blocks.extract);
* derive where a request stands (app.blocks.path), its clocks and the next step;
* rank the moves of the **Recovery plan** (docs/recovery-plan.md).

Files: `data/catalogue/providers/<org_key>.json`, one per organisation of `data/catalogue/channels.json` (I0, in git:
generic public facts only, never case data). Parser and rules: `app/domain/playbook.py` (`parse`); merged into the
catalogue by `app/domain/directory.py` (`load_catalogue`, `_merge_playbooks`), cached by the files' mtimes. **A file
that breaks a rule makes the whole catalogue invalid**: it is never loaded half-valid, and the directory page and
the tests report it.

## 1. Schema (version 1)

Unknown keys are refused at every level; a `"_comment"` string is allowed at the top level only.

| Key | What |
|---|---|
| `key` | the org key; the file name is `<key>.json` and `<key>` must be an org in channels.json |
| `version` | `1` |
| `side` | `provider` or `le` |
| `jurisdiction` | ISO-3166 alpha-2, `EU` or `null` |
| `issuer_jurisdictions` | whose authorities / courts it acts on directly (`[]` = not stated). Circle: `["US", "FR"]` |
| `ground_truth` | `reply` (default) or `onchain` (only the issuer's own event makes "frozen" true: app.freeze) |
| `notes` | free text, no addresses |
| `entities` | `[{key, name, jurisdiction, separate, notes, source_ids}]` (e.g. Binance.US separate from Binance) |
| `domains` | `{own: ["example.com"], sibling: [{domain, entity, purpose, <prov>}], vendor_portals: [{host, path_prefix, tenant, le_only, <prov>}]}` |
| `channels` | channels the playbook **declares** (new keys `<org>.<name>`), appended to the org and checked like channels.json: `{key, kind, value, purpose, role_default, label, notes, source_url, who, <prov>}` |
| `channels_ext` | what it says about an existing channels.json channel: `{"<key>": {who, purpose, notes, <prov>}}` |
| `paths` | see below |
| `reply_signals` | `[{phrase (≤ 200), means (ReplyStatus), instrument, channel_key, path, <prov>}]` |
| `tickets` | `[{system, regex (≤ 200, compilable; null until a real reply shows the format), <prov>}]` |
| `issues` | side `le` only: `[{instrument, jurisdiction, by, to: [org keys], notes, <prov>}]` — what an agency can issue to whom |
| `le_role` | side `le` only: `police` (Carabinieri, USSS), `judicial` (the Procura / PM: sequestro, Reg. 2018/1805 certificate, MLAT), `intake` (IC3: a complaint portal that files nothing with a provider, so never the brief's recipient: the next action is "get a case agent assigned, or instruct counsel") or `coordination` (Europol EC3). A binding or cross-border instrument is briefed to a `judicial` authority first |
| `sources` | `[{id, title, url "https://…", retrieved_at}]`, or an observed source `{id, title, observed: true, retrieved_at "YYYY-MM"}` (our own received reply: no URL, no day-level date and no address in its title) |

**Provenance** (`<prov>`, required on every claim): `source_ids` (≥ 1 id of `sources`), `basis` — `D` documented on
the provider's own page, `R` reported by a secondary source, `I` inferred, `O` observed in a reply to us — `confidence`
`H` / `M` / `L`, `retrieved_at` `YYYY-MM-DD` (`YYYY-MM` only for basis `O`: an observed fact never carries a day that
could tie it to a case).

**`who`** (channels): `any`; `victim_or_rep`; `le_only` (law enforcement / courts only — never offered to us);
`counsel_with_order` (anyone may write, but it acts only on LE process or a court order: offered with "expect a
redirect"). Every channel whose effective purpose is `le_request` must have a `who`.

**Paths**: `{key, kind, requester: [victim|pi|counsel|le|court|regulator], entity, channel_keys, instrument: {type,
issuer_jurisdictions, signing any|not_digital, language, notes}, evidence: [EVIDENCE keys], produces, timing:
{response_days, ack_hours, hold_days, auto_lift_days, preservation_days, portal_onboarding_days, deadlines: [{key, what,
exactly one of hours|days|working_days|months, starts, by, action, <prov>}]}, expected_replies, outcomes, on_refusal,
conflict, notes, <prov>}`.

* `kind`: `private_notice` (an unsolicited notice to a channel not published for victims: preservation and a risk
  flag) · `victim_report` (the provider's own published victim intake; may lead to a discretionary hold) ·
  `complaint` · `le_request` · `data_disclosure` · `court_order` · `cross_border` · `release` · `takedown`.
* `instrument.type`: `none`, `police_report`, `le_request`, `subpoena`, `court_order`, `us_or_fr_court_order`,
  `freezing_order`, `seizure_warrant`, `formal_directive`, `mlat`, `eu_freezing_order`, `eio`, `judicial_decision`.
  Binding: all but `none` and `police_report`.
* `deadline.what`: `submit_by`, `file_by`, `reply_by`, `hold_until`, `auto_lift`, `recognise_by`, `execute_by`,
  `validate_by`, `decide_by`; `deadline.starts`: `sent`, `provider_ack`, `provider_freeze_confirmed`, `hold_confirmed`,
  `order_served`, `fact_known`, `seizure`, `validation_requested`, `certificate_received`, `recognition`.
  Examples: MEXC `{what: submit_by, hours: 48, starts: provider_freeze_confirmed, by: victim}`; KuCoin `{what:
  auto_lift, days: 30, starts: hold_confirmed}`.
* EVIDENCE keys (what a path needs; how the Recovery plan finds each on file: app.domain.evidence_requirements):
  `incident_narrative, ownership_proof, victim_id, tx_list_copyable, trace_report_run, balance_reading, freeze_check,
  receiving_account, provider_ids, police_report, complaint_ref, ic3_ref, loa, poa, special_proxy, le_agency_identity,
  le_letterhead_request, court_order, seizure_warrant, mlat_bundle, english_version, freeze_duration_stmt,
  non_disclosure_stmt, prior_ticket_ref, native_vs_bridged_stmt, comms_export, wire_details, urgency_stmt,
  domestic_order`.
* ReplyStatus values (`expected_replies`, `outcomes`, `means`): `auto_reply, acknowledged, info_requested,
  le_process_required, hold_placed, frozen, funds_returned, declined_no_assets, declined_other, redirected, unclear`.

**Rules beyond the shapes**: a path's channels exist (channels.json for this org, or declared here); a path open to a
private requester never lists an `le_only` channel; `private_notice` / `victim_report` paths take no binding instrument
and private requesters only; `le_request` paths list `le` and no private requester; `null` means "to be confirmed" and
placeholders ("TBC", "unknown") are refused; `verified` / `verified_by` never appear (verification of a channel lives in
`entity_channels`, set by a person); an e-mail value must be on `domains.own` / `sibling`, with an https `source_url` on
the same domain and a local part in `directory.EMAIL_LOCAL_PARTS` (and the address tests in tests/test_directory.py /
tests/test_playbook.py list every catalogued address: adding one is a reviewed change to both).

## 2. Adding a provider

1. Make sure the organisation exists in `data/catalogue/channels.json` (an org entry with at least its website
   channel). Insert it without reformatting the file.
2. Copy `circle.json` or `tether.json` to `providers/<key>.json` and fill it **from the provider's own pages first**
   (basis `D`), secondary reports second (`R`, at most `M`), inference last (`I`, `L`). Every claim cites a source and
   the day you read it. A page that would not load is not a source: downgrade the claim and say so in `notes`.
3. Declare the LE-only channels (Kodex, LEORS, T3 FCU …) with `who: le_only` and, where a vendor hosts them, a
   `vendor_portals` entry with `le_only: true` and the tenant's `path_prefix`.
4. Give at least one path a private requester if the provider takes victim reports; otherwise the playbook is
   LE-only for us and every letter becomes a brief to the case officer (that is correct for e.g. Europol or T3 FCU).
5. Record the clocks with what starts them; never a clock on a guessed start.
6. Run `pytest tests/test_playbook.py tests/test_directory.py` (the validator, the catalogue merge, the address
   allowlist), then the block-path tests.

## 3. Verifying and keeping it current

* `Playbook.stale(days=180)` lists the claims last retrieved more than six months ago; re-read those pages and update
  `retrieved_at` (and the claim, when the page changed: provider pages drift without dates).
* An **observed** fact (a provider's own auto-reply naming a channel) is recorded with basis `O`, a month-only date and
  a source titled without a day or an address. It outranks research notes.
* A reply that names a channel, instrument or ticket format the playbook does not know shows as a disagreement on the
  Block status row ("AI reads …", a `third_party` / `unknown` channel a person must pick). Promote it by editing the
  file in a reviewed change; Aegis never edits a playbook by itself.
* A channel a person confirmed for one case lives in `entity_channels` (verified), not in the playbook.
