# Fixture schema

_Contains no case data._

A fixture is one JSON file describing one case: what is known on-chain, plus (optionally) the
case workspace — team, letters already sent, correspondence, LE contacts, evidence metadata and
notification rules. The fictional demo case `data/fixtures/demo_case.json` is the reference example.
Real fixtures live outside the repository (docs/data-handling.md §3) and are loaded by path:

```bash
python -m scripts.seed_case --fixture /path/outside/repo/<CASE-REF>/case.json
```

The same file backs the offline chain provider (`PROVIDER_MODE=fixture`). Seeding
(`app.services.seed_from_fixture`) is **idempotent**: re-running it updates rows in place and never
duplicates them. Every section below `transfers` is optional, and **unknown top-level sections are
ignored**, so a fixture can carry data for a feature that is not built yet. Timestamps are ISO 8601;
a missing offset means UTC.

## Core sections

| Section | Shape | Notes |
|---|---|---|
| `case` | object | `reference`, `title`, `status`, `victim_name`, `victim_entity`, `victim_jurisdiction`, `fraud_type`, `fraud_date`, `loss_amount`, `loss_asset`, `loss_usd`, `summary`, `facts` (letters), optional `ai_mode` (`off`/`redacted`/`full`, default `redacted`) and `status_summary` |
| `seeds` | list | `{role, chain, value, note}`; role is `origin_tx`, `victim_wallet`, `perpetrator_wallet` or `known_downstream` |
| `entities` | list | `{name, category, jurisdiction, website, compliance_email, le_portal_url, le_contact_notes, freeze_capable, sweep_window_hours, notes}`. Categories: `exchange`, `casino`, `swap_service`, `bridge`, `dex`, `mixer`, `otc`, `hosting`, `infra`, `stablecoin_issuer`, `law_enforcement`, `pi_firm`, `legal_counsel`, `regulator`, `unknown` |
| `addresses` | list | `{chain, address, address_type, label, label_source, entity, is_contract}` |
| `transfers` | list | `{chain, tx_hash, sub_index, timestamp, from, to, asset, amount (null = unknown), token_contract, block_number, source, confidence, method, notes, bridged_to: {chain, tx_hash}}` |

## Workspace sections

Loaded by `app/fixture_sections.py` in this order: `team`, `le_contacts`, `evidence`,
`sender_profile`, `stop_orders_imported`, `correspondence`, `notification_rules`. Each loader belongs to the feature
that owns its tables.

### `team`

```json
"team": [
  {"email": "case.admin@aegis.example", "display_name": "Demo Case Admin", "role": "admin",
   "password_env": "AEGIS_DEMO_ADMIN_PASSWORD", "system_admin": false, "can_create_cases": false,
   "expires_at": null}
]
```

* `role`: `admin` | `investigator` | `read_only` | `external` (lowest to highest: external < read_only < investigator < admin).
* Passwords are **never** written in a fixture. A new user gets the value of the environment
  variable named by `password_env`; when that is unset, a random password is generated and printed
  once by `scripts/seed_case.py`. For an existing user, a set `password_env` variable replaces the
  password; otherwise the password is left alone.
* `expires_at` (absolute) or `expires_in_days` (relative to the seed run, preferred for demo data)
  time-boxes the membership. External members always expire: 30 days after the seed by default, and
  never more than 90 days ahead (a later date is clamped to 90 days, with a warning in the seed log
  and the seed report).
* `can_create_cases` (default false) lets a new account open cases; system admins always may.
* Upserted by e-mail (lower-cased); the membership is upserted by (case, user).

### `stop_orders_imported`

Letters that were sent outside Aegis. Each becomes a `stop_orders` row with `origin = "imported"`
and, unless `log_correspondence` is false, an outbound `correspondence` row (`kind: stop_order`,
`status: sent`) linked to it. Generated drafts never supersede imported letters.

```json
"stop_orders_imported": [
  {"key": "kucoin-preservation-1", "entity": "KuCoin", "entity_category": "exchange",
   "kind": "preservation", "status": "sent", "template_key": null,
   "subject": "…", "body_markdown": "…", "recipient_email": "compliance@…", "recipient_cc": [],
   "sender": "…", "sent_at": "2026-10-15T09:00:00Z", "sent_via": "email",
   "external_ref": "ticket no.", "response_due_at": "2026-10-18T09:00:00Z", "responded_at": null,
   "identifiers": {"addresses": ["0x…"], "tx_hashes": ["0x…"]}, "notes": null,
   "classification": "R3", "log_correspondence": true}
]
```

* `key` (recommended) is a fixture-local id: the idempotency key (stored as
  `identifiers.fixture_key`) and what `correspondence[].stop_order_key` refers to. Without a key,
  rows match on (subject, sent_at).
* `kind`: free text, conventionally `preservation`, `freeze`, `issuer_blacklist`, `le_referral`,
  `status_request`, `info_request`, `release_request`.
* `status`: `draft` | `sent` | `acknowledged` | `frozen` | `declined` | `superseded` | `released` (default `sent`).
* `identifiers` may also carry `recipient` (a label shown when `recipient_email` is null, e.g.
  "Compliance / Legal Team (no e-mail on file; use the entity's law-enforcement request portal)"), `order_ids` (swap-service
  order references) and `amounts`. `notes` starting with `KNOWN DEFECT:` or containing `FOLLOW-UP:`
  are highlighted on the authority page.
* Kept by the authorities desk (not written by fixtures): `identifiers.hold` =
  `{state, amount, asset, at, frozen_amount}`, `identifiers.status_history` =
  `[{status, previous, at, by, amount, asset}]`, `identifiers.overdue_notified_for`.
* `body` is accepted as an alias of `body_markdown`. `entity` is created (category from
  `entity_category`, default `unknown`) when it is not in `entities`.
* `created_at` (optional): when the letter was written; default `sent_at`, so an imported letter is never shown as
  created after it was sent (the seed time).

### `correspondence`

```json
"correspondence": [
  {"key": "kc-ack", "entity": "KuCoin", "direction": "in", "channel": "email", "kind": "reply",
   "status": "received", "subject": "…", "body_markdown": "…", "sender": "…",
   "recipients": ["…"], "cc": [], "occurred_at": "…", "due_at": null,
   "stop_order_key": "kucoin-preservation-1", "in_reply_to_key": null, "thread_key": null,
   "external_ref": "…", "shared_with_external": false, "classification": "R2", "meta": {}}
]
```

* `direction`: `in` | `out` | `note`. `channel`: `email` | `portal` | `letter` | `phone` | `meeting` | `other`.
* `kind`: `stop_order` | `status_request` | `info_request` | `le_cover` | `release_request` | `reply` | `other`.
* `status`: `draft` | `sent` | `received` | `logged` (default `received` for `in`, else `logged`).
* `classification`: `R3` | `R2` | `C1` | `I0` (default `R2`).
* Idempotency: `key` (stored as `meta.fixture_key`), else (direction, subject, occurred_at).
* `meta` conventions: `synthetic` / `demo` mark invented items. The desk adds `format`
  (`text`|`markdown`), `source` (`logged`|`generated`|`stop_order_status`|`status`), `template_key`,
  `references`, `stop_order_id`, `trace_run_id`, `evidence_ids`, `superseded_by`,
  `overdue_notified_for`, `edited`, `amount_held`, `asset`. Generated letters are R3 drafts; the
  templates live in `app/reports/templates/letters/*.md.j2`.

### `le_contacts`

```json
"le_contacts": [
  {"agency": "…", "unit": "…", "role": "complaint desk", "name": null, "email": null, "phone": null,
   "reference": "DEMO-IT-0000000000", "jurisdiction": "Italy", "notes": "…",
   "classification": "R3", "entity": null}
]
```

Matched on (agency, reference, name). Named officers and real references belong only in a real
fixture outside the repository.

### `evidence`

Metadata only. Originals are **never copied**.

```json
"evidence": [
  {"folder": "law_enforcement", "title": "…", "description": "…", "source_type": "police_report",
   "storage": "reference", "source_path": "/absolute/path/to/original.pdf",
   "sha256": null, "size_bytes": null, "mime": "application/pdf", "doc_date": "…",
   "received_from": "…", "classification": "R3", "tlp": "TLP:AMBER", "tags": [],
   "shared_with_external": false, "meta": {}},
  {"folder": "chain_reports", "title": "…", "storage": "inline", "inline_text": "…", "classification": "C1"}
]
```

* `folder`: `law_enforcement` | `digital_artifacts` | `investigator_reports` |
  `stop_orders_correspondence` | `legal` | `financial` | `chain_reports` | `other`.
* `storage`: `reference` (an absolute `source_path`; when the file exists and `sha256` is missing,
  the seeder hashes it read-only and sets `verified_at`), `vault` (`vault_path` of an encrypted
  copy), `inline` (`inline_text`; hashed automatically).
* A reference `source_path` may name a zip member (`/abs/archive.zip!member`) or an `.rtfd`
  bundle (hashed as its `TXT.rtf`).
* `meta.section` places an item in a sub-section of its folder (`contacts`, `reports`, `messaging`,
  `recordings`, `screenshots`, `emails`). `meta.demo_file` (repo-relative, honoured only under
  `data/fixtures/demo_evidence/`) points a synthetic demo item at its file; the demo fixture
  stores those items `inline` so they carry their hash from the start.
* `classification` defaults to `R3`. `tlp` records a third-party marking (docs/data-handling.md §7).
* Matched on (folder, title).

### `sender_profile`

The case's sender of record (app/domain/sender.py): new letters read "We write as <org_name>, on
behalf of <on_behalf_of>" and close with this signature; e-mails sent from Aegis attach the authority
documents by default. One object (not a list); upserted per case. The demo fixture uses the default
every new case gets (app.domain.sender.defaults): the case mailbox as contact and the client's contact
e-mail as the default Cc. For example:

```json
"sender_profile": {
  "on_behalf_of": "Northbridge Analytics, Inc. (Jordan Avery)",
  "org_name": "Your Organisation",
  "signatory_name": "Investigations Desk", "signatory_title": null,
  "contact_email": null, "phone": null, "postal_address": null,
  "instrument": "Letter of Authorisation", "signature_block": null, "cc_default": ["victim@northbridge.example"],
  "authority_evidence_titles": ["Letter of authorisation — Northbridge Analytics, Inc. to Your Organisation (synthetic)"]
}
```

* `on_behalf_of` is required; `org_name` defaults to the deployment's organisation (`AEGIS_ORG_NAME`,
  default "Your Organisation"), `signatory_name` to `AEGIS_SIGNATORY_NAME` and `instrument`
  to "Letter of Authorisation". An instrument called a Power of Attorney is refused here (set it on
  the sender-profile page, where it must be confirmed as literally the instrument on file).
* `authority_evidence_titles` name items of this case's `evidence` section (loaded first); titles that
  are not found are skipped with a note in the seed report (counted, never named).
* `contact_email` null (or absent) means the case mailbox: letters name `AEGIS_MAIL_FROM` (read when
  the letter is rendered), the address the e-mail is sent from and replies come back to.
* `signature_block` (free text, one line each) replaces the composed signature lines.
* Without the section the case keeps the PI-firm block of `case.facts["investigator"]`. Imported
  letters are never re-rendered.

### `notification_rules`

```json
"notification_rules": [
  {"event_type": "vasp_deposit", "enabled": true, "min_usd": 1000, "min_pct_of_loss": null,
   "channels": ["in_app", "email"], "recipient_roles": ["admin", "investigator"], "overdue_days": null}
]
```

`event_type` must be one of `app.core.events.EVENT_TYPES`: `wallet_movement`, `vasp_deposit`,
`sweep_imminent`, `stop_order_status`, `correspondence_in`, `correspondence_out`,
`response_overdue`, `evidence_added`, `trace_completed`, `ai_summary`, `evidence_integrity`, `mail_prepared`.
Upserted per (case, event_type). After the sections are loaded, the seeder (and `create_case`)
writes the built-in defaults (`app.domain.notify.DEFAULT_RULES`) for every event type the case has
no row for, so the rule editor and delivery always agree.

## Masking reminder

A fixture committed to this repository is synthetic or follows docs/data-handling.md §4: fictional people
and references, reserved `.example` domains, no named contacts at services, and no passwords anywhere.
