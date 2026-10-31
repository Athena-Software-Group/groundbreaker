# Identity spec — passkeys, case teams, audit

_Status: **partly built**. Phase 2 foundation (19 Oct 2026): per-user
accounts with scrypt passwords and server-side sessions (`app/core/security.py`), `case_members`
with the roles external < read_only < investigator < admin and one policy dependency
`require_case_role` (`app/core/permissions.py`), and a hash-chained, append-only `audit_events`
log (`app/core/audit.py`). The `webauthn_credentials` and `user_sessions.stepped_up_at` columns
exist; passkeys, step-up and four-eyes approval are still **specification only** (Phase 6)._

> **As built vs. this spec.** The four built roles map onto §7 as: `admin` ≈ case owner,
> `investigator` ≈ lead investigator / investigator, `read_only` ≈ analyst, `external` ≈ external
> LE / victim liaison (sees only items flagged `shared_with_external`). System administrators
> (`users.is_system_admin`) currently see every case as case admin; break-glass with a second
> approver is still to be built. Opening a case (and so becoming its admin) needs a system admin
> or `users.can_create_cases`; case admins add existing accounts only, and only system admins
> create accounts. External memberships default to 30 days and are capped at 90 (extensions are
> audited). The cookie is `aegis_session` (SameSite=Strict, HttpOnly,
> Secure outside APP_ENV=local), not yet `__Host-aegis`. Audit rows are append-only in the ORM;
> the Postgres INSERT-only role and the UPDATE/DELETE trigger are still to do.

## 1. Goals

* Every action, and every read of R2/R3 data, is attributable to one person.
* Phishing-resistant login with no passwords to steal.
* **No biometric data ever leaves the user's device.** Face ID, Touch ID or Windows Hello unlocks a
  private key locally. The server sees only a signed assertion and the "user verified" flag. The
  privacy notice states that Aegis processes no biometric templates, which keeps biometric-processing
  rules (GDPR Art. 9, BIPA and similar) out of scope.

## 2. WebAuthn configuration

| Setting | Value |
|---|---|
| Library | `py_webauthn` (server). Alternatively an IdP with passkey support (Cognito, Okta, Entra) behind the ALB. |
| RP ID | The production apex domain. Origins are checked strictly against an allow-list. |
| `userVerification` | **`required`** for registration and every assertion. Reject any response without the UV flag. |
| `residentKey` | `required` (discoverable credentials, so login needs no username) |
| `pubKeyCredParams` | ES256 (-7), then RS256 (-257) |
| Challenge | 32 random bytes, stored server-side, single use, expires after 5 minutes |
| `excludeCredentials` | The user's existing credentials, so the same authenticator cannot be enrolled twice |
| Attestation | `none` for external and victim-liaison users. `direct` for staff, with an AAGUID allow-list (platform authenticators, FIDO2 hardware keys). |
| Synced passkeys | Allowed for analysts. Privileged roles (case owner, lead investigator, org admin) must also enrol one **device-bound hardware key**, because synced passkeys carry no attestation. |
| Assurance | AAL2 baseline; AAL3 (hardware key) for org admins |

## 3. Stored credential (`webauthn_credentials`)

| Field | Notes |
|---|---|
| `id` | UUID |
| `user_id` | FK users |
| `credential_id` | bytes, unique |
| `public_key` | COSE key. This is the only key material stored. |
| `sign_count` | Reject regressions on device-bound keys and raise a security alert. Synced passkeys may report 0. |
| `aaguid` | Authenticator model, checked against the allow-list for staff |
| `transports` | e.g. `internal`, `hybrid`, `usb`, `nfc` |
| `backup_eligible`, `backup_state` | BE/BS flags; shows whether the passkey is synced |
| `attestation_fmt` | `none`, `packed`, … |
| `user_verified_last` | UV flag of the last assertion |
| `nickname` | Set by the user (e.g. "MacBook Touch ID") |
| `created_at`, `last_used_at`, `revoked_at` | |

No biometric samples, templates or device identifiers beyond the AAGUID are stored.

## 4. Enrolment, credentials, sessions

* **Enrolment:** a single-use invite link (24 h, bound to e-mail and organisation) leads straight to passkey
  registration. No password is ever set.
* **At least 2 credentials per user**, for example a laptop platform passkey plus a phone or hardware key.
  The UI nags until the second one is enrolled. Privileged roles cannot act on a case until it is.
* **Sessions:** server-side. Cookie `__Host-aegis`, `Secure`, `HttpOnly`, `SameSite=Strict`. 30 min idle,
  12 h absolute. The session id rotates on login and on step-up. CSRF token on every state-changing form.

## 5. Step-up

A fresh UV assertion, within the **last 5 minutes**, is required for:

* revealing (unmasking) R2/R3 fields, or viewing R3 evidence;
* downloading or exporting evidence, letters, evidence packs or case data;
* approving or **sending** a letter, freeze request or exchange ticket;
* adding or removing case members, changing roles, inviting an external user;
* enabling live-provider egress on a real case;
* break-glass access and viewing the audit log.

The step-up time is recorded on the session, and each gated action records `stepped_up=true` and its
age in the audit event.

## 6. Recovery and lost devices

* First line: sign in with the second registered credential, then revoke the lost one.
* No second credential: an org admin re-proofs the user's identity, a **second admin approves**,
  every existing session and credential is revoked, and the user enrols afresh. The user is notified
  and the event is audited. No SMS or e-mail-only recovery.
* Lost device: self-service revoke from any other session, admin revoke, and a "sign out everywhere" kill switch.

## 7. Case teams and roles (summary)

Default deny. Access is per case through `case_members` (a user or a team, a role, an optional expiry).
No role, including org admin, implicitly sees every case. One policy dependency,
`require_case_perm(case_id, perm)`, guards every route. Non-members get 404. Postgres row-level
security is the backstop.

| Role | Can | Data ceiling |
|---|---|---|
| Case owner | Manage members, close the case, set legal hold, approve external disclosure | R3 (with step-up) |
| Lead investigator | Everything except membership and closing; approves outbound letters and tickets | R3 (with step-up) |
| Investigator | Run traces, add evidence, draft letters and tickets; unmask per field with a reason | R2 masked by default |
| Analyst | Read traces, graphs and alerts; no evidence download | C1 |
| Legal counsel | Read evidence and letters, approve letter wording | R3 (with step-up) |
| External LE | Time-boxed (default 30 days); only the evidence packages shared with them | As granted |
| Victim liaison | Status, ticket progress, own submissions | Own data only |
| Auditor | Audit and custody logs only, never content | I0 / IDs |
| Org admin | User lifecycle, team membership, credential revocation; no case content without break-glass | — |

* **Four-eyes:** sending anything that contains R2/R3 data needs a drafter plus an approver (lead
  investigator or counsel), each with step-up.
* **Break-glass:** an org admin gives a written reason, a second admin approves, access lasts 4 hours,
  and the case owner and auditors are alerted.
* External memberships auto-expire. All grants are reviewed monthly.

## 8. Audit events

An append-only, hash-chained `audit_log` (`prev_hash`, `row_hash`). The DB role has INSERT only, and a
trigger rejects UPDATE and DELETE. The chain is verified nightly and shipped to WORM storage. Events
store IDs and field names, **never values**.

Fields: `ts`, `request_id`, `actor_user_id`, `org_id`, `session_id`, `auth_method` (passkey | oidc),
`credential_id_hash`, `aaguid`, `user_verified`, `stepped_up`, `step_up_age_s`, `ip`, `user_agent`,
`case_id`, `object_type`, `object_id`, `action`, `classification`, `outcome` (allowed | denied), `reason`.

Actions: `LOGIN`, `LOGIN_FAILED`, `LOGOUT`, `STEP_UP`, `CREDENTIAL_REGISTERED`, `CREDENTIAL_REVOKED`,
`RECOVERY_STARTED`, `RECOVERY_APPROVED`, `SESSION_REVOKED`, `READ`, `READ_SENSITIVE` (field names),
`UNMASK`, `CREATE`, `UPDATE`, `DELETE`, `EXPORT`, `DOWNLOAD`, `SHARE`, `LETTER_APPROVED`,
`LETTER_SENT`, `TICKET_UPDATE`, `RUN_TRACE`, `LIVE_PROVIDER_QUERY`, `ROLE_GRANT`, `ROLE_REVOKE`,
`BREAK_GLASS`.

Repeated `LOGIN_FAILED` or denied attempts raise an alert after N attempts. Case owners and auditors
get a per-case "who accessed what" view.

## 9. AWS / IdP variant

With Cognito or another OIDC IdP at the ALB, the app must verify the signature and claims of the
`x-amzn-oidc-data` JWT (issuer, `exp`, signer ARN). It then maps the subject to a `users` row and records
`amr` as `auth_method`. Step-up uses a fresh IdP authentication (`max_age`) or an in-app WebAuthn
assertion. External LE can federate from their agency IdP under the same step-up rules.
