# Microsoft 365 setup for the e-mail desk

> **Connecting the investigations mailbox.** Aegis reads the shared mailbox's
> Inbox and Sent Items (the status of every block requested across the authorities: docs/guide.md "Mailbox sync
> and Block status", docs/block-status.md) and sends from it, app-only (client credentials), with
> Mail.ReadWrite + Mail.Send limited to that one mailbox by an Application Access Policy (steps 2–7), history
> read from the date you choose (`AEGIS_MAIL_INBOUND_SINCE`). "Draft — you send"
> (`AEGIS_MAIL_TRANSPORT=manual`, the default) stays available and needs none of this.

## Giving Aegis access: the short version

**The mailbox's own password is not used** and should not be given to Aegis: the shared mailbox stays
sign-in blocked (step 1). Aegis signs in as an **app** of your tenant, and only that app's credentials go into
Aegis. A Microsoft 365 / Entra administrator of the tenant that holds the investigations mailbox:

1. registers the app **Aegis case desk** (step 2) and notes its tenant id and client id;
2. creates a client secret (step 3);
3. grants **Mail.ReadWrite** and **Mail.Send** (application permissions) with admin consent (step 4);
4. limits the app to the investigations mailbox with an Application Access Policy and tests it both ways
   (step 5) — before anything else talks to the tenant;
5. puts the values into a file outside the repository, e.g. `~/.config/aegis/aegis.env` (step 6; never into the repository), and restarts
   the server and the scheduler;
6. checks `/admin/mail` (token and mailbox tests) and runs **Backfill since <date>** (e.g. 2026-01-01) on
   `/admin/mail/mailbox` (step 7), then reviews **Mail to review** and each case's **Block status** page.

Aegis sends letters (preservation and risk-control requests, follow-ups, LE cover letters) from
**one shared case mailbox** in your Microsoft 365 tenant, and reads replies from the same mailbox.
It talks to Microsoft Graph with an Entra app registration (client credentials). The app is limited
to that one mailbox: it cannot read or send as anyone else.

Every example below uses `example.com` and the all-zero GUID `00000000-0000-0000-0000-000000000000`.
Replace them with your own values. Never commit real values: keep them in a file outside the
repository, e.g. `~/.config/aegis/aegis.env` (mode 600), or, on AWS, in Secrets Manager.

What Aegis does with the mailbox (app/mail/graph.py):

| Step | Graph call | Permission |
|---|---|---|
| Send a letter | `POST /users/{mailbox}/messages` (the exact MIME bytes, base64, as a draft) then `POST …/messages/{id}/send` | Mail.ReadWrite, Mail.Send |
| Confirm a send after a timeout | `GET /users/{mailbox}/messages/{id}` (is it still a draft?) | Mail.ReadWrite |
| Delete an unsent draft (failed or stale send) | `GET /users/{mailbox}/messages?$filter=internetMessageId eq …`, then `POST …/messages/{id}/permanentDelete` (a plain DELETE only moves it to Deleted Items, still a draft) | Mail.ReadWrite |
| Mailbox sync: Inbox and Sent Items | `GET /users/{mailbox}/mailFolders/{inbox,sentitems}/messages/delta` (first request: `$filter=receivedDateTime ge <since>`; then the stored delta link), metadata only; for a message that may be case-related `GET …/messages/{id}/$value` (raw MIME); otherwise only `GET …/messages/{id}?$select=internetMessageHeaders` (thread headers) and, for Sent Items, `?$select=body` (text, in memory) | Mail.ReadWrite |
| Admin diagnostics | token request; `GET /users/{mailbox}/mailFolders/inbox` | — |

Sent letters land in the mailbox's Sent Items, exactly as if a person had sent them. One request
can carry at most 4 MB, so Aegis refuses an e-mail over 2.9 MB of MIME
(`AEGIS_MAIL_MAX_MESSAGE_BYTES`); submit larger files through the recipient's portal.

## 1. Create the shared mailbox

Exchange admin center → **Recipients → Mailboxes → Add a shared mailbox**, for example
`case-desk@example.com`, display name "Your Organisation — Case Desk".

* A shared mailbox needs no licence (up to 50 GB).
* Its user account must stay **sign-in blocked** (Microsoft 365 admin center → Users → the mailbox
  account → Block sign-in). Nobody signs in to it; people who need to read it get delegated access.
* Give delegated access (Full Access) only to the people who work cases. The mailbox holds R3 case
  material once letters go out (docs/data-handling.md §6.3).

## 2. Register the app in Microsoft Entra ID

Entra admin center → **App registrations → New registration**:

* Name: `Aegis case desk`
* Supported account types: **Accounts in this organizational directory only** (single tenant)
* Redirect URI: none

Note the **Application (client) ID** and the **Directory (tenant) ID** from the overview page.

## 3. Create a client secret

App registration → **Certificates & secrets → Client secrets → New client secret**. Choose an
expiry (at most 24 months), and put a reminder to rotate it in the calendar well before that date.
Copy the secret **value** once (it is shown only once) into your env file outside the repository
(e.g. `~/.config/aegis/aegis.env`).

A certificate is the better credential and is the recommended next step. Aegis v1 does not support
it yet: it needs the `cryptography` package, which is not a dependency yet. While
`AEGIS_M365_CLIENT_CERT_PATH` is set, Aegis reports the transport as not configured.

## 4. Grant the Graph permissions

App registration → **API permissions → Add a permission → Microsoft Graph → Application
permissions**: add **Mail.Send** and **Mail.ReadWrite**. Then click **Grant admin consent for
<tenant>**. Both must show "Granted".

On their own these permissions reach **every** mailbox in the tenant. Step 5 restricts them to the
case mailbox. Do not run Aegis against the tenant before step 5 is in place and tested.

## 5. Restrict the app to the case mailbox (Exchange Online PowerShell)

```powershell
Connect-ExchangeOnline -UserPrincipalName admin@example.com

# A mail-enabled security group whose only member is the case mailbox
New-DistributionGroup -Name "Aegis mailbox scope" -Alias aegis-mailbox-scope -Type Security `
  -Members case-desk@example.com
Set-DistributionGroup -Identity aegis-mailbox-scope@example.com -HiddenFromAddressListsEnabled $true

# The policy: this app may only access members of that group
New-ApplicationAccessPolicy -AppId 00000000-0000-0000-0000-000000000000 `
  -PolicyScopeGroupId aegis-mailbox-scope@example.com -AccessRight RestrictAccess `
  -Description "Aegis: case mailbox only"

# Check both ways: the case mailbox is Granted, any other mailbox is Denied
Test-ApplicationAccessPolicy -Identity case-desk@example.com -AppId 00000000-0000-0000-0000-000000000000
Test-ApplicationAccessPolicy -Identity someone.else@example.com -AppId 00000000-0000-0000-0000-000000000000
```

Changes to the policy can take an hour or more to apply to Graph calls. Until then a call to the
case mailbox may still answer 403, or a call to another mailbox may still succeed; re-test before
you rely on it.

**The successor model: RBAC for Applications.** Microsoft is replacing application access policies
with role-based access control for applications in Exchange Online. The equivalent setup is:

```powershell
# The app's enterprise application (service principal) object id, from Entra ID → Enterprise applications
New-ServicePrincipal -AppId 00000000-0000-0000-0000-000000000000 `
  -ObjectId 00000000-0000-0000-0000-000000000000 -DisplayName "Aegis case desk"
New-ManagementScope -Name "Aegis case mailbox" `
  -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'case-desk@example.com'"
New-ManagementRoleAssignment -App 00000000-0000-0000-0000-000000000000 -Role "Application Mail.Send" `
  -CustomResourceScope "Aegis case mailbox"
New-ManagementRoleAssignment -App 00000000-0000-0000-0000-000000000000 -Role "Application Mail.ReadWrite" `
  -CustomResourceScope "Aegis case mailbox"
Test-ServicePrincipalAuthorization -Identity 00000000-0000-0000-0000-000000000000 -Resource case-desk@example.com
```

With RBAC for Applications the scoped Exchange role assignments grant the access, so the
tenant-wide Graph permissions from step 4 must be **removed** (Entra grants and Exchange RBAC add
up: leaving the Entra grant in place keeps access to every mailbox). Switch when your tenant
supports it and Microsoft announces the retirement date for application access policies; test with
`Test-ServicePrincipalAuthorization` before removing the old policy. Aegis itself needs no change.

## 6. Configure Aegis

For the Graph transport (the default stays `manual` when this is not set). In a file outside the repository, e.g. `~/.config/aegis/aegis.env` (mode 600), loaded only into the server's and the scheduler's
environment (`set -a; . ~/.config/aegis/aegis.env; set +a`):

```ini
AEGIS_MAIL_TRANSPORT=graph
AEGIS_MAIL_FROM=case-desk@example.com
# From display name (default: AEGIS_ORG_NAME, the organisation letters are written by)
AEGIS_MAIL_FROM_NAME=Your Organisation
AEGIS_M365_TENANT_ID=00000000-0000-0000-0000-000000000000
AEGIS_M365_CLIENT_ID=00000000-0000-0000-0000-000000000000
AEGIS_M365_CLIENT_SECRET=<the secret value from step 3>
AEGIS_MAIL_INBOUND=on
# the backfill start: Inbox and Sent Items are read from this time (default: the first sync)
AEGIS_MAIL_INBOUND_SINCE=2026-01-01T00:00:00Z
# how often the scheduler reads both folders (minutes, default 15)
AEGIS_MAIL_SYNC_MINUTES=15
```

**What the mailbox sync does** (app/mail/ingest.py, app/mail/sync_outbound.py): every
`AEGIS_MAIL_SYNC_MINUTES` the scheduler (`python -m scripts.run_scheduler`) reads the Inbox and Sent Items
with one delta link per folder (`mail_sync_folders`), from `AEGIS_MAIL_INBOUND_SINCE` on the first run. It
keeps only case-related mail (docs/data-handling.md §6.4). Replies are matched to letters as before (now also
to letters found in Sent Items). A letter someone sent from Outlook is found in Sent Items and recorded on its
letter: the letter and its stop order are marked sent at the message's sentDateTime (`sent_via` "email
(investigations mailbox)", reply clock started) and the sent message is filed as R3 evidence. A Sent Items
message Aegis cannot tie to exactly one letter is logged on the authority with a **needs review** flag; nothing
is marked sent from it. Sent Items are read before the Inbox, so a backfill records a letter before it reads the
replies to it. **Sync now** and **Backfill since <date>** are on `/admin/mail/mailbox` (system admins). Each filed
reply is read for the Block status report (rules; the AI only where a case admin switched on "AI reads mailbox
replies" for the case, data-handling §6.1).

`AEGIS_VAULT_DIR` must be set too: every sent e-mail is filed as an evidence item, and replies are
held in the vault until they are filed. With `APP_ENV=local` and the graph transport, recipients
are limited to `AEGIS_MAIL_DEV_ALLOWED_DOMAINS` (default: the reserved example domains), so a
development machine cannot send to a real counterparty by mistake. To go live on such a
machine, `AEGIS_MAIL_LIVE_SENDING=1` lifts that limit (the case mailbox then sends anywhere, as the mailbox
itself does; the admin page shows "live sending ON").

Aegis only talks to `https://login.microsoftonline.com` and `https://graph.microsoft.com`; any other
`AEGIS_M365_LOGIN_HOST` / `AEGIS_M365_GRAPH_BASE` makes the transport "not configured". For tests and local
walks only, `AEGIS_M365_TEST_GRAPH_BASE` / `AEGIS_M365_TEST_LOGIN_HOST` may point both at a mock on
`http(s)://127.0.0.1:<port>`; they are honoured only with `APP_ENV=local` and refused (transport not configured,
no fallback to the real hosts) anywhere else. Never set them on a deployment. On AWS,
add both hosts to the egress allow-list (docs/aws-deployment.md).

## 7. Verify from `/admin/mail`

Sign in as a system administrator and open **Mail** (`/admin/mail`):

1. **Token test**: a token is issued; the application roles listed must include `Mail.Send` and
   `Mail.ReadWrite`.
2. **Mailbox test**: the case mailbox's inbox answers (message and unread counts).
3. **Send test message** to your own address: subject "Aegis test message", no case data. Check it
   arrives, and that it shows in the shared mailbox's Sent Items.
4. Reply to the test message, then **Check mailbox now**: it answers no case letter and comes from no
   authority's domain, so Aegis only counts it (`not_related`): unrelated mail is never stored (data-handling §6.4).
5. **Mailbox sync** (`/admin/mail/mailbox`): both folders show a last sync and "Delta link stored"; the
   result counts what was read per folder. To read the history, use **Backfill since** <date> (e.g. 2026-01-01; it is
   safe to repeat: messages already stored are skipped).

6. **Hidden recipients (Bcc), once, before the first real letter.** Aegis sets Bcc through Graph's
   `bccRecipients` on the draft (never a `Bcc:` header in the MIME) and refuses the send when Graph does
   not echo exactly those addresses. This has only been exercised against a mocked Graph. Send one test
   letter from a test case with a Bcc to your own address and a To you control: the To copy must show no
   Bcc line, the Bcc copy must arrive, and Sent Items must list the Bcc. If Graph refuses the Bcc step, the
   send fails cleanly (the draft is deleted, nothing goes out) and the letter can be sent without a Bcc.
   Record the date and the result here.

## 8. SPF, DKIM and DMARC for the sending domain

Recipients' compliance desks filter hard. Before the first real letter:

* **SPF**: the domain's TXT record includes Microsoft 365, e.g.
  `v=spf1 include:spf.protection.outlook.com -all` (merge with any existing senders; one SPF record
  per domain).
* **DKIM**: Microsoft Defender portal → Email & collaboration → Policies & rules → Threat policies →
  Email authentication settings → DKIM → the domain. Publish the two CNAME records it shows
  (`selector1._domainkey` and `selector2._domainkey`), then enable signing.
* **DMARC**: start with monitoring, e.g. `_dmarc.example.com TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"`.
  Once the reports show only legitimate senders passing, move to `p=quarantine`, then `p=reject`.

**Inbound: how Aegis trusts a reply.** A reply found by the Message-ID of an e-mail Aegis sent (In-Reply-To /
References), by its subject tag `[Aegis <REF> #<letter id>]` or by its conversation is filed
automatically only when it comes from one of the authority's own domains (the letter's To, the
entity's compliance address, its LE contacts and directory channels; never the Cc, a free-mail or
shared provider such as gmail.com, or the case mailbox's own domain) **and** Exchange Online's
verdict passes: the topmost `Authentication-Results` header must report `dmarc=pass` or
`compauth=pass` for the From domain (a Message-ID reaches everyone the letter was sent or forwarded
to, so it proves no more than a tag). A delivery failure (bounce) is filed automatically only when
it is a delivery-status report by its structure (multipart/report, a message/delivery-status part,
or an Exchange NDR returning the original; a postmaster / mailer-daemon sender alone never makes a
message a bounce), comes from the case mailbox's own mail server (postmaster / mailer-daemon / the
Exchange system sender on the mailbox's domain), is authenticated (the topmost
`Authentication-Results` passes for that domain, or its `internetMessageHeaders` show Exchange
generated it inside this tenant: `X-MS-Exchange-CrossTenant-Id` = `AEGIS_M365_TENANT_ID` (give the
tenant as its GUID for this), `X-MS-Exchange-Organization-AuthAs: Internal`,
`X-MS-Exchange-Message-Is-Ndr`), and names the Message-ID of an e-mail Aegis sent.
Anything else waits for a case admin on **Mail to review**. Exchange Online stamps that header on
every message it receives; nothing has to be configured for it.

## 9. Troubleshooting

| What Aegis shows | Likely cause | Fix |
|---|---|---|
| `token request refused (401: invalid_client) AADSTS7000215` | Wrong or expired client secret | Create a new secret (step 3), update `AEGIS_M365_CLIENT_SECRET`, restart |
| `token request refused (400: unauthorized_client) AADSTS700016` | Wrong client id, or the app is in another tenant | Check `AEGIS_M365_CLIENT_ID` / `AEGIS_M365_TENANT_ID` |
| `Graph refused the access token (401) after a refresh` | Token for the wrong tenant / audience | Check the tenant id; the scope is always `https://graph.microsoft.com/.default` |
| `Graph refused the request (403): check Mail.Send / Mail.ReadWrite …` | Permission missing, admin consent not granted, or the access policy does not include this mailbox (or has not applied yet) | Step 4 (both "Granted"), then `Test-ApplicationAccessPolicy` (step 5); wait up to an hour after a policy change |
| `Graph could not find the mailbox (404): check AEGIS_MAIL_FROM` | Typo in the address, or the mailbox is not in this tenant | Use the mailbox's primary SMTP address |
| `Graph answered 429 after retries` / "throttled" | Mailbox or tenant throttling (Exchange allows a few concurrent requests per app and mailbox) | Aegis already waits for `Retry-After`; try again later and avoid manual syncs in a loop |
| "Aegis could not confirm the send" (status unknown) | The send request timed out, or Graph (or a gateway) answered 5xx, after Graph may have received it | Do **not** resend by hand. **Check the mailbox now** (also run by the scheduler) asks Graph: the draft's isDraft, else Sent Items by internetMessageId. Sent → filed; missing 15 minutes after the attempt → failed; still an unsent draft → Aegis deletes the draft (every draft with the Message-ID; `Mail.ReadWrite`) and only then marks it failed, so the letter can be prepared again. If the deletion fails the e-mail stays unknown and the preview says so ("Unsent draft not deleted"): delete it in Drafts (or fix the cause) and check again. Until then Aegis refuses any other e-mail for the letter. There is no "retry send": a 5xx on the send step is never retried, because a retry could send the letter twice |

A request that times out while Aegis is *creating* the draft is retried. When creating fails in
the end (network / server error), or `/send` is refused outright (a 4xx), Aegis deletes every draft
carrying the e-mail's Message-ID before reporting the e-mail failed; if it cannot confirm that, it
reports the outcome as unknown instead, so the letter is never prepared again while a draft of it
may still be in the mailbox. A create that may have reached Graph (a read timeout or a 5xx) and
shows no draft in the listing is also reported unknown, because Graph can list a new draft late:
the mailbox check 15 minutes later deletes any draft that appeared, then marks the e-mail failed.
