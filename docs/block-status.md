# Block status — what every authority answered, and what to do next

Goal: read the case mailbox, determine the status of every block requested across all the authorities, and
report on it.

The e-mail desk files every reply from the case mailbox on the right authority (app/mail, docs/m365-setup.md).
**Block status** (`app/blocks/`, `app/web/routes_blocks.py`) reads those replies, works out the status of each
request, recommends the next action and reports it: a page per case, a card on the Overview, a column on the
Authorities tab, `.md` / `.csv` / `.docx` exports and the assistant's `/block-status`.

## 0. Safe outcomes by design

**A person confirms every positive outcome.** The positive statuses are `hold_placed`, `frozen` and
`funds_returned`. Neither the rules (`classify_rules`) nor the AI (`classify_ai`), nor an issuer's blacklist read
on-chain, ever make a request's derived status positive on their own:

* their positive reading becomes a **suggestion** — the badge detail reads *Reply suggests: Frozen (2.1 ETH) —
  confirm* (an on-chain reading: *On-chain: Frozen (… USDT) — confirm*), with the supporting quote, who read it
  (rules / AI / on-chain) and its **warnings** (`classify_rules.outcome_warnings`: the guard's signals read over
  the whole reply — "the reply also says it was released / lifted, or that the funds left", a negation, a condition
  or hypothesis, a question, a partial or empty outcome, another party or someone else's statement, past practice
  or policy, an object that is no funds, "a test" — plus "the rules / the AI read it as …", a different amount, a
  sender outside the authority's domain);
* the reply itself reads *unclear* (needs review) and the request **keeps its earlier non-positive state**: *Reply
  received — suggests Frozen (2.1 ETH), needs confirmation*, or e.g. *Acknowledged — suggests …* after an earlier
  acknowledgement; the row is *to confirm* and the next action is "read it and confirm the outcome yourself";
* the **held / frozen totals** (page, Overview card, exports, `/block-status`) count only outcomes a person
  confirmed (recorded on the stop order, or confirmed on this page — an investigator's confirmation counts already
  while it awaits a case admin as a proposal; whether totals should count only applied outcomes is an open
  design question);
* the **Confirm form preselects nothing** for a positive outcome: the status select starts on "— choose what the
  reply says —", the amount field is empty (the suggested amount is shown next to it as text) and confirming a
  hold or freeze needs the amount typed in (400 otherwise; never taken from the reply or the chain);
* **notifications** say "reply needs review" (or "on-chain reading needs review"), never the outcome or its amount.

Non-positive readings — auto-reply, redirected, acknowledged (with their ticket), LE process required,
information requested, declined — are safe and still apply automatically; they are read from the sender's own
text only, never from the quoted or echoed part (§2). The rules' own reading (e.g. `frozen`) is still stored in
`reply_classifications` (source `rules`): an opinion about the reply, never the request's status.

## 1. Requests and replies

| Request (one row) | Its outbound messages | Its replies |
|---|---|---|
| Every stop order (superseded ones aside) | its own letter and the follow-ups linked to it (status requests) | inbound correspondence of the authority with the order's `stop_order_id`, `in_reply_to_id` of one of its letters, or the same `thread_key` |
| Every other outbound letter not tied to a stop order (information request, LE cover letter, release request, a logged e-mail) | the letter | the same links to that letter |
| An issuer (Tether, Circle) with on-chain readings but no request | — | — (shows the on-chain lever) |

A reply with no link is tied to the latest request the authority received before it (an open stop order
first). Automatic replies and bounces that the mailbox filed as notes count as replies.

## 2. Reading a reply

1. **Rules** (`app/blocks/classify_rules.py`, pure and always recomputed). Quoted earlier messages are cut
   first (`>` lines, "On … wrote:", "-----Original Message-----", Outlook "From: … Sent: …", and the German /
   Italian / French / Spanish forms), so the words of our own letter never classify a reply. So is what a
   **ticket system echoes** of our letter (a common helpdesk shape): a "-- reply above this line --" /
   "##- Please type your reply above this line -##" marker (when it opens the message, the ticket system's own
   notification after it is read), a rule line (`________`, `-----`, `========`) **when an echo follows it** —
   within a few lines a header block (From: / Sent: / To: / Subject:), a ticket system's request fields, a reply
   header or `>` lines, or a line of the request's own letters or their subject (the status page passes them:
   `classify(…, echo=…)`); when the letters are not known, a letter's salutation right below the rule line
   ("Dear Compliance Team,") counts too — and a "Ticket details:" block with the fields of the request
   (Submitted / Subject: our subject / …). A rule line with no echo after it is the sender's own divider and the
   text below it is read: Outlook's `<hr>` under "Dear team,", a section divider between their paragraphs, the
   agent's comment below a ticket system's "Your request (#…) has been updated." (Zendesk shape). Such an acknowledgement reads
   *acknowledged* with their ticket number ("assigned ticket number: #…", "[#…]" in the subject), never *LE process
   required* from our own "A formal law-enforcement request will follow." The quoted / echoed part is still scanned
   for text addressed to an AI (§4). Sentence by
   sentence; a positive outcome that is negated ("we have **not** frozen"), conditional or future ("**once**
   we receive a court order we **will** freeze"), a question (with or without its "?": "Did / Have / Is / Could
   you …"), too late ("too late to freeze"), with a negated object ("we have frozen **nothing**", "frozen **none**
   of the assets"), only considered or requested ("a hold was considered **but not placed**") or lifted again
   later in its sentence, also after "; " and a capital ("frozen by mistake and have since been **released**",
   "the freeze was **lifted** / **removed** / **withdrawn** / **cancelled** / **rescinded**", "blacklisted by mistake;
   Tether has since **unblacklisted** the address"), or in the next two sentences ("The funds were frozen. They
   were **released** on 3 October", "… which **expired** after 72 hours", "… **no longer in effect**", "Full access
   has been **reinstated**"; a lift naming the freeze / hold anywhere in the reply counts too), is ignored: such a
   reply reads unclear and waits for review. Negations count in English, German, Italian, French and Spanish
   ("**nicht** gesperrt", "**non** abbiamo congelato", "n'ont **pas** été gelés"), also inside the matched words
   ("The wallet **no longer** remains frozen"), and so do zero amounts ("We have frozen **0** USDT"). Also ignored:
   an intention, a need or a policy ("we **plan to** / **need a court order to** put a hold", "**Normally**,
   accounts … are frozen", "frozen **only upon receipt of** a court order", "frozen **as of tomorrow**"), someone
   else's claim, a quotation, a hedge or a request back to us ("**In your letter you state** that …", "**Reports
   that** … are inaccurate", "**We believe** …", "**Please confirm** the funds have been frozen", "… **according to
   the user**"), another party or account ("frozen by the sending exchange, **not by us**", "**a different
   account**"), a platform-wide suspension ("suspended **for maintenance**", "disabled **network-wide**"), and a
   returned letter / request / document / e-mail (a return needs a funds object; a refund to the suspect is none).
   Partial outcomes ("We have frozen part of the funds; the remaining … had already been withdrawn") go to review.
   Also to review: what is no funds ("Your **e-mail address** has been blocked by our **spam
   filter**", "Your **portal account** has been locked after failed **log-in** attempts", "a hold **on processing
   your request**", "a freeze **on new sign-ups**"; a hold needs funds or an account after "on", a flag is no
   hold); another party as the subject ("**The bank** has frozen …", "**Tether** has frozen …"; only "we / our team
   has …" counts) or another matter ("belongs to **someone else**", "**unrelated**", "a **separate
   investigation**", "**in 2023**", "**last year**", "by **his bank** / **the issuer**"); a statement reported by
   anyone ("We were **told** …", "The user **informs** us …", "The customer **says** …", "the officer **wrote**:",
   "Our **earlier e-mail** said …", "We **mistakenly** reported …", "**Nobody** has frozen …"); a policy or a
   condition ("**In the event of** a court order …", "**Where** a court order is received …", "**Assuming** …",
   "**In case** …", "frozen **on receipt of** / **after we receive** a court order", "**Accounts** are frozen
   …" with no determiner, "are frozen **within 24 hours**"); a lapse or lift in other words ("**reversed**",
   "**taken off**", "**overturned**", "**let the funds go**", "**now open**", "access **given back**",
   "**forwarded** / **transferred** to …", "the funds had already **left**", "**had** frozen … **until** …", "**for
   the duration of** the review", "**at the time**", "**briefly**", "**for 48 hours**"); a correction, disclaimer
   or partial outcome after "; " or in the next two sentences ("**NOT by us** but by the issuer", "**Or so** the
   user claims", "Not by us, though.", "This is **incorrect**.", "**Correction**: we have not.", "a **template
   error**; **no action was taken**", "withdrawals **remain open**", "it **contains no** funds"; a footer "If you
   received this e-mail in error …" and "No further action is required" are not read); a returned fee, the
   payment details / records / instructions, and a return that **bounced** / is **back with us** / was
   **recalled**.
   Precision over recall: when in doubt the rules read unclear, never an outcome.
   "Your case is closed / pending" is no acknowledgement (a ticket needs a number). A sentence is not cut after an
   abbreviation ("approx. 2.1 ETH", "Ticket No. 48213"), and the patterns read across a decimal point
   ("Funds totalling USDT 12,633.77 are now frozen"); "No. 48213" is no negation; "4.500,00 EUR" is 4,500.00.
   The strongest outcome wins; the
   others stay in `also`. Extracted: the supporting sentence (verbatim), the amount with its asset, their
   ticket / case number (never our case reference or tracking tag), and for a redirect the addresses and
   URLs it names (minus the ones we wrote to, the case mailbox and those it calls legacy).

   | Status | Typical wording |
   |---|---|
   | `frozen` | "we have frozen …", "the funds have been frozen / blacklisted" |
   | `hold_placed` | "we placed a temporary hold", "the account has been restricted" |
   | `funds_returned` | "the funds have been returned / reversed / refunded" |
   | `declined_no_assets` | "no account found", "not our customer", "non-custodial", "already withdrawn" |
   | `le_process_required` | "submit via our law-enforcement portal (Kodex)", "we require a valid court order / subpoena" |
   | `info_requested` | "please provide the transaction hash …" |
   | `declined_other` | "we must decline your request" |
   | `redirected` | "this is a legacy inbox … please contact the following: …" (e.g. an issuer's legacy-inbox auto-reply) |
   | `acknowledged` | "received and logged under ticket …", "our team is reviewing" |
   | `auto_reply` | out-of-office, "this is an automated message" with nothing else |
   | `delivery_failed` | a bounce filed by the e-mail desk |
   | `unclear` | nothing recognisable, contradictory, or text addressed to an AI |

   The guard above decides only whether the rules *suggest* an outcome (§0): a reading that passes it is still a
   suggestion a person confirms, shown with the warnings of `outcome_warnings`.

   A reply carrying text addressed to an AI ("ignore previous instructions", "SYSTEM:", "mark this as frozen")
   is flagged *suspicious* and always needs review. A hold / freeze / return the rules find in such a reply is
   not used: the reply reads *unclear* (left out of the held / frozen totals and the badge), the rules' reading
   is shown as text ("rules read Frozen (25,000 USDT): not used"), and confirming it needs the tick below.
2. **AI, optional** (`app/blocks/classify_ai.py`): see §4.
3. **A person** (Confirm status, §3).

Precedence per reply: person > AI > rules. The AI's reading is used only when its quote was verified and it
agrees with the rules (frozen ≈ hold placed, declined ≈ no assets, auto-reply ≈ acknowledged); otherwise the
reply is `unclear` with both readings shown. A positive reading — the rules', the AI's agreeing one, or a verified
AI reading the rules read otherwise (warning "the rules read it as …") — is only ever a suggestion (§0). An AI reading whose
quote did not verify never decides; when it disagrees with the rules the reply is still flagged for review with
the AI's status as the suggestion. When the rules and the AI agree but read different amounts, the rules'
amount is shown and the reply needs review.

**Storage.** Opinions are written to `reply_classifications` (migration 0010, one row per mail message: rules,
then AI, then a person; a person's row is never overwritten by rules or AI) and, with the details the table has
no column for (ticket, redirect addresses, the AI's verification flags), to `correspondence.meta["block_status"]`
— also for replies logged by hand, which have no mail message. The e-mail desk calls
`app.blocks.status.on_reply_filed(db, case, corr)` after it files a reply (never raises): `app.mail.ingest.persist_to_case`
→ `block_status_hook`, so it covers the mailbox sync, a reply accepted on **Mail to review**, a system admin's
triage assign and an imported `.eml` / `.msg`. A reply logged by hand on the authority page is read on the next
page view (rules) or **Classify replies now**, which runs the same for the whole case. A bounce changes the
status to *Not delivered* without a second `block_status_changed` (the desk already warned).

**What a reply says beyond its status** (`app/blocks/extract.py`, rules version 9: a provider playbook's LE-process wording in an untracked acknowledgement reads "LE process required"). On the sender's own text only
(quoted text and our letters' echo cut), the rules read: the provider's **ticket(s)** (the generic ticket reader
plus the playbook's ticket formats, with the sender's address as the channel); the **instrument** it requires
(the playbook's `reply_signals`, then a lexicon — court order, subpoena, warrant, freezing order, MLAT, EIO, formal
legal directive, appropriate legal process, "exclusively for verified Law Enforcement Agencies", police report — in a
sentence that makes it a condition), with its issuer jurisdictions ("a US or French court": US / FR, read as a US
or French court order); the **channels** it names, classified against the playbook's domains (own, sibling,
vendor portal with its tenant and LE-only flag, another catalogue organisation = third party, unknown — a third
party / unknown target needs a person to pick it); what it **asks** for, mapped to the playbook's evidence keys
(police report, proof of ownership, UID, TxID, freeze duration, English, …); its **deadlines** (reply by, hold
until, submit by, auto-lift; English / Italian / German / French dates and durations); **LE contacts and
references** (Prot. n., R.G.N.R., Verfahrensnummer / Aktenzeichen, numéro de procédure, IC3 complaint ID, an
officer's rank and name, an LE sender's e-mail and phone); and the **identifiers** it names (EVM / TRON / Bitcoin
addresses with their checksums, tx hashes, UIDs, order ids; `known` when our own letters already cite them). With
the case's AI consent the model returns the same fields; each is kept only when grounded in the reply (a quote
verbatim in the sender's own text, a value that occurs in it, a stated date / duration that parses, a jurisdiction
its quote states) and merged after the rules' reading: where the two read the instrument or a deadline differently,
the rules' reading stays and the AI's is shown with a warning. Stored in `correspondence.meta["block_status"]
["extract"]` on **Classify replies now** / the mailbox hook; recomputed on every page view.

*Effects.* Advisory only: no status, stop order or letter changes. The block page shows "Read from the reply" on
the row (ticket, instrument, asks, deadlines; with `view_restricted` also the quotes, channels, identifiers and,
unless LE / PI contacts are masked, the contacts), with one-click proposals a person confirms: **Watch for a
freeze** (adds a TRON / EVM wallet to the freeze watch, `source_note` "named in reply c<id>"), **re-trace**, **Add as
LE contact**. The next action names the instrument ("They require a US or French court order"), the asks and the
nearest stated deadline. **Clocks:** an unambiguous *reply by* stated in a reply since our last letter shortens the
reply clock (never lengthens it); the earliest unambiguous deadline in the future is the row's *next deadline*. A
numeric date whose day and month could swap (03/04/2026, also with dots) is **ambiguous**: both readings are shown
and it never changes a clock by itself; nor does a date without a year, a hold expiry or an auto-lift (applied when
a person confirms the hold), nor any deadline read only by the AI.

**Redirects feed the e-mail desk.** A reply read as *redirected* (e.g. an issuer's "legacy inbox … contact the
following") shows on the authority page's **How to email** panel (`mail_guidance`: the address that redirected
moves to "not suggested", the named address is offered, a warning names both) and on the compose page of the
follow-up letter (`mail_compose.redirect_hint`: the named address typed in, the legacy one unticked). Both only
when the reply came from the authority's own domain and names an address on that domain; otherwise they only
warn. The **Resend** next action opens the follow-up (status request) form; once it went out the request is
*awaiting* again: the row shows the follow-up's To and date ("resent 20 Oct 2026 to …", the first addressee
under it), the source reads "resent … after their reply", and the reply date is the one the desk shows: a stop
order still awaiting its first response (a redirect logged as an automatic reply) keeps `response_due_at`, as
its card does; otherwise the follow-up letter's reply clock, as the desk's due list does.

**E-mails sent from Outlook** (app/mail/sync_outbound.py). A letter the mailbox sync recorded is the request's
outbound letter as usual. Sent Items are read **oldest first** (Graph lists the newest first), so a letter's first
send records it before its forward or follow-up is read. The authority of a Sent Items message is decided by its
**To** recipients first: a Cc'd partner firm or a colleague at another authority of the case never makes it
ambiguous, and any address on the authority's **own organisation domain(s)** — its addresses' domains, the
entity's website, the catalogue organisation's homepage / website / e-mail channels (e.g. `circle.com`) — is that
authority, also a new inbox a redirect named that is not on record yet. A **forward of our letter** ("FW:" /
"Fwd:" / "WG:" / "TR:" / "RV:" + its subject) to the authority is that letter sent again: in the thread of the
recorded original it is a resend (a follow-up of the request, `meta.follow_up_of`), and without the original on
record it records a draft as sent (the first send we know of) or is logged as a resend of the letter already sent.
A common shape — our letter to an issuer's legacy `compliance@` → their auto-reply naming the freeze inbox → we
forward the letter there → their answer from the new inbox — is one request: sent at the first send, redirected,
resent to the named address, and their answer lands on the same stop order. **Demo cases** (reference "DEMO-…",
or `facts.demo`: `Case.is_demo`) never take part in the graph mailbox sync's matching, so a real message is never
filed on a demo copy of a real authority or wallet. An Outlook answer **in the thread of a request** (a reply to the authority's question,
or to our own letter) is logged with the stop order and the thread of the message it answers
(`meta.follow_up_of`): it is that request's outbound message (the request reads *awaiting* again), and the
authority's answer to it lands on the same request, so *Confirm & apply* works on the stop order. A Sent Items
message the sync could not tie to one letter (several drafts matched, or none) is shown as **Sent from Outlook —
needs review** (kind "outlook"): counted in *replies to review*, in *Needs action* and on the Overview card, with
"Tie it to letter #… / #…" as the next action; it is never a request and never in the exports (the .md export
counts them), and the drafts it may have carried say "Possibly already sent from Outlook on <date> (entry #…):
check before sending" instead of "Send it"; once every candidate draft is marked sent the row asks for nothing
more. An Outlook e-mail that matched no letter at all (it cites the case, so it is on the authority's timeline
with *needs review* and on /admin/mail/mailbox) is not listed. A reply to such a message waits on **Mail to
review** (the e-mail desk's matching skips it) until a person ties it.

## 3. Status of a request, next action, Confirm status

The block status of a request is the stop order's **recorded** status (a person set it on the desk:
acknowledged / frozen with the amount held / declined / released) unless a later reply says something else;
else the deciding reply (the latest substantive one — an auto-reply never hides an earlier outcome); else
*Sent, awaiting reply*. A redirect, bounce or information request followed by a later outbound letter is
awaiting again ("resent": *Sent (resent to <address>), awaiting reply* when the resend went to another
address); their answer to the resend then decides, even an acknowledgement of it, and the row keeps showing
where it was resent. The addresses a redirect names are read against the addresses the request had gone to
**when the reply came** (never a later resend), so the address we resent to stays the redirect's target. A
redirect that is already answered never decides (`status._settled`): a hand-logged copy of a reply on record
(the same own text — e.g. an auto-reply also logged by hand minutes after the forward),
one naming an address our resend had already gone to before it (*Sent (resent to …), awaiting reply*, never
"Redirected (resend to <the address the letter was already forwarded to>)"), and one followed by a reply from the
address it names (their acknowledgement from the new inbox decides). The
address chosen keeps the request's purpose (`status.pick_resend`): a stop order or its status request takes
the freeze address (never the subpoena inbox while a freeze one is named), an information request or LE cover
letter the legal / LE one; the compose page and the authority's guidance pick by the letter being written.
For an issuer, a blacklist read on-chain (app/freeze) for an address the stop order
cites, after it was sent, is a suggestion too (*Sent, awaiting reply — on-chain: Frozen (… USDT), needs
confirmation*), never the status. A positive status (frozen / hold placed / funds returned) is only ever a
person's: the stop order's recorded status or a confirmation on this page (§0); a later machine reading of
another outcome shows as a suggestion next to it.

Shown per request: authority, request, sent (date, channel, To), last reply, status badge (*Not sent · Sent,
awaiting reply · Auto-reply · Redirected (resend to …) · Acknowledged · LE process required · Info requested ·
Hold placed · Frozen (amount) · Funds returned · Declined · Not delivered · Reply needs review*), where the
status comes from, the supporting quote, days waiting against the reply date, and the **next action**
(resend to the new address — check it against their published channels, warned when the reply did not come
from their own domain; an LE cover letter asking the police / the FBI's IC3 to file through the portal; a status
request quoting their ticket when overdue; answer their questions; ask law enforcement for a freezing order
while a hold lasts; …).

**Confirm status** (one click on the row, CSRF form):

* investigators confirm a reading — stored as the person's opinion; when it maps to a stop-order status it is a
  **proposal** that a case admin applies;
* case admins **Confirm & apply**: through `desk.record_stop_order_status` — hold placed / frozen → FROZEN with
  the amount held, declined / no assets → DECLINED, acknowledged → ACKNOWLEDGED, funds returned → RELEASED (only
  from FROZEN; otherwise 409 with what to do).
* the form never preselects a positive outcome nor prefills the amount (§0): for a hold or freeze the person
  chooses the status and types the amount held; a non-positive reading may be preselected;
* the form preselects the reading shown, but **never the AI's** for a reply flagged *suspicious* (text addressed
  to an AI) or one the rules and the AI read differently: then the rules' reading (or *unclear* for a
  suspicious reply), with the AI's reading shown as text and a warning; confirming a hold, freeze or return
  from such a reply needs the extra tick **"I read the reply myself"** (400 without it) — also when the form
  names an earlier reply of the same request while the deciding reply is the risky one.

**Sent from Outlook — needs review** rows have **Dismiss / tie to letter** (investigators+, as *Mark sent*):
tied to a draft, the letter is recorded as sent at the e-mail's date (its `.eml` already filed is the
evidence); tied to a sent letter, linked; dismissed, it stays on the timeline. System admins have the same on
`/admin/mail/mailbox`. Tie to letter offers only the letters the sync itself could have chosen: never one another
e-mail carries, nor one recorded as sent more than a day after the e-mail (400 otherwise). An Outlook e-mail
whose candidate letters have all been recorded as sent since reads **Sent from Outlook — probably a copy** and is
not counted as to review; a reply a person confirmed as *unclear* reads **Unclear (read by a person)** with the
next action "ask them what it means". The KPI tile **to review** counts the replies and Outlook e-mails to review plus the
requests waiting on our action (redirected, bounced, information requested, LE process) — the same number on
the page, the Overview card, the .md export and `/block-status`.

Each confirm is on the authority's timeline (a note, or the desk's own status entry), audited (`UPDATE` on
`block_status`: request key, status, applied, ids; never the reply's text) and emits `block_status_changed`
(in-app by default; titles carry the case reference, the request id, the status and the amount — no
counterparty name, no address). A refresh that changes a request's derived status emits the same event,
marked "not confirmed yet"; a new suggested outcome emits "<request> — reply needs review" (severity warning, no
outcome word, no amount); the first refresh of a case only records the snapshot.

## 3a. Request paths, the LE brief and the provider clocks

**Path step** (`app/blocks/path.py`, `BlockRow.path_step`, next to the status). Where the request stands in the
provider's process, derived on every read — never stored — from the replies (status, extraction, the playbook's
`reply_signals`), the stop order's recorded state, our letters to LE / counsel linked to the request and the steps
a person recorded: *notice sent* → *provider acknowledged* (a ticket / acknowledgement; Tether's ticket ack with its
"appropriate legal process" line) → *provider asks for more* → *temporary hold* (a person confirmed it; a reply that
reads as one leaves "suggests temporary hold") → *LE process required* (they act only on LE process or a court order,
point to an LE-only portal, or refuse while naming an instrument; a refusal the playbook calls final, or "no
account / assets", is *Outcome: declined (final)*) → *LE briefed* (an LE brief / counsel brief whose
`meta.follow_up_of` names the request was sent) → *LE request filed* / *Order obtained* / *Cross-border request*
(recorded by a person: **Record a step** on the row, investigators+, audited, on the authority's timeline, stored in
`cases.facts["_block_path"]`; *Undo* removes the last one) → *Outcome* (frozen / funds returned — Confirm status with
the amount, §0 — or, recorded by a person, *funds moved on* (re-trace) / *declined (final)*).

**"LE process required" is answered by briefing LE.** A sent letter to an LE authority or counsel linked to the
request (`meta.follow_up_of`) makes the request *LE briefed, awaiting LE process* (status awaiting, source
`le_route`); a follow-up to the provider itself does not (it still needs LE process).

**Jurisdiction.** The instrument's issuer jurisdictions (the reply's — "a US or French court" — else the playbook
path's, else the playbook's `issuer_jurisdictions`) are matched against each LE authority of the case (its LE
contact's jurisdiction, else its playbook's). The brief goes to one that can ask directly; when none can, the next
action and the brief name the **cross-border route** from the provider's playbook: for Circle and an Italian case, an
EU freezing order (Reg. (EU) 2018/1805) or a European Investigation Order to France, an MLAT request to the US, or
counsel for a US or French court order (the instruments the Italian side's playbook says it issues to Circle first).

**Next action = the playbook's next step** (`path.action`; the generic status text when it has none). It keeps
`{kind, text, href}` and gains `evidence` (what the step needs, from the playbook path's evidence keys) and `clock`
(the next deadline): *brief the officer with the pack* (LE process required; at a provider that never holds on a
private letter, already at its acknowledgement: "hand off now", quoting the ticket; the officer files through the
LE-only channel, Aegis never does), the cross-border route, a still-unsent LE brief ("send it"), *wait for LE to
file / chase the officer* once briefed, *ask for an order stating the freeze duration before the hold lapses*
(KuCoin: not digitally signed), the victim's own report where the provider has one (Gate), re-trace when the funds
moved on.

**The LE brief** (`le_brief`, to an LE authority; `counsel_brief`, to counsel) is prefilled from the request
(`?template=le_brief&ref=o12`, or chosen on the authority page): what the provider said (quoted), their ticket, the
instrument (jurisdiction, signing, language) and channel it requires, the evidence, the route, the addresses, hashes
and amounts at stake, the clocks; `meta.follow_up_of` is the request key.

**Clocks.** `due_at` = the earliest of our reply clock, an unambiguous reply-by stated in their reply, and the
playbook's own reply time for our path (`response_days`, a `reply_by` deadline). The playbook's deadlines of our
path, the paths it leads to and the one the reply names run from the event that starts each: our letter (`sent`),
their first reply (`provider_ack`), a temporary freeze their reply reports (`provider_freeze_confirmed`: MEXC's
48 hours for the LE request / the police-report proof, also before a person confirms the hold), a hold a person
confirmed (`hold_confirmed`: KuCoin's 30-day auto-lift, Binance.US's 14-day hold), an order a person recorded
(`order_served`). `hold_expires_at` is set only once a person confirmed the hold (the reply's stated expiry, else
the playbook's); `next_deadline` is the earliest unmet one in the future. An ambiguous date never sets a clock.

**Alerts** (`status.check_clocks`, run by `desk.check_overdue` — the scheduler's overdue pass,
`scripts/run_scheduler.py`; rules only, no AI): `provider_deadline` / `hold_expiring`, severity high, in-app and
e-mail by default, once ahead of each clock (half its span, at most three days: 24 hours for MEXC's 48) and once when
it passes (within three days); the same deadline read twice (their reply and the playbook) alerts once. Titles carry
the case reference and the request id, never the counterparty or an address.

**Exports.** The CSV gains `path_step, instrument, next_deadline, hold_expires_at, tickets`; the .md / .docx a
*Path*, *Route*, *Tickets*, *Next deadline* and *Hold expires* line per request; the JSON API `path`.

## 4. "AI reads mailbox replies" (per case, off by default)

* Stored in `cases.mail_ai_consent` (migration 0010). A case admin turns it on at the bottom of the Block status
  page, ticking the consent that names the data path ("Hugging Face Inference Router → DeepInfra (third-party
  inference provider)") and the model; the record keeps who, when, the provider, destination and model; the
  audit row has `confirmed_destination`. Turning it off keeps the record (enabled false).
* **What is sent:** the reply's full text (subject and body as filed, quoted earlier messages
  included) and the kind of request, nothing else. Only replies read from the case mailbox — never a note an
  investigator typed. The text is wrapped in `<<<UNTRUSTED_EXTERNAL_EMAIL id=<nonce>>>` … markers with a fresh
  nonce per call; the system prompt says it is untrusted data and that instructions in it are never followed.
* **No call** while the setting is off, the case's AI mode is `off`, `AEGIS_AI_DISABLED` is set, no provider is
  configured, or the provider / model differs from the consented one (*re-confirm*). At most 10 calls per
  refresh; a reply that failed for a non-transient reason is not sent again.
* **Checked:** a status from the enum; the quote verbatim in the sender's own text (not only in a quoted earlier
  message), at least 20 characters and 4 words, and for an outcome (frozen, hold, returned, declined) one that says
  it — for frozen / hold / returned a whole outcome word ("block" in "blockchain" is none) in a quote that overlaps
  a statement of the same outcome (a frozen statement never verifies a hold quote, nor the reverse) the rules'
  guard accepts (`classify_rules.positive_spans`), so the AI guard is never laxer than the
  rules: "We have not frozen …", "if we freeze …", "have you frozen …?", "we have frozen nothing", "a hold was
  considered but not placed", "frozen by mistake; the freeze has since been removed", "The funds were frozen.
  They were released …", "We lifted the freeze …" or "Please return the signed form …" is no quote (also for a
  reading stored earlier) — else dropped and the reading is not used (an AI reading that agrees with a rules
  frozen / hold / returned adds no confidence: the rules' confidence is shown); the quoted part of the reply (below "-----Original Message-----" / "On …
  wrote:", `>` lines), which the model reads too, is checked for text addressed to an AI ("ignore previous
  instructions", "SYSTEM:", "mark this case as frozen", a "status:" line only with an outcome value such as
  "Status: frozen", never an ordinary "Case status: open"): a hit marks the reply risky like an injection in its own text (the "I read the reply myself" tick is required,
  nothing is preselected); an amount only when it is one the reply states next to an asset
  or currency (the rules' parser, compared as decimals: never a phone number, a reference, or digits joined
  across tokens); account references that appear in it. Every call writes an `AI_QUERY` audit row (`kind` reply_classification, provider, data
  path, configured and served model, tokens, latency, the status enum) without the reply, the quote or the
  rationale.
* **Advisory only:** the AI never changes a stop order nor makes a status positive; a person confirms (§0).

## 5. Report and visibility

`GET /cases/{id}/blocks` (read-only and up; filters: open / needs action / resolved / not sent / a status,
authority type, overdue, to confirm). Amounts show exactly as stated for crypto (0.05683881 ETH, never rounded)
and to the cent for fiat, `GET /cases/{id}/blocks/export.{md|csv|docx}` (EXPORT audit; the report
for law enforcement or a PI firm, saying which statuses a person confirmed and which are advisory),
`GET /api/cases/{id}/blocks` (JSON). Read-only members see statuses, dates and next actions but no reply
quotes (R3) and LE / PI contact details masked; external members have no access. CSV cells that a spreadsheet
would run as a formula are prefixed with `'`. The Overview card lists the requests that need attention; the
Authorities tab has a *Block status* column; `/block-status` in the assistant gives the same picture
(rule-based, AI wording only when the case's AI mode allows it; reply text is never quoted; unless "AI reads
mailbox replies" is on, the details read from replies — their ticket numbers, the portal URLs and addresses a
reply names, the amounts a reply states — are placeholders or left out of what it sends to a model).

The **Recovery plan** (`/cases/{id}/recovery-plan`, a sub-tab next to this page; docs/recovery-plan.md) reads the same
rows, the latest trace, the on-chain readings, the watch list and the evidence on file, and ranks the moves that trap
the most money fastest; its "Read new replies" button posts here (`next` = the plan) and returns to the plan.

## 6. Tests

`tests/test_block_safe_outcomes.py` (§0: every false positive of the hardening review never becomes an outcome —
no positive status, nothing preselected, totals unchanged, a warning on any suggestion; a genuine "We have frozen
2.1 ETH on the account." is a suggestion a person confirms with the amount typed in; notifications),
`tests/test_mailbox_dryrun_fixes.py` (demo cases out of the matching; the ticket system's echo of our letter; the
Circle-style redirect → forward → reply flow on synthetic `circle-…-demo.example` data, also with the auto-reply
logged by hand after the forward; rule lines that are the sender's own divider — Zendesk updates, Outlook's `<hr>`,
section dividers — are read),

`tests/test_block_extract.py` (golden replies shaped like Tether's ticket acknowledgement, Circle's "US or French
court order", Binance's "unable to unilaterally freeze … freezing order", MEXC's 48h police-report window, KuCoin's
30-day auto-lift, an exchange naming a new deposit address and UID; Italian / German / French / US dates and LE
references; ambiguous dates never shorten a clock; grounded AI fields; the page's proposals),
`tests/test_block_path.py` (Circle's court-order reply on an Italian case → LE process required and the cross-border
route, a direct route with a US agency on the case; Tether's ticket ack → hand off to LE quoting the ticket; a sent
linked LE brief → LE briefed, a follow-up to the provider does not answer it; MEXC's 48-hour alert from its temporary
freeze; KuCoin's hold expiry only after a person confirms the hold; Gate's LE channel never offered to a PI and its
refusal routed to LE; recorded steps, the exports and the page; the counsel brief),
`tests/test_block_classify.py` (38 realistic samples, multilingual and adversarial), `tests/test_block_status.py`
(derivation, next actions, Confirm / apply role gating, exports, notifications, storage, on-chain, Overview,
Authorities, skill), `tests/test_block_ai.py` (consent gating, the wrapped request over `httpx.MockTransport`,
prompt injection never applied, quote verification, disagreement, audit), `tests/test_block_review_fixes.py`
(redirect → resend → reply, the purpose of the new To, guarded AI quotes, the crafted reply that must never be
preselected and the "I read the reply myself" tick, rules recall and negations, the skill's reply details, the
"to review" tile).
