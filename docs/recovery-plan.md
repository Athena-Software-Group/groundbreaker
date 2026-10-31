# Recovery plan — the moves that trap the most money fastest

Objective: *trap as much money as quickly as possible before it moves further down the road*.
The **Recovery plan** (`app/blocks/recovery.py`, `app/web/routes_recovery.py`) turns the case's current state into
a ranked list of **moves**, best first, with the reasoning for each in one line, the evidence it needs and one-click
actions. It is rebuilt on every read — the page, the Overview card, `GET /api/cases/{id}/recovery-plan` and the
assistant's `/recovery-plan` — so it follows the case as replies come in, the trace is re-run and the on-chain readings
change. Nothing is stored except the evidence waivers a case admin records.

Where: a sub-tab next to **Block status** (`/cases/{id}/recovery-plan`; both pages carry the sub-tabs), a card on the
Overview (the top three moves), the JSON API and `/recovery-plan` in the assistant.

## 1. Inputs

* **Every block request** (app.blocks.status, docs/block-status.md): its status, path step, next action, clocks
  (`next_deadline`, `hold_expires_at`, the reply clock), the asks read from the replies, their tickets.
* **The latest trace run**: its freeze candidates (custodial deposit addresses, issuer-freezable USDT / USDC wallets,
  swap services; app.tracing.freeze) and the unhosted wallets still holding funds (dormant, where the trace stopped).
* **On-chain freeze readings** (app.freeze): per issuer wallet, frozen, still freezable (balance not blacklisted),
  lifted, or zero; watched wallets included.
* **The watch list** and its movement alerts raised after the latest run (funds observed moving).
* **The provider playbooks** (docs/playbook.md) for the case's requester (`app.domain.sender.requester_kind`: pi /
  victim / counsel — never LE) and the case's LE authorities (their jurisdiction, what their playbooks issue to whom).
* **Evidence on file** (app.domain.evidence_requirements).

## 2. Moves

* **One move per target** (a provider, an issuer): the next action of its most actionable request — confirm a
  suggested outcome, brief LE, answer their questions, resend, send the draft, chase — with that request's clock.
* **Untouched targets**: funds in the trace (or a still-freezable on-chain balance) at a service nobody has asked yet
  → *Send <template> to <provider> now* (a stop order from the trace's identifiers; a preservation / information
  request when no stop order applies). When the provider acts on LE process only (Tether, Circle) the move says so
  and offers the LE cover letter in parallel. **The LE-only gate**: when no path is open to us, the move is *Brief
  <LE> about <provider> now* — never a letter to an LE-only channel.
* **Cross-border**: when the provider acts only on authorities of other jurisdictions (Circle: US / FR) and the case's
  LE authority is elsewhere (Italy), the move is *Start the cross-border route* with the options (an EU freezing order
  or EIO to France, an MLAT to the US), counsel's court order in parallel; effort is high, likelihood lower. **A case
  agent first**: when a complaint intake of a jurisdiction the provider acts on is on the case (IC3: US) or the victim
  lives there, the move is *Get a US case agent on <provider>* (quoting the IC3 reference: the agent asks directly),
  with the cross-border route as the slower fallback (likelihood × the agent route, 0.75). On a direct route to a
  provider that blocks on an urgent LE request pending a court order (Circle), the next action and the LE brief ask for
  that first.
* **Their deadline first**: when a provider's reply (or its playbook) sets a deadline on our side — MEXC's police
  report receipt within 48 hours of the submission / of its temporary freeze, the earlier governing — the move is
  *Answer <provider> by <deadline>* (the answer letter `info_response`: their ticket, each ask answered, what is
  enclosed, their deadline, the hold to keep), with the reply's asks on the checklist, LE's own clock and its fallback,
  and the LE brief as the second action. The LE brief asks for the LE path's instrument (MEXC: a freezing order
  through LEORS, whose onboarding time it states) and lists what LE's order needs (MEXC: the restriction's duration,
  non-disclosure), never the police receipt or the victim's ID. With no reply yet, a clock that runs from our own
  letter is a proactive step instead: *Send <provider> the police receipt by <deadline>* (a follow-up on the request,
  the paragraph prefilled), never an "answer". A temporary freeze a reply reports is always a hold to confirm,
  whatever else it says; once a reply came, its passed reply-due date drives no ranking. Every deep link opens the
  authority page with the letter template it names selected.
* **Briefs go to an authority that files**: IC3 (`le_role` intake) is never the recipient — with no case agent on the
  case the move says to get one assigned (quoting the IC3 reference) or to instruct counsel; a binding or cross-border
  instrument goes to the prosecutor (the Procura), not the police station. Where the provider acts on a court order
  counsel can obtain (Circle's US / French court order), a *counsel brief pack* action is offered in parallel
  (`…/pack/{key}.zip?brief=counsel`, a preview addressed to "Counsel" when none is on the case).
* **Wallets** a reply names (investigators only), classified by the sentence that names them and the next one or two
  when they refer back to it (`app.blocks.path.destinations`): a deposit address at another service (its name with
  custody context next to it: never a chain or wallet product named after it, such as BEP20 / Binance Smart Chain or
  Coinbase Wallet) → *Ask <service> to freeze <wallet> now*, whose letter is an urgent freeze request naming the
  address (`?template=info_request&freeze=<chain>:<address>`; the LE brief's paragraph is worded for LE); an address
  the trace already puts at a provider of the case → *Tell <provider> the funds just arrived* (a follow-up on its open
  request, the new deposit prefilled; its own move gains the "funds just arrived" urgency); the wallet itself at the
  replying provider (an internal transfer, a sub-account, a deposit address credited to a UID there; never a wallet
  the account holder withdrew out to) → *ask <provider> to extend the hold* inside its answer (the answer letter
  quotes it); at most five such leads, built first and capped after (deposit addresses at a service first, best
  score first; a wallet's watch + issuer moves count as one lead); an exchange that acts on LE process only (Binance)
  gets the LE brief as the lead's primary action; an external wallet →
  *Check <wallet> for a USDT / USDC balance* (one click, value unknown until read) and, when the funds just left for
  it, *Ask the issuer to blacklist <wallet>* ranked on its own (Tether on TRON, Tether / Circle on EVM; the T3 FCU form
  on TRON only). A provider that holds nothing but names where the funds went keeps the KYC and withdrawal records:
  its move is an LE disclosure request, not "close". These leads are not added again to the money in play. *Watch N
  unhosted wallets for movement* (dormant wallets not on the watch list), *Re-trace now* (watched wallets moved after
  the trace) and *Trace further* (funds sit where the trace stopped).
* **Waiting on others**: requests whose next action is to wait (acknowledged, LE filed …), with the clock each runs
  on. **Secured and closed**: holds a person confirmed, wallets frozen on-chain, closed requests.

## 3. Scoring

**score = value × urgency × likelihood ÷ effort** (a move with no traced value — records, a takedown — counts as
$100 so it ranks among its peers by urgency).

| Factor | Range | From |
|---|---|---|
| **Value** (USD) | — | an issuer's wallets: the balance read on-chain and not frozen (`confirmed`), plus the traced amount of wallets not read yet (an upper bound, flagged "balance not read on-chain"); a custodial service: the amount traced into its deposit addresses (upper bound); a hold a person confirmed: the amount held; static prices (`app.providers.prices`) |
| **Urgency** | ×1 – ×4 (product, capped) | a clock: passed ×2.5, ≤ 24 h ×3, ≤ 72 h ×2, ≤ 7 days ×1.4 (a playbook / reply deadline, the hold's expiry, their reply due); reply overdue ×1.5; the issuer lifted its freeze ×3; funds moved after the trace ×2.5; inside the sweep window ×2; funds arrived ≤ 48 h ×1.6, ≤ 7 days ×1.3; nobody asked yet ×1.5 |
| **Likelihood** | 0 – 0.95 | base: issuer blacklist 0.7 with the balance read on-chain, 0.35 unconfirmed (weighted when mixed); exchange 0.5 (0.2 if not freeze-capable), casino / OTC 0.4, swap service / bridge 0.1, hosting / infra 0.02. × the playbook for our requester: voluntary hold possible ×1, LE process only (or a reply that refused a private request) or LE-only gate × the best route (direct ×0.85, a case agent to get ×0.75, counsel's court order for a private client ×0.6, cross-border ×0.5, unknown ×0.7), a notice without a hold ×0.7, no playbook ×0.8. × the path step: asks ×1.1, temporary hold ×1.6, LE briefed ×1.2, LE filed ×1.4, order ×1.6. A decline ×0.5; a suggested outcome to confirm ≥ 0.5 |
| **Effort** | 0.3 – 4.5 | watch 0.3; confirm / send / read 0.5; resend / chase 0.75; re-trace 0.8; a letter / an answer 1; an LE brief 1.5; cross-border 3; + 0.2 per evidence item still to obtain (at most +1.5) |

The **reasoning line** joins the value basis, the top two urgency reasons, the likelihood reason (with the route) and
the effort; the page also shows the four factors and the score. Each move keeps its own value (for ranking); moves
on the same funds say "same funds as …"; two claims are on the same funds only when they are on the same wallet, or
one is an upper bound of what reached a wallet the other descends from in the trace graph (never through a shared
hub, a swap's off-chain link or any other indirect rule: two balances read on separate branches below one hub are
both counted; a service wallet's claim that leaves out what the trace saw it send on covers nothing below those
onward wallets; the pieces of one move, its readings and a held amount a person recorded beyond them, never exclude
each other). The totals count each
traced dollar once: *in play* (the largest of the claims on the same funds, never their sum; at most the traced loss,
plus the balances read beyond the traced funds — at a wallet the trace never saw, or above what the trace left at a
wallet it saw the funds leave: untraced finds, added and labelled, never counted zero times; a reading far above what
was traced in, or at a service's wallet, is a float: valued at what the trace left there), *expected* (value × likelihood,
the same way), *not asked yet* and *secured* (confirmed holds and on-chain freezes only; a hold
whose lapse date passed, or whose provider-stated condition on our side passed unmet — MEXC's police proof within 48
hours — no longer counts: its move becomes *ask whether the funds are still held* / *the deadline passed: send it now
and ask them to confirm the freeze still stands*, on the passed clock). The plan's notes carry the victim's own
standing deadlines from the LE playbooks (the querela term: 3 months from learning of the fact, counted from the
case's fraud date).

Tested orderings (tests/test_recovery_plan.py): the largest freezable balance nobody has asked about comes first; a
large freezable USDT balance read on-chain at an issuer that acknowledged (ticket) beats a small unhosted wallet that
moved; Circle on an Italian case is a cross-border move.

## 4. Evidence checklist (design §4.1, lightweight)

Each move lists its requirements — the playbook path's EVIDENCE keys (the target path when the provider wants LE
process), plus the asks read from the reply — and how each is satisfied by **existing objects**, never by reading
content: evidence items by type and folder (police report / complaint receipt, letter of authority — also the sender
profile's authority documents —, ownership proof, comms, a chain report), complaint and LE references on the case, the
latest trace run (its movements CSV is the copyable transaction list), the on-chain readings of the move's wallets, the
addresses the request cites, their ticket, the case summary. States: **on file**, **missing** (with how to get it),
**state it in the letter** (freeze duration, non-disclosure, native vs bridged, urgency, English: only when the
letter behind the move's link writes the sentence — the LE / counsel brief does, every letter is in English; otherwise
the item is missing, "add the sentence"), **from LE / counsel**
(agency identity, letterhead request, court order, seizure warrant, MLAT bundle, the domestic order: Aegis never
drafts one), **on file, failed its integrity check**, **waived**. Below admin, an item of the Financial folder shows as
"on file (restricted)" without its id.

**Waivers**: a case admin (`manage_case`) waives a requirement with a reason (`cases.facts["_evidence_waivers"]`),
audited as `UPDATE` with `op=waive_evidence` and the requirement key only (never the reason); undo is audited too.

## 5. Actions and the LE brief pack

Each move's actions open the prefilled letter on the authority page (`?template=stop_order|info_request|le_cover|
le_brief&ref=…#generate`: investigators draft, a person sends), post to existing forms (the freeze watch, with `next`
back to the plan; the trace run), add wallets to the watch list (`POST /cases/{id}/recovery-plan/watch`,
`poll_watch`), or download the **LE brief pack** (`GET /cases/{id}/recovery-plan/pack/{key}.zip`, investigators:
`view_restricted` + `export`, audited `EXPORT kind=le_brief_pack` with the evidence ids). No `evidence_packs` table:
the pack is built on request from existing export machinery —

* `brief.md`: the LE / counsel brief linked to the request (`meta.follow_up_of`, newest), else a preview rendered now
  and not saved (the LE brief for a request, the LE cover letter for an untouched target);
* `manifest.json` / `manifest.md`: the move, its reasoning and checklist, the evidence items it names plus the Law
  enforcement and Chain reports folders (id, title, folder, type, sha256, size, classification, TLP, collected /
  verified dates, integrity), the trace run, and the sha256 of every file in the pack;
* `movements.csv`: the latest trace run's movements (app.tracing.export);
* `freeze_readings.csv`: the latest on-chain readings of the move's wallets (block, method, raw response sha256).

Evidence originals are not included (the vault keeps them; the manifest names them by id and hash).

## 6. Guardrails

* Advisory: rules only, no AI in the plan. `/recovery-plan` sends the same structured plan to the model for a
  narrative when the case's AI mode allows it (redacted mode by default; reply tickets and URLs become placeholders
  unless "AI reads mailbox replies" is on), with the assistant's usual label and disclaimer.
* A hold, freeze or return counts only once a person confirms it (the secured total); a suggested outcome is a
  *confirm* move.
* Nothing is sent or drafted by the plan; LE-only channels are never offered to us; positive outcomes and LE filing are
  recorded by a person on Block status.
* Roles: read-only members see the plan with LE / PI contacts masked and without draft / watch / pack / waiver
  actions; wallets named in replies only with `view_restricted`; external members do not see it.
