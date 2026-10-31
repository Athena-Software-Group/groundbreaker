# Evidence intel: upload → parse → understand → categorise

Owner: the evidence feature. Code: `app/evidence_intel/` (text, rules, findings, ai, service); routes
`app/web/routes_evidence_intel.py`; partial `app/web/templates/evidence_intel_macros.html`; tests
`tests/test_evidence_intel.py`.

## What happens on upload

1. **Upload / reference / note** (`POST /cases/{id}/evidence/upload` and friends) registers the item as before.
2. **Parse** (`text.extract_text`): the text of the file, read by its bytes first (a mislabelled file is read as
   what it is), never executed or rendered:
   * PDF: the text layer (pypdf), at most 60 pages; a scan without a text layer says so;
   * .docx: paragraphs and tables (python-docx); a document that would inflate past 40 MB is refused;
   * .eml (and a .msg that is an RFC 822 message): From / To / Cc / Date / Subject, the plain (else HTML) body, the
     list of attachments (names, types, sizes; their bytes are not opened). A binary Outlook .msg: "save it as .eml";
   * text, CSV, JSON, Markdown; HTML and RTF with the markup removed (scripts, styles, embedded objects dropped);
   * images: **no OCR on this machine**: "no text (image): describe it or attach a text version"; the type is still
     read from the file name and folder.
   Caps: 25 MB read at all, 200,000 characters kept. An item whose bytes no longer match its sha256 is not read.
3. **Store**: an upload's text goes to the vault as `<vault>/text/<case id>/<item sha256>.txt` (0600; its own hash
   recorded). A referenced original is never copied, its text neither: it is read again when the item page shows
   it. The database (`evidence_items.meta["intel"]`) keeps the reading, a 280-character excerpt, the chain
   identifiers, references, dates, amounts and providers the rules found (never an officer's name, e-mail or phone:
   read again from the text when the page shows them) and, when the case consents, the AI's reading (type, verified,
   confidence, model). The AI's quote, summary, parties, dates, amounts and identifiers are document content: they go
   to a vault sidecar `<vault>/text/<case id>/<text sha256>.ai.json` (0600, its hash recorded), never the database
   (a referenced original's are not kept: it is never copied).
4. **Understand** (`rules.classify`): one of the document types below, with the cues that decided it (English,
   Italian, German and French lexicons; the file name counts more; the shape of the text: chat timestamps, an
   e-mail file, an ID document's machine-readable zone, many transaction hashes). Confidence clear / likely / weak.
   Optionally the AI (below) gives a second reading.
5. **Categorise**: the page says "Aegis read this as: <type> → <folder> (reasons)". **Nothing moves by itself**: a
   person confirms (one click) or picks another type. Confirming adds the type as a tag, records its requirement
   keys as explicit matches and files the item in the type's folder (the Financial folder needs a case admin).

| Type | Folder | Requirement keys |
|---|---|---|
| ic3_complaint | Law enforcement / reports | police_report, complaint_ref, ic3_ref |
| police_report (denuncia, querela, Strafanzeige, plainte) | Law enforcement / reports | police_report, complaint_ref |
| le_letter | Law enforcement / reports | — (use "Use evidence #N" on the checklist) |
| court_order / seizure_warrant / freezing_order | Legal | court_order / seizure_warrant / — (the tag opens the instrument gate) |
| trace_report, intelligence_report | Investigator reports | trace_report_run |
| special_proxy / poa / loa | Legal | special_proxy, poa, loa / poa, loa / loa |
| wire_confirmation / bank_statement | Financial | wire_details / ownership_proof, wire_details |
| exchange_statement, account_statement | Financial | ownership_proof |
| kyc_id_document | Financial | victim_id |
| chat_export / email_export | Digital artifacts / messaging, e-mails | comms_export |
| provider_reply | Stop orders & correspondence | — (offer: file it as the reply to the request) |
| invoice / contract / other | Investigator reports / Legal / Other | — |

## Checklists and the instrument gate

* **Nothing a heuristic says is applied by itself.** An unconfirmed reading (the rules',
  or a verified AI reading's) satisfies no requirement: the evidence checklists (Recovery plan, letters) keep the key
  missing (or "from LE / counsel") and show "suggested: police report — confirm" with the item, until a person
  confirms the type on the item page; it never opens the instrument gate. A case admin can still make a match
  explicit with "Use evidence #N" (never for an order).
* A confirmed type is an explicit match. An order (court order, freezing order, seizure warrant) is never offered as
  a one-click confirmation: the form asks for the court's country (US / FR opens Circle's court-order path) and the
  provider it is addressed to (`meta.to`: only that provider's binding path opens), prefilled from the text for a
  person to check.

## Findings and one-click proposals (item page)

Wallets (EVM, TRON, Bitcoin, Solana in a text that mentions Solana), transaction hashes, UIDs / account and order
ids, LE references (Prot. n., R.G.N.R., Aktenzeichen, numéro de procédure, IC3 complaint IDs) and contacts, dates,
amounts and catalogue providers. Each is a proposal a person clicks:

* **Whose wallet?** Aegis never decides it from the text (five rounds of wording rules each read some receipts,
  chats and complaints backwards). Every wallet the document names has no role until a person picks one: the
  victim's, the perpetrator's, an exchange / service, or unknown (`POST /cases/{id}/evidence/{item}/intel/wallet-role`,
  audited with the role and the item, never the address; kept across re-reads). The page shows the cue words next
  to the address as a hint only ('near "From:"', 'near "scammer"');
* **Watch for a freeze** (EVM / TRON wallets not yet watched; `POST /cases/{id}/freeze/watch`): disabled until a
  role is picked, and never for the victim's own wallet;
* **Seed the trace** (disabled until a role is picked: victim → victim wallet, perpetrator → perpetrator wallet
  (else known downstream), exchange / service or unknown → known downstream; only into a seed role that is empty,
  each empty role offered once; the route refuses to replace a seed with `only_empty`). A transaction hash is
  offered as the origin transaction. Nothing is watched or seeded by the pick itself;
* **Add as LE contact** and **Record the complaint reference** (`case.facts["complaints"]`, with the evidence id);
* **File as the reply to stop order #N** (a stop order to a provider the document names): an inbound
  correspondence whose body is the extracted text, so Block status reads it like a mailbox reply. A TLP:RED /
  TLP:AMBER+STRICT item is filed without its text (and the AI context withholds any message filed from one).

Findings, the excerpt and the proposals are shown to members who may open the item's content and see restricted
data (investigators and admins); others see the type and the reasons.

## The Evidence tab

* **Unclassified / suggested**: every visible item without a confirmed type (not read yet, suggested,
  unclassified), with a one-click Confirm (not for orders) and Review. The mailbox's own messages and Aegis trace
  reports stay out of it.
* **Re-read all evidence** (case admins): reads every item again, rules only unless the case consents to the AI
  (at most 25 AI calls per run, and never twice for the same text). It backfills imported items and moves nothing.
  The mailbox's own messages and their attachments are read by the rules only: whether a model reads them is the
  "AI reads mailbox replies" setting's call.
* **AI reads evidence** (per case, off by default): see docs/data-handling.md §6.1.

## AI reading (optional)

`cases.evidence_ai_consent` (migration 0011), a case admin's consent naming the data path and the model; a changed
provider or model stops the calls until an admin confirms again. Mode `off`, the kill switch and TLP:RED /
TLP:AMBER+STRICT items mean no call. The text is redacted in the case's redacted mode: the personal values the case
already holds and any e-mail or phone become placeholders, other personal data in a document is sent; an ID document
or financial record (the rules' reading, or the Financial folder) is not sent at all in that mode. The model returns the type,
a quote, a short summary, parties, dates, amounts and identifiers; each is kept only when it occurs in the text sent
(a type whose quote is not found is "unverified" and never offered as the suggestion). One `AI_QUERY` audit row per
call, no content.

## Audit

`READ_EVIDENCE` (per item: the text status, the type, whether the AI read it; per re-read run: counts), `UPDATE`
with `setting=evidence_type` (the confirmed type, the fields changed, the folder), `UPDATE` with
`setting=complaint_reference_added` (the evidence id only), `UPDATE` with `setting=wallet_role` (the role picked
and the chain, never the address), `CREATE` for a filed reply, `UPDATE` with
`setting=evidence_ai_reading` for the consent. Never text, names or references.
