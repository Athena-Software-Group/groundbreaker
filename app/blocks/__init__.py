"""Block status: what each authority answered to the blocks (stop orders, freeze / preservation
requests and follow-up letters) the case has requested, and what to do next.

* `classify_rules` — the pure, deterministic reply classifier (no I/O).
* `classify_ai` — the optional AI second opinion on a reply (per-case setting "AI reads mailbox
  replies", off by default; advisory only, never changes a stop order).
* `status` — the status engine: one row per case × authority × request, the derived block status,
  the recommended next action and "Confirm status".
* `report` — the Block status page data and the .md / .csv / .docx exports.

Nothing in this package imports the mail transport code: it reads the correspondence and mail rows
the e-mail desk filed and never sends anything (docs/block-status.md).
"""
