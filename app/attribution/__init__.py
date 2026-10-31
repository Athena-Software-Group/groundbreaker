"""Wallet owner identification: who owns each wallet of a case, how sure Aegis is, and who to ask.

* `service` — the sources (a person's attribution, the trace's entity map, the catalogue, public explorer tags, a
  behaviour profile), how they combine, who to ask with which template, the per-case lookup consent, the runs.
* `explorer` — Blockscout (EVM) and Tronscan (TRON) public tags and activity counters over the allow-listed client.

No request leaves Aegis for a case until a case admin turns "Owner lookups" on for it (docs/wallet-owners.md).
"""
