# Sample stop orders

These are sample preservation, freeze and blacklist requests ("stop orders") that Aegis generated
from the fictional demo case **DEMO-2026-001**. They show what the stop-order desk produces. They are
not letters to send.

- **The case is fictional.** The victim (*Jordan Avery*, *Northbridge Analytics, Inc.*), the
  impersonated company (*Exempla Holding AG*), the investigator (*Kestrel Ridge Investigations GmbH*),
  the law-enforcement references (`DEMO-IT-0000000000`, `IC3-DEMO-00000000`) and the swap-order
  reference are made up. Every e-mail domain is a reserved `.example` domain, and no individual's
  mailbox appears. Services such as exchanges, issuers and hosts are named as organisations only.
- **This is not legal advice.** A qualified investigator or lawyer must review any letter built
  from this template for the facts, jurisdiction, recipient and channel before it is used. Each
  recipient's current law-enforcement request portal and requirements must be checked as well.

Aegis — powered by Athena Software Group, Inc. (release: GroundBreaker).

## Letters

| File | Recipient | Request | Why |
|---|---|---|---|
| `stop-orders/01-circle-blacklist` | Circle (USDC issuer) | Check balance and blacklist | The loss asset was USDC. `0x57de…` received it on-chain (its onward hops are asserted only), and `0xe944…` is the perpetrator-controlled wallet it was relayed to before the USDC→ETH swap. |
| `stop-orders/02-tether-blacklist` | Tether (USDT issuer) | Check balance and blacklist | 1,359.899028 USDT is still at `TWdZZhGv…L77` (SWFT payout). It is upstream of an asserted hop, so the letter says *suspected*. |
| `stop-orders/03-rainbet-freeze` | Rainbet | Risk-control hold and preservation | Deposit address `0x74e6…` is asserted only. Nothing is cited as a transaction, so the letter says *suspected*. |
| `stop-orders/04-kucoin-freeze` | KuCoin | Risk-control hold and preservation | Observed deposit `0x580d…` to `0x0a17…`, swept to *KuCoin 17*. The account had deposits before the fraud (asserted). |
| `stop-orders/05-swft-bridgers-preservation` | SWFT / Bridgers | Preserve order records | Two observed swap orders (ETH → USDT-TRON, ETH → BTC). Their link to the victim's funds is asserted. |

Each letter comes as Markdown (`.md`, the stored body) and as Word (`.docx`, the export). The
`.docx` metadata is neutral: author *Aegis*, title set to the subject line.

### What the generator guarantees

- Every letter names the victim's origin transfer `0x70ab…a814` and the perpetrators'
  **first-recipient wallet `0x57de1021A507d46272d386995d5B58667Ac1F8df`**. That wallet is the true
  root, not the distribution hub `0x5445…`.
- **Asserted links are never stated as fact.** A hop that has not been observed on-chain is
  marked *asserted* and described, never cited by hash. A recipient reachable only through such
  a hop gets a *suspected* subject line and a caveat on the amounts.
- **There is one letter per counterparty.** An issuer gets a single letter, even when one of its
  own addresses is on the path. Regenerating supersedes the earlier drafts.
- **Non-custodial protocols get no letter.** The Uniswap Universal Router can neither freeze nor
  preserve anything. The trace follows the swap output instead: the USDT from the 16 Oct swap goes
  to Tether once its destination is resolved.
- The authority instrument the letters cite is the case's own (the sender of record's *Letter of
  Authorisation* here).

### Known gaps in this sample

- The relay hops `0x57de → 0x3007 → 0x0d0b → 0xba02 → 0xe944` are modelled with known amounts and
  *pending* hashes, so their own on-chain verification is still to come.
- The Circle letter lists `0x57de…` (observed USDC arrival, onward hop asserted) and `0xe944…`
  (swapped out of USDC; any remainder unconfirmed). The three relay wallets between them are left
  out: both their USDC arrival and departure are asserted, with known amounts.
- KuCoin and SWFT have no compliance mailbox in the demo case. The recipient is left blank, to be
  routed through the entity's law-enforcement request portal.

## Regenerating

The default `TRACE_MAX_HOPS=12` reaches the KuCoin deposit (hop 9; the true root sits five relay
hops before the hub). Keep the database outside the repository. The samples are signed by the
demo case's sender of record, so set its organisation and signatory; owner lookups stay off, so the
run makes no network call.

```bash
export DATABASE_URL=sqlite:////tmp/aegis-samples.db PROVIDER_MODE=fixture AEGIS_OWNER_LOOKUPS_AUTO=0
export AEGIS_ORG_NAME="Athena Software Group, Inc." AEGIS_SIGNATORY_NAME="Athena Investigations"
alembic upgrade head
python -m scripts.seed_case            # demo fixture data/fixtures/demo_case.json
python -m scripts.sample_stop_orders   # rewrites docs/samples/stop-orders/
AEGIS_DENYLIST=/path/outside/repo/denylist.txt python scripts/pii_scan.py
```

`scripts/sample_stop_orders.py` refuses to export any case whose reference does not start with
`DEMO-`. Any other case seeded into the same database therefore cannot end up in this folder.
