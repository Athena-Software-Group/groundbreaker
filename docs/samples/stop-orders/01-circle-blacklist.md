**Stop order #7** · case DEMO-2026-001 · status draft · generated
**To:** compliance@circle-demo.example
**Sent:** not sent (draft)

---

**Subject:** Urgent Preservation & Risk-Control Request – Blacklist request: address(es) that received fraud proceeds in USDC

Dear Compliance / Legal Team,

We write as Athena Software Group, Inc., on behalf of Northbridge Analytics, Inc. (Jordan Avery), USA, acting under the victim's Letter of Authorisation (attached). The victim lost approximately USD 399,247.92 (399,247.92 USDC) in a cryptocurrency investment fraud on 12 October 2026 that impersonated Exempla Holding AG (UID CHE-000.000.000, Musterstrasse 1, 0000 Musterstadt, Switzerland). The perpetrators operated under the persona "Adrian Example, CFO" via exempla-holding.example.

According to the victim's own transaction records, the funds left the victim's wallet `0x7AC32c88e5489B4c406fFc1d6B835f4EBa7B455b` in transaction `0x70abbe14aa9080b572aa69881536e5c165097c0574c4791467e915b708bba814` on 12.10.2026 10:49:47 UTC (**399,247.92 USDC**) and went to `0x57de1021A507d46272d386995d5B58667Ac1F8df`, the perpetrators' first-recipient wallet. From there the funds were moved on through further wallets. The transaction hashes of some intermediate hops are still being verified on-chain and will be supplied in the forensic report; anything marked *asserted* below is not yet observed on-chain and is described, not cited.

The matter has been reported to law enforcement: Carabinieri — Demo City station (demo), reference **DEMO-IT-0000000000** (filed 14.10.2026); FBI Internet Crime Complaint Center (IC3), reference **IC3-DEMO-00000000**.

A formal law-enforcement request will follow. Until then we ask you to **freeze or place a risk-control hold on** the records and assets described below. We are not asking for disclosure; any disclosure should follow formal legal process.

### 1. Identifiers linked to your service

- **Perpetrator-controlled address:** `0x57de1021a507d46272d386995d5b58667ac1f8df` (Ethereum) — Perpetrator first-receiving wallet — true root (reached via a perpetrator-registered ENS lure name)
  - Inbound: `0x70abbe14aa9080b572aa69881536e5c165097c0574c4791467e915b708bba814`, 12.10.2026 10:49:47 UTC, **399,247.92 USDC** (≈ USD 399,247.92), from `0x7ac32c88e5489b4c406ffc1d6b835f4eba7b455b`
  - *Asserted* onward (transaction hash pending on-chain verification): 399,247.92 USDC to `0x300762e2ba1fdb1fc02ed4e4fcee0d6b93d51fb4` (Perpetrator relay #1 (USDC 0x57de→0x0d0b); later also received hub outflow #1 (1.10 ETH)). Please check the current balance.
- **Perpetrator-controlled address:** `0xe9449ba33c8dcf6f859c9bc476b8debab64a4b1b` (Ethereum) — Perpetrator swap wallet — executed Uniswap USDC->ETH, then funded the hub with 156.611 ETH
  - *Asserted* inbound (transaction hash pending on-chain verification): 399,247.92 USDC from `0xba02b694e55f603fdfbb6e89abd5bafaf02246b5` (Perpetrator relay #3 (USDC 0x0d0b→0xe944)).
  - Onward: `0x9c91f8f5e567da86089791d12d3649dd6ce66bd49fe717db39acf9c2da79cb68`, 12.10.2026 11:09:59 UTC, 156.61134813 ETH to `0x54453e25e38b11009963361a123bde2b4457becb` (Distribution hub (156.611 ETH in, split within 90 min))
  - Funds were forwarded 2 minutes after arrival.

All of the above comes from passive public blockchain observation and from the victim's own transaction records; items marked *asserted* come from our investigative analysis and are pending on-chain confirmation. We have not logged into, queried or otherwise accessed any account, wallet or API.

### 2. Records requested to be frozen / preserved for a minimum of 180 days or until legal process is received

- Current balance of the token at the identified address(es).
- Blacklist / freeze of the identified address(es) pending law-enforcement process.
- Any prior compliance actions or reports concerning the identified address(es).
- Any linked accounts sharing the same KYC, device, IP, phone, email or withdrawal address.
- For every account, project or service linked to the identifiers above.

### 3. Requested action

We ask that the balances associated with the identifiers above be placed under an immediate risk-control hold pending formal process, and that the account holder **not be notified**, as this could lead to the movement of funds and the destruction of evidence.

We are a private party and cannot compel disclosure. Formal legal process, or a request through the competent criminal authorities, will follow. Please tell us your preferred channel and requirements for the formal law-enforcement request.

We can supply supporting evidence on request. Please contact the undersigned, the single point of contact for this matter.

Attached / to follow:

- Letter of Authorisation (the victim's authorisation of Athena Software Group, Inc.)
- Forensic report on the fund flow (Aegis trace #1)
- Law-enforcement complaint references

Yours faithfully,

Athena Investigations

Athena Software Group, Inc., on behalf of Northbridge Analytics, Inc. (Jordan Avery)

Cc: victim@northbridge.example


* * *

*Generated by Aegis on 31.10.2026 20:49 UTC from trace run #1 for case DEMO-2026-001. USD figures marked ≈ use reference prices. Links that are asserted but not yet observed on-chain are described, not cited.*