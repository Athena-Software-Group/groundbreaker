# Security policy

Aegis (GroundBreaker) — powered by Athena Software Group, Inc.

## Reporting a vulnerability

**Report privately to the maintainers (Athena Software Group, Inc.) through GitHub private
vulnerability reporting**: open the repository's **Security** tab and choose **Report a
vulnerability**. Do not open a public issue, pull request or discussion for a security problem.

Please include:

* what is affected (file, route, component) and the impact;
* steps to reproduce, using the **demo case or synthetic data only**;
* any suggested fix.

**Never include real case data** in a report: victim or investigator details, complaint references,
evidence, or wallet labels from a live investigation. If the issue is that real data is exposed,
say where it is without quoting it. docs/data-handling.md §8 has the incident procedure.

We aim to acknowledge reports within 3 business days and to agree a fix timeline after triage.

## Scope

* Application code in `app/`, `scripts/`, migrations and deployment configuration.
* Especially: authentication and session handling, case-level access control, injection or XSS in
  generated letters and views, path traversal in exports, secret or PII leakage in logs and
  notifications, and live-provider egress that a user did not authorise.

Third-party services (block explorers, exchanges, issuers) are out of scope. Report issues with
them to the respective vendor.

## Supported versions

Only the latest commit on the default branch is supported while the project is pre-release.

## Handling secrets

* Secrets live in `.env` locally (git-ignored) and in AWS Secrets Manager when hosted. Never in code,
  the image or CI logs.
* Before every commit, run `scripts/pii_scan.py` (with your out-of-repo denylist when you work with real case data) and
  gitleaks (pre-commit). CI repeats the generic checks.
* If a secret is committed, rotate it first, then purge it from history (docs/data-handling.md §8).
