# Aegis on AWS — target architecture

Goal: same container, hosted privately, behind a firewall and a WAF, with scheduled watch polling.

```
Internet ──▶ Route 53 ──▶ CloudFront (optional) ──▶ AWS WAF ──▶ ALB (HTTPS, Cognito auth)
                                                                    │
                                                 ┌──────────────────┴──────────────────┐
                                                 │ VPC  (private subnets, no public IPs)│
                                                 │  ECS Fargate service  (aegis app)  │
                                                 │  ECS scheduled task   (watch poller) │
                                                 │  RDS PostgreSQL 16 (Multi-AZ, KMS)   │
                                                 │  Secrets Manager (DB url, API keys)  │
                                                 │  S3 (exports/, evidence packs)       │
                                                 │  NAT GW + egress allow-list          │
                                                 └──────────────────────────────────────┘
```

## Components

| Layer | Service | Notes |
|---|---|---|
| Edge | **AWS WAF** on the ALB | AWSManagedRulesCommonRuleSet, KnownBadInputs, SQLi, IP reputation, rate-limit rule (e.g. 300 req/5 min/IP). Geo-restrict to the countries your analysts work from. |
| Auth | **ALB + Cognito** (or your IdP via OIDC) | Authenticate at the load balancer; the task only accepts traffic from the ALB security group. Map the verified OIDC subject to a `users` row (docs/identity-spec.md §9); until then the app's own per-user sign-in (`app/core/security.py`) stays on as defence in depth. |
| Compute | **ECS Fargate** | 1 service (0.5 vCPU / 1 GB is plenty for the demo), rolling deploys, `/healthz` for target-group checks. Image from ECR built by CodeBuild / GitHub Actions. The image runs uvicorn with `--proxy-headers`; set `FORWARDED_ALLOW_IPS` to the ALB subnet CIDRs in the task definition so the login rate limiter (per client IP, and per account + client IP) and the audit log see the real client address instead of the ALB's. |
| Scheduler | **EventBridge → ECS RunTask** | Every 5 min: `python -m scripts.run_scheduler --once` (watch-list poll with notifications for every open case, the overdue-reply check of the authorities desk, and with `AEGIS_MAIL_INBOUND=on` one read of the case mailbox plus the e-mail desk's housekeeping: expiring stale prepared e-mails and reconciling sends whose outcome is unknown). Outside AWS the same script loops by itself (`--interval 5`). Notifications go out by SMTP (`SMTP_*`, e.g. SES SMTP) and Slack (`SLACK_WEBHOOK_URL`). |
| Database | **RDS PostgreSQL 16** | Multi-AZ, KMS-encrypted, automated backups 7–35 d, deletion protection. Credentials in Secrets Manager injected as `DATABASE_URL`. Run `alembic upgrade head` as a one-off task on deploy. |
| Secrets | **Secrets Manager / SSM** | `ETHERSCAN_API_KEY`, `TRONGRID_API_KEY`, `APP_SECRET_KEY`, `SMTP_PASSWORD`, `SLACK_WEBHOOK_URL`, `HF_INFERENCE_TOKEN` (only when the case assistant is enabled; inference-only, never `HF_API_KEY`), `AEGIS_M365_CLIENT_SECRET` (only with the Microsoft 365 e-mail desk; record its expiry and rotate it before then, docs/m365-setup.md). Never in the image. `AEGIS_DEV_LOGIN_TOKEN` is never set outside APP_ENV=local. |
| Egress | **NAT Gateway + Network Firewall** (or proxy) | Allow-list: `api.etherscan.io`, `eth.blockscout.com`, `arbitrum.blockscout.com`, `base.blockscout.com`, `polygon.blockscout.com` (Blockscout, the keyless default EVM source), `api.trongrid.io`, `mempool.space`, price API; the SMTP relay and `hooks.slack.com` when those channels are configured; `router.huggingface.co` (or the dedicated `*.endpoints.huggingface.cloud` host) only when the case assistant is enabled (a per-deployment decision, and per case through its AI mode, docs/data-handling.md §6). `login.microsoftonline.com` and `graph.microsoft.com` (HTTPS only) when the e-mail desk uses Microsoft 365 (`AEGIS_MAIL_TRANSPORT=graph`, docs/m365-setup.md); the app refuses any other Graph or login host. Everything else is denied; the app has no other outbound needs (JS is vendored). Live lookups for a real case are a per-case decision (docs/data-handling.md §6). |
| Storage | **S3** | `.docx` exports, the evidence vault (`AEGIS_VAULT_DIR` becomes an S3 prefix once the storage adapter lands; today it is a path on an encrypted EFS / EBS volume, with `TMPDIR` on the same volume) and future evidence packs. SSE-KMS (per-case data keys), Block Public Access, a bucket policy limited to the task role and the VPC endpoint, and Object Lock for anything filed with LE. |
| Mail | **Microsoft 365 shared mailbox via Graph** | One shared case mailbox (`AEGIS_MAIL_FROM`), an Entra app with Mail.Send + Mail.ReadWrite application permissions restricted to that mailbox by an Exchange application access policy (docs/m365-setup.md). Inject `AEGIS_M365_TENANT_ID`, `AEGIS_M365_CLIENT_ID` as plain task environment and `AEGIS_M365_CLIENT_SECRET` from Secrets Manager. The scheduled task reads replies (`AEGIS_MAIL_INBOUND=on`); the raw .eml files sit in the evidence vault until filed. The mailbox itself is an R3 store (docs/data-handling.md §6.3). Never use the `file` transport outside a local machine. |
| Observability | CloudWatch Logs + Container Insights | Structured logs already go to stdout. Add an alarm on 5xx rate and on poller failures. |

## Infrastructure-as-code sketch (Terraform modules to create)

```
infra/
  network/      vpc, private/public subnets, nat, network firewall / egress rules
  data/         rds, secrets
  app/          ecr, ecs cluster/service/task, alb, target group, acm cert, waf web acl
  scheduler/    eventbridge rule → run-task, sns topic
```

## Deploy flow

1. `docker build -t aegis:$SHA .` → push to ECR.
2. One-off ECS task: `alembic upgrade head`.
3. Update service task definition → rolling deploy; ALB health check on `/healthz`.
4. (Optional, non-production environments only) one-off task `python -m scripts.seed_case` to load the fictional demo case `DEMO-2026-001`. **Never seed a real case from the image or the repo.** Real cases are imported from the evidence store by an authorised user. The image must contain only the demo fixture. `.dockerignore` keeps `.env`, exports and stray case files out of the `COPY . .` build context; keep it in step with `.gitignore` (docs/data-handling.md).

## Data residency (GDPR / Swiss FADP)

Cases routinely involve EU and Swiss parties: police complaints, investigators, impersonated
companies. They also involve data about alleged criminal offences (GDPR Art. 10).

* **Region:** deploy in an EU region (e.g. `eu-central-1` Frankfurt or `eu-central-2` Zurich), not
  `us-east-1`. Keep RDS, S3, backups, logs and KMS keys in that region. Disable cross-region replication
  unless it targets another EU region.
* **Before a hosted multi-user pilot:** a DPIA, a record of processing activities, controller/processor
  roles for each party, DPAs with AWS and any sub-processors, and a transfer assessment for any US
  access (EU-US Data Privacy Framework or SCCs; the Swiss-US DPF for Swiss data).
* **No case data in non-EU services** (US-only SaaS, LLM APIs, OCR) without a DPA and a transfer basis.
* **Logs:** CloudWatch log groups hold IDs only (docs/data-handling.md §1). Set retention explicitly.
* The cost estimate below is for us-east-1. EU regions cost about 10–20 % more.

## Cost (rough, us-east-1)

Fargate 0.5 vCPU/1 GB ≈ $15/mo · RDS db.t4g.micro Multi-AZ ≈ $30/mo · ALB ≈ $20/mo · NAT ≈ $35/mo · WAF ≈ $10/mo → **≈ $110/mo** before data transfer.

## Hardening checklist

- [ ] WAF logging to S3/CloudWatch; review blocked requests weekly
- [ ] ALB access logs on
- [ ] RDS: `rds.force_ssl=1`, IAM auth optional
- [ ] Task role: least privilege (Secrets read, S3 bucket RW, SNS publish)
- [ ] GuardDuty + Security Hub enabled on the account
- [ ] Config rule: no public RDS, no 0.0.0.0/0 ingress except ALB 443
- [ ] Rotate provider API keys quarterly
