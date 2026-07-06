# Northstar Goods Storefront

This is the public ecommerce demo workload that judges can visit behind Alibaba WAF. It is separate from the SecAi control plane and does not show SecAi branding or dashboard links.

The storefront is intentionally safe:

- No real accounts, payments, database, or file access.
- Public visitors do not need to sign in; `/login` only exists to generate authentication-failure traffic.
- Suspicious inputs are escaped or rejected.
- Test buttons create browser-snippet evidence and SLS-readable request logs.
- WAF rules are created only from the SecAi dashboard after approval.

## Local Run

Start SecAi first, then run:

```bash
SECAI_PUBLIC_BASE_URL=http://localhost:8000 \
SECAI_SITE_ID=demo-site \
uvicorn protected_site.app:app --reload --port 9000
```

Allow the storefront origin in SecAi:

```bash
SECAI_EXTRA_CORS_ORIGINS=http://localhost:9000
```

Open:

- Storefront: http://localhost:9000
- Traffic test panel: http://localhost:9000/attack-lab

## Alibaba Cloud Run

Build from the repository root:

```bash
docker build -f protected_site/Dockerfile -t secai-protected-shop .
```

Run it behind Alibaba WAF with:

```bash
SECAI_PUBLIC_BASE_URL=https://your-secai-api.example.com
SECAI_SITE_ID=site_from_secai_dashboard
```

Enable Alibaba log collection for stdout/container access logs and ship them to the same SLS project and logstore configured in SecAi Autopilot.

## Judge Flow

1. Visit the storefront through the WAF domain.
2. Open `/attack-lab`, labeled as the traffic test panel.
3. Run SQL injection, path traversal, login burst, and error spike tests.
4. Open SecAi dashboard with the shared demo login.
5. Click **Check Autopilot logs**.
6. Review generated incidents and approve a WAF-backed action.
7. Confirm the policy becomes `active` with an Alibaba WAF provider rule ID.
8. Reject/remove the action after proof to roll back the WAF rule.
