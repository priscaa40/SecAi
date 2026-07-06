# SecAi

SecAi is a Qwen Cloud-powered security incident autopilot for everyday website owners and small teams. It is designed for the Qwen Cloud Hackathon Track 4: Autopilot Agent.

SecAi runs as a hosted control plane on Alibaba Cloud. Everyday website owners can start with a browser snippet or connect Alibaba Autopilot, which uses Simple Log Service as the evidence layer and Alibaba WAF as the enforcement layer. The agent analyzes suspicious activity, creates a plain-language incident report, alerts the user, uses the owner's approval settings, and applies Alibaba WAF rules when Autopilot is active.

## Why This Fits Track 4

Track 4 asks for an agent that automates real-world business workflows end-to-end, handles ambiguous inputs, invokes external tools, and uses human-in-the-loop checkpoints. SecAi does that for small-team security operations:

1. Ingest suspicious web app activity from the browser snippet or Alibaba Autopilot's SLS evidence source.
2. Triage and investigate with Qwen Cloud.
3. Generate a readable incident report.
4. Alert the site owner.
5. Use the owner's approval checkpoint for the recommended action.
6. Apply approved or owner-preapproved Alibaba WAF remediation rules and audit whether they became active or failed.

## MVP Features

- Focused ingest:
  - Browser snippet for non-technical website owners.
  - Alibaba Autopilot SLS evidence for sites hosted on Alibaba Cloud.
  - Demo attack simulator for judging and local testing.
- Public `protected_site/` demo workload that judges can visit behind Alibaba WAF.
- FastAPI JSON API plus a dedicated static frontend in `frontend/`.
- SQLite persistence for local MVP development.
- Qwen Cloud / Model Studio agents built with LangChain `create_agent`. `DASHSCOPE_API_KEY` is required; SecAi does not run incident analysis without Qwen configured.
- Official-source security knowledge tools that bound agent classifications and remediation to CAPEC, CWE, OWASP, NIST, and OSV/NVD-backed profiles, with live NVD/OSV enrichment when events mention CVEs, CWEs, packages, frameworks, or dependencies.
- Discord report and approval channel.
- Owner-controlled approval defaults before remediation.
- Approval links from the frontend or Discord.
- Policy endpoint for approved remediation records and provider execution status.
- Alibaba Autopilot SLS ingest.
- Alibaba Autopilot setup for WAF-backed actions such as IP blocks, route rate limits, challenges, anti-scan rules, and virtual patches.

## Repository Map

- `secai/agent/` - the Track 4 Qwen agent workflow: triage, supervision, investigation, reporting, remediation, jobs, tools, and guardrails.
- `secai/event_sources/` - browser snippet events, Alibaba SLS log evidence, demo scenarios, normalization, and relevance filtering.
- `secai/dashboard_api/` - FastAPI routes that power setup, incidents, approvals, site settings, ingest, and Qwen usage views.
- `secai/actions/` - incident approval/rejection and remediation policy execution.
- `secai/integrations/` - Qwen Cloud, Alibaba WAF/Autopilot, and Discord integrations.
- `secai/knowledge/` - source-backed security profiles and the MCP stdio server for agent tools.
- `secai/database/` - persistence and encrypted storage helpers.
- `secai/models/` - shared Pydantic models and action constants.
- `secai/settings/` - environment settings and per-agent Qwen model selection.
- `protected_site/` - separate safe storefront used as the public Alibaba WAF test workload.

## Quick Start

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

In another terminal, serve the frontend:

```bash
python -m http.server 5173 --directory frontend
```

Open:

- Frontend: http://localhost:5173
- API docs: http://localhost:8000/docs

Run a demo attack:

```bash
curl -X POST "http://localhost:8000/api/demo/simulate?attack=sql_injection"
```

Then refresh the frontend and approve the recommended remediation as `owner@example.com`.

To test the public workload through a browser, allow the shop origin in the SecAi API and run the separate protected site:

```bash
SECAI_EXTRA_CORS_ORIGINS=http://localhost:9000 uvicorn main:app --reload
```

```bash
SECAI_PUBLIC_BASE_URL=http://localhost:8000 \
SECAI_SITE_ID=demo-site \
uvicorn protected_site.app:app --reload --port 9000
```

Open http://localhost:9000/attack-lab and use the buttons/forms instead of `curl`. The public storefront is branded as Northstar Goods, does not show SecAi dashboard links, and emits browser-snippet events plus JSON access logs while keeping all attack payloads inert.

## Environment Variables

```bash
DASHSCOPE_API_KEY=your_qwen_model_studio_key
QWEN_WORKSPACE_ID=your_model_studio_workspace_id
QWEN_REGION=ap-southeast-1
QWEN_MODEL=qwen-plus
QWEN_TRIAGE_MODEL=qwen3.5-flash
QWEN_SUPERVISOR_MODEL=qwen3.5-flash
QWEN_INVESTIGATOR_MODEL=qwen-plus
QWEN_REPORTER_MODEL=qwen-plus
QWEN_REMEDIATION_MODEL=qwen-plus
QWEN_ENABLE_THINKING=false
QWEN_MAX_OUTPUT_TOKENS=900
QWEN_TIMEOUT_SECONDS=45
QWEN_MAX_RETRIES=2
SECAI_ANALYSIS_MODE=sync
SECAI_SECRET_KEY=change_me_to_a_long_random_secret
SECURITY_KNOWLEDGE_TIMEOUT_SECONDS=8
SECAI_ALIBABA_PRINCIPAL_ARN=acs:ram::<account-id>:role/<secai-runtime-role>
PUBLIC_BASE_URL=http://localhost:8000
FRONTEND_BASE_URL=http://localhost:5173
SECAI_EXTRA_CORS_ORIGINS=http://localhost:9000
DATABASE_URL=sqlite:///./secai.db
```

`DASHSCOPE_API_KEY` is required. SecAi intentionally fails fast without it so the hackathon demo and deployed product remain genuinely Qwen-backed.

Set `QWEN_BASE_URL` only when you need an explicit endpoint override. Otherwise SecAi resolves the Alibaba Model Studio endpoint from `QWEN_WORKSPACE_ID` and `QWEN_REGION`.

Set `SECAI_ANALYSIS_MODE=background` for production-style event ingestion where the API stores events immediately and an analysis job runs the Qwen agent workflow in the background. The dashboard and `GET /api/analysis-jobs/{job_id}` show progress.

Website owners create an account only when they choose dashboard reports. Owner-facing dashboard API routes use `Authorization: Bearer <session_token>`, and each owner only sees websites and incidents attached to their account. Discord-only setup does not require a dashboard account.

`SECAI_SECRET_KEY` is required before saving private setup details because SecAi encrypts sensitive per-site connection data before storing it.

For Alibaba Cloud log connections, SecAi uses the website owner's RAM role and STS temporary credentials. When SecAi runs on Alibaba Cloud, prefer an Alibaba runtime identity such as an ECS/FC/ACK RAM role, OIDC role, or credentials URI so the Alibaba SDK can obtain temporary credentials without a long-lived AccessKey. The runtime identity should only be able to call `sts:AssumeRole` on the SecAi-created connector roles.

Set `SECAI_ALIBABA_ACCOUNT_ID` or `SECAI_ALIBABA_PRINCIPAL_ARN` so the dashboard can generate a customer-side RAM/ROS connector template that trusts the SecAi deployment with the per-site External ID.

`APP_RAM_USER_AK_ID` and `APP_RAM_USER_AK_SECRET` remain supported only for local or off-Alibaba deployments that cannot use Alibaba's temporary-credential providers. Store them only in `.env` or deployment secrets; do not share them in chat, docs, tickets, or screenshots.

## Browser Snippet

Create a site in the dashboard, then paste the generated script tag into the website pages you want SecAi to monitor:

```html
<script src="http://localhost:8000/api/integrations/browser.js?site_id=demo-site"></script>
```

The snippet can report suspicious page URLs, query strings, JavaScript errors, form submissions, repeated fast submits, and other browser-observable abuse signals.

If the monitored site is hosted on a different origin from the SecAi API, add that origin to `SECAI_EXTRA_CORS_ORIGINS` so browser snippet POSTs to `/api/events` pass CORS preflight.

## Storefront Demo

`protected_site/` is a separate FastAPI ecommerce storefront branded as Northstar Goods. It has public pages for products, login, download, checkout, contact, and `/attack-lab`.

The attack lab safely generates evidence for:

- SQL injection-looking search text.
- XSS-looking contact text that is escaped before rendering.
- Path traversal-looking downloads that return `403`.
- Login failure bursts that return `401`.
- Contact spam, browser error spikes, bot-like click bursts, and controlled checkout `500` responses.

Every request writes JSON access logs with SLS-friendly fields such as `method`, `path`, `query`, `status_code`, `ip`, `user_agent`, and `message`. In Alibaba Cloud, host this workload behind Alibaba WAF, send its logs to SLS, and connect the same SLS project/logstore in SecAi Autopilot.

## Alibaba Autopilot Log Evidence

For sites deployed on Alibaba Cloud, Autopilot can include Simple Log Service so SecAi can analyze server-side request logs. This is an evidence source inside Autopilot, not an enforcement layer. The website owner gives SecAi a role ARN and external ID, not permanent AccessKeys:

```http
PUT /api/sites/{site_id}/alibaba-sls
Authorization: Bearer <session_token>
Content-Type: application/json

{
  "endpoint": "ap-southeast-1.log.aliyuncs.com",
  "project": "my-website-logs",
  "logstore": "access-logs",
  "role_arn": "acs:ram::123456789:role/secai-log-reader",
  "external_id": "secai-generated-external-id"
}
```

Then check recent logs from the dashboard or API:

```http
POST /api/sites/{site_id}/alibaba-sls/pull
Authorization: Bearer <session_token>

{"query": "*", "minutes": 15, "limit": 100}
```

Repeated Alibaba SLS pulls are idempotent: SecAi fingerprints SLS source records, skips duplicates, and only creates analysis jobs for newly stored events.

## Alibaba Autopilot Connect

Alibaba Autopilot is the no-code enforcement path. The dashboard generates an Alibaba RAM/ROS connector template with a per-site External ID. The website owner enters their WAF instance ID, creates the role in Alibaba Cloud, and pastes the resulting role ARN into SecAi. SecAi then creates its own WAF defense template automatically.

Generate the connector template. Include the WAF instance and SLS log source fields when you want the ROS template to grant those permissions and echo those values back:

```http
GET /api/setup/alibaba-autopilot-template?external_id=secai-generated-external-id&region=ap-southeast-1&waf_instance_id=waf_v2_public_xxx&sls_project=my-website-logs&sls_logstore=access-logs
```

Connect the role first:

```http
PUT /api/sites/{site_id}/alibaba-autopilot
Authorization: Bearer <session_token>
Content-Type: application/json

{
  "role_arn": "acs:ram::123456789:role/secai-autopilot",
  "external_id": "secai-generated-external-id",
  "region": "ap-southeast-1",
  "enforcement_mode": "observe_only"
}
```

Add WAF details to enable approved or owner-preapproved remediation rules:

```json
{
  "role_arn": "acs:ram::123456789:role/secai-autopilot",
  "region": "ap-southeast-1",
  "enforcement_mode": "waf_enforced",
  "waf_instance_id": "waf_v2_public_xxx",
  "waf_domain": "www.example.com"
}
```

The customer never provides a WAF template ID. SecAi creates or reuses a WAF custom ACL defense template named `SecAi Autopilot` inside the saved WAF instance and stores Alibaba's generated ID internally.

SLS uses the same connector template pattern. When the owner enters a Log Service project and logstore before downloading the ROS template, the generated RAM policy is scoped to that project/logstore and the template outputs `SlsEndpoint`, `SlsProject`, and `SlsLogstore` for SecAi setup.

Check the installation state:

```http
GET /api/sites/{site_id}/autopilot-status
Authorization: Bearer <session_token>
```

`observe_only` means SecAi can report but cannot enforce. `waf_enforced` means owner-approved or owner-preapproved WAF actions are applied through Alibaba WAF and policies become `active` only after the provider call succeeds.

## Alibaba Cloud Deployment

For the hackathon submission, deploy `main:app` on Alibaba Cloud using Function Compute, Elastic Compute Service, or Container Service. Configure Qwen Cloud / Model Studio environment variables so `secai/integrations/qwen_cloud.py` calls the Qwen OpenAI-compatible endpoint.

Deploy `protected_site/` as a second container or service behind Alibaba WAF:

```bash
docker build -f protected_site/Dockerfile -t secai-protected-shop .
```

Set `SECAI_PUBLIC_BASE_URL` to the deployed SecAi API URL and `SECAI_SITE_ID` to the site created in SecAi. Set the SecAi API's `SECAI_EXTRA_CORS_ORIGINS` to the storefront domain, for example `https://shop.example.com`.

See:

- `Dockerfile`
- `deploy/alibaba_cloud.py`
- `deploy/alibaba_cloud.md`

The deployment proof script prints the resolved Qwen Model Studio endpoint.

## Agent Architecture

SecAi does not hardcode attack classification. Python normalizes events, exposes tools, and enforces safety guardrails. Qwen-powered LangChain agents decide:

- whether an event should become an incident
- attack type
- severity
- confidence
- investigation summary
- incident report
- remediation recommendation

The agent graph in `secai/agent/workflow.py` uses `triage_agent`, `supervisor_agent`, `investigator_agent`, `reporter_agent`, and `remediation_agent`. Browser and Alibaba SLS `signals` are evidence hints only, not final classifications. When a site has Alibaba SLS connected, the investigator can pull fresh security-relevant SLS events during investigation instead of relying only on events already stored in SecAi. Those live SLS pulls are persisted back into the normalized event store, so the database remains the source of truth for SecAi's workflow while SLS remains the raw evidence source.

The agents are constrained by a single source-backed security knowledge tool implementation derived from CAPEC, CWE, OWASP Automated Threats, OWASP Cheat Sheets, NIST/NVD, and OSV guidance. The investigator can query NVD and OSV live for current vulnerability context. Agent output is rejected if it uses an unknown security profile, missing source IDs, invented attack type, or remediation action that is not allowed for the selected security profile.

Internal agents call the security knowledge contract through SecAi's MCP stdio client, so the same tool boundary is used by the dashboard workflow and by external agents:

```bash
python -m secai.knowledge.security_knowledge
```

Available MCP tools include `list_security_profiles`, `lookup_security_profile`, `find_matching_security_profiles`, `get_remediation_options`, `search_nvd_vulnerabilities`, and `query_osv_package_vulnerabilities`.

## Qwen Usage Tracking

SecAi records Qwen usage and latency per agent call. Inspect local aggregates at:

```http
GET /api/qwen/usage
Authorization: Bearer <session_token>
```

Tracked fields include agent name, model, input tokens, output tokens, total tokens, latency, and estimated cost.

## Human Approval Channels

SecAi defaults to recording remediation as an approval request before applying policy changes. During setup, users choose where reports and approvals go:

- Website dashboard.
- Discord buttons.

Discord uses secure approval links backed by incident approval tokens, so users can approve or reject from a confirmation page without a dashboard account.

By default, every remediation action requires approval. A site owner can explicitly allow any validated action to run automatically:

```http
PUT /api/sites/{site_id}/remediation-preferences
Authorization: Bearer <session_token>
Content-Type: application/json

{"action": "block_ip", "requires_approval": false}
```

If no preference exists for an action, SecAi waits for approval. If the owner preapproves a WAF-backed action such as `block_ip`, `block_ip_range`, `rate_limit_ip`, `rate_limit_route`, `block_payload_pattern`, `virtual_patch`, `read_only_route`, `challenge_route`, `enable_anti_scan`, or `disable_route`, SecAi can execute it automatically after the agent output passes security-profile validation and the site is in `waf_enforced` mode.

If an owner rejects an already applied WAF action from the dashboard, SecAi deletes the SecAi-managed Alibaba WAF rule and marks the policy `expired` only after the provider delete call succeeds.

## Alibaba Cloud Integrations

SecAi supports non-Alibaba websites through the browser snippet. Alibaba-native users connect Alibaba Autopilot, with Simple Log Service for evidence and Alibaba WAF for no-code enforcement.

## Project Plan

See:

- `docs/PROJECT_PLAN.md`
- `docs/ARCHITECTURE.md`
- `docs/JUDGING_ALIGNMENT.md`
- `docs/QWEN_CLOUD_PRACTICES_TODO.md`
- `docs/ALIBABA_AND_APPROVAL_INTEGRATIONS.md`

## Tests

```bash
venv/bin/python -m pytest
```

Live Qwen integration smoke test:

```bash
SECAI_RUN_QWEN_INTEGRATION=1 DASHSCOPE_API_KEY=... pytest tests/test_qwen_integration.py
```
