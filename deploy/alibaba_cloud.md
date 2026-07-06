# Alibaba Cloud Deployment

SecAi is designed to run as an Alibaba Cloud-hosted control plane. The local MVP uses SQLite, but the deployment path is a containerized FastAPI app that calls Qwen Cloud / Model Studio for the agent workflow.

## Required Services

- Qwen Cloud / Model Studio for the agent reasoning API.
- Alibaba Cloud compute target, such as ECS, Function Compute custom container, or ACK.
- Optional production database: ApsaraDB RDS for PostgreSQL, PolarDB, or another managed database.
- Optional server-side log source: Alibaba Cloud Simple Log Service.
- Optional no-code enforcement source: Alibaba Cloud Web Application Firewall 3.0.

## Required Environment

```bash
DASHSCOPE_API_KEY=your_model_studio_api_key
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
SECAI_ANALYSIS_MODE=background
SECAI_SECRET_KEY=change_me_to_a_long_random_secret
SECAI_ALIBABA_PRINCIPAL_ARN=acs:ram::<account-id>:role/<secai-runtime-role>
ALIBABA_WAF_ENDPOINT=wafopenapi.ap-southeast-1.aliyuncs.com
PUBLIC_BASE_URL=https://your-secai-domain.example.com
FRONTEND_BASE_URL=https://your-secai-dashboard.example.com
SECAI_EXTRA_CORS_ORIGINS=https://shop.yourdomain.com
DATABASE_URL=sqlite:///./secai.db
```

`QWEN_BASE_URL` can be used as an explicit override. When it is not set, SecAi resolves the Model Studio endpoint from `QWEN_WORKSPACE_ID` and `QWEN_REGION`.

Prefer running SecAi with an Alibaba Cloud runtime identity, such as an ECS/FC/ACK RAM role, OIDC role, or credentials URI. The Alibaba SDK credential provider then obtains temporary credentials without a long-lived AccessKey. That runtime identity should only be able to call `sts:AssumeRole` on SecAi connector roles. Set `SECAI_ALIBABA_ACCOUNT_ID` or `SECAI_ALIBABA_PRINCIPAL_ARN` so SecAi can generate customer-side RAM/ROS connector templates that trust the SecAi deployment with a per-site External ID. SLS observe mode needs read-only permissions for one project/logstore. Alibaba Autopilot needs permission to create SecAi-managed WAF rules, including `yundun-waf:CreateDefenseRule`.

`APP_RAM_USER_AK_ID` and `APP_RAM_USER_AK_SECRET` remain supported only for local or non-Alibaba deployments that cannot use Alibaba temporary-credential providers. Store them only in deployment secrets.

## Container Run

```bash
docker build -t secai-autopilot .
docker run --rm -p 8000:8000 \
  -e DASHSCOPE_API_KEY \
  -e QWEN_WORKSPACE_ID \
  -e QWEN_REGION=ap-southeast-1 \
  -e QWEN_MODEL=qwen-plus \
  -e SECAI_SECRET_KEY \
  secai-autopilot
```

## Storefront Workload

Deploy `protected_site/` separately from the SecAi control plane. This is the public Northstar Goods storefront that judges can visit through Alibaba WAF.

```bash
docker build -f protected_site/Dockerfile -t secai-protected-shop .
docker run --rm -p 9000:9000 \
  -e SECAI_PUBLIC_BASE_URL=https://your-secai-domain.example.com \
  -e SECAI_SITE_ID=site_from_secai_dashboard \
  secai-protected-shop
```

Point the public storefront domain, for example `shop.yourdomain.com`, at Alibaba WAF and route WAF traffic to this workload. Enable stdout/container access-log collection into Alibaba Simple Log Service. The storefront emits JSON records with `method`, `path`, `query`, `status_code`, `ip`, `user_agent`, and `message`, which are the fields SecAi's Alibaba SLS evidence source expects.

## Deployment Proof

Run:

```bash
python deploy/alibaba_cloud.py
```

The script prints whether Qwen is configured and the exact Model Studio base URL SecAi will use.

## Hackathon Demo Path

1. Deploy the container on Alibaba Cloud.
2. Configure `DASHSCOPE_API_KEY` and Qwen endpoint settings.
3. Deploy `protected_site/` behind Alibaba WAF and enable SLS log collection for its access logs.
4. Set `SECAI_EXTRA_CORS_ORIGINS` on the SecAi API to the storefront origin.
5. Open the dashboard and connect Alibaba Autopilot for the storefront site.
6. Show `GET /api/sites/{site_id}/autopilot-status` returning `waf_enforced`.
7. Visit the storefront's `/attack-lab` page through the WAF domain and click SQL injection, path traversal, login burst, and error spike tests.
8. In the dashboard, click **Check Autopilot logs** and show the analysis job progress.
9. Review the Qwen-generated incident and approve remediation.
10. Show the approved remediation policy at `GET /api/policies/demo-site?ingest_key=demo-key` with `status=active` and an Alibaba WAF provider rule ID.
11. Repeat the triggering browser request and show WAF/log proof, then reject/remove the action to expire the policy.
12. Show authenticated Qwen usage telemetry at `GET /api/qwen/usage`.
