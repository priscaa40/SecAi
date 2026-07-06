"""Alibaba Cloud deployment proof and integration notes.

This file is intentionally small and explicit for the hackathon submission:
it shows where SecAi uses Alibaba Cloud services.

Production target:
- Run `main:app` on Alibaba Cloud Function Compute, Elastic Compute Service,
  or Container Service for Kubernetes.
- Configure `DASHSCOPE_API_KEY`, `QWEN_WORKSPACE_ID`, `QWEN_REGION`, and
  `QWEN_MODEL` so the backend calls Qwen Cloud / Model Studio through the
  OpenAI-compatible endpoint.
- Use an Alibaba Cloud managed database for production; SQLite is the local MVP.

Example environment:

DASHSCOPE_API_KEY=your_qwen_model_studio_key
QWEN_WORKSPACE_ID=your_model_studio_workspace_id
QWEN_REGION=ap-southeast-1
QWEN_MODEL=qwen-plus
QWEN_TRIAGE_MODEL=qwen3.5-flash
SECAI_ANALYSIS_MODE=background
SECAI_SECRET_KEY=change_me_to_a_long_random_secret
PUBLIC_BASE_URL=https://your-alibaba-cloud-secai-domain.example.com

The actual Qwen API call lives in `secai/integrations/qwen_cloud.py`.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secai.settings import get_settings, resolved_qwen_base_url


def qwen_cloud_is_configured() -> bool:
    """Return whether Qwen Cloud credentials are configured."""
    return bool(get_settings().dashscope_api_key)


def deployment_config() -> dict[str, str | bool | None]:
    """Return deployment settings useful for hackathon proof and debugging."""
    settings = get_settings()
    return {
        "qwen_configured": qwen_cloud_is_configured(),
        "qwen_model": settings.qwen_model,
        "qwen_triage_model": settings.qwen_triage_model,
        "qwen_supervisor_model": settings.qwen_supervisor_model,
        "qwen_investigator_model": settings.qwen_investigator_model,
        "qwen_reporter_model": settings.qwen_reporter_model,
        "qwen_remediation_model": settings.qwen_remediation_model,
        "qwen_base_url": resolved_qwen_base_url(settings),
        "qwen_region": settings.qwen_region,
        "qwen_workspace_id": settings.qwen_workspace_id,
        "qwen_enable_thinking": settings.qwen_enable_thinking,
        "qwen_max_output_tokens": settings.qwen_max_output_tokens,
        "qwen_timeout_seconds": settings.qwen_timeout_seconds,
        "qwen_max_retries": settings.qwen_max_retries,
        "secai_analysis_mode": settings.secai_analysis_mode,
        "secai_secret_key_configured": bool(settings.secai_secret_key),
        "app_ram_user_configured": bool(settings.app_ram_user_ak_id and settings.app_ram_user_ak_secret),
        "secai_alibaba_principal_configured": bool(settings.secai_alibaba_account_id or settings.secai_alibaba_principal_arn),
        "alibaba_sts_endpoint": settings.alibaba_sts_endpoint,
        "alibaba_waf_endpoint": settings.alibaba_waf_endpoint or f"wafopenapi.{settings.qwen_region}.aliyuncs.com",
        "public_base_url": settings.public_base_url,
    }


if __name__ == "__main__":
    for key, value in deployment_config().items():
        print(f"{key}={value}")
