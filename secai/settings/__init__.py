from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables and .env."""

    app_name: str = "SecAi Autopilot"
    database_url: str = Field(default="sqlite:///./secai.db")
    secai_secret_key: str | None = None
    dashscope_api_key: str | None = None
    qwen_base_url: str | None = None
    qwen_workspace_id: str | None = None
    qwen_region: str = "ap-southeast-1"
    qwen_model: str = "qwen-plus"
    qwen_triage_model: str | None = None
    qwen_supervisor_model: str | None = None
    qwen_investigator_model: str | None = None
    qwen_reporter_model: str | None = None
    qwen_remediation_model: str | None = None
    qwen_enable_thinking: bool = False
    qwen_max_output_tokens: int = 900
    qwen_timeout_seconds: float = 45
    qwen_max_retries: int = 2
    secai_analysis_mode: Literal["sync", "background"] = "sync"
    secai_max_payload_chars: int = 8000
    secai_recent_event_limit: int = 50
    secai_session_ttl_hours: int = 24
    secai_sls_poll_interval_seconds: int = 300
    secai_sls_poll_minutes: int = 15
    secai_sls_poll_limit: int = 100
    secai_sls_poll_query: str = '*'
    discord_bot_token: str | None = None
    app_ram_user_ak_id: str | None = None
    app_ram_user_ak_secret: str | None = None
    secai_alibaba_account_id: str | None = None
    secai_alibaba_principal_arn: str | None = None
    alibaba_sts_endpoint: str = "sts.aliyuncs.com"
    alibaba_waf_endpoint: str | None = None
    alibaba_sls_endpoint: str | None = None
    alibaba_sls_project: str | None = None
    alibaba_sls_logstore: str | None = None
    public_base_url: str = "http://localhost:8000"
    frontend_base_url: str = "http://localhost:5173"
    secai_extra_cors_origins: str = ""

    model_config = {
        "env_file": ".env",
        "env_prefix": "",
        "extra": "ignore",
    }


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()


def resolved_qwen_base_url(settings: Settings | None = None) -> str:
    """Return the Qwen Model Studio endpoint SecAi should call."""
    settings = settings or get_settings()
    if settings.qwen_base_url:
        return settings.qwen_base_url
    if settings.qwen_workspace_id:
        return f"https://{settings.qwen_workspace_id}.{settings.qwen_region}.maas.aliyuncs.com/compatible-mode/v1"
    return "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"


def qwen_model_for_agent(agent_name: str, settings: Settings | None = None) -> str:
    """Return the configured Qwen model for a specific SecAi agent."""
    settings = settings or get_settings()
    models = {
        "triage": settings.qwen_triage_model,
        "supervisor": settings.qwen_supervisor_model,
        "investigator": settings.qwen_investigator_model,
        "reporter": settings.qwen_reporter_model,
        "remediation": settings.qwen_remediation_model,
    }
    return models.get(agent_name) or settings.qwen_model
