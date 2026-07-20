from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables and .env."""

    app_name: str = "SecAi Autopilot"
    database_url: str
    dashscope_api_key: str | None = None
    qwen_model: str = "qwen-plus"
    qwen_investigator_model: str | None = None
    qwen_reviewer_model: str | None = None
    qwen_responder_model: str | None = None
    qwen_executor_model: str | None = None
    qwen_enable_thinking: bool = False
    qwen_max_output_tokens: int = 900
    qwen_timeout_seconds: float = 45
    qwen_max_retries: int = 2
    secai_max_payload_chars: int = 8000
    secai_max_request_bytes: int = 8192
    secai_recent_event_limit: int = 20
    secai_model_context_chars: int = 24000
    secai_mcp_timeout_seconds: float = 10
    secai_action_mcp_timeout_seconds: float = 60
    secai_session_ttl_hours: int = 24
    secai_approval_ttl_minutes: int = 30
    secai_data_retention_days: int = 30
    secai_retention_interval_seconds: int = 3600
    secai_remediation_protected_cidrs: str = ""
    secai_alibaba_provider_role_arn: str | None = None
    secai_policy_expiry_interval_seconds: int = 30
    secai_sls_poll_interval_seconds: int = 300
    secai_sls_poll_minutes: int = 15
    secai_sls_poll_limit: int = 100
    secai_sls_poll_query: str = "*"
    discord_bot_token: str | None = None
    discord_application_id: str | None = None
    discord_application_public_key: str | None = None
    discord_auto_register_commands: bool = True
    alibaba_cloud_ecs_metadata: str | None = None
    # Proxy peers allowed to supply forwarding headers to the control API.
    secai_trusted_proxy_cidrs: str = ""
    public_base_url: str = "http://localhost:8000"
    frontend_base_url: str = "http://localhost:5173"

    @field_validator("*", mode="before")
    @classmethod
    def strip_string_settings(cls, value):
        """Trim copied environment values before they are used in headers or URLs."""
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("discord_application_id")
    @classmethod
    def validate_discord_application_id(cls, value: str | None) -> str | None:
        if value and not value.isdigit():
            raise ValueError("DISCORD_APPLICATION_ID must contain only digits")
        return value

    @field_validator("discord_application_public_key")
    @classmethod
    def validate_discord_public_key(cls, value: str | None) -> str | None:
        if value:
            try:
                key = bytes.fromhex(value)
            except ValueError as exc:
                raise ValueError("DISCORD_APPLICATION_PUBLIC_KEY must be hexadecimal") from exc
            if len(key) != 32:
                raise ValueError("DISCORD_APPLICATION_PUBLIC_KEY must be a 32-byte Ed25519 key")
        return value

    model_config = {
        "env_file": ".env",
        "env_prefix": "",
        "extra": "ignore",
    }


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()  # type: ignore[call-arg]  # Values are loaded from the environment by BaseSettings.


def qwen_model_for_agent(agent_name: str, settings: Settings | None = None) -> str:
    """Return the configured Qwen model for a specific SecAi agent."""
    settings = settings or get_settings()
    models = {
        "investigator": settings.qwen_investigator_model,
        "reviewer": settings.qwen_reviewer_model,
        "responder": settings.qwen_responder_model,
        "executor": settings.qwen_executor_model,
    }
    return models.get(agent_name) or settings.qwen_model
