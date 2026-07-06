from __future__ import annotations

from functools import lru_cache

from langchain_openai import ChatOpenAI

from secai.settings import get_settings, qwen_model_for_agent, resolved_qwen_base_url


class QwenClient:
    """Configuration guard for Qwen Cloud / Model Studio."""

    def __init__(self) -> None:
        """Fail fast when Qwen credentials are missing."""
        self.settings = get_settings()
        if not self.settings.dashscope_api_key:
            raise RuntimeError("DASHSCOPE_API_KEY must be configured before SecAi can analyze incidents.")

    @property
    def enabled(self) -> bool:
        """Return whether Qwen API credentials are configured."""
        return bool(self.settings.dashscope_api_key)


@lru_cache
def get_chat_model(agent_name: str = "default") -> ChatOpenAI:
    """Create the LangChain chat model configured for Qwen."""
    settings = QwenClient().settings
    return ChatOpenAI(
        model=qwen_model_for_agent(agent_name, settings),
        api_key=settings.dashscope_api_key,
        base_url=resolved_qwen_base_url(settings),
        temperature=0.2,
        max_completion_tokens=settings.qwen_max_output_tokens,
        timeout=settings.qwen_timeout_seconds,
        max_retries=settings.qwen_max_retries,
        extra_body={"enable_thinking": settings.qwen_enable_thinking},
    )
