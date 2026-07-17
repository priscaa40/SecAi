from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from langchain.agents import create_agent
from pydantic import BaseModel

from secai import database
from secai.agent.trace import tool_names_from_result
from secai.integrations.qwen_cloud import get_chat_model
from secai.settings import get_settings, qwen_model_for_agent

_current_event_id: ContextVar[int | None] = ContextVar("secai_current_event_id", default=None)
_current_job_id: ContextVar[int | None] = ContextVar("secai_current_job_id", default=None)
_agent_calls: ContextVar[list[dict[str, Any]] | None] = ContextVar("secai_agent_calls", default=None)
_AGENT_CACHE: dict[tuple[str, type[BaseModel], str, tuple[str, ...]], Any] = {}


@contextmanager
def analysis_run(event_id: int | None, job_id: int | None) -> Iterator[None]:
    """Scope usage records and trace details to one investigation."""
    event_token = _current_event_id.set(event_id)
    job_token = _current_job_id.set(job_id)
    calls_token = _agent_calls.set([])
    try:
        yield
    finally:
        _current_event_id.reset(event_token)
        _current_job_id.reset(job_token)
        _agent_calls.reset(calls_token)


def agent_calls() -> list[dict[str, Any]]:
    """Return runtime details collected for the current investigation."""
    return list(_agent_calls.get() or [])


def invoke_structured_agent(
    name: str,
    response_format: type[BaseModel],
    system_prompt: str,
    user_prompt: str,
    tools: list[Any],
) -> Any:
    """Call one Qwen-backed role and require structured output."""
    agent = _agent_for(name, response_format, system_prompt, tools)
    started = time.perf_counter()
    try:
        result = agent.invoke({"messages": [{"role": "user", "content": user_prompt}]})
    except Exception as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        _record_agent_usage(name, {}, latency_ms, error_message=exc.__class__.__name__)
        raise
    latency_ms = int((time.perf_counter() - started) * 1000)
    usage = _record_agent_usage(name, result, latency_ms)
    settings = get_settings()
    _agent_calls.set(
        [
            *(_agent_calls.get() or []),
            {
                "agent": name,
                "model": qwen_model_for_agent(name, settings),
                "latency_ms": latency_ms,
                "tools": tool_names_from_result(result),
                **usage,
            },
        ]
    )
    structured = result.get("structured_response")
    if structured is None:
        raise RuntimeError(f"{name} agent did not return structured_response")
    return structured


def _agent_for(name: str, response_format: type[BaseModel], system_prompt: str, tools: list[Any]):
    cache_key = (name, response_format, system_prompt, tuple(_tool_name(tool) for tool in tools))
    if cache_key not in _AGENT_CACHE:
        _AGENT_CACHE[cache_key] = create_agent(
            model=get_chat_model(name),
            tools=tools,
            system_prompt=system_prompt,
            response_format=response_format,
            name=f"secai_{name}",
        )
    return _AGENT_CACHE[cache_key]


def _tool_name(tool: Any) -> str:
    return getattr(tool, "name", None) or getattr(tool, "__name__", tool.__class__.__name__)


def _record_agent_usage(
    name: str,
    result: dict[str, Any],
    latency_ms: int,
    error_message: str | None = None,
) -> dict[str, int | None]:
    usage = _extract_usage(result)
    settings = get_settings()
    database.insert_qwen_usage(
        {
            "agent_name": name,
            "model": qwen_model_for_agent(name, settings),
            "event_id": _current_event_id.get(),
            "job_id": _current_job_id.get(),
            "input_tokens": usage.get("input_tokens"),
            "output_tokens": usage.get("output_tokens"),
            "total_tokens": usage.get("total_tokens"),
            "model_calls": usage.get("model_calls", 1),
            "latency_ms": latency_ms,
            "error_message": error_message,
        }
    )
    return usage


def _extract_usage(result: dict[str, Any]) -> dict[str, int | None]:
    totals: dict[str, int | None] = {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "model_calls": 0,
    }
    seen_usage = False
    for message in result.get("messages") or []:
        metadata = getattr(message, "usage_metadata", None) or {}
        response_metadata = getattr(message, "response_metadata", None) or {}
        token_usage = response_metadata.get("token_usage") or {}
        input_tokens = metadata.get("input_tokens") or token_usage.get("prompt_tokens")
        output_tokens = metadata.get("output_tokens") or token_usage.get("completion_tokens")
        total_tokens = metadata.get("total_tokens") or token_usage.get("total_tokens")
        if input_tokens is not None or output_tokens is not None or total_tokens is not None:
            seen_usage = True
            totals["model_calls"] = int(totals["model_calls"] or 0) + 1
            totals["input_tokens"] = int(totals["input_tokens"] or 0) + int(input_tokens or 0)
            totals["output_tokens"] = int(totals["output_tokens"] or 0) + int(output_tokens or 0)
            totals["total_tokens"] = int(totals["total_tokens"] or 0) + int(
                total_tokens or (input_tokens or 0) + (output_tokens or 0)
            )
    if not seen_usage:
        return {"input_tokens": None, "output_tokens": None, "total_tokens": None, "model_calls": 1}
    return totals
