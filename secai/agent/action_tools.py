from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from langchain_core.tools import tool

from secai import database
from secai.actions import mcp_client
from secai.actions.capabilities import tool_name_for_action

_action_job_scope: ContextVar[int | None] = ContextVar("secai_action_job_scope", default=None)
_action_result: ContextVar[dict[str, Any] | None] = ContextVar("secai_action_result", default=None)


@contextmanager
def scoped_action_job(action_job_id: int) -> Iterator[None]:
    """Bind agent tools to one server-selected action job."""
    job_token = _action_job_scope.set(action_job_id)
    result_token = _action_result.set(None)
    try:
        yield
    finally:
        _action_job_scope.reset(job_token)
        _action_result.reset(result_token)


def action_result() -> dict[str, Any] | None:
    return _action_result.get()


def _invoke(name: str, action_job_id: int) -> str:
    scoped_id = _action_job_scope.get()
    if scoped_id is None or action_job_id != scoped_id:
        raise ValueError("The executor may act only on its assigned action job")
    if _action_result.get() is not None:
        raise ValueError("The assigned action tool has already been invoked")
    database.begin_action_tool_call(action_job_id, name)
    result = mcp_client.call_tool(name, {"action_job_id": action_job_id})
    if not isinstance(result, dict):
        raise RuntimeError("The MCP action tool returned an invalid result")
    database.record_action_tool_result(action_job_id, name, result)
    _action_result.set(result)
    return json.dumps(result, default=str, separators=(",", ":"))


@tool
def send_owner_security_alert(action_job_id: int) -> str:
    """Execute the assigned owner-alert job through SecAi's MCP action server."""
    return _invoke("send_owner_security_alert", action_job_id)


@tool
def collect_follow_up_cloud_evidence(action_job_id: int) -> str:
    """Execute the assigned fresh-cloud-evidence job through SecAi's MCP action server."""
    return _invoke("collect_follow_up_cloud_evidence", action_job_id)


@tool
def apply_temporary_ip_block(action_job_id: int) -> str:
    """Execute the assigned owner-approved temporary-block job through SecAi's MCP action server."""
    return _invoke("apply_temporary_ip_block", action_job_id)


_TOOLS = {
    "send_owner_security_alert": send_owner_security_alert,
    "collect_follow_up_cloud_evidence": collect_follow_up_cloud_evidence,
    "apply_temporary_ip_block": apply_temporary_ip_block,
}


def tool_for_action(action: str):
    """Return exactly one MCP-backed LangChain tool for a persisted action."""
    return _TOOLS[tool_name_for_action(action)]
