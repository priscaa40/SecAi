from __future__ import annotations

from typing import Any

from secai.mcp_stdio import McpToolError, StdioMcpClient
from secai.settings import get_settings

ActionMcpError = McpToolError


def _client() -> StdioMcpClient:
    return StdioMcpClient(
        "secai.actions.mcp_server",
        timeout_seconds=get_settings().secai_action_mcp_timeout_seconds,
    )


def list_tools() -> list[dict[str, Any]]:
    return _client().list_tools()


def call_tool(name: str, arguments: dict[str, Any] | None = None) -> Any:
    return _client().call_tool(name, arguments)
