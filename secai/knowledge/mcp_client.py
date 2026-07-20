from __future__ import annotations

import threading
from typing import Any

from secai.mcp_stdio import McpToolError, StdioMcpClient
from secai.settings import get_settings

SecurityKnowledgeMcpError = McpToolError

_shared_client: StdioMcpClient | None = None
_shared_client_lock = threading.Lock()


def _client() -> StdioMcpClient:
    """Return the process-wide MCP client for security knowledge."""
    global _shared_client
    with _shared_client_lock:
        if _shared_client is None:
            _shared_client = StdioMcpClient(
                "secai.knowledge.security_knowledge",
                timeout_seconds=get_settings().secai_mcp_timeout_seconds,
            )
        return _shared_client


def call_tool(name: str, arguments: dict[str, Any] | None = None) -> Any:
    """Call a SecAi security knowledge tool through official MCP stdio."""
    return _client().call_tool(name, arguments)


def list_tools() -> list[dict[str, Any]]:
    """Discover SecAi security knowledge tools through official MCP stdio."""
    return _client().list_tools()
