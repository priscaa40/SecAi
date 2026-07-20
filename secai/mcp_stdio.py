from __future__ import annotations

import json
import sys
import threading
from datetime import timedelta
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class McpToolError(RuntimeError):
    """Raised when a local MCP server cannot discover or execute a tool."""


class StdioMcpClient:
    """Thread-safe synchronous facade over the official async MCP stdio client."""

    def __init__(self, module: str, *, timeout_seconds: float = 10) -> None:
        self._server = StdioServerParameters(command=sys.executable, args=["-m", module])
        self._timeout_seconds = max(0.1, timeout_seconds)
        self._lock = threading.Lock()

    def list_tools(self) -> list[dict[str, Any]]:
        """Discover tool descriptors from the configured MCP server."""
        with self._lock:
            try:
                result = anyio.run(self._list_tools)
            except Exception as exc:
                raise McpToolError(f"MCP tool discovery failed: {exc}") from exc
        return [tool.model_dump(by_alias=True, exclude_none=True) for tool in result.tools]

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Call one MCP tool and return its structured payload."""
        with self._lock:
            try:
                result = anyio.run(self._call_tool, name, arguments or {})
            except Exception as exc:
                raise McpToolError(f"MCP tool {name} failed: {exc}") from exc
        if result.isError:
            raise McpToolError(_content_text(result.content) or f"MCP tool failed: {name}")
        if result.structuredContent is not None:
            payload = result.structuredContent
            return payload.get("result", payload) if isinstance(payload, dict) else payload
        return _content_payload(result.content)

    def close(self) -> None:
        """Compatibility hook; each official stdio session is scoped to one call."""

    async def _list_tools(self):
        async with stdio_client(self._server) as (read_stream, write_stream), ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(seconds=self._timeout_seconds),
        ) as session:
            await session.initialize()
            return await session.list_tools()

    async def _call_tool(self, name: str, arguments: dict[str, Any]):
        async with stdio_client(self._server) as (read_stream, write_stream), ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(seconds=self._timeout_seconds),
        ) as session:
            await session.initialize()
            return await session.call_tool(name, arguments)


def _content_text(content: Any) -> str | None:
    for item in content or []:
        text = getattr(item, "text", None)
        if text is not None:
            return str(text)
    return None


def _content_payload(content: Any) -> Any:
    text = _content_text(content)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text
