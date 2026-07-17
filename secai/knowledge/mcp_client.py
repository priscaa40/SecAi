from __future__ import annotations

import atexit
import json
import selectors
import subprocess
import sys
import threading
import time
from typing import Any

from secai.settings import get_settings


class SecurityKnowledgeMcpError(RuntimeError):
    """Raised when the security knowledge MCP server cannot satisfy a request."""


class SecurityKnowledgeMcpClient:
    """Minimal JSON-RPC stdio client for SecAi's security knowledge MCP server."""

    def __init__(self, command: list[str] | None = None, timeout_seconds: float | None = None):
        self.command = command or [sys.executable, "-m", "secai.knowledge.security_knowledge"]
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._next_id = 1
        self.timeout_seconds = timeout_seconds or get_settings().secai_mcp_timeout_seconds
        atexit.register(self.close)

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Call a security knowledge MCP tool and return its JSON payload."""
        response = self._request("tools/call", {"name": name, "arguments": arguments or {}})
        content = response.get("content") or []
        if response.get("isError"):
            raise SecurityKnowledgeMcpError(_content_text(content) or f"MCP tool failed: {name}")
        text = _content_text(content)
        if text is None:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise SecurityKnowledgeMcpError(f"MCP tool {name} returned invalid JSON: {text}") from exc

    def list_tools(self) -> list[dict[str, Any]]:
        """Return tool descriptors from the MCP server."""
        response = self._request("tools/list", {})
        return response.get("tools", [])

    def close(self) -> None:
        """Stop the MCP subprocess if it is running."""
        with self._lock:
            if not self._process:
                return
            process = self._process
            self._process = None
            try:
                process.stdin.close() if process.stdin else None
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                process.kill()

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            process = self._ensure_process()
            request_id = self._next_id
            self._next_id += 1
            message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            assert process.stdin is not None
            process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
            process.stdin.flush()
            response = self._read_response(process, request_id)
            if response.get("error"):
                raise SecurityKnowledgeMcpError(_error_message(response["error"]))
            return response.get("result") or {}

    def _ensure_process(self) -> subprocess.Popen[str]:
        if self._process and self._process.poll() is None:
            return self._process
        self._process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._initialize_locked()
        return self._process

    def _initialize_locked(self) -> None:
        process = self._process
        if not process:
            raise SecurityKnowledgeMcpError("Security knowledge MCP process was not started.")
        request_id = self._next_id
        self._next_id += 1
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "secai-api", "version": "0.1.0"},
            },
        }
        assert process.stdin is not None
        process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        process.stdin.flush()
        response = self._read_response(process, request_id)
        if response.get("error"):
            raise SecurityKnowledgeMcpError(_error_message(response["error"]))
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        process.stdin.flush()

    def _read_response(self, process: subprocess.Popen[str], request_id: int) -> dict[str, Any]:
        assert process.stdout is not None
        deadline = time.monotonic() + max(0.1, self.timeout_seconds)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if not selector.select(remaining):
                break
            line = process.stdout.readline()
            if not line:
                stderr = process.stderr.read() if process.stderr else ""
                self._process = None
                raise SecurityKnowledgeMcpError(f"Security knowledge MCP server stopped unexpectedly. {stderr}".strip())
            try:
                response = json.loads(line)
            except json.JSONDecodeError as exc:
                self._stop_unhealthy_process(process)
                raise SecurityKnowledgeMcpError("Security knowledge MCP server returned invalid JSON.") from exc
            if response.get("id") == request_id:
                return response
        self._stop_unhealthy_process(process)
        raise SecurityKnowledgeMcpError(
            f"Security knowledge MCP request timed out after {self.timeout_seconds:g} seconds."
        )

    def _stop_unhealthy_process(self, process: subprocess.Popen[str]) -> None:
        """Discard a timed-out subprocess so the next request starts cleanly."""
        if self._process is process:
            self._process = None
        try:
            process.kill()
            process.wait(timeout=1)
        except Exception:
            pass


def _content_text(content: Any) -> str | None:
    if isinstance(content, dict):
        text = content.get("text")
        return str(text) if text is not None else None
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return None
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            text = item.get("text")
            return str(text) if text is not None else None
        if isinstance(item, str):
            return item
    return None


def _error_message(error: Any) -> str:
    if isinstance(error, dict):
        message = error.get("message")
        if message:
            return str(message)
        data = error.get("data")
        if data:
            return str(data)
    text = _content_text(error)
    if text:
        return text
    return str(error)


_shared_client: SecurityKnowledgeMcpClient | None = None
_shared_client_lock = threading.Lock()


def _client() -> SecurityKnowledgeMcpClient:
    """Return the one process-wide MCP client used by SecAi's single analysis worker."""
    global _shared_client
    with _shared_client_lock:
        if _shared_client is None:
            _shared_client = SecurityKnowledgeMcpClient()
        return _shared_client


def call_tool(name: str, arguments: dict[str, Any] | None = None) -> Any:
    """Call a SecAi security knowledge tool through MCP stdio."""
    return _client().call_tool(name, arguments)


def list_tools() -> list[dict[str, Any]]:
    """List SecAi security knowledge tools through MCP stdio."""
    return _client().list_tools()


def close() -> None:
    """Close the shared MCP client."""
    global _shared_client
    with _shared_client_lock:
        client = _shared_client
        _shared_client = None
    if client:
        client.close()
