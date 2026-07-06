from __future__ import annotations

import atexit
import json
import subprocess
import sys
import threading
from typing import Any


class SecurityKnowledgeMcpError(RuntimeError):
    """Raised when the security knowledge MCP server cannot satisfy a request."""


class SecurityKnowledgeMcpClient:
    """Minimal JSON-RPC stdio client for SecAi's security knowledge MCP server."""

    def __init__(self, command: list[str] | None = None):
        self.command = command or [sys.executable, "-m", "secai.knowledge.security_knowledge"]
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._next_id = 1
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
                error = response["error"]
                raise SecurityKnowledgeMcpError(str(error.get("message") or error))
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
            error = response["error"]
            raise SecurityKnowledgeMcpError(str(error.get("message") or error))
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        process.stdin.flush()

    def _read_response(self, process: subprocess.Popen[str], request_id: int) -> dict[str, Any]:
        assert process.stdout is not None
        while True:
            line = process.stdout.readline()
            if not line:
                stderr = process.stderr.read() if process.stderr else ""
                self._process = None
                raise SecurityKnowledgeMcpError(f"Security knowledge MCP server stopped unexpectedly. {stderr}".strip())
            response = json.loads(line)
            if response.get("id") == request_id:
                return response


def _content_text(content: list[dict[str, Any]]) -> str | None:
    for item in content:
        if item.get("type") == "text":
            return item.get("text")
    return None


_default_client = SecurityKnowledgeMcpClient()


def call_tool(name: str, arguments: dict[str, Any] | None = None) -> Any:
    """Call a SecAi security knowledge tool through MCP stdio."""
    return _default_client.call_tool(name, arguments)


def list_tools() -> list[dict[str, Any]]:
    """List SecAi security knowledge tools through MCP stdio."""
    return _default_client.list_tools()


def close() -> None:
    """Close the shared MCP client."""
    _default_client.close()
