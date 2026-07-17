from __future__ import annotations

import json
from typing import Any


class RequestSizeLimitMiddleware:
    """Reject oversized request bodies before FastAPI buffers or parses them."""

    def __init__(self, app: Any, max_bytes: int):
        self.app = app
        self.max_bytes = max(1024, max_bytes)

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                declared_size = int(content_length)
            except ValueError:
                await self._reject(send, status=400, detail="Content-Length must be a valid number")
                return
            if declared_size < 0:
                await self._reject(send, status=400, detail="Content-Length must not be negative")
                return
            if declared_size > self.max_bytes:
                await self._reject(send)
                return
        body = bytearray()
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                await self._reject(send)
                return
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay() -> dict:
            nonlocal replayed
            if replayed:
                return {"type": "http.request", "body": b"", "more_body": False}
            replayed = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay, send)

    async def _reject(self, send: Any, *, status: int = 413, detail: str = "Request body is too large") -> None:
        payload = json.dumps({"detail": detail}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": payload})
