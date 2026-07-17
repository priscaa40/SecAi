from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlencode

from fastapi import Request

from protected_site.client_ip import trusted_client_ip

logger = logging.getLogger("protected_site.access")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
logger.propagate = False


async def access_log_middleware(request: Request, call_next):
    """Emit redacted, SLS-readable JSON access logs for every request."""
    started = time.perf_counter()
    body = await request.body()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        client_ip = _client_ip(request)
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "method": request.method,
            "request_method": request.method,
            "path": request.url.path,
            "uri": request.url.path,
            "request_uri": request.url.path,
            "query": redact_query(request.url.query),
            "args": redact_query(request.url.query),
            "status": status_code,
            "status_code": status_code,
            "ip": client_ip,
            "client_ip": client_ip,
            "remote_addr": client_ip,
            "user_agent": request.headers.get("user-agent", "")[:500],
            "http_user_agent": request.headers.get("user-agent", "")[:500],
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "message": body_message(body, request.headers.get("content-type", "")),
        }
        logger.info(json.dumps(event, separators=(",", ":")))


def body_message(body: bytes, content_type: str) -> str:
    """Return a redacted body summary useful for SLS evidence."""
    if not body:
        return ""
    text = body.decode("utf-8", errors="replace")
    if "application/x-www-form-urlencoded" in content_type:
        fields = parse_qsl(text, keep_blank_values=True)
        text = " ".join(f"{key}={'[REDACTED]' if _is_sensitive(key) else value}" for key, value in fields)
        return text[:1000]
    if "application/json" in content_type:
        try:
            return json.dumps(_redact_value(json.loads(text)), separators=(",", ":"))[:1000]
        except (json.JSONDecodeError, UnicodeError):
            return "[INVALID JSON BODY]"
    return "[BODY OMITTED]"


def redact_query(query: str) -> str:
    """Redact secret-bearing URL parameters before they reach access logs."""
    if not query:
        return ""
    return urlencode(
        [
            (key, "[REDACTED]" if _is_sensitive(key) else value)
            for key, value in parse_qsl(query, keep_blank_values=True)
        ]
    )


def _redact_value(value):
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _is_sensitive(str(key)) else _redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def _is_sensitive(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(
        part in normalized
        for part in (
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "authorization",
            "cookie",
            "card_number",
            "cvv",
        )
    )


def _client_ip(request: Request) -> str:
    return trusted_client_ip(request, os.getenv("SECAI_TRUSTED_PROXY_CIDRS", ""))
