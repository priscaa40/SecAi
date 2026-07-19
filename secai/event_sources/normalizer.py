from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote_plus

SQLI_PATTERNS = [
    r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    r"union\s+select",
    r"sleep\s*\(",
    r"drop\s+table",
    r"(?:['\"]|;)\s*--(?:\s|$)",
]
PATH_TRAVERSAL_PATTERNS = [r"\.\./", r"\.\.\\", r"/etc/passwd", r"boot\.ini"]
XSS_PATTERNS = [r"<script", r"javascript:", r"onerror\s*=", r"onload\s*="]


def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    """Turn raw browser or Alibaba SLS input into SecAi's event shape."""
    event = {
        "site_id": raw["site_id"],
        "source": raw.get("source", "browser"),
        "event_type": raw.get("event_type", "http_request"),
        "method": _clean_upper(raw.get("method")),
        "path": raw.get("path") or "/",
        "query": raw.get("query"),
        "status_code": raw.get("status_code"),
        "ip": raw.get("ip") or raw.get("metadata", {}).get("ip"),
        "user_agent": raw.get("user_agent"),
        "payload": raw.get("payload"),
        "signals": list(raw.get("signals") or []),
        "metadata": dict(raw.get("metadata") or {}),
    }
    event["signals"] = sorted(set(event["signals"] + infer_signals(event)))
    return event


def infer_signals(event: dict[str, Any]) -> list[str]:
    """Infer lightweight evidence hints from event fields."""
    decoded_query = unquote_plus(str(event.get("query") or ""))
    haystack = " ".join(
        str(value or "") for value in [event.get("path"), decoded_query, event.get("payload")]
    ).lower()
    signals: list[str] = []
    if _matches_any(SQLI_PATTERNS, haystack):
        signals.append("sql_injection_pattern")
    if _matches_any(PATH_TRAVERSAL_PATTERNS, haystack):
        signals.append("path_traversal_pattern")
    if _matches_any(XSS_PATTERNS, haystack):
        signals.append("xss_pattern")
    if event.get("status_code") in (401, 403):
        signals.append("auth_failure")
    if event.get("status_code") and int(event["status_code"]) >= 500:
        signals.append("server_error")
    if "bot" in str(event.get("user_agent") or "").lower():
        signals.append("bot_like_user_agent")
    return signals


def _matches_any(patterns: list[str], text: str) -> bool:
    """Return whether any regex pattern matches the provided text."""
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def _clean_upper(value: Any) -> str | None:
    """Convert a value to uppercase text when present."""
    return str(value).upper() if value else None
