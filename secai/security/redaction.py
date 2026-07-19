from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"
SENSITIVE_KEY_PARTS = {
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "session",
    "credit_card",
    "card_number",
    "cvv",
}
SLS_ALLOWED_FIELDS = {
    "timestamp",
    "time",
    "method",
    "request_method",
    "path",
    "uri",
    "request_uri",
    "query",
    "args",
    "status",
    "status_code",
    "ip",
    "client_ip",
    "remote_addr",
    "user_agent",
    "http_user_agent",
    "duration_ms",
    "message",
    "body",
    "host",
    "referer",
    "request_id",
    "content",
}
_KEY_VALUE_SECRET = re.compile(
    r"(?i)(\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|authorization|cookie|session|cvv|card[_-]?number)\b\s*[:=]\s*)([^\s&;,]+)"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def is_sensitive_key(key: str) -> bool:
    """Return whether a field name indicates secret or authentication data."""
    normalized = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")
    return any(part == normalized or part in normalized.split("_") for part in SENSITIVE_KEY_PARTS)


def sanitize_text(value: Any, limit: int = 2000) -> str:
    """Redact common inline credentials and cap untrusted text."""
    text = str(value or "")
    text = _BEARER.sub(f"Bearer {REDACTED}", text)
    text = _KEY_VALUE_SECRET.sub(lambda match: f"{match.group(1)}{REDACTED}", text)
    text = _CARD.sub(REDACTED, text)
    return text[: max(0, limit)]


def sanitize_query(value: Any, limit: int = 1000) -> str:
    """Redact secret query values while retaining security evidence."""
    text = str(value or "")
    try:
        pairs = parse_qsl(text, keep_blank_values=True)
    except ValueError:
        return sanitize_text(text, limit)
    if not pairs and "=" not in text:
        return sanitize_text(text, limit)
    sanitized = [(key, REDACTED if is_sensitive_key(key) else sanitize_text(item, 500)) for key, item in pairs]
    return urlencode(sanitized, doseq=True)[:limit]


def sanitize_url(value: Any, limit: int = 1000) -> str:
    """Redact URL credentials and query secrets."""
    text = str(value or "")
    try:
        parsed = urlsplit(text)
    except ValueError:
        return sanitize_text(text, limit)
    if not parsed.scheme and not parsed.netloc:
        return sanitize_query(text, limit)
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, sanitize_query(parsed.query), ""))[:limit]


def sanitize_mapping(value: Any, *, max_depth: int = 3, max_items: int = 40, text_limit: int = 1000) -> Any:
    """Recursively redact and bound JSON-like metadata."""
    if max_depth < 0:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for index, (raw_key, item) in enumerate(value.items()):
            if index >= max_items:
                result["_truncated"] = True
                break
            key = sanitize_text(raw_key, 100)
            if is_sensitive_key(key):
                result[key] = REDACTED
            elif key.lower() in {"url", "request_uri", "referer"}:
                result[key] = sanitize_url(item, text_limit)
            elif key.lower() in {"query", "args"}:
                result[key] = sanitize_query(item, text_limit)
            else:
                result[key] = sanitize_mapping(
                    item,
                    max_depth=max_depth - 1,
                    max_items=max_items,
                    text_limit=text_limit,
                )
        return result
    if isinstance(value, (list, tuple, set)):
        return [
            sanitize_mapping(item, max_depth=max_depth - 1, max_items=max_items, text_limit=text_limit)
            for item in list(value)[:max_items]
        ]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize_text(value, text_limit)


def sanitize_sls_contents(contents: dict[str, Any]) -> dict[str, Any]:
    """Allowlist the SLS fields useful for detection and discard everything else."""
    selected = {key: value for key, value in contents.items() if str(key).lower() in SLS_ALLOWED_FIELDS}
    return sanitize_mapping(selected, max_depth=2, max_items=len(SLS_ALLOWED_FIELDS), text_limit=1000)


def sanitize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Return the bounded, redacted event that may be persisted or sent to Qwen."""
    sanitized = dict(event)
    sanitized["site_id"] = sanitize_text(event.get("site_id"), 160)
    sanitized["source"] = sanitize_text(event.get("source"), 40)
    sanitized["event_type"] = sanitize_text(event.get("event_type"), 120)
    sanitized["method"] = sanitize_text(event.get("method"), 16) or None
    sanitized["path"] = sanitize_text(event.get("path"), 1000) or None
    sanitized["query"] = sanitize_query(event.get("query"), 1000) or None
    sanitized["ip"] = sanitize_text(event.get("ip"), 80) or None
    sanitized["user_agent"] = sanitize_text(event.get("user_agent"), 500) or None
    sanitized["payload"] = sanitize_text(event.get("payload"), 2000) or None
    sanitized["signals"] = [sanitize_text(item, 120) for item in list(event.get("signals") or [])[:30]]
    metadata = event.get("metadata") or {}
    if sanitized["source"] == "alibaba_sls" and isinstance(metadata, dict):
        sls = metadata.get("sls") or {}
        evidence = metadata.get("evidence") or []
        sanitized["metadata"] = {
            "sls": sanitize_sls_contents(sls if isinstance(sls, dict) else {}),
            "evidence": sanitize_mapping(evidence, max_depth=3, max_items=12, text_limit=500),
        }
    else:
        sanitized["metadata"] = sanitize_mapping(metadata, max_depth=3, max_items=40, text_limit=1000)
    return sanitized
