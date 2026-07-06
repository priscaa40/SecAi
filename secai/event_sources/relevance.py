from __future__ import annotations

from typing import Any


STRONG_ATTACK_SIGNALS = {
    "sql_injection_pattern",
    "path_traversal_pattern",
    "xss_pattern",
    "suspicious_form_payload",
    "rapid_form_submit",
    "bot_like_behavior",
    "client_error_spike",
}

BROWSER_EVENT_TYPES = {
    "suspicious_form_submit",
    "rapid_form_submit",
    "browser_error_spike",
    "bot_like_behavior",
}

BROWSER_SIGNALS = STRONG_ATTACK_SIGNALS | {
    "bot_like_user_agent",
}


def is_event_relevant(event: dict[str, Any]) -> bool:
    """Return whether one normalized event should be stored and analyzed."""
    source = event.get("source")
    if source == "browser":
        return is_browser_event_relevant(event)
    if source == "alibaba_sls":
        return is_sls_event_relevant(event)
    if source == "demo":
        return True
    return has_strong_attack_signal(event)


def is_browser_event_relevant(event: dict[str, Any]) -> bool:
    """Return whether a browser event matches SecAi's suspicious-only contract."""
    signals = set(event.get("signals") or [])
    event_type = event.get("event_type")
    if event_type not in BROWSER_EVENT_TYPES and not has_strong_attack_signal(event):
        return False
    return bool(signals & BROWSER_SIGNALS)


def is_sls_event_relevant(event: dict[str, Any]) -> bool:
    """Return whether one normalized Alibaba SLS event should enter the agent workflow."""
    if has_strong_attack_signal(event):
        return True
    status_code = _status_code(event.get("status_code"))
    if status_code in {401, 403}:
        return True
    if status_code is not None and status_code >= 500:
        return True
    return False


def has_strong_attack_signal(event: dict[str, Any]) -> bool:
    """Return whether normalizer or source-specific logic found attack evidence."""
    return bool(set(event.get("signals") or []) & STRONG_ATTACK_SIGNALS)


def _status_code(value: Any) -> int | None:
    """Coerce a status code into an int when possible."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
