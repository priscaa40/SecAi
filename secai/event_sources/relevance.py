from __future__ import annotations

from typing import Any

STRONG_ATTACK_SIGNALS = {
    "sql_injection_pattern",
    "path_traversal_pattern",
    "xss_pattern",
    "suspicious_form_payload",
    "rapid_form_submit",
}

BROWSER_ATTACK_SIGNALS = {
    "sql_injection_pattern",
    "path_traversal_pattern",
    "xss_pattern",
}
BROWSER_RAPID_SUBMIT_THRESHOLD = 10

SLS_GROUP_MINIMUM_RECORDS = {
    "authentication": 3,
    "bot_activity": 5,
    "client_error": 5,
    "not_found_scan": 6,
    "rate_limited": 3,
    "server_error": 3,
}


def is_event_relevant(event: dict[str, Any]) -> bool:
    """Return whether one normalized event should be stored and analyzed."""
    source = event.get("source")
    if source == "browser":
        return is_browser_event_relevant(event)
    if source == "alibaba_sls":
        if str(event.get("event_type") or "").endswith("_group"):
            return is_sls_group_relevant(event)
        return is_sls_candidate_relevant(event)
    return has_strong_attack_signal(event)


def is_browser_event_relevant(event: dict[str, Any]) -> bool:
    """Return whether a browser event matches SecAi's suspicious-only contract."""
    signals = set(event.get("signals") or [])
    event_type = event.get("event_type")
    if event_type == "suspicious_form_submit":
        return bool(signals & BROWSER_ATTACK_SIGNALS)
    if event_type == "rapid_form_submit":
        count = _integer((event.get("metadata") or {}).get("submit_count_10s"))
        return "rapid_form_submit" in signals and count is not None and count >= BROWSER_RAPID_SUBMIT_THRESHOLD
    return False


def is_sls_candidate_relevant(event: dict[str, Any]) -> bool:
    """Return whether one SLS record belongs in the bounded grouping stage."""
    if has_strong_attack_signal(event):
        return True
    status_code = _integer(event.get("status_code"))
    return status_code is not None and status_code >= 400


def is_sls_group_relevant(event: dict[str, Any]) -> bool:
    """Return whether a grouped SLS pattern is strong enough for Qwen analysis."""
    if has_strong_attack_signal(event):
        return True
    event_type = str(event.get("event_type") or "")
    if not (event_type.startswith("sls_") and event_type.endswith("_group")):
        return False
    family = event_type.removeprefix("sls_").removesuffix("_group")
    minimum = SLS_GROUP_MINIMUM_RECORDS.get(family)
    if minimum is None:
        return False
    evidence = (event.get("metadata") or {}).get("evidence") or []
    return len(evidence) >= minimum


def has_strong_attack_signal(event: dict[str, Any]) -> bool:
    """Return whether normalizer or source-specific logic found attack evidence."""
    return bool(set(event.get("signals") or []) & STRONG_ATTACK_SIGNALS)


def _integer(value: Any) -> int | None:
    """Coerce a value into an integer when possible."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
