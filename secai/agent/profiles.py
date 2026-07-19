from __future__ import annotations

from typing import Any

PROFILE_BY_SIGNAL = {
    "sql_injection_pattern": "sql_injection_attempt",
    "xss_pattern": "cross_site_scripting_attempt",
    "path_traversal_pattern": "path_traversal_attempt",
    "auth_failure": "suspicious_authentication_failure_burst",
    "rapid_form_submit": "automated_form_abuse",
    "server_error": "server_error_spike",
}

PROFILE_BY_EVENT_TYPE = {
    "sls_bot_activity_group": "bot_scraping",
    "sls_client_error_group": "vulnerability_scanning_or_probing",
    "sls_not_found_scan_group": "vulnerability_scanning_or_probing",
    "sls_rate_limited_group": "bot_scraping",
}


def candidate_profile_ids(event: dict[str, Any]) -> set[str]:
    """Return the deterministic profile candidates supplied to the investigator."""
    profile_ids = {PROFILE_BY_SIGNAL[signal] for signal in event.get("signals") or [] if signal in PROFILE_BY_SIGNAL}
    if profile_id := PROFILE_BY_EVENT_TYPE.get(str(event.get("event_type") or "")):
        profile_ids.add(profile_id)
    status_code = _status_code(event.get("status_code"))
    if status_code in {401, 403}:
        profile_ids.add("suspicious_authentication_failure_burst")
    if status_code is not None and status_code >= 500:
        profile_ids.add("server_error_spike")
    return profile_ids or {"unknown_suspicious_activity"}


def _status_code(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
