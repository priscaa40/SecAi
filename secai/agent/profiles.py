from __future__ import annotations

from typing import Any, TypedDict

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

class OwnerRecommendation(TypedDict):
    incident_title: str
    title: str
    explanation: str
    steps: list[str]


OWNER_RECOMMENDATIONS: dict[str, OwnerRecommendation] = {
    "sql_injection_attempt": {
        "incident_title": "Database attack attempt detected",
        "title": "Secure the affected form and check for database impact",
        "explanation": "Prevent submitted text from changing database commands, then confirm whether the attempts reached the server or database.",
        "steps": [
            "Ensure every database operation used by the affected route relies on parameterized queries.",
            "Review application and database logs around the incident time for unusual queries, errors, data reads, or data changes.",
            "Confirm whether the submitted values reached the server or database.",
            "If the route cannot be confirmed safe immediately, temporarily disable its database-backed submission endpoint until it is secured.",
        ],
    },
    "cross_site_scripting_attempt": {
        "incident_title": "Malicious script submission detected",
        "title": "Prevent submitted content from running as website code",
        "explanation": "Secure how the affected route accepts, stores, and displays user-provided content, then check whether the submitted script reached another visitor.",
        "steps": [
            "Encode user-provided content for the page context where it is displayed.",
            "Sanitize any rich text or HTML that the route intentionally allows.",
            "Check whether the submitted content was stored or displayed to another visitor.",
            "Remove any stored malicious content and invalidate affected sessions if execution is confirmed.",
        ],
    },
    "path_traversal_attempt": {
        "incident_title": "Restricted file access attempt detected",
        "title": "Restrict file access and check for unexpected downloads",
        "explanation": "Prevent the affected route from accepting arbitrary file paths and verify that protected files were not returned.",
        "steps": [
            "Replace user-provided file paths with a fixed allowlist of file identifiers.",
            "Normalize and validate every server-side file path before access.",
            "Review file-access and application logs around the incident time for unexpected downloads.",
            "Remove public access to any exposed backup, configuration, credential, or system files.",
        ],
    },
    "credential_stuffing_or_cracking": {
        "incident_title": "Repeated login attack detected",
        "title": "Protect the targeted accounts and strengthen login controls",
        "explanation": "Check whether any login succeeded after the repeated failures and prevent further automated attempts.",
        "steps": [
            "Review targeted accounts for successful logins during or shortly after the attack.",
            "Revoke suspicious sessions and reset credentials for any account that may be compromised.",
            "Add multi-factor authentication or a step-up challenge to sensitive login flows.",
            "Apply server-side login rate limits that account for both source and targeted account.",
        ],
    },
    "suspicious_authentication_failure_burst": {
        "incident_title": "Unusual login failures detected",
        "title": "Check the affected accounts and secure the login flow",
        "explanation": "Determine whether the failures were followed by a successful login and protect any account showing signs of compromise.",
        "steps": [
            "Check whether a successful login followed the failed attempts.",
            "Review the targeted accounts, devices, locations, and active sessions for unusual activity.",
            "Revoke suspicious sessions and reset credentials for any confirmed compromise.",
            "Apply server-side rate limits or a step-up challenge if the failures continue.",
        ],
    },
    "bot_scraping": {
        "incident_title": "Automated content collection detected",
        "title": "Confirm the traffic and protect high-value content",
        "explanation": "Determine whether the automation is approved, then limit access to expensive, private, or commercially valuable data if needed.",
        "steps": [
            "Confirm that the source is not an approved search crawler, uptime monitor, integration, or internal tool.",
            "Review which pages and records were collected and whether any private data was exposed.",
            "Add authenticated quotas or server-side rate limits to expensive and high-value routes.",
            "Restrict the source only after legitimate automation has been ruled out.",
        ],
    },
    "automated_form_abuse": {
        "incident_title": "Automated form abuse detected",
        "title": "Review the submissions and protect the affected form",
        "explanation": "Confirm what the server accepted, remove harmful submissions, and prevent continued automated use.",
        "steps": [
            "Review server-side records for the affected form to confirm what was accepted.",
            "Remove fraudulent, spam, or harmful submissions and reverse any resulting actions.",
            "Add a server-side rate limit or challenge to the form if repeated abuse is confirmed.",
            "Keep accessibility and legitimate retries working when adding the new control.",
        ],
    },
    "vulnerability_scanning_or_probing": {
        "incident_title": "Website weakness probing detected",
        "title": "Close exposed routes and remove unnecessary system details",
        "explanation": "Verify that the requested files and administration routes are not public, then reduce information that helps further probing.",
        "steps": [
            "Confirm that administration, backup, debug, configuration, and framework files are not publicly accessible.",
            "Remove sample files and unused routes from the production website.",
            "Disable detailed production error pages and unnecessary version information.",
            "Review successful responses during the probing window for unexpected file or page access.",
        ],
    },
    "server_error_spike": {
        "incident_title": "Unusual server errors detected",
        "title": "Find the failing component and restore reliable service",
        "explanation": "Identify what changed or failed on the affected route, then confirm whether suspicious input contributed to the errors.",
        "steps": [
            "Inspect application logs for the affected route and the dependency that returned the error.",
            "Compare the start of the errors with recent releases, configuration changes, and dependency failures.",
            "Roll back the related release if the errors began immediately after deployment.",
            "Validate and limit unusual input if it contributed to the failures.",
        ],
    },
    "unknown_suspicious_activity": {
        "incident_title": "Suspicious website activity detected",
        "title": "Review the affected route and confirm the impact",
        "explanation": "Use server-side records to determine what the activity reached and close any exposed behavior before it continues.",
        "steps": [
            "Review application and access logs around the incident time.",
            "Confirm what the affected route accepted, returned, or changed.",
            "Restrict the route temporarily if its safety cannot be confirmed.",
            "Add a targeted server-side control once the behavior is understood.",
        ],
    },
}


def owner_recommendation(profile_id: str) -> OwnerRecommendation:
    """Return reviewed client guidance for every reportable security profile."""
    return OWNER_RECOMMENDATIONS.get(profile_id, OWNER_RECOMMENDATIONS["unknown_suspicious_activity"])


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
