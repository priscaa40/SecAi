from __future__ import annotations

import json

from langchain_core.tools import tool

from secai import database
from secai.settings import get_settings
from secai.integrations import alibaba_autopilot
from secai.event_sources import alibaba_sls
from secai.knowledge import mcp_client as security_knowledge_mcp


@tool
def get_recent_events_for_site(site_id: str, limit: int = 25) -> str:
    """Return recent normalized SecAi events for a site as JSON."""
    capped_limit = min(limit, get_settings().secai_recent_event_limit)
    events = database.recent_events(site_id, limit=capped_limit)
    return json.dumps(events, default=str)


@tool
def summarize_event_window(site_id: str, ip: str | None = None, path: str | None = None, limit: int = 100) -> str:
    """Summarize recent event counts by IP, route, and evidence hints for investigation."""
    capped_limit = min(limit, get_settings().secai_recent_event_limit)
    events = database.recent_events(site_id, limit=capped_limit)
    if ip:
        events = [event for event in events if event.get("ip") == ip]
    if path:
        events = [event for event in events if event.get("path") == path]
    signals: dict[str, int] = {}
    routes: dict[str, int] = {}
    ips: dict[str, int] = {}
    for event in events:
        if event.get("path"):
            routes[event["path"]] = routes.get(event["path"], 0) + 1
        if event.get("ip"):
            ips[event["ip"]] = ips.get(event["ip"], 0) + 1
        for signal in event.get("signals", []):
            signals[signal] = signals.get(signal, 0) + 1
    return json.dumps(
        {
            "event_count": len(events),
            "top_routes": sorted(routes.items(), key=lambda item: item[1], reverse=True)[:5],
            "top_ips": sorted(ips.items(), key=lambda item: item[1], reverse=True)[:5],
            "evidence_hints": sorted(signals.items(), key=lambda item: item[1], reverse=True)[:8],
        },
        default=str,
    )


@tool
def pull_live_sls_logs(site_id: str, minutes: int = 15, query: str = "*", limit: int = 50) -> str:
    """Pull fresh security-relevant Alibaba SLS events for a connected site during investigation."""
    capped_limit = max(1, min(limit, 100))
    capped_minutes = max(1, min(minutes, 60))
    try:
        events = alibaba_sls.fetch_saved_site_events(site_id, query=query, minutes=capped_minutes, limit=capped_limit)
    except alibaba_sls.SlsNotConfigured:
        return json.dumps({"error": "alibaba_sls_not_connected", "message": "This site has no Alibaba SLS connection configured."})
    except alibaba_sls.SlsConnectionRevoked as exc:
        return json.dumps(
            {
                "error": "alibaba_sls_connection_revoked",
                "message": "The site owner needs to reconnect Alibaba SLS.",
                "detail": str(exc),
            }
        )
    except Exception as exc:
        return json.dumps({"error": "alibaba_sls_pull_failed", "message": str(exc)})
    stored_events: list[dict] = []
    duplicates_skipped = 0
    for event in events:
        stored_event = database.insert_event(event)
        if stored_event.pop("_deduplicated", False):
            duplicates_skipped += 1
        stored_events.append(stored_event)
    return json.dumps(
        {
            "events_seen": len(events),
            "events_persisted": len(events) - duplicates_skipped,
            "duplicates_skipped": duplicates_skipped,
            "minutes": capped_minutes,
            "query": query,
            "events": stored_events,
        },
        default=str,
    )


@tool
def get_site_policies(site_id: str) -> str:
    """Return currently approved SecAi policies for a site as JSON."""
    return json.dumps(database.list_policies(site_id), default=str)


@tool
def list_security_profiles() -> str:
    """Return source-backed SecAi security profiles as JSON."""
    return json.dumps(security_knowledge_mcp.call_tool("list_security_profiles"), default=str)


@tool
def lookup_security_profile(entry_id: str) -> str:
    """Return one source-backed SecAi security profile by ID as JSON."""
    return json.dumps(security_knowledge_mcp.call_tool("lookup_security_profile", {"entry_id": entry_id}), default=str)


@tool
def find_matching_security_profiles(event_json: str) -> str:
    """Return likely source-backed SecAi security profiles for a serialized event JSON object."""
    try:
        event = json.loads(event_json)
    except json.JSONDecodeError:
        event = {"metadata": {"raw": event_json}}
    return json.dumps(security_knowledge_mcp.call_tool("find_matching_security_profiles", {"event": event}), default=str)


@tool
def get_remediation_options(entry_id: str, site_id: str | None = None) -> str:
    """Return allowed remediation options for a source-backed SecAi security profile."""
    options = security_knowledge_mcp.call_tool("get_remediation_options", {"entry_id": entry_id})
    if site_id and not options.get("error"):
        profile_actions = options.get("allowed_actions", [])
        site_actions = alibaba_autopilot.available_actions_for_site(site_id, profile_actions)
        options = {
            **options,
            "site_id": site_id,
            "site_available_actions": site_actions,
            "site_autopilot_status": alibaba_autopilot.site_status(site_id),
        }
    return json.dumps(options, default=str)


@tool
def search_nvd_vulnerabilities(keyword: str | None = None, cwe_id: str | None = None, limit: int = 5) -> str:
    """Search the official NVD CVE API for current vulnerability context."""
    return json.dumps(
        security_knowledge_mcp.call_tool("search_nvd_vulnerabilities", {"keyword": keyword, "cwe_id": cwe_id, "limit": limit}),
        default=str,
    )


@tool
def query_osv_package_vulnerabilities(ecosystem: str, package: str, version: str | None = None) -> str:
    """Query the official OSV API for package vulnerability context."""
    return json.dumps(
        security_knowledge_mcp.call_tool(
            "query_osv_package_vulnerabilities",
            {"ecosystem": ecosystem, "package": package, "version": version},
        ),
        default=str,
    )
