from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from langchain_core.tools import tool

from secai import database
from secai.event_sources import alibaba_sls
from secai.knowledge import mcp_client as security_knowledge_mcp
from secai.settings import get_settings

_site_scope: ContextVar[str | None] = ContextVar("secai_agent_tool_site", default=None)


@contextmanager
def scoped_site(site_id: str) -> Iterator[None]:
    """Limit tenant-aware agent tools to the event's website."""
    token = _site_scope.set(site_id)
    try:
        yield
    finally:
        _site_scope.reset(token)


@tool
def get_recent_events_for_site(site_id: str, limit: int = 25) -> str:
    """Return recent normalized SecAi events for a site as JSON."""
    if error := _site_scope_error(site_id):
        return error
    capped_limit = min(limit, get_settings().secai_recent_event_limit)
    events = database.recent_analysis_events(site_id, limit=capped_limit)
    return _bounded_tool_json(events)


@tool
def summarize_event_window(site_id: str, ip: str | None = None, path: str | None = None, limit: int = 100) -> str:
    """Summarize recent event counts by IP, route, and evidence hints for investigation."""
    if error := _site_scope_error(site_id):
        return error
    capped_limit = min(limit, get_settings().secai_recent_event_limit)
    events = database.recent_analysis_events(site_id, limit=capped_limit)
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
    )


@tool
def pull_live_sls_logs(site_id: str, minutes: int = 15, query: str = "*", limit: int = 50) -> str:
    """Read fresh Alibaba SLS evidence without persisting or independently analyzing it."""
    if error := _site_scope_error(site_id):
        return error
    capped_limit = max(1, min(limit, get_settings().secai_recent_event_limit))
    capped_minutes = max(1, min(minutes, 60))
    try:
        events = alibaba_sls.fetch_saved_site_events(site_id, query=query, minutes=capped_minutes, limit=capped_limit)
    except alibaba_sls.SlsNotConfigured:
        return json.dumps(
            {"error": "alibaba_sls_not_connected", "message": "This site has no Alibaba SLS connection configured."}
        )
    except Exception:
        return json.dumps({"error": "alibaba_sls_pull_failed", "message": "Alibaba SLS could not be queried."})
    return _bounded_tool_json(
        {
            "events_seen": len(events),
            "read_only": True,
            "minutes": capped_minutes,
            "query": query,
            "events": events,
        },
    )


@tool
def get_site_policies(site_id: str) -> str:
    """Return currently approved SecAi policies for a site as JSON."""
    if error := _site_scope_error(site_id):
        return error
    return _bounded_tool_json(database.list_policies(site_id, limit=25))


@tool
def list_security_profiles() -> str:
    """Return source-backed SecAi security profiles as JSON."""
    return json.dumps(_security_knowledge_payload("list_security_profiles"), default=str)


@tool
def lookup_security_profile(entry_id: str) -> str:
    """Return one source-backed SecAi security profile by ID as JSON."""
    return json.dumps(_security_knowledge_payload("lookup_security_profile", {"entry_id": entry_id}), default=str)


@tool
def find_matching_security_profiles(event_json: str) -> str:
    """Return likely source-backed SecAi security profiles for a serialized event JSON object."""
    try:
        event = json.loads(event_json)
    except json.JSONDecodeError:
        event = {"metadata": {"raw": event_json}}
    return json.dumps(_security_knowledge_payload("find_matching_security_profiles", {"event": event}), default=str)


@tool
def search_nvd_vulnerabilities(keyword: str | None = None, cwe_id: str | None = None, limit: int = 5) -> str:
    """Search the official NVD CVE API for current vulnerability context."""
    return _bounded_tool_json(
        _security_knowledge_payload(
            "search_nvd_vulnerabilities", {"keyword": keyword, "cwe_id": cwe_id, "limit": limit}
        )
    )


@tool
def query_osv_package_vulnerabilities(ecosystem: str, package: str, version: str | None = None) -> str:
    """Query the official OSV API for package vulnerability context."""
    return _bounded_tool_json(
        _security_knowledge_payload(
            "query_osv_package_vulnerabilities",
            {"ecosystem": ecosystem, "package": package, "version": version},
        )
    )


def _site_scope_error(site_id: str) -> str | None:
    scoped_site_id = _site_scope.get()
    if scoped_site_id and site_id != scoped_site_id:
        return json.dumps(
            {
                "error": "website_scope_violation",
                "message": "This investigation can only access evidence for its own website.",
            }
        )
    return None


def _security_knowledge_payload(name: str, arguments: dict | None = None):
    """Return MCP payloads in the current agent-tool JSON contract."""
    try:
        return security_knowledge_mcp.call_tool(name, arguments)
    except security_knowledge_mcp.SecurityKnowledgeMcpError:
        return {
            "error": "security_knowledge_unavailable",
            "tool": name,
            "message": "The security knowledge service is temporarily unavailable.",
        }


def _bounded_tool_json(value: object) -> str:
    """Keep tool responses below the shared Qwen context budget."""
    rendered = json.dumps(value, default=str, separators=(",", ":"))
    limit = max(2000, get_settings().secai_model_context_chars // 2)
    if len(rendered) <= limit:
        return rendered
    return json.dumps({"truncated": True, "preview": rendered[: limit - 50]}, separators=(",", ":"))
