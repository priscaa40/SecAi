from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from typing import Any
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from secai.knowledge.security_knowledge_data import (
    MCP_TOOLS,
    OFFICIAL_SOURCE_URLS,
    SECURITY_PROFILES,
    SERVER_INFO,
)


def list_entries() -> list[dict[str, Any]]:
    """Return every source-backed security profile."""
    return [_public_entry(entry) for entry in SECURITY_PROFILES]


def get_entry(entry_id: str) -> dict[str, Any] | None:
    """Return one source-backed security profile by ID."""
    for entry in SECURITY_PROFILES:
        if entry["id"] == entry_id:
            return _with_source_metadata(entry)
    return None


def find_matching_entries(event: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    """Find source-backed security profiles that best match one event."""
    text_parts = [
        str(event.get("path") or ""),
        str(event.get("query") or ""),
        str(event.get("payload") or ""),
        " ".join(event.get("signals") or []),
        json.dumps(event.get("metadata") or {}, default=str),
        str(event.get("status_code") or ""),
        str(event.get("user_agent") or ""),
    ]
    haystack = " ".join(text_parts).lower()
    scored: list[tuple[int, dict[str, Any]]] = []
    for entry in SECURITY_PROFILES:
        score = 0
        for field in ("name", "what_it_means"):
            if any(token in haystack for token in str(entry[field]).lower().split()):
                score += 1
        for sign in entry["evidence_signs"]:
            score += sum(1 for token in _keywords(sign) if token in haystack)
        for source in entry["sources"]:
            if source.lower().replace(":", "_") in haystack:
                score += 2
        if score:
            scored.append((score, entry))
    scored.sort(key=lambda item: item[0], reverse=True)
    if not scored:
        return [_public_entry(get_entry("unknown_suspicious_activity"))]
    return [_public_entry(entry) for _, entry in scored[:limit]]


def search_nvd(keyword: str | None = None, cwe_id: str | None = None, limit: int = 5) -> dict[str, Any]:
    """Search the official NVD CVE API for current vulnerability context."""
    params: dict[str, Any] = {"resultsPerPage": max(1, min(limit, 20))}
    if keyword:
        params["keywordSearch"] = keyword
    if cwe_id:
        params["cweId"] = cwe_id
    if not keyword and not cwe_id:
        return {"source": "NVD", "error": "keyword or cwe_id is required"}
    data = _get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{urlencode(params)}")
    vulnerabilities = []
    for item in data.get("vulnerabilities", [])[:limit]:
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        vulnerabilities.append(
            {
                "id": cve.get("id"),
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "descriptions": cve.get("descriptions", [])[:2],
                "weaknesses": cve.get("weaknesses", [])[:5],
                "metrics": metrics,
                "references": cve.get("references", [])[:5],
            }
        )
    return {
        "source": "NVD",
        "url": OFFICIAL_SOURCE_URLS["NIST"],
        "query": params,
        "total_results": data.get("totalResults", len(vulnerabilities)),
        "vulnerabilities": vulnerabilities,
    }


def query_osv(ecosystem: str, package: str, version: str | None = None) -> dict[str, Any]:
    """Query the official OSV API for package vulnerability context."""
    payload: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": package}}
    if version:
        payload["version"] = version
    data = _post_json("https://api.osv.dev/v1/query", payload)
    vulnerabilities = []
    for vulnerability in data.get("vulns", [])[:20]:
        vulnerabilities.append(
            {
                "id": vulnerability.get("id"),
                "summary": str(vulnerability.get("summary") or "")[:1000],
                "details": str(vulnerability.get("details") or "")[:2000],
                "aliases": vulnerability.get("aliases", [])[:10],
                "modified": vulnerability.get("modified"),
                "published": vulnerability.get("published"),
                "references": vulnerability.get("references", [])[:5],
            }
        )
    return {
        "source": "OSV",
        "url": OFFICIAL_SOURCE_URLS["OSV"],
        "query": payload,
        "vulnerabilities": vulnerabilities,
    }


def call_tool(name: str | None, arguments: dict[str, Any] | None = None) -> Any:
    """Call one SecAi security knowledge MCP tool by name."""
    args = arguments or {}
    handlers: dict[str, Callable[[dict[str, Any]], Any]] = {
        "list_security_profiles": lambda params: list_entries(),
        "lookup_security_profile": lambda params: (
            get_entry(params["entry_id"]) or {"error": "unknown security profile"}
        ),
        "find_matching_security_profiles": lambda params: find_matching_entries(
            params["event"], limit=params.get("limit", 5)
        ),
        "search_nvd_vulnerabilities": lambda params: search_nvd(
            keyword=params.get("keyword"),
            cwe_id=params.get("cwe_id"),
            limit=params.get("limit", 5),
        ),
        "query_osv_package_vulnerabilities": lambda params: query_osv(
            ecosystem=params["ecosystem"],
            package=params["package"],
            version=params.get("version"),
        ),
    }
    if name not in handlers:
        raise ValueError(f"Unknown security knowledge tool: {name}")
    return handlers[name](args)


def main() -> None:
    """Run the SecAi security knowledge MCP server over stdio."""
    for line in sys.stdin:
        if not line.strip():
            continue
        response = handle_message(json.loads(line))
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


def handle_message(message: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC MCP message."""
    method = message.get("method")
    request_id = message.get("id")
    try:
        if method == "initialize":
            return _result(
                request_id,
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO,
                },
            )
        if method == "notifications/initialized":
            return None
        if method == "tools/list":
            return _result(request_id, {"tools": [_tool_descriptor(name, spec) for name, spec in MCP_TOOLS.items()]})
        if method == "tools/call":
            params = message.get("params") or {}
            payload = call_tool(params.get("name"), params.get("arguments") or {})
            return _result(
                request_id,
                {"content": [{"type": "text", "text": json.dumps(payload, default=str)}], "isError": False},
            )
        return _error(request_id, -32601, f"Unknown method: {method}")
    except Exception as exc:
        return _error(request_id, -32000, str(exc))


def _public_entry(entry: dict[str, Any] | None) -> dict[str, Any]:
    """Return an entry without internal matching-only fields."""
    if not entry:
        return {}
    return {
        "id": entry["id"],
        "name": entry["name"],
        "sources": entry["sources"],
        "what_it_means": entry["what_it_means"],
        "evidence_signs": entry["evidence_signs"],
        "confidence_boosters": entry["confidence_boosters"],
        "false_positive_cautions": entry["false_positive_cautions"],
        "source_urls": source_urls(entry["sources"]),
    }


def _with_source_metadata(entry: dict[str, Any]) -> dict[str, Any]:
    """Return a profile with official source URLs attached."""
    return {**dict(entry), "source_urls": source_urls(entry["sources"])}


def source_urls(source_ids: list[str]) -> dict[str, str]:
    """Return official source collection URLs for source IDs."""
    urls: dict[str, str] = {}
    for source_id in source_ids:
        prefix = source_id.split(":", 1)[0]
        if source_id.startswith("OWASP:OAT"):
            urls[source_id] = OFFICIAL_SOURCE_URLS["OWASP_AUTOMATED_THREATS"]
        elif source_id.startswith("OWASP:"):
            urls[source_id] = OFFICIAL_SOURCE_URLS["OWASP_CHEAT_SHEETS"]
        elif prefix in OFFICIAL_SOURCE_URLS:
            urls[source_id] = OFFICIAL_SOURCE_URLS[prefix]
    return urls


def _get_json(url: str) -> dict[str, Any]:
    """Fetch JSON from an official security source."""
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "SecAi/0.1"})
    try:
        with urlopen(request, timeout=_timeout_seconds()) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"error": str(exc), "url": url}


def _post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Post JSON to an official security source."""
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "SecAi/0.1"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=_timeout_seconds()) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"error": str(exc), "url": url}


def _tool_descriptor(name: str, spec: dict[str, Any]) -> dict[str, Any]:
    """Return one MCP tool descriptor."""
    return {"name": name, "description": spec["description"], "inputSchema": spec["inputSchema"]}


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-RPC result message."""
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    """Return a JSON-RPC error message."""
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _keywords(text: str) -> set[str]:
    """Split text into simple lowercase keyword tokens."""
    return {part.strip(" ,./\\:-_()").lower() for part in text.split() if len(part.strip(" ,./\\:-_()")) > 3}


def _timeout_seconds() -> float:
    """Return the security knowledge HTTP timeout from environment."""
    try:
        return float(os.getenv("SECURITY_KNOWLEDGE_TIMEOUT_SECONDS", "8"))
    except ValueError:
        return 8.0


if __name__ == "__main__":
    main()
