from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from mcp.server.fastmcp import FastMCP

from secai.knowledge.security_knowledge_data import (
    OFFICIAL_SOURCE_URLS,
    SECURITY_PROFILES,
)

mcp = FastMCP(
    "SecAi Security Knowledge",
    instructions="Read-only, source-backed security knowledge for the SecAi Qwen investigator.",
    json_response=True,
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


@mcp.tool(name="list_security_profiles")
def mcp_list_security_profiles() -> list[dict[str, Any]]:
    """List source-backed security profiles available to the investigator."""
    return list_entries()


@mcp.tool(name="lookup_security_profile")
def mcp_lookup_security_profile(entry_id: str) -> dict[str, Any]:
    """Return one security profile with official source references."""
    return get_entry(entry_id) or {"error": "unknown security profile"}


@mcp.tool(name="find_matching_security_profiles")
def mcp_find_matching_security_profiles(event: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    """Find security profiles that match normalized, untrusted event evidence."""
    return find_matching_entries(event, limit=max(1, min(limit, 10)))


@mcp.tool(name="search_nvd_vulnerabilities")
def mcp_search_nvd_vulnerabilities(
    keyword: str | None = None,
    cwe_id: str | None = None,
    limit: int = 5,
) -> dict[str, Any]:
    """Search the official NVD API for vulnerability context."""
    return search_nvd(keyword=keyword, cwe_id=cwe_id, limit=limit)


@mcp.tool(name="query_osv_package_vulnerabilities")
def mcp_query_osv_package_vulnerabilities(
    ecosystem: str,
    package: str,
    version: str | None = None,
) -> dict[str, Any]:
    """Query the official OSV API for package vulnerability context."""
    return query_osv(ecosystem=ecosystem, package=package, version=version)


def main() -> None:
    """Run the official SecAi security knowledge MCP server over stdio."""
    mcp.run(transport="stdio")


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
