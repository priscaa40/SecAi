from __future__ import annotations

import json
import os
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import sys
from typing import Any, Callable


OFFICIAL_SOURCE_URLS = {
    "CAPEC": "https://capec.mitre.org/data/downloads.html",
    "CWE": "https://cwe.mitre.org/data/downloads.html",
    "NIST": "https://nvd.nist.gov/developers/vulnerabilities",
    "OSV": "https://google.github.io/osv.dev/api/",
    "OWASP_AUTOMATED_THREATS": "https://owasp.org/www-project-automated-threats-to-web-applications/",
    "OWASP_CHEAT_SHEETS": "https://owasp.org/www-project-cheat-sheets/",
}

SERVER_INFO = {"name": "secai-security-knowledge", "version": "0.1.0"}

MCP_TOOLS: dict[str, dict[str, Any]] = {
    "list_security_profiles": {
        "description": "Return source-backed SecAi security profiles.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    "lookup_security_profile": {
        "description": "Return one source-backed SecAi security profile by ID.",
        "inputSchema": {
            "type": "object",
            "properties": {"entry_id": {"type": "string"}},
            "required": ["entry_id"],
            "additionalProperties": False,
        },
    },
    "find_matching_security_profiles": {
        "description": "Return likely SecAi security profiles for a serialized event JSON object.",
        "inputSchema": {
            "type": "object",
            "properties": {"event": {"type": "object"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10}},
            "required": ["event"],
            "additionalProperties": False,
        },
    },
    "get_remediation_options": {
        "description": "Return allowed remediation options for a source-backed SecAi security profile.",
        "inputSchema": {
            "type": "object",
            "properties": {"entry_id": {"type": "string"}},
            "required": ["entry_id"],
            "additionalProperties": False,
        },
    },
    "search_nvd_vulnerabilities": {
        "description": "Search the official NVD CVE API for current vulnerability context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string"},
                "cwe_id": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 20},
            },
            "additionalProperties": False,
        },
    },
    "query_osv_package_vulnerabilities": {
        "description": "Query the official OSV API for package vulnerability context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ecosystem": {"type": "string"},
                "package": {"type": "string"},
                "version": {"type": "string"},
            },
            "required": ["ecosystem", "package"],
            "additionalProperties": False,
        },
    },
}


SECURITY_PROFILES: list[dict[str, Any]] = [
    {
        "id": "sql_injection_attempt",
        "name": "SQL injection attempt",
        "sources": ["CAPEC:66", "CWE:89", "OWASP:SQL_INJECTION_CHEAT_SHEET", "OWASP:TOP_10_INJECTION"],
        "what_it_means": "An input appears to be trying to alter a database query.",
        "evidence_signs": [
            "SQL operators or comment syntax in query/body",
            "database error messages after unusual input",
            "repeated probing of parameterized routes",
        ],
        "confidence_boosters": [
            "same IP tries multiple SQL-like payloads",
            "payload appears in query parameters or form fields",
            "server errors follow SQL-like input",
        ],
        "false_positive_cautions": [
            "search boxes and admin tools may contain technical text legitimately",
            "developer documentation pages may contain SQL examples",
        ],
        "safe_recommendations": [
            "review the affected route",
            "use parameterized queries",
            "validate inputs server-side",
            "apply a temporary WAF virtual patch after approval",
        ],
        "allowed_actions": ["monitor", "notify_admin", "block_ip", "block_ip_range", "rate_limit_ip", "rate_limit_route", "block_payload_pattern", "virtual_patch"],
        "requires_approval": ["block_ip", "block_ip_range", "rate_limit_ip", "rate_limit_route", "block_payload_pattern", "virtual_patch"],
        "user_explanation": "Someone may be trying to make your app run database commands through a normal input field.",
    },
    {
        "id": "cross_site_scripting_attempt",
        "name": "Cross-site scripting attempt",
        "sources": ["CAPEC:63", "CWE:79", "OWASP:XSS_PREVENTION_CHEAT_SHEET", "OWASP:TOP_10_INJECTION"],
        "what_it_means": "An input appears to be trying to inject JavaScript or HTML into a page.",
        "evidence_signs": [
            "script tags or JavaScript URLs in query/body",
            "HTML event handlers such as onerror or onload",
            "payload submitted to comments, profiles, search, or contact forms",
        ],
        "confidence_boosters": [
            "payload is reflected in a response",
            "same source repeats script-like payloads",
            "target route accepts user-generated content",
        ],
        "false_positive_cautions": [
            "developer docs, CMS editors, and code samples may legitimately include HTML or JavaScript",
        ],
        "safe_recommendations": [
            "review where the input is rendered",
            "encode output by context",
            "sanitize rich text inputs",
            "apply a temporary payload-blocking rule after approval",
        ],
        "allowed_actions": ["monitor", "notify_admin", "block_ip", "block_ip_range", "rate_limit_ip", "rate_limit_route", "block_payload_pattern", "virtual_patch"],
        "requires_approval": ["block_ip", "block_ip_range", "rate_limit_ip", "rate_limit_route", "block_payload_pattern", "virtual_patch"],
        "user_explanation": "Someone may be trying to inject browser code into a page viewed by you or your users.",
    },
    {
        "id": "path_traversal_attempt",
        "name": "Path traversal attempt",
        "sources": ["CAPEC:126", "CWE:22", "OWASP:INPUT_VALIDATION_CHEAT_SHEET"],
        "what_it_means": "A request appears to be trying to access files outside the intended directory.",
        "evidence_signs": [
            "../ or ..\\ sequences in path/query",
            "references to sensitive files such as /etc/passwd or boot.ini",
            "download or file-view routes receive unusual file paths",
        ],
        "confidence_boosters": [
            "target route handles files",
            "multiple encoded traversal attempts from the same source",
            "403 or 500 responses after traversal payloads",
        ],
        "false_positive_cautions": [
            "some support tickets or documentation pages may include path examples",
        ],
        "safe_recommendations": [
            "review file access controls",
            "normalize and constrain file paths",
            "use allow-listed file identifiers",
            "apply a temporary WAF virtual patch after approval",
        ],
        "allowed_actions": ["monitor", "notify_admin", "block_ip", "block_ip_range", "rate_limit_ip", "rate_limit_route", "block_payload_pattern", "virtual_patch", "disable_route"],
        "requires_approval": ["block_ip", "block_ip_range", "rate_limit_ip", "rate_limit_route", "block_payload_pattern", "virtual_patch", "disable_route"],
        "user_explanation": "Someone may be trying to read files your website should never expose.",
    },
    {
        "id": "credential_stuffing_or_cracking",
        "name": "Credential stuffing or credential cracking",
        "sources": ["OWASP:OAT_007", "OWASP:OAT_008", "OWASP:CREDENTIAL_STUFFING_CHEAT_SHEET", "NIST:SP_800_61"],
        "what_it_means": "Automated login attempts may be testing stolen or guessed credentials.",
        "evidence_signs": [
            "many failed login attempts",
            "many accounts tried from one source",
            "same account tried from many sources",
            "automation-like user agents on authentication routes",
        ],
        "confidence_boosters": [
            "high failure rate over a short time window",
            "repeated attempts on /login or /auth routes",
            "successful login after many failures",
        ],
        "false_positive_cautions": [
            "a real user may mistype a password several times",
            "company VPNs can make many users appear from one IP",
        ],
        "safe_recommendations": [
            "rate-limit the login route",
            "notify affected users after review",
            "encourage MFA",
            "challenge suspicious login traffic after approval",
        ],
        "allowed_actions": ["monitor", "notify_admin", "block_ip", "block_ip_range", "rate_limit_ip", "rate_limit_route", "challenge_route"],
        "requires_approval": ["block_ip", "block_ip_range", "rate_limit_ip", "rate_limit_route", "challenge_route"],
        "user_explanation": "Someone may be using automation to try passwords against your login page.",
    },
    {
        "id": "bot_scraping",
        "name": "Bot scraping",
        "sources": ["OWASP:OAT_011", "OWASP:AUTOMATED_THREATS"],
        "what_it_means": "Automated clients may be collecting content or data from the site.",
        "evidence_signs": [
            "high request volume across many pages",
            "automation-like user agent",
            "low think time between requests",
            "repeated access to list/search pages",
        ],
        "confidence_boosters": [
            "many sequential pages requested quickly",
            "same source ignores normal navigation patterns",
        ],
        "false_positive_cautions": [
            "search engine crawlers and uptime monitors can look automated",
        ],
        "safe_recommendations": [
            "verify whether the client is a legitimate crawler",
            "rate-limit high-volume routes",
            "challenge automated traffic after approval",
        ],
        "allowed_actions": ["monitor", "notify_admin", "rate_limit_ip", "rate_limit_route", "challenge_route", "block_ip"],
        "requires_approval": ["rate_limit_ip", "rate_limit_route", "challenge_route", "block_ip"],
        "user_explanation": "Automated traffic may be copying pages or data from your site.",
    },
    {
        "id": "contact_form_spam",
        "name": "Contact-form spam",
        "sources": ["OWASP:OAT_017", "OWASP:AUTOMATED_THREATS"],
        "what_it_means": "Automated clients may be submitting unwanted content through forms.",
        "evidence_signs": [
            "many form submissions in a short window",
            "spam-like content or repeated messages",
            "automation-like user agent",
        ],
        "confidence_boosters": [
            "same IP submits repeated messages",
            "many failed or low-quality submissions target the same form",
        ],
        "false_positive_cautions": [
            "marketing campaigns can create sudden legitimate contact spikes",
        ],
        "safe_recommendations": [
            "monitor submissions",
            "add server-side validation",
            "rate-limit form endpoint after approval",
            "challenge or temporarily block abusive form traffic after approval",
        ],
        "allowed_actions": ["monitor", "notify_admin", "rate_limit_ip", "rate_limit_route", "block_payload_pattern", "challenge_route", "block_ip"],
        "requires_approval": ["rate_limit_ip", "rate_limit_route", "block_payload_pattern", "challenge_route", "block_ip"],
        "user_explanation": "Automated traffic may be abusing your contact or signup forms.",
    },
    {
        "id": "vulnerability_scanning_or_probing",
        "name": "Vulnerability scanning or probing",
        "sources": ["OWASP:OAT_014", "CAPEC:310", "NIST:SP_800_61"],
        "what_it_means": "A client appears to be exploring the app to identify weaknesses.",
        "evidence_signs": [
            "requests for many uncommon paths",
            "probing admin, config, backup, or framework-specific routes",
            "many 404/403 responses from one source",
        ],
        "confidence_boosters": [
            "broad route coverage in a short window",
            "known scanner user agent",
            "attempts to access sensitive filenames",
        ],
        "false_positive_cautions": [
            "security tools run by the owner can look like probing",
            "broken links can produce many 404s",
        ],
        "safe_recommendations": [
            "review requested paths",
            "hide sensitive files",
            "enable anti-scan protection after approval",
            "temporarily block abusive source IP after approval",
        ],
        "allowed_actions": ["monitor", "notify_admin", "enable_anti_scan", "block_ip", "block_ip_range", "rate_limit_ip", "rate_limit_route"],
        "requires_approval": ["enable_anti_scan", "block_ip", "block_ip_range", "rate_limit_ip", "rate_limit_route"],
        "user_explanation": "Someone may be mapping your site looking for weak spots.",
    },
    {
        "id": "server_error_spike",
        "name": "Server error spike",
        "sources": ["NIST:SP_800_61", "OWASP:LOGGING_CHEAT_SHEET"],
        "what_it_means": "A route or source is associated with unusual server errors.",
        "evidence_signs": [
            "multiple 500-level responses",
            "errors cluster around one route",
            "errors follow unusual payloads or request sizes",
        ],
        "confidence_boosters": [
            "sudden increase from normal baseline",
            "same route fails repeatedly",
            "error follows suspicious input",
        ],
        "false_positive_cautions": [
            "deployments, outages, or dependency failures can cause benign spikes",
        ],
        "safe_recommendations": [
            "notify admin",
            "review logs for stack traces",
            "rate-limit or temporarily disable the affected route after approval",
        ],
        "allowed_actions": ["monitor", "notify_admin", "rate_limit_route", "read_only_route", "disable_route"],
        "requires_approval": ["rate_limit_route", "read_only_route", "disable_route"],
        "user_explanation": "A part of your site is failing more than expected and needs review.",
    },
    {
        "id": "suspicious_authentication_failure_burst",
        "name": "Suspicious authentication failure burst",
        "sources": ["OWASP:CREDENTIAL_STUFFING_CHEAT_SHEET", "NIST:SP_800_61"],
        "what_it_means": "Authentication failures are clustered enough to deserve review.",
        "evidence_signs": [
            "several failed login attempts",
            "failures target one account or one route",
            "failures cluster around one IP or user agent",
        ],
        "confidence_boosters": [
            "burst is higher than normal",
            "multiple accounts are targeted",
            "same source repeats attempts",
        ],
        "false_positive_cautions": [
            "one real user may be locked out",
            "shared networks can group legitimate users under one IP",
        ],
        "safe_recommendations": [
            "monitor",
            "notify admin",
            "rate-limit or challenge login route after approval",
        ],
        "allowed_actions": ["monitor", "notify_admin", "rate_limit_route", "challenge_route"],
        "requires_approval": ["rate_limit_route", "challenge_route"],
        "user_explanation": "Login failures are clustered in a way that may indicate abuse.",
    },
    {
        "id": "unknown_suspicious_activity",
        "name": "Unknown suspicious activity",
        "sources": ["NIST:SP_800_61"],
        "what_it_means": "The evidence is unusual but does not clearly match a known SecAi security profile.",
        "evidence_signs": [
            "unusual activity that does not map cleanly to another entry",
            "connector-provided hints are weak or conflicting",
        ],
        "confidence_boosters": [
            "repeat activity from same source",
            "activity affects sensitive routes",
        ],
        "false_positive_cautions": [
            "insufficient context can make normal behavior look suspicious",
        ],
        "safe_recommendations": [
            "request more evidence",
            "monitor",
            "notify admin",
        ],
        "allowed_actions": ["monitor", "notify_admin"],
        "requires_approval": [],
        "user_explanation": "SecAi noticed something unusual, but more evidence is needed before naming it.",
    },
]


def list_entries() -> list[dict[str, Any]]:
    """Return every source-backed security profile."""
    return [_public_entry(entry) for entry in SECURITY_PROFILES]


def get_entry(entry_id: str) -> dict[str, Any] | None:
    """Return one source-backed security profile by ID."""
    for entry in SECURITY_PROFILES:
        if entry["id"] == entry_id:
            return _with_source_metadata(entry)
    return None


def valid_entry_ids() -> set[str]:
    """Return every allowed security profile ID."""
    return {entry["id"] for entry in SECURITY_PROFILES}


def valid_source_ids(entry_id: str) -> set[str]:
    """Return the approved source IDs for one security profile."""
    entry = get_entry(entry_id)
    return set(entry["sources"]) if entry else set()


def valid_attack_names() -> set[str]:
    """Return every attack name the agent is allowed to use."""
    return {entry["name"] for entry in SECURITY_PROFILES}


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
        for field in ("name", "what_it_means", "user_explanation"):
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


def remediation_options(entry_id: str) -> dict[str, Any] | None:
    """Return safe remediation choices for one security profile."""
    entry = get_entry(entry_id)
    if not entry:
        return None
    return {
        "id": entry["id"],
        "name": entry["name"],
        "sources": entry["sources"],
        "safe_recommendations": entry["safe_recommendations"],
        "allowed_actions": entry["allowed_actions"],
        "requires_approval": entry["requires_approval"],
        "false_positive_cautions": entry["false_positive_cautions"],
    }


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
                "weaknesses": cve.get("weaknesses", []),
                "metrics": metrics,
                "references": cve.get("references", {}).get("referenceData", [])[:5],
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
    return {
        "source": "OSV",
        "url": OFFICIAL_SOURCE_URLS["OSV"],
        "query": payload,
        "vulnerabilities": data.get("vulns", []),
    }


def call_tool(name: str | None, arguments: dict[str, Any] | None = None) -> Any:
    """Call one SecAi security knowledge MCP tool by name."""
    args = arguments or {}
    handlers: dict[str, Callable[[dict[str, Any]], Any]] = {
        "list_security_profiles": lambda params: list_entries(),
        "lookup_security_profile": lambda params: get_entry(params["entry_id"]) or {"error": "unknown security profile"},
        "find_matching_security_profiles": lambda params: find_matching_entries(params["event"], limit=params.get("limit", 5)),
        "get_remediation_options": lambda params: remediation_options(params["entry_id"]) or {"error": "unknown security profile"},
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
            return _result(request_id, {"content": [{"type": "text", "text": json.dumps(payload, default=str)}], "isError": False})
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
        "safe_recommendations": entry["safe_recommendations"],
        "allowed_actions": entry["allowed_actions"],
        "requires_approval": entry["requires_approval"],
        "user_explanation": entry["user_explanation"],
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
