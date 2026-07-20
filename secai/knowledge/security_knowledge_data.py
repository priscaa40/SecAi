from __future__ import annotations

from typing import Any

OFFICIAL_SOURCE_URLS = {
    "CAPEC": "https://capec.mitre.org/data/downloads.html",
    "CWE": "https://cwe.mitre.org/data/downloads.html",
    "NIST": "https://nvd.nist.gov/developers/vulnerabilities",
    "OSV": "https://google.github.io/osv.dev/api/",
    "OWASP_AUTOMATED_THREATS": "https://owasp.org/www-project-automated-threats-to-web-applications/",
    "OWASP_CHEAT_SHEETS": "https://owasp.org/www-project-cheat-sheets/",
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
    },
    {
        "id": "automated_form_abuse",
        "name": "Automated form abuse",
        "sources": ["OWASP:OAT_017", "OWASP:AUTOMATED_THREATS"],
        "what_it_means": "A website form is being submitted unusually quickly and may be driven by automation or repeated misuse.",
        "evidence_signs": [
            "several submissions to the same form in a short window",
            "repeated use of a login, registration, checkout, search, upload, or contact form",
            "interaction timing that is faster than normal human use",
        ],
        "confidence_boosters": [
            "the same form is targeted repeatedly across multiple time windows",
            "server records show rejected, repeated, or low-quality submissions",
        ],
        "false_positive_cautions": [
            "double-clicks, retries, accessibility tools, and fast legitimate workflows can create a short burst",
            "browser evidence alone cannot confirm whether the server accepted each submission",
        ],
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
    },
]
