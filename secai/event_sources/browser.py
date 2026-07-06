from __future__ import annotations

import json
from typing import Any

from secai.event_sources.relevance import is_browser_event_relevant


BROWSER_SNIPPET_TEMPLATE = """
(function() {
  const endpoint = __SECAI_ENDPOINT__;
  const siteId = __SECAI_SITE_ID__;
  const ingestKey = __SECAI_INGEST_KEY__;
  const suspiciousPatterns = [
    /(\\bor\\b|\\band\\b)\\s+['"]?\\d+['"]?\\s*=\\s*['"]?\\d+/i,
    /union\\s+select/i,
    /--/,
    /\\.\\.\\//,
    /\\.\\.\\\\/,
    /<script/i,
    /javascript:/i,
    /onerror\\s*=/i,
    /onload\\s*=/i
  ];
  const recentSubmits = [];
  const recentErrors = [];
  const recentActivity = [];
  let lastBotSignalAt = 0;
  function send(event) {
    fetch(endpoint, {method: "POST", headers: {"Content-Type": "application/json", "X-SecAi-Key": ingestKey}, body: JSON.stringify(event), keepalive: true}).catch(function() {});
  }
  function now() {
    return Date.now();
  }
  function remember(bucket, windowMs) {
    const current = now();
    bucket.push(current);
    while (bucket.length && current - bucket[0] > windowMs) bucket.shift();
    return bucket.length;
  }
  function formText(form) {
    return Array.from(form.elements || []).map(function(field) {
      if (!field || !("value" in field)) return "";
      return String(field.value || "");
    }).join(" ");
  }
  function hasSuspiciousText(text) {
    return suspiciousPatterns.some(function(pattern) { return pattern.test(text || ""); });
  }
  window.addEventListener("error", function(e) {
    const count = remember(recentErrors, 60000);
    if (count >= 3) {
      send({site_id: siteId, source: "browser", event_type: "browser_error_spike", path: location.pathname, payload: e.message, signals: ["client_error_spike"], metadata: {url: location.href, error_count_60s: count}});
    }
  });
  document.addEventListener("submit", function(e) {
    const form = e.target;
    const text = formText(form);
    const count = remember(recentSubmits, 10000);
    if (hasSuspiciousText(text)) {
      send({site_id: siteId, source: "browser", event_type: "suspicious_form_submit", path: location.pathname, payload: text.slice(0, 1000), signals: ["suspicious_form_payload"], metadata: {form_id: form.id || null, url: location.href}});
    } else if (count >= 3) {
      send({site_id: siteId, source: "browser", event_type: "rapid_form_submit", path: location.pathname, signals: ["rapid_form_submit"], metadata: {form_id: form.id || null, url: location.href, submit_count_10s: count}});
    }
  });
  ["click", "keydown"].forEach(function(type) {
    document.addEventListener(type, function() {
      const count = remember(recentActivity, 10000);
      if (count >= 80 && now() - lastBotSignalAt > 30000) {
        lastBotSignalAt = now();
        send({site_id: siteId, source: "browser", event_type: "bot_like_behavior", path: location.pathname, signals: ["bot_like_behavior"], metadata: {url: location.href, activity_count_10s: count}});
      }
    }, true);
  });
})();
"""


def render_snippet(public_base_url: str, site_id: str, ingest_key: str) -> str:
    """Render the suspicious-only browser snippet with JSON-escaped config."""
    endpoint = f"{public_base_url.rstrip('/')}/api/events"
    return (
        BROWSER_SNIPPET_TEMPLATE.replace("__SECAI_ENDPOINT__", json.dumps(endpoint))
        .replace("__SECAI_SITE_ID__", json.dumps(site_id))
        .replace("__SECAI_INGEST_KEY__", json.dumps(ingest_key))
    )


def is_relevant_event(event: dict[str, Any]) -> bool:
    """Return whether one normalized browser event should enter the agent workflow."""
    return is_browser_event_relevant(event)
