from __future__ import annotations

import json

from secai.event_sources.relevance import BROWSER_RAPID_SUBMIT_THRESHOLD

BROWSER_SNIPPET_TEMPLATE = """
(function() {
  const endpoint = __SECAI_ENDPOINT__;
  const siteId = __SECAI_SITE_ID__;
  const ingestKey = __SECAI_INGEST_KEY__;
  const installationKey = Symbol.for("secai.browser.installedSites");
  const rapidSubmitThreshold = __SECAI_RAPID_SUBMIT_THRESHOLD__;
  const rapidSubmitWindowMs = 10000;
  const installedSites = window[installationKey] || new Set();
  if (installedSites.has(siteId)) return;
  installedSites.add(siteId);
  window[installationKey] = installedSites;
  const suspiciousPatterns = [
    /(\\bor\\b|\\band\\b)\\s+['"]?\\d+['"]?\\s*=\\s*['"]?\\d+/i,
    /union\\s+select/i,
    /\\bsleep\\s*\\(/i,
    /\\bdrop\\s+table\\b/i,
    /(?:['"]|;)\\s*--(?:\\s|$)/,
    /\\.\\.\\//,
    /\\.\\.\\\\/,
    /<script/i,
    /javascript:/i,
    /onerror\\s*=/i,
    /onload\\s*=/i
  ];
  const submitHistory = new WeakMap();
  function send(event) {
    fetch(endpoint, {method: "POST", headers: {"Content-Type": "application/json", "X-SecAi-Key": ingestKey}, body: JSON.stringify(event), credentials: "omit", referrerPolicy: "no-referrer", keepalive: true}).catch(function() {});
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
  function formContext(form) {
    const method = String(form.getAttribute("method") || "get").toUpperCase();
    let actionPath = location.pathname;
    let identityPath = location.pathname;
    let actionScope = "same_origin";
    try {
      const action = new URL(form.getAttribute("action") || location.href, location.href);
      identityPath = action.pathname || "/";
      if (action.origin === location.origin) actionPath = identityPath;
      else actionScope = "cross_origin";
    } catch (_) {
      actionScope = "invalid";
    }
    const formName = String(form.id || form.getAttribute("name") || "").slice(0, 120);
    const formPosition = Array.prototype.indexOf.call(document.forms, form);
    const locator = formName ? "named:" + formName : "index:" + formPosition;
    return {
      method: method,
      actionPath: actionPath,
      actionScope: actionScope,
      signature: [method, actionScope, identityPath, locator].join("|").slice(0, 500)
    };
  }
  function rememberFormSubmission(form, context, windowMs) {
    const current = now();
    const storageKey = ["secai", "submissions", siteId, context.signature].join(":");
    try {
      const parsed = JSON.parse(sessionStorage.getItem(storageKey) || "[]");
      const bucket = (Array.isArray(parsed) ? parsed : []).slice(-rapidSubmitThreshold).filter(function(value) {
        return Number.isFinite(value) && value <= current && current - value <= windowMs;
      });
      bucket.push(current);
      sessionStorage.setItem(storageKey, JSON.stringify(bucket));
      return bucket.length;
    } catch (_) {
      // Some browsers or embedded contexts disable session storage.
    }
    let bucket = submitHistory.get(form);
    if (!bucket) {
      bucket = [];
      submitHistory.set(form, bucket);
    }
    return remember(bucket, windowMs);
  }
  function hasSensitiveFieldName(name) {
    const parts = String(name || "").split(/[^a-z0-9]+/).filter(Boolean);
    const sensitiveParts = new Set([
      "password", "passwd", "secret", "token", "apikey", "accesskey", "card", "pan", "cvv", "cvc",
      "session", "auth", "authentication", "authorization", "otp", "pin", "webauthn"
    ]);
    if (parts.some(function(part) { return sensitiveParts.has(part); })) return true;
    const compact = parts.join("");
    return /(password|passwd|secret|token|apikey|accesskey|cardnumber|creditcard|cvv|cvc|sessionid|onetimecode)/.test(compact);
  }
  function safeFieldValue(field) {
    if (!field || !("value" in field)) return "";
    const name = String(field.name || field.id || "").toLowerCase();
    const autocomplete = String(field.autocomplete || "").toLowerCase();
    const type = String(field.type || "").toLowerCase();
    if (field.disabled || (["checkbox", "radio"].includes(type) && !field.checked)) return "";
    if (["password", "hidden", "file", "submit", "button", "image", "reset"].includes(type)) return "";
    if (hasSensitiveFieldName(name)) return "";
    if (/(password|cc-|one-time-code)/.test(autocomplete)) return "";
    return String(field.value || "");
  }
  function suspiciousFormValue(form) {
    const fields = Array.from(form.elements || []);
    for (const field of fields) {
      const value = safeFieldValue(field);
      if (hasSuspiciousText(value)) return value;
    }
    return "";
  }
  function hasSuspiciousText(text) {
    return suspiciousPatterns.some(function(pattern) { return pattern.test(text || ""); });
  }
  document.addEventListener("submit", function(e) {
    const form = e.target;
    if (!form || !form.elements) return;
    const context = formContext(form);
    if (context.method === "DIALOG" || context.actionScope !== "same_origin") return;
    const suspiciousValue = suspiciousFormValue(form);
    const count = rememberFormSubmission(form, context, rapidSubmitWindowMs);
    const metadata = {
      form_id: String(form.id || "").slice(0, 120) || null,
      form_key: context.signature,
      page_path: location.pathname,
      form_action_scope: context.actionScope
    };
    if (suspiciousValue) {
      send({site_id: siteId, source: "browser", event_type: "suspicious_form_submit", method: context.method, path: context.actionPath, payload: suspiciousValue.slice(0, 1000), signals: ["suspicious_form_payload"], metadata: metadata});
    } else if (count === rapidSubmitThreshold) {
      metadata.submit_count_10s = count;
      send({site_id: siteId, source: "browser", event_type: "rapid_form_submit", method: context.method, path: context.actionPath, signals: ["rapid_form_submit"], metadata: metadata});
    }
  }, true);
})();
"""


def render_snippet(public_base_url: str, site_id: str, ingest_key: str) -> str:
    """Render the suspicious-only browser snippet with JSON-escaped config."""
    endpoint = f"{public_base_url.rstrip('/')}/api/events"
    return (
        BROWSER_SNIPPET_TEMPLATE.replace("__SECAI_ENDPOINT__", json.dumps(endpoint))
        .replace("__SECAI_SITE_ID__", json.dumps(site_id))
        .replace("__SECAI_INGEST_KEY__", json.dumps(ingest_key))
        .replace("__SECAI_RAPID_SUBMIT_THRESHOLD__", str(BROWSER_RAPID_SUBMIT_THRESHOLD))
    )
