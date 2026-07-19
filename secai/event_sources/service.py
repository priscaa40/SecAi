from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException

from secai import database
from secai.agent import jobs as analysis
from secai.event_sources.normalizer import normalize_event
from secai.event_sources.relevance import is_event_relevant
from secai.models import EventIn
from secai.security import rate_limit
from secai.security.redaction import sanitize_event
from secai.settings import get_settings


def ingest_event(payload: EventIn, ingest_key: str | None, request_ip: str = "unknown") -> dict[str, Any]:
    """Verify, store, and analyze one incoming event."""
    if not database.verify_ingest_key(payload.site_id, ingest_key):
        raise HTTPException(status_code=401, detail="Invalid site_id or ingest key")
    site = database.get_site(payload.site_id)
    if not site or site["evidence_source"] != "browser":
        raise HTTPException(status_code=403, detail="Browser evidence is not enabled for this website.")
    enforce_event_limits(payload)
    enforce_rate_limit(payload.site_id, request_ip)

    event = sanitize_event(normalize_event(payload.model_dump()))
    if not is_event_relevant(event):
        return ignored_event_result(event)

    result = store_and_queue_event(event)
    stored_event = result["event"]
    if result["status"] in {"deduplicated", "correlated"}:
        return {
            "event": stored_event,
            "incident": None,
            "notified": False,
            "analysis": {"status": result["status"], "reason": result["reason"], "source": event.get("source")},
            "analysis_job": result.get("job"),
        }
    job = result["job"]
    return {
        "event": stored_event,
        "incident": None,
        "notified": False,
        "analysis": analysis.job_analysis(job),
        "analysis_job": job,
    }


def store_and_queue_event(event: dict[str, Any]) -> dict[str, Any]:
    """Persist one bounded evidence candidate and durably queue its Qwen analysis."""
    event = sanitize_event(event)
    if event.get("source") == "browser":
        event["event_fingerprint"] = _browser_minute_fingerprint(event)
    stored_event = database.insert_event(event)
    if stored_event.pop("_deduplicated", False):
        return {
            "status": "deduplicated",
            "reason": "event_already_ingested",
            "event": stored_event,
            "job": database.get_analysis_job_for_event(stored_event["id"]),
        }
    job = database.create_analysis_job(stored_event["id"], stored_event["site_id"])
    analysis.wake_analysis_worker()
    return {"status": "queued", "event": stored_event, "job": job}


def _browser_minute_fingerprint(event: dict[str, Any]) -> str:
    """Coalesce one form's repeated browser warnings for one minute."""
    metadata = event.get("metadata") or {}
    identity = {
        "site_id": event.get("site_id"),
        "event_type": event.get("event_type"),
        "path": event.get("path"),
        "form_key": metadata.get("form_key"),
        "signals": sorted(event.get("signals") or []),
        "minute": int(datetime.now(UTC).timestamp() // 60),
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return f"browser:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


def ignored_event_result(event: dict[str, Any]) -> dict[str, Any]:
    """Return a successful no-op for source events that are not security relevant."""
    return {
        "event": None,
        "incident": None,
        "notified": False,
        "analysis": {"status": "ignored", "reason": "event_not_security_relevant", "source": event.get("source")},
        "analysis_job": None,
    }


def enforce_event_limits(payload: EventIn) -> None:
    """Reject events that are too large to analyze safely."""
    settings = get_settings()
    raw = payload.model_dump()
    raw_size = len(json.dumps(raw, default=str))
    text_size = sum(len(value or "") for value in [payload.query, payload.payload, payload.user_agent, payload.path])
    if raw_size > settings.secai_max_payload_chars or text_size > settings.secai_max_payload_chars:
        raise HTTPException(status_code=413, detail="Event payload is too large")


def enforce_rate_limit(site_id: str, request_ip: str) -> None:
    """Apply shared limits using the network peer, never the attacker-supplied event IP."""
    buckets = ((f"ingest:site:{site_id}", 120), (f"ingest:client:{request_ip or 'unknown'}", 60))
    for key, limit in buckets:
        if not rate_limit.consume(key, limit, 60):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
