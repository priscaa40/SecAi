from __future__ import annotations

import json
from collections import defaultdict, deque
from threading import Lock
from time import time
from typing import Any

from fastapi import HTTPException

from secai import database
from secai.agent import jobs as analysis
from secai.integrations import discord
from secai.settings import get_settings
from secai.event_sources.normalizer import normalize_event
from secai.event_sources.relevance import is_event_relevant
from secai.models import EventIn


_rate_limit_lock = Lock()
_rate_limit_window: dict[str, deque[float]] = defaultdict(deque)


def ingest_event(payload: EventIn, ingest_key: str | None) -> dict[str, Any]:
    """Verify, store, and analyze one incoming event."""
    if not database.verify_ingest_key(payload.site_id, ingest_key):
        raise HTTPException(status_code=401, detail="Invalid site_id or ingest key")
    enforce_event_limits(payload)
    enforce_rate_limit(payload.site_id, payload.ip)

    event = normalize_event(payload.model_dump())
    if not is_event_relevant(event):
        return ignored_event_result(event)

    stored_event = database.insert_event(event)
    if stored_event.pop("_deduplicated", False):
        existing_job = database.get_analysis_job_for_event(stored_event["id"])
        return {
            "event": stored_event,
            "incident": None,
            "notified": False,
            "analysis": {"status": "deduplicated", "reason": "event_already_ingested", "source": event.get("source")},
            "analysis_job": existing_job,
        }
    job = database.create_analysis_job(stored_event["id"], stored_event["site_id"])
    if get_settings().secai_analysis_mode == "background":
        analysis.executor.submit(analysis.run_analysis_job, stored_event, job["id"], True)
        return {"event": stored_event, "incident": None, "notified": False, "analysis": analysis.job_analysis(job), "analysis_job": job}
    incident, result = analysis.run_analysis_job(stored_event, job["id"])
    notified = discord.notify_incident(incident) if incident else False
    return {
        "event": stored_event,
        "incident": incident,
        "notified": notified,
        "analysis": result,
        "analysis_job": database.get_analysis_job(job["id"]),
    }


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


def enforce_rate_limit(site_id: str, ip: str | None) -> None:
    """Apply simple in-memory rate limits for event ingest."""
    now = time()
    keys = [f"site:{site_id}"]
    if ip:
        keys.append(f"ip:{ip}")
    with _rate_limit_lock:
        for key in keys:
            bucket = _rate_limit_window[key]
            while bucket and now - bucket[0] > 60:
                bucket.popleft()
            limit = 120 if key.startswith("site:") else 60
            if len(bucket) >= limit:
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            bucket.append(now)
