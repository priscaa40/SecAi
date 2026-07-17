from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import UTC, datetime
from typing import Any

from secai import database
from secai.event_sources import alibaba_sls
from secai.event_sources.relevance import is_sls_group_relevant
from secai.event_sources.service import store_and_queue_event
from secai.settings import get_settings

logger = logging.getLogger(__name__)

SLS_GROUP_WINDOW_SECONDS = 5 * 60

_stop_event = threading.Event()
_worker: threading.Thread | None = None


def start_sls_polling() -> None:
    """Start periodic Alibaba SLS polling when enabled by settings."""
    global _worker
    settings = get_settings()
    if settings.secai_sls_poll_interval_seconds <= 0:
        return
    if _worker and _worker.is_alive():
        return
    _stop_event.clear()
    _worker = threading.Thread(target=_poll_loop, name="secai-sls-poller", daemon=True)
    _worker.start()


def stop_sls_polling() -> bool:
    """Stop the periodic Alibaba SLS polling worker."""
    _stop_event.set()
    if _worker and _worker.is_alive():
        _worker.join(timeout=5)
    return not bool(_worker and _worker.is_alive())


def _poll_loop() -> None:
    settings = get_settings()
    interval = max(30, settings.secai_sls_poll_interval_seconds)
    while not _stop_event.wait(interval):
        try:
            poll_once()
        except Exception:
            logger.exception("Scheduled Alibaba SLS poll failed")


def poll_once() -> dict[str, Any]:
    """Poll each saved Alibaba SLS connection once and analyze new events."""
    settings = get_settings()
    summary: dict[str, Any] = {
        "sites_seen": 0,
        "events_seen": 0,
        "groups_seen": 0,
        "groups_created": 0,
        "groups_deduplicated": 0,
        "groups_filtered": 0,
        "events_ingested": 0,
        "duplicates_skipped": 0,
        "incidents_created": 0,
        "errors": [],
    }
    for config in database.list_alibaba_autopilot_configs_with_sls():
        site_id = config["site_id"]
        summary["sites_seen"] += 1
        try:
            events = alibaba_sls.fetch_saved_site_events(
                site_id,
                query=settings.secai_sls_poll_query,
                minutes=settings.secai_sls_poll_minutes,
                limit=settings.secai_sls_poll_limit,
            )
        except Exception as exc:
            logger.warning("Scheduled Alibaba SLS poll failed for site %s: %s", site_id, exc)
            summary["errors"].append({"site_id": site_id, "error": str(exc)})
            continue
        result = ingest_sls_events(events)
        summary["events_seen"] += result["events_seen"]
        summary["groups_seen"] += result["groups_seen"]
        summary["groups_created"] += result["groups_created"]
        summary["groups_deduplicated"] += result["groups_deduplicated"]
        summary["groups_filtered"] += result["groups_filtered"]
        summary["events_ingested"] += result["events_ingested"]
        summary["duplicates_skipped"] += result["duplicates_skipped"]
        summary["incidents_created"] += result["incidents_created"]
    return summary


def ingest_sls_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Deduplicate SLS records, then analyze one evidence candidate per new group."""
    new_event_count = 0
    window_events: list[dict[str, Any]] = []
    duplicates = 0
    for event in events:
        stored = database.insert_event(event)
        if stored.pop("_deduplicated", False):
            duplicates += 1
        else:
            new_event_count += 1
        window_events.append(stored)
    candidate_groups = group_sls_events(window_events)
    groups = [event for event in candidate_groups if is_sls_group_relevant(event)]
    result = {
        "events_seen": len(events),
        "groups_seen": len(candidate_groups),
        "groups_created": 0,
        "groups_deduplicated": 0,
        "groups_filtered": len(candidate_groups) - len(groups),
        "events_ingested": new_event_count,
        "duplicates_skipped": duplicates,
        "incidents_created": 0,
        "jobs_queued": 0,
    }
    for event in groups:
        outcome = store_and_queue_event(event)
        if outcome["status"] in {"deduplicated", "correlated"}:
            result["groups_deduplicated"] += 1
            continue
        if outcome["status"] == "queued":
            result["groups_created"] += 1
            result["jobs_queued"] += 1
        if outcome.get("incident"):
            result["incidents_created"] += 1
    return result


def group_sls_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse a fetched SLS batch into bounded, deterministic evidence candidates."""
    buckets: dict[tuple[str, str, str, str, int], list[dict[str, Any]]] = {}
    for event in events:
        family = _event_family(event)
        route = (
            str(event.get("path") or "")
            if family not in {"authentication", "bot_activity", "client_error", "not_found_scan", "rate_limited"}
            else ""
        )
        key = (
            str(event.get("site_id") or ""),
            family,
            str(event.get("ip") or ""),
            route,
            _event_window(event),
        )
        buckets.setdefault(key, []).append(event)
    return [_aggregate_sls_group(group, family=key[1], group_key=key) for key, group in buckets.items()]


def _aggregate_sls_group(
    events: list[dict[str, Any]], family: str, group_key: tuple[str, str, str, str, int]
) -> dict[str, Any]:
    representative = events[0]
    signals = sorted({str(signal) for event in events for signal in event.get("signals") or []})
    routes = sorted({str(event["path"]) for event in events if event.get("path")})[:8]
    status_codes = sorted({int(event["status_code"]) for event in events if _is_int(event.get("status_code"))})
    methods = sorted({str(event["method"]) for event in events if event.get("method")})
    group_id = _group_id(group_key)
    sample = next(
        (str(value) for event in events for value in (event.get("query"), event.get("payload")) if value),
        "",
    )
    summary = (
        f"{len(events)} related Alibaba SLS record(s); family={family}; "
        f"methods={','.join(methods) or 'unknown'}; routes={','.join(routes) or 'unknown'}; "
        f"status_codes={','.join(str(code) for code in status_codes) or 'unknown'}"
    )
    if sample:
        summary += f"; sample={sample[:500]}"
    sls_metadata = dict((representative.get("metadata") or {}).get("sls") or {})
    sls_metadata.update({"request_id": group_id, "message": summary})
    return {
        "site_id": representative["site_id"],
        "source": "alibaba_sls",
        "event_type": f"sls_{family}_group",
        "method": representative.get("method"),
        "path": representative.get("path"),
        "query": representative.get("query"),
        "status_code": representative.get("status_code"),
        "ip": representative.get("ip"),
        "user_agent": representative.get("user_agent"),
        "payload": summary,
        "signals": signals,
        "metadata": {
            "sls": sls_metadata,
            "evidence": [_compact_evidence(event) for event in events[:12]],
        },
    }


def _event_family(event: dict[str, Any]) -> str:
    signals = set(event.get("signals") or [])
    for signal, family in (
        ("sql_injection_pattern", "sql_injection"),
        ("xss_pattern", "cross_site_scripting"),
        ("path_traversal_pattern", "path_traversal"),
        ("rapid_form_submit", "form_abuse"),
        ("bot_like_user_agent", "bot_activity"),
        ("server_error", "server_error"),
        ("auth_failure", "authentication"),
    ):
        if signal in signals:
            return family
    status_code = int(event["status_code"]) if _is_int(event.get("status_code")) else None
    if status_code in {401, 403}:
        return "authentication"
    if status_code == 404:
        return "not_found_scan"
    if status_code == 429:
        return "rate_limited"
    if status_code is not None and status_code >= 500:
        return "server_error"
    if status_code is not None and status_code >= 400:
        return "client_error"
    return "suspicious_activity"


def _group_id(group_key: tuple[str, str, str, str, int]) -> str:
    encoded = json.dumps(group_key, separators=(",", ":"))
    return f"secai-sls-group-{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:24]}"


def _event_window(event: dict[str, Any]) -> int:
    metadata = event.get("metadata") or {}
    sls = metadata.get("sls") or {}
    value = sls.get("timestamp") or sls.get("time") or event.get("created_at")
    if value is None:
        return int(datetime.now(UTC).timestamp() // SLS_GROUP_WINDOW_SECONDS)
    try:
        timestamp = float(value)
        if timestamp > 10_000_000_000:
            timestamp /= 1000
    except (TypeError, ValueError):
        try:
            timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        except (TypeError, ValueError):
            timestamp = datetime.now(UTC).timestamp()
    return int(timestamp // SLS_GROUP_WINDOW_SECONDS)


def _is_int(value: Any) -> bool:
    try:
        int(value)
    except (TypeError, ValueError):
        return False
    return value is not None


def _compact_evidence(event: dict[str, Any]) -> dict[str, Any]:
    sls = (event.get("metadata") or {}).get("sls") or {}
    return {
        "observed_at": sls.get("timestamp") or sls.get("time") or event.get("created_at"),
        "source": "alibaba_sls",
        "ip": event.get("ip"),
        "method": event.get("method"),
        "path": event.get("path"),
        "status_code": event.get("status_code"),
        "signals": list(event.get("signals") or []),
        "event_type": event.get("event_type"),
    }
