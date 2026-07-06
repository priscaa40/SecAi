from __future__ import annotations

import logging
import threading
from typing import Any

from secai import database
from secai.agent import jobs as analysis
from secai.event_sources import alibaba_sls
from secai.integrations import discord
from secai.settings import get_settings


logger = logging.getLogger(__name__)

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


def stop_sls_polling() -> None:
    """Stop the periodic Alibaba SLS polling worker."""
    _stop_event.set()
    if _worker and _worker.is_alive():
        _worker.join(timeout=5)


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
    summary = {
        "sites_seen": 0,
        "events_seen": 0,
        "events_ingested": 0,
        "duplicates_skipped": 0,
        "incidents_created": 0,
        "errors": [],
    }
    for config in database.list_sls_configs():
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
        summary["events_ingested"] += result["events_ingested"]
        summary["duplicates_skipped"] += result["duplicates_skipped"]
        summary["incidents_created"] += result["incidents_created"]
    return summary


def ingest_sls_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Persist fetched SLS events, skip duplicates, and run analysis."""
    result = {"events_seen": len(events), "events_ingested": 0, "duplicates_skipped": 0, "incidents_created": 0}
    for event in events:
        stored_event = database.insert_event(event)
        if stored_event.pop("_deduplicated", False):
            result["duplicates_skipped"] += 1
            continue
        result["events_ingested"] += 1
        job = database.create_analysis_job(stored_event["id"], stored_event["site_id"])
        if get_settings().secai_analysis_mode == "background":
            analysis.executor.submit(analysis.run_analysis_job, stored_event, job["id"], True)
            continue
        incident, _ = analysis.run_analysis_job(stored_event, job["id"])
        if incident:
            result["incidents_created"] += 1
            discord.notify_incident(incident)
    return result
