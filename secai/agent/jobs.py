from __future__ import annotations

import logging
import threading
from typing import Any

from secai import database
from secai.agent import action_jobs
from secai.agent.workflow import process_event
from secai.integrations import discord

logger = logging.getLogger(__name__)

_stop_event = threading.Event()
_wake_event = threading.Event()
_worker: threading.Thread | None = None
_worker_lock = threading.Lock()
_active_job_id: int | None = None


def start_analysis_worker() -> dict[str, int]:
    """Recover stale work once and start the single database-backed analysis worker."""
    global _worker
    with _worker_lock:
        if _worker and _worker.is_alive():
            return {"completed": 0, "requeued": 0, "failed": 0}
        recovered = database.requeue_stale_analysis_jobs(max_attempts=3)
        _stop_event.clear()
        _wake_event.set()
        _worker = threading.Thread(target=_worker_loop, name="secai-analysis", daemon=True)
        _worker.start()
        return recovered


def stop_analysis_worker() -> bool:
    """Ask the analysis worker to stop after its current Qwen call returns."""
    _stop_event.set()
    _wake_event.set()
    worker = _worker
    if worker and worker.is_alive():
        worker.join(timeout=5)
    return not bool(worker and worker.is_alive())


def wake_analysis_worker() -> None:
    """Wake the worker after a new queued job is committed."""
    _wake_event.set()


def worker_metrics() -> dict[str, Any]:
    worker = _worker
    return {
        "running": bool(worker and worker.is_alive()),
        "active_job_id": _active_job_id,
    }


def _worker_loop() -> None:
    global _active_job_id
    while not _stop_event.is_set():
        try:
            job = database.claim_next_analysis_job()
        except Exception:
            logger.exception("SecAi could not claim the next analysis job")
            _wake_event.wait(2)
            _wake_event.clear()
            continue
        if not job:
            _wake_event.wait(2)
            _wake_event.clear()
            continue
        _active_job_id = job["id"]
        try:
            event = database.get_event(job["event_id"])
            if not event:
                database.update_analysis_job(
                    job["id"],
                    status="failed",
                    current_step="failed",
                    error="Stored evidence is missing.",
                )
                continue
            run_analysis_job(event, job["id"], send_notification=True)
        except Exception:
            logger.exception("Unexpected analysis worker failure for job %s", job["id"])
            failed_job = database.get_analysis_job(job["id"])
            database.update_analysis_job(
                job["id"],
                status="failed",
                current_step=_visible_failure_step(failed_job, "starting"),
                error="The investigation could not finish. Try again from the dashboard.",
            )
        finally:
            _active_job_id = None


def run_analysis_job(
    stored_event: dict[str, Any],
    job_id: int,
    send_notification: bool = False,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Run Qwen analysis for one claimed job and persist its terminal state."""
    existing_job = database.get_analysis_job(job_id)
    if existing_job and existing_job.get("incident_id") is not None:
        existing_incident = database.get_incident(existing_job["incident_id"])
        return existing_incident, {"status": "incident_created", "notified": False}
    database.update_analysis_job(job_id, status="running", current_step="investigator")
    try:
        incident = process_event(stored_event, job_id=job_id)
    except Exception as exc:
        logger.exception("SecAi analysis failed for event %s", stored_event.get("id"))
        completed_job = database.get_analysis_job(job_id)
        if completed_job and completed_job.get("incident_id") is not None:
            completed_incident = database.get_incident(completed_job["incident_id"])
            return completed_incident, {"status": "incident_created", "notified": False}
        reason = safe_analysis_error(exc)
        database.update_analysis_job(
            job_id,
            status="failed",
            current_step=_visible_failure_step(completed_job, "investigator"),
            error=reason,
        )
        return None, {"status": "failed", "reason": reason}
    if incident:
        action_jobs.wake_action_worker()
        selected_action = (incident.get("recommended_action") or {}).get("action")
        notified = discord.notify_incident(incident) if send_notification and selected_action != "send_owner_alert" else False
        return database.get_incident(incident["id"]), {"status": "incident_created", "notified": notified}
    database.update_analysis_job(job_id, status="no_incident", current_step="complete")
    return None, {"status": "no_incident"}


def job_analysis(job: dict[str, Any]) -> dict[str, str | int | None]:
    return {
        "status": job["status"],
        "job_id": job["id"],
        "current_step": job.get("current_step"),
        "reason": job.get("error"),
    }


def _visible_failure_step(job: dict[str, Any] | None, fallback: str) -> str:
    """Keep the active agent visible instead of replacing it with a generic failure step."""
    step = str((job or {}).get("current_step") or "")
    return step if step in {"investigator", "reviewer", "responder", "persist_incident"} else fallback


def is_qwen_moderation_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return "data_inspection_failed" in text or "datainspectionfailed" in text or "ip_infringement_suspect" in text


def safe_analysis_error(exc: Exception) -> str:
    """Return a stable public error without provider internals."""
    if is_qwen_moderation_error(exc):
        return "The investigation could not safely process this evidence. Review it and try again."
    if isinstance(exc, TimeoutError):
        return "The investigation took too long. Try again from the dashboard."
    return "The investigation could not finish. Try again from the dashboard."
