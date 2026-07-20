from __future__ import annotations

import logging
import threading
from typing import Any

from secai import database
from secai.agent.executor import execute_action_job
from secai.integrations import discord

logger = logging.getLogger(__name__)

_stop_event = threading.Event()
_wake_event = threading.Event()
_worker: threading.Thread | None = None
_worker_lock = threading.Lock()
_active_job_id: int | None = None


def start_action_worker() -> dict[str, int]:
    """Recover interrupted actions and start the durable Qwen Executor worker."""
    global _worker
    with _worker_lock:
        if _worker and _worker.is_alive():
            return {"requeued": 0, "failed": 0}
        recovered = database.requeue_stale_action_jobs(max_attempts=3)
        _stop_event.clear()
        _wake_event.set()
        _worker = threading.Thread(target=_worker_loop, name="secai-actions", daemon=True)
        _worker.start()
        return recovered


def stop_action_worker() -> bool:
    _stop_event.set()
    _wake_event.set()
    worker = _worker
    if worker and worker.is_alive():
        worker.join(timeout=5)
    return not bool(worker and worker.is_alive())


def wake_action_worker() -> None:
    _wake_event.set()


def worker_metrics() -> dict[str, Any]:
    worker = _worker
    return {"running": bool(worker and worker.is_alive()), "active_job_id": _active_job_id}


def run_action_job(job: dict[str, Any]) -> dict[str, Any]:
    """Run one claimed Qwen action job and store a safe terminal failure when needed."""
    try:
        completed = execute_action_job(job)
    except Exception:
        logger.exception("SecAi action execution failed for job %s", job.get("id"))
        failed = database.fail_action_job(
            job["id"],
            "The action agent could not finish this action. Retry it from the dashboard.",
        )
        incident = database.get_incident(job["incident_id"])
        if incident and job.get("requires_approval"):
            discord.notify_decision_result(incident, "approve", error=(failed or {}).get("error"))
        return failed or database.get_action_job(job["id"]) or job
    incident = database.get_incident(job["incident_id"])
    if incident and job.get("requires_approval"):
        discord.notify_decision_result(incident, "approve")
    return completed


def _worker_loop() -> None:
    global _active_job_id
    while not _stop_event.is_set():
        try:
            job = database.claim_next_action_job()
        except Exception:
            logger.exception("SecAi could not claim the next action job")
            _wake_event.wait(2)
            _wake_event.clear()
            continue
        if not job:
            _wake_event.wait(2)
            _wake_event.clear()
            continue
        _active_job_id = job["id"]
        try:
            run_action_job(job)
        finally:
            _active_job_id = None
