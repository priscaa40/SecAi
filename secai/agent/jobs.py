from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from secai import database
from secai.agent.workflow import process_event
from secai.integrations import discord


logger = logging.getLogger(__name__)
executor = ThreadPoolExecutor(max_workers=2)


def shutdown_executor() -> None:
    """Stop background analysis workers during app shutdown."""
    executor.shutdown(wait=False)


def recover_unfinished_jobs() -> int:
    """Resume queued or running analysis jobs after a process restart."""
    recovered = 0
    for job in database.list_unfinished_analysis_jobs():
        event = database.get_event(job["event_id"])
        if not event:
            database.update_analysis_job(job["id"], status="failed", current_step="failed", error="Stored event is missing.")
            continue
        database.update_analysis_job(job["id"], status="queued", current_step="recovered")
        executor.submit(run_analysis_job, event, job["id"], True)
        recovered += 1
    return recovered


def run_analysis_job(
    stored_event: dict[str, Any],
    job_id: int,
    send_notification: bool = False,
) -> tuple[dict[str, Any] | None, dict[str, str]]:
    """Run Qwen analysis for one stored event and update job status."""
    database.update_analysis_job(job_id, status="running", current_step="queued")
    try:
        incident = process_event(stored_event, job_id=job_id)
    except Exception as exc:
        logger.exception("SecAi analysis failed for event %s", stored_event.get("id"))
        status = "blocked" if is_qwen_moderation_error(exc) else "failed"
        reason = safe_analysis_error(exc)
        database.update_analysis_job(job_id, status=status, current_step="failed", error=reason)
        return None, {"status": status, "reason": reason}
    if incident:
        database.update_analysis_job(job_id, status="incident_created", current_step="complete", incident_id=incident["id"])
        database.attach_qwen_usage_to_incident(job_id, incident["id"])
        if send_notification:
            discord.notify_incident(incident)
        return incident, {"status": "incident_created"}
    database.update_analysis_job(job_id, status="no_incident", current_step="complete")
    return None, {"status": "no_incident"}


def job_analysis(job: dict[str, Any]) -> dict[str, str | int | None]:
    """Return a compact analysis status object for API responses."""
    return {
        "status": job["status"],
        "job_id": job["id"],
        "current_step": job.get("current_step"),
        "reason": job.get("error"),
    }


def is_qwen_moderation_error(exc: Exception) -> bool:
    """Return whether an exception looks like a Qwen safety block."""
    text = str(exc).lower()
    return "data_inspection_failed" in text or "datainspectionfailed" in text or "ip_infringement_suspect" in text


def safe_analysis_error(exc: Exception) -> str:
    """Return a user-safe analysis failure message."""
    if is_qwen_moderation_error(exc):
        return "Qwen Cloud safety moderation blocked this analysis. Review the event payload and try with less sensitive raw content."
    return str(exc)[:500]
