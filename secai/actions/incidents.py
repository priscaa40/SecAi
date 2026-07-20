from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from secai import database
from secai.actions import remediation
from secai.actions.capabilities import action_spec
from secai.agent.action_jobs import wake_action_worker
from secai.models import ApprovalIn


def approve_incident(
    incident_id: int,
    payload: ApprovalIn,
    approved_by: str,
    channel: str = "dashboard",
) -> dict[str, Any]:
    """Persist owner approval and queue the approved action for Qwen Executor."""
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident["status"] == "rejected":
        raise HTTPException(status_code=409, detail="Rejected incidents cannot be approved.")
    spec = action_spec((incident.get("recommended_action") or {}).get("action", ""))
    if not spec.requires_approval:
        raise HTTPException(status_code=409, detail="This action does not require owner approval.")
    database.ensure_action_job(incident_id, incident["site_id"], spec.name, spec.tool_name, True)
    try:
        result = database.approve_and_queue_action(incident_id, approved_by, channel, payload.note)
    except ValueError as exc:
        status = 404 if str(exc) == "Incident not found" else 409
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    wake_action_worker()
    return {
        **result,
        "policy": database.get_policy_for_incident(incident_id),
        "approved_by": approved_by,
        "execution": "queued" if result["action_job"]["status"] == "queued" else result["action_job"]["status"],
    }


def reject_incident(
    incident_id: int,
    payload: ApprovalIn,
    rejected_by: str,
    channel: str = "dashboard",
) -> dict[str, Any]:
    """Reject a proposed protective action before it has been approved."""
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    spec = action_spec((incident.get("recommended_action") or {}).get("action", ""))
    if not spec.requires_approval:
        raise HTTPException(status_code=409, detail="This action does not require owner approval.")
    database.ensure_action_job(incident_id, incident["site_id"], spec.name, spec.tool_name, True)
    try:
        result = database.reject_action(incident_id, rejected_by, channel, payload.note)
    except ValueError as exc:
        status = 404 if str(exc) == "Incident not found" else 409
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    return {**result, "rejected_by": rejected_by, "note": payload.note}


def retry_incident_action(incident_id: int, requested_by: str) -> dict[str, Any]:
    """Requeue the failed Qwen Executor job without changing owner approval."""
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    job = database.get_action_job_for_incident(incident_id)
    if not job or job["status"] != "failed":
        raise HTTPException(status_code=409, detail="This action is not waiting for a retry.")
    eligible_status = "approved" if job["requires_approval"] else "reported"
    if incident["status"] != eligible_status:
        raise HTTPException(status_code=409, detail="This incident is not eligible to retry its action.")
    queued = database.retry_action_job(job["id"])
    if not queued:
        raise HTTPException(status_code=409, detail="This action reached its retry limit.")
    wake_action_worker()
    return {
        "incident": incident,
        "policy": database.get_policy_for_incident(incident_id),
        "action_job": queued,
        "execution": "queued",
        "requested_by": requested_by,
    }


def remove_incident_protection(incident_id: int, requested_by: str) -> dict[str, Any]:
    """Remove an active provider rule while preserving the original approval decision."""
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident["status"] != "approved":
        raise HTTPException(status_code=409, detail="This incident has no approved protection to remove.")
    policy = database.get_policy_for_incident(incident_id)
    if not policy:
        raise HTTPException(status_code=409, detail="This incident has no protection policy.")
    if policy["status"] in {"revoked", "expired"}:
        return {"incident": incident, "policy": policy, "requested_by": requested_by, "already_removed": True}
    if policy["status"] != "active":
        raise HTTPException(status_code=409, detail="Only active protection can be removed.")
    try:
        policy = remediation.revoke_policy_for_incident(incident, final_status="revoked")
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Alibaba Cloud could not remove this protection.") from exc
    return {"incident": incident, "policy": policy, "requested_by": requested_by}


def reapply_incident_protection(incident_id: int, requested_by: str) -> dict[str, Any]:
    """Apply a manually removed block again before its original window ends."""
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident["status"] != "approved":
        raise HTTPException(status_code=409, detail="Approve this protection before applying it again.")
    try:
        policy = remediation.reapply_policy_for_incident(incident)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"incident": incident, "policy": policy, "requested_by": requested_by}
