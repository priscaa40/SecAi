from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from secai import database
from secai.actions import remediation
from secai.models import ApprovalIn


def approve_incident(
    incident_id: int,
    payload: ApprovalIn,
    approved_by: str,
    channel: str = "dashboard",
) -> dict[str, Any]:
    """Atomically approve an incident and execute its recommended policy once."""
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident["status"] == "rejected":
        raise HTTPException(status_code=409, detail="Rejected incidents cannot be approved.")
    if incident["status"] == "approved":
        return {
            "incident": incident,
            "policy": database.get_policy_for_incident(incident_id),
            "approved_by": approved_by,
            "already_final": True,
        }
    if incident["status"] == "applying":
        raise HTTPException(status_code=409, detail="This incident decision is already being processed.")

    claimed = database.transition_incident_status(incident_id, {"needs_review"}, "applying")
    if not claimed:
        raise HTTPException(status_code=409, detail="This incident can no longer be approved.")
    try:
        policy = remediation.create_policy_for_incident(claimed, claimed["recommended_action"])
    except ValueError as exc:
        database.transition_incident_status(incident_id, {"applying"}, "needs_review")
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        database.transition_incident_status(incident_id, {"applying"}, "needs_review")
        raise

    updated = database.transition_incident_status(incident_id, {"applying"}, "approved")
    if not updated:
        raise HTTPException(status_code=409, detail="The incident status changed while approval was running.")
    database.consume_approval_token(incident_id)
    decision = database.record_approval_decision(
        incident_id,
        incident["site_id"],
        approved_by,
        channel,
        "approved",
        payload.note,
        incident["status"],
        updated["status"],
    )
    return {"incident": updated, "policy": policy, "approved_by": approved_by, "decision": decision}


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
    if incident["status"] == "rejected":
        return {"incident": incident, "rejected_by": rejected_by, "note": payload.note, "already_final": True}
    if incident["status"] != "needs_review":
        raise HTTPException(
            status_code=409,
            detail="Only an action waiting for review can be rejected. Remove active protection separately.",
        )
    updated = database.transition_incident_status(incident_id, {"needs_review"}, "rejected")
    if not updated:
        raise HTTPException(status_code=409, detail="This incident can no longer be rejected.")
    database.consume_approval_token(incident_id)
    decision = database.record_approval_decision(
        incident_id,
        incident["site_id"],
        rejected_by,
        channel,
        "rejected",
        payload.note,
        incident["status"],
        updated["status"],
    )
    return {
        "incident": updated,
        "rejected_by": rejected_by,
        "note": payload.note,
        "decision": decision,
    }


def retry_incident_action(incident_id: int, requested_by: str) -> dict[str, Any]:
    """Retry provider execution without changing the owner's recorded decision."""
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident["status"] != "approved":
        raise HTTPException(status_code=409, detail="Approve this action before retrying protection.")
    policy = database.get_policy_for_incident(incident_id)
    if not policy or policy["status"] not in {"pending", "failed"}:
        raise HTTPException(status_code=409, detail="This protection is not waiting for a retry.")
    policy = remediation.retry_policy_for_incident(incident)
    return {"incident": incident, "policy": policy, "requested_by": requested_by}


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
