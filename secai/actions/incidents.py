from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from secai import database
from secai.models import ApprovalIn
from secai.actions import remediation


def approve_incident(incident_id: int, payload: ApprovalIn) -> dict[str, Any]:
    """Approve an incident's recommended remediation and create a policy."""
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident["status"] == "rejected":
        raise HTTPException(status_code=409, detail="Rejected incidents cannot be approved.")
    if incident["status"] in {"approved", "auto_approved"}:
        return {
            "incident": incident,
            "policy": database.get_policy_for_incident(incident_id),
            "approved_by": payload.approved_by,
            "already_final": True,
        }
    action = incident["recommended_action"]
    if payload.note and not action.get("reason"):
        action["reason"] = payload.note
    policy = remediation.create_policy_for_incident(incident, action)
    updated = database.update_incident_status(incident_id, "approved")
    database.consume_approval_token(incident_id)
    return {"incident": updated, "policy": policy, "approved_by": payload.approved_by}


def reject_incident(incident_id: int, payload: ApprovalIn) -> dict[str, Any]:
    """Reject an incident's recommended remediation."""
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident["status"] in {"approved", "auto_approved"}:
        try:
            policy = remediation.revoke_policy_for_incident(incident)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Could not remove the active WAF remediation: {exc}") from exc
        if not policy:
            raise HTTPException(status_code=409, detail="Approved incidents without an active WAF rule cannot be rejected.")
        updated = database.update_incident_status(incident_id, "rejected")
        database.consume_approval_token(incident_id)
        return {"incident": updated, "rejected_by": payload.approved_by, "note": payload.note, "policy": policy}
    if incident["status"] == "rejected":
        return {"incident": incident, "rejected_by": payload.approved_by, "note": payload.note, "already_final": True}
    updated = database.update_incident_status(incident_id, "rejected")
    database.consume_approval_token(incident_id)
    return {"incident": updated, "rejected_by": payload.approved_by, "note": payload.note}
