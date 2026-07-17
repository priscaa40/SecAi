from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from secai import database
from secai.actions import incidents as incident_service
from secai.dashboard_api.dependencies import current_user_email, ensure_incident_owner, ensure_site_owner
from secai.dashboard_api.routes.incident_views import incident_view, incident_views
from secai.models import ApprovalIn, IncidentOut

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    site_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=200),
    before_id: int | None = Query(default=None, ge=1),
    user_email: str = Depends(current_user_email),
) -> list[dict[str, Any]]:
    """List incidents owned by the authenticated user."""
    if site_id:
        ensure_site_owner(site_id, user_email)
        return incident_views(database.list_incidents(site_id, limit, before_id))
    owned_site_ids = [site["site_id"] for site in database.list_sites(user_email)]
    return incident_views(database.list_incidents_for_sites(owned_site_ids, limit, before_id))


def _owned_incident(incident_id: int, user_email: str) -> dict[str, Any]:
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    ensure_incident_owner(incident, user_email)
    return incident


@router.get("/{incident_id}", response_model=IncidentOut)
def incident_detail(incident_id: int, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Return one incident when it belongs to the authenticated user."""
    return incident_view(_owned_incident(incident_id, user_email))


@router.get("/{incident_id}/decisions")
def incident_decisions(incident_id: int, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Return the immutable approval and rejection history for an owned incident."""
    _owned_incident(incident_id, user_email)
    return {"incident_id": incident_id, "decisions": database.list_approval_decisions(incident_id)}


@router.post("/{incident_id}/approve")
def approve_incident(
    incident_id: int,
    payload: ApprovalIn,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Approve an owned incident's recommended remediation and create a policy."""
    _owned_incident(incident_id, user_email)
    return incident_service.approve_incident(incident_id, payload, user_email)


@router.post("/{incident_id}/reject")
def reject_incident(
    incident_id: int,
    payload: ApprovalIn,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Reject an owned incident's recommended remediation."""
    _owned_incident(incident_id, user_email)
    return incident_service.reject_incident(incident_id, payload, user_email)


@router.post("/{incident_id}/retry")
def retry_incident_action(incident_id: int, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Retry provider execution for an approved action that failed or was interrupted."""
    _owned_incident(incident_id, user_email)
    return incident_service.retry_incident_action(incident_id, user_email)


@router.post("/{incident_id}/remove-protection")
def remove_incident_protection(incident_id: int, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Remove an active Alibaba Cloud rule without rewriting the approval record."""
    _owned_incident(incident_id, user_email)
    return incident_service.remove_incident_protection(incident_id, user_email)
