from __future__ import annotations

import html
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from secai import database
from secai.dashboard_api.dependencies import current_user_email, ensure_incident_owner, ensure_site_owner
from secai.settings import get_settings
from secai.integrations import alibaba_autopilot
from secai.models import ApprovalIn, IncidentOut, WAF_REMEDIATION_ACTIONS
from secai.actions import incidents as incident_service


router = APIRouter(tags=["incidents"])


@router.get("/api/incidents", response_model=list[IncidentOut])
def list_incidents(site_id: str | None = None, user_email: str = Depends(current_user_email)) -> list[dict[str, Any]]:
    """List incidents owned by the authenticated user."""
    if site_id:
        ensure_site_owner(site_id, user_email)
        return database.list_incidents(site_id)
    sites = database.list_sites(user_email)
    owned_site_ids = [site["site_id"] for site in sites]
    return database.list_incidents_for_sites(owned_site_ids)


@router.get("/api/incidents/{incident_id}", response_model=IncidentOut)
def incident_detail(incident_id: int, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Return one incident when it belongs to the authenticated user."""
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    ensure_incident_owner(incident, user_email)
    return incident


@router.post("/api/incidents/{incident_id}/approve")
def approve_incident(
    incident_id: int,
    payload: ApprovalIn,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Approve an owned incident's recommended remediation and create a policy."""
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    ensure_incident_owner(incident, user_email)
    return incident_service.approve_incident(incident_id, payload)


@router.post("/api/incidents/{incident_id}/reject")
def reject_incident(
    incident_id: int,
    payload: ApprovalIn,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Reject an owned incident's recommended remediation."""
    incident = database.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    ensure_incident_owner(incident, user_email)
    return incident_service.reject_incident(incident_id, payload)


@router.get("/approval/{token}/approve", response_model=None)
def approve_from_token(token: str, redirect: bool = False) -> dict[str, Any] | RedirectResponse | HTMLResponse:
    """Show a confirmation page before approving remediation from a notification link."""
    incident = database.get_incident_by_approval_token(token)
    if not incident:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return HTMLResponse(_decision_page(token, "approve", redirect, incident))


@router.post("/approval/{token}/approve", response_model=None)
def approve_from_token_post(
    token: str,
    redirect: bool = False,
) -> dict[str, Any] | RedirectResponse | HTMLResponse:
    """Approve remediation from a notification confirmation form."""
    incident = database.get_incident_by_approval_token(token)
    if not incident:
        raise HTTPException(status_code=404, detail="Approval request not found")
    result = incident_service.approve_incident(
        incident["id"],
        ApprovalIn(approved_by="approval-link", note="Approved from notification link"),
    )
    if redirect:
        return RedirectResponse(f"{get_settings().frontend_base_url}/?incident={incident['id']}&approval=approved")
    return HTMLResponse(_approval_page("Approved", "SecAi has recorded your approval and updated the remediation policy."))


@router.get("/approval/{token}/reject", response_model=None)
def reject_from_token(token: str, redirect: bool = False) -> dict[str, Any] | RedirectResponse | HTMLResponse:
    """Show a confirmation page before rejecting remediation from a notification link."""
    incident = database.get_incident_by_approval_token(token)
    if not incident:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return HTMLResponse(_decision_page(token, "reject", redirect, incident))


@router.post("/approval/{token}/reject", response_model=None)
def reject_from_token_post(
    token: str,
    redirect: bool = False,
) -> dict[str, Any] | RedirectResponse | HTMLResponse:
    """Reject remediation from a notification confirmation form."""
    incident = database.get_incident_by_approval_token(token)
    if not incident:
        raise HTTPException(status_code=404, detail="Approval request not found")
    result = incident_service.reject_incident(
        incident["id"],
        ApprovalIn(approved_by="approval-link", note="Rejected from notification link"),
    )
    if redirect:
        return RedirectResponse(f"{get_settings().frontend_base_url}/?incident={incident['id']}&approval=rejected")
    return HTMLResponse(_approval_page("Rejected", "SecAi will not take the recommended action for this incident."))


def _approval_page(title: str, message: str) -> str:
    """Return a small confirmation page for notification approvals."""
    return f"""
    <!doctype html>
    <html>
      <head><title>SecAi {title}</title></head>
      <body style="font-family: system-ui, sans-serif; max-width: 640px; margin: 48px auto; line-height: 1.5;">
        <h1>SecAi action {title.lower()}</h1>
        <p>{message}</p>
        <p>You can close this page.</p>
      </body>
    </html>
    """


def _decision_page(token: str, decision: str, redirect: bool, incident: dict[str, Any]) -> str:
    """Return a confirmation form for notification approval links."""
    title = "Approve" if decision == "approve" else "Reject"
    redirect_query = "?redirect=true" if redirect else ""
    action = f"/approval/{token}/{decision}{redirect_query}"
    recommendation = incident.get("recommended_action", {})
    parameters = alibaba_autopilot.policy_parameters_for_action(recommendation, incident)
    detail_rows = [
        ("Action", recommendation.get("action", "review")),
        ("Target", recommendation.get("target", "this website")),
        ("Provider", "Alibaba WAF" if recommendation.get("action") in WAF_REMEDIATION_ACTIONS else "SecAi report"),
        ("Duration", f"{parameters.get('duration_seconds', 3600)} seconds"),
        ("Rollback", parameters.get("rollback", "Reject this request or disable the SecAi-managed rule.")),
        ("Reason", recommendation.get("reason", "SecAi recommends a human review.")),
    ]
    detail_html = "\n".join(
        f"<li><strong>{html.escape(label)}:</strong> {html.escape(str(value))}</li>" for label, value in detail_rows
    )
    return f"""
    <!doctype html>
    <html>
      <head><title>SecAi {title} action</title></head>
      <body style="font-family: system-ui, sans-serif; max-width: 640px; margin: 48px auto; line-height: 1.5;">
        <h1>{title} SecAi action?</h1>
        <p>This confirmation prevents chat previews and link scanners from changing your incident status.</p>
        <ul>{detail_html}</ul>
        <form method="post" action="{action}">
          <button type="submit" style="font: inherit; padding: 10px 16px;">{title}</button>
        </form>
      </body>
    </html>
    """
