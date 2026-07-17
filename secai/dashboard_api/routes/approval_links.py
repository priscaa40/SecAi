from __future__ import annotations

import html
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from secai import database
from secai.actions import incidents as incident_service
from secai.integrations.alibaba_security_group_rules import policy_parameters_for_action
from secai.models import SECURITY_GROUP_REMEDIATION_ACTIONS, ApprovalIn
from secai.settings import get_settings

router = APIRouter(tags=["approvals"])


@router.get("/approval/{token}/approve", response_model=None)
def approve_from_token(token: str, redirect: bool = False) -> HTMLResponse:
    """Show a confirmation page before approving from a notification link."""
    return HTMLResponse(decision_page(token, "approve", redirect, _incident_for_token(token)))


@router.post("/approval/{token}/approve", response_model=None)
def approve_from_token_post(token: str, redirect: bool = False) -> RedirectResponse | HTMLResponse:
    """Approve remediation from a notification confirmation form."""
    incident = _incident_for_token(token)
    incident_service.approve_incident(
        incident["id"],
        ApprovalIn(note="Approved from notification link"),
        "approval-link",
        "approval_link",
    )
    if redirect:
        return RedirectResponse(
            f"{get_settings().frontend_base_url}/?incident={incident['id']}&approval=approved",
            status_code=303,
        )
    return HTMLResponse(
        approval_page("Approved", "SecAi has recorded your approval and updated the remediation policy.")
    )


@router.get("/approval/{token}/reject", response_model=None)
def reject_from_token(token: str, redirect: bool = False) -> HTMLResponse:
    """Show a confirmation page before rejecting from a notification link."""
    return HTMLResponse(decision_page(token, "reject", redirect, _incident_for_token(token)))


@router.post("/approval/{token}/reject", response_model=None)
def reject_from_token_post(token: str, redirect: bool = False) -> RedirectResponse | HTMLResponse:
    """Reject remediation from a notification confirmation form."""
    incident = _incident_for_token(token)
    incident_service.reject_incident(
        incident["id"],
        ApprovalIn(note="Rejected from notification link"),
        "approval-link",
        "approval_link",
    )
    if redirect:
        return RedirectResponse(
            f"{get_settings().frontend_base_url}/?incident={incident['id']}&approval=rejected",
            status_code=303,
        )
    return HTMLResponse(approval_page("Rejected", "SecAi will not take the recommended action for this incident."))


def _incident_for_token(token: str) -> dict[str, Any]:
    incident = database.get_incident_by_approval_token(token)
    if not incident:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return incident


def approval_page(title: str, message: str) -> str:
    """Return a small result page for a notification decision."""
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


def decision_page(token: str, decision: str, redirect: bool, incident: dict[str, Any]) -> str:
    """Return a confirmation form for notification approval links."""
    title = "Approve" if decision == "approve" else "Reject"
    redirect_query = "?redirect=true" if redirect else ""
    safe_token = quote(token, safe="")
    action = html.escape(f"/approval/{safe_token}/{decision}{redirect_query}", quote=True)
    recommendation = incident.get("recommended_action", {})
    parameters = policy_parameters_for_action(recommendation, incident)
    detail_rows = [
        ("Action", recommendation.get("action", "review")),
        ("Target", recommendation.get("target", "this website")),
        (
            "Provider",
            "Alibaba ECS security group"
            if recommendation.get("action") in SECURITY_GROUP_REMEDIATION_ACTIONS
            else "SecAi report",
        ),
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
