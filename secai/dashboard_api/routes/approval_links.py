from __future__ import annotations

import html
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from secai import database
from secai.actions import incidents as incident_service
from secai.actions.protection_presentation import display_ip, duration_label
from secai.integrations import discord
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
    try:
        incident_service.approve_incident(
            incident["id"],
            ApprovalIn(note="Approved from Discord"),
            "discord",
            "discord",
        )
    except HTTPException as exc:
        discord.notify_decision_result(incident, "approve", error=str(exc.detail))
        return HTMLResponse(approval_page("Failed", "SecAi could not apply this decision. Check Discord for details."), status_code=exc.status_code)
    except Exception:
        discord.notify_decision_result(incident, "approve", error="Please open the report and try again.")
        return HTMLResponse(approval_page("Failed", "SecAi could not apply this decision. Check Discord for details."), status_code=502)
    if redirect:
        return RedirectResponse(
            f"{get_settings().frontend_base_url}/?incident={incident['id']}&approval=queued",
            status_code=303,
        )
    return HTMLResponse(
        approval_page("Queued", "Your approval was saved. Qwen Executor is now applying the action through its MCP tool.")
    )


@router.get("/approval/{token}/reject", response_model=None)
def reject_from_token(token: str, redirect: bool = False) -> HTMLResponse:
    """Show a confirmation page before rejecting from a notification link."""
    return HTMLResponse(decision_page(token, "reject", redirect, _incident_for_token(token)))


@router.post("/approval/{token}/reject", response_model=None)
def reject_from_token_post(token: str, redirect: bool = False) -> RedirectResponse | HTMLResponse:
    """Reject remediation from a notification confirmation form."""
    incident = _incident_for_token(token)
    try:
        result = incident_service.reject_incident(
            incident["id"],
            ApprovalIn(note="Rejected from Discord"),
            "discord",
            "discord",
        )
    except HTTPException as exc:
        discord.notify_decision_result(incident, "reject", error=str(exc.detail))
        return HTMLResponse(approval_page("Failed", "SecAi could not save this decision. Check Discord for details."), status_code=exc.status_code)
    except Exception:
        discord.notify_decision_result(incident, "reject", error="Please open the report and try again.")
        return HTMLResponse(approval_page("Failed", "SecAi could not save this decision. Check Discord for details."), status_code=502)
    discord.notify_decision_result(incident, "reject", result=result)
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
    redirect_query = "?redirect=true" if redirect else ""
    safe_token = quote(token, safe="")
    action = html.escape(f"/approval/{safe_token}/{decision}{redirect_query}", quote=True)
    recommendation = incident.get("recommended_action", {})
    parameters = policy_parameters_for_action(recommendation, incident)
    target = display_ip(recommendation.get("target"))
    duration = duration_label(int(parameters.get("duration_seconds", 3600)))
    approving = decision == "approve"
    title = f"Block {target} for {duration}?" if approving else f"Don't block {target}?"
    button = f"Block for {duration}" if approving else "Don't block"
    detail_rows = [
        ("Address", target),
        ("Duration", duration),
        (
            "Applied through",
            "Alibaba ECS security group"
            if recommendation.get("action") in SECURITY_GROUP_REMEDIATION_ACTIONS
            else "SecAi report",
        ),
        ("Reason", recommendation.get("reason", "SecAi recommends a human review.")),
    ]
    detail_html = "\n".join(
        f"<li><strong>{html.escape(label)}:</strong> {html.escape(str(value))}</li>" for label, value in detail_rows
    )
    return f"""
    <!doctype html>
    <html>
      <head><title>SecAi protection decision</title></head>
      <body style="font-family: system-ui, sans-serif; max-width: 640px; margin: 48px auto; line-height: 1.5;">
        <h1>{html.escape(title)}</h1>
        <p>{"Nothing changes until you confirm." if approving else "No traffic will be changed if you confirm."}</p>
        <ul>{detail_html}</ul>
        <form method="post" action="{action}">
          <button type="submit" style="font: inherit; padding: 10px 16px;">{html.escape(button)}</button>
        </form>
      </body>
    </html>
    """
