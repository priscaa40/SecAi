from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from secai import database
from secai.actions import remediation
from secai.actions.capabilities import action_spec
from secai.event_sources import alibaba_sls
from secai.event_sources.scheduler import ingest_sls_events
from secai.integrations import discord

mcp = FastMCP(
    "SecAi Autopilot Actions",
    instructions=(
        "Execute only the persisted SecAi action job identified by action_job_id. "
        "Every tool revalidates tenant scope, the incident recommendation, and any required human approval."
    ),
    json_response=True,
)


def _validated_request(action_job_id: int, expected_tool: str) -> tuple[dict[str, Any], dict[str, Any]]:
    job = database.get_action_job(action_job_id)
    if not job:
        raise ValueError("Action job not found")
    if job["status"] != "running":
        raise ValueError("Action job is not currently claimed by the executor")
    if job.get("current_step") != "mcp_tool_running":
        raise ValueError("This MCP invocation was not granted by the action executor")
    if job["tool_name"] != expected_tool:
        raise ValueError("The requested MCP tool does not match the persisted action")
    spec = action_spec(job["action"])
    if spec.tool_name != expected_tool or spec.requires_approval != job["requires_approval"]:
        raise ValueError("Action job capabilities do not match the server registry")
    incident = database.get_incident(job["incident_id"])
    if not incident or incident["site_id"] != job["site_id"]:
        raise ValueError("Action job tenant scope is invalid")
    if (incident.get("recommended_action") or {}).get("action") != job["action"]:
        raise ValueError("The action job no longer matches the persisted recommendation")
    if spec.requires_approval:
        decisions = database.list_approval_decisions(incident["id"])
        approved = next(
            (
                decision
                for decision in decisions
                if decision["id"] == job.get("approval_decision_id") and decision["decision"] == "approved"
            ),
            None,
        )
        if not approved or incident["status"] != "approved":
            raise ValueError("This action does not have a valid persisted owner approval")
    elif incident["status"] != "reported":
        raise ValueError("This report is not eligible for automatic action")
    return job, incident


def execute_owner_alert(action_job_id: int) -> dict[str, Any]:
    job, incident = _validated_request(action_job_id, "send_owner_security_alert")
    delivered = discord.notify_incident(incident)
    channels = [channel["channel"] for channel in database.list_report_channels(job["site_id"])]
    return {
        "action_job_id": action_job_id,
        "action": job["action"],
        "dashboard_report_available": True,
        "external_alert_delivered": delivered,
        "configured_channels": channels,
    }


def execute_follow_up_collection(action_job_id: int) -> dict[str, Any]:
    job, _ = _validated_request(action_job_id, "collect_follow_up_cloud_evidence")
    events = alibaba_sls.fetch_saved_site_events(job["site_id"], minutes=15, limit=50)
    result = ingest_sls_events(events)
    return {
        "action_job_id": action_job_id,
        "action": job["action"],
        "events_seen": result["events_seen"],
        "new_evidence": result["events_ingested"],
        "investigations_queued": result["jobs_queued"],
        "duplicates_skipped": result["duplicates_skipped"],
    }


def execute_temporary_ip_block(action_job_id: int) -> dict[str, Any]:
    job, incident = _validated_request(action_job_id, "apply_temporary_ip_block")
    policy = database.get_policy_for_incident(incident["id"])
    if policy and policy["status"] in {"pending", "failed"}:
        policy = remediation.retry_policy_for_incident(incident)
    elif not policy:
        policy = remediation.create_policy_for_incident(incident, incident["recommended_action"])
    if not policy or policy.get("status") != "active":
        detail = (policy or {}).get("error_message") or "Alibaba Cloud did not confirm an active rule"
        raise RuntimeError(detail)
    return {
        "action_job_id": action_job_id,
        "action": job["action"],
        "policy_id": policy["id"],
        "policy_status": policy["status"],
        "provider": policy["provider"],
        "provider_rule_id": policy.get("provider_rule_id"),
        "target": policy["target"],
        "expires_at": policy.get("expires_at"),
    }


@mcp.tool(name="send_owner_security_alert")
def send_owner_security_alert(action_job_id: int) -> dict[str, Any]:
    """Deliver the persisted incident through the website owner's configured report channel."""
    return execute_owner_alert(action_job_id)


@mcp.tool(name="collect_follow_up_cloud_evidence")
def collect_follow_up_cloud_evidence(action_job_id: int) -> dict[str, Any]:
    """Pull a fresh bounded Alibaba SLS window and queue investigations for new evidence."""
    return execute_follow_up_collection(action_job_id)


@mcp.tool(name="apply_temporary_ip_block")
def apply_temporary_ip_block(action_job_id: int) -> dict[str, Any]:
    """Apply one owner-approved temporary Alibaba security-group block."""
    return execute_temporary_ip_block(action_job_id)


def main() -> None:
    try:
        mcp.run(transport="stdio")
    finally:
        database.close_database_pool()


if __name__ == "__main__":
    main()
