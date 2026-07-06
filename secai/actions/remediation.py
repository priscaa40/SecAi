from __future__ import annotations

from typing import Any

from secai import database
from secai.integrations import alibaba_autopilot
from secai.models import REPORTING_ACTIONS, WAF_REMEDIATION_ACTIONS


def create_policy_for_incident(incident: dict[str, Any], action: dict[str, Any]) -> dict[str, Any] | None:
    """Create and execute a remediation policy for an approved incident."""
    action_name = action.get("action", "monitor")
    if action_name in REPORTING_ACTIONS:
        return None

    provider = "alibaba_waf" if action_name in WAF_REMEDIATION_ACTIONS else None
    parameters = alibaba_autopilot.policy_parameters_for_action(action, incident)
    policy = database.insert_policy(
        incident["site_id"],
        action_name,
        action.get("target", ""),
        action.get("reason", "Approved remediation"),
        incident.get("id"),
        provider=provider,
        parameters=parameters,
        status="pending",
    )
    if provider == "alibaba_waf":
        return _apply_alibaba_waf_policy(policy, incident)
    return database.update_policy_execution_state(
        policy["id"],
        "failed",
        error_message=f"No enforcement provider is available for action {action_name}.",
    )


def revoke_policy_for_incident(incident: dict[str, Any]) -> dict[str, Any] | None:
    """Remove an active provider policy for an incident when the owner overrules it."""
    policy = database.get_policy_for_incident(incident["id"])
    if not policy or policy.get("provider") != "alibaba_waf" or policy.get("status") != "active":
        return None
    try:
        result = alibaba_autopilot.delete_policy(incident["site_id"], policy)
    except Exception as exc:
        database.record_remediation_execution(
            incident["site_id"],
            policy["id"],
            incident.get("id"),
            "alibaba_waf",
            policy["action"],
            policy["target"],
            "failed",
            request={"provider_rule_id": policy.get("provider_rule_id")},
            response={},
            error_message=f"Rollback failed: {exc}",
        )
        raise

    database.record_remediation_execution(
        incident["site_id"],
        policy["id"],
        incident.get("id"),
        "alibaba_waf",
        policy["action"],
        policy["target"],
        "expired",
        request=result.get("request"),
        response=result.get("response"),
    )
    return database.update_policy_execution_state(policy["id"], "expired")


def _apply_alibaba_waf_policy(policy: dict[str, Any], incident: dict[str, Any]) -> dict[str, Any]:
    """Apply one policy through Alibaba WAF and record the result."""
    try:
        result = alibaba_autopilot.apply_policy(incident["site_id"], policy, incident)
    except Exception as exc:
        database.record_remediation_execution(
            incident["site_id"],
            policy["id"],
            incident.get("id"),
            "alibaba_waf",
            policy["action"],
            policy["target"],
            "failed",
            request=policy.get("parameters"),
            response={},
            error_message=str(exc),
        )
        return database.update_policy_execution_state(policy["id"], "failed", error_message=str(exc))

    database.record_remediation_execution(
        incident["site_id"],
        policy["id"],
        incident.get("id"),
        "alibaba_waf",
        policy["action"],
        policy["target"],
        "active",
        request=result.get("request"),
        response=result.get("response"),
    )
    return database.update_policy_execution_state(
        policy["id"],
        "active",
        provider_rule_id=result["provider_rule_id"],
    )
