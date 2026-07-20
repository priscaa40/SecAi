from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from secai import database
from secai.actions.protection_presentation import temporary_window_open
from secai.agent.validation import validate_remediation_target
from secai.integrations import alibaba_security_groups
from secai.integrations.alibaba_security_group_rules import policy_parameters_for_action
from secai.models import NON_NETWORK_ACTIONS, SECURITY_GROUP_REMEDIATION_ACTIONS


def create_policy_for_incident(incident: dict[str, Any], action: dict[str, Any]) -> dict[str, Any] | None:
    """Create and execute a remediation policy for an approved incident."""
    action_name = action.get("action", "send_owner_alert")
    if action_name in NON_NETWORK_ACTIONS:
        return None

    source_event_id = action.get("source_event_id") or incident.get("recommended_action", {}).get("source_event_id")
    source_event = database.get_event(source_event_id) if source_event_id else None
    normalized_target = validate_remediation_target(action_name, action.get("target", ""), source_event)
    action = {**action, "target": normalized_target}

    provider = "alibaba_security_group" if action_name in SECURITY_GROUP_REMEDIATION_ACTIONS else None
    parameters = policy_parameters_for_action(action, incident)
    expires_at = _policy_expiry(parameters)
    incident_id = incident.get("id")
    if not isinstance(incident_id, int):
        raise ValueError("A persisted incident ID is required before remediation")
    policy, created = database.get_or_insert_policy(
        incident["site_id"],
        action_name,
        action.get("target", ""),
        action.get("reason", "Approved remediation"),
        incident_id,
        provider=provider,
        parameters=parameters,
        expires_at=expires_at,
    )
    if not created:
        return policy
    if provider == "alibaba_security_group":
        return _apply_alibaba_security_group_policy(policy, incident)
    return database.update_policy_execution_state(
        policy["id"],
        "failed",
        error_message=f"No enforcement provider is available for action {action_name}.",
    )


def revoke_policy_for_incident(incident: dict[str, Any], final_status: str = "revoked") -> dict[str, Any] | None:
    """Remove an active provider policy for an incident when the owner overrules it."""
    policy = database.get_policy_for_incident(incident["id"])
    if not policy or policy.get("provider") != "alibaba_security_group":
        return None
    if policy.get("status") == "active":
        policy = database.transition_policy_status(policy["id"], {"active"}, "revoking")
    if not policy or policy.get("status") != "revoking":
        return None
    try:
        result = alibaba_security_groups.delete_policy(incident["site_id"], policy)
    except Exception as exc:
        database.record_remediation_execution(
            incident["site_id"],
            policy["id"],
            incident.get("id"),
            "alibaba_security_group",
            policy["action"],
            policy["target"],
            "failed",
            request={"provider_rule_id": policy.get("provider_rule_id")},
            response={},
            error_message=f"Security group rollback failed: {exc}",
        )
        database.update_policy_execution_state(
            policy["id"], "active", error_message="Rollback failed; retry is required"
        )
        raise

    database.record_remediation_execution(
        incident["site_id"],
        policy["id"],
        incident.get("id"),
        "alibaba_security_group",
        policy["action"],
        policy["target"],
        final_status,
        request=result.get("request"),
        response=result.get("response"),
    )
    return database.update_policy_execution_state(policy["id"], final_status)


def retry_policy_for_incident(incident: dict[str, Any]) -> dict[str, Any]:
    """Retry an interrupted or failed Alibaba security-group policy."""
    policy = database.get_policy_for_incident(incident["id"])
    if not policy or policy.get("status") not in {"pending", "failed"}:
        raise ValueError("This incident does not have retryable protection.")
    if policy.get("provider") != "alibaba_security_group":
        raise ValueError("This protection does not have an Alibaba Cloud provider.")
    return _apply_alibaba_security_group_policy(policy, incident)


def reapply_policy_for_incident(incident: dict[str, Any]) -> dict[str, Any]:
    """Reapply an owner-removed rule during its original temporary window."""
    policy = database.get_policy_for_incident(incident["id"])
    if not policy or policy.get("status") != "revoked":
        raise ValueError("This incident does not have removed protection to apply again.")
    if policy.get("provider") != "alibaba_security_group":
        raise ValueError("This protection does not have an Alibaba Cloud provider.")
    if not temporary_window_open(policy.get("expires_at")):
        raise ValueError("The temporary blocking window has ended.")
    return _apply_alibaba_security_group_policy(
        policy,
        incident,
        claim_statuses={"revoked"},
        failure_status="revoked",
        activation_expiry=policy["expires_at"],
    )


def _apply_alibaba_security_group_policy(
    policy: dict[str, Any],
    incident: dict[str, Any],
    *,
    claim_statuses: set[str] | None = None,
    failure_status: str = "failed",
    activation_expiry: str | None = None,
) -> dict[str, Any]:
    """Apply one policy through an Alibaba ECS security group and record the result."""
    claimed = database.transition_policy_status(
        policy["id"], claim_statuses or {"pending", "failed"}, "applying"
    )
    if not claimed:
        return database.get_policy(policy["id"]) or policy
    policy = claimed
    try:
        result = alibaba_security_groups.apply_policy(incident["site_id"], policy, incident)
    except Exception as exc:
        database.record_remediation_execution(
            incident["site_id"],
            policy["id"],
            incident.get("id"),
            "alibaba_security_group",
            policy["action"],
            policy["target"],
            "failed",
            request=policy.get("parameters"),
            response={},
            error_message=str(exc),
        )
        return database.update_policy_execution_state(policy["id"], failure_status, error_message=str(exc))

    database.record_remediation_execution(
        incident["site_id"],
        policy["id"],
        incident.get("id"),
        "alibaba_security_group",
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
        expires_at=activation_expiry or _policy_expiry(policy.get("parameters") or {}),
    )


def _policy_expiry(parameters: dict[str, Any]) -> str:
    """Start the temporary-protection clock when a provider rule becomes active."""
    duration = max(60, int(parameters.get("duration_seconds", 3600)))
    return (datetime.now(UTC) + timedelta(seconds=duration)).isoformat()
