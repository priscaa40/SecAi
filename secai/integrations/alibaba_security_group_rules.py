from __future__ import annotations

import hashlib
from ipaddress import ip_address, ip_network
from typing import Any

from secai.integrations.alibaba_autopilot import AlibabaAutopilotConnection
from secai.models import SECURITY_GROUP_REMEDIATION_ACTIONS
from secai.settings import get_settings


class AlibabaSecurityGroupExecutionError(Exception):
    """Raised when an Alibaba ECS security-group request cannot be verified."""


def policy_parameters_for_action(action: dict[str, Any], incident: dict[str, Any]) -> dict[str, Any]:
    """Build provider-neutral policy parameters from an incident recommendation."""
    action_name = action.get("action")
    target = action.get("target") or ""
    params: dict[str, Any] = {
        "duration_seconds": int(action.get("duration_seconds") or 3600),
        "rollback": "Revoke the SecAi-managed Alibaba ECS security group deny rule.",
    }
    if action_name in SECURITY_GROUP_REMEDIATION_ACTIONS:
        try:
            params["source_cidr"] = normalize_source_cidr(action_name, target)
        except ValueError:
            params["source_cidr"] = target
    if incident.get("affected_route"):
        params["route"] = incident["affected_route"]
    return params


def build_rule_request(
    connection: AlibabaAutopilotConnection,
    policy: dict[str, Any],
    incident: dict[str, Any],
) -> dict[str, Any]:
    """Translate a SecAi remediation policy into an Alibaba ECS request."""
    action = policy["action"]
    if action not in SECURITY_GROUP_REMEDIATION_ACTIONS:
        raise AlibabaSecurityGroupExecutionError(f"Security groups can only execute IP block actions, not {action}.")
    source_cidr = normalize_source_cidr(action, policy.get("target") or "")
    network = ip_network(source_cidr, strict=False)
    permission: dict[str, Any] = {
        "IpProtocol": "all",
        "PortRange": "-1/-1",
        "Policy": "drop",
        "Priority": "1",
        "Description": rule_name(policy, incident),
    }
    request: dict[str, Any] = {
        "RegionId": connection.region,
        "SecurityGroupId": connection.security_group_id,
        "Permissions": [permission],
    }
    if network.version == 6:
        permission["Ipv6SourceCidrIp"] = source_cidr
    else:
        permission["SourceCidrIp"] = source_cidr
    return request


def normalize_source_cidr(action: str, target: str) -> str:
    """Validate one globally routable source address for a protection rule."""
    target = (target or "").strip()
    if not target:
        raise ValueError("Security group remediation requires a source IP or CIDR target.")
    try:
        if "/" in target:
            network = ip_network(target, strict=False)
        else:
            address = ip_address(target)
            network = ip_network(f"{address}/{32 if address.version == 4 else 128}", strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid source IP or CIDR for {action}: {target}") from exc
    if action != "block_ip" or network.num_addresses != 1:
        raise ValueError("SecAi protection requires one source IP address.")
    if not network.network_address.is_global or not network.broadcast_address.is_global:
        raise ValueError("Security group remediation cannot target a non-global network.")
    protected_values = [
        value.strip() for value in get_settings().secai_remediation_protected_cidrs.split(",") if value.strip()
    ]
    protected = [ip_network(value, strict=False) for value in protected_values]
    if any(network.overlaps(item) for item in protected if network.version == item.version):
        raise ValueError("Security group remediation overlaps an owner-protected network.")
    return str(network)


def client_token(operation: str, policy: dict[str, Any]) -> str:
    """Return a stable Alibaba idempotency token for one policy operation."""
    raw = f"secai:{operation}:{policy.get('id')}:{policy.get('incident_id')}:{policy.get('action')}:{policy.get('target')}"
    return f"secai-{operation}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:40]}"


def matching_rule_id(response: dict[str, Any], request: dict[str, Any]) -> str | None:
    """Return the provider rule ID for the exact SecAi rule description."""
    expected = request["Permissions"][0]
    for rule in security_group_rules(response):
        if rule_matches(rule, expected):
            rule_id = rule.get("SecurityGroupRuleId") or rule.get("security_group_rule_id")
            if rule_id:
                return str(rule_id)
    return None


def equivalent_rule_ids(response: dict[str, Any], request: dict[str, Any]) -> set[str]:
    """Return IDs of equivalent rules, ignoring the SecAi description."""
    expected = {key: value for key, value in request["Permissions"][0].items() if key != "Description"}
    return {
        str(rule.get("SecurityGroupRuleId") or rule.get("security_group_rule_id"))
        for rule in security_group_rules(response)
        if rule_matches(rule, expected) and (rule.get("SecurityGroupRuleId") or rule.get("security_group_rule_id"))
    }


def security_group_rule_ids(response: dict[str, Any]) -> set[str]:
    """Return every provider rule ID present in an ECS response."""
    return {
        str(rule.get("SecurityGroupRuleId") or rule.get("security_group_rule_id"))
        for rule in security_group_rules(response)
        if rule.get("SecurityGroupRuleId") or rule.get("security_group_rule_id")
    }


def rule_name(policy: dict[str, Any], incident: dict[str, Any]) -> str:
    raw = f"secai-{incident.get('id') or policy.get('incident_id') or policy['id']}-{policy['action']}"
    return "".join(character if character.isalnum() or character in "._-" else "-" for character in raw)[:120]


def security_group_rules(response: dict[str, Any]) -> list[dict[str, Any]]:
    permissions = response.get("Permissions") or response.get("permissions") or {}
    return permissions.get("Permission") or permissions.get("permission") or []


def rule_matches(rule: dict[str, Any], expected: dict[str, Any]) -> bool:
    return all(
        str(rule.get(field) or rule.get(snake_case(field)) or "").lower() == str(value).lower()
        for field, value in expected.items()
    )


def snake_case(value: str) -> str:
    return "".join(("_" + character.lower()) if character.isupper() else character for character in value).lstrip("_")
