from __future__ import annotations

import logging
import time
from typing import Any

from secai.integrations.alibaba_autopilot import AlibabaAutopilotConnection, load_site_connection
from secai.integrations.alibaba_ecs import AlibabaEcsSecurityGroupClient
from secai.integrations.alibaba_resources import security_group_is_dedicated
from secai.integrations.alibaba_security_group_rules import (
    AlibabaSecurityGroupExecutionError,
    build_rule_request,
    client_token,
    equivalent_rule_ids,
    matching_rule_id,
    security_group_rule_ids,
)
from secai.models import SECURITY_GROUP_REMEDIATION_ACTIONS

logger = logging.getLogger(__name__)


class AlibabaSecurityGroupNotReady(Exception):
    """Raised when a site cannot use security-group enforcement."""


def apply_policy(site_id: str, policy: dict[str, Any], incident: dict[str, Any]) -> dict[str, Any]:
    """Create the Alibaba ECS security-group rule for an approved policy."""
    connection = load_site_connection(site_id)
    require_ready_connection(connection, removing=False)
    if not security_group_is_dedicated(connection):
        raise AlibabaSecurityGroupNotReady(
            "The selected security group must still be attached to exactly one website server."
        )
    if policy["action"] not in SECURITY_GROUP_REMEDIATION_ACTIONS:
        raise AlibabaSecurityGroupNotReady(
            f"Action {policy['action']} is not executable through Alibaba ECS security groups."
        )

    request = build_rule_request(connection, policy, incident)
    request["ClientToken"] = client_token("authorize", policy)
    client = AlibabaEcsSecurityGroupClient(connection)
    before = client.describe_security_group_rules(request)
    existing_rule_id = matching_rule_id(before, request)
    if existing_rule_id:
        return {
            "provider": "alibaba_security_group",
            "provider_rule_id": existing_rule_id,
            "request": request,
            "response": {"status": "existing_secai_rule"},
        }
    if equivalent_rule_ids(before, request):
        raise AlibabaSecurityGroupExecutionError(
            "An equivalent owner-managed Alibaba security-group rule already exists; SecAi will not claim or modify it."
        )

    before_rule_ids = security_group_rule_ids(before)
    response = client.authorize_security_group(request)
    provider_rule_id = None
    after: dict[str, Any] = {}
    for attempt in range(5):
        after = client.describe_security_group_rules(request)
        provider_rule_id = matching_rule_id(after, request)
        if provider_rule_id:
            break
        if attempt < 4:
            time.sleep(0.25 * (2**attempt))
    if not provider_rule_id:
        cleanup_unverified_rule(client, before_rule_ids, after, request, policy)
        raise AlibabaSecurityGroupExecutionError(
            "Alibaba accepted the rule request, but SecAi could not verify a provider security-group rule ID."
        )
    return {
        "provider": "alibaba_security_group",
        "provider_rule_id": provider_rule_id,
        "request": request,
        "response": response,
    }


def delete_policy(site_id: str, policy: dict[str, Any]) -> dict[str, Any]:
    """Delete and verify removal of the Alibaba rule created for a policy."""
    connection = load_site_connection(site_id)
    require_ready_connection(connection, removing=True)
    if policy.get("provider") != "alibaba_security_group" or not policy.get("provider_rule_id"):
        raise AlibabaSecurityGroupNotReady("This policy does not have an Alibaba security group rule to remove.")

    request = {
        "RegionId": connection.region,
        "SecurityGroupId": connection.security_group_id,
        "SecurityGroupRuleId": [policy["provider_rule_id"]],
        "ClientToken": client_token("revoke", policy),
    }
    client = AlibabaEcsSecurityGroupClient(connection)
    rule_id = str(policy["provider_rule_id"])
    before = client.describe_security_group_rules(request)
    if rule_id not in security_group_rule_ids(before):
        return {
            "provider": "alibaba_security_group",
            "provider_rule_id": rule_id,
            "request": request,
            "response": {"status": "already_removed"},
        }

    response = client.revoke_security_group(request)
    for attempt in range(5):
        after = client.describe_security_group_rules(request)
        if rule_id not in security_group_rule_ids(after):
            break
        if attempt < 4:
            time.sleep(0.25 * (2**attempt))
    else:
        raise AlibabaSecurityGroupExecutionError(
            "Alibaba accepted the removal request, but the security-group rule is still present."
        )
    return {
        "provider": "alibaba_security_group",
        "provider_rule_id": rule_id,
        "request": request,
        "response": response,
    }


def require_ready_connection(connection: AlibabaAutopilotConnection, *, removing: bool) -> None:
    if connection.enforcement_mode != "security_group":
        raise AlibabaSecurityGroupNotReady(
            "Alibaba Autopilot is connected in observe-only mode; security group enforcement is not enabled."
        )
    if not connection.security_group_id:
        purpose = "remove remediation" if removing else "enforce remediation"
        raise AlibabaSecurityGroupNotReady(f"Alibaba ECS security group ID is required before SecAi can {purpose}.")


def cleanup_unverified_rule(
    client: AlibabaEcsSecurityGroupClient,
    before_rule_ids: set[str],
    after: dict[str, Any],
    request: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    """Best-effort cleanup when ECS creates one rule SecAi cannot identify by description."""
    new_effective_ids = equivalent_rule_ids(after, request) - before_rule_ids
    if len(new_effective_ids) != 1:
        return
    new_rule_id = new_effective_ids.pop()
    try:
        client.revoke_security_group(
            {
                "RegionId": request["RegionId"],
                "SecurityGroupId": request["SecurityGroupId"],
                "SecurityGroupRuleId": [new_rule_id],
                "ClientToken": client_token("cleanup", policy),
            }
        )
    except Exception:
        logger.exception("Could not clean up a newly identified but unverified Alibaba security group rule")
