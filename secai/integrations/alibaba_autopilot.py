from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from secai import database
from secai.integrations import alibaba_credentials
from secai.models import SECURITY_GROUP_REMEDIATION_ACTIONS
from secai.settings import get_settings


class AlibabaAutopilotNotConfigured(Exception):
    """Raised when a site has not connected Alibaba Autopilot."""


@dataclass(frozen=True)
class AlibabaAutopilotConnection:
    """Per-site Alibaba Cloud connection used by event and action providers."""

    site_id: str
    role_arn: str
    external_id: str
    account_id: str
    region: str
    enforcement_mode: str
    security_group_id: str | None = None
    sls_endpoint: str | None = None
    sls_project: str | None = None
    sls_logstore: str | None = None


def load_site_connection(site_id: str) -> AlibabaAutopilotConnection:
    """Load a site's saved Alibaba Autopilot connection."""
    config = database.get_alibaba_autopilot_config(site_id)
    if not config or config.get("connection_status") != "verified" or not config.get("role_arn"):
        raise AlibabaAutopilotNotConfigured(f"No Alibaba Autopilot connection saved for site {site_id}.")
    return AlibabaAutopilotConnection(
        site_id=site_id,
        role_arn=config["role_arn"],
        external_id=config["external_id"],
        account_id=config["account_id"],
        region=config["region"],
        enforcement_mode=config["enforcement_mode"],
        security_group_id=config.get("security_group_id"),
        sls_endpoint=config.get("sls_endpoint"),
        sls_project=config.get("sls_project"),
        sls_logstore=config.get("sls_logstore"),
    )


def public_config(config: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return Alibaba Autopilot config fields safe for the dashboard."""
    if not config:
        return None
    return {
        "site_id": config["site_id"],
        "role_arn": config.get("role_arn"),
        "external_id": config["external_id"],
        "account_id": config.get("account_id"),
        "connection_status": config["connection_status"],
        "connection_error": config.get("connection_error"),
        "verified_at": config.get("verified_at"),
        "region": config["region"],
        "security_group_id": config.get("security_group_id"),
        "sls_endpoint": config.get("sls_endpoint"),
        "sls_project": config.get("sls_project"),
        "sls_logstore": config.get("sls_logstore"),
        "enforcement_mode": config["enforcement_mode"],
        "created_at": config["created_at"],
        "updated_at": config["updated_at"],
    }


def site_status(site_id: str) -> dict[str, Any]:
    """Return installation and enforcement status for one protected site."""
    config = database.get_alibaba_autopilot_config(site_id)
    verified = bool(config and config.get("connection_status") == "verified")
    logs_connected = bool(
        config
        and verified
        and config.get("sls_endpoint")
        and config.get("sls_project")
        and config.get("sls_logstore")
    )
    security_group_connected = bool(
        config and verified and config.get("enforcement_mode") == "security_group" and config.get("security_group_id")
    )
    executions = database.list_remediation_executions(site_id, limit=10)
    failed = [item for item in executions if item["status"] == "failed"]
    enforcement_mode = "security_group" if security_group_connected else "observe_only"
    return {
        "site_id": site_id,
        "configured": bool(config),
        "connection_status": config.get("connection_status") if config else "not_connected",
        "logs_connected": logs_connected,
        "security_group_connected": security_group_connected,
        "autopilot_active": security_group_connected,
        "enforcement_mode": enforcement_mode,
        "available_actions": available_actions_for_mode(enforcement_mode),
        "config": public_config(config),
        "authorization": authorization_bundle(config) if config else None,
        "last_execution": executions[0] if executions else None,
        "failed_executions": failed,
    }


def discover_resources(site_id: str) -> dict[str, Any]:
    """Return Alibaba resources SecAi knows how to use for a site."""
    config = database.get_alibaba_autopilot_config(site_id)
    return {
        "site_id": site_id,
        "connected": bool(config),
        "logs": [
            item
            for item in [
                {
                    "type": "sls",
                    "endpoint": config.get("sls_endpoint") if config else None,
                    "project": config.get("sls_project") if config else None,
                    "logstore": config.get("sls_logstore") if config else None,
                    "source": "alibaba_autopilot",
                },
            ]
            if item["endpoint"] and item["project"] and item["logstore"]
        ],
        "security_groups": [
            {
                "type": "ecs_security_group",
                "security_group_id": config.get("security_group_id") if config else None,
                "region": config.get("region") if config else None,
                "enforcement_mode": config.get("enforcement_mode") if config else "observe_only",
            }
        ]
        if config and config.get("security_group_id")
        else [],
    }


def authorization_bundle(config: dict[str, Any]) -> dict[str, Any]:
    """Return the exact customer authorization material for this site connection."""
    provider_role_arn = get_settings().secai_alibaba_provider_role_arn
    if not provider_role_arn:
        raise AlibabaAutopilotNotConfigured(
            "SECAI_ALIBABA_PROVIDER_ROLE_ARN must identify SecAi's Control ECS RAM role."
        )
    alibaba_credentials.parse_role_arn(provider_role_arn)
    external_id = config["external_id"]
    trust_policy = {
        "Version": "1",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"RAM": [provider_role_arn]},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }
    permission_policy = {
        "Version": "1",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "log:ListProject",
                    "log:ListLogStores",
                    "log:GetLogStoreLogs",
                    "ecs:DescribeSecurityGroups",
                    "ecs:DescribeSecurityGroupAttribute",
                    "ecs:AuthorizeSecurityGroup",
                    "ecs:RevokeSecurityGroup",
                ],
                "Resource": ["*"],
            }
        ],
    }
    role_suffix = re.sub(r"[^A-Za-z0-9.-]", "-", str(config["site_id"]))
    role_name = f"secai-{role_suffix.lower()}"[:64]
    template = {
        "ROSTemplateFormatVersion": "2015-09-01",
        "Description": "Customer-managed role that lets SecAi inspect one website and apply owner-approved protection.",
        "Resources": {
            "SecAiWebsiteProtectionRole": {
                "Type": "ALIYUN::RAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "Description": "Temporary cross-account access for this SecAi website connection",
                    "AssumeRolePolicyDocument": trust_policy,
                    "Policies": [
                        {"PolicyName": "SecAiWebsiteProtection", "PolicyDocument": permission_policy}
                    ],
                    "MaxSessionDuration": 3600,
                },
            }
        },
        "Outputs": {
            "RoleArn": {
                "Description": "Paste this value back into SecAi",
                "Value": {"Fn::GetAtt": ["SecAiWebsiteProtectionRole", "Arn"]},
            }
        },
    }
    return {
        "provider_role_arn": provider_role_arn,
        "external_id": external_id,
        "role_name": role_name,
        "trust_policy": trust_policy,
        "permission_policy": permission_policy,
        "ros_template": template,
    }


def available_actions_for_site(site_id: str) -> list[str]:
    """Return actions the agent may recommend for a site's current install mode."""
    return available_actions_for_mode(site_status(site_id)["enforcement_mode"])


def available_actions_for_mode(enforcement_mode: str) -> list[str]:
    """Return execution-capable actions for an enforcement mode."""
    actions = ["monitor", "notify_admin"]
    if enforcement_mode == "security_group":
        actions.extend(sorted(SECURITY_GROUP_REMEDIATION_ACTIONS))
    return actions
