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
    ecs_instance_id: str | None = None
    collector_machine_group: str | None = None
    collector_config_name: str | None = None


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
        ecs_instance_id=config.get("ecs_instance_id"),
        collector_machine_group=config.get("collector_machine_group"),
        collector_config_name=config.get("collector_config_name"),
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
        "ecs_instance_id": config.get("ecs_instance_id"),
        "collector_status": config.get("collector_status", "not_configured"),
        "collector_error": config.get("collector_error"),
        "collector_machine_group": config.get("collector_machine_group"),
        "collector_config_name": config.get("collector_config_name"),
        "collector_create_index": bool(config.get("collector_create_index")),
        "collector_verified_at": config.get("collector_verified_at"),
        "enforcement_mode": config["enforcement_mode"],
        "created_at": config["created_at"],
        "updated_at": config["updated_at"],
    }


def site_status(site_id: str) -> dict[str, Any]:
    """Return installation and enforcement status for one protected site."""
    config = database.get_alibaba_autopilot_config(site_id)
    verified = bool(config and config.get("connection_status") == "verified")
    collector_connected = bool(config and config.get("collector_status") == "verified")
    logs_connected = bool(
        config
        and verified
        and collector_connected
        and config.get("sls_endpoint")
        and config.get("sls_project")
        and config.get("sls_logstore")
    )
    security_group_connected = bool(
        config and verified and config.get("enforcement_mode") == "security_group" and config.get("security_group_id")
    )
    executions = database.list_remediation_executions(site_id, limit=10)
    failed = [item for item in executions if item["status"] == "failed"]
    autopilot_active = bool(logs_connected and security_group_connected)
    enforcement_mode = "security_group" if autopilot_active else "observe_only"
    return {
        "site_id": site_id,
        "configured": bool(config),
        "connection_status": config.get("connection_status") if config else "not_connected",
        "collector_status": config.get("collector_status", "not_configured") if config else "not_configured",
        "collector_connected": collector_connected,
        "logs_connected": logs_connected,
        "security_group_connected": security_group_connected,
        "autopilot_active": autopilot_active,
        "enforcement_mode": enforcement_mode,
        "available_actions": available_actions_for_mode(enforcement_mode),
        "config": public_config(config),
        "authorization": authorization_bundle(config) if config else None,
        "collector_setup": collector_bundle(config) if config and _collector_plan_complete(config) else None,
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
        "collector": {
            "instance_id": config.get("ecs_instance_id"),
            "machine_group": config.get("collector_machine_group"),
            "config_name": config.get("collector_config_name"),
            "status": config.get("collector_status", "not_configured"),
        }
        if config and config.get("ecs_instance_id")
        else None,
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
                    "ecs:DescribeInstances",
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
    template: dict[str, Any] = {
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


def collector_resource_names(site_id: str) -> dict[str, str]:
    """Return stable provider resource names for one website collector."""
    suffix = re.sub(r"[^a-z0-9_-]", "-", site_id.lower()).strip("-_") or "website"
    suffix = suffix[:80].rstrip("-_")
    return {
        "machine_group": f"secai-{suffix}-machines"[:128].rstrip("-_"),
        "config_name": f"secai-{suffix}-docker"[:128].rstrip("-_"),
        "user_defined_id": f"secai-{suffix}"[:128].rstrip("-_"),
        "container_name": f"secai-loongcollector-{suffix}"[:128].rstrip("-_"),
    }


def collector_bundle(config: dict[str, Any]) -> dict[str, Any]:
    """Generate the exact ROS stack that installs and wires one website collector."""
    if not _collector_plan_complete(config):
        raise AlibabaAutopilotNotConfigured("Choose a website server and Log Service source first.")
    names = collector_resource_names(str(config["site_id"]))
    region = str(config["region"])
    account_id = str(config["account_id"])
    project = str(config["sls_project"])
    logstore = str(config["sls_logstore"])
    instance_id = str(config["ecs_instance_id"])
    image = (
        f"aliyun-observability-release-registry.{region}.cr.aliyuncs.com/"
        "loongcollector/loongcollector:v3.3.3.0-f44ebb3-aliyun"
    )
    create_index = bool(config.get("collector_create_index"))
    install_script = f"""#!/bin/sh
set -eu
command -v docker >/dev/null 2>&1 || {{ echo 'Docker is required on this ECS server.' >&2; exit 1; }}
test -S /var/run/docker.sock || {{ echo 'Docker is not running on this ECS server.' >&2; exit 1; }}
docker pull {image}
docker rm -f {names['container_name']} >/dev/null 2>&1 || true
docker run -d --name {names['container_name']} --restart unless-stopped \
  -v /:/logtail_host:ro \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e ALIYUN_LOGTAIL_CONFIG=/etc/ilogtail/conf/{region}/ilogtail_config.json \
  -e ALIYUN_LOGTAIL_USER_ID={account_id} \
  -e ALIYUN_LOGTAIL_USER_DEFINED_ID={names['user_defined_id']} \
  {image}
docker ps --filter name=^{names['container_name']}$ --filter status=running --format '{{{{.Names}}}}' | grep -Fx {names['container_name']}
"""
    template: dict[str, Any] = {
        "ROSTemplateFormatVersion": "2015-09-01",
        "Description": (
            "Install SecAi's Alibaba LoongCollector on one approved ECS server and send only "
            "containers labelled secai.service=storefront to the selected Logstore. "
            + ("Create the Logstore index because none exists." if create_index else "Keep the Logstore's existing index.")
        ),
        "Resources": {
            "SecAiLogIndex": {
                "Type": "ALIYUN::SLS::Index",
                "DeletionPolicy": "Retain",
                "Properties": {
                    "ProjectName": project,
                    "LogstoreName": logstore,
                    "FullTextIndex": {
                        "Enable": True,
                        "CaseSensitive": False,
                        "IncludeChinese": False,
                        "Delimiter": ",'\";=()[]{}?@&<>/:\\n\\t\\r ",
                    },
                    "KeyIndices": [
                        {
                            "Name": "content",
                            "Type": "text",
                            "EnableAnalytics": True,
                            "CaseSensitive": False,
                            "IncludeChinese": False,
                            "Delimiter": ",'\";=()[]{}?@&<>/:\\n\\t\\r ",
                        },
                        {"Name": "status", "Type": "long", "EnableAnalytics": True},
                        {"Name": "status_code", "Type": "long", "EnableAnalytics": True},
                        {"Name": "ip", "Type": "text", "EnableAnalytics": True},
                        {"Name": "client_ip", "Type": "text", "EnableAnalytics": True},
                        {"Name": "remote_addr", "Type": "text", "EnableAnalytics": True},
                        {"Name": "method", "Type": "text", "EnableAnalytics": True},
                        {"Name": "path", "Type": "text", "EnableAnalytics": True},
                        {"Name": "query", "Type": "text", "EnableAnalytics": True},
                        {"Name": "user_agent", "Type": "text", "EnableAnalytics": True},
                        {"Name": "http_user_agent", "Type": "text", "EnableAnalytics": True},
                        {"Name": "message", "Type": "text", "EnableAnalytics": True},
                        {"Name": "timestamp", "Type": "text", "EnableAnalytics": True},
                    ],
                },
            },
            "SecAiMachineGroup": {
                "Type": "ALIYUN::SLS::MachineGroup",
                "Properties": {
                    "ProjectName": project,
                    "GroupName": names["machine_group"],
                    "MachineIdentifyType": "userdefined",
                    "MachineList": [names["user_defined_id"]],
                },
            },
            "InstallLoongCollector": {
                "Type": "ALIYUN::ECS::RunCommand",
                "DependsOn": "SecAiMachineGroup",
                "Properties": {
                    "Name": f"secai-install-{config['site_id']}"[:128],
                    "Description": "Install the Alibaba LoongCollector approved for this SecAi website.",
                    "Type": "RunShellScript",
                    "ContentEncoding": "PlainText",
                    "CommandContent": install_script,
                    "InstanceIds": [instance_id],
                    "Timeout": 600,
                    "Sync": True,
                    "KeepCommand": False,
                },
            },
            "SecAiDockerCollection": {
                "Type": "ALIYUN::SLS::LogtailConfig",
                "DependsOn": ["InstallLoongCollector", "SecAiLogIndex"],
                "Properties": {
                    "ProjectName": project,
                    "LogstoreName": logstore,
                    "LogtailConfigName": names["config_name"],
                    "RawConfigData": {
                        "configName": names["config_name"],
                        "inputType": "plugin",
                        "inputDetail": {
                            "plugin": {
                                "inputs": [
                                    {
                                        "type": "service_docker_stdout",
                                        "detail": {
                                            "IncludeLabel": {"secai.service": "storefront"},
                                            "Stdout": True,
                                            "Stderr": False,
                                        },
                                    }
                                ]
                            }
                        },
                    },
                },
            },
            "ApplySecAiCollection": {
                "Type": "ALIYUN::SLS::ApplyConfigToMachineGroup",
                "DependsOn": ["SecAiMachineGroup", "SecAiDockerCollection"],
                "Properties": {
                    "ProjectName": project,
                    "ConfigName": names["config_name"],
                    "GroupName": names["machine_group"],
                },
            },
        },
        "Outputs": {
            "EcsInstanceId": {"Description": "Approved website server", "Value": instance_id},
            "MachineGroup": {"Description": "SecAi collector machine group", "Value": names["machine_group"]},
            "CollectionConfig": {"Description": "SecAi Docker collection", "Value": names["config_name"]},
            "CollectorInvocationId": {
                "Description": "Cloud Assistant installation invocation",
                "Value": {"Fn::GetAtt": ["InstallLoongCollector", "InvokeId"]},
            },
        },
    }
    if not create_index:
        template["Resources"].pop("SecAiLogIndex")
        template["Resources"]["SecAiDockerCollection"]["DependsOn"] = ["InstallLoongCollector"]
    return {
        "status": config.get("collector_status", "pending"),
        "error": config.get("collector_error"),
        "instance_id": instance_id,
        "machine_group": names["machine_group"],
        "config_name": names["config_name"],
        "ros_template": template,
    }


def _collector_plan_complete(config: dict[str, Any]) -> bool:
    return bool(
        config.get("connection_status") == "verified"
        and config.get("account_id")
        and config.get("region")
        and config.get("ecs_instance_id")
        and config.get("sls_project")
        and config.get("sls_logstore")
    )


def available_actions_for_site(site_id: str) -> list[str]:
    """Return actions the agent may recommend for a site's current install mode."""
    return available_actions_for_mode(site_status(site_id)["enforcement_mode"])


def available_actions_for_mode(enforcement_mode: str) -> list[str]:
    """Return execution-capable actions for an enforcement mode."""
    actions = ["collect_follow_up_cloud_evidence", "send_owner_alert"]
    if enforcement_mode == "security_group":
        actions.extend(sorted(SECURITY_GROUP_REMEDIATION_ACTIONS))
    return actions
