from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from dataclasses import replace
from threading import Lock
from typing import Any
from urllib.parse import quote, urlencode

from secai import database
from secai.database import encryption
from secai.settings import get_settings
from secai.models import REPORTING_ACTIONS, WAF_REMEDIATION_ACTIONS


class AlibabaAutopilotNotConfigured(Exception):
    """Raised when a site has not connected Alibaba Autopilot."""


class AlibabaAutopilotPrincipalNotConfigured(Exception):
    """Raised when SecAi cannot generate a valid customer-side trust policy."""


class AlibabaWafNotReady(Exception):
    """Raised when a site is not configured for WAF enforcement."""


class AlibabaWafExecutionError(Exception):
    """Raised when Alibaba WAF does not accept a remediation rule."""


@dataclass(frozen=True)
class AlibabaAutopilotConnection:
    """Per-site Alibaba Cloud connection used for no-code autopilot."""

    site_id: str
    role_arn: str
    external_id: str
    region: str
    enforcement_mode: str
    waf_instance_id: str | None = None
    waf_domain: str | None = None
    waf_template_id: int | None = None
    sls_endpoint: str | None = None
    sls_project: str | None = None
    sls_logstore: str | None = None


_credential_cache: dict[str, tuple[Any, float]] = {}
_credential_lock = Lock()
DEFAULT_CONNECTOR_ROLE_NAME = "secai-autopilot"
DEFAULT_WAF_TEMPLATE_NAME = "SecAi Autopilot"
DEFAULT_WAF_TEMPLATE_SCENE = "custom_acl"
ALIBABACLOUD_ROS_CONSOLE = "https://ros.console.alibabacloud.com"
ALIYUN_ROS_CONSOLE = "https://ros.console.aliyun.com"
logger = logging.getLogger(__name__)


def load_site_connection(site_id: str) -> AlibabaAutopilotConnection:
    """Load a site's saved Alibaba Autopilot connection."""
    config = database.get_alibaba_autopilot_config(site_id)
    if not config:
        raise AlibabaAutopilotNotConfigured(f"No Alibaba Autopilot connection saved for site {site_id}.")
    return AlibabaAutopilotConnection(
        site_id=site_id,
        role_arn=config["role_arn"],
        external_id=encryption.decrypt_secret(config["encrypted_external_id"]),
        region=config["region"],
        enforcement_mode=config["enforcement_mode"],
        waf_instance_id=config.get("waf_instance_id"),
        waf_domain=config.get("waf_domain"),
        waf_template_id=config.get("waf_template_id"),
        sls_endpoint=config.get("sls_endpoint"),
        sls_project=config.get("sls_project"),
        sls_logstore=config.get("sls_logstore"),
    )


def invalidate_cache(site_id: str) -> None:
    """Drop cached STS credentials for a site after Alibaba settings change."""
    with _credential_lock:
        _credential_cache.pop(site_id, None)


def public_config(config: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return Alibaba Autopilot config fields safe for the dashboard."""
    if not config:
        return None
    return {
        "site_id": config["site_id"],
        "role_arn": config["role_arn"],
        "external_id": encryption.mask_secret(encryption.decrypt_secret(config["encrypted_external_id"])),
        "region": config["region"],
        "waf_instance_id": config.get("waf_instance_id"),
        "waf_domain": config.get("waf_domain"),
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
    sls_config = database.get_sls_config(site_id)
    logs_connected = bool(
        sls_config
        or (
            config
            and config.get("sls_endpoint")
            and config.get("sls_project")
            and config.get("sls_logstore")
        )
    )
    waf_connected = bool(
        config
        and config.get("enforcement_mode") == "waf_enforced"
        and config.get("waf_instance_id")
    )
    executions = database.list_remediation_executions(site_id, limit=10)
    failed = [item for item in executions if item["status"] == "failed"]
    enforcement_mode = "waf_enforced" if waf_connected else "observe_only"
    return {
        "site_id": site_id,
        "configured": bool(config),
        "logs_connected": logs_connected,
        "waf_connected": waf_connected,
        "autopilot_active": waf_connected,
        "enforcement_mode": enforcement_mode,
        "available_actions": available_actions_for_mode(enforcement_mode),
        "config": public_config(config),
        "last_execution": executions[0] if executions else None,
        "failed_executions": failed,
    }


def discover_resources(site_id: str) -> dict[str, Any]:
    """Return Alibaba resources SecAi knows how to use for a site."""
    config = database.get_alibaba_autopilot_config(site_id)
    sls_config = database.get_sls_config(site_id)
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
                {
                    "type": "sls",
                    "endpoint": sls_config.get("endpoint") if sls_config else None,
                    "project": sls_config.get("project") if sls_config else None,
                    "logstore": sls_config.get("logstore") if sls_config else None,
                    "source": "alibaba_sls",
                },
            ]
            if item["endpoint"] and item["project"] and item["logstore"]
        ],
        "waf": [
            {
                "type": "waf",
                "instance_id": config.get("waf_instance_id") if config else None,
                "domain": config.get("waf_domain") if config else None,
                "region": config.get("region") if config else None,
                "enforcement_mode": config.get("enforcement_mode") if config else "observe_only",
            }
        ]
        if config and config.get("waf_instance_id")
        else [],
    }


def connector_template(
    external_id: str,
    region: str = "ap-southeast-1",
    role_name: str = DEFAULT_CONNECTOR_ROLE_NAME,
    waf_instance_id: str | None = None,
    sls_project: str | None = None,
    sls_logstore: str | None = None,
    sls_endpoint: str | None = None,
    template_url: str | None = None,
) -> dict[str, Any]:
    """Build the customer-side RAM role template for Alibaba Autopilot."""
    settings = get_settings()
    principal = settings.secai_alibaba_principal_arn
    if not principal and settings.secai_alibaba_account_id:
        principal = f"acs:ram::{settings.secai_alibaba_account_id}:root"
    principal_configured = bool(principal)
    if not principal_configured:
        raise AlibabaAutopilotPrincipalNotConfigured(
            "SECAI_ALIBABA_ACCOUNT_ID or SECAI_ALIBABA_PRINCIPAL_ARN must be configured before generating the Alibaba ROS connector template."
        )
    trust_policy = _connector_trust_policy(principal, external_id)
    waf_instance_id = (waf_instance_id or "").strip()
    sls_project = (sls_project or "").strip()
    sls_logstore = (sls_logstore or "").strip()
    sls_endpoint = (sls_endpoint or "").strip()
    if (sls_project or sls_logstore) and not sls_endpoint:
        sls_endpoint = f"{region}.log.aliyuncs.com"
    include_waf = True
    include_sls = bool(sls_project and sls_logstore)
    permission_policy = _connector_permission_policy(include_waf=include_waf, include_sls=include_sls)
    parameters: dict[str, Any] = {
        "RoleName": {
            "Type": "String",
            "Default": role_name,
            "Description": "RAM role name created for SecAi Autopilot.",
        },
        "ExternalId": {
            "Type": "String",
            "Default": external_id,
            "Description": "External ID generated by SecAi for this site connection.",
        },
    }
    outputs: dict[str, Any] = {
        "RoleArn": {
            "Description": "Paste this RAM Role ARN into SecAi.",
            "Value": {"Fn::GetAtt": ["SecAiAutopilotRole", "Arn"]},
        },
        "ExternalId": {
            "Description": "External ID SecAi will use for STS AssumeRole.",
            "Value": {"Ref": "ExternalId"},
        },
    }
    if include_waf:
        parameters["WafInstanceId"] = {
            "Type": "String",
            "Default": waf_instance_id,
            "Description": "WAF instance ID for the site SecAi will protect. SecAi creates its own defense template inside this instance.",
        }
        outputs["WafInstanceId"] = {
            "Description": "Paste this WAF Instance ID into SecAi. SecAi creates the defense template automatically.",
            "Value": {"Ref": "WafInstanceId"},
        }
    if include_sls:
        parameters["SlsProject"] = {
            "Type": "String",
            "Default": sls_project,
            "Description": "Log Service project that contains request logs for this site.",
        }
        parameters["SlsLogstore"] = {
            "Type": "String",
            "Default": sls_logstore,
            "Description": "Logstore inside the Log Service project.",
        }
        parameters["SlsEndpoint"] = {
            "Type": "String",
            "Default": sls_endpoint,
            "Description": "Log Service endpoint for the project region.",
        }
        outputs["SlsEndpoint"] = {
            "Description": "Paste this Log Service endpoint into SecAi.",
            "Value": {"Ref": "SlsEndpoint"},
        }
        outputs["SlsProject"] = {
            "Description": "Paste this Log Service project into SecAi.",
            "Value": {"Ref": "SlsProject"},
        }
        outputs["SlsLogstore"] = {
            "Description": "Paste this Log Service logstore into SecAi.",
            "Value": {"Ref": "SlsLogstore"},
        }
    template = {
        "ROSTemplateFormatVersion": "2015-09-01",
        "Description": "Creates a RAM role that lets SecAi Autopilot read Log Service evidence and manage SecAi-owned Alibaba WAF rules without permanent AccessKeys.",
        "Parameters": parameters,
        "Resources": {
            "SecAiAutopilotRole": {
                "Type": "ALIYUN::RAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleName"},
                    "Description": "Scoped role for SecAi Autopilot. Uses STS AssumeRole with an external ID; no permanent customer AccessKeys are shared.",
                    "AssumeRolePolicyDocument": trust_policy,
                    "Policies": [
                        {
                            "PolicyName": "SecAiAutopilotPolicy",
                            "PolicyDocument": permission_policy,
                        }
                    ],
                },
            }
        },
        "Outputs": outputs,
    }
    alibabacloud_console = f"{ALIBABACLOUD_ROS_CONSOLE}/overview"
    aliyun_console = f"{ALIYUN_ROS_CONSOLE}/overview"
    quick_create_url = ros_quick_create_url(region, template_url) if template_url else alibabacloud_console
    return {
        "external_id": external_id,
        "role_name": role_name,
        "role_arn_hint": f"acs:ram::<your-alibaba-account-id>:role/{role_name}",
        "waf_instance_id": waf_instance_id,
        "sls_endpoint": sls_endpoint,
        "sls_project": sls_project,
        "sls_logstore": sls_logstore,
        "region": region,
        "console_url": quick_create_url,
        "quick_create_url": quick_create_url,
        "template_url": template_url or "",
        "console_url_aliyun": aliyun_console,
        "console_url_alibabacloud": alibabacloud_console,
        "principal": principal,
        "principal_configured": principal_configured,
        "trust_policy": trust_policy,
        "permission_policy": permission_policy,
        "template": template,
    }


def ros_quick_create_url(region: str, template_url: str, page_title: str = "SecAi Autopilot RAM Connector") -> str:
    """Build the international ROS console quick-create URL for a hosted template."""
    region = (region or "ap-southeast-1").strip()
    params = urlencode(
        {
            "templateType": "Example",
            "templateUrl": template_url,
            "pageTitle": page_title,
            "hideStepRow": "true",
            "hideStackConfig": "true",
            "isSimplified": "true",
            "balanceIntercept": "true",
        },
    )
    return f"{ALIBABACLOUD_ROS_CONSOLE}/{quote(region, safe='')}/templates/public/createStack?{params}"


def _connector_trust_policy(principal: str, external_id: str) -> dict[str, Any]:
    return {
        "Version": "1",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"RAM": [principal]},
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }


def _connector_permission_policy(*, include_waf: bool = True, include_sls: bool = False) -> dict[str, Any]:
    statements: list[dict[str, Any]] = []
    if include_sls:
        statements.append(
            {
                "Effect": "Allow",
                "Action": [
                    "log:GetProject",
                    "log:GetLogStore",
                    "log:GetLogs",
                    "log:GetHistograms",
                    "log:ListLogStores",
                ],
                "Resource": [
                    {"Fn::Sub": "acs:log:*:${ALIYUN::AccountId}:project/${SlsProject}"},
                    {"Fn::Sub": "acs:log:*:${ALIYUN::AccountId}:project/${SlsProject}/logstore/${SlsLogstore}"},
                ],
            }
        )
    if include_waf:
        statements.append(
            {
                "Effect": "Allow",
                "Action": [
                    "yundun-waf:CreateDefenseTemplate",
                    "yundun-waf:CreateDefenseRule",
                    "yundun-waf:DeleteDefenseRule",
                    "yundun-waf:DescribeDefenseRule",
                    "yundun-waf:DescribeDefenseRules",
                    "yundun-waf:DescribeDefenseTemplate",
                    "yundun-waf:DescribeDefenseTemplates",
                    "yundun-waf:DescribeInstance",
                    "yundun-waf:DescribeDomains",
                    "yundun-waf:DescribeDomainDetail",
                ],
                "Resource": ["*"],
            }
        )
    return {"Version": "1", "Statement": statements}


def available_actions_for_site(site_id: str, profile_actions: list[str] | None = None) -> list[str]:
    """Return actions the agent may recommend for a site's current install mode."""
    status = site_status(site_id)
    available = available_actions_for_mode(status["enforcement_mode"])
    if profile_actions is None:
        return available
    return [action for action in profile_actions if action in available]


def available_actions_for_mode(enforcement_mode: str) -> list[str]:
    """Return execution-capable actions for an enforcement mode."""
    actions = ["monitor", "notify_admin"]
    if enforcement_mode == "waf_enforced":
        actions.extend(sorted(WAF_REMEDIATION_ACTIONS))
    return actions


def policy_parameters_for_action(action: dict[str, Any], incident: dict[str, Any]) -> dict[str, Any]:
    """Build provider-neutral policy parameters from an incident recommendation."""
    target = action.get("target") or ""
    affected_route = incident.get("affected_route")
    params: dict[str, Any] = {
        "duration_seconds": int(action.get("duration_seconds") or 3600),
        "rollback": "Disable or delete the SecAi-managed WAF rule.",
    }
    if affected_route:
        params["route"] = affected_route
    if target.startswith("/"):
        params["route"] = target
    if action.get("action") in {"block_payload_pattern", "virtual_patch"}:
        params["pattern"] = target or incident.get("attack_type") or "suspicious input"
    return params


def get_or_create_defense_template(site_id: str) -> int:
    """Return SecAi's managed WAF defense template ID, creating it when needed."""
    config = database.get_alibaba_autopilot_config(site_id)
    if not config:
        raise AlibabaAutopilotNotConfigured(f"No Alibaba Autopilot connection saved for site {site_id}.")
    if config.get("waf_template_id"):
        return int(config["waf_template_id"])

    connection = load_site_connection(site_id)
    if not connection.waf_instance_id:
        raise AlibabaWafNotReady("Alibaba WAF instance ID is required before SecAi can create its managed template.")

    client = _waf_client(connection)
    existing_template_id = _find_managed_defense_template(client, connection)
    if existing_template_id:
        database.save_alibaba_waf_template_id(site_id, existing_template_id)
        return existing_template_id

    request = {
        "InstanceId": connection.waf_instance_id,
        "DefenseScene": DEFAULT_WAF_TEMPLATE_SCENE,
        "TemplateName": DEFAULT_WAF_TEMPLATE_NAME,
        "TemplateOrigin": "custom",
        "TemplateStatus": 1,
        "TemplateType": "user_custom",
        "Description": "Managed by SecAi Autopilot. Rules are added and removed automatically.",
        "RegionId": connection.region,
    }
    response = client.create_defense_template(request)
    template_id = _extract_template_id(response)
    if not template_id:
        raise AlibabaWafExecutionError("Alibaba WAF did not return a template ID for the managed defense template.")
    database.save_alibaba_waf_template_id(site_id, template_id)
    logger.info("Created Alibaba WAF defense template %s for site %s", template_id, site_id)
    return template_id


def _find_managed_defense_template(client: Any, connection: AlibabaAutopilotConnection) -> int | None:
    """Find the existing SecAi-managed custom ACL template, if one exists."""
    response = client.describe_defense_templates(
        {
            "InstanceId": connection.waf_instance_id,
            "DefenseScene": DEFAULT_WAF_TEMPLATE_SCENE,
            "TemplateName": DEFAULT_WAF_TEMPLATE_NAME,
            "TemplateType": "user_custom",
            "PageNumber": 1,
            "PageSize": 50,
            "RegionId": connection.region,
        }
    )
    for template in response.get("Templates") or response.get("templates") or []:
        if not isinstance(template, dict):
            continue
        name = template.get("TemplateName") or template.get("template_name")
        scene = template.get("DefenseScene") or template.get("defense_scene")
        template_id = template.get("TemplateId") or template.get("template_id")
        if name == DEFAULT_WAF_TEMPLATE_NAME and scene == DEFAULT_WAF_TEMPLATE_SCENE and template_id:
            return int(template_id)
    return None


def apply_policy(site_id: str, policy: dict[str, Any], incident: dict[str, Any]) -> dict[str, Any]:
    """Create the Alibaba WAF rule for one approved SecAi policy."""
    connection = load_site_connection(site_id)
    if connection.enforcement_mode != "waf_enforced":
        raise AlibabaWafNotReady("Alibaba Autopilot is connected in observe-only mode; WAF enforcement is not enabled.")
    if not connection.waf_instance_id:
        raise AlibabaWafNotReady("Alibaba WAF instance ID is required before SecAi can enforce remediation.")
    if policy["action"] not in WAF_REMEDIATION_ACTIONS:
        raise AlibabaWafNotReady(f"Action {policy['action']} is not executable through Alibaba WAF.")
    connection = replace(connection, waf_template_id=get_or_create_defense_template(site_id))

    request = build_waf_rule_request(connection, policy, incident)
    response = _waf_client(connection).create_defense_rule(request)
    provider_rule_id = _extract_provider_rule_id(response)
    if not provider_rule_id:
        raise AlibabaWafExecutionError("Alibaba WAF did not return a rule ID for the created defense rule.")
    return {
        "provider": "alibaba_waf",
        "provider_rule_id": provider_rule_id,
        "request": request,
        "response": response,
    }


def delete_policy(site_id: str, policy: dict[str, Any]) -> dict[str, Any]:
    """Delete the Alibaba WAF rule created for one SecAi policy."""
    connection = load_site_connection(site_id)
    if connection.enforcement_mode != "waf_enforced":
        raise AlibabaWafNotReady("Alibaba Autopilot is connected in observe-only mode; WAF enforcement is not enabled.")
    if not connection.waf_instance_id:
        raise AlibabaWafNotReady("Alibaba WAF instance ID is required before SecAi can remove remediation.")
    if policy.get("provider") != "alibaba_waf" or not policy.get("provider_rule_id"):
        raise AlibabaWafNotReady("This policy does not have an Alibaba WAF rule ID to remove.")
    connection = replace(connection, waf_template_id=get_or_create_defense_template(site_id))
    request = {
        "InstanceId": connection.waf_instance_id,
        "TemplateId": connection.waf_template_id,
        "DefenseScene": _defense_scene_for_action(policy["action"]),
        "RuleId": policy["provider_rule_id"],
        "DefenseType": "template",
        "RegionId": connection.region,
    }
    response = _waf_client(connection).delete_defense_rule(request)
    return {"provider": "alibaba_waf", "provider_rule_id": policy["provider_rule_id"], "request": request, "response": response}


def build_waf_rule_request(
    connection: AlibabaAutopilotConnection,
    policy: dict[str, Any],
    incident: dict[str, Any],
) -> dict[str, Any]:
    """Translate a SecAi remediation policy into an Alibaba WAF CreateDefenseRule request."""
    rule_name = _rule_name(policy)
    action = policy["action"]
    target = policy.get("target") or incident.get("affected_route") or "/"
    params = policy.get("parameters") or {}
    route = params.get("route") or incident.get("affected_route") or target
    ttl = int(params.get("duration_seconds") or 3600)

    if action == "enable_anti_scan":
        defense_scene = _defense_scene_for_action(action)
        rule = {
            "name": rule_name,
            "protectionType": "highfreq",
            "action": "block",
            "status": 1,
            "config": json.dumps({"target": "remote_addr", "interval": 60, "ttl": ttl, "count": 20}),
        }
    else:
        defense_scene = _defense_scene_for_action(action)
        rule = _custom_acl_rule(action, rule_name, target, str(route or "/"), ttl, params)

    return {
        "InstanceId": connection.waf_instance_id,
        "TemplateId": connection.waf_template_id,
        "DefenseScene": defense_scene,
        "Rules": json.dumps([rule], separators=(",", ":")),
        "DefenseType": "template",
        "RegionId": connection.region,
    }


def _custom_acl_rule(action: str, rule_name: str, target: str, route: str, ttl: int, params: dict[str, Any]) -> dict[str, Any]:
    """Build an Alibaba WAF custom ACL rule."""
    conditions: list[dict[str, str]] = []
    waf_action = "block"
    cc_status = 0
    ratelimit = None

    if action in {"block_ip", "block_ip_range"}:
        conditions.append({"key": "IP", "opValue": "eq", "values": target})
    elif action == "rate_limit_ip":
        conditions.append({"key": "IP", "opValue": "eq", "values": target})
        cc_status = 1
        ratelimit = {"target": "remote_addr", "interval": 60, "threshold": 60, "ttl": ttl}
    elif action == "rate_limit_route":
        conditions.append(_url_condition(route))
        cc_status = 1
        ratelimit = {"target": "remote_addr", "interval": 60, "threshold": 120, "ttl": ttl}
    elif action == "read_only_route":
        conditions.extend([_url_condition(route), {"key": "Http-Method", "opValue": "regex", "values": "POST|PUT|PATCH|DELETE"}])
    elif action == "challenge_route":
        conditions.append(_url_condition(route))
        waf_action = "js"
    elif action == "disable_route":
        conditions.append(_url_condition(route))
    elif action in {"block_payload_pattern", "virtual_patch"}:
        conditions.append({"key": "All-Data", "opValue": "regex", "values": str(params.get("pattern") or target)})
        if route and route.startswith("/"):
            conditions.append(_url_condition(route))
    else:
        conditions.append(_url_condition(route))

    rule: dict[str, Any] = {
        "name": rule_name,
        "action": waf_action,
        "conditions": conditions[:5],
        "ccStatus": cc_status,
        "status": 1,
        "origin": "custom",
    }
    if ratelimit:
        rule["ratelimit"] = ratelimit
        rule["effect"] = "rule"
    return rule


def _defense_scene_for_action(action: str) -> str:
    if action == "enable_anti_scan":
        return "antiscan"
    return "custom_acl"


def _url_condition(route: str) -> dict[str, str]:
    return {"key": "URL", "opValue": "contain", "values": route or "/"}


def _rule_name(policy: dict[str, Any]) -> str:
    raw = f"secai-{policy.get('incident_id') or policy['id']}-{policy['action']}"
    return "".join(character if character.isalnum() or character in "._-" else "-" for character in raw)[:80]


def _extract_provider_rule_id(response: dict[str, Any]) -> str | None:
    for key in ("rule_id", "ruleId", "RuleId"):
        if response.get(key):
            return str(response[key])
    for key in ("rule_ids", "ruleIds", "RuleIds"):
        values = response.get(key)
        if isinstance(values, list) and values:
            return str(values[0])
        if isinstance(values, str) and values:
            return values.split(",")[0]
    if response.get("request_id"):
        return str(response["request_id"])
    return None


def _extract_template_id(response: dict[str, Any]) -> int | None:
    for key in ("template_id", "templateId", "TemplateId"):
        if response.get(key):
            return int(response[key])
    return None


def get_temp_credentials(conn: AlibabaAutopilotConnection, duration_seconds: int = 3600):
    """Return cached STS credentials for a customer Alibaba Autopilot connection."""
    with _credential_lock:
        cached = _credential_cache.get(conn.site_id)
        if cached and cached[1] - 60 > time.time():
            return cached[0]

        client = _sts_client()
        request = _assume_role_request(
            role_arn=conn.role_arn,
            role_session_name=f"secai-autopilot-{conn.site_id}",
            external_id=conn.external_id,
            duration_seconds=duration_seconds,
        )
        response = client.assume_role(request)
        credentials = response.body.credentials
        _credential_cache[conn.site_id] = (credentials, time.time() + duration_seconds)
        return credentials


def _assume_role_request(role_arn: str, role_session_name: str, external_id: str, duration_seconds: int):
    """Build an Alibaba STS AssumeRole request."""
    try:
        from alibabacloud_sts20150401 import models as sts_models
    except ModuleNotFoundError as exc:
        raise RuntimeError("Install alibabacloud_sts20150401 to use Alibaba RAM role connections.") from exc
    return sts_models.AssumeRoleRequest(
        role_arn=role_arn,
        role_session_name=role_session_name,
        external_id=external_id,
        duration_seconds=duration_seconds,
    )


def _sts_client():
    """Return a Tea OpenAPI STS client using SecAi deployment credentials."""
    settings = get_settings()
    try:
        from alibabacloud_sts20150401.client import Client as StsClient
        from alibabacloud_tea_openapi.models import Config as OpenApiConfig
        from alibabacloud_credentials.client import Client as CredentialClient
    except ModuleNotFoundError as exc:
        raise RuntimeError("Install alibabacloud_credentials, alibabacloud_tea_openapi, and alibabacloud_sts20150401 to use Alibaba RAM role connections.") from exc

    if settings.app_ram_user_ak_id and settings.app_ram_user_ak_secret:
        return StsClient(
            OpenApiConfig(
                access_key_id=settings.app_ram_user_ak_id,
                access_key_secret=settings.app_ram_user_ak_secret,
                endpoint=settings.alibaba_sts_endpoint,
            )
        )

    return StsClient(
        OpenApiConfig(
            credential=CredentialClient(),
            endpoint=settings.alibaba_sts_endpoint,
        )
    )


def _waf_client(conn: AlibabaAutopilotConnection):
    return AlibabaWafOpenApiClient(conn)


class AlibabaWafOpenApiClient:
    """Small wrapper around Alibaba WAF 3.0 CreateDefenseRule."""

    def __init__(self, conn: AlibabaAutopilotConnection):
        self.conn = conn

    def create_defense_template(self, request: dict[str, Any]) -> dict[str, Any]:
        client, waf_models = self._sdk_client()
        model = waf_models.CreateDefenseTemplateRequest(
            instance_id=request["InstanceId"],
            defense_scene=request["DefenseScene"],
            template_name=request["TemplateName"],
            template_origin=request["TemplateOrigin"],
            template_status=request["TemplateStatus"],
            template_type=request["TemplateType"],
            description=request.get("Description"),
            region_id=request.get("RegionId"),
        )
        response = client.create_defense_template(model)
        body = getattr(response, "body", response)
        return _object_to_dict(body)

    def describe_defense_templates(self, request: dict[str, Any]) -> dict[str, Any]:
        client, waf_models = self._sdk_client()
        model = waf_models.DescribeDefenseTemplatesRequest(
            instance_id=request["InstanceId"],
            defense_scene=request.get("DefenseScene"),
            template_name=request.get("TemplateName"),
            template_type=request.get("TemplateType"),
            page_number=request.get("PageNumber"),
            page_size=request.get("PageSize"),
            region_id=request.get("RegionId"),
        )
        response = client.describe_defense_templates(model)
        body = getattr(response, "body", response)
        return _object_to_dict(body)

    def create_defense_rule(self, request: dict[str, Any]) -> dict[str, Any]:
        client, waf_models = self._sdk_client()
        model = waf_models.CreateDefenseRuleRequest(
            instance_id=request["InstanceId"],
            template_id=request.get("TemplateId"),
            defense_scene=request["DefenseScene"],
            rules=request["Rules"],
            defense_type=request.get("DefenseType"),
            region_id=request.get("RegionId"),
        )
        response = client.create_defense_rule(model)
        body = getattr(response, "body", response)
        return _object_to_dict(body)

    def delete_defense_rule(self, request: dict[str, Any]) -> dict[str, Any]:
        client, waf_models = self._sdk_client()
        model = waf_models.DeleteDefenseRuleRequest(
            instance_id=request["InstanceId"],
            template_id=request.get("TemplateId"),
            defense_scene=request["DefenseScene"],
            rule_id=request["RuleId"],
            defense_type=request.get("DefenseType"),
            region_id=request.get("RegionId"),
        )
        response = client.delete_defense_rule(model)
        body = getattr(response, "body", response)
        return _object_to_dict(body)

    def _sdk_client(self):
        credentials = get_temp_credentials(self.conn)
        settings = get_settings()
        endpoint = settings.alibaba_waf_endpoint or f"wafopenapi.{self.conn.region}.aliyuncs.com"
        try:
            from alibabacloud_tea_openapi.models import Config as OpenApiConfig
            from alibabacloud_waf_openapi20211001 import models as waf_models
            from alibabacloud_waf_openapi20211001.client import Client as WafClient
        except ModuleNotFoundError as exc:
            raise RuntimeError("Install alibabacloud-waf-openapi20211001 to use Alibaba WAF remediation.") from exc

        client = WafClient(
            OpenApiConfig(
                access_key_id=credentials.access_key_id,
                access_key_secret=credentials.access_key_secret,
                security_token=credentials.security_token,
                endpoint=endpoint,
            )
        )
        return client, waf_models


def _object_to_dict(value: Any) -> dict[str, Any]:
    """Return SDK objects as plain dictionaries."""
    if isinstance(value, dict):
        return value
    if hasattr(value, "to_map"):
        mapped = value.to_map()
        return mapped if isinstance(mapped, dict) else {"value": mapped}
    result = {}
    for key in ("request_id", "rule_id", "rule_ids", "RequestId", "RuleId", "RuleIds"):
        if hasattr(value, key):
            result[key] = getattr(value, key)
    return result
