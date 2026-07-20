from __future__ import annotations

import json
import logging
import time
from typing import Any

from secai.integrations import alibaba_coordinates, alibaba_credentials
from secai.integrations.alibaba_autopilot import AlibabaAutopilotConnection

logger = logging.getLogger(__name__)


class AlibabaResourceDiscoveryError(RuntimeError):
    """Raised when SecAi cannot inspect resources through a customer connection."""


def discover(connection: AlibabaAutopilotConnection, region: str | None = None) -> dict[str, Any]:
    """Discover resources using only this website's temporary customer role."""
    try:
        region = alibaba_coordinates.normalize_region(region or connection.region)
    except ValueError as exc:
        raise AlibabaResourceDiscoveryError(str(exc)) from exc
    endpoint = alibaba_coordinates.sls_endpoint_for_region(region)
    warnings: list[str] = []
    try:
        log_sources = _discover_log_sources(endpoint, connection)
    except Exception as exc:
        logger.warning("Alibaba Log Service discovery failed for %s", region, exc_info=exc)
        log_sources = []
        warnings.append("SecAi could not read website activity resources in this region.")
    try:
        security_groups = _discover_security_groups(region, connection)
    except Exception as exc:
        logger.warning("Alibaba ECS security-group discovery failed for %s", region, exc_info=exc)
        security_groups = []
        warnings.append("SecAi could not check whether approved protection is available in this region.")
    try:
        instances = _discover_instances(region, connection)
    except Exception as exc:
        logger.warning("Alibaba ECS instance discovery failed for %s", region, exc_info=exc)
        instances = []
        warnings.append("SecAi could not check the website servers in this region.")
    if not log_sources and not security_groups and not instances and warnings:
        raise AlibabaResourceDiscoveryError(
            "Alibaba Cloud authorized the connection, but no usable resources could be read."
        )
    return {
        "region": region,
        "sls_endpoint": endpoint,
        "log_sources": log_sources,
        "security_groups": security_groups,
        "instances": instances,
        "warnings": warnings,
    }


def logstore_has_index(connection: AlibabaAutopilotConnection) -> bool:
    """Return whether the selected Logstore already has a SecAi-compatible index."""
    if not connection.sls_endpoint or not connection.sls_project or not connection.sls_logstore:
        raise AlibabaResourceDiscoveryError("Choose one Log Service source before preparing its collector.")
    try:
        from aliyun.log import GetLogsRequest, LogClient
    except ModuleNotFoundError as exc:
        raise AlibabaResourceDiscoveryError("The Alibaba Log Service SDK is not installed.") from exc
    credential = alibaba_credentials.credential_for_connection(connection)
    client = LogClient(
        connection.sls_endpoint,
        credential.access_key_id,
        credential.access_key_secret,
        credential.security_token,
    )
    try:
        now = int(time.time())
        client.get_logs(
            GetLogsRequest(
                project=connection.sls_project,
                logstore=connection.sls_logstore,
                fromTime=now - 60,
                toTime=now,
                query='status >= 400 or " OR " or "union select" or "../" or "<script" or "javascript:"',
                line=1,
            )
        )
        return True
    except Exception as exc:
        error_code = str(getattr(exc, "get_error_code", lambda: "")() or "")
        error_message = str(getattr(exc, "get_error_message", lambda: "")() or exc)
        normalized = f"{error_code} {error_message}".lower()
        if "indexconfignotexist" in normalized or "without index config" in normalized:
            return False
        if "not configed in index" in normalized or "not configured in index" in normalized:
            raise AlibabaResourceDiscoveryError(
                "This Logstore already has a search index, but it is missing fields SecAi needs. "
                "In SLS Index Attributes, add number indexes for status and status_code and enable full-text "
                "search, then try again. SecAi will keep the existing index unchanged."
            ) from exc
        logger.warning(
            "Alibaba Log Service index inspection failed for %s/%s",
            connection.sls_project,
            connection.sls_logstore,
            exc_info=exc,
        )
        raise AlibabaResourceDiscoveryError(
            "SecAi could not check this Logstore's search setup. Confirm the website role can query it."
        ) from exc


def _discover_log_sources(endpoint: str, connection: AlibabaAutopilotConnection) -> list[dict[str, str]]:
    try:
        from aliyun.log import LogClient
    except ModuleNotFoundError as exc:
        raise AlibabaResourceDiscoveryError("The Alibaba Log Service SDK is not installed.") from exc
    credential = alibaba_credentials.credential_for_connection(connection)
    client = LogClient(
        endpoint,
        credential.access_key_id,
        credential.access_key_secret,
        credential.security_token,
    )
    projects = []
    for offset in range(0, 1000, 100):
        page = list(client.list_project(offset, 100, "").get_projects())
        projects.extend(page)
        if len(page) < 100:
            break
    sources: list[dict[str, str]] = []
    for project in projects:
        project_name = _field(project, "projectName", "project_name")
        if not project_name:
            continue
        logstores: list[str] = []
        for offset in range(0, 5000, 500):
            page = list(client.list_logstore(project_name, None, offset, 500).get_logstores())
            logstores.extend(str(item) for item in page)
            if len(page) < 500:
                break
        sources.extend(
            {
                "endpoint": endpoint,
                "project": project_name,
                "logstore": str(logstore),
                "label": f"{project_name} / {logstore}",
            }
            for logstore in logstores
        )
    return sorted(sources, key=lambda item: item["label"].lower())


def _discover_security_groups(
    region: str,
    connection: AlibabaAutopilotConnection,
    security_group_id: str | None = None,
) -> list[dict[str, Any]]:
    try:
        from alibabacloud_ecs20140526 import models as ecs_models
        from alibabacloud_ecs20140526.client import Client as EcsClient
    except ModuleNotFoundError as exc:
        raise AlibabaResourceDiscoveryError("The Alibaba ECS SDK is not installed.") from exc
    client = EcsClient(alibaba_credentials.openapi_config(f"ecs.{region}.aliyuncs.com", connection))
    groups: list[Any] = []
    next_token: str | None = None
    for _ in range(20):
        request_args: dict[str, Any] = {
            "region_id": region,
            "max_results": 100,
            "is_query_ecs_count": True,
        }
        if security_group_id:
            request_args["security_group_ids"] = json.dumps([security_group_id])
        if next_token:
            request_args["next_token"] = next_token
        response = client.describe_security_groups(ecs_models.DescribeSecurityGroupsRequest(**request_args))
        payload = _as_dict(getattr(response, "body", response))
        container = payload.get("SecurityGroups") or payload.get("security_groups") or {}
        page = container.get("SecurityGroup") or container.get("security_group") or []
        groups.extend(page)
        next_token = _field(payload, "NextToken", "next_token") or None
        if not next_token or security_group_id:
            break
    discovered = []
    for group in groups:
        item = _as_dict(group)
        if item.get("ServiceManaged") or item.get("service_managed"):
            continue
        group_id = _field(item, "SecurityGroupId", "security_group_id")
        if not group_id:
            continue
        name = _field(item, "SecurityGroupName", "security_group_name") or group_id
        ecs_count = int(item.get("EcsCount") or item.get("ecs_count") or 0)
        discovered.append(
            {
                "security_group_id": group_id,
                "name": name,
                "description": _field(item, "Description", "description"),
                "vpc_id": _field(item, "VpcId", "vpc_id"),
                "ecs_count": ecs_count,
                "dedicated": ecs_count == 1,
            }
        )
    return sorted(discovered, key=lambda item: str(item["name"]).lower())


def _discover_instances(region: str, connection: AlibabaAutopilotConnection) -> list[dict[str, Any]]:
    """Return running Linux ECS servers eligible for collector installation."""
    try:
        from alibabacloud_ecs20140526 import models as ecs_models
        from alibabacloud_ecs20140526.client import Client as EcsClient
    except ModuleNotFoundError as exc:
        raise AlibabaResourceDiscoveryError("The Alibaba ECS SDK is not installed.") from exc
    client = EcsClient(alibaba_credentials.openapi_config(f"ecs.{region}.aliyuncs.com", connection))
    instances: list[Any] = []
    next_token: str | None = None
    for _ in range(20):
        request_args: dict[str, Any] = {"region_id": region, "max_results": 100, "status": "Running"}
        if next_token:
            request_args["next_token"] = next_token
        response = client.describe_instances(ecs_models.DescribeInstancesRequest(**request_args))
        payload = _as_dict(getattr(response, "body", response))
        container = payload.get("Instances") or payload.get("instances") or {}
        page = container.get("Instance") or container.get("instance") or []
        instances.extend(page)
        next_token = _field(payload, "NextToken", "next_token") or None
        if not next_token:
            break
    discovered = []
    for raw_instance in instances:
        item = _as_dict(raw_instance)
        os_type = _field(item, "OSType", "os_type").lower()
        if os_type and os_type != "linux":
            continue
        instance_id = _field(item, "InstanceId", "instance_id")
        if not instance_id:
            continue
        private_ips = _nested_list(item, ("VpcAttributes", "vpc_attributes"), ("PrivateIpAddress", "private_ip_address"), ("IpAddress", "ip_address"))
        if not private_ips:
            private_ips = _nested_list(item, ("InnerIpAddress", "inner_ip_address"), ("IpAddress", "ip_address"))
        security_group_ids = _nested_list(
            item,
            ("SecurityGroupIds", "security_group_ids"),
            ("SecurityGroupId", "security_group_id"),
        )
        name = _field(item, "InstanceName", "instance_name") or instance_id
        discovered.append(
            {
                "instance_id": instance_id,
                "name": name,
                "status": _field(item, "Status", "status") or "Running",
                "os_type": os_type or "linux",
                "private_ip": private_ips[0] if private_ips else "",
                "security_group_ids": security_group_ids,
                "label": f"{name} · {instance_id}",
            }
        )
    return sorted(discovered, key=lambda item: str(item["label"]).lower())


def security_group_is_dedicated(connection: AlibabaAutopilotConnection) -> bool:
    """Re-check that the saved write target still belongs to exactly one ECS instance."""
    if not connection.security_group_id:
        return False
    groups = _discover_security_groups(connection.region, connection, connection.security_group_id)
    return len(groups) == 1 and groups[0]["security_group_id"] == connection.security_group_id and groups[0]["dedicated"]


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "to_map"):
        mapped = value.to_map()
        return mapped if isinstance(mapped, dict) else {}
    return {}


def _field(value: Any, *names: str) -> str:
    item = _as_dict(value)
    for name in names:
        candidate = item.get(name)
        if candidate is not None:
            return str(candidate)
        candidate = getattr(value, name, None)
        if candidate is not None:
            return str(candidate)
    return ""


def _nested_list(value: Any, *levels: tuple[str, ...]) -> list[str]:
    current: Any = value
    for names in levels:
        item = _as_dict(current)
        current = next((item[name] for name in names if name in item), None)
        if current is None:
            return []
    if not isinstance(current, list):
        return []
    return [str(item) for item in current if str(item)]
