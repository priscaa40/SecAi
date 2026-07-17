from __future__ import annotations

from typing import Any

from secai.integrations import alibaba_credentials
from secai.integrations.alibaba_autopilot import AlibabaAutopilotConnection


class AlibabaEcsSecurityGroupClient:
    """Small adapter around Alibaba ECS security-group ingress operations."""

    def __init__(self, connection: AlibabaAutopilotConnection):
        self.connection = connection

    def authorize_security_group(self, request: dict[str, Any]) -> dict[str, Any]:
        client, ecs_models = self._sdk_client()
        permission = request["Permissions"][0]
        model = ecs_models.AuthorizeSecurityGroupRequest(
            region_id=request.get("RegionId"),
            security_group_id=request["SecurityGroupId"],
            client_token=request.get("ClientToken"),
            permissions=[
                ecs_models.AuthorizeSecurityGroupRequestPermissions(
                    ip_protocol=permission["IpProtocol"],
                    port_range=permission["PortRange"],
                    policy=permission["Policy"],
                    priority=permission["Priority"],
                    source_cidr_ip=permission.get("SourceCidrIp"),
                    ipv_6source_cidr_ip=permission.get("Ipv6SourceCidrIp"),
                    description=permission["Description"],
                )
            ],
        )
        response = client.authorize_security_group(model)
        return object_to_dict(getattr(response, "body", response))

    def revoke_security_group(self, request: dict[str, Any]) -> dict[str, Any]:
        client, ecs_models = self._sdk_client()
        model_args = {
            "region_id": request.get("RegionId"),
            "security_group_id": request["SecurityGroupId"],
            "client_token": request.get("ClientToken"),
        }
        if request.get("SecurityGroupRuleId"):
            model_args["security_group_rule_id"] = request["SecurityGroupRuleId"]
        else:
            permission = request["Permissions"][0]
            model_args["permissions"] = [
                ecs_models.RevokeSecurityGroupRequestPermissions(
                    ip_protocol=permission["IpProtocol"],
                    port_range=permission["PortRange"],
                    policy=permission["Policy"],
                    priority=permission["Priority"],
                    source_cidr_ip=permission.get("SourceCidrIp"),
                    ipv_6source_cidr_ip=permission.get("Ipv6SourceCidrIp"),
                )
            ]
        model = ecs_models.RevokeSecurityGroupRequest(**model_args)
        response = client.revoke_security_group(model)
        return object_to_dict(getattr(response, "body", response))

    def describe_security_group_rules(self, request: dict[str, Any]) -> dict[str, Any]:
        client, ecs_models = self._sdk_client()
        model = ecs_models.DescribeSecurityGroupAttributeRequest(
            region_id=request["RegionId"],
            security_group_id=request["SecurityGroupId"],
            direction="ingress",
            max_results=1000,
        )
        response = client.describe_security_group_attribute(model)
        return object_to_dict(getattr(response, "body", response))

    def _sdk_client(self):
        endpoint = f"ecs.{self.connection.region}.aliyuncs.com"
        try:
            from alibabacloud_ecs20140526 import models as ecs_models
            from alibabacloud_ecs20140526.client import Client as EcsClient
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "Install alibabacloud-ecs20140526 to use Alibaba ECS security group remediation."
            ) from exc

        client = EcsClient(alibaba_credentials.openapi_config(endpoint, self.connection))
        return client, ecs_models


def object_to_dict(value: Any) -> dict[str, Any]:
    """Return SDK response objects as plain dictionaries."""
    if isinstance(value, dict):
        return value
    if hasattr(value, "to_map"):
        mapped = value.to_map()
        return mapped if isinstance(mapped, dict) else {"value": mapped}
    result = {}
    for key in (
        "request_id",
        "RequestId",
        "security_group_rule_id",
        "SecurityGroupRuleId",
        "rule_id",
        "RuleId",
    ):
        if hasattr(value, key):
            result[key] = getattr(value, key)
    return result
