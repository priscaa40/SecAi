from __future__ import annotations

import json
import re
from functools import lru_cache
from types import SimpleNamespace
from typing import Any

from alibabacloud_credentials.client import Client as CredentialClient
from alibabacloud_credentials.provider import (
    DefaultCredentialsProvider,
    EcsRamRoleCredentialsProvider,
    RamRoleArnCredentialsProvider,
)
from alibabacloud_tea_openapi.models import Config as OpenApiConfig

from secai.settings import get_settings

ROLE_ARN_PATTERN = re.compile(r"^acs:ram::(?P<account_id>[0-9]{16}):role/(?P<role_name>[A-Za-z0-9.-]{1,64})$")


class AlibabaRoleAuthorizationError(RuntimeError):
    """Raised when SecAi cannot assume a website owner's RAM role."""


def parse_role_arn(role_arn: str) -> tuple[str, str]:
    """Validate a customer RAM role ARN and return its account and role names."""
    normalized = role_arn.strip()
    match = ROLE_ARN_PATTERN.fullmatch(normalized)
    if not match:
        raise ValueError("Enter a RAM role ARN such as acs:ram::1234567890123456:role/secai-site-example.")
    return match.group("account_id"), match.group("role_name")


@lru_cache(maxsize=1)
def _base_provider():
    """Return SecAi's own runtime identity; it may only broker customer role sessions."""
    role_name = get_settings().alibaba_cloud_ecs_metadata
    if role_name:
        return EcsRamRoleCredentialsProvider(role_name=role_name)
    return DefaultCredentialsProvider()


@lru_cache(maxsize=256)
def _assumed_client(site_id: str, role_arn: str, external_id: str, session_policy: str) -> CredentialClient:
    """Cache the SDK provider; the provider refreshes temporary STS credentials itself."""
    session_name = re.sub(r"[^A-Za-z0-9.@_-]", "-", f"secai-{site_id}")[:64]
    provider = RamRoleArnCredentialsProvider(
        credentials_provider=_base_provider(),
        role_arn=role_arn,
        external_id=external_id,
        role_session_name=session_name,
        duration_seconds=3600,
        policy=session_policy,
    )
    return CredentialClient(provider=provider)


def invalidate_assumed_role_cache() -> None:
    """Drop cached providers after a website role is changed or disconnected."""
    _assumed_client.cache_clear()


def client_for_connection(connection: Any) -> CredentialClient:
    """Return the refreshing temporary-credential client for one website connection."""
    role_arn = str(getattr(connection, "role_arn", "") or "")
    external_id = str(getattr(connection, "external_id", "") or "")
    site_id = str(getattr(connection, "site_id", "") or "")
    if not site_id or not role_arn or not external_id:
        raise AlibabaRoleAuthorizationError("This website's Alibaba Cloud role has not been verified.")
    return _assumed_client(site_id, role_arn, external_id, session_policy_for_connection(connection))


def session_policy_for_connection(connection: Any) -> str:
    """Scope each STS session to discovery plus this site's selected resources."""
    role_arn = str(getattr(connection, "role_arn", "") or "")
    account_id = str(getattr(connection, "account_id", "") or "")
    if not account_id and role_arn:
        account_id, _ = parse_role_arn(role_arn)
    region = str(getattr(connection, "region", "") or "*")
    statements: list[dict[str, Any]] = [
        {
            "Effect": "Allow",
            "Action": [
                "log:ListProject",
                "log:ListLogStores",
                "ecs:DescribeInstances",
                "ecs:DescribeSecurityGroups",
            ],
            "Resource": ["*"],
        }
    ]
    sls_project = str(getattr(connection, "sls_project", "") or "")
    sls_logstore = str(getattr(connection, "sls_logstore", "") or "")
    if account_id and sls_project and sls_logstore:
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["log:GetLogStoreLogs"],
                "Resource": [f"acs:log:{region}:{account_id}:project/{sls_project}/logstore/{sls_logstore}"],
            }
        )
    security_group_id = str(getattr(connection, "security_group_id", "") or "")
    if account_id and security_group_id:
        statements.extend(
            [
                {
                    "Effect": "Allow",
                    "Action": ["ecs:DescribeSecurityGroupAttribute", "ecs:RevokeSecurityGroup"],
                    "Resource": [f"acs:ecs:{region}:{account_id}:securitygroup/{security_group_id}"],
                },
                {
                    "Effect": "Allow",
                    "Action": ["ecs:AuthorizeSecurityGroup"],
                    "Resource": ["*"],
                },
            ]
        )
    return json.dumps({"Version": "1", "Statement": statements}, separators=(",", ":"), sort_keys=True)


def credential_for_connection(connection: Any):
    """Resolve temporary customer credentials for SDKs without provider support."""
    try:
        return client_for_connection(connection).get_credential()
    except Exception as exc:
        raise AlibabaRoleAuthorizationError(
            "SecAi could not use this website's Alibaba Cloud role. Check the role trust and external ID."
        ) from exc


def openapi_config(endpoint: str, connection: Any) -> OpenApiConfig:
    """Build an OpenAPI config isolated to one website owner's assumed role."""
    return OpenApiConfig(credential=client_for_connection(connection), endpoint=endpoint)


def verify_role(site_id: str, role_arn: str, external_id: str) -> str:
    """Assume a proposed customer role and return its account ID only after STS succeeds."""
    account_id, _ = parse_role_arn(role_arn)
    connection = SimpleNamespace(site_id=site_id, role_arn=role_arn.strip(), external_id=external_id)
    invalidate_assumed_role_cache()
    credential = credential_for_connection(connection)
    if not credential.access_key_id or not credential.access_key_secret or not credential.security_token:
        raise AlibabaRoleAuthorizationError("Alibaba Cloud did not return a complete temporary role session.")
    return account_id
