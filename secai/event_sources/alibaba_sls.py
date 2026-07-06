from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
import time
from typing import Any

from secai import database
from secai.database import encryption
from secai.settings import get_settings
from secai.event_sources.normalizer import normalize_event
from secai.event_sources.relevance import is_sls_event_relevant


SUSPICIOUS_QUERY = 'status >= 400 or " OR " or "union select" or "../" or "<script" or "javascript:"'
_credential_cache: dict[str, tuple[Any, float]] = {}
_credential_lock = Lock()


class SlsNotConfigured(Exception):
    """Raised when a site has not connected Alibaba SLS."""


class SlsConnectionRevoked(Exception):
    """Raised when a saved SLS RAM role can no longer be assumed."""


@dataclass(frozen=True)
class CustomerSlsConnection:
    """Per-site Alibaba SLS connection used to assume a customer RAM role."""

    customer_id: str
    role_arn: str
    external_id: str
    sls_project: str
    sls_logstore: str
    sls_endpoint: str


def load_site_connection(site_id: str) -> CustomerSlsConnection:
    """Load a site's saved Alibaba SLS connection."""
    config = database.get_sls_config(site_id)
    if not config:
        raise SlsNotConfigured(f"No Alibaba SLS connection saved for site {site_id}.")
    return CustomerSlsConnection(
        customer_id=site_id,
        role_arn=config["role_arn"],
        external_id=encryption.decrypt_secret(config["encrypted_external_id"]),
        sls_project=config["project"],
        sls_logstore=config["logstore"],
        sls_endpoint=config["endpoint"],
    )


def invalidate_cache(site_id: str) -> None:
    """Drop cached STS credentials for a site after its SLS settings change."""
    with _credential_lock:
        _credential_cache.pop(site_id, None)


def fetch_saved_site_events(
    site_id: str,
    query: str = SUSPICIOUS_QUERY,
    minutes: int = 15,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Fetch recent security-relevant SLS events for a connected site."""
    connection = load_site_connection(site_id)
    logs = fetch_logs(
        connection,
        query if query and query != "*" else SUSPICIOUS_QUERY,
        int((datetime.now(timezone.utc) - timedelta(minutes=minutes)).timestamp()),
        int(datetime.now(timezone.utc).timestamp()),
        limit=limit,
    )
    return _logs_to_events(site_id, logs)


def fetch_events(
    site_id: str,
    query: str = SUSPICIOUS_QUERY,
    minutes: int = 15,
    limit: int = 100,
    config: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Fetch recent Alibaba SLS logs and convert them into SecAi events."""
    settings = get_settings()
    endpoint = config.get("endpoint") if config else settings.alibaba_sls_endpoint
    project = config.get("project") if config else settings.alibaba_sls_project
    logstore = config.get("logstore") if config else settings.alibaba_sls_logstore
    if not config or not config.get("role_arn") or not all([endpoint, project, logstore, config.get("external_id")]):
        raise RuntimeError("Alibaba SLS requires endpoint, project, logstore, RoleArn, and ExternalId.")
    connection = CustomerSlsConnection(
        customer_id=site_id,
        role_arn=config["role_arn"],
        external_id=config["external_id"],
        sls_project=project,
        sls_logstore=logstore,
        sls_endpoint=endpoint,
    )
    logs = fetch_logs(
        connection,
        query if query and query != "*" else SUSPICIOUS_QUERY,
        int((datetime.now(timezone.utc) - timedelta(minutes=minutes)).timestamp()),
        int(datetime.now(timezone.utc).timestamp()),
        limit=limit,
    )
    return _logs_to_events(site_id, logs)


def fetch_logs(conn: CustomerSlsConnection, query: str, from_time: int, to_time: int, limit: int = 100):
    """Fetch SLS logs through temporary credentials from a customer RAM role."""
    credentials = get_temp_credentials(conn)
    try:
        from aliyun.log import GetLogsRequest, LogClient
    except ModuleNotFoundError as exc:
        raise RuntimeError("Install aliyun-log-python-sdk to use Alibaba Simple Log Service.") from exc

    log_client = LogClient(
        conn.sls_endpoint,
        credentials.access_key_id,
        credentials.access_key_secret,
        credentials.security_token,
    )
    request = GetLogsRequest(
        project=conn.sls_project,
        logstore=conn.sls_logstore,
        fromTime=from_time,
        toTime=to_time,
        query=query,
        line=limit,
    )
    return log_client.get_logs(request).get_logs()


def get_temp_credentials(conn: CustomerSlsConnection, duration_seconds: int = 3600):
    """Return cached STS credentials for a customer SLS connection."""
    with _credential_lock:
        cached = _credential_cache.get(conn.customer_id)
        if cached and cached[1] - 60 > time.time():
            return cached[0]

        client = _sts_client()
        request = _assume_role_request(
            role_arn=conn.role_arn,
            role_session_name=f"secai-{conn.customer_id}",
            external_id=conn.external_id,
            duration_seconds=duration_seconds,
        )
        try:
            response = client.assume_role(request)
        except Exception as exc:
            raise SlsConnectionRevoked(f"Could not assume Alibaba SLS role for site {conn.customer_id}: {exc}") from exc
        credentials = response.body.credentials
        _credential_cache[conn.customer_id] = (credentials, time.time() + duration_seconds)
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
        from alibabacloud_tea_openapi.models import Config as OpenApiConfig
        from alibabacloud_sts20150401.client import Client as StsClient
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


def _logs_to_events(site_id: str, logs: list[Any]) -> list[dict[str, Any]]:
    """Convert SLS SDK log objects into normalized SecAi events."""
    events: list[dict[str, Any]] = []
    for log in logs:
        contents = _log_contents(log)
        event = _sls_log_to_event(site_id, contents)
        if is_security_relevant_event(event):
            events.append(event)
    return events


def is_security_relevant_event(event: dict[str, Any]) -> bool:
    """Return whether a normalized source event should enter SecAi."""
    return is_sls_event_relevant(event)


def _sls_log_to_event(site_id: str, contents: dict[str, Any]) -> dict[str, Any]:
    """Convert one Alibaba SLS log record into a normalized SecAi event."""
    path = contents.get("path") or contents.get("request_uri") or contents.get("uri")
    status_code = contents.get("status") or contents.get("status_code")
    try:
        parsed_status = int(status_code) if status_code is not None else None
    except ValueError:
        parsed_status = None
    return normalize_event(
        {
            "site_id": site_id,
            "source": "alibaba_sls",
            "event_type": "sls_log",
            "method": contents.get("method") or contents.get("request_method"),
            "path": path,
            "query": contents.get("query") or contents.get("args"),
            "status_code": parsed_status,
            "ip": contents.get("remote_addr") or contents.get("client_ip") or contents.get("ip"),
            "user_agent": contents.get("http_user_agent") or contents.get("user_agent"),
            "payload": contents.get("message") or contents.get("body"),
            "metadata": {"sls": contents},
        }
    )


def _log_contents(log: Any) -> dict[str, Any]:
    """Return content fields from either Alibaba SDK log object shape."""
    if hasattr(log, "get_contents"):
        return dict(log.get_contents())
    contents = getattr(log, "contents", None)
    if contents is not None:
        return dict(contents)
    if isinstance(log, dict):
        return dict(log)
    return {}
