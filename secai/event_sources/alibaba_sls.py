from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from secai import database
from secai.event_sources.normalizer import normalize_event
from secai.event_sources.relevance import is_sls_candidate_relevant
from secai.integrations import alibaba_autopilot, alibaba_coordinates, alibaba_credentials
from secai.security.redaction import sanitize_sls_contents

SUSPICIOUS_QUERY = 'status >= 400 or " OR " or "union select" or "../" or "<script" or "javascript:"'


class SlsNotConfigured(Exception):
    """Raised when a site has not connected Alibaba SLS."""


class SlsReadinessError(RuntimeError):
    """Raised when a selected Logstore cannot yet serve SecAi queries."""


@dataclass(frozen=True)
class SlsConnection:
    """Saved SLS coordinates and the website-specific temporary-role identity."""

    site_id: str
    role_arn: str
    external_id: str
    account_id: str
    region: str
    sls_project: str
    sls_logstore: str
    sls_endpoint: str


def load_site_connection(site_id: str) -> SlsConnection:
    """Load a site's saved Alibaba SLS connection."""
    config = database.get_alibaba_autopilot_config(site_id)
    if (
        not config
        or config.get("connection_status") != "verified"
        or config.get("collector_status") != "verified"
        or not config.get("role_arn")
        or not all([config.get("sls_endpoint"), config.get("sls_project"), config.get("sls_logstore")])
    ):
        raise SlsNotConfigured(f"No Alibaba SLS connection saved for site {site_id}.")
    endpoint = alibaba_coordinates.validate_sls_endpoint(config["region"], config["sls_endpoint"])
    return SlsConnection(
        site_id=site_id,
        role_arn=config["role_arn"],
        external_id=config["external_id"],
        account_id=config["account_id"],
        region=config["region"],
        sls_project=config["sls_project"],
        sls_logstore=config["sls_logstore"],
        sls_endpoint=endpoint,
    )


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
        query or SUSPICIOUS_QUERY,
        int((datetime.now(UTC) - timedelta(minutes=minutes)).timestamp()),
        int(datetime.now(UTC).timestamp()),
        limit=limit,
    )
    return _logs_to_events(site_id, logs)


def fetch_logs(conn: SlsConnection, query: str, from_time: int, to_time: int, limit: int = 100):
    """Fetch SLS logs through SecAi's ECS instance RAM role."""
    try:
        from aliyun.log import GetLogsRequest
    except ModuleNotFoundError as exc:
        raise RuntimeError("Install aliyun-log-python-sdk to use Alibaba Simple Log Service.") from exc

    log_client = _log_client(conn)
    request = GetLogsRequest(
        project=conn.sls_project,
        logstore=conn.sls_logstore,
        fromTime=from_time,
        toTime=to_time,
        query=query,
        line=limit,
    )
    try:
        return log_client.get_logs(request).get_logs()
    except Exception as exc:
        error_code = str(getattr(exc, "get_error_code", lambda: "")() or "")
        error_message = str(getattr(exc, "get_error_message", lambda: "")() or exc)
        normalized = f"{error_code} {error_message}".lower()
        if "indexconfignotexist" in normalized or "without index config" in normalized:
            raise SlsReadinessError(
                "This Alibaba SLS Logstore still has no index configuration. Check the SecAiLogIndex resource in "
                "the collector ROS stack, wait about one minute after it succeeds, then create fresh website activity."
            ) from exc
        if "not configed in index" in normalized or "not configured in index" in normalized:
            raise SlsReadinessError(
                "The selected Alibaba SLS Logstore is missing a field index required by SecAi. Create long indexes "
                "for status and status_code and text indexes for ip, client_ip, remote_addr, method, path, query, "
                "user_agent, message, and timestamp, then trigger a new test request."
            ) from exc
        raise


def _log_client(conn: SlsConnection):
    credential = alibaba_credentials.credential_for_connection(conn)
    try:
        from aliyun.log import LogClient
    except ModuleNotFoundError as exc:
        raise RuntimeError("Install aliyun-log-python-sdk to use Alibaba Simple Log Service.") from exc
    return LogClient(
        conn.sls_endpoint,
        credential.access_key_id,
        credential.access_key_secret,
        credential.security_token,
    )


def validate_log_source(connection: SlsConnection) -> None:
    """Verify that a selected Logstore can execute SecAi's wildcard poll query."""
    now = datetime.now(UTC)
    fetch_logs(
        connection,
        "*",
        int((now - timedelta(minutes=5)).timestamp()),
        int(now.timestamp()),
        limit=1,
    )


def verify_collector_readiness(config: dict[str, Any], *, minutes: int = 30) -> dict[str, Any]:
    """Require both a fresh collector heartbeat and an actual website log record."""
    required = (
        "role_arn",
        "external_id",
        "account_id",
        "region",
        "sls_endpoint",
        "sls_project",
        "sls_logstore",
        "collector_machine_group",
    )
    if config.get("connection_status") != "verified" or not all(config.get(key) for key in required):
        raise SlsReadinessError("Save the website server and Log Service source before checking the collector.")
    connection = SlsConnection(
        site_id=str(config["site_id"]),
        role_arn=str(config["role_arn"]),
        external_id=str(config["external_id"]),
        account_id=str(config["account_id"]),
        region=str(config["region"]),
        sls_endpoint=alibaba_coordinates.validate_sls_endpoint(str(config["region"]), str(config["sls_endpoint"])),
        sls_project=str(config["sls_project"]),
        sls_logstore=str(config["sls_logstore"]),
    )
    client = _log_client(connection)
    machines = list(
        client.list_machines(
            connection.sls_project,
            str(config["collector_machine_group"]),
            0,
            100,
        ).get_machines()
    )
    expected_id = alibaba_autopilot.collector_resource_names(connection.site_id)["user_defined_id"]
    now = int(datetime.now(UTC).timestamp())
    healthy = [
        machine
        for machine in machines
        if str(getattr(machine, "user_defined_id", "")) == expected_id
        and now - int(getattr(machine, "heartbeat_time", 0) or 0) <= 10 * 60
    ]
    if not healthy:
        raise SlsReadinessError(
            "LoongCollector is not reporting from the selected server yet. Confirm the ROS stack finished "
            "successfully, wait about two minutes, and try again."
        )
    logs = list(
        fetch_logs(
            connection,
            "*",
            int((datetime.now(UTC) - timedelta(minutes=minutes)).timestamp()),
            int(datetime.now(UTC).timestamp()),
            limit=1,
        )
    )
    if not logs:
        raise SlsReadinessError(
            "LoongCollector is connected, but no website activity has reached this Logstore. Open the website "
            "once, wait about a minute, and check again."
        )
    return {"machines": len(healthy), "records": len(logs)}


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
    """Return whether a normalized source record belongs in SLS grouping."""
    return is_sls_candidate_relevant(event)


def _sls_log_to_event(site_id: str, contents: dict[str, Any]) -> dict[str, Any]:
    """Convert one Alibaba SLS log record into a normalized SecAi event."""
    raw_contents = dict(contents)
    structured = _structured_content(raw_contents.get("content"))
    contents = sanitize_sls_contents({**raw_contents, **structured})
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


def _structured_content(value: Any) -> dict[str, Any]:
    """Decode JSON emitted to Docker stdout without trusting arbitrary nested data."""
    if not isinstance(value, str) or not value.lstrip().startswith("{"):
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _log_contents(log: Any) -> dict[str, Any]:
    """Return content fields from either Alibaba SDK log object shape."""
    if hasattr(log, "get_contents"):
        contents = dict(log.get_contents())
        if not (contents.get("timestamp") or contents.get("time")) and hasattr(log, "get_time"):
            try:
                timestamp = float(log.get_time())
                if timestamp > 10_000_000_000:
                    timestamp /= 1000
                contents["timestamp"] = datetime.fromtimestamp(timestamp, UTC).isoformat()
            except (TypeError, ValueError, OSError, OverflowError):
                pass
        return contents
    raw_contents = getattr(log, "contents", None)
    if raw_contents is not None:
        return dict(raw_contents)
    if isinstance(log, dict):
        return dict(log)
    return {}
