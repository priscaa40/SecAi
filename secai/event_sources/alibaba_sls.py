from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from secai import database
from secai.event_sources.normalizer import normalize_event
from secai.event_sources.relevance import is_sls_candidate_relevant
from secai.integrations import alibaba_coordinates, alibaba_credentials
from secai.security.redaction import sanitize_sls_contents

SUSPICIOUS_QUERY = 'status >= 400 or " OR " or "union select" or "../" or "<script" or "javascript:"'


class SlsNotConfigured(Exception):
    """Raised when a site has not connected Alibaba SLS."""


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
        query if query and query != "*" else SUSPICIOUS_QUERY,
        int((datetime.now(UTC) - timedelta(minutes=minutes)).timestamp()),
        int(datetime.now(UTC).timestamp()),
        limit=limit,
    )
    return _logs_to_events(site_id, logs)


def fetch_logs(conn: SlsConnection, query: str, from_time: int, to_time: int, limit: int = 100):
    """Fetch SLS logs through SecAi's ECS instance RAM role."""
    credential = alibaba_credentials.credential_for_connection(conn)
    try:
        from aliyun.log import GetLogsRequest, LogClient
    except ModuleNotFoundError as exc:
        raise RuntimeError("Install aliyun-log-python-sdk to use Alibaba Simple Log Service.") from exc

    log_client = LogClient(
        conn.sls_endpoint,
        credential.access_key_id,
        credential.access_key_secret,
        credential.security_token,
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
    contents = sanitize_sls_contents(contents)
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
