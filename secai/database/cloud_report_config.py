from __future__ import annotations

import hmac
import json
import secrets
from typing import Any

from secai.database._utils import utc_now
from secai.database.connection import connect


def prepare_alibaba_connection(
    site_id: str,
    *,
    external_id: str | None = None,
    region: str = "ap-southeast-1",
) -> dict[str, Any]:
    """Create or resume the customer authorization handshake for one site."""
    now = utc_now()
    with connect() as conn:
        conn.execute("begin immediate")
        existing = conn.execute("select * from site_alibaba_autopilot_configs where site_id = ?", (site_id,)).fetchone()
        if existing:
            if external_id and existing["external_id"] != external_id:
                raise ValueError("The saved Alibaba external ID does not match this deployment configuration.")
            return dict(existing)
        connection_external_id = external_id or f"secai-{secrets.token_urlsafe(24)}"
        conn.execute(
            """
            insert into site_alibaba_autopilot_configs (
                site_id, external_id, connection_status, region, enforcement_mode,
                created_at, updated_at
            ) values (?, ?, 'pending', ?, 'observe_only', ?, ?)
            """,
            (site_id, connection_external_id, region, now, now),
        )
    stored = get_alibaba_autopilot_config(site_id)
    if not stored:
        raise RuntimeError("Failed to prepare Alibaba Cloud connection")
    return stored


def verify_alibaba_connection(site_id: str, role_arn: str, account_id: str, region: str) -> dict[str, Any]:
    """Mark a site connection verified after STS AssumeRole succeeds."""
    now = utc_now()
    with connect() as conn:
        result = conn.execute(
            """
            update site_alibaba_autopilot_configs
            set role_arn = ?, account_id = ?, region = ?, connection_status = 'verified',
                connection_error = null, verified_at = ?, security_group_id = null,
                sls_endpoint = null, sls_project = null, sls_logstore = null,
                ecs_instance_id = null, collector_status = 'not_configured',
                collector_error = null, collector_machine_group = null,
                collector_config_name = null, collector_create_index = 0, collector_verified_at = null,
                enforcement_mode = 'observe_only', updated_at = ?
            where site_id = ?
            """,
            (role_arn, account_id, region, now, now, site_id),
        )
        if result.rowcount != 1:
            raise ValueError("Prepare this Alibaba Cloud connection before verifying the customer role.")
    stored = get_alibaba_autopilot_config(site_id)
    if not stored:
        raise RuntimeError("Failed to verify Alibaba Cloud connection")
    return stored


def mark_alibaba_connection_error(site_id: str, message: str) -> None:
    """Record a safe owner-facing verification failure without storing provider secrets."""
    with connect() as conn:
        conn.execute(
            """
            update site_alibaba_autopilot_configs
            set connection_status = 'error', connection_error = ?, verified_at = null, updated_at = ?
            where site_id = ?
            """,
            (message[:500], utc_now(), site_id),
        )


def save_alibaba_autopilot_config(site_id: str, config: dict[str, Any]) -> dict[str, Any]:
    """Save verified per-site SLS and ECS resource selections."""
    now = utc_now()
    with connect() as conn:
        current = conn.execute(
            "select connection_status from site_alibaba_autopilot_configs where site_id = ?",
            (site_id,),
        ).fetchone()
        if not current or current["connection_status"] != "verified":
            raise ValueError("Verify the website's Alibaba Cloud role before selecting resources.")
        conn.execute(
            """
            update site_alibaba_autopilot_configs
            set region = ?, security_group_id = ?, sls_endpoint = ?, sls_project = ?,
                sls_logstore = ?, ecs_instance_id = ?, collector_status = 'pending',
                collector_error = null, collector_machine_group = ?, collector_config_name = ?,
                collector_create_index = ?, collector_verified_at = null, enforcement_mode = ?, updated_at = ?
            where site_id = ?
            """,
            (
                config["region"],
                config.get("security_group_id"),
                config.get("sls_endpoint"),
                config.get("sls_project"),
                config.get("sls_logstore"),
                config["ecs_instance_id"],
                config["collector_machine_group"],
                config["collector_config_name"],
                int(bool(config.get("collector_create_index"))),
                config["enforcement_mode"],
                now,
                site_id,
            ),
        )
    stored = get_alibaba_autopilot_config(site_id)
    if not stored:
        raise RuntimeError("Failed to save Alibaba Autopilot settings")
    return stored


def mark_alibaba_collector_error(site_id: str, message: str) -> dict[str, Any]:
    """Keep an incomplete collector visible with a safe owner-facing reason."""
    with connect() as conn:
        result = conn.execute(
            """
            update site_alibaba_autopilot_configs
            set collector_status = 'error', collector_error = ?, collector_verified_at = null, updated_at = ?
            where site_id = ?
            """,
            (message[:500], utc_now(), site_id),
        )
        if result.rowcount != 1:
            raise ValueError("Configure this website's Alibaba collector before verifying it.")
    stored = get_alibaba_autopilot_config(site_id)
    if not stored:
        raise RuntimeError("Failed to save Alibaba collector status")
    return stored


def verify_alibaba_collector(site_id: str) -> dict[str, Any]:
    """Mark collection ready only after provider heartbeat and evidence checks pass."""
    now = utc_now()
    with connect() as conn:
        result = conn.execute(
            """
            update site_alibaba_autopilot_configs
            set collector_status = 'verified', collector_error = null,
                collector_verified_at = ?, updated_at = ?
            where site_id = ? and connection_status = 'verified'
              and ecs_instance_id is not null and sls_endpoint is not null
              and sls_project is not null and sls_logstore is not null
              and collector_machine_group is not null and collector_config_name is not null
            """,
            (now, now, site_id),
        )
        if result.rowcount != 1:
            raise ValueError("Complete this website's Alibaba collector plan before verifying it.")
    stored = get_alibaba_autopilot_config(site_id)
    if not stored:
        raise RuntimeError("Failed to verify Alibaba collector")
    return stored


def delete_alibaba_connection(site_id: str) -> bool:
    """Delete one site's Alibaba authorization and resource selections."""
    with connect() as conn:
        result = conn.execute("delete from site_alibaba_autopilot_configs where site_id = ?", (site_id,))
    return result.rowcount == 1


def get_alibaba_autopilot_config(site_id: str) -> dict[str, Any] | None:
    """Fetch Alibaba Cloud Autopilot settings for a site."""
    with connect() as conn:
        row = conn.execute("select * from site_alibaba_autopilot_configs where site_id = ?", (site_id,)).fetchone()
    return dict(row) if row else None


def list_alibaba_autopilot_configs_with_sls() -> list[dict[str, Any]]:
    """Return Autopilot connections that have a complete SLS evidence source."""
    with connect() as conn:
        rows = conn.execute(
            """
            select * from site_alibaba_autopilot_configs
            where connection_status = 'verified'
              and collector_status = 'verified'
              and sls_endpoint is not null and sls_project is not null and sls_logstore is not null
            order by updated_at desc
            """
        ).fetchall()
    return [dict(row) for row in rows]


def save_report_channel(site_id: str, channel: str, enabled: bool, config: dict[str, Any]) -> dict[str, Any]:
    """Save one report/approval channel for a site."""
    now = utc_now()
    with connect() as conn:
        existing = conn.execute(
            "select created_at from site_report_channels where site_id = ? and channel = ?",
            (site_id, channel),
        ).fetchone()
        created_at = existing["created_at"] if existing else now
        conn.execute(
            """
            insert into site_report_channels (site_id, channel, enabled, config_json, created_at, updated_at)
            values (?, ?, ?, ?, ?, ?)
            on conflict(site_id, channel)
            do update set enabled = excluded.enabled, config_json = excluded.config_json, updated_at = excluded.updated_at
            """,
            (site_id, channel, int(enabled), json.dumps(config), created_at, now),
        )
    return {
        "site_id": site_id,
        "channel": channel,
        "enabled": enabled,
        "config": config,
        "created_at": created_at,
        "updated_at": now,
    }


def list_report_channels(site_id: str, enabled_only: bool = True) -> list[dict[str, Any]]:
    """List report/approval channels for a site."""
    query = "select * from site_report_channels where site_id = ?"
    params: tuple[Any, ...] = (site_id,)
    if enabled_only:
        query += " and enabled = 1"
    query += " order by channel"
    with connect() as conn:
        rows = conn.execute(query, params).fetchall()
    result = []
    for row in rows:
        data = dict(row)
        data["enabled"] = bool(data["enabled"])
        data["config"] = json.loads(data.pop("config_json") or "{}")
        result.append(data)
    return result


def connect_discord_setup_code(code_hash: str, channel_id: str, guild_id: str | None) -> dict[str, Any] | None:
    """Consume one Discord setup code and bind its site to the invoking channel."""
    now = utc_now()
    with connect() as conn:
        rows = conn.execute("select * from site_report_channels where channel = 'discord' and enabled = 1").fetchall()
        for row in rows:
            data = dict(row)
            config = json.loads(data.get("config_json") or "{}")
            stored_hash = str(config.get("setup_code_hash") or "")
            if not stored_hash or not hmac.compare_digest(stored_hash, code_hash):
                continue
            if config.get("setup_expires_at") and config["setup_expires_at"] <= now:
                return None
            config = {
                "status": "connected",
                "channel_id": channel_id,
                "guild_id": guild_id,
                "connected_at": now,
            }
            conn.execute(
                "update site_report_channels set config_json = ?, updated_at = ? "
                "where site_id = ? and channel = 'discord'",
                (json.dumps(config), now, data["site_id"]),
            )
            return {"site_id": data["site_id"], "channel": "discord", "config": config}
    return None
