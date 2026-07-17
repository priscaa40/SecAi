from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from secai.database._utils import token_hash, utc_now
from secai.database.connection import connect
from secai.settings import get_settings


def insert_incident(incident: dict[str, Any], analysis_job_id: int | None = None) -> dict[str, Any]:
    """Store an incident, atomically completing its analysis job when one is supplied."""
    now = utc_now()
    status = incident.get("status", "needs_review")
    approval_token = secrets.token_urlsafe(32) if status == "needs_review" else None
    with connect() as conn:
        job = None
        if analysis_job_id is not None:
            if getattr(conn, "dialect", "sqlite") == "sqlite":
                conn.execute("begin immediate")
                job = conn.execute("select * from analysis_jobs where id = ?", (analysis_job_id,)).fetchone()
            else:
                job = conn.execute(
                    "select * from analysis_jobs where id = ? for update",
                    (analysis_job_id,),
                ).fetchone()
            if not job:
                raise ValueError("Analysis job does not exist")
            if job["site_id"] != incident["site_id"]:
                raise ValueError("Analysis job and incident must belong to the same website")
            if job["incident_id"] is not None:
                existing = conn.execute("select * from incidents where id = ?", (job["incident_id"],)).fetchone()
                if not existing:
                    raise RuntimeError("Analysis job references a missing incident")
                return {**_decode_incident(dict(existing)), "approval_token": None}
            if job["status"] != "running":
                raise ValueError("Analysis job must be running before it can create an incident")

        incident_id = _insert_incident_row(conn, incident, status, now)
        if approval_token:
            _insert_approval_token(conn, incident_id, approval_token, now)
        if analysis_job_id is not None:
            linked = conn.execute(
                """
                update analysis_jobs
                set status = 'incident_created', current_step = 'complete', error = null,
                    incident_id = ?, claimed_at = null, updated_at = ?
                where id = ? and incident_id is null
                returning id
                """,
                (incident_id, now, analysis_job_id),
            ).fetchone()
            if not linked:
                raise RuntimeError("Analysis job was completed concurrently")
            conn.execute(
                "update qwen_usage set incident_id = ? where job_id = ?",
                (incident_id, analysis_job_id),
            )
    return {**incident, "approval_token": approval_token, "id": incident_id, "created_at": now, "updated_at": now}


def _insert_incident_row(conn: Any, incident: dict[str, Any], status: str, now: str) -> int:
    cursor = conn.execute(
        """
        insert into incidents (
            site_id, title, severity, status, attack_type, affected_route,
            confidence, report, recommended_action_json, created_at, updated_at
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) returning id
        """,
        (
            incident["site_id"],
            incident["title"],
            incident["severity"],
            status,
            incident["attack_type"],
            incident.get("affected_route"),
            incident["confidence"],
            incident["report"],
            json.dumps(incident["recommended_action"]),
            now,
            now,
        ),
    )
    incident_id = cursor.fetchone()["id"]
    if incident_id is None:
        raise RuntimeError("Failed to assign incident ID")
    return int(incident_id)


def _insert_approval_token(conn: Any, incident_id: int, approval_token: str, now: str) -> None:
    expires_at = (datetime.now(UTC) + timedelta(minutes=max(1, get_settings().secai_approval_ttl_minutes))).isoformat()
    conn.execute(
        "insert into approval_tokens (incident_id, token_hash, expires_at, consumed_at, created_at) "
        "values (?, ?, ?, null, ?)",
        (incident_id, token_hash(approval_token), expires_at, now),
    )


def list_incidents(
    site_id: str | None = None,
    limit: int = 100,
    before_id: int | None = None,
) -> list[dict[str, Any]]:
    """List incidents, optionally filtered by site."""
    query = "select * from incidents"
    clauses: list[str] = []
    params: list[Any] = []
    if site_id:
        clauses.append("site_id = ?")
        params.append(site_id)
    if before_id is not None:
        clauses.append("id < ?")
        params.append(before_id)
    if clauses:
        query += " where " + " and ".join(clauses)
    query += " order by id desc limit ?"
    params.append(max(1, min(limit, 200)))
    with connect() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
    return [_decode_incident(dict(row)) for row in rows]


def list_incidents_for_sites(
    site_ids: list[str],
    limit: int = 100,
    before_id: int | None = None,
) -> list[dict[str, Any]]:
    """List incidents scoped to a set of owned site IDs."""
    if not site_ids:
        return []
    placeholders = ",".join("?" for _ in site_ids)
    with connect() as conn:
        before_clause = " and id < ?" if before_id is not None else ""
        params: tuple[Any, ...] = (*site_ids, *((before_id,) if before_id is not None else ()), max(1, min(limit, 200)))
        rows = conn.execute(
            f"select * from incidents where site_id in ({placeholders}){before_clause} order by id desc limit ?",
            params,
        ).fetchall()
    return [_decode_incident(dict(row)) for row in rows]


def get_incident(incident_id: int) -> dict[str, Any] | None:
    """Fetch one incident by ID."""
    with connect() as conn:
        row = conn.execute("select * from incidents where id = ?", (incident_id,)).fetchone()
    return _decode_incident(dict(row)) if row else None


def get_incident_by_approval_token(token: str) -> dict[str, Any] | None:
    """Fetch one incident from a notification approval token."""
    with connect() as conn:
        row = conn.execute(
            """
            select incidents.* from approval_tokens
            join incidents on incidents.id = approval_tokens.incident_id
            where approval_tokens.token_hash = ?
              and approval_tokens.consumed_at is null
              and approval_tokens.expires_at > ?
            """,
            (token_hash(token), utc_now()),
        ).fetchone()
    return _decode_incident(dict(row)) if row else None


def _decode_incident(row: dict[str, Any]) -> dict[str, Any]:
    """Decode stored incident JSON fields into Python values."""
    row["recommended_action"] = json.loads(row.pop("recommended_action_json", "{}"))
    return row


def update_incident_status(incident_id: int, status: str) -> dict[str, Any] | None:
    """Update an incident's status."""
    now = utc_now()
    with connect() as conn:
        conn.execute("update incidents set status = ?, updated_at = ? where id = ?", (status, now, incident_id))
    return get_incident(incident_id)


def transition_incident_status(
    incident_id: int,
    from_statuses: set[str],
    to_status: str,
) -> dict[str, Any] | None:
    """Atomically transition an incident when it is still in an expected state."""
    if not from_statuses:
        return None
    placeholders = ",".join("?" for _ in from_statuses)
    now = utc_now()
    with connect() as conn:
        conn.execute("begin immediate")
        cursor = conn.execute(
            f"update incidents set status = ?, updated_at = ? where id = ? and status in ({placeholders})",
            (to_status, now, incident_id, *sorted(from_statuses)),
        )
        if cursor.rowcount != 1:
            return None
        row = conn.execute("select * from incidents where id = ?", (incident_id,)).fetchone()
    return _decode_incident(dict(row)) if row else None


def consume_approval_token(incident_id: int) -> None:
    """Invalidate an incident approval token after a final decision."""
    now = utc_now()
    with connect() as conn:
        conn.execute(
            "update approval_tokens set consumed_at = ? where incident_id = ? and consumed_at is null",
            (now, incident_id),
        )


def record_approval_decision(
    incident_id: int,
    site_id: str,
    actor: str,
    channel: str,
    decision: str,
    note: str | None,
    previous_status: str,
    resulting_status: str,
) -> dict[str, Any]:
    """Persist an immutable human or automatic remediation decision."""
    created_at = utc_now()
    with connect() as conn:
        cursor = conn.execute(
            """
            insert into approval_decisions (
                incident_id, site_id, actor, channel, decision, note,
                previous_status, resulting_status, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?) returning id
            """,
            (incident_id, site_id, actor, channel, decision, note, previous_status, resulting_status, created_at),
        )
        decision_id = cursor.fetchone()["id"]
    return {
        "id": decision_id,
        "incident_id": incident_id,
        "site_id": site_id,
        "actor": actor,
        "channel": channel,
        "decision": decision,
        "note": note,
        "previous_status": previous_status,
        "resulting_status": resulting_status,
        "created_at": created_at,
    }


def list_approval_decisions(incident_id: int) -> list[dict[str, Any]]:
    """Return immutable decision history for one incident."""
    with connect() as conn:
        rows = conn.execute(
            "select * from approval_decisions where incident_id = ? order by id",
            (incident_id,),
        ).fetchall()
    return [dict(row) for row in rows]
