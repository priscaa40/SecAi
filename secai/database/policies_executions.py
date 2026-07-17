from __future__ import annotations

import json
from typing import Any

from secai.database._utils import utc_now
from secai.database.connection import connect


def insert_policy(
    site_id: str,
    action: str,
    target: str,
    reason: str,
    incident_id: int | None = None,
    *,
    provider: str | None = None,
    provider_rule_id: str | None = None,
    parameters: dict[str, Any] | None = None,
    status: str = "pending",
    expires_at: str | None = None,
) -> dict[str, Any]:
    """Store an approved remediation policy."""
    created_at = utc_now()
    with connect() as conn:
        cursor = conn.execute(
            """
            insert into policies (
                site_id, action, target, reason, incident_id, provider, provider_rule_id,
                parameters_json, status, applied_at, error_message, expires_at, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) returning id
            """,
            (
                site_id,
                action,
                target,
                reason,
                incident_id,
                provider,
                provider_rule_id,
                json.dumps(parameters or {}),
                status,
                created_at if status == "active" else None,
                None,
                expires_at,
                created_at,
            ),
        )
        policy_id = cursor.fetchone()["id"]
    if policy_id is None:
        raise RuntimeError("Failed to assign remediation policy ID")
    stored = get_policy(policy_id)
    if not stored:
        raise RuntimeError("Failed to store remediation policy")
    return stored


def get_or_insert_policy(
    site_id: str,
    action: str,
    target: str,
    reason: str,
    incident_id: int,
    *,
    provider: str | None,
    parameters: dict[str, Any],
    expires_at: str | None,
) -> tuple[dict[str, Any], bool]:
    """Create one policy per incident and return whether this call created it."""
    created_at = utc_now()
    with connect() as conn:
        conn.execute("begin immediate")
        existing = conn.execute("select * from policies where incident_id = ?", (incident_id,)).fetchone()
        if existing:
            return _decode_policy(dict(existing)), False
        cursor = conn.execute(
            """
            insert into policies (
                site_id, action, target, reason, incident_id, provider, provider_rule_id,
                parameters_json, status, applied_at, error_message, expires_at, created_at
            ) values (?, ?, ?, ?, ?, ?, null, ?, 'pending', null, null, ?, ?)
            on conflict (incident_id) where incident_id is not null do nothing
            returning id
            """,
            (site_id, action, target, reason, incident_id, provider, json.dumps(parameters), expires_at, created_at),
        )
        inserted = cursor.fetchone()
        if not inserted:
            existing = conn.execute("select * from policies where incident_id = ?", (incident_id,)).fetchone()
            if not existing:
                raise RuntimeError("Failed to store remediation policy")
            return _decode_policy(dict(existing)), False
        row = conn.execute("select * from policies where id = ?", (inserted["id"],)).fetchone()
    if not row:
        raise RuntimeError("Failed to store remediation policy")
    return _decode_policy(dict(row)), True


def update_policy_execution_state(
    policy_id: int,
    status: str,
    *,
    provider_rule_id: str | None = None,
    error_message: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    """Update provider execution status for one remediation policy."""
    applied_at = utc_now() if status == "active" else None
    with connect() as conn:
        conn.execute(
            """
            update policies
            set status = ?, provider_rule_id = coalesce(?, provider_rule_id), applied_at = ?,
                error_message = ?, expires_at = coalesce(?, expires_at)
            where id = ?
            """,
            (status, provider_rule_id, applied_at, error_message, expires_at, policy_id),
        )
    stored = get_policy(policy_id)
    if not stored:
        raise RuntimeError("Failed to update remediation policy")
    return stored


def transition_policy_status(
    policy_id: int,
    from_statuses: set[str],
    to_status: str,
) -> dict[str, Any] | None:
    """Atomically claim a policy lifecycle transition."""
    if not from_statuses:
        return None
    placeholders = ",".join("?" for _ in from_statuses)
    with connect() as conn:
        conn.execute("begin immediate")
        cursor = conn.execute(
            f"update policies set status = ?, error_message = null where id = ? and status in ({placeholders})",
            (to_status, policy_id, *sorted(from_statuses)),
        )
        if cursor.rowcount != 1:
            return None
        row = conn.execute("select * from policies where id = ?", (policy_id,)).fetchone()
    return _decode_policy(dict(row)) if row else None


def reconcile_interrupted_actions() -> dict[str, int]:
    """Make provider work interrupted by a process stop visible and safely retryable."""
    now = utc_now()
    with connect() as conn:
        apply_failures = conn.execute(
            """
            update policies
            set status = 'failed', error_message = 'Protection was interrupted; retry is required'
            where status = 'applying'
            """
        ).rowcount
        rollback_failures = conn.execute(
            """
            update policies
            set status = 'active', error_message = 'Removal was interrupted; retry is required'
            where status = 'revoking'
            """
        ).rowcount
        completed_decisions = conn.execute(
            """
            update incidents
            set status = 'approved', updated_at = ?
            where status = 'applying'
              and exists (select 1 from policies where policies.incident_id = incidents.id)
            """,
            (now,),
        ).rowcount
        restored_reviews = conn.execute(
            """
            update incidents
            set status = 'needs_review', updated_at = ?
            where status = 'applying'
            """,
            (now,),
        ).rowcount
    return {
        "apply_failures": apply_failures,
        "rollback_failures": rollback_failures,
        "completed_decisions": completed_decisions,
        "restored_reviews": restored_reviews,
    }


def get_policy(policy_id: int) -> dict[str, Any] | None:
    """Fetch one remediation policy by ID."""
    with connect() as conn:
        row = conn.execute("select * from policies where id = ?", (policy_id,)).fetchone()
    return _decode_policy(dict(row)) if row else None


def list_policies(site_id: str, limit: int = 100, before_id: int | None = None) -> list[dict[str, Any]]:
    """List approved policies for a site."""
    with connect() as conn:
        before_clause = " and id < ?" if before_id is not None else ""
        params = (site_id, *((before_id,) if before_id is not None else ()), max(1, min(limit, 200)))
        rows = conn.execute(
            f"select * from policies where site_id = ?{before_clause} order by id desc limit ?",
            params,
        ).fetchall()
    return [_decode_policy(dict(row)) for row in rows]


def list_due_active_policies(now: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    """Return active provider policies whose explicit expiry time has passed."""
    with connect() as conn:
        rows = conn.execute(
            """
            select * from policies
            where status = 'active' and expires_at is not null and expires_at <= ?
            order by expires_at
            limit ?
            """,
            (now or utc_now(), limit),
        ).fetchall()
    return [_decode_policy(dict(row)) for row in rows]


def claim_due_policy(now: str | None = None) -> dict[str, Any] | None:
    """Atomically claim one due active policy for expiry."""
    deadline = now or utc_now()
    with connect() as conn:
        conn.execute("begin immediate")
        row = conn.execute(
            """
            select * from policies
            where status = 'active' and expires_at is not null and expires_at <= ?
            order by expires_at, id limit 1
            """,
            (deadline,),
        ).fetchone()
        if not row:
            return None
        cursor = conn.execute(
            "update policies set status = 'revoking' where id = ? and status = 'active'",
            (row["id"],),
        )
        if cursor.rowcount != 1:
            return None
        claimed = conn.execute("select * from policies where id = ?", (row["id"],)).fetchone()
    return _decode_policy(dict(claimed)) if claimed else None


def get_policy_for_incident(incident_id: int) -> dict[str, Any] | None:
    """Fetch the first policy created from an incident."""
    with connect() as conn:
        row = conn.execute(
            "select * from policies where incident_id = ? order by id limit 1",
            (incident_id,),
        ).fetchone()
    return _decode_policy(dict(row)) if row else None


def get_policies_for_incidents(incident_ids: set[int]) -> dict[int, dict[str, Any]]:
    """Fetch incident execution state in one query for dashboard lists."""
    if not incident_ids:
        return {}
    placeholders = ",".join("?" for _ in incident_ids)
    with connect() as conn:
        rows = conn.execute(
            f"select * from policies where incident_id in ({placeholders})",
            tuple(sorted(incident_ids)),
        ).fetchall()
    decoded = [_decode_policy(dict(row)) for row in rows]
    return {item["incident_id"]: item for item in decoded}


def _decode_policy(row: dict[str, Any]) -> dict[str, Any]:
    """Decode stored remediation policy JSON fields."""
    row["parameters"] = json.loads(row.pop("parameters_json", "{}") or "{}")
    return row


def record_remediation_execution(
    site_id: str,
    policy_id: int | None,
    incident_id: int | None,
    provider: str,
    action: str,
    target: str,
    status: str,
    request: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
    error_message: str | None = None,
) -> dict[str, Any]:
    """Store an audit record proving whether a remediation provider ran."""
    created_at = utc_now()
    with connect() as conn:
        cursor = conn.execute(
            """
            insert into remediation_executions (
                site_id, policy_id, incident_id, provider, action, target, status,
                request_json, response_json, error_message, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) returning id
            """,
            (
                site_id,
                policy_id,
                incident_id,
                provider,
                action,
                target,
                status,
                json.dumps(request or {}),
                json.dumps(response or {}),
                error_message,
                created_at,
            ),
        )
        execution_id = cursor.fetchone()["id"]
    return {
        "id": execution_id,
        "site_id": site_id,
        "policy_id": policy_id,
        "incident_id": incident_id,
        "provider": provider,
        "action": action,
        "target": target,
        "status": status,
        "request": request or {},
        "response": response or {},
        "error_message": error_message,
        "created_at": created_at,
    }


def list_remediation_executions(site_id: str, limit: int = 25) -> list[dict[str, Any]]:
    """List recent remediation execution audit records for a site."""
    with connect() as conn:
        rows = conn.execute(
            "select * from remediation_executions where site_id = ? order by id desc limit ?",
            (site_id, limit),
        ).fetchall()
    result = []
    for row in rows:
        data = dict(row)
        data["request"] = json.loads(data.pop("request_json", "{}") or "{}")
        data["response"] = json.loads(data.pop("response_json", "{}") or "{}")
        result.append(data)
    return result
