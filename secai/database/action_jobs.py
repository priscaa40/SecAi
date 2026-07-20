from __future__ import annotations

import json
from typing import Any

from secai.database._utils import utc_now
from secai.database.connection import connect, database_backend


def ensure_action_job(
    incident_id: int,
    site_id: str,
    action: str,
    tool_name: str,
    requires_approval: bool,
) -> dict[str, Any]:
    """Create the one canonical executable-action job for an incident."""
    now = utc_now()
    initial_status = "awaiting_approval" if requires_approval else "queued"
    with connect() as conn:
        conn.execute(
            """
            insert into action_jobs (
                incident_id, site_id, action, tool_name, requires_approval,
                approval_decision_id, status, current_step, attempt_count,
                claimed_at, result_json, error, created_at, updated_at
            ) values (?, ?, ?, ?, ?, null, ?, ?, 0, null, '{}', null, ?, ?)
            on conflict (incident_id) do nothing
            """,
            (
                incident_id,
                site_id,
                action,
                tool_name,
                int(requires_approval),
                initial_status,
                "human_approval" if requires_approval else "queued",
                now,
                now,
            ),
        )
        row = conn.execute("select * from action_jobs where incident_id = ?", (incident_id,)).fetchone()
    if not row:
        raise RuntimeError("Failed to create action job")
    stored = _decode_action_job(dict(row))
    if stored["site_id"] != site_id or stored["action"] != action or stored["tool_name"] != tool_name:
        raise ValueError("The persisted action job does not match the incident recommendation")
    return stored


def get_action_job(action_job_id: int) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("select * from action_jobs where id = ?", (action_job_id,)).fetchone()
    return _decode_action_job(dict(row)) if row else None


def get_action_job_for_incident(incident_id: int) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("select * from action_jobs where incident_id = ?", (incident_id,)).fetchone()
    return _decode_action_job(dict(row)) if row else None


def get_action_jobs_for_incidents(incident_ids: set[int]) -> dict[int, dict[str, Any]]:
    if not incident_ids:
        return {}
    placeholders = ",".join("?" for _ in incident_ids)
    with connect() as conn:
        rows = conn.execute(
            f"select * from action_jobs where incident_id in ({placeholders})",
            tuple(sorted(incident_ids)),
        ).fetchall()
    decoded = [_decode_action_job(dict(row)) for row in rows]
    return {job["incident_id"]: job for job in decoded}


def list_action_jobs_for_site(site_id: str, limit: int = 25) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "select * from action_jobs where site_id = ? order by id desc limit ?",
            (site_id, max(1, min(limit, 100))),
        ).fetchall()
    return [_decode_action_job(dict(row)) for row in rows]


def approve_and_queue_action(
    incident_id: int,
    approved_by: str,
    channel: str,
    note: str | None,
) -> dict[str, Any]:
    """Durably record human approval before making the MCP action job executable."""
    now = utc_now()
    with connect() as conn:
        if database_backend() == "sqlite":
            conn.execute("begin immediate")
        incident = _locked_incident(conn, incident_id)
        if not incident:
            raise ValueError("Incident not found")
        if incident["status"] == "rejected":
            raise ValueError("Rejected incidents cannot be approved")
        job = conn.execute("select * from action_jobs where incident_id = ?", (incident_id,)).fetchone()
        if not job:
            raise ValueError("This incident has no executable action job")
        if incident["status"] == "approved":
            decision = conn.execute(
                "select * from approval_decisions where incident_id = ? and decision = 'approved' order by id desc limit 1",
                (incident_id,),
            ).fetchone()
            return {
                "incident": _decode_incident(dict(incident)),
                "decision": dict(decision) if decision else None,
                "action_job": _decode_action_job(dict(job)),
                "already_final": True,
            }
        if incident["status"] != "needs_review" or job["status"] != "awaiting_approval":
            raise ValueError("This incident can no longer be approved")

        updated = conn.execute(
            "update incidents set status = 'approved', updated_at = ? where id = ? and status = 'needs_review' returning *",
            (now, incident_id),
        ).fetchone()
        decision_id = conn.execute(
            """
            insert into approval_decisions (
                incident_id, site_id, actor, channel, decision, note,
                previous_status, resulting_status, created_at
            ) values (?, ?, ?, ?, 'approved', ?, 'needs_review', 'approved', ?) returning id
            """,
            (incident_id, incident["site_id"], approved_by, channel, note, now),
        ).fetchone()["id"]
        queued = conn.execute(
            """
            update action_jobs
            set approval_decision_id = ?, status = 'queued', current_step = 'queued', error = null, updated_at = ?
            where id = ? and status = 'awaiting_approval'
            returning *
            """,
            (decision_id, now, job["id"]),
        ).fetchone()
        if not queued:
            raise RuntimeError("The approved action could not be queued")
        conn.execute(
            "update approval_tokens set consumed_at = ? where incident_id = ? and consumed_at is null",
            (now, incident_id),
        )
        decision = conn.execute("select * from approval_decisions where id = ?", (decision_id,)).fetchone()
    return {
        "incident": _decode_incident(dict(updated)),
        "decision": dict(decision),
        "action_job": _decode_action_job(dict(queued)),
    }


def reject_action(
    incident_id: int,
    rejected_by: str,
    channel: str,
    note: str | None,
) -> dict[str, Any]:
    """Durably reject an action and make its agent job permanently unclaimable."""
    now = utc_now()
    with connect() as conn:
        if database_backend() == "sqlite":
            conn.execute("begin immediate")
        incident = _locked_incident(conn, incident_id)
        if not incident:
            raise ValueError("Incident not found")
        job = conn.execute("select * from action_jobs where incident_id = ?", (incident_id,)).fetchone()
        if incident["status"] == "rejected":
            return {
                "incident": _decode_incident(dict(incident)),
                "action_job": _decode_action_job(dict(job)) if job else None,
                "already_final": True,
            }
        if incident["status"] != "needs_review":
            raise ValueError("Only an action waiting for review can be rejected")
        updated = conn.execute(
            "update incidents set status = 'rejected', updated_at = ? where id = ? and status = 'needs_review' returning *",
            (now, incident_id),
        ).fetchone()
        decision_id = conn.execute(
            """
            insert into approval_decisions (
                incident_id, site_id, actor, channel, decision, note,
                previous_status, resulting_status, created_at
            ) values (?, ?, ?, ?, 'rejected', ?, 'needs_review', 'rejected', ?) returning id
            """,
            (incident_id, incident["site_id"], rejected_by, channel, note, now),
        ).fetchone()["id"]
        rejected_job = None
        if job:
            rejected_job = conn.execute(
                """
                update action_jobs set status = 'rejected', current_step = 'rejected',
                    approval_decision_id = ?, claimed_at = null, updated_at = ?
                where id = ? and status = 'awaiting_approval' returning *
                """,
                (decision_id, now, job["id"]),
            ).fetchone()
        conn.execute(
            "update approval_tokens set consumed_at = ? where incident_id = ? and consumed_at is null",
            (now, incident_id),
        )
        decision = conn.execute("select * from approval_decisions where id = ?", (decision_id,)).fetchone()
    return {
        "incident": _decode_incident(dict(updated)),
        "decision": dict(decision),
        "action_job": _decode_action_job(dict(rejected_job)) if rejected_job else None,
    }


def claim_next_action_job() -> dict[str, Any] | None:
    """Atomically claim the next queued MCP action for the single action worker."""
    now = utc_now()
    with connect() as conn:
        if database_backend() == "postgresql":
            row = conn.execute(
                """
                with next_job as (
                    select id from action_jobs where status = 'queued'
                    order by id for update skip locked limit 1
                )
                update action_jobs
                set status = 'running', current_step = 'executor', attempt_count = attempt_count + 1,
                    claimed_at = ?, updated_at = ?
                where id = (select id from next_job)
                returning *
                """,
                (now, now),
            ).fetchone()
        else:
            conn.execute("begin immediate")
            next_row = conn.execute(
                "select id from action_jobs where status = 'queued' order by id limit 1"
            ).fetchone()
            if not next_row:
                return None
            row = conn.execute(
                """
                update action_jobs
                set status = 'running', current_step = 'executor', attempt_count = attempt_count + 1,
                    claimed_at = ?, updated_at = ?
                where id = ? and status = 'queued' returning *
                """,
                (now, now, next_row["id"]),
            ).fetchone()
    return _decode_action_job(dict(row)) if row else None


def update_action_job_step(action_job_id: int, step: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "update action_jobs set current_step = ?, updated_at = ? where id = ? and status = 'running' returning *",
            (step, utc_now(), action_job_id),
        ).fetchone()
    return _decode_action_job(dict(row)) if row else None


def begin_action_tool_call(action_job_id: int, tool_name: str) -> dict[str, Any]:
    """Atomically grant the one MCP invocation allowed for this executor attempt."""
    with connect() as conn:
        row = conn.execute(
            """
            update action_jobs set current_step = 'mcp_tool_running', updated_at = ?
            where id = ? and status = 'running' and current_step = 'executor'
                and tool_name = ? and result_json = '{}'
            returning *
            """,
            (utc_now(), action_job_id, tool_name),
        ).fetchone()
    if not row:
        raise ValueError("The assigned MCP action tool cannot be invoked again")
    return _decode_action_job(dict(row))


def record_action_tool_result(
    action_job_id: int,
    tool_name: str,
    tool_result: dict[str, Any],
) -> dict[str, Any]:
    """Durably receipt the MCP call before Qwen writes its final response."""
    job = get_action_job(action_job_id)
    if not job or job["status"] != "running" or job["tool_name"] != tool_name:
        raise ValueError("The MCP result does not match a running action job")
    if job.get("result", {}).get("tool_invoked"):
        raise ValueError("The assigned MCP action tool has already been invoked")
    receipt = {"tool": tool_name, "tool_invoked": True, "tool_result": tool_result}
    with connect() as conn:
        row = conn.execute(
            """
            update action_jobs set result_json = ?, current_step = 'mcp_tool_complete', updated_at = ?
            where id = ? and status = 'running' and tool_name = ? returning *
            """,
            (json.dumps(receipt, default=str), utc_now(), action_job_id, tool_name),
        ).fetchone()
    if not row:
        raise RuntimeError("The MCP tool receipt could not be persisted")
    return _decode_action_job(dict(row))


def complete_action_job(action_job_id: int, result: dict[str, Any]) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            """
            update action_jobs set status = 'succeeded', current_step = 'complete', result_json = ?,
                error = null, claimed_at = null, updated_at = ?
            where id = ? and status = 'running' returning *
            """,
            (json.dumps(result, default=str), utc_now(), action_job_id),
        ).fetchone()
    return _decode_action_job(dict(row)) if row else None


def fail_action_job(action_job_id: int, error: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            """
            update action_jobs set status = 'failed', current_step = 'failed', error = ?,
                claimed_at = null, updated_at = ?
            where id = ? and status = 'running' returning *
            """,
            (error, utc_now(), action_job_id),
        ).fetchone()
    return _decode_action_job(dict(row)) if row else None


def retry_action_job(action_job_id: int, max_attempts: int = 3) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            """
            update action_jobs set status = 'queued', current_step = 'queued', error = null,
                claimed_at = null, updated_at = ?
            where id = ? and status = 'failed' and attempt_count < ? returning *
            """,
            (utc_now(), action_job_id, max_attempts),
        ).fetchone()
    return _decode_action_job(dict(row)) if row else None


def requeue_stale_action_jobs(max_attempts: int = 3) -> dict[str, int]:
    now = utc_now()
    with connect() as conn:
        failed = conn.execute(
            """
            update action_jobs set status = 'failed', current_step = 'failed',
                error = 'Action agent stopped repeatedly before completion', claimed_at = null, updated_at = ?
            where status = 'running' and attempt_count >= ?
            """,
            (now, max_attempts),
        ).rowcount
        requeued = conn.execute(
            """
            update action_jobs set status = 'queued', current_step = 'recovered', error = null,
                claimed_at = null, updated_at = ? where status = 'running'
            """,
            (now,),
        ).rowcount
    return {"requeued": requeued, "failed": failed}


def _locked_incident(conn: Any, incident_id: int):
    suffix = " for update" if getattr(conn, "dialect", "sqlite") == "postgresql" else ""
    return conn.execute(f"select * from incidents where id = ?{suffix}", (incident_id,)).fetchone()


def _decode_incident(row: dict[str, Any]) -> dict[str, Any]:
    row["recommended_action"] = json.loads(row.pop("recommended_action_json", "{}") or "{}")
    return row


def _decode_action_job(row: dict[str, Any]) -> dict[str, Any]:
    row["requires_approval"] = bool(row.get("requires_approval"))
    row["result"] = json.loads(row.pop("result_json", "{}") or "{}")
    return row
