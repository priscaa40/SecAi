from __future__ import annotations

from typing import Any

from secai.database._utils import utc_now
from secai.database.connection import connect, database_backend


def create_analysis_job(event_id: int, site_id: str, status: str = "queued") -> dict[str, Any]:
    """Create a job that tracks analysis progress for an event."""
    now = utc_now()
    with connect() as conn:
        cursor = conn.execute(
            """
            insert into analysis_jobs (
                event_id, site_id, status, current_step, error, incident_id,
                attempt_count, claimed_at, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) returning id
            """,
            (event_id, site_id, status, None, None, None, 0, None, now, now),
        )
        job_id = cursor.fetchone()["id"]
    if job_id is None:
        raise RuntimeError("Failed to assign analysis job ID")
    return get_analysis_job(job_id) or {
        "id": job_id,
        "event_id": event_id,
        "site_id": site_id,
        "status": status,
        "current_step": None,
        "error": None,
        "incident_id": None,
        "attempt_count": 0,
        "claimed_at": None,
        "created_at": now,
        "updated_at": now,
    }


def get_analysis_job(job_id: int) -> dict[str, Any] | None:
    """Fetch one analysis job by ID."""
    with connect() as conn:
        row = conn.execute("select * from analysis_jobs where id = ?", (job_id,)).fetchone()
    return dict(row) if row else None


def get_analysis_job_for_event(event_id: int) -> dict[str, Any] | None:
    """Fetch the latest analysis job for an event."""
    with connect() as conn:
        row = conn.execute(
            "select * from analysis_jobs where event_id = ? order by id desc limit 1",
            (event_id,),
        ).fetchone()
    return dict(row) if row else None


def list_analysis_jobs_for_site(site_id: str, limit: int = 25) -> list[dict[str, Any]]:
    """Return recent analysis work so the dashboard can show progress and failures."""
    with connect() as conn:
        rows = conn.execute(
            "select * from analysis_jobs where site_id = ? order by id desc limit ?",
            (site_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def claim_next_analysis_job() -> dict[str, Any] | None:
    """Atomically claim the oldest queued analysis job for the single worker."""
    now = utc_now()
    with connect() as conn:
        if database_backend() == "postgresql":
            row = conn.execute(
                """
                with next_job as (
                    select analysis_jobs.id from analysis_jobs
                    join events on events.id = analysis_jobs.event_id
                    where analysis_jobs.status = 'queued' and analysis_jobs.incident_id is null
                    order by case when events.source = 'alibaba_sls' then 0 else 1 end, analysis_jobs.id
                    for update skip locked
                    limit 1
                )
                update analysis_jobs
                set status = 'running', current_step = 'starting', error = null,
                    attempt_count = attempt_count + 1, claimed_at = ?, updated_at = ?
                where id = (select id from next_job)
                returning *
                """,
                (now, now),
            ).fetchone()
        else:
            conn.execute("begin immediate")
            next_row = conn.execute(
                """
                select analysis_jobs.id from analysis_jobs
                join events on events.id = analysis_jobs.event_id
                where analysis_jobs.status = 'queued' and analysis_jobs.incident_id is null
                order by case when events.source = 'alibaba_sls' then 0 else 1 end, analysis_jobs.id
                limit 1
                """
            ).fetchone()
            if not next_row:
                return None
            row = conn.execute(
                """
                update analysis_jobs
                set status = 'running', current_step = 'starting', error = null,
                    attempt_count = attempt_count + 1, claimed_at = ?, updated_at = ?
                where id = ? and status = 'queued' and incident_id is null
                returning *
                """,
                (now, now, next_row["id"]),
            ).fetchone()
    return dict(row) if row else None


def requeue_stale_analysis_jobs(max_attempts: int = 3) -> dict[str, int]:
    """Recover jobs left running by a stopped process before the worker starts."""
    now = utc_now()
    with connect() as conn:
        completed = conn.execute(
            """
            update analysis_jobs
            set status = 'incident_created', current_step = 'complete', error = null,
                claimed_at = null, updated_at = ?
            where incident_id is not null and status != 'incident_created'
            """,
            (now,),
        ).rowcount
        failed = conn.execute(
            """
            update analysis_jobs
            set status = 'failed', current_step = 'stopped',
                error = 'Analysis stopped repeatedly before completion', claimed_at = null, updated_at = ?
            where status = 'running' and incident_id is null and attempt_count >= ?
            """,
            (now, max_attempts),
        ).rowcount
        requeued = conn.execute(
            """
            update analysis_jobs
            set status = 'queued', current_step = 'recovered', error = null,
                claimed_at = null, updated_at = ?
            where status = 'running' and incident_id is null
            """,
            (now,),
        ).rowcount
    return {"completed": completed, "requeued": requeued, "failed": failed}


def retry_analysis_job(job_id: int, max_attempts: int = 3) -> dict[str, Any] | None:
    """Atomically return a failed analysis job to the queue when retries remain."""
    with connect() as conn:
        row = conn.execute(
            """
            update analysis_jobs
            set status = 'queued', current_step = 'queued', error = null,
                claimed_at = null, updated_at = ?
            where id = ? and status = 'failed' and incident_id is null and attempt_count < ?
            returning *
            """,
            (utc_now(), job_id, max_attempts),
        ).fetchone()
    return dict(row) if row else None


def update_analysis_job(
    job_id: int,
    status: str | None = None,
    current_step: str | None = None,
    error: str | None = None,
) -> dict[str, Any] | None:
    """Update a job that has not already produced an incident."""
    updates = ["updated_at = ?"]
    values: list[Any] = [utc_now()]
    for column, value in (
        ("status", status),
        ("current_step", current_step),
        ("error", error),
    ):
        if value is not None:
            updates.append(f"{column} = ?")
            values.append(value)
    if status in {"filtered", "no_incident", "incident_created", "failed"}:
        updates.append("claimed_at = null")
    values.append(job_id)
    with connect() as conn:
        row = conn.execute(
            f"update analysis_jobs set {', '.join(updates)} where id = ? and incident_id is null returning *",
            tuple(values),
        ).fetchone()
    return dict(row) if row else None


def insert_qwen_usage(usage: dict[str, Any]) -> dict[str, Any]:
    """Store token, model, and latency data for a Qwen call."""
    created_at = utc_now()
    with connect() as conn:
        cursor = conn.execute(
            """
            insert into qwen_usage (
                job_id, event_id, incident_id, agent_name, model, input_tokens,
                output_tokens, total_tokens, model_calls, latency_ms, error_message, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) returning id
            """,
            (
                usage.get("job_id"),
                usage.get("event_id"),
                usage.get("incident_id"),
                usage["agent_name"],
                usage["model"],
                usage.get("input_tokens"),
                usage.get("output_tokens"),
                usage.get("total_tokens"),
                usage.get("model_calls", 1),
                usage["latency_ms"],
                usage.get("error_message"),
                created_at,
            ),
        )
        usage_id = cursor.fetchone()["id"]
    return {**usage, "id": usage_id, "created_at": created_at}


def list_qwen_usage_for_sites(site_ids: list[str], limit: int = 100) -> list[dict[str, Any]]:
    """List Qwen usage records scoped to owned sites."""
    if not site_ids:
        return []
    placeholders = ",".join("?" for _ in site_ids)
    with connect() as conn:
        rows = conn.execute(
            f"""
            select qwen_usage.*
            from qwen_usage
            left join analysis_jobs on analysis_jobs.id = qwen_usage.job_id
            left join events on events.id = qwen_usage.event_id
            where coalesce(analysis_jobs.site_id, events.site_id) in ({placeholders})
            order by qwen_usage.id desc
            limit ?
            """,
            (*site_ids, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def summarize_qwen_usage_for_sites(site_ids: list[str]) -> dict[str, Any]:
    """Return aggregate Qwen usage scoped to owned sites."""
    if not site_ids:
        return {
            "calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "avg_latency_ms": 0,
        }
    placeholders = ",".join("?" for _ in site_ids)
    with connect() as conn:
        row = conn.execute(
            f"""
            select
                coalesce(sum(qwen_usage.model_calls), 0) as calls,
                coalesce(sum(qwen_usage.input_tokens), 0) as input_tokens,
                coalesce(sum(qwen_usage.output_tokens), 0) as output_tokens,
                coalesce(sum(qwen_usage.total_tokens), 0) as total_tokens,
                coalesce(avg(qwen_usage.latency_ms), 0) as avg_latency_ms
            from qwen_usage
            left join analysis_jobs on analysis_jobs.id = qwen_usage.job_id
            left join events on events.id = qwen_usage.event_id
            where coalesce(analysis_jobs.site_id, events.site_id) in ({placeholders})
            """,
            tuple(site_ids),
        ).fetchone()
    return dict(row)
