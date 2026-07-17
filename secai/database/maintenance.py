from __future__ import annotations

from datetime import UTC, datetime, timedelta

from secai import database
from secai.settings import get_settings


def purge_expired_data(retention_days: int | None = None) -> dict[str, int]:
    """Delete expired sessions and terminal records beyond the retention window."""
    days = max(1, retention_days or get_settings().secai_data_retention_days)
    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    now = database.utc_now()
    with database.connect() as conn:
        conn.execute("begin immediate")
        counts = {
            "sessions": conn.execute("delete from sessions where expires_at <= ?", (now,)).rowcount,
            "approval_tokens": conn.execute(
                "delete from approval_tokens where consumed_at is not null or expires_at <= ?",
                (now,),
            ).rowcount,
        }
        counts["incidents"] = conn.execute(
            """
            delete from incidents where updated_at < ?
              and status in ('reported', 'approved', 'rejected')
              and not exists (
                select 1 from policies where policies.incident_id = incidents.id
                  and policies.status in ('pending', 'applying', 'active', 'revoking')
              )
            """,
            (cutoff,),
        ).rowcount
        counts["events"] = conn.execute(
            """
            delete from events where created_at < ?
              and not exists (
                select 1 from analysis_jobs where analysis_jobs.event_id = events.id
                  and analysis_jobs.status in ('queued', 'running')
              )
            """,
            (cutoff,),
        ).rowcount
    return counts
