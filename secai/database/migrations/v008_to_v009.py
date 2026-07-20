from __future__ import annotations

from typing import Any


def apply(conn: Any) -> None:
    """Remember whether the collector stack should create the selected Logstore index."""
    if getattr(conn, "dialect", "sqlite") == "postgresql":
        exists = conn.execute(
            "select 1 from information_schema.tables where table_schema = current_schema() "
            "and table_name = 'site_alibaba_autopilot_configs'"
        ).fetchone()
    else:
        exists = conn.execute(
            "select 1 from sqlite_master where type = 'table' and name = 'site_alibaba_autopilot_configs'"
        ).fetchone()
    if exists:
        conn.execute(
            "alter table site_alibaba_autopilot_configs "
            "add column collector_create_index integer not null default 0"
        )
