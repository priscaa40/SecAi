from __future__ import annotations

from typing import Any


def apply(conn: Any) -> None:
    """Require a verified LoongCollector installation for Alibaba evidence."""
    if getattr(conn, "dialect", "sqlite") == "postgresql":
        exists = conn.execute(
            "select 1 from information_schema.tables where table_schema = current_schema() "
            "and table_name = 'site_alibaba_autopilot_configs'"
        ).fetchone()
    else:
        exists = conn.execute(
            "select 1 from sqlite_master where type = 'table' and name = 'site_alibaba_autopilot_configs'"
        ).fetchone()
    if not exists:
        return
    for statement in (
        "alter table site_alibaba_autopilot_configs add column ecs_instance_id text",
        "alter table site_alibaba_autopilot_configs add column collector_status text not null default 'not_configured'",
        "alter table site_alibaba_autopilot_configs add column collector_error text",
        "alter table site_alibaba_autopilot_configs add column collector_machine_group text",
        "alter table site_alibaba_autopilot_configs add column collector_config_name text",
        "alter table site_alibaba_autopilot_configs add column collector_verified_at text",
    ):
        conn.execute(statement)
