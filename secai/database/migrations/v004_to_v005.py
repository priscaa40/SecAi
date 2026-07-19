from __future__ import annotations

from typing import Any


def apply(conn: Any) -> None:
    """Persist the evidence source selected for each existing website."""
    conn.execute(
        "alter table sites add column evidence_source text not null default 'browser' "
        "check (evidence_source in ('browser', 'alibaba_autopilot'))"
    )
    conn.execute(
        """
        update sites
        set evidence_source = 'alibaba_autopilot'
        where exists (
            select 1 from site_alibaba_autopilot_configs config
            where config.site_id = sites.site_id
        )
        """
    )
    if getattr(conn, "dialect", "sqlite") == "postgresql":
        conn.execute("alter table sites alter column evidence_source drop default")
