from __future__ import annotations

import secrets
from typing import Any


def apply(conn: Any) -> None:
    """Replace the deployment-bound Alibaba table with customer role authorization."""
    rows = conn.execute(
        "select site_id, region, security_group_id, sls_endpoint, sls_project, sls_logstore, "
        "enforcement_mode, created_at, updated_at from site_alibaba_autopilot_configs"
    ).fetchall()
    conn.execute("alter table site_alibaba_autopilot_configs rename to site_alibaba_autopilot_configs_v3")
    conn.execute(
        """
        create table site_alibaba_autopilot_configs (
            site_id text primary key,
            role_arn text,
            external_id text not null unique,
            account_id text,
            connection_status text not null default 'pending',
            connection_error text,
            verified_at text,
            region text not null,
            security_group_id text,
            sls_endpoint text,
            sls_project text,
            sls_logstore text,
            enforcement_mode text not null,
            created_at text not null,
            updated_at text not null,
            foreign key (site_id) references sites(site_id) on delete cascade,
            check (connection_status in ('pending', 'verified', 'error'))
        )
        """
    )
    for row in rows:
        conn.execute(
            """
            insert into site_alibaba_autopilot_configs (
                site_id, role_arn, external_id, account_id, connection_status, connection_error,
                verified_at, region, security_group_id, sls_endpoint, sls_project, sls_logstore,
                enforcement_mode, created_at, updated_at
            ) values (?, null, ?, null, 'pending', ?, null, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["site_id"],
                f"secai-migrated-{secrets.token_urlsafe(24)}",
                "Reconnect Alibaba Cloud to authorize this website with its customer role.",
                row["region"],
                row["security_group_id"],
                row["sls_endpoint"],
                row["sls_project"],
                row["sls_logstore"],
                row["enforcement_mode"],
                row["created_at"],
                row["updated_at"],
            ),
        )
    conn.execute("drop table site_alibaba_autopilot_configs_v3")
