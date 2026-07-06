from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from secai.settings import get_settings


def utc_now() -> str:
    """Return the current UTC time as an ISO string."""
    return datetime.now(timezone.utc).isoformat()


def _db_path() -> str:
    """Return the SQLite file path from DATABASE_URL."""
    database_url = get_settings().database_url
    if database_url.startswith("sqlite:///"):
        return database_url.replace("sqlite:///", "", 1)
    return "secai.db"


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    """Open a SQLite connection and commit changes when done."""
    path = _db_path()
    if path not in (":memory:", ""):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("pragma busy_timeout = 5000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create local database tables if they do not already exist."""
    with connect() as conn:
        if _db_path() not in (":memory:", ""):
            conn.execute("pragma journal_mode = WAL")
        conn.executescript(
            """
            create table if not exists sites (
                site_id text primary key,
                name text not null,
                owner_email text,
                ingest_key text not null,
                created_at text not null
            );

            create table if not exists users (
                id integer primary key autoincrement,
                email text not null unique,
                password_hash text not null,
                created_at text not null
            );

            create table if not exists sessions (
                token text primary key,
                user_id integer not null,
                created_at text not null,
                expires_at text not null
            );

            create table if not exists events (
                id integer primary key autoincrement,
                site_id text not null,
                source text not null,
                event_type text not null,
                event_fingerprint text,
                method text,
                path text,
                query text,
                status_code integer,
                ip text,
                user_agent text,
                payload text,
                signals_json text not null,
                metadata_json text not null,
                created_at text not null
            );

            create table if not exists incidents (
                id integer primary key autoincrement,
                site_id text not null,
                title text not null,
                severity text not null,
                status text not null,
                attack_type text not null,
                affected_route text,
                confidence real not null,
                report text not null,
                recommended_action_json text not null,
                approval_token text,
                created_at text not null,
                updated_at text not null
            );

            create table if not exists policies (
                id integer primary key autoincrement,
                site_id text not null,
                action text not null,
                target text not null,
                reason text not null,
                incident_id integer,
                provider text,
                provider_rule_id text,
                parameters_json text not null default '{}',
                status text not null default 'pending',
                applied_at text,
                error_message text,
                expires_at text,
                created_at text not null
            );

            create table if not exists remediation_executions (
                id integer primary key autoincrement,
                site_id text not null,
                policy_id integer,
                incident_id integer,
                provider text not null,
                action text not null,
                target text not null,
                status text not null,
                request_json text not null,
                response_json text not null,
                error_message text,
                created_at text not null
            );

            create table if not exists analysis_jobs (
                id integer primary key autoincrement,
                event_id integer not null,
                site_id text not null,
                status text not null,
                current_step text,
                error text,
                incident_id integer,
                created_at text not null,
                updated_at text not null
            );

            create table if not exists qwen_usage (
                id integer primary key autoincrement,
                job_id integer,
                event_id integer,
                incident_id integer,
                agent_name text not null,
                model text not null,
                input_tokens integer,
                output_tokens integer,
                total_tokens integer,
                latency_ms integer not null,
                estimated_cost_usd real,
                created_at text not null
            );

            create table if not exists remediation_preferences (
                site_id text not null,
                action text not null,
                requires_approval integer not null,
                updated_at text not null,
                primary key (site_id, action)
            );

            create table if not exists site_sls_configs (
                site_id text primary key,
                endpoint text not null,
                project text not null,
                logstore text not null,
                role_arn text not null,
                encrypted_external_id text not null,
                created_at text not null,
                updated_at text not null
            );

            create table if not exists site_alibaba_autopilot_configs (
                site_id text primary key,
                role_arn text not null,
                encrypted_external_id text not null,
                region text not null,
                waf_instance_id text,
                waf_domain text,
                waf_template_id integer,
                sls_endpoint text,
                sls_project text,
                sls_logstore text,
                enforcement_mode text not null,
                created_at text not null,
                updated_at text not null
            );

            create table if not exists site_report_channels (
                site_id text not null,
                channel text not null,
                enabled integer not null,
                config_json text not null,
                created_at text not null,
                updated_at text not null,
                primary key (site_id, channel)
            );
            """
        )
        _ensure_session_columns(conn)
        _ensure_event_indexes(conn)
        _ensure_common_indexes(conn)
        _ensure_policy_columns(conn)


def _session_expires_at() -> str:
    """Return the expiry timestamp for a newly issued owner session."""
    ttl_hours = max(1, get_settings().secai_session_ttl_hours)
    return (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()


def _ensure_session_columns(conn: sqlite3.Connection) -> None:
    """Add expiry metadata for databases created before sessions expired."""
    columns = {row["name"] for row in conn.execute("pragma table_info(sessions)").fetchall()}
    if "expires_at" not in columns:
        conn.execute("alter table sessions add column expires_at text")
        conn.execute("update sessions set expires_at = ?", (_session_expires_at(),))


def _ensure_event_indexes(conn: sqlite3.Connection) -> None:
    """Ensure normalized event identity is available for idempotent ingest."""
    columns = {row["name"] for row in conn.execute("pragma table_info(events)").fetchall()}
    if "event_fingerprint" not in columns:
        conn.execute("alter table events add column event_fingerprint text")
    conn.execute(
        """
        create unique index if not exists idx_events_site_fingerprint
        on events(site_id, event_fingerprint)
        where event_fingerprint is not null
        """
    )


def _ensure_common_indexes(conn: sqlite3.Connection) -> None:
    """Create query indexes used by incident views, event context, and recovery."""
    conn.execute("create index if not exists idx_events_site_id on events(site_id, id desc)")
    conn.execute("create index if not exists idx_incidents_site_id on incidents(site_id, id desc)")
    conn.execute("create index if not exists idx_analysis_jobs_event_id on analysis_jobs(event_id)")
    conn.execute("create index if not exists idx_sessions_expires_at on sessions(expires_at)")


def _ensure_policy_columns(conn: sqlite3.Connection) -> None:
    """Add policy execution fields for databases created by older SecAi builds."""
    columns = {row["name"] for row in conn.execute("pragma table_info(policies)").fetchall()}
    additions = {
        "provider": "text",
        "provider_rule_id": "text",
        "parameters_json": "text not null default '{}'",
        "status": "text not null default 'pending'",
        "applied_at": "text",
        "error_message": "text",
        "expires_at": "text",
    }
    for column, definition in additions.items():
        if column not in columns:
            conn.execute(f"alter table policies add column {column} {definition}")


def create_site(name: str, owner_email: str | None = None) -> dict[str, Any]:
    """Create a monitored site and generate its ingest key."""
    site_id = f"site_{secrets.token_hex(6)}"
    ingest_key = f"sk_{secrets.token_urlsafe(24)}"
    with connect() as conn:
        conn.execute(
            "insert into sites (site_id, name, owner_email, ingest_key, created_at) values (?, ?, ?, ?, ?)",
            (site_id, name, owner_email, ingest_key, utc_now()),
        )
    return {"site_id": site_id, "name": name, "owner_email": owner_email, "ingest_key": ingest_key}


def create_user(email: str, password_hash: str) -> dict[str, Any]:
    """Create a website owner account."""
    created_at = utc_now()
    normalized_email = email.strip().lower()
    with connect() as conn:
        cursor = conn.execute(
            "insert into users (email, password_hash, created_at) values (?, ?, ?)",
            (normalized_email, password_hash, created_at),
        )
        user_id = cursor.lastrowid
    return {"id": user_id, "email": normalized_email, "created_at": created_at}


def get_user_by_email(email: str) -> dict[str, Any] | None:
    """Fetch one user by email."""
    with connect() as conn:
        row = conn.execute("select * from users where email = ?", (email.strip().lower(),)).fetchone()
    return dict(row) if row else None


def get_user_by_session(token: str) -> dict[str, Any] | None:
    """Fetch the user attached to a session token."""
    with connect() as conn:
        row = conn.execute(
            """
            select users.id, users.email, users.created_at, sessions.expires_at
            from sessions
            join users on users.id = sessions.user_id
            where sessions.token = ?
            """,
            (token,),
        ).fetchone()
        if row and row["expires_at"] <= utc_now():
            conn.execute("delete from sessions where token = ?", (token,))
            return None
    return dict(row) if row else None


def create_session(user_id: int) -> dict[str, Any]:
    """Create an authenticated session token for a user."""
    token = secrets.token_urlsafe(32)
    created_at = utc_now()
    expires_at = _session_expires_at()
    with connect() as conn:
        conn.execute(
            "insert into sessions (token, user_id, created_at, expires_at) values (?, ?, ?, ?)",
            (token, user_id, created_at, expires_at),
        )
    return {"token": token, "user_id": user_id, "created_at": created_at, "expires_at": expires_at}


def delete_session(token: str) -> None:
    """Delete a session token."""
    with connect() as conn:
        conn.execute("delete from sessions where token = ?", (token,))


def delete_user(user_id: int) -> None:
    """Delete a user and any login sessions created during failed setup."""
    with connect() as conn:
        conn.execute("delete from sessions where user_id = ?", (user_id,))
        conn.execute("delete from users where id = ?", (user_id,))


def get_site(site_id: str) -> dict[str, Any] | None:
    """Fetch one site by site ID."""
    with connect() as conn:
        row = conn.execute("select * from sites where site_id = ?", (site_id,)).fetchone()
    return dict(row) if row else None


def delete_site(site_id: str) -> None:
    """Delete a site and setup records created during a failed onboarding run."""
    with connect() as conn:
        for table in (
            "remediation_executions",
            "site_alibaba_autopilot_configs",
            "site_report_channels",
            "site_sls_configs",
            "remediation_preferences",
            "analysis_jobs",
            "policies",
            "incidents",
            "events",
        ):
            conn.execute(f"delete from {table} where site_id = ?", (site_id,))
        conn.execute("delete from sites where site_id = ?", (site_id,))


def public_site_script_config(site_id: str) -> dict[str, Any] | None:
    """Return only the site fields needed to render the browser snippet."""
    site = get_site(site_id)
    if not site:
        return None
    return {"site_id": site["site_id"], "ingest_key": site["ingest_key"]}


def list_sites(owner_email: str | None = None) -> list[dict[str, Any]]:
    """List monitored sites, optionally filtered by owner email."""
    query = "select * from sites"
    params: tuple[Any, ...] = ()
    if owner_email:
        query += " where owner_email = ?"
        params = (owner_email,)
    query += " order by created_at desc"
    with connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def user_owns_site(site_id: str, owner_email: str) -> bool:
    """Return whether a site belongs to the given owner email."""
    site = get_site(site_id)
    return bool(site and site.get("owner_email") == owner_email)


def ensure_demo_site() -> dict[str, Any]:
    """Create the built-in demo site if it does not exist."""
    with connect() as conn:
        row = conn.execute("select * from sites where site_id = ?", ("demo-site",)).fetchone()
        if row:
            return dict(row)
        ingest_key = "demo-key"
        conn.execute(
            "insert into sites (site_id, name, owner_email, ingest_key, created_at) values (?, ?, ?, ?, ?)",
            ("demo-site", "Demo Web Shop", "owner@example.com", ingest_key, utc_now()),
        )
    return {"site_id": "demo-site", "name": "Demo Web Shop", "owner_email": "owner@example.com", "ingest_key": "demo-key"}


def ensure_demo_user(password_hash: str) -> dict[str, Any]:
    """Create or reset the built-in demo owner account."""
    email = "owner@example.com"
    existing = get_user_by_email(email)
    if existing:
        with connect() as conn:
            conn.execute("update users set password_hash = ? where email = ?", (password_hash, email))
        return get_user_by_email(email) or existing
    return create_user(email, password_hash)


def verify_ingest_key(site_id: str, ingest_key: str | None) -> bool:
    """Return whether an ingest key is valid for a site."""
    site = get_site(site_id)
    return bool(site and ingest_key and secrets.compare_digest(site["ingest_key"], ingest_key))


def insert_event(event: dict[str, Any]) -> dict[str, Any]:
    """Store one normalized event."""
    created_at = utc_now()
    fingerprint = event.get("event_fingerprint") or _event_fingerprint(event)
    metadata = dict(event.get("metadata", {}))
    if fingerprint:
        metadata.setdefault("secai", {})["event_fingerprint"] = fingerprint
    with connect() as conn:
        try:
            cursor = conn.execute(
                """
                insert into events (
                    site_id, source, event_type, event_fingerprint, method, path, query, status_code, ip,
                    user_agent, payload, signals_json, metadata_json, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["site_id"],
                    event["source"],
                    event["event_type"],
                    fingerprint,
                    event.get("method"),
                    event.get("path"),
                    event.get("query"),
                    event.get("status_code"),
                    event.get("ip"),
                    event.get("user_agent"),
                    event.get("payload"),
                    json.dumps(event.get("signals", [])),
                    json.dumps(metadata),
                    created_at,
                ),
            )
        except sqlite3.IntegrityError:
            if fingerprint:
                row = conn.execute(
                    "select * from events where site_id = ? and event_fingerprint = ?",
                    (event["site_id"], fingerprint),
                ).fetchone()
                if row:
                    existing = _decode_event(dict(row))
                    existing["_deduplicated"] = True
                    return existing
            raise
        event_id = cursor.lastrowid
    return {**event, "metadata": metadata, "event_fingerprint": fingerprint, "id": event_id, "created_at": created_at}


def recent_events(site_id: str, limit: int = 100) -> list[dict[str, Any]]:
    """Return recent normalized events for a site."""
    with connect() as conn:
        rows = conn.execute(
            "select * from events where site_id = ? order by id desc limit ?",
            (site_id, limit),
        ).fetchall()
    return [_decode_event(dict(row)) for row in rows]


def get_event(event_id: int) -> dict[str, Any] | None:
    """Fetch one normalized event by ID."""
    with connect() as conn:
        row = conn.execute("select * from events where id = ?", (event_id,)).fetchone()
    return _decode_event(dict(row)) if row else None


def _decode_event(row: dict[str, Any]) -> dict[str, Any]:
    """Decode stored event JSON fields into Python values."""
    row["signals"] = json.loads(row.pop("signals_json", "[]"))
    row["metadata"] = json.loads(row.pop("metadata_json", "{}"))
    return row


def _event_fingerprint(event: dict[str, Any]) -> str | None:
    """Return a stable identity for source records that can be pulled repeatedly."""
    if event.get("source") != "alibaba_sls":
        return None
    metadata = event.get("metadata") or {}
    source_payload = {
        "site_id": event.get("site_id"),
        "source": event.get("source"),
        "event_type": event.get("event_type"),
        "method": event.get("method"),
        "path": event.get("path"),
        "query": event.get("query"),
        "status_code": event.get("status_code"),
        "ip": event.get("ip"),
        "user_agent": event.get("user_agent"),
        "payload": event.get("payload"),
        "sls": metadata.get("sls") or {},
    }
    encoded = json.dumps(source_payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def insert_incident(incident: dict[str, Any]) -> dict[str, Any]:
    """Store an incident and assign an approval token."""
    now = utc_now()
    approval_token = incident.get("approval_token") or secrets.token_urlsafe(24)
    with connect() as conn:
        cursor = conn.execute(
            """
            insert into incidents (
                site_id, title, severity, status, attack_type, affected_route,
                confidence, report, recommended_action_json, approval_token, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident["site_id"],
                incident["title"],
                incident["severity"],
                incident.get("status", "needs_review"),
                incident["attack_type"],
                incident.get("affected_route"),
                incident["confidence"],
                incident["report"],
                json.dumps(incident["recommended_action"]),
                approval_token,
                now,
                now,
            ),
        )
        incident_id = cursor.lastrowid
    return {**incident, "approval_token": approval_token, "id": incident_id, "created_at": now, "updated_at": now}


def list_incidents(site_id: str | None = None) -> list[dict[str, Any]]:
    """List incidents, optionally filtered by site."""
    query = "select * from incidents"
    params: tuple[Any, ...] = ()
    if site_id:
        query += " where site_id = ?"
        params = (site_id,)
    query += " order by id desc"
    with connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_decode_incident(dict(row)) for row in rows]


def list_incidents_for_sites(site_ids: list[str]) -> list[dict[str, Any]]:
    """List incidents scoped to a set of owned site IDs."""
    if not site_ids:
        return []
    placeholders = ",".join("?" for _ in site_ids)
    with connect() as conn:
        rows = conn.execute(
            f"select * from incidents where site_id in ({placeholders}) order by id desc",
            tuple(site_ids),
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
        row = conn.execute("select * from incidents where approval_token = ?", (token,)).fetchone()
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


def consume_approval_token(incident_id: int) -> None:
    """Invalidate an incident approval token after a final decision."""
    now = utc_now()
    with connect() as conn:
        conn.execute("update incidents set approval_token = null, updated_at = ? where id = ?", (now, incident_id))


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
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        policy_id = cursor.lastrowid
    stored = get_policy(policy_id)
    if not stored:
        raise RuntimeError("Failed to store remediation policy")
    return stored


def update_policy_execution_state(
    policy_id: int,
    status: str,
    *,
    provider_rule_id: str | None = None,
    error_message: str | None = None,
) -> dict[str, Any]:
    """Update provider execution status for one remediation policy."""
    applied_at = utc_now() if status == "active" else None
    with connect() as conn:
        conn.execute(
            """
            update policies
            set status = ?, provider_rule_id = coalesce(?, provider_rule_id), applied_at = ?, error_message = ?
            where id = ?
            """,
            (status, provider_rule_id, applied_at, error_message, policy_id),
        )
    stored = get_policy(policy_id)
    if not stored:
        raise RuntimeError("Failed to update remediation policy")
    return stored


def get_policy(policy_id: int) -> dict[str, Any] | None:
    """Fetch one remediation policy by ID."""
    with connect() as conn:
        row = conn.execute("select * from policies where id = ?", (policy_id,)).fetchone()
    return _decode_policy(dict(row)) if row else None


def list_policies(site_id: str) -> list[dict[str, Any]]:
    """List approved policies for a site."""
    with connect() as conn:
        rows = conn.execute("select * from policies where site_id = ? order by id desc", (site_id,)).fetchall()
    return [_decode_policy(dict(row)) for row in rows]


def get_policy_for_incident(incident_id: int) -> dict[str, Any] | None:
    """Fetch the first policy created from an incident."""
    with connect() as conn:
        row = conn.execute("select * from policies where incident_id = ? order by id limit 1", (incident_id,)).fetchone()
    return _decode_policy(dict(row)) if row else None


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
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        execution_id = cursor.lastrowid
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


def create_analysis_job(event_id: int, site_id: str, status: str = "queued") -> dict[str, Any]:
    """Create a job that tracks analysis progress for an event."""
    now = utc_now()
    with connect() as conn:
        cursor = conn.execute(
            """
            insert into analysis_jobs (event_id, site_id, status, current_step, error, incident_id, created_at, updated_at)
            values (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, site_id, status, None, None, None, now, now),
        )
        job_id = cursor.lastrowid
    return get_analysis_job(job_id) or {
        "id": job_id,
        "event_id": event_id,
        "site_id": site_id,
        "status": status,
        "current_step": None,
        "error": None,
        "incident_id": None,
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
        row = conn.execute("select * from analysis_jobs where event_id = ? order by id desc limit 1", (event_id,)).fetchone()
    return dict(row) if row else None


def list_analysis_jobs(limit: int = 25) -> list[dict[str, Any]]:
    """List recent analysis jobs."""
    with connect() as conn:
        rows = conn.execute("select * from analysis_jobs order by id desc limit ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def list_unfinished_analysis_jobs(limit: int = 100) -> list[dict[str, Any]]:
    """Return jobs that should be resumed after a process restart."""
    with connect() as conn:
        rows = conn.execute(
            """
            select * from analysis_jobs
            where status in ('queued', 'running')
            order by id
            limit ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def update_analysis_job(
    job_id: int,
    status: str | None = None,
    current_step: str | None = None,
    error: str | None = None,
    incident_id: int | None = None,
) -> dict[str, Any] | None:
    """Update analysis job status, step, error, or incident link."""
    job = get_analysis_job(job_id)
    if not job:
        return None
    updated = {
        "status": status if status is not None else job["status"],
        "current_step": current_step if current_step is not None else job["current_step"],
        "error": error if error is not None else job["error"],
        "incident_id": incident_id if incident_id is not None else job["incident_id"],
        "updated_at": utc_now(),
    }
    with connect() as conn:
        conn.execute(
            """
            update analysis_jobs
            set status = ?, current_step = ?, error = ?, incident_id = ?, updated_at = ?
            where id = ?
            """,
            (updated["status"], updated["current_step"], updated["error"], updated["incident_id"], updated["updated_at"], job_id),
        )
    return get_analysis_job(job_id)


def insert_qwen_usage(usage: dict[str, Any]) -> dict[str, Any]:
    """Store token, cost, model, and latency data for a Qwen call."""
    created_at = utc_now()
    with connect() as conn:
        cursor = conn.execute(
            """
            insert into qwen_usage (
                job_id, event_id, incident_id, agent_name, model, input_tokens,
                output_tokens, total_tokens, latency_ms, estimated_cost_usd, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                usage["latency_ms"],
                usage.get("estimated_cost_usd"),
                created_at,
            ),
        )
        usage_id = cursor.lastrowid
    return {**usage, "id": usage_id, "created_at": created_at}


def attach_qwen_usage_to_incident(job_id: int, incident_id: int) -> None:
    """Attach Qwen usage rows from a job to the incident it created."""
    with connect() as conn:
        conn.execute("update qwen_usage set incident_id = ? where job_id = ?", (incident_id, job_id))


def list_qwen_usage(limit: int = 100) -> list[dict[str, Any]]:
    """List recent Qwen usage records."""
    with connect() as conn:
        rows = conn.execute("select * from qwen_usage order by id desc limit ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


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


def summarize_qwen_usage() -> dict[str, Any]:
    """Return aggregate Qwen usage and estimated cost."""
    with connect() as conn:
        row = conn.execute(
            """
            select
                count(*) as calls,
                coalesce(sum(input_tokens), 0) as input_tokens,
                coalesce(sum(output_tokens), 0) as output_tokens,
                coalesce(sum(total_tokens), 0) as total_tokens,
                coalesce(sum(estimated_cost_usd), 0) as estimated_cost_usd,
                coalesce(avg(latency_ms), 0) as avg_latency_ms
            from qwen_usage
            """
        ).fetchone()
    return dict(row)


def summarize_qwen_usage_for_sites(site_ids: list[str]) -> dict[str, Any]:
    """Return aggregate Qwen usage scoped to owned sites."""
    if not site_ids:
        return {
            "calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "estimated_cost_usd": 0,
            "avg_latency_ms": 0,
        }
    placeholders = ",".join("?" for _ in site_ids)
    with connect() as conn:
        row = conn.execute(
            f"""
            select
                count(*) as calls,
                coalesce(sum(qwen_usage.input_tokens), 0) as input_tokens,
                coalesce(sum(qwen_usage.output_tokens), 0) as output_tokens,
                coalesce(sum(qwen_usage.total_tokens), 0) as total_tokens,
                coalesce(sum(qwen_usage.estimated_cost_usd), 0) as estimated_cost_usd,
                coalesce(avg(qwen_usage.latency_ms), 0) as avg_latency_ms
            from qwen_usage
            left join analysis_jobs on analysis_jobs.id = qwen_usage.job_id
            left join events on events.id = qwen_usage.event_id
            where coalesce(analysis_jobs.site_id, events.site_id) in ({placeholders})
            """,
            tuple(site_ids),
        ).fetchone()
    return dict(row)


def set_remediation_preference(site_id: str, action: str, requires_approval: bool) -> dict[str, Any]:
    """Set whether a remediation action requires approval for a site."""
    updated_at = utc_now()
    with connect() as conn:
        conn.execute(
            """
            insert into remediation_preferences (site_id, action, requires_approval, updated_at)
            values (?, ?, ?, ?)
            on conflict(site_id, action)
            do update set requires_approval = excluded.requires_approval, updated_at = excluded.updated_at
            """,
            (site_id, action, int(requires_approval), updated_at),
        )
    return {
        "site_id": site_id,
        "action": action,
        "requires_approval": requires_approval,
        "updated_at": updated_at,
    }


def list_remediation_preferences(site_id: str) -> list[dict[str, Any]]:
    """List approval preferences for remediation actions on a site."""
    with connect() as conn:
        rows = conn.execute("select * from remediation_preferences where site_id = ? order by action", (site_id,)).fetchall()
    return [
        {
            **dict(row),
            "requires_approval": bool(row["requires_approval"]),
        }
        for row in rows
    ]


def remediation_requires_approval(site_id: str, action: str) -> bool:
    """Return whether an action should wait for human approval by default."""
    with connect() as conn:
        row = conn.execute(
            "select requires_approval from remediation_preferences where site_id = ? and action = ?",
            (site_id, action),
        ).fetchone()
    if not row:
        return True
    return bool(row["requires_approval"])


def save_sls_config(site_id: str, config: dict[str, str]) -> dict[str, Any]:
    """Save encrypted Alibaba SLS connection settings for a site."""
    now = utc_now()
    with connect() as conn:
        existing = conn.execute("select created_at from site_sls_configs where site_id = ?", (site_id,)).fetchone()
        created_at = existing["created_at"] if existing else now
        conn.execute(
            """
            insert into site_sls_configs (
                site_id, endpoint, project, logstore, role_arn, encrypted_external_id, created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?)
            on conflict(site_id)
            do update set
                endpoint = excluded.endpoint,
                project = excluded.project,
                logstore = excluded.logstore,
                role_arn = excluded.role_arn,
                encrypted_external_id = excluded.encrypted_external_id,
                updated_at = excluded.updated_at
            """,
            (
                site_id,
                config["endpoint"],
                config["project"],
                config["logstore"],
                config["role_arn"],
                config["encrypted_external_id"],
                created_at,
                now,
            ),
        )
    stored = get_sls_config(site_id)
    if not stored:
        raise RuntimeError("Failed to save Alibaba SLS settings")
    return stored


def get_sls_config(site_id: str) -> dict[str, Any] | None:
    """Fetch Alibaba SLS settings for a site."""
    with connect() as conn:
        row = conn.execute("select * from site_sls_configs where site_id = ?", (site_id,)).fetchone()
    return dict(row) if row else None


def list_sls_configs() -> list[dict[str, Any]]:
    """Return every saved Alibaba SLS connection for background polling."""
    with connect() as conn:
        rows = conn.execute("select * from site_sls_configs order by updated_at desc").fetchall()
    return [dict(row) for row in rows]


def save_alibaba_autopilot_config(site_id: str, config: dict[str, Any]) -> dict[str, Any]:
    """Save Alibaba Cloud Autopilot connection settings for a site."""
    now = utc_now()
    with connect() as conn:
        existing = conn.execute(
            "select created_at from site_alibaba_autopilot_configs where site_id = ?",
            (site_id,),
        ).fetchone()
        created_at = existing["created_at"] if existing else now
        conn.execute(
            """
            insert into site_alibaba_autopilot_configs (
                site_id, role_arn, encrypted_external_id, region, waf_instance_id, waf_domain,
                waf_template_id, sls_endpoint, sls_project, sls_logstore, enforcement_mode,
                created_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict(site_id)
            do update set
                role_arn = excluded.role_arn,
                encrypted_external_id = excluded.encrypted_external_id,
                region = excluded.region,
                waf_instance_id = excluded.waf_instance_id,
                waf_domain = excluded.waf_domain,
                waf_template_id = excluded.waf_template_id,
                sls_endpoint = excluded.sls_endpoint,
                sls_project = excluded.sls_project,
                sls_logstore = excluded.sls_logstore,
                enforcement_mode = excluded.enforcement_mode,
                updated_at = excluded.updated_at
            """,
            (
                site_id,
                config["role_arn"],
                config["encrypted_external_id"],
                config["region"],
                config.get("waf_instance_id"),
                config.get("waf_domain"),
                config.get("waf_template_id"),
                config.get("sls_endpoint"),
                config.get("sls_project"),
                config.get("sls_logstore"),
                config["enforcement_mode"],
                created_at,
                now,
            ),
        )
    stored = get_alibaba_autopilot_config(site_id)
    if not stored:
        raise RuntimeError("Failed to save Alibaba Autopilot settings")
    return stored


def get_alibaba_autopilot_config(site_id: str) -> dict[str, Any] | None:
    """Fetch Alibaba Cloud Autopilot settings for a site."""
    with connect() as conn:
        row = conn.execute("select * from site_alibaba_autopilot_configs where site_id = ?", (site_id,)).fetchone()
    return dict(row) if row else None


def save_alibaba_waf_template_id(site_id: str, template_id: int) -> None:
    """Save SecAi's internally managed Alibaba WAF defense template ID."""
    with connect() as conn:
        conn.execute(
            """
            update site_alibaba_autopilot_configs
            set waf_template_id = ?, updated_at = ?
            where site_id = ?
            """,
            (template_id, utc_now(), site_id),
        )


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
    return {"site_id": site_id, "channel": channel, "enabled": enabled, "config": config, "created_at": created_at, "updated_at": now}


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
