from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from secai.database._utils import token_hash, utc_now
from secai.database.connection import connect
from secai.settings import get_settings


def _session_expires_at() -> str:
    """Return the expiry timestamp for a newly issued owner session."""
    ttl_hours = max(1, get_settings().secai_session_ttl_hours)
    return (datetime.now(UTC) + timedelta(hours=ttl_hours)).isoformat()


def create_site(name: str, owner_email: str | None, evidence_source: str) -> dict[str, Any]:
    """Create a monitored site and generate its ingest key."""
    site_id = f"site_{secrets.token_hex(6)}"
    ingest_key = f"sk_{secrets.token_urlsafe(24)}"
    with connect() as conn:
        conn.execute(
            "insert into sites (site_id, name, owner_email, ingest_key, evidence_source, created_at) "
            "values (?, ?, ?, ?, ?, ?)",
            (site_id, name, owner_email, ingest_key, evidence_source, utc_now()),
        )
    return {
        "site_id": site_id,
        "name": name,
        "owner_email": owner_email,
        "ingest_key": ingest_key,
        "evidence_source": evidence_source,
    }


def create_user(email: str, password_hash: str) -> dict[str, Any]:
    """Create a website owner account."""
    created_at = utc_now()
    normalized_email = email.strip().lower()
    with connect() as conn:
        cursor = conn.execute(
            "insert into users (email, password_hash, created_at) values (?, ?, ?) returning id",
            (normalized_email, password_hash, created_at),
        )
        user_id = cursor.fetchone()["id"]
    return {"id": user_id, "email": normalized_email, "created_at": created_at}


def get_user_by_email(email: str) -> dict[str, Any] | None:
    """Fetch one user by email."""
    with connect() as conn:
        row = conn.execute("select * from users where email = ?", (email.strip().lower(),)).fetchone()
    return dict(row) if row else None


def get_user_by_session(token: str) -> dict[str, Any] | None:
    """Fetch the user attached to a session token."""
    hashed_token = token_hash(token)
    with connect() as conn:
        row = conn.execute(
            """
            select users.id, users.email, users.created_at, sessions.expires_at
            from sessions
            join users on users.id = sessions.user_id
            where sessions.token = ?
            """,
            (hashed_token,),
        ).fetchone()
        if row and row["expires_at"] <= utc_now():
            conn.execute("delete from sessions where token = ?", (hashed_token,))
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
            (token_hash(token), user_id, created_at, expires_at),
        )
    return {"token": token, "user_id": user_id, "created_at": created_at, "expires_at": expires_at}


def delete_session(token: str) -> None:
    """Delete a session token."""
    with connect() as conn:
        conn.execute("delete from sessions where token = ?", (token_hash(token),))


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
    if not site or site["evidence_source"] != "browser":
        return None
    return {"site_id": site["site_id"], "ingest_key": site["ingest_key"]}


def rotate_site_ingest_key(site_id: str) -> str:
    """Replace a browser ingest key and return the new credential once."""
    ingest_key = f"sk_{secrets.token_urlsafe(24)}"
    with connect() as conn:
        cursor = conn.execute("update sites set ingest_key = ? where site_id = ?", (ingest_key, site_id))
        if cursor.rowcount != 1:
            raise KeyError(site_id)
    return ingest_key


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


def ensure_judge_site(owner_email: str) -> dict[str, Any]:
    """Create the isolated judge site if it does not exist."""
    with connect() as conn:
        row = conn.execute("select * from sites where site_id = ?", ("judge-site",)).fetchone()
        if row:
            conn.execute(
                "update sites set owner_email = ?, evidence_source = ? where site_id = ?",
                (owner_email, "alibaba_autopilot", "judge-site"),
            )
            return {**dict(row), "owner_email": owner_email, "evidence_source": "alibaba_autopilot"}
        ingest_key = secrets.token_urlsafe(32)
        conn.execute(
            "insert into sites (site_id, name, owner_email, ingest_key, evidence_source, created_at) "
            "values (?, ?, ?, ?, ?, ?)",
            ("judge-site", "Northstar Goods", owner_email, ingest_key, "alibaba_autopilot", utc_now()),
        )
    site = get_site("judge-site")
    if not site:
        raise RuntimeError("Failed to create judge site")
    return site


def ensure_judge_user(password_hash: str, email: str) -> dict[str, Any]:
    """Create the isolated judge account once."""
    existing = get_user_by_email(email)
    if existing:
        with connect() as conn:
            conn.execute("update users set password_hash = ? where id = ?", (password_hash, existing["id"]))
        user = get_user_by_email(email)
        if not user:
            raise RuntimeError("Failed to update judge user")
        return user
    return create_user(email, password_hash)


def verify_ingest_key(site_id: str, ingest_key: str | None) -> bool:
    """Return whether an ingest key is valid for a site."""
    site = get_site(site_id)
    return bool(site and ingest_key and secrets.compare_digest(site["ingest_key"], ingest_key))
