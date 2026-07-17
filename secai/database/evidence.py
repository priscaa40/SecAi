from __future__ import annotations

import hashlib
import json
from typing import Any

from secai.database._utils import utc_now
from secai.database.connection import connect
from secai.security.redaction import sanitize_event


def insert_event(event: dict[str, Any]) -> dict[str, Any]:
    """Store one normalized event."""
    event = sanitize_event(event)
    created_at = utc_now()
    fingerprint = event.get("event_fingerprint") or _event_fingerprint(event)
    metadata = dict(event.get("metadata", {}))
    if fingerprint:
        metadata.setdefault("secai", {})["event_fingerprint"] = fingerprint
    with connect() as conn:
        cursor = conn.execute(
            """
            insert into events (
                site_id, source, event_type, event_fingerprint, method, path, query, status_code, ip,
                user_agent, payload, signals_json, metadata_json, created_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict (site_id, event_fingerprint) where event_fingerprint is not null do nothing
            returning id
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
        inserted = cursor.fetchone()
        if not inserted and fingerprint:
            row = conn.execute(
                "select * from events where site_id = ? and event_fingerprint = ?",
                (event["site_id"], fingerprint),
            ).fetchone()
            if row:
                existing = _decode_event(dict(row))
                existing["_deduplicated"] = True
                return existing
        if not inserted:
            raise RuntimeError("Failed to store event")
        event_id = inserted["id"]
    return {**event, "metadata": metadata, "event_fingerprint": fingerprint, "id": event_id, "created_at": created_at}


def recent_events(site_id: str, limit: int = 100) -> list[dict[str, Any]]:
    """Return recent normalized events for a site."""
    with connect() as conn:
        rows = conn.execute(
            "select * from events where site_id = ? order by id desc limit ?",
            (site_id, limit),
        ).fetchall()
    return [_decode_event(dict(row)) for row in rows]


def recent_analysis_events(site_id: str, limit: int = 100) -> list[dict[str, Any]]:
    """Return analysis candidates without counting raw SLS records and their group twice."""
    with connect() as conn:
        rows = conn.execute(
            """
            select * from events
            where site_id = ? and not (source = 'alibaba_sls' and event_type = 'sls_log')
            order by id desc limit ?
            """,
            (site_id, limit),
        ).fetchall()
    return [_decode_event(dict(row)) for row in rows]


def get_event(event_id: int) -> dict[str, Any] | None:
    """Fetch one normalized event by ID."""
    with connect() as conn:
        row = conn.execute("select * from events where id = ?", (event_id,)).fetchone()
    return _decode_event(dict(row)) if row else None


def get_events(event_ids: set[int]) -> dict[int, dict[str, Any]]:
    """Fetch a set of evidence events in one query."""
    if not event_ids:
        return {}
    placeholders = ",".join("?" for _ in event_ids)
    with connect() as conn:
        rows = conn.execute(
            f"select * from events where id in ({placeholders})",
            tuple(sorted(event_ids)),
        ).fetchall()
    decoded = [_decode_event(dict(row)) for row in rows]
    return {item["id"]: item for item in decoded}


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
