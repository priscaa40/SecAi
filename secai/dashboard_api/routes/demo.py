from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from secai.models import EventIn
from secai.event_sources.service import ingest_event


router = APIRouter(prefix="/api/demo", tags=["demo"])


@router.post("/simulate")
def simulate_demo_attack(
    attack: str = Query(default="sql_injection"),
    site_id: str = Query(default="demo-site"),
    ingest_key: str = Query(default="demo-key"),
) -> dict[str, Any]:
    """Create and ingest a built-in demo attack event."""
    event = demo_event(site_id, attack)
    return ingest_event(EventIn(**event), ingest_key)


def demo_event(site_id: str, attack: str) -> dict[str, Any]:
    """Build a realistic demo event for a named attack scenario."""
    base = {"site_id": site_id, "source": "demo", "event_type": "http_request"}
    scenarios = {
        "sql_injection": {
            "method": "GET",
            "path": "/products",
            "query": "id=1 OR 1=1--",
            "status_code": 200,
            "ip": "198.51.100.23",
            "user_agent": "curl/8.0",
        },
        "credential_stuffing": {
            "method": "POST",
            "path": "/login",
            "status_code": 401,
            "ip": "203.0.113.44",
            "user_agent": "python-requests/2.31",
            "signals": ["auth_failure", "repeated_login_failure"],
        },
        "path_traversal": {
            "method": "GET",
            "path": "/download",
            "query": "file=../../etc/passwd",
            "status_code": 403,
            "ip": "192.0.2.99",
        },
        "server_error_spike": {
            "method": "POST",
            "path": "/checkout",
            "status_code": 500,
            "ip": "198.51.100.77",
            "signals": ["server_error"],
        },
        "contact_form_spam": {
            "method": "POST",
            "path": "/contact",
            "status_code": 200,
            "ip": "203.0.113.91",
            "user_agent": "SpamBot",
        },
    }
    return {**base, **scenarios.get(attack, scenarios["sql_injection"])}
