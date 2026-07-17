from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import Response

from secai import database
from secai.event_sources import browser
from secai.event_sources import service as ingest_service
from secai.models import EventIn
from secai.security.client_ip import request_client_ip
from secai.settings import get_settings

router = APIRouter(tags=["ingest"])


@router.post("/api/events")
def ingest_event(request: Request, payload: EventIn, x_secai_key: str | None = Header(default=None)) -> dict[str, Any]:
    """Accept one browser snippet event."""
    if payload.source != "browser":
        raise HTTPException(status_code=403, detail="The public ingest endpoint accepts browser evidence only.")
    return ingest_service.ingest_event(payload, x_secai_key, request_client_ip(request))


@router.get("/api/integrations/browser.js")
def browser_snippet(site_id: str) -> Response:
    """Return the JavaScript snippet used for browser-side event ingest."""
    settings = get_settings()
    site_config = database.public_site_script_config(site_id)
    if not site_config:
        raise HTTPException(status_code=404, detail="Site not found")
    script = browser.render_snippet(settings.public_base_url, site_id, site_config["ingest_key"])
    return Response(
        script,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )
