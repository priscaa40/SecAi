from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from secai import database
from secai.dashboard_api import auth_service
from secai.dashboard_api.rate_limit import enforce_request_rate
from secai.integrations import discord
from secai.models import PublicSetupIn

router = APIRouter(prefix="/api/setup", tags=["setup"])


@router.post("/website")
def setup_website(request: Request, payload: PublicSetupIn) -> dict:
    """Create a protected website from the public setup wizard."""
    enforce_request_rate(request, "website-setup", 5, 3600)
    channels = set(payload.report_channels)
    if not channels:
        raise HTTPException(status_code=400, detail="Choose at least one place for SecAi to send reports.")
    if "dashboard" in channels and (not payload.dashboard_email or not payload.dashboard_password):
        raise HTTPException(status_code=400, detail="Email and password are required for dashboard reports.")
    if payload.watch_method == "alibaba_autopilot" and "dashboard" not in channels:
        raise HTTPException(
            status_code=400,
            detail="An owner dashboard account is required to authorize Alibaba Cloud for a website.",
        )
    if "discord" in channels and (discord_error := discord.setup_readiness_error()):
        raise HTTPException(
            status_code=503,
            detail=discord_error,
        )
    if "discord" in channels:
        try:
            discord.verify_application_configuration()
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    session = None
    site = None
    try:
        owner_email = None
        if "dashboard" in channels:
            assert payload.dashboard_email is not None and payload.dashboard_password is not None
            session = auth_service.signup(payload.dashboard_email, payload.dashboard_password)
            owner_email = session["user"]["email"]

        site = database.create_site(payload.website_name, owner_email, payload.watch_method)
        messaging_setup = []
        if "dashboard" in channels:
            database.save_report_channel(site["site_id"], "dashboard", True, {})
        if "discord" in channels:
            messaging_setup.append(discord.create_channel_setup(site["site_id"]))

        return {
            "site": site,
            "session": session,
            "channels": sorted(channels),
            "messaging_setup": messaging_setup,
            "selected_evidence_source": payload.watch_method,
            "snippet": (
                f'<script src="/api/integrations/browser.js?site_id={site["site_id"]}"></script>'
                if payload.watch_method == "browser"
                else None
            ),
        }
    except Exception:
        if site:
            database.delete_site(site["site_id"])
        if session:
            database.delete_user(session["user"]["id"])
        raise
