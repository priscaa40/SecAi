from __future__ import annotations

import logging
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, Request

from secai import database
from secai.dashboard_api import auth_service
from secai.database import encryption
from secai.settings import get_settings
from secai.integrations import alibaba_autopilot
from secai.models import PublicSetupIn


router = APIRouter(prefix="/api/setup", tags=["setup"])
logger = logging.getLogger(__name__)


@router.get("/alibaba-autopilot-template")
def alibaba_autopilot_template(
    request: Request,
    external_id: str = Query(min_length=8, max_length=160),
    region: str = Query(default="ap-southeast-1", min_length=1, max_length=80),
    role_name: str = Query(default=alibaba_autopilot.DEFAULT_CONNECTOR_ROLE_NAME, min_length=1, max_length=64),
    waf_instance_id: str | None = Query(default=None, max_length=180),
    sls_endpoint: str | None = Query(default=None, max_length=300),
    sls_project: str | None = Query(default=None, max_length=160),
    sls_logstore: str | None = Query(default=None, max_length=160),
) -> dict:
    """Return the Alibaba ROS/RAM connector template for a site connection."""
    params = _alibaba_template_params(external_id, region, role_name, waf_instance_id, sls_endpoint, sls_project, sls_logstore)
    template_url = f"{str(request.base_url).rstrip('/')}/api/setup/alibaba-autopilot-template/ros.json?{urlencode(params)}"
    return _connector_template_from_params(params, template_url=template_url)


@router.get("/alibaba-autopilot-template/ros.json")
def alibaba_autopilot_template_file(
    external_id: str = Query(min_length=8, max_length=160),
    region: str = Query(default="ap-southeast-1", min_length=1, max_length=80),
    role_name: str = Query(default=alibaba_autopilot.DEFAULT_CONNECTOR_ROLE_NAME, min_length=1, max_length=64),
    waf_instance_id: str | None = Query(default=None, max_length=180),
    sls_endpoint: str | None = Query(default=None, max_length=300),
    sls_project: str | None = Query(default=None, max_length=160),
    sls_logstore: str | None = Query(default=None, max_length=160),
) -> dict:
    """Return the raw ROS JSON template that Alibaba Cloud quick create imports."""
    params = _alibaba_template_params(external_id, region, role_name, waf_instance_id, sls_endpoint, sls_project, sls_logstore)
    return _connector_template_from_params(params)["template"]


def _alibaba_template_params(
    external_id: str,
    region: str,
    role_name: str,
    waf_instance_id: str | None,
    sls_endpoint: str | None,
    sls_project: str | None,
    sls_logstore: str | None,
) -> dict[str, str]:
    params = {
        "external_id": external_id.strip(),
        "region": region.strip(),
        "role_name": role_name.strip(),
    }
    optional = {
        "waf_instance_id": waf_instance_id,
        "sls_endpoint": sls_endpoint,
        "sls_project": sls_project,
        "sls_logstore": sls_logstore,
    }
    for key, value in optional.items():
        stripped = value.strip() if value else ""
        if stripped:
            params[key] = stripped
    return params


def _connector_template_from_params(params: dict[str, str], template_url: str | None = None) -> dict:
    try:
        return alibaba_autopilot.connector_template(
            external_id=params["external_id"],
            region=params["region"],
            role_name=params["role_name"],
            waf_instance_id=params.get("waf_instance_id"),
            sls_endpoint=params.get("sls_endpoint"),
            sls_project=params.get("sls_project"),
            sls_logstore=params.get("sls_logstore"),
            template_url=template_url,
        )
    except alibaba_autopilot.AlibabaAutopilotPrincipalNotConfigured as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/website")
def setup_website(payload: PublicSetupIn) -> dict:
    """Create a protected website from the public setup wizard."""
    channels = set(payload.report_channels)
    if not channels:
        raise HTTPException(status_code=400, detail="Choose at least one place for SecAi to send reports.")
    needs_encryption = payload.watch_method == "alibaba_autopilot"
    if needs_encryption and not get_settings().secai_secret_key:
        raise HTTPException(status_code=500, detail="SECAI_SECRET_KEY must be configured before saving private setup details.")
    if "dashboard" in channels and (not payload.dashboard_email or not payload.dashboard_password):
        raise HTTPException(status_code=400, detail="Email and password are required for dashboard reports.")
    if payload.watch_method == "alibaba_autopilot" and not all([payload.sls_role_arn, payload.sls_external_id, payload.alibaba_region]):
        raise HTTPException(status_code=400, detail="Alibaba RAM role, external ID, and region are required for Alibaba Autopilot.")
    session = None
    site = None
    try:
        owner_email = None
        if "dashboard" in channels:
            session = auth_service.signup(payload.dashboard_email, payload.dashboard_password)
            owner_email = session["user"]["email"]

        site = database.create_site(payload.website_name, owner_email)
        messaging_setup = []
        if payload.watch_method == "alibaba_autopilot":
            encrypted_external_id = encryption.encrypt_secret(payload.sls_external_id)
            waf_ready = bool(payload.waf_instance_id)
            database.save_alibaba_autopilot_config(
                site["site_id"],
                {
                    "role_arn": payload.sls_role_arn.strip(),
                    "encrypted_external_id": encrypted_external_id,
                    "region": (payload.alibaba_region or "ap-southeast-1").strip(),
                    "waf_instance_id": payload.waf_instance_id.strip() if payload.waf_instance_id else None,
                    "waf_domain": payload.waf_domain.strip() if payload.waf_domain else None,
                    "waf_template_id": None,
                    "sls_endpoint": payload.sls_endpoint.strip() if payload.sls_endpoint else None,
                    "sls_project": payload.sls_project.strip() if payload.sls_project else None,
                    "sls_logstore": payload.sls_logstore.strip() if payload.sls_logstore else None,
                    "enforcement_mode": "waf_enforced" if waf_ready else "observe_only",
                },
            )
            if all([payload.sls_endpoint, payload.sls_project, payload.sls_logstore]):
                database.save_sls_config(
                    site["site_id"],
                    {
                        "endpoint": payload.sls_endpoint.strip(),
                        "project": payload.sls_project.strip(),
                        "logstore": payload.sls_logstore.strip(),
                        "role_arn": payload.sls_role_arn.strip(),
                        "encrypted_external_id": encrypted_external_id,
                    },
                )
            if waf_ready:
                try:
                    alibaba_autopilot.get_or_create_defense_template(site["site_id"])
                except Exception as exc:
                    logger.warning("Could not provision SecAi WAF template for site %s during public setup: %s", site["site_id"], exc)
        if "dashboard" in channels:
            database.save_report_channel(site["site_id"], "dashboard", True, {})
        if "discord" in channels:
            setup_code = secrets.token_urlsafe(8)
            messaging_setup.append({"channel": "discord", "setup_code": setup_code})
            database.save_report_channel(
                site["site_id"],
                "discord",
                True,
                {"status": "pending_bot_connection", "setup_code": setup_code},
            )

        for action in payload.automatic_actions:
            database.set_remediation_preference(site["site_id"], action, False)

        return {
            "site": site,
            "session": session,
            "channels": sorted(channels),
            "messaging_setup": messaging_setup,
            "snippet": f'<script src="/api/integrations/browser.js?site_id={site["site_id"]}"></script>',
        }
    except Exception:
        if site:
            database.delete_site(site["site_id"])
        if session:
            database.delete_user(session["user"]["id"])
        raise
