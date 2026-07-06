from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from secai import database
from secai.dashboard_api.dependencies import current_user_email, ensure_site_owner
from secai.database import encryption
from secai.settings import get_settings
from secai.agent import jobs as analysis
from secai.integrations import discord
from secai.integrations import alibaba_autopilot
from secai.event_sources import alibaba_sls
from secai.models import (
    AlibabaAutopilotConfigIn,
    AlibabaSlsConfigIn,
    AlibabaSlsPullIn,
    RemediationPreferenceIn,
    SiteCreate,
    SiteOut,
)


router = APIRouter(prefix="/api/sites", tags=["sites"])
logger = logging.getLogger(__name__)


@router.post("", response_model=SiteOut)
def create_site(payload: SiteCreate, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Create a monitored site and return its ingest credentials."""
    return database.create_site(payload.name, user_email)


@router.get("")
def list_sites(user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """List monitored sites owned by the authenticated user."""
    return {"sites": database.list_sites(user_email)}


@router.get("/{site_id}/remediation-preferences")
def remediation_preferences(site_id: str, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """List which remediation actions require approval for a site."""
    ensure_site_owner(site_id, user_email)
    return {
        "site_id": site_id,
        "default": "requires_approval",
        "preferences": database.list_remediation_preferences(site_id),
    }


@router.put("/{site_id}/remediation-preferences")
def set_remediation_preference(
    site_id: str,
    payload: RemediationPreferenceIn,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Set whether one remediation action can run automatically."""
    ensure_site_owner(site_id, user_email)
    preference = database.set_remediation_preference(site_id, payload.action, payload.requires_approval)
    return {"preference": preference}


@router.put("/{site_id}/alibaba-sls")
def save_alibaba_sls_config(
    site_id: str,
    payload: AlibabaSlsConfigIn,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Save Alibaba SLS settings for an owned site."""
    ensure_site_owner(site_id, user_email)
    config = database.save_sls_config(
        site_id,
        {
            "endpoint": payload.endpoint.strip(),
            "project": payload.project.strip(),
            "logstore": payload.logstore.strip(),
            "role_arn": payload.role_arn.strip(),
            "encrypted_external_id": encryption.encrypt_secret(payload.external_id),
        },
    )
    alibaba_sls.invalidate_cache(site_id)
    return {"config": _public_sls_config(config)}


@router.get("/{site_id}/alibaba-sls")
def get_alibaba_sls_config(site_id: str, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Return masked Alibaba SLS settings for an owned site."""
    ensure_site_owner(site_id, user_email)
    config = database.get_sls_config(site_id)
    return {"configured": bool(config), "config": _public_sls_config(config) if config else None}


@router.put("/{site_id}/alibaba-autopilot")
def save_alibaba_autopilot_config(
    site_id: str,
    payload: AlibabaAutopilotConfigIn,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Save Alibaba Autopilot settings for no-code log detection and WAF enforcement."""
    ensure_site_owner(site_id, user_email)
    if payload.enforcement_mode == "waf_enforced" and not payload.waf_instance_id:
        raise HTTPException(status_code=400, detail="Alibaba WAF instance ID is required for Autopilot enforcement.")
    has_partial_sls = any([payload.sls_endpoint, payload.sls_project, payload.sls_logstore])
    has_complete_sls = all([payload.sls_endpoint, payload.sls_project, payload.sls_logstore])
    if has_partial_sls and not has_complete_sls:
        raise HTTPException(status_code=400, detail="Log Service endpoint, project, and logstore are all required when connecting logs.")

    existing = database.get_alibaba_autopilot_config(site_id)
    external_id = payload.external_id.strip() if payload.external_id else ""
    if external_id and not external_id.startswith("****"):
        encrypted_external_id = encryption.encrypt_secret(external_id)
    elif existing:
        encrypted_external_id = existing["encrypted_external_id"]
    else:
        raise HTTPException(status_code=400, detail="External ID is required the first time Alibaba Autopilot is connected.")
    waf_instance_id = payload.waf_instance_id.strip() if payload.waf_instance_id else None
    waf_template_id = (
        existing.get("waf_template_id")
        if existing and existing.get("waf_instance_id") == waf_instance_id
        else None
    )
    config = database.save_alibaba_autopilot_config(
        site_id,
        {
            "role_arn": payload.role_arn.strip(),
            "encrypted_external_id": encrypted_external_id,
            "region": payload.region.strip(),
            "waf_instance_id": waf_instance_id,
            "waf_domain": payload.waf_domain.strip() if payload.waf_domain else None,
            "waf_template_id": waf_template_id,
            "sls_endpoint": payload.sls_endpoint.strip() if payload.sls_endpoint else None,
            "sls_project": payload.sls_project.strip() if payload.sls_project else None,
            "sls_logstore": payload.sls_logstore.strip() if payload.sls_logstore else None,
            "enforcement_mode": payload.enforcement_mode,
        },
    )
    if has_complete_sls:
        database.save_sls_config(
            site_id,
            {
                "endpoint": payload.sls_endpoint.strip(),
                "project": payload.sls_project.strip(),
                "logstore": payload.sls_logstore.strip(),
                "role_arn": payload.role_arn.strip(),
                "encrypted_external_id": encrypted_external_id,
            },
        )
        alibaba_sls.invalidate_cache(site_id)
    alibaba_autopilot.invalidate_cache(site_id)
    if payload.enforcement_mode == "waf_enforced" and waf_instance_id:
        try:
            alibaba_autopilot.get_or_create_defense_template(site_id)
            config = database.get_alibaba_autopilot_config(site_id) or config
        except Exception as exc:
            logger.warning("Could not provision SecAi WAF template for site %s during setup: %s", site_id, exc)
    return {
        "config": alibaba_autopilot.public_config(config),
        "status": alibaba_autopilot.site_status(site_id),
    }


@router.get("/{site_id}/alibaba-resources")
def alibaba_resources(site_id: str, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Return Alibaba Cloud resources connected to this SecAi site."""
    ensure_site_owner(site_id, user_email)
    return alibaba_autopilot.discover_resources(site_id)


@router.get("/{site_id}/autopilot-status")
def autopilot_status(site_id: str, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Return whether this site is observe-only or has WAF enforcement active."""
    ensure_site_owner(site_id, user_email)
    return alibaba_autopilot.site_status(site_id)


@router.post("/{site_id}/alibaba-sls/pull")
def pull_alibaba_sls_logs(
    site_id: str,
    payload: AlibabaSlsPullIn,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Pull logs from a site's saved Alibaba SLS connection."""
    ensure_site_owner(site_id, user_email)
    saved = database.get_sls_config(site_id)
    if not saved:
        raise HTTPException(status_code=400, detail="Connect Alibaba Cloud logs before checking recent activity.")
    parsed = alibaba_sls.fetch_events(
        site_id,
        payload.query,
        payload.minutes,
        payload.limit,
        {
            "endpoint": saved["endpoint"],
            "project": saved["project"],
            "logstore": saved["logstore"],
            "role_arn": saved["role_arn"],
            "external_id": encryption.decrypt_secret(saved["encrypted_external_id"]),
        },
    )
    incidents = []
    duplicates_skipped = 0
    events_ingested = 0
    for event in parsed:
        stored_event = database.insert_event(event)
        if stored_event.pop("_deduplicated", False):
            duplicates_skipped += 1
            continue
        events_ingested += 1
        job = database.create_analysis_job(stored_event["id"], stored_event["site_id"])
        if get_settings().secai_analysis_mode == "background":
            analysis.executor.submit(analysis.run_analysis_job, stored_event, job["id"], True)
        else:
            incident, _ = analysis.run_analysis_job(stored_event, job["id"])
            if incident:
                discord.notify_incident(incident)
                incidents.append(incident)
    return {
        "events_seen": len(parsed),
        "events_ingested": events_ingested,
        "duplicates_skipped": duplicates_skipped,
        "incidents_created": len(incidents),
        "incidents": incidents,
    }


def _public_sls_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return Alibaba SLS settings safe for the dashboard."""
    return {
        "site_id": config["site_id"],
        "endpoint": config["endpoint"],
        "project": config["project"],
        "logstore": config["logstore"],
        "role_arn": config["role_arn"],
        "external_id": encryption.mask_secret(encryption.decrypt_secret(config["encrypted_external_id"])),
        "created_at": config["created_at"],
        "updated_at": config["updated_at"],
    }
