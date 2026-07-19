from __future__ import annotations

from dataclasses import replace
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from secai import database
from secai.dashboard_api.dependencies import (
    current_user_email,
    ensure_site_owner,
    is_judge_owner,
    protect_judge_configuration,
)
from secai.dashboard_api.rate_limit import enforce_request_rate
from secai.event_sources import alibaba_sls
from secai.event_sources.scheduler import ingest_sls_events
from secai.integrations import alibaba_autopilot, alibaba_coordinates, alibaba_credentials, discord
from secai.integrations import alibaba_resources as alibaba_resource_service
from secai.models import (
    AlibabaAutopilotConfigIn,
    AlibabaConnectionVerifyIn,
    AlibabaResourceDiscoveryIn,
    AlibabaSlsPullIn,
    SiteCreate,
    SiteOut,
)

router = APIRouter(prefix="/api/sites", tags=["sites"])


@router.delete("/{site_id}")
def delete_site(site_id: str, user_email: str = Depends(current_user_email)) -> dict[str, str]:
    """Permanently delete an owned site and all SecAi data attached to it."""
    ensure_site_owner(site_id, user_email)
    protect_judge_configuration(site_id, user_email)
    if _policy_that_blocks_cloud_changes(site_id):
        raise HTTPException(
            status_code=409,
            detail="Remove the website's active protection before deleting it.",
        )
    database.delete_site(site_id)
    alibaba_credentials.invalidate_assumed_role_cache()
    return {"status": "deleted", "site_id": site_id}


@router.post("/{site_id}/rotate-ingest-key")
def rotate_ingest_key(site_id: str, user_email: str = Depends(current_user_email)) -> dict[str, str]:
    """Rotate a site's browser ingest credential."""
    ensure_site_owner(site_id, user_email)
    protect_judge_configuration(site_id, user_email)
    return {"site_id": site_id, "ingest_key": database.rotate_site_ingest_key(site_id)}


@router.post("/{site_id}/discord-setup")
def create_discord_setup(site_id: str, user_email: str = Depends(current_user_email)) -> dict[str, str]:
    """Create or replace the one-time Discord binding for an owned website."""
    ensure_site_owner(site_id, user_email)
    protect_judge_configuration(site_id, user_email)
    if readiness_error := discord.setup_readiness_error():
        raise HTTPException(status_code=503, detail=readiness_error)
    try:
        discord.verify_application_configuration()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return discord.create_channel_setup(site_id)


@router.post("", response_model=SiteOut)
def create_site(payload: SiteCreate, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Create a monitored site and return its ingest credentials."""
    if is_judge_owner(user_email):
        raise HTTPException(status_code=403, detail="The public judge account is limited to the isolated judge site.")
    return database.create_site(payload.name, user_email, payload.evidence_source)


@router.get("")
def list_sites(user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """List monitored sites owned by the authenticated user."""
    return {"sites": database.list_sites(user_email)}


@router.put("/{site_id}/alibaba-autopilot")
def save_alibaba_autopilot_config(
    site_id: str,
    payload: AlibabaAutopilotConfigIn,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Save Alibaba Autopilot settings for no-code log detection and security group enforcement."""
    ensure_site_owner(site_id, user_email)
    protect_judge_configuration(site_id, user_email)
    security_group_id = payload.security_group_id.strip() if payload.security_group_id else None
    if payload.enforcement_mode == "security_group" and not security_group_id:
        raise HTTPException(
            status_code=400, detail="Alibaba ECS security group ID is required for Autopilot enforcement."
        )
    has_partial_sls = any([payload.sls_endpoint, payload.sls_project, payload.sls_logstore])
    has_complete_sls = all([payload.sls_endpoint, payload.sls_project, payload.sls_logstore])
    if has_partial_sls and not has_complete_sls:
        raise HTTPException(
            status_code=400, detail="Log Service endpoint, project, and logstore are all required when connecting logs."
        )
    try:
        region = alibaba_coordinates.normalize_region(payload.region)
        if has_complete_sls:
            assert payload.sls_endpoint is not None
            alibaba_coordinates.validate_sls_endpoint(region, payload.sls_endpoint)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    saved = database.get_alibaba_autopilot_config(site_id)
    if not saved or saved.get("connection_status") != "verified":
        raise HTTPException(status_code=400, detail="Verify this website's Alibaba Cloud role first.")
    provider_coordinates_changed = bool(
        saved
        and (
            saved["region"] != region
            or saved.get("security_group_id") != security_group_id
            or saved["enforcement_mode"] != payload.enforcement_mode
        )
    )
    if provider_coordinates_changed and _policy_that_blocks_cloud_changes(site_id):
        raise HTTPException(
            status_code=409,
            detail="Remove the website's active protection before changing its cloud connection.",
        )

    connection = replace(alibaba_autopilot.load_site_connection(site_id), region=region)
    try:
        resources = alibaba_resource_service.discover(connection, region)
    except alibaba_resource_service.AlibabaResourceDiscoveryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    sls_endpoint = payload.sls_endpoint.strip() if payload.sls_endpoint else None
    sls_project = payload.sls_project.strip() if payload.sls_project else None
    sls_logstore = payload.sls_logstore.strip() if payload.sls_logstore else None
    if has_complete_sls and not any(
        item["endpoint"] == sls_endpoint and item["project"] == sls_project and item["logstore"] == sls_logstore
        for item in resources["log_sources"]
    ):
        raise HTTPException(status_code=400, detail="Choose a Log Service source returned for this website role and region.")
    if has_complete_sls:
        assert sls_endpoint and sls_project and sls_logstore
        try:
            alibaba_sls.validate_log_source(
                alibaba_sls.SlsConnection(
                    site_id=site_id,
                    role_arn=connection.role_arn,
                    external_id=connection.external_id,
                    account_id=connection.account_id,
                    region=region,
                    sls_endpoint=sls_endpoint,
                    sls_project=sls_project,
                    sls_logstore=sls_logstore,
                )
            )
        except alibaba_sls.SlsReadinessError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if security_group_id:
        selected_group = next(
            (item for item in resources["security_groups"] if item["security_group_id"] == security_group_id),
            None,
        )
        if not selected_group:
            raise HTTPException(status_code=400, detail="Choose a security group returned for this website role and region.")
        if not selected_group["dedicated"]:
            raise HTTPException(
                status_code=400,
                detail="Cloud protection requires a security group attached to exactly one website server.",
            )
    try:
        config = database.save_alibaba_autopilot_config(
            site_id,
            {
                "region": region,
                "security_group_id": security_group_id,
                "sls_endpoint": sls_endpoint,
                "sls_project": sls_project,
                "sls_logstore": sls_logstore,
                "enforcement_mode": payload.enforcement_mode,
            },
        )
    except database.INTEGRITY_ERRORS as exc:
        raise HTTPException(
            status_code=409,
            detail="That log source or protection group is already assigned to another SecAi website.",
        ) from exc
    return {
        "config": alibaba_autopilot.public_config(config),
        "status": alibaba_autopilot.site_status(site_id),
    }


@router.get("/{site_id}/alibaba-resources")
def alibaba_resources(site_id: str, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Return Alibaba Cloud resources connected to this SecAi site."""
    ensure_site_owner(site_id, user_email)
    return alibaba_autopilot.discover_resources(site_id)


@router.post("/{site_id}/alibaba-connection/prepare")
def prepare_alibaba_connection(
    site_id: str,
    request: Request,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Generate the external ID and authorization template for one owned website."""
    ensure_site_owner(site_id, user_email)
    protect_judge_configuration(site_id, user_email)
    enforce_request_rate(request, f"alibaba-prepare:{site_id}", 10, 3600)
    try:
        database.prepare_alibaba_connection(site_id)
        return alibaba_autopilot.site_status(site_id)
    except (ValueError, alibaba_autopilot.AlibabaAutopilotNotConfigured) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/{site_id}/alibaba-connection/verify")
def verify_alibaba_connection(
    site_id: str,
    payload: AlibabaConnectionVerifyIn,
    request: Request,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Verify the customer-approved role before resource discovery is allowed."""
    ensure_site_owner(site_id, user_email)
    protect_judge_configuration(site_id, user_email)
    enforce_request_rate(request, f"alibaba-verify:{site_id}", 20, 3600)
    saved = database.get_alibaba_autopilot_config(site_id)
    if not saved:
        raise HTTPException(status_code=400, detail="Start the Alibaba Cloud connection first.")
    if (
        saved.get("connection_status") == "verified"
        and saved.get("role_arn") != payload.role_arn.strip()
        and _policy_that_blocks_cloud_changes(site_id)
    ):
        raise HTTPException(
            status_code=409,
            detail="Remove the website's active protection before changing its Alibaba Cloud role.",
        )
    try:
        region = alibaba_coordinates.normalize_region(payload.region)
        _, role_name = alibaba_credentials.parse_role_arn(payload.role_arn.strip())
        expected_role_name = alibaba_autopilot.authorization_bundle(saved)["role_name"]
        if role_name != expected_role_name:
            raise ValueError("Use the RoleArn output from this website's generated ROS template.")
        account_id = alibaba_credentials.verify_role(site_id, payload.role_arn.strip(), saved["external_id"])
    except (
        ValueError,
        alibaba_autopilot.AlibabaAutopilotNotConfigured,
        alibaba_credentials.AlibabaRoleAuthorizationError,
    ) as exc:
        message = "SecAi could not verify that role. Check its trust policy, external ID, and permissions."
        database.mark_alibaba_connection_error(site_id, message)
        raise HTTPException(status_code=400, detail=message) from exc
    database.verify_alibaba_connection(site_id, payload.role_arn.strip(), account_id, region)
    alibaba_credentials.invalidate_assumed_role_cache()
    return alibaba_autopilot.site_status(site_id)


@router.delete("/{site_id}/alibaba-connection")
def disconnect_alibaba_connection(
    site_id: str,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Disconnect a customer role only when no active provider work depends on it."""
    ensure_site_owner(site_id, user_email)
    protect_judge_configuration(site_id, user_email)
    if _policy_that_blocks_cloud_changes(site_id):
        raise HTTPException(
            status_code=409,
            detail="Remove the website's active protection before disconnecting Alibaba Cloud.",
        )
    database.delete_alibaba_connection(site_id)
    alibaba_credentials.invalidate_assumed_role_cache()
    return alibaba_autopilot.site_status(site_id)


@router.post("/{site_id}/alibaba-resources/discover")
def discover_alibaba_resources(
    site_id: str,
    payload: AlibabaResourceDiscoveryIn,
    request: Request,
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Discover Alibaba resources for an owned site's requested region."""
    ensure_site_owner(site_id, user_email)
    enforce_request_rate(request, f"alibaba-discover:{site_id}", 60, 3600)
    try:
        connection = replace(
            alibaba_autopilot.load_site_connection(site_id),
            region=alibaba_coordinates.normalize_region(payload.region),
        )
        return alibaba_resource_service.discover(connection, connection.region)
    except (
        ValueError,
        alibaba_autopilot.AlibabaAutopilotNotConfigured,
        alibaba_resource_service.AlibabaResourceDiscoveryError,
    ) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{site_id}/autopilot-status")
def autopilot_status(site_id: str, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Return whether this site is observe-only or has security group enforcement active."""
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
    saved = database.get_alibaba_autopilot_config(site_id)
    if not saved or not all([saved.get("sls_endpoint"), saved.get("sls_project"), saved.get("sls_logstore")]):
        raise HTTPException(status_code=400, detail="Connect Alibaba Cloud logs before checking recent activity.")
    try:
        parsed = alibaba_sls.fetch_saved_site_events(
            site_id,
            query=payload.query,
            minutes=payload.minutes,
            limit=payload.limit,
        )
    except alibaba_sls.SlsReadinessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = ingest_sls_events(parsed)
    return {
        **result,
        "incidents": [],
    }


def _policy_that_blocks_cloud_changes(site_id: str) -> dict[str, Any] | None:
    """Return provider work that must stay reachable through the saved cloud coordinates."""
    return next(
        (
            policy
            for policy in database.list_policies(site_id, limit=200)
            if policy["status"] in {"pending", "applying", "active", "revoking"}
        ),
        None,
    )
