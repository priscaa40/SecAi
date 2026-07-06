from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from secai import database
from secai.dashboard_api.dependencies import current_user_email, ensure_site_owner


router = APIRouter(tags=["operations"])


@router.get("/api/analysis-jobs/{job_id}")
def analysis_job(job_id: int, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Return analysis job progress and its incident if available."""
    job = database.get_analysis_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    ensure_site_owner(job["site_id"], user_email)
    incident = database.get_incident(job["incident_id"]) if job.get("incident_id") else None
    return {"job": job, "incident": incident}


@router.get("/api/qwen/usage")
def qwen_usage(
    limit: int = Query(default=25, ge=1, le=250),
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Return Qwen usage, cost, model, and latency telemetry for owned sites."""
    site_ids = [site["site_id"] for site in database.list_sites(user_email)]
    return {
        "summary": database.summarize_qwen_usage_for_sites(site_ids),
        "recent_calls": database.list_qwen_usage_for_sites(site_ids, limit),
    }


@router.get("/api/policies/{site_id}")
def policies(site_id: str, ingest_key: str = Query(...)) -> dict[str, Any]:
    """Return approved remediation policies for a protected site."""
    if not database.verify_ingest_key(site_id, ingest_key):
        raise HTTPException(status_code=401, detail="Invalid site_id or ingest key")
    return {"site_id": site_id, "policies": database.list_policies(site_id)}
