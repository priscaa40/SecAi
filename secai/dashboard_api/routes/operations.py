from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from secai import database
from secai.dashboard_api.dependencies import current_user_email, ensure_site_owner

router = APIRouter(tags=["operations"])


@router.get("/api/analysis-jobs")
def list_analysis_jobs(
    site_id: str,
    limit: int = Query(default=25, ge=1, le=100),
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Show active and completed analysis work without exposing failed attempts."""
    ensure_site_owner(site_id, user_email)
    jobs = database.list_analysis_jobs_for_site(site_id, limit)
    return {"jobs": [job for job in jobs if job["status"] != "failed"]}


@router.get("/api/analysis-jobs/{job_id}")
def analysis_job(job_id: int, user_email: str = Depends(current_user_email)) -> dict[str, Any]:
    """Return analysis job progress and its incident if available."""
    job = database.get_analysis_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    ensure_site_owner(job["site_id"], user_email)
    incident = database.get_incident(job["incident_id"]) if job.get("incident_id") else None
    return {"job": job, "incident": incident}


@router.get("/api/policies/{site_id}")
def policies(
    site_id: str,
    limit: int = Query(default=100, ge=1, le=200),
    before_id: int | None = Query(default=None, ge=1),
    user_email: str = Depends(current_user_email),
) -> dict[str, Any]:
    """Return remediation policies only to the authenticated site owner."""
    ensure_site_owner(site_id, user_email)
    return {"site_id": site_id, "policies": database.list_policies(site_id, limit, before_id)}
