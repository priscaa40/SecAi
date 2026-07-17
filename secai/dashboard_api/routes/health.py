from __future__ import annotations

from fastapi import APIRouter, Response

from secai import database
from secai.agent import jobs
from secai.knowledge import mcp_client
from secai.settings import get_settings

router = APIRouter()


@router.get("/health")
def health(response: Response) -> dict:
    """Return liveness plus the local dependencies required to accept work."""
    checks: dict[str, bool] = {"database": False, "qwen_configured": bool(get_settings().dashscope_api_key)}
    try:
        with database.connect() as conn:
            checks["database"] = conn.execute("select 1 as healthy").fetchone()["healthy"] == 1
    except Exception:
        checks["database"] = False
    healthy = all(checks.values())
    if not healthy:
        response.status_code = 503
    worker = jobs.worker_metrics()
    return {
        "status": "ok" if healthy else "degraded",
        "service": "secai-autopilot",
        "checks": checks,
        "analysis_worker": worker,
    }


@router.get("/ready")
def readiness(response: Response) -> dict:
    """Verify the database, Qwen configuration, MCP process, and queue admission state."""
    checks: dict[str, bool] = {
        "database": False,
        "qwen_configured": bool(get_settings().dashscope_api_key),
        "mcp": False,
    }
    try:
        with database.connect() as conn:
            checks["database"] = conn.execute("select 1 as healthy").fetchone()["healthy"] == 1
    except Exception:
        pass
    try:
        checks["mcp"] = bool(mcp_client.list_tools())
    except Exception:
        checks["mcp"] = False
    checks["analysis_worker"] = bool(jobs.worker_metrics()["running"])
    ready = all(checks.values())
    if not ready:
        response.status_code = 503
    return {"status": "ready" if ready else "not_ready", "checks": checks}
