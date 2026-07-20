from __future__ import annotations

from fastapi import APIRouter, Response

from secai import database
from secai.actions import mcp_client as action_mcp_client
from secai.agent import action_jobs, jobs
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
        "action_worker": action_jobs.worker_metrics(),
    }


@router.get("/ready")
def readiness(response: Response) -> dict:
    """Verify the database, Qwen configuration, MCP process, and queue admission state."""
    checks: dict[str, bool] = {
        "database": False,
        "qwen_configured": bool(get_settings().dashscope_api_key),
        "knowledge_mcp": False,
        "action_mcp": False,
    }
    try:
        with database.connect() as conn:
            checks["database"] = conn.execute("select 1 as healthy").fetchone()["healthy"] == 1
    except Exception:
        pass
    try:
        checks["knowledge_mcp"] = bool(mcp_client.list_tools())
    except Exception:
        checks["knowledge_mcp"] = False
    try:
        discovered = {tool["name"] for tool in action_mcp_client.list_tools()}
        checks["action_mcp"] = {
            "send_owner_security_alert",
            "collect_follow_up_cloud_evidence",
            "apply_temporary_ip_block",
        }.issubset(discovered)
    except Exception:
        checks["action_mcp"] = False
    checks["analysis_worker"] = bool(jobs.worker_metrics()["running"])
    checks["action_worker"] = bool(action_jobs.worker_metrics()["running"])
    ready = all(checks.values())
    if not ready:
        response.status_code = 503
    return {"status": "ready" if ready else "not_ready", "checks": checks}
