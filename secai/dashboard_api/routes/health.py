from __future__ import annotations

from fastapi import APIRouter


router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    """Return a simple service health response."""
    return {"status": "ok", "service": "secai-autopilot"}
