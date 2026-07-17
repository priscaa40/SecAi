from __future__ import annotations

from fastapi import HTTPException, Request

from secai.security.client_ip import request_client_ip
from secai.security.rate_limit import consume


def enforce_request_rate(request: Request, scope: str, limit: int, window_seconds: int = 60) -> None:
    """Apply an in-process rate limit to a public endpoint."""
    peer = request_client_ip(request)
    if not consume(f"public:{scope}:{peer}", limit, window_seconds):
        raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")
