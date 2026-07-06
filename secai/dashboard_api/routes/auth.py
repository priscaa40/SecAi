from __future__ import annotations

from fastapi import APIRouter, Depends

from secai.dashboard_api import auth_service
from secai.dashboard_api.dependencies import current_user, session_token
from secai.models import AuthLoginIn, AuthOut, AuthSignupIn


router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/signup", response_model=AuthOut)
def signup(payload: AuthSignupIn) -> dict:
    """Create a website owner account."""
    return auth_service.signup(payload.email, payload.password)


@router.post("/login", response_model=AuthOut)
def login(payload: AuthLoginIn) -> dict:
    """Log in a website owner."""
    return auth_service.login(payload.email, payload.password)


@router.post("/logout")
def logout(token: str = Depends(session_token)) -> dict:
    """Log out the current owner session."""
    auth_service.logout(token)
    return {"status": "ok"}


@router.get("/me")
def me(user: dict = Depends(current_user)) -> dict:
    """Return the current website owner."""
    return {"user": user}
