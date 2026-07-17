from __future__ import annotations

from fastapi import Depends, Header, HTTPException

from secai import database
from secai.settings import get_settings


def session_token(authorization: str | None = Header(default=None)) -> str:
    """Return the bearer token from the Authorization header."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Login is required.")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Login is required.")
    return token


def current_user(authorization: str | None = Header(default=None)) -> dict:
    """Return the authenticated website owner."""
    bearer = session_token(authorization)
    user = database.get_user_by_session(bearer)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    return user


def current_user_email(user: dict = Depends(current_user)) -> str:
    """Return the authenticated owner's email."""
    return user["email"]


def ensure_site_owner(site_id: str, owner_email: str) -> None:
    """Reject access when a site does not belong to the authenticated owner."""
    if not database.user_owns_site(site_id, owner_email):
        raise HTTPException(status_code=404, detail="Site not found")


def ensure_incident_owner(incident: dict, owner_email: str) -> None:
    """Reject access when an incident is outside the authenticated owner's sites."""
    ensure_site_owner(incident["site_id"], owner_email)


def is_judge_owner(owner_email: str) -> bool:
    """Return whether this request belongs to the isolated public judge tenant."""
    settings = get_settings()
    return settings.secai_judge_mode and owner_email == settings.secai_judge_email


def protect_judge_configuration(site_id: str, owner_email: str) -> None:
    """Prevent public judge credentials from changing cloud or automation configuration."""
    if site_id == "judge-site" and is_judge_owner(owner_email):
        raise HTTPException(
            status_code=403,
            detail="Judge cloud and automation settings are preconfigured and read-only.",
        )
