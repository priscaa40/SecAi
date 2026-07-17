from __future__ import annotations

import hashlib
import hmac
import secrets

from fastapi import HTTPException

from secai import database


def signup(email: str, password: str) -> dict:
    """Create an owner account and return a session."""
    normalized_email = email.strip().lower()
    if database.get_user_by_email(normalized_email):
        raise HTTPException(status_code=409, detail="An account already exists for this email.")
    try:
        user = database.create_user(normalized_email, hash_password(password))
    except database.INTEGRITY_ERRORS as exc:
        raise HTTPException(status_code=409, detail="An account already exists for this email.") from exc
    session = database.create_session(user["id"])
    return {"token": session["token"], "user": _public_user(user)}


def login(email: str, password: str) -> dict:
    """Verify an owner password and return a session."""
    user = database.get_user_by_email(email)
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    session = database.create_session(user["id"])
    return {"token": session["token"], "user": _public_user(user)}


def logout(token: str) -> None:
    """End one owner session."""
    database.delete_session(token)


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2 and a random salt."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 260_000)
    return f"pbkdf2_sha256$260000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Return whether a password matches a stored PBKDF2 hash."""
    try:
        algorithm, iterations, salt_hex, digest_hex = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _public_user(user: dict) -> dict:
    """Return user fields safe for API responses."""
    return {"id": user["id"], "email": user["email"], "created_at": user["created_at"]}
