from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet
from fastapi import HTTPException

from secai.settings import get_settings


def encrypt_secret(value: str) -> str:
    """Encrypt a sensitive setting for database storage."""
    return _fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    """Decrypt a sensitive setting read from the database."""
    return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")


def mask_secret(value: str) -> str:
    """Return a short masked representation of a secret."""
    if len(value) <= 4:
        return "****"
    return f"****{value[-4:]}"


def _fernet() -> Fernet:
    """Build a Fernet instance from SECAI_SECRET_KEY."""
    secret_key = get_settings().secai_secret_key
    if not secret_key:
        raise HTTPException(status_code=500, detail="SECAI_SECRET_KEY must be configured before saving Alibaba Cloud credentials.")
    digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))
