from __future__ import annotations

import hashlib
from datetime import UTC, datetime


def utc_now() -> str:
    """Return the current UTC time as an ISO string."""
    return datetime.now(UTC).isoformat()


def token_hash(token: str) -> str:
    """Return the stable hash stored for a one-time or session token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
