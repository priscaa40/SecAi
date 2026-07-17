from __future__ import annotations

import re

_REGION = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def normalize_region(value: str) -> str:
    """Return one bounded Alibaba region identifier safe for SDK endpoint construction."""
    region = value.strip().lower()
    if not 2 <= len(region) <= 40 or not _REGION.fullmatch(region):
        raise ValueError("Choose a valid Alibaba Cloud region.")
    return region


def sls_endpoint_for_region(region: str) -> str:
    """Return the only SLS endpoint SecAi accepts for a selected region."""
    return f"{normalize_region(region)}.log.aliyuncs.com"


def validate_sls_endpoint(region: str, endpoint: str) -> str:
    """Reject arbitrary hosts so ECS role credentials only reach Alibaba SLS."""
    normalized = endpoint.strip().lower().rstrip(".")
    expected = sls_endpoint_for_region(region)
    if normalized != expected:
        raise ValueError(f"Website activity must use the Alibaba Cloud endpoint {expected}.")
    return normalized
