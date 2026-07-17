from __future__ import annotations

from ipaddress import ip_address, ip_network

from fastapi import Request


def trusted_client_ip(request: Request, trusted_proxy_cidrs: str = "") -> str:
    """Return the client IP, honoring forwarding headers only from trusted proxies."""
    peer = request.client.host if request.client else ""
    if not _address_in_cidrs(peer, trusted_proxy_cidrs):
        return peer

    forwarded = request.headers.get("x-forwarded-for", "")
    candidates = [value.strip() for value in forwarded.split(",") if value.strip()]
    real_ip = request.headers.get("x-real-ip", "").strip()
    if not candidates and real_ip:
        candidates = [real_ip]

    # Walk from the proxy nearest the app toward the original client. This avoids
    # trusting attacker-supplied values prepended to X-Forwarded-For.
    for candidate in reversed(candidates):
        if not _valid_ip(candidate):
            continue
        if not _address_in_cidrs(candidate, trusted_proxy_cidrs):
            return candidate
    return peer


def _address_in_cidrs(value: str, configured_cidrs: str) -> bool:
    try:
        address = ip_address(value)
    except ValueError:
        return False
    for configured in configured_cidrs.split(","):
        configured = configured.strip()
        if not configured:
            continue
        try:
            network = ip_network(configured, strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return True
    return False


def _valid_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True
