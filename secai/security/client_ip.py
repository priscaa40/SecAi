from __future__ import annotations

from ipaddress import ip_address, ip_network

from fastapi import Request

from secai.settings import get_settings


def request_client_ip(request: Request) -> str:
    """Return the visitor IP, trusting forwarding headers only from configured proxies."""
    peer = request.client.host if request.client else "unknown"
    return resolve_client_ip(
        peer,
        request.headers.get("x-forwarded-for", ""),
        request.headers.get("x-real-ip", ""),
        get_settings().secai_trusted_proxy_cidrs,
    )


def resolve_client_ip(peer: str, forwarded_for: str, real_ip: str, trusted_proxy_cidrs: str) -> str:
    """Walk a trusted proxy chain from nearest hop to the original visitor."""
    if not _address_in_cidrs(peer, trusted_proxy_cidrs):
        return peer or "unknown"
    candidates = [value.strip() for value in forwarded_for.split(",") if value.strip()]
    if not candidates and real_ip.strip():
        candidates = [real_ip.strip()]
    for candidate in reversed(candidates):
        if _valid_ip(candidate) and not _address_in_cidrs(candidate, trusted_proxy_cidrs):
            return candidate
    return peer or "unknown"


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
