from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Any

from secai.agent.profiles import candidate_profile_ids
from secai.agent.schemas import IncidentResponse, InvestigationDecision, SecurityProfileContext
from secai.integrations import alibaba_autopilot
from secai.knowledge import mcp_client as security_knowledge_mcp
from secai.models import REPORTING_ACTIONS
from secai.settings import get_settings


def validate_investigation_decision(
    investigation: InvestigationDecision, event: dict[str, Any]
) -> SecurityProfileContext:
    """Validate Qwen's profile selection and return application-owned profile data."""
    entry = _validated_profile(investigation.security_profile_id)
    if investigation.decision == "escalate" and investigation.security_profile_id not in candidate_profile_ids(event):
        raise ValueError("Escalated investigation must use a security profile supplied in its evidence prompt")
    return {"id": entry["id"], "name": entry["name"], "reference_ids": list(entry["sources"])}


def validate_response_decision(
    response: IncidentResponse,
    event: dict[str, Any],
) -> None:
    """Ensure the response stays grounded in the investigation and source capabilities."""
    capabilities = response_capabilities(event)
    if response.action not in capabilities["available_actions"]:
        raise ValueError(f"Action {response.action} is not available for this evidence source")
    if response.action in REPORTING_ACTIONS:
        response.target = ""
        response.human_checkpoint = ""
        return
    response.target = validate_remediation_target(response.action, response.target, event)


def response_capabilities(event: dict[str, Any]) -> dict[str, Any]:
    """Return the small action contract safe to include in the responder prompt."""
    available_actions = ["monitor", "notify_admin"]
    verified_ip = verified_public_sls_ip(event)
    if verified_ip:
        provider_actions = set(alibaba_autopilot.available_actions_for_site(event["site_id"]))
        if "block_ip" in provider_actions:
            available_actions.append("block_ip")
    return {
        "available_actions": available_actions,
        "trusted_server_evidence": bool(verified_ip),
        "verified_source_ip": verified_ip,
    }


def verified_public_sls_ip(event: dict[str, Any]) -> str | None:
    """Return the observed public IP only for trusted server-side evidence."""
    if event.get("source") != "alibaba_sls":
        return None
    value = str(event.get("ip") or "").strip()
    if not value:
        return None
    try:
        address = ip_address(value)
    except ValueError:
        return None
    return str(address) if address.is_global else None


def validate_remediation_target(action: str, target_value: str, event: dict | None = None) -> str:
    """Validate the only active network action: blocking one observed public IP."""
    if action in REPORTING_ACTIONS:
        return ""
    if action != "block_ip":
        raise ValueError(f"Unsupported remediation action: {action}")
    target_value = (target_value or "").strip()
    if not target_value:
        raise ValueError("IP blocking requires a source IP target")
    try:
        if "/" in target_value:
            target = ip_network(target_value, strict=False)
            if target.num_addresses != 1:
                raise ValueError("block_ip must target one address")
            address = target.network_address
        else:
            address = ip_address(target_value)
            target = ip_network(f"{address}/{32 if address.version == 4 else 128}", strict=False)
    except ValueError as exc:
        raise ValueError("The remediation target is not one valid IP address") from exc
    if not address.is_global:
        raise ValueError("Remediation cannot target a private, reserved, loopback, multicast, or non-global address")

    configured = get_settings().secai_remediation_protected_cidrs
    try:
        protected = [ip_network(value.strip(), strict=False) for value in configured.split(",") if value.strip()]
    except ValueError as exc:
        raise ValueError("SECAI_REMEDIATION_PROTECTED_CIDRS contains an invalid network") from exc
    if any(address in network for network in protected if address.version == network.version):
        raise ValueError("The remediation target overlaps an owner-protected network")

    if event is not None:
        observed_ip = verified_public_sls_ip(event)
        if not observed_ip:
            raise ValueError("IP blocking requires a public source IP from Alibaba SLS evidence")
        if address != ip_address(observed_ip):
            raise ValueError("The remediation target must equal the source IP observed in Alibaba SLS evidence")
    return str(target)


def _validated_profile(profile_id: str) -> dict[str, Any]:
    entry = _lookup_security_profile(profile_id)
    if not entry:
        raise ValueError(f"Unknown security profile ID: {profile_id}")
    return entry


def _lookup_security_profile(entry_id: str) -> dict | None:
    """Read one profile through the security knowledge MCP boundary."""
    entry = security_knowledge_mcp.call_tool("lookup_security_profile", {"entry_id": entry_id})
    return None if entry.get("error") else entry
