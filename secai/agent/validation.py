from __future__ import annotations

from secai.agent.schemas import RemediationDecision, TriageDecision
from secai.integrations import alibaba_autopilot
from secai.knowledge import mcp_client as security_knowledge_mcp


GENERIC_ATTACK_WORDS = {"attempt", "attack", "activity", "incident", "possible", "suspected", "likely"}


def apply_safety_guardrails(remediation: RemediationDecision) -> dict:
    """Validate remediation and return normalized model output."""
    validate_remediation_against_security_profile(remediation)
    return remediation.model_dump()


def validate_triage_decision(triage: TriageDecision) -> None:
    """Reject triage output that is not grounded in official-source security knowledge."""
    entry = _lookup_security_profile(triage.security_profile_id)
    if not entry:
        raise ValueError(f"Unknown security profile ID: {triage.security_profile_id}")
    if not _attack_type_matches_security_profile(triage.attack_type, entry["name"]):
        raise ValueError(f"Attack type {triage.attack_type!r} does not match security profile name: {entry['name']}")
    triage.attack_type = entry["name"]
    if not triage.source_ids:
        raise ValueError("TriageDecision must include source_ids")
    invalid_sources = set(triage.source_ids) - set(entry["sources"])
    if invalid_sources:
        raise ValueError(f"TriageDecision used invalid source_ids: {sorted(invalid_sources)}")


def validate_remediation_decision(remediation: RemediationDecision, triage: TriageDecision, site_id: str | None = None) -> None:
    """Reject remediation that does not match the triage result."""
    if remediation.security_profile_id != triage.security_profile_id:
        raise ValueError("RemediationDecision security_profile_id must match TriageDecision")
    validate_remediation_against_security_profile(remediation)
    if site_id:
        available_actions = alibaba_autopilot.available_actions_for_site(site_id)
        if remediation.action not in available_actions:
            raise ValueError(
                f"Action {remediation.action} is not available for site {site_id}. "
                "Connect Alibaba WAF Autopilot before recommending WAF remediation."
            )


def validate_remediation_against_security_profile(remediation: RemediationDecision) -> None:
    """Reject remediation actions not allowed by the selected security profile."""
    entry = _lookup_security_profile(remediation.security_profile_id)
    if not entry:
        raise ValueError(f"Unknown remediation security profile ID: {remediation.security_profile_id}")
    if not remediation.source_ids:
        raise ValueError("RemediationDecision must include source_ids")
    invalid_sources = set(remediation.source_ids) - set(entry["sources"])
    if invalid_sources:
        raise ValueError(f"RemediationDecision used invalid source_ids: {sorted(invalid_sources)}")
    if remediation.action not in entry["allowed_actions"]:
        raise ValueError(f"Action {remediation.action} is not allowed for {remediation.security_profile_id}")


def _lookup_security_profile(entry_id: str) -> dict | None:
    """Read one profile through the security knowledge MCP tool boundary."""
    entry = security_knowledge_mcp.call_tool("lookup_security_profile", {"entry_id": entry_id})
    return None if entry.get("error") else entry


def _attack_type_matches_security_profile(candidate: str, canonical_name: str) -> bool:
    """Return whether an agent's attack label is a close match for the security profile name."""
    candidate_words = _meaningful_words(candidate)
    canonical_words = _meaningful_words(canonical_name)
    if not candidate_words or not canonical_words:
        return False
    return candidate_words == canonical_words or candidate_words.issubset(canonical_words) or canonical_words.issubset(candidate_words)


def _meaningful_words(value: str) -> set[str]:
    """Normalize an attack label into meaningful comparison words."""
    normalized = "".join(character.lower() if character.isalnum() else " " for character in value)
    return {word for word in normalized.split() if word not in GENERIC_ATTACK_WORDS}
