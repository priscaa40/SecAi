from __future__ import annotations

from typing import Any

from secai import database
from secai.actions.capabilities import requires_approval, tool_name_for_action
from secai.actions.protection_presentation import TEMPORARY_BLOCK_DURATION_SECONDS, display_ip
from secai.agent.schemas import IncidentResponse, InvestigationDecision, ReviewDecision, SecurityProfileContext
from secai.agent.validation import response_capabilities


def persist_incident(
    event: dict[str, Any],
    investigation: InvestigationDecision,
    review: ReviewDecision,
    response: IncidentResponse,
    security_profile: SecurityProfileContext,
    agent_trace: list[dict[str, Any]] | None = None,
    analysis_job_id: int | None = None,
) -> dict[str, Any]:
    """Store one reviewed report with an approval-first action contract."""
    action_requires_approval = requires_approval(response.action)
    human_checkpoint = response.human_checkpoint
    if action_requires_approval and not human_checkpoint:
        human_checkpoint = "Confirm this source IP is not trusted before applying the temporary block."
    if not action_requires_approval:
        human_checkpoint = ""

    protection_status = _protection_status(response, event)
    summary = {
        "title": response.headline,
        "potential_impact": response.potential_impact,
        "evidence": response.evidence_summary,
        "recommended_action": response.recommended_action,
    }
    recommendation = {
        "title": response.recommendation_title,
        "explanation": response.recommendation_explanation,
        "steps": response.recommendation_steps,
    }
    report_text = response.as_text()
    grouped_evidence = (event.get("metadata") or {}).get("evidence")
    evidence_count = len(grouped_evidence) if isinstance(grouped_evidence, list) and grouped_evidence else 1
    evidence = {
        "observed_at": _observed_at(event),
        "source": event.get("source"),
        "ip": event.get("ip"),
        "method": event.get("method"),
        "path": event.get("path"),
        "status_code": event.get("status_code"),
        "signals": list(event.get("signals") or []),
    }
    incident = {
        "site_id": event["site_id"],
        "title": summary["title"],
        "severity": investigation.severity,
        "status": "needs_review" if action_requires_approval else "reported",
        "attack_type": security_profile["name"],
        "affected_route": investigation.affected_route or event.get("path"),
        "confidence": investigation.confidence,
        "report": report_text,
        "recommended_action": {
            "action": response.action,
            "target": response.target,
            "duration_seconds": TEMPORARY_BLOCK_DURATION_SECONDS if action_requires_approval else None,
            "reason": response.reason,
            "requires_approval": action_requires_approval,
            "human_checkpoint": human_checkpoint,
            "security_profile_id": security_profile["id"],
            "security_reference_ids": sorted(set(security_profile["reference_ids"])),
            "false_positive_considerations": investigation.false_positive_considerations,
            "uncertainty": investigation.uncertainty,
            "investigation_summary": investigation.summary,
            "review_summary": review.reason,
            "report_sections": {
                "owner_summary": summary,
                "summary": response.technical_summary,
                "what_happened": response.what_happened,
                "what_is_unknown": response.what_is_unknown,
                "why_it_matters": response.why_it_matters,
            },
            "owner_recommendation": recommendation,
            "protection_status": protection_status,
            "evidence_used": sorted(set(investigation.evidence_used)),
            "evidence": evidence,
            "evidence_source": event.get("source"),
            "source_event_id": event.get("id"),
            "evidence_sources": [event.get("source")] if event.get("source") else [],
            "source_event_ids": [event["id"]] if isinstance(event.get("id"), int) else [],
            "evidence_count": evidence_count,
            "agent_trace": agent_trace or [],
        },
    }
    return database.insert_incident(
        incident,
        analysis_job_id=analysis_job_id,
        action_job={
            "action": response.action,
            "tool_name": tool_name_for_action(response.action),
            "requires_approval": action_requires_approval,
        },
    )


def _protection_status(response: IncidentResponse, event: dict[str, Any]) -> dict[str, str]:
    """Explain automation through the website's connected access, not internal action names."""
    capabilities = response_capabilities(event)
    if response.action == "apply_temporary_ip_block":
        target = display_ip(response.target)
        return {
            "state": "approval_required",
            "title": f"Block {target} for 1 hour?",
            "explanation": (
                "SecAi can temporarily stop requests from this address while you investigate. "
                "Nothing changes until you approve."
            ),
        }
    if event.get("source") == "browser":
        return {
            "state": "unavailable",
            "title": "Automatic blocking is unavailable",
            "explanation": (
                "Your current connection provides browser activity only. It is not authorized to access server logs "
                "or network controls. Because of this, the source of the activity cannot be verified or blocked automatically, "
                "and the result of the activity cannot be confirmed."
            ),
        }
    if not capabilities.get("verified_source_ip"):
        return {
            "state": "unavailable",
            "title": "Automatic blocking is unavailable",
            "explanation": (
                "Your cloud connection provides server activity, but this incident does not contain a verified public "
                "source address. The source of the activity cannot be blocked automatically without that address."
            ),
        }
    if "apply_temporary_ip_block" not in capabilities.get("available_actions", []):
        return {
            "state": "not_authorized",
            "title": "Automatic blocking is not authorized",
            "explanation": (
                "The source was identified through your cloud logs, but this website connection is not authorized to "
                "change network controls. No traffic change was made."
            ),
        }
    return {
        "state": "not_proposed",
        "title": "No automatic traffic change was proposed",
        "explanation": (
            "The source was identified through your cloud logs, but the reviewed evidence did not support an automatic "
            "traffic change. No network rule was created."
        ),
    }


def _observed_at(event: dict[str, Any]) -> str | None:
    sls = (event.get("metadata") or {}).get("sls") or {}
    return sls.get("timestamp") or sls.get("time") or event.get("created_at")
