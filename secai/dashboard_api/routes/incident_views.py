from __future__ import annotations

from typing import Any

from secai import database
from secai.actions.protection_presentation import protection_presentation


def incident_views(incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build API views for incidents without issuing one policy query per row."""
    incident_ids = {item["id"] for item in incidents}
    policies = database.get_policies_for_incidents(incident_ids)
    action_jobs = database.get_action_jobs_for_incidents(incident_ids)
    event_ids = {event_id for item in incidents for event_id in _source_event_ids(item.get("recommended_action") or {})}
    events = database.get_events(event_ids)
    return [
        _build_incident_view(
            item,
            policy=policies.get(item["id"]),
            action_job=action_jobs.get(item["id"]),
            events=[
                events[event_id]
                for event_id in _source_event_ids(item.get("recommended_action") or {})
                if event_id in events
            ],
        )
        for item in incidents
    ]


def incident_view(incident: dict[str, Any]) -> dict[str, Any]:
    """Expose evidence, decision state, and execution state as separate fields."""
    policy = database.get_policy_for_incident(incident["id"])
    action_job = database.get_action_job_for_incident(incident["id"])
    events = [
        event
        for event_id in _source_event_ids(incident.get("recommended_action") or {})
        if (event := database.get_event(event_id)) is not None
    ]
    return _build_incident_view(incident, policy=policy, action_job=action_job, events=events)


def _build_incident_view(
    incident: dict[str, Any],
    *,
    policy: dict[str, Any] | None,
    action_job: dict[str, Any] | None,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    execution_status = policy["status"] if policy else (action_job or {}).get("status", "not_started")
    policy_view = (
        {
            "status": policy["status"],
            "provider": policy.get("provider"),
            "provider_rule_id": policy.get("provider_rule_id"),
            "error_message": policy.get("error_message"),
            "expires_at": policy.get("expires_at"),
            "target": policy["target"],
            "action": policy["action"],
        }
        if policy
        else None
    )
    return {
        **incident,
        "evidence": [evidence for event in events for evidence in _event_evidence(event)],
        "policy": policy_view,
        "action_job": action_job,
        "execution_status": execution_status,
        "active_policy": bool(policy and policy["status"] == "active"),
        "protection": protection_presentation(incident, policy, action_job=action_job),
    }


def _source_event_ids(action: dict[str, Any]) -> list[int]:
    """Return unique evidence event IDs in recommendation order."""
    values = action.get("source_event_ids") or []
    if action.get("source_event_id") is not None:
        values = [action["source_event_id"], *values]
    return list(dict.fromkeys(value for value in values if isinstance(value, int)))


def _event_evidence(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize a single event or grouped event into report evidence rows."""
    grouped = (event.get("metadata") or {}).get("evidence")
    items = grouped if isinstance(grouped, list) and grouped else [event]
    return [
        {
            "observed_at": item.get("observed_at") or item.get("created_at") or event.get("created_at"),
            "source": item.get("source") or event.get("source"),
            "ip": item.get("ip"),
            "method": item.get("method"),
            "path": item.get("path"),
            "status_code": item.get("status_code"),
            "signals": item.get("signals") or [],
            "event_type": item.get("event_type") or event.get("event_type"),
        }
        for item in items
        if isinstance(item, dict)
    ]
