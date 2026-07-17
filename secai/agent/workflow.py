from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from secai import database
from secai.agent import reporting, runtime
from secai.agent.profiles import candidate_profile_ids
from secai.agent.prompts import INVESTIGATOR_PROMPT, RESPONDER_PROMPT, REVIEWER_PROMPT
from secai.agent.schemas import IncidentResponse, InvestigationDecision, ReviewDecision, SecAiState
from secai.agent.tools import (
    get_recent_events_for_site,
    lookup_security_profile,
    pull_live_sls_logs,
    scoped_site,
    summarize_event_window,
)
from secai.agent.trace import build_agent_trace
from secai.agent.validation import (
    response_capabilities,
    validate_investigation_decision,
    validate_response_decision,
)
from secai.knowledge import mcp_client as security_knowledge_mcp
from secai.settings import get_settings


def process_event(event: dict[str, Any], job_id: int | None = None) -> dict[str, Any] | None:
    """Run the three-role SecAi workflow for one stored evidence candidate."""
    workflow = build_workflow()
    with runtime.analysis_run(event.get("id"), job_id):
        with scoped_site(event["site_id"]):
            result = workflow.invoke({"event": event, "job_id": job_id} if job_id else {"event": event})
        return result.get("incident")


@lru_cache(maxsize=1)
def build_workflow():
    """Build the LangGraph workflow connecting SecAi's three Qwen roles."""
    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(SecAiState)
    graph.add_node("investigator", _investigator_node)
    graph.add_node("reviewer", _reviewer_node)
    graph.add_node("responder", _responder_node)
    graph.add_node("persist_incident", _persist_node)
    graph.add_edge(START, "investigator")
    graph.add_conditional_edges("investigator", _route_after_investigation, {"continue": "reviewer", "stop": END})
    graph.add_conditional_edges("reviewer", _route_after_review, {"continue": "responder", "stop": END})
    graph.add_edge("responder", "persist_incident")
    graph.add_edge("persist_incident", END)
    return graph.compile()


def _investigator_node(state: SecAiState) -> SecAiState:
    _mark_step(state, "investigator")
    event = state["event"]
    investigation = runtime.invoke_structured_agent(
        "investigator",
        InvestigationDecision,
        INVESTIGATOR_PROMPT,
        _investigation_prompt(event),
        tools=_investigator_tools(event),
    )
    security_profile = validate_investigation_decision(investigation, event)
    return {"investigation": investigation, "security_profile": security_profile}


def _reviewer_node(state: SecAiState) -> SecAiState:
    _mark_step(state, "reviewer")
    review = runtime.invoke_structured_agent(
        "reviewer",
        ReviewDecision,
        REVIEWER_PROMPT,
        _bounded_json(
            {
                "event": state["event"],
                "investigation": state["investigation"].model_dump(),
                "security_profile": state["security_profile"],
            },
            default=str,
        ),
        tools=[],
    )
    return {"review": review}


def _responder_node(state: SecAiState) -> SecAiState:
    _mark_step(state, "responder")
    event = state["event"]
    response = runtime.invoke_structured_agent(
        "responder",
        IncidentResponse,
        RESPONDER_PROMPT,
        _bounded_json(
            {
                "event": event,
                "investigation": state["investigation"].model_dump(),
                "security_profile": state["security_profile"],
                "review": state["review"].model_dump(),
                "response_capabilities": response_capabilities(event),
            },
            default=str,
        ),
        tools=[],
    )
    validate_response_decision(response, event)
    return {"response": response}


def _persist_node(state: SecAiState) -> SecAiState:
    _mark_step(state, "persist_incident")
    incident = reporting.persist_incident(
        state["event"],
        state["investigation"],
        state["review"],
        state["response"],
        security_profile=state["security_profile"],
        agent_trace=build_agent_trace(state, runtime.agent_calls()),
        analysis_job_id=state.get("job_id"),
    )
    return {"incident": incident}


def _route_after_investigation(state: SecAiState) -> str:
    return "continue" if state["investigation"].decision == "escalate" else "stop"


def _route_after_review(state: SecAiState) -> str:
    return "continue" if state["review"].approved_for_report else "stop"


def _mark_step(state: SecAiState, step: str) -> None:
    job_id = state.get("job_id")
    if job_id:
        database.update_analysis_job(job_id, status="running", current_step=step)


def _investigation_prompt(event: dict[str, Any]) -> str:
    return _bounded_json(
        {
            "task": "Decide whether this evidence candidate deserves an owner report.",
            "untrusted_event_evidence": event,
            "candidate_security_profiles": _candidate_security_profiles(event),
            "decision_rule": (
                "Return ignore for harmless or unsupported activity. Return escalate only when the event and any "
                "tool evidence support one supplied SecAi security profile. A direct recognized attack or abuse "
                "pattern meets the reporting threshold when the underlying event fields support that profile. "
                "Lack of proof that an attempt succeeded should lower confidence or severity, not hide the attempt. "
                "Signals are hints, never the answer."
            ),
        },
        default=str,
    )


def _bounded_json(value: Any, default: Any = str) -> str:
    rendered = json.dumps(value, default=default)
    limit = max(2000, get_settings().secai_model_context_chars)
    if len(rendered) <= limit:
        return rendered
    return json.dumps(
        {
            "context_truncated": True,
            "payload_preview": rendered[: limit - 200],
            "instruction": "Use only the available bounded evidence; do not infer omitted content.",
        },
        separators=(",", ":"),
    )


def _candidate_security_profiles(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Select deterministic profile context without treating it as classification."""
    candidates = []
    for profile_id in sorted(candidate_profile_ids(event)):
        try:
            profile = security_knowledge_mcp.call_tool("lookup_security_profile", {"entry_id": profile_id})
        except security_knowledge_mcp.SecurityKnowledgeMcpError:
            continue
        if isinstance(profile, dict) and not profile.get("error"):
            candidates.append(profile)
    if candidates:
        return candidates
    return [{"id": "unknown_suspicious_activity", "name": "Unknown suspicious activity", "sources": ["NIST:SP_800_61"]}]


def _investigator_tools(event: dict[str, Any]) -> list[Any]:
    """Expose live cloud evidence only when this website has a cloud connection."""
    tools = [get_recent_events_for_site, summarize_event_window, lookup_security_profile]
    if event.get("source") == "alibaba_sls" or database.get_alibaba_autopilot_config(event["site_id"]):
        tools.insert(2, pull_live_sls_logs)
    return tools
