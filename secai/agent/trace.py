from __future__ import annotations

from typing import Any

from secai.agent.schemas import SecAiState


def tool_names_from_result(result: dict[str, Any]) -> list[str]:
    """Return unique tools invoked during one LangChain agent call."""
    names: list[str] = []
    for message in result.get("messages") or []:
        for tool_call in getattr(message, "tool_calls", None) or []:
            name = tool_call.get("name") if isinstance(tool_call, dict) else getattr(tool_call, "name", None)
            if name and str(name) not in names:
                names.append(str(name))
    return names


def build_agent_trace(state: SecAiState, runtime_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build the compact visible trace of SecAi's three Qwen roles."""
    runtime_by_agent = {str(item["agent"]): item for item in runtime_calls}
    investigation = state["investigation"]
    review = state["review"]
    response = state["response"]
    outputs: dict[str, dict[str, Any]] = {
        "investigator": {
            "decision": investigation.decision,
            "profile": investigation.security_profile_id,
            "confidence": investigation.confidence,
            "summary": investigation.summary,
            "security_reference_ids": state["security_profile"]["reference_ids"],
            "related_event_count": investigation.related_event_count,
            "evidence_used": investigation.evidence_used,
        },
        "reviewer": {
            "decision": "approved" if review.approved_for_report else "stopped",
            "summary": review.reason,
            "evidence_gaps": review.evidence_gaps,
        },
        "responder": {
            "decision": response.action,
            "summary": response.headline,
            "target": response.target,
            "human_checkpoint": response.human_checkpoint,
        },
    }
    trace: list[dict[str, Any]] = []
    for agent in ("investigator", "reviewer", "responder"):
        runtime = runtime_by_agent.get(agent, {})
        trace.append(
            {
                "agent": agent,
                "model": runtime.get("model"),
                "latency_ms": runtime.get("latency_ms"),
                "input_tokens": runtime.get("input_tokens"),
                "output_tokens": runtime.get("output_tokens"),
                "total_tokens": runtime.get("total_tokens"),
                "model_calls": runtime.get("model_calls"),
                "tools": runtime.get("tools", []),
                **outputs[agent],
            }
        )
    return trace
