from __future__ import annotations

import os
from typing import Any

import pytest
from pydantic import BaseModel

from secai import database
from secai.actions import mcp_client as action_mcp_client
from secai.actions import mcp_server
from secai.agent import executor, runtime, schemas, validation, workflow
from secai.agent.schemas import ActionExecutionReport
from secai.evaluation.runner import load_cases, score_predictions
from secai.integrations.qwen_cloud import get_chat_model
from secai.knowledge import mcp_client as knowledge_mcp_client
from secai.models import RemediationAction
from secai.settings import get_settings


def _investigation(decision: schemas.InvestigationDecisionType = "escalate") -> schemas.InvestigationDecision:
    return schemas.InvestigationDecision(
        decision=decision,
        title="Possible SQL injection against product search",
        security_profile_id="sql_injection_attempt" if decision == "escalate" else "unknown_suspicious_activity",
        severity="high" if decision == "escalate" else "low",
        confidence=0.91 if decision == "escalate" else 0.2,
        affected_route="/products",
        summary="The request contains a SQL operator and comment pattern.",
        related_event_count=2,
        notable_patterns=["Repeated SQL-like query strings"],
        evidence_used=["Alibaba SLS request records"],
        false_positive_considerations=["Owner-run tests can look similar."],
        uncertainty="Application impact is not visible in access logs.",
    )


def _response(action: RemediationAction = "apply_temporary_ip_block") -> schemas.IncidentResponse:
    return schemas.IncidentResponse(
        headline="Someone tried to send a harmful database command through your product page",
        potential_impact="If successful, it could expose or change stored information.",
        evidence_summary="Your logs show this activity reached your website.",
        recommended_action=(
            "Block the source temporarily while you investigate."
            if action == "apply_temporary_ip_block"
            else "Review the affected page and supporting evidence."
        ),
        technical_summary="The requests contain a database command pattern associated with injection attempts.",
        what_happened="Repeated requests tried to alter the product database query.",
        what_is_unknown="The evidence does not show whether the database processed the requests.",
        why_it_matters="A vulnerable query could expose or change stored data.",
        recommendation_title="Secure the affected query",
        recommendation_explanation="Prevent submitted text from changing database commands.",
        recommendation_steps=["Use parameterized database queries.", "Review database activity around the requests."],
        action=action,
        target="8.8.4.4" if action == "apply_temporary_ip_block" else "",
        reason="The reviewed evidence supports this response.",
        human_checkpoint="Confirm this is not a trusted source." if action == "apply_temporary_ip_block" else "",
    )


def _sls_event() -> dict[str, Any]:
    return {
        "site_id": "test-site",
        "source": "alibaba_sls",
        "event_type": "sls_sql_injection_group",
        "method": "GET",
        "path": "/products",
        "query": "id=1 OR 1=1--",
        "status_code": 403,
        "ip": "8.8.4.4",
        "signals": ["sql_injection_pattern"],
        "metadata": {"sls": {"request_id": "group-1"}},
    }


def _incident(action: str, status: str) -> dict[str, Any]:
    return database.insert_incident(
        {
            "site_id": "test-site",
            "title": "Executable security response",
            "severity": "high",
            "status": status,
            "attack_type": "Suspicious activity",
            "confidence": 0.9,
            "report": "SecAi found activity that requires a response.",
            "recommended_action": {
                "action": action,
                "target": "8.8.4.4" if action == "apply_temporary_ip_block" else "",
                "reason": "Use the connected response capability.",
            },
        }
    )


def test_qwen_workflow_runs_investigator_reviewer_responder_and_queues_action(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(validation.alibaba_autopilot, "available_actions_for_site", lambda site_id: ["apply_temporary_ip_block"])

    def fake_agent(name, response_format, system_prompt, user_prompt, tools):
        calls.append(name)
        if response_format is schemas.InvestigationDecision:
            assert {tool.name for tool in tools} >= {"pull_live_sls_logs", "lookup_security_profile"}
            return _investigation()
        if response_format is schemas.ReviewDecision:
            return schemas.ReviewDecision(approved_for_report=True, reason="The evidence supports a report.")
        if response_format is schemas.IncidentResponse:
            assert "apply_temporary_ip_block" in user_prompt
            return _response()
        raise AssertionError(response_format)

    monkeypatch.setattr(runtime, "invoke_structured_agent", fake_agent)
    event = database.insert_event(_sls_event())

    incident = workflow.process_event(event)

    assert incident and incident["status"] == "needs_review"
    assert incident["attack_type"] == "SQL injection attempt"
    assert calls == ["investigator", "reviewer", "responder"]
    job = database.get_action_job_for_incident(incident["id"])
    assert job and job["status"] == "awaiting_approval"
    assert job["tool_name"] == "apply_temporary_ip_block"


def test_reviewer_can_stop_an_unsupported_investigation(monkeypatch) -> None:
    calls: list[str] = []

    def fake_agent(name, response_format, system_prompt, user_prompt, tools):
        calls.append(name)
        if response_format is schemas.InvestigationDecision:
            return _investigation()
        return schemas.ReviewDecision(
            approved_for_report=False,
            reason="An owner-run test is a plausible explanation.",
            evidence_gaps=["No repeated activity"],
        )

    monkeypatch.setattr(runtime, "invoke_structured_agent", fake_agent)
    assert workflow.process_event(database.insert_event(_sls_event())) is None
    assert calls == ["investigator", "reviewer"]


def test_agent_repairs_one_guardrail_invalid_decision(monkeypatch) -> None:
    calls: list[str] = []

    def fake_agent(name, response_format, system_prompt, user_prompt, tools):
        calls.append(name)
        if response_format is schemas.InvestigationDecision:
            if calls.count("investigator") == 1:
                return _investigation().model_copy(update={"security_profile_id": "cross_site_scripting_attempt"})
            assert "application_validation_error" in user_prompt
            return _investigation()
        if response_format is schemas.ReviewDecision:
            return schemas.ReviewDecision(approved_for_report=True, reason="The evidence supports a report.")
        return _response(action="send_owner_alert")

    monkeypatch.setattr(runtime, "invoke_structured_agent", fake_agent)

    incident = workflow.process_event(database.insert_event(_sls_event()))

    assert incident
    assert incident["attack_type"] == "SQL injection attempt"
    assert calls == ["investigator", "investigator", "reviewer", "responder"]


def test_reasoning_tools_and_execution_tools_are_real_mcp_servers() -> None:
    knowledge_tools = {tool["name"] for tool in knowledge_mcp_client.list_tools()}
    action_tools_found = {tool["name"] for tool in action_mcp_client.list_tools()}
    profile = knowledge_mcp_client.call_tool("lookup_security_profile", {"entry_id": "sql_injection_attempt"})

    assert {"lookup_security_profile", "find_matching_security_profiles"} <= knowledge_tools
    assert action_tools_found == {
        "send_owner_security_alert",
        "collect_follow_up_cloud_evidence",
        "apply_temporary_ip_block",
    }
    assert "CWE:89" in profile["sources"]


def test_action_mcp_subprocess_receives_database_configuration(monkeypatch) -> None:
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "")
    monkeypatch.setenv("DISCORD_APPLICATION_ID", "")
    monkeypatch.setenv("DISCORD_APPLICATION_PUBLIC_KEY", "")
    incident = _incident("send_owner_alert", "reported")
    database.ensure_action_job(incident["id"], "test-site", "send_owner_alert", "send_owner_security_alert", False)
    job = database.claim_next_action_job()
    assert job
    database.begin_action_tool_call(job["id"], "send_owner_security_alert")

    result = action_mcp_client.call_tool("send_owner_security_alert", {"action_job_id": job["id"]})

    assert result["action_job_id"] == job["id"]
    assert result["dashboard_report_available"] is True


def test_action_mcp_rejects_a_network_change_without_persisted_approval() -> None:
    incident = _incident("apply_temporary_ip_block", "needs_review")
    job = database.ensure_action_job(
        incident["id"], "test-site", "apply_temporary_ip_block", "apply_temporary_ip_block", True
    )
    with database.connect() as connection:
        connection.execute("update action_jobs set status = 'queued' where id = ?", (job["id"],))
    claimed = database.claim_next_action_job()
    assert claimed
    database.begin_action_tool_call(claimed["id"], "apply_temporary_ip_block")

    with pytest.raises(ValueError, match="valid persisted owner approval"):
        mcp_server.execute_temporary_ip_block(claimed["id"])


def test_qwen_executor_must_invoke_its_mcp_tool(monkeypatch) -> None:
    incident = _incident("send_owner_alert", "reported")
    database.ensure_action_job(incident["id"], "test-site", "send_owner_alert", "send_owner_security_alert", False)
    job = database.claim_next_action_job()
    assert job
    monkeypatch.setattr(
        executor.runtime,
        "invoke_structured_agent",
        lambda *args, **kwargs: ActionExecutionReport(
            outcome="executed",
            tool_name="send_owner_security_alert",
            summary="I would send the owner alert using the available tool.",
        ),
    )

    with pytest.raises(RuntimeError, match="without invoking"):
        executor.execute_action_job(job)


def test_action_capabilities_keep_browser_evidence_away_from_network_changes(monkeypatch) -> None:
    monkeypatch.setattr(validation.alibaba_autopilot, "available_actions_for_site", lambda site_id: ["apply_temporary_ip_block"])
    browser_event = {**_sls_event(), "source": "browser"}

    assert validation.response_capabilities(browser_event)["available_actions"] == ["send_owner_alert"]
    assert "apply_temporary_ip_block" in validation.response_capabilities(_sls_event())["available_actions"]
    with pytest.raises(ValueError):
        validation.validate_remediation_target("apply_temporary_ip_block", "0.0.0.0/0", _sls_event())


def test_evaluation_corpus_and_metrics_cover_the_real_pipeline() -> None:
    cases = load_cases()
    predictions = [
        {
            "name": case["name"],
            "incident_created": case["expected_incident"],
            "profile": case.get("expected_profile"),
        }
        for case in cases
    ]
    metrics = score_predictions(cases, predictions)

    assert {case["source_contract"] for case in cases} == {
        "alibaba_sls",
        "browser_snippet",
        "pipeline_filter",
    }
    assert metrics["incident_precision"] == 1
    assert metrics["incident_recall"] == 1
    assert metrics["profile_accuracy"] == 1


class QwenSmokeResponse(BaseModel):
    verdict: str
    confidence: float


@pytest.mark.skipif(
    os.getenv("SECAI_RUN_QWEN_INTEGRATION") != "1" or not os.getenv("DASHSCOPE_API_KEY"),
    reason="set SECAI_RUN_QWEN_INTEGRATION=1 and DASHSCOPE_API_KEY to run live Qwen integration",
)
def test_live_qwen_returns_structured_output() -> None:
    get_settings.cache_clear()
    get_chat_model.cache_clear()
    result = runtime.invoke_structured_agent(
        "integration_smoke",
        QwenSmokeResponse,
        "Return only the requested structured response.",
        "Confirm that SecAi can use structured output.",
        tools=[],
    )

    assert result.verdict
    assert 0 <= result.confidence <= 1
