from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from secai import database
from secai.actions import mcp_server as action_mcp_server
from secai.agent import action_jobs as action_worker
from secai.agent import action_tools, executor
from secai.agent.schemas import ActionExecutionReport
from secai.dashboard_api import auth_service
from secai.dashboard_api.app import app
from secai.integrations import alibaba_autopilot, alibaba_security_groups

client = TestClient(app)


def _auth_headers(email: str = "owner@example.com") -> dict[str, str]:
    user = database.get_user_by_email(email)
    if not user:
        user = database.create_user(email, auth_service.hash_password("password123"))
    session = database.create_session(user["id"])
    return {"Authorization": f"Bearer {session['token']}"}


def _set_evidence_source(source: str) -> None:
    with database.connect() as connection:
        connection.execute("update sites set evidence_source = ? where site_id = ?", (source, "test-site"))


def _connect_cloud() -> None:
    database.prepare_alibaba_connection("test-site")
    database.verify_alibaba_connection(
        "test-site",
        "acs:ram::1111222233334444:role/SecAi-test-site",
        "1111222233334444",
        "ap-southeast-1",
    )
    names = alibaba_autopilot.collector_resource_names("test-site")
    database.save_alibaba_autopilot_config(
        "test-site",
        {
            "region": "ap-southeast-1",
            "security_group_id": "sg-test123",
            "sls_endpoint": "ap-southeast-1.log.aliyuncs.com",
            "sls_project": "test-project",
            "sls_logstore": "test-logstore",
            "ecs_instance_id": "i-storefront",
            "collector_machine_group": names["machine_group"],
            "collector_config_name": names["config_name"],
            "enforcement_mode": "security_group",
        },
    )
    database.verify_alibaba_collector("test-site")


def _review_incident() -> dict[str, Any]:
    event = database.insert_event(
        {
            "site_id": "test-site",
            "source": "alibaba_sls",
            "event_type": "sls_sql_injection_group",
            "method": "GET",
            "path": "/products",
            "query": "id=1 OR 1=1--",
            "status_code": 403,
            "ip": "8.8.4.4",
            "signals": ["sql_injection_pattern"],
            "metadata": {"sls": {"request_id": "group-review"}},
        }
    )
    return database.insert_incident(
        {
            "site_id": "test-site",
            "title": "Review suspicious database probing",
            "severity": "high",
            "status": "needs_review",
            "attack_type": "SQL injection attempt",
            "affected_route": "/products",
            "confidence": 0.95,
            "report": "Repeated SQL-like input was observed in trusted cloud activity.",
            "recommended_action": {
                "action": "apply_temporary_ip_block",
                "target": "8.8.4.4",
                "reason": "Temporarily stop requests from the observed source.",
                "source_event_id": event["id"],
                "duration_seconds": 3600,
            },
        }
    )


class FakeSecurityGroupClient:
    def __init__(self) -> None:
        self.authorized = False
        self.permission: dict[str, Any] | None = None
        self.authorize_requests: list[dict[str, Any]] = []
        self.revoke_requests: list[dict[str, Any]] = []

    def authorize_security_group(self, request: dict[str, Any]) -> dict[str, Any]:
        self.authorized = True
        self.permission = dict(request["Permissions"][0])
        self.authorize_requests.append(request)
        return {"RequestId": "req-1"}

    def revoke_security_group(self, request: dict[str, Any]) -> dict[str, Any]:
        self.authorized = False
        self.revoke_requests.append(request)
        return {"RequestId": "revoke-1"}

    def describe_security_group_rules(self, request: dict[str, Any]) -> dict[str, Any]:
        if not self.authorized:
            return {"Permissions": {"Permission": []}}
        return {
            "Permissions": {
                "Permission": [{**(self.permission or {}), "SecurityGroupRuleId": "sgr-secai-1"}]
            }
        }


def _execute_next_action(monkeypatch) -> dict[str, Any]:
    handlers = {
        "send_owner_security_alert": action_mcp_server.execute_owner_alert,
        "collect_follow_up_cloud_evidence": action_mcp_server.execute_follow_up_collection,
        "apply_temporary_ip_block": action_mcp_server.execute_temporary_ip_block,
    }

    def call_tool(name: str, arguments: dict[str, Any] | None = None):
        return handlers[name](int((arguments or {})["action_job_id"]))

    def invoke_executor(name, response_format, system_prompt, user_prompt, tools):
        payload = json.loads(user_prompt)
        tools[0].invoke({"action_job_id": payload["action_job_id"]})
        return ActionExecutionReport(
            outcome="executed",
            tool_name=payload["required_tool"],
            summary="MCP action completed.",
        )

    monkeypatch.setattr(action_tools.mcp_client, "call_tool", call_tool)
    monkeypatch.setattr(executor.runtime, "invoke_structured_agent", invoke_executor)
    job = database.claim_next_action_job()
    assert job
    return action_worker.run_action_job(job)


def test_authentication_session_round_trip() -> None:
    signup = client.post(
        "/api/auth/signup",
        json={"email": "new-owner@example.com", "password": "password123"},
    )

    assert signup.status_code == 200
    headers = {"Authorization": f"Bearer {signup.json()['token']}"}
    assert client.get("/api/auth/me", headers=headers).json()["user"]["email"] == "new-owner@example.com"
    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_setup_creates_the_selected_evidence_contract() -> None:
    browser = client.post(
        "/api/setup/website",
        json={
            "website_name": "Browser Shop",
            "watch_method": "browser",
            "report_channels": ["dashboard"],
            "dashboard_email": "browser-owner@example.com",
            "dashboard_password": "password123",
        },
    ).json()
    cloud = client.post(
        "/api/setup/website",
        json={
            "website_name": "Cloud Shop",
            "watch_method": "alibaba_autopilot",
            "report_channels": ["dashboard"],
            "dashboard_email": "cloud-owner@example.com",
            "dashboard_password": "password123",
        },
    ).json()

    assert browser["site"]["site_id"] in browser["snippet"]
    assert cloud["snippet"] is None
    assert cloud["site"]["evidence_source"] == "alibaba_autopilot"


def test_public_browser_ingest_filters_noise_and_rejects_server_evidence() -> None:
    _set_evidence_source("browser")
    origin = "https://store.example"
    preflight = client.options(
        "/api/events",
        headers={
            "origin": origin,
            "access-control-request-method": "POST",
            "access-control-request-headers": "content-type,x-secai-key",
        },
    )
    ignored = client.post(
        "/api/events",
        headers={"origin": origin, "x-secai-key": "test-key"},
        json={"site_id": "test-site", "source": "browser", "event_type": "page_view", "path": "/"},
    )
    queued = client.post(
        "/api/events",
        headers={"origin": origin, "x-secai-key": "test-key"},
        json={
            "site_id": "test-site",
            "source": "browser",
            "event_type": "suspicious_form_submit",
            "method": "POST",
            "path": "/search",
            "payload": "1 OR 1=1--",
            "signals": ["suspicious_form_payload"],
            "metadata": {"form_key": "POST|same_origin|/search|named:search"},
        },
    )
    forged_cloud = client.post(
        "/api/events",
        headers={"x-secai-key": "test-key"},
        json={"site_id": "test-site", "source": "alibaba_sls", "event_type": "sls_log"},
    )

    assert preflight.status_code == 204
    assert preflight.headers["access-control-allow-origin"] == "*"
    assert ignored.json()["analysis"]["status"] == "ignored"
    assert queued.json()["analysis"]["status"] == "queued"
    assert forged_cloud.status_code == 403


def test_owner_scope_hides_incidents_and_cloud_setup_from_other_users() -> None:
    incident = _review_incident()
    other_headers = _auth_headers("other-owner@example.com")

    assert client.get(f"/api/incidents/{incident['id']}", headers=other_headers).status_code == 404
    assert client.post("/api/sites/test-site/alibaba-connection/prepare", headers=other_headers).status_code == 404


def test_dashboard_does_not_return_failed_investigation_attempts() -> None:
    event = database.insert_event(
        {
            "site_id": "test-site",
            "source": "browser",
            "event_type": "rapid_form_submit",
            "signals": ["rapid_form_submit"],
        }
    )
    job = database.create_analysis_job(event["id"], "test-site")
    database.update_analysis_job(job["id"], status="failed", current_step="investigator", error="failed")

    response = client.get("/api/analysis-jobs?site_id=test-site", headers=_auth_headers())

    assert response.status_code == 200
    assert all(item["id"] != job["id"] for item in response.json()["jobs"])
    assert client.post(f"/api/analysis-jobs/{job['id']}/retry", headers=_auth_headers()).status_code == 404


def test_owner_approval_executes_verified_mcp_action_and_can_roll_it_back(monkeypatch) -> None:
    _connect_cloud()
    incident = _review_incident()
    provider = FakeSecurityGroupClient()
    monkeypatch.setattr(alibaba_security_groups, "AlibabaEcsSecurityGroupClient", lambda connection: provider)
    monkeypatch.setattr(alibaba_security_groups, "security_group_is_dedicated", lambda connection: True)
    headers = _auth_headers()

    approved = client.post(f"/api/incidents/{incident['id']}/approve", headers=headers, json={})
    assert approved.status_code == 202
    assert approved.json()["action_job"]["status"] == "queued"

    completed = _execute_next_action(monkeypatch)
    policy = database.get_policy_for_incident(incident["id"])
    assert completed["status"] == "succeeded"
    assert policy and policy["status"] == "active"
    assert policy["provider_rule_id"] == "sgr-secai-1"
    assert provider.authorize_requests[0]["Permissions"][0]["SourceCidrIp"] == "8.8.4.4/32"

    removed = client.post(f"/api/incidents/{incident['id']}/remove-protection", headers=headers)
    assert removed.status_code == 200
    assert removed.json()["policy"]["status"] == "revoked"
    assert provider.revoke_requests[0]["SecurityGroupRuleId"] == ["sgr-secai-1"]


def test_notification_link_requires_post_before_changing_the_decision(monkeypatch) -> None:
    incident = _review_incident()
    token = incident["approval_token"]
    monkeypatch.setattr(
        "secai.dashboard_api.routes.approval_links.discord.notify_decision_result",
        lambda *args, **kwargs: True,
    )

    confirmation = client.get(f"/approval/{token}/reject?redirect=true")
    assert confirmation.status_code == 200
    assert 'method="post"' in confirmation.text
    assert database.get_incident(incident["id"])["status"] == "needs_review"

    rejected = client.post(f"/approval/{token}/reject?redirect=true", follow_redirects=False)
    assert rejected.status_code == 303
    assert database.get_incident(incident["id"])["status"] == "rejected"
    assert database.get_policy_for_incident(incident["id"]) is None
