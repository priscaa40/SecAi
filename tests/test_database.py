from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from secai import database
from secai.actions import expiry
from secai.agent import jobs as analysis_jobs
from secai.database import schema
from secai.database.connection import SCHEMA_VERSION
from secai.security.redaction import REDACTED, sanitize_event


def _incident() -> dict[str, Any]:
    return {
        "site_id": "test-site",
        "title": "Suspicious request confirmed",
        "severity": "high",
        "status": "needs_review",
        "attack_type": "SQL injection attempt",
        "affected_route": "/products",
        "confidence": 0.94,
        "report": "The investigation found a likely SQL injection attempt.",
        "recommended_action": {
            "action": "apply_temporary_ip_block",
            "target": "8.8.4.4",
            "reason": "Temporarily stop requests from the confirmed source.",
        },
    }


def _running_analysis_job() -> tuple[dict[str, Any], dict[str, Any]]:
    event = database.insert_event(
        {
            "site_id": "test-site",
            "source": "alibaba_sls",
            "event_type": "sls_sql_injection_group",
            "path": "/products",
            "ip": "8.8.4.4",
            "signals": ["sql_injection_pattern"],
            "metadata": {},
        }
    )
    queued = database.create_analysis_job(event["id"], "test-site")
    claimed = database.claim_next_analysis_job()
    assert claimed and claimed["id"] == queued["id"]
    return event, claimed


def test_current_schema_is_created_and_old_versions_are_rejected(tmp_path) -> None:
    with database.connect() as connection:
        version = connection.execute("select version from schema_metadata where singleton = 1").fetchone()
        tables = {
            row["name"]
            for row in connection.execute(
                "select name from sqlite_master where type = 'table' and name not like 'sqlite_%'"
            ).fetchall()
        }
    assert version["version"] == SCHEMA_VERSION
    assert {"analysis_jobs", "action_jobs", "approval_decisions", "qwen_usage"} <= tables

    old_path = tmp_path / "old.db"
    old = sqlite3.connect(old_path)
    old.row_factory = sqlite3.Row
    old.execute("create table schema_metadata (singleton integer primary key, version integer not null)")
    old.execute("insert into schema_metadata values (1, 9)")
    old.commit()
    try:
        with pytest.raises(RuntimeError, match="requires schema 10"):
            schema.initialize(old, str(old_path), SCHEMA_VERSION)
    finally:
        old.close()


def test_incident_and_job_persistence_is_atomic_and_idempotent() -> None:
    event, job = _running_analysis_job()
    usage = database.insert_qwen_usage(
        {
            "job_id": job["id"],
            "event_id": event["id"],
            "agent_name": "investigator",
            "model": "qwen-plus",
            "input_tokens": 100,
            "output_tokens": 20,
            "total_tokens": 120,
            "latency_ms": 25,
        }
    )

    first = database.insert_incident(_incident(), analysis_job_id=job["id"])
    repeated = database.insert_incident({**_incident(), "title": "duplicate"}, analysis_job_id=job["id"])

    assert repeated["id"] == first["id"]
    assert repeated["title"] == first["title"]
    stored_job = database.get_analysis_job(job["id"])
    assert stored_job and stored_job["status"] == "incident_created"
    with database.connect() as connection:
        assert connection.execute("select count(*) as count from incidents").fetchone()["count"] == 1
        stored_usage = connection.execute("select * from qwen_usage where id = ?", (usage["id"],)).fetchone()
    assert stored_usage["incident_id"] == first["id"]


def test_owner_decision_can_only_be_claimed_once() -> None:
    incident = database.insert_incident(_incident())

    def claim() -> bool:
        return database.transition_incident_status(incident["id"], {"needs_review"}, "applying") is not None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: claim(), range(2)))

    assert sorted(results) == [False, True]


def test_durable_queue_prioritizes_cloud_evidence_and_limits_retries() -> None:
    browser = database.insert_event(
        {
            "site_id": "test-site",
            "source": "browser",
            "event_type": "rapid_form_submit",
            "signals": ["rapid_form_submit"],
        }
    )
    cloud = database.insert_event(
        {
            "site_id": "test-site",
            "source": "alibaba_sls",
            "event_type": "sls_server_error_group",
            "signals": ["server_error"],
            "metadata": {"sls": {"request_id": "priority-test"}},
        }
    )
    browser_job = database.create_analysis_job(browser["id"], "test-site")
    cloud_job = database.create_analysis_job(cloud["id"], "test-site")

    assert database.claim_next_analysis_job()["id"] == cloud_job["id"]
    claimed_browser = database.claim_next_analysis_job()
    assert claimed_browser["id"] == browser_job["id"]
    database.update_analysis_job(claimed_browser["id"], status="failed", current_step="investigator", error="failed")
    assert analysis_jobs._retry_failed_job(claimed_browser["id"]) is True
    assert database.get_analysis_job(claimed_browser["id"])["status"] == "queued"


def test_sensitive_event_values_are_redacted_before_storage() -> None:
    event = sanitize_event(
        {
            "site_id": "test-site",
            "source": "alibaba_sls",
            "event_type": "sls_log",
            "query": "username=a&password=hunter2&token=abc",
            "payload": "Authorization: Bearer secret-token card_number=4111111111111111",
            "metadata": {"sls": {"cookie": "sid=secret", "message": "password=hidden", "unneeded": "discard"}},
        }
    )
    stored = database.insert_event(event)
    rendered = str(database.get_event(stored["id"]))

    assert "hunter2" not in rendered
    assert "secret-token" not in rendered
    assert "4111111111111111" not in rendered
    assert REDACTED in rendered


def test_expiry_worker_processes_each_due_rule_once(monkeypatch) -> None:
    policy = {"id": 11, "incident_id": 7}
    incident = {"id": 7, "site_id": "test-site"}
    claims: list[dict[str, Any] | None] = [policy, None]
    monkeypatch.setattr(expiry.database, "claim_due_policy", lambda: claims.pop(0))
    monkeypatch.setattr(expiry.database, "get_incident", lambda incident_id: incident)
    monkeypatch.setattr(
        expiry.remediation,
        "revoke_policy_for_incident",
        lambda stored_incident, final_status: {"status": final_status},
    )

    assert expiry.expire_due_policies() == {"seen": 1, "expired": 1, "failed": 0}
