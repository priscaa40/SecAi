from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from aliyun import log as aliyun_log

from secai import database
from secai.event_sources import alibaba_sls, scheduler
from secai.integrations import alibaba_autopilot, alibaba_credentials, alibaba_resources


def _connection(site_id: str = "test-site", account_id: str = "1111222233334444"):
    return SimpleNamespace(
        site_id=site_id,
        role_arn=f"acs:ram::{account_id}:role/SecAiWebsiteProtectionRole",
        external_id=f"external-{site_id}",
        account_id=account_id,
        region="ap-southeast-1",
        sls_endpoint="ap-southeast-1.log.aliyuncs.com",
        sls_project="storefront-logs",
        sls_logstore="access",
        security_group_id="sg-storefront",
    )


def _record(
    *,
    request_id: str,
    ip: str = "8.8.4.4",
    path: str = "/login",
    status_code: int = 401,
    signals: list[str] | None = None,
) -> dict:
    return {
        "site_id": "test-site",
        "source": "alibaba_sls",
        "event_type": "sls_log",
        "method": "POST",
        "path": path,
        "status_code": status_code,
        "ip": ip,
        "user_agent": "browser",
        "signals": signals if signals is not None else (["auth_failure"] if status_code in {401, 403} else []),
        "metadata": {"sls": {"request_id": request_id}},
    }


def _save_verified_connection(site_id: str = "test-site", account_id: str = "1111222233334444") -> None:
    database.prepare_alibaba_connection(site_id, external_id=f"external-{site_id}")
    database.verify_alibaba_connection(
        site_id,
        f"acs:ram::{account_id}:role/SecAi-{site_id.replace('_', '-')}",
        account_id,
        "ap-southeast-1",
    )
    names = alibaba_autopilot.collector_resource_names(site_id)
    database.save_alibaba_autopilot_config(
        site_id,
        {
            "region": "ap-southeast-1",
            "security_group_id": "sg-storefront",
            "sls_endpoint": "ap-southeast-1.log.aliyuncs.com",
            "sls_project": f"{site_id}-logs",
            "sls_logstore": "access",
            "ecs_instance_id": f"i-{site_id}",
            "collector_machine_group": names["machine_group"],
            "collector_config_name": names["config_name"],
            "enforcement_mode": "security_group",
        },
    )
    database.verify_alibaba_collector(site_id)


def test_customer_role_sessions_are_valid_scoped_and_isolated(monkeypatch) -> None:
    providers = []

    class FakeProvider:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            providers.append(self)

    class FakeClient:
        def __init__(self, provider):
            self.provider = provider

    monkeypatch.setattr(alibaba_credentials, "_base_provider", lambda: object())
    monkeypatch.setattr(alibaba_credentials, "RamRoleArnCredentialsProvider", FakeProvider)
    monkeypatch.setattr(alibaba_credentials, "CredentialClient", FakeClient)
    alibaba_credentials.invalidate_assumed_role_cache()

    first = alibaba_credentials.client_for_connection(_connection("site-one", "1111222233334444"))
    first_again = alibaba_credentials.client_for_connection(_connection("site-one", "1111222233334444"))
    second = alibaba_credentials.client_for_connection(_connection("site-two", "5555666677778888"))
    policy = json.loads(alibaba_credentials.session_policy_for_connection(_connection()))

    assert alibaba_credentials.parse_role_arn(
        "acs:ram::1111222233334444:role/SecAiWebsiteProtectionRole"
    ) == ("1111222233334444", "SecAiWebsiteProtectionRole")
    assert first is first_again
    assert first is not second
    assert len(providers) == 2
    assert "access_key_secret" not in providers[0].kwargs
    assert "acs:log:ap-southeast-1:1111222233334444:project/storefront-logs/logstore/access" in json.dumps(policy)
    assert "sg-storefront" in json.dumps(policy)
    alibaba_credentials.invalidate_assumed_role_cache()


def test_sls_reads_use_the_selected_websites_temporary_credentials(monkeypatch) -> None:
    captured = {}

    class FakeLogClient:
        def __init__(self, endpoint, access_key_id, access_key_secret, security_token):
            captured.update(
                endpoint=endpoint,
                access_key_id=access_key_id,
                access_key_secret=access_key_secret,
                security_token=security_token,
            )

        def get_logs(self, request):
            captured["query"] = request.query
            return SimpleNamespace(get_logs=lambda: [])

    monkeypatch.setattr(
        alibaba_sls.alibaba_credentials,
        "credential_for_connection",
        lambda connection: SimpleNamespace(
            access_key_id="temporary-ak",
            access_key_secret="temporary-secret",
            security_token="temporary-token",
        ),
    )
    monkeypatch.setattr(aliyun_log, "LogClient", FakeLogClient)

    logs = alibaba_sls.fetch_logs(_connection(), "status >= 400", 100, 200)

    assert logs == []
    assert captured["endpoint"] == "ap-southeast-1.log.aliyuncs.com"
    assert captured["access_key_id"] == "temporary-ak"
    assert captured["security_token"] == "temporary-token"
    assert captured["query"] == "status >= 400"


def test_sls_normalization_decodes_structured_logs_and_attack_queries() -> None:
    events = alibaba_sls._logs_to_events(
        "test-site",
        [
            SimpleNamespace(
                get_contents=lambda: {
                    "content": '{"method":"GET","path":"/products","query":"id=1%20OR%201=1--","status":403,"ip":"8.8.4.4"}'
                }
            )
        ],
    )

    assert len(events) == 1
    assert events[0]["path"] == "/products"
    assert events[0]["status_code"] == 403
    assert "sql_injection_pattern" in events[0]["signals"]


def test_sls_grouping_deduplicates_and_only_queues_relevant_behavior(monkeypatch) -> None:
    analyzed = []
    seen = set()

    def store(event, send_notification=False):
        fingerprint = event["metadata"]["sls"]["request_id"]
        if fingerprint in seen:
            return {"status": "deduplicated", "event": event, "job": {"id": 1}}
        seen.add(fingerprint)
        analyzed.append(event)
        return {"status": "queued", "event": event, "job": {"id": len(analyzed)}}

    monkeypatch.setattr(scheduler, "store_and_queue_event", store)
    records = [
        _record(request_id="request-1"),
        _record(request_id="request-2", path="/session"),
        _record(request_id="request-3", path="/token"),
        _record(request_id="request-4", ip="1.1.1.1"),
    ]

    first = scheduler.ingest_sls_events(records)
    repeated = scheduler.ingest_sls_events(records)

    assert first["groups_created"] == 1
    assert first["groups_filtered"] == 1
    assert first["jobs_queued"] == 1
    assert repeated["groups_deduplicated"] == 1
    assert repeated["jobs_queued"] == 0
    assert len(analyzed) == 1


def test_strong_attack_signature_bypasses_repetition_threshold(monkeypatch) -> None:
    analyzed = []
    monkeypatch.setattr(
        scheduler,
        "store_and_queue_event",
        lambda event: analyzed.append(event) or {"status": "queued", "event": event, "job": {"id": 1}},
    )

    result = scheduler.ingest_sls_events(
        [_record(request_id="strong-1", status_code=403, signals=["path_traversal_pattern"])]
    )

    assert result["jobs_queued"] == 1
    assert analyzed[0]["event_type"] == "sls_path_traversal_group"


@pytest.mark.parametrize(
    ("error_code", "error_message", "expected"),
    [
        ("IndexConfigNotExist", "logstore without index config", False),
        ("", "", True),
    ],
)
def test_logstore_index_check_preserves_existing_configuration(
    monkeypatch,
    error_code: str,
    error_message: str,
    expected: bool,
) -> None:
    class IndexError(Exception):
        def get_error_code(self):
            return error_code

        def get_error_message(self):
            return error_message

    class FakeLogClient:
        def __init__(self, *args):
            pass

        def get_logs(self, request):
            if error_code:
                raise IndexError
            return SimpleNamespace(get_logs=lambda: [])

    monkeypatch.setattr(
        alibaba_resources.alibaba_credentials,
        "credential_for_connection",
        lambda connection: SimpleNamespace(
            access_key_id="temporary-ak",
            access_key_secret="temporary-secret",
            security_token="temporary-token",
        ),
    )
    monkeypatch.setattr(aliyun_log, "LogClient", FakeLogClient)

    assert alibaba_resources.logstore_has_index(_connection()) is expected


def test_one_revoked_customer_role_does_not_stop_other_sites(monkeypatch) -> None:
    _save_verified_connection()
    other = database.create_site("Other website", "owner@example.com", "alibaba_autopilot")
    _save_verified_connection(other["site_id"], "5555666677778888")
    calls = []

    def fetch(site_id, **kwargs):
        calls.append(site_id)
        if site_id == "test-site":
            raise RuntimeError("role revoked")
        return []

    monkeypatch.setattr(alibaba_sls, "fetch_saved_site_events", fetch)
    result = scheduler.poll_once()

    assert set(calls) == {"test-site", other["site_id"]}
    assert result["sites_seen"] == 2
    assert result["errors"] == [{"site_id": "test-site", "error": "role revoked"}]
