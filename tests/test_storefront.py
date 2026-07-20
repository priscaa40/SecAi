import json
import logging
from urllib.parse import parse_qs

from fastapi.testclient import TestClient
from starlette.requests import Request

from protected_site.app import create_app
from protected_site.client_ip import trusted_client_ip
from protected_site.telemetry import body_message, redact_query

client = TestClient(create_app())


def test_storefront_branding_and_optional_browser_collector(monkeypatch) -> None:
    monkeypatch.setenv("SECAI_PUBLIC_BASE_URL", "https://secai.example.com")
    monkeypatch.setenv("SECAI_SITE_ID", "site_public_test")
    connected = client.get("/")
    monkeypatch.delenv("SECAI_SITE_ID")
    standalone = client.get("/")

    assert connected.status_code == 200
    assert "Northstar Goods" in connected.text
    assert "https://secai.example.com/api/integrations/browser.js?site_id=site_public_test" in connected.text
    assert "/api/integrations/browser.js" not in standalone.text
    assert "SecAi dashboard" not in connected.text


def test_attack_lab_routes_are_safe_controlled_demonstrations() -> None:
    xss = client.post("/contact", data={"message": "<script>alert(1)</script>"})
    traversal = client.get("/download?file=../../etc/passwd")
    login = client.post("/login", data={"email": "admin@example.com", "password": "guess"})
    checkout = client.post("/checkout?fail=true")

    assert "<script>alert(1)</script>" not in xss.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in xss.text
    assert traversal.status_code == 403
    assert login.status_code == 401
    assert checkout.status_code == 500


def test_access_logs_are_sls_readable_without_leaking_secrets(caplog) -> None:
    caplog.set_level(logging.INFO, logger="protected_site.access")
    response = client.get("/products?q=1%20OR%201=1--", headers={"x-forwarded-for": "203.0.113.10"})
    records = [record for record in caplog.records if record.name == "protected_site.access"]
    payload = json.loads(records[-1].message)
    query = redact_query("q=shoes&access_token=secret&password=hunter2")
    message = body_message(
        b'{"email":"person@example.com","credentials":{"api_key":"top-secret"}}',
        "application/json",
    )

    assert response.status_code == 200
    assert payload["path"] == "/products"
    assert payload["client_ip"] != "203.0.113.10"
    assert parse_qs(payload["query"])["q"] == ["1 OR 1=1--"]
    assert "shoes" in query and "hunter2" not in query
    assert "person@example.com" in message and "top-secret" not in message
    assert body_message(b"opaque secret material", "text/plain") == "[BODY OMITTED]"


def test_forwarded_ip_is_used_only_from_a_trusted_proxy() -> None:
    def request(peer: str, forwarded: bytes) -> Request:
        return Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [(b"x-forwarded-for", forwarded)],
                "client": (peer, 1234),
                "server": ("test", 80),
                "scheme": "http",
                "query_string": b"",
            }
        )

    assert trusted_client_ip(request("203.0.113.20", b"8.8.8.8"), "10.0.0.0/8") == "203.0.113.20"
    assert trusted_client_ip(request("10.0.0.5", b"8.8.8.8, 198.51.100.7"), "10.0.0.0/8") == "198.51.100.7"
