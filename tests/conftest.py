import os
from pathlib import Path

import pytest

TEST_DB_PATH = Path(".pytest_secai.db")

os.environ.setdefault("DATABASE_URL", f"sqlite:///{TEST_DB_PATH}")
os.environ.setdefault("DASHSCOPE_API_KEY", "test-qwen-key")
os.environ.setdefault("DISCORD_BOT_TOKEN", "test-discord-bot")
os.environ.setdefault("DISCORD_APPLICATION_ID", "123456789012345678")
os.environ.setdefault("DISCORD_APPLICATION_PUBLIC_KEY", "11" * 32)
os.environ.setdefault("DISCORD_AUTO_REGISTER_COMMANDS", "true")
os.environ.setdefault("PUBLIC_BASE_URL", "https://api.secai.test")
os.environ.setdefault(
    "SECAI_ALIBABA_PROVIDER_ROLE_ARN",
    "acs:ram::1234567890123456:role/secai-control-runtime",
)


TABLES = [
    "approval_decisions",
    "approval_tokens",
    "remediation_executions",
    "site_alibaba_autopilot_configs",
    "site_report_channels",
    "qwen_usage",
    "analysis_jobs",
    "policies",
    "incidents",
    "events",
    "sessions",
    "users",
    "sites",
]


def _reset_test_database() -> None:
    from secai import database
    from secai.dashboard_api import auth_service
    from secai.security import rate_limit

    rate_limit.reset()
    database.init_db()
    with database.connect() as conn:
        if database.database_backend() == "postgresql":
            conn.execute(f"truncate table {', '.join(TABLES)} restart identity cascade")
        else:
            for table in TABLES:
                conn.execute(f"delete from {table}")
            conn.execute("delete from sqlite_sequence")
    database.create_user("owner@example.com", auth_service.hash_password("password123"))
    with database.connect() as conn:
        conn.execute(
            "insert into sites (site_id, name, owner_email, ingest_key, created_at) values (?, ?, ?, ?, ?)",
            ("test-site", "Test Website", "owner@example.com", "test-key", database.utc_now()),
        )


@pytest.fixture(autouse=True)
def clean_database():
    _reset_test_database()
    yield
    _reset_test_database()


def pytest_sessionstart(session):
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()


def pytest_sessionfinish(session, exitstatus):
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
