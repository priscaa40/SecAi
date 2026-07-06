import os
from pathlib import Path

import pytest


TEST_DB_PATH = Path(".pytest_secai.db")

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"
os.environ.setdefault("DASHSCOPE_API_KEY", "test-qwen-key")
os.environ.setdefault("SECAI_ANALYSIS_MODE", "sync")
os.environ.setdefault("SECAI_SECRET_KEY", "test-secret-key")
os.environ.setdefault("DISCORD_BOT_TOKEN", "test-discord-bot")
os.environ.setdefault("SECAI_ALIBABA_ACCOUNT_ID", "1234567890123456")


TABLES = [
    "remediation_executions",
    "site_alibaba_autopilot_configs",
    "site_report_channels",
    "site_sls_configs",
    "remediation_preferences",
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

    database.init_db()
    with database.connect() as conn:
        for table in TABLES:
            conn.execute(f"delete from {table}")
        conn.execute("delete from sqlite_sequence")
    database.ensure_demo_site()
    database.ensure_demo_user(auth_service.hash_password("password123"))


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
