from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from secai import database
from secai.dashboard_api import auth_service
from secai.dashboard_api.routes import auth, demo, health, incidents, ingest, operations, setup, sites
from secai.settings import get_settings
from secai.integrations.qwen_cloud import QwenClient
from secai.agent.jobs import recover_unfinished_jobs, shutdown_executor
from secai.event_sources.scheduler import start_sls_polling, stop_sls_polling
from secai.knowledge import mcp_client as security_knowledge_mcp


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initialize app resources on startup and clean up on shutdown."""
    database.init_db()
    database.ensure_demo_site()
    database.ensure_demo_user(auth_service.hash_password("password123"))
    QwenClient()
    if get_settings().secai_analysis_mode == "background":
        recover_unfinished_jobs()
    start_sls_polling()
    yield
    stop_sls_polling()
    security_knowledge_mcp.close()
    shutdown_executor()


def create_app() -> FastAPI:
    """Create the SecAi API application."""
    app = FastAPI(title="SecAi Autopilot API", version="0.1.0", lifespan=lifespan)
    settings = get_settings()
    extra_origins = {
        origin.strip()
        for origin in settings.secai_extra_cors_origins.split(",")
        if origin.strip()
    }
    allowed_origins = sorted(
        {
            settings.frontend_base_url,
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        }
        | extra_origins
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(auth.router)
    app.include_router(setup.router)
    app.include_router(health.router)
    app.include_router(sites.router)
    app.include_router(ingest.router)
    app.include_router(demo.router)
    app.include_router(incidents.router)
    app.include_router(operations.router)
    return app


app = create_app()
