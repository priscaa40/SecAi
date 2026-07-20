from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from secai import database
from secai.actions.expiry import start_policy_expiry, stop_policy_expiry
from secai.actions.retention import start_retention_worker, stop_retention_worker
from secai.agent.action_jobs import start_action_worker, stop_action_worker
from secai.agent.jobs import start_analysis_worker, stop_analysis_worker
from secai.dashboard_api import auth_service
from secai.dashboard_api.request_limits import RequestSizeLimitMiddleware
from secai.dashboard_api.routes import approval_links, auth, health, incidents, ingest, operations, setup, sites
from secai.dashboard_api.routes import discord as discord_routes
from secai.event_sources import alibaba_sls
from secai.event_sources.scheduler import start_sls_polling, stop_sls_polling
from secai.integrations import alibaba_autopilot, alibaba_coordinates, alibaba_credentials, discord
from secai.integrations.qwen_cloud import QwenClient
from secai.security import rate_limit
from secai.settings import get_settings


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initialize app resources on startup and clean up on shutdown."""
    database.init_db()
    settings = get_settings()
    QwenClient()
    discord_values = {
        "DISCORD_BOT_TOKEN": settings.discord_bot_token,
        "DISCORD_APPLICATION_ID": settings.discord_application_id,
        "DISCORD_APPLICATION_PUBLIC_KEY": settings.discord_application_public_key,
    }
    if any(discord_values.values()) and not all(discord_values.values()):
        missing = [name for name, value in discord_values.items() if not value]
        raise RuntimeError(f"Discord configuration requires: {', '.join(missing)}")
    if settings.discord_auto_register_commands and discord.discord_is_configured():
        readiness_error = discord.setup_readiness_error()
        if readiness_error:
            raise RuntimeError(readiness_error)
        discord.register_commands()
    database.reconcile_interrupted_actions()
    rate_limit.reset()
    start_analysis_worker()
    start_action_worker()
    start_sls_polling()
    start_policy_expiry()
    start_retention_worker()
    yield
    retention_stopped = stop_retention_worker()
    expiry_stopped = stop_policy_expiry()
    sls_stopped = stop_sls_polling()
    analysis_stopped = stop_analysis_worker()
    action_stopped = stop_action_worker()
    if all((retention_stopped, expiry_stopped, sls_stopped, analysis_stopped, action_stopped)):
        database.close_database_pool()


def create_app() -> FastAPI:
    """Create the SecAi API application."""
    app = FastAPI(title="SecAi Autopilot API", version="0.1.0", lifespan=lifespan)
    settings = get_settings()
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.secai_max_request_bytes)
    allowed_origins = sorted(
        {
            settings.frontend_base_url,
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        }
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def allow_public_browser_ingest(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Allow the public browser collector to report from any website."""
        if request.url.path != "/api/events":
            return await call_next(request)
        if request.method == "OPTIONS" and request.headers.get("access-control-request-method"):
            return Response(
                status_code=204,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, X-SecAi-Key",
                    "Access-Control-Max-Age": "600",
                },
            )
        response = await call_next(request)
        if request.headers.get("origin"):
            response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    app.include_router(auth.router)
    app.include_router(setup.router)
    app.include_router(health.router)
    app.include_router(sites.router)
    app.include_router(ingest.router)
    app.include_router(discord_routes.router)
    app.include_router(incidents.router)
    app.include_router(approval_links.router)
    app.include_router(operations.router)
    return app


app = create_app()
