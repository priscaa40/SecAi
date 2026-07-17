from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from protected_site.catalog import BRAND_NAME
from protected_site.pages import (
    attack_lab,
    checkout,
    contact_page,
    contact_submit,
    download,
    health,
    home,
    login_page,
    login_submit,
    products,
)
from protected_site.telemetry import access_log_middleware


def create_app() -> FastAPI:
    """Create the public ecommerce workload protected by SecAi Autopilot."""
    app = FastAPI(title=f"{BRAND_NAME} Storefront", version="0.1.0")
    app.middleware("http")(access_log_middleware)
    app.add_api_route("/", home, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/attack-lab", attack_lab, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/products", products, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/login", login_page, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/login", login_submit, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/download", download, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/checkout", checkout, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/checkout", checkout, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/contact", contact_page, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/contact", contact_submit, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/health", health, methods=["GET"])
    return app


app = create_app()
