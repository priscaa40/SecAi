from __future__ import annotations

import html
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, parse_qsl

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse


logger = logging.getLogger("protected_site.access")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
logger.propagate = False


BRAND_NAME = "Northstar Goods"

PRODUCTS: list[dict[str, Any]] = [
    {
        "slug": "trail-mug",
        "name": "Trail Mug",
        "price": "$18",
        "category": "Kitchen",
        "badge": "Bestseller",
        "description": "Double-wall ceramic mug for long desk days and early trail starts.",
        "art": "mug",
    },
    {
        "slug": "canvas-tote",
        "name": "Canvas Tote",
        "price": "$24",
        "category": "Travel",
        "badge": "New",
        "description": "Heavy cotton tote with internal pockets for market runs and daily carry.",
        "art": "tote",
    },
    {
        "slug": "desk-lamp",
        "name": "Desk Lamp",
        "price": "$42",
        "category": "Home",
        "badge": "Warm light",
        "description": "Adjustable task lamp with a soft matte shade and brass switch.",
        "art": "lamp",
    },
    {
        "slug": "linen-notebook",
        "name": "Linen Notebook",
        "price": "$16",
        "category": "Office",
        "badge": "Restocked",
        "description": "Lay-flat notebook with ruled cream pages and a woven cover.",
        "art": "notebook",
    },
    {
        "slug": "pour-over-kettle",
        "name": "Pour-Over Kettle",
        "price": "$36",
        "category": "Kitchen",
        "badge": "Gift pick",
        "description": "Compact gooseneck kettle for careful morning coffee rituals.",
        "art": "kettle",
    },
    {
        "slug": "stone-planter",
        "name": "Stone Planter",
        "price": "$28",
        "category": "Home",
        "badge": "Low stock",
        "description": "Textured tabletop planter with a drainage tray and natural finish.",
        "art": "planter",
    },
]


def create_app() -> FastAPI:
    """Create the public ecommerce workload protected by Alibaba WAF."""
    app = FastAPI(title=f"{BRAND_NAME} Storefront", version="0.1.0")
    app.middleware("http")(_access_log_middleware)
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


async def _access_log_middleware(request: Request, call_next):
    """Emit SLS-readable JSON access logs for every request."""
    started = time.perf_counter()
    body = await request.body()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration_ms = int((time.perf_counter() - started) * 1000)
        client_ip = _client_ip(request)
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "request_method": request.method,
            "path": request.url.path,
            "uri": request.url.path,
            "request_uri": str(request.url),
            "query": request.url.query,
            "args": request.url.query,
            "status": status_code,
            "status_code": status_code,
            "ip": client_ip,
            "client_ip": client_ip,
            "remote_addr": client_ip,
            "user_agent": request.headers.get("user-agent", ""),
            "http_user_agent": request.headers.get("user-agent", ""),
            "duration_ms": duration_ms,
            "message": _body_message(body, request.headers.get("content-type", "")),
        }
        logger.info(json.dumps(event, separators=(",", ":")))


def home(request: Request) -> HTMLResponse:
    """Render the storefront landing page."""
    featured = _featured_product(PRODUCTS[0], "large")
    compact_products = "".join(_compact_product(product) for product in PRODUCTS[1:4])
    body = f"""
    <section class="hero">
      <div class="hero-copy">
        <p class="eyebrow">New seasonal edit</p>
        <h1>Everyday goods for calmer mornings and cleaner desks.</h1>
        <p class="lead">
          Shop useful home, travel, and desk pieces selected for small routines that feel better.
        </p>
        <div class="actions">
          <a class="button" href="/products">Shop collection</a>
          <a class="button secondary" href="/attack-lab">Open test panel</a>
        </div>
      </div>
      <div class="hero-display" aria-label="Featured products">
        {featured}
      </div>
    </section>

    <section class="promo-strip" aria-label="Store benefits">
      <span>Free shipping over $50</span>
      <span>Small-batch restocks</span>
      <span>Easy returns</span>
    </section>

    <section class="section-heading">
      <p class="eyebrow">Popular right now</p>
      <h2>Customer favorites</h2>
    </section>
    <section class="grid three compact-products">{compact_products}</section>
    """
    return _page(request, "Home", body)


def attack_lab(request: Request) -> HTMLResponse:
    """Render guided public attack simulations."""
    body = """
    <section class="page-heading test-heading">
      <p class="eyebrow">Store traffic test panel</p>
      <h1>Generate suspicious storefront traffic.</h1>
      <p class="lead">Use these controls to produce browser and access-log evidence through normal storefront routes.</p>
    </section>

    <section class="grid two">
      <article class="lab-card">
        <div>
          <p class="test-type">Query payload</p>
          <h2>SQL injection search</h2>
          <p>Submits a catalog search containing SQL operators.</p>
        </div>
        <form action="/products" method="get">
          <input name="q" value="1 OR 1=1--" aria-label="SQL injection test query">
          <button type="submit">Run SQLi search</button>
        </form>
      </article>

      <article class="lab-card">
        <div>
          <p class="test-type">Form payload</p>
          <h2>XSS contact message</h2>
          <p>Submits script-like text through the customer-care form.</p>
        </div>
        <form action="/contact" method="post">
          <textarea name="message" aria-label="XSS test message">&lt;script&gt;alert(1)&lt;/script&gt;</textarea>
          <button type="submit">Submit XSS text</button>
        </form>
      </article>

      <article class="lab-card">
        <div>
          <p class="test-type">File request</p>
          <h2>Path traversal download</h2>
          <p>Requests a sensitive-looking file path and receives a blocked response.</p>
        </div>
        <form action="/download" method="get">
          <input name="file" value="../../etc/passwd" aria-label="Path traversal file">
          <button type="submit">Request blocked file</button>
        </form>
      </article>

      <article class="lab-card">
        <div>
          <p class="test-type">Auth traffic</p>
          <h2>Login failure burst</h2>
          <p>Sends repeated failed sign-in attempts against the member route.</p>
        </div>
        <button type="button" onclick="runLoginBurst()">Run login burst</button>
      </article>

      <article class="lab-card">
        <div>
          <p class="test-type">Form rate</p>
          <h2>Rapid contact spam</h2>
          <p>Dispatches repeated customer-care submissions and matching POST traffic.</p>
        </div>
        <form id="rapid-spam-form" action="/contact" method="post" onsubmit="event.preventDefault()">
          <textarea name="message">Limited-time offer from automated form traffic.</textarea>
          <button type="button" onclick="runRapidSpam()">Run rapid submits</button>
        </form>
      </article>

      <article class="lab-card">
        <div>
          <p class="test-type">Checkout errors</p>
          <h2>Server error spike</h2>
          <p>Calls a checkout route that returns repeated 500 responses.</p>
        </div>
        <button type="button" onclick="runErrorSpike()">Run error spike</button>
      </article>

      <article class="lab-card">
        <div>
          <p class="test-type">Browser runtime</p>
          <h2>Browser error spike</h2>
          <p>Raises client-side errors for browser-observable signals.</p>
        </div>
        <button type="button" onclick="triggerBrowserErrors()">Raise browser errors</button>
      </article>

      <article class="lab-card">
        <div>
          <p class="test-type">Interaction burst</p>
          <h2>Bot-like activity</h2>
          <p>Creates a short burst of click events from the storefront page.</p>
        </div>
        <button type="button" onclick="triggerBotActivity()">Run bot-like clicks</button>
      </article>
    </section>

    <section class="status-card" id="lab-status" role="status">Ready.</section>
    """
    return _page(request, "Traffic Test Panel", body, extra_script=_lab_script())


def products(request: Request, q: str = "") -> HTMLResponse:
    """Render product search results."""
    safe_query = html.escape(q)
    matches = _matching_products(q)
    product_items = "".join(_product_card(product) for product in matches)
    result_note = ""
    if q and len(matches) == len(PRODUCTS):
        result_note = f'<p class="notice">Catalog search received: <code>{safe_query}</code></p>'
    elif q:
        result_note = f'<p class="notice">Showing results for <code>{safe_query}</code>.</p>'
    body = f"""
    <section class="page-heading">
      <p class="eyebrow">Catalog</p>
      <h1>Shop the collection.</h1>
      <p class="lead">Search home, kitchen, travel, and office goods from the current edit.</p>
    </section>
    <form class="search-form" action="/products" method="get">
      <input name="q" value="{safe_query}" placeholder="Search mugs, totes, lamps" aria-label="Search products">
      <button type="submit">Search</button>
    </form>
    {result_note}
    <section class="grid three product-grid">{product_items}</section>
    """
    return _page(request, "Products", body)


def login_page(request: Request) -> HTMLResponse:
    """Render member sign-in form."""
    body = """
    <section class="page-heading">
      <p class="eyebrow">Member account</p>
      <h1>Sign in for order updates.</h1>
      <p class="lead">Use the form to check member-account traffic and authentication responses.</p>
    </section>
    <form class="panel account-panel" action="/login" method="post">
      <label>Email <input name="email" value="admin@example.com" autocomplete="email"></label>
      <label>Password <input name="password" type="password" value="wrong-password" autocomplete="current-password"></label>
      <button type="submit">Sign in</button>
    </form>
    """
    return _page(request, "Member Sign In", body)


async def login_submit(request: Request) -> HTMLResponse:
    """Return a controlled authentication failure."""
    fields = await _form_fields(request)
    email = html.escape(fields.get("email", "customer@example.com"))
    body = f"""
    <section class="page-heading">
      <p class="eyebrow">Sign-in failed</p>
      <h1>We could not sign you in.</h1>
      <p class="lead">The sign-in attempt for <code>{email}</code> returned a 401 response.</p>
      <a class="button secondary" href="/attack-lab">Back to test panel</a>
    </section>
    """
    return _page(request, "Sign-In Failed", body, status_code=401)


def download(request: Request, file: str = "spring-catalog.pdf") -> HTMLResponse:
    """Return a safe file response or controlled 403 for traversal tests."""
    safe_file = html.escape(file)
    if _looks_like_traversal(file):
        body = f"""
        <section class="page-heading">
          <p class="eyebrow">Download blocked</p>
          <h1>Forbidden file path.</h1>
          <p class="lead">The request for <code>{safe_file}</code> is not allowed.</p>
          <a class="button secondary" href="/attack-lab">Back to test panel</a>
        </section>
        """
        return _page(request, "Download Blocked", body, status_code=403)
    body = f"""
    <section class="page-heading">
      <p class="eyebrow">Catalog download</p>
      <h1>Catalog request received.</h1>
      <p class="lead">Requested file: <code>{safe_file}</code></p>
    </section>
    """
    return _page(request, "Catalog Download", body)


def checkout(request: Request, fail: bool = False) -> HTMLResponse:
    """Render checkout or a controlled server-error test."""
    if fail:
        body = """
        <section class="page-heading">
          <p class="eyebrow">Checkout status</p>
          <h1>Checkout service unavailable.</h1>
          <p class="lead">This request returned a 500 response for storefront monitoring.</p>
        </section>
        """
        return _page(request, "Checkout Error", body, status_code=500)
    body = """
    <section class="page-heading checkout-heading">
      <p class="eyebrow">Checkout</p>
      <h1>Review your bag.</h1>
      <p class="lead">This preview order contains a Trail Mug, Canvas Tote, and Desk Lamp.</p>
    </section>
    <section class="checkout-layout">
      <div class="panel order-list">
        <div><strong>Trail Mug</strong><span>$18</span></div>
        <div><strong>Canvas Tote</strong><span>$24</span></div>
        <div><strong>Desk Lamp</strong><span>$42</span></div>
        <div class="total"><strong>Total</strong><span>$84</span></div>
      </div>
      <form class="panel" action="/checkout?fail=true" method="post">
        <label>Email <input name="email" value="customer@example.com"></label>
        <label>Postal code <input name="postal_code" value="10001"></label>
        <button type="submit">Place preview order</button>
      </form>
    </section>
    """
    return _page(request, "Checkout", body)


def contact_page(request: Request) -> HTMLResponse:
    """Render customer-care form."""
    body = """
    <section class="page-heading">
      <p class="eyebrow">Customer care</p>
      <h1>Send a message.</h1>
      <p class="lead">Questions about an order, product, or return can be sent here.</p>
    </section>
    <form class="panel" action="/contact" method="post">
      <label>Message <textarea name="message">I have a question about my order.</textarea></label>
      <button type="submit">Send message</button>
    </form>
    """
    return _page(request, "Contact", body)


async def contact_submit(request: Request) -> HTMLResponse:
    """Echo escaped contact text."""
    fields = await _form_fields(request)
    message = html.escape(fields.get("message", ""))
    body = f"""
    <section class="page-heading">
      <p class="eyebrow">Message received</p>
      <h1>Thanks, we received it.</h1>
      <p class="lead">Message preview:</p>
      <pre>{message}</pre>
      <a class="button secondary" href="/attack-lab">Back to test panel</a>
    </section>
    """
    return _page(request, "Message Received", body)


def health() -> dict[str, str]:
    """Return health status for Alibaba load balancers."""
    return {"status": "ok", "service": "northstar-goods-storefront"}


def _page(
    request: Request,
    title: str,
    body: str,
    *,
    status_code: int = 200,
    extra_script: str = "",
) -> HTMLResponse:
    """Render one complete HTML page with the browser monitoring snippet."""
    secai_base = _env("SECAI_PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
    site_id = _env("SECAI_SITE_ID", "demo-site")
    snippet = f'<script defer src="{html.escape(secai_base)}/api/integrations/browser.js?site_id={html.escape(site_id)}"></script>'
    content = f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{html.escape(title)} | {BRAND_NAME}</title>
        <style>{_styles()}</style>
        {snippet}
      </head>
      <body>
        <header class="topbar">
          <a class="brand" href="/" aria-label="{BRAND_NAME} home">
            <span class="brand-mark" aria-hidden="true">N</span>
            <span>{BRAND_NAME}</span>
          </a>
          <nav aria-label="Primary navigation">
            <a href="/products">Shop</a>
            <a href="/checkout">Bag</a>
            <a href="/contact">Contact</a>
            <a href="/attack-lab">Test panel</a>
          </nav>
        </header>
        <main>{body}</main>
        <footer>
          <span>{BRAND_NAME}</span>
          <span>Home, travel, kitchen, and desk goods.</span>
        </footer>
        {extra_script}
      </body>
    </html>
    """
    return HTMLResponse(content, status_code=status_code)


def _featured_product(product: dict[str, Any], size: str) -> str:
    """Return the large hero product display."""
    return f"""
    <article class="featured-card {size}">
      {_product_art(product["art"], product["name"])}
      <div class="featured-copy">
        <p>{html.escape(product["badge"])}</p>
        <h2>{html.escape(product["name"])}</h2>
        <span>{html.escape(product["price"])}</span>
      </div>
    </article>
    """


def _compact_product(product: dict[str, Any]) -> str:
    """Return a compact product teaser."""
    return f"""
    <article class="compact-card">
      {_product_art(product["art"], product["name"])}
      <div>
        <p>{html.escape(product["category"])}</p>
        <h3>{html.escape(product["name"])}</h3>
        <span>{html.escape(product["price"])}</span>
      </div>
    </article>
    """


def _product_card(product: dict[str, Any]) -> str:
    """Return one catalog product card."""
    return f"""
    <article class="product-card">
      <div class="product-art">{_product_art(product["art"], product["name"])}</div>
      <div class="product-meta">
        <span class="badge">{html.escape(product["badge"])}</span>
        <h2>{html.escape(product["name"])}</h2>
        <p>{html.escape(product["description"])}</p>
        <div class="buy-row">
          <strong>{html.escape(product["price"])}</strong>
          <a class="button secondary" href="/checkout">Add to bag</a>
        </div>
      </div>
    </article>
    """


def _matching_products(query: str) -> list[dict[str, Any]]:
    """Return matching products, or all products for suspicious/no-match strings."""
    normalized = query.strip().lower()
    if not normalized:
        return PRODUCTS
    matches = [
        product
        for product in PRODUCTS
        if normalized in product["name"].lower()
        or normalized in product["category"].lower()
        or normalized in product["description"].lower()
    ]
    return matches or PRODUCTS


def _product_art(kind: str, label: str) -> str:
    """Return small inline product art for the storefront."""
    safe_label = html.escape(label, quote=True)
    if kind == "mug":
        inner = """
        <rect x="44" y="62" width="76" height="78" rx="14" fill="#f9fbf8" stroke="#1d2730" stroke-width="5"/>
        <path d="M120 82h16c18 0 18 38 0 38h-16" fill="none" stroke="#1d2730" stroke-width="5" stroke-linecap="round"/>
        <path d="M56 78h52" stroke="#ef795e" stroke-width="8" stroke-linecap="round"/>
        <circle cx="78" cy="108" r="14" fill="#f4c95d"/>
        """
    elif kind == "tote":
        inner = """
        <path d="M46 74h86l-8 74H54z" fill="#f7e7cb" stroke="#1d2730" stroke-width="5" stroke-linejoin="round"/>
        <path d="M68 78c0-28 44-28 44 0" fill="none" stroke="#1d2730" stroke-width="5" stroke-linecap="round"/>
        <path d="M58 100h62" stroke="#2f8f83" stroke-width="7" stroke-linecap="round"/>
        <circle cx="92" cy="124" r="12" fill="#ef795e"/>
        """
    elif kind == "lamp":
        inner = """
        <path d="M73 48h54l-12 42H61z" fill="#f4c95d" stroke="#1d2730" stroke-width="5" stroke-linejoin="round"/>
        <path d="M94 90v48" stroke="#1d2730" stroke-width="5" stroke-linecap="round"/>
        <path d="M62 142h64" stroke="#1d2730" stroke-width="5" stroke-linecap="round"/>
        <circle cx="94" cy="118" r="12" fill="#ef795e"/>
        """
    elif kind == "notebook":
        inner = """
        <rect x="52" y="42" width="78" height="110" rx="8" fill="#6f7ebc" stroke="#1d2730" stroke-width="5"/>
        <path d="M70 42v110" stroke="#f7e7cb" stroke-width="5"/>
        <path d="M84 72h30M84 92h30M84 112h24" stroke="#f9fbf8" stroke-width="5" stroke-linecap="round"/>
        """
    elif kind == "kettle":
        inner = """
        <path d="M56 86c8-24 58-24 68 0l-8 58H64z" fill="#f9fbf8" stroke="#1d2730" stroke-width="5" stroke-linejoin="round"/>
        <path d="M118 88l34-24" stroke="#1d2730" stroke-width="5" stroke-linecap="round"/>
        <path d="M62 86c0-28 56-28 56 0" fill="none" stroke="#1d2730" stroke-width="5"/>
        <circle cx="90" cy="116" r="13" fill="#2f8f83"/>
        """
    else:
        inner = """
        <path d="M56 92h72l-10 54H66z" fill="#d8c7a6" stroke="#1d2730" stroke-width="5" stroke-linejoin="round"/>
        <path d="M74 92c2-28 30-38 44-52 6 24-4 42-22 52" fill="#2f8f83" stroke="#1d2730" stroke-width="5" stroke-linejoin="round"/>
        <path d="M86 92c-8-22-24-28-40-30 2 24 18 34 40 30" fill="#8fc6a3" stroke="#1d2730" stroke-width="5" stroke-linejoin="round"/>
        """
    return f"""
    <svg class="product-svg" viewBox="0 0 180 180" role="img" aria-label="{safe_label}" xmlns="http://www.w3.org/2000/svg">
      <rect width="180" height="180" rx="18" fill="#fff7eb"/>
      <circle cx="36" cy="36" r="20" fill="#f4c95d" opacity="0.55"/>
      <circle cx="146" cy="138" r="28" fill="#b8d8d2" opacity="0.72"/>
      {inner}
    </svg>
    """


async def _form_fields(request: Request) -> dict[str, str]:
    """Parse URL-encoded form fields without extra dependencies."""
    raw = (await request.body()).decode("utf-8", errors="replace")
    parsed = parse_qs(raw, keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


def _body_message(body: bytes, content_type: str) -> str:
    """Return a decoded body summary useful for SLS evidence."""
    if not body:
        return ""
    text = body.decode("utf-8", errors="replace")
    if "application/x-www-form-urlencoded" in content_type:
        fields = parse_qsl(text, keep_blank_values=True)
        text = " ".join(f"{key}={value}" for key, value in fields)
    return text[:1000]


def _client_ip(request: Request) -> str:
    """Prefer WAF/proxy forwarding headers when available."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else ""


def _looks_like_traversal(value: str) -> bool:
    """Return whether a requested file path is a traversal test."""
    lowered = value.lower()
    return "../" in lowered or "..\\" in lowered or "/etc/passwd" in lowered or "boot.ini" in lowered


def _env(name: str, default: str) -> str:
    """Read one environment variable with a default."""
    return os.getenv(name, default)


def _lab_script() -> str:
    """Return attack-lab helper JavaScript."""
    return """
    <script>
      const statusBox = () => document.getElementById("lab-status");
      const setStatus = (message) => { statusBox().textContent = message; };
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      async function postForm(path, fields) {
        const body = new URLSearchParams(fields);
        return fetch(path, {
          method: "POST",
          headers: {"Content-Type": "application/x-www-form-urlencoded"},
          body
        });
      }
      async function runLoginBurst() {
        setStatus("Sending failed login burst...");
        for (let i = 0; i < 6; i += 1) {
          await postForm("/login", {email: "admin@example.com", password: "guess-" + i});
          await sleep(120);
        }
        setStatus("Login burst complete. Check the storefront access logs.");
      }
      async function runErrorSpike() {
        setStatus("Triggering checkout errors...");
        for (let i = 0; i < 4; i += 1) {
          await fetch("/checkout?fail=true&attempt=" + i, {method: "POST"});
          await sleep(150);
        }
        setStatus("Server error spike complete. Check the storefront access logs.");
      }
      async function runRapidSpam() {
        const form = document.getElementById("rapid-spam-form");
        setStatus("Dispatching rapid contact submits...");
        for (let i = 0; i < 4; i += 1) {
          const event = typeof SubmitEvent === "function"
            ? new SubmitEvent("submit", {bubbles: true, cancelable: true})
            : new Event("submit", {bubbles: true, cancelable: true});
          form.dispatchEvent(event);
          await postForm("/contact", {message: form.elements.message.value + " #" + i});
          await sleep(150);
        }
        setStatus("Rapid contact submits complete.");
      }
      function triggerBrowserErrors() {
        setStatus("Raising client-side errors...");
        for (let i = 0; i < 3; i += 1) {
          setTimeout(() => { throw new Error("Storefront browser error spike " + i); }, i * 150);
        }
        setTimeout(() => setStatus("Browser error spike sent."), 700);
      }
      function triggerBotActivity() {
        setStatus("Creating bot-like activity burst...");
        for (let i = 0; i < 90; i += 1) {
          document.dispatchEvent(new MouseEvent("click", {bubbles: true, cancelable: true}));
        }
        setStatus("Bot-like activity burst complete.");
      }
    </script>
    """


def _styles() -> str:
    """Return inline styles for the storefront."""
    return """
    :root {
      --paper: #fffaf3;
      --canvas: #f4efe7;
      --ink: #1d2730;
      --muted: #65707a;
      --line: rgba(29, 39, 48, 0.14);
      --brand: #ef795e;
      --brand-dark: #b64634;
      --gold: #f4c95d;
      --mint: #b8d8d2;
      --green: #2f8f83;
      --violet: #6f7ebc;
      --shadow: 0 20px 45px rgba(61, 47, 34, 0.12);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--canvas); color: var(--ink); line-height: 1.55; }
    a { color: var(--ink); text-decoration: none; font-weight: 760; }
    .topbar {
      display: flex; align-items: center; justify-content: space-between; gap: 20px;
      min-height: 76px; padding: 0 max(20px, calc((100vw - 1180px) / 2));
      border-bottom: 1px solid var(--line); background: rgba(255, 250, 243, 0.94);
      position: sticky; top: 0; backdrop-filter: blur(14px); z-index: 2;
    }
    .brand { display: inline-flex; align-items: center; gap: 10px; color: var(--ink); font-size: 1rem; }
    .brand-mark {
      display: inline-flex; align-items: center; justify-content: center;
      width: 34px; height: 34px; border-radius: 50%; background: var(--ink); color: var(--paper); font-weight: 900;
    }
    nav { display: flex; flex-wrap: wrap; gap: 18px; align-items: center; }
    nav a { color: #43505b; font-size: 0.94rem; }
    main { width: min(1180px, calc(100% - 40px)); margin: 0 auto; padding: 44px 0 58px; }
    footer {
      width: min(1180px, calc(100% - 40px)); margin: 0 auto; padding: 26px 0 48px;
      display: flex; justify-content: space-between; gap: 18px; flex-wrap: wrap; color: var(--muted);
      border-top: 1px solid var(--line);
    }
    footer span:first-child { color: var(--ink); font-weight: 850; }
    h1, h2, h3 { margin: 0; line-height: 1.08; }
    h1 { font-size: clamp(2.25rem, 5vw, 4.5rem); max-width: 830px; }
    h2 { font-size: clamp(1.45rem, 2.3vw, 2.2rem); }
    h3 { font-size: 1.1rem; }
    p { color: var(--muted); margin: 0; }
    .lead { font-size: 1.06rem; max-width: 690px; }
    .hero { display: grid; grid-template-columns: minmax(0, 1fr) minmax(320px, 0.62fr); gap: 34px; align-items: center; min-height: 66vh; }
    .hero-copy, .page-heading, .section-heading { display: grid; gap: 18px; }
    .eyebrow, .test-type {
      color: var(--brand-dark); font-size: 0.76rem; font-weight: 900; letter-spacing: 0; text-transform: uppercase;
    }
    .actions { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 8px; }
    .button, button {
      display: inline-flex; align-items: center; justify-content: center; min-height: 44px; border: 0;
      border-radius: 8px; background: var(--ink); color: white; padding: 0 18px; font-weight: 850; cursor: pointer;
    }
    .button.secondary, button.secondary { background: var(--paper); color: var(--ink); border: 1px solid var(--line); }
    .hero-display { position: relative; }
    .featured-card, .status-card, article, .panel {
      border: 1px solid var(--line); border-radius: 8px; background: var(--paper); box-shadow: var(--shadow);
    }
    .featured-card {
      display: grid; gap: 20px; padding: 24px; overflow: hidden; transform: rotate(1deg);
    }
    .featured-card.large .product-svg { width: 100%; min-height: 330px; }
    .featured-copy { display: flex; align-items: end; justify-content: space-between; gap: 16px; }
    .featured-copy p, .compact-card p { color: var(--brand-dark); font-size: 0.78rem; font-weight: 850; text-transform: uppercase; }
    .featured-copy span, .compact-card span { color: var(--ink); font-weight: 900; }
    .promo-strip {
      display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1px; overflow: hidden;
      border: 1px solid var(--line); border-radius: 8px; background: var(--line); margin: 8px 0 42px;
    }
    .promo-strip span { background: var(--paper); padding: 16px; text-align: center; font-weight: 830; }
    .grid { display: grid; gap: 16px; margin-top: 24px; }
    .grid.two { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .grid.three { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .compact-card, .lab-card, .product-card, .panel { display: grid; gap: 14px; padding: 20px; box-shadow: none; }
    .compact-card { grid-template-columns: 104px 1fr; align-items: center; }
    .compact-card .product-svg { width: 104px; height: 104px; }
    .product-card { padding: 0; overflow: hidden; }
    .product-art { background: #fff1df; }
    .product-card .product-svg { width: 100%; height: auto; display: block; border-radius: 0; }
    .product-meta { display: grid; gap: 12px; padding: 18px; }
    .badge { width: max-content; color: var(--brand-dark); font-size: 0.74rem; font-weight: 900; text-transform: uppercase; }
    .buy-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 4px; }
    .buy-row strong { font-size: 1.2rem; }
    .lab-card { align-content: space-between; min-height: 262px; }
    .status-card { margin-top: 18px; padding: 20px; }
    form { display: grid; gap: 12px; }
    label { display: grid; gap: 7px; color: #3a4650; font-weight: 780; }
    input, textarea {
      width: 100%; min-height: 44px; border: 1px solid var(--line); border-radius: 8px;
      background: white; color: var(--ink); padding: 10px 12px; font: inherit;
    }
    textarea { min-height: 104px; resize: vertical; }
    .search-form { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 12px; margin-top: 26px; }
    .notice { margin-top: 18px; }
    .checkout-layout { display: grid; grid-template-columns: minmax(0, 1fr) minmax(280px, 0.72fr); gap: 18px; margin-top: 26px; }
    .order-list div { display: flex; justify-content: space-between; gap: 16px; padding: 12px 0; border-bottom: 1px solid var(--line); }
    .order-list .total { border-bottom: 0; font-size: 1.18rem; }
    .account-panel { max-width: 520px; margin-top: 24px; }
    code, pre { font-family: "SFMono-Regular", Consolas, monospace; }
    code { background: #fff1df; border-radius: 4px; padding: 2px 5px; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #1d2730; color: #fffaf3; border-radius: 8px; padding: 16px; }
    .product-svg { display: block; border-radius: 8px; }
    @media (max-width: 820px) {
      .hero, .grid.two, .grid.three, .promo-strip, .search-form, .checkout-layout { grid-template-columns: 1fr; }
      .topbar { align-items: flex-start; flex-direction: column; padding-top: 16px; padding-bottom: 16px; }
      nav { gap: 12px; }
      .featured-card { transform: none; }
    }
    """


app = create_app()
