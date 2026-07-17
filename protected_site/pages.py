from __future__ import annotations

import html
from urllib.parse import parse_qs

from fastapi import Request
from fastapi.responses import HTMLResponse

from protected_site.assets import lab_script
from protected_site.catalog import PRODUCTS, matching_products
from protected_site.render import compact_product, featured_product, product_card, render_page


def home(request: Request) -> HTMLResponse:
    """Render the storefront landing page."""
    featured = featured_product(PRODUCTS[0], "large")
    compact_products = "".join(compact_product(product) for product in PRODUCTS[1:4])
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
    return render_page(request, "Home", body)


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
          <h2>Rapid form submissions</h2>
          <p>Dispatches ten submissions to one form and matching POST traffic.</p>
        </div>
        <form id="rapid-form" action="/contact" method="post" onsubmit="event.preventDefault()">
          <textarea name="message">Limited-time offer from automated form traffic.</textarea>
          <button type="button" onclick="runRapidFormBurst()">Run rapid submits</button>
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

    </section>

    <section class="status-card" id="lab-status" role="status">Ready.</section>
    """
    return render_page(request, "Traffic Test Panel", body, extra_script=lab_script())


def products(request: Request, q: str = "") -> HTMLResponse:
    """Render product search results."""
    safe_query = html.escape(q)
    matches = matching_products(q)
    product_items = "".join(product_card(product) for product in matches)
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
    return render_page(request, "Products", body)


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
    return render_page(request, "Member Sign In", body)


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
    return render_page(request, "Sign-In Failed", body, status_code=401)


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
        return render_page(request, "Download Blocked", body, status_code=403)
    body = f"""
    <section class="page-heading">
      <p class="eyebrow">Catalog download</p>
      <h1>Catalog request received.</h1>
      <p class="lead">Requested file: <code>{safe_file}</code></p>
    </section>
    """
    return render_page(request, "Catalog Download", body)


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
        return render_page(request, "Checkout Error", body, status_code=500)
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
    return render_page(request, "Checkout", body)


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
    return render_page(request, "Contact", body)


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
    return render_page(request, "Message Received", body)


def health() -> dict[str, str]:
    """Return health status for Alibaba load balancers."""
    return {"status": "ok", "service": "northstar-goods-storefront"}


async def _form_fields(request: Request) -> dict[str, str]:
    """Parse URL-encoded form fields without extra dependencies."""
    raw = (await request.body()).decode("utf-8", errors="replace")
    parsed = parse_qs(raw, keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


def _looks_like_traversal(value: str) -> bool:
    """Return whether a requested file path is a traversal test."""
    lowered = value.lower()
    return "../" in lowered or "..\\" in lowered or "/etc/passwd" in lowered or "boot.ini" in lowered
