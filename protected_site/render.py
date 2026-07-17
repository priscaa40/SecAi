from __future__ import annotations

import html
import os

from fastapi import Request
from fastapi.responses import HTMLResponse

from protected_site.assets import styles
from protected_site.catalog import BRAND_NAME, Product


def render_page(
    request: Request,
    title: str,
    body: str,
    *,
    status_code: int = 200,
    extra_script: str = "",
) -> HTMLResponse:
    """Render one complete HTML page with the browser monitoring snippet."""
    del request
    secai_base = os.getenv("SECAI_PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
    site_id = os.getenv("SECAI_SITE_ID", "judge-site")
    snippet = f'<script defer src="{html.escape(secai_base)}/api/integrations/browser.js?site_id={html.escape(site_id)}"></script>'
    content = f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{html.escape(title)} | {BRAND_NAME}</title>
        <style>{styles()}</style>
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


def featured_product(product: Product, size: str) -> str:
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


def compact_product(product: Product) -> str:
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


def product_card(product: Product) -> str:
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
