from __future__ import annotations


def lab_script() -> str:
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
      async function runRapidFormBurst() {
        const form = document.getElementById("rapid-form");
        setStatus("Dispatching rapid form submissions...");
        for (let i = 0; i < 10; i += 1) {
          const event = typeof SubmitEvent === "function"
            ? new SubmitEvent("submit", {bubbles: true, cancelable: true})
            : new Event("submit", {bubbles: true, cancelable: true});
          form.dispatchEvent(event);
          await postForm("/contact", {message: form.elements.message.value + " #" + i});
          await sleep(150);
        }
        setStatus("Rapid form submissions complete.");
      }
    </script>
    """


def styles() -> str:
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
