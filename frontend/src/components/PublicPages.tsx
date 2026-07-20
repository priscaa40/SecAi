import { ArrowRight, ShieldCheck } from "lucide-react";
import type { FormEvent } from "react";

import type { Session } from "../types";
import { SetupWizard } from "./SetupWizard";

export function Brand() {
  return (
    <div className="brand-block">
      <span className="product-mark"><ShieldCheck size={22} aria-hidden="true" /></span>
      <span className="brand-name">SecAi</span>
    </div>
  );
}

export function PublicHome({ onStartSetup, onShowLogin }: { onStartSetup: () => void; onShowLogin: () => void }) {
  return (
    <div className="public-shell">
      <header className="public-topbar">
        <Brand />
        <div className="account-bar">
          <button type="button" className="ghost-button" onClick={onShowLogin}>Log in</button>
          <button type="button" onClick={onStartSetup}>Set up SecAi</button>
        </div>
      </header>

      <main>
        <section className="home-hero simple-home-hero">
          <div className="hero-copy">
            <p className="home-kicker">Your security team in your pocket</p>
            <h1>Find out when your website is under attack—and what to do about it.</h1>
            <p>SecAi investigates suspicious activity as it happens and quickly gives you a clear report with a recommended response, so you can act before more damage is done.</p>
            <div className="public-actions">
              <button type="button" onClick={onStartSetup}>Protect my website <ArrowRight size={17} /></button>
              <button type="button" className="secondary-button" onClick={onShowLogin}>Log in</button>
            </div>
          </div>
          <div className="hero-explanation">
            <p>Every report gives you:</p>
            <ol>
              <li><strong>What happened</strong><span>A clear explanation of the suspicious activity and the part of your website involved.</span></li>
              <li><strong>Evidence source</strong><span>Where SecAi saw the activity and the details that support its conclusion.</span></li>
              <li><strong>What to do next</strong><span>One recommended response, what it will change, and whether your approval is required.</span></li>
            </ol>
          </div>
        </section>

        <section className="home-process">
          <div className="section-intro">
            <p className="eyebrow">How SecAi investigates</p>
            <h2>Three focused roles turn warning signs into one clear report.</h2>
            <p>Each role checks a different part of the case, so the final recommendation is based on evidence rather than a single first impression.</p>
          </div>
          <ol>
            <li><span>1</span><strong>Investigator</strong><p>Finds related activity and identifies the likely threat.</p></li>
            <li><span>2</span><strong>Reviewer</strong><p>Challenges the evidence and filters weak conclusions.</p></li>
            <li><span>3</span><strong>Responder</strong><p>Explains the risk and recommends the safest response.</p></li>
            <li><span>4</span><strong>Executor</strong><p>Invokes the selected action through a guarded MCP tool.</p></li>
          </ol>
        </section>

        <section className="control-story simple-control-story">
          <div>
            <p className="eyebrow">Your approval</p>
            <h2>You approve what happens next.</h2>
          </div>
          <p>SecAi can investigate, report, collect fresh evidence, and send alerts automatically. A network change waits for your approval; then Qwen Executor invokes the guarded MCP tool and the dashboard shows the verified result.</p>
        </section>

        <section className="quick-start simple-quick-start">
          <div><h2>Put SecAi to work on your website</h2><p>Setup guides you through connecting an evidence source and choosing where reports are sent.</p></div>
          <button type="button" onClick={onStartSetup}>Protect my website <ArrowRight size={17} /></button>
        </section>
      </main>
    </div>
  );
}

export function LoginPage({
  email, password, mode, status, busy, onEmail, onPassword, onMode, onSubmit, onBack,
}: {
  email: string; password: string; mode: "login" | "signup"; status: string; busy: boolean;
  onEmail: (value: string) => void; onPassword: (value: string) => void;
  onMode: (value: "login" | "signup") => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onBack: () => void;
}) {
  return (
    <div className="public-shell auth-page">
      <header className="public-topbar"><Brand /><button type="button" className="ghost-button" onClick={onBack}>Back to home</button></header>
      <main className="login-layout">
        <div className="login-copy">
          <p className="home-kicker">SecAi dashboard</p>
          <h1>Review reports for your websites.</h1>
          <p>Log in to see recent incidents, approve or decline recommended actions, and manage how each website is connected.</p>
        </div>
        <AuthPanel email={email} password={password} mode={mode} status={status} busy={busy} onEmail={onEmail} onPassword={onPassword} onMode={onMode} onSubmit={onSubmit} />
      </main>
    </div>
  );
}

function AuthPanel({ email, password, mode, status, busy, onEmail, onPassword, onMode, onSubmit }: {
  email: string; password: string; mode: "login" | "signup"; status: string; busy: boolean;
  onEmail: (value: string) => void; onPassword: (value: string) => void;
  onMode: (value: "login" | "signup") => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <section className="auth-card">
      <p className="eyebrow">{mode === "login" ? "Welcome back" : "Create your workspace"}</p>
      <h2>{mode === "login" ? "Log in to SecAi" : "Create your SecAi account"}</h2>
      <p>{mode === "login" ? "Use the email and password from setup." : "Your reports are private and tied to this email."}</p>
      <form className="panel-form" onSubmit={onSubmit}>
        <label>Email address<input type="email" value={email} onChange={(event) => onEmail(event.target.value)} placeholder="you@example.com" autoComplete="email" required /></label>
        <label>Password<input type="password" value={password} onChange={(event) => onPassword(event.target.value)} placeholder={mode === "signup" ? "At least 8 characters" : "Your password"} minLength={mode === "signup" ? 8 : 1} autoComplete={mode === "login" ? "current-password" : "new-password"} required /></label>
        <button type="submit" disabled={busy}>{busy ? "Please wait…" : mode === "login" ? "Open my dashboard" : "Create my account"}<ArrowRight size={16} /></button>
      </form>
      <button type="button" className="link-button" onClick={() => onMode(mode === "login" ? "signup" : "login")}>{mode === "login" ? "New to SecAi? Create an account" : "Already have an account? Log in"}</button>
      {status && status !== "Your reports are up to date." ? <p className="status-line" role="status" aria-live="polite">{status}</p> : null}
    </section>
  );
}

export function SetupPage({ apiBase, onSession, onBack }: { apiBase: string; onSession: (session: Session) => void; onBack: () => void }) {
  return (
    <div className="public-shell setup-page">
      <header className="public-topbar"><Brand /><button type="button" className="ghost-button" onClick={onBack}>Exit setup</button></header>
      <main><SetupWizard apiBase={apiBase} onSession={onSession} /></main>
    </div>
  );
}
