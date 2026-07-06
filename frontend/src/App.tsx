import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clipboard,
  Download,
  Eye,
  ExternalLink,
  Globe,
  LayoutDashboard,
  LogOut,
  MessageCircle,
  Play,
  Plus,
  RefreshCw,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  Siren,
  Target,
  XCircle,
} from "lucide-react";
import type { ReactNode } from "react";
import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  approveIncident,
  createSite,
  getAlibabaAutopilotTemplate,
  getAutopilotStatus,
  getRemediationPreferences,
  listIncidents,
  listSites,
  login,
  logout,
  me,
  pullAlibabaSlsLogs,
  qwenUsage,
  rejectIncident,
  runDemo,
  saveAlibabaAutopilotConfig,
  setRemediationPreference,
  setupWebsite,
  signup,
} from "./api";
import type {
  AlibabaAutopilotTemplate,
  AutopilotStatus,
  Incident,
  RemediationPreference,
  Session,
  Site,
  UsageSummary,
} from "./types";
import "./App.css";

const storedApiBase = localStorage.getItem("secai.apiBase") || "http://localhost:8000";
const storedToken = localStorage.getItem("secai.token") || "";
const remediationActions = [
  "monitor",
  "notify_admin",
  "block_ip",
  "block_ip_range",
  "rate_limit_ip",
  "rate_limit_route",
  "block_payload_pattern",
  "virtual_patch",
  "read_only_route",
  "challenge_route",
  "enable_anti_scan",
  "disable_route",
];
const automaticActionChoices = remediationActions;
type PublicView = "home" | "setup" | "login";

function newExternalId() {
  const cryptoApi: Crypto | undefined = globalThis.crypto;
  if (cryptoApi?.randomUUID) {
    return `secai-${cryptoApi.randomUUID().replace(/-/g, "").slice(0, 16)}`;
  }
  if (cryptoApi) {
    const bytes = new Uint8Array(8);
    cryptoApi.getRandomValues(bytes);
    return `secai-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  }
  return `secai-${Math.random().toString(36).slice(2, 14)}`;
}

type SetupDraft = {
  websiteName: string;
  watchMethod: "browser" | "alibaba_autopilot";
  channels: string[];
  dashboardEmail: string;
  dashboardPassword: string;
  discordConnected: boolean;
  slsEndpoint: string;
  slsProject: string;
  slsLogstore: string;
  slsRoleArn: string;
  slsExternalId: string;
  alibabaRegion: string;
  wafInstanceId: string;
  wafDomain: string;
  automaticActions: string[];
};

const initialDraft: SetupDraft = {
  websiteName: "",
  watchMethod: "browser",
  channels: ["dashboard"],
  dashboardEmail: localStorage.getItem("secai.email") || "",
  dashboardPassword: "",
  discordConnected: false,
  slsEndpoint: "",
  slsProject: "",
  slsLogstore: "",
  slsRoleArn: "",
  slsExternalId: newExternalId(),
  alibabaRegion: "ap-southeast-1",
  wafInstanceId: "",
  wafDomain: "",
  automaticActions: [],
};

function App() {
  const [apiBase, setApiBase] = useState(storedApiBase);
  const [session, setSession] = useState<Session | null>(null);
  const [view, setView] = useState<PublicView>(() => viewFromPath(window.location.pathname));
  const [authMode, setAuthMode] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState(localStorage.getItem("secai.email") || "");
  const [password, setPassword] = useState("");
  const [sites, setSites] = useState<Site[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null);
  const [selectedSiteId, setSelectedSiteId] = useState("");
  const [usage, setUsage] = useState<UsageSummary | null>(null);
  const [siteName, setSiteName] = useState("");
  const [autopilotStatus, setAutopilotStatus] = useState<AutopilotStatus | null>(null);
  const [preferences, setPreferences] = useState<RemediationPreference[]>([]);
  const [status, setStatus] = useState("Ready.");
  const [busy, setBusy] = useState(false);

  const selectedSite = useMemo(
    () => sites.find((site) => site.site_id === selectedSiteId) || sites[0] || null,
    [sites, selectedSiteId],
  );

  const selectedIncident = useMemo(
    () => incidents.find((incident) => incident.id === selectedIncidentId) || incidents[0] || null,
    [incidents, selectedIncidentId],
  );

  useEffect(() => {
    if (storedToken) void restoreSession(storedApiBase, storedToken);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    function syncRoute() {
      setView(viewFromPath(window.location.pathname));
    }
    window.addEventListener("popstate", syncRoute);
    return () => window.removeEventListener("popstate", syncRoute);
  }, []);

  useEffect(() => {
    if (session && selectedSite) void loadSiteSettings(session, selectedSite.site_id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.token, selectedSite?.site_id]);

  async function restoreSession(base: string, token: string) {
    setBusy(true);
    try {
      const result = await me(base, token);
      const restored = { apiBase: base, token, user: result.user };
      setSession(restored);
      await loadWorkspace(restored);
    } catch {
      localStorage.removeItem("secai.token");
    } finally {
      setBusy(false);
    }
  }

  function saveSession(nextSession: Session) {
    localStorage.setItem("secai.apiBase", nextSession.apiBase);
    localStorage.setItem("secai.email", nextSession.user.email);
    localStorage.setItem("secai.token", nextSession.token);
    setApiBase(nextSession.apiBase);
    setSession(nextSession);
    replaceRoute("/dashboard");
  }

  function navigate(nextView: PublicView) {
    const path = nextView === "home" ? "/" : `/${nextView}`;
    window.history.pushState(null, "", path);
    setView(nextView);
  }

  async function loadWorkspace(activeSession = session) {
    if (!activeSession) return;
    setBusy(true);
    setStatus("Refreshing reports...");
    try {
      const [siteResult, usageResult] = await Promise.all([listSites(activeSession), qwenUsage(activeSession)]);
      const nextSiteId = selectedSiteId || siteResult.sites[0]?.site_id || "";
      const incidentResult = await listIncidents(activeSession, nextSiteId || undefined);
      setSites(siteResult.sites);
      setUsage(usageResult.summary);
      setSelectedSiteId(nextSiteId);
      setIncidents(incidentResult);
      setSelectedIncidentId((current) => current || incidentResult[0]?.id || null);
      setStatus(`Reports for ${activeSession.user.email}`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to load reports.");
    } finally {
      setBusy(false);
    }
  }

  async function loadSiteSettings(activeSession: Session, siteId: string) {
    try {
      const [pref, autopilot] = await Promise.all([
        getRemediationPreferences(activeSession, siteId),
        getAutopilotStatus(activeSession, siteId),
      ]);
      setPreferences(pref.preferences);
      setAutopilotStatus(autopilot);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to load website settings.");
    }
  }

  async function handleAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    try {
      const result =
        authMode === "login" ? await login(apiBase, email.trim().toLowerCase(), password) : await signup(apiBase, email.trim().toLowerCase(), password);
      const nextSession = { apiBase: apiBase.replace(/\/$/, ""), token: result.token, user: result.user };
      saveSession(nextSession);
      setPassword("");
      await loadWorkspace(nextSession);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Could not sign you in.");
    } finally {
      setBusy(false);
    }
  }

  async function handleLogout() {
    if (session) await logout(session).catch(() => undefined);
    localStorage.removeItem("secai.token");
    setSession(null);
    setSites([]);
    setIncidents([]);
    navigate("home");
  }

  async function handleCreateSite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!session || !siteName.trim()) return;
    setBusy(true);
    try {
      const site = await createSite(session, siteName.trim());
      setSiteName("");
      setSelectedSiteId(site.site_id);
      await loadWorkspace(session);
    } finally {
      setBusy(false);
    }
  }

  async function handleSiteChange(siteId: string) {
    if (!session) return;
    setSelectedSiteId(siteId);
    const incidentResult = await listIncidents(session, siteId);
    setIncidents(incidentResult);
    setSelectedIncidentId(incidentResult[0]?.id || null);
  }

  async function handleDemo() {
    if (!session || !selectedSite) return;
    setBusy(true);
    try {
      await runDemo(session, selectedSite);
      await loadWorkspace(session);
    } finally {
      setBusy(false);
    }
  }

  async function handleDecision(action: "approve" | "reject", incidentId: number) {
    if (!session) return;
    setBusy(true);
    try {
      if (action === "approve") {
        await approveIncident(session, incidentId);
      } else {
        await rejectIncident(session, incidentId);
      }
      await loadWorkspace(session);
    } finally {
      setBusy(false);
    }
  }

  if (session) {
    return (
      <Dashboard
        session={session}
        sites={sites}
        incidents={incidents}
        selectedSite={selectedSite}
        selectedSiteId={selectedSiteId}
        selectedIncident={selectedIncident}
        usage={usage}
        siteName={siteName}
        autopilotStatus={autopilotStatus}
        preferences={preferences}
        status={status}
        busy={busy}
        onLogout={handleLogout}
        onRefresh={() => loadWorkspace()}
        onSiteName={setSiteName}
        onCreateSite={handleCreateSite}
        onSelectSite={handleSiteChange}
        onAutopilotStatus={setAutopilotStatus}
        onSlsPulled={() => loadWorkspace(session)}
        onPreferences={setPreferences}
        onDemo={handleDemo}
        onSelectIncident={setSelectedIncidentId}
        onDecision={handleDecision}
      />
    );
  }

  if (view === "setup") {
    return (
      <SetupPage
        apiBase={apiBase}
        onApiBase={setApiBase}
        onBack={() => navigate("home")}
        onSession={(nextSession) => {
          saveSession(nextSession);
          void loadWorkspace(nextSession);
        }}
      />
    );
  }

  if (view === "login") {
    return (
      <LoginPage
        apiBase={apiBase}
        email={email}
        password={password}
        mode={authMode}
        status={status}
        busy={busy}
        onApiBase={setApiBase}
        onEmail={setEmail}
        onPassword={setPassword}
        onMode={setAuthMode}
        onSubmit={handleAuth}
        onBack={() => navigate("home")}
        onDemoLogin={() => {
          setAuthMode("login");
          setEmail("owner@example.com");
          setPassword("password123");
        }}
      />
    );
  }

  return (
    <PublicHome
      onStartSetup={() => navigate("setup")}
      onShowLogin={() => navigate("login")}
    />
  );
}

function viewFromPath(pathname: string): PublicView {
  if (pathname === "/setup") return "setup";
  if (pathname === "/login") return "login";
  return "home";
}

function replaceRoute(path: string) {
  window.history.replaceState(null, "", path);
}

// ─── Public Home ──────────────────────────────────────────────────────────────

function PublicHome({
  onStartSetup,
  onShowLogin,
}: {
  onStartSetup: () => void;
  onShowLogin: () => void;
}) {
  return (
    <div className="public-shell">
      <header className="topbar public-topbar">
        <div className="brand-block">
          <span className="product-mark">
            <ShieldCheck size={22} aria-hidden="true" />
          </span>
          <span style={{ fontWeight: 700, fontSize: "1.1rem", letterSpacing: "-0.02em" }}>SecAi</span>
        </div>
        <div className="account-bar">
          <button type="button" className="ghost-button" onClick={onShowLogin}>
            Log in
          </button>
          <button type="button" onClick={onStartSetup}>
            Get started
            <ArrowRight size={16} aria-hidden="true" />
          </button>
        </div>
      </header>

      <main>
        <section className="home-hero">
          <div className="hero-copy">
            <p className="eyebrow">Autopilot Security</p>
            <h2>Website security help for busy owners</h2>
            <p>
              When something suspicious happens on your website, SecAi explains it in plain language
              and asks what to do. No security expertise required.
            </p>
            <div className="public-actions">
              <button type="button" onClick={onStartSetup}>
                Protect a website
                <ArrowRight size={16} aria-hidden="true" />
              </button>
              <button type="button" className="secondary-button" onClick={onShowLogin}>
                Log in
              </button>
            </div>
          </div>
          <div className="home-preview" aria-label="Example SecAi report">
            <div className="preview-header">
              <span className="preview-dot" />
              <strong style={{ fontSize: "0.85rem" }}>Live incident</strong>
              <Pill tone="high">high severity</Pill>
            </div>
            <h3>Suspicious login burst detected</h3>
            <p>
              47 failed login attempts in 30 seconds from a single IP. This looks like a password guessing attack targeting your admin panel.
            </p>
            <div className="preview-action">
              <span>Recommended action</span>
              <strong>Block attacking IP for 24 hours</strong>
            </div>
            <div className="decision-row">
              <button type="button" style={{ flex: 1 }}>
                <CheckCircle2 size={16} /> Approve
              </button>
              <button type="button" className="secondary-button" style={{ flex: 1 }}>
                Dismiss
              </button>
            </div>
          </div>
        </section>

        <section className="how-it-works">
          <div>
            <p className="eyebrow">How it works</p>
            <h2>Three choices, then SecAi watches for you</h2>
          </div>
          <div className="public-card-grid">
            <article className="public-card">
              <Eye size={24} aria-hidden="true" />
              <h3>Choose how to watch</h3>
              <p>Paste a small script into any website, or connect Alibaba Autopilot for cloud-native evidence and WAF enforcement.</p>
            </article>
            <article className="public-card">
              <MessageCircle size={24} aria-hidden="true" />
              <h3>Choose where reports go</h3>
              <p>Get plain-language incident reports in the SecAi dashboard, Discord, or both. No developer account needed.</p>
            </article>
            <article className="public-card">
              <Shield size={24} aria-hidden="true" />
              <h3>Stay in control</h3>
              <p>SecAi asks before blocking, slowing, or disabling anything. You decide which actions can run automatically.</p>
            </article>
          </div>
        </section>

        <section className="quick-start">
          <div>
            <p className="eyebrow">Ready to start</p>
            <h2>Setup takes less than 5 minutes</h2>
            <p style={{ maxWidth: 520, margin: "8px auto 0" }}>
              No Discord developer setup. No Alibaba secret keys. SecAi asks only for what you need.
            </p>
          </div>
          <div className="public-actions" style={{ justifyContent: "center" }}>
            <button type="button" onClick={onStartSetup}>
              Start setup
              <ArrowRight size={16} aria-hidden="true" />
            </button>
          </div>
        </section>
      </main>
    </div>
  );
}

// ─── Login Page ───────────────────────────────────────────────────────────────

function LoginPage({
  apiBase,
  email,
  password,
  mode,
  status,
  busy,
  onApiBase,
  onEmail,
  onPassword,
  onMode,
  onSubmit,
  onBack,
  onDemoLogin,
}: {
  apiBase: string;
  email: string;
  password: string;
  mode: "login" | "signup";
  status: string;
  busy: boolean;
  onApiBase: (value: string) => void;
  onEmail: (value: string) => void;
  onPassword: (value: string) => void;
  onMode: (value: "login" | "signup") => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onBack: () => void;
  onDemoLogin: () => void;
}) {
  return (
    <div className="public-shell">
      <header className="topbar public-topbar">
        <div className="brand-block">
          <span className="product-mark">
            <ShieldCheck size={22} aria-hidden="true" />
          </span>
          <span style={{ fontWeight: 700, fontSize: "1.1rem" }}>SecAi</span>
        </div>
        <button type="button" className="ghost-button" onClick={onBack}>
          Back
        </button>
      </header>
      <main>
        <section className="login-layout">
          <div className="login-copy">
            <p className="eyebrow">Dashboard access</p>
            <h2>Review incidents and approve actions</h2>
            <p>
              Use this when you chose dashboard reports. If you set up Discord-only, you don't need a dashboard account — approvals happen right in Discord.
            </p>
            <div className="login-actions">
              <button type="button" onClick={onDemoLogin}>
                <Play size={16} /> Use demo login
              </button>
              <span className="demo-creds">owner@example.com / password123</span>
            </div>
          </div>
          <AuthPanel
            apiBase={apiBase}
            email={email}
            password={password}
            mode={mode}
            status={status}
            busy={busy}
            onApiBase={onApiBase}
            onEmail={onEmail}
            onPassword={onPassword}
            onMode={onMode}
            onSubmit={onSubmit}
          />
        </section>
      </main>
    </div>
  );
}

// ─── Auth Panel ───────────────────────────────────────────────────────────────

function AuthPanel({
  apiBase,
  email,
  password,
  mode,
  status,
  busy,
  onApiBase,
  onEmail,
  onPassword,
  onMode,
  onSubmit,
}: {
  apiBase: string;
  email: string;
  password: string;
  mode: "login" | "signup";
  status: string;
  busy: boolean;
  onApiBase: (value: string) => void;
  onEmail: (value: string) => void;
  onPassword: (value: string) => void;
  onMode: (value: "login" | "signup") => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <section className="auth-card">
      <p className="eyebrow">{mode === "login" ? "Welcome back" : "New account"}</p>
      <h3>{mode === "login" ? "Log in to reports" : "Create dashboard account"}</h3>
      <p style={{ fontSize: "0.88rem" }}>Dashboard reports are private — only your account can see them.</p>
      <form className="panel-form flat" onSubmit={onSubmit}>
        <label>
          SecAi server
          <input type="url" value={apiBase} onChange={(event) => onApiBase(event.target.value)} required />
        </label>
        <label>
          Email
          <input type="email" value={email} onChange={(event) => onEmail(event.target.value)} placeholder="you@example.com" required />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(event) => onPassword(event.target.value)}
            placeholder={mode === "signup" ? "At least 8 characters" : "Your password"}
            minLength={mode === "signup" ? 8 : 1}
            required
          />
        </label>
        <button type="submit" disabled={busy} style={{ marginTop: 8 }}>
          {mode === "login" ? "Open dashboard" : "Create account"}
          <ArrowRight size={16} />
        </button>
      </form>
      <button type="button" className="link-button" onClick={() => onMode(mode === "login" ? "signup" : "login")}>
        {mode === "login" ? "Need an account? Create one" : "Already have an account? Log in"}
      </button>
      {status ? <p className="status-line">{status}</p> : null}
    </section>
  );
}

// ─── Setup Page ───────────────────────────────────────────────────────────────

function SetupPage({
  apiBase,
  onApiBase,
  onSession,
  onBack,
}: {
  apiBase: string;
  onApiBase: (value: string) => void;
  onSession: (session: Session) => void;
  onBack: () => void;
}) {
  return (
    <div className="public-shell">
      <header className="topbar public-topbar">
        <div className="brand-block">
          <span className="product-mark">
            <ShieldCheck size={22} aria-hidden="true" />
          </span>
          <span style={{ fontWeight: 700, fontSize: "1.1rem" }}>SecAi</span>
        </div>
        <button type="button" className="ghost-button" onClick={onBack}>
          Back
        </button>
      </header>
      <main>
        <SetupWizard apiBase={apiBase} onApiBase={onApiBase} onSession={onSession} />
      </main>
    </div>
  );
}

// ─── Setup Wizard ─────────────────────────────────────────────────────────────

function SetupWizard({
  apiBase,
  onApiBase,
  onSession,
}: {
  apiBase: string;
  onApiBase: (value: string) => void;
  onSession: (session: Session) => void;
}) {
  const [step, setStep] = useState(0);
  const [draft, setDraft] = useState<SetupDraft>(initialDraft);
  const [createdSnippet, setCreatedSnippet] = useState("");
  const [messagingSetup, setMessagingSetup] = useState<{ channel: "discord"; setup_code: string }[]>([]);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const steps = ["Website", "Watch", "Reports", "Control", "Finish"];

  function patch(next: Partial<SetupDraft>) {
    setDraft((current) => ({ ...current, ...next }));
  }

  function toggleChannel(channel: string) {
    const next = draft.channels.includes(channel)
      ? draft.channels.filter((item) => item !== channel)
      : draft.channels.concat(channel);
    patch({ channels: next.length ? next : draft.channels });
  }

  function toggleAction(action: string) {
    patch({
      automaticActions: draft.automaticActions.includes(action)
        ? draft.automaticActions.filter((item) => item !== action)
        : draft.automaticActions.concat(action),
    });
  }

  function canContinue() {
    if (step === 0) return draft.websiteName.trim().length > 0;
    if (step === 1) {
      if (draft.watchMethod === "browser") return true;
      return Boolean(draft.slsRoleArn && draft.slsExternalId && draft.alibabaRegion);
    }
    if (step === 2) {
      if (draft.channels.includes("dashboard") && (!draft.dashboardEmail || draft.dashboardPassword.length < 8)) return false;
      if (draft.channels.includes("discord") && !draft.discordConnected) return false;
      return draft.channels.length > 0;
    }
    return true;
  }

  async function finishSetup() {
    setBusy(true);
    setMessage("Finishing setup...");
    try {
      const result = await setupWebsite(apiBase.replace(/\/$/, ""), {
        website_name: draft.websiteName,
        watch_method: draft.watchMethod,
        report_channels: draft.channels,
        dashboard_email: draft.channels.includes("dashboard") ? draft.dashboardEmail : undefined,
        dashboard_password: draft.channels.includes("dashboard") ? draft.dashboardPassword : undefined,
        sls_endpoint: draft.watchMethod !== "browser" ? draft.slsEndpoint || undefined : undefined,
        sls_project: draft.watchMethod !== "browser" ? draft.slsProject || undefined : undefined,
        sls_logstore: draft.watchMethod !== "browser" ? draft.slsLogstore || undefined : undefined,
        sls_role_arn: draft.watchMethod !== "browser" ? draft.slsRoleArn : undefined,
        sls_external_id: draft.watchMethod !== "browser" ? draft.slsExternalId : undefined,
        alibaba_region: draft.watchMethod === "alibaba_autopilot" ? draft.alibabaRegion : undefined,
        waf_instance_id: draft.watchMethod === "alibaba_autopilot" ? draft.wafInstanceId || undefined : undefined,
        waf_domain: draft.watchMethod === "alibaba_autopilot" ? draft.wafDomain || undefined : undefined,
        automatic_actions: draft.automaticActions,
      });
      setCreatedSnippet(result.snippet.startsWith("http") ? result.snippet : `<script src="${apiBase.replace(/\/$/, "")}/api/integrations/browser.js?site_id=${result.site.site_id}"></script>`);
      setMessagingSetup(result.messaging_setup || []);
      setMessage("Setup is complete.");
      if (result.session) onSession({ apiBase: apiBase.replace(/\/$/, ""), token: result.session.token, user: result.session.user });
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not finish setup.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="wizard-shell">
      <div className="wizard-progress">
        {steps.map((label, index) => (
          <span key={label} className={index === step ? "active" : index < step ? "done" : ""}>
            {index + 1}. {label}
          </span>
        ))}
      </div>

      {step === 0 ? (
        <WizardCard eyebrow="Step 1 of 5" title="Which website should SecAi protect?">
          <label>
            Website name
            <input value={draft.websiteName} onChange={(event) => patch({ websiteName: event.target.value })} placeholder="My online shop" autoFocus />
          </label>
          <p className="helper-text">Use a name you'll recognize later. Your visitors won't see this.</p>
          <details className="advanced-box">
            <summary>Advanced: custom SecAi server</summary>
            <label style={{ marginTop: 12 }}>
              Server URL
              <input type="url" value={apiBase} onChange={(event) => onApiBase(event.target.value)} />
            </label>
          </details>
        </WizardCard>
      ) : null}

      {step === 1 ? (
        <WizardCard eyebrow="Step 2 of 5" title="How should SecAi watch your site?">
          <div className="choice-cards">
            <ChoiceCard
              icon={<Clipboard size={24} />}
              title="Paste a script"
              text="Works with any website. Watches for suspicious form behavior, browser errors, and repeated fast actions."
              selected={draft.watchMethod === "browser"}
              onClick={() => patch({ watchMethod: "browser" })}
            />
            <ChoiceCard
              icon={<ShieldCheck size={24} />}
              title="Alibaba Autopilot"
              text="Cloud-native evidence from Alibaba logs and WAF enforcement for approved actions."
              selected={draft.watchMethod === "alibaba_autopilot"}
              onClick={() => patch({ watchMethod: "alibaba_autopilot" })}
            />
          </div>
          {draft.watchMethod === "alibaba_autopilot" ? (
            <div className="nested-form">
              <div className="callout">
                <ShieldCheck size={18} aria-hidden="true" />
                <p>
                  SecAi uses one scoped RAM role. The template grants Log Service evidence access and SecAi-managed WAF rule access without permanent AccessKeys.
                </p>
              </div>
              <AlibabaConnectorCard
                apiBase={apiBase}
                externalId={draft.slsExternalId}
                region={draft.alibabaRegion}
                roleArn={draft.slsRoleArn}
                wafInstanceId={draft.wafInstanceId}
                slsEndpoint={draft.slsEndpoint}
                slsProject={draft.slsProject}
                slsLogstore={draft.slsLogstore}
                onRegion={(value) => patch({ alibabaRegion: value })}
                onRoleArn={(value) => patch({ slsRoleArn: value })}
              />
              <div className="connector-grid">
                <label>
                  WAF instance ID
                  <input value={draft.wafInstanceId} onChange={(event) => patch({ wafInstanceId: event.target.value })} />
                </label>
                <label>
                  Protected domain
                  <input value={draft.wafDomain} onChange={(event) => patch({ wafDomain: event.target.value })} placeholder="www.example.com" />
                </label>
              </div>
              <details className="advanced-box">
                <summary>Optional: Log Service source</summary>
                <label>
                  SLS endpoint
                  <input value={draft.slsEndpoint} onChange={(event) => patch({ slsEndpoint: event.target.value })} placeholder="ap-southeast-1.log.aliyuncs.com" />
                </label>
                <label>
                  Project name
                  <input value={draft.slsProject} onChange={(event) => patch({ slsProject: event.target.value })} />
                </label>
                <label>
                  Logstore name
                  <input value={draft.slsLogstore} onChange={(event) => patch({ slsLogstore: event.target.value })} />
                </label>
              </details>
            </div>
          ) : null}
        </WizardCard>
      ) : null}

      {step === 2 ? (
        <WizardCard eyebrow="Step 3 of 5" title="Where should reports & approvals go?">
          <div className="choice-cards">
            <ChoiceCard
              icon={<LayoutDashboard size={24} />}
              title="Dashboard"
              text="Private report area inside SecAi. Best for reviewing incidents in one place."
              selected={draft.channels.includes("dashboard")}
              onClick={() => toggleChannel("dashboard")}
            />
            <ChoiceCard
              icon={<MessageCircle size={24} />}
              title="Discord"
              text="Incident reports with approve/reject buttons right in your Discord channel."
              selected={draft.channels.includes("discord")}
              onClick={() => toggleChannel("discord")}
            />
          </div>
          {draft.channels.includes("dashboard") ? (
            <div className="nested-form">
              <label>
                Email
                <input type="email" value={draft.dashboardEmail} onChange={(event) => patch({ dashboardEmail: event.target.value })} placeholder="you@example.com" />
              </label>
              <label>
                Password
                <input type="password" value={draft.dashboardPassword} onChange={(event) => patch({ dashboardPassword: event.target.value })} placeholder="At least 8 characters" />
              </label>
            </div>
          ) : null}
          {draft.channels.includes("discord") ? (
            <ConnectBox
              title="Discord channel"
              text="After setup, SecAi gives you a short code and an invite link. No Discord developer account needed."
              connected={draft.discordConnected}
              onConnect={() => patch({ discordConnected: true })}
            />
          ) : null}
        </WizardCard>
      ) : null}

      {step === 3 ? (
        <WizardCard eyebrow="Step 4 of 5" title="What can SecAi do automatically?">
          <p className="helper-text">Default: SecAi asks first. Select actions you're comfortable letting SecAi run after validation.</p>
          <div className="choice-list">
            {automaticActionChoices.map((action) => (
              <label className="check-row" key={action}>
                <input type="checkbox" checked={draft.automaticActions.includes(action)} onChange={() => toggleAction(action)} />
                <span>{friendlyAction(action)}</span>
              </label>
            ))}
          </div>
        </WizardCard>
      ) : null}

      {step === 4 ? (
        <WizardCard eyebrow="Step 5 of 5" title="Review & finish">
          <div className="review-list">
            <span><strong>Website</strong>{draft.websiteName}</span>
            <span><strong>Monitoring</strong>{watchMethodLabel(draft.watchMethod)}</span>
            <span><strong>Reports via</strong>{draft.channels.map(friendlyAction).join(", ")}</span>
            <span><strong>Auto-actions</strong>{draft.automaticActions.length ? draft.automaticActions.map(friendlyAction).join(", ") : "Ask first for everything"}</span>
          </div>
          {createdSnippet ? (
            <div className="setup-result">
              <strong>Setup complete</strong>
              {draft.watchMethod === "browser" ? (
                <>
                  <p className="helper-text">Paste this script before the closing &lt;/body&gt; tag on your website.</p>
                  <pre>{createdSnippet}</pre>
                </>
              ) : (
                <p className="helper-text">
                  {draft.wafInstanceId
                    ? "Alibaba Autopilot is active. Approved or automatic WAF actions can now be applied."
                    : "Alibaba Autopilot role is connected. Add WAF details from the dashboard to enable enforcement."}
                </p>
              )}
              {draft.channels.includes("discord") ? (
                <div className="callout">
                  <MessageCircle size={18} aria-hidden="true" />
                  <div>
                    <p>Messaging setup is pending. Open the SecAi bot and enter the code below:</p>
                    <div className="setup-codes">
                      {messagingSetup.map((item) => (
                        <span key={item.channel}>
                          <strong>{friendlyAction(item.channel)}</strong>
                          <code>{item.setup_code}</code>
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          ) : null}
          {message ? <p className="status-line">{message}</p> : null}
        </WizardCard>
      ) : null}

      <div className="wizard-actions">
        <button type="button" className="secondary-button" onClick={() => setStep(Math.max(0, step - 1))} disabled={step === 0 || busy}>
          Back
        </button>
        {step < 4 ? (
          <button type="button" onClick={() => setStep(step + 1)} disabled={!canContinue() || busy}>
            Continue
            <ArrowRight size={16} />
          </button>
        ) : (
          <button type="button" onClick={finishSetup} disabled={!canContinue() || busy || Boolean(createdSnippet)}>
            <CheckCircle2 size={16} /> Finish setup
          </button>
        )}
      </div>
    </section>
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

function Dashboard({
  session,
  sites,
  incidents,
  selectedSite,
  selectedSiteId,
  selectedIncident,
  usage,
  siteName,
  autopilotStatus,
  preferences,
  status,
  busy,
  onLogout,
  onRefresh,
  onSiteName,
  onCreateSite,
  onSelectSite,
  onAutopilotStatus,
  onSlsPulled,
  onPreferences,
  onDemo,
  onSelectIncident,
  onDecision,
}: {
  session: Session;
  sites: Site[];
  incidents: Incident[];
  selectedSite: Site | null;
  selectedSiteId: string;
  selectedIncident: Incident | null;
  usage: UsageSummary | null;
  siteName: string;
  autopilotStatus: AutopilotStatus | null;
  preferences: RemediationPreference[];
  status: string;
  busy: boolean;
  onLogout: () => void;
  onRefresh: () => void;
  onSiteName: (value: string) => void;
  onCreateSite: (event: FormEvent<HTMLFormElement>) => void;
  onSelectSite: (siteId: string) => void;
  onAutopilotStatus: (status: AutopilotStatus | null) => void;
  onSlsPulled: () => void;
  onPreferences: (preferences: RemediationPreference[]) => void;
  onDemo: () => void;
  onSelectIncident: (incidentId: number) => void;
  onDecision: (action: "approve" | "reject", incidentId: number) => void;
}) {
  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-block">
          <span className="product-mark">
            <ShieldCheck size={20} aria-hidden="true" />
          </span>
          <div>
            <p className="eyebrow" style={{ marginBottom: 0 }}>Dashboard</p>
            <span style={{ fontWeight: 700, fontSize: "1rem" }}>SecAi</span>
          </div>
        </div>
        <div className="account-bar">
          <span>{session.user.email}</span>
          <button type="button" className="secondary-button" onClick={onRefresh} disabled={busy}>
            <RefreshCw size={15} />
            Refresh
          </button>
          <button type="button" className="secondary-button" onClick={onLogout}>
            <LogOut size={15} />
            Log out
          </button>
        </div>
      </header>

      <main>
        <section className="overview-band">
          <div>
            <p className="eyebrow">Security overview</p>
            <h2>Review incidents, approve actions</h2>
            <p>Only websites connected to this account appear here.</p>
          </div>
          <div className="metrics-grid">
            <Metric icon={<Siren size={16} />} label="Incidents" value={incidents.length.toString()} />
            <Metric icon={<Globe size={16} />} label="Websites" value={sites.length.toString()} />
            <Metric icon={<Search size={16} />} label="Qwen calls" value={usage?.calls.toString() ?? "-"} />
            <Metric icon={<Target size={16} />} label="Tokens used" value={usage?.total_tokens.toString() ?? "-"} />
          </div>
        </section>

        <section className="workbench">
          <aside className="setup-pane">
            <SiteSetup
              siteName={siteName}
              sites={sites}
              selectedSite={selectedSite}
              selectedSiteId={selectedSiteId}
              busy={busy}
              onSiteName={onSiteName}
              onCreateSite={onCreateSite}
              onSelectSite={onSelectSite}
            />
            <SetupChoices
              session={session}
              site={selectedSite}
              autopilotStatus={autopilotStatus}
              busy={busy}
              onAutopilotStatus={onAutopilotStatus}
              onSlsPulled={onSlsPulled}
            />
            <PreferencesPanel session={session} site={selectedSite} preferences={preferences} busy={busy} onPreferences={onPreferences} />
            <button type="button" onClick={onDemo} disabled={busy || !selectedSite} style={{ width: "100%" }}>
              <Play size={16} aria-hidden="true" />
              Simulate attack
            </button>
          </aside>
          <IncidentQueue incidents={incidents} selectedIncidentId={selectedIncident?.id ?? null} onSelect={onSelectIncident} />
          <IncidentReport incident={selectedIncident} status={status} busy={busy} onDecision={onDecision} />
        </section>
      </main>
    </div>
  );
}

// ─── Site Setup Panel ─────────────────────────────────────────────────────────

function SiteSetup({
  siteName,
  sites,
  selectedSite,
  selectedSiteId,
  busy,
  onSiteName,
  onCreateSite,
  onSelectSite,
}: {
  siteName: string;
  sites: Site[];
  selectedSite: Site | null;
  selectedSiteId: string;
  busy: boolean;
  onSiteName: (value: string) => void;
  onCreateSite: (event: FormEvent<HTMLFormElement>) => void;
  onSelectSite: (siteId: string) => void;
}) {
  return (
    <section className="panel-section">
      <div className="section-header">
        <div className="section-title">
          <Globe size={18} />
          <h3>Websites</h3>
        </div>
      </div>
      <form className="mini-form" onSubmit={onCreateSite}>
        <label>
          New website
          <input value={siteName} onChange={(event) => onSiteName(event.target.value)} placeholder="My shop" required />
        </label>
        <button type="submit" disabled={busy}>
          <Plus size={16} /> Add
        </button>
      </form>
      <label>
        Active website
        <select value={selectedSiteId} onChange={(event) => onSelectSite(event.target.value)}>
          {sites.length === 0 ? <option value="">No websites yet</option> : null}
          {sites.map((site) => (
            <option key={site.site_id} value={site.site_id}>
              {site.name}
            </option>
          ))}
        </select>
      </label>
      {selectedSite ? (
        <p className="helper-text">Showing reports for <strong style={{ color: "var(--text-primary)" }}>{selectedSite.name}</strong></p>
      ) : null}
    </section>
  );
}

// ─── Setup Choices ────────────────────────────────────────────────────────────

function SetupChoices({
  session,
  site,
  autopilotStatus,
  busy,
  onAutopilotStatus,
  onSlsPulled,
}: {
  session: Session;
  site: Site | null;
  autopilotStatus: AutopilotStatus | null;
  busy: boolean;
  onAutopilotStatus: (status: AutopilotStatus | null) => void;
  onSlsPulled: () => void;
}) {
  const snippet = site ? `<script src="${session.apiBase}/api/integrations/browser.js?site_id=${site.site_id}"></script>` : "";
  return (
    <section className="panel-section">
      <div className="section-header">
        <div className="section-title">
          <Eye size={18} />
          <h3>Monitoring</h3>
        </div>
      </div>
      <div className="setup-choice">
        <h3>Browser script</h3>
        <p>Paste into your website to watch forms, browser errors, and suspicious activity.</p>
        <pre>{snippet || "Add a website first."}</pre>
        <button type="button" className="secondary-button" disabled={!snippet} onClick={() => navigator.clipboard.writeText(snippet)}>
          <Clipboard size={15} /> Copy script
        </button>
      </div>
      <AlibabaAutopilotSetup
        session={session}
        site={site}
        status={autopilotStatus}
        busy={busy}
        onStatus={onAutopilotStatus}
        onLogsPulled={onSlsPulled}
      />
    </section>
  );
}

// ─── Alibaba Autopilot Setup ──────────────────────────────────────────────────

function AlibabaAutopilotSetup({
  session,
  site,
  status,
  busy,
  onStatus,
  onLogsPulled,
}: {
  session: Session;
  site: Site | null;
  status: AutopilotStatus | null;
  busy: boolean;
  onStatus: (status: AutopilotStatus | null) => void;
  onLogsPulled: () => void;
}) {
  const [roleArn, setRoleArn] = useState("");
  const [externalId, setExternalId] = useState(`secai-${Math.random().toString(36).slice(2, 10)}`);
  const [region, setRegion] = useState("ap-southeast-1");
  const [wafInstanceId, setWafInstanceId] = useState("");
  const [wafDomain, setWafDomain] = useState("");
  const [slsEndpoint, setSlsEndpoint] = useState("");
  const [slsProject, setSlsProject] = useState("");
  const [slsLogstore, setSlsLogstore] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    const config = status?.config;
    setRoleArn(config?.role_arn || "");
    setExternalId(config?.external_id || newExternalId());
    setRegion(config?.region || "ap-southeast-1");
    setWafInstanceId(config?.waf_instance_id || "");
    setWafDomain(config?.waf_domain || "");
    setSlsEndpoint(config?.sls_endpoint || "");
    setSlsProject(config?.sls_project || "");
    setSlsLogstore(config?.sls_logstore || "");
  }, [status?.config]);

  async function handleSave(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!site) return;
    const hasWaf = Boolean(wafInstanceId);
    try {
      const saved = await saveAlibabaAutopilotConfig(session, site.site_id, {
        role_arn: roleArn,
        external_id: externalId.startsWith("****") ? undefined : externalId,
        region,
        enforcement_mode: hasWaf ? "waf_enforced" : "observe_only",
        waf_instance_id: wafInstanceId || undefined,
        waf_domain: wafDomain || undefined,
        sls_endpoint: slsEndpoint || undefined,
        sls_project: slsProject || undefined,
        sls_logstore: slsLogstore || undefined,
      });
      onStatus(saved.status);
      setMessage(hasWaf ? "Alibaba Autopilot is active." : "Alibaba RAM role connected. Add WAF details to enable enforcement.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not connect Alibaba Autopilot.");
    }
  }

  async function checkLogs() {
    if (!site) return;
    try {
      const result = await pullAlibabaSlsLogs(session, site.site_id, "*", 15, 100);
      setMessage(
        `Checked ${result.events_seen} entries — ${result.events_ingested} new, ${result.duplicates_skipped} skipped, ${result.incidents_created} incidents.`,
      );
      onLogsPulled();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not check Autopilot logs.");
    }
  }

  return (
    <div className="setup-choice">
      <div className="section-header compact">
        <div className="section-title">
          <ShieldCheck size={16} />
          <h3>Alibaba Autopilot</h3>
        </div>
        <Pill tone={status?.autopilot_active ? "low" : "medium"}>
          {status?.autopilot_active ? "active" : status?.configured ? "role connected" : "not connected"}
        </Pill>
      </div>
      <div className="status-grid">
        <ReportField label="Role" value={status?.configured ? "connected" : "not connected"} />
        <ReportField label="Logs" value={status?.logs_connected ? "connected" : "not connected"} />
        <ReportField label="WAF" value={status?.waf_connected ? "connected" : "not connected"} />
        <ReportField label="Mode" value={friendlyStatus(status?.enforcement_mode || "observe_only")} />
      </div>
      {status?.last_execution ? (
        <p className="helper-text">
          Last action: <strong style={{ color: "var(--text-primary)" }}>{friendlyAction(status.last_execution.action)}</strong> on {status.last_execution.target || "site"} — {friendlyStatus(status.last_execution.status)}
        </p>
      ) : null}
      {status?.failed_executions?.length ? (
        <p className="status-line danger-text">Last action failed: {status.failed_executions[0].error_message}</p>
      ) : null}
      <form className="stack-form" onSubmit={handleSave}>
        <AlibabaConnectorCard
          apiBase={session.apiBase}
          externalId={externalId}
          region={region}
          roleArn={roleArn}
          wafInstanceId={wafInstanceId}
          slsEndpoint={slsEndpoint}
          slsProject={slsProject}
          slsLogstore={slsLogstore}
          disabled={!site}
          onRegion={setRegion}
          onRoleArn={setRoleArn}
        />
        <div className="connector-grid">
          <label>
            WAF instance ID
            <input value={wafInstanceId} onChange={(event) => setWafInstanceId(event.target.value)} disabled={!site} />
          </label>
          <label>
            Protected domain
            <input value={wafDomain} onChange={(event) => setWafDomain(event.target.value)} disabled={!site} placeholder="www.example.com" />
          </label>
        </div>
        <details className="advanced-box">
          <summary>Optional log source</summary>
          <label>
            SLS endpoint
            <input value={slsEndpoint} onChange={(event) => setSlsEndpoint(event.target.value)} disabled={!site} />
          </label>
          <label>
            Project
            <input value={slsProject} onChange={(event) => setSlsProject(event.target.value)} disabled={!site} />
          </label>
          <label>
            Logstore
            <input value={slsLogstore} onChange={(event) => setSlsLogstore(event.target.value)} disabled={!site} />
          </label>
        </details>
        <button type="submit" disabled={busy || !site || !roleArn || !externalId}>
          <ShieldCheck size={15} /> Connect Autopilot
        </button>
      </form>
      <button type="button" className="secondary-button" onClick={checkLogs} disabled={busy || !site || !status?.logs_connected}>
        <RefreshCw size={15} /> Check Autopilot logs
      </button>
      {message ? <p className="status-line">{message}</p> : null}
    </div>
  );
}

// ─── Preferences Panel ────────────────────────────────────────────────────────

function PreferencesPanel({
  session,
  site,
  preferences,
  busy,
  onPreferences,
}: {
  session: Session;
  site: Site | null;
  preferences: RemediationPreference[];
  busy: boolean;
  onPreferences: (preferences: RemediationPreference[]) => void;
}) {
  async function toggle(action: string, requiresApproval: boolean) {
    if (!site) return;
    const updated = await setRemediationPreference(session, site.site_id, action, requiresApproval);
    onPreferences(preferences.filter((item) => item.action !== action).concat(updated.preference));
  }

  return (
    <section className="panel-section">
      <div className="section-header">
        <div className="section-title">
          <Settings size={18} />
          <h3>Automatic actions</h3>
        </div>
      </div>
      <p className="helper-text">Default: ask first. Toggle to automate.</p>
      {remediationActions.map((action) => {
        const requiresApproval = preferences.find((item) => item.action === action)?.requires_approval ?? true;
        return (
          <label className="toggle-row" key={action}>
            <span>{friendlyAction(action)}</span>
            <select
              value={requiresApproval ? "approval" : "automatic"}
              onChange={(event) => toggle(action, event.target.value === "approval")}
              disabled={busy || !site}
            >
              <option value="approval">Ask first</option>
              <option value="automatic">Automatic</option>
            </select>
          </label>
        );
      })}
    </section>
  );
}

// ─── Incident Queue ───────────────────────────────────────────────────────────

function IncidentQueue({ incidents, selectedIncidentId, onSelect }: { incidents: Incident[]; selectedIncidentId: number | null; onSelect: (incidentId: number) => void }) {
  return (
    <section className="queue-pane">
      <div className="section-header" style={{ padding: "16px 20px", borderBottom: "1px solid var(--border)" }}>
        <div className="section-title">
          <Siren size={18} />
          <h3>Incidents</h3>
        </div>
        <span className="counter">{incidents.length}</span>
      </div>
      <div className="incident-list">
        {incidents.length === 0 ? (
          <div className="empty-state">
            <ShieldCheck size={32} style={{ color: "var(--text-muted)", marginBottom: 12 }} />
            <p>No reports for this website yet.</p>
            <p style={{ fontSize: "0.8rem", marginTop: 4 }}>Try the &quot;Simulate attack&quot; button to see how it works.</p>
          </div>
        ) : (
          incidents.map((incident) => (
            <button type="button" key={incident.id} className={`incident-row ${incident.id === selectedIncidentId ? "active" : ""}`} onClick={() => onSelect(incident.id)}>
              <strong>{incident.title}</strong>
              <span>{incident.attack_type} — {incident.affected_route || "unknown route"}</span>
              <span className="meta-row">
                <Pill tone={incident.severity}>{incident.severity}</Pill>
                <Pill>{friendlyStatus(incident.status)}</Pill>
              </span>
            </button>
          ))
        )}
      </div>
    </section>
  );
}

// ─── Incident Report ──────────────────────────────────────────────────────────

function IncidentReport({ incident, status, busy, onDecision }: { incident: Incident | null; status: string; busy: boolean; onDecision: (action: "approve" | "reject", incidentId: number) => void }) {
  const action = incident?.recommended_action || {};
  const appSpecificNextSteps = Array.isArray(action.app_specific_next_steps) ? action.app_specific_next_steps.map(String) : [];
  const canApprove = incident?.status === "needs_review";
  const canReject = Boolean(incident && incident.status !== "rejected");
  const rejectLabel = incident?.status === "approved" || incident?.status === "auto_approved" ? "Remove rule" : "Reject";
  return (
    <section className="report-pane">
      <div className="section-header" style={{ padding: "16px 20px", borderBottom: "1px solid var(--border)" }}>
        <div className="section-title">
          <AlertTriangle size={18} />
          <h3>Incident detail</h3>
        </div>
        {incident ? <Pill tone={incident.severity}>{friendlyStatus(incident.status)}</Pill> : <span className="counter">{status}</span>}
      </div>
      {incident ? (
        <div className="report-body">
          <div className="report-grid">
            <ReportField label="Severity" value={incident.severity} />
            <ReportField label="Attack type" value={incident.attack_type} />
            <ReportField label="Route" value={incident.affected_route || "unknown"} />
          </div>
          <div className="report-section">
            <div className="section-title">
              <Siren size={18} aria-hidden="true" />
              <h3>What happened</h3>
            </div>
            <p>{incident.report}</p>
          </div>
          <div className="action-summary">
            <ReportField label="Recommended action" value={friendlyAction(String(action.action || "review"))} />
            <ReportField label="Target" value={String(action.target || "this website")} />
            <ReportField label="Reason" value={String(action.reason || "Review recommended.")} />
            <ReportField label="Approval" value={action.requires_approval === false ? "Automatic" : "Requires approval"} />
          </div>
          {appSpecificNextSteps.length ? (
            <div className="report-section">
              <div className="section-title">
                <ShieldCheck size={18} aria-hidden="true" />
                <h3>Next steps</h3>
              </div>
              <ul className="next-step-list">
                {appSpecificNextSteps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ul>
            </div>
          ) : null}
          <div className="decision-row">
            <button type="button" onClick={() => onDecision("approve", incident.id)} disabled={busy || !canApprove} style={{ flex: 1 }}>
              <CheckCircle2 size={16} aria-hidden="true" />
              Approve
            </button>
            <button type="button" className="danger-button" onClick={() => onDecision("reject", incident.id)} disabled={busy || !canReject} style={{ flex: 1 }}>
              <XCircle size={16} aria-hidden="true" />
              {rejectLabel}
            </button>
          </div>
          <details>
            <summary>Technical details</summary>
            <pre style={{ marginTop: 8 }}>{JSON.stringify(incident.recommended_action, null, 2)}</pre>
          </details>
        </div>
      ) : (
        <div className="empty-state">
          <Search size={32} style={{ color: "var(--text-muted)", marginBottom: 12 }} />
          <p>Select an incident from the list to review it.</p>
        </div>
      )}
    </section>
  );
}

// ─── Reusable Sub-Components ──────────────────────────────────────────────────

function AlibabaConnectorCard({
  apiBase,
  externalId,
  region,
  roleArn,
  wafInstanceId,
  slsEndpoint,
  slsProject,
  slsLogstore,
  disabled = false,
  onRegion,
  onRoleArn,
}: {
  apiBase: string;
  externalId: string;
  region: string;
  roleArn: string;
  wafInstanceId: string;
  slsEndpoint: string;
  slsProject: string;
  slsLogstore: string;
  disabled?: boolean;
  onRegion: (value: string) => void;
  onRoleArn: (value: string) => void;
}) {
  const [template, setTemplate] = useState<AlibabaAutopilotTemplate | null>(null);
  const [templateMessage, setTemplateMessage] = useState("");
  const canCreateTemplate = Boolean(externalId && !externalId.startsWith("****"));

  useEffect(() => {
    let cancelled = false;
    if (!canCreateTemplate) {
      setTemplate(null);
      setTemplateMessage("");
      return () => {
        cancelled = true;
      };
    }
    getAlibabaAutopilotTemplate(
      apiBase.replace(/\/$/, ""),
      externalId,
      region,
      "secai-autopilot",
      wafInstanceId,
      slsEndpoint,
      slsProject,
      slsLogstore,
    )
      .then((result) => {
        if (!cancelled) {
          setTemplate(result);
          setTemplateMessage(
            result.principal_configured
              ? "Quick create is ready. Review the RAM role stack in Alibaba Cloud, create it, then paste the RoleArn output below."
              : "SecAi deployment is missing SECAI_ALIBABA_ACCOUNT_ID or SECAI_ALIBABA_PRINCIPAL_ARN.",
          );
        }
      })
      .catch((error) => {
        if (!cancelled) setTemplateMessage(error instanceof Error ? error.message : "Could not build Alibaba connector template.");
      });
    return () => {
      cancelled = true;
    };
  }, [apiBase, canCreateTemplate, externalId, region, wafInstanceId, slsEndpoint, slsProject, slsLogstore]);

  function copyValue(value: string) {
    if (!value) return;
    if (navigator.clipboard?.writeText) void navigator.clipboard.writeText(value);
  }

  function downloadTemplate() {
    if (!template) return;
    const blob = new Blob([JSON.stringify(template.template, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${template.role_name}-ros-template.json`;
    link.click();
    URL.revokeObjectURL(url);
    setTemplateMessage("Template downloaded. In Alibaba Cloud ROS, create a stack from the downloaded file. After creation finishes, copy the RoleArn output into SecAi.");
  }

  return (
    <div className="connector-template">
      <div className="connector-template-header">
        <div>
          <h3>Alibaba RAM connector</h3>
          <p>Generated for this SecAi site.</p>
        </div>
        <div className="template-action-row">
          <a
            className={`button-link ${!template ? "disabled-link" : ""}`}
            href={template?.quick_create_url || template?.console_url || undefined}
            target="_blank"
            rel="noreferrer"
            aria-disabled={!template}
            tabIndex={!template ? -1 : undefined}
            onClick={(event) => {
              if (!template) event.preventDefault();
            }}
          >
            <ExternalLink size={15} /> Open ROS quick create
          </a>
          <button type="button" className="secondary-button" onClick={downloadTemplate} disabled={disabled || !template}>
            <Download size={15} /> Download JSON
          </button>
        </div>
      </div>
      {template ? (
        <ol className="template-next-steps">
          <li>Alibaba Cloud opens with the SecAi template selected.</li>
          <li>Create the stack in region {template.region}.</li>
          <li>Paste the RoleArn output here.</li>
        </ol>
      ) : null}
      <div className="connector-grid">
        <label>
          Region
          <input value={region} onChange={(event) => onRegion(event.target.value)} disabled={disabled} />
        </label>
        <label>
          External ID
          <span className="input-action">
            <input value={externalId} readOnly disabled={disabled} />
            <button type="button" className="icon-button" onClick={() => copyValue(externalId)} disabled={disabled || !externalId} aria-label="Copy External ID">
              <Clipboard size={15} />
            </button>
          </span>
        </label>
      </div>
      <label>
        RAM role ARN
        <span className="input-action">
          <input value={roleArn} onChange={(event) => onRoleArn(event.target.value)} disabled={disabled} placeholder={template?.role_arn_hint || "acs:ram::<your-alibaba-account-id>:role/secai-autopilot"} />
          <button type="button" className="icon-button" onClick={() => copyValue(template?.role_arn_hint || "")} disabled={disabled || !template} aria-label="Copy role ARN format">
            <Clipboard size={15} />
          </button>
        </span>
      </label>
      {templateMessage ? <p className={`status-line ${templateMessage.includes("missing") ? "danger-text" : ""}`}>{templateMessage}</p> : null}
    </div>
  );
}

function WizardCard({ eyebrow, title, children }: { eyebrow: string; title: string; children: ReactNode }) {
  return (
    <div className="wizard-card">
      <p className="eyebrow">{eyebrow}</p>
      <h2>{title}</h2>
      {children}
    </div>
  );
}

function ChoiceCard({
  icon,
  title,
  text,
  selected,
  onClick,
}: {
  icon: ReactNode;
  title: string;
  text: string;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" className={`choice-card ${selected ? "selected" : ""}`} onClick={onClick}>
      {icon}
      <strong>{title}</strong>
      <span>{text}</span>
    </button>
  );
}

function ConnectBox({ title, text, connected, onConnect }: { title: string; text: string; connected: boolean; onConnect: () => void }) {
  return (
    <div className="connect-box">
      <div>
        <h3>{title}</h3>
        <p>{text}</p>
      </div>
      <button type="button" className={connected ? "secondary-button" : "ghost-button"} onClick={onConnect}>
        {connected ? <><CheckCircle2 size={15} /> Ready</> : "Set up after finish"}
      </button>
    </div>
  );
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="metric">
      <div style={{ display: "flex", alignItems: "center", gap: 6, color: "var(--accent)" }}>
        {icon}
        <span>{label}</span>
      </div>
      <strong>{value}</strong>
    </div>
  );
}

function ReportField({ label, value }: { label: string; value: string }) {
  return (
    <div className="report-field">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Pill({ children, tone }: { children: string; tone?: string }) {
  return <span className={`pill ${tone ? `tone-${tone}` : ""}`}>{children}</span>;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function friendlyAction(action: string) {
  return action
    .replaceAll("_", " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function friendlyStatus(status: string) {
  const labels: Record<string, string> = {
    needs_review: "Needs review",
    auto_approved: "Auto-approved",
    approved: "Approved",
    rejected: "Rejected",
    observe_only: "Observe only",
    waf_enforced: "WAF enforced",
  };
  return labels[status] || status.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function watchMethodLabel(method: SetupDraft["watchMethod"]) {
  if (method === "browser") return "Browser script";
  return "Alibaba Autopilot";
}

export default App;
