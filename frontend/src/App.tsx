import { type FormEvent, useEffect, useState } from "react";

import {
  getIncident,
  login,
  logout,
  me,
  pullAlibabaSlsLogs,
  signup,
} from "./api";
import "./App.css";
import { Dashboard } from "./components/Dashboard";
import { LoginPage, PublicHome, SetupPage } from "./components/PublicPages";
import { useWorkspace } from "./hooks/useWorkspace";
import type { Session } from "./types";

const runtimeConfig = window.__SECAI_CONFIG__ || {};
const configuredApiBase = runtimeConfig.apiBase || window.location.origin;
const storedToken = sessionStorage.getItem("secai.token") || "";
const requestedIncidentId = incidentIdFromLocation();
const requestedApproval = new URLSearchParams(window.location.search).get("approval");

type PublicView = "home" | "setup" | "login";

function App() {
  const apiBase = configuredApiBase;
  const [session, setSession] = useState<Session | null>(null);
  const [view, setView] = useState<PublicView>(() => requestedIncidentId && !storedToken
    ? "login"
    : viewFromPath(window.location.pathname));
  const [authMode, setAuthMode] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState(localStorage.getItem("secai.email") || "");
  const [password, setPassword] = useState("");
  const workspace = useWorkspace(session);

  useEffect(() => {
    if (storedToken) void restoreSession(configuredApiBase, storedToken);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    function syncRoute() {
      setView(viewFromPath(window.location.pathname));
    }
    window.addEventListener("popstate", syncRoute);
    return () => window.removeEventListener("popstate", syncRoute);
  }, []);

  async function restoreSession(base: string, token: string) {
    workspace.setBusy(true);
    try {
      const result = await me(base, token);
      const restored = { apiBase: base, token, user: result.user };
      setSession(restored);
      await loadSessionWorkspace(restored);
    } catch {
      sessionStorage.removeItem("secai.token");
      setSession(null);
      workspace.clearWorkspace();
    } finally {
      workspace.setBusy(false);
    }
  }

  function saveSession(nextSession: Session) {
    localStorage.setItem("secai.email", nextSession.user.email);
    sessionStorage.setItem("secai.token", nextSession.token);
    setSession(nextSession);
    replaceRoute("/dashboard");
  }

  function navigate(nextView: PublicView) {
    const path = nextView === "home" ? "/" : `/${nextView}`;
    window.history.pushState(null, "", path);
    setView(nextView);
  }

  async function handleAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    workspace.setBusy(true);
    try {
      const normalizedEmail = email.trim().toLowerCase();
      const result = authMode === "login"
        ? await login(apiBase, normalizedEmail, password)
        : await signup(apiBase, normalizedEmail, password);
      const nextSession = { apiBase: apiBase.replace(/\/$/, ""), token: result.token, user: result.user };
      saveSession(nextSession);
      setPassword("");
      await loadSessionWorkspace(nextSession);
    } catch (error) {
      workspace.setStatus(error instanceof Error ? error.message : "We could not sign you in.");
    } finally {
      workspace.setBusy(false);
    }
  }

  async function handleLogout() {
    if (session) await logout(session).catch(() => undefined);
    sessionStorage.removeItem("secai.token");
    setSession(null);
    workspace.clearWorkspace();
    navigate("home");
  }

  async function handleDashboardRefresh() {
    if (!session) return;
    const site = workspace.selectedSite;
    if (site?.evidence_source !== "alibaba_autopilot" || !workspace.autopilotStatus?.logs_connected) {
      await workspace.loadWorkspace(session, site?.site_id);
      return;
    }
    workspace.setBusy(true);
    workspace.setStatus("Checking Alibaba Cloud for recent activity…");
    try {
      const result = await pullAlibabaSlsLogs(session, site.site_id, "*", 15, 100);
      await workspace.loadWorkspace(session, site.site_id);
      workspace.setStatus(result.jobs_queued > 0
        ? `SecAi found suspicious activity and started ${result.jobs_queued} ${result.jobs_queued === 1 ? "investigation" : "investigations"}.`
        : `Checked ${result.events_seen} recent Alibaba Cloud ${result.events_seen === 1 ? "record" : "records"}. No new investigation was needed.`);
    } catch (error) {
      workspace.setStatus(error instanceof Error ? error.message : "SecAi could not check recent Alibaba Cloud activity.");
    } finally {
      workspace.setBusy(false);
    }
  }

  async function loadSessionWorkspace(activeSession: Session) {
    if (!requestedIncidentId) {
      await workspace.loadWorkspace(activeSession);
      return;
    }
    let incident;
    try {
      incident = await getIncident(activeSession, requestedIncidentId);
    } catch {
      await workspace.loadWorkspace(activeSession);
      workspace.setStatus("That report link is no longer available for this account.");
      return;
    }
    await workspace.loadWorkspace(activeSession, incident.site_id);
    workspace.setSelectedIncidentId(incident.id);
    if (requestedApproval === "queued" && incident.status === "approved") {
      workspace.setStatus("Your approval was recorded. The Executor is applying the approved protection.");
    }
    if (requestedApproval === "rejected" && incident.status === "rejected") {
      workspace.setStatus("Your decision was recorded. No action will be taken.");
    }
    if (requestedApproval === "failed") {
      workspace.setStatus("Your approval was recorded, but Alibaba Cloud did not apply the block. Review the report to retry.");
    }
  }

  if (session) {
    return (
      <Dashboard
        session={session}
        sites={workspace.sites}
        incidents={workspace.incidents}
        analysisJobs={workspace.analysisJobs}
        selectedSite={workspace.selectedSite}
        selectedSiteId={workspace.selectedSiteId}
        selectedIncident={workspace.selectedIncident}
        siteName={workspace.siteName}
        siteEvidenceSource={workspace.siteEvidenceSource}
        autopilotStatus={workspace.autopilotStatus}
        status={workspace.status}
        busy={workspace.busy}
        onLogout={handleLogout}
        onRefresh={handleDashboardRefresh}
        onSiteName={workspace.setSiteName}
        onSiteEvidenceSource={workspace.setSiteEvidenceSource}
        onCreateSite={workspace.handleCreateSite}
        onSelectSite={workspace.handleSiteChange}
        onAutopilotStatus={workspace.setAutopilotStatus}
        onSlsPulled={() => workspace.loadWorkspace(session)}
        onSelectIncident={workspace.setSelectedIncidentId}
        onDecision={workspace.handleDecision}
        onProtection={workspace.handleProtection}
      />
    );
  }

  if (view === "setup") {
    return <SetupPage apiBase={apiBase} onBack={() => navigate("home")} onSession={(nextSession) => { saveSession(nextSession); void workspace.loadWorkspace(nextSession); }} />;
  }

  if (view === "login") {
    return (
      <LoginPage
        email={email}
        password={password}
        mode={authMode}
        status={workspace.status}
        busy={workspace.busy}
        onEmail={setEmail}
        onPassword={setPassword}
        onMode={setAuthMode}
        onSubmit={handleAuth}
        onBack={() => navigate("home")}
      />
    );
  }

  return <PublicHome onStartSetup={() => navigate("setup")} onShowLogin={() => navigate("login")} />;
}

function viewFromPath(pathname: string): PublicView {
  if (pathname === "/setup") return "setup";
  if (pathname === "/login") return "login";
  return "home";
}

function replaceRoute(path: string) {
  window.history.replaceState(null, "", path);
}

function incidentIdFromLocation() {
  const value = new URLSearchParams(window.location.search).get("incident");
  if (!value || !/^\d+$/.test(value)) return null;
  const incidentId = Number(value);
  return Number.isSafeInteger(incidentId) && incidentId > 0 ? incidentId : null;
}

export default App;
