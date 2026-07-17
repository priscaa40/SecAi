import {
  ArrowRight,
  BellRing,
  Clipboard,
  CloudCog,
  Globe2,
  Home,
  LogOut,
  MessageCircle,
  Plus,
  RefreshCw,
  ShieldCheck,
  Wifi,
} from "lucide-react";
import { type FormEvent, useState } from "react";

import { createDiscordSetup } from "../api";
import type { AnalysisJob, AutopilotStatus, DiscordSetup, Incident, Session, Site } from "../types";
import { AlibabaAutopilotSetup } from "./AlibabaPanels";
import { IncidentQueue, IncidentReport } from "./IncidentPanels";
import { Brand } from "./PublicPages";

type DashboardView = "overview" | "incidents" | "protection";

export function Dashboard({
  session, sites, incidents, analysisJobs, selectedSite, selectedSiteId, selectedIncident, siteName, autopilotStatus, status, busy,
  onLogout, onRefresh, onSiteName, onCreateSite, onSelectSite, onAutopilotStatus, onSlsPulled, onSelectIncident, onDecision, onProtection, onRetryAnalysisJob,
}: {
  session: Session; sites: Site[]; incidents: Incident[]; analysisJobs: AnalysisJob[]; selectedSite: Site | null; selectedSiteId: string; selectedIncident: Incident | null;
  siteName: string; autopilotStatus: AutopilotStatus | null;
  status: string; busy: boolean; onLogout: () => void; onRefresh: () => void; onSiteName: (value: string) => void;
  onCreateSite: (event: FormEvent<HTMLFormElement>) => void; onSelectSite: (siteId: string) => void;
  onAutopilotStatus: (status: AutopilotStatus | null) => void; onSlsPulled: () => void;
  onSelectIncident: (incidentId: number) => void;
  onDecision: (action: "approve" | "reject", incidentId: number) => void;
  onProtection: (action: "retry" | "remove", incidentId: number) => void;
  onRetryAnalysisJob: (jobId: number) => void;
}) {
  const [activeView, setActiveView] = useState<DashboardView>("overview");
  const attentionCount = incidents.filter((incident) => incident.status === "needs_review").length;

  function openIncident(incidentId: number) {
    onSelectIncident(incidentId);
    setActiveView("incidents");
  }

  const viewCopy: Record<DashboardView, { eyebrow: string; title: string; description: string }> = {
    overview: { eyebrow: "Overview", title: selectedSite?.name || "No website connected", description: "Reports and connection status for this website." },
    incidents: { eyebrow: "Incidents", title: "Security reports", description: "Review what happened and decide whether SecAi should act." },
    protection: { eyebrow: "Protection", title: "Evidence and protection", description: "Connect website activity and see whether approved protection is available." },
  };

  return (
    <div className="dashboard-shell">
      <aside className="dashboard-sidebar">
        <Brand />
        <div className="site-switcher">
          <label htmlFor="sidebar-site">Protecting</label>
          <select id="sidebar-site" value={selectedSiteId} onChange={(event) => onSelectSite(event.target.value)} disabled={busy}>
            {sites.length === 0 ? <option value="">No website connected</option> : null}
            {sites.map((site) => <option key={site.site_id} value={site.site_id}>{site.name}</option>)}
          </select>
        </div>
        <nav className="dashboard-nav" aria-label="Dashboard">
          <button type="button" aria-current={activeView === "overview" ? "page" : undefined} className={activeView === "overview" ? "active" : ""} onClick={() => setActiveView("overview")}><Home size={18} aria-hidden="true" /> Overview</button>
          <button type="button" aria-current={activeView === "incidents" ? "page" : undefined} className={activeView === "incidents" ? "active" : ""} onClick={() => setActiveView("incidents")}><BellRing size={18} aria-hidden="true" /> Incidents {attentionCount ? <span>{attentionCount}</span> : null}</button>
          <button type="button" aria-current={activeView === "protection" ? "page" : undefined} className={activeView === "protection" ? "active" : ""} onClick={() => setActiveView("protection")}><ShieldCheck size={18} aria-hidden="true" /> Protection</button>
        </nav>
        <div className="sidebar-account"><span className="account-avatar">{session.user.email.slice(0, 1).toUpperCase()}</span><span><strong>{session.user.email}</strong><small>Website owner</small></span><button type="button" onClick={onLogout} aria-label="Log out"><LogOut size={17} /></button></div>
      </aside>

      <main className="dashboard-main">
        <header className="dashboard-header">
          <div><p className="eyebrow">{viewCopy[activeView].eyebrow}</p><h1>{viewCopy[activeView].title}</h1><p>{viewCopy[activeView].description}</p></div>
          <button type="button" className="secondary-button refresh-button" onClick={onRefresh} disabled={busy}><RefreshCw size={16} className={busy ? "spin" : ""} /> {busy ? "Checking…" : "Check for updates"}</button>
        </header>
        {status !== "Your reports are up to date." && !busy ? <div className="workspace-message" role="status" aria-live="polite">{status}</div> : null}

        {activeView === "overview" ? (
          <OverviewPage incidents={incidents} analysisJobs={analysisJobs} autopilotStatus={autopilotStatus} onOpenIncidents={() => setActiveView("incidents")} onOpenProtection={() => setActiveView("protection")} onOpenIncident={openIncident} />
        ) : null}

        {activeView === "incidents" ? (
          <section className="incident-workspace">
            <IncidentQueue incidents={incidents} analysisJobs={analysisJobs} selectedIncidentId={selectedIncident?.id ?? null} onSelect={onSelectIncident} onRetry={onRetryAnalysisJob} busy={busy} />
            <IncidentReport incident={selectedIncident} status={status} busy={busy} onDecision={onDecision} onProtection={onProtection} />
          </section>
        ) : null}

        {activeView === "protection" ? (
          <section className="protection-page">
            <SiteSetup siteName={siteName} sites={sites} selectedSite={selectedSite} selectedSiteId={selectedSiteId} busy={busy} onSiteName={onSiteName} onCreateSite={onCreateSite} onSelectSite={onSelectSite} />
            <SetupChoices session={session} site={selectedSite} autopilotStatus={autopilotStatus} busy={busy} onAutopilotStatus={onAutopilotStatus} onSlsPulled={onSlsPulled} />
          </section>
        ) : null}
      </main>
    </div>
  );
}

function OverviewPage({ incidents, analysisJobs, autopilotStatus, onOpenIncidents, onOpenProtection, onOpenIncident }: {
  incidents: Incident[]; analysisJobs: AnalysisJob[]; autopilotStatus: AutopilotStatus | null;
  onOpenIncidents: () => void; onOpenProtection: () => void; onOpenIncident: (id: number) => void;
}) {
  const cloudConnected = Boolean(autopilotStatus?.logs_connected);
  const attention = incidents.filter((incident) => incident.status === "needs_review");
  const activeInvestigations = analysisJobs.filter((job) => ["queued", "running"].includes(job.status));
  const failedInvestigations = analysisJobs.filter((job) => job.status === "failed");
  const overviewTitle = attention.length
    ? `${attention.length} ${attention.length === 1 ? "report needs" : "reports need"} a decision`
    : failedInvestigations.length
      ? `${failedInvestigations.length} ${failedInvestigations.length === 1 ? "investigation needs" : "investigations need"} attention`
      : activeInvestigations.length
        ? `${activeInvestigations.length} ${activeInvestigations.length === 1 ? "investigation is" : "investigations are"} in progress`
        : "All good!";
  const overviewDescription = attention.length
    ? "Review the evidence before SecAi changes anything."
    : failedInvestigations.length
      ? "Open security reports to see which investigation could not finish."
      : activeInvestigations.length
        ? "SecAi is checking recent activity. Finished reports will appear here."
        : "New reports will appear here when SecAi finds any suspicious activity.";
  const hasActivity = Boolean(attention.length || failedInvestigations.length || activeInvestigations.length);

  return (
    <div className="overview-page">
      <section className={`overview-status ${attention.length || failedInvestigations.length ? "needs-attention" : "all-clear"}`}>
        <div><h2>{overviewTitle}</h2><p>{overviewDescription}</p></div>
        <button type="button" className={hasActivity ? "" : "secondary-button"} onClick={hasActivity ? onOpenIncidents : onOpenProtection}>{hasActivity ? "View activity" : "Check connections"}<ArrowRight size={16} /></button>
      </section>

      <section className="overview-facts">
        <span><strong>{attention.length}</strong><small>Waiting for you</small></span>
        <span><strong>{activeInvestigations.length}</strong><small>Being investigated</small></span>
        <span><strong>{cloudConnected ? "Alibaba Cloud" : "Website script"}</strong><small>Evidence source</small></span>
      </section>

      <div className="overview-columns">
        <section className="overview-section recent-card">
          <div className="card-header"><div><h2>Recent reports</h2></div><button type="button" className="link-button" onClick={onOpenIncidents}>View all <ArrowRight size={15} /></button></div>
          {incidents.length ? <div className="recent-list">{incidents.slice(0, 5).map((incident) => <button type="button" key={incident.id} onClick={() => onOpenIncident(incident.id)}><span className={`risk-dot risk-${incident.severity}`} /><span><strong>{incident.title}</strong><small>{incident.status === "needs_review" ? "Decision required" : incident.status === "reported" ? "Report ready" : "Decision recorded"}</small></span><span className={`risk-label risk-text-${incident.severity}`}>{incident.severity}</span><ArrowRight size={16} /></button>)}</div> : <div className="empty-state compact-empty"><h3>No reports yet</h3><p>SecAi has not found anything that needs a report.</p></div>}
        </section>

        <section className="overview-section connection-summary">
          <h2>Monitoring method</h2>
          <strong>{cloudConnected ? "Alibaba Cloud activity" : "Website monitoring script"}</strong>
          <p>{cloudConnected ? "SecAi can investigate trusted website activity and carry out a temporary protective change after you approve it." : "The script works on any website and reports suspicious browser activity. It cannot see requests that bypass the browser, so attackers can avoid it."}</p>
          <button type="button" className="secondary-button" onClick={onOpenProtection}>{cloudConnected ? "Manage connection" : "Compare connection options"}<ArrowRight size={15} /></button>
        </section>
      </div>
    </div>
  );
}

function SiteSetup({ siteName, sites, selectedSite, selectedSiteId, busy, onSiteName, onCreateSite, onSelectSite }: {
  siteName: string; sites: Site[]; selectedSite: Site | null; selectedSiteId: string; busy: boolean;
  onSiteName: (value: string) => void; onCreateSite: (event: FormEvent<HTMLFormElement>) => void; onSelectSite: (siteId: string) => void;
}) {
  return (
    <section className="panel-section site-management">
      <div className="section-header"><div className="section-title"><Globe2 size={20} /><div><p className="eyebrow">Website</p><h2>{selectedSite?.name || "Connect your first website"}</h2></div></div></div>
      <p>{selectedSite ? "These settings apply only to this website. Choose another website at any time." : "Add a name first. SecAi will then help you connect website activity."}</p>
      {sites.length > 1 ? <label>Website to manage<select value={selectedSiteId} onChange={(event) => onSelectSite(event.target.value)} disabled={busy}>{sites.map((site) => <option key={site.site_id} value={site.site_id}>{site.name}</option>)}</select></label> : null}
      <details className="add-site-details" open={!selectedSite}><summary><Plus size={16} /> Add another website</summary><form className="mini-form" onSubmit={onCreateSite}><label>Website name<input value={siteName} onChange={(event) => onSiteName(event.target.value)} placeholder="For example, Northstar Shop" required /></label><button type="submit" disabled={busy}><Plus size={16} /> Add website</button></form></details>
    </section>
  );
}

function SetupChoices({ session, site, autopilotStatus, busy, onAutopilotStatus, onSlsPulled }: {
  session: Session; site: Site | null; autopilotStatus: AutopilotStatus | null; busy: boolean;
  onAutopilotStatus: (status: AutopilotStatus | null) => void; onSlsPulled: () => void;
}) {
  const snippet = site ? `<script src="${session.apiBase}/api/integrations/browser.js?site_id=${site.site_id}"></script>` : "";
  const [copied, setCopied] = useState(false);
  const [discordBusy, setDiscordBusy] = useState(false);
  const [discordSetup, setDiscordSetup] = useState<DiscordSetup | null>(null);
  const [discordMessage, setDiscordMessage] = useState("");

  function copySnippet() {
    if (!snippet) return;
    void navigator.clipboard.writeText(snippet);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  }

  async function prepareDiscord() {
    if (!site) return;
    setDiscordBusy(true);
    setDiscordMessage("");
    try {
      setDiscordSetup(await createDiscordSetup(session, site.site_id));
    } catch (error) {
      setDiscordMessage(error instanceof Error ? error.message : "Discord setup could not be created.");
    } finally {
      setDiscordBusy(false);
    }
  }

  return (
    <section className="panel-section connection-panel">
      <div className="section-header"><div className="section-title"><Wifi size={20} /><div><p className="eyebrow">Monitoring method</p><h2>Choose how SecAi watches your website</h2></div></div></div>
      <p>There are two ways to connect a website. Alibaba Cloud is recommended but only available for websites hosted there. The monitoring script works anywhere, with the limitations explained below.</p>
      <div className="connection-choice recommended-connection"><span className="connection-icon"><CloudCog size={21} /></span><div><strong>Connect Alibaba Cloud</strong><p>SecAi can see requests reaching your website, giving it more complete and reliable evidence. It can also carry out a temporary protective change after you approve it.</p><small>For websites hosted on Alibaba Cloud. You approve a temporary role in the website owner&apos;s account; SecAi never asks for permanent AccessKeys.</small></div><strong className="recommendation-label">Recommended</strong></div>
      <AlibabaAutopilotSetup session={session} site={site} status={autopilotStatus} busy={busy} onStatus={onAutopilotStatus} onLogsPulled={onSlsPulled} />
      <div className="cloud-divider"><Globe2 size={19} /><span><strong>Or add a monitoring script</strong><small>Works with any website</small></span></div>
      <div className="connection-choice browser-connection"><span className="connection-icon"><Globe2 size={21} /></span><div><strong>Add a monitoring script</strong><p>Quick to install and works with any website. It can notice attack-like entries and unusually rapid use of forms that submit back to your website.</p><small>It only sees form activity inside a visitor's browser. Direct requests are invisible, and attackers can bypass it by disabling JavaScript.</small></div></div>
      <details className="install-details"><summary><Clipboard size={16} /> Show monitoring script</summary><p>Paste this before the closing <code>&lt;/body&gt;</code> tag on every page that should be monitored. It skips recognized sensitive fields and sends a field value only when it matches an attack pattern; rapid-submission warnings contain no form values.</p><p>If the website uses a Content Security Policy, allow the SecAi address in both <code>script-src</code> and <code>connect-src</code>.</p><pre>{snippet || "Add a website first to create its installation code."}</pre><button type="button" className="secondary-button" disabled={!snippet} onClick={copySnippet}><Clipboard size={15} /> {copied ? "Copied" : "Copy code"}</button></details>
      <div className="cloud-divider"><MessageCircle size={19} /><span><strong>Discord reports</strong><small>Optional delivery channel</small></span></div>
      <div className="connection-choice discord-connection">
        <span className="connection-icon"><MessageCircle size={21} /></span>
        <div><strong>Connect Discord</strong><p>Receive the same recommendation, protection status, and approval link in a private server channel.</p><small>Creating a new code replaces any unfinished Discord connection for this website.</small></div>
        <button type="button" className="secondary-button" onClick={prepareDiscord} disabled={!site || busy || discordBusy}>{discordBusy ? "Preparing…" : "Create connection"}</button>
      </div>
      {discordSetup ? (
        <div className="callout discord-setup-result">
          <MessageCircle size={18} aria-hidden="true" />
          <div>
            <p><a href={discordSetup.invite_url} target="_blank" rel="noreferrer">Add SecAi to Discord</a>, then select <code>/connect</code> from Discord&apos;s command menu in the private server channel where reports should arrive. Enter this one-time code in the command&apos;s <code>code</code> field:</p>
            <code>{discordSetup.setup_code}</code>
            <small>Sending the command as ordinary message text will not connect it.</small>
          </div>
        </div>
      ) : null}
      {discordMessage ? <p className="status-line danger-text" role="status">{discordMessage}</p> : null}
    </section>
  );
}
