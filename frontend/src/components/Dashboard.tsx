import {
  ArrowRight,
  BellRing,
  Clipboard,
  Globe2,
  Home,
  LogOut,
  MessageCircle,
  Plus,
  RefreshCw,
  ShieldCheck,
  Wifi,
  X,
} from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";

import { createDiscordSetup } from "../api";
import type { AnalysisJob, AutopilotStatus, DiscordSetup, Incident, Session, Site } from "../types";
import { AlibabaAutopilotSetup } from "./AlibabaPanels";
import { IncidentQueue, IncidentReport } from "./IncidentPanels";
import { InvestigationProgress } from "./InvestigationProgress";
import { Brand } from "./PublicPages";

type DashboardView = "overview" | "incidents" | "protection";

export function Dashboard({
  session, sites, incidents, analysisJobs, selectedSite, selectedSiteId, selectedIncident, siteName, siteEvidenceSource, autopilotStatus, status, busy,
  onLogout, onRefresh, onSiteName, onSiteEvidenceSource, onCreateSite, onSelectSite, onAutopilotStatus, onSlsPulled, onSelectIncident, onDecision, onProtection, onRetryAnalysisJob,
}: {
  session: Session; sites: Site[]; incidents: Incident[]; analysisJobs: AnalysisJob[]; selectedSite: Site | null; selectedSiteId: string; selectedIncident: Incident | null;
  siteName: string; siteEvidenceSource: Site["evidence_source"]; autopilotStatus: AutopilotStatus | null;
  status: string; busy: boolean; onLogout: () => void; onRefresh: () => void; onSiteName: (value: string) => void;
  onSiteEvidenceSource: (value: Site["evidence_source"]) => void;
  onCreateSite: (event: FormEvent<HTMLFormElement>) => Promise<boolean>; onSelectSite: (siteId: string) => void;
  onAutopilotStatus: (status: AutopilotStatus | null) => void; onSlsPulled: () => void;
  onSelectIncident: (incidentId: number) => void;
  onDecision: (action: "approve" | "reject", incidentId: number) => void;
  onProtection: (action: "retry" | "remove" | "reapply", incidentId: number) => void;
  onRetryAnalysisJob: (jobId: number) => void;
}) {
  const [activeView, setActiveView] = useState<DashboardView>("overview");
  const [addSiteOpen, setAddSiteOpen] = useState(false);
  const attentionCount = incidents.filter((incident) => incident.status === "needs_review").length;

  useEffect(() => {
    if (selectedSite?.evidence_source === "alibaba_autopilot" && autopilotStatus && !autopilotStatus.logs_connected) {
      setActiveView("overview");
    }
  }, [selectedSite?.site_id, selectedSite?.evidence_source, autopilotStatus?.logs_connected]);

  async function addSite(event: FormEvent<HTMLFormElement>) {
    if (await onCreateSite(event)) setAddSiteOpen(false);
  }

  function closeAddSite() {
    if (busy) return;
    onSiteName("");
    onSiteEvidenceSource("browser");
    setAddSiteOpen(false);
  }

  function openIncident(incidentId: number) {
    onSelectIncident(incidentId);
    setActiveView("incidents");
  }

  const viewCopy: Record<DashboardView, { eyebrow: string; title: string; description: string }> = {
    overview: { eyebrow: "Overview", title: selectedSite?.name || "No website connected", description: "Reports and connection status for this website." },
    incidents: { eyebrow: "Incidents", title: "Security reports", description: "Review what happened and decide whether SecAi should act." },
    protection: { eyebrow: "Connections", title: "Optional connections", description: "Manage browser monitoring, Discord delivery, and additional websites." },
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
          <button type="button" className="sidebar-add-site" onClick={() => setAddSiteOpen(true)} disabled={busy}><Plus size={15} /> Add another website</button>
        </div>
        <nav className="dashboard-nav" aria-label="Dashboard">
          <button type="button" aria-current={activeView === "overview" ? "page" : undefined} className={activeView === "overview" ? "active" : ""} onClick={() => setActiveView("overview")}><Home size={18} aria-hidden="true" /> Overview</button>
          <button type="button" aria-current={activeView === "incidents" ? "page" : undefined} className={activeView === "incidents" ? "active" : ""} onClick={() => setActiveView("incidents")}><BellRing size={18} aria-hidden="true" /> Incidents {attentionCount ? <span>{attentionCount}</span> : null}</button>
          <button type="button" aria-current={activeView === "protection" ? "page" : undefined} className={activeView === "protection" ? "active" : ""} onClick={() => setActiveView("protection")}><ShieldCheck size={18} aria-hidden="true" /> Connections</button>
        </nav>
        <div className="sidebar-account"><span className="account-avatar">{session.user.email.slice(0, 1).toUpperCase()}</span><span><strong>{session.user.email}</strong><small>Website owner</small></span><button type="button" onClick={onLogout} aria-label="Log out"><LogOut size={17} /></button></div>
      </aside>

      <main className="dashboard-main">
        <header className="dashboard-header">
          <div><p className="eyebrow">{viewCopy[activeView].eyebrow}</p><h1>{viewCopy[activeView].title}</h1><p>{viewCopy[activeView].description}</p></div>
          <button type="button" className="secondary-button refresh-button" onClick={onRefresh} disabled={busy}><RefreshCw size={16} className={busy ? "spin" : ""} /> {busy ? "Checking…" : "Check recent activity"}</button>
        </header>
        {status !== "Your reports are up to date." && !busy ? <div className="workspace-message" role="status" aria-live="polite">{status}</div> : null}

        {activeView === "overview" ? (
          <OverviewPage session={session} site={selectedSite} incidents={incidents} analysisJobs={analysisJobs} autopilotStatus={autopilotStatus} busy={busy} onAutopilotStatus={onAutopilotStatus} onSlsPulled={onSlsPulled} onOpenIncidents={() => setActiveView("incidents")} onOpenProtection={() => setActiveView("protection")} onOpenIncident={openIncident} onRetryInvestigation={onRetryAnalysisJob} />
        ) : null}

        {activeView === "incidents" ? (
          <section className="incident-workspace">
            <IncidentQueue incidents={incidents} analysisJobs={analysisJobs} selectedIncidentId={selectedIncident?.id ?? null} onSelect={onSelectIncident} onRetry={onRetryAnalysisJob} busy={busy} />
            <IncidentReport incident={selectedIncident} status={status} busy={busy} onDecision={onDecision} onProtection={onProtection} />
          </section>
        ) : null}

        {activeView === "protection" ? (
          <section className="protection-page">
            <SetupChoices session={session} site={selectedSite} autopilotStatus={autopilotStatus} busy={busy} onAutopilotStatus={onAutopilotStatus} onSlsPulled={onSlsPulled} />
          </section>
        ) : null}
      </main>

      {addSiteOpen ? (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) closeAddSite(); }} onKeyDown={(event) => { if (event.key === "Escape") closeAddSite(); }}>
          <section className="site-modal" role="dialog" aria-modal="true" aria-labelledby="add-site-title">
            <div className="site-modal-header"><div><p className="eyebrow">New website</p><h2 id="add-site-title">Add a website</h2></div><button type="button" className="ghost-button modal-close" onClick={closeAddSite} disabled={busy} aria-label="Close"><X size={18} /></button></div>
            <p>Create a separate workspace for this website and choose its primary evidence source.</p>
            <form className="site-modal-form" onSubmit={addSite}>
              <label>Website name<input value={siteName} onChange={(event) => onSiteName(event.target.value)} placeholder="For example, Northstar Shop" autoFocus required /></label>
              <label>Evidence source<select value={siteEvidenceSource} onChange={(event) => onSiteEvidenceSource(event.target.value as Site["evidence_source"])}><option value="browser">Website script</option><option value="alibaba_autopilot">Alibaba Cloud</option></select></label>
              <div className="site-modal-actions"><button type="button" className="secondary-button" onClick={closeAddSite} disabled={busy}>Cancel</button><button type="submit" disabled={busy || !siteName.trim()}><Plus size={16} /> {busy ? "Adding…" : "Add website"}</button></div>
            </form>
          </section>
        </div>
      ) : null}
    </div>
  );
}

function OverviewPage({ session, site, incidents, analysisJobs, autopilotStatus, busy, onAutopilotStatus, onSlsPulled, onOpenIncidents, onOpenProtection, onOpenIncident, onRetryInvestigation }: {
  session: Session; site: Site | null; incidents: Incident[]; analysisJobs: AnalysisJob[]; autopilotStatus: AutopilotStatus | null; busy: boolean;
  onAutopilotStatus: (status: AutopilotStatus | null) => void; onSlsPulled: () => void;
  onOpenIncidents: () => void; onOpenProtection: () => void; onOpenIncident: (id: number) => void;
  onRetryInvestigation: (jobId: number) => void;
}) {
  const cloudConnected = Boolean(autopilotStatus?.logs_connected);
  const usesAlibaba = site?.evidence_source === "alibaba_autopilot";
  const openConnection = usesAlibaba && !cloudConnected
    ? () => document.getElementById("alibaba-connection")?.scrollIntoView({ behavior: "smooth", block: "start" })
    : onOpenProtection;
  const attention = incidents.filter((incident) => incident.status === "needs_review");
  const activeInvestigations = analysisJobs.filter((job) => ["queued", "running"].includes(job.status));
  const failedInvestigations = analysisJobs.filter((job) => job.status === "failed");
  const visibleInvestigations = [...activeInvestigations, ...failedInvestigations].slice(0, 3);
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
        <button type="button" className={hasActivity ? "" : "secondary-button"} onClick={hasActivity ? onOpenIncidents : openConnection}>{hasActivity ? "View activity" : usesAlibaba && !cloudConnected ? "Finish Alibaba setup" : "Check connections"}<ArrowRight size={16} /></button>
      </section>

      {usesAlibaba && !cloudConnected ? <AlibabaConnectionPanel id="alibaba-connection" session={session} site={site} status={autopilotStatus} busy={busy} onStatus={onAutopilotStatus} onLogsPulled={onSlsPulled} /> : null}

      <section className="overview-facts">
        <span><strong>{attention.length}</strong><small>Waiting for you</small></span>
        <span><strong>{activeInvestigations.length}</strong><small>Being investigated</small></span>
        <span><strong>{usesAlibaba ? "Alibaba Cloud" : "Website script"}</strong><small>Evidence source</small></span>
      </section>

      {visibleInvestigations.length ? (
        <section className="overview-section live-investigations">
          <div className="card-header"><div><p className="eyebrow">SecAi agents</p><h2>Live investigations</h2></div><button type="button" className="link-button" onClick={onOpenIncidents}>View activity <ArrowRight size={15} /></button></div>
          <div className="overview-investigation-list">
            {visibleInvestigations.map((job) => <InvestigationProgress job={job} busy={busy} onRetry={onRetryInvestigation} key={job.id} />)}
          </div>
        </section>
      ) : null}

      <div className="overview-columns">
        <section className="overview-section recent-card">
          <div className="card-header"><div><h2>Recent reports</h2></div><button type="button" className="link-button" onClick={onOpenIncidents}>View all <ArrowRight size={15} /></button></div>
          {incidents.length ? <div className="recent-list">{incidents.slice(0, 5).map((incident) => <button type="button" key={incident.id} onClick={() => onOpenIncident(incident.id)}><span className={`risk-dot risk-${incident.severity}`} /><span><strong>{incident.title}</strong><small>{incident.status === "needs_review" ? "Decision required" : incident.status === "reported" ? "Report ready" : "Decision recorded"}</small></span><span className={`risk-label risk-text-${incident.severity}`}>{incident.severity}</span><ArrowRight size={16} /></button>)}</div> : <div className="empty-state compact-empty"><h3>No reports yet</h3><p>SecAi has not found anything that needs a report.</p></div>}
        </section>
      </div>
    </div>
  );
}

function AlibabaConnectionPanel({ id, session, site, status, busy, onStatus, onLogsPulled }: {
  id?: string;
  session: Session;
  site: Site | null;
  status: AutopilotStatus | null;
  busy: boolean;
  onStatus: (status: AutopilotStatus | null) => void;
  onLogsPulled: () => void;
}) {
  return (
    <section id={id} className="panel-section overview-connection-panel">
      <div className="section-header"><div className="section-title"><ShieldCheck size={20} /><div><p className="eyebrow">Evidence source</p><h2>Alibaba Cloud connection</h2></div></div></div>
      <p>Connect this website&apos;s Alibaba Cloud activity so SecAi can investigate trusted server evidence. Completed connection details stay read-only until you choose Edit.</p>
      {status ? <AlibabaAutopilotSetup session={session} site={site} status={status} busy={busy} onStatus={onStatus} onLogsPulled={onLogsPulled} /> : <p className="helper-text">Loading Alibaba Cloud connection…</p>}
    </section>
  );
}

function SetupChoices({ session, site, autopilotStatus, busy, onAutopilotStatus, onSlsPulled }: {
  session: Session;
  site: Site | null;
  autopilotStatus: AutopilotStatus | null;
  busy: boolean;
  onAutopilotStatus: (status: AutopilotStatus | null) => void;
  onSlsPulled: () => void;
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

  const usesAlibaba = site?.evidence_source === "alibaba_autopilot";
  const alibabaConnected = Boolean(usesAlibaba && autopilotStatus?.logs_connected);

  return (
    <div className="connection-page-stack">
      {alibabaConnected ? <AlibabaConnectionPanel session={session} site={site} status={autopilotStatus} busy={busy} onStatus={onAutopilotStatus} onLogsPulled={onSlsPulled} /> : null}
      <section className="panel-section connection-panel">
      <div className="section-header"><div className="section-title"><Wifi size={20} /><div><p className="eyebrow">Optional connections</p><h2>{site?.evidence_source === "browser" ? "Browser monitoring and report delivery" : "Report delivery"}</h2></div></div></div>
      <p>{site?.evidence_source === "browser" ? "Install the selected browser monitoring script and optionally connect Discord delivery." : alibabaConnected ? "Manage Alibaba Cloud above and optionally connect Discord delivery." : "Finish Alibaba Cloud setup on Overview. You can still prepare optional Discord delivery here."}</p>
      {site?.evidence_source === "browser" ? (
        <>
          <div className="cloud-divider"><Globe2 size={19} /><span><strong>Add a monitoring script</strong><small>Works with any website</small></span></div>
          <div className="connection-choice browser-connection"><span className="connection-icon"><Globe2 size={21} /></span><div><strong>Add a monitoring script</strong><p>Quick to install and works with any website. It can notice attack-like entries and unusually rapid use of forms that submit back to your website.</p><small>It only sees form activity inside a visitor's browser. Direct requests are invisible, and attackers can bypass it by disabling JavaScript.</small></div></div>
          <details className="install-details"><summary><Clipboard size={16} /> Show monitoring script</summary><p>Paste this before the closing <code>&lt;/body&gt;</code> tag on every page that should be monitored. The generated URL includes this website&apos;s ID. It skips recognized sensitive fields and sends a field value only when it matches an attack pattern; rapid-submission warnings contain no form values.</p><p>If the website uses a Content Security Policy, allow the SecAi address in both <code>script-src</code> and <code>connect-src</code>.</p><pre>{snippet || "Add a website first to create its installation code."}</pre><button type="button" className="secondary-button" disabled={!snippet} onClick={copySnippet}><Clipboard size={15} /> {copied ? "Copied" : "Copy code"}</button></details>
        </>
      ) : null}
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
    </div>
  );
}
