import { Copy, Download, ExternalLink, Pencil, RefreshCw, ShieldCheck, Trash2, X } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";

import {
  disconnectAlibabaConnection,
  discoverAlibabaResourcesForSite,
  prepareAlibabaConnection,
  pullAlibabaSlsLogs,
  saveAlibabaAutopilotConfig,
  verifyAlibabaCollector,
  verifyAlibabaConnection,
} from "../api";
import type { AutopilotStatus, Session, Site } from "../types";
import { AlibabaConnectorCard } from "./AlibabaConnectorCard";

const actionCopy: Record<string, string> = {
  monitor: "Keep watching",
  notify_admin: "Notify my team",
  block_ip: "Temporarily block one suspicious address",
};

function friendlyAction(action: string) {
  return actionCopy[action] || action.replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function friendlyStatus(status: string) {
  const labels: Record<string, string> = { active: "Active", applying: "Applying", failed: "Failed", revoked: "Removed", expired: "Ended" };
  return labels[status] || friendlyAction(status);
}

function ReportField({ label, value }: { label: string; value: string }) {
  return <div className="report-field"><span>{label}</span><strong>{value}</strong></div>;
}

export function AlibabaAutopilotSetup({
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
  const [region, setRegion] = useState("ap-southeast-1");
  const [roleArn, setRoleArn] = useState("");
  const [securityGroupId, setSecurityGroupId] = useState("");
  const [instanceId, setInstanceId] = useState("");
  const [slsEndpoint, setSlsEndpoint] = useState("");
  const [slsProject, setSlsProject] = useState("");
  const [slsLogstore, setSlsLogstore] = useState("");
  const [message, setMessage] = useState("");
  const [editing, setEditing] = useState(false);
  const [operation, setOperation] = useState<"" | "preparing" | "verifying" | "saving" | "collector" | "checking" | "disconnecting">("");
  const currentSiteId = useRef(site?.site_id);
  const operationVersion = useRef(0);
  currentSiteId.current = site?.site_id;

  useEffect(() => {
    operationVersion.current += 1;
    setMessage("");
    setOperation("");
    setEditing(false);
  }, [site?.site_id]);

  useEffect(() => {
    const config = status?.config;
    setRegion(config?.region || "ap-southeast-1");
    setRoleArn(config?.role_arn || "");
    setSecurityGroupId(config?.security_group_id || "");
    setInstanceId(config?.ecs_instance_id || "");
    setSlsEndpoint(config?.sls_endpoint || "");
    setSlsProject(config?.sls_project || "");
    setSlsLogstore(config?.sls_logstore || "");
  }, [status?.config]);

  async function runOperation(
    name: typeof operation,
    work: (siteId: string) => Promise<void>,
    failureMessage: string,
  ) {
    if (!site || operation) return;
    const siteId = site.site_id;
    const version = ++operationVersion.current;
    setOperation(name);
    setMessage("");
    try {
      await work(siteId);
    } catch (error) {
      if (currentSiteId.current === siteId && operationVersion.current === version) {
        setMessage(error instanceof Error ? error.message : failureMessage);
      }
    } finally {
      if (currentSiteId.current === siteId && operationVersion.current === version) setOperation("");
    }
  }

  function startConnection() {
    void runOperation("preparing", async (siteId) => {
      const next = await prepareAlibabaConnection(session, siteId);
      onStatus(next);
      setMessage("Authorization details are ready. Create the role in your Alibaba Cloud account, then verify it below.");
    }, "SecAi could not start the Alibaba Cloud connection.");
  }

  function verifyConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!roleArn.trim()) return;
    void runOperation("verifying", async (siteId) => {
      const next = await verifyAlibabaConnection(session, siteId, roleArn.trim(), region);
      onStatus(next);
      setMessage(`Connected to Alibaba Cloud account ${next.config?.account_id}. Now choose this website's resources.`);
    }, "SecAi could not verify that Alibaba Cloud role.");
  }

  function handleSave(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void runOperation("saving", async (siteId) => {
      const hasSecurityGroup = Boolean(securityGroupId);
      const saved = await saveAlibabaAutopilotConfig(session, siteId, {
        region,
        ecs_instance_id: instanceId,
        enforcement_mode: hasSecurityGroup ? "security_group" : "observe_only",
        security_group_id: securityGroupId || undefined,
        sls_endpoint: slsEndpoint || undefined,
        sls_project: slsProject || undefined,
        sls_logstore: slsLogstore || undefined,
      });
      onStatus(saved.status);
      setEditing(false);
      setMessage(
        saved.status.config?.collector_create_index
          ? "Installation plan ready. The collector stack will add the missing Logstore search index."
          : "Installation plan ready. The collector stack will keep the Logstore's existing search index.",
      );
    }, "SecAi could not save these resources.");
  }

  function checkActivity() {
    void runOperation("checking", async (siteId) => {
      const result = await pullAlibabaSlsLogs(session, siteId, "*", 15, 100);
      const parts = [
        `Checked ${result.events_seen} recent activity ${result.events_seen === 1 ? "record" : "records"}.`,
        `Added ${result.events_ingested} new activity ${result.events_ingested === 1 ? "record" : "records"}.`,
        result.jobs_queued > 0
          ? `Queued ${result.jobs_queued} ${result.jobs_queued === 1 ? "investigation" : "investigations"}.`
          : "No strong or repeated threat pattern was found.",
      ];
      setMessage(parts.join(" "));
      onLogsPulled();
    }, "SecAi could not check recent website activity.");
  }

  function verifyCollector() {
    void runOperation("collector", async (siteId) => {
      const result = await verifyAlibabaCollector(session, siteId);
      onStatus(result.status);
      setMessage("Alibaba Cloud is connected. SecAi confirmed that the collector is running.");
      onLogsPulled();
    }, "SecAi could not verify the Alibaba collector yet.");
  }

  function cancelEdit() {
    const config = status?.config;
    setRegion(config?.region || "ap-southeast-1");
    setSecurityGroupId(config?.security_group_id || "");
    setInstanceId(config?.ecs_instance_id || "");
    setSlsEndpoint(config?.sls_endpoint || "");
    setSlsProject(config?.sls_project || "");
    setSlsLogstore(config?.sls_logstore || "");
    setEditing(false);
    setMessage("");
  }

  function disconnect() {
    if (!window.confirm("Disconnect Alibaba Cloud from this website? SecAi will stop receiving trusted server activity until you reconnect it.")) return;
    void runOperation("disconnecting", async (siteId) => {
      const next = await disconnectAlibabaConnection(session, siteId);
      onStatus(next);
      setEditing(false);
      setRoleArn("");
      setSecurityGroupId("");
      setInstanceId("");
      setSlsEndpoint("");
      setSlsProject("");
      setSlsLogstore("");
      setMessage("Alibaba Cloud is disconnected from this website.");
    }, "SecAi could not disconnect Alibaba Cloud.");
  }

  function downloadTemplate() {
    if (!status?.authorization) return;
    const blob = new Blob([JSON.stringify(status.authorization.ros_template, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `secai-${site?.site_id || "website"}-alibaba-role.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function downloadCollectorTemplate() {
    if (!status?.collector_setup) return;
    const blob = new Blob([JSON.stringify(status.collector_setup.ros_template, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `secai-${site?.site_id || "website"}-collector.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  const verified = status?.connection_status === "verified";
  const connectionReady = Boolean(verified && status?.logs_connected);
  const resourcesSelected = Boolean(status?.config?.ecs_instance_id && status?.config?.sls_endpoint && status?.config?.sls_project && status?.config?.sls_logstore);
  const showResourceEditor = Boolean(verified && (!resourcesSelected || editing));
  const authorization = status?.authorization;
  const lastExecution = status?.last_execution;
  const operationBusy = busy || Boolean(operation);

  return (
    <div className="setup-choice" aria-busy={operationBusy}>
      <div className="section-header compact">
        <div className="section-title"><ShieldCheck size={16} aria-hidden="true" /><h3>Alibaba Cloud connection</h3></div>
        <div className="connection-heading-actions">
          <span className={`connection-state ${connectionReady ? "connected" : ""}`}>{connectionReady ? "Connected" : resourcesSelected ? "Collector setup needed" : verified ? "Role verified" : status?.configured ? "Authorization needed" : "Not connected"}</span>
          {resourcesSelected && !editing ? <button type="button" className="secondary-button compact-button" onClick={() => setEditing(true)} disabled={operationBusy}><Pencil size={14} /> Edit</button> : null}
        </div>
      </div>

      {!status?.configured ? (
        <div className="cloud-authorization-intro">
          <p>SecAi uses a temporary role approved in the website owner&apos;s Alibaba Cloud account. It does not ask for AccessKeys, and each website gets a separate connection.</p>
          <button type="button" onClick={startConnection} disabled={!site || operationBusy}>
            <ShieldCheck size={15} /> {operation === "preparing" ? "Preparing…" : "Start Alibaba Cloud connection"}
          </button>
        </div>
      ) : null}

      {status?.configured && !verified && authorization ? (
        <div className="cloud-authorization-flow">
          <ol>
            <li><strong>Download the role template.</strong> It is unique to this website and trusts only SecAi&apos;s Control role with this connection&apos;s external ID.</li>
            <li><strong>Create a stack in Alibaba Cloud ROS.</strong> Choose &quot;Local Template&quot;, upload the template in the website owner&apos;s Alibaba account, review it, and create the stack.</li>
            <li><strong>Copy the RoleArn output (from the "Outputs" tab).</strong> Paste it below so SecAi can verify the connection.</li>
          </ol>
          <div className="authorization-actions">
            <button type="button" className="secondary-button" onClick={downloadTemplate}><Download size={15} /> Download role template</button>
            <a href="https://ros.console.aliyun.com/" target="_blank" rel="noreferrer">Open Alibaba Cloud ROS <ExternalLink size={14} /></a>
          </div>
          <details className="install-details">
            <summary><Copy size={15} /> Show manual authorization values</summary>
            <p>Provider role ARN</p><pre>{authorization.provider_role_arn}</pre>
            <p>External ID</p><pre>{authorization.external_id}</pre>
            <p>Trust policy</p><pre>{JSON.stringify(authorization.trust_policy, null, 2)}</pre>
          </details>
          <form className="stack-form" onSubmit={verifyConnection}>
            <label>Role ARN from the stack output<input value={roleArn} onChange={(event) => setRoleArn(event.target.value)} placeholder="acs:ram::1234567890123456:role/secai-site-..." disabled={operationBusy} required /></label>
            <label>Website region<input value={region} onChange={(event) => setRegion(event.target.value)} disabled={operationBusy} required /></label>
            <button type="submit" disabled={operationBusy || !roleArn.trim()}><ShieldCheck size={15} /> {operation === "verifying" ? "Verifying role…" : "Verify role"}</button>
          </form>
          <button type="button" className="text-button danger-text" onClick={disconnect} disabled={operationBusy}><Trash2 size={14} /> Cancel this connection</button>
          {status.connection_status === "error" ? <p className="helper-text danger-text">{status.config?.connection_error}</p> : null}
        </div>
      ) : null}

      {verified ? (
        <>
          <div className="status-grid">
            <ReportField label="Customer account" value={status?.config?.account_id || "Verified"} />
            <ReportField label="Region" value={status?.config?.region || region} />
            <ReportField label="Website server" value={status?.config?.ecs_instance_id || "Choose below"} />
            <ReportField label="Log source" value={resourcesSelected ? `${status.config?.sls_project} / ${status.config?.sls_logstore}` : "Choose below"} />
            <ReportField label="Protection target" value={status?.security_group_connected ? status.config?.security_group_id || "Available" : "Observe only"} />
          </div>
          {lastExecution ? (
            <div className={`cloud-execution-summary execution-${lastExecution.status}`}>
              <strong>Latest protective action: {friendlyStatus(lastExecution.status)}</strong>
              <span>{friendlyAction(lastExecution.action)}{lastExecution.target ? ` · ${lastExecution.target}` : ""}</span>
              {lastExecution.provider_rule_id ? <code>Alibaba rule {lastExecution.provider_rule_id}</code> : null}
              {lastExecution.error_message ? <small>{lastExecution.error_message}</small> : null}
            </div>
          ) : null}
          {showResourceEditor ? (
            <form className="stack-form connection-editor" onSubmit={handleSave}>
              <AlibabaConnectorCard
                key={site?.site_id}
                discoverResources={(requestedRegion) => discoverAlibabaResourcesForSite(session, site!.site_id, requestedRegion)}
                region={region}
                instanceId={instanceId}
                securityGroupId={securityGroupId}
                slsEndpoint={slsEndpoint}
                slsProject={slsProject}
                slsLogstore={slsLogstore}
                disabled={!site || operationBusy}
                onRegion={(value) => {
                  setRegion(value); setInstanceId(""); setSecurityGroupId(""); setSlsEndpoint(""); setSlsProject(""); setSlsLogstore("");
                }}
                onInstance={setInstanceId}
                onLogSource={(source) => {
                  setSlsEndpoint(source?.endpoint || ""); setSlsProject(source?.project || ""); setSlsLogstore(source?.logstore || "");
                }}
                onSecurityGroup={setSecurityGroupId}
              />
              <div className="authorization-actions">
                <button type="submit" disabled={operationBusy || !site || !instanceId || !slsEndpoint || !slsProject || !slsLogstore}>
                  {operation === "saving" ? <RefreshCw size={15} className="spin" /> : <ShieldCheck size={15} />} {operation === "saving" ? "Preparing…" : "Create installation plan"}
                </button>
                {resourcesSelected ? <button type="button" className="secondary-button" onClick={cancelEdit} disabled={operationBusy}><X size={14} /> Cancel</button> : null}
                <button type="button" className="text-button danger-text" onClick={disconnect} disabled={operationBusy}><Trash2 size={14} /> Disconnect Alibaba Cloud</button>
              </div>
            </form>
          ) : null}
          {resourcesSelected && !connectionReady && !editing && status?.collector_setup ? (
            <div className="cloud-authorization-flow collector-install-flow">
              <ol>
                <li><strong>Download the collector template.</strong> It is locked to server <code>{status.collector_setup.instance_id}</code> and the selected Logstore.</li>
                <li><strong>Create a new stack in Alibaba Cloud ROS.</strong> Choose &quot;Local Template&quot;, upload the file, review the command and resources, then approve the stack.</li>
                <li><strong>Wait for the collector.</strong> After the ROS stack succeeds, allow up to two minutes for LoongCollector to report that it is running.</li>
                <li><strong>Verify the connection.</strong> SecAi checks the collector heartbeat. You do not need to wait for an attack or website visit.</li>
              </ol>
              <div className="authorization-actions">
                <button type="button" className="secondary-button" onClick={downloadCollectorTemplate} disabled={operationBusy}><Download size={15} /> Download collector template</button>
                <a href="https://ros.console.aliyun.com/" target="_blank" rel="noreferrer">Open Alibaba Cloud ROS <ExternalLink size={14} /></a>
                <button type="button" onClick={verifyCollector} disabled={operationBusy}>
                  <ShieldCheck size={15} /> {operation === "collector" ? "Verifying…" : "Verify collector"}
                </button>
              </div>
              {status.config?.collector_error ? <p className="helper-text danger-text">{status.config.collector_error}</p> : null}
              <details className="install-details">
                <summary>Collector verification help</summary>
                <p>If this website&apos;s role was created before collector setup was available, update its existing ROS role stack with the current template so SecAi can read the collector heartbeat.</p>
                <button type="button" className="secondary-button" onClick={downloadTemplate} disabled={operationBusy || !authorization}><Download size={15} /> Download current role template</button>
              </details>
            </div>
          ) : null}
          {connectionReady ? <div className="authorization-actions">
            <button type="button" className="secondary-button" onClick={checkActivity} disabled={operationBusy || !status?.logs_connected}>
              <RefreshCw size={15} className={operation === "checking" ? "spin" : ""} /> {operation === "checking" ? "Checking…" : "Check recent activity"}
            </button>
          </div> : null}
        </>
      ) : null}
      {message ? <p className="status-line" role="status" aria-live="polite">{message}</p> : null}
    </div>
  );
}
