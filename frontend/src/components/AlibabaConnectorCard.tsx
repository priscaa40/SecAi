import { RefreshCw, ShieldCheck } from "lucide-react";
import { useState } from "react";

import type { AlibabaDiscoveredResources, AlibabaLogSource } from "../types";

export function AlibabaConnectorCard({
  region,
  securityGroupId,
  slsEndpoint,
  slsProject,
  slsLogstore,
  disabled = false,
  discoverResources,
  onRegion,
  onLogSource,
  onSecurityGroup,
}: {
  region: string;
  securityGroupId: string;
  slsEndpoint: string;
  slsProject: string;
  slsLogstore: string;
  disabled?: boolean;
  discoverResources: (region: string) => Promise<AlibabaDiscoveredResources>;
  onRegion: (value: string) => void;
  onLogSource: (source: AlibabaLogSource | null) => void;
  onSecurityGroup: (securityGroupId: string) => void;
}) {
  const [resources, setResources] = useState<AlibabaDiscoveredResources | null>(null);
  const [message, setMessage] = useState("");
  const [discovering, setDiscovering] = useState(false);

  async function findResources() {
    if (!region.trim()) return;
    setDiscovering(true);
    setMessage("Checking the resources this website role can use…");
    try {
      const result = await discoverResources(region.trim());
      setResources(result);
      const sourceStillExists = result.log_sources.some(
        (source) => source.endpoint === slsEndpoint && source.project === slsProject && source.logstore === slsLogstore,
      );
      if (!sourceStillExists) onLogSource(null);
      if (!result.security_groups.some((group) => group.security_group_id === securityGroupId && group.dedicated)) {
        onSecurityGroup("");
      }
      setMessage(
        result.log_sources.length
          ? "Choose the activity for this website. Protection is optional and always requires your approval."
          : "No Log Service source was found in this region.",
      );
    } catch (error) {
      setResources(null);
      setMessage(error instanceof Error ? error.message : "SecAi could not inspect this region.");
    } finally {
      setDiscovering(false);
    }
  }

  const warnings = resources ? Array.from(new Set(resources.warnings.map(ownerFacingResourceWarning))) : [];
  const dedicatedGroups = resources?.security_groups.filter((group) => group.dedicated) || [];

  return (
    <div className="connector-template">
      <div className="connector-template-header">
        <div>
          <h3>Choose this website&apos;s cloud resources</h3>
          <p>SecAi only shows resources available through the role you verified for this website.</p>
        </div>
      </div>
      <div className="connector-grid region-discovery-grid">
        <label>
          Alibaba Cloud region
          <input
            list="alibaba-region-options"
            value={region}
            onChange={(event) => {
              setResources(null);
              setMessage("");
              onRegion(event.target.value);
            }}
            disabled={disabled}
          />
          <datalist id="alibaba-region-options">
            <option value="ap-southeast-1">Singapore</option>
            <option value="ap-southeast-3">Kuala Lumpur</option>
            <option value="ap-southeast-5">Jakarta</option>
            <option value="cn-hongkong">Hong Kong</option>
            <option value="cn-hangzhou">Hangzhou</option>
            <option value="eu-central-1">Frankfurt</option>
            <option value="us-west-1">Silicon Valley</option>
          </datalist>
        </label>
        <button type="button" className="secondary-button" onClick={findResources} disabled={disabled || discovering || !region.trim()}>
          <RefreshCw size={15} className={discovering ? "spin" : ""} aria-hidden="true" /> {discovering ? "Checking resources…" : "Find resources"}
        </button>
      </div>
      {resources ? (
        <div className="connector-grid resource-selectors">
          <label>
            Website activity to investigate
            <select
              value={slsEndpoint && slsProject && slsLogstore ? `${slsProject}\n${slsLogstore}` : ""}
              onChange={(event) => {
                const source = resources.log_sources.find((item) => `${item.project}\n${item.logstore}` === event.target.value);
                onLogSource(source || null);
              }}
              disabled={disabled}
            >
              <option value="">Choose website activity</option>
              {resources.log_sources.map((source) => (
                <option key={`${source.project}/${source.logstore}`} value={`${source.project}\n${source.logstore}`}>{source.label}</option>
              ))}
            </select>
          </label>
          <label>
            Approved protection target <span className="optional-label">Optional</span>
            <select value={securityGroupId} onChange={(event) => onSecurityGroup(event.target.value)} disabled={disabled}>
              <option value="">Investigation and reports only</option>
              {dedicatedGroups.map((group) => (
                <option key={group.security_group_id} value={group.security_group_id}>{group.name} · {group.security_group_id}</option>
              ))}
            </select>
          </label>
          <div className="permission-note resource-protection-status">
            <ShieldCheck size={18} aria-hidden="true" />
            <span>
              <strong>{securityGroupId ? "Protection can be requested" : "No traffic changes"}</strong>
              <small>{securityGroupId ? "SecAi may recommend a temporary change to this group, but it cannot apply it until you approve." : "SecAi will investigate and report without changing Alibaba Cloud traffic."}</small>
            </span>
          </div>
        </div>
      ) : null}
      {resources && resources.security_groups.length > dedicatedGroups.length ? (
        <p className="helper-text">Shared security groups are not offered because a protective change could affect another server.</p>
      ) : null}
      {warnings.map((warning) => <p className="helper-text" key={warning}>{warning}</p>)}
      {message ? <p className="status-line" role="status" aria-live="polite">{message}</p> : null}
    </div>
  );
}

function ownerFacingResourceWarning(warning: string) {
  const normalized = warning.toLowerCase();
  if (normalized.includes("log service")) return "SecAi could not check all website activity in this region.";
  if (normalized.includes("security group")) return "SecAi could not check whether cloud protection is available in this region.";
  return "Some Alibaba Cloud resources could not be checked. You can continue with the options shown.";
}
