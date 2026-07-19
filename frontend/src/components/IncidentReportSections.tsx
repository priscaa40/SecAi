import { AlertTriangle, CheckCircle2, ChevronDown, CircleCheckBig, Clock3, Eye, RefreshCw, ShieldCheck, XCircle } from "lucide-react";
import type { ReactNode } from "react";

import type { Incident, IncidentEvidence, RecommendedAction } from "../types";
import {
  formatDate,
  friendlyText,
  protectionStatusLabel,
  sourceLabel,
  statusLabel,
} from "./incidentPresentation";

export function EvidencePanel({ evidence }: { evidence: IncidentEvidence[] }) {
  return (
    <details className="explain-details evidence-details">
      <summary><span><Eye size={19} /><span><strong>Evidence</strong><small>{evidence.length} activity record{evidence.length === 1 ? "" : "s"} behind this report</small></span></span><ChevronDown size={18} /></summary>
      <div className="evidence-list">
        {evidence.map((item, index) => {
          const route = [item.method, item.path].filter(Boolean).join(" ");
          const signals = item.signals?.length ? item.signals.map(friendlyText).join(", ") : item.event_type ? friendlyText(item.event_type) : "No warning sign recorded";
          return (
            <article className="evidence-item" key={`${item.observed_at || item.created_at || "evidence"}-${index}`}>
              <div><small>Time</small><strong>{formatDate(item.observed_at || item.created_at)}</strong></div>
              <div><small>Address</small><strong>{item.ip || "Not recorded"}</strong></div>
              <div><small>Request</small><strong>{route || "Not recorded"}</strong></div>
              <div><small>Status</small><strong>{item.status_code ?? "Not recorded"}</strong></div>
              <div className="evidence-wide"><small>Warning signs</small><strong>{signals}</strong></div>
              <div><small>Source</small><strong>{sourceLabel(item.source)}</strong></div>
            </article>
          );
        })}
      </div>
    </details>
  );
}

export function HumanDecision({
  incident,
  action,
  busy,
  onDecision,
}: {
  incident: Incident;
  action: RecommendedAction;
  busy: boolean;
  onDecision: (action: "approve" | "reject", incidentId: number) => void;
}) {
  const needsDecision = incident.status === "needs_review" && action.action === "block_ip";
  if (needsDecision) {
    return (
      <div className="decision-panel">
        <div>
          <p className="eyebrow">Your decision</p>
          <strong>Should SecAi apply this protection?</strong>
          <span>Nothing will change until you approve it.</span>
        </div>
        <div className="decision-row">
          <button type="button" onClick={() => onDecision("approve", incident.id)} disabled={busy}><CheckCircle2 size={17} /> Approve protection</button>
          <button type="button" className="secondary-button" onClick={() => onDecision("reject", incident.id)} disabled={busy}><XCircle size={17} /> Decline</button>
        </div>
      </div>
    );
  }

  const copy: Record<string, string> = {
    approved: "You approved the recommended protection.",
    rejected: "You declined the recommendation. No new protection will be started.",
  };
  return (
    <div className={`human-decision decision-${incident.status}`}>
      <small>Human decision</small>
      <strong>{copy[incident.status] || statusLabel(incident.status)}</strong>
    </div>
  );
}

export function ProtectionOutcome({
  incident,
  action,
  busy,
  onRetry,
  onRemove,
}: {
  incident: Incident;
  action: RecommendedAction;
  busy: boolean;
  onRetry: () => void;
  onRemove: () => void;
}) {
  const protectionStatus = getProtectionStatus(incident, action);
  const providerRuleId = getProviderRuleId(incident);
  const error = incident.policy?.error_message;
  const target = incident.policy?.target || action.target;
  const expiresAt = incident.policy?.expires_at;
  const copy = protectionStatusCopy(protectionStatus);
  const active = protectionStatus === "active";

  return (
    <div className={`protection-outcome protection-${protectionStatus}`} role="status" aria-live="polite">
      <div className="protection-outcome-heading">
        <span>{copy.icon}</span>
        <div><p className="eyebrow">Protection result</p><strong>{copy.title}</strong><small>{copy.description}</small></div>
      </div>
      {target ? <span><small>Address</small><strong>{String(target)}</strong></span> : null}
      {providerRuleId ? <span><small>Alibaba rule</small><code>{providerRuleId}</code></span> : null}
      {expiresAt && active ? <span><small>Scheduled to end</small><strong>{formatDate(expiresAt)}</strong></span> : null}
      {error ? <p className="execution-error">{error}</p> : null}
      {protectionStatus === "failed" || protectionStatus === "pending" ? (
        <button type="button" onClick={onRetry} disabled={busy}><RefreshCw size={16} /> Retry protection</button>
      ) : null}
      {active ? <button type="button" className="danger-button" onClick={onRemove} disabled={busy}>Remove protection</button> : null}
    </div>
  );
}

export function buildEvidence(incident: Incident, action: RecommendedAction): IncidentEvidence[] {
  if (incident.evidence?.length) return incident.evidence;
  const source = Array.isArray(action.evidence_sources)
    ? String(action.evidence_sources[0] || "")
    : action.evidence_source
      ? String(action.evidence_source)
      : null;
  return [{ observed_at: incident.created_at, source, ip: action.target ? String(action.target) : null, path: incident.affected_route, signals: [incident.attack_type] }];
}

export function getProtectionStatus(incident: Incident, action: RecommendedAction) {
  if (incident.policy?.status) return incident.policy.status;
  if (action.action !== "block_ip") return "not_required";
  if (incident.status === "needs_review" || incident.status === "rejected") return "not_started";
  return incident.execution_status || "not_started";
}

export function getProviderRuleId(incident: Incident) {
  return incident.policy?.provider_rule_id || null;
}

function protectionStatusCopy(status: string) {
  const waitingIcon = <Clock3 size={19} />;
  const copy: Record<string, { title: string; description: string; icon: ReactNode }> = {
    not_required: { title: "No traffic change needed", description: "This response only reports or continues monitoring.", icon: <Eye size={19} /> },
    not_started: { title: "No protection applied", description: "Your website traffic has not been changed.", icon: waitingIcon },
    pending: { title: "Protection is waiting to start", description: "Your approval was saved and the change is queued.", icon: waitingIcon },
    applying: { title: "Protection is being applied", description: "SecAi is waiting for Alibaba Cloud to confirm the rule.", icon: <RefreshCw size={19} className="spin" /> },
    active: { title: "Protection is active", description: "Alibaba Cloud confirmed the temporary rule.", icon: <ShieldCheck size={19} /> },
    revoking: { title: "Protection is being removed", description: "SecAi is waiting for Alibaba Cloud to remove the rule.", icon: <RefreshCw size={19} className="spin" /> },
    revoked: { title: "Protection was removed", description: "The temporary rule is no longer active.", icon: <CircleCheckBig size={19} /> },
    expired: { title: "Protection ended", description: "The temporary rule reached its planned end time.", icon: <CircleCheckBig size={19} /> },
    failed: { title: "Protection failed", description: "Alibaba Cloud did not confirm the requested change.", icon: <AlertTriangle size={19} /> },
  };
  return copy[status] || { title: protectionStatusLabel(status), description: "See the report record for the current state.", icon: waitingIcon };
}
