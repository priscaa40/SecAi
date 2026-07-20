import { CheckCircle2, ChevronDown, Eye, RefreshCw, XCircle } from "lucide-react";

import type { Incident, IncidentEvidence, RecommendedAction } from "../types";
import {
  formatDate,
  friendlyText,
  sourceLabel,
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
  const needsDecision = incident.status === "needs_review" && action.action === "apply_temporary_ip_block";
  const target = incident.protection.target || "this address";
  const duration = incident.protection.duration_label || "1 hour";
  if (needsDecision) {
    return (
      <div className="decision-panel">
        <div>
          <p className="eyebrow">Your action</p>
          <strong>Nothing changes until you choose.</strong>
        </div>
        <div className="decision-row">
          <button type="button" onClick={() => onDecision("approve", incident.id)} disabled={busy}><CheckCircle2 size={17} /> Block for {duration}</button>
          <button type="button" className="secondary-button" onClick={() => onDecision("reject", incident.id)} disabled={busy}><XCircle size={17} /> Don&apos;t block</button>
        </div>
      </div>
    );
  }

  const summary = incident.protection.human_action;
  if (!summary) return null;
  return (
    <div className={`human-decision decision-${incident.status}`}>
      <small>Your action</small>
      <strong>{summary}</strong>
    </div>
  );
}

export function ProtectionOutcome({
  incident,
  action,
  busy,
  onRetry,
  onRemove,
  onReapply,
}: {
  incident: Incident;
  action: RecommendedAction;
  busy: boolean;
  onRetry: () => void;
  onRemove: () => void;
  onReapply: () => void;
}) {
  const protectionStatus = getProtectionStatus(incident, action);
  const providerRuleId = getProviderRuleId(incident);
  const error = incident.policy?.error_message;
  const target = incident.protection.target || "this address";
  const expiresAt = incident.policy?.expires_at;
  const showProviderRule = protectionStatus === "active" && providerRuleId;
  const hasOutcome = Boolean(
    showProviderRule
    || (expiresAt && protectionStatus === "active")
    || error
    || incident.protection.can_retry
    || incident.protection.can_unblock
    || incident.protection.can_reapply,
  );

  function unblock() {
    if (window.confirm(`Unblock ${target} now? Requests from this address will be allowed again.`)) onRemove();
  }

  if (!hasOutcome) return null;

  return (
    <div className={`protection-outcome protection-${protectionStatus}`} role="status" aria-live="polite">
      {showProviderRule ? <span><small>Alibaba rule</small><code>{providerRuleId}</code></span> : null}
      {expiresAt && protectionStatus === "active" ? <span><small>Blocked until</small><strong>{formatDate(expiresAt)}</strong></span> : null}
      {error ? <p className="execution-error">{error}</p> : null}
      {incident.protection.can_retry ? (
        <button type="button" onClick={onRetry} disabled={busy}><RefreshCw size={16} /> Retry block</button>
      ) : null}
      {incident.protection.can_unblock ? <button type="button" className="danger-button" onClick={unblock} disabled={busy}>Unblock {target}</button> : null}
      {incident.protection.can_reapply ? <button type="button" onClick={onReapply} disabled={busy}>Block {target} again</button> : null}
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
  if (action.action !== "apply_temporary_ip_block") return "not_required";
  if (incident.status === "needs_review" || incident.status === "rejected") return "not_started";
  return incident.execution_status || "not_started";
}

export function getProviderRuleId(incident: Incident) {
  return incident.policy?.provider_rule_id || null;
}
