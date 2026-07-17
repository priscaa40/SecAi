import { AlertTriangle, ChevronDown, FileSearch, Search, ShieldCheck, UsersRound } from "lucide-react";

import type { AgentTraceStep, Incident, RecommendedAction } from "../types";
import {
  EvidencePanel,
  HumanDecision,
  ProtectionOutcome,
  buildEvidence,
  getProtectionStatus,
  getProviderRuleId,
} from "./IncidentReportSections";
import {
  AGENT_LABELS,
  confidencePercent,
  formatDate,
  friendlyText,
  protectionStatusLabel,
  statusLabel,
} from "./incidentPresentation";

export function IncidentReport({
  incident,
  status,
  busy,
  onDecision,
  onProtection = () => undefined,
}: {
  incident: Incident | null;
  status: string;
  busy: boolean;
  onDecision: (action: "approve" | "reject", incidentId: number) => void;
  onProtection?: (action: "retry" | "remove", incidentId: number) => void;
}) {
  if (!incident) {
    return (
      <section className="report-pane">
        <div className="empty-state report-empty">
          <Search size={38} />
          <h2>Choose a report to review</h2>
          <p>{status || "Select a report to see the evidence, recommendation, and protection result."}</p>
        </div>
      </section>
    );
  }

  const action: RecommendedAction = incident.recommended_action;
  const reportSections = action.report_sections;
  const ownerRecommendation = action.owner_recommendation;
  const protectionStatus = action.protection_status;
  const rawTrace: AgentTraceStep[] = Array.isArray(action.agent_trace) ? action.agent_trace : [];
  const agentTrace = ["investigator", "reviewer", "responder"]
    .map((role) => rawTrace.find((step) => step.agent === role))
    .filter((step): step is AgentTraceStep => Boolean(step));
  const evidence = buildEvidence(incident, action);
  const requiresDecision = incident.status === "needs_review" && action.action === "block_ip";
  const providerRuleId = getProviderRuleId(incident);

  return (
    <article className="report-pane">
      <header className="incident-hero">
        <div className="incident-hero-meta">
          <span className={`risk-label risk-text-${incident.severity}`}>{incident.severity} risk</span>
          <span>{statusLabel(incident.status)}</span>
          <time>{formatDate(incident.created_at)}</time>
        </div>
        <h1>{incident.title}</h1>
        <p className="incident-subtitle">{incident.affected_route ? `Detected on ${incident.affected_route}. ` : ""}Review the summary and recommendation below.</p>
      </header>

      <div className="report-body">
        <section className="plain-report-section">
          <div className="report-section-icon warning"><AlertTriangle size={20} /></div>
          <div>
            <p className="eyebrow">Summary</p>
            <h2>{friendlyText(incident.attack_type)}</h2>
            <p>{reportSections.summary}</p>
            <div className="report-explanation-grid">
              <div><strong>What is known</strong><p>{reportSections.what_happened}</p></div>
              <div><strong>What remains unknown</strong><p>{reportSections.what_is_unknown}</p></div>
              <div><strong>Why it matters</strong><p>{reportSections.why_it_matters}</p></div>
            </div>
          </div>
        </section>

        <section className="recommendation-card">
          <div className="recommendation-heading">
            <div className="report-section-icon safe"><ShieldCheck size={20} /></div>
            <div><p className="eyebrow">Recommendation</p><h2>{ownerRecommendation.title}</h2></div>
          </div>
          <p>{ownerRecommendation.explanation}</p>
          <ol className="next-step-list">{ownerRecommendation.steps.map((step) => <li key={step}>{step}</li>)}</ol>
        </section>

        <section className={`report-card protection-status-card protection-state-${protectionStatus.state}`}>
          <div className="card-heading">
            <ShieldCheck size={19} />
            <div><p className="eyebrow">Protection status</p><h2>{protectionStatus.title}</h2></div>
          </div>
          <p>{protectionStatus.explanation}</p>
          {action.target ? <small className="protection-target">Source address: {String(action.target)}</small> : null}

          {action.action === "block_ip" ? (
            <>
              <HumanDecision incident={incident} action={action} busy={busy} onDecision={onDecision} />
              <ProtectionOutcome
                incident={incident}
                action={action}
                busy={busy}
                onRetry={() => onProtection("retry", incident.id)}
                onRemove={() => onProtection("remove", incident.id)}
              />
            </>
          ) : null}

          {incident.status === "needs_review" && !requiresDecision ? (
            <p className="status-line danger-text">This report does not contain a supported single-address protection. No action can be approved from this report.</p>
          ) : null}
        </section>

        <EvidencePanel evidence={evidence} />

        <details className="explain-details">
          <summary><span><UsersRound size={19} /><span><strong>Investigation details</strong><small>See how the evidence was reviewed</small></span></span><ChevronDown size={18} /></summary>
          <div className="agent-trace">
            {agentTrace.length ? agentTrace.map((step, index) => {
              const role = AGENT_LABELS[step.agent];
              return (
                <article className="agent-trace-step" key={step.agent}>
                  <span className="trace-number">{index + 1}</span>
                  <div>
                    <div className="trace-heading"><strong>{role.label}</strong></div>
                    <small className="trace-role-description">{role.description}</small>
                    <p>{step.summary}</p>
                    {step.decision ? <small>Result: {friendlyText(step.decision)}</small> : null}
                  </div>
                </article>
              );
            }) : <p className="helper-text">The investigator, reviewer, and responder checked this report together.</p>}
          </div>
        </details>

        <details className="technical-details">
          <summary><FileSearch size={17} /> Report record</summary>
          <div className="technical-grid">
            <span><small>Report ID</small><strong>#{incident.id}</strong></span>
            <span><small>Protection</small><strong>{protectionStatusLabel(getProtectionStatus(incident, action))}</strong></span>
            <span><small>Confidence</small><strong>{confidencePercent(incident.confidence)}%</strong></span>
            {providerRuleId ? <span><small>Alibaba rule</small><strong>{providerRuleId}</strong></span> : null}
          </div>
        </details>
      </div>
    </article>
  );
}
