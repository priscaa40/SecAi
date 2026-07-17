import { AlertTriangle, CheckCircle2, CircleCheckBig, Clock3, RefreshCw } from "lucide-react";
import { useMemo, useState } from "react";

import type { AnalysisJob, Incident } from "../types";
import {
  ACTIVE_JOB_STATUSES,
  FAILED_JOB_STATUSES,
  formatDate,
  friendlyText,
  jobLabel,
  statusLabel,
} from "./incidentPresentation";

type IncidentFilter = "attention" | "all" | "handled";

export function IncidentQueue({
  incidents,
  analysisJobs,
  selectedIncidentId,
  onSelect,
  onRetry,
  busy,
}: {
  incidents: Incident[];
  analysisJobs: AnalysisJob[];
  selectedIncidentId: number | null;
  onSelect: (incidentId: number) => void;
  onRetry: (jobId: number) => void;
  busy: boolean;
}) {
  const [filter, setFilter] = useState<IncidentFilter>("all");
  const attentionCount = incidents.filter((incident) => incident.status === "needs_review").length;
  const visibleJobs = analysisJobs
    .filter((job) => ACTIVE_JOB_STATUSES.has(job.status) || FAILED_JOB_STATUSES.has(job.status))
    .slice(0, 5);
  const visibleIncidents = useMemo(() => {
    if (filter === "attention") return incidents.filter((incident) => incident.status === "needs_review");
    if (filter === "handled") return incidents.filter((incident) => incident.status !== "needs_review");
    return incidents;
  }, [filter, incidents]);

  return (
    <section className="queue-pane" aria-label="Security activity">
      <div className="queue-header">
        <div><p className="eyebrow">Activity</p><h2>Security reports</h2></div>
        <span className="counter">{incidents.length}</span>
      </div>
      {visibleJobs.length ? (
        <div className="analysis-job-list" aria-label="Current investigations" aria-live="polite">
          {visibleJobs.map((job) => {
            const evidence = job.event || job.evidence?.[0];
            const failed = FAILED_JOB_STATUSES.has(job.status);
            const canRetry = failed && job.attempt_count < 3;
            return (
              <div className={`analysis-job job-${failed ? "failed" : "active"}`} key={job.id}>
                {failed ? <AlertTriangle size={17} /> : <RefreshCw size={17} className={job.status === "running" ? "spin" : ""} />}
                <span>
                  <strong>{jobLabel(job.status)}</strong>
                  <small>{job.error || job.current_step || [evidence?.method, evidence?.path].filter(Boolean).join(" ") || `Received ${formatDate(job.created_at)}`}</small>
                </span>
                {canRetry ? <button type="button" onClick={() => onRetry(job.id)} disabled={busy}>Retry</button> : null}
                {failed && !canRetry ? <small>Retry limit reached</small> : null}
              </div>
            );
          })}
        </div>
      ) : null}
      <div className="filter-tabs" aria-label="Filter security reports">
        <button type="button" aria-pressed={filter === "attention"} className={filter === "attention" ? "active" : ""} onClick={() => setFilter("attention")}>Needs you {attentionCount ? <span>{attentionCount}</span> : null}</button>
        <button type="button" aria-pressed={filter === "all"} className={filter === "all" ? "active" : ""} onClick={() => setFilter("all")}>All</button>
        <button type="button" aria-pressed={filter === "handled"} className={filter === "handled" ? "active" : ""} onClick={() => setFilter("handled")}>History</button>
      </div>
      <div className="incident-list">
        {visibleIncidents.length === 0 ? (
          <div className="empty-state compact-empty">
            <CircleCheckBig size={34} />
            <h3>{filter === "attention" ? "Nothing needs your decision" : "No reports here yet"}</h3>
            <p>{filter === "attention" ? "SecAi will ask before making a protective change." : "New reports will appear here after an investigation finishes."}</p>
          </div>
        ) : visibleIncidents.map((incident) => (
          <button type="button" key={incident.id} aria-current={incident.id === selectedIncidentId ? "true" : undefined} className={`incident-row ${incident.id === selectedIncidentId ? "active" : ""}`} onClick={() => onSelect(incident.id)}>
            <span className="incident-row-topline"><span className={`risk-label risk-text-${incident.severity}`}>{incident.severity}</span><time>{formatDate(incident.created_at)}</time></span>
            <strong>{incident.title}</strong>
            <span className="incident-description">{incident.affected_route ? `Affected ${incident.affected_route}` : friendlyText(incident.attack_type)}</span>
            <span className={`incident-status status-${incident.status}`}>
              {incident.status === "needs_review" ? <Clock3 size={14} /> : <CheckCircle2 size={14} />}
              {statusLabel(incident.status)}
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}
