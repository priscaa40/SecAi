import { AlertTriangle, Check, Clock3, RefreshCw } from "lucide-react";

import type { AnalysisJob } from "../types";
import { formatDate } from "./incidentPresentation";

type AgentName = "investigator" | "reviewer" | "responder";
type AgentStatus = "waiting" | "working" | "complete" | "failed";

const AGENTS: { name: AgentName; label: string; description: string }[] = [
  {
    name: "investigator",
    label: "Investigator",
    description: "Examining the evidence and identifying the likely attack.",
  },
  {
    name: "reviewer",
    label: "Reviewer",
    description: "Checking the evidence and challenging the Investigator's conclusion.",
  },
  {
    name: "responder",
    label: "Responder",
    description: "Turning the reviewed findings into a clear report and recommending the safest next step.",
  },
];

export function InvestigationProgress({
  job,
  compact = false,
  busy = false,
  onRetry,
}: {
  job: AnalysisJob;
  compact?: boolean;
  busy?: boolean;
  onRetry?: (jobId: number) => void;
}) {
  const stages = agentStages(job);
  const active = stages.find((stage) => stage.status === "working");
  const failed = stages.find((stage) => stage.status === "failed");
  const evidence = job.event || job.evidence?.[0];
  const request = [evidence?.method, evidence?.path].filter(Boolean).join(" ");
  const canRetry = job.status === "failed" && job.attempt_count < 3 && onRetry;
  const finalizing = job.status === "running" && job.current_step === "persist_incident";
  const savingFailed = job.status === "failed" && job.current_step === "persist_incident";
  let heading = "Starting the investigation";
  if (job.status === "queued") heading = "Waiting for the Investigator";
  if (job.status === "failed") heading = "The investigation could not start";
  if (finalizing) heading = "Preparing the report";
  if (active) heading = `${active.label} is working`;
  if (savingFailed) heading = "The report could not be saved";
  if (failed) heading = `${failed.label} could not finish`;

  return (
    <article className={`investigation-progress ${compact ? "compact" : ""} job-${job.status}`} aria-live="polite">
      <header>
        <span className="investigation-progress-icon">
          {job.status === "failed" ? <AlertTriangle size={18} /> : <RefreshCw size={18} className={active ? "spin" : ""} />}
        </span>
        <div>
          <p className="eyebrow">Investigation #{job.id}</p>
          <strong>{heading}</strong>
          <small>{request || `Started ${formatDate(job.created_at)}`}</small>
        </div>
        {canRetry ? <button type="button" onClick={() => onRetry?.(job.id)} disabled={busy}>Retry</button> : null}
      </header>

      <ol className="investigation-agents">
        {stages.map((stage) => (
          <li className={`agent-stage stage-${stage.status}`} key={stage.name}>
            <span className="agent-stage-marker" aria-hidden="true">
              {stage.status === "complete" ? <Check size={13} /> : stage.status === "working" ? <RefreshCw size={12} className="spin" /> : stage.status === "failed" ? <AlertTriangle size={12} /> : <Clock3 size={12} />}
            </span>
            <div>
              <span><strong>{stage.label}</strong><small>{stageStatusLabel(stage.status)}</small></span>
              <p>{stage.description}</p>
            </div>
          </li>
        ))}
      </ol>

      {finalizing ? <p className="investigation-system-step">All three agents are complete. SecAi is saving the report.</p> : null}
      {job.error ? <p className="investigation-error">{job.error}</p> : null}
      {job.status === "failed" && !canRetry ? <small className="retry-limit">Retry limit reached</small> : null}
    </article>
  );
}

export function agentStages(job: AnalysisJob) {
  const currentIndex = AGENTS.findIndex((agent) => agent.name === job.current_step);
  const failed = job.status === "failed";
  const allComplete = job.current_step === "persist_incident" || job.current_step === "complete" || job.status === "incident_created" || job.status === "no_incident";

  return AGENTS.map((agent, index) => {
    let status: AgentStatus = "waiting";
    if (allComplete) status = "complete";
    else if (currentIndex >= 0 && index < currentIndex) status = "complete";
    else if (currentIndex === index) status = failed ? "failed" : "working";
    return { ...agent, status };
  });
}

function stageStatusLabel(status: AgentStatus) {
  const labels: Record<AgentStatus, string> = {
    waiting: "Waiting",
    working: "Working",
    complete: "Complete",
    failed: "Failed",
  };
  return labels[status];
}
