import { AlertTriangle, Check, Clock3, Minus, RefreshCw } from "lucide-react";

import type { ActionJob, AnalysisJob, Incident } from "../types";
import { formatDate } from "./incidentPresentation";

type AgentName = "investigator" | "reviewer" | "responder" | "executor";
type AgentStatus = "waiting" | "working" | "complete" | "skipped" | "failed";

const AGENTS: { name: AgentName; label: string }[] = [
  { name: "investigator", label: "Investigator" },
  { name: "reviewer", label: "Reviewer" },
  { name: "responder", label: "Responder" },
  { name: "executor", label: "Executor" },
];

export function InvestigationProgress({
  job,
  incident,
}: {
  job?: AnalysisJob | null;
  incident?: Incident | null;
}) {
  if (!job && !incident) return null;
  const stages = agentStages(job, incident?.action_job);
  const identifier = job ? `Investigation #${job.id}` : `Report #${incident?.id}`;
  const startedAt = job?.created_at || incident?.created_at;

  return (
    <aside className="investigation-pipeline" aria-label={`${identifier} agent progress`} aria-live="polite">
      <header>
        <span><strong>{identifier}</strong><small>{formatDate(startedAt)}</small></span>
      </header>
      <ol>
        {stages.map((stage) => (
          <li className={`pipeline-stage stage-${stage.status}`} key={stage.name}>
            <span className="pipeline-stage-marker" aria-hidden="true">{stageIcon(stage.status)}</span>
            <span><strong>{stage.label}</strong><small>{stage.statusLabel}</small></span>
          </li>
        ))}
      </ol>
    </aside>
  );
}

export function agentStages(job?: AnalysisJob | null, actionJob?: ActionJob | null) {
  const activeAnalysis = Boolean(job && ["queued", "running"].includes(job.status));
  const analysisComplete = activeAnalysis && ["persist_incident", "complete"].includes(job?.current_step || "");
  const currentIndex = activeAnalysis
    ? AGENTS.findIndex((agent) => agent.name === job?.current_step)
    : -1;

  return AGENTS.map((agent, index) => {
    if (agent.name === "executor") {
      return { ...agent, ...executorStage(activeAnalysis ? null : actionJob) };
    }
    let status: AgentStatus = activeAnalysis && !analysisComplete ? "waiting" : "complete";
    if (activeAnalysis && !analysisComplete && currentIndex >= 0 && index < currentIndex) status = "complete";
    if (activeAnalysis && !analysisComplete && currentIndex === index) status = "working";
    return { ...agent, status, statusLabel: defaultStatusLabel(status) };
  });
}

function executorStage(actionJob?: ActionJob | null): { status: AgentStatus; statusLabel: string } {
  if (!actionJob) return { status: "waiting", statusLabel: "Waiting" };
  const states: Record<ActionJob["status"], { status: AgentStatus; statusLabel: string }> = {
    awaiting_approval: { status: "waiting", statusLabel: "Needs approval" },
    queued: { status: "waiting", statusLabel: "Queued" },
    running: { status: "working", statusLabel: "Working" },
    succeeded: { status: "complete", statusLabel: "Complete" },
    rejected: { status: "skipped", statusLabel: "Not run" },
    failed: { status: "failed", statusLabel: "Failed" },
  };
  return states[actionJob.status];
}

function defaultStatusLabel(status: AgentStatus) {
  const labels: Record<AgentStatus, string> = {
    waiting: "Waiting",
    working: "Working",
    complete: "Complete",
    skipped: "Not run",
    failed: "Failed",
  };
  return labels[status];
}

function stageIcon(status: AgentStatus) {
  if (status === "complete") return <Check size={12} />;
  if (status === "working") return <RefreshCw size={11} className="spin" />;
  if (status === "skipped") return <Minus size={11} />;
  if (status === "failed") return <AlertTriangle size={11} />;
  return <Clock3 size={11} />;
}
