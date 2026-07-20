const STATUS_LABELS: Record<string, string> = {
  needs_review: "Your decision needed",
  reported: "Report ready",
  approved: "Approved by you",
  rejected: "Declined by you",
};

export const AGENT_LABELS: Record<string, { label: string; description: string }> = {
  investigator: { label: "Investigator", description: "Finds related activity and identifies the likely threat." },
  reviewer: { label: "Reviewer", description: "Challenges the evidence and filters weak conclusions." },
  responder: { label: "Responder", description: "Explains the risk and recommends the safest response." },
  executor: { label: "Executor", description: "Carries out the reviewed response after any required approval." },
};

export const ACTIVE_JOB_STATUSES = new Set(["queued", "running"]);

export function friendlyText(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

export function statusLabel(status: string) {
  return STATUS_LABELS[status] || friendlyText(status);
}

export function confidencePercent(confidence: number) {
  return Math.round(confidence <= 1 ? confidence * 100 : confidence);
}

export function formatDuration(milliseconds?: number | null) {
  if (milliseconds === undefined || milliseconds === null) return null;
  if (milliseconds < 1000) return `${milliseconds} ms`;
  const seconds = milliseconds / 1000;
  return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)} sec`;
}

export function formatDate(value?: string | null) {
  if (!value) return "Time unavailable";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

export function sourceLabel(value?: string | null) {
  if (!value) return "Not recorded";
  if (value === "alibaba_sls") return "Alibaba Cloud activity";
  if (value === "browser") return "Website monitoring script";
  return friendlyText(value);
}

export function protectionStatusLabel(status: string) {
  const labels: Record<string, string> = {
    not_required: "No traffic change",
    not_started: "Not started",
    pending: "Waiting to apply",
    applying: "Applying",
    active: "Active",
    revoking: "Removing",
    revoked: "Removed",
    expired: "Ended",
    failed: "Failed",
    awaiting_approval: "Waiting for your approval",
    queued: "Queued for Qwen Executor",
    running: "Qwen Executor running",
    succeeded: "Completed",
    rejected: "Declined",
  };
  return labels[status] || friendlyText(status);
}
