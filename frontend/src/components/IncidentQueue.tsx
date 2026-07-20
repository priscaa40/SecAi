import { CheckCircle2, CircleCheckBig, Clock3 } from "lucide-react";
import { useMemo, useState } from "react";

import type { Incident } from "../types";
import {
  formatDate,
  friendlyText,
  statusLabel,
} from "./incidentPresentation";

type IncidentFilter = "attention" | "all" | "handled";

export function IncidentQueue({
  incidents,
  selectedIncidentId,
  onSelect,
}: {
  incidents: Incident[];
  selectedIncidentId: number | null;
  onSelect: (incidentId: number) => void;
}) {
  const [filter, setFilter] = useState<IncidentFilter>("all");
  const attentionCount = incidents.filter((incident) => incident.status === "needs_review").length;
  const visibleIncidents = useMemo(() => {
    if (filter === "attention") return incidents.filter((incident) => incident.status === "needs_review");
    if (filter === "handled") return incidents.filter((incident) => incident.status !== "needs_review");
    return incidents;
  }, [filter, incidents]);

  return (
    <aside className="queue-pane" aria-label="Security reports">
      <div className="queue-header">
        <div><p className="eyebrow">Activity</p><h2>Reports</h2></div>
        <span className="counter">{incidents.length}</span>
      </div>
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
    </aside>
  );
}
