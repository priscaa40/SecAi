from __future__ import annotations

from typing import Any, Literal, TypedDict

from pydantic import BaseModel, Field

from secai.models import RemediationAction, Severity


WorkflowDecision = Literal["ignore", "create_incident", "request_more_evidence"]


class TriageDecision(BaseModel):
    """First agent decision about whether an event should become an incident."""

    decision: WorkflowDecision
    title: str
    attack_type: str
    security_profile_id: str
    source_ids: list[str] = Field(default_factory=list)
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    affected_route: str | None = None
    reasoning: str
    evidence_used: list[str] = Field(default_factory=list)
    false_positive_considerations: list[str] = Field(default_factory=list)
    uncertainty: str


class InvestigationSummary(BaseModel):
    """Agent summary of related evidence and patterns around an event."""

    summary: str
    related_event_count: int = Field(ge=0)
    notable_patterns: list[str] = Field(default_factory=list)
    evidence_used: list[str] = Field(default_factory=list)


class IncidentReport(BaseModel):
    """Plain-language incident report for a non-expert website owner."""

    executive_summary: str
    what_happened: str
    why_it_matters: str
    recommended_next_step: str

    def as_text(self) -> str:
        """Render the structured report as readable paragraphs."""
        return (
            f"{self.executive_summary}\n\n"
            f"What happened: {self.what_happened}\n\n"
            f"Why it matters: {self.why_it_matters}\n\n"
            f"Recommended next step: {self.recommended_next_step}"
        )


class RemediationDecision(BaseModel):
    """Agent recommendation for the next safe remediation step."""

    security_profile_id: str
    source_ids: list[str] = Field(default_factory=list)
    action: RemediationAction
    target: str
    reason: str
    requires_approval: bool
    human_checkpoint: str


class SupervisorDecision(BaseModel):
    """Agent quality-control decision before incident creation."""

    approved_for_incident_creation: bool
    reason: str


class SecAiState(TypedDict, total=False):
    """Shared LangGraph state passed between SecAi agent nodes."""

    event: dict[str, Any]
    job_id: int
    triage: TriageDecision
    investigation: InvestigationSummary
    report: IncidentReport
    remediation: RemediationDecision
    supervisor: SupervisorDecision
    incident: dict[str, Any] | None
