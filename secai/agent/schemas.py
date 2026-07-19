from __future__ import annotations

from typing import Any, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from secai.models import RemediationAction, Severity

InvestigationDecisionType = Literal["ignore", "escalate"]


class AgentOutput(BaseModel):
    """Require Qwen to return exactly the declared structured schema."""

    model_config = ConfigDict(extra="forbid")


class InvestigationDecision(AgentOutput):
    """Classification and evidence assessment produced by the investigator."""

    decision: InvestigationDecisionType
    title: str
    security_profile_id: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    affected_route: str | None = None
    summary: str
    related_event_count: int = Field(ge=0)
    notable_patterns: list[str] = Field(default_factory=list)
    evidence_used: list[str] = Field(default_factory=list)
    false_positive_considerations: list[str] = Field(default_factory=list)
    uncertainty: str


class ReviewDecision(AgentOutput):
    """Independent challenge of an investigation before a report is created."""

    approved_for_report: bool
    reason: str
    evidence_gaps: list[str] = Field(default_factory=list)


class IncidentResponse(AgentOutput):
    """Plain-language report plus one capability-safe automation decision."""

    headline: str = Field(min_length=8, max_length=160)
    potential_impact: str = Field(min_length=8, max_length=400)
    evidence_summary: str = Field(min_length=8, max_length=400)
    recommended_action: str = Field(min_length=8, max_length=400)
    technical_summary: str = Field(min_length=8, max_length=800)
    what_happened: str = Field(min_length=8, max_length=1200)
    what_is_unknown: str = Field(min_length=8, max_length=800)
    why_it_matters: str = Field(min_length=8, max_length=800)
    recommendation_title: str = Field(min_length=8, max_length=200)
    recommendation_explanation: str = Field(min_length=8, max_length=1000)
    recommendation_steps: list[str] = Field(min_length=1, max_length=4)
    action: RemediationAction
    target: str = ""
    reason: str
    human_checkpoint: str = ""

    def as_text(self) -> str:
        """Render the structured report as readable paragraphs."""
        rendered_steps = "\n".join(f"- {step}" for step in self.recommendation_steps)
        return (
            f"{self.headline}\n\n"
            f"{self.potential_impact}\n\n"
            f"{self.evidence_summary}\n\n"
            f"Recommended action: {self.recommended_action}\n\n"
            f"Technical summary: {self.technical_summary}\n\n"
            f"What happened: {self.what_happened}\n\n"
            f"What remains unknown: {self.what_is_unknown}\n\n"
            f"Why it matters: {self.why_it_matters}\n\n"
            f"Recommendation: {self.recommendation_title}\n"
            f"{self.recommendation_explanation}\n{rendered_steps}"
        )


class SecurityProfileContext(TypedDict):
    """Application-owned profile data attached after Qwen selects a valid ID."""

    id: str
    name: str
    reference_ids: list[str]


class SecAiState(TypedDict, total=False):
    """Shared LangGraph state passed between SecAi's three roles."""

    event: dict[str, Any]
    job_id: int
    investigation: InvestigationDecision
    security_profile: SecurityProfileContext
    review: ReviewDecision
    response: IncidentResponse
    incident: dict[str, Any] | None
