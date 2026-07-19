from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

IngestSource = Literal["browser", "alibaba_sls"]
EvidenceSource = Literal["browser", "alibaba_autopilot"]
Severity = Literal["low", "medium", "high", "critical"]
RemediationAction = Literal[
    "monitor",
    "notify_admin",
    "block_ip",
]
AutopilotEnforcementMode = Literal["observe_only", "security_group"]
REPORTING_ACTIONS = {"monitor", "notify_admin"}
SECURITY_GROUP_REMEDIATION_ACTIONS = {
    "block_ip",
}


class ApiInput(BaseModel):
    """Reject unknown request fields instead of silently accepting stale clients."""

    model_config = ConfigDict(extra="forbid")


class SiteCreate(ApiInput):
    """Request body for creating a monitored website."""

    name: str = Field(min_length=1, max_length=120)
    evidence_source: EvidenceSource


class SiteOut(BaseModel):
    """Response body for a created website and its ingest key."""

    site_id: str
    name: str
    ingest_key: str
    evidence_source: EvidenceSource


class AuthSignupIn(ApiInput):
    """Request body for creating a website owner account."""

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=256)


class AuthLoginIn(ApiInput):
    """Request body for logging in a website owner."""

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class AuthOut(BaseModel):
    """Authenticated owner session returned by signup and login."""

    token: str
    user: dict[str, Any]


class PublicSetupIn(ApiInput):
    """Public setup request for creating a protected website."""

    website_name: str = Field(min_length=1, max_length=120)
    watch_method: EvidenceSource
    report_channels: list[Literal["dashboard", "discord"]] = Field(min_length=1)
    dashboard_email: str | None = Field(default=None, max_length=254)
    dashboard_password: str | None = Field(default=None, max_length=256)


class EventIn(ApiInput):
    """Normalized security event accepted by an evidence-source boundary."""

    site_id: str = Field(min_length=1, max_length=160)
    source: IngestSource = "browser"
    event_type: str = Field(default="http_request", min_length=1, max_length=120)
    method: str | None = Field(default=None, max_length=16)
    path: str | None = Field(default=None, max_length=2000)
    query: str | None = Field(default=None, max_length=4000)
    status_code: int | None = None
    ip: str | None = Field(default=None, max_length=80)
    user_agent: str | None = Field(default=None, max_length=1000)
    payload: str | None = Field(default=None, max_length=4000)
    signals: list[str] = Field(default_factory=list, max_length=30)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentEvidenceOut(BaseModel):
    """Concrete evidence fields rendered in an incident report."""

    observed_at: str | None = None
    source: str | None = None
    ip: str | None = None
    method: str | None = None
    path: str | None = None
    status_code: int | None = None
    signals: list[str] = Field(default_factory=list)
    event_type: str | None = None


class ProtectionPolicyOut(BaseModel):
    """Execution state for an owner-approved protective action."""

    status: str
    provider: str | None = None
    provider_rule_id: str | None = None
    error_message: str | None = None
    expires_at: str | None = None
    target: str | None = None
    action: str | None = None


class IncidentOut(BaseModel):
    """Incident response returned by the API and dashboard."""

    id: int
    site_id: str
    title: str
    severity: Severity
    status: str
    attack_type: str
    affected_route: str | None = None
    confidence: float
    report: str
    recommended_action: dict[str, Any]
    created_at: str
    updated_at: str
    execution_status: str = "not_required"
    active_policy: bool = False
    evidence: list[IncidentEvidenceOut] = Field(default_factory=list)
    policy: ProtectionPolicyOut | None = None


class ApprovalIn(ApiInput):
    """Request body for approving or rejecting remediation."""

    note: str | None = Field(default=None, max_length=1000)


class AlibabaAutopilotConfigIn(ApiInput):
    """Request body for no-code Alibaba Cloud Autopilot setup."""

    region: str = Field(default="ap-southeast-1", min_length=1, max_length=80)
    ecs_instance_id: str = Field(min_length=3, max_length=180)
    enforcement_mode: AutopilotEnforcementMode = "observe_only"
    security_group_id: str | None = Field(default=None, max_length=180)
    sls_endpoint: str | None = Field(default=None, max_length=300)
    sls_project: str | None = Field(default=None, max_length=160)
    sls_logstore: str | None = Field(default=None, max_length=160)


class AlibabaConnectionVerifyIn(ApiInput):
    """Customer RAM role to verify for one website connection."""

    role_arn: str = Field(min_length=20, max_length=300)
    region: str = Field(default="ap-southeast-1", min_length=1, max_length=80)


class AlibabaResourceDiscoveryIn(ApiInput):
    """Region to inspect through a website's verified customer RAM role."""

    region: str = Field(default="ap-southeast-1", min_length=1, max_length=80)


class AlibabaSlsPullIn(ApiInput):
    """Request body for pulling logs from a saved Alibaba SLS connection."""

    query: str = 'status >= 400 or " OR " or "union select" or "../" or "<script" or "javascript:"'
    minutes: int = Field(default=15, ge=1, le=1440)
    limit: int = Field(default=100, ge=1, le=1000)
