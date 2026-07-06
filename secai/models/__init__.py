from typing import Any, Literal
from pydantic import BaseModel, Field


IngestSource = Literal["browser", "alibaba_sls", "alibaba_waf", "demo"]
Severity = Literal["low", "medium", "high", "critical"]
RemediationAction = Literal[
    "monitor",
    "notify_admin",
    "block_ip",
    "block_ip_range",
    "rate_limit_ip",
    "rate_limit_route",
    "block_payload_pattern",
    "virtual_patch",
    "read_only_route",
    "challenge_route",
    "enable_anti_scan",
    "disable_route",
]
AutopilotEnforcementMode = Literal["observe_only", "waf_enforced"]
REPORTING_ACTIONS = {"monitor", "notify_admin"}
WAF_REMEDIATION_ACTIONS = {
    "block_ip",
    "block_ip_range",
    "rate_limit_ip",
    "rate_limit_route",
    "block_payload_pattern",
    "virtual_patch",
    "read_only_route",
    "challenge_route",
    "enable_anti_scan",
    "disable_route",
}


class SiteCreate(BaseModel):
    """Request body for creating a monitored website."""

    name: str = Field(min_length=1, max_length=120)
    owner_email: str | None = None


class SiteOut(BaseModel):
    """Response body for a created website and its ingest key."""

    site_id: str
    name: str
    ingest_key: str


class AuthSignupIn(BaseModel):
    """Request body for creating a website owner account."""

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=256)


class AuthLoginIn(BaseModel):
    """Request body for logging in a website owner."""

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class AuthOut(BaseModel):
    """Authenticated owner session returned by signup and login."""

    token: str
    user: dict[str, Any]


class PublicSetupIn(BaseModel):
    """Public setup request for creating a protected website."""

    website_name: str = Field(min_length=1, max_length=120)
    watch_method: Literal["browser", "alibaba_autopilot"] = "browser"
    report_channels: list[Literal["dashboard", "discord"]] = Field(min_length=1)
    dashboard_email: str | None = Field(default=None, max_length=254)
    dashboard_password: str | None = Field(default=None, max_length=256)
    sls_endpoint: str | None = Field(default=None, max_length=300)
    sls_project: str | None = Field(default=None, max_length=160)
    sls_logstore: str | None = Field(default=None, max_length=160)
    sls_role_arn: str | None = Field(default=None, max_length=400)
    sls_external_id: str | None = Field(default=None, max_length=160)
    alibaba_region: str | None = Field(default=None, max_length=80)
    waf_instance_id: str | None = Field(default=None, max_length=180)
    waf_domain: str | None = Field(default=None, max_length=255)
    automatic_actions: list[RemediationAction] = Field(default_factory=list)


class EventIn(BaseModel):
    """Incoming security event sent by the browser snippet, Alibaba SLS, or demo."""

    site_id: str
    source: IngestSource = "browser"
    event_type: str = "http_request"
    method: str | None = None
    path: str | None = None
    query: str | None = None
    status_code: int | None = None
    ip: str | None = None
    user_agent: str | None = None
    payload: str | None = None
    signals: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EventOut(EventIn):
    """Stored event response with database ID and timestamp."""

    id: int
    created_at: str


class RemediationProposal(BaseModel):
    """Simple public shape for a proposed remediation action."""

    action: RemediationAction
    target: str
    reason: str
    requires_approval: bool = True


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


class ApprovalIn(BaseModel):
    """Request body for approving or rejecting remediation."""

    approved_by: str = "demo-user"
    note: str | None = None


class SlsPullIn(BaseModel):
    """Request body for pulling logs from Alibaba Simple Log Service."""

    site_id: str
    ingest_key: str
    query: str = "*"
    minutes: int = Field(default=15, ge=1, le=1440)
    limit: int = Field(default=100, ge=1, le=1000)


class AlibabaSlsConfigIn(BaseModel):
    """Request body for saving Alibaba Simple Log Service settings for a site."""

    endpoint: str = Field(min_length=3, max_length=300)
    project: str = Field(min_length=1, max_length=160)
    logstore: str = Field(min_length=1, max_length=160)
    role_arn: str = Field(min_length=1, max_length=400)
    external_id: str = Field(min_length=1, max_length=160)


class AlibabaAutopilotConfigIn(BaseModel):
    """Request body for no-code Alibaba Cloud Autopilot setup."""

    role_arn: str = Field(min_length=1, max_length=400)
    external_id: str | None = Field(default=None, max_length=160)
    region: str = Field(default="ap-southeast-1", min_length=1, max_length=80)
    enforcement_mode: AutopilotEnforcementMode = "observe_only"
    waf_instance_id: str | None = Field(default=None, max_length=180)
    waf_domain: str | None = Field(default=None, max_length=255)
    sls_endpoint: str | None = Field(default=None, max_length=300)
    sls_project: str | None = Field(default=None, max_length=160)
    sls_logstore: str | None = Field(default=None, max_length=160)


class AlibabaSlsPullIn(BaseModel):
    """Request body for pulling logs from a saved Alibaba SLS connection."""

    query: str = 'status >= 400 or " OR " or "union select" or "../" or "<script" or "javascript:"'
    minutes: int = Field(default=15, ge=1, le=1440)
    limit: int = Field(default=100, ge=1, le=1000)


class RemediationPreferenceIn(BaseModel):
    """Request body for choosing whether an action can run automatically."""

    action: RemediationAction
    requires_approval: bool = True
