export type User = {
  id: number;
  email: string;
  created_at: string;
};

export type Site = {
  site_id: string;
  name: string;
  evidence_source: "browser" | "alibaba_autopilot";
  owner_email?: string | null;
  ingest_key: string;
  created_at?: string;
};

export type RecommendedAction = {
  action: "monitor" | "notify_admin" | "block_ip";
  target?: string;
  reason?: string;
  report_sections: {
    owner_summary: {
      title: string;
      potential_impact: string;
      evidence: string;
      recommended_action: string;
    };
    summary: string;
    what_happened: string;
    what_is_unknown: string;
    why_it_matters: string;
  };
  owner_recommendation: {
    title: string;
    explanation: string;
    steps: string[];
  };
  protection_status: {
    state: "approval_required" | "unavailable" | "not_authorized" | "not_proposed";
    title: string;
    explanation: string;
  };
  requires_approval?: boolean;
  duration_seconds?: number;
  evidence_used?: string[];
  source_event_id?: number;
  agent_trace?: AgentTraceStep[];
  [key: string]: unknown;
};

export type AgentTraceStep = {
  agent: string;
  decision: string;
  summary: string;
  tools?: string[];
  security_reference_ids?: string[];
};

export type IncidentEvidence = {
  observed_at?: string | null;
  created_at?: string | null;
  source?: string | null;
  ip?: string | null;
  method?: string | null;
  path?: string | null;
  status_code?: number | null;
  signals?: string[];
  event_type?: string | null;
};

export type ProtectionPolicy = {
  status: "not_required" | "not_started" | "pending" | "applying" | "active" | "revoking" | "revoked" | "expired" | "failed";
  provider_rule_id?: string | null;
  error_message?: string | null;
  expires_at?: string | null;
  target?: string | null;
  action?: string | null;
};

export type Incident = {
  id: number;
  site_id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  status: string;
  attack_type: string;
  affected_route?: string | null;
  confidence: number;
  report: string;
  recommended_action: RecommendedAction;
  created_at: string;
  updated_at: string;
  execution_status: "not_required" | "not_started" | "pending" | "applying" | "active" | "revoking" | "revoked" | "expired" | "failed";
  active_policy: boolean;
  evidence?: IncidentEvidence[];
  policy?: ProtectionPolicy | null;
};

export type AnalysisJob = {
  id: number;
  site_id: string;
  status: "queued" | "running" | "failed" | "incident_created" | "no_incident";
  current_step?: string | null;
  error?: string | null;
  incident_id?: number | null;
  attempt_count: number;
  created_at: string;
  updated_at?: string;
  evidence?: IncidentEvidence[];
  event?: IncidentEvidence | null;
};

export type Session = {
  apiBase: string;
  token: string;
  user: User;
};

export type AuthResult = {
  token: string;
  user: User;
};

export type AlibabaAutopilotConfig = {
  site_id: string;
  role_arn?: string | null;
  external_id: string;
  account_id?: string | null;
  connection_status: "pending" | "verified" | "error";
  connection_error?: string | null;
  verified_at?: string | null;
  region: string;
  security_group_id?: string | null;
  sls_endpoint?: string | null;
  sls_project?: string | null;
  sls_logstore?: string | null;
  ecs_instance_id?: string | null;
  collector_status: "not_configured" | "pending" | "verified" | "error";
  collector_error?: string | null;
  collector_machine_group?: string | null;
  collector_config_name?: string | null;
  collector_create_index: boolean;
  collector_verified_at?: string | null;
  enforcement_mode: "observe_only" | "security_group";
  created_at: string;
  updated_at: string;
};

export type AlibabaLogSource = {
  endpoint: string;
  project: string;
  logstore: string;
  label: string;
};

export type AlibabaSecurityGroup = {
  security_group_id: string;
  name: string;
  description: string;
  vpc_id: string;
  ecs_count: number;
  dedicated: boolean;
};

export type AlibabaEcsInstance = {
  instance_id: string;
  name: string;
  status: string;
  os_type: string;
  private_ip: string;
  security_group_ids: string[];
  label: string;
};

export type AlibabaDiscoveredResources = {
  region: string;
  sls_endpoint: string;
  log_sources: AlibabaLogSource[];
  security_groups: AlibabaSecurityGroup[];
  instances: AlibabaEcsInstance[];
  warnings: string[];
};

export type RemediationExecution = {
  id: number;
  site_id: string;
  policy_id?: number | null;
  incident_id?: number | null;
  provider: string;
  action: string;
  target: string;
  status: string;
  provider_rule_id?: string | null;
  error_message?: string | null;
  created_at: string;
};

export type AutopilotStatus = {
  site_id: string;
  configured: boolean;
  connection_status: "not_connected" | "pending" | "verified" | "error";
  collector_status: "not_configured" | "pending" | "verified" | "error";
  collector_connected: boolean;
  logs_connected: boolean;
  security_group_connected: boolean;
  autopilot_active: boolean;
  enforcement_mode: "observe_only" | "security_group";
  available_actions: string[];
  config: AlibabaAutopilotConfig | null;
  authorization: AlibabaAuthorization | null;
  collector_setup: AlibabaCollectorSetup | null;
  last_execution: RemediationExecution | null;
  failed_executions: RemediationExecution[];
};

export type AlibabaCollectorSetup = {
  status: "not_configured" | "pending" | "verified" | "error";
  error?: string | null;
  instance_id: string;
  machine_group: string;
  config_name: string;
  ros_template: Record<string, unknown>;
};

export type AlibabaAuthorization = {
  provider_role_arn: string;
  external_id: string;
  role_name: string;
  trust_policy: Record<string, unknown>;
  permission_policy: Record<string, unknown>;
  ros_template: Record<string, unknown>;
};

export type AlibabaSlsPullResult = {
  events_seen: number;
  events_ingested: number;
  groups_seen: number;
  groups_created: number;
  groups_deduplicated: number;
  groups_filtered: number;
  duplicates_skipped: number;
  incidents_created: number;
  incidents: Incident[];
  jobs_queued: number;
};

export type PublicSetupResult = {
  site: Site;
  session: AuthResult | null;
  channels: string[];
  messaging_setup: { channel: "discord"; setup_code: string; invite_url: string; expires_at: string }[];
  selected_evidence_source: "browser" | "alibaba_autopilot";
  snippet: string | null;
};

export type DiscordSetup = {
  channel: "discord";
  setup_code: string;
  invite_url: string;
  expires_at: string;
};
