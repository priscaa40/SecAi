export type User = {
  id: number;
  email: string;
  created_at: string;
};

export type Site = {
  site_id: string;
  name: string;
  owner_email?: string | null;
  ingest_key: string;
  created_at?: string;
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
  recommended_action: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type UsageSummary = {
  calls: number;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  estimated_cost_usd: number;
  avg_latency_ms: number;
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

export type AlibabaSlsConfig = {
  site_id: string;
  endpoint: string;
  project: string;
  logstore: string;
  role_arn: string;
  external_id: string;
  created_at: string;
  updated_at: string;
};

export type AlibabaAutopilotConfig = {
  site_id: string;
  role_arn: string;
  external_id: string;
  region: string;
  waf_instance_id?: string | null;
  waf_domain?: string | null;
  sls_endpoint?: string | null;
  sls_project?: string | null;
  sls_logstore?: string | null;
  enforcement_mode: "observe_only" | "waf_enforced";
  created_at: string;
  updated_at: string;
};

export type AlibabaAutopilotTemplate = {
  external_id: string;
  role_name: string;
  role_arn_hint: string;
  waf_instance_id: string;
  sls_endpoint: string;
  sls_project: string;
  sls_logstore: string;
  region: string;
  console_url: string;
  quick_create_url: string;
  template_url: string;
  console_url_alibabacloud: string;
  console_url_aliyun: string;
  principal: string;
  principal_configured: boolean;
  trust_policy: Record<string, unknown>;
  permission_policy: Record<string, unknown>;
  template: Record<string, unknown>;
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
  error_message?: string | null;
  created_at: string;
};

export type AutopilotStatus = {
  site_id: string;
  configured: boolean;
  logs_connected: boolean;
  waf_connected: boolean;
  autopilot_active: boolean;
  enforcement_mode: "observe_only" | "waf_enforced";
  available_actions: string[];
  config: AlibabaAutopilotConfig | null;
  last_execution: RemediationExecution | null;
  failed_executions: RemediationExecution[];
};

export type AlibabaSlsPullResult = {
  events_seen: number;
  events_ingested: number;
  duplicates_skipped: number;
  incidents_created: number;
  incidents: Incident[];
};

export type RemediationPreference = {
  site_id: string;
  action: string;
  requires_approval: boolean;
  updated_at: string;
};

export type PublicSetupResult = {
  site: Site;
  session: AuthResult | null;
  channels: string[];
  messaging_setup: { channel: "discord"; setup_code: string }[];
  snippet: string;
};
