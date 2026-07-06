import type {
  AlibabaAutopilotTemplate,
  AlibabaSlsConfig,
  AlibabaSlsPullResult,
  AutopilotStatus,
  AuthResult,
  Incident,
  RemediationPreference,
  PublicSetupResult,
  Session,
  Site,
  UsageSummary,
} from "./types";

type RequestOptions = {
  method?: "GET" | "POST" | "PUT";
  body?: unknown;
  auth?: boolean;
};

export async function apiRequest<T>(
  apiBase: string,
  path: string,
  options: RequestOptions = {},
  token?: string,
): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (options.auth !== false && token) {
    headers.Authorization = `Bearer ${token}`;
  }

  let response: Response;
  try {
    response = await fetch(`${apiBase}${path}`, {
      method: options.method ?? "GET",
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
  } catch (error) {
    throw new Error(`Could not reach SecAi API at ${apiBase}. Make sure the backend is running and the API address is correct.`);
  }

  if (!response.ok) {
    const fallback = `${response.status} ${response.statusText}`;
    try {
      const payload = (await response.json()) as { detail?: string };
      throw new Error(payload.detail || fallback);
    } catch (error) {
      if (error instanceof Error && error.message !== fallback) throw error;
      throw new Error(fallback);
    }
  }

  return response.json() as Promise<T>;
}

export function signup(apiBase: string, email: string, password: string) {
  return apiRequest<AuthResult>(apiBase, "/api/auth/signup", {
    method: "POST",
    body: { email, password },
    auth: false,
  });
}

export function login(apiBase: string, email: string, password: string) {
  return apiRequest<AuthResult>(apiBase, "/api/auth/login", {
    method: "POST",
    body: { email, password },
    auth: false,
  });
}

export function setupWebsite(
  apiBase: string,
  body: {
    website_name: string;
    watch_method: "browser" | "alibaba_autopilot";
    report_channels: string[];
    dashboard_email?: string;
    dashboard_password?: string;
    sls_endpoint?: string;
    sls_project?: string;
    sls_logstore?: string;
    sls_role_arn?: string;
    sls_external_id?: string;
    alibaba_region?: string;
    waf_instance_id?: string;
    waf_domain?: string;
    automatic_actions: string[];
  },
) {
  return apiRequest<PublicSetupResult>(apiBase, "/api/setup/website", {
    method: "POST",
    body,
    auth: false,
  });
}

export function getAlibabaAutopilotTemplate(
  apiBase: string,
  externalId: string,
  region: string,
  roleName = "secai-autopilot",
  wafInstanceId = "",
  slsEndpoint = "",
  slsProject = "",
  slsLogstore = "",
) {
  const query = new URLSearchParams({
    external_id: externalId,
    region,
    role_name: roleName,
  });
  if (wafInstanceId) query.set("waf_instance_id", wafInstanceId);
  if (slsEndpoint) query.set("sls_endpoint", slsEndpoint);
  if (slsProject) query.set("sls_project", slsProject);
  if (slsLogstore) query.set("sls_logstore", slsLogstore);
  return apiRequest<AlibabaAutopilotTemplate>(
    apiBase,
    `/api/setup/alibaba-autopilot-template?${query.toString()}`,
    { auth: false },
  );
}

export function logout(session: Session) {
  return apiRequest(session.apiBase, "/api/auth/logout", { method: "POST" }, session.token);
}

export function me(apiBase: string, token: string) {
  return apiRequest<{ user: Session["user"] }>(apiBase, "/api/auth/me", {}, token);
}

export function listSites(session: Session) {
  return apiRequest<{ sites: Site[] }>(session.apiBase, "/api/sites", {}, session.token);
}

export function createSite(session: Session, name: string) {
  return apiRequest<Site>(
    session.apiBase,
    "/api/sites",
    {
      method: "POST",
      body: { name },
    },
    session.token,
  );
}

export function listIncidents(session: Session, siteId?: string) {
  const query = siteId ? `?site_id=${encodeURIComponent(siteId)}` : "";
  return apiRequest<Incident[]>(session.apiBase, `/api/incidents${query}`, {}, session.token);
}

export function approveIncident(session: Session, incidentId: number) {
  return apiRequest(
    session.apiBase,
    `/api/incidents/${incidentId}/approve`,
    {
      method: "POST",
      body: { approved_by: session.user.email, note: "Approved from SecAi dashboard" },
    },
    session.token,
  );
}

export function rejectIncident(session: Session, incidentId: number) {
  return apiRequest(
    session.apiBase,
    `/api/incidents/${incidentId}/reject`,
    {
      method: "POST",
      body: { approved_by: session.user.email, note: "Rejected from SecAi dashboard" },
    },
    session.token,
  );
}

export function runDemo(session: Session, site: Site) {
  return apiRequest(
    session.apiBase,
    `/api/demo/simulate?attack=sql_injection&site_id=${encodeURIComponent(site.site_id)}&ingest_key=${encodeURIComponent(
      site.ingest_key,
    )}`,
    { method: "POST", auth: false },
  );
}

export function qwenUsage(session: Session) {
  return apiRequest<{ summary: UsageSummary }>(session.apiBase, "/api/qwen/usage", {}, session.token);
}

export function getRemediationPreferences(session: Session, siteId: string) {
  return apiRequest<{ preferences: RemediationPreference[] }>(
    session.apiBase,
    `/api/sites/${siteId}/remediation-preferences`,
    {},
    session.token,
  );
}

export function setRemediationPreference(session: Session, siteId: string, action: string, requiresApproval: boolean) {
  return apiRequest<{ preference: RemediationPreference }>(
    session.apiBase,
    `/api/sites/${siteId}/remediation-preferences`,
    {
      method: "PUT",
      body: { action, requires_approval: requiresApproval },
    },
    session.token,
  );
}

export function getAlibabaSlsConfig(session: Session, siteId: string) {
  return apiRequest<{ configured: boolean; config: AlibabaSlsConfig | null }>(
    session.apiBase,
    `/api/sites/${siteId}/alibaba-sls`,
    {},
    session.token,
  );
}

export function saveAlibabaSlsConfig(
  session: Session,
  siteId: string,
  body: {
    endpoint: string;
    project: string;
    logstore: string;
    role_arn: string;
    external_id: string;
  },
) {
  return apiRequest<{ config: AlibabaSlsConfig }>(
    session.apiBase,
    `/api/sites/${siteId}/alibaba-sls`,
    { method: "PUT", body },
    session.token,
  );
}

export function pullAlibabaSlsLogs(session: Session, siteId: string, query: string, minutes: number, limit: number) {
  return apiRequest<AlibabaSlsPullResult>(
    session.apiBase,
    `/api/sites/${siteId}/alibaba-sls/pull`,
    {
      method: "POST",
      body: { query, minutes, limit },
    },
    session.token,
  );
}

export function getAutopilotStatus(session: Session, siteId: string) {
  return apiRequest<AutopilotStatus>(
    session.apiBase,
    `/api/sites/${siteId}/autopilot-status`,
    {},
    session.token,
  );
}

export function saveAlibabaAutopilotConfig(
  session: Session,
  siteId: string,
  body: {
    role_arn: string;
    external_id?: string;
    region: string;
    enforcement_mode: "observe_only" | "waf_enforced";
    waf_instance_id?: string;
    waf_domain?: string;
    sls_endpoint?: string;
    sls_project?: string;
    sls_logstore?: string;
  },
) {
  return apiRequest<{ status: AutopilotStatus }>(
    session.apiBase,
    `/api/sites/${siteId}/alibaba-autopilot`,
    { method: "PUT", body },
    session.token,
  );
}
