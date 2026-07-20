import type {
  AlibabaDiscoveredResources,
  AlibabaSlsPullResult,
  AnalysisJob,
  AutopilotStatus,
  AuthResult,
  DiscordSetup,
  Incident,
  PublicSetupResult,
  Session,
  Site,
} from "./types";

type RequestOptions = {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  body?: unknown;
  auth?: boolean;
  timeoutMs?: number;
};

export async function apiRequest<T>(
  apiBase: string,
  path: string,
  options: RequestOptions = {},
  token?: string,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (options.auth !== false && token) {
    headers.Authorization = `Bearer ${token}`;
  }

  let response: Response;
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), options.timeoutMs ?? 15000);
  try {
    response = await fetch(`${apiBase}${path}`, {
      method: options.method ?? "GET",
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("SecAi took too long to respond. Try again.");
    }
    throw new Error("SecAi is unavailable right now. Try again in a moment.");
  } finally {
    window.clearTimeout(timeout);
  }

  if (!response.ok) {
    const fallback = `${response.status} ${response.statusText}`;
    let detail = "";
    try {
      const payload = (await response.json()) as { detail?: string };
      detail = payload.detail || "";
    } catch {
      // The status code remains useful when a proxy returns a non-JSON error page.
    }
    throw new Error(detail || fallback);
  }

  return response.json() as Promise<T>;
}

export function analysisJob(session: Session, jobId: number) {
  return apiRequest<{ job: AnalysisJob; incident?: Incident | null }>(
    session.apiBase,
    `/api/analysis-jobs/${jobId}`,
    {},
    session.token,
  );
}

export function listAnalysisJobs(session: Session, siteId: string) {
  return apiRequest<{ jobs: AnalysisJob[] }>(
    session.apiBase,
    `/api/analysis-jobs?site_id=${encodeURIComponent(siteId)}`,
    {},
    session.token,
  );
}

export function retryAnalysisJob(session: Session, jobId: number) {
  return apiRequest<{ job: AnalysisJob }>(
    session.apiBase,
    `/api/analysis-jobs/${jobId}/retry`,
    { method: "POST" },
    session.token,
  );
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
  },
) {
  return apiRequest<PublicSetupResult>(apiBase, "/api/setup/website", {
    method: "POST",
    body,
    auth: false,
  });
}

export function discoverAlibabaResourcesForSite(session: Session, siteId: string, region: string) {
  return apiRequest<AlibabaDiscoveredResources>(
    session.apiBase,
    `/api/sites/${encodeURIComponent(siteId)}/alibaba-resources/discover`,
    {
      method: "POST",
      body: { region },
      timeoutMs: 30000,
    },
    session.token,
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

export function createSite(session: Session, name: string, evidenceSource: Site["evidence_source"]) {
  return apiRequest<Site>(
    session.apiBase,
    "/api/sites",
    {
      method: "POST",
      body: { name, evidence_source: evidenceSource },
    },
    session.token,
  );
}

export function createDiscordSetup(session: Session, siteId: string) {
  return apiRequest<DiscordSetup>(
    session.apiBase,
    `/api/sites/${encodeURIComponent(siteId)}/discord-setup`,
    { method: "POST" },
    session.token,
  );
}

export function listIncidents(session: Session, siteId?: string) {
  const query = siteId ? `?site_id=${encodeURIComponent(siteId)}` : "";
  return apiRequest<Incident[]>(session.apiBase, `/api/incidents${query}`, {}, session.token);
}

export function getIncident(session: Session, incidentId: number) {
  return apiRequest<Incident>(session.apiBase, `/api/incidents/${incidentId}`, {}, session.token);
}

export function approveIncident(session: Session, incidentId: number) {
  return apiRequest(
    session.apiBase,
    `/api/incidents/${incidentId}/approve`,
    {
      method: "POST",
      body: { note: "Approved from SecAi dashboard" },
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
      body: { note: "Rejected from SecAi dashboard" },
    },
    session.token,
  );
}

export function retryIncidentProtection(session: Session, incidentId: number) {
  return apiRequest(
    session.apiBase,
    `/api/incidents/${incidentId}/retry`,
    { method: "POST" },
    session.token,
  );
}

export function removeIncidentProtection(session: Session, incidentId: number) {
  return apiRequest(
    session.apiBase,
    `/api/incidents/${incidentId}/remove-protection`,
    { method: "POST" },
    session.token,
  );
}

export function reapplyIncidentProtection(session: Session, incidentId: number) {
  return apiRequest(
    session.apiBase,
    `/api/incidents/${incidentId}/reapply-protection`,
    { method: "POST" },
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

export function prepareAlibabaConnection(session: Session, siteId: string) {
  return apiRequest<AutopilotStatus>(
    session.apiBase,
    `/api/sites/${encodeURIComponent(siteId)}/alibaba-connection/prepare`,
    { method: "POST" },
    session.token,
  );
}

export function verifyAlibabaConnection(session: Session, siteId: string, roleArn: string, region: string) {
  return apiRequest<AutopilotStatus>(
    session.apiBase,
    `/api/sites/${encodeURIComponent(siteId)}/alibaba-connection/verify`,
    { method: "POST", body: { role_arn: roleArn, region }, timeoutMs: 30000 },
    session.token,
  );
}

export function disconnectAlibabaConnection(session: Session, siteId: string) {
  return apiRequest<AutopilotStatus>(
    session.apiBase,
    `/api/sites/${encodeURIComponent(siteId)}/alibaba-connection`,
    { method: "DELETE" },
    session.token,
  );
}

export function verifyAlibabaCollector(session: Session, siteId: string) {
  return apiRequest<{ status: AutopilotStatus; readiness: { logstore_queryable: boolean } }>(
    session.apiBase,
    `/api/sites/${encodeURIComponent(siteId)}/alibaba-collector/verify`,
    { method: "POST", timeoutMs: 30000 },
    session.token,
  );
}

export function prepareAlibabaCollectorTemplate(session: Session, siteId: string) {
  return apiRequest<{ status: AutopilotStatus; collector_setup: NonNullable<AutopilotStatus["collector_setup"]> }>(
    session.apiBase,
    `/api/sites/${encodeURIComponent(siteId)}/alibaba-collector/template`,
    { method: "POST", timeoutMs: 30000 },
    session.token,
  );
}

export function saveAlibabaAutopilotConfig(
  session: Session,
  siteId: string,
  body: {
    region: string;
    ecs_instance_id: string;
    enforcement_mode: "observe_only" | "security_group";
    security_group_id?: string;
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
