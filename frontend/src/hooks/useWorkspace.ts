import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";

import {
  approveIncident,
  createSite,
  getAutopilotStatus,
  listAnalysisJobs,
  listIncidents,
  listSites,
  rejectIncident,
  removeIncidentProtection,
  reapplyIncidentProtection,
  retryAnalysisJob,
  retryIncidentProtection,
} from "../api";
import { ACTIVE_JOB_STATUSES } from "../components/incidentPresentation";
import type { AnalysisJob, AutopilotStatus, Incident, Session, Site } from "../types";

export const WORKSPACE_READY = "Your reports are up to date.";
const DASHBOARD_POLL_INTERVAL_MS = 30_000;
const ACTIVE_INVESTIGATION_POLL_INTERVAL_MS = 2_000;

export function useWorkspace(session: Session | null) {
  const [sites, setSites] = useState<Site[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [analysisJobs, setAnalysisJobs] = useState<AnalysisJob[]>([]);
  const hasActiveInvestigation = analysisJobs.some((job) => ACTIVE_JOB_STATUSES.has(job.status));
  const hasActiveAction = incidents.some((incident) => ["queued", "running"].includes(incident.action_job?.status || ""));
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null);
  const [selectedSiteId, setSelectedSiteId] = useState("");
  const [siteName, setSiteName] = useState("");
  const [siteEvidenceSource, setSiteEvidenceSource] = useState<Site["evidence_source"]>("browser");
  const [autopilotStatus, setAutopilotStatus] = useState<AutopilotStatus | null>(null);
  const [status, setStatus] = useState(WORKSPACE_READY);
  const [busy, setBusy] = useState(false);
  const loadVersion = useRef(0);
  const siteChangeVersion = useRef(0);

  const selectedSite = useMemo(
    () => sites.find((site) => site.site_id === selectedSiteId) || sites[0] || null,
    [sites, selectedSiteId],
  );

  const selectedIncident = useMemo(
    () => incidents.find((incident) => incident.id === selectedIncidentId)
      || incidents.find((incident) => incident.status === "needs_review")
      || incidents[0]
      || null,
    [incidents, selectedIncidentId],
  );

  useEffect(() => {
    if (!session || !selectedSite) {
      setAutopilotStatus(null);
      return undefined;
    }
    let current = true;
    const activeSession = session;
    const siteId = selectedSite.site_id;
    setAutopilotStatus(null);
    void getAutopilotStatus(activeSession, siteId)
      .then((result) => {
        if (current) setAutopilotStatus(result);
      })
      .catch((error) => {
        if (!current) return;
        setAutopilotStatus(null);
        setStatus(error instanceof Error ? error.message : "We could not load this website's protection settings.");
      });
    return () => {
      current = false;
    };
  }, [session, selectedSite]);

  useEffect(() => {
    if (!session || !selectedSiteId) return undefined;
    let current = true;
    const refreshActivity = () => {
      if (document.visibilityState !== "visible") return;
      void Promise.all([listIncidents(session, selectedSiteId), listAnalysisJobs(session, selectedSiteId)])
        .then(([incidentResult, jobResult]) => {
          if (!current) return;
          setIncidents(incidentResult);
          setAnalysisJobs(jobResult.jobs);
          setSelectedIncidentId((current) => current
            || incidentResult.find((item) => item.status === "needs_review")?.id
            || incidentResult[0]?.id
            || null);
        })
        .catch(() => undefined);
    };
    const refreshWhenVisible = () => {
      if (document.visibilityState === "visible") refreshActivity();
    };
    const timer = window.setInterval(
      refreshActivity,
      hasActiveInvestigation || hasActiveAction ? ACTIVE_INVESTIGATION_POLL_INTERVAL_MS : DASHBOARD_POLL_INTERVAL_MS,
    );
    document.addEventListener("visibilitychange", refreshWhenVisible);
    return () => {
      current = false;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
    };
  }, [session, selectedSiteId, hasActiveInvestigation, hasActiveAction]);

  async function loadWorkspace(activeSession = session, preferredSiteId = selectedSiteId) {
    if (!activeSession) return;
    const version = ++loadVersion.current;
    siteChangeVersion.current += 1;
    setBusy(true);
    setStatus("Checking for new security activity…");
    try {
      const siteResult = await listSites(activeSession);
      const nextSiteId = siteResult.sites.some((site) => site.site_id === preferredSiteId)
        ? preferredSiteId
        : siteResult.sites[0]?.site_id || "";
      const [incidentResult, jobResult] = await Promise.all([
        listIncidents(activeSession, nextSiteId || undefined),
        nextSiteId ? listAnalysisJobs(activeSession, nextSiteId) : Promise.resolve({ jobs: [] }),
      ]);
      if (loadVersion.current !== version) return;
      setSites(siteResult.sites);
      setSelectedSiteId(nextSiteId);
      setIncidents(incidentResult);
      setAnalysisJobs(jobResult.jobs);
      setSelectedIncidentId((current) => current && incidentResult.some((item) => item.id === current)
        ? current
        : incidentResult.find((item) => item.status === "needs_review")?.id || incidentResult[0]?.id || null);
      setStatus(WORKSPACE_READY);
    } catch (error) {
      if (loadVersion.current !== version) return;
      setStatus(error instanceof Error ? error.message : "We could not refresh your reports.");
    } finally {
      if (loadVersion.current === version) setBusy(false);
    }
  }

  function clearWorkspace() {
    loadVersion.current += 1;
    siteChangeVersion.current += 1;
    setSites([]);
    setIncidents([]);
    setAnalysisJobs([]);
    setSelectedSiteId("");
    setSelectedIncidentId(null);
    setAutopilotStatus(null);
    setSiteName("");
    setSiteEvidenceSource("browser");
    setStatus(WORKSPACE_READY);
    setBusy(false);
  }

  async function handleCreateSite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!session || !siteName.trim()) return false;
    setBusy(true);
    try {
      const site = await createSite(session, siteName.trim(), siteEvidenceSource);
      setSiteName("");
      setSiteEvidenceSource("browser");
      setSelectedSiteId(site.site_id);
      await loadWorkspace(session, site.site_id);
      return true;
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "We could not add this website.");
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function handleSiteChange(siteId: string) {
    if (!session) return;
    loadVersion.current += 1;
    const version = ++siteChangeVersion.current;
    setBusy(true);
    setAutopilotStatus(null);
    setSelectedSiteId(siteId);
    try {
      const [incidentResult, jobResult] = await Promise.all([
        listIncidents(session, siteId),
        listAnalysisJobs(session, siteId),
      ]);
      if (siteChangeVersion.current !== version) return;
      setIncidents(incidentResult);
      setAnalysisJobs(jobResult.jobs);
      setSelectedIncidentId(incidentResult.find((item) => item.status === "needs_review")?.id || incidentResult[0]?.id || null);
    } catch (error) {
      if (siteChangeVersion.current !== version) return;
      setStatus(error instanceof Error ? error.message : "We could not load this website's reports.");
    } finally {
      if (siteChangeVersion.current === version) setBusy(false);
    }
  }

  async function handleDecision(action: "approve" | "reject", incidentId: number) {
    if (!session) return;
    setBusy(true);
    try {
      if (action === "approve") await approveIncident(session, incidentId);
      else await rejectIncident(session, incidentId);
      await loadWorkspace(session);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "We could not save your decision.");
    } finally {
      setBusy(false);
    }
  }

  async function handleProtection(action: "retry" | "remove" | "reapply", incidentId: number) {
    if (!session) return;
    setBusy(true);
    try {
      if (action === "retry") await retryIncidentProtection(session, incidentId);
      else if (action === "reapply") await reapplyIncidentProtection(session, incidentId);
      else await removeIncidentProtection(session, incidentId);
      await loadWorkspace(session);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "We could not update this protection.");
    } finally {
      setBusy(false);
    }
  }

  async function handleAnalysisRetry(jobId: number) {
    if (!session) return;
    setBusy(true);
    try {
      await retryAnalysisJob(session, jobId);
      await loadWorkspace(session);
      setStatus("The investigation is queued to run again.");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "We could not retry this investigation.");
    } finally {
      setBusy(false);
    }
  }

  return {
    sites,
    incidents,
    analysisJobs,
    selectedSite,
    selectedSiteId,
    selectedIncident,
    siteName,
    siteEvidenceSource,
    autopilotStatus,
    status,
    busy,
    setSiteName,
    setSiteEvidenceSource,
    setAutopilotStatus,
    setSelectedIncidentId,
    setStatus,
    setBusy,
    loadWorkspace,
    clearWorkspace,
    handleCreateSite,
    handleSiteChange,
    handleDecision,
    handleProtection,
    handleAnalysisRetry,
  };
}
