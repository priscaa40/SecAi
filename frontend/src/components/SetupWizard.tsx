import { ArrowRight, CheckCircle2, MessageCircle } from "lucide-react";
import { useState } from "react";

import { setupWebsite } from "../api";
import type { Session } from "../types";
import { AlertsStep, EvidenceSourceStep, WizardCard, type SetupDraft } from "./SetupWizardSteps";

const initialDraft: SetupDraft = {
  websiteName: "",
  watchMethod: "alibaba_autopilot",
  channels: ["dashboard"],
  dashboardEmail: localStorage.getItem("secai.email") || "",
  dashboardPassword: "",
};

export function SetupWizard({
  apiBase,
  onSession,
}: {
  apiBase: string;
  onSession: (session: Session) => void;
}) {
  const [step, setStep] = useState(0);
  const [draft, setDraft] = useState<SetupDraft>(initialDraft);
  const [createdSnippet, setCreatedSnippet] = useState("");
  const [messagingSetup, setMessagingSetup] = useState<
    { channel: "discord"; setup_code: string; invite_url: string; expires_at: string }[]
  >([]);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [pendingSession, setPendingSession] = useState<Session | null>(null);
  const steps = ["Your website", "Evidence source", "Alerts", "Finish"];

  function patch(next: Partial<SetupDraft>) {
    setDraft((current) => ({ ...current, ...next }));
  }

  function toggleChannel(channel: string) {
    const next = draft.channels.includes(channel)
      ? draft.channels.filter((item) => item !== channel)
      : draft.channels.concat(channel);
    if (next.length) patch({ channels: next });
  }

  function canContinue() {
    if (step === 0) return draft.websiteName.trim().length > 0;
    if (step === 1) {
      return true;
    }
    if (step === 2) {
      if (draft.watchMethod === "alibaba_autopilot" && !draft.channels.includes("dashboard")) return false;
      if (draft.channels.includes("dashboard") && (!draft.dashboardEmail || draft.dashboardPassword.length < 8)) return false;
      return draft.channels.length > 0;
    }
    return true;
  }

  async function finishSetup() {
    setBusy(true);
    setMessage("Creating your SecAi workspace…");
    try {
      const base = apiBase.replace(/\/$/, "");
      const result = await setupWebsite(base, {
        website_name: draft.websiteName,
        watch_method: draft.watchMethod,
        report_channels: draft.channels,
        dashboard_email: draft.channels.includes("dashboard") ? draft.dashboardEmail : undefined,
        dashboard_password: draft.channels.includes("dashboard") ? draft.dashboardPassword : undefined,
      });
      setCreatedSnippet(
        result.snippet.startsWith("http")
          ? result.snippet
          : `<script src="${base}/api/integrations/browser.js?site_id=${result.site.site_id}"></script>`,
      );
      setMessagingSetup(result.messaging_setup || []);
      setMessage("Your SecAi workspace is ready.");
      if (result.session) {
        setPendingSession({ apiBase: base, token: result.session.token, user: result.session.user });
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "We could not finish setup. Check the details and try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="wizard-shell">
      <div className="wizard-progress">
        {steps.map((label, index) => (
          <span key={label} aria-current={index === step ? "step" : undefined} className={index === step ? "active" : index < step ? "done" : ""}>
            {index + 1}. {label}
          </span>
        ))}
      </div>

      {step === 0 ? (
        <WizardCard eyebrow="Step 1 of 4" title="Start with your website">
          <p className="wizard-lead">Give this workspace a name you will recognize. You can add more websites later.</p>
          <label>
            Website name
            <input value={draft.websiteName} onChange={(event) => patch({ websiteName: event.target.value })} placeholder="Northstar Shop" autoFocus />
          </label>
          <p className="helper-text">This name is only used inside SecAi.</p>
        </WizardCard>
      ) : null}

      {step === 1 ? <EvidenceSourceStep draft={draft} patch={patch} /> : null}

      {step === 2 ? <AlertsStep draft={draft} patch={patch} toggleChannel={toggleChannel} /> : null}

      {step === 3 ? (
        <WizardCard eyebrow="Step 4 of 4" title="Review and turn on SecAi">
          <p className="wizard-lead">SecAi can investigate and report on its own. It will ask you before making any change to website traffic.</p>
          <div className="review-list">
            <span><strong>Website</strong>{draft.websiteName}</span>
            <span><strong>Evidence</strong>{watchMethodLabel(draft.watchMethod)}</span>
            <span><strong>Reports</strong>{draft.channels.map(channelLabel).join(", ")}</span>
            <span><strong>Next step</strong>{draft.watchMethod === "alibaba_autopilot" ? "Authorize your Alibaba Cloud account from the dashboard" : "Add the monitoring script"}</span>
          </div>
          {createdSnippet ? (
            <div className="setup-result">
              <strong>Your SecAi workspace is ready</strong>
              {draft.watchMethod === "browser" ? (
                <>
                  <p className="helper-text">Paste this before the closing &lt;/body&gt; tag on every page that should be monitored.</p>
                  <pre>{createdSnippet}</pre>
                </>
              ) : (
                <p className="helper-text">Open the dashboard to authorize this website&apos;s Alibaba Cloud role and choose its activity source. SecAi never asks for permanent AccessKeys.</p>
              )}
              {draft.channels.includes("discord") ? (
                <div className="callout">
                  <MessageCircle size={18} aria-hidden="true" />
                  <div>
                    <p>
                      Invite the SecAi bot, then select <code>/connect</code> from Discord&apos;s command menu in the private
                      server channel where reports should arrive. Paste the one-time code into
                      the command&apos;s <code>code</code> field. Sending the command as ordinary message text will not connect it.
                    </p>
                    <div className="setup-codes">
                      {messagingSetup.map((item) => (
                        <span key={item.channel}>
                          <strong>Discord</strong>
                          <code>{item.setup_code}</code>
                          {item.invite_url ? <a href={item.invite_url} target="_blank" rel="noreferrer">Add SecAi to Discord</a> : null}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ) : null}
              {pendingSession ? (
                <button type="button" onClick={() => onSession(pendingSession)}>Open my dashboard <ArrowRight size={16} /></button>
              ) : (
                <p className="helper-text">Save the connection details shown above before closing this page.</p>
              )}
            </div>
          ) : null}
          {message ? <p className="status-line" role="status" aria-live="polite">{message}</p> : null}
        </WizardCard>
      ) : null}

      <div className="wizard-actions">
        <button type="button" className="secondary-button" onClick={() => setStep(Math.max(0, step - 1))} disabled={step === 0 || busy}>
          Back
        </button>
        {step < 3 ? (
          <button type="button" onClick={() => setStep(step + 1)} disabled={!canContinue() || busy}>
            Continue <ArrowRight size={16} />
          </button>
        ) : (
          <button type="button" onClick={finishSetup} disabled={!canContinue() || busy || Boolean(createdSnippet)}>
            <CheckCircle2 size={16} /> Turn on SecAi
          </button>
        )}
      </div>
    </section>
  );
}

function channelLabel(channel: string) {
  return channel === "dashboard" ? "SecAi dashboard" : channel === "discord" ? "Discord" : channel;
}

function watchMethodLabel(method: SetupDraft["watchMethod"]) {
  return method === "browser" ? "Website script (browser activity only)" : "Alibaba Cloud activity";
}
