import { Clipboard, LayoutDashboard, MessageCircle, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";

export type SetupDraft = {
  websiteName: string;
  watchMethod: "browser" | "alibaba_autopilot";
  channels: string[];
  dashboardEmail: string;
  dashboardPassword: string;
};

export function WizardCard({ eyebrow, title, children }: { eyebrow: string; title: string; children: ReactNode }) {
  return (
    <div className="wizard-card">
      <p className="eyebrow">{eyebrow}</p>
      <h2>{title}</h2>
      {children}
    </div>
  );
}

export function EvidenceSourceStep({
  draft,
  patch,
}: {
  draft: SetupDraft;
  patch: (next: Partial<SetupDraft>) => void;
}) {
  return (
    <WizardCard eyebrow="Step 2 of 4" title="Choose where SecAi gets its evidence">
      <p className="wizard-lead">SecAi can use trusted cloud activity or a lightweight website script. Choose the option that matches where your website runs.</p>
      <div className="choice-cards">
        <ChoiceCard
          icon={<ShieldCheck size={24} />}
          title="Alibaba Cloud connection"
          text="Recommended for websites hosted on Alibaba Cloud. It sees requests reaching your website, provides stronger evidence, and can apply a protective change after you approve it."
          selected={draft.watchMethod === "alibaba_autopilot"}
          onClick={() => patch({ watchMethod: "alibaba_autopilot" })}
        />
        <ChoiceCard
          icon={<Clipboard size={24} />}
          title="Website monitoring script"
          text="Works on any website and is quick to install, but only sees activity in a visitor's browser. Direct requests are invisible and attackers can bypass it."
          selected={draft.watchMethod === "browser"}
          onClick={() => patch({ watchMethod: "browser" })}
        />
      </div>
      {draft.watchMethod === "alibaba_autopilot" ? <p className="helper-text">After your account is created, Overview will generate a customer-specific role template. You approve it in your own Alibaba Cloud account, then SecAi verifies the connection.</p> : null}
    </WizardCard>
  );
}

export function AlertsStep({
  draft,
  patch,
  toggleChannel,
}: {
  draft: SetupDraft;
  patch: (next: Partial<SetupDraft>) => void;
  toggleChannel: (channel: string) => void;
}) {
  return (
    <WizardCard eyebrow="Step 3 of 4" title="Choose where reports should reach you">
      <p className="wizard-lead">Use the dashboard, Discord, or both. A protective change always waits for your approval.</p>
      <div className="choice-cards">
        <ChoiceCard icon={<LayoutDashboard size={24} />} title="Dashboard" text="Review evidence, make decisions, and see the result of every approved change." selected={draft.channels.includes("dashboard")} onClick={() => toggleChannel("dashboard")} />
        <ChoiceCard icon={<MessageCircle size={24} />} title="Discord" text="Receive reports and review protection from a private server channel." selected={draft.channels.includes("discord")} onClick={() => toggleChannel("discord")} />
      </div>
      {draft.channels.includes("dashboard") ? (
        <div className="nested-form">
          <label>Account email<input type="email" value={draft.dashboardEmail} onChange={(event) => patch({ dashboardEmail: event.target.value })} placeholder="you@example.com" /></label>
          <label>Create a password<input type="password" value={draft.dashboardPassword} onChange={(event) => patch({ dashboardPassword: event.target.value })} placeholder="At least 8 characters" /></label>
        </div>
      ) : null}
      {draft.channels.includes("discord") ? (
        <div className="callout"><MessageCircle size={18} aria-hidden="true" /><p>After setup, use the bot invite and one-time code to choose where Discord reports should arrive.</p></div>
      ) : null}
      {draft.watchMethod === "alibaba_autopilot" && !draft.channels.includes("dashboard") ? <p className="helper-text danger-text">Keep the dashboard selected so you can authorize the website owner&apos;s Alibaba Cloud account.</p> : null}
    </WizardCard>
  );
}

function ChoiceCard({ icon, title, text, selected, onClick }: {
  icon: ReactNode;
  title: string;
  text: string;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" aria-pressed={selected} className={`choice-card ${selected ? "selected" : ""}`} onClick={onClick}>
      {icon}<strong>{title}</strong><span>{text}</span>
    </button>
  );
}
