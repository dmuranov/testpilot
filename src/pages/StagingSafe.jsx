import React from 'react';
import { Link } from 'react-router-dom';
import { GitBranch, ArrowRight, Github, Zap, Check, ExternalLink } from 'lucide-react';

// Staging Safe — the 5-step wizard (Connect → Learn → Scenarios → Baseline → Monitor)
// is too complex to rebuild natively for V1. This page explains the feature
// and links out to the existing Azure-hosted wizard. Native rebuild is Phase 2.

const Step = ({ n, title, desc }) => (
  <div className="flex gap-4 items-start">
    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary/15 border border-primary/40 text-primary font-syne font-bold flex items-center justify-center text-sm">
      {n}
    </div>
    <div className="flex-1 min-w-0">
      <h3 className="font-syne font-bold text-sm">{title}</h3>
      <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
    </div>
  </div>
);

export default function StagingSafe() {
  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <GitBranch className="w-6 h-6 text-primary" />
          <h1 className="text-3xl font-syne font-bold">Staging Safe</h1>
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-primary/15 text-primary border border-primary/30">BETA</span>
        </div>
        <p className="text-muted-foreground text-sm">
          Connect a GitHub repo. Every commit auto-deploys to a stable staging URL and runs all your scenarios. Catch regressions before they ship.
        </p>
      </div>

      {/* How it works */}
      <div className="bg-card border border-border rounded p-6 space-y-5">
        <h2 className="text-xs font-syne font-bold uppercase tracking-wider text-primary">How it works</h2>
        <Step n="1" title="Connect" desc="Authorize GitHub access to one of your repos." />
        <Step n="2" title="Learn" desc="TestPilot deploys your code to a private Netlify staging URL and learns your app structure." />
        <Step n="3" title="Scenarios" desc="Confirm or edit which test scenarios will run on every commit." />
        <Step n="4" title="Baseline" desc="Run all scenarios once to capture a baseline of what currently works." />
        <Step n="5" title="Monitor" desc="Every commit triggers auto-deploy → re-tests → regression report by email." />
      </div>

      {/* Pricing/gating note */}
      <div className="bg-card border border-border rounded p-4 flex items-start gap-3">
        <Zap className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
        <div className="text-xs text-muted-foreground">
          <p className="font-bold text-foreground mb-1">Starter plan or above</p>
          <p>Requires a paid TestPilot plan + your own GitHub repo. Stable Netlify URL per app is locked at provision time.</p>
        </div>
      </div>

      {/* CTA */}
      <div className="bg-card border border-primary/40 rounded p-6">
        <div className="flex items-start gap-4">
          <Github className="w-8 h-8 text-primary flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <h3 className="font-syne font-bold mb-1">Set up your first Staging Safe app</h3>
            <p className="text-xs text-muted-foreground mb-4">
              The 5-step wizard is hosted on the classic TestPilot UI. Click below to open it in a new tab.
            </p>
            <a
              href="https://testpilotapp.dev/app"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 bg-primary text-primary-foreground px-4 py-2 rounded font-syne font-bold text-sm hover:opacity-90"
            >
              Open Staging Safe wizard <ArrowRight className="w-4 h-4" />
            </a>
          </div>
        </div>
      </div>

      <p className="text-xs text-muted-foreground flex items-center gap-1 pt-2 border-t border-border">
        <ExternalLink className="w-3 h-3" /> Native Base44 wizard coming in V2.
      </p>
    </div>
  );
}
