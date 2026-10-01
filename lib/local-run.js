// One rule for "is this the production process?", shared by server.js and the
// mail-sending libs, so a server started on a laptop against the production
// database can never mail real people or run production's background jobs.
//
// Only the production pm2 process sets NODE_ENV=production (ecosystem.config.cjs).
// Anything else is a local run. TESTPILOT_LOCAL=1|true|yes forces local mode on
// a production-like box. TESTPILOT_OUTBOUND_MAIL=1 turns mail back on for a
// local run WITHOUT re-arming the production jobs — the two are separate
// switches on purpose (receiving your own login link locally must not start
// the retention sweep or nudge real prospects).
//
// Seen live 2026-10-01: a local test run sent the onboarding "stall nudge" to a
// real prospect twice, because the local instance had no record of production
// having already sent it, and the sweep fires two minutes after boot.
const truthy = (v) => /^(1|true|yes)$/i.test(String(v || ''));

export function runMode(env = process.env) {
  const forcedLocal = truthy(env.TESTPILOT_LOCAL);
  const isProd = env.NODE_ENV === 'production' && !forcedLocal;
  const mailForced = truthy(env.TESTPILOT_OUTBOUND_MAIL);
  return {
    isProd,
    local: !isProd,
    prodJobs: isProd,                        // retention, stall nudges, digest, health alerts, scheduled runs, signal sweeps
    mailEnabled: isProd || mailForced,       // every Resend call
    reason: isProd ? 'NODE_ENV=production'
      : forcedLocal ? 'TESTPILOT_LOCAL is set'
      : `NODE_ENV=${env.NODE_ENV || '(unset)'}`,
    mailReason: isProd ? 'production' : mailForced ? 'forced on by TESTPILOT_OUTBOUND_MAIL' : 'off (local run)',
  };
}

export const RUN_MODE = runMode();
