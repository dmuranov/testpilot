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
import { createRequire } from 'node:module';
const truthy = (v) => /^(1|true|yes)$/i.test(String(v || ''));

// The production checkout path comes from ecosystem.config.cjs (the one
// place that defines it), with the known value as a fallback.
function productionPathFromEcosystem() {
  try {
    const eco = createRequire(import.meta.url)('../ecosystem.config.cjs');
    const app = (eco.apps || []).find((a) => a.name === 'testpilot');
    if (app?.cwd) return app.cwd;
  } catch {}
  return '/home/azureuser/testpilot';
}

// The production box also identifies itself by WHERE the process runs: under
// pm2 (pm_id is set) in the deploy path. That fallback exists for one reason:
// a process that was started with a bare "pm2 start server.js" has no
// NODE_ENV, and the deploy that first ships this rule still reloads it that
// way. A laptop never matches (no pm2, different path).
export const PRODUCTION_PATH = productionPathFromEcosystem();
export function runMode(env = process.env, cwd = process.cwd()) {
  const forcedLocal = truthy(env.TESTPILOT_LOCAL);
  const byEnv = env.NODE_ENV === 'production';
  // Only THE pm2 process named "testpilot" (pm2 sets `name`) in the production
  // checkout — an extra "pm2 start server.js --name something" there is local.
  const byPlace = env.pm_id !== undefined && env.name === 'testpilot' && String(cwd).replace(/\\/g, '/').startsWith(PRODUCTION_PATH);
  const isProd = (byEnv || byPlace) && !forcedLocal;
  const onProductionBox = byEnv || byPlace; // even when forced local: logs there must never carry tokens
  const mailForced = truthy(env.TESTPILOT_OUTBOUND_MAIL);
  return {
    isProd,
    local: !isProd,
    onProductionBox,
    prodJobs: isProd,                        // retention, stall nudges, digest, health alerts, scheduled runs, signal sweeps
    mailEnabled: isProd || mailForced,       // every Resend call
    reason: forcedLocal ? 'TESTPILOT_LOCAL is set'
      : byEnv ? 'NODE_ENV=production'
      : byPlace ? `pm2 process "testpilot" on ${PRODUCTION_PATH} (NODE_ENV not set — start from ecosystem.config.cjs)`
      : `NODE_ENV=${env.NODE_ENV || '(unset)'}, not the pm2 "testpilot" process on the production path`,
    mailReason: isProd ? 'production' : mailForced ? 'forced on by TESTPILOT_OUTBOUND_MAIL' : 'off (local run)',
  };
}

export const RUN_MODE = runMode();

// Internal / test identities: the super admin and @example.* test addresses.
// Used by the onboarding alert (no alerts for our own test runs) and by the
// mail chokepoint (full links in suppressed-mail logs only for these).
const SUPER_ADMIN = (process.env.SUPER_ADMIN_EMAIL || 'danijel.muranovic@gmail.com').toLowerCase();
export function isInternalAddress(email) {
  const e = String(email || '').toLowerCase();
  return !e || e === SUPER_ADMIN || /@example\.(com|org|net)$/.test(e);
}
