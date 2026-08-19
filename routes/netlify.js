// routes/netlify.js
// Netlify provisioning + deployment for TestPilot Staging Safe
// ES Module syntax — compatible with server.js

import express from 'express';
import { createClient } from '@supabase/supabase-js';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { randomUUID, randomBytes } from 'crypto';
import { runStagingSafeTests } from './staging-test.js';

const router = express.Router();

const supabaseClient = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const NETLIFY_TOKEN = process.env.NETLIFY_ACCESS_TOKEN;
const NETLIFY_API = 'https://api.netlify.com/api/v1';

// ─────────────────────────────────────────────
// PAID-ONLY GATE
// Funnel rework: Staging Safe is a paid feature. Free + OneRun get a clean
// 402 with the unified copy. We resolve plan via Supabase users (cookie
// already parsed by the global cookieParser middleware in server.js).
// Skipped for the GET status route so the UI can render its initial empty
// state without bouncing on a 402; the read is harmless without writes.
// ─────────────────────────────────────────────
async function requirePaidPlan(req, res, next) {
  try {
    if (req.method === 'GET') return next();
    const sessionMap = req.app?.locals?.sessions;
    const token = req.cookies?.tpsession;
    let plan = 'free';
    if (sessionMap && token && sessionMap.get) {
      const s = sessionMap.get(token);
      if (s?.plan) plan = s.plan;
    }
    if (plan === 'free' || plan === 'onerun') {
      return res.status(402).json({ error: 'This feature requires a paid plan.', code: 'PLAN_FEATURE_LOCKED' });
    }
    return next();
  } catch {
    return next();
  }
}
router.use(requirePaidPlan);

// App-ownership guard (Phase-2 IDOR defense). Every staging route is keyed on
// :app_id; without this they filtered ONLY on app_id (.eq('app_id', ...)) and
// never on the requester, so any user (and, for the GET-bypassed status route,
// any UNauthenticated caller) could read/provision/deploy/destroy another
// tenant's staging by guessing the id. The `apps` table records the owner as
// user_email (= session email, set by /api/v1/apps/upsert); identity comes from
// the shared sessions Map via the tpsession cookie. Runs for every route with an
// :app_id param. A fresh app with no row yet is allowed on GET only (no data to
// leak — the status route renders its empty "ready to connect" state); writes
// against an unknown app are denied.
router.param('app_id', async (req, res, next, app_id) => {
  const sessionMap = req.app?.locals?.sessions;
  const token = req.cookies?.tpsession;
  const email = ((sessionMap && token && sessionMap.get(token)?.email) || '').toLowerCase();
  if (!email) return res.status(401).json({ error: 'Not authenticated', code: 'AUTH_REQUIRED' });
  try {
    const { data: app } = await supabaseClient.from('apps').select('user_email').eq('app_id', app_id).maybeSingle();
    if (!app) {
      if (req.method === 'GET') return next();   // fresh app, never upserted → no data to leak
      return res.status(404).json({ error: 'App not found', code: 'NOT_FOUND' });
    }
    if ((app.user_email || '').toLowerCase() !== email) {
      return res.status(403).json({ error: 'This app belongs to another account.', code: 'OWNERSHIP_MISMATCH' });
    }
    return next();
  } catch (e) {
    console.error('[staging:ownership]', app_id, e.message);
    return res.status(500).json({ error: 'ownership check failed' });
  }
});

// ─────────────────────────────────────────────
// HELPER: Netlify API call
// ─────────────────────────────────────────────
async function netlifyAPI(method, endpoint, body = null, isZip = false) {
  const headers = { 'Authorization': `Bearer ${NETLIFY_TOKEN}` };
  if (isZip) {
    headers['Content-Type'] = 'application/zip';
  } else {
    headers['Content-Type'] = 'application/json';
  }

  const options = { method, headers };
  if (body) options.body = isZip ? body : JSON.stringify(body);

  const response = await fetch(`${NETLIFY_API}${endpoint}`, options);
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Netlify API error ${response.status}: ${error}`);
  }
  return response.json();
}

// ─────────────────────────────────────────────
// HELPER: Create Netlify site for an app
// ─────────────────────────────────────────────
// The staging clone is publicly reachable: Netlify Basic Auth via `_headers`
// is plan-gated on this account, so the URL itself is the only thing between a
// customer's pre-release code and anyone who guesses it. The old name was
// `tp-<app name>-<last 6 of app_id>` — the app name is public and the suffix is
// 24 bits, so the namespace was walkable. The name now carries no app identity
// and 96 bits of entropy, and can no longer collide with another customer's.
// The app -> site mapping lives in `apps.netlify_site_id`; the Netlify dashboard
// no longer says which site belongs to whom.
async function provisionNetlifySite() {
  const subdomain = `tp-${randomBytes(12).toString('hex')}`;
  const site = await netlifyAPI('POST', '/sites', { name: subdomain, custom_domain: null });
  // A Netlify *site* has no `subdomain` field — only a *deploy* does. Reading it
  // here produced the literal string "https://undefined.netlify.app", which is
  // what got stored as staging_url and later handed to the test runner.
  // `ssl_url` is the site's canonical https URL; the others are fallbacks.
  const staging_url = site.ssl_url || `https://${site.default_domain || site.name}`;
  if (!staging_url.includes(subdomain)) {
    throw new Error(`Netlify returned a site URL that does not match the requested name: ${staging_url}`);
  }
  return {
    netlify_site_id: site.id,
    staging_url,
    subdomain: site.name,
  };
}

// ─────────────────────────────────────────────
// HELPER: Pull code from GitHub and deploy to Netlify via ZIP
// ─────────────────────────────────────────────
async function deployToNetlify(app, commitSha) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'testpilot-'));
  const zipPath = path.join(tmpDir, 'deploy.zip');

  try {
    const [owner, repo] = app.github_repo.split('/');
    const githubZipUrl = `https://api.github.com/repos/${owner}/${repo}/zipball/${commitSha}`;

    const zipResponse = await fetch(githubZipUrl, {
      headers: {
        'Authorization': `Bearer ${app.github_access_token}`,
        'Accept': 'application/vnd.github+json',
      },
      redirect: 'follow',
    });

    if (!zipResponse.ok) throw new Error(`GitHub ZIP download failed: ${zipResponse.status}`);

    const buffer = Buffer.from(await zipResponse.arrayBuffer());
    fs.writeFileSync(zipPath, buffer);

    const zipBuffer = fs.readFileSync(zipPath);
    const deploy = await netlifyAPI('POST', `/sites/${app.netlify_site_id}/deploys`, zipBuffer, true);
    const readyDeploy = await waitForDeploy(deploy.id, app.netlify_site_id);

    // Return the SITE's stable URL, not readyDeploy.subdomain (which is the
    // per-deploy preview URL with a hash prefix — different on every push).
    // app.staging_url was set once at provision time and is locked to this site.
    return {
      deploy_id: readyDeploy.id,
      staging_url: app.staging_url,
      state: readyDeploy.state,
    };

  } finally {
    try { fs.rmSync(tmpDir, { recursive: true }); } catch {}
  }
}

// ─────────────────────────────────────────────
// HELPER: Poll Netlify until deploy is ready
// ─────────────────────────────────────────────
async function waitForDeploy(deployId, siteId, maxWaitMs = 180000) {
  const startTime = Date.now();
  while (Date.now() - startTime < maxWaitMs) {
    const deploy = await netlifyAPI('GET', `/deploys/${deployId}`);
    if (deploy.state === 'ready') return deploy;
    if (deploy.state === 'error') throw new Error(`Netlify deploy failed: ${deploy.error_message}`);
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  throw new Error('Netlify deploy timed out after 3 minutes');
}

// ─────────────────────────────────────────────
// ENDPOINT: Provision Netlify site for an app
// POST /api/v1/apps/:app_id/staging/provision
// ─────────────────────────────────────────────
router.post('/apps/:app_id/staging/provision', async (req, res) => {
  const { app_id } = req.params;

  try {
    const { data: app, error } = await supabaseClient.from('apps').select('*').eq('app_id', app_id).single();
    if (error || !app) return res.status(404).json({ error: 'app not found' });
    if (!app.github_repo) return res.status(400).json({ error: 'GitHub repo must be connected before provisioning staging' });

    if (app.netlify_site_id) {
      return res.json({ success: true, message: 'Staging already provisioned', staging_url: app.staging_url });
    }

    console.log(`[Staging Safe] Provisioning Netlify site for app ${app_id} (${app.name})`);
    const { netlify_site_id, staging_url } = await provisionNetlifySite();

    await supabaseClient.from('apps').update({ netlify_site_id, staging_url }).eq('app_id', app_id);

    console.log(`[Staging Safe] Provisioned: ${staging_url}`);
    res.json({ success: true, staging_url, netlify_site_id, message: 'Staging environment ready' });

  } catch (err) {
    console.error('Netlify provision error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// ENDPOINT: Get staging status for an app
// GET /api/v1/apps/:app_id/staging
// ─────────────────────────────────────────────
//
// Called speculatively by the UI's ssSwitchApp() — fires the moment the user
// clicks an app card, before they may have ever connected GitHub. If the row
// doesn't exist yet in the staging `apps` table, return a 200 with a
// "not-yet-provisioned" payload instead of a 404/500 so the UI can render its
// initial state without throwing.
router.get('/apps/:app_id/staging', async (req, res) => {
  const { app_id } = req.params;
  try {
    const { data: app, error } = await supabaseClient
      .from('apps')
      .select('staging_url, netlify_site_id, last_commit_sha, last_commit_message, learn_status, baseline_run_at, monitoring_paused')
      .eq('app_id', app_id)
      .maybeSingle(); // .single() throws PGRST116 on zero rows; .maybeSingle() returns null

    // Distinguish "row doesn't exist yet" (200, defaults) from "real db error"
    // (500 with actual cause logged).
    if (error) {
      console.error('[staging-status] supabase error', { app_id, code: error.code, message: error.message, details: error.details });
      return res.status(500).json({ error: 'Database error', code: error.code });
    }

    if (!app) {
      // Fresh app, never upserted. UI treats this as "ready to connect GitHub".
      return res.json({
        staging_url: null,
        provisioned: false,
        last_commit_sha: null,
        last_commit_message: null,
        learn_status: 'pending',
        baseline_run_at: null,
        monitoring_paused: false,
        not_yet_provisioned: true,
      });
    }

    res.json({
      staging_url: app.staging_url || null,
      provisioned: !!app.netlify_site_id,
      last_commit_sha: app.last_commit_sha || null,
      last_commit_message: app.last_commit_message || null,
      learn_status: app.learn_status || 'pending',
      baseline_run_at: app.baseline_run_at || null,
      monitoring_paused: !!app.monitoring_paused,
    });
  } catch (err) {
    console.error('[staging-status] unexpected error', { app_id, message: err.message, stack: err.stack?.slice(0, 500) });
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// INTERNAL: Deploy commit to staging
// Called by the GitHub webhook handler
// ─────────────────────────────────────────────
export async function triggerStagingDeploy(appId, commitSha, commitMessage) {
  try {
    const { data: app, error } = await supabaseClient.from('apps').select('*').eq('app_id', appId).single();
    if (error || !app) throw new Error('app not found');
    if (!app.netlify_site_id) throw new Error('staging not provisioned');
    if (!app.github_access_token) throw new Error('GitHub not connected');

    console.log(`[Staging Safe] Deploying commit ${commitSha} for app ${appId}`);
    const deploy = await deployToNetlify(app, commitSha);
    console.log(`[Staging Safe] Deploy complete: ${deploy.staging_url}`);

    // Auto-run scenarios after the deploy is live. server.js sets
    // globalThis.__tpHelpers because importing helpers from ../server.js
    // here would create a circular dependency (server.js imports this file
    // for the router). Helpers are populated before app.listen(), so by the
    // time any webhook fires they're available.
    const helpers = globalThis.__tpHelpers;
    if (helpers) {
      runStagingSafeTests(appId, commitSha, commitMessage, helpers).catch(err => {
        console.error(`[Staging Safe] Post-deploy tests failed for app=${appId} commit=${commitSha}:`, err.message);
      });
    } else {
      console.warn(`[Staging Safe] globalThis.__tpHelpers not set — skipping auto-tests for app=${appId}`);
    }

    return { success: true, deploy_id: deploy.deploy_id, staging_url: deploy.staging_url, commit_sha: commitSha, commit_message: commitMessage };

  } catch (err) {
    console.error(`[Staging Safe] Deploy failed for app ${appId}:`, err.message);
    throw err;
  }
}

// ─────────────────────────────────────────────
// ENDPOINT: Manually trigger a staging deploy
// POST /api/v1/apps/:app_id/staging/deploy
// ─────────────────────────────────────────────
router.post('/apps/:app_id/staging/deploy', async (req, res) => {
  const { app_id } = req.params;
  const { commit_sha } = req.body;

  try {
    const { data: app, error } = await supabaseClient
      .from('apps').select('last_commit_sha, last_commit_message').eq('app_id', app_id).single();

    if (error || !app) return res.status(404).json({ error: 'app not found' });

    const sha = commit_sha || app.last_commit_sha;
    if (!sha) return res.status(400).json({ error: 'No commit SHA available. Push a commit first.' });

    res.json({ success: true, message: 'Staging deploy started', commit_sha: sha });

    triggerStagingDeploy(app_id, sha, app.last_commit_message).catch(err => {
      console.error('Manual staging deploy failed:', err.message);
    });

  } catch (err) {
    console.error('Manual deploy trigger error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// ENDPOINT: Pause monitoring (reversible — keeps the staging site,
// scenarios, baseline; just stops reacting to new commits)
// POST /api/v1/apps/:app_id/staging/monitoring/pause
// ─────────────────────────────────────────────
router.post('/apps/:app_id/staging/monitoring/pause', async (req, res) => {
  const { app_id } = req.params;
  try {
    const { error } = await supabaseClient
      .from('apps')
      .update({ monitoring_paused: true })
      .eq('app_id', app_id);
    if (error) throw error;
    res.json({ success: true, monitoring_paused: true });
  } catch (err) {
    console.error('[monitoring/pause]', app_id, err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// ENDPOINT: Resume monitoring
// POST /api/v1/apps/:app_id/staging/monitoring/resume
// ─────────────────────────────────────────────
router.post('/apps/:app_id/staging/monitoring/resume', async (req, res) => {
  const { app_id } = req.params;
  try {
    const { error } = await supabaseClient
      .from('apps')
      .update({ monitoring_paused: false })
      .eq('app_id', app_id);
    if (error) throw error;
    res.json({ success: true, monitoring_paused: false });
  } catch (err) {
    console.error('[monitoring/resume]', app_id, err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// ENDPOINT: Delete Netlify site
// DELETE /api/v1/apps/:app_id/staging
// ─────────────────────────────────────────────
router.delete('/apps/:app_id/staging', async (req, res) => {
  const { app_id } = req.params;
  try {
    const { data: app, error } = await supabaseClient
      .from('apps').select('netlify_site_id').eq('app_id', app_id).single();

    if (error || !app?.netlify_site_id) return res.json({ success: true, message: 'No staging site to delete' });

    await netlifyAPI('DELETE', `/sites/${app.netlify_site_id}`);
    await supabaseClient.from('apps').update({ netlify_site_id: null, staging_url: null }).eq('app_id', app_id);

    res.json({ success: true, message: 'Staging site deleted' });

  } catch (err) {
    console.error('Staging delete error:', err);
    res.status(500).json({ error: err.message });
  }
});

export default router;
