// routes/github.js
// GitHub OAuth + webhook receiver for TestPilot
// ES Module syntax — compatible with server.js

import express from 'express';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';
import { triggerStagingDeploy } from './netlify.js';

const router = express.Router();

const supabaseClient = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;
const BASE_URL = process.env.BASE_URL || 'https://testpilotapp.dev';

// App-ownership guard (Phase-2 IDOR defense). The `apps` table records the owner
// as user_email (= session email, set by /api/v1/apps/upsert). Identity comes
// from the shared sessions Map (server.js sets app.locals.sessions) via the
// tpsession cookie. Fails closed: 401 (no session), 403 (mismatch / unknown app).
// NOTE: applied ONLY to the user-facing routes below — the GitHub webhook
// (/webhooks/github/:app_id) authenticates by HMAC signature, has no session,
// and must NOT pass through this.
async function assertGithubAppOwner(req, res, app_id) {
  const sessionMap = req.app?.locals?.sessions;
  const token = req.cookies?.tpsession;
  const email = ((sessionMap && token && sessionMap.get(token)?.email) || '').toLowerCase();
  if (!email) { res.status(401).json({ error: 'Not authenticated', code: 'AUTH_REQUIRED' }); return false; }
  const { data: app } = await supabaseClient.from('apps').select('user_email').eq('app_id', app_id).maybeSingle();
  if (!app || (app.user_email || '').toLowerCase() !== email) {
    res.status(403).json({ error: 'This app belongs to another account.', code: 'OWNERSHIP_MISMATCH' });
    return false;
  }
  return true;
}

// ─────────────────────────────────────────────
// PAID-ONLY GATE
// Funnel rework: GitHub-connect routes are part of Staging Safe (paid).
// Webhook receiver + OAuth callback MUST stay reachable (GitHub's IPs hit
// the webhook; the OAuth flow needs the redirect target). Everything
// user-initiated gets the 402.
// ─────────────────────────────────────────────
router.use((req, res, next) => {
  // Allow webhook + OAuth callback regardless of session.
  if (req.path.startsWith('/webhooks/') || req.path === '/auth/github/callback') return next();
  // Allow the initial OAuth handshake (GET /auth/github) — the user is
  // about to be redirected; they're authenticated by then. The eventual
  // POST connect-repo is what we really want to gate.
  if (req.method === 'GET' && req.path === '/auth/github') return next();
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
});

// ─────────────────────────────────────────────
// HELPER: Verify GitHub webhook signature
// ─────────────────────────────────────────────
function verifyGithubSignature(req) {
  const signature = req.headers['x-hub-signature-256'];
  if (!signature) return false;
  // Hash the raw request body bytes that GitHub actually signed. server.js's
  // global express.json() captures these into req.rawBody via its `verify`
  // callback. Refuse to verify if rawBody is missing — silently falling back
  // to JSON.stringify(req.body) would hide future middleware-order bugs.
  if (!req.rawBody) return false;
  const hmac = crypto.createHmac('sha256', GITHUB_WEBHOOK_SECRET);
  const digest = 'sha256=' + hmac.update(req.rawBody).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────
// HELPER: Register webhook on GitHub repo
// ─────────────────────────────────────────────
async function registerGithubWebhook(accessToken, owner, repo, appId) {
  const response = await fetch(`https://api.github.com/repos/${owner}/${repo}/hooks`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/vnd.github+json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      name: 'web',
      active: true,
      events: ['push'],
      config: {
        url: `${BASE_URL}/api/v1/webhooks/github/${appId}`,
        content_type: 'json',
        secret: GITHUB_WEBHOOK_SECRET
      }
    })
  });

  if (!response.ok) {
    const error = await response.json();
    if (error.errors && error.errors[0]?.message?.includes('already exists')) {
      return { already_exists: true };
    }
    throw new Error(`GitHub webhook registration failed: ${JSON.stringify(error)}`);
  }

  return response.json();
}

// ─────────────────────────────────────────────
// HELPER: Get user repos from GitHub
// ─────────────────────────────────────────────
async function getUserRepos(accessToken) {
  const response = await fetch('https://api.github.com/user/repos?sort=updated&per_page=50', {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/vnd.github+json'
    }
  });
  if (!response.ok) throw new Error('Failed to fetch GitHub repos');
  return response.json();
}

// ─────────────────────────────────────────────
// STEP 1: Redirect user to GitHub OAuth
// GET /api/v1/auth/github?app_id=app_xxx
// ─────────────────────────────────────────────
router.get('/auth/github', (req, res) => {
  const { app_id } = req.query;
  if (!app_id) return res.status(400).json({ error: 'app_id is required' });

  const state = Buffer.from(JSON.stringify({ app_id })).toString('base64');
  const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
  githubAuthUrl.searchParams.set('client_id', GITHUB_CLIENT_ID);
  githubAuthUrl.searchParams.set('redirect_uri', `${BASE_URL}/api/v1/auth/github/callback`);
  githubAuthUrl.searchParams.set('scope', 'repo');
  githubAuthUrl.searchParams.set('state', state);

  res.redirect(githubAuthUrl.toString());
});

// ─────────────────────────────────────────────
// STEP 2: GitHub OAuth callback
// GET /api/v1/auth/github/callback
// ─────────────────────────────────────────────
router.get('/auth/github/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) return res.redirect(`${BASE_URL}/app?error=github_denied`);

  let app_id;
  try {
    const decoded = JSON.parse(Buffer.from(state, 'base64').toString());
    app_id = decoded.app_id;
  } catch {
    return res.redirect(`${BASE_URL}/app?error=invalid_state`);
  }

  try {
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${BASE_URL}/api/v1/auth/github/callback`
      })
    });

    const tokenData = await tokenResponse.json();
    if (!tokenData.access_token) throw new Error('No access token received from GitHub');

    const accessToken = tokenData.access_token;

    const userResponse = await fetch('https://api.github.com/user', {
      headers: { 'Authorization': `Bearer ${accessToken}`, 'Accept': 'application/vnd.github+json' }
    });
    const githubUser = await userResponse.json();

    const { error: updateError } = await supabaseClient
      .from('apps')
      .update({ github_access_token: accessToken, github_owner: githubUser.login })
      .eq('app_id', app_id);

    if (updateError) throw updateError;

    res.redirect(`${BASE_URL}/app?github_connected=true&app_id=${app_id}`);

  } catch (err) {
    console.error('GitHub OAuth callback error:', err);
    res.redirect(`${BASE_URL}/app?error=github_auth_failed`);
  }
});

// ─────────────────────────────────────────────
// STEP 3: User selects which repo to connect
// POST /api/v1/apps/:app_id/github/connect-repo
// ─────────────────────────────────────────────
router.post('/apps/:app_id/github/connect-repo', async (req, res) => {
  const { app_id } = req.params;
  if (!(await assertGithubAppOwner(req, res, app_id))) return;
  const { repo } = req.body;

  if (!repo || !repo.includes('/')) {
    return res.status(400).json({ error: 'repo must be in format owner/repo-name' });
  }

  try {
    const { data: app, error: fetchError } = await supabaseClient
      .from('apps').select('*').eq('app_id', app_id).single();

    if (fetchError || !app) return res.status(404).json({ error: 'app not found' });
    if (!app.github_access_token) return res.status(400).json({ error: 'GitHub not connected. Connect GitHub first.' });

    const [owner, repoName] = repo.split('/');
    const webhook = await registerGithubWebhook(app.github_access_token, owner, repoName, app_id);

    const { error: updateError } = await supabaseClient
      .from('apps')
      .update({ github_repo: repo, github_webhook_id: webhook.id ? String(webhook.id) : null })
      .eq('app_id', app_id);

    if (updateError) throw updateError;

    res.json({ success: true, message: `GitHub repo ${repo} connected. Webhook registered.`, staging_url: app.staging_url || null });

  } catch (err) {
    console.error('Connect repo error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// STEP 3b: List user's GitHub repos
// GET /api/v1/apps/:app_id/github/repos
// ─────────────────────────────────────────────
router.get('/apps/:app_id/github/repos', async (req, res) => {
  const { app_id } = req.params;
  if (!(await assertGithubAppOwner(req, res, app_id))) return;

  try {
    const { data: app, error } = await supabaseClient
      .from('apps').select('github_access_token').eq('app_id', app_id).single();

    if (error || !app?.github_access_token) return res.status(400).json({ error: 'GitHub not connected' });

    const repos = await getUserRepos(app.github_access_token);
    res.json({ repos: repos.map(r => ({ full_name: r.full_name, name: r.name, private: r.private, updated_at: r.updated_at })) });

  } catch (err) {
    console.error('List repos error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// STEP 4: Receive GitHub push webhook
// POST /api/v1/webhooks/github/:app_id
// ─────────────────────────────────────────────
router.post('/webhooks/github/:app_id', express.raw({ type: 'application/json' }), async (req, res) => {
  const { app_id } = req.params;

  if (!verifyGithubSignature(req)) {
    console.warn(`Invalid GitHub webhook signature for app ${app_id}`);
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const event = req.headers['x-github-event'];
  if (event !== 'push') return res.json({ received: true, action: 'ignored', event });

  const payload = req.body;
  const branch = payload.ref?.replace('refs/heads/', '');
  if (branch !== 'main') return res.json({ received: true, action: 'ignored', reason: `branch ${branch} is not main` });

  const commit_sha = payload.after;
  const commit_message = payload.head_commit?.message || '';

  console.log(`[GitHub Webhook] app=${app_id} commit=${commit_sha} branch=${branch}`);

  try {
    // Honor the pause flag: when monitoring is paused, drop the event on the
    // floor (don't even update last_commit_sha — when the user resumes, the
    // commit they care about is the latest, which they'll deploy manually).
    const { data: appRow } = await supabaseClient
      .from('apps')
      .select('monitoring_paused')
      .eq('app_id', app_id)
      .maybeSingle();
    if (appRow?.monitoring_paused) {
      console.log(`[GitHub Webhook] app=${app_id} ignoring push — monitoring is paused`);
      return res.json({ received: true, action: 'ignored', reason: 'monitoring_paused' });
    }

    await supabaseClient
      .from('apps')
      .update({ last_commit_sha: commit_sha, last_commit_message: commit_message })
      .eq('app_id', app_id);

    // Auto-deploy + auto-test on every push (the "Every commit auto-deploys
    // and auto-tests" promise from the wizard's How-it-works step). Fire and
    // forget — the deploy + tests can take minutes, GitHub only waits 10s
    // for a webhook response.
    triggerStagingDeploy(app_id, commit_sha, commit_message).catch(err => {
      console.error(`[Staging Safe] Auto-deploy failed for app=${app_id} commit=${commit_sha}:`, err.message);
    });

    res.json({ received: true, action: 'queued', app_id, commit_sha, commit_message });

  } catch (err) {
    console.error('GitHub webhook processing error:', err);
    res.status(500).json({ error: err.message });
  }
});

export default router;
