// routes/signal.js
// POST /api/signal — public, unauthenticated by necessity (pre-signup funnel
// visitors have no cookie). Everything here assumes the payload is hostile.
// ES Module syntax — compatible with server.js (package.json "type":"module").

import express from 'express';
import crypto from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { enqueueFixJob } from '../lib/bridge-client.js';
import { sendAdminAlert } from '../lib/admin-alert.js';

const router = express.Router();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const CFG = {
  MAX_EVENTS_PER_BATCH: 20,
  MAX_STR: 400,
  MAX_STACK: 2000,
  SESSION_BURST: 12,            // batches per session per minute
  GLOBAL_BURST: 600,            // batches per minute across all sessions
  SIG_THROTTLE_MS: 60_000,      // one DB write per (session, signature) per minute
  HELP_COOLDOWN_MS: 10 * 60_000,
  MIN_OCCURRENCES: 3,           // never enqueue an agent job off a single report
  MIN_SESSIONS: 2,
};

const ALLOWED_TYPES = new Set([
  'uncaught_error', 'unhandled_rejection', 'http_error',
  'network_failure', 'stuck_after_error', 'stream_stalled', 'stream_error',
]);

// Anything that isn't a plain URL path gets bucketed rather than passed on.
// Nothing downstream should ever interpolate this into a shell, but defence
// in depth is free here.
const SAFE_PATH = /^\/[A-Za-z0-9/_\-.:]{0,200}$/;

// ---------------------------------------------------------------- rate limits
const buckets = new Map();      // sessionId -> { n, resetAt }
let globalBucket = { n: 0, resetAt: 0 };

function allow(sessionId) {
  const now = Date.now();
  if (now > globalBucket.resetAt) globalBucket = { n: 0, resetAt: now + 60_000 };
  if (++globalBucket.n > CFG.GLOBAL_BURST) return false;

  let b = buckets.get(sessionId);
  if (!b || now > b.resetAt) { b = { n: 0, resetAt: now + 60_000 }; buckets.set(sessionId, b); }
  return ++b.n <= CFG.SESSION_BURST;
}

const seen = new Map();         // `${session}:${hash}` -> lastWrittenAt
const helped = new Map();       // sessionId -> lastOfferedAt

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of buckets) if (now > v.resetAt + 300_000) buckets.delete(k);
  for (const [k, v] of seen) if (now - v > 600_000) seen.delete(k);
  for (const [k, v] of helped) if (now - v > CFG.HELP_COOLDOWN_MS * 2) helped.delete(k);
}, 120_000).unref?.();

// -------------------------------------------------------------- normalization
function normalizePath(p) {
  if (typeof p !== 'string' || !SAFE_PATH.test(p)) return '/<invalid>';
  return p
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:id')
    .replace(/\/\d+(?=\/|$)/g, '/:id')
    .replace(/\/[0-9a-f]{24,}(?=\/|$)/gi, '/:id');
}

/* Browser stacks point at hashed bundles (app.4f3a2b.js:1:88213), so the file
 * and line change on every deploy. Keep the function name only — it survives
 * a rebuild, which is the whole point of a stable signature.
 * Swap this for a sourcemap lookup later if function names get minified too.
 */
function stackOrigin(stack) {
  if (typeof stack !== 'string') return 'unknown';
  const lines = stack.split('\n').slice(0, 12);
  for (const line of lines) {
    const t = line.trim();
    let m = t.match(/^at\s+(?:async\s+)?([A-Za-z0-9_$.<>]+)\s*\(/);   // Chrome
    if (m) return m[1];
    m = t.match(/^([A-Za-z0-9_$.<>]+)@/);                             // Firefox
    if (m) return m[1];
    if (/^at\s+https?:/.test(t)) return 'anonymous';
  }
  return 'unknown';
}

/* An in-band failure's ev.name is a coarse bucket (e.g. TestPilot's own
 * category: 'app_bug'|'tool_limitation'|'environment'|'uncertain' — see
 * routes/classify.js), not a distinct cause. Genuinely different failures
 * routinely share one bucket (nav_timeout, login_vision, and crawl_gap are
 * all 'environment'/'tool_limitation'), so name alone would collapse them
 * into one signature: the first gets a fix, every different one after it
 * gets silently dismissed as already handled. Mixing in a normalized prefix
 * of the message separates them, while still converging the SAME cause
 * across different users — who rarely share a value, hence stripped before
 * the prefix is taken. Deliberately loose (not a hash) so it's inspectable
 * in the stored raw_sample / signature debugging.
 */
function messagePrefix(msg, wordCount = 8) {
  if (typeof msg !== 'string') return '';
  return msg
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, '<url>')
    .replace(/[\w.+-]+@[\w-]+\.[\w.]+/g, '<email>')
    .replace(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/g, '<domain>')   // bare domains without a scheme
    .replace(/\d+/g, '#')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, wordCount)
    .join(' ');
}

function signatureOf(ev) {
  let parts;
  if (ev.type === 'http_error' || ev.type === 'network_failure' || ev.type === 'stream_stalled') {
    // stream_stalled has no meaningful status/method, but the endpoint that
    // stalled (ev.path) is the useful discriminator — two different streams
    // stalling on the same page must not collapse into one signature.
    parts = [ev.type, ev.status || 0, ev.method || 'GET', normalizePath(ev.path)];
  } else if (ev.type === 'stream_error') {
    // An in-band failure inside an otherwise-200 stream (e.g. /api/learn's
    // {phase:'error', category}). No HTTP status applies. ev.name alone
    // (TestPilot's own category — app_bug/tool_limitation/environment/
    // uncertain) is too coarse: nav_timeout, login_vision, and crawl_gap are
    // all 'environment' or 'tool_limitation', so name-only would still
    // collapse genuinely different causes into one signature. The message
    // prefix is the real discriminator here; name narrows it further.
    parts = [ev.type, ev.name || 'unknown', messagePrefix(ev.message), normalizePath(ev.path)];
  } else {
    parts = [ev.type, ev.name || 'Error', stackOrigin(ev.stack), normalizePath(ev.page || '/')];
  }
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex');
}

// A type string outside ALLOWED_TYPES could be a hostile payload (expected,
// silent) or our own client code having drifted from this list (a real bug —
// the detector fired, batched, and posted fine; it just vanishes here with
// no trace). Log each distinct unrecognized value once per process lifetime
// so the second case is visible without letting the first one spam stdout.
const warnedTypes = new Set();

// ------------------------------------------------------------------ ingestion
function clean(ev, page) {
  if (!ev || typeof ev !== 'object') return null;
  if (!ALLOWED_TYPES.has(ev.type)) {
    if (typeof ev.type === 'string' && !warnedTypes.has(ev.type) && warnedTypes.size < 50) {
      warnedTypes.add(ev.type);
      console.warn(`[signal] unrecognized event type "${ev.type}" — dropped (check ALLOWED_TYPES vs signal.js's TYPE constants if this looks like ours)`);
    }
    return null;
  }
  const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : null);
  return {
    type: ev.type,
    name: str(ev.name, 60),
    message: str(ev.message, CFG.MAX_STR),
    stack: str(ev.stack, CFG.MAX_STACK),
    method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(ev.method) ? ev.method : 'GET',
    status: Number.isInteger(ev.status) && ev.status >= 100 && ev.status < 600 ? ev.status : null,
    path: str(ev.path, 200),
    page: str(page, 200),
  };
}

router.post('/', express.json({ limit: '32kb' }), async (req, res) => {
  // Always 200 with a small body: a failing signal endpoint must never look
  // like an app error to the client.
  const reply = { offerHelp: false, cannedMessage: null, context: null };

  try {
    const body = req.body || {};
    const sessionId = typeof body.sessionId === 'string' ? body.sessionId.slice(0, 64) : null;
    if (!sessionId || !Array.isArray(body.events) || !body.events.length) return res.json(reply);
    if (!allow(sessionId)) return res.json(reply);

    const events = body.events
      .slice(0, CFG.MAX_EVENTS_PER_BATCH)
      .map((e) => clean(e, body.page))
      .filter(Boolean);

    const canOffer = () => {
      const last = helped.get(sessionId) || 0;
      if (Date.now() - last < CFG.HELP_COOLDOWN_MS) return false;
      helped.set(sessionId, Date.now());
      return true;
    };

    // Collapse duplicates inside the batch so one broken render loop is one row.
    const byHash = new Map();
    for (const ev of events) {
      if (ev.type === 'stuck_after_error') {
        if (canOffer()) reply.offerHelp = true;
        continue;
      }
      const hash = signatureOf(ev);
      if (!byHash.has(hash)) byHash.set(hash, ev);
    }

    for (const [hash, ev] of byHash) {
      const key = `${sessionId}:${hash}`;
      if (Date.now() - (seen.get(key) || 0) < CFG.SIG_THROTTLE_MS) continue;
      seen.set(key, Date.now());

      const { data, error } = await supabase.rpc('record_signal', {
        p_hash: hash,
        p_sample: { page: ev.page, event: ev },
        p_session: sessionId,
        p_min_occurrences: CFG.MIN_OCCURRENCES,
        p_min_sessions: CFG.MIN_SESSIONS,
      });
      if (error) { console.error('record_signal failed:', error.message); continue; }

      const row = Array.isArray(data) ? data[0] : data;
      if (!row) continue;

      if (row.out_should_enqueue) {
        // Exactly one caller ever reaches here for a given hash — the RPC
        // flipped status to 'queued' under a row lock.
        enqueueFixJob({ hash, page: ev.page, event: ev })
          .then((r) => supabase.from('error_signatures')
            .update({ job_id: r && r.jobId ? String(r.jobId) : null, status: 'fix_in_progress' })
            .eq('signature_hash', hash))
          .catch((e) => {
            console.error('enqueueFixJob failed:', e.message);
            // Hand the signature back so a later hit can retry rather than
            // leaving it stuck in 'queued' with nothing working on it.
            supabase.from('error_signatures')
              .update({ status: 'watching' })
              .eq('signature_hash', hash)
              .then(() => {}, () => {});
          });
      }

      if (row.out_is_regression) {
        sendAdminAlert(
          `Regression: the fix for ${hash.slice(0, 7)} did not hold`,
          { hash, page: ev.page, event: ev },
          hash,
        );
      }

      if (['queued', 'fix_in_progress'].includes(row.out_status)) {
        if (canOffer()) {
          reply.offerHelp = true;
          reply.cannedMessage = "We've seen this one and a fix is already underway.";
          reply.context = { hash: hash.slice(0, 12), type: ev.type, path: ev.path || ev.page };
        }
      } else if (row.out_status === 'regressed' || row.out_status === 'watching') {
        if (canOffer()) {
          reply.offerHelp = true;
          reply.context = { hash: hash.slice(0, 12), type: ev.type, path: ev.path || ev.page };
        }
      } else if (row.out_status === 'fix_shipped') {
        if (canOffer()) {
          reply.offerHelp = true;
          reply.cannedMessage = 'This was fixed recently. Reload the page and it should be gone.';
          reply.context = { hash: hash.slice(0, 12), type: ev.type, path: ev.path || ev.page };
        }
      }
    }

    return res.json(reply);
  } catch (err) {
    console.error('signal route error:', err);
    return res.json(reply);
  }
});

export default router;
