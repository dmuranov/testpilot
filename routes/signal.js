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
  HOURLY_ENQUEUE_CAP: 3,        // max auto-fix jobs started in any rolling hour
  CIRCUIT_WINDOW_MS: 10 * 60_000,   // "distinct new signatures" lookback for the breaker
  CIRCUIT_THRESHOLD: 5,             // more than this many brand-new signatures in the window trips it
  CIRCUIT_COOLDOWN_MS: 30 * 60_000, // how long the breaker stays open once tripped
  STRANDED_QUEUED_MS: 5 * 60_000,      // a 'queued' row with no job_id past this age is stranded
  STRANDED_SWEEP_INTERVAL_MS: 5 * 60_000,
  IGNORED_DIGEST_INTERVAL_MS: 7 * 24 * 60 * 60_000, // weekly
  IGNORED_DIGEST_THRESHOLD: 10, // occurrence_count on the WORST ignored signature before it's worth an email
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

// ------------------------------------------------------------ enqueue limits
// A per-signature threshold (3 occurrences/2 sessions) has no idea how many
// OTHER signatures are also crossing it right now. A bad deploy produces
// many distinct brand-new signatures at once — different stack origins on
// different pages — each independently legitimate by its own count, but
// ten simultaneous agent runs and ten PRs is not the right response to one
// bad deploy; one rollback is. Two independent guards:
//   - an hourly ceiling on actual auto-enqueues, so volume alone can't run
//     up unbounded agent/API spend even on a slow, steady stream of real bugs
//   - a circuit breaker keyed on brand-new signatures appearing (not on
//     enqueues — this needs to trip BEFORE any of them individually reaches
//     enqueue-eligibility, since that's the whole point of catching a bad
//     deploy fast rather than after several independent thresholds clear)
const enqueueTimestamps = [];      // one entry per actual auto-enqueue, for the hourly cap
const newSignatureTimestamps = []; // one entry per signature's very first occurrence
let breakerTrippedUntil = 0;

function pruneOlderThan(arr, windowMs) {
  const cutoff = Date.now() - windowMs;
  while (arr.length && arr[0] < cutoff) arr.shift();
}

function noteNewSignature() {
  const now = Date.now();
  newSignatureTimestamps.push(now);
  pruneOlderThan(newSignatureTimestamps, CFG.CIRCUIT_WINDOW_MS);
  if (newSignatureTimestamps.length > CFG.CIRCUIT_THRESHOLD && now >= breakerTrippedUntil) {
    breakerTrippedUntil = now + CFG.CIRCUIT_COOLDOWN_MS;
    sendAdminAlert(
      `Circuit breaker: ${newSignatureTimestamps.length} distinct new error signatures in ${Math.round(CFG.CIRCUIT_WINDOW_MS / 60000)} minutes — auto-fix paused`,
      { count: newSignatureTimestamps.length, windowMs: CFG.CIRCUIT_WINDOW_MS, pausedUntil: new Date(breakerTrippedUntil).toISOString() },
      'circuit-breaker',
    );
  }
}

// Reason is returned (not just a boolean) because the caller needs to know
// whether this is retryable later (rate/breaker — put the signature back to
// 'watching') or terminal (a 4xx — see the client-error check at the call
// site, handled separately since it isn't a rate limit at all).
function enqueueRateLimitReason() {
  const now = Date.now();
  if (now < breakerTrippedUntil) return 'circuit_breaker';
  pruneOlderThan(enqueueTimestamps, 60 * 60_000);
  if (enqueueTimestamps.length >= CFG.HOURLY_ENQUEUE_CAP) return 'hourly_cap';
  return null;
}

// Every rollback below writes a signature's status back from 'queued' —
// the RPC's enqueue branch only ever fires from 'watching', so a row left
// stranded at 'queued' (this write failing silently, a network blip, the
// process dying mid-request) can never be picked up again no matter how
// many more times the underlying bug recurs. Logging on failure here is
// necessary but not sufficient — see sweepStrandedQueued below for the
// same-shape failure this can't catch (nothing runs this code at all).
function resetSignatureStatus(hash, status) {
  return supabase.from('error_signatures').update({ status }).eq('signature_hash', hash)
    .then(({ error }) => {
      if (error) console.error(`[signal] failed to reset ${hash.slice(0, 12)} to '${status}':`, error.message);
    }, (e) => {
      console.error(`[signal] failed to reset ${hash.slice(0, 12)} to '${status}':`, e.message);
    });
}

// Self-healing backstop for exactly that case: a row sitting in 'queued'
// with no job_id (so no enqueue attempt is actually in flight for it) past
// a few minutes is stranded, whatever the cause. Sweeping it back to
// 'watching' means the next real occurrence — and there will be one, since
// nothing about the underlying bug changed — gets a fresh chance to enqueue.
//
// Filtered on queued_at, NOT last_seen: last_seen is bumped by record_signal
// on every occurrence, including while the row is stranded and actively
// recurring — the case that matters most, and the one a last_seen-based
// filter can never catch (a live bug's last_seen is always recent).
// queued_at (see sql/002_queued_at.sql) is stamped once, on the transition
// into 'queued', and untouched by anything after — its age is genuinely how
// long the row has been stuck.
async function sweepStrandedQueued() {
  try {
    const cutoff = new Date(Date.now() - CFG.STRANDED_QUEUED_MS).toISOString();
    const { data, error } = await supabase
      .from('error_signatures')
      .update({ status: 'watching' })
      .eq('status', 'queued')
      .is('job_id', null)
      .lt('queued_at', cutoff)
      .select('signature_hash');
    if (error) { console.error('[signal] stranded-queued sweep failed:', error.message); return; }
    if (data && data.length) {
      console.warn(`[signal] swept ${data.length} signature(s) stranded in 'queued' back to 'watching': ${data.map((r) => r.signature_hash.slice(0, 12)).join(', ')}`);
    }
  } catch (e) {
    console.error('[signal] stranded-queued sweep failed:', e.message);
  }
}
setInterval(sweepStrandedQueued, CFG.STRANDED_SWEEP_INTERVAL_MS).unref?.();

// 'ignored' is terminal (see the isClientError branch below) — a 4xx that
// crosses the enqueue threshold is written off permanently and never
// re-evaluated. Correct for a typo'd URL, but a shipped validation
// regression that starts rejecting previously-valid input is a real bug
// wearing a 4xx, and would be silently written off the same way. A query
// nobody is scheduled to run is a query nobody runs — this turns
// sql/watch-ignored-signatures.sql into an actual alert instead of
// something that depends on a human remembering, the same way the
// occurrence-count sweep depends on a human reading it. Sends nothing when
// the worst offender is still just routine trickle (many distinct typos,
// few hits each); sends once when one signature's count suggests a cliff
// (many hits on the SAME rejected shape) instead.
async function sendIgnoredDigestIfDue() {
  try {
    const { data, error } = await supabase
      .from('error_signatures')
      .select('signature_hash,occurrence_count,session_count,raw_sample')
      .eq('status', 'ignored')
      .order('occurrence_count', { ascending: false })
      .limit(20);
    if (error) { console.error('[signal] ignored-digest query failed:', error.message); return; }
    if (!data || !data.length) return;

    const worst = data[0];
    if (worst.occurrence_count < CFG.IGNORED_DIGEST_THRESHOLD) return; // routine trickle — nothing worth a human's time

    const table = data.map((r) => {
      const ev = (r.raw_sample && r.raw_sample.event) || {};
      return `${r.occurrence_count}x (${r.session_count} sessions) — ${ev.path || (r.raw_sample && r.raw_sample.page) || 'unknown'} status=${ev.status ?? 'n/a'} — ${r.signature_hash.slice(0, 12)}`;
    }).join('\n');

    await sendAdminAlert(
      `Weekly check: ${worst.occurrence_count}x on one 'ignored' signature — possible validation regression, not just typo trickle`,
      { topSignatureHash: worst.signature_hash, topOccurrenceCount: worst.occurrence_count, table },
      'ignored-digest-weekly',
    );
  } catch (e) {
    console.error('[signal] ignored-digest failed:', e.message);
  }
}
setInterval(sendIgnoredDigestIfDue, CFG.IGNORED_DIGEST_INTERVAL_MS).unref?.();

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

      if (row.out_occurrences === 1) noteNewSignature();

      if (row.out_should_enqueue) {
        // 4xx is an input problem, not a bug — a rejected URL, bad
        // credentials, a validation guard doing its job. Every distinct
        // typo normalizes to the same signature, so this class crosses the
        // occurrence/session threshold FASTER than most real bugs ever
        // would; auto-enqueueing on it means asking an agent to "fix" a
        // guard that's working correctly. 5xx and anything with no status
        // at all (network_failure, uncaught_error, stream_stalled, ...) is
        // TestPilot's own fault and stays eligible.
        const isClientError = typeof ev.status === 'number' && ev.status >= 400 && ev.status < 500;
        const rateLimitReason = isClientError ? null : enqueueRateLimitReason();

        if (isClientError) {
          // Terminal, not retryable — mark it so future occurrences of the
          // same signature don't re-evaluate at all (the RPC's 'watching'
          // branch never touches 'ignored'). Help is still offered below;
          // "we noticed you're stuck" is genuinely right even when nothing
          // is going to auto-fix it.
          row.out_status = 'ignored';
          resetSignatureStatus(hash, 'ignored');
        } else if (rateLimitReason) {
          console.warn(`[signal] enqueue suppressed for ${hash.slice(0, 12)} (${rateLimitReason})`);
          // Retryable — hand it back to 'watching' so a later hit (this
          // signature, still real) gets re-evaluated once capacity frees up,
          // rather than sitting in 'queued' with nothing ever processing it.
          row.out_status = 'watching';
          resetSignatureStatus(hash, 'watching');
        } else {
          // Exactly one caller ever reaches here for a given hash — the RPC
          // flipped status to 'queued' under a row lock.
          enqueueTimestamps.push(Date.now());
          enqueueFixJob({ hash, page: ev.page, event: ev })
            .then((r) => supabase.from('error_signatures')
              .update({ job_id: r && r.jobId ? String(r.jobId) : null, status: 'fix_in_progress' })
              .eq('signature_hash', hash))
            .catch((e) => {
              console.error('enqueueFixJob failed:', e.message);
              // Hand the signature back so a later hit can retry rather than
              // leaving it stuck in 'queued' with nothing working on it.
              resetSignatureStatus(hash, 'watching');
            });
        }
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
      } else if (row.out_status === 'regressed' || row.out_status === 'watching' || row.out_status === 'ignored') {
        // 'ignored' (a 4xx that crossed the threshold, or one rate-limited
        // by the caps above) still gets a genuine "we noticed you're
        // stuck" — it only skips the misleading "a fix is underway".
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
