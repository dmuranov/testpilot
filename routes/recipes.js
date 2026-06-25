// STEP-REPLAY MEMORY. Captures the successful action sequence of a clean test
// run and lets a future run of the SAME (app, scenario) replay it — skipping the
// slow per-step vision "think" — with a strict verify+fallback guard (the live
// agent takes over the moment a recorded step no longer matches the screen).
//
// TRUST MODEL: a recipe is an optimization, never a correctness dependency. Every
// replayed step is verified by IDENTITY (did it resolve to the SAME element/value
// it did at capture, via stepIdentity), not merely "did the executor not error".
// Any miss → silent fallback to the live agent. See test/recipes.test.mjs.
import { promises as fs } from 'fs';
import path from 'path';
import crypto from 'crypto';

// Resolved absolute path (not a bare relative string) so it can't bind to a
// different dir depending on the process cwd. Defaults under the app dir.
const RECIPES_DIR = process.env.TESTPILOT_RECIPES_DIR || path.join(process.cwd(), 'recipes');

// Placeholders that stand in for live credentials in a persisted recipe — the
// real email/password are NEVER written to disk (M5). server.js redacts on
// capture and re-substitutes the live credential on replay.
export const EMAIL_TOKEN = '__TP_LOGIN_EMAIL__';
export const PASSWORD_TOKEN = '__TP_LOGIN_PASSWORD__';

// Same task phrased identically → same recipe. Normalize away casing/whitespace
// so trivial differences still hit. (Deliberately NOT fuzzy — a different task
// must NOT reuse the wrong recipe; the cost of a miss is just a live run.)
export function normalizeScenario(scenario) {
  return String(scenario || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

export function recipeKey(appId, scenario) {
  const norm = normalizeScenario(scenario);
  const hash = crypto.createHash('sha1').update(norm).digest('hex').slice(0, 16);
  return `${String(appId || 'app').replace(/[^a-z0-9_-]/gi, '_')}__${hash}`;
}

// Only capture from a CLEANLY-completed run: the agent reached `done`, no
// CONFIRMED app bugs, and status is EXACTLY `completed`. `completed_with_unverified`
// is excluded (H2) — a run whose required check went unconfirmed must never
// become a "known-good" recipe that's then replayed forever.
export function shouldCaptureRun(result) {
  const status = String(result?.status || '');
  const bugs = Array.isArray(result?.bugs) ? result.bugs.length : (result?.summary?.bugs || 0);
  const calledDone = Array.isArray(result?.steps) && result.steps.some(s => s.action === 'done');
  return status === 'completed' && bugs === 0 && calledDone;
}

// Which actions are worth recording/replaying — the ones that move the workflow.
// Excludes verify/scroll/wait/done (re-derived live) and anything else.
export function isReplayableAction(action) {
  return ['navigate', 'click', 'fill', 'fill_form', 'select_dropdown'].includes(String(action?.action || ''));
}

// A recipe is usable only if EVERY step is a known replayable action AND carries
// the `_expect` identity block (so each replayed step can be identity-verified —
// C1). Anything else — a non-replayable/injected action, or an old pre-identity
// recipe — rejects the whole recipe and the caller runs live. We deliberately do
// NOT enforce per-action field shapes here: the action field names vary
// (select_dropdown uses `trigger`, fill_form uses `fills`, …), the executor is
// defensive about missing fields (a miss → "could not find" → drift → live), and
// navigate URLs are independently clamped to the app origin on replay (H3). So
// the only real risks to gate are a non-replayable action and a missing identity.
export function validateSteps(steps) {
  return Array.isArray(steps) && steps.length > 0 &&
    steps.every(s => isReplayableAction(s) && s._expect && typeof s._expect === 'object');
}

// A replayed step "still matches" if its executor succeeded (status 'pass') AND
// the outcome doesn't signal a not-found/blocked/failure. This is necessary but
// NOT sufficient — the caller ALSO checks stepIdentity (C1). Any miss → caller
// drops replay and hands the live agent the current state.
export function replayStepHeld(status, outcome) {
  if (status !== 'pass') return false;
  return !/could not|couldn'?t|not found|no se pudo|blocked|did ?n.?t|failed|REPEATED CLICK BLOCKED|CLOSE BLOCKED|DUPLICATE FILL/i.test(String(outcome || ''));
}

// The IDENTITY of a step's RESULT, parsed from its outcome string. This is the
// core C1 defense: at capture we store this; on replay we recompute it from the
// live outcome and require a match, so a step that resolved to a DIFFERENT
// element/value (reordered list, moved field, changed first-option dropdown) is
// caught even though the executor reported a clean "pass".
//  - id:  a stable entity id ([ID: ...]) when the action opened/acted on an
//         identifiable record — the strongest signal.
//  - sig: a weaker fallback signature (clicked text / selected option / nav path
//         / filled field) used when there is no [ID:].
export function stepIdentity(action, outcome) {
  const o = String(outcome || '');
  const norm = s => (s ? String(s).toLowerCase().replace(/\s+/g, ' ').trim() : null);
  const id = norm((o.match(/\[ID:\s*([^\]]+)\]/) || [])[1]);
  const act = String(action?.action || '');
  let sig = id;
  if (!sig) {
    if (act === 'select_dropdown') {
      sig = (o.match(/Selected\s+"([^"]+)"/i) || [])[1] || null;
    } else if (act === 'navigate') {
      const u = (o.match(/https?:\/\/[^\s"]+/i) || [])[0] || String(action?.url || '');
      sig = u ? u.split(/[?#]/)[0] : null;
    } else if (act === 'click') {
      sig = (o.match(/Clicked\s+"([^"]+)"/i) || [])[1] || (o.match(/(Dismissed[^.]*)/i) || [])[1] || null;
    } else if (act === 'fill' || act === 'fill_form') {
      sig = (o.match(/Filled\s+"([^"]+)"/i) || [])[1] || act;
    }
  }
  return { id, sig: norm(sig) };
}

export async function loadRecipe(appId, scenario) {
  try {
    const p = path.join(RECIPES_DIR, recipeKey(appId, scenario) + '.json');
    const r = JSON.parse(await fs.readFile(p, 'utf-8'));
    return validateSteps(r?.steps) ? r : null; // H3: reject corrupted / pre-identity recipes
  } catch { return null; } // no recipe yet / unreadable → live run
}

export async function saveRecipe(appId, scenario, steps, meta = {}) {
  try {
    if (!Array.isArray(steps) || steps.length === 0) return false;
    await fs.mkdir(RECIPES_DIR, { recursive: true });
    const p = path.join(RECIPES_DIR, recipeKey(appId, scenario) + '.json');
    let prior = null;
    try { prior = JSON.parse(await fs.readFile(p, 'utf-8')); } catch {}
    const record = {
      appId,
      scenario,
      normalizedScenario: normalizeScenario(scenario),
      steps,
      createdAt: prior?.createdAt || new Date().toISOString(),
      lastCapturedAt: new Date().toISOString(),
      captures: (prior?.captures || 0) + 1,
      ...meta,
    };
    // Atomic write (M6): write a temp file then rename, so a concurrent
    // loadRecipe never observes a half-written (torn) file.
    const tmp = p + '.' + crypto.randomBytes(4).toString('hex') + '.tmp';
    await fs.writeFile(tmp, JSON.stringify(record, null, 2));
    await fs.rename(tmp, p);
    return true;
  } catch { return false; } // capture failure must never break a test
}
