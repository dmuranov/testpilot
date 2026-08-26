// ═══════════════════════════════════════════════════════════════
// classify.js — the single source of truth for separating
// "the APP's faults" from "TESTPILOT's own limitations".
//
// The whole trust problem comes down to this: the moment a failure is
// recorded, its CAUSE is usually known (a Playwright selector missed, a
// vision call timed out, login couldn't be read, the app rendered an
// error). But historically every failure was dropped into one flat
// `bugs[]` array and the cause was lost — so a selector-miss looked
// identical to a real defect in every downstream layer (status,
// multi-role aggregation, staging regression flags, the red UI count).
//
// Every surface now stamps a finding with a CATEGORY + CONFIDENCE + CAUSE
// at the point of recording, using the helpers below. Exactly one rule
// then propagates everywhere: ONLY a high-confidence `app_bug` is allowed
// to count as a defect, flip status to "blocked/with-bugs", mark a
// regression, or say "do not publish". Everything else is still shown to
// the user — but in a separate "couldn't verify" bucket, never as the
// app's fault.
// ═══════════════════════════════════════════════════════════════

export const Category = {
  // The app demonstrably did the wrong thing. The ONLY category that
  // counts as a real defect in headline counts / regressions / status.
  APP_BUG: 'app_bug',
  // TestPilot couldn't find or operate something (selector miss, crawl
  // gap, budget exhausted). Says nothing about the app's correctness.
  TOOL_LIMITATION: 'tool_limitation',
  // Outside the app under test: our network/Anthropic API, login we
  // couldn't read, navigation timeout, wrong credentials supplied to us.
  ENVIRONMENT: 'environment',
  // Not enough evidence to call it either way. Informational only.
  UNCERTAIN: 'uncertain',
};

export const Confidence = { HIGH: 'high', LOW: 'low' };

// Machine cause string → default category. These are the causes the
// testing surfaces actually emit. `vision_broken` maps to APP_BUG but is
// deliberately recorded at LOW confidence from a single vision call — it
// must be confirmed (a second look / re-shot) before it can block a
// deploy. See promoteIfConfirmed().
const CAUSE_CATEGORY = {
  // ── app-side evidence ───────────────────────────────────────────
  vision_broken:      Category.APP_BUG,        // vision SAW a broken state
  app_error_visible:  Category.APP_BUG,        // an error/stacktrace rendered by the app
  // A structured assertion (URL pattern / DOM text / network response) is
  // deterministic evidence — a regex either matched reality or it didn't.
  // Unlike vision_broken it does NOT start low-confidence: there's no single
  // ambiguous model call to doubt here, so no second-opinion confirm pass is
  // needed before it can count as a real defect. See server.js's structured
  // verify path.
  state_assertion_failed: Category.APP_BUG,
  // ── TestPilot couldn't do something ─────────────────────────────
  selector_miss:      Category.TOOL_LIMITATION,
  click_failed:       Category.TOOL_LIMITATION,
  field_not_found:    Category.TOOL_LIMITATION,
  dropdown_failed:    Category.TOOL_LIMITATION,
  playwright_error:   Category.TOOL_LIMITATION,
  crawl_gap:          Category.TOOL_LIMITATION,
  budget_exhausted:   Category.TOOL_LIMITATION,
  // ── outside the app ─────────────────────────────────────────────
  login_vision:       Category.ENVIRONMENT,    // couldn't READ the login form
  login_credentials:  Category.ENVIRONMENT,    // creds we were given were rejected
  login_timeout:      Category.ENVIRONMENT,
  nav_timeout:        Category.ENVIRONMENT,
  api_error:          Category.ENVIRONMENT,     // Anthropic / our network failed
  timeout:            Category.ENVIRONMENT,
  // ── inconclusive ────────────────────────────────────────────────
  vision_uncertain:   Category.UNCERTAIN,
  // No network call matched the assertion's pattern at all — could be a
  // wrong pattern, timing, or a real miss. Not positive evidence of either.
  state_assertion_uncertain: Category.UNCERTAIN,
  // The assertion PASSED, but its own negative control didn't: the same
  // pattern also matches a trivially blank/absent state, so the pass may not
  // mean what it claims to. Informational, not a bug — the step's own
  // WORKS verdict stands — but worth a human's eye on the check itself.
  state_assertion_unproven: Category.UNCERTAIN,
};

/**
 * Build a normalized finding. Use this everywhere a failure/bug/issue is
 * recorded so every consumer can trust `category`/`confidence`.
 *
 * @param {object} f
 * @param {string} f.cause        machine cause (key of CAUSE_CATEGORY); unknown → uncertain
 * @param {string} f.description  human-readable detail
 * @param {string} [f.category]   override the cause→category default
 * @param {string} [f.confidence] 'high' | 'low' (default: high, except vision_broken→low)
 * @param {string} [f.severity]   only meaningful for app_bug; forced to null otherwise
 * @returns {object} finding with {category, confidence, cause, description, severity, ...rest}
 */
export function classifyFailure(f = {}) {
  const cause = f.cause || 'unknown';
  const category = f.category || CAUSE_CATEGORY[cause] || Category.UNCERTAIN;

  // A single vision "BROKEN" is inherently low-confidence — one model
  // call, one screenshot, no second opinion. It is a *candidate* app bug
  // until confirmed. Callers that confirm it should pass confidence:'high'.
  let confidence = f.confidence;
  if (!confidence) confidence = cause === 'vision_broken' ? Confidence.LOW : Confidence.HIGH;

  // Severity only means something for a real app defect. Anything else
  // carrying a severity label gives false equivalence with real bugs.
  const severity = category === Category.APP_BUG ? (f.severity || 'medium') : null;

  const { cause: _c, category: _cat, confidence: _cf, severity: _s, ...rest } = f;
  return { category, confidence, cause, severity, ...rest };
}

// Only a CONFIRMED app bug is a real defect. A low-confidence app_bug
// (single unconfirmed vision call) is shown to the user as a "possible
// issue" but must NOT drive counts, status, regressions, or "do not publish".
export function isConfirmedAppBug(finding) {
  return finding?.category === Category.APP_BUG && finding?.confidence === Confidence.HIGH;
}
export function isAppBug(finding) {
  return finding?.category === Category.APP_BUG;
}

// Promote a low-confidence vision bug to high confidence once a second
// independent observation agrees. Mutates and returns the finding.
export function promoteIfConfirmed(finding, confirmed) {
  if (confirmed && finding?.category === Category.APP_BUG) finding.confidence = Confidence.HIGH;
  return finding;
}

// Bucket a list of findings for headline display. `bugs` (the only count
// that should ever be shown as "defects found") = confirmed app bugs.
export function summarizeFindings(findings = []) {
  const out = { bugs: 0, possible: 0, toolLimitations: 0, environment: 0, uncertain: 0 };
  for (const f of findings) {
    if (isConfirmedAppBug(f)) out.bugs++;
    else if (f.category === Category.APP_BUG) out.possible++;     // low-confidence app bug
    else if (f.category === Category.TOOL_LIMITATION) out.toolLimitations++;
    else if (f.category === Category.ENVIRONMENT) out.environment++;
    else out.uncertain++;
  }
  return out;
}

// Legacy/fallback path: classify a raw outcome/failure_reason STRING when
// no structured cause is available (e.g. staging records that only stored
// `failure_reason`). Conservative: only positive evidence of an app error
// yields app_bug; anything that smells like a tool/login/network issue is
// kept OUT of the defect count.
export function classifyReasonText(text = '') {
  const t = String(text).toLowerCase();
  if (!t.trim()) return Category.UNCERTAIN;

  // TestPilot couldn't find/operate something.
  if (/could not find|couldn'?t find|no such element|selector|not visible|not found on (screen|page)|unable to locate|element not interactable/.test(t))
    return Category.TOOL_LIMITATION;

  // Outside the app: login we couldn't read, our API, network, timeouts.
  if (/login failed|could not (log|sign) ?in|email or password fields|anthropic|api (error|timeout|overloaded)|rate.?limit|econnreset|etimedout|network|navigation timeout|timed out|deadline exceeded|page\.goto/.test(t))
    return Category.ENVIRONMENT;

  // Positive evidence the APP itself errored.
  if (/\b(500|502|503|internal server error|stack ?trace|unhandled|exception|validation error|app crashed|blank (page|screen)|error message|rendered an error)\b/.test(t))
    return Category.APP_BUG;

  return Category.UNCERTAIN;
}
