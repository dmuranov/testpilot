// Trust-critical classification logic, extracted from server.js so it can be
// unit-tested (the agent loop + deep-scan in server.js need a browser/Anthropic
// to run, but THESE decisions are pure functions of their inputs). Every bug
// the independent review + the security-dev audit caught this session is
// covered by test/sec-classify.test.mjs against THESE functions — so the live
// code (which imports them) is regression-guarded.
//
// Each function is lifted verbatim from the corresponding server.js site; if
// you change behavior here, update the test.

// ── SCOPE CAP (count enforcement) ──────────────────────────────
// Parse a cap ONLY from explicit limit phrasing. Returns the integer cap or
// null. Must NOT match "at least N" or benign prose ("only 5 tickets visible").
// A bare "only N" was REMOVED — too ambiguous, false-matched descriptive text.
export function parseScopeCap(scenario) {
  const m = String(scenario || '').match(/\b(?:no more than|not more than|at most|exactly|do not\s+[a-z ]{0,24}(?:more than|beyond|exceed)|do not exceed)\s+(\d+)\b/i);
  return m ? parseInt(m[1], 10) : null;
}

// ── DROPDOWN divergence note ───────────────────────────────────
// Whether to show the "you requested X but it didn't exist; selected Y" note.
// FALSE for "any/first" selections (method first-option*) — those succeeded as
// intended, so the note would be a false app-gap report. FALSE when the actual
// option matches the request (substring either way).
export function shouldFlagDropdownDivergence({ selected, requested, method }) {
  const actual = String(selected || '').trim();
  const req = String(requested || '').trim();
  if (!actual || !req) return false;
  if (String(method || '').startsWith('first-option')) return false;
  const matches = actual.toLowerCase().includes(req.toLowerCase()) || req.toLowerCase().includes(actual.toLowerCase());
  return !matches;
}

// ── COMMIT detection (scope-guard counting) ────────────────────
// Is this step a SUCCESSFUL state-changing commit toward the cap? Pure given
// the action/outcome/status. Excludes verify/nav, failures (checked on the CORE
// outcome, stripping the divergence NOTE so "did not exist" doesn't false-fail),
// and confirm-modal-OPEN clicks (counted twice otherwise).
export function isCommitStep({ action, outcome, status }) {
  if (status !== 'pass') return false;
  const o = String(outcome || ''), act = String(action?.action || '');
  const tg = String(action?.target || '');
  const stateChanging = ['select_dropdown', 'click', 'fill', 'fill_form'].includes(act);
  if (!stateChanging) return false;
  const oCore = o.split(/ — NOTE:| \[(?:HINT|PROGRESS|STRONG HINT)/)[0];
  // Failure terms — EN + ES.
  const failed = /could not|couldn'?t|did ?n.?t|⚠️|possible issue|unconfirmed|blocked|\bfailed\b|\bunable\b|not found|no se pudo|no se encontr|fall[oó]|no fue posible|sin resultado/i.test(oCore);
  if (failed) return false;
  if (/modal opened with options/i.test(o)) return false;
  return looksLikeCommit(o, act, tg);
}

// Does this OUTCOME (or click target) describe a successful state-changing
// commit? FULL bilingual coverage — English past-tense verbs are word-bounded
// (avoid false matches like "completely"/"sentence"); Spanish uses stems
// (covers -ado/-ada/-ido conjugations). Exported so the test asserts both.
const COMMIT_OUTCOME = /\bselected\b.*\bfrom\b|\b(created|saved|updated|deleted|removed|submitted|sent|completed|resolved|finished|accepted|rejected|approved|published|confirmed|marked|assigned|added)\b|asignad|completad|resuelt|finaliz|rechazad|guardad|confirmad|marcad|cread|actualizad|eliminad|borrad|enviad|aprobad|publicad|a[ñn]adid|agregad|aceptad/i;
const COMMIT_CLICK = /\b(save|create|update|delete|remove|submit|send|complete|resolve|finish|accept|reject|approve|publish|confirm|mark|assign|add)\b|guardar|crear|actualizar|eliminar|borrar|enviar|completar|resolver|finalizar|aceptar|rechazar|aprobar|publicar|confirmar|marcar|asignar|a[ñn]adir|agregar/i;
export function looksLikeCommit(outcome, action, target) {
  return COMMIT_OUTCOME.test(String(outcome || ''))
    || (String(action) === 'click' && COMMIT_CLICK.test(String(target || '')));
}

// ── SECURITY: public-path + auth-endpoint heuristics ───────────
export function isPublicPath(url) { return /\/public\//i.test(String(url || '')); }

// Replaying a captured auth/login/token request re-sends the original user's
// credentials, so a response containing that user's data is EXPECTED, not a
// cross-tenant leak. Exclude these from the IDOR/replay check.
export function isAuthReplayEndpoint(url, postData) {
  return /\/(auth|login|sign-?in|token|session|oauth|logout)(\b|\/|$)/i.test(String(url || ''))
    || /"password"\s*:|"pass"\s*:|grant_type=/i.test(String(postData || ''));
}

// ── SECURITY: CORS verdict ─────────────────────────────────────
// reflected-origin + credentials = real exploitable (critical). wildcard "*" +
// credentials = browser-REJECTED per Fetch spec → NOT exploitable, low hygiene.
export function corsVerdict({ acao, acac, evilOrigin }) {
  const acacTrue = /true/i.test(acac || '');
  if (acao === evilOrigin && acacTrue) return { verdict: 'VULNERABLE', severity: 'critical', kind: 'reflected' };
  if (acao === '*' && acacTrue) return { verdict: 'SUSPICIOUS', severity: 'low', kind: 'wildcard-creds' };
  if (acao === '*') return { verdict: 'SUSPICIOUS', severity: 'low', kind: 'wildcard' };
  return { verdict: 'SAFE', severity: 'none', kind: 'restricted' };
}

// ── SECURITY: no-auth verdict ──────────────────────────────────
// data without auth on a non-/public/ path = VULNERABLE/high. On /public/ =
// low hygiene — UNLESS it leaks User A's private data, then critical regardless.
export function noAuthVerdict({ hasData, isPublic, leaksPrivateData }) {
  if (!hasData) return { verdict: 'SAFE', severity: 'none' };
  if (leaksPrivateData) return { verdict: 'VULNERABLE', severity: 'critical' };
  if (!isPublic) return { verdict: 'VULNERABLE', severity: 'high' };
  return { verdict: 'SUSPICIOUS', severity: 'low' };
}

// ── SECURITY: cross-tenant (API replay) verdict ────────────────
// Confirmed leak (User B's response contains User A's private data) always wins.
// /public/ endpoints: identical/non-empty across users is expected → SAFE.
// Unconfirmed match on a non-public endpoint → SUSPICIOUS (never a HIGH "likely").
export function crossTenantVerdict({ gotUserAData, isPublic, responsesMatch, hasRealData }) {
  if (gotUserAData) return { verdict: 'VULNERABLE', severity: 'critical' };
  if (!isPublic && responsesMatch && hasRealData) return { verdict: 'SUSPICIOUS', severity: 'medium' };
  if (!isPublic && hasRealData) return { verdict: 'SUSPICIOUS', severity: 'medium' };
  return { verdict: 'SAFE', severity: 'none' };
}

// ── SECURITY: WSTG IDs + trustworthiness stamping ──────────────
export const WSTG = {
  api_replay: { id: 'WSTG-v42-ATHZ-04', name: 'IDOR via API', trust: '★★★★☆' },
  idor_direct: { id: 'WSTG-v42-ATHZ-03', name: 'IDOR (direct URL)', trust: '★★★★☆' },
  mutation: { id: 'WSTG-v42-ATHZ-04', name: 'Unauthorized mutation', trust: '★★★★☆' },
  no_auth: { id: 'WSTG-v42-ATHZ-02', name: 'Missing authorization', trust: '★★★★★' },
  token_swap: { id: 'WSTG-v42-SESS-06', name: 'Session invalidation', trust: '★★★★★' },
  token_swap_nav: { id: 'WSTG-v42-SESS-06', name: 'Session invalidation', trust: '★★★★★' },
  cors: { id: 'WSTG-v42-CLNT-07', name: 'CORS misconfiguration', trust: '★★★★★' },
  headers: { id: 'WSTG-v42-CONF-12', name: 'Security headers', trust: '★★★★★' },
  jwt: { id: 'WSTG-v42-SESS-09', name: 'JWT hygiene', trust: '★★★★☆' },
  rate_limit: { id: 'WSTG-v42-ATHN-03', name: 'Login rate limiting', trust: '★★★★☆' },
  info_disclosure: { id: 'WSTG-v42-ERRH-01', name: 'Information disclosure', trust: '★★★★☆' },
  open_redirect: { id: 'WSTG-v42-CLNT-04', name: 'Open redirect', trust: '★★★★☆' },
  mass_assignment: { id: 'WSTG-v42-BUSL-09', name: 'Mass assignment', trust: '★★★★☆' },
  cookie: { id: 'WSTG-v42-SESS-02', name: 'Cookie attributes', trust: '★★★★★' },
  broken_resource: { id: 'TP-PERF-04', name: 'Broken resources', trust: '★★★★★' },
  privacy_tracking: { id: 'TP-PRIV-01 (GDPR/ePrivacy)', name: 'Pre-consent tracking', trust: '★★★★★' },
  privacy_cookie: { id: 'TP-PRIV-02 (GDPR/ePrivacy)', name: 'Pre-consent cookies', trust: '★★★★★' },
};

// A SUSPICIOUS/unconfirmed verdict is INDICATIVE regardless of the test's
// baseline confidence → ★★★☆☆ + a caveat. Mutates the finding in place
// (matches server.js behavior) and returns it.
export function stampFinding(r) {
  const base = String(r.type || '').replace(/_skipped$/, '');
  const meta = WSTG[base] || WSTG[r.type];
  if (meta) { r.wstg = meta.id; r.wstgName = meta.name; }
  let trust = meta ? meta.trust : '★★★★☆';
  if (r.verdict === 'SUSPICIOUS' || r.verdict === 'INCONCLUSIVE' || r.verdict === 'POTENTIAL_VULNERABILITY') trust = '★★★☆☆';
  r.trust = trust;
  if (trust === '★★★☆☆' && r.note && !/manual|confirm|indicative|verify/i.test(r.note)) {
    r.note += ' [INDICATIVE — not auto-confirmed; manual verification needed before treating as a real finding].';
  }
  return r;
}
