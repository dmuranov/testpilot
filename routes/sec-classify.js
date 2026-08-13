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

// Sub-classify a commit as create / mutate / destroy — for the cleanup ledger.
// CONSERVATIVE on create: only clearly-create verbs, never the ambiguous "saved",
// so a merely-edited record is never marked for teardown. A false miss (orphan)
// is safe; a false create (deleting a real record) is not.
const CREATE_RE = /\b(created|submitted|published|posted|added)\b|cread|enviad|publicad|a[ñn]adid|agregad/i;
const DESTROY_RE = /\b(deleted|removed|cancell?ed)\b|eliminad|borrad|cancelad/i;
const CREATE_TARGET = /\b(create|add|new|submit|post|publish)\b|crear|a[ñn]adir|agregar|nuev|publicar/i;
const DESTROY_TARGET = /\b(delete|remove|trash|discard)\b|eliminar|borrar|quitar|descartar/i;
export function classifyCommit({ action, outcome, status }) {
  if (!isCommitStep({ action, outcome, status })) return null;
  const o = String(outcome || '');
  const clickTgt = String(action && action.action) === 'click' ? String((action && action.target) || '') : '';
  if (DESTROY_RE.test(o) || DESTROY_TARGET.test(clickTgt)) return 'destroy';
  if (CREATE_RE.test(o) || CREATE_TARGET.test(clickTgt)) return 'create';
  return 'mutate';
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
  data_exposure: { id: 'OWASP-API3 / WSTG-v42-ATHZ-04', name: 'Excessive data exposure', trust: '★★★★☆' },
  xss_reflected: { id: 'WSTG-v42-INPV-01', name: 'Reflected XSS', trust: '★★★★☆' },
  session_fixation: { id: 'WSTG-v42-SESS-03', name: 'Session fixation', trust: '★★★★★' },
  logout_invalidation: { id: 'WSTG-v42-SESS-06', name: 'Session termination (logout)', trust: '★★★★☆' },
  secret_exposure: { id: 'WSTG-v42-CONF-04 / OWASP-A02', name: 'Exposed secret in client bundle', trust: '★★★★★' },
  rls_exposure: { id: 'WSTG-v42-ATHZ-02 / Supabase-RLS', name: 'Supabase RLS / anon-key exposure', trust: '★★★★★' },
};

// ── SECURITY: exposed secrets in the client JS bundle ──────────
// Vibe-coded apps routinely ship LIVE keys / service-role secrets in frontend
// JS. High-signal only (distinctive prefixes + a DECODED Supabase JWT role, so
// the safe anon key is ignored and only a real service_role key fires) — public
// results must not false-positive. Returns [{name, sev, redacted, file, note}].
const SECRET_PATTERNS = [
  { name: 'Stripe live secret key', re: /sk_live_[A-Za-z0-9]{20,}/g, sev: 'critical' },
  { name: 'Stripe restricted key',  re: /rk_live_[A-Za-z0-9]{20,}/g, sev: 'critical' },
  { name: 'Anthropic API key',      re: /sk-ant-[A-Za-z0-9-]{24,}/g, sev: 'critical' },
  { name: 'Supabase secret key',    re: /sb_secret_[A-Za-z0-9_-]{20,}/g, sev: 'critical' },
  { name: 'OpenAI project key',     re: /sk-proj-[A-Za-z0-9_-]{20,}/g, sev: 'critical' },
  { name: 'Google API key',         re: /AIza[0-9A-Za-z_-]{35}/g, sev: 'high' },
  { name: 'AWS access key ID',      re: /AKIA[0-9A-Z]{16}/g, sev: 'critical' },
  { name: 'GitHub token',           re: /gh[pousr]_[A-Za-z0-9]{36,}/g, sev: 'critical' },
  { name: 'Private key block',      re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, sev: 'critical' },
  { name: 'Supabase service env var', re: /SUPABASE_SERVICE(?:_ROLE)?_KEY/g, sev: 'high' },
];
function tpRedact(s) { s = String(s); return s.length > 14 ? s.slice(0, 9) + '…' + s.slice(-4) : s.slice(0, 5) + '…'; }
export function scanForSecrets(haystacks) {
  const found = new Map();
  const add = (name, sev, sample, file, note) => { const k = name + '|' + sample; if (!found.has(k)) found.set(k, { name, sev, redacted: sample, file, note }); };
  for (const h of (haystacks || [])) {
    const text = String(h.text || '');
    if (!text) continue;
    const file = (String(h.url || '').split('?')[0].split('/').pop()) || h.url || 'bundle';
    for (const p of SECRET_PATTERNS) {
      p.re.lastIndex = 0; let m, guard = 0;
      while ((m = p.re.exec(text)) && guard++ < 50) {
        add(p.name, p.sev, tpRedact(m[0]), file, `A ${p.name} is present in your client-side JavaScript (${file}) — anyone can read it straight from the browser. Rotate it now and move it to the server.`);
        if (found.size > 60) break;
      }
    }
    const jwtRe = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}/g;
    let jm, jg = 0;
    while ((jm = jwtRe.exec(text)) && jg++ < 50) {
      try {
        const b64 = jm[0].split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        const payload = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
        if (payload && payload.role === 'service_role') {
          add('Supabase service_role key', 'critical', tpRedact(jm[0]), file, `Your Supabase SERVICE_ROLE key is embedded in the client bundle (${file}). It bypasses ALL row-level security — anyone can read or wipe your entire database. Rotate it immediately; the browser should only ever use the anon key.`);
        }
      } catch {}
      if (found.size > 60) break;
    }
  }
  return [...found.values()];
}

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


// ── SECURITY: static-asset detection ───────────────────────────
// Static assets (JS/CSS bundles, images, fonts, media, WebAssembly / game-engine
// data like .wasm/.pck/.data) are PUBLIC BY ARCHITECTURE — the browser cannot
// load them otherwise. Loaders (Godot, Unity, Vite) fetch them via XHR/fetch so
// they get captured, but they are NOT API endpoints; serving them without auth
// is not an authz bug. Excluded from no_auth / cross-tenant checks so the vuln
// count reflects real data endpoints only. NOTE: .json is deliberately absent —
// data APIs commonly use it.
const STATIC_ASSET_EXT = /\.(?:js|mjs|cjs|jsx|ts|tsx|css|scss|sass|less|map|wasm|pck|data|unityweb|glb|gltf|bin|png|jpe?g|gif|svg|webp|avif|ico|bmp|cur|woff2?|ttf|eot|otf|mp4|webm|ogg|ogv|mp3|wav|flac|m4a|mov|pdf|zip|gz|br|txt)$/i;
export function isStaticAsset(url) {
  const path = String(url || '').split('#')[0].split('?')[0];
  return STATIC_ASSET_EXT.test(path);
}

// ── SECURITY: Supabase anon-key / RLS exposure ─────────────────
// Extract a target's Supabase project URL + PUBLIC anon key from its client
// bundle. The anon key is MEANT to be public — the real question is whether the
// tables behind it are protected by Row-Level Security. Returns {url, anonKey}
// or null. anonKey is a JWT whose decoded role is 'anon' (NOT service_role — a
// service_role in the bundle is the separate, already-flagged critical leak).
export function extractSupabaseConfig(haystacks) {
  let url = null, anonKey = null;
  const urlRe = /https:\/\/[a-z0-9]{16,}\.supabase\.co/i;
  const jwtRe = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}/g;
  for (const h of (haystacks || [])) {
    const text = String(h.text || '');
    if (!text) continue;
    if (!url) { const m = text.match(urlRe); if (m) url = m[0]; }
    if (!anonKey) {
      jwtRe.lastIndex = 0; let jm, guard = 0;
      while ((jm = jwtRe.exec(text)) && guard++ < 200) {
        try {
          const b64 = jm[0].split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
          const payload = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
          if (payload && payload.role === 'anon') { anonKey = jm[0]; break; }
        } catch {}
      }
      // Modern Supabase public key format (2024+) is not a JWT: sb_publishable_...
      if (!anonKey) { const pm = text.match(/sb_publishable_[A-Za-z0-9_-]{20,}/); if (pm) anonKey = pm[0]; }
    }
    if (url && anonKey) break;
  }
  return (url && anonKey) ? { url, anonKey } : null;
}

// Table names PostgREST exposes, parsed from the OpenAPI (Swagger 2.0) spec
// served at GET <url>/rest/v1/ with the anon apikey. Tables/views appear as
// top-level 'definitions' and as single-segment 'paths'. Excludes the root and
// rpc/ function endpoints.
export function supabaseTablesFromSpec(spec) {
  const out = new Set();
  if (spec && spec.definitions && typeof spec.definitions === 'object') {
    for (const k of Object.keys(spec.definitions)) out.add(k);
  }
  if (spec && spec.paths && typeof spec.paths === 'object') {
    for (const p of Object.keys(spec.paths)) {
      const m = String(p).match(/^\/([A-Za-z0-9_]+)$/);
      if (m && m[1] && !/^rpc$/i.test(m[1])) out.add(m[1]);
    }
  }
  return [...out];
}

// Classify one anon-key READ probe against a Supabase table. The anon key is
// public, so a 200 returning ROWS means RLS is missing/permissive for anon.
// Sensitive columns (PII/secrets) → VULNERABLE/critical (an unambiguous leak).
// Rows without obvious PII → SUSPICIOUS/medium (could be an intended public
// catalog — verify, don't scream). Anon-readable but empty → SUSPICIOUS/low.
// Any non-200 (401/403/404) → anon blocked → SAFE.
export function rlsReadVerdict({ status, rowCount, sensitiveFields }) {
  if (status !== 200) return { verdict: 'SAFE', severity: 'none' };                                   // 401/403/404 — anon blocked or table absent
  if (rowCount > 0 && sensitiveFields && sensitiveFields.length) return { verdict: 'VULNERABLE', severity: 'critical' };
  if (rowCount > 0) return { verdict: 'SUSPICIOUS', severity: 'medium' };                              // real rows readable by anon — verify intent
  return { verdict: 'SAFE', severity: 'none' };                                                        // 200 [] — RLS filtering rows / no data exposed
}

// Discover candidate Supabase table names from the app's OWN traffic + bundle.
// Necessary because modern Supabase blocks OpenAPI introspection for public keys
// (GET /rest/v1/ → 401), so the spec can't be listed. We look for the
// /rest/v1/<table> paths the app itself calls — the real tables, no guessing.
// Excludes the rpc/ function namespace.
export function supabaseTablesFromTraffic(sources) {
  const out = new Set();
  const re = /\/rest\/v1\/([A-Za-z0-9_]+)/g;
  for (const src of (sources || [])) {
    const text = String(src || '');
    let m; re.lastIndex = 0; let guard = 0;
    while ((m = re.exec(text)) && guard++ < 20000) {
      if (m[1] && !/^rpc$/i.test(m[1])) out.add(m[1]);
    }
  }
  return [...out];
}
