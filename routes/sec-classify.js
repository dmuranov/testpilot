// Trust-critical classification logic, extracted from server.js so it can be
// unit-tested (the agent loop + deep-scan in server.js need a browser/Anthropic
// to run, but THESE decisions are pure functions of their inputs). Every bug
// the independent review + the security-dev audit caught this session is
// covered by test/sec-classify.test.mjs against THESE functions — so the live
// code (which imports them) is regression-guarded.
//
// Each function is lifted verbatim from the corresponding server.js site; if
// you change behavior here, update the test.

import { createHash } from 'crypto';

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
// "public" must be a whole PATH SEGMENT (/api/public/…, /public/config). A
// route that merely contains the word (/publications, ?tab=public) gets no
// free pass. The path alone is only a HINT — the scan confirms it by probing
// the endpoint logged-out (see isConfirmedPublic).
export function isPublicPath(url) {
  let path = String(url || '');
  try { path = new URL(path).pathname; } catch { path = path.split('?')[0]; }
  return /(?:^|\/)public(?:\/|$)/i.test(path);
}

// Public-by-design only when the path says so AND the unauthenticated probe
// actually got data back. A "/public/" path that 401s logged-out is NOT public.
export function isConfirmedPublic(url, noAuthProbe) {
  return isPublicPath(url) && !!noAuthProbe && noAuthProbe.status === 200 && !!noAuthProbe.hasData;
}

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
// No data is SAFE only when the app actually answered with a refusal (401/403,
// a 404 for a resource User A could read, or an empty 2xx). A request that never
// arrived, a server error or a malformed-request 4xx tested nothing.
export function noAuthVerdict({ hasData, isPublic, leaksPrivateData, reached = true, status = 200, aStatus }) {
  if (!reached) return { verdict: 'INCONCLUSIVE', severity: 'none', kind: 'unreachable' };
  if (hasData) {
    if (leaksPrivateData) return { verdict: 'VULNERABLE', severity: 'critical', kind: 'leak' };
    if (!isPublic) return { verdict: 'VULNERABLE', severity: 'high', kind: 'open' };
    return { verdict: 'SUSPICIOUS', severity: 'low', kind: 'public' };
  }
  if (status === 401 || status === 403) return { verdict: 'SAFE', severity: 'none', kind: 'refused' };
  if ((status === 404 || status === 410) && aStatus === 200) return { verdict: 'SAFE', severity: 'none', kind: 'refused' };
  if (status >= 200 && status < 300) return { verdict: 'SAFE', severity: 'none', kind: 'empty' };
  return { verdict: 'INCONCLUSIVE', severity: 'none', kind: status >= 500 ? 'server-error' : 'rejected' };
}

// ── SECURITY: request identity ─────────────────────────────────
// Exact key for one captured call. RPC/GraphQL/tRPC apps POST different bodies
// to the SAME url (listEntity Job vs listEntity Invoice), so a url-only map
// overwrote earlier responses and the A/B comparison compared the wrong pair.
export function requestKey({ method, url, postData }) {
  const m = String(method || 'GET').toUpperCase();
  const body = postData ? ` #${createHash('sha1').update(String(postData)).digest('hex').slice(0, 12)}` : '';
  return `${m} ${String(url || '')}${body}`;
}

const VOLATILE_QUERY = /^(_|t|ts|timestamp|nonce|cb|cache|rand|r|_t|__t)$/i;
const ID_TOKEN = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{8,}|\d{2,}|[A-Za-z0-9_-]{20,})$/i;
function normalizeIdsInText(s) {
  return String(s || '')
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, 'ID')
    .replace(/\b[0-9a-f]{16,}\b/gi, 'ID')
    .replace(/\b\d{3,}\b/g, 'ID');
}
// Dedupe key: same endpoint SHAPE. Hex / numeric / uuid path segments collapse to
// :id, volatile cache-buster params are dropped, id-like param values collapse
// to *, and the body is hashed with its ids normalized — so /jobs/1 and /jobs/2
// dedupe, but listEntity{Job} and listEntity{Invoice} stay separate endpoints.
export function endpointKey({ method, url, postData }) {
  const m = String(method || 'GET').toUpperCase();
  let u;
  try { u = new URL(String(url || '')); } catch { return `${m} ${normalizeIdsInText(url)}`; }
  const path = u.pathname.split('/').map(seg => (seg && ID_TOKEN.test(seg) ? ':id' : seg)).join('/');
  const params = [];
  for (const [k, v] of u.searchParams) {
    if (VOLATILE_QUERY.test(k)) continue;
    params.push(`${k}=${ID_TOKEN.test(v) ? '*' : v}`);
  }
  params.sort();
  const q = params.length ? `?${params.join('&')}` : '';
  const body = postData ? ` #${createHash('sha1').update(normalizeIdsInText(postData)).digest('hex').slice(0, 12)}` : '';
  return `${m} ${u.origin}${path}${q}${body}`;
}

// ── SECURITY: read vs write classification ─────────────────────
// Read-only mode may replay a call as User B ONLY if it is side-effect-free.
// GET/HEAD always are. Base44 / GraphQL / tRPC apps fetch data with POST, so a
// POST is a read when its path verb or body says so; an AMBIGUOUS POST (a REST
// create, an unknown RPC) is treated as a write and never replayed read-only.
const READ_TOKENS = new Set(['list', 'get', 'fetch', 'search', 'find', 'load', 'read', 'view', 'show', 'count', 'query', 'stats', 'summary', 'describe', 'lookup', 'me', 'context', 'whoami', 'profile', 'settings', 'config', 'history', 'export', 'preview', 'check', 'exists', 'filter', 'paginate', 'options', 'metadata', 'status', 'health', 'version']);
const WRITE_TOKENS = new Set(['create', 'update', 'delete', 'remove', 'save', 'set', 'upsert', 'insert', 'send', 'submit', 'post', 'put', 'patch', 'write', 'mutate', 'add', 'assign', 'invoke', 'run', 'execute', 'trigger', 'start', 'stop', 'cancel', 'approve', 'reject', 'publish', 'upload', 'import', 'sync', 'reset', 'register', 'login', 'signup', 'logout', 'invite', 'mark', 'toggle', 'archive', 'restore', 'generate', 'process', 'bulk', 'batch', 'edit', 'change', 'move', 'copy', 'duplicate', 'complete', 'finish', 'pay', 'charge', 'refund', 'notify', 'email', 'clear', 'purge', 'destroy', 'increment', 'decrement', 'join', 'leave', 'accept', 'decline', 'confirm', 'verify', 'resend', 'refresh', 'revoke', 'rotate', 'grant', 'transfer']);
function pathTokens(url) {
  let path = String(url || '');
  try { path = new URL(path).pathname; } catch { path = path.split('?')[0]; }
  return path.split('/').filter(Boolean)
    .flatMap(seg => seg.replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(/[\s_\-.]+/))
    .map(t => t.toLowerCase()).filter(Boolean);
}
export function isReadRequest({ method, url, postData }) {
  const m = String(method || 'GET').toUpperCase();
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return true;
  if (m !== 'POST') return false;
  const tokens = pathTokens(url);
  if (tokens.some(t => WRITE_TOKENS.has(t))) return false;
  if (tokens.some(t => READ_TOKENS.has(t))) return true;
  const body = String(postData || '');
  if (/"query"\s*:\s*"\s*(query\b|\{)/i.test(body) && !/"query"\s*:\s*"\s*mutation\b/i.test(body)) return true; // GraphQL query
  if (/"(operation|action|op|type|method)"\s*:\s*"(list|get|read|search|find|fetch|query|count)"/i.test(body)) return true;
  return false;
}

// ── SECURITY: record identity extraction ───────────────────────
// A cross-account leak is decided by OWNERSHIP, not by whether User A's email
// happens to appear in the body: most leaked records (a job card, an invoice)
// never repeat their owner's email. We collect the record ids and the
// owner-field values in a JSON body; the scan then compares User A's set with
// what User B's replay returned.
const ID_KEY = /^(id|_id|uuid|pk|record_id|recordId|objectId|object_id)$/i;
const REF_KEY = /(?:[a-z_]_id|[a-z]Id|[a-z_]ID|_uuid|[a-z]Uuid)$/;
const OWNER_KEY = /^(created_by|createdBy|created_by_id|createdById|owner|owner_id|ownerId|user_id|userId|author|author_id|authorId|org_id|orgId|organization_id|organizationId|tenant_id|tenantId|account_id|accountId|company_id|companyId|customer_id|customerId|assigned_to|assignedTo|email|user_email|userEmail)$/i;
// Small integers and short strings under a reference key (status_id: 1,
// type_id: "A") are enums, not records — they would collide across tenants.
function identityValue(v, { primary = true, minLen = 3 } = {}) {
  if (typeof v === 'number' && Number.isFinite(v)) return (primary || v >= 100) ? String(v) : null;
  if (typeof v === 'string') { const s = v.trim(); return s.length >= minLen && s.length <= 200 ? s : null; }
  return null;
}
export function extractRecordIdentity(body) {
  const ids = new Set(), owners = new Set();
  let root;
  try { root = typeof body === 'string' ? JSON.parse(body) : body; } catch { return { ids: [], owners: [] }; }
  let visited = 0;
  const walk = (node, depth) => {
    if (!node || typeof node !== 'object' || depth > 10 || visited++ > 5000) return;
    if (Array.isArray(node)) { for (const x of node) walk(x, depth + 1); return; }
    for (const [k, v] of Object.entries(node)) {
      if (OWNER_KEY.test(k)) { const val = identityValue(v); if (val !== null) owners.add(val); }
      else if (ID_KEY.test(k)) { const val = identityValue(v); if (val !== null) ids.add(val); }
      else if (REF_KEY.test(k)) { const val = identityValue(v, { primary: false, minLen: 6 }); if (val !== null) ids.add(val); }
      if (v && typeof v === 'object') walk(v, depth + 1);
    }
  };
  walk(root, 0);
  return { ids: [...ids], owners: [...owners] };
}

// Does a JSON body carry a record id (a POST-style record read: getEntity
// {"id":…}, {"job_id":…})? Used to pick IDOR candidates on RPC apps.
export function hasRecordIdInBody(postData) {
  return extractRecordIdentity(postData).ids.some(v => /^(?:[0-9a-f-]{8,}|\d+)$/i.test(v));
}

// Which of User A's EXCLUSIVE identifiers (never seen in User B's own session,
// never returned unauthenticated) appear in a body User B received.
export function findLeakedIdentity({ body, exclusiveIds = [], exclusiveOwners = [], markers = [] }) {
  const text = String(body || '');
  const lower = text.toLowerCase();
  const own = new Set(extractRecordIdentity(text).ids);
  const ownOwners = new Set(extractRecordIdentity(text).owners);
  const idMatches = exclusiveIds.filter(id => own.has(id));
  const ownerMatches = exclusiveOwners.filter(o => ownOwners.has(o));
  const markerMatches = markers.filter(m => lower.includes(String(m).toLowerCase()));
  return { idMatches, ownerMatches, markerMatches };
}

// ── SECURITY: cross-tenant (API replay) verdict ────────────────
// The single rule: SAFE only when the request genuinely REACHED the app and the
// app genuinely REFUSED (or returned none of User A's records). Anything the
// scan could not judge is INCONCLUSIVE — never SAFE.
//   reached        — a response actually arrived (status > 0; not CORS/network)
//   status         — HTTP status of User B's replay
//   aStatus        — HTTP status User A's own session got for the same call
//   hasRealData    — 2xx with a non-empty, non-HTML body
//   comparable     — User A's response held identifiable records to compare
//   ownerMatches / idMatches / markerMatches — from findLeakedIdentity
//   isPublic       — path says public AND the logged-out probe confirmed it
//   responsesMatch — A's and B's bodies are byte-identical
export function crossTenantVerdict({ reached, status, aStatus, hasRealData, comparable, ownerMatches = [], idMatches = [], markerMatches = [], isPublic, responsesMatch }) {
  if (!reached) return { verdict: 'INCONCLUSIVE', severity: 'none', kind: 'unreachable' };
  if (ownerMatches.length || markerMatches.length) return { verdict: 'VULNERABLE', severity: 'critical', kind: 'owner' };
  if (idMatches.length) return { verdict: 'VULNERABLE', severity: 'high', kind: 'record-id' };
  if (status >= 500) return { verdict: 'INCONCLUSIVE', severity: 'none', kind: 'server-error' };
  if (status === 401 || status === 403) return { verdict: 'SAFE', severity: 'none', kind: 'refused' };
  if (status === 404 || status === 410) {
    return aStatus === 200 ? { verdict: 'SAFE', severity: 'none', kind: 'refused' } : { verdict: 'INCONCLUSIVE', severity: 'none', kind: 'not-found' };
  }
  if (status >= 400) return { verdict: 'INCONCLUSIVE', severity: 'none', kind: 'rejected' };
  if (isPublic) return { verdict: 'SAFE', severity: 'none', kind: 'public' };
  if (!hasRealData) {
    return comparable ? { verdict: 'SAFE', severity: 'none', kind: 'isolated-empty' } : { verdict: 'INCONCLUSIVE', severity: 'none', kind: 'nothing-to-compare' };
  }
  if (comparable) return { verdict: 'SAFE', severity: 'none', kind: 'isolated' };
  if (responsesMatch) return { verdict: 'SUSPICIOUS', severity: 'medium', kind: 'identical' };
  return { verdict: 'INCONCLUSIVE', severity: 'none', kind: 'no-baseline' };
}

// ── SECURITY: replay prioritisation ────────────────────────────
// Only the first N unique endpoints get replayed; put the ones that can
// actually leak first: authenticated data reads whose User A response held
// records. Auth/login endpoints go last (they are excluded anyway).
export function prioritizeEndpoints(list) {
  const score = e => (e.aHasRecords ? 4 : 0) + (e.authed ? 3 : 0) + (e.isRead ? 2 : 0) + (e.aStatus === 200 ? 1 : 0) - (e.isAuthEndpoint ? 10 : 0);
  return [...list].map((e, i) => ({ e, i, s: score(e) })).sort((a, b) => b.s - a.s || a.i - b.i).map(x => x.e);
}

// ── SECURITY: login rate-limit probe body ──────────────────────
// The probe must never touch the customer's REAL test account: a login endpoint
// that locks accounts would lock User A. Swap every identity field for a
// fabricated address and every password for garbage. If no identity field can
// be found the probe is not safe to send — return ok:false and skip.
const IDENTITY_KEY = /^(email|e-?mail|username|user_?name|user|login|identifier|account|handle|phone)$/i;
export function fabricateLoginBody(postData, probeEmail) {
  const raw = String(postData || '');
  const probe = probeEmail || `tp-probe-${Math.random().toString(36).slice(2, 10)}@example.com`;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      let swapped = false;
      const walk = (o) => {
        for (const k of Object.keys(o)) {
          if (o[k] && typeof o[k] === 'object') { walk(o[k]); continue; }
          if (IDENTITY_KEY.test(k)) { o[k] = probe; swapped = true; }
          else if (/pass/i.test(k)) o[k] = 'WRONGPASS-' + Math.random().toString(36).slice(2);
        }
      };
      walk(parsed);
      return swapped ? { ok: true, body: JSON.stringify(parsed), probeEmail: probe } : { ok: false, reason: 'no identity field in login body' };
    }
  } catch {}
  if (/^[^=&\s]+=[^&]*(&[^=&\s]+=[^&]*)*$/.test(raw)) {
    const p = new URLSearchParams(raw);
    let swapped = false;
    for (const k of [...p.keys()]) {
      if (IDENTITY_KEY.test(k)) { p.set(k, probe); swapped = true; }
      else if (/pass/i.test(k)) p.set(k, 'WRONGPASS-' + Math.random().toString(36).slice(2));
    }
    return swapped ? { ok: true, body: p.toString(), probeEmail: probe } : { ok: false, reason: 'no identity field in login body' };
  }
  return { ok: false, reason: 'login body is not JSON or form-encoded' };
}

// ── SECURITY: IDOR candidate detection ─────────────────────────
// URLs that name a specific record. REST paths (/users/12345), hex/uuid
// segments, ?id= style params, numeric segments.
const ID_BEARING_PATTERNS = [
  /[?&]id=/i,
  /[?&](user|order|account|record|item|doc|invoice|client|job|ticket|post)Id=/i,
  /\/[a-f0-9]{8,}(?:\/|$|\?)/i,
  /\/(users|orders|accounts|records|items|docs|invoices|clients|jobs|tickets|posts|profile|account)\/[^\/?]+/i,
  /\/\d{3,}(?:\/|$|\?)/,
];
export function isIdBearingUrl(url) { return ID_BEARING_PATTERNS.some(p => p.test(String(url || ''))); }
export function isIdorCandidate({ method, url, postData }) {
  if (!isReadRequest({ method, url, postData })) return false;
  if (isAuthReplayEndpoint(url, postData)) return false;
  const m = String(method || 'GET').toUpperCase();
  if (m === 'GET' || m === 'HEAD') return isIdBearingUrl(url);
  return isIdBearingUrl(url) || hasRecordIdInBody(postData);
}

// Is a 2xx body real data (not an empty collection / HTML shell)?
export function bodyHasData(status, body) {
  const t = String(body || '');
  if (status < 200 || status >= 300) return false;
  if (t.length <= 20) return false;
  if (/<!doctype|<html/i.test(t.slice(0, 200))) return false;
  if (/^\s*(\[\s*\]|\{\s*\}|null)\s*$/.test(t)) return false;
  if (/^\s*\{\s*"(data|results|items|rows|records|result)"\s*:\s*(\[\s*\]|null|\{\s*\})\s*\}\s*$/.test(t)) return false;
  return true;
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
  if (trust === '★★★☆☆' && r.note && !/manual|confirm|indicative|verify|not tested|not run/i.test(r.note)) {
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
