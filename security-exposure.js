// security-exposure.js — "is anything published that shouldn't be?"
//
// Every other check in the security suite needs two logged-in users, a browser,
// an Anthropic key and a run credit. This one needs a URL. It asks the question
// TestPilot's own deploy failed in August 2026: express.static('./') published
// the working directory, and /sessions.json served 57 live session tokens to
// anyone who asked.
//
// THE FALSE-POSITIVE PROBLEM, which is the whole engineering difficulty here:
// almost every host in our market (Netlify, Vercel, Lovable, Base44) answers
// unknown paths with 200 + index.html so a client-side router can handle them.
// A checker that trusts status codes reports every probe as a hit and the
// product loses all credibility on its first run. So we fingerprint the host's
// "nothing here" response first, and only report a path whose body BOTH differs
// from that fingerprint AND matches a content signature for the file we asked
// for. A status code is never trusted on its own.
//
// Evidence never contains secret values. For a .env we report which KEYS are
// exposed, never what they are set to.

import crypto from 'crypto';

const UA = 'TestPilot-SecurityScan/1.0 (+https://testpilotapp.dev)';
const BODY_CAP = 256 * 1024;   // never read more than this from a probe
const TIMEOUT_MS = 8000;

function looksBinary(buf) {
  for (let i = 0; i < Math.min(buf.length, 512); i++) if (buf[i] === 0) return true;
  return false;
}

async function probe(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': UA, 'Range': 'bytes=0-' + (BODY_CAP - 1) },
      redirect: 'manual',
      signal: controller.signal,
    });
    const buf = Buffer.from((await res.arrayBuffer()).slice(0, BODY_CAP));
    return {
      status: res.status,
      type: (res.headers.get('content-type') || '').split(';')[0].trim(),
      bytes: buf.length,
      body: looksBinary(buf) ? '' : buf.toString('utf8'),
      raw: buf,
      hash: crypto.createHash('sha1').update(buf).digest('hex'),
    };
  } catch (e) {
    return { status: 0, error: e.name === 'AbortError' ? 'timeout' : e.message, raw: Buffer.alloc(0), body: '', hash: '' };
  } finally {
    clearTimeout(timer);
  }
}

// Names only, never values.
function envKeys(body) {
  const keys = [];
  for (const line of body.split('\n').slice(0, 200)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=/);
    if (m) keys.push(m[1]);
  }
  return [...new Set(keys)];
}

function isEnvFile(b) {
  return /^\s*(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=/m.test(b);
}

function envEvidence(b) {
  const k = envKeys(b);
  const shown = k.slice(0, 8).join(', ');
  return k.length + ' variable(s) exposed' + (k.length ? ': ' + shown + (k.length > 8 ? ', …' : '') : '');
}

const CHECKS = [
  { path: '/.env', severity: 'critical', title: 'Environment file published',
    sig: isEnvFile, evidence: envEvidence },
  { path: '/.env.local', severity: 'critical', title: 'Environment file published',
    sig: isEnvFile, evidence: envEvidence },
  { path: '/.env.production', severity: 'critical', title: 'Environment file published',
    sig: isEnvFile, evidence: envEvidence },
  { path: '/.git/config', severity: 'critical', title: 'Git repository published',
    sig: b => b.includes('[core]'),
    evidence: () => 'Git config is readable — the repository may be fully clonable' },
  { path: '/.git/HEAD', severity: 'critical', title: 'Git repository published',
    sig: b => /^ref:\s+refs\//m.test(b),
    evidence: () => 'Full source history may be reconstructable' },
  { path: '/id_rsa', severity: 'critical', title: 'Private key published',
    sig: b => b.includes('PRIVATE KEY'),
    evidence: () => 'A private key file is downloadable' },
  { path: '/.npmrc', severity: 'critical', title: 'Package registry token published',
    sig: b => b.includes('_authToken') || b.includes('//registry'),
    evidence: () => 'Registry auth token is readable' },
  { path: '/sessions.json', severity: 'critical', title: 'Session store published',
    sig: b => { try { const j = JSON.parse(b); return Array.isArray(j) ? j.length > 0 : Object.keys(j).length > 0; } catch { return false; } },
    evidence: b => { try { const j = JSON.parse(b); const n = Array.isArray(j) ? j.length : Object.keys(j).length; return n + ' session record(s) downloadable — each one may be a usable login'; } catch { return 'Session data is downloadable'; } } },
  { path: '/database.sqlite', severity: 'critical', title: 'Database file published',
    sigRaw: r => r.slice(0, 15).toString('latin1').startsWith('SQLite format'),
    evidence: () => 'The database itself is downloadable' },
  { path: '/dump.sql', severity: 'critical', title: 'Database dump published',
    sig: b => /CREATE TABLE|INSERT INTO/i.test(b),
    evidence: () => 'A SQL dump is downloadable' },
  { path: '/package.json', severity: 'high', title: 'Build manifest published',
    sig: b => { try { const j = JSON.parse(b); return !!(j.name || j.dependencies); } catch { return false; } },
    evidence: b => { try { const j = JSON.parse(b); return 'Dependency list readable (' + Object.keys(j.dependencies || {}).length + ' deps) — maps your exact versions for known-CVE lookup'; } catch { return 'Manifest readable'; } } },
  { path: '/docker-compose.yml', severity: 'high', title: 'Deployment config published',
    sig: b => /^\s*services:/m.test(b),
    evidence: () => 'Service topology and often credentials are readable' },
  { path: '/Dockerfile', severity: 'high', title: 'Build config published',
    sig: b => /^FROM\s+\S/mi.test(b),
    evidence: () => 'Build steps are readable' },
  { path: '/.DS_Store', severity: 'low', title: 'Directory index leaked',
    sigRaw: r => r.slice(0, 8).toString('latin1').includes('Bud1'),
    evidence: () => 'Reveals file names in the deployed folder' },
];

// ── SITE VERIFICATION PREDICATES ──────────────────────────────
// Used by /api/security/verify-site. They live here, beside the scanner, so
// the deployed rule and the test are literally the same function.
//
// The trap: hosts in our market answer ANY path with 200 + index.html, and some
// 404 pages render the requested path back into the markup ("Page /tp-verify-x
// not found"). A token check that asks "does the response contain the token"
// therefore verifies every domain on earth, including ones the caller does not
// own. So the file must BE the token, and the meta match must find the token
// beside the verification name rather than loose in the page.
export function tokenFileMatches(body, token) {
  if (!body || !token) return false;
  const trimmed = String(body).trim();
  if (trimmed.length > 64) return false;   // a page, not a token file
  return trimmed === token;
}

export function metaTagMatches(html, token) {
  if (!html || !token) return false;
  const s = String(html);
  const at = s.indexOf('testpilot-site-verification');
  if (at === -1) return false;
  // Window BOTH ways: <meta content="…" name="testpilot-site-verification">
  // is as valid as the other order, and a forward-only window silently fails
  // it — which reads to the user as "I added the tag and it says no".
  return s.slice(Math.max(0, at - 200), at + 200).includes(token);
}

export async function scanExposedFiles(appUrl) {
  const origin = new URL(appUrl).origin;

  // 1. Fingerprint "nothing here". Two random paths: one bare and one that
  //    looks like a file, because some hosts only fall back to index.html for
  //    extensionless paths.
  const rand = () => crypto.randomBytes(8).toString('hex');
  const baselines = await Promise.all([
    probe(origin + '/tp-nonexistent-' + rand()),
    probe(origin + '/tp-nonexistent-' + rand() + '.json'),
  ]);
  const baselineHashes = new Set(baselines.filter(b => b.status === 200).map(b => b.hash));
  const catchAll = baselineHashes.size > 0;

  const findings = [];
  let checkedPaths = 0;

  for (const check of CHECKS) {
    const res = await probe(origin + check.path);
    checkedPaths++;
    if (res.status !== 200) continue;
    if (baselineHashes.has(res.hash)) continue;               // the SPA fallback
    if (res.type === 'text/html' && !check.sigRaw) continue;   // a page, not the file
    const matched = check.sigRaw ? check.sigRaw(res.raw) : (!!res.body && check.sig(res.body));
    if (!matched) continue;
    findings.push({
      severity: check.severity,
      title: check.title,
      path: check.path,
      detail: origin + check.path + ' is publicly downloadable — no login, no token, just the URL.',
      evidence: check.sigRaw ? check.evidence() : check.evidence(res.body),
      bytes: res.bytes,
    });
  }

  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => rank[a.severity] - rank[b.severity]);

  return { origin, checkedPaths, hostAnswersEverythingWith200: catchAll, findings };
}
