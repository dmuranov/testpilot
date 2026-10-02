// End-to-end FREE client journey against a LOCAL TestPilot server, exactly as
// first-run.html and the dashboard do it over HTTP: signup → learn (free) →
// one free flow run → free click-check (/api/sweep). Prints what a client
// would see at each step plus a summary. See docs/client-journey-runbook.md.
//
//   node scripts/e2e-free-journey.mjs
//   TP_APP=https://www.saucedemo.com TP_APP_EMAIL=standard_user TP_APP_PW=secret_sauce node scripts/e2e-free-journey.mjs
//
// The server must be running locally (node server.js, no NODE_ENV): local
// mode sends no mail and runs no production jobs (lib/local-run.js). The test
// identity is an @example.com address, which the server treats as internal.
const BASE = process.env.TP_BASE || 'http://localhost:3001';
const USER = process.env.TP_USER || `e2e-free-${Date.now()}@example.com`; // @example.com = internal: no onboarding alerts
const APP_URL = process.env.TP_APP || 'https://www.saucedemo.com';
const APP_EMAIL = process.env.TP_APP_EMAIL || 'standard_user';   // saucedemo's published demo login
const APP_PW = process.env.TP_APP_PW || 'secret_sauce';
const SCENARIO = process.env.TP_SCENARIO || 'Log in, add the Sauce Labs Backpack to the cart, open the cart and check that the backpack is listed with its price.';

let cookie = '';
const t0 = Date.now();
const stamp = () => ((Date.now() - t0) / 1000).toFixed(0).padStart(4) + 's';
const log = (...a) => console.log(stamp(), ...a);
const post = async (path, body) => {
  const r = await fetch(BASE + path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) }, body: JSON.stringify(body) });
  const sc = r.headers.get('set-cookie'); if (sc && /tpsession=/.test(sc)) cookie = sc.split(';')[0];
  return r;
};
const get = (path) => fetch(BASE + path, { headers: cookie ? { Cookie: cookie } : {} });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const summary = { user: USER, app: APP_URL };

// 1. signup via the funnel (what first-run.html does)
{
  const r = await post('/api/funnel/start', { userEmail: USER, url: APP_URL, source: 'e2e', medium: 'local', campaign: 'free-journey' });
  const d = await r.json().catch(() => ({}));
  log('funnel/start', r.status, JSON.stringify(d).slice(0, 220));
  if (!r.ok) { summary.signup = 'FAIL ' + (d.error || r.status); console.log(JSON.stringify(summary, null, 2)); process.exit(1); }
  summary.signup = `ok plan=${d.session?.plan} free_run_used=${d.session?.free_run_used} cookie=${cookie ? 'yes' : 'NO'}`;
}

// 2. learn (free), streamed like the page reads it
let appId = null;
{
  const r = await post('/api/learn', { url: APP_URL, userEmail: USER, email: APP_EMAIL, password: APP_PW, freeLearn: true });
  log('learn', r.status, r.headers.get('content-type'));
  if (!r.ok) { const d = await r.json().catch(() => ({})); summary.learn = 'FAIL ' + (d.error || r.status) + ' ' + (d.code || ''); console.log(JSON.stringify(summary, null, 2)); process.exit(1); }
  const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = ''; let last = null; let loginMsg = null;
  while (true) {
    const { done, value } = await reader.read(); if (done) break;
    buf += dec.decode(value, { stream: true }); const lines = buf.split('\n'); buf = lines.pop();
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      let ev; try { ev = JSON.parse(line.slice(6)); } catch { continue; }
      if (ev.appId) appId = ev.appId;
      if (ev.phase === 'login' && ev.message) loginMsg = ev.message;
      if (ev.message) log('  learn:', ev.phase || '', String(ev.message).slice(0, 160));
      last = ev;
    }
  }
  summary.learn = `${last?.phase || 'stream-ended'} appId=${appId} login="${(loginMsg || '').slice(0, 90)}"`;
  if (!appId || last?.phase === 'error') { console.log(JSON.stringify(summary, null, 2)); process.exit(1); }
}

// 3. one free flow run
{
  const r = await post('/api/test', { appId, scenario: SCENARIO, email: APP_EMAIL, password: APP_PW, freeRun: true, userEmail: USER });
  const d = await r.json().catch(() => ({}));
  log('test', r.status, JSON.stringify(d).slice(0, 200));
  if (!r.ok || !d.testId) { summary.run = 'FAIL ' + (d.error || r.status) + ' ' + (d.code || ''); }
  else {
    let res = null;
    for (let i = 0; i < 180; i++) { // up to 15 min
      await sleep(5000);
      res = await get('/api/test/' + d.testId).then((x) => x.json()).catch(() => null);
      if (res && res.status && res.status !== 'running' && res.status !== 'pending' && res.status !== 'queued' && res.status !== 'starting') break;
      if (i % 6 === 5) log('  run status:', res?.status, 'steps:', res?.steps?.length ?? '?');
    }
    const steps = res?.steps || [];
    summary.run = `${res?.status} steps=${steps.length} passed=${steps.filter((s) => s.status === 'pass').length} failed=${steps.filter((s) => s.status === 'fail').length} bugs=${(res?.bugs || res?.findings || []).length}` + (res?.blockedReason ? ` blocked="${String(res.blockedReason.description || res.blockedReason).slice(0, 160)}"` : '');
    for (const s of steps.slice(0, 12)) log('  step', s.step, s.status, String(s.action || '').slice(0, 70), '→', String(s.outcome || '').slice(0, 90));
  }
}

// 4. free security check (dashboard "Check everything" → /api/sweep)
{
  const r = await post('/api/sweep', { appId, email: APP_EMAIL, password: APP_PW });
  const d = await r.json().catch(() => ({}));
  log('sweep', r.status, JSON.stringify(d).slice(0, 200));
  if (!r.ok || !d.sweepId) { summary.security = 'FAIL ' + (d.error || r.status) + ' ' + (d.code || ''); }
  else {
    let rep = null;
    for (let i = 0; i < 180; i++) {
      await sleep(5000);
      rep = await get('/api/sweep/' + d.sweepId).then((x) => x.json()).catch(() => null);
      if (rep && rep.status && rep.status !== 'running') break;
      if (i % 6 === 5) log('  sweep status:', rep?.status, 'items:', rep?.items?.length ?? '?', 'last:', String(rep?.log?.slice(-1)[0]?.message || rep?.log?.slice(-1)[0] || '').slice(0, 100));
    }
    const items = rep?.items || [];
    const by = {}; for (const it of items) { const k = it.verdict || it.status || it.severity || 'item'; by[k] = (by[k] || 0) + 1; }
    summary.security = `${rep?.status} items=${items.length} ${JSON.stringify(by)}`;
    for (const it of items.slice(0, 14)) log('  item', String(it.verdict || it.status || '').padEnd(9), String(it.title || it.name || it.check || '').slice(0, 90));
  }
}

console.log('\n=== FREE JOURNEY SUMMARY ===');
console.log(JSON.stringify(summary, null, 2));
