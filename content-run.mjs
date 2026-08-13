#!/usr/bin/env node
/**
 * content-run.mjs — run on the VM. Learns a public app (no creds), then runs a
 * "first-time visitor" test scenario, and reports the appId + testId + summary.
 * Consumes the SSE streams so we know exactly when each phase finishes.
 *
 *   node content-run.mjs "<appUrl>" "<scenario>"
 */
import 'dotenv/config';

const BASE = 'http://localhost:3001';
const OWNER = 'danijel.muranovic@gmail.com';           // super admin — bypasses ownership
const KEY = process.env.ANTHROPIC_SUPPORT_KEY;
const SECRET = process.env.BASE44_SHARED_SECRET;
if (!KEY) { console.error('no ANTHROPIC_SUPPORT_KEY'); process.exit(1); }

const url = process.argv[2];
const scenario = process.argv[3] || 'As a brand-new first-time visitor, explore the public site, click the main navigation and primary call-to-action buttons, and try to sign up for an account. Note anything broken, dead-ends, console errors, forms that fail to validate, or confusing steps.';
if (!url) { console.error('usage: node content-run.mjs <url> [scenario]'); process.exit(1); }

const hdr = { 'Content-Type': 'application/json', 'x-base44-auth': SECRET || '' };

// Read an SSE stream to completion, collecting parsed data objects.
async function drainSSE(res, onEvent) {
  const rd = res.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  for (;;) {
    const { done, value } = await rd.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf('\n\n')) >= 0) {
      const block = buf.slice(0, i); buf = buf.slice(i + 2);
      const line = block.split('\n').find(l => l.startsWith('data:'));
      if (!line) continue;
      try { onEvent(JSON.parse(line.slice(5).trim())); } catch {}
    }
  }
}

let appId = process.env.APPID || null;
const t0 = Date.now();
if (appId) {
  console.log(`\n### SKIP LEARN — using existing appId=${appId}`);
} else {
console.log(`\n### LEARN ${url}`);
{
  const res = await fetch(`${BASE}/api/learn`, {
    method: 'POST', headers: hdr,
    body: JSON.stringify({ url, userEmail: OWNER, apiKey: KEY }),
  });
  if (!res.ok) { console.error('learn HTTP', res.status, await res.text()); process.exit(1); }
  let pages = 0, forms = 0, lastMsg = '';
  await drainSSE(res, ev => {
    if (ev.appId) appId = ev.appId;
    if (ev.type === 'page' || ev.page) pages++;
    if (typeof ev.formsCount === 'number') forms = ev.formsCount;
    if (ev.message) lastMsg = ev.message;
    if (ev.type === 'complete' || ev.done || ev.map) {
      if (ev.appId) appId = ev.appId;
      if (ev.map?.pages) pages = ev.map.pages.length;
    }
  });
  console.log(`learned in ${((Date.now()-t0)/1000|0)}s  appId=${appId}  crawled≈${pages} pages  last="${lastMsg.slice(0,120)}"`);
}
}
if (!appId) { console.error('no appId from learn — aborting test'); process.exit(1); }

console.log(`\n### TEST ${appId}`);
{
  // /api/test takes appId + scenario (NOT url/description — that's /api/learn).
  const res = await fetch(`${BASE}/api/test`, {
    method: 'POST', headers: hdr,
    body: JSON.stringify({ appId, scenario, apiKey: KEY, userEmail: OWNER }),
  });
  const j = await res.json();
  const testId = j.testId;
  console.log(`testId=${testId} status=${j.status}`);
  if (!testId) { console.error('no testId', j); process.exit(1); }
  // Stream the run to completion.
  const s = await fetch(`${BASE}/api/test/${testId}/stream`, { headers: { 'x-base44-auth': SECRET || '', Cookie: '' } });
  let steps = 0, done = false, doneMsg = '';
  if (s.ok) {
    await drainSSE(s, ev => {
      if (ev.type === 'step' || ev.step) steps++;
      if (ev.type === 'done' || ev.type === 'complete' || ev.status === 'completed' || ev.status === 'blocked') { done = true; doneMsg = ev.message || ev.summary || doneMsg; }
    });
  }
  console.log(`test finished (stream): steps≈${steps} done=${done}`);
  console.log(`>>> RESULT_FILE tests/${testId}.json`);
}
