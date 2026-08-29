// routes/link-audit.js
// Site Report — checks every link discovered during a crawl (not just the
// ones the crawl itself followed), so a dead link that isn't in the nav
// still shows up. Pure HTTP, no Playwright, no model calls — kept as its
// own module per the site-report spec's constraint not to keep growing
// server.js.
//
// Every target goes through the same SSRF guard used for the user-submitted
// crawl URL (routes/ssrf.js). That guard only validates the URL it's given —
// it does not follow redirects — so a link that 302s to an internal address
// would sail through if we let fetch() auto-follow. We instead follow
// redirects manually, one hop at a time, and re-run the guard on every hop.

import { assertPublicUrl } from './ssrf.js';

const DEFAULT_CONCURRENCY = 8;
const TIMEOUT_MS = 8000;
const DEFAULT_CAP = 300;
const MAX_REDIRECTS = 5;

async function checkOneUrl(url) {
  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const safe = await assertPublicUrl(current).catch((e) => ({ ok: false, error: String(e && e.message || e) }));
    if (!safe.ok) return { status: null, blocked: true, error: safe.error };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      let res = await fetch(current, { method: 'HEAD', redirect: 'manual', signal: controller.signal });
      // Some servers reject/misbehave on HEAD (405/501, or 0 which fetch
      // reports for an opaqueredirect/blocked response) — fall back to a
      // ranged GET so we don't download the whole body just for a status.
      if (res.status === 405 || res.status === 501 || res.status === 0) {
        res = await fetch(current, { method: 'GET', redirect: 'manual', headers: { Range: 'bytes=0-0' }, signal: controller.signal });
      }
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get('location');
        if (!loc) return { status: res.status };
        try { current = new URL(loc, current).href; } catch { return { status: res.status, error: 'bad-redirect-location' }; }
        continue; // re-validate the new target on the next iteration
      }
      return { status: res.status, finalUrl: hop > 0 ? current : undefined };
    } catch (e) {
      return { status: null, error: String(e && e.message || e).slice(0, 120) };
    } finally {
      clearTimeout(timer);
    }
  }
  return { status: null, error: 'too-many-redirects' };
}

/**
 * @param {Map<string, Set<string>>} linkMap  absolute URL -> set of page paths it appears on
 * @param {{ appOrigin?: string, concurrency?: number, cap?: number }} opts
 * @returns {Promise<Array<{url:string,status:number|null,firstParty:boolean,pages:string[],error?:string,blocked?:boolean}>>}
 */
export async function auditLinks(linkMap, opts = {}) {
  const { appOrigin = null, concurrency = DEFAULT_CONCURRENCY, cap = DEFAULT_CAP } = opts;
  const entries = [...linkMap.entries()].slice(0, cap);
  const results = new Array(entries.length);
  let next = 0;

  async function worker() {
    for (;;) {
      const idx = next++;
      if (idx >= entries.length) return;
      const [url, pages] = entries[idx];
      let firstParty = false;
      try { firstParty = appOrigin ? new URL(url).origin === appOrigin : false; } catch {}
      const r = await checkOneUrl(url);
      results[idx] = { url, firstParty, pages: [...pages], ...r };
    }
  }

  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, entries.length)) }, worker));
  return results;
}
