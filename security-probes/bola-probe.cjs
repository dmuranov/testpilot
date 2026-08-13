#!/usr/bin/env node
/**
 * BOLA / horizontal-IDOR probe for Base44 (and similar) apps.
 *
 * Base44 entity APIs return ALL rows by default (no row-level security) unless
 * the app adds it. Apps that filter client-side LOOK isolated in the UI but leak
 * every tenants data at the API. UI-only tests miss this entirely; this probe
 * catches it by logging in as two DIFFERENT low-priv users and replaying the
 * entity calls one made using the OTHERs token.
 *
 * Usage:
 *   node bola-probe.cjs <startUrl> <victimEmail> <victimPass> <attackerEmail> <attackerPass>
 * Verdict: for each entity, LEAK if the attacker token returns rows owned by
 * someone other than the attacker.
 */
const { chromium } = require("/home/azureuser/testpilot/node_modules/playwright");

async function login(browser, startUrl, email, password) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const entityCalls = new Map(); // "Entity" -> full url (list-style)
  let bearer = null, meUrl = null;
  page.on("request", req => {
    const u = req.url();
    const m = u.match(/\/api\/apps\/[^/]+\/entities\/([A-Za-z0-9_]+)(\?|$|\/)/);
    if (m) {
      const h = req.headers();
      if (h.authorization && !bearer) bearer = h.authorization;
      if (/\/entities\/User\/me/.test(u)) meUrl = u;
      // Prefer the list call (has ?limit / ?sort), not per-id
      const ent = m[1];
      if (!entityCalls.has(ent) || /[?&]limit=/.test(u)) entityCalls.set(ent, u);
    }
  });
  await page.goto(startUrl, { waitUntil: "domcontentloaded", timeout: 30000 });
  await page.waitForTimeout(3500);
  const e = await page.$("input[type=email], input[name*=email i], input[placeholder*=mail i], input[type=text]");
  const p = await page.$("input[type=password]");
  if (!e || !p) { await ctx.close(); throw new Error("login form not found for " + email); }
  await e.fill(email); await p.fill(password);
  const btn = await page.$("button[type=submit], button:has-text(\"Iniciar\"), button:has-text(\"Entrar\"), button:has-text(\"Login\"), button:has-text(\"Acceder\")");
  if (btn) await btn.click(); else await p.press("Enter");
  await page.waitForTimeout(6000);
  const origin = new URL(startUrl).origin;
  await ctx.close();
  return { bearer, entityCalls, meUrl, origin };
}

async function fetchJson(origin, url, bearer) {
  const r = await fetch(url, { headers: { Authorization: bearer, "Content-Type": "application/json" } });
  let body = null; try { body = await r.json(); } catch {}
  const rows = Array.isArray(body) ? body : (body && (body.items || body.data || body.results)) || [];
  return { status: r.status, rows };
}
function ownerOf(row) {
  return row.owner_user_id || row.created_by_id || row.created_by || row.owner || row.user_email || row.email || "(unknown)";
}

(async () => {
  const [startUrl, vE, vP, aE, aP] = process.argv.slice(2);
  if (!aP) { console.error("usage: node bola-probe.cjs <url> <victimEmail> <victimPass> <attackerEmail> <attackerPass>"); process.exit(1); }
  const browser = await chromium.launch({ headless: true });
  try {
    const victim = await login(browser, startUrl, vE, vP);
    const attacker = await login(browser, startUrl, aE, aP);
    if (!victim.bearer || !attacker.bearer) throw new Error("failed to capture a bearer token");
    // attacker identity
    let attackerId = aE.toLowerCase();
    if (attacker.meUrl) { const me = await fetchJson(attacker.origin, attacker.meUrl, attacker.bearer); const m = me.rows[0] || (me.status===200?null:null); }
    const entities = [...new Set([...victim.entityCalls.keys()])].filter(e => e !== "User");
    console.log("== BOLA probe ==");
    console.log("victim:", vE, "| attacker:", aE);
    console.log("entities loaded by victim UI:", entities.join(", "));
    console.log("");
    let leaks = 0;
    const rowId = r => r.id || r._id || r.uid || JSON.stringify(r).slice(0,64);
    for (const ent of entities) {
      const url = victim.entityCalls.get(ent);
      const [a, v] = [await fetchJson(attacker.origin, url, attacker.bearer),
                      await fetchJson(victim.origin, url, victim.bearer)];
      if (a.status !== 200) { console.log(`  ${ent}: attacker HTTP ${a.status} (blocked - good)`); continue; }
      const vIds = new Set(v.rows.map(rowId));
      // Rows the attacker can read that ALSO belong to the victims dataset and
      // were NOT created by the attacker => cross-account object exposure.
      const aliasA = aE.split("@")[0].toLowerCase();
      const notAttackers = a.rows.filter(r => { const o = String(ownerOf(r)).toLowerCase(); return o !== aE.toLowerCase() && !o.includes(aliasA); });
      const crossVisible = notAttackers.filter(r => vIds.has(rowId(r)));
      const leak = crossVisible.length > 0;
      if (leak) leaks++;
      console.log(`  ${ent}: attacker sees ${a.rows.length} rows; ${crossVisible.length} are victim-owned & readable ${leak ? "=> ⚠ LEAK" : "=> ok"}`);
      if (leak) {
        const sample = crossVisible.slice(0,3).map(r => rowId(r) + (r.title||r.name||r.email? " ("+String(r.title||r.name||r.email).slice(0,30)+")":"" ));
        console.log(`     e.g. ${sample.join("; ")}`);
      }
    }
    console.log("");
    console.log(leaks > 0 ? `VERDICT: ⚠ FAIL — ${leaks} entit${leaks===1?"y":"ies"} expose cross-account rows (broken object-level authorization). Dismiss any that are legitimately shared reference data.`
                          : "VERDICT: ✅ PASS — no cross-account entity leakage detected.");
    } catch (e) {
    console.error("PROBE ERROR:", e.message);
  } finally {
    await browser.close();
  }
})();
