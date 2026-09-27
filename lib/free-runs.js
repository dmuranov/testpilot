// Free run allowance: how many EXTRA runs a free identity may start once its
// single free run (or free security scan) is already used. server.js decides
// how many runs an identity gets (runsFor) and which endpoints take one; this
// module owns the counter and the reserve/commit/release rule.
//
//   reserve(res, email) — takes one extra run synchronously (so two parallel
//                         requests cannot both take the last one) and returns a
//                         hold.
//   hold.commit()       — the run is really starting; keep the charge. Called
//                         right before the endpoint's success response.
//   response 'finish'   — if it arrives with no commit (an early 4xx, an error
//                         response), the run is given back. A client that goes
//                         away BEFORE the response is not a release: the handler
//                         may still start the run, and it stays charged.
//
// Persisted to `file` the same way free-security-used.json is, so a deploy
// (pm2 reload) does not re-grant everyone their extras. Keyed by
// canonicalEmail so gmail dots / plus-aliases are one identity.
export function createFreeRunAllowance({ canonicalEmail, runsFor, file, fs, log = console }) {
  const used = new Map();   // canonical email -> extra runs spent

  async function load() {
    try {
      for (const [e, n] of JSON.parse(await fs.readFile(file, 'utf-8'))) used.set(e, Number(n) || 0);
    } catch (e) {
      if (e.code !== 'ENOENT') log.warn('[free-runs] load failed:', e.message);
    }
  }
  function save() {
    fs.writeFile(file, JSON.stringify([...used])).catch(() => {});
  }

  const left = (email) =>
    Math.max(0, (runsFor(email) - 1) - (used.get(canonicalEmail(email)) || 0));
  const available = (email) => !!email && left(email) > 0;

  function reserve(res, email) {
    const ce = canonicalEmail(email);
    used.set(ce, (used.get(ce) || 0) + 1);
    save();
    let settled = false;
    res.once('finish', () => {
      if (settled) return;
      settled = true;
      used.set(ce, Math.max(0, (used.get(ce) || 0) - 1));
      save();
      log.log('[free-runs]', email, 'extra run released;', left(email), 'left');
    });
    return {
      commit() {
        if (settled) return;
        settled = true;
        log.log('[free-runs]', email, 'spent an extra run;', left(email), 'left');
      },
    };
  }

  return { load, left, available, reserve, used };
}
