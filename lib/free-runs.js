// Free run allowance: how many EXTRA runs a free identity may start once its
// single free run (or free security scan) is already used. server.js decides
// how many runs an identity gets (runsFor) and which endpoints take one; this
// module owns the counter and the reserve/commit/release/refund rule.
//
//   reserve(res, email) — takes one extra run synchronously (so two parallel
//                         requests cannot both take the last one) and returns a
//                         hold. Holds live in memory only.
//   hold.commit()       — the run is really starting; the spend is recorded and
//                         persisted. Called right before the endpoint's success
//                         response. A commit that arrives after the TTL below
//                         has released the hold still charges: the run is
//                         starting, so it is paid for, even if that briefly
//                         puts the identity one over.
//   hold.refund()       — the committed run ended without a verdict about the
//                         app (our tooling failed): give the EXTRA back. This is
//                         what the endpoints' existing "no verdict → refund"
//                         blocks call for an extra run, instead of resetting the
//                         base free_run_used flag, which belongs to a different
//                         pool.
//   any response sent   — if the handler sends a response (res.end, which
//   without commit        res.json/send go through) without having committed,
//                         the hold is released — whatever the socket is doing.
//                         This wraps end() rather than listening for 'finish'
//                         because a response written to a client that already
//                         went away never finishes. A client that disconnects
//                         while the handler is still running is not a release:
//                         the handler may still start the run, and it stays
//                         charged.
//   holdTtlMs           — a handler that never answers at all would otherwise
//                         pin the hold for the life of the process; after this
//                         long it is released (default 15 min, far beyond any
//                         browser launch + login).
//
//   left(email)         — extras still startable now: runs - 1 - spent - held.
//                         What the gates use.
//   remaining(email)    — extras not yet spent: runs - 1 - spent. What the
//                         client is told, so another tab merely HOLDING the last
//                         extra (perhaps about to 4xx) does not paint a paywall.
//
// Only committed spends are persisted (to `file`, written tmp+rename and
// serialised), so a restart between reserve and commit charges nothing, and a
// crash mid-write cannot leave truncated JSON. Until the file has been read,
// left() and remaining() are 0 (fail closed), so a request in the first
// milliseconds after a restart cannot spend, or be told it has, an extra the
// identity no longer has. A file that cannot be parsed or has the wrong shape
// (anything but an array of [email, non-negative integer]) is moved aside in
// full as `<file>.corrupt-<timestamp>` — nothing from it is applied, and an
// earlier sample is never overwritten. Keyed by canonicalEmail so gmail dots /
// plus-aliases are one identity.
export function createFreeRunAllowance({ canonicalEmail, runsFor, file, fs, log = console, holdTtlMs = 15 * 60 * 1000, now = () => new Date() }) {
  const spent = new Map();   // canonical email -> committed extra runs (persisted)
  const held = new Map();    // canonical email -> in-flight reservations (memory)
  let loaded = false;
  let saving = Promise.resolve();

  const validEntry = (x) => Array.isArray(x) && typeof x[0] === 'string' && Number.isInteger(x[1]) && x[1] >= 0;

  async function load() {
    let entries = null;
    try {
      const parsed = JSON.parse(await fs.readFile(file, 'utf-8'));
      if (!Array.isArray(parsed) || !parsed.every(validEntry)) {
        throw new Error('not an array of [email, non-negative integer]');
      }
      entries = parsed;
    } catch (e) {
      if (e.code !== 'ENOENT') {
        const aside = file + '.corrupt-' + now().toISOString().replace(/[:.]/g, '-');
        log.warn('[free-runs] load failed, moving the file aside as', aside + ':', e.message);
        await fs.rename(file, aside).catch((re) => log.warn('[free-runs] could not move it:', re.message));
      }
    }
    // Validated in full above; additive, not a replace, so a spend committed
    // before the file was read survives the load.
    for (const [e, n] of entries || []) spent.set(e, (spent.get(e) || 0) + n);
    loaded = true;
    await save();
  }
  function save() {
    if (!loaded) return Promise.resolve();   // never clobber the file with a partial map
    const body = JSON.stringify([...spent]);
    saving = saving
      .then(() => fs.writeFile(file + '.tmp', body))
      .then(() => fs.rename(file + '.tmp', file))
      .catch((e) => log.warn('[free-runs] save failed:', e.message));
    return saving;
  }

  const remaining = (email) => {
    if (!loaded || !email) return 0;
    return Math.max(0, (runsFor(email) - 1) - (spent.get(canonicalEmail(email)) || 0));
  };
  const left = (email) => {
    if (!loaded || !email) return 0;
    const ce = canonicalEmail(email);
    return Math.max(0, (runsFor(email) - 1) - (spent.get(ce) || 0) - (held.get(ce) || 0));
  };
  const available = (email) => left(email) > 0;

  function reserve(res, email) {
    const ce = canonicalEmail(email);
    held.set(ce, (held.get(ce) || 0) + 1);
    let settled = false;
    let committed = false;
    let timedOut = false;
    const drop = () => {
      const n = (held.get(ce) || 0) - 1;
      if (n > 0) held.set(ce, n); else held.delete(ce);
    };
    const timer = setTimeout(() => { timedOut = true; release('no response after ' + holdTtlMs + 'ms'); }, holdTtlMs);
    if (typeof timer.unref === 'function') timer.unref();
    const release = (why) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      drop();
      log.log('[free-runs]', email, 'extra run released (' + why + ');', left(email), 'left');
    };

    const end = res.end;
    res.end = function (...args) {
      release('response sent without commit');
      return end.apply(this, args);
    };

    return {
      commit() {
        if (committed) return;
        if (settled && !timedOut) return;   // handler already answered without starting anything
        if (!settled) { settled = true; clearTimeout(timer); drop(); }
        committed = true;
        spent.set(ce, (spent.get(ce) || 0) + 1);
        save();
        log.log('[free-runs]', email, timedOut ? 'late commit after TTL — charged;' : 'spent an extra run;', left(email), 'left');
      },
      refund() {
        if (!committed) return;     // nothing was charged
        committed = false;          // at most once
        const n = (spent.get(ce) || 0) - 1;
        if (n > 0) spent.set(ce, n); else spent.delete(ce);
        save();
        log.log('[free-runs]', email, 'extra run refunded (no verdict);', left(email), 'left');
      },
    };
  }

  return { load, left, remaining, available, reserve, get loaded() { return loaded; } };
}
