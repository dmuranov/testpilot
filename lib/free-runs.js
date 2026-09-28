// Free run allowance: how many EXTRA runs a free identity may start once its
// single free run (or free security scan) is already used. server.js decides
// how many runs an identity gets (runsFor) and which endpoints take one; this
// module owns the counter and the reserve/commit/release/refund rule.
//
//   reserve(res, email) — takes one extra run synchronously (so two parallel
//                         requests cannot both take the last one) and returns a
//                         hold. Holds live in memory only. The response is
//                         referenced only until the hold settles; then its
//                         end() is restored and the reference dropped, so a
//                         long-running run does not pin req/res.
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
// crash mid-write cannot leave truncated JSON.
//
// Fail closed, always: until the file has been read and understood, left()
// and remaining() are 0 — nobody gets an extra, nobody is told they have one.
// If the file cannot be read (anything but "does not exist") OR cannot be
// parsed OR has the wrong shape (anything but an array of [email, non-negative
// integer]), it is left exactly as it is, a warning says so, and load() tries
// again after retryMs — so a transient I/O blip is neither a clean slate that
// re-grants everyone their extras nor a permanent outage, and a genuinely
// corrupt file waits for a human without being overwritten. Keyed by
// canonicalEmail so gmail dots / plus-aliases are one identity.
export function createFreeRunAllowance({ canonicalEmail, runsFor, file, fs, log = console, holdTtlMs = 15 * 60 * 1000, retryMs = 60 * 1000 }) {
  const spent = new Map();   // canonical email -> committed extra runs (persisted)
  const held = new Map();    // canonical email -> in-flight reservations (memory)
  let loaded = false;
  let saving = Promise.resolve();
  let attempts = 0;

  const validEntry = (x) => Array.isArray(x) && typeof x[0] === 'string' && Number.isInteger(x[1]) && x[1] >= 0;

  async function load() {
    if (loaded) return;
    attempts += 1;
    try {
      let raw;
      let created = false;
      try {
        raw = await fs.readFile(file, 'utf-8');
      } catch (e) {
        if (e.code !== 'ENOENT') throw e;
        raw = '[]';
        created = true;
      }
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed) || !parsed.every(validEntry)) {
        throw new Error('not an array of [email, non-negative integer]');
      }
      // Validated in full above; additive, not a replace, so a spend committed
      // before the file was read survives the load. Written back only when
      // there is something the file does not have yet — a clean boot reads it
      // and leaves it alone.
      const hadInMemory = spent.size > 0;
      for (const [e, n] of parsed) spent.set(e, (spent.get(e) || 0) + n);
      loaded = true;
      if (created || hadInMemory) await save();
    } catch (e) {
      log.warn('[free-runs] load attempt', attempts, 'failed —', file, 'left untouched, extras disabled, retrying in', retryMs + 'ms:', e.message);
      const t = setTimeout(load, retryMs);
      if (typeof t.unref === 'function') t.unref();
    }
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
    let refunded = false;
    let timedOut = false;
    let response = res;
    const end = res.end;
    const drop = () => {
      const n = (held.get(ce) || 0) - 1;
      if (n > 0) held.set(ce, n); else held.delete(ce);
    };
    // Give the response back its own end() and stop referencing it.
    const detach = () => {
      if (!response) return;
      response.end = end;
      response = null;
    };
    const timer = setTimeout(() => { timedOut = true; release('no response after ' + holdTtlMs + 'ms'); }, holdTtlMs);
    if (typeof timer.unref === 'function') timer.unref();
    const release = (why) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      detach();
      drop();
      log.log('[free-runs]', email, 'extra run released (' + why + ');', left(email), 'left');
    };

    res.end = function (...args) {
      release('response sent without commit');
      return end.apply(this, args);
    };

    return {
      commit() {
        if (committed || refunded) return;   // once, and never again after a refund
        if (settled && !timedOut) return;   // handler already answered without starting anything
        if (!settled) { settled = true; clearTimeout(timer); detach(); drop(); }
        committed = true;
        spent.set(ce, (spent.get(ce) || 0) + 1);
        save();
        log.log('[free-runs]', email, timedOut ? 'late commit after TTL — charged;' : 'spent an extra run;', left(email), 'left');
      },
      refund() {
        if (!committed || refunded) return;   // nothing charged, or already given back
        refunded = true;
        const n = (spent.get(ce) || 0) - 1;
        if (n > 0) spent.set(ce, n); else spent.delete(ce);
        save();
        log.log('[free-runs]', email, 'extra run refunded (no verdict);', left(email), 'left');
      },
    };
  }

  return { load, left, remaining, available, reserve, get loaded() { return loaded; } };
}
