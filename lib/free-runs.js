// Free run allowance: how many EXTRA runs a free identity may start once its
// single free run (or free security scan) is already used. server.js decides
// how many runs an identity gets (runsFor) and which endpoints take one; this
// module owns the counter and the reserve/commit/release rule.
//
//   reserve(res, email) — takes one extra run synchronously (so two parallel
//                         requests cannot both take the last one) and returns a
//                         hold. Holds live in memory only.
//   hold.commit()       — the run is really starting; the spend is recorded and
//                         persisted. Called right before the endpoint's success
//                         response.
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
// Only committed spends are persisted (to `file`, written tmp+rename and
// serialised), so a restart between reserve and commit charges nothing, and a
// crash mid-write cannot leave truncated JSON. Until the file has been read,
// available() is false (fail closed), so a request in the first milliseconds
// after a restart cannot spend an extra the identity no longer has. A file
// that cannot be parsed is moved aside as `<file>.corrupt`, never overwritten.
// Keyed by canonicalEmail so gmail dots / plus-aliases are one identity.
export function createFreeRunAllowance({ canonicalEmail, runsFor, file, fs, log = console, holdTtlMs = 15 * 60 * 1000 }) {
  const spent = new Map();   // canonical email -> committed extra runs (persisted)
  const held = new Map();    // canonical email -> in-flight reservations (memory)
  let loaded = false;
  let saving = Promise.resolve();

  async function load() {
    try {
      // Additive, not a replace: a spend committed before the file was read
      // must survive the load.
      for (const [e, n] of JSON.parse(await fs.readFile(file, 'utf-8'))) {
        spent.set(e, (spent.get(e) || 0) + (Number(n) || 0));
      }
    } catch (e) {
      if (e.code !== 'ENOENT') {
        log.warn('[free-runs] load failed, moving the file aside:', e.message);
        await fs.rename(file, file + '.corrupt').catch((re) => log.warn('[free-runs] could not move it:', re.message));
      }
    }
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

  const left = (email) => {
    const ce = canonicalEmail(email);
    return Math.max(0, (runsFor(email) - 1) - (spent.get(ce) || 0) - (held.get(ce) || 0));
  };
  const available = (email) => loaded && !!email && left(email) > 0;

  function reserve(res, email) {
    const ce = canonicalEmail(email);
    held.set(ce, (held.get(ce) || 0) + 1);
    let settled = false;
    const drop = () => {
      const n = (held.get(ce) || 0) - 1;
      if (n > 0) held.set(ce, n); else held.delete(ce);
    };
    const release = (why) => {
      if (settled) return;
      settled = true;
      drop();
      log.log('[free-runs]', email, 'extra run released (' + why + ');', left(email), 'left');
    };

    const end = res.end;
    res.end = function (...args) {
      release('response sent without commit');
      return end.apply(this, args);
    };
    const timer = setTimeout(() => release('no response after ' + holdTtlMs + 'ms'), holdTtlMs);
    if (typeof timer.unref === 'function') timer.unref();

    return {
      commit() {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        drop();
        spent.set(ce, (spent.get(ce) || 0) + 1);
        save();
        log.log('[free-runs]', email, 'spent an extra run;', left(email), 'left');
      },
    };
  }

  return { load, left, available, reserve, get loaded() { return loaded; } };
}
