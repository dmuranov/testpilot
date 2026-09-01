/* TestPilot signal.js — passive error/stuck watcher.
 * Loaded on every page (first-run, dashboard, live-test, widget).
 * Rule: this script must never be able to break the page it watches.
 */
(function () {
  'use strict';

  try {
    var ENDPOINT = '/api/signal';
    var BATCH_MS = 3000;
    var STUCK_MS = 20000;      // error, then nothing worked for this long
    var MAX_QUEUE = 20;        // hard cap: a runaway loop can't flood us
    var MAX_MSG = 300;

    // How long an open EventSource can go without a message before it counts
    // as stalled. This is app knowledge (a fast test step vs. a slow crawl
    // have very different natural gaps) that a generic watcher can't infer,
    // so it's configurable per page via a data attribute on this script's
    // own tag, read once at load time — <script src="/signal.js" data-stall-ms="180000">.
    // Default (90s) is a "we don't know this stream's cadence" fallback, not
    // a considered value — a false "stalled" report pops the support widget
    // on someone whose run is fine, which is worse than missing a real one.
    // Any page hosting /api/test/:id/stream MUST override this: runAgentTest
    // documents ~100s for a single step (server.js, launchBrowser section,
    // "2-3 stacked = the observed ~100s/step") — first-run.html, live-test.html
    // and index.html all set data-stall-ms="180000" for exactly this reason.
    // Every type string this file (or a page calling tpReportSignal) may
    // emit, in one place. Cross-check this list against ALLOWED_TYPES in
    // routes/signal.js by hand when either changes — clean() there silently
    // drops anything not in that set, so a typo here means the corresponding
    // detector fires locally, gets batched, POSTs fine, and produces nothing
    // server-side. No shared import across the browser/server boundary here:
    // signal.js is a classic (non-module) script so document.currentScript
    // still works for STALL_MS below — switching to type="module" to import
    // a shared constants file would break that.
    var TYPE = {
      UNCAUGHT_ERROR: 'uncaught_error',
      UNHANDLED_REJECTION: 'unhandled_rejection',
      HTTP_ERROR: 'http_error',
      NETWORK_FAILURE: 'network_failure',
      STUCK_AFTER_ERROR: 'stuck_after_error',
      STREAM_STALLED: 'stream_stalled'
      // stream_error is caller-supplied via tpReportSignal (e.g. first-run.html),
      // not emitted from within this file — listed here only as documentation:
      // 'stream_error'
    };

    var STALL_MS = (function () {
      try {
        var ds = document.currentScript && document.currentScript.dataset;
        var n = ds && parseInt(ds.stallMs, 10);
        return (n && n > 0) ? n : 90000;
      } catch (e) { return 90000; }
    })();

    // Captured BEFORE we wrap. Flushing through the wrapper would mean a 500
    // from /api/signal enqueues an event about itself -> flush -> 500 -> loop.
    var nativeFetch = window.fetch ? window.fetch.bind(window) : null;
    if (!nativeFetch) return;

    var queue = [];
    var flushTimer = null;
    var lastErrorAt = 0;
    var lastSuccessAt = Date.now();
    var stuckReported = false;

    function isSignalUrl(u) {
      return typeof u === 'string' && u.indexOf(ENDPOINT) !== -1;
    }

    function getSessionId() {
      try {
        var id = localStorage.getItem('tp_signal_id');
        if (!id) {
          id = 'anon_' + Math.random().toString(36).slice(2, 11);
          localStorage.setItem('tp_signal_id', id);
        }
        return id;
      } catch (e) {
        return 'anon_nostorage';
      }
    }

    // Error messages occasionally carry an email or a token. Hash-relevant
    // fields never include the message, but the sample is stored, so scrub it.
    function redact(s) {
      if (typeof s !== 'string') return null;
      return s
        .replace(/[\w.+-]+@[\w-]+\.[\w.]+/g, '<email>')
        .replace(/\b(?:eyJ|sk-|ghp_|Bearer\s+)[\w.\-]{8,}/gi, '<token>')
        .slice(0, MAX_MSG);
    }

    function pathOf(input) {
      try {
        var raw = typeof input === 'string' ? input : (input && input.url);
        if (!raw) return null;
        var u = new URL(raw, window.location.origin);
        if (u.origin !== window.location.origin) return null;   // same-origin only
        return u.pathname;                                       // query string dropped on purpose
      } catch (e) {
        return null;
      }
    }

    function enqueue(ev) {
      if (queue.length >= MAX_QUEUE) return;
      ev.t = Date.now();
      queue.push(ev);
      if (ev.type !== TYPE.STUCK_AFTER_ERROR) {
        lastErrorAt = Date.now();
        stuckReported = false;
      }
      if (!flushTimer) {
        flushTimer = setTimeout(function () { flushTimer = null; flush(); }, BATCH_MS);
      }
    }

    function flush(useBeacon) {
      if (!queue.length) return;
      var body = JSON.stringify({
        sessionId: getSessionId(),
        page: window.location.pathname,
        events: queue.splice(0, queue.length)
      });

      if (useBeacon && navigator.sendBeacon) {
        try { navigator.sendBeacon(ENDPOINT, new Blob([body], { type: 'application/json' })); } catch (e) {}
        return;
      }

      nativeFetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body,
        keepalive: true
      })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (data && data.offerHelp) {
            window.dispatchEvent(new CustomEvent('tp_offer_help', { detail: data }));
          }
        })
        .catch(function () { /* silent: never retry, never re-enqueue */ });
    }

    // --- uncaught errors -----------------------------------------------------
    window.addEventListener('error', function (e) {
      // Resource load failures (img/script/link) fire here with no error object.
      if (!e.error && e.target && e.target !== window) return;
      enqueue({
        type: TYPE.UNCAUGHT_ERROR,
        name: (e.error && e.error.name) || 'Error',
        message: redact(e.message),
        stack: redact(e.error && e.error.stack)
      });
    }, true);

    window.addEventListener('unhandledrejection', function (e) {
      var r = e.reason;
      enqueue({
        type: TYPE.UNHANDLED_REJECTION,
        name: (r && r.name) || 'Error',
        message: redact(r && r.message ? r.message : String(r)),
        stack: redact(r && r.stack)
      });
    });

    // --- fetch wrapper -------------------------------------------------------
    window.fetch = function () {
      var args = arguments;
      var p = pathOf(args[0]);
      var method = (args[1] && args[1].method) || 'GET';

      return nativeFetch.apply(window, args).then(function (res) {
        try {
          if (p && p.indexOf('/api/') === 0 && !isSignalUrl(p)) {
            // A 200 with Content-Type: text/event-stream is a handshake, not
            // a result — the real work (and any failure) happens inside the
            // body afterward, invisible to this wrapper. Marking it a
            // "success" here would disarm the stuck detector at the exact
            // moment the actual work starts. Whoever reads the stream must
            // report its own outcome via window.tpReportSignal instead; this
            // wrapper only still catches a handshake that fails outright.
            // Both current getReader() consumers (/api/learn, /api/capture-session)
            // send real text/event-stream, but a future one may not follow that
            // convention — ndjson and octet-stream are the other shapes a
            // long-lived, progressively-read response tends to use.
            var ct = '';
            try { ct = res.headers.get('content-type') || ''; } catch (e2) {}
            var isStream = ct.indexOf('text/event-stream') !== -1
              || ct.indexOf('ndjson') !== -1
              || ct.indexOf('octet-stream') !== -1;

            if (!res.ok) {
              enqueue({ type: TYPE.HTTP_ERROR, status: res.status, method: method, path: p });
            } else if (!isStream) {
              lastSuccessAt = Date.now();
            }
          }
        } catch (e) {}
        return res;
      }, function (err) {
        try {
          if (p && p.indexOf('/api/') === 0 && !isSignalUrl(p)) {
            enqueue({ type: TYPE.NETWORK_FAILURE, method: method, path: p });
          }
        } catch (e) {}
        throw err;   // the app still sees its own error, untouched
      });
    };

    // --- explicit hook for failures no generic wrapper can see ---------------
    // A stream returning 200 and then failing INSIDE its body (an SSE-style
    // `{phase:'error'}` line, a bug found mid-test) is pure application
    // semantics — there's no generic way to know that shape means failure.
    // Wrapping response.body itself to watch for this would mean handing the
    // page a reconstructed Response that isn't the one the browser made,
    // which is the wrong trade for a script whose only job is to never break
    // the page it watches. So: expose this, and let the one or two call
    // sites that actually parse those bodies (e.g. first-run.html's
    // runLearnStream) report their own verdict.
    window.tpReportSignal = function (ev) {
      try {
        if (!ev || typeof ev !== 'object' || typeof ev.type !== 'string') return;
        enqueue({
          type: ev.type,
          name: ev.name,
          message: redact(ev.message),
          stack: redact(ev.stack),
          method: ev.method,
          status: ev.status,
          path: ev.path
        });
      } catch (e) {}
    };

    // --- EventSource instrumentation ------------------------------------------
    // fetch-wrapping doesn't cover this: first-run's test view and the whole
    // of live-test.html watch progress via EventSource, not fetch.
    //
    // error events are NOT a reliable failure signal on their own — the spec
    // fires them on every dropped connection, including ones the browser is
    // about to transparently retry, and often on a tab navigating away
    // mid-stream. Reporting every one would put transport noise into
    // error_signatures and, at a 3-occurrences/2-sessions threshold, could
    // enqueue an agent job for a bug that was never real. So: only report
    // when the browser has actually given up (readyState CLOSED), or when
    // reconnect attempts keep failing (several CONNECTING errors without a
    // successful open between them) — a single blip is not a bug.
    //
    // Silence while still open is a different, generic thing this CAN detect
    // without knowing what a "terminal" event looks like for any given
    // stream: no message for STALL_MS. It's a proxy for "stuck", not proof
    // of one, hence the generous configurable default above.
    (function () {
      var NativeEventSource = window.EventSource;
      if (!NativeEventSource) return;

      function instrument(es, url) {
        try {
          var path = pathOf(url);
          var lastActivityAt = Date.now();
          var connectErrors = 0;
          var connectWindowStart = 0;
          var fatalReported = false;
          var stalledReported = false;

          es.addEventListener('open', function () {
            connectErrors = 0;
            lastActivityAt = Date.now();
          });

          es.addEventListener('message', function () {
            lastActivityAt = Date.now();
          });

          es.addEventListener('error', function () {
            if (fatalReported) return;
            if (es.readyState === NativeEventSource.CLOSED) {
              fatalReported = true;
              enqueue({ type: TYPE.NETWORK_FAILURE, method: 'GET', path: path });
              return;
            }
            if (es.readyState === NativeEventSource.CONNECTING) {
              var now = Date.now();
              if (now - connectWindowStart > 30000) { connectWindowStart = now; connectErrors = 0; }
              connectErrors += 1;
              if (connectErrors >= 3) {
                fatalReported = true;
                enqueue({ type: TYPE.NETWORK_FAILURE, method: 'GET', path: path });
              }
            }
          });

          var stallCheck = setInterval(function () {
            try {
              if (fatalReported || stalledReported || es.readyState === NativeEventSource.CLOSED) {
                clearInterval(stallCheck);
                return;
              }
              if (Date.now() - lastActivityAt < STALL_MS) return;
              stalledReported = true;
              enqueue({ type: TYPE.STREAM_STALLED, name: 'StreamStalled', path: path });
              flush();
            } catch (e) {}
          }, 5000);
        } catch (e) {}
      }

      var Wrapped = function (url, opts) {
        var es = new NativeEventSource(url, opts);
        instrument(es, url);
        return es;
      };
      Wrapped.prototype = NativeEventSource.prototype;
      Wrapped.CONNECTING = NativeEventSource.CONNECTING;
      Wrapped.OPEN = NativeEventSource.OPEN;
      Wrapped.CLOSED = NativeEventSource.CLOSED;
      window.EventSource = Wrapped;
      // Load-order flag: a page whose own script opens an EventSource at
      // parse time (live-test.html's connect()) can only get the wrapped
      // constructor if this script ran first. That's a real dependency on
      // tag order, not something a diff makes obvious — a future "tidy up
      // the script tags" pass could re-add defer here, silently going back
      // to the native EventSource with no error anywhere. Any such page
      // should check this flag before connecting and warn if it's missing,
      // rather than let stall/CLOSED detection go quietly inert again.
      window.__tpEventSourceWrapped = true;
    })();

    // --- stuck detector ------------------------------------------------------
    // Fires only if an error happened AND nothing has succeeded since. Someone
    // who hit a blip and carried on is not stuck.
    setInterval(function () {
      try {
        if (!lastErrorAt || stuckReported) return;
        if (lastSuccessAt > lastErrorAt) { lastErrorAt = 0; return; }
        if (Date.now() - lastErrorAt < STUCK_MS) return;
        stuckReported = true;
        enqueue({ type: TYPE.STUCK_AFTER_ERROR });
        flush();
      } catch (e) {}
    }, 5000);

    window.addEventListener('pagehide', function () { flush(true); });
  } catch (initError) {
    /* never throw out of here */
  }
})();
