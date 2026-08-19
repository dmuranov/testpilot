// attrib.js — where did this visitor come from?
//
// Clarity already records utm_* natively, but only against the hit that carried
// them. A visitor who lands on / from a campaign and signs up two pages later
// looks like "direct" by the time it matters. This keeps the FIRST touch in
// localStorage and re-applies it as Clarity tags on every page, so a recording
// of a signup still says "peerpush".
//
// Loaded on landing.html and index.html. Does nothing until Clarity exists,
// which means it does nothing at all if the visitor declined analytics cookies.
(function () {
  'use strict';

  var KEY = 'tp_attrib';        // first touch — written once, never overwritten
  var KEY_LAST = 'tp_attrib_last';  // most recent campaign click

  // Hosts we care about by name. Anything else is kept as its bare hostname.
  var KNOWN = {
    'explee.com': 'explee',
    'peerpush.net': 'peerpush',
    'reddit.com': 'reddit',
    'news.ycombinator.com': 'hackernews',
    'producthunt.com': 'producthunt',
    'twitter.com': 'twitter',
    'x.com': 'twitter',
    'linkedin.com': 'linkedin',
    'facebook.com': 'facebook',
    'youtube.com': 'youtube',
    'google.com': 'google',
    'bing.com': 'bing',
    'duckduckgo.com': 'duckduckgo'
  };

  function param(name) {
    try { return new URLSearchParams(window.location.search).get(name) || ''; }
    catch (e) { return ''; }
  }

  function readJSON(key) {
    try { return JSON.parse(window.localStorage.getItem(key) || 'null'); }
    catch (e) { return null; }
  }

  function writeJSON(key, value) {
    try { window.localStorage.setItem(key, JSON.stringify(value)); } catch (e) {}
  }

  function clean(s, fallback) {
    s = (s || '').toString().toLowerCase().replace(/[^a-z0-9._-]/g, '').slice(0, 40);
    return s || fallback;
  }

  // Referrer -> source, for traffic that arrives without utm_* on the URL.
  function fromReferrer() {
    var host = '';
    try { host = document.referrer ? new URL(document.referrer).hostname.replace(/^www\./, '') : ''; }
    catch (e) {}
    if (!host) return { source: 'direct', medium: 'none', campaign: 'none' };
    if (host === window.location.hostname) return null;  // our own pages, not a new arrival
    for (var known in KNOWN) {
      if (host === known || host.slice(-(known.length + 1)) === '.' + known) {
        return { source: KNOWN[known], medium: 'referral', campaign: 'none' };
      }
    }
    return { source: clean(host, 'referral'), medium: 'referral', campaign: 'none' };
  }

  function fromUtm() {
    var source = param('utm_source');
    if (!source) return null;
    return {
      source: clean(source, 'unknown'),
      medium: clean(param('utm_medium'), 'unknown'),
      campaign: clean(param('utm_campaign'), 'none')
    };
  }

  function stamp(a) {
    a.landing = window.location.pathname;
    a.at = new Date().toISOString();
    return a;
  }

  var utm = fromUtm();
  var first = readJSON(KEY);

  if (!first) {
    // Nothing stored yet: a utm_* click wins, otherwise fall back to referrer.
    var initial = utm || fromReferrer();
    if (initial) { first = stamp(initial); writeJSON(KEY, first); }
  }
  if (utm) writeJSON(KEY_LAST, stamp(utm));

  var last = readJSON(KEY_LAST);

  // Handed to app code so a signup can post attribution to the backend, where
  // it survives a cleared localStorage. Nothing consumes this yet.
  window.tpAttribution = { first: first, last: last };

  if (!first) return;

  function apply() {
    try {
      window.clarity('set', 'source', first.source);
      window.clarity('set', 'medium', first.medium);
      window.clarity('set', 'campaign', first.campaign);
      window.clarity('set', 'landingPage', first.landing || '/');
      if (last && last.source !== first.source) {
        window.clarity('set', 'sourceLatest', last.source);
      }
      // Clarity samples recordings once a project is over its daily cap. A paid
      // or hand-placed campaign click is exactly the session worth keeping.
      if (first.medium !== 'none' && first.source !== 'direct') {
        window.clarity('upgrade', 'campaign visit');
      }
    } catch (e) {}
  }

  // Clarity is consent-gated, so it may appear late (the visitor clicks Accept)
  // or never (they decline). Poll briefly, then give up quietly.
  if (window.clarity) return apply();
  var tries = 0;
  var timer = setInterval(function () {
    if (window.clarity) { clearInterval(timer); apply(); }
    else if (++tries > 120) clearInterval(timer);   // ~60s
  }, 500);
})();
