/*!
 * TestPilot embed loader (v1)
 * One-line install:
 *   <script src="https://testpilotapp.dev/embed.js" data-tp-token="pk_live_xxx" defer></script>
 *
 * Injects a floating "Test" button into the host app. Clicking it opens the
 * TestPilot panel (an iframe to /widget) that lets the user pick a test, which
 * TestPilot learns + runs against the CURRENT page — optionally as the
 * logged-in user (the host app's own auth token, read first-party from
 * localStorage, only when the user opts in).
 *
 * The browser only ever holds the publishable pk_ token. The secret Anthropic
 * key was connected once, at portal setup, and lives server-side.
 */
(function () {
  'use strict';
  if (window.__tpEmbedLoaded) return;
  window.__tpEmbedLoaded = true;

  var script = document.currentScript || (function () {
    var s = document.getElementsByTagName('script');
    for (var i = s.length - 1; i >= 0; i--) if (/embed\.js(\?|$)/.test(s[i].src)) return s[i];
    return null;
  })();

  var token = (script && script.getAttribute('data-tp-token')) || '';
  var origin = (function () {
    try { return new URL(script.src).origin; } catch (e) { return 'https://testpilotapp.dev'; }
  })();
  var position = (script && script.getAttribute('data-tp-position')) || 'bottom-right';
  // Visibility gate. "team" (default) keeps the button hidden from end users —
  // the host app reveals it only for its team via window.TestPilot.show() or by
  // setting window[teamFlag]=true. "query" shows it only when the URL carries
  // ?<triggerParam>=1. "always" shows it to everyone (internal/staff apps).
  var gate = (script && script.getAttribute('data-tp-gate')) || 'team';
  var teamFlag = (script && script.getAttribute('data-tp-flag')) || '__TESTPILOT_TEAM__';
  var triggerParam = (script && script.getAttribute('data-tp-trigger-param')) || 'tptest';

  if (!token) {
    console.warn('[TestPilot] embed.js loaded without data-tp-token — get one from your TestPilot portal.');
  }

  // ---- Best-effort, opt-in auth capture (first-party) --------------------
  // Base44 (and most SPA builders) keep the logged-in JWT in localStorage.
  // We only READ it, and only send it after the user explicitly opts in via
  // the panel's "Test as logged-in user" toggle. Nothing is captured silently.
  function captureAuth() {
    var out = { bearer: null, storage: {} };
    try {
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        var v = localStorage.getItem(k);
        if (!v) continue;
        // JWT-shaped values (three base64url segments) are the auth token.
        if (/^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/.test(v.replace(/^"|"$/g, ''))) {
          if (!out.bearer) out.bearer = v.replace(/^"|"$/g, '');
        }
        if (/token|auth|session|jwt/i.test(k)) out.storage[k] = v.slice(0, 2000);
      }
    } catch (e) { /* storage may be blocked; ignore */ }
    return out;
  }

  // ---- UI ----------------------------------------------------------------
  var launcher = document.createElement('button');
  launcher.setAttribute('aria-label', 'Run a TestPilot test');
  launcher.type = 'button';
  var side = position === 'bottom-left' ? 'left:20px;' : 'right:20px;';
  launcher.style.cssText = [
    'position:fixed', 'bottom:20px', side.slice(0, -1), 'z-index:2147483000',
    'display:flex', 'align-items:center', 'gap:8px',
    'padding:10px 16px', 'border:none', 'border-radius:999px', 'cursor:pointer',
    'font:600 13px/1 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif',
    'color:#080808', 'background:#f5a623', 'box-shadow:0 4px 16px rgba(0,0,0,.28)',
    'transition:transform .12s ease, box-shadow .12s ease'
  ].join(';');
  launcher.innerHTML = '<span style="font-size:15px">✈</span><span>Test</span>';
  launcher.onmouseenter = function () { launcher.style.transform = 'translateY(-1px)'; launcher.style.boxShadow = '0 6px 22px rgba(0,0,0,.34)'; };
  launcher.onmouseleave = function () { launcher.style.transform = ''; launcher.style.boxShadow = '0 4px 16px rgba(0,0,0,.28)'; };

  var panel = document.createElement('iframe');
  panel.title = 'TestPilot';
  panel.style.cssText = [
    'position:fixed', 'bottom:76px', side.slice(0, -1), 'z-index:2147483000',
    'width:400px', 'max-width:calc(100vw - 32px)', 'height:560px', 'max-height:calc(100vh - 110px)',
    'border:none', 'border-radius:14px', 'box-shadow:0 12px 48px rgba(0,0,0,.4)',
    'background:#080808', 'display:none', 'overflow:hidden'
  ].join(';');
  panel.setAttribute('allow', '');
  var panelOpen = false;

  function openPanel() {
    if (!panel.src) {
      // Target URL is passed via postMessage after load, not the src, so the
      // token/URL never land in the iframe URL, referrer, or history.
      panel.src = origin + '/widget?embed=1';
    }
    panel.style.display = 'block';
    panelOpen = true;
    launcher.querySelector('span:last-child').textContent = 'Close';
  }
  function closePanel() {
    panel.style.display = 'none';
    panelOpen = false;
    launcher.querySelector('span:last-child').textContent = 'Test';
  }
  launcher.addEventListener('click', function () { panelOpen ? closePanel() : openPanel(); });

  // ---- Bridge: widget <-> host page -------------------------------------
  window.addEventListener('message', function (ev) {
    if (ev.origin !== origin || !ev.data || typeof ev.data !== 'object') return;
    var msg = ev.data;
    if (msg.tp !== 1) return;
    if (msg.type === 'ready') {
      panel.contentWindow.postMessage({
        tp: 1, type: 'init',
        token: token,
        target: location.href,
        title: document.title
      }, origin);
    } else if (msg.type === 'requestAuth') {
      // Widget asked for auth ONLY because the user toggled it on.
      panel.contentWindow.postMessage({ tp: 1, type: 'auth', auth: captureAuth() }, origin);
    } else if (msg.type === 'resize' && msg.height) {
      panel.style.height = Math.min(msg.height, window.innerHeight - 110) + 'px';
    } else if (msg.type === 'close') {
      closePanel();
    }
  });

  // ── Visibility gating ───────────────────────────────────────────────────
  var manualShow = false;
  function shouldShow() {
    if (gate === 'always') return true;
    if (gate === 'query') { try { return new URLSearchParams(location.search).has(triggerParam); } catch (e) { return false; } }
    return manualShow || window[teamFlag] === true; // team (default)
  }
  function applyVisibility() {
    var show = shouldShow();
    launcher.style.display = show ? 'flex' : 'none';
    if (!show && panelOpen) closePanel();
  }

  // Public API the host app calls to reveal/hide the button for its own team.
  // e.g. after your admin/team member logs in:  window.TestPilot.show()
  //      on logout:                             window.TestPilot.hide()
  window.TestPilot = window.TestPilot || {};
  window.TestPilot.show = function () { manualShow = true; applyVisibility(); };
  window.TestPilot.hide = function () { manualShow = false; applyVisibility(); };
  window.TestPilot.refresh = applyVisibility;

  function mount() {
    document.body.appendChild(launcher);
    document.body.appendChild(panel);
    applyVisibility();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();
})();
