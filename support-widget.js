/* TestPilot support-widget.js — no framework, no build step.
 * Loads after signal.js on any server-rendered page. Stays inert until
 * signal.js dispatches tp_offer_help.
 *
 * Posts JSON to /api/support, which accepts both that and the original
 * multipart form post the manual "contact support" flow already used.
 */
(function () {
  'use strict';

  var SUPPORT_ENDPOINT = '/api/support';
  var SNOOZE_KEY = 'tp_help_snoozed_until';
  var SNOOZE_MS = 30 * 60 * 1000;

  var root = null;
  var pending = null;   // { cannedMessage, context }

  function snoozed() {
    try { return Date.now() < Number(localStorage.getItem(SNOOZE_KEY) || 0); }
    catch (e) { return false; }
  }
  function snooze() {
    try { localStorage.setItem(SNOOZE_KEY, String(Date.now() + SNOOZE_MS)); } catch (e) {}
  }

  function injectStyles() {
    if (document.getElementById('tp-help-styles')) return;
    var css = [
      '.tp-help{position:fixed;right:20px;bottom:20px;z-index:2147483000;width:340px;max-width:calc(100vw - 40px);',
      'background:#fff;color:#1a1a1a;border:1px solid #d8dbe0;border-radius:8px;',
      'box-shadow:0 8px 28px rgba(16,22,34,.18);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}',
      '.tp-help[hidden]{display:none}',
      '.tp-help__head{display:flex;align-items:flex-start;gap:10px;padding:14px 14px 0}',
      '.tp-help__title{margin:0;font-size:14px;font-weight:600;flex:1}',
      '.tp-help__close{border:0;background:none;font-size:20px;line-height:1;color:#6b7280;cursor:pointer;padding:0 2px}',
      '.tp-help__close:hover{color:#111}',
      '.tp-help__body{padding:6px 14px 14px}',
      '.tp-help__msg{margin:6px 0 10px;color:#4b5563}',
      '.tp-help textarea{width:100%;box-sizing:border-box;min-height:74px;resize:vertical;padding:8px;',
      'border:1px solid #cfd4dc;border-radius:6px;font:inherit;color:inherit}',
      '.tp-help__actions{display:flex;gap:8px;align-items:center;margin-top:10px}',
      '.tp-help__send{background:var(--tp-accent,#1f6feb);color:#fff;border:0;border-radius:6px;',
      'padding:8px 14px;font:inherit;font-weight:500;cursor:pointer}',
      '.tp-help__send:disabled{opacity:.55;cursor:default}',
      '.tp-help__skip{background:none;border:0;color:#6b7280;font:inherit;cursor:pointer;padding:8px 4px}',
      '.tp-help__status{margin:0;color:#4b5563}',
      '.tp-help :focus-visible{outline:2px solid var(--tp-accent,#1f6feb);outline-offset:2px}',
      '@media (prefers-reduced-motion:no-preference){.tp-help{animation:tp-help-in .18s ease-out}}',
      '@keyframes tp-help-in{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}',
    ].join('');
    var el = document.createElement('style');
    el.id = 'tp-help-styles';
    el.textContent = css;
    document.head.appendChild(el);
  }

  function build() {
    injectStyles();
    root = document.createElement('aside');
    root.className = 'tp-help';
    root.setAttribute('role', 'dialog');
    root.setAttribute('aria-label', 'Help with this page');
    root.hidden = true;
    root.innerHTML =
      '<div class="tp-help__head">' +
        '<h2 class="tp-help__title"></h2>' +
        '<button type="button" class="tp-help__close" aria-label="Dismiss">&times;</button>' +
      '</div>' +
      '<div class="tp-help__body">' +
        '<p class="tp-help__msg"></p>' +
        '<div class="tp-help__form">' +
          '<label class="tp-help__label" for="tp-help-text">What were you trying to do?</label>' +
          '<textarea id="tp-help-text" placeholder="I clicked Run and the page stopped responding"></textarea>' +
          '<div class="tp-help__actions">' +
            '<button type="button" class="tp-help__send">Send to support</button>' +
            '<button type="button" class="tp-help__skip">Not now</button>' +
          '</div>' +
        '</div>' +
        '<p class="tp-help__status" role="status" aria-live="polite" hidden></p>' +
      '</div>';
    document.body.appendChild(root);

    root.querySelector('.tp-help__close').addEventListener('click', dismiss);
    root.querySelector('.tp-help__skip').addEventListener('click', dismiss);
    root.querySelector('.tp-help__send').addEventListener('click', send);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && root && !root.hidden) dismiss();
    });
    return root;
  }

  function dismiss() {
    if (root) root.hidden = true;
    snooze();
  }

  function open(detail) {
    if (!root) build();
    if (!root.hidden) return;              // already talking; don't reset it
    pending = detail || {};

    var canned = pending.cannedMessage;
    root.querySelector('.tp-help__title').textContent =
      canned ? 'A known problem' : 'Something went wrong here';
    root.querySelector('.tp-help__msg').textContent =
      canned || 'This page hit an error. Tell us what you were doing and we will pick it up.';

    var form = root.querySelector('.tp-help__form');
    var status = root.querySelector('.tp-help__status');
    form.hidden = false;
    status.hidden = true;
    root.querySelector('.tp-help__send').disabled = false;
    root.querySelector('#tp-help-text').value = '';
    root.hidden = false;
    root.querySelector('#tp-help-text').focus();
  }

  function finish(text) {
    root.querySelector('.tp-help__form').hidden = true;
    var status = root.querySelector('.tp-help__status');
    status.textContent = text;
    status.hidden = false;
  }

  function send() {
    var box = root.querySelector('#tp-help-text');
    var note = box.value.trim();
    var btn = root.querySelector('.tp-help__send');
    btn.disabled = true;

    var sessionId = '';
    try { sessionId = localStorage.getItem('tp_signal_id') || ''; } catch (e) {}

    var payload = {
      source: 'widget',
      sessionId: sessionId,
      url: window.location.href,
      // The captured signal travels with the message, so nobody has to
      // describe a stack trace they never saw.
      context: pending && pending.context ? pending.context : null,
      description: note || '(no description given — reported from the error prompt)',
    };

    fetch(SUPPORT_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json().catch(function () { return {}; }); })
      .then(function () {
        finish('Sent. We have the page and the error, and will follow up by email.');
        setTimeout(function () { if (root) root.hidden = true; }, 4000);
      })
      .catch(function () {
        btn.disabled = false;
        finish('That did not send. Email support@testpilotapp.dev and we will pick it up from there.');
      });
  }

  window.addEventListener('tp_offer_help', function (e) {
    try {
      if (snoozed()) return;
      open(e.detail);
    } catch (err) { /* never break the page */ }
  });
})();
