/* Field hints \u2014 a short "what goes here, with an example" popup the moment a
 * user clicks into ANY form field, so nobody has to guess the format and
 * fail (a real signup once typed a file:// path into the URL box and left).
 *
 * Behavior: shows on focus, disappears after 15s, or as soon as another field
 * is focused (that field's hint replaces it), or on Escape. Shown every time
 * while the field is still empty; once a field has content, only for the
 * first 2 focuses in this browser, so returning users aren't nagged.
 *
 * Rules are CSS selectors, so fields without ids (the security test's User
 * A / User B inputs) are covered too. A rule's text may be a function for
 * hints that depend on context (the scenario box in Checkout mode).
 * Loaded by first-run.html and index.html; works with re-rendered DOM.
 */
(function () {
  if (window.__tpFieldHints) return;
  window.__tpFieldHints = true;

  var TEST_LOGIN = 'The email of a <b>test account on your app</b> (not your TestPilot email). TestPilot uses it to log in to your app. Tip: create a throwaway user, e.g. <i>test@yourapp.com</i>.';
  var TEST_PW = 'Password of that <b>test account on your app</b>. Used only to log in during the test. Never use a real customer\u2019s account.';
  var APP_URL = 'Paste your app\u2019s web address, starting with <b>https://</b> \u2014 e.g. <i>https://myapp.vercel.app</i>. It must be live on the internet: files on your computer (<i>file://</i>) and <i>localhost</i> can\u2019t be tested. A staging or preview link works.';
  var FLOW = 'Describe <b>one journey</b> in plain English: what to do, then what should be true at the end. Example: <i>\u201cLog in, search for wireless mouse, add it to the cart, and check the cart shows 1 item.\u201d</i>';
  var CHECKOUT = 'Describe the purchase/booking journey and where to stop. Example: <i>\u201cSearch for wireless mouse, add it to the cart, go to checkout, fill the shipping form with test data, and stop at the payment page.\u201d</i>';
  var SESSION = 'Only for apps with <b>Google/SSO login, 2FA or CAPTCHA</b>: paste a captured login session (Playwright storageState JSON or a cookies array). Otherwise leave this empty and use email + password.';
  var PICK_APP = 'Pick which of your apps to test. Not in the list? Add it first with <b>Learn New App</b>.';
  var API_KEY = 'Your Anthropic API key \u2014 it starts with <b>sk-ant-</b>. Get one at console.anthropic.com \u2192 API Keys. Only needed after your free run; you pay Anthropic directly (about \u20ac0.10\u20130.50 per run).';

  var RULES = [
    // Signup / first run
    ['#f-email', 'Your email \u2014 we send your test report and sign-in links here. A work email is best, e.g. <i>you@company.com</i>.'],
    ['#f-url, #learn-url, #widget-url', APP_URL],
    ['#f-start-app-email, #f-app-email, #learn-email, #test-email, #widget-email, #chat-email, #sweep-email, #ss-cred-email', TEST_LOGIN],
    ['#f-start-app-pw, #f-app-pw, #learn-password, #test-password, #widget-password, #chat-password, #sweep-password, #ss-cred-password', TEST_PW],
    ['#f-scenario, #ss-new-desc', FLOW],
    ['#test-scenario', function () { try { return state.testMode === 'flow_e2e' ? CHECKOUT : FLOW; } catch (e) { return FLOW; } }], // the dashboard's top-level `let state` isn't on window
    ['#learn-desc', 'Optional: one sentence about what your app does and who uses it, e.g. <i>\u201cBooking tool for dental clinics, in Spanish.\u201d</i> Helps TestPilot understand your pages.'],
    ['#learn-session-state, #test-session-state, #sched-session', SESSION],

    // Security test: User A = legitimate user, User B = attacker
    ['[onchange*="secConfig.userA.name"]', 'A label for <b>User A</b> \u2014 the legitimate user, e.g. <i>\u201cTenant A\u201d</i> or <i>\u201cCustomer\u201d</i>.'],
    ['[onchange*="secConfig.userA.email"]', '<b>User A \u2014 the legitimate user.</b> Login email of a normal (non-admin) test account that has access to your app and owns some data. TestPilot records everything A can see.'],
    ['[onchange*="secConfig.userA.password"]', 'Password for <b>User A</b> (the legitimate user\u2019s test account).'],
    ['[onchange*="secConfig.userB.name"]', 'A label for <b>User B</b> \u2014 the attacker, e.g. <i>\u201cOther tenant\u201d</i>.'],
    ['[onchange*="secConfig.userB.email"]', '<b>User B \u2014 plays the attacker.</b> Login of a <b>different</b> normal test account (ideally another team/company). TestPilot tries to read and change User A\u2019s data as B; if it works, that\u2019s a leak.'],
    ['[onchange*="secConfig.userB.password"]', 'Password for <b>User B</b> (the attacker\u2019s test account).'],
    ['[onchange*="secConfig.userA.sessionState"], [onchange*="secConfig.userB.sessionState"]', SESSION + ' Or click <b>Capture</b> to log in once yourself.'],

    // Multi-role
    ['[onchange*="mrSetRole"][onchange*="\'name\'"]', 'A name for this user role, e.g. <i>Admin</i>, <i>Customer</i>, <i>Professional</i>.'],
    ['[onchange*="mrSetRole"][onchange*="\'email\'"]', 'Test login email for <b>this role</b> on your app. Each role needs its own account.'],
    ['[onchange*="mrSetRole"][onchange*="\'password\'"]', 'Password for this role\u2019s test account.'],
    ['[onchange*="mrSetRole"][onchange*="\'scenario\'"]', 'What <b>this role</b> should do, plain English, with what should be true after. Example: <i>\u201cCreate a job for client Test and check it appears in Jobs.\u201d</i>'],

    // Pickers
    ['#sched-app, #chat-app, #sweep-app, #sec-app, #ss-app-select, [onchange*="mrSetApp"], [onchange*="state.selectedApp = state.apps.find"]', PICK_APP],
    ['[id$="-saved-role"]', 'Reuse a login you saved before, or leave it on <b>none</b> and enter the email and password below.'],

    // Scheduled runs
    ['#sched-scenario', 'The journey to re-run on a schedule, with what should be true at the end. Example: <i>\u201cLog in, open Orders, and check the list loads with at least one order.\u201d</i>'],
    ['#sched-freq', 'How often to re-run it. <b>Daily</b> suits most apps \u2014 you get an email the moment something that used to pass starts failing.'],
    ['#sched-alert', 'Where to send failure alerts. Leave empty to use your account email.'],

    // Other tools
    ['#sidebar-api-key, #widget-key', API_KEY],
    ['#cleanup-url', 'Optional, advanced: an endpoint <b>on your app</b> that deletes test data, starting with https://, e.g. <i>https://myapp.com/api/tp-cleanup</i>. TestPilot sends it the IDs of records it created.'],
    ['#cleanup-token', 'A shared secret your cleanup endpoint checks, so only TestPilot can call it. Any long random string.'],
    ['#chat-input', 'Tell the agent the next step in plain words, e.g. <i>\u201cgo to Settings\u201d</i>, <i>\u201cclick Save\u201d</i>, <i>\u201cwhat do you see?\u201d</i>'],
    ['#cap-role', 'A name for this login so you can reuse it, e.g. <i>Admin</i>, <i>Free user</i>, <i>Customer</i>.'],
    ['#cap-email', TEST_LOGIN],
    ['#cap-password', 'Password for this test login. Leave it empty for Google-only accounts \u2014 you\u2019ll finish that login yourself in a live window.'],
    ['#ss-new-name', 'A short name for this scenario, e.g. <i>\u201cCustomer books an appointment\u201d</i>.'],
    ['#support-desc', 'Tell us what happened, what you expected, and what you tried. Mention the page or test name if you can \u2014 a real person replies by email.'],
    ['[id^="twofa-input-"]', 'Enter the 6-digit code from your authenticator app or SMS for the test account.'],

    // Fallbacks so no field is ever silent
    ['input[type="email"]', 'An email address, e.g. <i>name@company.com</i>.'],
    ['input[type="password"]', TEST_PW],
    ['input[type="url"]', APP_URL],
    ['textarea', 'Plain English is fine. Be specific: what to do, and what should be true at the end.'],
  ];

  var SKIP_TYPES = /^(checkbox|radio|hidden|file|range|submit|button|color)$/i;
  var box = null, current = null, timer = null;

  function seenKey(el) { return 'tp-hint-seen:' + (el.id || el.getAttribute('onchange') || el.name || el.placeholder || '').slice(0, 80); }
  function seenCount(el) { try { return +localStorage.getItem(seenKey(el)) || 0; } catch (e) { return 0; } }
  function bumpSeen(el) { try { localStorage.setItem(seenKey(el), String(seenCount(el) + 1)); } catch (e) {} }

  function hintFor(el) {
    for (var i = 0; i < RULES.length; i++) {
      try { if (el.matches(RULES[i][0])) { var t = RULES[i][1]; return typeof t === 'function' ? t(el) : t; } } catch (e) {}
    }
    return null;
  }

  function ensureBox() {
    if (box) return box;
    box = document.createElement('div');
    box.id = 'tp-field-hint';
    box.setAttribute('role', 'tooltip');
    box.style.cssText = 'position:fixed;z-index:2147483646;max-width:380px;background:#111;color:#e8e8e8;border:1px solid rgba(200,240,64,.45);border-left:3px solid #c8f040;border-radius:4px;padding:10px 14px;font:13px/1.55 system-ui,-apple-system,sans-serif;box-shadow:0 8px 28px rgba(0,0,0,.55);opacity:0;transition:opacity .15s;pointer-events:auto';
    box.addEventListener('mousedown', function (e) { e.preventDefault(); }); // clicking the hint must not blur the field
    document.body.appendChild(box);
    return box;
  }

  function place() {
    if (!box || !current) return;
    if (!document.contains(current)) return hide();
    var r = current.getBoundingClientRect();
    var w = Math.max(260, Math.min(380, r.width));
    box.style.width = Math.min(w, window.innerWidth - 32) + 'px';
    var left = Math.min(Math.max(16, r.left), window.innerWidth - box.offsetWidth - 16);
    var below = r.bottom + 8, above = r.top - box.offsetHeight - 8;
    box.style.left = left + 'px';
    box.style.top = ((below + box.offsetHeight > window.innerHeight - 8 && above > 8) ? above : below) + 'px';
  }

  function hide() {
    clearTimeout(timer); timer = null;
    if (current) current.removeAttribute('aria-describedby');
    current = null;
    if (box) { box.style.opacity = '0'; box.style.display = 'none'; }
  }

  function show(el, html) {
    ensureBox();
    current = el;
    box.innerHTML = html;
    box.style.display = 'block';
    el.setAttribute('aria-describedby', 'tp-field-hint');
    place();
    requestAnimationFrame(function () { if (box) box.style.opacity = '1'; });
    clearTimeout(timer);
    timer = setTimeout(hide, 15000);
    bumpSeen(el);
  }

  document.addEventListener('focusin', function (e) {
    var el = e.target;
    if (!el || !el.matches || !el.matches('input, textarea, select')) return;
    if (SKIP_TYPES.test(el.type || '') || el.readOnly || el.disabled) return hide();
    if (el === current) return;
    var html = hintFor(el);
    if (!html) return hide();
    var empty = !String(el.value || '').trim();
    if (!empty && seenCount(el) >= 2) return hide();
    show(el, html);
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') hide(); });
  window.addEventListener('scroll', place, true);
  window.addEventListener('resize', place);
})();
