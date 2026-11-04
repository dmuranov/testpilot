// Login help during a run, shared by the dashboard (index.html) and the chat
// first-run (first-run.html): the verification-code prompt (awaiting_2fa) and
// the live browser takeover (awaiting_oauth_handoff → live_view_ready → live_frame).
// A page that wants the code prompt somewhere specific gives that element
// id="tp-live-host".
function tpLiveEsc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }

function show2faPrompt(runId, message) {
  if (!runId) return;
  // A box still waiting for a code stays; one already answered is replaced, so
  // a second code request on the same run (a retried login) gets a new input.
  const prev = document.getElementById('twofa-prompt-' + runId);
  if (prev) { if (prev.querySelector('input')) return; prev.remove(); }
  const host = document.getElementById('tp-live-host') || document.getElementById('learn-stream') || document.getElementById('test-stream') || document.getElementById('sec-stream') || document.body;
  const box = document.createElement('div');
  box.id = 'twofa-prompt-' + runId;
  box.style.cssText = 'margin:12px 0;padding:14px;border:1px solid var(--accent,#6c5ce7);border-radius:8px;background:rgba(108,92,231,0.08)';
  box.innerHTML = `
    <div style="font-weight:600;margin-bottom:8px">🔐 ${tpLiveEsc(message || 'Enter the verification code sent to your inbox')}</div>
    <div style="display:flex;gap:8px;align-items:center">
      <input id="twofa-input-${runId}" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="123456"
        style="flex:1;padding:9px;border:1px solid #ccc;border-radius:6px;font-family:monospace;letter-spacing:2px" />
      <button id="twofa-btn-${runId}" class="btn btn-primary">Submit code</button>
    </div>
    <div id="twofa-err-${runId}" style="color:#e74c3c;font-size:12px;margin-top:6px"></div>`;
  host.appendChild(box);
  const input = box.querySelector(`#twofa-input-${runId}`);
  const btn = box.querySelector(`#twofa-btn-${runId}`);
  const err = box.querySelector(`#twofa-err-${runId}`);
  input.focus();
  const submit = async () => {
    const code = (input.value || '').trim();
    if (!code) { err.textContent = 'Enter the code first.'; return; }
    btn.disabled = true; err.textContent = '';
    try {
      const r = await fetch(`/api/2fa/${encodeURIComponent(runId)}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code })
      });
      if (!r.ok) { const j = await r.json().catch(() => ({})); err.textContent = j.error || 'Could not submit code.'; btn.disabled = false; return; }
      box.innerHTML = '<div style="color:var(--accent,#6c5ce7);font-weight:600">🔐 Code submitted — continuing…</div>';
    } catch (e) { err.textContent = 'Network error — try again.'; btn.disabled = false; }
  };
  btn.addEventListener('click', submit);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
}

// OAuth login handoff — shown when login fails on a page that also offers a
// Google/GitHub/... sign-in button (the account likely has no real password).
// "Take over" streams the actual paused browser live (via the server's CDP
// screencast) so the user can finish the OAuth flow themselves; the test
// resumes automatically once they click Done. Self-contained like
// show2faPrompt, for the same reason (server is blocked while paused).
// The handoff prompt and the live-view canvas both need to be reliably fully
// visible and interactable — they used to get appended into whichever
// .test-stream log panel was active, which caps at max-height:500px with its
// own overflow-y:auto. Confirmed live: the box landed mostly below the fold
// with no auto-scroll, the user could see only its top edge, and had no way
// to reach the "Done" button or type into the canvas. A fixed full-viewport
// overlay guarantees visibility regardless of the log panel's scroll state.
function getLiveOverlayHost() {
  let overlay = document.getElementById('tp-live-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'tp-live-overlay';
    // flex-direction:column so two simultaneous handoffs (a running test
    // hits a login wall while a separate saved-session capture is ALSO
    // mid-flight, each for a DIFFERENT app) stack cleanly top-to-bottom.
    // Confirmed live: the default row layout put a 1280px-wide live-view
    // canvas for one app next to another app's prompt box, overlapping and
    // crowding each other — the user typed into the wrong one because
    // neither was labeled and they visually blurred together.
    overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;display:flex;flex-direction:column;align-items:center;justify-content:flex-start;gap:16px;overflow:auto;background:rgba(0,0,0,0.65);padding:24px';
    document.body.appendChild(overlay);
  }
  return overlay;
}
function closeLiveOverlay(runId) {
  document.getElementById('oauth-handoff-' + runId)?.remove();
  const overlay = document.getElementById('tp-live-overlay');
  if (overlay && !overlay.firstElementChild) overlay.remove();
}
// Close THIS box. If a newer offer's box has since taken the run's id, that
// one stays — closing by runId would remove the box the user still needs.
function closeLiveBox(runId, box) {
  if (document.getElementById('oauth-handoff-' + runId) === box) return closeLiveOverlay(runId);
  box.remove();
  const overlay = document.getElementById('tp-live-overlay');
  if (overlay && !overlay.firstElementChild) overlay.remove();
}

// Every takeover signal carries the offer it answers, so the server can refuse
// a stale box's buttons. Older servers ignore the body.
function postLiveViewSignal(runId, action, box) {
  return fetch(`/api/live-view/${encodeURIComponent(runId)}/${action}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ offerId: box?.dataset?.offerId || null }),
  });
}

function showOAuthHandoffPrompt(runId, message, hostname, offerId) {
  if (!runId) return;
  window._tpSeenOffers = window._tpSeenOffers || new Set();
  // An offer this document has already shown — replayed by a reconnecting
  // stream after the user acted on it — never gets a box again.
  if (offerId && window._tpSeenOffers.has(offerId)) return;
  const existing = document.getElementById('oauth-handoff-' + runId);
  if (existing) {
    // Same offer already on screen: nothing to do. Only an offer never seen
    // before (a retry's new offer) replaces the box, whose buttons the server
    // would refuse.
    if (!offerId || existing.dataset.offerId === offerId) return;
    if (window._tpLiveViews) delete window._tpLiveViews[runId];
    existing.remove();
  }
  if (offerId) window._tpSeenOffers.add(offerId);
  const box = document.createElement('div');
  box.id = 'oauth-handoff-' + runId;
  if (offerId) box.dataset.offerId = offerId;
  box.style.cssText = 'width:100%;max-width:720px;margin:auto;padding:14px;border:1px solid var(--accent,#6c5ce7);border-radius:8px;background:var(--bg-elevated,#15151c)';
  // A visible app-name badge, not just prose in the message — scannable at a
  // glance when more than one handoff is stacked at once (see getLiveOverlayHost).
  const badge = hostname ? `<div style="display:inline-block;font-family:'DM Mono',monospace;font-size:11px;color:var(--accent,#6c5ce7);background:rgba(108,92,231,0.12);border-radius:4px;padding:2px 8px;margin-bottom:8px">${tpLiveEsc(hostname)}</div>` : '';
  box.innerHTML = `
    ${badge}
    <div style="font-weight:600;margin-bottom:10px">🔑 ${tpLiveEsc(message || 'Login failed — this app may need Google sign-in')}</div>
    <div style="display:flex;gap:8px">
      <button id="oauth-take-${runId}" class="btn btn-primary">Take over &amp; log in myself</button>
      <button id="oauth-skip-${runId}" class="btn btn-ghost ghost">Skip</button>
    </div>`;
  getLiveOverlayHost().appendChild(box);
  box.scrollIntoView({ block: 'center' });
  box.querySelector(`#oauth-skip-${runId}`).addEventListener('click', async () => {
    box.innerHTML = '<div style="color:var(--text-muted)">Skipped — continuing with the normal error.</div>';
    await postLiveViewSignal(runId, 'decline', box).catch(() => {});
    setTimeout(() => closeLiveBox(runId, box), 1500);
  });
  box.querySelector(`#oauth-take-${runId}`).addEventListener('click', async () => {
    box.innerHTML = '<div style="color:var(--accent,#6c5ce7)">Connecting…</div>';
    const r = await postLiveViewSignal(runId, 'accept', box).catch(() => null);
    if (!r || !r.ok) {
      box.innerHTML = '<div style="color:#e74c3c">Could not start the live view — the offer may have expired. The test will continue with the normal error.</div>';
      setTimeout(() => closeLiveBox(runId, box), 3000);
      return;
    }
    // The canvas/controls get built by openLiveView() once the server confirms
    // the screencast actually started (the live_view_ready SSE event) —
    // starting it takes a moment, so don't build the UI before it's real.
  });
}

// Built once live_view_ready arrives (screencast is actually running). Frame
// size must match server.js startLiveView's maxWidth/maxHeight.
// Must match runAgentTest's browser.newContext viewport (server.js) exactly —
// any mismatch means a click computed from canvas coordinates lands at the
// wrong point on the real page (confirmed live: clicking "Accept All" on a
// cookie banner did nothing when this was 1024x768 against a 1280x800 page).
const LIVE_VIEW_W = 1280, LIVE_VIEW_H = 800;
function openLiveView(runId, hostname, offerId) {
  const box = document.getElementById('oauth-handoff-' + runId);
  if (!box) return;
  // A ready event for an earlier offer (replayed or late) must not turn this
  // offer's prompt into a canvas for a screencast that is not its own.
  if (offerId && box.dataset.offerId && box.dataset.offerId !== offerId) return;
  box.style.maxWidth = LIVE_VIEW_W + 'px'; // was 720px, sized for the prompt's buttons — too narrow for the canvas
  // Same app-name badge as showOAuthHandoffPrompt — stays labeled once this
  // box turns into the live canvas, still critical when a second handoff for
  // a DIFFERENT app is stacked right below it (getLiveOverlayHost).
  const badge = hostname ? `<div style="display:inline-block;font-family:'DM Mono',monospace;font-size:11px;color:var(--accent,#6c5ce7);background:rgba(108,92,231,0.12);border-radius:4px;padding:2px 8px;margin-bottom:8px">${tpLiveEsc(hostname)}</div>` : '';
  box.innerHTML = `
    ${badge}
    <div style="font-weight:600;margin-bottom:8px">🔑 Log in yourself below, then click Done.</div>
    <canvas id="live-canvas-${runId}" width="${LIVE_VIEW_W}" height="${LIVE_VIEW_H}" tabindex="0"
      style="width:100%;max-width:${LIVE_VIEW_W}px;border:1px solid var(--border,#333);border-radius:4px;cursor:pointer;outline:none;background:#000"></canvas>
    <div style="display:flex;gap:8px;margin-top:10px">
      <button id="oauth-done-${runId}" class="btn btn-primary">Done — I'm logged in</button>
    </div>`;
  const canvas = box.querySelector(`#live-canvas-${runId}`);
  const ctx2d = canvas.getContext('2d');
  window._tpLiveViews = window._tpLiveViews || {};
  const entry = { canvas, ctx2d, frameW: LIVE_VIEW_W, frameH: LIVE_VIEW_H };
  window._tpLiveViews[runId] = entry;

  const send = (payload) => fetch(`/api/live-view/${encodeURIComponent(runId)}/input`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
  }).catch(() => {});
  // Coordinates must be in the CURRENT frame's own native resolution, not the
  // fixed 1280x800 canvas size — a click computed in the wrong space lands at
  // the wrong point on the real page. This matters once the live view switches
  // onto an OAuth popup (watchForPopups, server.js): Google's sign-in popup is
  // a much smaller window than the original 1280x800 page, so its screencast
  // frames arrive at that smaller native size (confirmed live: typing into the
  // Google email field worked — Input.insertText doesn't depend on coordinates
  // — but clicking "Next" did nothing, because the click was dispatched in
  // 1280x800 space against a popup whose real viewport was far smaller).
  const toFrameCoords = (clientX, clientY) => {
    const r = canvas.getBoundingClientRect();
    return { x: (clientX - r.left) * (entry.frameW / r.width), y: (clientY - r.top) * (entry.frameH / r.height) };
  };
  canvas.addEventListener('mousedown', (e) => { canvas.focus(); const p = toFrameCoords(e.clientX, e.clientY); send({ type: 'mousedown', ...p }); });
  canvas.addEventListener('mouseup', (e) => { const p = toFrameCoords(e.clientX, e.clientY); send({ type: 'mouseup', ...p }); });
  canvas.addEventListener('mousemove', (e) => { const p = toFrameCoords(e.clientX, e.clientY); send({ type: 'mousemove', ...p }); });
  canvas.addEventListener('keydown', async (e) => {
    e.preventDefault();
    // Ctrl/Cmd+V was falling into the printable-character branch below and
    // sending the literal letter "v" — the modifier was silently dropped, so
    // paste looked like it just did nothing (confirmed live: pasting a
    // password typed a "v" instead). Read the clipboard directly and relay
    // its contents as text instead of trying to make a real paste happen on
    // the remote page.
    if ((e.ctrlKey || e.metaKey) && (e.key === 'v' || e.key === 'V')) {
      try {
        const text = await navigator.clipboard.readText();
        if (text) send({ type: 'text', text });
      } catch { /* clipboard read needs permission/HTTPS — nothing more we can do */ }
      return;
    }
    // Printable characters go as one Input.insertText (correct for Unicode);
    // everything else (Enter/Tab/Backspace/...) goes as a real key event.
    if (e.key.length === 1) { send({ type: 'text', text: e.key }); return; }
    send({ type: 'keydown', key: e.key, code: e.code, keyCode: e.keyCode });
  });
  canvas.addEventListener('keyup', (e) => {
    if (e.key.length === 1) return;
    send({ type: 'keyup', key: e.key, code: e.code, keyCode: e.keyCode });
  });

  box.querySelector(`#oauth-done-${runId}`).addEventListener('click', async () => {
    box.innerHTML = '<div style="color:var(--accent,#6c5ce7)">Continuing…</div>';
    delete window._tpLiveViews[runId];
    await postLiveViewSignal(runId, 'done', box).catch(() => {});
    closeLiveBox(runId, box);
  });
}

function renderLiveFrame(runId, base64Jpeg) {
  const entry = window._tpLiveViews && window._tpLiveViews[runId];
  if (!entry) return;
  const img = new Image();
  img.onload = () => {
    // Resize the canvas's backing store to the frame's actual resolution (it
    // changes when the live view switches between the original page and an
    // OAuth popup of a different size) so drawImage draws 1:1 with no
    // stretch, and toFrameCoords' click math stays correct for whichever
    // page is currently live.
    if (entry.frameW !== img.naturalWidth || entry.frameH !== img.naturalHeight) {
      entry.frameW = img.naturalWidth;
      entry.frameH = img.naturalHeight;
      entry.canvas.width = img.naturalWidth;
      entry.canvas.height = img.naturalHeight;
    }
    entry.ctx2d.drawImage(img, 0, 0);
  };
  img.src = 'data:image/jpeg;base64,' + base64Jpeg;
}
