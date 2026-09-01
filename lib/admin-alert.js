/* Regression alerts belong to testpilot, not the bridge: the bridge only
 * hears about a bug once a fix job is enqueued, and a regression is
 * precisely the case where we do NOT want to enqueue another one.
 */

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'alex@testpilot.dev';
const FROM = process.env.ALERT_FROM || 'TestPilot <alerts@testpilotapp.dev>';

const recent = new Map();
const DEDUPE_MS = 60 * 60_000;

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

export async function sendAdminAlert(subject, context, dedupeKey) {
  const key = dedupeKey || subject;
  if (Date.now() - (recent.get(key) || 0) < DEDUPE_MS) return;
  recent.set(key, Date.now());

  if (!RESEND_API_KEY) { console.warn('[alert]', subject, context); return; }

  const html = `
    <p>${escapeHtml(subject)}</p>
    <pre style="background:#f4f4f4;padding:12px;border-radius:4px;white-space:pre-wrap">${escapeHtml(JSON.stringify(context, null, 2))}</pre>
    <p>No fix job was queued for this. A shipped fix coming back means the patch
    missed part of the cause, so it needs a look rather than another agent run.</p>
  `;

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: FROM, to: [ADMIN_EMAIL], subject, html }),
    });
    if (!res.ok) throw new Error(await res.text());
  } catch (err) {
    console.error('[alert] send failed:', err.message);
  }
}
