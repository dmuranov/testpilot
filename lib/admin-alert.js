/* Regression alerts belong to testpilot, not the bridge: the bridge only
 * hears about a bug once a fix job is enqueued, and a regression is
 * precisely the case where we do NOT want to enqueue another one.
 */

import { sendResend } from './resend.js';

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'danijel.muranovic@gmail.com';
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


  const html = `
    <p>${escapeHtml(subject)}</p>
    <pre style="background:#f4f4f4;padding:12px;border-radius:4px;white-space:pre-wrap">${escapeHtml(JSON.stringify(context, null, 2))}</pre>
    <p>No fix job was queued for this. A shipped fix coming back means the patch
    missed part of the cause, so it needs a look rather than another agent run.</p>
  `;

  try {
    await sendResend({ from: FROM, to: [ADMIN_EMAIL], subject, html }, { tag: 'alert' });
  } catch (err) {
    // The alert's content must survive a failed send — it is the only record.
    console.error('[alert] send failed:', err.message, '|', subject, JSON.stringify(context));
  }
}
