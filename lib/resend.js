// The ONE place that talks to Resend. Every outbound mail — user mail from
// server.js's mailer(), admin alerts, onboarding alerts — goes through here,
// so the run-mode rule (lib/local-run.js) is enforced once: a server that is
// not the production process never mails real people.
//
// Order of checks matters: the run-mode suppression comes FIRST (it needs no
// key, and a laptop .env usually has none), then the key check. In
// production a missing key THROWS, as mailer() always did — a rotated-away key
// must surface as a failed login-link request, not as "check your email" with
// nothing arriving.
import { RUN_MODE, isInternalAddress } from './local-run.js';

const RESEND_API_KEY = process.env.RESEND_API_KEY;
// Anything token-shaped (long hex / uuid runs) — login links, verification
// codes — must never reach a log for a real person's address.
const TOKEN_RE = /[A-Za-z0-9_-]{24,}/g;
const forLog = (recipients, allInternal) => (allInternal ? recipients.join(', ') : `${recipients.length} external recipient${recipients.length === 1 ? '' : 's'}`);

export async function sendResend({ from, to, subject, html, text, replyTo }, { tag = 'mail' } = {}) {
  const recipients = (Array.isArray(to) ? to : [to]).filter((a) => typeof a === 'string' && a.trim());
  if (!recipients.length) { console.warn(`[${tag}] not sent (no recipient):`, subject); return { id: null, skipped: 'no-recipient' }; }
  const allInternal = recipients.every(isInternalAddress);
  const who = forLog(recipients, allInternal);
  if (!RUN_MODE.mailEnabled) {
    // Logged with the first lines of text and every link, so a local developer
    // can use their own login link — but only for internal/test recipients.
    // For anyone else (TESTPILOT_LOCAL on a production-like box) no links are
    // logged and anything token-shaped in the text is redacted, in href, path,
    // fragment or plain text alike.
    const rawBody = String(text || String(html || '').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim().slice(0, 400);
    const body = allInternal ? rawBody : rawBody.replace(TOKEN_RE, '<redacted>');
    const links = allInternal
      ? [...String(html || '').matchAll(/href=["']([^"']+)["']/g)].map((m) => m[1]).filter((h) => !/^mailto:/i.test(h))
      : [];
    console.log(`[${tag}] suppressed (local run):`, subject, '→', who, body ? '| ' + body : '', links.length ? '| links: ' + links.join(' ') : '');
    return { id: null, suppressed: true };
  }
  if (!RESEND_API_KEY) {
    if (RUN_MODE.isProd) throw new Error('RESEND_API_KEY is not set — mail cannot be sent');
    console.warn(`[${tag}] not sent (no RESEND_API_KEY):`, subject, '→', who);
    return { id: null, skipped: 'no-api-key' };
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${RESEND_API_KEY}` },
    body: JSON.stringify({ from, to: recipients, subject, html, text, ...(replyTo ? { reply_to: replyTo } : {}) }),
  });
  if (!res.ok) throw new Error(`Resend error: ${await res.text()}`);
  const out = await res.json();
  console.log(`[${tag}] sent:`, subject, '→', who); // external addresses are counted, not named
  return out;
}
