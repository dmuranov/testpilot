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
import { RUN_MODE } from './local-run.js';

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const SUPER_ADMIN = (process.env.SUPER_ADMIN_EMAIL || 'danijel.muranovic@gmail.com').toLowerCase();
// Same notion as lib/onboarding-alert.js isInternal(): test identities and the admin.
const isInternalAddress = (a) => { const e = String(a || '').toLowerCase(); return e === SUPER_ADMIN || /@example\.(com|org|net)$/.test(e); };

export async function sendResend({ from, to, subject, html, text, replyTo }, { tag = 'mail' } = {}) {
  const recipients = Array.isArray(to) ? to : [to];
  const who = recipients.join(', ');
  if (!RUN_MODE.mailEnabled) {
    // Logged with the first lines of text and every link, so a local developer
    // can use their own login link. Links carry live tokens: shown in full only
    // when every recipient is an internal/test address, redacted otherwise
    // (TESTPILOT_LOCAL on a production-like box must not write real users'
    // tokens into pm2 logs).
    const body = String(text || String(html || '').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim().slice(0, 400);
    const allInternal = recipients.every(isInternalAddress);
    const links = [...String(html || '').matchAll(/href="([^"]+)"/g)].map((m) => m[1]).filter((h) => !/^mailto:/i.test(h))
      .map((h) => (allInternal ? h : h.replace(/\?.*$/, '?<redacted>')));
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
  console.log(`[${tag}] sent:`, subject, '→', who);
  return out;
}
