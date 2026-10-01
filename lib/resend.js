// The ONE place that talks to Resend. Every outbound mail — user mail from
// server.js's mailer(), admin alerts, onboarding alerts — goes through here,
// so the run-mode rule (lib/local-run.js) is enforced once: a server that is
// not the production process never mails real people. A suppressed mail is
// logged with its subject, recipient, the first lines of its text and every
// link in it, so a local developer can still use their own login link.
import { RUN_MODE } from './local-run.js';

const RESEND_API_KEY = process.env.RESEND_API_KEY;

export async function sendResend({ from, to, subject, html, text, replyTo }, { tag = 'mail' } = {}) {
  const recipients = Array.isArray(to) ? to : [to];
  if (!RESEND_API_KEY) {
    console.warn(`[${tag}] not sent (no RESEND_API_KEY):`, subject, '→', recipients.join(', '));
    return { id: null, skipped: 'no-api-key' };
  }
  if (!RUN_MODE.mailEnabled) {
    const body = String(text || String(html || '').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim().slice(0, 400);
    const links = [...String(html || '').matchAll(/href="([^"]+)"/g)].map((m) => m[1]).filter((h) => !/^mailto:/i.test(h));
    console.log(`[${tag}] suppressed (local run):`, subject, '→', recipients.join(', '), body ? '| ' + body : '', links.length ? '| links: ' + links.join(' ') : '');
    return { id: null, suppressed: true };
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${RESEND_API_KEY}` },
    body: JSON.stringify({ from, to: recipients, subject, html, text, ...(replyTo ? { reply_to: replyTo } : {}) }),
  });
  if (!res.ok) throw new Error(`Resend error: ${await res.text()}`);
  return res.json();
}
