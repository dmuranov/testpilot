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
  // No recipient is a caller bug and must surface as one: a caller that only
  // checks for a throw (a schedule's regression alert) must not record "sent".
  if (!recipients.length) throw new Error(`no recipient for mail "${subject}"`);
  const allInternal = recipients.every(isInternalAddress);
  const who = forLog(recipients, allInternal);
  // What a not-sent mail leaves in the log: the first lines of text and, so a
  // local developer can use their own login link, every link — but only for
  // internal/test recipients and never on the production box (a token in
  // ~/.pm2/logs outlives any maintenance window). For anyone else anything
  // token-shaped is redacted, in href, path, fragment or plain text alike.
  const showLinks = allInternal && !RUN_MODE.onProductionBox;
  const notSentDetail = () => {
    const rawBody = String(text || String(html || '').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim().slice(0, 400);
    const body = showLinks ? rawBody : rawBody.replace(TOKEN_RE, '<redacted>');
    const links = showLinks ? [...String(html || '').matchAll(/href=["']([^"']+)["']/g)].map((m) => m[1]).filter((h) => !/^mailto:/i.test(h)) : [];
    return (body ? '| ' + body : '') + (links.length ? ' | links: ' + links.join(' ') : '');
  };
  if (!RUN_MODE.mailEnabled) {
    console.log(`[${tag}] suppressed (local run):`, subject, '→', who, notSentDetail());
    return { id: null, suppressed: true };
  }
  if (!RESEND_API_KEY) {
    if (RUN_MODE.isProd) throw new Error('RESEND_API_KEY is not set — mail cannot be sent');
    console.warn(`[${tag}] not sent (no RESEND_API_KEY):`, subject, '→', who, notSentDetail());
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
