/* Per-user onboarding alerts.
 *
 * The signal pipeline (routes/signal.js) reacts to RECURRING bugs: one
 * person hitting one error once never crosses its threshold. But at our
 * volume every new user is one person hitting one error once. A ChatGPT
 * signup who typed a file:// path and a DSV signup whose magic link was
 * eaten by a mail scanner both failed silently and were only found days
 * later by reading logs. This mails the admin the moment a real user fails
 * at signup, crawl, or test, with who, what they entered, and what they saw,
 * so someone can reach out while they still care.
 */

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'danijel.muranovic@gmail.com';
const FROM = process.env.ALERT_FROM || 'TestPilot <alerts@testpilotapp.dev>';
const SUPER_ADMIN = (process.env.SUPER_ADMIN_EMAIL || 'danijel.muranovic@gmail.com').toLowerCase();

const recent = new Map();
const DEDUPE_MS = 30 * 60_000; // same user + stage + error: at most one mail per 30 min

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// server.js registers the user-facing recovery (lib has no DB/mailer access).
let failureHook = null;
export function onOnboardingFailure(fn) { failureHook = fn; }

export function isInternal(email) {
  const e = String(email || '').toLowerCase();
  return !e || e === SUPER_ADMIN || /@example\.(com|org|net)$/.test(e);
}

// Fire-and-forget: never throws, never delays the response to the user.
export function alertOnboardingIssue({ stage, email, url, status, error, code, detail } = {}) {
  if (isInternal(email)) return;
  try { failureHook && failureHook({ stage, email, url, status, error, code }); } catch (e) { console.error('[onboarding-alert] hook failed:', e.message); }
  const key = `${String(email).toLowerCase()}|${stage}|${code || String(error || '').slice(0, 60)}`;
  if (Date.now() - (recent.get(key) || 0) < DEDUPE_MS) return;
  recent.set(key, Date.now());

  const subject = `🚧 ${email} hit a ${stage} error: ${String(error || code || 'unknown').replace(/\s+/g, ' ').slice(0, 70)}`;
  const rows = [
    ['User', email], ['Stage', stage], ['What they entered', url || '—'],
    ['HTTP status', status ?? '—'], ['Code', code || '—'], ['Error shown / raised', error || '—'],
    ...(detail ? [['Detail', typeof detail === 'string' ? detail : JSON.stringify(detail)]] : []),
    ['When (UTC)', new Date().toISOString().replace('T', ' ').slice(0, 19)],
  ];
  const html = `
    <p>A real user just failed during onboarding. They probably won't retry on their own.</p>
    <table style="border-collapse:collapse;font-family:monospace;font-size:13px">
      ${rows.map(([k, v]) => `<tr><td style="padding:4px 12px 4px 0;color:#666;vertical-align:top">${escapeHtml(k)}</td><td style="padding:4px 0;white-space:pre-wrap">${escapeHtml(v)}</td></tr>`).join('')}
    </table>
    <p style="color:#666">Reply to them directly: <a href="mailto:${escapeHtml(email)}">${escapeHtml(email)}</a></p>`;

  if (!RESEND_API_KEY) { console.warn('[onboarding-alert]', subject); return; }
  fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: FROM, to: [ADMIN_EMAIL], reply_to: email, subject, html }),
  }).then(async (r) => { if (!r.ok) console.error('[onboarding-alert] send failed:', await r.text()); })
    .catch((err) => console.error('[onboarding-alert] send failed:', err.message));
  console.log('[onboarding-alert]', subject);
}

// Express middleware: alert on any 4xx/5xx JSON response from an onboarding
// route (the pre-stream validation failures: bad URL, blocked host, budget,
// slot limit, ...). In-stream failures are reported at their catch sites.
export function watchOnboarding(stage, getContext) {
  return (req, res, next) => {
    const origJson = res.json.bind(res);
    res.json = (body) => {
      if (res.statusCode >= 400) {
        try {
          const ctx = getContext(req) || {};
          alertOnboardingIssue({ stage, status: res.statusCode, error: body?.error, code: body?.code, ...ctx });
        } catch {}
      }
      return origJson(body);
    };
    next();
  };
}
