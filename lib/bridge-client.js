/* testpilot -> testpilot-support-bridge
 *
 * The bridge is a separate process on its own port with its own repo clone.
 * Its only public surface for Symphony/Alex is POST /mcp (StreamableHTTP),
 * which needs an MCP client to speak. Rather than pull that dependency into
 * this repo to call one tool, this calls the plain JSON route the bridge
 * exposes at routes/fix-request.js, which invokes the same submitTicket()
 * the MCP tool does — see testpilot-support-bridge/lib/tickets.js.
 */

const BRIDGE_URL = process.env.BRIDGE_URL || 'http://127.0.0.1:3099';
const BRIDGE_TOKEN = process.env.BRIDGE_TOKEN;
const TIMEOUT_MS = Number(process.env.BRIDGE_TIMEOUT_MS || 8000);

function describe({ hash, page, event }) {
  const where = event.path || page || 'unknown page';
  const lines = [
    'Auto-detected by TestPilot signal telemetry (no human filed this).',
    '',
    `Signature: ${hash}`,
    `Page: ${page || 'unknown'}`,
    `Event: ${event.type}${event.status ? ` ${event.status}` : ''}`,
    `Request: ${event.method || ''} ${where}`.trim(),
  ];
  if (event.name) lines.push(`Error: ${event.name}`);
  if (event.message) lines.push(`Message: ${event.message}`);
  if (event.stack) lines.push('', 'Stack (top frames):', event.stack.split('\n').slice(0, 8).join('\n'));
  return lines.join('\n');
}

export async function enqueueFixJob({ hash, page, event }) {
  if (!BRIDGE_TOKEN) throw new Error('BRIDGE_TOKEN not set — refusing to call the bridge unauthenticated');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(`${BRIDGE_URL}/api/fix-request`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${BRIDGE_TOKEN}`,
      },
      signal: controller.signal,
      body: JSON.stringify({
        // resolve_ticket's `email` is who gets replied to. An auto-detected
        // bug has no customer waiting on a reply, so this is the admin
        // address and the real reporter context lives in the description.
        email: process.env.ADMIN_EMAIL || 'alex@testpilot.dev',
        plan: 'internal',
        url: page || null,
        description: describe({ hash, page, event }),
        source: 'signal',
        signatureHash: hash,
      }),
    });

    if (!res.ok) throw new Error(`bridge returned ${res.status}: ${(await res.text()).slice(0, 300)}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}
