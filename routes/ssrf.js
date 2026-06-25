// SSRF guard for user-submitted target URLs. Blocks navigation to loopback,
// private, link-local, and cloud-metadata addresses so a user can't point the
// scanner's headless browser at internal infrastructure (e.g. 169.254.169.254
// Azure IMDS, localhost:3001, 10.x services) and read it back via the agent's
// screenshots/outcomes. Pure range/host predicates are unit-tested in
// test/ssrf.test.mjs; assertPublicUrl also DNS-resolves the host and checks
// every resolved address (so a public name that points at a private IP is
// blocked too). RESIDUAL: DNS rebinding between this check and the actual
// connect is NOT covered here — the proper fix is network egress isolation of
// the browser (see the infra notes).
import dns from 'dns/promises';
import net from 'net';

// Is an IPv4/IPv6 literal in a blocked (non-public) range?
export function isBlockedIp(ip) {
  const a = String(ip || '').trim();
  if (net.isIPv6(a)) {
    const l = a.toLowerCase();
    if (l === '::1' || l === '::') return true;                 // loopback / unspecified
    if (l.startsWith('fe8') || l.startsWith('fe9') || l.startsWith('fea') || l.startsWith('feb')) return true; // fe80::/10 link-local
    if (l.startsWith('fc') || l.startsWith('fd')) return true;  // fc00::/7 unique-local
    const m = l.match(/(?:::ffff:)(\d+\.\d+\.\d+\.\d+)$/);      // IPv4-mapped
    if (m) return isBlockedIp(m[1]);
    return false;
  }
  if (!net.isIPv4(a)) return true; // not a valid IP literal → block (fail closed)
  const o = a.split('.').map(Number);
  if (o.length !== 4 || o.some(n => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [x, y] = o;
  if (x === 127) return true;                        // 127/8 loopback
  if (x === 10) return true;                         // 10/8 private
  if (x === 172 && y >= 16 && y <= 31) return true;  // 172.16/12 private
  if (x === 192 && y === 168) return true;           // 192.168/16 private
  if (x === 169 && y === 254) return true;           // 169.254/16 link-local (incl. cloud metadata)
  if (x === 0) return true;                          // 0/8 "this" network
  if (x === 100 && y >= 64 && y <= 127) return true; // 100.64/10 CGNAT
  if (x >= 224) return true;                         // 224+ multicast / reserved
  return false;
}

// Hostnames that must never be resolved/navigated (literal internal names).
export function isBlockedHostname(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h.endsWith('.internal') || h.endsWith('.local')) return true;
  if (h === 'metadata.google.internal') return true;
  return false;
}

// Full async check: scheme + hostname blocklist + DNS-resolved IP ranges.
// Returns { ok: true } or { ok: false, error }.
export async function assertPublicUrl(rawUrl) {
  let u;
  const raw = String(rawUrl || '').trim();
  const hasScheme = /^[a-z][a-z0-9+.-]*:/i.test(raw); // any scheme (http:, ftp:, javascript:, file:…)
  try { u = new URL(hasScheme ? raw : 'https://' + raw); }
  catch { return { ok: false, error: 'Invalid URL' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { ok: false, error: 'Only http(s) URLs are allowed.' };
  const host = u.hostname;
  if (isBlockedHostname(host)) return { ok: false, error: 'That host is not allowed (internal/loopback).' };
  if (net.isIP(host)) {
    return isBlockedIp(host) ? { ok: false, error: 'That address is not allowed (private/loopback/metadata).' } : { ok: true };
  }
  let addrs = [];
  try { addrs = await dns.lookup(host, { all: true }); }
  catch { return { ok: false, error: 'Could not resolve host.' }; }
  if (!addrs.length) return { ok: false, error: 'Could not resolve host.' };
  for (const { address } of addrs) {
    if (isBlockedIp(address)) return { ok: false, error: 'That host resolves to a private/internal address and is not allowed.' };
  }
  return { ok: true };
}
