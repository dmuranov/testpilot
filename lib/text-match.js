// "Does the page show this text?" — shared by the live check and its negative
// control, so the two can never drift apart.
//
// The expected value is what a person reads on the page ("Cart (1)", "$24.00",
// "Total: €48.00"). It used to be compiled as a regular expression whenever it
// happened to compile, so "Cart (1)" looked for "Cart 1" and "$24.00" could
// never match at all ("$" = end of text): a correct page was reported as a bug
// (seen 2026-11-11 on a new client's very first test). So:
//   1. the words as written, ignoring case and runs of whitespace;
//   2. only if that fails, the value as a pattern (for a deliberate one such
//      as "Order #\d+").
const squash = (s) => String(s ?? '').replace(/[\s ]+/g, ' ').trim().toLowerCase();

export function safeRegex(pattern) {
  if (!pattern || typeof pattern !== 'string') return null;
  try { return new RegExp(pattern, 'i'); } catch { return null; }
}

export function matchesText(valueOrPattern, text) {
  const want = squash(valueOrPattern);
  if (!want) return true;   // nothing asked for: same as the old empty-pattern behaviour
  const have = squash(text);
  if (have.includes(want)) return true;
  const re = safeRegex(String(valueOrPattern));
  return re ? re.test(String(text ?? '')) : false;
}
