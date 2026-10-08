// Free runs cap the client's own test description at 100 words. The dashboard appends a fixed
// instruction to every scenario ("(Repeatable run: ...)" or "(Read-only run: ...)", ~70 words);
// that text is ours, not the client's, so it never counts towards the limit. Counting it refused
// an 80-word description as "over 100" (Formidium, 2026-10-08).
export const FREE_RUN_WORD_LIMIT = 100;

export function userScenarioWords(scenario) {
  const own = String(scenario || '').split(/\(\s*(?:Repeatable run|Read-only run):/)[0];
  return own.trim().split(/\s+/).filter(Boolean).length;
}
