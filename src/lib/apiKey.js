// API key storage helpers. Mirrors the original TestPilot pattern:
// per-user localStorage so multiple users on the same device don't clobber
// each other's keys, and so signing out clears the key.

export function apiKeyName(email) {
  return 'testpilot_api_key_' + (email || 'anon');
}

export function getApiKey(email) {
  if (typeof window === 'undefined') return '';
  return localStorage.getItem(apiKeyName(email)) || '';
}

export function setApiKey(email, key) {
  if (typeof window === 'undefined') return;
  if (key && key.trim()) localStorage.setItem(apiKeyName(email), key.trim());
  else localStorage.removeItem(apiKeyName(email));
}

export function maskApiKey(key) {
  if (!key || key.length < 12) return '••••••••';
  return key.substring(0, 7) + '•••' + key.substring(key.length - 4);
}

export function hasApiKey(email) {
  return getApiKey(email).length > 10;
}
