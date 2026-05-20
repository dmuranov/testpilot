import React from 'react';
import { base44 } from '@/api/base44Client';
import { useState, useEffect } from 'react';
import { AlertCircle, Check } from 'lucide-react';

export default function Settings() {
  const [user, setUser] = useState(null);
  const [apiKey, setApiKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    base44.auth.me().then(setUser).catch(() => {});
  }, []);

  const handleSaveKey = async () => {
    setLoading(true);
    setMessage(null);
    setError(null);

    try {
      const res = await base44.functions.invoke('verifyAnthropicKey', { apiKey });
      if (res.data.ok) {
        sessionStorage.setItem('anthropic_api_key', apiKey);
        setMessage('API key verified and saved');
        setTimeout(() => setMessage(null), 3000);
      } else {
        setError(res.data.error || 'Invalid API key');
      }
    } catch (err) {
      setError(err.message || 'Failed to verify key');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl">
      <div className="mb-8">
        <h1 className="text-3xl font-syne font-bold">Settings</h1>
      </div>

      <div className="space-y-6">
        {/* API Key */}
        <div className="bg-card border border-border rounded p-8">
          <h2 className="text-lg font-syne font-bold mb-4">Anthropic API Key</h2>
          <p className="text-sm text-muted-foreground mb-4">
            Your personal API key from <a href="https://console.anthropic.com" target="_blank" rel="noopener" className="text-primary hover:underline">console.anthropic.com</a>. Only you can see it.
          </p>

          {error && (
            <div className="bg-destructive/20 border border-destructive/50 rounded p-3 mb-4 flex gap-2 text-sm">
              <AlertCircle className="w-4 h-4 text-destructive flex-shrink-0 mt-0.5" />
              <p className="text-destructive">{error}</p>
            </div>
          )}

          {message && (
            <div className="bg-green-500/20 border border-green-500/50 rounded p-3 mb-4 flex gap-2 text-sm">
              <Check className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
              <p className="text-green-500">{message}</p>
            </div>
          )}

          <div className="space-y-3">
            <input
              type="password"
              placeholder="sk-ant-..."
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="w-full bg-input border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary"
            />
            <button
              onClick={handleSaveKey}
              disabled={loading || !apiKey}
              className="bg-primary text-primary-foreground px-4 py-2 rounded font-syne font-bold hover:opacity-90 disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Save & Verify'}
            </button>
          </div>
        </div>

        {/* Account Info */}
        <div className="bg-card border border-border rounded p-8">
          <h2 className="text-lg font-syne font-bold mb-4">Account</h2>
          <div className="space-y-3">
            <div>
              <p className="text-sm text-muted-foreground">Full Name</p>
              <p className="text-base font-mono">{user?.full_name || '—'}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Email</p>
              <p className="text-base font-mono">{user?.email || '—'}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Role</p>
              <p className="text-base font-mono capitalize">{user?.role || '—'}</p>
            </div>
          </div>
        </div>

        {/* Logout */}
        <div className="bg-card border border-border rounded p-8">
          <button
            onClick={() => base44.auth.logout('/')}
            className="text-destructive hover:text-destructive/80 font-syne font-bold transition-colors"
          >
            Logout
          </button>
        </div>
      </div>
    </div>
  );
}