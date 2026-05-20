import React, { useState, useEffect } from 'react';
import { base44 } from '@/api/base44Client';
import { useQuery } from '@tanstack/react-query';
import { MessageSquare, AlertCircle, ExternalLink } from 'lucide-react';
import { getApiKey, hasApiKey } from '@/lib/apiKey';

// Interactive Test: live chat with the agent driving a browser. The chat
// UI (message list + screenshot pane + send box) is the most complex piece
// of original TestPilot — too React-y to rebuild natively for V1. We start
// the session via the Base44 startChatSession function (proxies to Azure
// /api/chat/start) then iframe the existing Azure chat UI for the live
// interaction.

export default function InteractiveTest() {
  const [user, setUser] = useState(null);
  const [appId, setAppId] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [noLogin, setNoLogin] = useState(false);
  const [sessionId, setSessionId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    base44.auth.me().then(setUser).catch(() => {});
  }, []);

  const { data: apps } = useQuery({
    queryKey: ['apps', user?.email],
    queryFn: () => base44.entities.App.filter({ owner_email: user?.email }),
    enabled: !!user?.email,
    initialData: [],
  });

  const startSession = async (e) => {
    e.preventDefault();
    setError(null);
    if (!appId) { setError('Select an app'); return; }
    if (!hasApiKey(user?.email)) { setError('Add your Claude API key in the sidebar first'); return; }
    if (!noLogin && (!email || !password)) { setError('Login credentials required (or check "No login")'); return; }

    setLoading(true);
    try {
      const res = await base44.functions.invoke('startChatSession', {
        appId: apps.find((a) => a.id === appId)?.app_id,
        email: noLogin ? null : email,
        password: noLogin ? null : password,
        apiKey: getApiKey(user?.email),
      });
      if (res?.data?.sessionId) {
        setSessionId(res.data.sessionId);
      } else {
        setError(res?.data?.error || 'Failed to start session');
        setLoading(false);
      }
    } catch (err) {
      setError(err.message || 'Failed to start session');
      setLoading(false);
    }
  };

  const endSession = async () => {
    if (!sessionId) return;
    try {
      await base44.functions.invoke('endChatSession', { sessionId });
    } catch {}
    setSessionId(null);
    setLoading(false);
  };

  // Active session: iframe the existing Azure chat UI
  if (sessionId) {
    const iframeUrl = `https://testpilotapp.dev/chat?session=${encodeURIComponent(sessionId)}`;
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <MessageSquare className="w-6 h-6 text-primary" />
            <h1 className="text-2xl font-syne font-bold">Interactive Session</h1>
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-primary/15 text-primary border border-primary/30">BETA</span>
          </div>
          <button onClick={endSession} className="px-4 py-2 rounded border border-destructive text-destructive hover:bg-destructive/10 text-sm">
            End Session
          </button>
        </div>
        <div className="bg-card border border-border rounded overflow-hidden">
          <iframe
            src={iframeUrl}
            className="w-full"
            style={{ height: '75vh', border: 'none' }}
            title="Interactive chat session"
          />
        </div>
        <p className="text-xs text-muted-foreground">
          Session ID: <code className="font-mono">{sessionId}</code>
        </p>
      </div>
    );
  }

  // Setup
  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <MessageSquare className="w-6 h-6 text-primary" />
          <h1 className="text-3xl font-syne font-bold">Interactive Test</h1>
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-primary/15 text-primary border border-primary/30">BETA</span>
        </div>
        <p className="text-muted-foreground text-sm">
          Live chat with the agent. Type commands in plain English ("Click the blue button", "What's on this page?") and the agent executes them on your app in real time.
        </p>
      </div>

      {error && (
        <div className="bg-destructive/15 border border-destructive/40 rounded p-3 flex gap-2 items-start">
          <AlertCircle className="w-4 h-4 text-destructive flex-shrink-0 mt-0.5" />
          <p className="text-sm text-destructive">{error}</p>
        </div>
      )}

      <form onSubmit={startSession} className="bg-card border border-border rounded p-6 space-y-4">
        <div>
          <label className="block text-xs font-syne font-bold mb-2 uppercase tracking-wider">App</label>
          <select
            value={appId}
            onChange={(e) => setAppId(e.target.value)}
            required
            className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="">— Select a learned app —</option>
            {apps.filter((a) => a.status === 'ready').map((a) => (
              <option key={a.id} value={a.id}>{a.name}</option>
            ))}
          </select>
        </div>

        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" checked={noLogin} onChange={(e) => setNoLogin(e.target.checked)} className="accent-primary" />
          <span className="text-sm">No login required</span>
        </label>

        {!noLogin && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-syne font-bold mb-2 uppercase tracking-wider">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="user@app.com"
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div>
              <label className="block text-xs font-syne font-bold mb-2 uppercase tracking-wider">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••"
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
          </div>
        )}

        <button type="submit" disabled={loading || !appId} className="w-full bg-primary text-primary-foreground py-2.5 rounded font-syne font-bold hover:opacity-90 disabled:opacity-50">
          {loading ? 'Connecting…' : '💬 Start Session'}
        </button>
      </form>

      <p className="text-xs text-muted-foreground flex items-center gap-1">
        <ExternalLink className="w-3 h-3" /> Live chat UI hosted on <a href="https://testpilotapp.dev" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline ml-1">testpilotapp.dev</a> — embedded after session starts.
      </p>
    </div>
  );
}
