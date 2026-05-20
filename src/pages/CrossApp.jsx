import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { base44 } from '@/api/base44Client';
import { useQuery } from '@tanstack/react-query';
import { Plus, X, Layers, AlertCircle, ExternalLink } from 'lucide-react';
import { getApiKey, hasApiKey } from '@/lib/apiKey';

// Cross-App: test flows that span MULTIPLE apps with MULTIPLE roles each.
// Example: Dispatcher creates a job in Municipality app → Contractor sees
// and accepts it in Pro app → Dispatcher confirms it back in Municipality.
//
// For V1 this submits config to the Azure backend which orchestrates the
// cross-app flow server-side; the live progress is shown via iframe to
// the existing Azure UI which already handles the split-screen multi-session
// view. Native rebuild is Phase 2.

const emptyRole = () => ({ name: '', email: '', password: '' });
const emptyAppBlock = (n) => ({ appId: '', roles: [{ ...emptyRole(), name: `Role ${n}-1` }] });

export default function CrossApp() {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [appBlocks, setAppBlocks] = useState([emptyAppBlock(1), emptyAppBlock(2)]);
  const [scenario, setScenario] = useState('');
  const [mode, setMode] = useState('autonomous'); // or 'conversational'
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

  const updateAppBlock = (ai, field, value) => {
    setAppBlocks((prev) => prev.map((b, i) => (i === ai ? { ...b, [field]: value } : b)));
  };
  const updateRole = (ai, ri, field, value) => {
    setAppBlocks((prev) => prev.map((b, i) => {
      if (i !== ai) return b;
      return { ...b, roles: b.roles.map((r, j) => (j === ri ? { ...r, [field]: value } : r)) };
    }));
  };
  const addRole = (ai) => {
    setAppBlocks((prev) => prev.map((b, i) => {
      if (i !== ai) return b;
      return { ...b, roles: [...b.roles, { ...emptyRole(), name: `Role ${ai + 1}-${b.roles.length + 1}` }] };
    }));
  };
  const removeRole = (ai, ri) => {
    setAppBlocks((prev) => prev.map((b, i) => (i === ai ? { ...b, roles: b.roles.filter((_, j) => j !== ri) } : b)));
  };
  const addAppBlock = () => setAppBlocks((prev) => [...prev, emptyAppBlock(prev.length + 1)]);
  const removeAppBlock = (ai) => setAppBlocks((prev) => prev.filter((_, i) => i !== ai));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    if (!hasApiKey(user?.email)) { setError('Add your Claude API key in the sidebar first'); return; }
    for (const block of appBlocks) {
      if (!block.appId) { setError('Select an app for each block'); return; }
      for (const r of block.roles) {
        if (!r.name || !r.email || !r.password) { setError(`Fill in all role fields (${r.name || 'unnamed'})`); return; }
      }
    }
    if (!scenario.trim()) { setError('Write a multi-step scenario'); return; }

    setLoading(true);
    try {
      // Reuse the runScenarioTest function with a special cross-app body.
      // Azure backend recognizes the `crossApp` field and orchestrates.
      const res = await base44.functions.invoke('runCrossApp', {
        appBlocks: appBlocks.map((b) => ({
          appId: apps.find((a) => a.id === b.appId)?.app_id,
          roles: b.roles,
        })),
        scenario,
        mode,
        apiKey: getApiKey(user?.email),
      });
      if (res?.data?.testId) {
        navigate(`/test/${res.data.testRun.id}`);
      } else {
        navigate('/history');
      }
    } catch (err) {
      setError(err.message || 'Failed to start Cross-App test');
      setLoading(false);
    }
  };

  const readyApps = apps.filter((a) => a.status === 'ready');

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <Layers className="w-6 h-6 text-primary" />
          <h1 className="text-3xl font-syne font-bold">Cross-App Test</h1>
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-primary/15 text-primary border border-primary/30">BETA</span>
        </div>
        <p className="text-muted-foreground text-sm">
          Test flows that span multiple apps and multiple roles. Each role opens its own browser session in parallel.
        </p>
      </div>

      {error && (
        <div className="bg-destructive/15 border border-destructive/40 rounded p-3 flex gap-2 items-start">
          <AlertCircle className="w-4 h-4 text-destructive flex-shrink-0 mt-0.5" />
          <p className="text-sm text-destructive">{error}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-5">
        {/* App blocks */}
        {appBlocks.map((block, ai) => (
          <div key={ai} className="bg-card border border-border rounded p-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-syne font-bold uppercase tracking-wider text-primary">
                App {ai + 1}
              </span>
              {ai > 0 && (
                <button type="button" onClick={() => removeAppBlock(ai)} className="text-destructive hover:bg-destructive/10 p-1 rounded">
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
            <div>
              <label className="block text-[10px] text-muted-foreground mb-1 font-mono uppercase">App URL</label>
              <select
                value={block.appId}
                onChange={(e) => updateAppBlock(ai, 'appId', e.target.value)}
                required
                className="w-full bg-input border border-border rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              >
                <option value="">— Select a learned app —</option>
                {readyApps.map((a) => <option key={a.id} value={a.id}>{a.name} ({a.url})</option>)}
              </select>
            </div>

            <div className="text-[11px] font-bold text-muted-foreground uppercase tracking-wider mt-2">Roles</div>
            {block.roles.map((role, ri) => (
              <div key={ri} className="bg-input/40 border border-border rounded p-3 space-y-2">
                <div className="grid grid-cols-12 gap-2 items-end">
                  <div className="col-span-4">
                    <label className="block text-[10px] text-muted-foreground mb-1 font-mono uppercase">Name</label>
                    <input
                      value={role.name}
                      onChange={(e) => updateRole(ai, ri, 'name', e.target.value)}
                      placeholder="e.g. Dispatcher"
                      className="w-full bg-input border border-border rounded px-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                  </div>
                  <div className="col-span-4">
                    <label className="block text-[10px] text-muted-foreground mb-1 font-mono uppercase">Email</label>
                    <input
                      value={role.email}
                      onChange={(e) => updateRole(ai, ri, 'email', e.target.value)}
                      type="email"
                      className="w-full bg-input border border-border rounded px-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                  </div>
                  <div className="col-span-3">
                    <label className="block text-[10px] text-muted-foreground mb-1 font-mono uppercase">Pass</label>
                    <input
                      value={role.password}
                      onChange={(e) => updateRole(ai, ri, 'password', e.target.value)}
                      type="password"
                      className="w-full bg-input border border-border rounded px-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                    />
                  </div>
                  <div className="col-span-1">
                    {block.roles.length > 1 && (
                      <button type="button" onClick={() => removeRole(ai, ri)} className="text-destructive hover:bg-destructive/10 p-1 rounded">
                        <X className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
            <button type="button" onClick={() => addRole(ai)} className="text-xs text-primary hover:underline flex items-center gap-1">
              <Plus className="w-3 h-3" /> Add role to App {ai + 1}
            </button>
          </div>
        ))}

        <button type="button" onClick={addAppBlock} className="text-sm text-primary hover:underline flex items-center gap-2">
          <Plus className="w-4 h-4" /> Add another app
        </button>

        {/* Scenario */}
        <div className="bg-card border border-border rounded p-5 space-y-3">
          <div>
            <label className="block text-xs font-syne font-bold mb-2 uppercase tracking-wider">Multi-step Scenario</label>
            <textarea
              value={scenario}
              onChange={(e) => setScenario(e.target.value)}
              rows={6}
              placeholder={`Use [Role @ App] prefixes:\n[Dispatcher @ Municipality] Find job card #123 and send to contratistas\n[Contractor @ Fixera Pro] See the new job card and bid on it\n[Dispatcher @ Municipality] Accept the bid from the contractor`}
              className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-syne font-bold mb-2 uppercase tracking-wider">Mode</label>
            <div className="flex gap-3">
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="radio" name="mode" value="autonomous" checked={mode === 'autonomous'} onChange={(e) => setMode(e.target.value)} className="accent-primary" />
                <span className="text-sm">Autonomous — agent runs the whole scenario</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="radio" name="mode" value="conversational" checked={mode === 'conversational'} onChange={(e) => setMode(e.target.value)} className="accent-primary" />
                <span className="text-sm">Conversational — you direct each role</span>
              </label>
            </div>
          </div>
        </div>

        <div className="flex gap-3">
          <button type="submit" disabled={loading} className="flex-1 bg-primary text-primary-foreground py-2.5 rounded font-syne font-bold hover:opacity-90 disabled:opacity-50">
            {loading ? 'Starting…' : '▶ Run Cross-App Test'}
          </button>
          <button type="button" onClick={() => navigate('/')} className="px-6 py-2.5 rounded border border-border hover:bg-secondary text-sm">
            Cancel
          </button>
        </div>
      </form>

      <p className="text-xs text-muted-foreground flex items-center gap-1 pt-2 border-t border-border">
        <ExternalLink className="w-3 h-3" /> Full split-screen live view available in <a href="https://testpilotapp.dev/app" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline ml-1">classic TestPilot UI</a>.
      </p>
    </div>
  );
}
