import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { base44 } from '@/api/base44Client';
import { useQuery } from '@tanstack/react-query';
import { Plus, X, Users, AlertCircle } from 'lucide-react';
import { getApiKey, hasApiKey } from '@/lib/apiKey';

const emptyRole = () => ({ name: '', email: '', password: '', scenario: '' });

export default function MultiRole() {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [appId, setAppId] = useState('');
  const [roles, setRoles] = useState([
    { ...emptyRole(), name: 'Role 1' },
    { ...emptyRole(), name: 'Role 2' },
  ]);
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

  const updateRole = (i, field, value) => {
    setRoles((prev) => prev.map((r, idx) => (idx === i ? { ...r, [field]: value } : r)));
  };

  const addRole = () => {
    if (roles.length >= 3) return;
    setRoles((prev) => [...prev, { ...emptyRole(), name: `Role ${prev.length + 1}` }]);
  };

  const removeRole = (i) => {
    if (roles.length <= 2) return;
    setRoles((prev) => prev.filter((_, idx) => idx !== i));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    if (!appId) { setError('Select an app first'); return; }
    if (!hasApiKey(user?.email)) { setError('Add your Claude API key in the sidebar first'); return; }
    const valid = roles.filter((r) => r.email && r.password && r.scenario.trim());
    if (valid.length < 2) { setError('At least 2 roles need email, password and scenario'); return; }

    setLoading(true);
    try {
      const res = await base44.functions.invoke('runMultiRole', {
        appId,
        roles: valid,
        apiKey: getApiKey(user?.email),
      });
      const groupId = res?.data?.multi_role_group_id;
      if (groupId) {
        navigate(`/history?group=${groupId}`);
      } else {
        navigate('/history');
      }
    } catch (err) {
      setError(err.message || 'Failed to start Multi-Role test');
      setLoading(false);
    }
  };

  const selectedApp = apps.find((a) => a.id === appId);

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <Users className="w-6 h-6 text-primary" />
          <h1 className="text-3xl font-syne font-bold">Multi-Role Test</h1>
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-primary/15 text-primary border border-primary/30">BETA</span>
        </div>
        <p className="text-muted-foreground text-sm">
          Run a scenario across multiple user roles sequentially. Role 2 sees what Role 1 created.
        </p>
      </div>

      {error && (
        <div className="bg-destructive/15 border border-destructive/40 rounded p-3 flex gap-2 items-start">
          <AlertCircle className="w-4 h-4 text-destructive flex-shrink-0 mt-0.5" />
          <p className="text-sm text-destructive">{error}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-5">
        {/* App selector */}
        <div className="bg-card border border-border rounded p-5">
          <label className="block text-xs font-syne font-bold mb-2 uppercase tracking-wider">App</label>
          <select
            value={appId}
            onChange={(e) => setAppId(e.target.value)}
            required
            className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="">— Select a learned app —</option>
            {apps.filter((a) => a.status === 'ready').map((a) => (
              <option key={a.id} value={a.id}>{a.name} ({a.url})</option>
            ))}
          </select>
          {apps.filter((a) => a.status === 'ready').length === 0 && (
            <p className="text-xs text-destructive mt-2">No ready apps. Learn one first.</p>
          )}
        </div>

        {/* Roles */}
        {roles.map((role, i) => (
          <div key={i} className="bg-card border border-border rounded p-5 space-y-3">
            <div className="flex items-center justify-between gap-3">
              <input
                value={role.name}
                onChange={(e) => updateRole(i, 'name', e.target.value)}
                placeholder="Role name (e.g. Admin, Contractor)"
                className="bg-transparent text-base font-syne font-bold flex-1 max-w-xs focus:outline-none border-b border-transparent focus:border-primary"
              />
              {i >= 2 && (
                <button type="button" onClick={() => removeRole(i)} className="text-destructive hover:bg-destructive/10 p-1 rounded" title="Remove role">
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] text-muted-foreground mb-1 font-mono uppercase">Email</label>
                <input
                  value={role.email}
                  onChange={(e) => updateRole(i, 'email', e.target.value)}
                  placeholder="user@app.com"
                  type="email"
                  className="w-full bg-input border border-border rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <div>
                <label className="block text-[10px] text-muted-foreground mb-1 font-mono uppercase">Password</label>
                <input
                  value={role.password}
                  onChange={(e) => updateRole(i, 'password', e.target.value)}
                  type="password"
                  placeholder="••••"
                  className="w-full bg-input border border-border rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
            </div>
            <div>
              <label className="block text-[10px] text-muted-foreground mb-1 font-mono uppercase">
                What should {role.name || 'this role'} do?
              </label>
              <textarea
                value={role.scenario}
                onChange={(e) => updateRole(i, 'scenario', e.target.value)}
                rows={3}
                placeholder="e.g. Navigate to Jobs, create a new job for client Ivan Fernandez. Verify it appears in the list."
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
          </div>
        ))}

        {roles.length < 3 && (
          <button type="button" onClick={addRole} className="flex items-center gap-2 text-sm text-primary hover:underline">
            <Plus className="w-4 h-4" /> Add role ({roles.length}/3)
          </button>
        )}

        <div className="flex gap-3 pt-2">
          <button
            type="submit"
            disabled={loading || !appId}
            className="flex-1 bg-primary text-primary-foreground py-2.5 rounded font-syne font-bold hover:opacity-90 disabled:opacity-50"
          >
            {loading ? 'Starting…' : '▶ Run Multi-Role Test'}
          </button>
          <button type="button" onClick={() => navigate('/')} className="px-6 py-2.5 rounded border border-border hover:bg-secondary text-sm">
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
