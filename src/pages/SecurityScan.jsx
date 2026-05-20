import React from 'react';
import { useNavigate } from 'react-router-dom';
import { base44 } from '@/api/base44Client';
import { useQuery } from '@tanstack/react-query';
import { useState, useEffect } from 'react';
import { AlertCircle, AlertTriangle } from 'lucide-react';

export default function SecurityScanPage() {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const [formData, setFormData] = useState({
    appId: '',
    userAName: '',
    userAEmail: '',
    userAPassword: '',
    userBName: '',
    userBEmail: '',
    userBPassword: '',
    destructive: false,
    apiKey: ''
  });

  useEffect(() => {
    base44.auth.me().then(setUser).catch(() => {});
  }, []);

  const { data: apps } = useQuery({
    queryKey: ['apps', user?.email],
    queryFn: () => base44.entities.App.filter({ owner_email: user?.email }),
    enabled: !!user?.email,
    initialData: []
  });

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await base44.functions.invoke('runSecurityScan', {
        appId: formData.appId,
        userA: { name: formData.userAName, email: formData.userAEmail, password: formData.userAPassword },
        userB: { name: formData.userBName, email: formData.userBEmail, password: formData.userBPassword },
        destructive: formData.destructive,
        apiKey: formData.apiKey
      });

      navigate(`/security/${res.data.scan.id}`);
    } catch (err) {
      setError(err.message || 'Failed to start scan');
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-syne font-bold">Security Scan</h1>
        <p className="text-muted-foreground mt-2">Deep scan for authorization bypass, data leakage, and write vulnerabilities</p>
      </div>

      {error && (
        <div className="bg-destructive/20 border border-destructive/50 rounded p-4 mb-6 flex gap-3">
          <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0" />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="bg-card border border-border rounded p-8 space-y-6">
          <div>
            <label className="block text-sm font-syne font-bold mb-2">Select App *</label>
            <select
              name="appId"
              value={formData.appId}
              onChange={handleChange}
              required
              className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            >
              <option value="">Choose an app...</option>
              {apps.filter(a => a.status === 'ready').map(app => (
                <option key={app.id} value={app.id}>{app.name}</option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-6">
            <div className="space-y-4 pb-6 border-b border-border">
              <h3 className="font-syne font-bold">User A</h3>
              <input
                type="text"
                name="userAName"
                placeholder="Full name"
                value={formData.userAName}
                onChange={handleChange}
                required
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
              <input
                type="email"
                name="userAEmail"
                placeholder="Email"
                value={formData.userAEmail}
                onChange={handleChange}
                required
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
              <input
                type="password"
                name="userAPassword"
                placeholder="Password"
                value={formData.userAPassword}
                onChange={handleChange}
                required
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
              <p className="text-xs text-muted-foreground">Data subject — scan probe User A's records with User B's session</p>
            </div>

            <div className="space-y-4 pb-6 border-b border-border">
              <h3 className="font-syne font-bold">User B</h3>
              <input
                type="text"
                name="userBName"
                placeholder="Full name"
                value={formData.userBName}
                onChange={handleChange}
                required
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
              <input
                type="email"
                name="userBEmail"
                placeholder="Email"
                value={formData.userBEmail}
                onChange={handleChange}
                required
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
              <input
                type="password"
                name="userBPassword"
                placeholder="Password"
                value={formData.userBPassword}
                onChange={handleChange}
                required
                className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
              />
              <p className="text-xs text-muted-foreground">Attacker session — probe User A's data</p>
            </div>
          </div>

          <div className={`border-2 rounded p-4 ${formData.destructive ? 'border-destructive/50 bg-destructive/10' : 'border-border'}`}>
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                name="destructive"
                checked={formData.destructive}
                onChange={handleChange}
                className="w-4 h-4 rounded border-border mt-1"
              />
              <div>
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-destructive" />
                  <span className="font-syne font-bold">Include destructive write tests</span>
                </div>
                <p className="text-xs text-muted-foreground mt-1">PUT/DELETE/mass-assignment probes. Modifies/deletes real data if vulnerable. Staging only.</p>
              </div>
            </label>
          </div>

          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded p-4">
            <p className="text-xs text-yellow-700 dark:text-yellow-300">⚠ Indicative scan — not a substitute for professional penetration testing. Engage a specialty firm for compliance audits.</p>
          </div>

          <div>
            <label className="block text-sm font-syne font-bold mb-2">Anthropic API Key</label>
            <input
              type="password"
              name="apiKey"
              value={formData.apiKey}
              onChange={handleChange}
              placeholder="sk-ant-..."
              required
              className="w-full bg-input border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>

          <div className="flex gap-3">
            <button
              type="submit"
              disabled={loading}
              className="flex-1 bg-primary text-primary-foreground py-2 rounded font-syne font-bold hover:opacity-90 disabled:opacity-50"
            >
              {loading ? 'Starting scan...' : '🔬 Run Security Scan'}
            </button>
            <button
              type="button"
              onClick={() => navigate('/')}
              className="px-6 py-2 rounded border border-border hover:bg-secondary"
            >
              Cancel
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}