import React from 'react';
import { useNavigate } from 'react-router-dom';
import { base44 } from '@/api/base44Client';
import { useQuery } from '@tanstack/react-query';
import { useState, useEffect } from 'react';
import { AlertCircle } from 'lucide-react';

export default function ScenarioTest() {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const [formData, setFormData] = useState({
    appId: '',
    scenario: '',
    email: '',
    password: '',
    apiKey: '',
    noLogin: false
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
      const res = await base44.functions.invoke('runScenarioTest', {
        appId: formData.appId,
        scenario: formData.scenario,
        email: formData.noLogin ? null : formData.email,
        password: formData.noLogin ? null : formData.password,
        apiKey: formData.apiKey,
        freeRun: true
      });

      navigate(`/test/${res.data.testRun.id}`);
    } catch (err) {
      setError(err.message || 'Failed to run test');
      setLoading(false);
    }
  };

  const selectedApp = apps.find(a => a.id === formData.appId);
  const wordCount = formData.scenario.trim().split(/\s+/).length;

  return (
    <div className="max-w-3xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-syne font-bold">Scenario Test</h1>
        <p className="text-muted-foreground mt-2">Describe what to test in plain English</p>
      </div>

      {error && (
        <div className="bg-destructive/20 border border-destructive/50 rounded p-4 mb-6 flex gap-3">
          <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0" />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="bg-card border border-border rounded p-8 space-y-6">
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
          {apps.filter(a => a.status === 'ready').length === 0 && (
            <p className="text-xs text-destructive mt-1">No ready apps. Learn one first.</p>
          )}
        </div>

        <div>
          <label className="block text-sm font-syne font-bold mb-2">Scenario *</label>
          <textarea
            name="scenario"
            value={formData.scenario}
            onChange={handleChange}
            placeholder="Navigate to Clients, create a new client named 'Test User', verify it appears in the list..."
            rows="6"
            required
            className="w-full bg-input border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary"
          />
          <div className="flex justify-between items-center mt-2 text-xs text-muted-foreground">
            <span>{wordCount} words</span>
            {wordCount > 100 && <span className="text-destructive">Exceeds 100 word limit</span>}
          </div>
        </div>

        {selectedApp && (
          <>
            <div className="flex gap-4">
              <div className="flex-1">
                <label className="block text-sm font-syne font-bold mb-2">Email</label>
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="user@example.com"
                  disabled={formData.noLogin}
                  className="w-full bg-input border border-border rounded px-3 py-2 text-sm disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-primary"
                />
              </div>
              <div className="flex-1">
                <label className="block text-sm font-syne font-bold mb-2">Password</label>
                <input
                  type="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="••••••••"
                  disabled={formData.noLogin}
                  className="w-full bg-input border border-border rounded px-3 py-2 text-sm disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-primary"
                />
              </div>
            </div>

            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                name="noLogin"
                checked={formData.noLogin}
                onChange={handleChange}
                className="w-4 h-4 rounded border-border"
              />
              <span className="text-sm">No login required</span>
            </label>
          </>
        )}

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
            disabled={loading || !formData.appId}
            className="flex-1 bg-primary text-primary-foreground py-2 rounded font-syne font-bold hover:opacity-90 disabled:opacity-50"
          >
            {loading ? 'Running...' : '▶ Run Test'}
          </button>
          <button
            type="button"
            onClick={() => navigate('/')}
            className="px-6 py-2 rounded border border-border hover:bg-secondary"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}