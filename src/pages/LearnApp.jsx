import React from 'react';
import { useNavigate } from 'react-router-dom';
import { base44 } from '@/api/base44Client';
import { useState, useEffect } from 'react';
import { AlertCircle, Loader } from 'lucide-react';

export default function LearnApp() {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [learning, setLearning] = useState(false);
  const [appId, setAppId] = useState(null);

  const [formData, setFormData] = useState({
    url: '',
    email: '',
    password: '',
    description: '',
    apiKey: '',
    noLogin: false
  });

  useEffect(() => {
    base44.auth.me().then(setUser).catch(() => {});
  }, []);

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
      // Call backend function
      const res = await base44.functions.invoke('learnNewApp', {
        url: formData.url,
        email: formData.noLogin ? null : formData.email,
        password: formData.noLogin ? null : formData.password,
        description: formData.description,
        apiKey: formData.apiKey,
        freeRun: true
      });

      setAppId(res.data.appId);
      setLearning(true);

      // Poll status until ready
      const pollStatus = async () => {
        let attempts = 0;
        const maxAttempts = 60; // 5 minutes

        while (attempts < maxAttempts) {
          const apps = await base44.entities.App.filter({ app_id: res.data.appId });
          if (apps && apps[0]?.status === 'ready') {
            navigate(`/apps/${apps[0].id}`);
            return;
          }
          if (apps && apps[0]?.status === 'error') {
            setError('Learning failed. Please try again.');
            setLearning(false);
            return;
          }
          attempts++;
          await new Promise(r => setTimeout(r, 5000));
        }
        setError('Learning took too long. Please check back soon.');
        setLearning(false);
      };

      pollStatus();
    } catch (err) {
      setError(err.message || 'Failed to start learning');
      setLoading(false);
    }
  };

  if (learning) {
    return (
      <div className="max-w-2xl mx-auto py-16 text-center">
        <div className="bg-card border border-border rounded p-8">
          <Loader className="w-12 h-12 mx-auto mb-4 animate-spin text-primary" />
          <h2 className="text-2xl font-syne font-bold mb-2">Learning your app...</h2>
          <p className="text-muted-foreground">This takes 1-5 minutes. Hang tight.</p>
          <p className="text-xs text-muted-foreground mt-4 font-mono">ID: {appId}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-syne font-bold">Learn New App</h1>
        <p className="text-muted-foreground mt-2">Register a web app for testing</p>
      </div>

      {error && (
        <div className="bg-destructive/20 border border-destructive/50 rounded p-4 mb-6 flex gap-3">
          <AlertCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
          <p className="text-destructive text-sm">{error}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="bg-card border border-border rounded p-8 space-y-6">
        <div>
          <label className="block text-sm font-syne font-bold mb-2">App URL *</label>
          <input
            type="url"
            name="url"
            value={formData.url}
            onChange={handleChange}
            placeholder="https://example.com"
            required
            className="w-full bg-input border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary"
          />
          <p className="text-xs text-muted-foreground mt-1">The URL where your app is live</p>
        </div>

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
              className="w-full bg-input border border-border rounded px-3 py-2 text-sm font-mono disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-primary"
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
              className="w-full bg-input border border-border rounded px-3 py-2 text-sm font-mono disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-primary"
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

        <div>
          <label className="block text-sm font-syne font-bold mb-2">Description</label>
          <textarea
            name="description"
            value={formData.description}
            onChange={handleChange}
            placeholder="What does this app do?"
            rows="3"
            className="w-full bg-input border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary"
          />
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
          <p className="text-xs text-muted-foreground mt-1">Get one at <a href="https://console.anthropic.com" target="_blank" rel="noopener" className="text-primary hover:underline">console.anthropic.com</a></p>
        </div>

        <div className="flex gap-3">
          <button
            type="submit"
            disabled={loading}
            className="flex-1 bg-primary text-primary-foreground py-2 rounded font-syne font-bold hover:opacity-90 disabled:opacity-50 transition-opacity"
          >
            {loading ? 'Starting...' : '▶ Learn App'}
          </button>
          <button
            type="button"
            onClick={() => navigate('/apps')}
            className="px-6 py-2 rounded border border-border hover:bg-secondary transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}