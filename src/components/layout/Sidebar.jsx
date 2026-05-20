import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, Zap, Lock, Settings, LogOut, Briefcase, History, Users, Layers, MessageSquare, GitBranch, Check, X, Loader2 } from 'lucide-react';
import { base44 } from '@/api/base44Client';
import { getApiKey, setApiKey, maskApiKey, hasApiKey } from '@/lib/apiKey';

const Logo = () => (
  <div className="flex items-baseline gap-0.5 font-syne font-bold text-lg">
    <span className="text-foreground">Test</span>
    <span className="text-primary">&gt;_Pilot</span>
  </div>
);

export default function Sidebar() {
  const location = useLocation();
  const [user, setUser] = useState(null);
  const [apiKey, setApiKeyState] = useState('');
  const [editingKey, setEditingKey] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [keyError, setKeyError] = useState(null);

  useEffect(() => {
    base44.auth.me().then((u) => {
      setUser(u);
      setApiKeyState(getApiKey(u?.email));
    }).catch(() => {});
  }, []);

  const navItems = [
    { icon: LayoutDashboard, label: 'Dashboard', path: '/' },
    { icon: Briefcase, label: 'Apps', path: '/apps' },
    { icon: Zap, label: 'Scenario Test', path: '/test' },
    { icon: MessageSquare, label: 'Interactive Test', path: '/interactive', badge: 'BETA' },
    { icon: Users, label: 'Multi-Role', path: '/multirole', badge: 'BETA' },
    { icon: Layers, label: 'Cross-App', path: '/crossapp', badge: 'BETA' },
    { icon: Lock, label: 'Security', path: '/security' },
    { icon: GitBranch, label: 'Staging Safe', path: '/staging-safe', badge: 'BETA' },
    { icon: History, label: 'Test History', path: '/history' },
    { icon: Settings, label: 'Settings', path: '/settings' },
  ];

  const isActive = (path) => {
    if (path === '/') return location.pathname === '/';
    return location.pathname === path || location.pathname.startsWith(path + '/');
  };

  const handleLogout = () => base44.auth.logout('/');

  const saveApiKey = async (newKey) => {
    const trimmed = (newKey || '').trim();
    if (!trimmed) {
      setApiKey(user?.email, '');
      setApiKeyState('');
      setKeyError(null);
      setEditingKey(false);
      return;
    }
    if (!trimmed.startsWith('sk-ant-')) {
      setKeyError('Keys start with sk-ant-');
      return;
    }
    setVerifying(true);
    setKeyError(null);
    try {
      const res = await base44.functions.invoke('verifyAnthropicKey', { apiKey: trimmed });
      if (res?.data?.ok) {
        setApiKey(user?.email, trimmed);
        setApiKeyState(trimmed);
        setEditingKey(false);
      } else {
        setKeyError(res?.data?.error || 'Validation failed');
      }
    } catch (e) {
      setKeyError(e.message || 'Validation failed');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="w-64 bg-sidebar border-r border-sidebar-border flex flex-col h-screen">
      {/* Logo */}
      <div className="px-6 py-6 border-b border-sidebar-border">
        <Link to="/" className="inline-block">
          <Logo />
        </Link>
        <p className="text-[10px] text-muted-foreground font-mono mt-1">v1 — universal ai tester</p>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        {navItems.map(({ icon: Icon, label, path, badge }) => (
          <Link
            key={path}
            to={path}
            className={`flex items-center gap-3 px-3 py-2 rounded text-sm transition-colors ${
              isActive(path)
                ? 'bg-sidebar-accent text-sidebar-accent-foreground font-medium'
                : 'text-sidebar-foreground hover:bg-sidebar-accent/40'
            }`}
          >
            <Icon className="w-4 h-4 flex-shrink-0" />
            <span className="flex-1 truncate">{label}</span>
            {badge && (
              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-primary/15 text-primary border border-primary/30">
                {badge}
              </span>
            )}
          </Link>
        ))}
      </nav>

      {/* User + API key */}
      <div className="px-4 py-3 border-t border-sidebar-border space-y-3">
        {user && (
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] font-mono text-muted-foreground truncate flex-1">
              {user.email}
            </span>
            <button onClick={handleLogout} className="text-[10px] text-muted-foreground hover:text-foreground flex items-center gap-1" title="Sign out">
              <LogOut className="w-3 h-3" /> Sign out
            </button>
          </div>
        )}

        {/* Anthropic API Key */}
        <div>
          <label className="block text-[10px] uppercase tracking-wider text-primary font-bold mb-1.5">
            Claude API Key
          </label>
          {hasApiKey(user?.email) && !editingKey ? (
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] font-mono text-muted-foreground flex-1 truncate">
                {maskApiKey(apiKey)}
              </span>
              <button
                onClick={() => setEditingKey(true)}
                className="text-[10px] px-2 py-1 rounded border border-border hover:bg-secondary"
              >
                Change
              </button>
            </div>
          ) : (
            <>
              <input
                type="password"
                placeholder="sk-ant-..."
                defaultValue={apiKey}
                disabled={verifying}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') saveApiKey(e.target.value);
                }}
                onBlur={(e) => {
                  if (editingKey || !hasApiKey(user?.email)) saveApiKey(e.target.value);
                }}
                className={`w-full text-[11px] font-mono px-2 py-1.5 rounded bg-input border ${keyError ? 'border-destructive' : 'border-primary/30'} text-foreground focus:outline-none focus:ring-1 focus:ring-primary`}
              />
              {verifying && (
                <div className="text-[10px] text-primary mt-1 font-mono flex items-center gap-1">
                  <Loader2 className="w-3 h-3 animate-spin" /> Validating…
                </div>
              )}
              {keyError && (
                <div className="text-[10px] text-destructive mt-1 font-mono">
                  ⚠ {keyError}
                </div>
              )}
              {!verifying && !keyError && (
                <p className="text-[10px] text-muted-foreground mt-1 font-mono leading-snug">
                  Need a key? <a href="https://console.anthropic.com" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">console.anthropic.com →</a>
                </p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
