import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, Zap, Lock, Settings, LogOut, Briefcase, History } from 'lucide-react';
import { base44 } from '@/api/base44Client';

const Logo = () => (
  <div className="flex items-baseline gap-0.5 font-syne font-bold text-lg">
    <span className="text-foreground">Test</span>
    <span className="text-primary">&gt;_Pilot</span>
  </div>
);

export default function Sidebar() {
  const location = useLocation();
  const [user, setUser] = React.useState(null);

  React.useEffect(() => {
    base44.auth.me().then(setUser).catch(() => {});
  }, []);

  const navItems = [
    { icon: LayoutDashboard, label: 'Dashboard', path: '/' },
    { icon: Briefcase, label: 'Apps', path: '/apps' },
    { icon: Zap, label: 'Test', path: '/test' },
    { icon: History, label: 'History', path: '/history' },
    { icon: Lock, label: 'Security', path: '/security' },
    { icon: Settings, label: 'Settings', path: '/settings' },
  ];

  const isActive = (path) => location.pathname === path || location.pathname.startsWith(path + '/');

  const handleLogout = () => {
    base44.auth.logout('/');
  };

  return (
    <div className="w-64 bg-sidebar border-r border-sidebar-border flex flex-col h-screen">
      {/* Logo */}
      <div className="px-6 py-6 border-b border-sidebar-border">
        <Link to="/" className="inline-block">
          <Logo />
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto">
        {navItems.map(({ icon: Icon, label, path }) => (
          <Link
            key={path}
            to={path}
            className={`flex items-center gap-3 px-4 py-2 rounded text-sm transition-colors ${
              isActive(path)
                ? 'bg-sidebar-accent text-sidebar-primary font-medium'
                : 'text-sidebar-foreground hover:bg-sidebar-accent hover:bg-opacity-50'
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
          </Link>
        ))}
      </nav>

      {/* User */}
      <div className="px-6 py-4 border-t border-sidebar-border space-y-3">
        <div className="text-xs text-sidebar-foreground text-opacity-70">
          <div className="truncate font-medium">{user?.full_name || 'User'}</div>
          <div className="truncate">{user?.email}</div>
        </div>
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-2 px-3 py-2 text-sm text-sidebar-foreground hover:bg-sidebar-accent rounded transition-colors"
        >
          <LogOut className="w-4 h-4" />
          Logout
        </button>
      </div>
    </div>
  );
}