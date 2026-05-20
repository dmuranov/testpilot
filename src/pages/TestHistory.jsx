import React, { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { base44 } from '@/api/base44Client';
import { useQuery } from '@tanstack/react-query';
import { format } from 'date-fns';

const KIND_LABELS = {
  scenario: 'Scenario',
  multi_role: 'Multi-Role',
  security: 'Security',
  staging_safe: 'Staging Safe',
};

const STATUS_COLORS = {
  running: 'text-primary',
  completed: 'text-green-500',
  completed_with_bugs: 'text-yellow-500',
  blocked: 'text-destructive',
  blocked_loop: 'text-destructive',
  aborted_budget: 'text-destructive',
  error: 'text-destructive',
};

export default function TestHistory() {
  const [user, setUser] = React.useState(null);
  const [filterKind, setFilterKind] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  React.useEffect(() => {
    base44.auth.me().then(setUser).catch(() => {});
  }, []);

  const { data: runs, isLoading } = useQuery({
    queryKey: ['testRuns-all', user?.email],
    queryFn: () => base44.entities.TestRun.filter({ owner_email: user?.email }, '-started_at', 200),
    enabled: !!user?.email,
    initialData: [],
  });

  const { data: apps } = useQuery({
    queryKey: ['apps', user?.email],
    queryFn: () => base44.entities.App.filter({ owner_email: user?.email }),
    enabled: !!user?.email,
    initialData: [],
  });

  const appMap = useMemo(() => Object.fromEntries(apps.map((a) => [a.id, a])), [apps]);

  const filtered = useMemo(() => runs.filter((r) => {
    if (filterKind !== 'all' && r.kind !== filterKind) return false;
    if (filterStatus !== 'all' && r.status !== filterStatus) return false;
    return true;
  }), [runs, filterKind, filterStatus]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-3xl font-syne font-bold">Test History</h1>
          <p className="text-muted-foreground mt-1">All your test runs across every app</p>
        </div>
        <Link to="/test" className="bg-primary text-primary-foreground px-4 py-2 rounded font-syne font-bold hover:opacity-90">
          + New Test
        </Link>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <div>
          <label className="block text-xs text-muted-foreground font-mono mb-1">Kind</label>
          <select
            value={filterKind}
            onChange={(e) => setFilterKind(e.target.value)}
            className="bg-input border border-border rounded px-3 py-2 text-sm"
          >
            <option value="all">All kinds</option>
            <option value="scenario">Scenario</option>
            <option value="multi_role">Multi-Role</option>
            <option value="security">Security</option>
            <option value="staging_safe">Staging Safe</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-muted-foreground font-mono mb-1">Status</label>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-input border border-border rounded px-3 py-2 text-sm"
          >
            <option value="all">All statuses</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="completed_with_bugs">Completed (bugs)</option>
            <option value="blocked">Blocked</option>
            <option value="blocked_loop">Blocked (loop)</option>
            <option value="error">Error</option>
          </select>
        </div>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-8">
          <div className="animate-spin w-6 h-6 border-2 border-primary border-t-transparent rounded-full" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16 border border-border rounded bg-card/50">
          <p className="text-muted-foreground mb-4">
            {runs.length === 0 ? 'No tests run yet.' : 'No tests match the current filters.'}
          </p>
          {runs.length === 0 && (
            <Link to="/test" className="inline-block bg-primary text-primary-foreground px-6 py-2 rounded font-syne font-bold">
              Run Your First Test
            </Link>
          )}
        </div>
      ) : (
        <div className="bg-card border border-border rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-secondary/50 border-b border-border">
              <tr className="text-left">
                <th className="px-4 py-3 font-mono text-xs text-muted-foreground">App</th>
                <th className="px-4 py-3 font-mono text-xs text-muted-foreground">Kind</th>
                <th className="px-4 py-3 font-mono text-xs text-muted-foreground">Scenario</th>
                <th className="px-4 py-3 font-mono text-xs text-muted-foreground">Status</th>
                <th className="px-4 py-3 font-mono text-xs text-muted-foreground">Bugs</th>
                <th className="px-4 py-3 font-mono text-xs text-muted-foreground">When</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => (
                <tr key={r.id} className="border-b border-border last:border-0 hover:bg-secondary/30">
                  <td className="px-4 py-3">
                    <Link to={`/test/${r.id}`} className="hover:text-primary">
                      {appMap[r.app]?.name || '(unknown)'}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-muted-foreground">{KIND_LABELS[r.kind] || r.kind}</td>
                  <td className="px-4 py-3 text-xs truncate max-w-xs">
                    <Link to={`/test/${r.id}`} className="hover:text-primary block truncate">
                      {r.scenario || '—'}
                    </Link>
                  </td>
                  <td className={`px-4 py-3 text-xs font-mono ${STATUS_COLORS[r.status] || ''}`}>{r.status}</td>
                  <td className="px-4 py-3 text-xs font-mono">
                    {r.bugs_count > 0 ? <span className="text-destructive">{r.bugs_count}</span> : r.bugs_count ?? 0}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {r.started_at ? format(new Date(r.started_at), 'd MMM HH:mm') : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
