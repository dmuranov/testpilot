import React from 'react';
import { Link } from 'react-router-dom';
import { base44 } from '@/api/base44Client';
import { useQuery } from '@tanstack/react-query';
import { Zap, Lock, Briefcase, TrendingUp } from 'lucide-react';
import { format } from 'date-fns';

const StatCard = ({ label, value, icon: Icon, bgColor }) => (
  <div className="bg-card border border-border rounded p-6">
    <div className="flex items-start justify-between">
      <div>
        <p className="text-muted-foreground text-sm font-mono">{label}</p>
        <p className="text-3xl font-syne font-bold mt-2">{value}</p>
      </div>
      <div className={`p-3 rounded ${bgColor}`}>
        <Icon className="w-6 h-6 text-primary" />
      </div>
    </div>
  </div>
);

export default function Dashboard() {
  const [user, setUser] = React.useState(null);

  React.useEffect(() => {
    base44.auth.me().then(setUser).catch(() => {});
  }, []);

  const { data: apps } = useQuery({
    queryKey: ['apps', user?.email],
    queryFn: () => base44.entities.App.filter({ owner_email: user?.email }),
    enabled: !!user?.email,
    initialData: []
  });

  const { data: testRuns } = useQuery({
    queryKey: ['testRuns', user?.email],
    queryFn: () => base44.entities.TestRun.filter({ owner_email: user?.email }, '-finished_at', 10),
    enabled: !!user?.email,
    initialData: []
  });

  const bugsThisMonth = testRuns.filter(t => {
    if (!t.finished_at) return false;
    const date = new Date(t.finished_at);
    const now = new Date();
    return date.getMonth() === now.getMonth() && date.getFullYear() === now.getFullYear();
  }).reduce((sum, t) => sum + (t.bugs_count || 0), 0);

  const testsThisMonth = testRuns.filter(t => {
    if (!t.finished_at) return false;
    const date = new Date(t.finished_at);
    const now = new Date();
    return date.getMonth() === now.getMonth() && date.getFullYear() === now.getFullYear();
  }).length;

  const passingRate = testRuns.length > 0 
    ? Math.round((testRuns.filter(t => t.status === 'completed').length / testRuns.length) * 100)
    : 0;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-4xl font-syne font-bold">Dashboard</h1>
        <p className="text-muted-foreground mt-2">Welcome back, {user?.full_name}.</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <StatCard label="Apps Registered" value={apps.length} icon={Briefcase} bgColor="bg-primary/10" />
        <StatCard label="Tests This Month" value={testsThisMonth} icon={Zap} bgColor="bg-accent/10" />
        <StatCard label="Bugs Found" value={bugsThisMonth} icon={Lock} bgColor="bg-destructive/10" />
        <StatCard label="Passing Rate" value={`${passingRate}%`} icon={TrendingUp} bgColor="bg-green-500/10" />
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link
          to="/apps/learn"
          className="bg-primary text-primary-foreground px-6 py-4 rounded font-syne font-bold hover:opacity-90 transition-opacity text-center"
        >
          + Learn New App
        </Link>
        <Link
          to="/test"
          className="border border-border bg-card px-6 py-4 rounded font-syne font-bold hover:bg-secondary transition-colors text-center"
        >
          ▶ Run Scenario Test
        </Link>
        <Link
          to="/security"
          className="border border-border bg-card px-6 py-4 rounded font-syne font-bold hover:bg-secondary transition-colors text-center"
        >
          🔬 Run Security Scan
        </Link>
      </div>

      {/* Recent Tests */}
      {testRuns.length > 0 && (
        <div className="bg-card border border-border rounded p-6">
          <h2 className="text-xl font-syne font-bold mb-4">Recent Test Runs</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 font-mono font-medium text-muted-foreground">App</th>
                  <th className="text-left py-3 px-4 font-mono font-medium text-muted-foreground">Type</th>
                  <th className="text-left py-3 px-4 font-mono font-medium text-muted-foreground">Scenario</th>
                  <th className="text-left py-3 px-4 font-mono font-medium text-muted-foreground">Status</th>
                  <th className="text-left py-3 px-4 font-mono font-medium text-muted-foreground">Finished</th>
                </tr>
              </thead>
              <tbody>
                {testRuns.map((testRun) => (
                  <tr key={testRun.id} className="border-b border-border hover:bg-secondary/30 transition-colors">
                    <td className="py-3 px-4 font-mono text-sm">{testRun.app || '—'}</td>
                    <td className="py-3 px-4 font-mono text-sm capitalize">{testRun.kind}</td>
                    <td className="py-3 px-4 text-xs truncate max-w-xs">{testRun.scenario?.substring(0, 40)}...</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-1 text-xs rounded font-mono ${
                        testRun.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                        testRun.status === 'running' ? 'bg-accent/20 text-primary' :
                        'bg-destructive/20 text-destructive'
                      }`}>
                        {testRun.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-xs text-muted-foreground">
                      {testRun.finished_at ? format(new Date(testRun.finished_at), 'MMM d, HH:mm') : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Empty State */}
      {apps.length === 0 && (
        <div className="text-center py-16 border border-border rounded bg-card/50">
          <h3 className="text-lg font-syne font-bold mb-2">No apps registered yet</h3>
          <p className="text-muted-foreground mb-6">Learn your first app to start testing</p>
          <Link
            to="/apps/learn"
            className="inline-block bg-primary text-primary-foreground px-6 py-2 rounded font-syne font-bold hover:opacity-90"
          >
            Learn Your First App
          </Link>
        </div>
      )}
    </div>
  );
}