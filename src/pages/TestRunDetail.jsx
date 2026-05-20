import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { base44 } from '@/api/base44Client';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, RefreshCw, Download, Copy, AlertCircle, CheckCircle, Circle, XCircle } from 'lucide-react';

// Live status polling: while the test is running on Azure, poll every 5s
// to update the entity. The Base44 function `getTestStatus` proxies to
// Azure's /api/test/:testId and writes the latest fields back to our
// TestRun entity. Stops polling once status is terminal.
const TERMINAL = new Set(['completed', 'completed_with_bugs', 'blocked', 'blocked_loop', 'aborted_budget', 'error']);

const StatusBadge = ({ status }) => {
  const map = {
    running: { label: '⏳ Running', cls: 'bg-primary/20 text-primary border-primary/40' },
    completed: { label: '✓ Completed', cls: 'bg-green-500/20 text-green-500 border-green-500/40' },
    completed_with_bugs: { label: '⚠ Completed (bugs)', cls: 'bg-yellow-500/20 text-yellow-500 border-yellow-500/40' },
    blocked: { label: '✕ Blocked', cls: 'bg-destructive/20 text-destructive border-destructive/40' },
    blocked_loop: { label: '🔁 Stuck in loop', cls: 'bg-destructive/20 text-destructive border-destructive/40' },
    aborted_budget: { label: '$ Budget aborted', cls: 'bg-destructive/20 text-destructive border-destructive/40' },
    error: { label: '💥 Error', cls: 'bg-destructive/20 text-destructive border-destructive/40' },
  };
  const m = map[status] || { label: status, cls: 'bg-secondary text-muted-foreground border-border' };
  return <span className={`inline-block px-3 py-1 rounded border text-xs font-mono ${m.cls}`}>{m.label}</span>;
};

const StatCard = ({ label, value, color = 'text-foreground' }) => (
  <div className="bg-card border border-border rounded p-4">
    <p className="text-xs text-muted-foreground font-mono">{label}</p>
    <p className={`text-2xl font-syne font-bold mt-1 ${color}`}>{value ?? '—'}</p>
  </div>
);

export default function TestRunDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [refreshing, setRefreshing] = useState(false);

  // Initial fetch + on poll
  const { data: testRun, isLoading, error } = useQuery({
    queryKey: ['testRun', id],
    queryFn: () => base44.entities.TestRun.get(id),
    enabled: !!id,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && !TERMINAL.has(status) ? 5000 : false;
    },
  });

  // Trigger Azure status sync while running. The query above just reads
  // our cached entity; this forces Base44 → Azure → update entity.
  useEffect(() => {
    if (!testRun || TERMINAL.has(testRun.status)) return;
    const tick = async () => {
      try {
        await base44.functions.invoke('getTestStatus', { testId: testRun.test_id });
        queryClient.invalidateQueries({ queryKey: ['testRun', id] });
      } catch { /* polling errors are silent */ }
    };
    const interval = setInterval(tick, 5000);
    tick(); // fire one immediately
    return () => clearInterval(interval);
  }, [testRun?.test_id, testRun?.status, id, queryClient]);

  const manualRefresh = async () => {
    setRefreshing(true);
    try {
      await base44.functions.invoke('getTestStatus', { testId: testRun.test_id });
      await queryClient.invalidateQueries({ queryKey: ['testRun', id] });
    } finally {
      setRefreshing(false);
    }
  };

  const copyReport = () => {
    if (!testRun) return;
    const text = [
      `TestPilot Report`,
      `Test: ${testRun.test_id}`,
      `Scenario: ${testRun.scenario || '(no scenario)'}`,
      `Status: ${testRun.status}`,
      `Steps: ${testRun.steps_passed || 0} passed / ${testRun.steps_failed || 0} failed`,
      `Bugs: ${testRun.bugs_count || 0}`,
      ``,
      `--- Summary ---`,
      testRun.summary_md || '(no summary yet)',
    ].join('\n');
    navigator.clipboard.writeText(text);
  };

  if (isLoading) {
    return <div className="flex justify-center py-16"><div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full" /></div>;
  }

  if (error || !testRun) {
    return (
      <div className="max-w-2xl mx-auto py-12 text-center">
        <AlertCircle className="w-12 h-12 text-destructive mx-auto mb-4" />
        <h2 className="text-xl font-syne font-bold mb-2">Test run not found</h2>
        <p className="text-muted-foreground mb-6">It may have been deleted, or the link is invalid.</p>
        <Link to="/history" className="bg-primary text-primary-foreground px-6 py-2 rounded font-syne font-bold inline-block">
          Back to history
        </Link>
      </div>
    );
  }

  const isRunning = !TERMINAL.has(testRun.status);
  const bugs = Array.isArray(testRun.bugs_json) ? testRun.bugs_json : (testRun.bugs_json?.bugs || []);

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="flex-1 min-w-0">
          <button onClick={() => navigate(-1)} className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-2">
            <ArrowLeft className="w-4 h-4" /> Back
          </button>
          <h1 className="text-2xl font-syne font-bold mb-1">Test Run</h1>
          <p className="text-xs font-mono text-muted-foreground break-all">{testRun.test_id}</p>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge status={testRun.status} />
          {isRunning && (
            <button onClick={manualRefresh} disabled={refreshing} className="p-2 rounded hover:bg-secondary disabled:opacity-50" title="Refresh">
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            </button>
          )}
        </div>
      </div>

      {/* Scenario */}
      {testRun.scenario && (
        <div className="bg-card border border-border rounded p-4">
          <p className="text-xs text-muted-foreground font-mono mb-1">SCENARIO</p>
          <p className="text-sm whitespace-pre-wrap">{testRun.scenario}</p>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Steps Total" value={testRun.steps_total} />
        <StatCard label="Passed" value={testRun.steps_passed} color="text-green-500" />
        <StatCard label="Failed" value={testRun.steps_failed} color="text-destructive" />
        <StatCard label="Bugs Found" value={testRun.bugs_count} color={testRun.bugs_count > 0 ? 'text-destructive' : 'text-foreground'} />
      </div>

      {/* Live view (only while running) */}
      {isRunning && testRun.live_view_url && (
        <div className="bg-card border border-border rounded overflow-hidden">
          <div className="px-4 py-2 border-b border-border flex items-center justify-between">
            <p className="text-xs font-mono text-muted-foreground">LIVE EXECUTION</p>
            <span className="text-xs text-primary font-mono flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-primary animate-pulse" /> streaming
            </span>
          </div>
          <iframe
            src={testRun.live_view_url}
            className="w-full"
            style={{ height: '600px', border: 'none' }}
            title="Live test execution"
          />
        </div>
      )}

      {/* Executive summary (when complete) */}
      {!isRunning && testRun.summary_md && (
        <div className="bg-card border border-border rounded p-6">
          <h2 className="text-lg font-syne font-bold mb-3">Executive Summary</h2>
          <pre className="text-sm whitespace-pre-wrap font-sans text-muted-foreground">{testRun.summary_md}</pre>
        </div>
      )}

      {/* Bugs (when complete) */}
      {!isRunning && bugs.length > 0 && (
        <div className="bg-card border border-destructive/40 rounded p-6">
          <h2 className="text-lg font-syne font-bold mb-3 text-destructive">Bugs Found ({bugs.length})</h2>
          <div className="space-y-3">
            {bugs.map((bug, i) => (
              <div key={i} className="border border-border rounded p-3">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xs font-mono text-destructive font-bold">BUG-{String(i + 1).padStart(2, '0')}</span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-secondary text-muted-foreground uppercase">{bug.severity || 'medium'}</span>
                  {bug.step && <span className="text-xs text-muted-foreground">Step {bug.step}</span>}
                </div>
                <p className="text-sm">{bug.description}</p>
                {bug.screenshot && (
                  <a href={bug.screenshot.startsWith('http') ? bug.screenshot : `https://testpilotapp.dev${bug.screenshot}`} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline mt-2 inline-block">
                    📸 View screenshot →
                  </a>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {!isRunning && bugs.length === 0 && testRun.status === 'completed' && (
        <div className="bg-green-500/10 border border-green-500/40 rounded p-6 text-center">
          <CheckCircle className="w-10 h-10 text-green-500 mx-auto mb-2" />
          <p className="font-syne font-bold text-green-500">No bugs found</p>
          <p className="text-sm text-muted-foreground mt-1">The scenario completed cleanly.</p>
        </div>
      )}

      {/* Actions */}
      <div className="flex flex-wrap gap-2 pt-4 border-t border-border">
        <button onClick={copyReport} className="flex items-center gap-2 px-4 py-2 rounded border border-border hover:bg-secondary text-sm">
          <Copy className="w-4 h-4" /> Copy report
        </button>
        {testRun.report_url && (
          <a href={testRun.report_url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 px-4 py-2 rounded border border-border hover:bg-secondary text-sm">
            <Download className="w-4 h-4" /> Download PDF
          </a>
        )}
        <Link to="/history" className="px-4 py-2 rounded border border-border hover:bg-secondary text-sm">
          Back to history
        </Link>
      </div>
    </div>
  );
}
