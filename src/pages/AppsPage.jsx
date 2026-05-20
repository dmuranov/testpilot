import React from 'react';
import { Link } from 'react-router-dom';
import { base44 } from '@/api/base44Client';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Trash2, ExternalLink, Zap } from 'lucide-react';

export default function AppsPage() {
  const [user, setUser] = React.useState(null);
  const queryClient = useQueryClient();

  React.useEffect(() => {
    base44.auth.me().then(setUser).catch(() => {});
  }, []);

  const { data: apps, isLoading } = useQuery({
    queryKey: ['apps', user?.email],
    queryFn: () => base44.entities.App.filter({ owner_email: user?.email }),
    enabled: !!user?.email,
    initialData: []
  });

  const deleteMutation = useMutation({
    mutationFn: (appId) => base44.entities.App.delete(appId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['apps'] });
    }
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-syne font-bold">Learned Apps</h1>
          <p className="text-muted-foreground mt-1">Apps registered for testing</p>
        </div>
        <Link
          to="/apps/learn"
          className="bg-primary text-primary-foreground px-4 py-2 rounded font-syne font-bold hover:opacity-90"
        >
          + Learn New App
        </Link>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-8">
          <div className="animate-spin w-6 h-6 border-2 border-primary border-t-transparent rounded-full" />
        </div>
      ) : apps.length === 0 ? (
        <div className="text-center py-16 border border-border rounded bg-card/50">
          <p className="text-muted-foreground mb-4">No apps learned yet</p>
          <Link
            to="/apps/learn"
            className="inline-block bg-primary text-primary-foreground px-6 py-2 rounded font-syne font-bold"
          >
            Learn Your First App
          </Link>
        </div>
      ) : (
        <div className="grid gap-4">
          {apps.map((app) => (
            <div key={app.id} className="bg-card border border-border rounded p-6 hover:border-primary/50 transition-colors">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <h3 className="text-lg font-syne font-bold">{app.name}</h3>
                  <p className="text-muted-foreground font-mono text-sm mt-1">{app.url}</p>
                  {app.description && <p className="text-muted-foreground text-sm mt-2">{app.description}</p>}
                  <div className="mt-3 flex items-center gap-2">
                    <span className={`px-2 py-1 text-xs rounded font-mono ${
                      app.status === 'ready' ? 'bg-green-500/20 text-green-400' :
                      app.status === 'learning' ? 'bg-accent/20 text-primary' :
                      'bg-destructive/20 text-destructive'
                    }`}>
                      {app.status}
                    </span>
                    {app.learned_at && (
                      <span className="text-xs text-muted-foreground font-mono">
                        Learned {new Date(app.learned_at).toLocaleDateString()}
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex gap-2">
                  <Link
                    to={`/apps/${app.id}`}
                    className="p-2 rounded border border-border hover:bg-secondary transition-colors"
                    title="View details"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </Link>
                  {app.status === 'ready' && (
                    <Link
                      to="/test"
                      className="p-2 rounded border border-border hover:bg-secondary transition-colors"
                      title="Run test"
                    >
                      <Zap className="w-4 h-4" />
                    </Link>
                  )}
                  <button
                    onClick={() => deleteMutation.mutate(app.id)}
                    className="p-2 rounded border border-border hover:bg-destructive/20 text-destructive transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}