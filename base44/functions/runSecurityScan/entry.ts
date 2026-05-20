import { createClientFromRequest } from 'npm:@base44/sdk@0.8.25';

Deno.serve(async (req) => {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me();

    if (!user) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const payload = await req.json();
    const { appId, userA, userB, destructive, apiKey } = payload;

    // Get the app
    const apps = await base44.entities.App.filter({ app_id: appId });
    if (!apps || apps.length === 0) {
      return Response.json({ error: 'App not found' }, { status: 404 });
    }

    // Create SecurityScan entity first
    const scan = await base44.entities.SecurityScan.create({
      app: apps[0].id,
      user_a_name: userA.name,
      user_a_email: userA.email,
      user_b_name: userB.name,
      user_b_email: userB.email,
      destructive,
      status: 'running',
      owner_email: user.email,
      started_at: new Date().toISOString()
    });

    // Call Azure backend (fire and forget, will poll separately)
    const azureKey = Deno.env.get('AZURE_BACKEND_KEY');
    const azureRes = await fetch('https://testpilotapp.dev/api/security/api-intercept', {
      method: 'POST',
      headers: {
        'X-Base44-Auth': azureKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        appId,
        userA,
        userB,
        mode: destructive ? 'destructive' : 'read-only',
        apiKey,
        userEmail: user.email
      })
    });

    if (!azureRes.ok) {
      const err = await azureRes.text();
      await base44.entities.SecurityScan.update(scan.id, { status: 'error' });
      return Response.json({ error: err }, { status: azureRes.status });
    }

    const results = await azureRes.json();

    // Update scan with results
    await base44.entities.SecurityScan.update(scan.id, {
      status: 'completed',
      finished_at: new Date().toISOString(),
      report_json: results,
      total_tests: results.total || 0,
      vulns_count: results.vulnerabilities?.length || 0,
      suspicious_count: results.suspicious?.length || 0,
      safe_count: results.safe?.length || 0,
      report_url: results.report_url || ''
    });

    return Response.json({ scan });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
});