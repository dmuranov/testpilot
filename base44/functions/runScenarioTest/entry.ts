import { createClientFromRequest } from 'npm:@base44/sdk@0.8.25';

Deno.serve(async (req) => {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me();

    if (!user) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const payload = await req.json();
    const { appId, scenario, email, password, apiKey, freeRun } = payload;

    // Get the app
    const app = await base44.entities.App.filter({ app_id: appId });
    if (!app || app.length === 0) {
      return Response.json({ error: 'App not found' }, { status: 404 });
    }

    // Call Azure backend
    const azureKey = Deno.env.get('AZURE_BACKEND_KEY');
    const azureRes = await fetch('https://testpilotapp.dev/api/test', {
      method: 'POST',
      headers: {
        'X-Base44-Auth': azureKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        appId,
        scenario,
        email: email || null,
        password: password || null,
        apiKey,
        freeRun,
        userEmail: user.email
      })
    });

    if (!azureRes.ok) {
      const err = await azureRes.text();
      return Response.json({ error: err }, { status: azureRes.status });
    }

    const { testId, status } = await azureRes.json();

    // Create TestRun entity
    const testRun = await base44.entities.TestRun.create({
      test_id: testId,
      app: app[0].id,
      kind: 'scenario',
      scenario,
      status: 'running',
      owner_email: user.email,
      started_at: new Date().toISOString(),
      live_view_url: `https://testpilotapp.dev/live-test/${testId}`
    });

    return Response.json({ testId, testRun });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
});